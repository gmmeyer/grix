//! Timers: setitimer, POSIX timers (timer_create) and timerfds. Each has a
//! monotonic deadline, or for ITIMER_VIRTUAL/ITIMER_PROF and timers on
//! CPU-time clocks, one in the process's or a thread's CPU time. The
//! scheduler programs the CPU timer for the earliest one (together with
//! sleeping threads' deadlines; a CPU-time one only while its threads run,
//! `cpu_deadline`) and calls `fire` once it has passed: signal timers queue
//! their signal, timerfds count the expiration and wake I/O waiters.
//!
//! Like Linux, a timer only re-arms once its last expiry has been consumed:
//! while its signal is still queued, or its timerfd still readable, it drops
//! out of the deadlines, and the periods that pass meanwhile are counted
//! when the signal is taken (as overruns) or the fd read. So a 1 ns periodic
//! timer can't keep the CPU in the timer interrupt.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::errno::*;
use crate::ipc;
use crate::kmem::Charge;
use crate::process::Process;
use crate::signal::{self, SigInfo, Target};
use crate::time;

pub const SIGALRM: u32 = 14;
const SIGVTALRM: u32 = 26;
const SIGPROF: u32 = 27;
const SI_KERNEL: i32 = 0x80;
const SI_TIMER: i32 = -2;
/// timer_create's per-process limit (Linux's is RLIMIT_SIGPENDING-sized):
/// `fire` and the scheduler look through a process's.
pub const MAX_POSIX_TIMERS: usize = 1024;
/// And in all processes together: what bounds kernel memory, as each is
/// charged to `kmem` as well (`TIMER_COST`). EAGAIN at either.
const MAX_TIMERS_TOTAL: usize = 8192;
/// A timer's share of the heap: B-tree nodes are half empty when timers
/// are made in order.
const TIMER_COST: u64 = 2 * (core::mem::size_of::<PosixTimer>() + 4) as u64;
/// `SigInfo::timer` for ITIMER_REAL's SIGALRM.
const REAL_TIMER: u32 = u32::MAX;
/// `SigInfo::timer` for ITIMER_VIRTUAL's and ITIMER_PROF's signals.
const CPU_ITIMERS: [u32; 2] = [u32::MAX - 1, u32::MAX - 2];
/// The highest id timer_create hands out (the rest are the itimers').
pub const MAX_TIMER_ID: u32 = u32::MAX - 3;
/// A periodic timer whose signal is ignored still wakes the CPU; Linux backs
/// those off too ("posix-timers: Prevent softirq starvation by small
/// intervals and SIG_IGN").
const IGNORED_MIN_PERIOD: u64 = 4_000_000;

/// When a timer expires next (monotonic ns) and its period (0 = one-shot).
#[derive(Clone, Copy, Default, Debug)]
pub struct Interval {
    pub next: Option<u64>,
    pub period: u64,
}

impl Interval {
    /// Count the expirations up to `now` and move on to the next one, or
    /// disarm a one-shot timer.
    pub fn expire(&mut self, now: u64) -> u64 {
        let Some(next) = self.next.filter(|&n| n <= now) else { return 0 };
        if self.period == 0 {
            self.next = None;
            return 1;
        }
        let n = (now - next) / self.period + 1;
        self.next = Some(next.saturating_add(n.saturating_mul(self.period)));
        n
    }

    /// Time left until the next expiry (gettime), looking past expiries that
    /// haven't been processed yet: 0 once a one-shot timer has run out.
    pub fn remaining(&self, now: u64) -> u64 {
        let mut t = *self;
        t.expire(now);
        t.next.map_or(0, |n| n.saturating_sub(now).max(1))
    }
}

/// How a POSIX timer reports expiries (struct sigevent).
#[derive(Clone, Copy, Debug)]
pub enum Notify {
    /// SIGEV_NONE: only timer_gettime sees it.
    None,
    /// SIGEV_SIGNAL (to the process) or SIGEV_THREAD_ID (to one thread).
    Signal { signo: u32, value: u64, thread: Option<u32> },
}

/// Whose CPU time a timer counts.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CpuClock {
    Process,
    Thread(u32),
}

impl CpuClock {
    /// The time on this clock (None: the thread is gone).
    pub fn now(self, p: &Process) -> Option<u64> {
        match self {
            CpuClock::Process => Some(p.process_cpu_ns()),
            CpuClock::Thread(tid) => p.thread_cpu_ns(tid),
        }
    }
}

/// Timers in all processes (`MAX_TIMERS_TOTAL`).
static TIMERS: AtomicUsize = AtomicUsize::new(0);

/// A timer's place in `TIMERS` and its charge, given back when it's dropped.
pub struct TimerHeld(#[allow(dead_code)] Charge);

impl TimerHeld {
    pub fn new() -> Result<TimerHeld, Errno> {
        if TIMERS.load(Ordering::Relaxed) >= MAX_TIMERS_TOTAL {
            crate::stats::hit(grix_abi::stats::Limit::Timers);
            return Err(EAGAIN);
        }
        let charge = Charge::new(TIMER_COST).map_err(|_| EAGAIN)?;
        // Under the kernel lock: check-then-add doesn't race.
        TIMERS.fetch_add(1, Ordering::Relaxed);
        Ok(TimerHeld(charge))
    }
}

impl Drop for TimerHeld {
    fn drop(&mut self) {
        TIMERS.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct PosixTimer {
    /// In CPU time, for a CPU-time clock's.
    pub timing: Interval,
    /// The clock absolute times (TIMER_ABSTIME) are on.
    pub clock: u64,
    pub cpu: Option<CpuClock>,
    pub notify: Notify,
    /// The overrun count of the last signal taken (timer_getoverrun).
    pub overrun: u32,
    /// Its signal is queued and hasn't been taken yet.
    pub pending: bool,
    pub _held: TimerHeld,
}

/// A timerfd: readable once it has expired, `read` returns and resets the count.
#[derive(Default)]
pub struct TimerFd {
    pub timing: Interval,
    /// The clock absolute times (TFD_TIMER_ABSTIME) are on.
    pub clock: u64,
    pub expirations: u64,
    /// Bumped on every expiry (for edge-triggered epoll).
    pub version: u64,
}

impl TimerFd {
    /// Catch up with the clock. Expiries are counted lazily (read, poll,
    /// gettime) as well as by `fire`; whoever counts one wakes the waiters.
    pub fn update(&mut self, now: u64) -> u64 {
        let n = self.timing.expire(now);
        if n > 0 {
            self.expirations = self.expirations.saturating_add(n);
            self.version += 1;
            ipc::changed();
        }
        n
    }
}

#[derive(Default)]
pub struct Timers {
    /// ITIMER_REAL: SIGALRM to the process.
    pub real: Interval,
    /// ITIMER_REAL's SIGALRM is queued and hasn't been taken yet.
    pub real_pending: bool,
    /// ITIMER_VIRTUAL and ITIMER_PROF, in the process's CPU time (all of
    /// it is counted as user time), and whether their signals are queued.
    pub cpu_itimers: [Interval; 2],
    pub cpu_pending: [bool; 2],
    pub posix: BTreeMap<u32, PosixTimer>,
    pub next_id: u32,
}

/// Every timerfd still open, so the scheduler wakes up for them. A
/// timerfd belongs to its file, which outlives whoever made it (fork,
/// SCM_RIGHTS), so no process's list would do. Weak: `add_timerfd` forgets
/// the closed ones, and open files are bounded (`fd::max_open_files`).
static TIMER_FDS: Mutex<Vec<Weak<Mutex<TimerFd>>>> = Mutex::new(Vec::new());

pub fn add_timerfd(fd: &Arc<Mutex<TimerFd>>) {
    let mut fds = TIMER_FDS.lock();
    // Once it's full, not each time: there may be tens of thousands.
    if fds.len() == fds.capacity() {
        fds.retain(|w| w.strong_count() > 0);
    }
    fds.push(Arc::downgrade(fd));
}

/// The earliest deadline of a timerfd that can wake someone up: not one
/// still readable from its last expiry.
pub fn timerfd_deadline() -> Option<u64> {
    let fds = TIMER_FDS.lock();
    let armed = fds.iter().filter_map(Weak::upgrade).filter_map(|t| {
        let t = t.lock();
        t.timing.next.filter(|_| t.expirations == 0)
    });
    armed.min()
}

/// Count the timerfds' expiries. Returns whether one became readable.
pub fn fire_timerfds() -> bool {
    let now = time::monotonic_ns();
    let mut fired = false;
    for fd in TIMER_FDS.lock().iter().filter_map(Weak::upgrade) {
        let mut t = fd.lock();
        if t.expirations == 0 && t.update(now) > 0 {
            fired = true;
        }
    }
    fired
}

impl Timers {
    /// The earliest deadline of a timer that can wake someone up. SIGEV_NONE
    /// timers can't, so they don't keep an otherwise deadlocked program
    /// alive; nor can timers whose last expiry is still unconsumed.
    pub fn next_deadline(&self) -> Option<u64> {
        let real = self.real.next.filter(|_| !self.real_pending);
        let posix = self
            .posix
            .values()
            .filter(|t| t.cpu.is_none() && !t.pending && matches!(t.notify, Notify::Signal { .. }))
            .filter_map(|t| t.timing.next);
        real.into_iter().chain(posix).min()
    }

    /// Has it a timer at all (armed or not)?
    pub fn any(&self) -> bool {
        self.real.next.is_some() || self.cpu_itimers.iter().any(|i| i.next.is_some()) || !self.posix.is_empty()
    }

    /// The timing of timer `id` (a POSIX timer's or an itimer's).
    fn timing(&mut self, id: u32) -> Option<&mut Interval> {
        match id {
            REAL_TIMER => Some(&mut self.real),
            id if id == CPU_ITIMERS[0] => Some(&mut self.cpu_itimers[0]),
            id if id == CPU_ITIMERS[1] => Some(&mut self.cpu_itimers[1]),
            id => self.posix.get_mut(&id).map(|t| &mut t.timing),
        }
    }
}

/// The time on timer `id`'s clock.
fn clock_of(p: &Process, id: u32) -> u64 {
    let cpu = match id {
        id if CPU_ITIMERS.contains(&id) => Some(CpuClock::Process),
        id => p.timers.posix.get(&id).and_then(|t| t.cpu),
    };
    match cpu {
        Some(c) => c.now(p).unwrap_or(0),
        None => time::monotonic_ns(),
    }
}

/// When a CPU-time timer of `p`'s can next be due, on the monotonic
/// clock: only while its threads run, and soonest if they all keep
/// running (the CPU time of n threads goes n times as fast). Firing early
/// costs nothing: `fire` checks the CPU time.
pub fn cpu_deadline(p: &Process) -> Option<u64> {
    if p.timers.cpu_itimers.iter().all(|i| i.next.is_none()) && p.timers.posix.is_empty() {
        return None;
    }
    let now = time::monotonic_ns();
    let running = |tid: u32| (p.running && tid == p.current) || crate::smp::running_since(tid).is_some();
    let threads = p.threads.keys().filter(|&&tid| running(tid)).count() as u64;
    if threads == 0 {
        return None;
    }
    let left = |next: u64, cpu_now: u64| next.saturating_sub(cpu_now);
    let process_now = p.process_cpu_ns();
    let itimers = (0..2)
        .filter(|&i| !p.timers.cpu_pending[i])
        .filter_map(|i| p.timers.cpu_itimers[i].next)
        .map(|next| left(next, process_now) / threads);
    let posix =
        p.timers.posix.values().filter(|t| !t.pending && matches!(t.notify, Notify::Signal { .. })).filter_map(|t| {
            match (t.cpu?, t.timing.next?) {
                (CpuClock::Process, next) => Some(left(next, process_now) / threads),
                (c @ CpuClock::Thread(tid), next) if running(tid) => Some(left(next, c.now(p)?)),
                _ => None,
            }
        });
    itimers.chain(posix).min().map(|wait| now.saturating_add(wait))
}

/// Has `p` an armed CPU-time timer (whose deadline `cpu_deadline` must
/// work out again as its threads come and go)?
pub fn cpu_timed(p: &Process) -> bool {
    p.timers.cpu_itimers.iter().any(|i| i.next.is_some())
        || p.timers.posix.values().any(|t| t.cpu.is_some() && t.timing.next.is_some())
}

/// Queue a timer's signal. Returns whether it was queued; an ignored one
/// backs its timer off to a minimum period instead.
fn send_timer_signal(p: &mut Process, target: Target, info: SigInfo, id: u32) -> bool {
    let _ = signal::send(p, target, info);
    if signal::queued_timer_signal(p, id).is_some() {
        return true;
    }
    let now = clock_of(p, id);
    if let Some(timing) = p.timers.timing(id)
        && let Some(next) = timing.next
    {
        timing.next = Some(next.max(now.saturating_add(IGNORED_MIN_PERIOD)));
    }
    false
}

/// Handle every timer of `p`'s whose deadline has passed. Returns whether
/// anything happened (a signal was sent).
pub fn fire(p: &mut Process) -> bool {
    // Most processes have none: the tick needn't count their CPU time.
    if !p.timers.any() {
        return false;
    }
    let now = time::monotonic_ns();
    let mut fired = false;
    if !p.timers.real_pending && p.timers.real.expire(now) > 0 {
        // Like Linux's it_real_fn: one SIGALRM however many periods passed.
        let mut info = SigInfo::sent(SIGALRM, SI_KERNEL, 0, 0, "SIGALRM: the interval timer (alarm/setitimer) expired");
        info.fields = [0; 4]; // sent by the kernel: no pid or uid
        info.timer = Some(REAL_TIMER);
        p.timers.real_pending = send_timer_signal(p, Target::Process, info, REAL_TIMER);
        fired = true;
    }
    let cpu_now = p.process_cpu_ns();
    for (i, (signo, why)) in [
        (SIGVTALRM, "SIGVTALRM: the virtual interval timer (setitimer ITIMER_VIRTUAL) expired"),
        (SIGPROF, "SIGPROF: the profiling interval timer (setitimer ITIMER_PROF) expired"),
    ]
    .into_iter()
    .enumerate()
    {
        if !p.timers.cpu_pending[i] && p.timers.cpu_itimers[i].expire(cpu_now) > 0 {
            let mut info = SigInfo::sent(signo, SI_KERNEL, 0, 0, why);
            info.fields = [0; 4];
            info.timer = Some(CPU_ITIMERS[i]);
            p.timers.cpu_pending[i] = send_timer_signal(p, Target::Process, info, CPU_ITIMERS[i]);
            fired = true;
        }
    }
    let clocks: Vec<(u32, u64)> = p
        .timers
        .posix
        .iter()
        .filter(|(_, t)| !t.pending && t.timing.next.is_some())
        .filter_map(|(&id, t)| Some((id, t.cpu.map_or(Some(now), |c| c.now(p))?)))
        .collect();
    let due: Vec<(u32, u64)> = clocks
        .into_iter()
        .filter_map(|(id, at)| Some((id, p.timers.posix.get_mut(&id)?.timing.expire(at))).filter(|&(_, n)| n > 0))
        .collect();
    for (id, n) in due {
        fired = true;
        let Notify::Signal { signo, value, thread } = p.timers.posix[&id].notify else { continue };
        let extra = (n - 1).min(i32::MAX as u64);
        let mut info = SigInfo::sent(signo, SI_TIMER, 0, 0, "signal from a POSIX timer (timer_create)");
        info.fields = [id as u64 | extra << 32, value, 0, 0];
        info.timer = Some(id);
        let target = match thread {
            Some(tid) if p.threads.contains_key(&tid) => Target::Thread(tid),
            _ => Target::Process,
        };
        let queued = send_timer_signal(p, target, info, id);
        p.timers.posix.get_mut(&id).unwrap().pending = queued;
    }
    if fired {
        crate::sched::timer_changed();
    }
    fired
}

/// A timer's signal was taken (delivered, or dequeued by sigtimedwait or a
/// signalfd): count the periods that passed meanwhile as overruns and let
/// the timer re-arm. Returns whether its deadline must be programmed again.
pub fn delivered(p: &mut Process, info: &mut SigInfo) -> bool {
    let Some(id) = info.timer else { return false };
    crate::sched::deadlines_changed();
    let now = clock_of(p, id);
    let timers = &mut p.timers;
    match id {
        REAL_TIMER => {
            timers.real_pending = false;
            timers.real.expire(now); // the itimers have no overrun count
            true
        }
        id if CPU_ITIMERS.contains(&id) => {
            let i = if id == CPU_ITIMERS[0] { 0 } else { 1 };
            timers.cpu_pending[i] = false;
            timers.cpu_itimers[i].expire(now);
            true
        }
        id => {
            let Some(t) = timers.posix.get_mut(&id) else { return false };
            let missed = t.timing.expire(now);
            let overrun = ((info.fields[0] >> 32) + missed).min(i32::MAX as u64);
            info.fields[0] = id as u64 | overrun << 32;
            t.overrun = overrun as u32;
            t.pending = false;
            true
        }
    }
}

/// Signals were discarded (now ignored, or their thread exited): timers
/// whose signal is gone must re-arm.
pub fn resync(p: &mut Process) {
    crate::sched::deadlines_changed();
    let ids: Vec<u32> = p.timers.posix.iter().filter(|(_, t)| t.pending).map(|(&id, _)| id).collect();
    for id in ids {
        if signal::queued_timer_signal(p, id).is_none() {
            p.timers.posix.get_mut(&id).unwrap().pending = false;
            crate::sched::timer_changed();
        }
    }
    if p.timers.real_pending && signal::queued_timer_signal(p, REAL_TIMER).is_none() {
        p.timers.real_pending = false;
        crate::sched::timer_changed();
    }
    for (i, id) in CPU_ITIMERS.into_iter().enumerate() {
        if p.timers.cpu_pending[i] && signal::queued_timer_signal(p, id).is_none() {
            p.timers.cpu_pending[i] = false;
            crate::sched::timer_changed();
        }
    }
}
