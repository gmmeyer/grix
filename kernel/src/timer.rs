//! Timers: setitimer(ITIMER_REAL), POSIX timers (timer_create) and
//! timerfds. Each has a monotonic deadline. The scheduler programs the CPU
//! timer for the earliest one (together with sleeping threads' deadlines)
//! and calls `fire` once it has passed: signal timers queue their signal,
//! timerfds count the expiration and wake I/O waiters.
//!
//! Like Linux, a timer only re-arms once its last expiry has been consumed:
//! while its signal is still queued, or its timerfd still readable, it drops
//! out of the deadlines, and the periods that pass meanwhile are counted
//! when the signal is taken (as overruns) or the fd read. So a 1 ns periodic
//! timer can't keep the CPU in the timer interrupt.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use spin::Mutex;

use crate::ipc;
use crate::process::Process;
use crate::signal::{self, SigInfo, Target};
use crate::time;

pub const SIGALRM: u32 = 14;
const SI_KERNEL: i32 = 0x80;
const SI_TIMER: i32 = -2;
/// timer_create's per-process limit (Linux's is RLIMIT_SIGPENDING-sized);
/// it bounds kernel memory.
pub const MAX_POSIX_TIMERS: usize = 1024;
/// `SigInfo::timer` for ITIMER_REAL's SIGALRM.
const REAL_TIMER: u32 = u32::MAX;
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

pub struct PosixTimer {
    pub timing: Interval,
    /// The clock absolute times (TIMER_ABSTIME) are on.
    pub clock: u64,
    pub notify: Notify,
    /// The overrun count of the last signal taken (timer_getoverrun).
    pub overrun: u32,
    /// Its signal is queued and hasn't been taken yet.
    pub pending: bool,
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
    pub posix: BTreeMap<u32, PosixTimer>,
    pub next_id: u32,
    /// Every timerfd still open, so the scheduler wakes up for them.
    pub fds: Vec<Weak<Mutex<TimerFd>>>,
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
            .filter(|t| !t.pending && matches!(t.notify, Notify::Signal { .. }))
            .filter_map(|t| t.timing.next);
        let fds = self.fds.iter().filter_map(|w| w.upgrade()).filter_map(|t| {
            let t = t.lock();
            t.timing.next.filter(|_| t.expirations == 0)
        });
        real.into_iter().chain(posix).chain(fds).min()
    }

    pub fn add_fd(&mut self, fd: &Arc<Mutex<TimerFd>>) {
        self.fds.retain(|w| w.strong_count() > 0);
        self.fds.push(Arc::downgrade(fd));
    }
}

/// Queue a timer's signal. Returns whether it was queued; an ignored one
/// backs its timer off to a minimum period instead.
fn send_timer_signal(p: &mut Process, target: Target, info: SigInfo, id: u32) -> bool {
    let _ = signal::send(p, target, info);
    if signal::queued_timer_signal(p, id).is_some() {
        return true;
    }
    let timing = if id == REAL_TIMER { &mut p.timers.real } else { &mut p.timers.posix.get_mut(&id).unwrap().timing };
    if let Some(next) = timing.next {
        timing.next = Some(next.max(time::monotonic_ns().saturating_add(IGNORED_MIN_PERIOD)));
    }
    false
}

/// Handle every timer whose deadline has passed. Returns whether anything
/// happened (a signal was sent or a timerfd became readable).
pub fn fire(p: &mut Process) -> bool {
    let now = time::monotonic_ns();
    let mut fired = false;
    if !p.timers.real_pending && p.timers.real.expire(now) > 0 {
        // Like Linux's it_real_fn: one SIGALRM however many periods passed.
        let mut info = SigInfo::sent(SIGALRM, SI_KERNEL, 0, "SIGALRM: the interval timer (alarm/setitimer) expired");
        info.fields = [0; 4]; // sent by the kernel: no pid or uid
        info.timer = Some(REAL_TIMER);
        p.timers.real_pending = send_timer_signal(p, Target::Process, info, REAL_TIMER);
        fired = true;
    }
    let due: Vec<(u32, u64)> = p
        .timers
        .posix
        .iter_mut()
        .filter(|(_, t)| !t.pending)
        .filter_map(|(&id, t)| Some((id, t.timing.expire(now))).filter(|&(_, n)| n > 0))
        .collect();
    for (id, n) in due {
        fired = true;
        let Notify::Signal { signo, value, thread } = p.timers.posix[&id].notify else { continue };
        let extra = (n - 1).min(i32::MAX as u64);
        let mut info = SigInfo::sent(signo, SI_TIMER, 0, "signal from a POSIX timer (timer_create)");
        info.fields = [id as u64 | extra << 32, value, 0, 0];
        info.timer = Some(id);
        let target = match thread {
            Some(tid) if p.threads.contains_key(&tid) => Target::Thread(tid),
            _ => Target::Process,
        };
        let queued = send_timer_signal(p, target, info, id);
        p.timers.posix.get_mut(&id).unwrap().pending = queued;
    }
    p.timers.fds.retain(|w| w.strong_count() > 0);
    for fd in p.timers.fds.iter().filter_map(|w| w.upgrade()) {
        let mut t = fd.lock();
        if t.expirations == 0 && t.update(now) > 0 {
            fired = true;
        }
    }
    if fired {
        p.timer_dirty = true;
    }
    fired
}

/// A timer's signal was taken (delivered, or dequeued by sigtimedwait or a
/// signalfd): count the periods that passed meanwhile as overruns and let
/// the timer re-arm. Returns whether its deadline must be programmed again.
pub fn delivered(timers: &mut Timers, info: &mut SigInfo) -> bool {
    let now = time::monotonic_ns();
    match info.timer {
        Some(REAL_TIMER) => {
            timers.real_pending = false;
            timers.real.expire(now); // ITIMER_REAL has no overrun count
            true
        }
        Some(id) => {
            let Some(t) = timers.posix.get_mut(&id) else { return false };
            let missed = t.timing.expire(now);
            let overrun = ((info.fields[0] >> 32) + missed).min(i32::MAX as u64);
            info.fields[0] = id as u64 | overrun << 32;
            t.overrun = overrun as u32;
            t.pending = false;
            true
        }
        None => false,
    }
}

/// Signals were discarded (now ignored, or their thread exited): timers
/// whose signal is gone must re-arm.
pub fn resync(p: &mut Process) {
    let ids: Vec<u32> = p.timers.posix.iter().filter(|(_, t)| t.pending).map(|(&id, _)| id).collect();
    for id in ids {
        if signal::queued_timer_signal(p, id).is_none() {
            p.timers.posix.get_mut(&id).unwrap().pending = false;
            p.timer_dirty = true;
        }
    }
    if p.timers.real_pending && signal::queued_timer_signal(p, REAL_TIMER).is_none() {
        p.timers.real_pending = false;
        p.timer_dirty = true;
    }
}
