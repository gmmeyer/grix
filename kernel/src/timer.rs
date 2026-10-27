//! Timers: setitimer(ITIMER_REAL), POSIX timers (timer_create) and
//! timerfds. Each has a monotonic deadline. The scheduler programs the CPU
//! timer for the earliest one (together with sleeping threads' deadlines)
//! and calls `fire` once it has passed: signal timers queue their signal,
//! timerfds count the expiration and wake I/O waiters.

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

    /// Time left until the next expiry: never 0 while armed (0 means disarmed).
    pub fn remaining(&self, now: u64) -> u64 {
        self.next.map_or(0, |n| n.saturating_sub(now).max(1))
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
    /// The overrun count of the last signal delivered (timer_getoverrun).
    pub overrun: u32,
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
    /// Catch up with the clock (expiries are counted lazily as well as by `fire`).
    pub fn update(&mut self, now: u64) -> u64 {
        let n = self.timing.expire(now);
        if n > 0 {
            self.expirations = self.expirations.saturating_add(n);
            self.version += 1;
        }
        n
    }
}

#[derive(Default)]
pub struct Timers {
    /// ITIMER_REAL: SIGALRM to the process.
    pub real: Interval,
    pub posix: BTreeMap<u32, PosixTimer>,
    pub next_id: u32,
    /// Every timerfd still open, so the scheduler wakes up for them.
    pub fds: Vec<Weak<Mutex<TimerFd>>>,
}

impl Timers {
    /// The earliest deadline of a timer that can wake someone up. SIGEV_NONE
    /// timers can't, so they don't keep an otherwise deadlocked program alive.
    pub fn next_deadline(&self) -> Option<u64> {
        let posix = self.posix.values().filter(|t| matches!(t.notify, Notify::Signal { .. }));
        let fds = self.fds.iter().filter_map(|w| w.upgrade()).filter_map(|t| t.lock().timing.next);
        [self.real.next].into_iter().chain(posix.map(|t| t.timing.next)).flatten().chain(fds).min()
    }

    pub fn add_fd(&mut self, fd: &Arc<Mutex<TimerFd>>) {
        self.fds.retain(|w| w.strong_count() > 0);
        self.fds.push(Arc::downgrade(fd));
    }
}

/// A timer's signal was taken (delivered or dequeued by sigtimedwait):
/// remember its overrun for timer_getoverrun.
pub fn delivered(timers: &mut Timers, info: &SigInfo) {
    if let Some(t) = info.timer.and_then(|id| timers.posix.get_mut(&id)) {
        t.overrun = (info.fields[0] >> 32) as u32;
    }
}

/// Handle every timer whose deadline has passed. Returns whether anything
/// happened (a signal was sent or a timerfd became readable).
pub fn fire(p: &mut Process) -> bool {
    let now = time::monotonic_ns();
    let mut fired = false;
    if p.timers.real.expire(now) > 0 {
        // Like Linux's it_real_fn: one SIGALRM however many periods passed.
        let mut info = SigInfo::sent(SIGALRM, SI_KERNEL, 0, "SIGALRM: the interval timer (alarm/setitimer) expired");
        info.fields = [0; 4]; // sent by the kernel: no pid or uid
        let _ = signal::send(p, Target::Process, info);
        fired = true;
    }
    let due: Vec<(u32, u64)> = p
        .timers
        .posix
        .iter_mut()
        .filter_map(|(&id, t)| Some((id, t.timing.expire(now))).filter(|&(_, n)| n > 0))
        .collect();
    for (id, n) in due {
        fired = true;
        let Notify::Signal { signo, value, thread } = p.timers.posix[&id].notify else { continue };
        let extra = (n - 1).min(i32::MAX as u64) as u32;
        // A signal for this timer that hasn't been taken yet absorbs the
        // expiry as an overrun, as on Linux.
        if let Some(queued) = signal::queued_timer_signal(p, id) {
            let overrun = ((queued.fields[0] >> 32) as u32).saturating_add(extra + 1).min(i32::MAX as u32);
            queued.fields[0] = id as u64 | (overrun as u64) << 32;
            continue;
        }
        let mut info = SigInfo::sent(signo, SI_TIMER, 0, "signal from a POSIX timer (timer_create)");
        info.fields = [id as u64 | (extra as u64) << 32, value, 0, 0];
        info.timer = Some(id);
        let target = match thread {
            Some(tid) if p.threads.contains_key(&tid) => Target::Thread(tid),
            _ => Target::Process,
        };
        let _ = signal::send(p, target, info);
    }
    p.timers.fds.retain(|w| w.strong_count() > 0);
    for fd in p.timers.fds.iter().filter_map(|w| w.upgrade()) {
        if fd.lock().update(now) > 0 {
            fired = true;
            ipc::changed();
        }
    }
    if fired {
        p.timer_dirty = true;
    }
    fired
}
