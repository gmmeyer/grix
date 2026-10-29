//! Timer syscalls: setitimer/getitimer, timer_create & co, timerfd_*.
//! The timers themselves live in `crate::timer`.

use alloc::sync::Arc;
use spin::Mutex;

use super::table::nr;
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, O_NONBLOCK, O_RDONLY, new_file};
use crate::process::Process;
use crate::time;
use crate::timer::{CpuClock, Interval, MAX_POSIX_TIMERS, MAX_TIMER_ID, Notify, PosixTimer, SIGALRM, TimerFd};
use crate::uaccess::*;

const NS: u64 = 1_000_000_000;
const TIMER_ABSTIME: u64 = 1;

/// The clocks timers can run on: wall-clock ones (None) and, for POSIX
/// timers, the CPU time of the process or one of its threads.
fn timer_clock(p: &mut Process, n: u32, clock: u64, cpu_ok: bool) -> Result<Option<CpuClock>, Errno> {
    let cpu = match clock as i32 {
        0 | 1 | 7 | 11 => return Ok(None), // REALTIME, MONOTONIC, BOOTTIME, TAI
        8 | 9 => return Err(EPERM),        // *_ALARM: need CAP_WAKE_ALARM
        2 => CpuClock::Process,            // PROCESS_CPUTIME_ID
        3 => CpuClock::Thread(p.current),  // THREAD_CPUTIME_ID
        // clock_getcpuclockid/pthread_getcpuclockid: ~id << 3, bit 2 for a
        // thread, and the kind of CPU time in the low bits (3 isn't one).
        c if c < 0 && c & 3 != 3 => {
            let id = !(c >> 3) as u32;
            if c & 4 != 0 {
                let tid = if id == 0 { p.current } else { id };
                if !p.threads.contains_key(&tid) {
                    return Err(EINVAL);
                }
                CpuClock::Thread(tid)
            } else if id == 0 || id == p.pid {
                CpuClock::Process
            } else {
                let (name, _) = super::table::info(n);
                return p.unimplemented(n, name, "timers on another process's CPU-time clock", EINVAL).map(|_| None);
            }
        }
        _ => return Err(EINVAL),
    };
    // timerfds only run on wall clocks, as on Linux.
    if cpu_ok { Ok(Some(cpu)) } else { Err(EINVAL) }
}

/// An absolute time on `clock` as a monotonic deadline.
fn absolute_to_monotonic(clock: u64, t: u64) -> u64 {
    match clock {
        0 | 11 => time::realtime_to_monotonic(t),
        _ => t,
    }
}

/// Read a `struct itimerspec { it_interval, it_value }` (two timespecs).
fn read_itimerspec(p: &mut Process, ptr: u64) -> Result<(u64, u64), Errno> {
    let interval = read_timespec_ns(&mut p.aspace, ptr)?;
    let value = read_timespec_ns(&mut p.aspace, ptr + 16)?;
    Ok((interval, value))
}

/// `now` is the time on the timer's clock.
fn write_itimerspec(p: &mut Process, ptr: u64, t: &Interval, now: u64) -> Result<(), Errno> {
    write_timespec(&mut p.aspace, ptr, t.period)?;
    write_timespec(&mut p.aspace, ptr + 16, t.remaining(now))
}

/// The time a timer runs on: its CPU-time clock's, or the monotonic one.
fn timer_now(p: &Process, cpu: Option<CpuClock>) -> u64 {
    cpu.map_or_else(time::monotonic_ns, |c| c.now(p).unwrap_or(0))
}

/// Arm (or, with a zero value, disarm) a timer from an itimerspec.
fn arm(p: &Process, clock: u64, cpu: Option<CpuClock>, flags: u64, interval: u64, value: u64) -> Interval {
    if value == 0 {
        return Interval::default();
    }
    let next = match (flags & TIMER_ABSTIME != 0, cpu) {
        (true, Some(_)) => value,
        (true, None) => absolute_to_monotonic(clock, value),
        (false, cpu) => timer_now(p, cpu).saturating_add(value),
    };
    Interval { next: Some(next), period: interval }
}

// ---------------------------------------------------------------- setitimer

/// Read a `struct timeval` (seconds, microseconds) as nanoseconds.
fn read_timeval_ns(p: &mut Process, ptr: u64) -> Result<u64, Errno> {
    let sec = read_u64(&mut p.aspace, ptr)? as i64;
    let usec = read_u64(&mut p.aspace, ptr + 8)? as i64;
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return Err(EINVAL);
    }
    Ok((sec as u64).saturating_mul(NS).saturating_add(usec as u64 * 1000))
}

fn write_itimerval(p: &mut Process, ptr: u64, t: &Interval, now: u64) -> Result<(), Errno> {
    // Round up, as Linux does, so an armed timer never reads as disarmed.
    let us = |ns: u64| ns.div_ceil(1000);
    let mut b = [0u8; 32];
    for (i, ns) in [t.period, t.remaining(now)].into_iter().enumerate() {
        b[i * 16..i * 16 + 8].copy_from_slice(&(us(ns) / 1_000_000).to_le_bytes());
        b[i * 16 + 8..i * 16 + 16].copy_from_slice(&(us(ns) % 1_000_000).to_le_bytes());
    }
    copy_out(&mut p.aspace, ptr, &b)
}

/// ITIMER_REAL (wall time), ITIMER_VIRTUAL or ITIMER_PROF (the process's
/// CPU time, which is all user time here, so the two run alike), and the
/// time on its clock.
fn itimer(p: &mut Process, which: u64) -> Result<(&mut Interval, Option<CpuClock>), Errno> {
    match which {
        0 => Ok((&mut p.timers.real, None)),
        1 | 2 => Ok((&mut p.timers.cpu_itimers[which as usize - 1], Some(CpuClock::Process))),
        _ => Err(EINVAL),
    }
}

pub fn getitimer(p: &mut Process, which: u64, curr: u64) -> SysResult {
    let (t, cpu) = itimer(p, which)?;
    let t = *t;
    let now = timer_now(p, cpu);
    write_itimerval(p, curr, &t, now).map(|_| 0)
}

pub fn setitimer(p: &mut Process, which: u64, new: u64, old: u64) -> SysResult {
    let cpu = itimer(p, which)?.1;
    // A NULL new value disarms (an old Linux quirk that alarm(0) relies on).
    let (interval, value) = if new == 0 { (0, 0) } else { (read_timeval_ns(p, new)?, read_timeval_ns(p, new + 16)?) };
    let prev = *itimer(p, which)?.0;
    if old != 0 {
        let now = timer_now(p, cpu);
        write_itimerval(p, old, &prev, now)?;
    }
    let timing = arm(p, 1, cpu, 0, interval, value);
    *itimer(p, which)?.0 = timing;
    p.timer_dirty = true;
    Ok(0)
}

/// alarm (x86_64's): ITIMER_REAL in `secs` seconds (0 disarms it); the
/// seconds the last one had left, rounded as Linux does (and 1 for any
/// less than half a second).
#[cfg(target_arch = "x86_64")]
pub fn alarm(p: &mut Process, secs: u64) -> SysResult {
    let left = p.timers.real.remaining(time::monotonic_ns());
    let old = match (left / 1_000_000_000, left % 1_000_000_000) {
        (s, ns) if ns >= 500_000_000 => s + 1,
        (0, ns) if ns > 0 => 1,
        (s, _) => s,
    };
    let timing = arm(p, 1, None, 0, 0, secs.saturating_mul(1_000_000_000));
    p.timers.real = timing;
    p.timer_dirty = true;
    Ok(old)
}

// ---------------------------------------------------------------- POSIX timers

pub fn timer_create(p: &mut Process, clock: u64, sevp: u64, idp: u64) -> SysResult {
    const SIGEV_SIGNAL: u32 = 0;
    const SIGEV_NONE: u32 = 1;
    const SIGEV_THREAD_ID: u32 = 4;
    let cpu = timer_clock(p, nr::timer_create, clock, true)?;
    if p.timers.posix.len() >= MAX_POSIX_TIMERS {
        crate::stats::hit(grix_abi::stats::Limit::Timers);
        return Err(EAGAIN);
    }
    // The next id not in use (ids wrap, below the itimers' own).
    let mut id = p.timers.next_id;
    while p.timers.posix.contains_key(&id) || id > MAX_TIMER_ID {
        id = if id >= MAX_TIMER_ID { 0 } else { id + 1 };
    }
    // struct sigevent: sigev_value, sigev_signo, sigev_notify, then the tid.
    let notify = if sevp == 0 {
        Notify::Signal { signo: SIGALRM, value: id as u64, thread: None }
    } else {
        let value = read_u64(&mut p.aspace, sevp)?;
        let signo = read_u32(&mut p.aspace, sevp + 8)?;
        let how = read_u32(&mut p.aspace, sevp + 12)?;
        let tid = read_u32(&mut p.aspace, sevp + 16)?;
        let valid_signo = (1..=crate::signal::NSIG).contains(&signo);
        match how {
            SIGEV_NONE => Notify::None,
            SIGEV_SIGNAL if valid_signo => Notify::Signal { signo, value, thread: None },
            SIGEV_THREAD_ID if valid_signo && p.threads.contains_key(&tid) => {
                Notify::Signal { signo, value, thread: Some(tid) }
            }
            // SIGEV_THREAD is done by libc (with SIGEV_THREAD_ID).
            _ => return Err(EINVAL),
        }
    };
    write_u32(&mut p.aspace, idp, id)?;
    p.timers.next_id = id.wrapping_add(1);
    let timer = PosixTimer { timing: Interval::default(), notify, overrun: 0, clock, cpu, pending: false };
    p.timers.posix.insert(id, timer);
    Ok(0)
}

fn posix_timer(p: &mut Process, id: u64) -> Result<&mut PosixTimer, Errno> {
    u32::try_from(id).ok().and_then(|id| p.timers.posix.get_mut(&id)).ok_or(EINVAL)
}

pub fn timer_settime(p: &mut Process, id: u64, flags: u64, new: u64, old: u64) -> SysResult {
    let (clock, cpu) = {
        let t = posix_timer(p, id)?;
        (t.clock, t.cpu)
    };
    let (interval, value) = read_itimerspec(p, new)?;
    let now = timer_now(p, cpu);
    let timing = arm(p, clock, cpu, flags, interval, value);
    let t = posix_timer(p, id)?;
    let prev = t.timing;
    t.timing = timing;
    t.overrun = 0;
    p.timer_dirty = true;
    // A CPU-time timer set to a time already passed fires now, its signal
    // delivered as this call returns (Linux's posix_cpu_timer_set), not
    // at the next timer interrupt, which may come a little later.
    if cpu.is_some() && timing.next.is_some_and(|next| next <= now) {
        crate::timer::fire(p);
    }
    if old != 0 {
        write_itimerspec(p, old, &prev, now)?;
    }
    Ok(0)
}

pub fn timer_gettime(p: &mut Process, id: u64, curr: u64) -> SysResult {
    let t = posix_timer(p, id)?;
    let (timing, cpu) = (t.timing, t.cpu);
    let now = timer_now(p, cpu);
    write_itimerspec(p, curr, &timing, now).map(|_| 0)
}

pub fn timer_getoverrun(p: &mut Process, id: u64) -> SysResult {
    Ok(posix_timer(p, id)?.overrun as u64)
}

pub fn timer_delete(p: &mut Process, id: u64) -> SysResult {
    let id = u32::try_from(id).map_err(|_| EINVAL)?;
    p.timers.posix.remove(&id).ok_or(EINVAL)?;
    p.timer_dirty = true;
    Ok(0)
}

// ---------------------------------------------------------------- timerfd

pub fn timerfd_create(p: &mut Process, clock: u64, flags: u64) -> SysResult {
    const TFD_CLOEXEC: u64 = 0o2000000;
    const TFD_NONBLOCK: u64 = 0o4000;
    if flags & !(TFD_CLOEXEC | TFD_NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    timer_clock(p, nr::timerfd_create, clock, false)?;
    let tfd = Arc::new(Mutex::new(TimerFd { clock, ..TimerFd::default() }));
    p.timers.add_fd(&tfd);
    let file = new_file(FileKind::TimerFd(tfd), O_RDONLY | (flags as u32 & O_NONBLOCK));
    p.fds.alloc(FdEntry { file, cloexec: flags & TFD_CLOEXEC != 0 }, 0)
}

fn timerfd_of(p: &Process, fd: u64) -> Result<Arc<Mutex<TimerFd>>, Errno> {
    match &p.fds.get(fd)?.lock().kind {
        FileKind::TimerFd(t) => Ok(t.clone()),
        _ => Err(EINVAL),
    }
}

pub fn timerfd_settime(p: &mut Process, fd: u64, flags: u64, new: u64, old: u64) -> SysResult {
    const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
    if flags & !(TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
        return Err(EINVAL);
    }
    let tfd = timerfd_of(p, fd)?;
    let (interval, value) = read_itimerspec(p, new)?;
    let prev = {
        let mut t = tfd.lock();
        let prev = t.timing;
        // The clock is never set inside the sandbox, so CANCEL_ON_SET never fires.
        t.timing = arm(p, t.clock, None, flags, interval, value);
        t.expirations = 0;
        t.version += 1;
        prev
    };
    p.timer_dirty = true;
    crate::ipc::changed();
    if old != 0 {
        write_itimerspec(p, old, &prev, time::monotonic_ns())?;
    }
    Ok(0)
}

pub fn timerfd_gettime(p: &mut Process, fd: u64, curr: u64) -> SysResult {
    let tfd = timerfd_of(p, fd)?;
    let t = {
        let mut t = tfd.lock();
        t.update(time::monotonic_ns());
        t.timing
    };
    write_itimerspec(p, curr, &t, time::monotonic_ns()).map(|_| 0)
}
