//! Timer syscalls: setitimer/getitimer, timer_create & co, timerfd_*.
//! The timers themselves live in `crate::timer`.

use alloc::sync::Arc;
use spin::Mutex;

use super::table::nr;
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, O_NONBLOCK, O_RDONLY, new_file};
use crate::process::Process;
use crate::time;
use crate::timer::{Interval, MAX_POSIX_TIMERS, Notify, PosixTimer, SIGALRM, TimerFd};
use crate::uaccess::*;

const NS: u64 = 1_000_000_000;
const TIMER_ABSTIME: u64 = 1;

/// The clocks timers can run on. CPU-time clocks aren't tracked (the
/// CPU-time clocks report wall time), so their timers are unimplemented.
fn clock_ok(p: &mut Process, n: u32, clock: u64) -> Result<(), Errno> {
    match clock as i32 {
        0 | 1 | 7 | 11 => Ok(()), // REALTIME, MONOTONIC, BOOTTIME, TAI
        8 | 9 => Err(EPERM),      // *_ALARM: need CAP_WAKE_ALARM
        2 | 3 => {
            let (name, _) = super::table::info(n);
            p.unimplemented(n, name, "CPU-time clock timers", EINVAL).map(|_| ())
        }
        _ => Err(EINVAL),
    }
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

fn write_itimerspec(p: &mut Process, ptr: u64, t: &Interval) -> Result<(), Errno> {
    write_timespec(&mut p.aspace, ptr, t.period)?;
    write_timespec(&mut p.aspace, ptr + 16, t.remaining(time::monotonic_ns()))
}

/// Arm (or, with a zero value, disarm) a timer from an itimerspec.
fn arm(clock: u64, flags: u64, interval: u64, value: u64) -> Interval {
    if value == 0 {
        return Interval::default();
    }
    let next = if flags & TIMER_ABSTIME != 0 {
        absolute_to_monotonic(clock, value)
    } else {
        time::monotonic_ns().saturating_add(value)
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

fn write_itimerval(p: &mut Process, ptr: u64, t: &Interval) -> Result<(), Errno> {
    // Round up, as Linux does, so an armed timer never reads as disarmed.
    let us = |ns: u64| ns.div_ceil(1000);
    let mut b = [0u8; 32];
    for (i, ns) in [t.period, t.remaining(time::monotonic_ns())].into_iter().enumerate() {
        b[i * 16..i * 16 + 8].copy_from_slice(&(us(ns) / 1_000_000).to_le_bytes());
        b[i * 16 + 8..i * 16 + 16].copy_from_slice(&(us(ns) % 1_000_000).to_le_bytes());
    }
    copy_out(&mut p.aspace, ptr, &b)
}

/// ITIMER_REAL only: the virtual and profiling timers count CPU time, which isn't tracked.
fn real_only(p: &mut Process, n: u32, which: u64) -> Result<(), Errno> {
    match which {
        0 => Ok(()),
        1 | 2 => {
            let (name, _) = super::table::info(n);
            p.unimplemented(n, name, "ITIMER_VIRTUAL/ITIMER_PROF (CPU-time timers)", EINVAL).map(|_| ())
        }
        _ => Err(EINVAL),
    }
}

pub fn getitimer(p: &mut Process, which: u64, curr: u64) -> SysResult {
    real_only(p, nr::getitimer, which)?;
    let t = p.timers.real;
    write_itimerval(p, curr, &t).map(|_| 0)
}

pub fn setitimer(p: &mut Process, which: u64, new: u64, old: u64) -> SysResult {
    real_only(p, nr::setitimer, which)?;
    // A NULL new value disarms (an old Linux quirk that alarm(0) relies on).
    let (interval, value) = if new == 0 { (0, 0) } else { (read_timeval_ns(p, new)?, read_timeval_ns(p, new + 16)?) };
    let prev = p.timers.real;
    if old != 0 {
        write_itimerval(p, old, &prev)?;
    }
    p.timers.real = arm(1, 0, interval, value);
    p.timer_dirty = true;
    Ok(0)
}

// ---------------------------------------------------------------- POSIX timers

pub fn timer_create(p: &mut Process, clock: u64, sevp: u64, idp: u64) -> SysResult {
    const SIGEV_SIGNAL: u32 = 0;
    const SIGEV_NONE: u32 = 1;
    const SIGEV_THREAD_ID: u32 = 4;
    clock_ok(p, nr::timer_create, clock)?;
    if p.timers.posix.len() >= MAX_POSIX_TIMERS {
        return Err(EAGAIN);
    }
    let id = p.timers.next_id;
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
    p.timers.posix.insert(id, PosixTimer { timing: Interval::default(), notify, overrun: 0, clock, pending: false });
    Ok(0)
}

fn posix_timer(p: &mut Process, id: u64) -> Result<&mut PosixTimer, Errno> {
    u32::try_from(id).ok().and_then(|id| p.timers.posix.get_mut(&id)).ok_or(EINVAL)
}

pub fn timer_settime(p: &mut Process, id: u64, flags: u64, new: u64, old: u64) -> SysResult {
    posix_timer(p, id)?;
    let (interval, value) = read_itimerspec(p, new)?;
    let t = posix_timer(p, id)?;
    let prev = t.timing;
    t.timing = arm(t.clock, flags, interval, value);
    t.overrun = 0;
    p.timer_dirty = true;
    if old != 0 {
        write_itimerspec(p, old, &prev)?;
    }
    Ok(0)
}

pub fn timer_gettime(p: &mut Process, id: u64, curr: u64) -> SysResult {
    let t = posix_timer(p, id)?.timing;
    write_itimerspec(p, curr, &t).map(|_| 0)
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
    clock_ok(p, nr::timerfd_create, clock)?;
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
        t.timing = arm(t.clock, flags, interval, value);
        t.expirations = 0;
        t.version += 1;
        prev
    };
    p.timer_dirty = true;
    crate::ipc::changed();
    if old != 0 {
        write_itimerspec(p, old, &prev)?;
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
    write_itimerspec(p, curr, &t).map(|_| 0)
}
