//! Time, identity, limits, signals, futex and the remaining small syscalls.

use grix_abi::policy::Capability;

use super::{require, table::nr};
use crate::errno::*;
use crate::mm::frame;
use crate::process::{self, PID, Process, SigAction};
use crate::uaccess::*;
use crate::{rng, time};

const CLONE_THREAD: u64 = 0x10000;

/// Threads and processes are gated now and implemented later.
pub fn clone(p: &mut Process, n: u32, flags: u64) -> SysResult {
    let (cap, what) = if flags & CLONE_THREAD != 0 {
        (Capability::Threads, "threads")
    } else {
        (Capability::Process, "child processes")
    };
    require(p, n, cap, "")?;
    let (name, _) = super::table::info(n);
    p.unimplemented(n, name, what, ENOSYS)
}

#[allow(non_upper_case_globals)]
pub fn dispatch(p: &mut Process, n: u32, name: &str, a: [u64; 6]) -> SysResult {
    match n {
        nr::set_tid_address => Ok(PID),
        nr::set_robust_list => Ok(0),
        nr::uname => uname(p, a[0]),
        nr::clock_gettime => clock_gettime(p, a[0], a[1]),
        nr::clock_getres => {
            if a[1] != 0 {
                write_timespec(&mut p.aspace, a[1], 1)?;
            }
            Ok(0)
        }
        nr::gettimeofday => {
            if a[0] != 0 {
                let now = time::realtime_ns();
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&(now / 1_000_000_000).to_le_bytes());
                b[8..].copy_from_slice(&((now % 1_000_000_000) / 1000).to_le_bytes());
                copy_out(&mut p.aspace, a[0], &b)?;
            }
            if a[1] != 0 {
                zero_out(&mut p.aspace, a[1], 8)?;
            }
            Ok(0)
        }
        nr::nanosleep => {
            let ns = read_timespec_ns(&mut p.aspace, a[0])?;
            time::sleep_ns(ns);
            Ok(0)
        }
        nr::clock_nanosleep => {
            const TIMER_ABSTIME: u64 = 1;
            let ns = read_timespec_ns(&mut p.aspace, a[2])?;
            if a[1] & TIMER_ABSTIME != 0 {
                let now = clock_now(a[0]).ok_or(EINVAL)?;
                time::sleep_ns(ns.saturating_sub(now));
            } else {
                time::sleep_ns(ns);
            }
            Ok(0)
        }
        nr::getrandom => {
            let len = a[1].min(32 << 20);
            let mut chunk = [0u8; 256];
            let mut done = 0;
            while done < len {
                let k = (len - done).min(256) as usize;
                rng::fill(&mut chunk[..k]);
                copy_out(&mut p.aspace, a[0] + done, &chunk[..k])?;
                done += k as u64;
            }
            Ok(len)
        }
        nr::getpid | nr::gettid | nr::getpgid | nr::getsid => Ok(PID),
        nr::getppid => Ok(0),
        nr::getuid | nr::geteuid => Ok(p.uid as u64),
        nr::getgid | nr::getegid => Ok(p.gid as u64),
        nr::getresuid | nr::getresgid => {
            let id = if n == nr::getresuid { p.uid } else { p.gid };
            for ptr in &a[..3] {
                write_u32(&mut p.aspace, *ptr, id)?;
            }
            Ok(0)
        }
        nr::getgroups => Ok(0),
        nr::setuid | nr::setreuid | nr::setresuid | nr::setgid | nr::setregid | nr::setresgid => set_ids(p, n, name, a),
        nr::umask => {
            let old = p.umask;
            p.umask = a[0] as u32 & 0o777;
            Ok(old as u64)
        }
        nr::prctl => prctl(p, a),
        nr::getrlimit => prlimit(p, 0, a[0], 0, a[1]),
        nr::setrlimit => prlimit(p, 0, a[0], a[1], 0),
        nr::prlimit64 => prlimit(p, a[0], a[1], a[2], a[3]),
        nr::getrusage => {
            let mut b = [0u8; 144];
            let now = time::monotonic_ns();
            b[..8].copy_from_slice(&(now / 1_000_000_000).to_le_bytes());
            b[8..16].copy_from_slice(&((now % 1_000_000_000) / 1000).to_le_bytes());
            let (_, used) = frame::stats();
            b[32..40].copy_from_slice(&(used * 4).to_le_bytes()); // ru_maxrss in KiB
            copy_out(&mut p.aspace, a[1], &b).map(|_| 0)
        }
        nr::sysinfo => sysinfo(p, a[0]),
        nr::times => {
            let ticks = time::monotonic_ns() / 10_000_000;
            if a[0] != 0 {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&ticks.to_le_bytes());
                copy_out(&mut p.aspace, a[0], &b)?;
            }
            Ok(ticks)
        }
        nr::sched_getaffinity => {
            if a[1] < 8 {
                return Err(EINVAL);
            }
            write_u64(&mut p.aspace, a[2], 1)?;
            Ok(8)
        }
        nr::sched_setaffinity | nr::sched_yield | nr::sched_setparam | nr::sched_setscheduler => Ok(0),
        nr::sched_getscheduler => Ok(0),
        nr::sched_getparam => write_u32(&mut p.aspace, a[1], 0).map(|_| 0),
        nr::getpriority => Ok(20),
        nr::setpriority => Ok(0),
        nr::getcpu => {
            for ptr in &a[..2] {
                if *ptr != 0 {
                    write_u32(&mut p.aspace, *ptr, 0)?;
                }
            }
            Ok(0)
        }
        nr::personality => Ok(0),
        nr::capget => {
            if a[1] != 0 {
                zero_out(&mut p.aspace, a[1], 24)?;
            }
            Ok(0)
        }
        nr::membarrier => {
            if a[0] == 0 {
                Ok(0)
            } else {
                Err(EINVAL)
            }
        }
        // glibc probes rseq and copes with ENOSYS; not worth reporting.
        nr::rseq => Err(ENOSYS),

        // signals
        nr::rt_sigaction => rt_sigaction(p, a[0], a[1], a[2], a[3]),
        nr::rt_sigprocmask => rt_sigprocmask(p, a[0], a[1], a[2], a[3]),
        nr::rt_sigpending => write_u64(&mut p.aspace, a[0], p.sigpending).map(|_| 0),
        nr::sigaltstack => {
            if a[1] != 0 {
                let [sp, flags, size] = p.altstack;
                let mut b = [0u8; 24];
                b[..8].copy_from_slice(&sp.to_le_bytes());
                b[8..12].copy_from_slice(&(flags as u32).to_le_bytes());
                b[16..].copy_from_slice(&size.to_le_bytes());
                copy_out(&mut p.aspace, a[1], &b)?;
            }
            if a[0] != 0 {
                let sp = read_u64(&mut p.aspace, a[0])?;
                let flags = read_u32(&mut p.aspace, a[0] + 8)? as u64;
                let size = read_u64(&mut p.aspace, a[0] + 16)?;
                p.altstack = [sp, flags, size];
            }
            Ok(0)
        }
        nr::kill | nr::tkill => send_signal(p, a[0], a[1]),
        nr::tgkill => send_signal(p, a[1], a[2]),

        nr::futex => futex(p, a),

        _ => p.unimplemented(n, name, "", ENOSYS),
    }
}

fn clock_now(clock: u64) -> Option<u64> {
    match clock as i64 {
        0 | 5 | 11 => Some(time::realtime_ns()), // REALTIME, REALTIME_COARSE, TAI
        1 | 4 | 6 | 7 | 2 | 3 => Some(time::monotonic_ns()), // MONOTONIC*, BOOTTIME, CPUTIME
        c if c < 0 => Some(time::monotonic_ns()), // per-process/thread CPU clocks
        _ => None,
    }
}

fn clock_gettime(p: &mut Process, clock: u64, tp: u64) -> SysResult {
    let ns = clock_now(clock).ok_or(EINVAL)?;
    write_timespec(&mut p.aspace, tp, ns).map(|_| 0)
}

fn uname(p: &mut Process, buf: u64) -> SysResult {
    let mut b = [0u8; 65 * 6];
    let fields = ["Linux", "grix", "6.1.0-grix", "#1 SMP grix", "aarch64", "(none)"];
    for (i, f) in fields.iter().enumerate() {
        b[i * 65..i * 65 + f.len()].copy_from_slice(f.as_bytes());
    }
    copy_out(&mut p.aspace, buf, &b).map(|_| 0)
}

fn sysinfo(p: &mut Process, buf: u64) -> SysResult {
    let (total, used) = frame::stats();
    let ram = total * 4096;
    let free = (total - used) * 4096;
    let mut b = [0u8; 112];
    b[..8].copy_from_slice(&(time::monotonic_ns() / 1_000_000_000).to_le_bytes());
    b[32..40].copy_from_slice(&ram.to_le_bytes());
    b[40..48].copy_from_slice(&free.to_le_bytes());
    b[80..82].copy_from_slice(&1u16.to_le_bytes()); // procs
    b[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
    copy_out(&mut p.aspace, buf, &b).map(|_| 0)
}

/// An unprivileged process may only "change" its ids to the ones it already
/// has (programs do this to drop privileges); anything else is EPERM.
fn set_ids(p: &mut Process, n: u32, name: &str, a: [u64; 6]) -> SysResult {
    let (current, count) = match n {
        nr::setuid => (p.uid, 1),
        nr::setreuid => (p.uid, 2),
        nr::setresuid => (p.uid, 3),
        nr::setgid => (p.gid, 1),
        nr::setregid => (p.gid, 2),
        _ => (p.gid, 3),
    };
    let keep = |id: u64| id as u32 == current || (count > 1 && id as u32 == u32::MAX);
    if a[..count].iter().all(|&id| keep(id)) {
        return Ok(0);
    }
    p.deny(n, name, "privileged", "changing user or group id")
}

fn prctl(p: &mut Process, a: [u64; 6]) -> SysResult {
    const PR_SET_PDEATHSIG: u64 = 1;
    const PR_GET_DUMPABLE: u64 = 3;
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    const PR_CAPBSET_READ: u64 = 23;
    const PR_SET_TIMERSLACK: u64 = 29;
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_GET_NO_NEW_PRIVS: u64 = 39;
    const PR_SET_VMA: u64 = 0x53564d41;
    match a[0] {
        PR_SET_NAME => {
            let mut name = [0u8; 16];
            let s = read_cstr(&mut p.aspace, a[1], 4096).unwrap_or_default();
            let n = s.len().min(15);
            name[..n].copy_from_slice(&s.as_bytes()[..n]);
            p.name = name;
            Ok(0)
        }
        PR_GET_NAME => {
            let name = p.name;
            copy_out(&mut p.aspace, a[1], &name).map(|_| 0)
        }
        PR_GET_DUMPABLE | PR_GET_NO_NEW_PRIVS => Ok(1),
        PR_SET_PDEATHSIG | PR_SET_DUMPABLE | PR_SET_TIMERSLACK | PR_SET_NO_NEW_PRIVS | PR_SET_VMA => Ok(0),
        PR_CAPBSET_READ => Ok(0),
        _ => Err(EINVAL),
    }
}

fn prlimit(p: &mut Process, pid: u64, res: u64, new: u64, old: u64) -> SysResult {
    if pid != 0 && pid != PID {
        return Err(ESRCH);
    }
    let i = usize::try_from(res).ok().filter(|&i| i < p.rlimits.len()).ok_or(EINVAL)?;
    if old != 0 {
        let (cur, max) = p.rlimits[i];
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&cur.to_le_bytes());
        b[8..].copy_from_slice(&max.to_le_bytes());
        copy_out(&mut p.aspace, old, &b)?;
    }
    if new != 0 {
        let cur = read_u64(&mut p.aspace, new)?;
        let max = read_u64(&mut p.aspace, new + 8)?;
        let (_, hard) = p.rlimits[i];
        if cur > max || max > hard {
            return Err(if cur > max { EINVAL } else { EPERM });
        }
        p.rlimits[i] = (cur, max);
    }
    Ok(0)
}

// ---------------------------------------------------------------- signals

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIGKILL: u64 = 9;
const SIGSTOP: u64 = 19;
/// Signals whose default action is to do nothing (CHLD, CONT, STOP, TSTP, TTIN, TTOU, URG, WINCH).
const DEFAULT_IGNORED: u64 = 1 << 17 | 1 << 18 | 1 << 19 | 1 << 20 | 1 << 21 | 1 << 22 | 1 << 23 | 1 << 28;

fn bit(sig: u64) -> u64 {
    1 << (sig - 1)
}

fn rt_sigaction(p: &mut Process, sig: u64, act: u64, oact: u64, size: u64) -> SysResult {
    if size != 8 || !(1..=64).contains(&sig) {
        return Err(EINVAL);
    }
    if oact != 0 {
        let o = p.sigactions[sig as usize];
        let mut b = [0u8; 32];
        for (i, v) in [o.handler, o.flags, o.restorer, o.mask].iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        copy_out(&mut p.aspace, oact, &b)?;
    }
    if act != 0 {
        if sig == SIGKILL || sig == SIGSTOP {
            return Err(EINVAL);
        }
        let mut b = [0u8; 32];
        copy_in(&mut p.aspace, act, &mut b)?;
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        p.sigactions[sig as usize] = SigAction { handler: w(0), flags: w(1), restorer: w(2), mask: w(3) };
    }
    Ok(0)
}

fn rt_sigprocmask(p: &mut Process, how: u64, set: u64, oset: u64, size: u64) -> SysResult {
    if size != 8 {
        return Err(EINVAL);
    }
    if oset != 0 {
        write_u64(&mut p.aspace, oset, p.sigmask)?;
    }
    if set != 0 {
        let s = read_u64(&mut p.aspace, set)? & !(bit(SIGKILL) | bit(SIGSTOP));
        p.sigmask = match how {
            0 => p.sigmask | s,
            1 => p.sigmask & !s,
            2 => s,
            _ => return Err(EINVAL),
        };
        let deliverable = p.sigpending & !p.sigmask;
        if deliverable != 0 {
            let sig = deliverable.trailing_zeros() as u64 + 1;
            p.sigpending &= !bit(sig);
            return deliver(p, sig);
        }
    }
    Ok(0)
}

fn send_signal(p: &mut Process, target: u64, sig: u64) -> SysResult {
    if target != PID && target != 0 && target as i64 != -1 {
        return Err(ESRCH);
    }
    if sig > 64 {
        return Err(EINVAL);
    }
    if sig == 0 {
        return Ok(0);
    }
    if p.sigmask & bit(sig) != 0 {
        p.sigpending |= bit(sig);
        return Ok(0);
    }
    deliver(p, sig)
}

fn deliver(p: &mut Process, sig: u64) -> SysResult {
    let handler = p.sigactions[sig as usize].handler;
    match handler {
        SIG_IGN if sig != SIGKILL => Ok(0),
        SIG_DFL if DEFAULT_IGNORED & bit(sig) != 0 => Ok(0),
        SIG_DFL | SIG_IGN => process::exit_signaled(sig as u32, 0, 0, "signal sent by the program itself"),
        _ => {
            let _ = p.unimplemented(nr::rt_sigaction, "rt_sigaction", "delivering signals to handlers", ENOSYS);
            process::exit_signaled(sig as u32, 0, 0, "signal handlers are not supported yet")
        }
    }
}

// ---------------------------------------------------------------- futex

fn futex(p: &mut Process, a: [u64; 6]) -> SysResult {
    const WAIT: u64 = 0;
    const WAKE: u64 = 1;
    const REQUEUE: u64 = 3;
    const CMP_REQUEUE: u64 = 4;
    const WAIT_BITSET: u64 = 9;
    const WAKE_BITSET: u64 = 10;
    let [uaddr, op, val, timeout, ..] = a;
    match op & 127 {
        WAIT | WAIT_BITSET => {
            if read_u32(&mut p.aspace, uaddr)? != val as u32 {
                return Err(EAGAIN);
            }
            // Only one thread exists, so nobody can wake us.
            if timeout == 0 {
                return p.unimplemented(nr::futex, "futex", "waiting forever (single thread)", EINTR);
            }
            let ns = read_timespec_ns(&mut p.aspace, timeout)?;
            if op & 127 == WAIT_BITSET {
                time::sleep_until_monotonic(ns); // absolute
            } else {
                time::sleep_ns(ns);
            }
            Err(ETIMEDOUT)
        }
        WAKE | WAKE_BITSET | REQUEUE | CMP_REQUEUE => Ok(0),
        _ => p.unimplemented(nr::futex, "futex", "operation", ENOSYS),
    }
}
