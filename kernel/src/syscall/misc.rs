//! Time, identity, limits and the remaining small syscalls.

use super::table::nr;
use crate::errno::*;
use crate::mm::frame;
use crate::process::{PID, Process};
use crate::uaccess::*;
use crate::{rng, time};

#[allow(non_upper_case_globals)]
pub fn dispatch(p: &mut Process, n: u32, name: &str, a: [u64; 6]) -> SysResult {
    match n {
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
        nr::getpid | nr::getpgid | nr::getsid => Ok(PID),
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
        // The primary group, as after a normal login (initgroups).
        nr::getgroups => match a[0] {
            0 => Ok(1),
            _ => write_u32(&mut p.aspace, a[1], p.gid).map(|_| 1),
        },
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
        nr::sched_setaffinity | nr::sched_setparam | nr::sched_setscheduler => Ok(0),
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
        // glibc probes rseq and libuv probes io_uring; both cope with ENOSYS.
        nr::rseq | nr::io_uring_setup => Err(ENOSYS),

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
    use crate::procfs::{HOSTNAME, RELEASE, VERSION};
    let fields = ["Linux", HOSTNAME, RELEASE, VERSION, "aarch64", "(none)"];
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
