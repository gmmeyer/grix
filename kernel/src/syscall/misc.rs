//! Time, identity, limits and the remaining small syscalls.

use super::table::nr;
use crate::errno::*;
use crate::mm::frame;
use crate::process::Process;
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
        nr::getuid => Ok(p.ids.ruid as u64),
        nr::geteuid => Ok(p.uid as u64),
        nr::getgid => Ok(p.ids.rgid as u64),
        nr::getegid => Ok(p.gid as u64),
        nr::getresuid | nr::getresgid => {
            let ids =
                if n == nr::getresuid { [p.ids.ruid, p.uid, p.ids.suid] } else { [p.ids.rgid, p.gid, p.ids.sgid] };
            for (ptr, id) in a[..3].iter().zip(ids) {
                write_u32(&mut p.aspace, *ptr, id)?;
            }
            Ok(0)
        }
        nr::setgroups => {
            if p.uid != 0 {
                return Err(EPERM);
            }
            let n = a[0] as usize;
            if n > crate::process::MAX_GROUPS {
                return Err(EINVAL);
            }
            let mut groups = alloc::vec::Vec::with_capacity(n);
            for i in 0..n as u64 {
                groups.push(read_u32(&mut p.aspace, a[1] + 4 * i)?);
            }
            p.ids.groups = groups;
            Ok(0)
        }
        // The primary group, as after a normal login (initgroups).
        nr::getgroups => {
            let groups = p.ids.groups.clone();
            match a[0] as usize {
                0 => Ok(groups.len() as u64),
                n if n < groups.len() => Err(EINVAL),
                _ => {
                    for (i, g) in groups.iter().enumerate() {
                        write_u32(&mut p.aspace, a[1] + 4 * i as u64, *g)?;
                    }
                    Ok(groups.len() as u64)
                }
            }
        }
        nr::setuid | nr::setreuid | nr::setresuid | nr::setgid | nr::setregid | nr::setresgid => set_ids(p, n, name, a),
        nr::setfsuid | nr::setfsgid => set_fs_id(p, n, name, a[0] as u32),
        nr::umask => {
            let old = p.fs.update(|f| core::mem::replace(&mut f.umask, a[0] as u32 & 0o777));
            Ok(old as u64)
        }
        nr::prctl => prctl(p, a),
        nr::getrlimit => prlimit(p, 0, a[0], 0, a[1]),
        nr::setrlimit => prlimit(p, 0, a[0], a[1], 0),
        nr::prlimit64 => prlimit(p, a[0], a[1], a[2], a[3]),
        nr::getrusage => {
            // RUSAGE_SELF, RUSAGE_THREAD, or RUSAGE_CHILDREN (those waited for).
            // All CPU time counts as user time: system time isn't separated.
            let cpu = match a[0] as i32 {
                0 => p.process_cpu_ns(),
                1 => p.thread_cpu_ns(p.current).unwrap_or(0),
                -1 => p.children_cpu_ns,
                _ => return Err(EINVAL),
            };
            let mut b = [0u8; 144];
            b[..8].copy_from_slice(&(cpu / 1_000_000_000).to_le_bytes());
            b[8..16].copy_from_slice(&((cpu % 1_000_000_000) / 1000).to_le_bytes());
            let (_, used) = frame::stats();
            b[32..40].copy_from_slice(&(used * 4).to_le_bytes()); // ru_maxrss in KiB
            copy_out(&mut p.aspace, a[1], &b).map(|_| 0)
        }
        nr::sysinfo => sysinfo(p, a[0]),
        nr::times => {
            let ticks = time::monotonic_ns() / 10_000_000;
            if a[0] != 0 {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&(p.process_cpu_ns() / 10_000_000).to_le_bytes()); // tms_utime
                b[16..24].copy_from_slice(&(p.children_cpu_ns / 10_000_000).to_le_bytes()); // tms_cutime
                copy_out(&mut p.aspace, a[0], &b)?;
            }
            Ok(ticks)
        }
        nr::sched_getaffinity => {
            if a[1] < 8 {
                return Err(EINVAL);
            }
            // Every CPU (bits 0..n).
            write_u64(&mut p.aspace, a[2], (1u64 << crate::smp::count()) - 1)?;
            Ok(8)
        }
        nr::sched_setaffinity | nr::sched_setparam | nr::sched_setscheduler => Ok(0),
        nr::sched_getscheduler => Ok(0),
        nr::sched_getparam => write_u32(&mut p.aspace, a[1], 0).map(|_| 0),
        nr::getpriority => Ok(20),
        nr::setpriority => Ok(0),
        nr::getcpu => {
            // The CPU, and its NUMA node (there's one).
            for (ptr, v) in a[..2].iter().zip([crate::smp::me() as u32, 0]) {
                if *ptr != 0 {
                    write_u32(&mut p.aspace, *ptr, v)?;
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
        nr::membarrier => membarrier(p, a[0], a[1]),
        nr::mincore => mincore(p, a[0], a[1], a[2]),
        // glibc probes rseq and libuv probes io_uring; both cope with ENOSYS.
        nr::rseq | nr::io_uring_setup => Err(ENOSYS),

        _ => p.unimplemented(n, name, "", ENOSYS),
    }
}

fn clock_now(p: &Process, clock: u64) -> Option<u64> {
    match clock as i32 {
        0 | 5 | 11 => Some(time::realtime_ns()),     // REALTIME, REALTIME_COARSE, TAI
        1 | 4 | 6 | 7 => Some(time::monotonic_ns()), // MONOTONIC*, BOOTTIME
        2 => Some(p.process_cpu_ns()),               // PROCESS_CPUTIME_ID
        3 => p.thread_cpu_ns(p.current),             // THREAD_CPUTIME_ID
        // clock_getcpuclockid/pthread_getcpuclockid: ~id << 3, bit 2 for a thread.
        c if c < 0 => {
            let id = !(c >> 3) as u32;
            if c & 4 != 0 {
                p.thread_cpu_ns(if id == 0 { p.current } else { id })
            } else if id == 0 || id == p.pid {
                Some(p.process_cpu_ns())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn clock_gettime(p: &mut Process, clock: u64, tp: u64) -> SysResult {
    let ns = clock_now(p, clock).ok_or(EINVAL)?;
    write_timespec(&mut p.aspace, tp, ns).map(|_| 0)
}

fn uname(p: &mut Process, buf: u64) -> SysResult {
    let mut b = [0u8; 65 * 6];
    use crate::procfs::{HOSTNAME, RELEASE, VERSION};
    let fields = ["Linux", HOSTNAME, RELEASE, VERSION, crate::arch::PLATFORM, "(none)"];
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

/// setuid and friends, by Linux's rules (credentials(7)): uid 0 may set
/// any ids; others may only move among their real, effective and saved
/// ones. The ids mean nothing outside the sandbox: this is how programs
/// started as root (apt, daemons) drop to another user.
fn set_ids(p: &mut Process, n: u32, _name: &str, a: [u64; 6]) -> SysResult {
    const KEEP: u32 = u32::MAX;
    let privileged = p.uid == 0;
    let users = matches!(n, nr::setuid | nr::setreuid | nr::setresuid);
    let (r, e, s) = if users { (p.ids.ruid, p.uid, p.ids.suid) } else { (p.ids.rgid, p.gid, p.ids.sgid) };
    let arg = |i: usize| a[i] as u32;
    let mine = |id: u32| id == r || id == e || id == s;
    let (nr_, ne, ns) = match n {
        nr::setuid | nr::setgid => {
            let id = arg(0);
            if id == KEEP {
                return Err(EINVAL);
            } else if privileged {
                (id, id, id)
            } else if id == r || id == s {
                (r, id, s)
            } else {
                return Err(EPERM);
            }
        }
        nr::setreuid | nr::setregid => {
            let (nr_, ne) = (arg(0), arg(1));
            if !privileged && ((nr_ != KEEP && nr_ != r && nr_ != e) || (ne != KEEP && !mine(ne))) {
                return Err(EPERM);
            }
            let nr_ = if nr_ == KEEP { r } else { nr_ };
            let ne = if ne == KEEP { e } else { ne };
            // The saved id follows the effective one when the real one is
            // set, or the effective one changes to something not the real.
            let ns = if arg(0) != KEEP || (arg(1) != KEEP && ne != r) { ne } else { s };
            (nr_, ne, ns)
        }
        _ => {
            let ids = [arg(0), arg(1), arg(2)];
            if !privileged && ids.iter().any(|&id| id != KEEP && !mine(id)) {
                return Err(EPERM);
            }
            let pick = |id: u32, old: u32| if id == KEEP { old } else { id };
            (pick(ids[0], r), pick(ids[1], e), pick(ids[2], s))
        }
    };
    if users {
        (p.ids.ruid, p.uid, p.ids.suid) = (nr_, ne, ns);
    } else {
        (p.ids.rgid, p.gid, p.ids.sgid) = (nr_, ne, ns);
    }
    crate::fs::lock().proc_owner(p.pid, (p.uid, p.gid));
    Ok(0)
}

/// setfsuid and setfsgid. The file system ids here are always the
/// effective ones, as on Linux until a program sets them apart, so asking
/// for the effective id (or an invalid one, -1, which is how a program
/// reads it) changes nothing. Linux returns the old id whatever happens,
/// so a program sees a refused change only by asking again: one it may
/// make but grix can't (an id apart from the effective one) is reported
/// and refused the same way.
fn set_fs_id(p: &mut Process, n: u32, name: &str, id: u32) -> SysResult {
    let users = n == nr::setfsuid;
    let (r, e, s) = if users { (p.ids.ruid, p.uid, p.ids.suid) } else { (p.ids.rgid, p.gid, p.ids.sgid) };
    if id != u32::MAX && id != e && (p.uid == 0 || id == r || id == s) {
        let _ = p.unimplemented(n, name, "file system ids apart from the effective ones", EINVAL);
    }
    Ok(e as u64)
}

fn prctl(p: &mut Process, a: [u64; 6]) -> SysResult {
    const PR_SET_PDEATHSIG: u64 = 1;
    const PR_GET_PDEATHSIG: u64 = 2;
    const PR_GET_DUMPABLE: u64 = 3;
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_GET_KEEPCAPS: u64 = 7;
    const PR_SET_KEEPCAPS: u64 = 8;
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    const PR_GET_SECCOMP: u64 = 21;
    const PR_CAPBSET_READ: u64 = 23;
    const PR_CAPBSET_DROP: u64 = 24;
    const PR_SET_TIMERSLACK: u64 = 29;
    const PR_GET_TIMERSLACK: u64 = 30;
    const PR_SET_CHILD_SUBREAPER: u64 = 36;
    const PR_GET_CHILD_SUBREAPER: u64 = 37;
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_GET_NO_NEW_PRIVS: u64 = 39;
    const PR_GET_TID_ADDRESS: u64 = 40;
    const PR_SET_THP_DISABLE: u64 = 41;
    const PR_GET_THP_DISABLE: u64 = 42;
    const PR_CAP_AMBIENT: u64 = 47;
    const PR_CAP_AMBIENT_IS_SET: u64 = 1;
    const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
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
        // Nothing to signal (no parent), dump, or slack: these are settings
        // with no effect inside the sandbox.
        PR_SET_PDEATHSIG | PR_SET_DUMPABLE | PR_SET_TIMERSLACK | PR_SET_NO_NEW_PRIVS | PR_SET_VMA => Ok(0),
        PR_GET_PDEATHSIG => write_u32(&mut p.aspace, a[1], 0).map(|_| 0),
        PR_GET_TIMERSLACK => Ok(50_000), // Linux's default, in ns
        PR_SET_KEEPCAPS | PR_SET_THP_DISABLE => Ok(0),
        PR_GET_KEEPCAPS | PR_GET_THP_DISABLE | PR_GET_SECCOMP => Ok(0),
        // There are no child processes yet, so being a subreaper changes nothing.
        PR_SET_CHILD_SUBREAPER => {
            p.subreaper = a[1] != 0;
            Ok(0)
        }
        PR_GET_CHILD_SUBREAPER => write_u32(&mut p.aspace, a[1], p.subreaper as u32).map(|_| 0),
        PR_GET_TID_ADDRESS => {
            let addr = p.cur().clear_child_tid;
            write_u64(&mut p.aspace, a[1], addr).map(|_| 0)
        }
        // No capabilities: none to read, drop or raise.
        PR_CAPBSET_READ => Ok(0),
        PR_CAPBSET_DROP => Ok(0),
        PR_CAP_AMBIENT if a[1] == PR_CAP_AMBIENT_IS_SET || a[1] == PR_CAP_AMBIENT_CLEAR_ALL => Ok(0),
        PR_CAP_AMBIENT => Err(EPERM),
        n => p.unimplemented(nr::prctl, "prctl", &alloc::format!("option {n}"), EINVAL),
    }
}

/// membarrier: with one CPU every thread already sees the caller's stores
/// in order (switching threads takes an exception), so each barrier is
/// immediate. The expedited ones need registering first, as on Linux.
fn membarrier(p: &mut Process, cmd: u64, flags: u64) -> SysResult {
    const QUERY: u64 = 0;
    const GLOBAL: u64 = 1;
    const GLOBAL_EXPEDITED: u64 = 2;
    const REGISTER_GLOBAL_EXPEDITED: u64 = 4;
    const PRIVATE_EXPEDITED: u64 = 8;
    const REGISTER_PRIVATE_EXPEDITED: u64 = 16;
    const PRIVATE_EXPEDITED_SYNC_CORE: u64 = 32;
    const REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 64;
    if flags != 0 {
        return Err(EINVAL);
    }
    let registered = |p: &Process, reg: u64| p.membarrier_registered & reg != 0;
    match cmd {
        QUERY => Ok(GLOBAL
            | GLOBAL_EXPEDITED
            | REGISTER_GLOBAL_EXPEDITED
            | PRIVATE_EXPEDITED
            | REGISTER_PRIVATE_EXPEDITED
            | PRIVATE_EXPEDITED_SYNC_CORE
            | REGISTER_PRIVATE_EXPEDITED_SYNC_CORE),
        REGISTER_GLOBAL_EXPEDITED | REGISTER_PRIVATE_EXPEDITED | REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            p.membarrier_registered |= cmd;
            Ok(0)
        }
        // Every thread running on another CPU goes through the kernel (a
        // barrier, and a context synchronization): any process's, or this
        // one's.
        GLOBAL | GLOBAL_EXPEDITED => {
            crate::smp::barrier_others(None);
            Ok(0)
        }
        PRIVATE_EXPEDITED if registered(p, REGISTER_PRIVATE_EXPEDITED) => {
            crate::smp::barrier_others(Some(p.pid));
            Ok(0)
        }
        PRIVATE_EXPEDITED_SYNC_CORE if registered(p, REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) => {
            crate::smp::barrier_others(Some(p.pid));
            Ok(0)
        }
        PRIVATE_EXPEDITED | PRIVATE_EXPEDITED_SYNC_CORE => Err(EPERM),
        _ => Err(EINVAL),
    }
}

/// mincore: one byte per page, 1 if it's in memory (faulted in).
fn mincore(p: &mut Process, addr: u64, len: u64, vec: u64) -> SysResult {
    use crate::mm::{PAGE_SIZE, page_up};
    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(EINVAL);
    }
    let end = page_up(len).and_then(|l| addr.checked_add(l)).ok_or(ENOMEM)?;
    if end > crate::mm::aspace::USER_TOP {
        return Err(ENOMEM);
    }
    let mut out = alloc::vec::Vec::new();
    let mut page = addr;
    while page < end {
        if p.aspace.find(page).is_none() {
            return Err(ENOMEM);
        }
        out.push(p.aspace.pt.lookup(page).is_some() as u8);
        page += PAGE_SIZE;
        if out.len() == 4096 {
            let at = vec + ((page - addr) / PAGE_SIZE) - 4096;
            copy_out(&mut p.aspace, at, &out)?;
            out.clear();
        }
    }
    let at = vec + ((end - addr) / PAGE_SIZE) - out.len() as u64;
    copy_out(&mut p.aspace, at, &out).map(|_| 0)
}

fn prlimit(p: &mut Process, pid: u64, res: u64, new: u64, old: u64) -> SysResult {
    if pid != 0 && pid != p.pid as u64 {
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
