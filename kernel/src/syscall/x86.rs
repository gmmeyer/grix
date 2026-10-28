//! x86_64's system calls that arm64 never had: the ones the `*at`, `*2`
//! and `p*` calls replaced, each turned into the call that replaced it (as
//! Linux's own implementations do), and `arch_prctl`. The gate is the old
//! call's (`table.rs` gives it the new one's), checked before this.

use super::table::nr;
use super::{AT_FDCWD, dispatch, file, proc};
use crate::arch::TrapFrame;
use crate::errno::*;
use crate::process::Process;
use crate::uaccess::*;

const AT: u64 = AT_FDCWD as i64 as u64;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const SIGCHLD: u64 = 17;
const CLONE_VM: u64 = 0x100;
const CLONE_VFORK: u64 = 0x4000;

/// Call `n` with `a`, if it's one of these; None for every other call.
pub(super) fn legacy(p: &mut Process, tf: &mut TrapFrame, n: u32, a: [u64; 6]) -> Option<SysResult> {
    let call = |p: &mut Process, tf: &mut TrapFrame, n: u32, args: [u64; 6]| dispatch(p, tf, n, args);
    Some(match n {
        nr::open => call(p, tf, nr::openat, [AT, a[0], a[1], a[2], 0, 0]),
        nr::creat => call(p, tf, nr::openat, [AT, a[0], O_CREAT | O_WRONLY | O_TRUNC, a[1], 0, 0]),
        nr::stat => call(p, tf, nr::newfstatat, [AT, a[0], a[1], 0, 0, 0]),
        nr::lstat => call(p, tf, nr::newfstatat, [AT, a[0], a[1], AT_SYMLINK_NOFOLLOW, 0, 0]),
        nr::access => call(p, tf, nr::faccessat, [AT, a[0], a[1], 0, 0, 0]),
        nr::readlink => call(p, tf, nr::readlinkat, [AT, a[0], a[1], a[2], 0, 0]),
        nr::mkdir => call(p, tf, nr::mkdirat, [AT, a[0], a[1], 0, 0, 0]),
        nr::rmdir => call(p, tf, nr::unlinkat, [AT, a[0], AT_REMOVEDIR, 0, 0, 0]),
        nr::unlink => call(p, tf, nr::unlinkat, [AT, a[0], 0, 0, 0, 0]),
        nr::rename => call(p, tf, nr::renameat2, [AT, a[0], AT, a[1], 0, 0]),
        nr::link => call(p, tf, nr::linkat, [AT, a[0], AT, a[1], 0, 0]),
        nr::symlink => call(p, tf, nr::symlinkat, [a[0], AT, a[1], 0, 0, 0]),
        nr::chmod => call(p, tf, nr::fchmodat, [AT, a[0], a[1], 0, 0, 0]),
        nr::chown => call(p, tf, nr::fchownat, [AT, a[0], a[1], a[2], 0, 0]),
        nr::lchown => call(p, tf, nr::fchownat, [AT, a[0], a[1], a[2], AT_SYMLINK_NOFOLLOW, 0]),
        nr::mknod => call(p, tf, nr::mknodat, [AT, a[0], a[1], a[2], 0, 0]),
        nr::pipe => call(p, tf, nr::pipe2, [a[0], 0, 0, 0, 0, 0]),
        nr::dup2 if a[0] == a[1] => {
            // Unlike dup3, the same fd twice is fine if it's open.
            call(p, tf, nr::fcntl, [a[0], 1 /* F_GETFD */, 0, 0, 0, 0]).map(|_| a[1])
        }
        nr::dup2 => call(p, tf, nr::dup3, [a[0], a[1], 0, 0, 0, 0]),
        nr::epoll_create if a[0] as i32 <= 0 => Err(EINVAL),
        nr::epoll_create => call(p, tf, nr::epoll_create1, [0; 6]),
        nr::epoll_wait => file::epoll_wait(p, a[0], a[1], a[2], file::ms_timeout(a[3])),
        nr::inotify_init => call(p, tf, nr::inotify_init1, [0; 6]),
        nr::eventfd => call(p, tf, nr::eventfd2, [a[0], 0, 0, 0, 0, 0]),
        nr::signalfd => call(p, tf, nr::signalfd4, [a[0], a[1], a[2], 0, 0, 0]),
        nr::poll => file::poll_ns(p, a[0], a[1], file::ms_timeout(a[2])),
        nr::select => select(p, a),
        // Waits for a signal: what ppoll does with nothing to watch.
        nr::pause => file::poll_ns(p, 0, 0, None),
        nr::alarm => super::timer::alarm(p, a[0] as u32 as u64),
        nr::time => time(p, a[0]),
        nr::getpgrp => proc::group_of(p, 0, false),
        // clone(flags, stack, parent_tid, child_tid, tls).
        nr::fork => call(p, tf, nr::clone, [SIGCHLD, 0, 0, 0, 0, 0]),
        nr::vfork => call(p, tf, nr::clone, [CLONE_VM | CLONE_VFORK | SIGCHLD, 0, 0, 0, 0, 0]),
        nr::arch_prctl => arch_prctl(p, a[0], a[1]),
        nr::getdents => p.unimplemented(n, "getdents", "the old linux_dirent (libc uses getdents64)", ENOSYS),
        nr::utime | nr::utimes | nr::futimesat => {
            p.unimplemented(n, super::table::info(n).0, "the old time structures (libc uses utimensat)", ENOSYS)
        }
        _ => return None,
    })
}

/// time(tloc): seconds of the time of day.
fn time(p: &mut Process, tloc: u64) -> SysResult {
    let secs = crate::time::realtime_ns() / 1_000_000_000;
    if tloc != 0 {
        write_u64(&mut p.aspace, tloc, secs)?;
    }
    Ok(secs)
}

/// select(nfds, readfds, writefds, exceptfds, timeval): pselect6 with a
/// timeval's timeout.
fn select(p: &mut Process, a: [u64; 6]) -> SysResult {
    let timeout = if a[4] == 0 {
        None
    } else {
        let sec = read_u64(&mut p.aspace, a[4])?;
        let usec = read_u64(&mut p.aspace, a[4] + 8)?;
        if (sec as i64) < 0 || usec >= 1_000_000 {
            return Err(EINVAL);
        }
        Some(sec.saturating_mul(1_000_000_000).saturating_add(usec * 1000))
    };
    file::select_ns(p, a[0], a[1], a[2], a[3], timeout)
}

/// arch_prctl: the FS base, which is TLS on x86_64 (GS is unused).
fn arch_prctl(p: &mut Process, code: u64, addr: u64) -> SysResult {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;
    match code {
        ARCH_SET_FS if crate::arch::valid_tls(addr) => {
            crate::arch::set_tls(addr);
            Ok(0)
        }
        ARCH_SET_FS => Err(EPERM),
        ARCH_GET_FS => write_u64(&mut p.aspace, addr, crate::arch::tls()).map(|_| 0),
        ARCH_GET_GS => write_u64(&mut p.aspace, addr, 0).map(|_| 0),
        ARCH_SET_GS => p.unimplemented(nr::arch_prctl, "arch_prctl", "ARCH_SET_GS", EINVAL),
        // CET, AMX and the rest: not here (glibc asks and goes on).
        _ => Err(EINVAL),
    }
}
