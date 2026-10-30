//! Threads: clone/clone3, thread exit, futex, sleeping and yielding.

use alloc::vec::Vec;
use grix_abi::policy::Capability;
use grix_abi::stats::{Limit, Resource};

use super::{require, table::nr};
use crate::arch::{self, TrapFrame};
use crate::errno::*;
use crate::process::{self, Process, Thread, WaitOn};
use crate::time;
use crate::uaccess::*;

pub const CLONE_VM: u64 = 0x100;
pub const CLONE_SIGHAND: u64 = 0x800;
const CLONE_PIDFD: u64 = 0x1000;
pub const CLONE_VFORK: u64 = 0x4000;
pub const CLONE_PARENT: u64 = 0x8000;
pub const CLONE_THREAD: u64 = 0x10000;
pub const CLONE_SETTLS: u64 = 0x80000;
pub const CLONE_PARENT_SETTID: u64 = 0x10_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
pub const CLONE_CHILD_SETTID: u64 = 0x100_0000;
/// clone3 only: the child's handlers are reset to the default.
pub const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
/// clone3 only: the child goes into a cgroup.
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
/// CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET
pub const CLONE_NAMESPACES: u64 =
    0x2_0000 | 0x200_0000 | 0x400_0000 | 0x800_0000 | 0x1000_0000 | 0x2000_0000 | 0x4000_0000;

/// unshare's (in clone, these bits are the exit signal).
pub const CLONE_NEWTIME: u64 = 0x80;

/// "new namespaces (CLONE_NEWUSER|...)" for the namespace flags in `flags`,
/// so each kind is reported.
pub fn namespaces_denied(flags: u64) -> alloc::string::String {
    const NAMES: [(u64, &str); 8] = [
        (0x2_0000, "CLONE_NEWNS"),
        (0x200_0000, "CLONE_NEWCGROUP"),
        (0x400_0000, "CLONE_NEWUTS"),
        (0x800_0000, "CLONE_NEWIPC"),
        (0x1000_0000, "CLONE_NEWUSER"),
        (0x2000_0000, "CLONE_NEWPID"),
        (0x4000_0000, "CLONE_NEWNET"),
        (CLONE_NEWTIME, "CLONE_NEWTIME"),
    ];
    let names: Vec<&str> = NAMES.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, n)| *n).collect();
    alloc::format!("new namespaces ({})", names.join("|"))
}

pub struct CloneArgs {
    pub flags: u64,
    pub stack: u64,
    pub parent_tid: u64,
    pub tls: u64,
    pub child_tid: u64,
    /// Where CLONE_PIDFD puts the pidfd.
    pub pidfd: u64,
}

/// clone(flags, stack, parent_tid, tls, child_tid) — arm64 argument order.
pub fn clone(p: &mut Process, tf: &TrapFrame, a: [u64; 6]) -> SysResult {
    // Only the low 32 bits are flags (clone3 has the rest).
    let args =
        CloneArgs { flags: a[0] & 0xffff_ffff, stack: a[1], parent_tid: a[2], tls: a[3], child_tid: a[4], pidfd: a[2] };
    // clone puts both at parent_tid.
    if args.flags & (CLONE_PIDFD | CLONE_PARENT_SETTID) == CLONE_PIDFD | CLONE_PARENT_SETTID {
        return Err(EINVAL);
    }
    do_clone(p, tf, nr::clone, args)
}

pub fn clone3(p: &mut Process, tf: &TrapFrame, uargs: u64, size: u64) -> SysResult {
    if size < 64 {
        return Err(EINVAL);
    }
    let mut b = [0u8; 64];
    copy_in(&mut p.aspace, uargs, &mut b)?;
    let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    // struct clone_args: flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls
    let (stack, stack_size) = (w(5), w(6));
    let (flags, exit_signal) = (w(0), w(4));
    // clone3_args_valid: no unknown flags, no exit signal in the flags,
    // and none at all for a thread or a sibling (whose exit signal is the
    // caller's).
    if exit_signal > crate::signal::NSIG as u64
        || flags & 0xff != 0
        || flags & !(0xffff_ffff | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP) != 0
        || (flags & (CLONE_THREAD | CLONE_PARENT) != 0 && exit_signal != 0)
    {
        return Err(EINVAL);
    }
    if flags & CLONE_INTO_CGROUP != 0 {
        return p.unimplemented(nr::clone3, "clone3", "CLONE_INTO_CGROUP", EINVAL);
    }
    let args = CloneArgs {
        flags: flags | exit_signal,
        stack: if stack == 0 { 0 } else { stack.checked_add(stack_size).ok_or(EINVAL)? },
        parent_tid: w(3),
        tls: w(7),
        child_tid: w(2),
        pidfd: w(1),
    };
    do_clone(p, tf, nr::clone3, args)
}

fn do_clone(p: &mut Process, tf: &TrapFrame, n: u32, args: CloneArgs) -> SysResult {
    let (name, _) = super::table::info(n);
    let flags = args.flags;
    // As arch_prctl(ARCH_SET_FS) would refuse it (Linux's copy_thread).
    if flags & CLONE_SETTLS != 0 && !arch::valid_tls(args.tls) {
        return Err(EPERM);
    }
    if flags & CLONE_NAMESPACES != 0 {
        return p.deny(n, name, "privileged", &namespaces_denied(flags & CLONE_NAMESPACES));
    }
    // Siblings of init would have no parent to reap them (copy_process).
    if flags & CLONE_PARENT != 0 && p.pid == process::INIT {
        return Err(EINVAL);
    }
    if flags & (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND) == CLONE_SIGHAND | CLONE_CLEAR_SIGHAND {
        return Err(EINVAL);
    }
    if flags & CLONE_THREAD == 0 {
        return super::proc::fork(p, tf, n, args);
    }
    require(p, n, Capability::Threads, "")?;
    if flags & (CLONE_VM | CLONE_SIGHAND) != CLONE_VM | CLONE_SIGHAND {
        return Err(EINVAL);
    }
    // A pidfd is a process's, not a thread's (before Linux 6.9).
    if flags & CLONE_PIDFD != 0 {
        return Err(EINVAL);
    }
    let threads = crate::procs::threads();
    if threads >= process::threads_max() {
        crate::stats::hit(Limit::Threads);
        return Err(EAGAIN);
    }
    // Its kernel state, budgeted: EAGAIN as Linux's copy_process fails
    // when it can't allocate a task.
    let charge = crate::kmem::Charge::new(process::THREAD_COST).map_err(|_| EAGAIN)?;

    let tid = process::new_tid();
    // The child resumes right after the system call with the parent's
    // registers, returning 0.
    let mut regs = *tf;
    regs.set_return(0);
    if args.stack != 0 {
        regs.set_sp(args.stack);
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        write_u32(&mut p.aspace, args.parent_tid, tid)?;
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        write_u32(&mut p.aspace, args.child_tid, tid)?;
    }
    let sigmask = p.cur().sigmask;
    let seccomp = p.cur().seccomp.clone();
    let landlock = p.cur().landlock.clone();
    let mempolicy = p.cur().mempolicy;
    let name = p.thread_name(p.current);
    let mut t = Thread::new(tid);
    t.charge = charge;
    // Named as its creator is (Linux's copy_process copies comm).
    if name != p.name {
        t.name = name;
    }
    t.seccomp = seccomp;
    t.landlock = landlock;
    t.mempolicy = mempolicy;
    t.regs = regs;
    arch::save_fp(&mut t.fp);
    t.tls = if flags & CLONE_SETTLS != 0 { args.tls } else { arch::tls() };
    t.clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 { args.child_tid } else { 0 };
    t.sigmask = sigmask;
    p.threads.insert(tid, t);
    crate::procs::thread_added();
    crate::fs::task_changed(p.pid, tid, true);
    p.runq.push_back(tid);
    crate::sched::timer_changed();
    crate::stats::peak(Resource::Threads, threads as u64 + 1);
    Ok(tid as u64)
}

/// exit(2): end the calling thread only. The process ends with the last thread.
pub fn exit_thread(p: &mut Process, code: i32) -> SysResult {
    p.exited_cpu_ns += p.thread_cpu_ns(p.current).unwrap_or(0);
    // Its time on the CPU since `slice_start`, which the scheduler won't
    // count now that it's gone.
    let now = time::monotonic_ns();
    crate::stats::cpu(now.saturating_sub(p.slice_start));
    p.slice_start = now;
    let t = p.threads.remove(&p.current).expect("current thread missing");
    crate::procs::threads_gone(1);
    // Its queued signals went with it, perhaps a timer's.
    crate::timer::resync(p);
    if p.threads.is_empty() {
        p.terminate(process::exited(code));
        return Err(EBLOCKED);
    }
    crate::fs::task_changed(p.pid, t.tid, false);
    if t.clear_child_tid != 0 && write_u32(&mut p.aspace, t.clear_child_tid, 0).is_ok() {
        word_wake(p, false, t.clear_child_tid, 1, u32::MAX);
    }
    Err(EBLOCKED)
}

pub fn set_tid_address(p: &mut Process, addr: u64) -> SysResult {
    p.cur().clear_child_tid = addr;
    Ok(p.current as u64)
}

pub fn sched_yield(p: &mut Process) -> SysResult {
    p.resched = true;
    Ok(0)
}

pub fn nanosleep(p: &mut Process, req: u64) -> SysResult {
    let ns = read_timespec_ns(&mut p.aspace, req)?;
    let deadline = p.timeout_deadline(Some(ns));
    p.block(WaitOn::Sleep, deadline, Ok(0))
}

pub fn clock_nanosleep(p: &mut Process, clock: u64, flags: u64, req: u64) -> SysResult {
    const TIMER_ABSTIME: u64 = 1;
    let ns = read_timespec_ns(&mut p.aspace, req)?;
    let deadline = if flags & TIMER_ABSTIME == 0 {
        p.timeout_deadline(Some(ns)).unwrap()
    } else {
        match clock {
            0 | 5 | 11 => time::realtime_to_monotonic(ns), // REALTIME, REALTIME_COARSE, TAI
            1 | 4 | 6 | 7 => ns,                           // MONOTONIC*, BOOTTIME
            _ => return Err(EINVAL),
        }
    };
    p.block(WaitOn::Sleep, Some(deadline), Ok(0))
}

// ---------------------------------------------------------------- futex

/// Wake up to `n` waiters on `addr` whose bitset intersects `bitset`.
pub fn futex_wake(p: &mut Process, addr: u64, n: u32, bitset: u32) -> u32 {
    let Some(q) = p.futexes.get_mut(&addr) else { return 0 };
    let mut woken = Vec::new();
    q.retain(|&(tid, bits)| {
        if (woken.len() as u32) < n && bits & bitset != 0 {
            woken.push(tid);
            false
        } else {
            true
        }
    });
    if q.is_empty() {
        p.futexes.remove(&addr);
    }
    for &tid in &woken {
        // A futex_waitv returns the index of the word that woke it.
        let index =
            p.threads.get(&tid).and_then(|t| t.futexv.as_ref()).and_then(|v| v.addrs.iter().position(|&a| a == addr));
        p.wake(tid, Some(index.unwrap_or(0) as u64));
    }
    woken.len() as u32
}

/// The word at `addr` as a futex call means it: FUTEX_PRIVATE_FLAG says it's
/// this process's, wherever it is.
fn word_key(p: &Process, private: bool, addr: u64) -> Option<crate::futex::Key> {
    if private { None } else { crate::futex::key(&p.aspace, addr) }
}

/// `futex_wake`, of a word that may be shared.
fn word_wake(p: &mut Process, private: bool, addr: u64, n: u32, bitset: u32) -> u32 {
    match word_key(p, private, addr) {
        Some(key) => crate::futex::wake(p, key, n, bitset),
        None => futex_wake(p, addr, n, bitset),
    }
}

/// Move up to `n` waiters from `from` to `to`.
fn futex_requeue(p: &mut Process, from: u64, to: u64, n: u32) -> u32 {
    let Some(mut q) = p.futexes.remove(&from) else { return 0 };
    let moved: Vec<(u32, u32)> = q.drain(..(n as usize).min(q.len())).collect();
    if !q.is_empty() {
        p.futexes.insert(from, q);
    }
    for &(tid, _) in &moved {
        let Some(t) = p.threads.get_mut(&tid) else { continue };
        match (t.wait.as_mut(), t.futexv.as_mut()) {
            (Some(w), Some(v)) if w.on == WaitOn::FutexV => {
                v.addrs.iter_mut().filter(|a| **a == from).for_each(|a| *a = to);
            }
            (Some(w), _) => w.on = WaitOn::Futex(to),
            _ => {}
        }
    }
    let count = moved.len() as u32;
    p.futexes.entry(to).or_default().extend(moved);
    count
}

fn sign_extend12(v: u32) -> i32 {
    ((v << 20) as i32) >> 20
}

pub fn futex(p: &mut Process, a: [u64; 6]) -> SysResult {
    const WAIT: u64 = 0;
    const WAKE: u64 = 1;
    const REQUEUE: u64 = 3;
    const CMP_REQUEUE: u64 = 4;
    const WAKE_OP: u64 = 5;
    const WAIT_BITSET: u64 = 9;
    const WAKE_BITSET: u64 = 10;
    const CLOCK_REALTIME: u64 = 256;
    const PRIVATE: u64 = 128;
    let [uaddr, op, val, timeout, uaddr2, val3] = a;
    let private = op & PRIVATE != 0;
    // `val` and the count in `timeout` are C ints; negative counts wake nobody.
    let count = |v: u64| (v as i32).max(0) as u32;
    if uaddr % 4 != 0 {
        return Err(EINVAL);
    }
    match op & 127 {
        cmd @ (WAIT | WAIT_BITSET) => {
            let bitset = if cmd == WAIT { u32::MAX } else { val3 as u32 };
            if bitset == 0 {
                return Err(EINVAL);
            }
            if read_u32(&mut p.aspace, uaddr)? != val as u32 {
                return Err(EAGAIN);
            }
            let deadline = match timeout {
                0 => None,
                t => {
                    let ns = read_timespec_ns(&mut p.aspace, t)?;
                    match (cmd, op & CLOCK_REALTIME != 0) {
                        (WAIT, _) => p.timeout_deadline(Some(ns)),          // relative
                        (_, true) => Some(time::realtime_to_monotonic(ns)), // absolute, realtime
                        (_, false) => Some(ns),                             // absolute, monotonic
                    }
                }
            };
            let tid = p.current;
            if let Some(key) = word_key(p, private, uaddr) {
                crate::futex::enqueue(key, p.pid, tid, bitset);
                return p.block(WaitOn::SharedFutex(key), deadline, Err(ETIMEDOUT));
            }
            p.futexes.entry(uaddr).or_default().push_back((tid, bitset));
            p.block(WaitOn::Futex(uaddr), deadline, Err(ETIMEDOUT))
        }
        WAKE => Ok(word_wake(p, private, uaddr, count(val), u32::MAX) as u64),
        WAKE_BITSET => {
            if val3 as u32 == 0 {
                return Err(EINVAL);
            }
            Ok(word_wake(p, private, uaddr, count(val), val3 as u32) as u64)
        }
        cmd @ (REQUEUE | CMP_REQUEUE) => {
            if cmd == CMP_REQUEUE && read_u32(&mut p.aspace, uaddr)? != val3 as u32 {
                return Err(EAGAIN);
            }
            let woken = word_wake(p, private, uaddr, count(val), u32::MAX);
            let moved = match (word_key(p, private, uaddr), word_key(p, private, uaddr2)) {
                (Some(from), Some(to)) => crate::futex::requeue(p, from, to, count(timeout)),
                // From one kind of word to the other: there's no moving
                // it, and waking is always allowed.
                (Some(from), None) => crate::futex::wake(p, from, count(timeout), u32::MAX),
                (None, Some(_)) => futex_wake(p, uaddr, count(timeout), u32::MAX),
                (None, None) => futex_requeue(p, uaddr, uaddr2, count(timeout)),
            };
            Ok((woken + if cmd == CMP_REQUEUE { moved } else { 0 }) as u64)
        }
        WAKE_OP => {
            let enc = val3 as u32;
            let op = (enc >> 28) & 0xf;
            let cmp = (enc >> 24) & 0xf;
            let mut oparg = sign_extend12((enc >> 12) & 0xfff) as u32;
            let cmparg = sign_extend12(enc & 0xfff);
            if op & 8 != 0 {
                oparg = 1u32.checked_shl(oparg).ok_or(EINVAL)?;
            }
            if uaddr2 % 4 != 0 {
                return Err(EINVAL);
            }
            if op & 7 > 4 {
                return Err(ENOSYS);
            }
            let old = crate::uaccess::update_u32(&mut p.aspace, uaddr2, |old| match op & 7 {
                0 => oparg,
                1 => old.wrapping_add(oparg),
                2 => old | oparg,
                3 => old & !oparg,
                _ => old ^ oparg,
            })?;
            let old = old as i32;
            let hit = match cmp {
                0 => old == cmparg,
                1 => old != cmparg,
                2 => old < cmparg,
                3 => old <= cmparg,
                4 => old > cmparg,
                5 => old >= cmparg,
                _ => return Err(ENOSYS),
            };
            let mut woken = word_wake(p, private, uaddr, count(val), u32::MAX);
            if hit {
                woken += word_wake(p, private, uaddr2, count(timeout), u32::MAX);
            }
            Ok(woken as u64)
        }
        // Priority-inheritance futexes (PTHREAD_PRIO_INHERIT mutexes).
        6..=8 | 11..=13 => p.unimplemented(nr::futex, "futex", "priority-inheritance futexes", ENOSYS),
        _ => Err(ENOSYS),
    }
}

/// futex_waitv(2) (Linux 5.16, Wine and Proton's fsync): wait on up to
/// 128 futex words at once, each with its expected value, until any is
/// woken (the call returns its index) or the absolute deadline on
/// `clock` passes. Each word is queued like a FUTEX_WAIT's, so every
/// futex wake and requeue reaches it.
pub fn futex_waitv(p: &mut Process, waiters: u64, count: u64, flags: u64, timeout: u64, clock: u64) -> SysResult {
    /// FUTEX2_SIZE_U32, and FUTEX2_PRIVATE (FUTEX_PRIVATE_FLAG), the only
    /// flags a waiter may have.
    const SIZE_U32: u32 = 2;
    const PRIVATE: u32 = 128;
    const MAX: u64 = 128;
    if flags != 0 || count == 0 || count > MAX {
        return Err(EINVAL);
    }
    // Every word is checked before any value is: struct futex_waitv is
    // { u64 val, u64 uaddr, u32 flags, u32 reserved }.
    let mut words = Vec::with_capacity(count as usize);
    for i in 0..count {
        let mut w = [0u8; 24];
        copy_in(&mut p.aspace, waiters + i * 24, &mut w)?;
        let val = u64::from_le_bytes(w[0..8].try_into().unwrap());
        let addr = u64::from_le_bytes(w[8..16].try_into().unwrap());
        let wflags = u32::from_le_bytes(w[16..20].try_into().unwrap());
        let reserved = u32::from_le_bytes(w[20..24].try_into().unwrap());
        if reserved != 0 || wflags & !(SIZE_U32 | PRIVATE) != 0 || wflags & 3 != SIZE_U32 || addr % 4 != 0 {
            return Err(EINVAL);
        }
        // The value is a u32's: anything above it can never match.
        if val > u32::MAX as u64 {
            return Err(EINVAL);
        }
        words.push((addr, val as u32));
    }
    let deadline = match timeout {
        0 => None,
        t => {
            let ns = read_timespec_ns(&mut p.aspace, t)?;
            match clock {
                0 => Some(time::realtime_to_monotonic(ns)), // CLOCK_REALTIME
                1 => Some(ns),                              // CLOCK_MONOTONIC
                _ => return Err(EINVAL),
            }
        }
    };
    for &(addr, val) in &words {
        if read_u32(&mut p.aspace, addr)? != val {
            return Err(EAGAIN);
        }
    }
    // One queue entry per distinct word: a word given twice wakes as its first.
    let addrs: Vec<u64> = words.iter().map(|w| w.0).collect();
    let charge = crate::kmem::Charge::new(addrs.len() as u64 * 16)?;
    let tid = p.current;
    for (i, &addr) in addrs.iter().enumerate() {
        if !addrs[..i].contains(&addr) {
            p.futexes.entry(addr).or_default().push_back((tid, u32::MAX));
        }
    }
    p.cur().futexv = Some(process::FutexV { addrs, _charge: charge });
    p.block(WaitOn::FutexV, deadline, Err(ETIMEDOUT))
}
