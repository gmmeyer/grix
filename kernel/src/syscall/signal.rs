//! Signal syscalls: dispositions, masks, sending, waiting, sigaltstack.
//! Queues, delivery and rt_sigreturn are in `crate::signal`.

use crate::errno::*;
use crate::process::{INIT, Process, SigAction, WaitOn};
use crate::procs::PROCS;
use crate::signal::{
    self, AltStack, NSIG, SA_KNOWN, SI_TKILL, SI_USER, SIGKILL, SIGSTOP, SigInfo, Target, UNBLOCKABLE,
};
use crate::uaccess::*;
use alloc::vec::Vec;

/// The kernel's sigset_t is 64 bits; libc passes its size to every call.
const SIGSET_SIZE: u64 = 8;
const SENT_BY_PROGRAM: &str = "signal sent by the program itself";

fn signo(sig: u64) -> Result<u32, Errno> {
    if (1..=NSIG as u64).contains(&sig) { Ok(sig as u32) } else { Err(EINVAL) }
}

pub fn rt_sigaction(p: &mut Process, sig: u64, act: u64, oact: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(EINVAL);
    }
    let sig = signo(sig)?;
    // Read the new action before writing the old one: they may be the same buffer.
    let new = if act != 0 {
        if sig == SIGKILL || sig == SIGSTOP {
            return Err(EINVAL);
        }
        let mut b = [0u8; 32];
        copy_in(&mut p.aspace, act, &mut b)?;
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Some(SigAction { handler: w(0), flags: w(1) & SA_KNOWN, restorer: w(2), mask: w(3) & !UNBLOCKABLE })
    } else {
        None
    };
    if oact != 0 {
        let o = p.action(sig);
        let mut b = [0u8; 32];
        for (i, v) in [o.handler, o.flags, o.restorer, o.mask].iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        copy_out(&mut p.aspace, oact, &b)?;
    }
    if let Some(new) = new {
        p.set_action(sig, new);
        // POSIX: setting a pending signal to be ignored discards it.
        if signal::is_ignored(&new, sig) {
            signal::discard(p, sig);
        }
    }
    Ok(0)
}

pub fn rt_sigprocmask(p: &mut Process, how: u64, set: u64, oset: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(EINVAL);
    }
    let old = p.cur().sigmask;
    if set != 0 {
        let s = read_u64(&mut p.aspace, set)?;
        let mask = match how {
            0 => old | s,  // SIG_BLOCK
            1 => old & !s, // SIG_UNBLOCK
            2 => s,        // SIG_SETMASK
            _ => return Err(EINVAL),
        };
        // Newly unblocked pending signals are delivered on the way out.
        p.cur().sigmask = mask & !UNBLOCKABLE;
    }
    if oset != 0 {
        write_u64(&mut p.aspace, oset, old)?;
    }
    Ok(0)
}

pub fn rt_sigpending(p: &mut Process, set: u64, size: u64) -> SysResult {
    if size > SIGSET_SIZE {
        return Err(EINVAL);
    }
    let shared = p.shared_pending.mask;
    let t = p.cur();
    let pending = (t.pending.mask | shared) & t.sigmask;
    let bytes = pending.to_le_bytes();
    copy_out(&mut p.aspace, set, &bytes[..size as usize]).map(|_| 0)
}

pub fn rt_sigsuspend(p: &mut Process, mask: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(EINVAL);
    }
    let mask = read_u64(&mut p.aspace, mask)?;
    signal::mask_while_waiting(p, mask);
    p.block(WaitOn::Signal, None, Err(EINTR))
}

/// The optional sigmask argument of ppoll, epoll_pwait and epoll_pwait2.
pub fn wait_mask(p: &mut Process, mask: u64, size: u64) -> Result<(), Errno> {
    if mask == 0 {
        return Ok(());
    }
    if size != SIGSET_SIZE {
        return Err(EINVAL);
    }
    let mask = read_u64(&mut p.aspace, mask)?;
    signal::mask_while_waiting(p, mask);
    Ok(())
}

/// pselect6 passes its sigmask as a pointer to `{ const sigset_t *ss; size_t ss_len; }`.
pub fn pselect_mask(p: &mut Process, arg: u64) -> Result<(), Errno> {
    if arg == 0 {
        return Ok(());
    }
    let ss = read_u64(&mut p.aspace, arg)?;
    let len = read_u64(&mut p.aspace, arg + 8)?;
    wait_mask(p, ss, len)
}

pub fn rt_sigtimedwait(p: &mut Process, set: u64, info: u64, ts: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(EINVAL);
    }
    let set = read_u64(&mut p.aspace, set)? & !UNBLOCKABLE;
    let timeout = if ts == 0 { None } else { Some(read_timespec_ns(&mut p.aspace, ts)?) };
    if let Some(si) = signal::dequeue(p, set) {
        if info != 0 {
            copy_out(&mut p.aspace, info, &si.bytes())?;
        }
        return Ok(si.signo as u64);
    }
    if timeout == Some(0) {
        return Err(EAGAIN);
    }
    // A matching signal re-runs the call to dequeue it, with the same deadline.
    let deadline = p.timeout_deadline(timeout);
    p.block(WaitOn::SigWait(set), deadline, Err(EAGAIN))
}

pub fn sigaltstack(p: &mut Process, sp: u64, ss: u64, oss: u64) -> SysResult {
    let new = if ss != 0 {
        let ss_sp = read_u64(&mut p.aspace, ss)?;
        let flags = read_u32(&mut p.aspace, ss + 8)?;
        let size = read_u64(&mut p.aspace, ss + 16)?;
        Some(AltStack { sp: ss_sp, size, flags })
    } else {
        None
    };
    let t = p.cur();
    let old = t.altstack;
    if let Some(new) = new {
        t.altstack.set(new, sp)?;
    }
    if oss != 0 {
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&old.sp.to_le_bytes());
        b[8..12].copy_from_slice(&(old.state(sp) | (old.flags & signal::SS_AUTODISARM)).to_le_bytes());
        b[16..].copy_from_slice(&old.size.to_le_bytes());
        copy_out(&mut p.aspace, oss, &b)?;
    }
    Ok(0)
}

pub fn kill(p: &mut Process, pid: u64, sig: u64) -> SysResult {
    let pid = pid as i32;
    let sig = if sig == 0 { 0 } else { signo(sig)? };
    let (me, my_pgid, uid) = (p.pid, p.pgid, p.uid);
    let mut procs = PROCS.lock();
    // A positive pid is one process; 0 our process group, -pgid another
    // one; -1 everyone but init and ourselves.
    let targets: Vec<u32> = match pid {
        pid if pid > 0 => alloc::vec![pid as u32],
        0 => procs.all(p).filter(|q| q.pgid == my_pgid).map(|q| q.pid).collect(),
        -1 => procs.all(p).map(|q| q.pid).filter(|&q| q != INIT && q != me).collect(),
        g if g == i32::MIN => return Err(ESRCH),
        g => procs.all(p).filter(|q| q.pgid == g.unsigned_abs()).map(|q| q.pid).collect(),
    };
    let mut found = false;
    for target in targets {
        let Some(q) = procs.get(p, target) else {
            // Signalling a zombie works, and does nothing.
            found |= pid > 0 && procs.zombies.contains_key(&target);
            continue;
        };
        found = true;
        if sig == 0 || super::proc::shields_init(q, me, sig) {
            continue;
        }
        signal::send(q, Target::Process, SigInfo::sent(sig, SI_USER, me, uid, SENT_BY_PROGRAM))?;
    }
    crate::sched::timer_changed();
    if found { Ok(0) } else { Err(ESRCH) }
}

/// pidfd_send_signal(pidfd, sig, info, flags): kill() for the process a
/// pidfd refers to, with a siginfo of the caller's if it gives one.
pub fn pidfd_send_signal(p: &mut Process, pidfd: u64, sig: u64, uinfo: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(EINVAL);
    }
    let pid = super::proc::pidfd_pid(p, pidfd)?;
    let sig = if sig == 0 { 0 } else { signo(sig)? };
    let (me, uid) = (p.pid, p.uid);
    let info = if uinfo == 0 {
        SigInfo::sent(sig, SI_USER, me, uid, SENT_BY_PROGRAM)
    } else {
        let mut b = [0u8; 128];
        copy_in(&mut p.aspace, uinfo, &mut b)?;
        let signo_field = i32::from_le_bytes(b[..4].try_into().unwrap());
        let code = i32::from_le_bytes(b[8..12].try_into().unwrap());
        if signo_field != sig as i32 {
            return Err(EINVAL);
        }
        // Only the kernel (or the process itself) may claim kill or tkill
        // sent it, as for rt_sigqueueinfo.
        if pid != me && (code >= 0 || code == SI_TKILL) {
            return Err(EPERM);
        }
        let mut fields = [0u64; 4];
        for (i, f) in fields.iter_mut().enumerate() {
            *f = u64::from_le_bytes(b[16 + i * 8..24 + i * 8].try_into().unwrap());
        }
        SigInfo { signo: sig, errno: 0, code, fields, fault: None, timer: None, why: SENT_BY_PROGRAM }
    };
    let mut procs = PROCS.lock();
    let Some(q) = procs.get(p, pid) else {
        // A zombie can still be signalled, to no effect.
        return if procs.zombies.contains_key(&pid) { Ok(0) } else { Err(ESRCH) };
    };
    if sig == 0 || super::proc::shields_init(q, me, sig) {
        return Ok(0);
    }
    signal::send(q, Target::Process, info)?;
    crate::sched::timer_changed();
    Ok(0)
}

/// tkill(tid, sig) when `tgid` is None, tgkill(tgid, tid, sig) otherwise.
pub fn tgkill(p: &mut Process, tgid: Option<u64>, tid: u64, sig: u64) -> SysResult {
    let (tgid, tid) = (tgid.map(|g| g as i32), tid as i32);
    if tid <= 0 || tgid.is_some_and(|g| g <= 0) {
        return Err(EINVAL);
    }
    let tid = tid as u32;
    let (me, uid) = (p.pid, p.uid);
    let mut procs = PROCS.lock();
    let owner = procs.all(p).find(|q| q.threads.contains_key(&tid)).map(|q| q.pid);
    let Some(owner) = owner.filter(|&o| tgid.is_none_or(|g| g as u32 == o)) else { return Err(ESRCH) };
    if sig == 0 {
        return Ok(0);
    }
    let sig = signo(sig)?;
    let q = procs.get(p, owner).unwrap();
    if super::proc::shields_init(q, me, sig) {
        return Ok(0);
    }
    let info = SigInfo::sent(sig, SI_TKILL, me, uid, SENT_BY_PROGRAM);
    signal::send(q, Target::Thread(tid), info)?;
    crate::sched::timer_changed();
    Ok(0)
}

/// rt_sigqueueinfo(tgid, sig, info) when `tid` is None, rt_tgsigqueueinfo otherwise.
pub fn rt_sigqueueinfo(p: &mut Process, tgid: u64, tid: Option<u64>, sig: u64, uinfo: u64) -> SysResult {
    if tgid as i32 != p.pid as i32 || tid.is_some_and(|t| !p.threads.contains_key(&(t as u32))) {
        // Queueing to other processes isn't supported (it needs si_code checks).
        return Err(ESRCH);
    }
    let sig = signo(sig)?;
    let mut b = [0u8; 128];
    copy_in(&mut p.aspace, uinfo, &mut b)?;
    // Programs may only forge si_code for signals to themselves, which is all
    // there is here; Linux overrides si_signo.
    let code = i32::from_le_bytes(b[8..12].try_into().unwrap());
    let mut fields = [0u64; 4];
    for (i, f) in fields.iter_mut().enumerate() {
        *f = u64::from_le_bytes(b[16 + i * 8..24 + i * 8].try_into().unwrap());
    }
    let info = SigInfo { signo: sig, errno: 0, code, fields, fault: None, timer: None, why: SENT_BY_PROGRAM };
    let target = tid.map_or(Target::Process, |t| Target::Thread(t as u32));
    signal::send(p, target, info).map(|_| 0)
}
