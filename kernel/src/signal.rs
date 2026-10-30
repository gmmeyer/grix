//! Signals: pending queues, delivery to handlers through an `rt_sigframe` on
//! the user stack, `rt_sigreturn`, and interrupting blocked syscalls.
//!
//! The frame is laid out exactly as Linux does it (`arch::sigframe`): libc's
//! `ucontext_t`, Go's preemption (which rewrites the saved registers) and
//! unwinders all read it directly.
//!
//! Delivery happens on the way back to user mode (`return_to_user`), like Linux's
//! do_notify_resume: after a syscall, a fault or a timer interrupt, the
//! current thread's deliverable signals get frames. A thread blocked in a
//! syscall is woken by `send` and its syscall either fails with EINTR or, for
//! `SA_RESTART` handlers and restartable calls, re-executes after the handler.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{self, TrapFrame};
use crate::errno::*;
use crate::mm::aspace::{AddressSpace, SIGPAGE};
use crate::process::{JobReport, Process, SigAction, Thread, Wait, WaitOn};
use crate::syscall::table::nr;
use crate::time;
use crate::uaccess::*;

pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGSEGV: u32 = 11;
pub const SIGPIPE: u32 = 13;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGSYS: u32 = 31;
const SIGRTMIN: u32 = 32;
pub const NSIG: u32 = 64;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SA_NOCLDSTOP: u64 = 1;
pub const SA_NOCLDWAIT: u64 = 2;
pub const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;
/// The flags rt_sigaction keeps (Linux's UAPI_SA_FLAGS), so programs probing
/// with SA_UNSUPPORTED (0x400) see it cleared.
pub const SA_KNOWN: u64 =
    1 | 2 | SA_SIGINFO | 0x800 | SA_RESTORER | SA_ONSTACK | SA_RESTART | SA_NODEFER | SA_RESETHAND;

// si_code values.
pub const SI_USER: i32 = 0;
pub const SI_TKILL: i32 = -6;
pub const SEGV_MAPERR: i32 = 1;
pub const SEGV_ACCERR: i32 = 2;
pub const BUS_ADRALN: i32 = 1;
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub const ILL_ILLOPC: i32 = 1;
pub const TRAP_BRKPT: i32 = 1;
pub const FPE_FLTUNK: i32 = 14;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;

pub const fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

pub const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);
/// Delivered before other pending signals, as Linux does (SYNCHRONOUS_MASK).
const SYNCHRONOUS: u64 = bit(SIGSEGV) | bit(SIGBUS) | bit(SIGILL) | bit(SIGTRAP) | bit(SIGFPE) | bit(SIGSYS);
/// Signals whose default action is to do nothing: CHLD, URG, WINCH, and
/// CONT (whose continuing happens when it's sent, whatever its action).
const DEFAULT_IGNORED: u64 = bit(SIGCHLD) | bit(SIGCONT) | bit(23) | bit(28);
/// Signals whose default action stops the process.
pub const STOP_SIGNALS: u64 = bit(SIGSTOP) | bit(SIGTSTP) | bit(SIGTTIN) | bit(SIGTTOU);
/// Real-time signals queue every instance. Like Linux's RLIMIT_SIGPENDING,
/// one limit covers all queues (it bounds kernel memory).
const MAX_QUEUED_RT: u64 = 4096;
static QUEUED_RT: AtomicU64 = AtomicU64::new(0);

/// A synchronous fault: the address, and the syndrome the CPU gave (arm64's
/// ESR), which the signal frame may report.
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub addr: u64,
    pub pc: u64,
    pub syndrome: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct SigInfo {
    pub signo: u32,
    /// si_errno: 0 but for a seccomp filter's SIGSYS (its data).
    pub errno: i32,
    pub code: i32,
    /// The siginfo union from byte 16: pid and uid (kill), the address
    /// (faults), pid, uid and value (sigqueue).
    pub fields: [u64; 4],
    pub fault: Option<Fault>,
    /// The POSIX timer that sent it, so later expiries count as overruns.
    pub timer: Option<u32>,
    /// Why the signal was raised, reported if it ends the program.
    pub why: &'static str,
}

impl SigInfo {
    /// Sent by process `pid`: kill, tgkill, or the kernel on its behalf (SIGPIPE).
    pub fn sent(signo: u32, code: i32, pid: u32, uid: u32, why: &'static str) -> Self {
        SigInfo {
            signo,
            errno: 0,
            code,
            fields: [pid as u64 | (uid as u64) << 32, 0, 0, 0],
            fault: None,
            timer: None,
            why,
        }
    }

    /// A child ended, stopped or continued (usually SIGCHLD): its pid,
    /// uid, and exit code or signal, from wait4 status `status`.
    pub fn child(signo: u32, pid: u32, uid: u32, status: i32) -> Self {
        let (code, value) = match status & 0x7f {
            _ if status == 0xffff => (CLD_CONTINUED, SIGCONT as i32),
            0x7f => (CLD_STOPPED, (status >> 8) & 0xff),
            0 => (CLD_EXITED, (status >> 8) & 0xff),
            sig => (CLD_KILLED, sig),
        };
        let fields = [pid as u64 | (uid as u64) << 32, value as u32 as u64, 0, 0];
        SigInfo { signo, errno: 0, code, fields, fault: None, timer: None, why: "a child process ended" }
    }

    pub fn bytes(&self) -> [u8; 128] {
        let mut b = [0u8; 128];
        b[0..4].copy_from_slice(&self.signo.to_le_bytes());
        b[4..8].copy_from_slice(&self.errno.to_le_bytes());
        b[8..12].copy_from_slice(&self.code.to_le_bytes());
        for (i, w) in self.fields.iter().enumerate() {
            b[16 + i * 8..24 + i * 8].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}

/// Pending signals. A standard signal is pending at most once; real-time
/// signals queue each instance in order.
#[derive(Default)]
pub struct SigQueue {
    pub mask: u64,
    items: VecDeque<SigInfo>,
}

impl SigQueue {
    fn push(&mut self, info: SigInfo) -> Result<(), Errno> {
        let b = bit(info.signo);
        if info.signo < SIGRTMIN && self.mask & b != 0 {
            return Ok(());
        }
        if info.signo >= SIGRTMIN {
            if QUEUED_RT.load(Ordering::Relaxed) >= MAX_QUEUED_RT {
                crate::stats::hit(grix_abi::stats::Limit::QueuedSignals);
                return Err(EAGAIN);
            }
            QUEUED_RT.fetch_add(1, Ordering::Relaxed);
        }
        self.mask |= b;
        self.items.push_back(info);
        Ok(())
    }

    fn take(&mut self, sig: u32) -> Option<SigInfo> {
        let i = self.items.iter().position(|s| s.signo == sig)?;
        let info = self.items.remove(i);
        if sig >= SIGRTMIN {
            QUEUED_RT.fetch_sub(1, Ordering::Relaxed);
        }
        if !self.items.iter().any(|s| s.signo == sig) {
            self.mask &= !bit(sig);
        }
        info
    }

    fn timer_entry(&mut self, id: u32) -> Option<&mut SigInfo> {
        self.items.iter_mut().find(|s| s.timer == Some(id))
    }

    fn discard(&mut self, sig: u32) {
        let before = self.items.len();
        self.items.retain(|s| s.signo != sig);
        if sig >= SIGRTMIN {
            QUEUED_RT.fetch_sub((before - self.items.len()) as u64, Ordering::Relaxed);
        }
        self.mask &= !bit(sig);
    }
}

impl Drop for SigQueue {
    fn drop(&mut self) {
        let rt = self.items.iter().filter(|s| s.signo >= SIGRTMIN).count();
        QUEUED_RT.fetch_sub(rt as u64, Ordering::Relaxed);
    }
}

pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
pub const SS_AUTODISARM: u32 = 1 << 31;
use crate::arch::MINSIGSTKSZ;

/// A thread's sigaltstack.
#[derive(Clone, Copy, Debug)]
pub struct AltStack {
    pub sp: u64,
    pub size: u64,
    /// As the program set them (Linux's sas_ss_flags).
    pub flags: u32,
}

impl Default for AltStack {
    fn default() -> Self {
        AltStack { sp: 0, size: 0, flags: SS_DISABLE }
    }
}

impl AltStack {
    /// Linux's on_sig_stack: with SS_AUTODISARM we can only be on the stack
    /// if the program re-armed it while running on it, so assume we're not.
    pub fn contains(&self, sp: u64) -> bool {
        self.flags & SS_AUTODISARM == 0 && sp > self.sp && sp - self.sp <= self.size
    }

    /// The state sigaltstack reports (sas_ss_flags).
    pub fn state(&self, sp: u64) -> u32 {
        if self.size == 0 {
            SS_DISABLE
        } else if self.contains(sp) {
            SS_ONSTACK
        } else {
            0
        }
    }

    /// sigaltstack's set half (do_sigaltstack). `sp` is the thread's stack pointer.
    pub fn set(&mut self, new: AltStack, sp: u64) -> Result<(), Errno> {
        if self.contains(sp) {
            return Err(EPERM);
        }
        let mode = new.flags & !SS_AUTODISARM;
        if mode != SS_DISABLE && mode != SS_ONSTACK && mode != 0 {
            return Err(EINVAL);
        }
        *self = if mode == SS_DISABLE {
            AltStack { sp: 0, size: 0, flags: new.flags }
        } else if new.size < MINSIGSTKSZ {
            return Err(ENOMEM);
        } else {
            new
        };
        Ok(())
    }
}

pub fn is_ignored(act: &SigAction, sig: u32) -> bool {
    act.handler == SIG_IGN || (act.handler == SIG_DFL && DEFAULT_IGNORED & bit(sig) != 0)
}

/// The default action ends the program (Term or Core on Linux).
fn is_fatal(act: &SigAction, sig: u32) -> bool {
    act.handler == SIG_DFL && (DEFAULT_IGNORED | STOP_SIGNALS) & bit(sig) == 0
}

/// The default action stops the process.
fn is_stop(act: &SigAction, sig: u32) -> bool {
    act.handler == SIG_DFL && STOP_SIGNALS & bit(sig) != 0
}

/// Set when a process stops or continues: `procs::reap_others` tells the
/// parents (`Process::job_notice`).
pub static JOBS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Stop the process (a stop signal's default action, Linux's
/// do_signal_stop). Its threads stay where they are, runnable or waiting;
/// the scheduler passes it over until SIGCONT. Linux doesn't stop orphaned
/// process groups for SIGTSTP, SIGTTIN and SIGTTOU; here nothing is
/// orphaned (the host stands for the shell init was started from).
fn stop(p: &mut Process, sig: u32) {
    if p.stopped {
        return;
    }
    p.stopped = true;
    let status = 0x7f | (sig as i32) << 8;
    p.job_report = Some(JobReport::Stopped(sig));
    p.job_notice = Some(SigInfo::child(SIGCHLD, p.pid, p.uid, status));
    JOBS.store(true, Ordering::Relaxed);
    if p.pid == crate::process::INIT {
        crate::console::event(&grix_abi::wire::Event::Stopped { signal: sig });
    }
    // Off the CPUs: this one at its next scheduling point, the others now.
    if p.running {
        p.resched = true;
    }
    crate::smp::kick_others(p.pid);
    p.timer_dirty = true;
    // A parent's wait4 looks again.
    crate::ipc::changed();
}

/// SIGCONT was sent: whatever its action, pending stop signals go, and a
/// stopped process continues (Linux's prepare_signal).
fn resume(p: &mut Process) {
    for sig in [SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU] {
        p.shared_pending.discard(sig);
        for t in p.threads.values_mut() {
            t.pending.discard(sig);
        }
    }
    if !p.stopped {
        return;
    }
    p.stopped = false;
    p.job_report = Some(JobReport::Continued);
    p.job_notice = Some(SigInfo::child(SIGCHLD, p.pid, p.uid, 0xffff));
    JOBS.store(true, Ordering::Relaxed);
    if p.pid == crate::process::INIT {
        crate::console::event(&grix_abi::wire::Event::Continued);
    }
    p.timer_dirty = true;
    crate::ipc::changed();
}

/// Signals the thread won't take now. rt_sigtimedwait temporarily accepts the
/// ones it waits for (Linux swaps `blocked` and `real_blocked`).
fn effective_mask(t: &Thread) -> u64 {
    match t.wait {
        Some(Wait { on: WaitOn::SigWait(set), .. }) => t.sigmask & !set,
        _ => t.sigmask,
    }
}

/// Pending signal numbers in delivery order: synchronous faults first, then lowest first.
fn in_order(mask: u64) -> impl Iterator<Item = u32> {
    let sync = mask & SYNCHRONOUS;
    [sync, mask & !sync].into_iter().flat_map(|m| (0..64).filter(move |i| m & (1 << i) != 0).map(|i| i + 1))
}

/// Bumped whenever a signal is queued (signalfd's version for edge-triggered epoll).
static GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn generation() -> u64 {
    GENERATION.load(Ordering::Relaxed)
}

/// Signals pending for thread `tid`: its own and the process's.
pub fn pending_for(p: &Process, tid: u32) -> u64 {
    p.threads.get(&tid).map_or(0, |t| t.pending.mask) | p.shared_pending.mask
}

/// struct signalfd_siginfo for a dequeued signal.
pub fn signalfd_record(si: &SigInfo) -> [u8; 128] {
    let mut b = [0u8; 128];
    let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(0, &si.signo.to_le_bytes());
    put(4, &si.errno.to_le_bytes());
    put(8, &si.code.to_le_bytes());
    match (si.fault, si.timer) {
        (Some(f), _) => put(72, &f.addr.to_le_bytes()), // ssi_addr
        (None, Some(_)) => {
            put(24, &(si.fields[0] as u32).to_le_bytes()); // ssi_tid: the timer id
            put(32, &((si.fields[0] >> 32) as u32).to_le_bytes()); // ssi_overrun
            put(44, &(si.fields[1] as u32).to_le_bytes()); // ssi_int
            put(48, &si.fields[1].to_le_bytes()); // ssi_ptr
        }
        (None, None) => {
            put(12, &(si.fields[0] as u32).to_le_bytes()); // ssi_pid
            put(16, &((si.fields[0] >> 32) as u32).to_le_bytes()); // ssi_uid
            put(44, &(si.fields[1] as u32).to_le_bytes()); // ssi_int (sigqueue value)
            put(48, &si.fields[1].to_le_bytes()); // ssi_ptr
        }
    }
    b
}

/// The not-yet-delivered signal from POSIX timer `id`, wherever it is queued.
pub fn queued_timer_signal(p: &mut Process, id: u32) -> Option<&mut SigInfo> {
    if p.shared_pending.timer_entry(id).is_some() {
        return p.shared_pending.timer_entry(id);
    }
    p.threads.values_mut().find_map(|t| t.pending.timer_entry(id))
}

/// Discard pending instances of `sig` everywhere (its disposition became "ignore").
pub fn discard(p: &mut Process, sig: u32) {
    p.shared_pending.discard(sig);
    for t in p.threads.values_mut() {
        t.pending.discard(sig);
    }
    crate::timer::resync(p);
}

/// Where a signal goes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// kill: one thread that doesn't block it.
    Process,
    /// tgkill, faults, SIGPIPE.
    Thread(u32),
}

/// Raise a signal, as Linux's send_signal + complete_signal: drop it if it
/// would be ignored, end the program now if its default action is fatal,
/// otherwise queue it and wake the thread that should handle it.
pub fn send(p: &mut Process, target: Target, info: SigInfo) -> Result<(), Errno> {
    let sig = info.signo;
    let b = bit(sig);
    let act = p.action(sig);
    // Continuing and stopping cancel each other's pending signals.
    if sig == SIGCONT {
        resume(p);
    } else if STOP_SIGNALS & b != 0 {
        p.shared_pending.discard(SIGCONT);
        for t in p.threads.values_mut() {
            t.pending.discard(SIGCONT);
        }
    }
    let wants = |tid: u32| p.threads.get(&tid).is_some_and(|t| effective_mask(t) & b == 0);
    // Like complete_signal, try the thread kill() names (the main thread)
    // first, then the others.
    let receiver = match target {
        Target::Thread(tid) => Some(tid).filter(|&t| wants(t)),
        Target::Process => [p.pid, p.current].into_iter().chain(p.threads.keys().copied()).find(|&t| wants(t)),
    };
    // A thread in rt_sigtimedwait takes the signal without acting on it.
    let sigwaiter = receiver.is_some_and(|tid| p.threads[&tid].sigmask & b != 0);
    // Blocked signals are kept even if ignored: the disposition may change
    // before they are unblocked.
    if receiver.is_some() && !sigwaiter {
        if is_ignored(&act, sig) {
            return Ok(());
        }
        if is_fatal(&act, sig) {
            die(p, &info);
            return Ok(());
        }
        if is_stop(&act, sig) {
            stop(p, sig);
            return Ok(());
        }
    }
    // A process signal goes to the chosen thread's queue, so no other thread
    // takes it first (on Linux only the chosen one is told to look). If every
    // thread blocks it, it waits on the process for whoever unblocks it.
    let queued_on = receiver.or(match target {
        Target::Thread(tid) => Some(tid),
        Target::Process => None,
    });
    match queued_on {
        Some(tid) => p.threads.get_mut(&tid).ok_or(ESRCH)?.pending.push(info)?,
        None => p.shared_pending.push(info)?,
    }
    // A thread running on another CPU takes it when it next enters the
    // kernel: now, not at its next time slice (which a thread alone on
    // its CPU never ends). Go preempts goroutines this way.
    if let Some(tid) = queued_on {
        crate::smp::kick_thread(tid);
    }
    // signalfd readers (and epoll on them) look at pending signals. Waking
    // every I/O waiter is only worth it once a signalfd exists (Go sends
    // SIGURG every few milliseconds).
    GENERATION.fetch_add(1, Ordering::Relaxed);
    if p.uses_signalfd {
        crate::ipc::changed();
    }
    if let Some(tid) = receiver {
        notify(p, tid);
    }
    Ok(())
}

/// The kernel raises a signal at the calling thread (SIGPIPE).
pub fn raise(p: &mut Process, sig: u32, why: &'static str) {
    let info = SigInfo::sent(sig, SI_USER, p.pid, p.uid, why);
    let _ = send(p, Target::Thread(p.current), info);
}

/// A synchronous fault in user code. With a handler the signal is delivered
/// on the way back to EL0 with the faulting pc; if it is blocked or ignored
/// the program dies, as with Linux's force_sig_fault.
pub fn fault(p: &mut Process, sig: u32, code: i32, fault: Fault, why: &'static str) {
    let info =
        SigInfo { signo: sig, errno: 0, code, fields: [fault.addr, 0, 0, 0], fault: Some(fault), timer: None, why };
    force(p, info, fault.pc)
}

/// Force a synchronous signal on the calling thread (Linux's
/// force_sig_info with HANDLER_CURRENT): delivered on the way back to
/// user mode if it has a handler, else, or if it's blocked, the process
/// dies of it. `pc` is where, for the report.
pub fn force(p: &mut Process, info: SigInfo, pc: u64) {
    let sig = info.signo;
    let act = p.action(sig);
    let t = p.cur();
    if act.handler == SIG_DFL || act.handler == SIG_IGN || t.sigmask & bit(sig) != 0 {
        p.kill(sig, info.fault.map_or(0, |f| f.addr), pc, info.why, true);
        return;
    }
    t.pending.push(info).expect("standard signals always queue");
}

/// A signal's default action ends the process. Faults and signals the
/// kernel raised are reported (for the main program, everything is: its end
/// is the sandbox's), not one process signalling another.
fn die(p: &mut Process, info: &SigInfo) {
    let (addr, pc) = info.fault.map_or((0, 0), |f| (f.addr, f.pc));
    let report = info.fault.is_some() || info.code > 0;
    p.kill(info.signo, addr, pc, info.why, report)
}

// ---------------------------------------------------------------- interrupting blocked syscalls

/// The first pending signal that would run a handler or end the program
/// (ignored ones are skipped at delivery), in `return_to_user`'s order.
fn acting_signal(p: &Process, t: &Thread) -> Option<u32> {
    let blocked = t.sigmask;
    let acts = |sig: &u32| !is_ignored(&p.action(*sig), *sig);
    in_order(t.pending.mask & !blocked).find(acts).or_else(|| in_order(p.shared_pending.mask & !blocked).find(acts))
}

/// Linux's restartable syscalls (-ERESTARTSYS): they re-execute after an
/// `SA_RESTART` handler. Waits with timeouts, poll/select/epoll and sleeps
/// always fail with EINTR instead (see signal(7)).
fn restartable(regs: &TrapFrame) -> bool {
    match regs.syscall_nr() as u32 {
        nr::read | nr::readv | nr::write | nr::writev | nr::pread64 | nr::pwrite64 | nr::preadv | nr::pwritev => true,
        nr::recvfrom | nr::recvmsg | nr::sendto | nr::sendmsg | nr::openat | nr::flock | nr::getrandom => true,
        nr::sendmmsg => true,
        // recvmmsg with a timeout is EINTR, as the other timed waits.
        nr::recvmmsg => regs.arg(4) == 0,
        nr::wait4 | nr::waitid => true,
        // x86_64's older calls keep their own numbers (`syscall::x86`).
        #[cfg(target_arch = "x86_64")]
        nr::open | nr::creat => true,
        // F_SETLKW and F_OFD_SETLKW.
        nr::fcntl => matches!(regs.arg(1), 7 | 38),
        // FUTEX_WAIT / FUTEX_WAIT_BITSET without a timeout.
        nr::futex => matches!(regs.arg(1) & 127, 0 | 9) && regs.arg(3) == 0,
        _ => false,
    }
}

/// Should a pending signal end thread `t`'s wait?
fn should_wake(p: &Process, t: &Thread) -> bool {
    match t.wait {
        None => false,
        // The parent of a vfork child takes its signals once the child execs or exits.
        Some(Wait { on: WaitOn::Vfork, .. }) => false,
        // rt_sigtimedwait re-runs and dequeues it.
        Some(Wait { on: WaitOn::SigWait(set), .. }) if (t.pending.mask | p.shared_pending.mask) & set != 0 => true,
        Some(_) => acting_signal(p, t).is_some(),
    }
}

/// A signal was queued for thread `tid`: if it is blocked in a syscall that
/// the signal should interrupt, rewind it to the `svc`. Whether the call then
/// fails with EINTR or re-runs is decided when the handler is delivered.
fn notify(p: &mut Process, tid: u32) {
    if !p.threads.get(&tid).is_some_and(|t| should_wake(p, t)) {
        return;
    }
    p.cancel_wait(tid);
    let t = p.threads.get_mut(&tid).unwrap();
    t.regs.rewind_syscall();
    t.restarting = true;
    t.recheck = true;
    p.runq.push_back(tid);
}

/// The calling thread's syscall is about to block. If a signal is already
/// deliverable (a mask-changing wait like rt_sigsuspend unblocked it), don't
/// sleep: rewind to the `svc` as `notify` would. Returns whether it did.
pub fn interrupt_self(p: &mut Process, tf: &mut TrapFrame) -> bool {
    let tid = p.current;
    if !p.threads.get(&tid).is_some_and(|t| should_wake(p, t)) {
        return false; // no signal, or the thread exited
    }
    p.cancel_wait(tid);
    tf.rewind_syscall();
    p.cur().restarting = true;
    true
}

/// A handler is about to run for a thread whose syscall was rewound to its
/// `svc`: fail the syscall with EINTR unless the handler has `SA_RESTART`
/// and the call is restartable (Linux's -ERESTARTSYS handling in do_signal).
fn interrupt_syscall(a: &mut AddressSpace, t: &mut Thread, tf: &mut TrapFrame, act: &SigAction) {
    // A write that got some data out returns that much, restart or not.
    let done = core::mem::take(&mut t.io_done);
    if done > 0 {
        tf.skip_syscall();
        tf.set_return(done);
        return;
    }
    if act.flags & SA_RESTART != 0 && restartable(tf) {
        return;
    }
    // nanosleep and relative clock_nanosleep report the time left.
    let rem = match tf.syscall_nr() as u32 {
        nr::nanosleep => tf.arg(1),
        nr::clock_nanosleep if tf.arg(1) & 1 == 0 => tf.arg(3),
        _ => 0,
    };
    if rem != 0
        && let Some(d) = t.restart_deadline
    {
        let _ = write_timespec(a, rem, d.saturating_sub(time::monotonic_ns()));
    }
    tf.skip_syscall();
    tf.set_return((-(EINTR.0 as i64)) as u64);
}

// ---------------------------------------------------------------- delivery

/// How many handler frames to push per return to user space. More pending
/// signals are delivered at the next kernel exit (rt_sigreturn at the latest).
const MAX_FRAMES: usize = 8;

/// Deliver the current thread's pending signals before it returns to EL0.
/// A process that has ended (or ends now, from a signal) never returns:
/// something else runs instead, and gets its signals.
pub fn return_to_user(tf: &mut TrapFrame) {
    let mut guard = crate::process::running().lock();
    loop {
        let Some(p) = guard.as_mut() else { return };
        if (p.exit_status.is_some() || p.stopped) && p.running {
            crate::sched::schedule(&mut guard, tf);
        }
        // Nothing to run here now: `smp::finish` waits for something.
        let Some(p) = guard.as_mut().filter(|p| p.running) else { return };
        deliver(p, tf);
        if p.exit_status.is_none() && !p.stopped {
            // A timer whose signal was just taken re-arms.
            crate::sched::update_timer(p);
            return;
        }
    }
}

fn deliver(p: &mut Process, tf: &mut TrapFrame) {
    let tid = p.current;
    // A woken syscall gets to see whether it can complete first (see
    // `Thread::recheck`); signals wait for its next return to user space.
    // It stays `restarting` until the svc actually runs again: an interrupt
    // may come first, and then the signal decides as usual.
    if let Some(t) = p.threads.get_mut(&tid)
        && core::mem::take(&mut t.recheck)
    {
        return;
    }
    let mut frames = 0;
    while frames < MAX_FRAMES {
        let Some(t) = p.threads.get_mut(&tid) else { return };
        let blocked = t.sigmask;
        let info = match in_order(t.pending.mask & !blocked).next() {
            Some(sig) => t.pending.take(sig),
            None => in_order(p.shared_pending.mask & !blocked).next().and_then(|sig| p.shared_pending.take(sig)),
        };
        let Some(mut info) = info else {
            // A mask-changing wait ended without running a handler: restore
            // the mask (unless the wait is being re-run) and look again.
            if !t.restarting
                && let Some(mask) = t.saved_sigmask.take()
            {
                t.sigmask = mask;
                continue;
            }
            break;
        };
        if crate::timer::delivered(p, &mut info) {
            p.timer_dirty = true;
        }
        let act = p.action(info.signo);
        if is_ignored(&act, info.signo) {
            continue;
        }
        if is_fatal(&act, info.signo) {
            die(p, &info);
            return;
        }
        // Back at the syscall it was in (if any) when it continues.
        if is_stop(&act, info.signo) {
            stop(p, info.signo);
            return;
        }
        let Some(t) = p.threads.get_mut(&tid) else { return };
        if core::mem::take(&mut t.restarting) {
            interrupt_syscall(&mut p.aspace, t, tf, &act);
        }
        // A FIFO open it waited in is interrupted: its end goes (a
        // restart opens afresh).
        t.fifo_wait = None;
        if push_frame(p, tf, &info, &act).is_err() {
            // Linux's force_sigsegv: a signal that can't be delivered ends the program.
            let why = "no room for a signal frame (stack overflow or bad sigaltstack)";
            p.kill(SIGSEGV, tf.sp(), tf.pc(), why, true);
            return;
        }
        frames += 1;
    }
    // Without a handler, a rewound syscall simply runs again (with its
    // original deadline, see `Process::block`). It stays `restarting` until
    // it does: an interrupt pending as it returns to user mode brings it
    // back here first, perhaps with a signal, which must still end the call
    // as above. A handler run over the rewound call unawares would have it
    // start again afterwards, a write sending again what it had already
    // sent (`Thread::io_done`).
}

/// Build a signal frame for `info` and redirect `tf` to the handler
/// (Linux's setup_rt_frame and setup_return).
fn push_frame(p: &mut Process, tf: &mut TrapFrame, info: &SigInfo, act: &SigAction) -> Result<(), Errno> {
    let sig = info.signo;
    let t = p.threads.get_mut(&p.current).unwrap();
    let sp = tf.sp();
    let alt = t.altstack;
    let top = if act.flags & SA_ONSTACK != 0 && alt.state(sp) == 0 { alt.sp.wrapping_add(alt.size) } else { sp };
    let restorer = if act.flags & SA_RESTORER != 0 { act.restorer } else { SIGPAGE };
    let ctx = arch::sigframe::Context {
        info: info.bytes(),
        stack: (alt.sp, alt.flags, alt.size),
        mask: t.saved_sigmask.unwrap_or(t.sigmask),
        fault: info.fault,
        restorer,
    };
    let frame = arch::sigframe::push_frame(&mut p.aspace, tf, top, &ctx)?;

    let t = p.threads.get_mut(&p.current).unwrap();
    t.saved_sigmask = None;
    // The handler's own blocking calls must not inherit the interrupted call's timeout.
    t.restart_deadline = None;
    if alt.flags & SS_AUTODISARM != 0 {
        t.altstack = AltStack::default();
    }
    let mut mask = t.sigmask | act.mask;
    if act.flags & SA_NODEFER == 0 {
        mask |= bit(sig);
    }
    t.sigmask = mask & !UNBLOCKABLE;
    if act.flags & SA_RESETHAND != 0 {
        p.sigactions.update(|a| a[sig as usize].handler = SIG_DFL);
    }
    arch::sigframe::enter_handler(tf, frame, sig, act.handler, restorer, act.flags & SA_SIGINFO != 0);
    Ok(())
}

/// rt_sigreturn: restore the context saved in the frame at sp. A frame that
/// fails Linux's checks (including any attempt to return to a privileged
/// mode) ends the program with SIGSEGV.
pub fn sigreturn(p: &mut Process, tf: &mut TrapFrame) -> SysResult {
    let Ok((mask, (sp, flags, size))) = arch::sigframe::sigreturn(&mut p.aspace, tf) else {
        p.kill(SIGSEGV, tf.sp(), tf.pc(), "rt_sigreturn with a corrupt signal frame", true);
        return Err(EBLOCKED);
    };
    let t = p.cur();
    t.sigmask = mask & !UNBLOCKABLE;
    // Like Linux's restore_altstack, errors other than EFAULT are ignored.
    let _ = t.altstack.set(AltStack { sp, flags, size }, tf.sp());
    Ok(tf.return_value())
}

// ---------------------------------------------------------------- for syscalls

/// rt_sigtimedwait: take a pending signal in `set` (thread-directed first).
pub fn dequeue(p: &mut Process, set: u64) -> Option<SigInfo> {
    let t = p.cur();
    let info = match in_order(t.pending.mask & set).next() {
        Some(sig) => t.pending.take(sig),
        None => in_order(p.shared_pending.mask & set).next().and_then(|sig| p.shared_pending.take(sig)),
    }?;
    let mut info = info;
    if crate::timer::delivered(p, &mut info) {
        p.timer_dirty = true;
    }
    Some(info)
}

/// Use `mask` until the current syscall finishes or a handler it was
/// interrupted for returns (rt_sigsuspend, ppoll, pselect6, epoll_pwait).
/// A restarted syscall calls this again, so the first saved mask is kept.
pub fn mask_while_waiting(p: &mut Process, mask: u64) {
    let t = p.cur();
    t.saved_sigmask.get_or_insert(t.sigmask);
    t.sigmask = mask & !UNBLOCKABLE;
}

/// After a syscall that didn't fail with EINTR: undo `mask_while_waiting`.
pub fn syscall_done(p: &mut Process, interrupted: bool) {
    if let Some(t) = p.threads.get_mut(&p.current)
        && !interrupted
        && let Some(mask) = t.saved_sigmask.take()
    {
        t.sigmask = mask;
    }
}
