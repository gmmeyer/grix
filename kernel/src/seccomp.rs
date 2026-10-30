//! seccomp: filters a program installs to restrict itself (seccomp(2),
//! prctl(PR_SET_SECCOMP)), as Linux's kernel/seccomp.c does them.
//!
//! grix's own gates (`syscall::table`, then `syscall::require` in the
//! handlers) come first and decide what the policy denies: a call the
//! policy refuses is denied (and reported) whatever a filter says. A
//! filter runs only on calls the policy allows, and can only take more
//! away (fail them, signal, kill), never give anything back, so it can't
//! weaken the policy. What it refuses is the program's own choice, not a
//! denial: nothing is reported, except a kill (a `Fault` event, as any
//! fatal signal the kernel raises).
//!
//! State is per thread (`Thread::seccomp`), as on Linux: the mode, the
//! newest filter (each holds the one before it: a stack shared by every
//! thread and process that inherited it, so fork and clone share it
//! rather than copy it), and no_new_privs. execve keeps all three.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::errno::*;
use crate::kmem::Charge;
use crate::process::Process;
use crate::signal::{self, SigInfo};
use crate::syscall::table::nr;
use crate::uaccess::*;

pub const MODE_DISABLED: u8 = 0;
pub const MODE_STRICT: u8 = 1;
pub const MODE_FILTER: u8 = 2;

// seccomp(2)'s operations and flags (include/uapi/linux/seccomp.h).
const SET_MODE_STRICT: u64 = 0;
const SET_MODE_FILTER: u64 = 1;
const GET_ACTION_AVAIL: u64 = 2;
const GET_NOTIF_SIZES: u64 = 3;
const FLAG_TSYNC: u64 = 1;
const FLAG_LOG: u64 = 2;
const FLAG_SPEC_ALLOW: u64 = 4;
const FLAG_NEW_LISTENER: u64 = 8;
const FLAG_TSYNC_ESRCH: u64 = 16;
const FLAG_WAIT_KILLABLE_RECV: u64 = 32;
const FLAG_MASK: u64 =
    FLAG_TSYNC | FLAG_LOG | FLAG_SPEC_ALLOW | FLAG_NEW_LISTENER | FLAG_TSYNC_ESRCH | FLAG_WAIT_KILLABLE_RECV;

// Return actions, in order of precedence (the lowest as an s32 wins).
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_KILL_THREAD: u32 = 0;
pub const RET_TRAP: u32 = 0x0003_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const RET_TRACE: u32 = 0x7ff0_0000;
pub const RET_LOG: u32 = 0x7ffc_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ACTION_FULL: u32 = 0xffff_0000;
const RET_DATA: u32 = 0x0000_ffff;
const MAX_ERRNO: u32 = 4095;

/// SIGSYS's si_code for a filter's SECCOMP_RET_TRAP.
const SYS_SECCOMP: i32 = 1;

/// Linux's BPF_MAXINSNS: the longest program.
const MAX_INSNS: usize = 4096;
/// Linux's MAX_INSNS_PER_PATH: the instructions one call may run through
/// all of a thread's filters, each counting 4 more.
const MAX_INSNS_PER_PATH: usize = (1 << 18) / 8;
/// Filters alive in every process together, and their instructions: a
/// program can fork and install filters in each child, so the bound is
/// global (each also charges its memory to `kmem`).
const MAX_FILTERS: usize = 1024;
const MAX_INSNS_TOTAL: usize = 64 * 1024;
static FILTERS: AtomicUsize = AtomicUsize::new(0);
static INSNS_TOTAL: AtomicUsize = AtomicUsize::new(0);

/// What the filters see (struct seccomp_data): the call's number, the
/// architecture, the pc after the call, and its six arguments.
const DATA_LEN: u32 = 64;

#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xc000_00b7; // EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xc000_003e; // EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE

/// What strict mode allows (Linux's mode1_syscalls).
const STRICT_ALLOWED: [u32; 4] = [nr::read, nr::write, nr::exit, nr::rt_sigreturn];

/// A thread's seccomp state.
#[derive(Clone, Default)]
pub struct State {
    pub mode: u8,
    /// The newest filter; it holds the ones installed before it.
    pub filter: Option<Arc<Filter>>,
    /// PR_SET_NO_NEW_PRIVS: once set, never cleared, and inherited.
    pub no_new_privs: bool,
}

impl State {
    /// How many filters (/proc/<pid>/status's Seccomp_filters).
    pub fn filters(&self) -> usize {
        core::iter::successors(self.filter.as_deref(), |f| f.prev.as_deref()).count()
    }
}

#[derive(Clone, Copy)]
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

pub struct Filter {
    insns: Vec<Insn>,
    prev: Option<Arc<Filter>>,
    _charge: Charge,
}

impl Drop for Filter {
    fn drop(&mut self) {
        FILTERS.fetch_sub(1, Ordering::Relaxed);
        INSNS_TOTAL.fetch_sub(self.insns.len(), Ordering::Relaxed);
        // The filters before it go too unless someone else holds them: one
        // at a time, not recursively (a stack may be thousands deep).
        let mut next = self.prev.take();
        while let Some(f) = next {
            match Arc::try_unwrap(f) {
                Ok(mut f) => next = f.prev.take(),
                Err(_) => break,
            }
        }
    }
}

impl Filter {
    /// Take the budget for a program of `len` instructions.
    fn new(insns: Vec<Insn>) -> Result<Filter, Errno> {
        let len = insns.len();
        if FILTERS.load(Ordering::Relaxed) >= MAX_FILTERS || INSNS_TOTAL.load(Ordering::Relaxed) + len > MAX_INSNS_TOTAL
        {
            crate::stats::hit(grix_abi::stats::Limit::KernelMemory);
            return Err(ENOMEM);
        }
        let charge = Charge::new((len * core::mem::size_of::<Insn>() + core::mem::size_of::<Filter>()) as u64)?;
        // Under the kernel lock: check-then-add doesn't race.
        FILTERS.fetch_add(1, Ordering::Relaxed);
        INSNS_TOTAL.fetch_add(len, Ordering::Relaxed);
        Ok(Filter { insns, prev: None, _charge: charge })
    }
}

// Classic BPF (include/uapi/linux/filter.h, bpf_common.h).
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;
const W: u16 = 0x00;
const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const MEM: u16 = 0x60;
const LEN: u16 = 0x80;
const K: u16 = 0x00;
const X: u16 = 0x08;
const A: u16 = 0x10;
const ADD: u16 = 0x00;
const SUB: u16 = 0x10;
const MUL: u16 = 0x20;
const DIV: u16 = 0x30;
const OR: u16 = 0x40;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const RSH: u16 = 0x70;
const NEG: u16 = 0x80;
const XOR: u16 = 0xa0;
const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JGT: u16 = 0x20;
const JGE: u16 = 0x30;
const JSET: u16 = 0x40;
const TAX: u16 = 0x00;
const TXA: u16 = 0x80;
/// Scratch memory words (BPF_MEMWORDS).
const MEMWORDS: u32 = 16;

/// Check a program as Linux's bpf_check_classic and seccomp_check_filter
/// do, rewriting the length loads to the constant they are: only the
/// instructions seccomp allows, loads of whole aligned words of
/// seccomp_data, jumps forward and inside the program, scratch memory
/// written before it's read on every path, and a return at the end. Any
/// failure is EINVAL.
fn check(insns: &mut [Insn]) -> Result<(), Errno> {
    let len = insns.len();
    for (pc, i) in insns.iter_mut().enumerate() {
        let (code, k) = (i.code, i.k);
        match code {
            c if c == LD | W | ABS => {
                if k >= DATA_LEN || k & 3 != 0 {
                    return Err(EINVAL);
                }
            }
            c if c == LD | W | LEN => *i = Insn { code: LD | IMM, jt: 0, jf: 0, k: DATA_LEN },
            c if c == LDX | W | LEN => *i = Insn { code: LDX | IMM, jt: 0, jf: 0, k: DATA_LEN },
            c if c == RET | K || c == RET | A => {}
            c if c == ALU | NEG => {}
            c if c & 7 == ALU && c & !(0xf0 | X) == ALU => match c & 0xf0 {
                ADD | SUB | MUL | AND | OR | XOR => {}
                DIV if c & X != 0 || k != 0 => {}
                LSH | RSH if c & X != 0 || k < 32 => {}
                _ => return Err(EINVAL),
            },
            c if c == LD | IMM || c == LDX | IMM || c == MISC | TAX || c == MISC | TXA => {}
            c if c == LD | MEM || c == LDX | MEM || c == ST || c == STX => {
                if k >= MEMWORDS {
                    return Err(EINVAL);
                }
            }
            c if c == JMP | JA => {
                if k as usize >= len - pc - 1 {
                    return Err(EINVAL);
                }
            }
            c if c & 7 == JMP && matches!(c & 0xf0, JEQ | JGT | JGE | JSET) && c & !(0xf0 | X) == JMP => {
                if pc + i.jt as usize + 1 >= len || pc + i.jf as usize + 1 >= len {
                    return Err(EINVAL);
                }
            }
            _ => return Err(EINVAL),
        }
    }
    if !matches!(insns[len - 1].code, c if c == RET | K || c == RET | A) {
        return Err(EINVAL);
    }
    // Linux's check_load_and_stores: scratch words valid on every path in.
    let mut masks = alloc::vec![0xffffu16; len];
    let mut valid = 0u16;
    for pc in 0..len {
        valid &= masks[pc];
        let i = insns[pc];
        match i.code {
            c if c == ST || c == STX => valid |= 1 << i.k,
            c if c == LD | MEM || c == LDX | MEM => {
                if valid & (1 << i.k) == 0 {
                    return Err(EINVAL);
                }
            }
            c if c == JMP | JA => {
                masks[pc + 1 + i.k as usize] &= valid;
                valid = !0;
            }
            c if c & 7 == JMP => {
                masks[pc + 1 + i.jt as usize] &= valid;
                masks[pc + 1 + i.jf as usize] &= valid;
                valid = !0;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Run a checked program over `data` (seccomp_data as words). Every jump
/// goes forward and the last instruction returns, so it ends within the
/// program's length.
fn run(insns: &[Insn], data: &[u32; 16]) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut m = [0u32; MEMWORDS as usize];
    let mut pc = 0;
    while let Some(&i) = insns.get(pc) {
        pc += 1;
        let k = i.k;
        match i.code & 7 {
            LD => match i.code {
                c if c == LD | W | ABS => a = data[(k / 4) as usize],
                c if c == LD | MEM => a = m[k as usize],
                _ => a = k,
            },
            LDX => x = if i.code == LDX | MEM { m[k as usize] } else { k },
            ST => m[k as usize] = a,
            STX => m[k as usize] = x,
            ALU => {
                let v = if i.code & X != 0 { x } else { k };
                a = match i.code & 0xf0 {
                    ADD => a.wrapping_add(v),
                    SUB => a.wrapping_sub(v),
                    MUL => a.wrapping_mul(v),
                    // Classic BPF's division by zero ends the program with 0.
                    DIV if v == 0 => return 0,
                    DIV => a / v,
                    OR => a | v,
                    AND => a & v,
                    XOR => a ^ v,
                    // As Linux runs it (eBPF's 32-bit shifts take the count mod 32).
                    LSH => a.wrapping_shl(v),
                    RSH => a.wrapping_shr(v),
                    _ => a.wrapping_neg(), // NEG
                };
            }
            JMP => {
                let v = if i.code & X != 0 { x } else { k };
                let taken = match i.code & 0xf0 {
                    JA => {
                        pc += k as usize;
                        continue;
                    }
                    JEQ => a == v,
                    JGT => a > v,
                    JGE => a >= v,
                    _ => a & v != 0, // JSET
                };
                pc += if taken { i.jt } else { i.jf } as usize;
            }
            RET => return if i.code == RET | A { a } else { k },
            _ if i.code == MISC | TAX => x = a,
            _ => a = x, // MISC | TXA
        }
    }
    0
}

/// What a call does, its filters having run.
pub enum Verdict {
    Allow,
    /// It doesn't run; this is its result (ERRNO, TRACE without a tracer).
    Return(SysResult),
    /// It doesn't run, its registers are left as they were, and SIGSYS is
    /// forced on the thread (TRAP).
    Trap,
    /// The thread ends with this signal (KILL_THREAD with SIGSYS; strict
    /// mode with SIGKILL), or the process if it's the last one.
    KillThread(u32),
    KillProcess,
}

/// Linux's ACTION_ONLY: the action as an s32, the smaller winning.
fn precedence(ret: u32) -> i32 {
    (ret & RET_ACTION_FULL) as i32
}

/// The verdict on call `n` with arguments `a`, at `pc` (after the
/// instruction), for the calling thread (Linux's __secure_computing).
pub fn verdict(p: &mut Process, n: u32, a: [u64; 6], pc: u64) -> Verdict {
    let t = p.cur();
    match t.seccomp.mode {
        MODE_DISABLED => return Verdict::Allow,
        MODE_STRICT if STRICT_ALLOWED.contains(&n) => return Verdict::Allow,
        MODE_STRICT => {
            crate::console::klog!("seccomp: strict mode killed thread {} at syscall {n}\n", t.tid);
            return Verdict::KillThread(signal::SIGKILL);
        }
        _ => {}
    }
    let mut data = [0u32; 16];
    data[0] = n;
    data[1] = AUDIT_ARCH;
    data[2] = pc as u32;
    data[3] = (pc >> 32) as u32;
    for (i, v) in a.iter().enumerate() {
        data[4 + 2 * i] = *v as u32;
        data[5 + 2 * i] = (*v >> 32) as u32;
    }
    // Newest first; a tie goes to the newer filter.
    let mut ret = RET_ALLOW;
    let mut f = t.seccomp.filter.as_deref();
    while let Some(filter) = f {
        let r = run(&filter.insns, &data);
        if precedence(r) < precedence(ret) {
            ret = r;
        }
        f = filter.prev.as_deref();
    }
    let value = ret & RET_DATA;
    match ret & RET_ACTION_FULL {
        RET_ALLOW | RET_LOG => Verdict::Allow,
        RET_ERRNO => match value.min(MAX_ERRNO) {
            0 => Verdict::Return(Ok(0)),
            e => Verdict::Return(Err(Errno(e))),
        },
        // No tracer, and no listener (user notification is unimplemented:
        // no filter can have one), are ENOSYS, as on Linux.
        RET_TRACE | RET_USER_NOTIF => Verdict::Return(Err(ENOSYS)),
        RET_TRAP => {
            // si_call_addr, then si_syscall and si_arch; si_errno is the
            // filter's data. The registers are the call's own (Linux's
            // syscall_rollback), as nothing has changed them.
            let fields = [pc, n as u64 | (AUDIT_ARCH as u64) << 32, 0, 0];
            let info = SigInfo {
                signo: signal::SIGSYS,
                errno: value as i32,
                code: SYS_SECCOMP,
                fields,
                fault: None,
                timer: None,
                why: "SIGSYS from its seccomp filter (SECCOMP_RET_TRAP), blocked or ignored",
            };
            signal::force(p, info, pc);
            Verdict::Trap
        }
        RET_KILL_THREAD => {
            crate::console::klog!("seccomp: filter killed thread {} at syscall {n}\n", p.current);
            Verdict::KillThread(signal::SIGSYS)
        }
        // KILL_PROCESS, and anything unknown (Linux's default case).
        _ => Verdict::KillProcess,
    }
}

/// seccomp(2).
pub fn seccomp(p: &mut Process, op: u64, flags: u64, uargs: u64) -> SysResult {
    match op {
        SET_MODE_STRICT if flags != 0 || uargs != 0 => Err(EINVAL),
        SET_MODE_STRICT => set_strict(p),
        SET_MODE_FILTER => set_filter(p, flags, uargs),
        GET_ACTION_AVAIL if flags != 0 => Err(EINVAL),
        GET_ACTION_AVAIL => match read_u32(&mut p.aspace, uargs)? {
            RET_KILL_PROCESS | RET_KILL_THREAD | RET_TRAP | RET_ERRNO | RET_TRACE | RET_LOG | RET_ALLOW => Ok(0),
            // As a kernel before 5.0, which had no user notification.
            RET_USER_NOTIF => p.unimplemented(nr::seccomp, "seccomp", "SECCOMP_RET_USER_NOTIF", EOPNOTSUPP),
            _ => Err(EOPNOTSUPP),
        },
        GET_NOTIF_SIZES => p.unimplemented(nr::seccomp, "seccomp", "SECCOMP_GET_NOTIF_SIZES", EINVAL),
        _ => Err(EINVAL),
    }
}

/// prctl(PR_SET_SECCOMP, mode, filter).
pub fn prctl_set(p: &mut Process, mode: u64, filter: u64) -> SysResult {
    match mode {
        // Linux ignores the third argument here.
        1 => set_strict(p),
        2 => set_filter(p, 0, filter),
        _ => Err(EINVAL),
    }
}

fn may_assign(p: &mut Process, mode: u8) -> bool {
    let cur = p.cur().seccomp.mode;
    cur == MODE_DISABLED || cur == mode
}

/// Only read, write, exit and rt_sigreturn from now on. (Linux also makes
/// x86_64's rdtsc fault; here the counter stays readable.)
fn set_strict(p: &mut Process) -> SysResult {
    // Fast calls go through the filters from now (`fast::calls_allowed`).
    crate::fast::changed();
    if !may_assign(p, MODE_STRICT) {
        return Err(EINVAL);
    }
    p.cur().seccomp.mode = MODE_STRICT;
    Ok(0)
}

/// SECCOMP_SET_MODE_FILTER (seccomp_set_mode_filter).
fn set_filter(p: &mut Process, flags: u64, uargs: u64) -> SysResult {
    // Fast calls go through the filters from now, every thread's with
    // TSYNC (`fast::calls_allowed`).
    crate::fast::changed();
    if flags & !FLAG_MASK != 0 {
        return Err(EINVAL);
    }
    if flags & FLAG_TSYNC != 0 && flags & FLAG_NEW_LISTENER != 0 && flags & FLAG_TSYNC_ESRCH == 0 {
        return Err(EINVAL);
    }
    if flags & FLAG_WAIT_KILLABLE_RECV != 0 && flags & FLAG_NEW_LISTENER == 0 {
        return Err(EINVAL);
    }
    // A listener's descriptor would hand each filtered call to a
    // supervisor: unimplemented, and refused as a kernel before 5.0
    // refuses the flag.
    if flags & FLAG_NEW_LISTENER != 0 {
        return p.unimplemented(nr::seccomp, "seccomp", "SECCOMP_FILTER_FLAG_NEW_LISTENER", EINVAL);
    }
    // struct sock_fprog { unsigned short len; struct sock_filter *filter; }
    let len = read_u64(&mut p.aspace, uargs)? as u16 as usize;
    let ptr = read_u64(&mut p.aspace, uargs.checked_add(8).ok_or(EFAULT)?)?;
    if len == 0 || len > MAX_INSNS {
        return Err(EINVAL);
    }
    // Without no_new_privs, Linux wants CAP_SYS_ADMIN. Root has that here
    // as it would outside a container: a filter only ever takes away, and
    // nothing honours setuid bits, so this is all the check guards.
    if !p.cur().seccomp.no_new_privs && p.uid != 0 {
        return Err(EACCES);
    }
    let mut raw = alloc::vec![0u8; len * 8];
    copy_in(&mut p.aspace, ptr, &mut raw)?;
    let mut insns: Vec<Insn> = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|b| Insn {
            code: u16::from_le_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
        .collect();
    check(&mut insns)?;
    let mut filter = Filter::new(insns)?;
    if !may_assign(p, MODE_FILTER) {
        return Err(EINVAL);
    }
    let caller = p.current;
    let prev = p.cur().seccomp.filter.clone();
    let path: usize = core::iter::successors(prev.as_deref(), |f| f.prev.as_deref()).map(|f| f.insns.len() + 4).sum();
    if filter.insns.len() + path > MAX_INSNS_PER_PATH {
        return Err(ENOMEM);
    }
    if flags & FLAG_TSYNC != 0 {
        // Every other thread must be unfiltered, or have filters this
        // thread's descend from (seccomp_can_sync_threads): else the call
        // fails with that thread's id.
        for (&tid, t) in &p.threads {
            let ok = tid == caller
                || t.seccomp.mode == MODE_DISABLED
                || (t.seccomp.mode == MODE_FILTER && is_ancestor(t.seccomp.filter.as_ref(), prev.as_ref()));
            if !ok {
                return if flags & FLAG_TSYNC_ESRCH != 0 { Err(ESRCH) } else { Ok(tid as u64) };
            }
        }
    }
    filter.prev = prev;
    let filter = Arc::new(filter);
    let t = p.cur();
    t.seccomp.filter = Some(filter.clone());
    t.seccomp.mode = MODE_FILTER;
    let nnp = t.seccomp.no_new_privs;
    if flags & FLAG_TSYNC != 0 {
        // seccomp_sync_threads: the same stack everywhere, and
        // no_new_privs with it. Threads running on other CPUs are in user
        // mode (this CPU has the kernel), and see it at their next call.
        for t in p.threads.values_mut() {
            t.seccomp.filter = Some(filter.clone());
            t.seccomp.mode = MODE_FILTER;
            t.seccomp.no_new_privs |= nnp;
        }
    }
    Ok(0)
}

/// Is `parent` (None: no filter) `child` or one of the filters under it?
fn is_ancestor(parent: Option<&Arc<Filter>>, child: Option<&Arc<Filter>>) -> bool {
    let Some(parent) = parent else { return true };
    let mut f = child;
    while let Some(c) = f {
        if Arc::ptr_eq(c, parent) {
            return true;
        }
        f = c.prev.as_ref();
    }
    false
}
