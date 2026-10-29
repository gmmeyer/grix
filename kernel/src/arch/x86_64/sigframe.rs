//! Linux's x86_64 signal frame (arch/x86/kernel/signal_64.c):
//! `struct rt_sigframe { char *pretcode; ucontext uc; siginfo info; }`, the
//! kernel's ucontext (an 8-byte sigset), and the FP state (fxsave's 512
//! bytes, 64-byte aligned) above it, which `sigcontext.fpstate` points at.

use alloc::vec;

use super::{FpState, TrapFrame, USER_CS, USER_RFLAGS, USER_SS};
use crate::errno::*;
use crate::mm::aspace::AddressSpace;
use crate::signal::Fault;
use crate::uaccess::{copy_in, copy_out};

// Offsets from the frame's start.
const PRETCODE: usize = 0;
const UC: usize = 8;
const UC_FLAGS: usize = UC;
const UC_STACK: usize = UC + 16;
/// struct sigcontext_64.
const MC: usize = UC + 40;
const MC_REGS: usize = MC; // r8..r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags
const MC_SEGS: usize = MC + 144; // cs, gs, fs, ss (u16s)
const MC_ERR: usize = MC + 152;
const MC_TRAPNO: usize = MC + 160;
const MC_OLDMASK: usize = MC + 168;
const MC_CR2: usize = MC + 176;
const MC_FPSTATE: usize = MC + 184;
const UC_SIGMASK: usize = MC + 256;
const INFO: usize = UC_SIGMASK + 8;
const FRAME_SIZE: usize = INFO + 128;
const _: () = assert!(FRAME_SIZE == 440);

const FP_SIZE: u64 = 512;
/// Below the stack pointer user code may use without moving it.
const RED_ZONE: u64 = 128;

const UC_SIGCONTEXT_SS: u64 = 2;
const UC_STRICT_RESTORE_SS: u64 = 4;

/// The flags rt_sigreturn may restore (Linux's FIX_EFLAGS: arithmetic,
/// TF, DF, AC, RF): never IF, IOPL or anything privileged.
const FIX_EFLAGS: u64 = 0x50dd5;

/// User addresses are below this (canonical): iretq to one that isn't
/// faults in the kernel.
pub const USER_END: u64 = super::USER_TOP;

/// `mov $15 (rt_sigreturn), %eax; syscall`, for handlers without
/// SA_RESTORER (libc always gives one on x86_64).
pub const TRAMPOLINE: [u8; 8] = [0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xcc];

/// What a signal frame holds besides the registers.
pub struct Context {
    pub info: [u8; 128],
    /// The alternate stack: sp, flags, size.
    pub stack: (u64, u32, u64),
    /// The mask to restore when the handler returns.
    pub mask: u64,
    pub fault: Option<Fault>,
    /// Where the handler returns: SA_RESTORER's, or the sigpage's.
    pub restorer: u64,
}

fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// The general registers, in sigcontext's order.
fn regs(tf: &mut TrapFrame) -> [&mut u64; 18] {
    [
        &mut tf.r8,
        &mut tf.r9,
        &mut tf.r10,
        &mut tf.r11,
        &mut tf.r12,
        &mut tf.r13,
        &mut tf.r14,
        &mut tf.r15,
        &mut tf.rdi,
        &mut tf.rsi,
        &mut tf.rbp,
        &mut tf.rbx,
        &mut tf.rdx,
        &mut tf.rax,
        &mut tf.rcx,
        &mut tf.rsp,
        &mut tf.rip,
        &mut tf.rflags,
    ]
}

/// Write a frame for a handler below `top` (sp, or the top of the
/// alternate stack), with `tf`'s registers: its address.
pub fn push_frame(a: &mut AddressSpace, tf: &TrapFrame, top: u64, ctx: &Context) -> Result<u64, Errno> {
    // On the stack it was using, past its red zone.
    let top = if top == tf.rsp { top.checked_sub(RED_ZONE).ok_or(EFAULT)? } else { top };
    let fp_at = top.checked_sub(FP_SIZE).ok_or(EFAULT)? & !63;
    // As if a return address had been pushed: a function's entry alignment.
    let frame = (fp_at.checked_sub(FRAME_SIZE as u64).ok_or(EFAULT)? & !15).checked_sub(8).ok_or(EFAULT)?;

    let mut fp = FpState::default();
    super::save_fp(&mut fp);
    copy_out(a, fp_at, &fp.area)?;

    let mut b = vec![0u8; FRAME_SIZE];
    let mut regs_tf = *tf;
    put_u64(&mut b, PRETCODE, ctx.restorer);
    put_u64(&mut b, UC_FLAGS, UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS);
    put_u64(&mut b, UC_STACK, ctx.stack.0);
    b[UC_STACK + 8..UC_STACK + 12].copy_from_slice(&ctx.stack.1.to_le_bytes());
    put_u64(&mut b, UC_STACK + 16, ctx.stack.2);
    for (i, r) in regs(&mut regs_tf).into_iter().enumerate() {
        put_u64(&mut b, MC_REGS + i * 8, *r);
    }
    b[MC_SEGS..MC_SEGS + 2].copy_from_slice(&(tf.cs as u16).to_le_bytes());
    b[MC_SEGS + 6..MC_SEGS + 8].copy_from_slice(&(tf.ss as u16).to_le_bytes());
    if let Some(f) = ctx.fault {
        let syndrome = f.syndrome.unwrap_or(0);
        put_u64(&mut b, MC_ERR, syndrome & 0xffff_ffff);
        put_u64(&mut b, MC_TRAPNO, syndrome >> 32);
        put_u64(&mut b, MC_CR2, f.addr);
    }
    put_u64(&mut b, MC_OLDMASK, ctx.mask);
    put_u64(&mut b, MC_FPSTATE, fp_at);
    put_u64(&mut b, UC_SIGMASK, ctx.mask);
    b[INFO..INFO + 128].copy_from_slice(&ctx.info);
    copy_out(a, frame, &b)?;
    Ok(frame)
}

/// Run `handler` for `sig` on the frame at `frame` (whose first word,
/// `pretcode`, is its return address: `Context::restorer`).
pub fn enter_handler(tf: &mut TrapFrame, frame: u64, sig: u32, handler: u64, _restorer: u64, _siginfo: bool) {
    tf.rdi = sig as u64;
    tf.rsi = frame + INFO as u64;
    tf.rdx = frame + UC as u64;
    tf.rax = 0;
    tf.rsp = frame;
    tf.rip = handler;
    // Linux clears DF, TF and RF for the handler.
    tf.rflags &= !((1 << 10) | (1 << 8) | (1 << 16));
    tf.cs = USER_CS;
    tf.ss = USER_SS;
}

/// rt_sigreturn: the frame below sp (the handler's `ret` took its return
/// address) back into `tf`, registers and FP state, and the mask and
/// alternate stack it saved. A bad frame changes nothing.
pub fn sigreturn(a: &mut AddressSpace, tf: &mut TrapFrame) -> Result<(u64, (u64, u32, u64)), Errno> {
    let frame = tf.rsp.checked_sub(8).ok_or(EFAULT)?;
    let mut b = vec![0u8; FRAME_SIZE];
    copy_in(a, frame, &mut b)?;
    let mut fp = FpState::default();
    let fp_at = get_u64(&b, MC_FPSTATE);
    if fp_at != 0 {
        copy_in(a, fp_at, &mut fp.area)?;
        // Reserved MXCSR bits would fault in fxrstor: only the CPU's own.
        let mut cur = FpState::default();
        super::save_fp(&mut cur);
        let mask = match u32::from_le_bytes(cur.area[28..32].try_into().unwrap()) {
            0 => 0xffbf,
            m => m,
        };
        let mxcsr = u32::from_le_bytes(fp.area[24..28].try_into().unwrap()) & mask;
        fp.area[24..28].copy_from_slice(&mxcsr.to_le_bytes());
    }
    let mut new = *tf;
    for (i, r) in regs(&mut new).into_iter().enumerate() {
        *r = get_u64(&b, MC_REGS + i * 8);
    }
    // iretq loads both from the frame; one it would fault on in the
    // kernel (a non-canonical address, or the kernel's half) is refused.
    if new.rip >= USER_END || new.rsp >= USER_END {
        return Err(EINVAL);
    }
    new.rflags = (new.rflags & FIX_EFLAGS) | USER_RFLAGS;
    new.cs = USER_CS;
    new.ss = USER_SS;
    // No system call to restart from here.
    new.orig_rax = !0;
    *tf = new;
    super::restore_fp(&fp);
    let stack = (
        get_u64(&b, UC_STACK),
        u32::from_le_bytes(b[UC_STACK + 8..UC_STACK + 12].try_into().unwrap()),
        get_u64(&b, UC_STACK + 16),
    );
    Ok((get_u64(&b, UC_SIGMASK), stack))
}
