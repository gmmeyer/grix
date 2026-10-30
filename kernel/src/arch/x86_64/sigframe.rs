//! Linux's x86_64 signal frame (arch/x86/kernel/signal_64.c):
//! `struct rt_sigframe { char *pretcode; ucontext uc; siginfo info; }`, the
//! kernel's ucontext (an 8-byte sigset), and the FP state above it
//! (64-byte aligned), which `sigcontext.fpstate` points at: fxsave's 512
//! bytes, or with XSAVE the whole XSAVE area, described in the 48 bytes
//! fxsave leaves to software (`struct _fpx_sw_bytes`) and followed by
//! FP_XSTATE_MAGIC2 (arch/x86/kernel/fpu/signal.c).

use alloc::vec;

use super::{FpState, TrapFrame, USER_CS, USER_RFLAGS, USER_SS};
use crate::errno::*;
use crate::mm::aspace::AddressSpace;
use crate::signal::{AltStack, Fault};
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

/// fxsave's area: XSAVE's legacy region.
const FXSAVE_SIZE: usize = 512;
/// `struct _fpx_sw_bytes` in the legacy region: magic1, extended_size,
/// xfeatures, xstate_size.
const SW_BYTES: usize = 464;
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// The XSAVE header, after the legacy region: XSTATE_BV, XCOMP_BV, and
/// 48 reserved bytes.
const XHEADER: usize = 512;
const XHEADER_END: usize = 576;
/// Below the stack pointer user code may use without moving it.
const RED_ZONE: u64 = 128;

const UC_FP_XSTATE: u64 = 1;
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

/// The most stack a handler's frame takes (Linux's AT_MINSIGSTKSZ,
/// `init_sigframe_size`): the FP state, 64-byte aligned, and the frame
/// below it, 16-byte aligned less a return address's 8.
pub fn max_size() -> u64 {
    let xsize = super::xsave_size();
    let fp_size = if xsize == 0 { FXSAVE_SIZE } else { xsize + 4 };
    ((fp_size + 63 + FRAME_SIZE + 15 + 8) as u64).next_multiple_of(16)
}

/// Write a frame for a handler below `top` (sp, or the top of the
/// alternate stack, which it must then fit `within`), with `tf`'s
/// registers: its address.
pub fn push_frame(
    a: &mut AddressSpace,
    tf: &TrapFrame,
    top: u64,
    within: Option<AltStack>,
    ctx: &Context,
) -> Result<u64, Errno> {
    // On the stack it was using, past its red zone.
    let top = if top == tf.rsp { top.checked_sub(RED_ZONE).ok_or(EFAULT)? } else { top };
    let xsize = super::xsave_size();
    let fp_size = if xsize == 0 { FXSAVE_SIZE } else { xsize + 4 };
    let fp_at = top.checked_sub(fp_size as u64).ok_or(EFAULT)? & !63;
    // As if a return address had been pushed: a function's entry alignment.
    let frame = (fp_at.checked_sub(FRAME_SIZE as u64).ok_or(EFAULT)? & !15).checked_sub(8).ok_or(EFAULT)?;
    if within.is_some_and(|alt| !alt.holds(frame)) {
        return Err(EFAULT);
    }

    let mut fp = FpState::default();
    super::save_fp(&mut fp);
    let mut uc_flags = UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS;
    if xsize == 0 {
        copy_out(a, fp_at, &fp.area[..FXSAVE_SIZE])?;
    } else {
        let sw = &mut fp.area[SW_BYTES..FXSAVE_SIZE];
        sw.fill(0);
        sw[0..4].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
        sw[4..8].copy_from_slice(&(fp_size as u32).to_le_bytes());
        sw[8..16].copy_from_slice(&super::xsave_features().to_le_bytes());
        sw[16..20].copy_from_slice(&(xsize as u32).to_le_bytes());
        copy_out(a, fp_at, &fp.area[..xsize])?;
        copy_out(a, fp_at + xsize as u64, &FP_XSTATE_MAGIC2.to_le_bytes())?;
        uc_flags |= UC_FP_XSTATE;
    }

    let mut b = vec![0u8; FRAME_SIZE];
    let mut regs_tf = *tf;
    put_u64(&mut b, PRETCODE, ctx.restorer);
    put_u64(&mut b, UC_FLAGS, uc_flags);
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
        read_fp(a, fp_at, &mut fp)?;
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

/// The FP state of a frame at `fp_at` into `fp`, as `restore_fp` will
/// take it. With XSAVE, a frame with the whole area (its software bytes
/// and both magics as `push_frame` writes them) restores every component;
/// any other, its x87/SSE state only, the rest starting over, as Linux's
/// fx_only. An XSAVE header that xrstor would refuse is rejected, as
/// Linux's validate_user_xstate_header does.
fn read_fp(a: &mut AddressSpace, fp_at: u64, fp: &mut FpState) -> Result<(), Errno> {
    copy_in(a, fp_at, &mut fp.area[..FXSAVE_SIZE])?;
    // Reserved MXCSR bits would fault in fxrstor or xrstor: only the CPU's own.
    let mut cur = FpState::default();
    super::save_fp(&mut cur);
    let mask = match u32::from_le_bytes(cur.area[28..32].try_into().unwrap()) {
        0 => 0xffbf,
        m => m,
    };
    let mxcsr = u32::from_le_bytes(fp.area[24..28].try_into().unwrap()) & mask;
    fp.area[24..28].copy_from_slice(&mxcsr.to_le_bytes());

    let (xsize, xcr0) = (super::xsave_size(), super::xsave_features());
    if xsize == 0 {
        return Ok(());
    }
    let sw = &fp.area[SW_BYTES..FXSAVE_SIZE];
    let word = |off: usize| u32::from_le_bytes(sw[off..off + 4].try_into().unwrap());
    let whole = word(0) == FP_XSTATE_MAGIC1 && word(4) as usize == xsize + 4 && word(16) as usize == xsize && {
        let mut magic2 = [0u8; 4];
        copy_in(a, fp_at + xsize as u64, &mut magic2)?;
        u32::from_le_bytes(magic2) == FP_XSTATE_MAGIC2
    };
    if !whole {
        // x87 and SSE from the frame (XSTATE_BV), every other component initial.
        fp.area[XHEADER..XHEADER + 8].copy_from_slice(&0b11u64.to_le_bytes());
        return Ok(());
    }
    let features = u64::from_le_bytes(sw[8..16].try_into().unwrap());
    copy_in(a, fp_at + FXSAVE_SIZE as u64, &mut fp.area[FXSAVE_SIZE..xsize])?;
    let bv = get_u64(&fp.area, XHEADER);
    // Components outside XCR0, the compacted format (XCOMP_BV) or the
    // reserved bytes would make xrstor fault.
    if bv & !xcr0 != 0 || fp.area[XHEADER + 8..XHEADER_END].iter().any(|&b| b != 0) {
        return Err(EINVAL);
    }
    // Components the frame doesn't say it has start over.
    put_u64(&mut fp.area, XHEADER, bv & features);
    Ok(())
}
