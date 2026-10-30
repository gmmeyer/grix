//! Linux's arm64 signal frame (arch/arm64/kernel/signal.c):
//! `struct rt_sigframe { siginfo info; ucontext uc; }` and a frame record,
//! with the FP/SIMD and ESR records in `sigcontext.__reserved`.

use alloc::vec;

use super::{FpState, TrapFrame};
use crate::errno::*;
use crate::mm::aspace::AddressSpace;
use crate::signal::{AltStack, Fault};
use crate::uaccess::{copy_in, copy_out};

// struct rt_sigframe { siginfo info; ucontext uc; } followed by a frame
// record {fp, lr} for unwinders. Offsets are from the frame's start.
const UC: usize = 128;
const UC_STACK: usize = UC + 16;
const UC_SIGMASK: usize = UC + 40;
/// struct sigcontext, 16-byte aligned after uc_sigmask's 128-byte glibc sigset.
const MCONTEXT: usize = UC + 176;
const MC_REGS: usize = MCONTEXT + 8;
const MC_SP: usize = MCONTEXT + 256;
const MC_PC: usize = MCONTEXT + 264;
const MC_PSTATE: usize = MCONTEXT + 272;
/// sigcontext.__reserved: a list of {magic, size} records ending with a zero one.
const RESERVED: usize = MCONTEXT + 288;
const RESERVED_SIZE: usize = 4096;
const FRAME_SIZE: usize = RESERVED + RESERVED_SIZE;
const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: usize = 528;
const ESR_MAGIC: u32 = 0x4553_5201;
const ESR_SIZE: usize = 16;
/// sizeof(struct rt_sigframe), a multiple of 16 so the frame stays aligned.
const _: () = assert!(FRAME_SIZE == 4688);

/// PSTATE bits user code may not set: EL and SP selection, AArch32, DAIF masks.
const PSTATE_PRIVILEGED: u64 = 0x3df;
const PSTATE_NZCV: u64 = 0xf000_0000;

/// `mov x8, #139 (rt_sigreturn); svc #0`. Signal handlers return here unless
/// they bring their own SA_RESTORER, as Go and glibc on arm64 don't: they rely
/// on the vDSO's __kernel_rt_sigreturn, which is exactly this code.
pub const TRAMPOLINE: [u8; 8] = [0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4];

/// What a signal frame holds besides the registers.
pub struct Context {
    pub info: [u8; 128],
    /// The alternate stack: sp, flags, size.
    pub stack: (u64, u32, u64),
    /// The mask to restore when the handler returns.
    pub mask: u64,
    pub fault: Option<Fault>,
    /// Where the handler returns: SA_RESTORER's, or the sigpage's. x86_64's
    /// frame holds it; here it goes in x30 (`enter_handler`).
    #[allow(dead_code)]
    pub restorer: u64,
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// The most stack a handler's frame takes (Linux's AT_MINSIGSTKSZ,
/// `signal_minsigstksz`): the frame and its frame record, from a top
/// aligned down to 16 bytes (Linux's 16 bytes of "max alignment padding").
pub fn max_size() -> u64 {
    (FRAME_SIZE + 16 + 16) as u64
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
    let record = top.checked_sub(16).ok_or(EFAULT)? & !15;
    let frame = record.checked_sub(FRAME_SIZE as u64).ok_or(EFAULT)?;
    if within.is_some_and(|alt| !alt.holds(frame)) {
        return Err(EFAULT);
    }

    let mut b = vec![0u8; FRAME_SIZE + 16];
    b[..UC].copy_from_slice(&ctx.info);
    put_u64(&mut b, UC_STACK, ctx.stack.0);
    put_u32(&mut b, UC_STACK + 8, ctx.stack.1);
    put_u64(&mut b, UC_STACK + 16, ctx.stack.2);
    put_u64(&mut b, UC_SIGMASK, ctx.mask);
    put_u64(&mut b, MCONTEXT, ctx.fault.map_or(0, |f| f.addr));
    for (i, x) in tf.x.iter().enumerate() {
        put_u64(&mut b, MC_REGS + i * 8, *x);
    }
    put_u64(&mut b, MC_SP, tf.sp_el0);
    put_u64(&mut b, MC_PC, tf.elr);
    put_u64(&mut b, MC_PSTATE, tf.spsr);
    // The current thread's FP/SIMD state is live in the CPU (the kernel never touches it).
    let mut fp = FpState::default();
    super::save_fp(&mut fp);
    put_u32(&mut b, RESERVED, FPSIMD_MAGIC);
    put_u32(&mut b, RESERVED + 4, FPSIMD_SIZE as u32);
    put_u32(&mut b, RESERVED + 8, fp.fpsr as u32);
    put_u32(&mut b, RESERVED + 12, fp.fpcr as u32);
    for (i, q) in fp.q.iter().enumerate() {
        b[RESERVED + 16 + i * 16..RESERVED + 32 + i * 16].copy_from_slice(&q.to_le_bytes());
    }
    if let Some(esr) = ctx.fault.and_then(|f| f.syndrome) {
        let at = RESERVED + FPSIMD_SIZE;
        put_u32(&mut b, at, ESR_MAGIC);
        put_u32(&mut b, at + 4, ESR_SIZE as u32);
        put_u64(&mut b, at + 8, esr);
    }
    // The terminating {0, 0} record is already zero.
    put_u64(&mut b, FRAME_SIZE, tf.x[29]);
    put_u64(&mut b, FRAME_SIZE + 8, tf.x[30]);
    copy_out(a, frame, &b)?;
    Ok(frame)
}

/// Run `handler` for `sig` on the frame at `frame`, returning to `restorer`.
pub fn enter_handler(tf: &mut TrapFrame, frame: u64, sig: u32, handler: u64, restorer: u64, siginfo: bool) {
    tf.x[0] = sig as u64;
    if siginfo {
        tf.x[1] = frame;
        tf.x[2] = frame + UC as u64;
    }
    tf.sp_el0 = frame;
    tf.x[29] = frame + FRAME_SIZE as u64;
    tf.x[30] = restorer;
    tf.elr = handler;
}

/// rt_sigreturn: the frame at sp back into `tf` (registers and FP/SIMD),
/// and the mask and alternate stack it saved. A bad frame changes nothing.
pub fn sigreturn(a: &mut AddressSpace, tf: &mut TrapFrame) -> Result<(u64, (u64, u32, u64)), Errno> {
    let (b, fp) = read_frame(a, tf.sp_el0)?;
    for (i, x) in tf.x.iter_mut().enumerate() {
        *x = get_u64(&b, MC_REGS + i * 8);
    }
    tf.sp_el0 = get_u64(&b, MC_SP);
    tf.elr = get_u64(&b, MC_PC);
    tf.spsr = get_u64(&b, MC_PSTATE) & PSTATE_NZCV;
    super::restore_fp(&fp);
    let stack = (get_u64(&b, UC_STACK), get_u32(&b, UC_STACK + 8), get_u64(&b, UC_STACK + 16));
    Ok((get_u64(&b, UC_SIGMASK), stack))
}

/// Read and validate a signal frame (restore_sigframe, parse_user_sigframe).
fn read_frame(a: &mut AddressSpace, frame: u64) -> Result<(alloc::vec::Vec<u8>, FpState), Errno> {
    if frame & 15 != 0 {
        return Err(EFAULT);
    }
    let mut b = vec![0u8; FRAME_SIZE];
    copy_in(a, frame, &mut b)?;
    if get_u64(&b, MC_PSTATE) & PSTATE_PRIVILEGED != 0 {
        return Err(EINVAL);
    }
    let mut fp = None;
    let mut off = 0;
    let records = &b[RESERVED..];
    loop {
        if records.len() - off < 8 {
            return Err(EINVAL);
        }
        let (magic, size) = (get_u32(records, off), get_u32(records, off + 4) as usize);
        if magic == 0 {
            if size != 0 {
                return Err(EINVAL);
            }
            break;
        }
        if size < 8 || size % 16 != 0 || size > records.len() - off {
            return Err(EINVAL);
        }
        match magic {
            FPSIMD_MAGIC if fp.is_none() && size == FPSIMD_SIZE => {
                let mut s = FpState {
                    fpsr: get_u32(records, off + 8) as u64,
                    fpcr: get_u32(records, off + 12) as u64,
                    ..FpState::default()
                };
                for (i, q) in s.q.iter_mut().enumerate() {
                    let at = off + 16 + i * 16;
                    *q = u128::from_le_bytes(records[at..at + 16].try_into().unwrap());
                }
                fp = Some(s);
            }
            ESR_MAGIC => {}
            _ => return Err(EINVAL),
        }
        off += size;
    }
    Ok((b, fp.ok_or(EINVAL)?))
}
