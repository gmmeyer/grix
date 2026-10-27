//! AArch64 specifics: boot, exception entry, system registers.

use core::arch::{asm, global_asm};

use crate::signal::{self, *};
use crate::{process, sched, syscall};

pub mod irq;

global_asm!(include_str!("boot.S"));
global_asm!(include_str!("vectors.S"));
global_asm!(include_str!("fpsimd.S"));

/// Register state saved on every exception. Layout must match vectors.S.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 272);

/// User FP/SIMD registers. Layout must match fpsimd.S.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct FpState {
    pub q: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

unsafe extern "C" {
    fn enter_user_asm(entry: u64, sp: u64, kernel_stack_top: u64) -> !;
    fn fpsimd_save(state: *mut FpState);
    fn fpsimd_restore(state: *const FpState);
    static __stack_top: u8;
}

pub fn save_fp(state: &mut FpState) {
    unsafe { fpsimd_save(state) };
}

pub fn restore_fp(state: &FpState) {
    unsafe { fpsimd_restore(state) };
}

/// The user thread pointer (TLS base).
pub fn tpidr() -> u64 {
    let v;
    unsafe { asm!("mrs {}, tpidr_el0", out(reg) v) };
    v
}

pub fn set_tpidr(v: u64) {
    unsafe { asm!("msr tpidr_el0, {}", in(reg) v) };
}

/// Drop to EL0 at `entry` with stack pointer `sp`. Never returns: from here on
/// the kernel only runs in exception handlers.
pub fn enter_user(entry: u64, sp: u64) -> ! {
    let top = (&raw const __stack_top) as u64;
    unsafe { enter_user_asm(entry, sp, top) }
}

// Exception classes (ESR_EL1.EC).
const EC_UNKNOWN: u64 = 0x00;
const EC_SVC64: u64 = 0x15;
const EC_IABT_LOWER: u64 = 0x20;
const EC_PC_ALIGN: u64 = 0x22;
const EC_DABT_LOWER: u64 = 0x24;
const EC_SP_ALIGN: u64 = 0x26;
const EC_FP_EXC: u64 = 0x2c;
const EC_BRK: u64 = 0x3c;

#[unsafe(no_mangle)]
extern "C" fn trap_handler(tf: &mut TrapFrame, kind: u64) {
    match kind {
        8 => {
            el0_sync(tf);
            signal::return_to_user(tf);
        }
        9 => {
            sched::irq(tf);
            signal::return_to_user(tf);
        }
        // The kernel runs with IRQs masked, so nothing should arrive here.
        5 => {}
        _ => panic!("unexpected exception: kind={kind} esr={:#x} far={:#x} elr={:#x}", esr(), far(), tf.elr),
    }
}

fn el0_sync(tf: &mut TrapFrame) {
    let esr = esr();
    let ec = esr >> 26;
    let (sig, code, addr, esr, why) = match ec {
        EC_SVC64 => return syscall::handle(tf),
        EC_IABT_LOWER | EC_DABT_LOWER => {
            let far = far();
            let dfsc = esr & 0x3f;
            let access = if ec == EC_IABT_LOWER {
                process::Access::Exec
            } else if esr & (1 << 6) != 0 {
                process::Access::Write
            } else {
                process::Access::Read
            };
            match dfsc {
                // Translation fault at any level: demand paging. A
                // permission fault on a write may be a page shared
                // copy-on-write; `user_fault` tells.
                0b000100..=0b000111 => return process::user_fault(tf, far, access, esr),
                0b001101..=0b001111 if access == process::Access::Write => {
                    return process::user_fault(tf, far, access, esr);
                }
                0b100001 => (SIGBUS, BUS_ADRALN, far, Some(esr), "alignment fault"),
                _ => (SIGSEGV, SEGV_ACCERR, far, Some(esr), access.describe_violation()),
            }
        }
        EC_UNKNOWN => (SIGILL, ILL_ILLOPC, tf.elr, None, "illegal instruction"),
        EC_BRK => (SIGTRAP, TRAP_BRKPT, tf.elr, None, "breakpoint (brk)"),
        EC_PC_ALIGN => (SIGBUS, BUS_ADRALN, far(), None, "misaligned pc"),
        EC_SP_ALIGN => (SIGBUS, BUS_ADRALN, tf.sp_el0, None, "misaligned sp"),
        EC_FP_EXC => (SIGFPE, FPE_FLTUNK, tf.elr, None, "floating point exception"),
        _ => (SIGILL, ILL_ILLOPC, tf.elr, None, "unhandled exception class"),
    };
    let mut guard = process::PROCESS.lock();
    let p = guard.as_mut().expect("fault without a process");
    signal::fault(p, sig, code, signal::Fault { addr, pc: tf.elr, esr }, why);
}

pub fn esr() -> u64 {
    let v;
    unsafe { asm!("mrs {}, esr_el1", out(reg) v) };
    v
}

pub fn far() -> u64 {
    let v;
    unsafe { asm!("mrs {}, far_el1", out(reg) v) };
    v
}

pub fn counter() -> u64 {
    let v;
    unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) v) };
    v
}

/// Main ID register: implementer, part number, revision.
pub fn midr() -> u64 {
    let v;
    unsafe { asm!("mrs {}, midr_el1", out(reg) v) };
    v
}

pub fn counter_freq() -> u64 {
    let v;
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) v) };
    v
}

/// Let EL0 read the virtual counter directly, as Linux does.
pub fn allow_el0_counter() {
    unsafe { asm!("msr cntkctl_el1, {}", "isb", in(reg) 1u64 << 1) };
}

/// Hardware random number (FEAT_RNG), if the CPU has it.
pub fn rndr() -> Option<u64> {
    let isar0: u64;
    unsafe { asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0) };
    if (isar0 >> 60) & 0xf == 0 {
        return None;
    }
    let v: u64;
    let ok: u64;
    // RNDR = s3_3_c2_c4_0; sets NZCV to 0b0100 on failure.
    unsafe { asm!("mrs {v}, s3_3_c2_c4_0", "cset {ok}, ne", v = out(reg) v, ok = out(reg) ok) };
    (ok != 0).then_some(v)
}

/// Linux AT_HWCAP bits for the features this CPU has. Only plain unprivileged
/// instructions are advertised (no SVE, no CPUID emulation, no pointer auth).
pub fn hwcap() -> u64 {
    let (isar0, pfr0): (u64, u64);
    unsafe {
        asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0);
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0);
    }
    let field = |reg: u64, shift: u32| (reg >> shift) & 0xf;
    let mut cap = 0u64;
    let fp = field(pfr0, 16);
    let simd = field(pfr0, 20);
    if fp != 0xf {
        cap |= 1 << 0; // FP
    }
    if simd != 0xf {
        cap |= 1 << 1; // ASIMD
    }
    if fp == 1 {
        cap |= 1 << 9; // FPHP
    }
    if simd == 1 {
        cap |= 1 << 10; // ASIMDHP
    }
    let aes = field(isar0, 4);
    if aes >= 1 {
        cap |= 1 << 3; // AES
    }
    if aes >= 2 {
        cap |= 1 << 4; // PMULL
    }
    if field(isar0, 8) >= 1 {
        cap |= 1 << 5; // SHA1
    }
    let sha2 = field(isar0, 12);
    if sha2 >= 1 {
        cap |= 1 << 6; // SHA2
    }
    if sha2 >= 2 {
        cap |= 1 << 21; // SHA512
    }
    if field(isar0, 16) >= 1 {
        cap |= 1 << 7; // CRC32
    }
    if field(isar0, 20) >= 2 {
        cap |= 1 << 8; // ATOMICS
    }
    if field(isar0, 28) >= 1 {
        cap |= 1 << 12; // ASIMDRDM
    }
    if field(isar0, 32) >= 1 {
        cap |= 1 << 17; // SHA3
    }
    if field(isar0, 44) >= 1 {
        cap |= 1 << 20; // ASIMDDP
    }
    cap
}

pub fn set_user_page_table(root_pa: u64) {
    unsafe {
        asm!(
            "msr ttbr0_el1, {}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            in(reg) root_pa
        )
    };
}

/// Make page-table writes visible to the table walker.
pub fn pte_barrier() {
    unsafe { asm!("dsb ishst", "isb") };
}

pub fn flush_tlb() {
    unsafe { asm!("dsb ishst", "tlbi vmalle1", "dsb nsh", "isb") };
}

/// Make freshly written instructions at kernel address `kva` visible to instruction fetch.
pub fn sync_icache(kva: u64, len: u64) {
    let mut a = kva & !63;
    while a < kva + len {
        unsafe { asm!("dc cvau, {}", in(reg) a) };
        a += 64;
    }
    unsafe { asm!("dsb ish", "ic iallu", "dsb ish", "isb") };
}

/// PSCI SYSTEM_OFF. The VMM ends the VM.
pub fn power_off() -> ! {
    unsafe { asm!("hvc #0", in("x0") 0x8400_0008u64) };
    loop {
        unsafe { asm!("wfe") };
    }
}
