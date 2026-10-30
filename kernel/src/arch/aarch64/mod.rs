//! AArch64 specifics: boot, exception entry, system registers.

use core::arch::{asm, global_asm};

use super::stack_top;
use crate::signal::{self, *};
use crate::{process, sched, syscall};

pub mod abi;
pub mod irq;
pub mod pte;

/// Where this machine's RAM, boot image and devices are (QEMU `virt`'s).
pub mod machine {
    pub use grix_abi::image::IMAGE_BASE;
    pub use grix_abi::machine::{VIRTIO, VIRTIO_IRQ, VIRTIO_SLOTS, VIRTIO_STRIDE, ram_regions};
}
pub mod sigframe;
pub mod uart;

global_asm!(include_str!("boot.S"));
global_asm!(include_str!("vectors.S"));
global_asm!(include_str!("fpsimd.S"));
global_asm!(include_str!("vdso.S"));

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

/// What the rest of the kernel knows of a trapped thread's registers: Linux's
/// arm64 conventions (x8 the system call's number, x0..x5 its arguments, x0
/// its result; the svc is 4 bytes).
impl TrapFrame {
    /// A thread entering user mode at `pc` with stack `sp`, every other
    /// register zero.
    pub fn new_user(pc: u64, sp: u64) -> TrapFrame {
        TrapFrame { elr: pc, sp_el0: sp, ..TrapFrame::default() }
    }

    pub fn syscall_nr(&self) -> u64 {
        self.x[8]
    }

    /// Argument `n` (0..6) of the system call.
    pub fn arg(&self, n: usize) -> u64 {
        self.x[n]
    }

    pub fn syscall_args(&self) -> [u64; 6] {
        [self.x[0], self.x[1], self.x[2], self.x[3], self.x[4], self.x[5]]
    }

    /// The system call's result, as it returns.
    pub fn set_return(&mut self, v: u64) {
        self.x[0] = v;
    }

    pub fn return_value(&self) -> u64 {
        self.x[0]
    }

    pub fn pc(&self) -> u64 {
        self.elr
    }

    pub fn sp(&self) -> u64 {
        self.sp_el0
    }

    pub fn set_sp(&mut self, sp: u64) {
        self.sp_el0 = sp;
    }

    /// Back to the system call instruction it trapped from, to run it again
    /// (its arguments are all still there).
    pub fn rewind_syscall(&mut self) {
        self.elr -= 4;
    }

    /// Past it again: a rewound call that returns after all.
    pub fn skip_syscall(&mut self) {
        self.elr += 4;
    }
}

/// User FP/SIMD registers. Layout must match fpsimd.S.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct FpState {
    pub q: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

/// A thread's FP state as `process::Thread` holds it: inline, as it's
/// 528 bytes (x86_64's is boxed).
pub type ThreadFp = FpState;
/// Heap bytes a thread's FP state takes beside its `Thread`: none.
pub const FP_HEAP_BYTES: usize = 0;

unsafe extern "C" {
    fn enter_user_asm(entry: u64, sp: u64, kernel_stack_top: u64) -> !;
    fn return_to_frame_asm(frame: *const TrapFrame) -> !;
    fn fpsimd_save(state: *mut FpState);
    fn fpsimd_restore(state: *const FpState);
    fn secondary_entry_addr() -> u64;
    fn empty_l0_addr() -> u64;
    fn boot_l1_addr() -> u64;
}

/// Map physical `start..end` (RAM past the 4 GiB boot.S maps) in the
/// kernel's half, as boot.S maps RAM: 1 GiB blocks in its level 1 table.
/// Nothing was there, so there's nothing to flush. (`_table` gives page
/// tables, which x86_64 needs.)
pub fn map_ram(start: u64, end: u64, _table: &mut dyn FnMut() -> u64) {
    const GIB: u64 = 1 << 30;
    // Normal WB (MAIR idx 1), inner shareable, AF, UXN; EL1-only.
    const BLOCK: u64 = 0x0040_0000_0000_0705;
    let l1 = crate::mm::p2v(unsafe { boot_l1_addr() }) as *mut u64;
    for i in start / GIB..end.div_ceil(GIB) {
        assert!(i < 512, "RAM beyond what one level 1 table maps");
        // SAFETY: the boot tables' level 1 table, mapped linearly; the
        // entry was empty.
        unsafe { l1.add(i as usize).write_volatile((i * GIB) | BLOCK) };
    }
    // The entries reach memory before any table walk (this CPU's, or one
    // started later) looks for them.
    unsafe { asm!("dsb ish", "isb") };
}

/// Where a secondary CPU starts (physical: its MMU is off).
pub fn secondary_entry_phys() -> u64 {
    // .text.boot runs where it's loaded: its address is physical.
    unsafe { secondary_entry_addr() }
}

/// A user page table that maps nothing (physical address: it's in
/// .bss.boot, which is linked where it's loaded).
pub fn empty_page_table() -> u64 {
    unsafe { empty_l0_addr() }
}

/// Return to EL0 from `frame`, which must be at the top of this CPU's stack.
///
/// # Safety
/// `frame` holds a valid EL0 state (pstate EL0t), as a trap leaves it.
pub unsafe fn return_to_frame(frame: *const TrapFrame) -> ! {
    unsafe { return_to_frame_asm(frame) }
}

pub fn save_fp(state: &mut FpState) {
    unsafe { fpsimd_save(state) };
}

pub fn restore_fp(state: &FpState) {
    unsafe { fpsimd_restore(state) };
}

/// The user thread pointer (TLS base: TPIDR_EL0).
pub fn tls() -> u64 {
    let v;
    unsafe { asm!("mrs {}, tpidr_el0", out(reg) v) };
    v
}

/// Can `v` be a thread pointer? Any value can be TPIDR_EL0's.
pub fn valid_tls(_v: u64) -> bool {
    true
}

pub fn set_tls(v: u64) {
    unsafe { asm!("msr tpidr_el0, {}", in(reg) v) };
}

/// Physical memory is mapped linearly here, in TTBR1's half (as linker.ld).
pub const KERNEL_OFFSET: u64 = 0xFFFF_0000_0000_0000;

/// The end of user addresses: TTBR0's 48 bits.
pub const USER_TOP: u64 = 1 << 48;

/// Where position-independent executables go (ELF_ET_DYN_BASE: two thirds
/// of the way up).
pub const ELF_DYN_BASE: u64 = 0x0000_aaaa_aaa0_0000;

/// ELF's e_machine for the programs this kernel runs.
pub const ELF_MACHINE: u16 = 183; // EM_AARCH64
/// Why an ELF for another machine doesn't load.
pub const ELF_OTHER_MACHINE: &str = "not an AArch64 binary";
/// AT_PLATFORM and uname's machine.
pub const PLATFORM: &str = "aarch64";
/// Linux's MINSIGSTKSZ: room for a frame with the FP/SIMD record.
pub const MINSIGSTKSZ: u64 = 5120;

/// This CPU's number (MPIDR affinity 0: the VMMs number CPUs 0..n).
pub fn cpu_number() -> usize {
    let mpidr: u64;
    // SAFETY: reading an ID register.
    unsafe { asm!("mrs {}, mpidr_el1", out(reg) mpidr) };
    (mpidr & 0xff) as usize
}

/// Wait for an interrupt (a masked one still wakes it), earlier writes seen
/// first.
pub fn wait_for_interrupt() {
    // SAFETY: IRQs stay masked; WFI still wakes.
    unsafe { asm!("dsb sy", "wfi") };
}

/// Run `f`, which touches user memory: plain loads and stores reach it
/// (PAN, arm64's SMAP, is off).
#[inline(always)]
pub fn user_access<R>(f: impl FnOnce() -> R) -> R {
    f()
}

/// Order memory writes (a virtqueue's) before a device register write.
pub fn device_barrier() {
    // SAFETY: a barrier.
    unsafe { asm!("dsb sy") };
}

/// Start CPU `cpu` at physical `entry` with its stack in x0: PSCI CPU_ON
/// (SMC32 id, HVC conduit). PSCI's result: 0, or a negative error.
pub fn start_cpu(cpu: usize, entry: u64, stack: u64) -> i64 {
    let r: u64;
    // SAFETY: the VMM starts `cpu` at `entry` with the MMU off.
    unsafe {
        asm!("hvc #0", inout("x0") 0xc400_0003u64 => r, inout("x1") cpu as u64 => _, inout("x2") entry => _,
             inout("x3") stack => _);
    }
    r as i64
}

/// Tell the VMM CPU `cpu` was sent a kick (`irq::send_sgi`): grix-vmm waits
/// in WFI for the guest and doesn't see SGIs (`KICK_CALL`; KVM answers
/// NOT_SUPPORTED, and WFI wakes on the SGI there). Nothing for QEMU.
pub fn vmm_kick(cpu: usize) {
    if !irq::on_grix_vmm() {
        return;
    }
    // SAFETY: a hypervisor call with no memory effects. SMCCC returns results
    // in x0..x3 (KVM zeroes x1..x3).
    unsafe {
        asm!("hvc #0", inout("x0") grix_abi::machine::KICK_CALL => _, inout("x1") cpu as u64 => _, out("x2") _,
             out("x3") _);
    }
}

/// `SNAPSHOT_CALL`: x0..x5 as the VMM leaves them (a restored run returns
/// here, the rest of the registers as they were).
pub fn snapshot_call() -> [u64; 6] {
    let (x0, x1, x2, x3, x4, x5): (u64, u64, u64, u64, u64, u64);
    // SAFETY: a hypervisor call; the VMM saves every register.
    unsafe {
        asm!("hvc #0", inout("x0") grix_abi::image::SNAPSHOT_CALL => x0, out("x1") x1, out("x2") x2, out("x3") x3,
             out("x4") x4, out("x5") x5);
    }
    [x0, x1, x2, x3, x4, x5]
}

/// Drop to EL0 at `entry` with stack pointer `sp`. Never returns: from here on
/// the kernel only runs in exception handlers.
pub fn enter_user(entry: u64, sp: u64) -> ! {
    unsafe { enter_user_asm(entry, sp, stack_top(0)) }
}

// Exception classes (ESR_EL1.EC).
const EC_UNKNOWN: u64 = 0x00;
const EC_SVC64: u64 = 0x15;
const EC_SYS64: u64 = 0x18;
const EC_IABT_LOWER: u64 = 0x20;
const EC_PC_ALIGN: u64 = 0x22;
const EC_DABT_LOWER: u64 = 0x24;
const EC_SP_ALIGN: u64 = 0x26;
const EC_FP_EXC: u64 = 0x2c;
const EC_BRK: u64 = 0x3c;

#[unsafe(no_mangle)]
extern "C" fn trap_handler(tf: &mut TrapFrame, kind: u64) {
    if !matches!(kind, 5 | 8 | 9) {
        // Taken into the canary with room left for the frame.
        let sp = tf as *const TrapFrame as u64 + core::mem::size_of::<TrapFrame>() as u64;
        if super::stack::overflowed(cpu_number(), sp) {
            panic!("kernel stack overflow on CPU {} at {:#x}, sp {sp:#x}, far {:#x}", cpu_number(), tf.elr, far());
        }
        panic!(
            "unexpected exception: kind={kind} esr={:#x} far={:#x} elr={:#x} lr={:#x} sp_el0={:#x}",
            esr(),
            far(),
            tf.elr,
            tf.x[30],
            tf.sp_el0
        );
    }
    crate::smp::enter(match kind {
        8 if esr() >> 26 == EC_SVC64 => crate::smp::Stat::Syscall,
        8 => crate::smp::Stat::Fault,
        _ => crate::smp::Stat::Irq,
    });
    // The thread this CPU ran may have ended meanwhile (exit_group or
    // execve on another CPU): then there's nothing to handle for it.
    let has_thread = process::running().lock().as_ref().is_some_and(|p| p.running);
    match kind {
        8 if has_thread => {
            el0_sync(tf);
            signal::return_to_user(tf);
        }
        9 => {
            sched::irq(tf);
            signal::return_to_user(tf);
        }
        // The kernel runs with IRQs masked, so nothing should arrive at 5.
        _ => {}
    }
    // Something to run (waiting for it if need be), and the kernel back.
    crate::smp::finish(tf);
}

/// An exception in the kernel with no room for its frame on this CPU's
/// stack (vectors.S): on the emergency stack, `sp` the one it came in at.
#[unsafe(no_mangle)]
extern "C" fn stack_overflow_report(sp: u64) -> ! {
    let elr: u64;
    // SAFETY: reading a system register.
    unsafe { asm!("mrs {}, elr_el1", out(reg) elr) };
    panic!("kernel stack overflow on CPU {} at {elr:#x}, sp {sp:#x}, far {:#x}, esr {:#x}", cpu_number(), far(), esr());
}

fn el0_sync(tf: &mut TrapFrame) {
    let esr = esr();
    let ec = esr >> 26;
    let (sig, code, addr, esr, why) = match ec {
        EC_SVC64 => return syscall::handle(tf),
        EC_IABT_LOWER | EC_DABT_LOWER => {
            let far = far();
            let dfsc = esr & 0x3f;
            // WnR is also set for cache maintenance (CM), which only
            // needs to read the page, as Linux's is_write_abort says:
            // `dc cvau` on a JIT's executable view of its code (Erlang's
            // __clear_cache) must fault it in, not fail.
            let access = if ec == EC_IABT_LOWER {
                process::Access::Exec
            } else if esr & (1 << 6) != 0 && esr & (1 << 8) == 0 {
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
        // An MRS of an ID register: EC_SYS64 with FEAT_IDST, undefined
        // (and decoded from the instruction) without it.
        EC_SYS64 if emulate_mrs_trap(tf, esr) => return,
        EC_UNKNOWN if emulate_undefined_mrs(tf) => return,
        EC_SYS64 => (SIGILL, ILL_ILLOPC, tf.elr, None, "system register access"),
        EC_UNKNOWN => (SIGILL, ILL_ILLOPC, tf.elr, None, "illegal instruction"),
        EC_BRK => (SIGTRAP, TRAP_BRKPT, tf.elr, None, "breakpoint (brk)"),
        EC_PC_ALIGN => (SIGBUS, BUS_ADRALN, far(), None, "misaligned pc"),
        EC_SP_ALIGN => (SIGBUS, BUS_ADRALN, tf.sp_el0, None, "misaligned sp"),
        EC_FP_EXC => (SIGFPE, FPE_FLTUNK, tf.elr, None, "floating point exception"),
        _ => (SIGILL, ILL_ILLOPC, tf.elr, None, "unhandled exception class"),
    };
    let mut guard = process::running().lock();
    let p = guard.as_mut().expect("fault without a process");
    signal::fault(p, sig, code, signal::Fault { addr, pc: tf.elr, syndrome: esr }, why);
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
fn midr() -> u64 {
    let v;
    unsafe { asm!("mrs {}, midr_el1", out(reg) v) };
    v
}

pub fn counter_freq() -> u64 {
    let v;
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) v) };
    v
}

/// Let user code read the counter directly (the vDSO does), as Linux does.
pub fn allow_user_counter() {
    unsafe { asm!("msr cntkctl_el1, {}", "isb", in(reg) 1u64 << 1) };
}

/// A hardware random number (FEAT_RNG's RNDR), if the CPU has it.
pub fn hw_random() -> Option<u64> {
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

/// ID_AA64ISAR0_EL1's fields user mode sees: AES, SHA1, SHA2, CRC32,
/// Atomic, RDM, SHA3 and DP, the ones `hwcap` turns into HWCAP bits (not
/// RNDR, TS, FHM, SM3, SM4 or TLB, which it doesn't advertise).
const ISAR0_VISIBLE: u64 = 0xf << 4 | 0xf << 8 | 0xf << 12 | 0xf << 16 | 0xf << 20 | 0xf << 28 | 0xf << 32 | 0xf << 44;

/// What user mode reads in ID_AA64ISAR0_EL1 (and HWCAP is made of).
fn user_isar0() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, id_aa64isar0_el1", out(reg) v) };
    v & ISAR0_VISIBLE
}

/// What user mode reads in ID_AA64PFR0_EL1: FP and AdvSIMD, and EL0 and
/// EL1 as AArch64 only, as Linux shows them (its hidden fields' safe
/// values). No SVE, DIT, AMU, RAS, GIC or the other ELs.
fn user_pfr0() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, id_aa64pfr0_el1", out(reg) v) };
    (v & (0xff << 16)) | 0x11
}

/// The value of ID register (op0, op1, CRn, CRm, op2) that an MRS from
/// user mode gets, as Linux's emulate_sys_reg gives it
/// (arch/arm64/kernel/cpufeature.c): only op0 3, op1 0, CRn 0, and CRm
/// 0 or 2-7. In CRm 0, MIDR_EL1 (as this machine shows it, the same as
/// /proc/cpuinfo), MPIDR_EL1 (Linux's SYS_MPIDR_SAFE_VAL, so no CPU's
/// topology shows) and REVIDR_EL1 (0); nothing else. Elsewhere only the
/// fields this kernel supports, enables and advertises in HWCAP;
/// registers it shows nothing of read as 0, as Linux's untracked and
/// hidden ones do (but ID_AA64DFR0_EL1's DebugVer, 6 as Linux has it).
fn user_id_register(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> Option<u64> {
    if op0 != 3 || op1 != 0 || crn != 0 {
        return None;
    }
    match (crm, op2) {
        (0, 0) => Some(midr()),
        (0, 5) => Some(1 << 31),
        (0, 6) => Some(0),
        (0 | 1, _) => None,
        (4, 0) => Some(user_pfr0()),
        (5, 0) => Some(6),
        (6, 0) => Some(user_isar0()),
        (2..=7, _) => Some(0),
        _ => None,
    }
}

/// Finish an emulated MRS: the value in Xt (XZR discards it) and on to
/// the next instruction.
fn complete_mrs(tf: &mut TrapFrame, rt: u64, value: u64) {
    if rt < 31 {
        tf.x[rt as usize] = value;
    }
    tf.elr += 4;
}

/// EC_SYS64: with FEAT_IDST, an MRS of an ID register from EL0 traps
/// here (ISS: op0, op2, op1, CRn, Rt, CRm, and 1 for a read).
fn emulate_mrs_trap(tf: &mut TrapFrame, esr: u64) -> bool {
    let iss = esr & 0x1ff_ffff;
    let field = |shift: u32, bits: u32| (iss >> shift) & ((1 << bits) - 1);
    if iss & 1 == 0 {
        return false;
    }
    match user_id_register(field(20, 2), field(14, 3), field(10, 4), field(1, 4), field(17, 3)) {
        Some(v) => {
            complete_mrs(tf, field(5, 5), v);
            true
        }
        None => false,
    }
}

/// Without FEAT_IDST, the same MRS is undefined at EL0: read the
/// instruction (Linux's try_emulate_mrs) and emulate it if it's one.
fn emulate_undefined_mrs(tf: &mut TrapFrame) -> bool {
    let mut b = [0u8; 4];
    {
        let mut guard = process::running().lock();
        let Some(p) = guard.as_mut() else { return false };
        if crate::uaccess::copy_in(&mut p.aspace, tf.elr, &mut b).is_err() {
            return false;
        }
    }
    let insn = u32::from_le_bytes(b) as u64;
    // MRS: 1101 0101 0011 o0 op1 CRn CRm op2 Rt (op0 is 2 + o0).
    if insn & 0xfff0_0000 != 0xd530_0000 {
        return false;
    }
    let field = |shift: u32, bits: u32| (insn >> shift) & ((1 << bits) - 1);
    match user_id_register(2 + field(19, 1), field(16, 3), field(12, 4), field(8, 4), field(5, 3)) {
        Some(v) => {
            complete_mrs(tf, field(0, 5), v);
            true
        }
        None => false,
    }
}

/// Linux AT_HWCAP bits for the features this CPU has, made from the ID
/// registers as user mode sees them (`user_id_register`), so the two
/// agree. Only plain unprivileged instructions are advertised (no SVE, no
/// pointer auth), and HWCAP_CPUID: reading the ID registers is emulated.
pub fn hwcap() -> u64 {
    let (isar0, pfr0) = (user_isar0(), user_pfr0());
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
    cap | 1 << 11 // CPUID
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

/// Order what was written to a page (zeroing, contents) before the entry
/// that publishes it: another CPU's walker or thread may use the entry at
/// once.
pub fn publish_barrier() {
    unsafe { asm!("dmb ishst") };
}

/// Make page-table writes visible to the table walker.
pub fn pte_barrier() {
    unsafe { asm!("dsb ishst", "isb") };
}

/// Above this many pages a flush is of everything (as Linux's
/// MAX_DVM_OPS bounds a range's TLBIs).
const FLUSH_PAGES: u64 = 64;

/// Forget cached translations of `[start, end)` (page aligned) in the
/// address space whose root is `root`, on every CPU: before a page whose
/// mapping changed is reused. TTBR0's ASID is always 0 (each switch
/// flushes this CPU's, `set_user_page_table`), so a page's TLBI reaches
/// every process's entries for that address: more than needed, never less.
pub fn flush_tlb(_root: u64, start: u64, end: u64) {
    crate::smp::note(crate::smp::Stat::Flush, 1);
    if (end - start) / 4096 > FLUSH_PAGES {
        unsafe { asm!("dsb ishst", "tlbi vmalle1is", "dsb ish", "isb") };
        return;
    }
    // SAFETY: TLB maintenance; the page tables were written first.
    unsafe { asm!("dsb ishst") };
    for va in (start..end).step_by(4096) {
        // Last level only (the tables above it don't change while the
        // address space lives), ASID 0 in bits 63:48.
        unsafe { asm!("tlbi vale1is, {}", in(reg) (va >> 12) & ((1 << 44) - 1)) };
    }
    unsafe { asm!("dsb ish", "isb") };
}

/// Flushes another CPU asked for and this one missed: none (`flush_tlb`
/// broadcasts).
pub fn tlb_sync() {}

/// Make freshly written instructions at kernel address `kva` visible to instruction fetch.
pub fn sync_icache(kva: u64, len: u64) {
    let mut a = kva & !63;
    while a < kva + len {
        unsafe { asm!("dc cvau, {}", in(reg) a) };
        a += 64;
    }
    // Every CPU's instruction cache: threads move between CPUs.
    unsafe { asm!("dsb ish", "ic ialluis", "dsb ish", "isb") };
}

/// PSCI SYSTEM_OFF. The VMM ends the VM.
pub fn power_off() -> ! {
    unsafe { asm!("hvc #0", in("x0") 0x8400_0008u64) };
    loop {
        unsafe { asm!("wfe") };
    }
}

/// /proc/cpuinfo, as Linux arm64 writes it, for `cpus` CPUs.
pub fn cpuinfo(s: &mut alloc::string::String, cpus: u32) {
    use core::fmt::Write;
    const NAMES: [&str; 22] = [
        "fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32", "atomics", "fphp", "asimdhp", "cpuid",
        "asimdrdm", "jscvt", "fcma", "lrcpc", "dcpop", "sha3", "sm3", "sm4", "asimddp", "sha512",
    ];
    let hw = hwcap();
    let features: alloc::vec::Vec<&str> =
        NAMES.iter().enumerate().filter(|(i, _)| hw & (1 << i) != 0).map(|(_, n)| *n).collect();
    let midr = midr();
    let bogomips = counter_freq() * 2 / 10_000;
    for cpu in 0..cpus {
        let _ = write!(
            s,
            "processor\t: {cpu}\nBogoMIPS\t: {}.{:02}\nFeatures\t: {}\nCPU implementer\t: {:#04x}\n\
             CPU architecture: 8\nCPU variant\t: {:#x}\nCPU part\t: {:#05x}\nCPU revision\t: {}\n\n",
            bogomips / 100,
            bogomips % 100,
            features.join(" "),
            (midr >> 24) & 0xff,
            (midr >> 20) & 0xf,
            (midr >> 4) & 0xfff,
            midr & 0xf,
        );
    }
}
