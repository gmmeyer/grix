//! Interrupts: GICv3 (`grix_abi::machine`'s layout) and the EL1 virtual timer.
//!
//! The kernel always runs with IRQs masked. Interrupts are taken only from
//! EL0 (preemption) or noticed after `wfi` in the idle loop, which wakes on a
//! pending interrupt even while masked.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use grix_abi::machine::{GICR_GRIX_VMM, GICR_STRIDE};

use crate::mm::KERNEL_OFFSET;
use crate::time;

const GICD: u64 = KERNEL_OFFSET + grix_abi::machine::GICD;

/// The redistributors' physical base: where the VMM put them (the boot
/// image says).
static GICR: AtomicU64 = AtomicU64::new(0);
/// They're where grix-vmm puts them: it's the VMM.
static GRIX_VMM: AtomicBool = AtomicBool::new(false);

/// Is the VMM grix-vmm (which wants `KICK_CALL`s)?
pub fn on_grix_vmm() -> bool {
    GRIX_VMM.load(Ordering::Relaxed)
}

/// Virtual timer PPI.
pub const TIMER_INTID: u32 = 27;
const SPURIOUS: u32 = 1023;

fn reg32(addr: u64) -> *mut u32 {
    addr as *mut u32
}

/// The SGI CPUs kick each other with (`smp::kick`).
pub const KICK_INTID: u32 = 0;

/// Set the GIC up, on CPU 0. `gicr` is the redistributors' physical base,
/// which depends on the VMM (the boot image says).
pub fn init(gicr: u64) {
    GICR.store(gicr, Ordering::Relaxed);
    GRIX_VMM.store(gicr == GICR_GRIX_VMM, Ordering::Relaxed);
    // SAFETY: GIC distributor registers, mapped at GICD.
    unsafe {
        // Distributor: affinity routing, group 1 enabled (single security state).
        let ctlr = reg32(GICD);
        ctlr.write_volatile((1 << 4) | (1 << 1));
        while ctlr.read_volatile() & (1 << 31) != 0 {}
    }
    init_cpu(0);
}

/// CPU `cpu`'s part of the GIC, on that CPU.
pub fn init_cpu(cpu: usize) {
    // Its redistributor: RD_base frame, then SGI_base frame 64 KiB later.
    let gicr = KERNEL_OFFSET + GICR.load(Ordering::Relaxed) + cpu as u64 * GICR_STRIDE;
    let gicr_sgi = gicr + 0x1_0000;
    unsafe {
        // Wake the redistributor.
        let waker = reg32(gicr + 0x14);
        waker.write_volatile(waker.read_volatile() & !(1 << 1));
        while waker.read_volatile() & (1 << 2) != 0 {}
        // The timer PPI and the kick SGI: group 1, mid priority, enabled.
        let mine = (1 << TIMER_INTID) | (1 << KICK_INTID);
        let igroupr0 = reg32(gicr_sgi + 0x80);
        igroupr0.write_volatile(igroupr0.read_volatile() | mine);
        for id in [TIMER_INTID, KICK_INTID] {
            ((gicr_sgi + 0x400 + id as u64) as *mut u8).write_volatile(0x80);
        }
        reg32(gicr_sgi + 0x100).write_volatile(mine);
        // CPU interface (system registers): enable, unmask all priorities, group 1 on.
        asm!("mrs {t}, S3_0_C12_C12_5", "orr {t}, {t}, #1", "msr S3_0_C12_C12_5, {t}", "isb", t = out(reg) _); // ICC_SRE_EL1
        asm!("msr S3_0_C4_C6_0, {}", in(reg) 0xffu64); // ICC_PMR_EL1
        asm!("msr S3_0_C12_C12_3, {}", in(reg) 0u64); // ICC_BPR1_EL1
        asm!("msr S3_0_C12_C12_7, {}", "isb", in(reg) 1u64); // ICC_IGRPEN1_EL1
    }
    timer_off();
}

/// Route shared peripheral interrupt `intid` to this CPU (group 1, mid
/// priority, level-triggered).
pub fn enable_spi(intid: u32) {
    let n = intid as u64;
    // SAFETY: GIC distributor registers, mapped at GICD.
    unsafe {
        let igroupr = reg32(GICD + 0x80 + (n / 32) * 4);
        igroupr.write_volatile(igroupr.read_volatile() | (1 << (n % 32)));
        ((GICD + 0x400 + n) as *mut u8).write_volatile(0x80); // GICD_IPRIORITYR
        ((GICD + 0x6000 + n * 8) as *mut u64).write_volatile(0); // GICD_IROUTER: affinity 0.0.0.0
        reg32(GICD + 0x100 + (n / 32) * 4).write_volatile(1 << (n % 32)); // GICD_ISENABLER
    }
}

/// Send the kick SGI to CPU `cpu` (affinity 0.0.0.cpu).
pub fn send_sgi(cpu: u32) {
    // ICC_SGI1R_EL1: INTID in [27:24], target list in [15:0] (aff1..3 = 0).
    let v = ((KICK_INTID as u64) << 24) | (1u64 << cpu);
    unsafe { asm!("msr S3_0_C12_C11_5, {}", "isb", in(reg) v) };
}

/// Is an interrupt pending for this CPU (without acknowledging it)?
pub fn pending() -> bool {
    let id: u64;
    unsafe { asm!("mrs {}, S3_0_C12_C12_2", out(reg) id) }; // ICC_HPPIR1_EL1
    ((id & 0xff_ffff) as u32) < SPURIOUS
}

/// Acknowledge the highest-priority pending interrupt, if any.
pub fn ack() -> Option<u32> {
    let id: u64;
    unsafe { asm!("mrs {}, S3_0_C12_C12_0", out(reg) id) }; // ICC_IAR1_EL1
    let id = (id & 0xff_ffff) as u32;
    (id < SPURIOUS).then_some(id)
}

pub fn eoi(id: u32) {
    unsafe { asm!("msr S3_0_C12_C12_1, {}", "isb", in(reg) id as u64) }; // ICC_EOIR1_EL1
}

/// Fire the timer interrupt at monotonic time `deadline_ns` (immediately if it has passed).
pub fn timer_at(deadline_ns: u64) {
    let cval = time::counter_at(deadline_ns);
    unsafe { asm!("msr cntv_cval_el0, {}", "msr cntv_ctl_el0, {}", "isb", in(reg) cval, in(reg) 1u64) };
}

pub fn timer_off() {
    unsafe { asm!("msr cntv_ctl_el0, {}", "isb", in(reg) 0u64) };
}
