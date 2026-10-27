//! Interrupts: GICv3 (QEMU `virt` layout) and the EL1 virtual timer.
//!
//! The kernel always runs with IRQs masked. Interrupts are taken only from
//! EL0 (preemption) or noticed after `wfi` in the idle loop, which wakes on a
//! pending interrupt even while masked.

use core::arch::asm;

use crate::mm::KERNEL_OFFSET;
use crate::time;

const GICD: u64 = KERNEL_OFFSET + 0x0800_0000;
/// Redistributor of CPU 0: RD_base frame, then SGI_base frame 64 KiB later.
const GICR: u64 = KERNEL_OFFSET + 0x080A_0000;
const GICR_SGI: u64 = GICR + 0x1_0000;

/// Virtual timer PPI.
pub const TIMER_INTID: u32 = 27;
const SPURIOUS: u32 = 1023;

fn reg32(addr: u64) -> *mut u32 {
    addr as *mut u32
}

pub fn init() {
    unsafe {
        // Distributor: affinity routing, group 1 enabled (single security state).
        let ctlr = reg32(GICD);
        ctlr.write_volatile((1 << 4) | (1 << 1));
        while ctlr.read_volatile() & (1 << 31) != 0 {}
        // Wake the redistributor.
        let waker = reg32(GICR + 0x14);
        waker.write_volatile(waker.read_volatile() & !(1 << 1));
        while waker.read_volatile() & (1 << 2) != 0 {}
        // Timer PPI: group 1, mid priority, enabled.
        let igroupr0 = reg32(GICR_SGI + 0x80);
        igroupr0.write_volatile(igroupr0.read_volatile() | (1 << TIMER_INTID));
        ((GICR_SGI + 0x400 + TIMER_INTID as u64) as *mut u8).write_volatile(0x80);
        reg32(GICR_SGI + 0x100).write_volatile(1 << TIMER_INTID);
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

/// Sleep until an interrupt is pending and acknowledge it (the caller
/// handles it and signals EOI). IRQs stay masked.
pub fn wait_for_interrupt() -> Option<u32> {
    unsafe { asm!("dsb sy", "wfi") };
    ack()
}
