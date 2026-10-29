//! Interrupts: the local APIC (xAPIC registers, `machine`'s address), the
//! IOAPIC for devices, and the APIC timer; and the TSC's rate.
//!
//! The kernel always runs with IF clear. An interrupt from user mode is
//! taken there; one that comes while a CPU idles in `sti; hlt` is only
//! noted (`taken`). Either way it waits in `PENDING` until `ack` returns
//! it, which is what the GIC's acknowledge register gives on arm64; one
//! still pending in the APIC (IRR) is let in for a moment first.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use grix_abi::machine::x86_64::{IOAPIC, LAPIC};

use super::uart::{inb, outb};
use crate::mm::KERNEL_OFFSET;
use crate::time;

/// The APIC timer's vector, the kick IPI's (`smp::kick`), and the TLB
/// flush IPI's (`flush_tlb`), which never reaches `ack`.
pub const TIMER_INTID: u32 = 0xec;
pub const KICK_INTID: u32 = 0xed;
pub const FLUSH_INTID: u32 = 0xee;
const SPURIOUS: u32 = 0xff;
/// Device GSI `g` interrupts on vector `DEVICE_VECTOR + g` (`ack` gives `g`).
const DEVICE_VECTOR: u32 = 0x30;
const DEVICE_GSIS: u32 = 24;

const MAX_CPUS: usize = grix_abi::machine::MAX_CPUS as usize;

/// Vectors taken and not yet acknowledged, per CPU.
static PENDING: [[AtomicU64; 4]; MAX_CPUS] = [const { [const { AtomicU64::new(0) }; 4] }; MAX_CPUS];

/// The APIC timer's rate (divide by 1), measured at boot.
static TIMER_HZ: AtomicU64 = AtomicU64::new(1_000_000_000);

fn lapic(reg: u64) -> *mut u32 {
    (KERNEL_OFFSET + LAPIC + reg) as *mut u32
}

fn read(reg: u64) -> u32 {
    // SAFETY: local APIC registers, mapped linearly.
    unsafe { lapic(reg).read_volatile() }
}

fn write(reg: u64, v: u32) {
    // SAFETY: as above.
    unsafe { lapic(reg).write_volatile(v) }
}

pub fn lapic_id() -> u32 {
    read(0x20) >> 24
}

fn me() -> usize {
    lapic_id() as usize % MAX_CPUS
}

/// Set interrupts up, on CPU 0: the 8259s masked (if the machine has them),
/// this CPU's APIC, and the timer's rate.
pub fn init(_gicr: u64) {
    outb(0x21, 0xff);
    outb(0xa1, 0xff);
    init_cpu(0);
    // Count down from the top for 10 ms of TSC.
    write(0x320, 1 << 16 | TIMER_INTID);
    write(0x380, u32::MAX);
    let tsc_hz = super::counter_freq();
    let start = super::counter();
    while super::counter() - start < tsc_hz / 100 {
        core::hint::spin_loop();
    }
    let left = read(0x390);
    write(0x380, 0);
    TIMER_HZ.store((u32::MAX - left) as u64 * 100, Ordering::Relaxed);
}

/// This CPU's local APIC: on, every priority accepted, the timer one-shot
/// at divide-by-1 and stopped.
pub fn init_cpu(_cpu: usize) {
    write(0xf0, 0x100 | SPURIOUS);
    write(0x80, 0);
    write(0x3e0, 0xb);
    timer_off();
}

fn ioapic(reg: u32, v: u32) {
    let base = (KERNEL_OFFSET + IOAPIC) as *mut u32;
    // SAFETY: the IOAPIC's index and data registers, mapped linearly.
    unsafe {
        base.write_volatile(reg);
        base.add(4).write_volatile(v);
    }
}

/// Route device GSI `gsi` to CPU 0: fixed delivery, level-triggered, active
/// high (virtio-mmio's lines).
pub fn enable_device_irq(gsi: u32) {
    ioapic(0x10 + 2 * gsi + 1, 0);
    ioapic(0x10 + 2 * gsi, (DEVICE_VECTOR + gsi) | 1 << 15);
}

/// An IPI to the CPU with APIC ID `cpu`: the ICR's low word (vector,
/// delivery mode, level), once the last one has gone.
fn ipi(cpu: u32, low: u32) {
    write(0x310, cpu << 24);
    write(0x300, low);
    while read(0x300) & (1 << 12) != 0 {
        core::hint::spin_loop();
    }
}

/// Send the kick IPI to CPU `cpu` (APIC ID `cpu`).
pub fn send_sgi(cpu: u32) {
    send_ipi(cpu, KICK_INTID);
}

/// Send fixed-delivery vector `vector` to CPU `cpu`.
pub fn send_ipi(cpu: u32, vector: u32) {
    ipi(cpu, vector | 1 << 14);
}

/// Start CPU `cpu` in real mode at physical `vector << 12`: INIT, then the
/// startup IPI twice, as the MP specification has it (its waits are for
/// real hardware: KVM's and QEMU's APICs need none).
pub fn start_ap(cpu: u32, vector: u8) {
    ipi(cpu, 0x500 | 1 << 14);
    for _ in 0..2 {
        ipi(cpu, 0x600 | 1 << 14 | vector as u32);
    }
}

/// A vector was delivered to this CPU (by a trap, or in the idle loop).
pub fn taken(vector: u8) {
    PENDING[me()][vector as usize / 64].fetch_or(1 << (vector % 64), Ordering::Relaxed);
}

/// Is one waiting for this CPU in the APIC (IRR) that IF kept out?
fn in_apic() -> bool {
    (0..8).any(|i| read(0x200 + i * 0x10) != 0)
}

/// Is an interrupt pending for this CPU (without acknowledging it)?
pub fn pending() -> bool {
    PENDING[me()].iter().any(|w| w.load(Ordering::Relaxed) != 0) || in_apic()
}

/// Acknowledge the highest pending interrupt, if any: a device's GSI, or
/// `TIMER_INTID` / `KICK_INTID`.
pub fn ack() -> Option<u32> {
    let mine = &PENDING[me()];
    if mine.iter().all(|w| w.load(Ordering::Relaxed) == 0) && in_apic() {
        // Let it in; it's noted (`taken`) and nothing else.
        // SAFETY: interrupts on for one instruction.
        unsafe { asm!("sti", "nop", "cli", options(nomem, nostack)) };
    }
    for i in (0..4).rev() {
        let w = mine[i].load(Ordering::Relaxed);
        if w != 0 {
            let bit = 63 - w.leading_zeros();
            mine[i].fetch_and(!(1 << bit), Ordering::Relaxed);
            let vector = i as u32 * 64 + bit;
            return Some(match vector {
                v if (DEVICE_VECTOR..DEVICE_VECTOR + DEVICE_GSIS).contains(&v) => v - DEVICE_VECTOR,
                v => v,
            });
        }
    }
    None
}

/// The end of an interrupt (the APIC's highest in service: they're taken
/// one at a time, and each `ack` has its `eoi`).
pub fn eoi(_id: u32) {
    write(0xb0, 0);
}

/// Fire the timer interrupt at monotonic time `deadline_ns` (at once if it
/// has passed; early if it's further than the counter reaches, and the
/// scheduler sets it again).
pub fn timer_at(deadline_ns: u64) {
    let delta = deadline_ns.saturating_sub(time::monotonic_ns());
    let ticks = (delta as u128 * TIMER_HZ.load(Ordering::Relaxed) as u128 / 1_000_000_000).clamp(1, u32::MAX as u128);
    write(0x320, TIMER_INTID);
    write(0x380, ticks as u32);
}

pub fn timer_off() {
    write(0x380, 0);
    write(0x320, 1 << 16 | TIMER_INTID);
}

/// The TSC's rate: what the hypervisor says (its timing leaf, which
/// grix-vmm and KVM-based VMMs fill in), what CPUID 0x15 says, or measured
/// against the PIT (QEMU under TCG: its TSC runs at the host's rate).
pub fn measure_tsc() -> u64 {
    let cpuid = super::cpuid;
    if cpuid(1, 0)[2] & (1 << 31) != 0 && cpuid(0x4000_0000, 0)[0] >= 0x4000_0010 {
        let khz = cpuid(0x4000_0010, 0)[0];
        if khz != 0 {
            return khz as u64 * 1000;
        }
    }
    if cpuid(0, 0)[0] >= 0x15 {
        let [den, num, crystal, _] = cpuid(0x15, 0);
        if den != 0 && num != 0 && crystal != 0 {
            return crystal as u64 * num as u64 / den as u64;
        }
    }
    pit_measure()
}

/// TSC ticks over 20 ms of the PIT's channel 0 (1.193182 MHz), read back by
/// latching its count: no gate or speaker port needed.
fn pit_measure() -> u64 {
    const PIT_HZ: u64 = 1_193_182;
    const TICKS: u64 = PIT_HZ / 50;
    // Channel 0, low then high byte, mode 2 (rate generator), from 0xffff.
    outb(0x43, 0x34);
    outb(0x40, 0xff);
    outb(0x40, 0xff);
    let count = || {
        outb(0x43, 0x00);
        let lo = inb(0x40) as u64;
        let hi = inb(0x40) as u64;
        hi << 8 | lo
    };
    let start = count();
    let tsc0 = super::counter();
    let mut elapsed = 0;
    let mut last = start;
    // A machine without a PIT reads all ones: give up after a while (each
    // read is a VM exit), and guess.
    for _ in 0..4_000_000 {
        if elapsed >= TICKS {
            break;
        }
        let now = count();
        elapsed += (last + 0x1_0000 - now) % 0x1_0000;
        last = now;
    }
    let tsc = super::counter() - tsc0;
    // (Too early to say so: the console isn't up.)
    if elapsed < TICKS {
        return 1_000_000_000;
    }
    (tsc as u128 * PIT_HZ as u128 / elapsed as u128) as u64
}
