//! The machine the kernel runs on: where its devices are, for the VMM that
//! makes it (QEMU or `grix-vmm`) and the kernel that drives it. The items
//! at the top are arm64's; x86_64's are in [`x86_64`].
//!
//! On arm64 it's QEMU `virt`'s layout, which `grix-vmm` follows too, except for the
//! GIC redistributors: the boot image's header says where they are
//! ([`image::Header::gicr`](crate::image::Header)). Everything is below
//! [`RAM_BASE`](crate::image::RAM_BASE), which the kernel maps as device
//! memory.

/// GICv3 distributor.
pub const GICD: u64 = 0x0800_0000;
/// GICv3 redistributors on QEMU `virt` (128 KiB per CPU, right after the
/// distributor).
pub const GICR_QEMU: u64 = 0x080a_0000;
/// GICv3 redistributors on `grix-vmm`. Hypervisor.framework reserves room
/// for as many vCPUs as the machine could have (32 MiB on an M3), which
/// from [`GICR_QEMU`] would cover the UART and the virtio transports; here
/// that room runs up to [`GICR_GRIX_VMM_END`].
pub const GICR_GRIX_VMM: u64 = 0x1000_0000;
pub const GICR_GRIX_VMM_END: u64 = 0x3000_0000;

/// Each CPU's redistributor frames (RD_base, then SGI_base), CPU `n` at
/// `gicr + n * GICR_STRIDE`.
pub const GICR_STRIDE: u64 = 0x2_0000;

/// The most CPUs a machine has. CPU `n` has affinity 0.0.0.n.
pub const MAX_CPUS: u32 = 8;

/// A hypervisor call (HVC, SMCCC OEM range) asking the VMM to wake CPU x1
/// if it's waiting in WFI: a VMM that handles WFI itself (grix-vmm on
/// Hypervisor.framework) doesn't see the SGI that should have woken it.
/// Others answer NOT_SUPPORTED, and their WFI wakes on the SGI.
pub const KICK_CALL: u64 = 0xc300_0002;

/// PL011 UART, and its size.
pub const UART: u64 = 0x0900_0000;
pub const UART_SIZE: u64 = 0x1000;

/// virtio-mmio transports: `VIRTIO_SLOTS` of them, `VIRTIO_STRIDE` apart.
pub const VIRTIO: u64 = 0x0a00_0000;
pub const VIRTIO_STRIDE: u64 = 0x200;
pub const VIRTIO_SLOTS: u64 = 32;
/// Transport `i` interrupts on INTID `VIRTIO_IRQ + i` (SPI 16 + i).
pub const VIRTIO_IRQ: u32 = 48;

/// The virtio console's port for the host (port 0 is a `virtconsole`'s, which
/// QEMU drops output for under backpressure), and its two queues (port n > 0
/// has 2n + 2 and 2n + 3); queue 3 is control transmit.
pub const CONSOLE_PORT: u32 = 1;
pub const CONSOLE_RX: u32 = 2 * CONSOLE_PORT + 2;
pub const CONSOLE_TX: u32 = 2 * CONSOLE_PORT + 3;
pub const CONSOLE_CONTROL_TX: u32 = 3;

/// The x86_64 machine: QEMU `microvm`'s layout (with `ioapic2=off`), which
/// `grix-vmm` on x86 KVM follows too. RAM starts at 0 (up to
/// [`image::MAX_RAM`](crate::image::MAX_RAM), below the devices); the
/// kernel is loaded at 2 MiB and the boot image at [`x86_64::IMAGE_BASE`].
pub mod x86_64 {
    pub const RAM_BASE: u64 = 0;
    pub const IMAGE_BASE: u64 = 0x0800_0000;

    /// The 16550 UART's I/O ports (COM1).
    pub const UART_PORT: u16 = 0x3f8;

    /// virtio-mmio transports, as on `microvm`: transport `i` at
    /// `VIRTIO + i * VIRTIO_STRIDE`, on IOAPIC pin (GSI) `VIRTIO_GSI + i`.
    pub const VIRTIO: u64 = 0xfeb0_0000;
    pub const VIRTIO_STRIDE: u64 = 0x200;
    pub const VIRTIO_SLOTS: u64 = 8;
    pub const VIRTIO_GSI: u32 = 5;

    pub const IOAPIC: u64 = 0xfec0_0000;
    pub const LAPIC: u64 = 0xfee0_0000;

    /// The port the kernel's calls to the VMM go out on (KVM answers
    /// `vmcall` itself): `out` of [`crate::image::SNAPSHOT_CALL`] in eax,
    /// the answer in rax, rdi, rsi, rdx, rcx and r8, as arm64's x0..x5.
    /// Nothing else is there: QEMU ignores it, and rax comes back as it was.
    pub const VMM_PORT: u16 = 0x0e10;
}
