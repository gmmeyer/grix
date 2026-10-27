//! The machine the kernel runs on: where its devices are, for the VMM that
//! makes it (QEMU `virt` or `grix-vmm`) and the kernel that drives it.
//!
//! It's QEMU `virt`'s layout, which `grix-vmm` follows too, except for the
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
