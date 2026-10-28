//! The PL011 UART: the console before virtio is up, and for panics.

use crate::mm::KERNEL_OFFSET;

const UART: u64 = KERNEL_OFFSET + grix_abi::machine::UART;
const UART_DR: u64 = 0x00;
const UART_FR: u64 = 0x18;
const UART_LCR_H: u64 = 0x2c;
const UART_CR: u64 = 0x30;
const FR_TXFE: u32 = 1 << 7;
/// The PL011's FIFOs (QEMU's are 16 deep too).
const FIFO_DEPTH: usize = 16;

fn reg(off: u64) -> *mut u32 {
    (UART + off) as *mut u32
}

/// 8-bit words, FIFOs on, transmitter enabled.
pub fn init() {
    // SAFETY: PL011 registers, mapped at UART.
    unsafe {
        reg(UART_LCR_H).write_volatile((3 << 5) | (1 << 4));
        reg(UART_CR).write_volatile(1 | (1 << 8)); // UARTEN, TXE
    }
}

/// Send bytes. Every register access is a VM exit, so wait for an empty
/// transmit FIFO once per FIFO-full of bytes instead of checking before
/// each one.
pub fn put(parts: &[&[u8]]) {
    let mut room = 0;
    for &b in parts.iter().flat_map(|p| p.iter()) {
        if room == 0 {
            // SAFETY: PL011 registers, mapped at UART.
            while unsafe { reg(UART_FR).read_volatile() } & FR_TXFE == 0 {
                core::hint::spin_loop();
            }
            room = FIFO_DEPTH;
        }
        // SAFETY: as above.
        unsafe { reg(UART_DR).write_volatile(b as u32) };
        room -= 1;
    }
}
