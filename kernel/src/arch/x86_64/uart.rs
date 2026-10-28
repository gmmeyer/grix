//! The 16550 UART on COM1's ports: the console before virtio is up, and
//! for panics.

use core::arch::asm;

use grix_abi::machine::x86_64::UART_PORT;

const DATA: u16 = UART_PORT;
const IER: u16 = UART_PORT + 1;
const FCR: u16 = UART_PORT + 2;
const LCR: u16 = UART_PORT + 3;
const MCR: u16 = UART_PORT + 4;
const LSR: u16 = UART_PORT + 5;
const LSR_THRE: u8 = 1 << 5;
const FIFO_DEPTH: usize = 16;

pub(crate) fn outb(port: u16, v: u8) {
    // SAFETY: an I/O port write to a device of ours.
    unsafe { asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack)) };
}

pub(crate) fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: as above.
    unsafe { asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack)) };
    v
}

/// 115200 8N1, FIFOs on, no interrupts.
pub fn init() {
    outb(IER, 0);
    outb(LCR, 0x80);
    outb(DATA, 1);
    outb(IER, 0);
    outb(LCR, 3);
    outb(FCR, 0xc7);
    outb(MCR, 3);
}

/// Send bytes. Every port access is a VM exit, so wait for an empty
/// transmit FIFO once per FIFO-full of bytes instead of before each one.
pub fn put(parts: &[&[u8]]) {
    let mut room = 0;
    for &b in parts.iter().flat_map(|p| p.iter()) {
        if room == 0 {
            while inb(LSR) & LSR_THRE == 0 {
                core::hint::spin_loop();
            }
            room = FIFO_DEPTH;
        }
        outb(DATA, b);
        room -= 1;
    }
}
