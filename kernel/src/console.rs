//! Serial console (PL011) carrying framed messages to the host. See `grix_abi::wire`.

use core::fmt::{self, Write};
use grix_abi::wire::{self, Channel, ExitKind};
use spin::Mutex;

use crate::mm::KERNEL_OFFSET;

const UART: u64 = KERNEL_OFFSET + 0x0900_0000;
const UART_DR: u64 = 0x00;
const UART_FR: u64 = 0x18;
const FR_TXFF: u32 = 1 << 5;

static LOCK: Mutex<()> = Mutex::new(());

fn putb(b: u8) {
    unsafe {
        let fr = (UART + UART_FR) as *const u32;
        while fr.read_volatile() & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        ((UART + UART_DR) as *mut u32).write_volatile(b as u32);
    }
}

fn raw_write(ch: Channel, data: &[u8]) {
    for chunk in data.chunks(wire::MAX_FRAME) {
        for b in wire::frame_header(ch, chunk.len()) {
            putb(b);
        }
        for &b in chunk {
            putb(b);
        }
    }
}

pub fn write(ch: Channel, data: &[u8]) {
    let _guard = LOCK.lock();
    raw_write(ch, data);
}

pub fn event(ev: &wire::Event) {
    write(Channel::Event, &ev.encode());
}

/// Buffers formatted text into frames without needing the heap.
struct FrameWriter {
    ch: Channel,
    buf: [u8; 256],
    len: usize,
    locked: bool,
}

impl FrameWriter {
    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        if self.locked {
            write(self.ch, &self.buf[..self.len]);
        } else {
            raw_write(self.ch, &self.buf[..self.len]);
        }
        self.len = 0;
    }
}

impl Write for FrameWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.buf.len() {
                self.flush();
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

pub fn log(args: fmt::Arguments) {
    let mut w = FrameWriter { ch: Channel::Log, buf: [0; 256], len: 0, locked: true };
    let _ = w.write_fmt(args);
    w.flush();
}

/// Report final status and power off.
pub fn exit(kind: ExitKind, code: i32) -> ! {
    write(Channel::Exit, &wire::encode_exit(kind, code));
    crate::arch::power_off()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Lock-free: the panic may have happened while the console lock was held.
    let mut w = FrameWriter { ch: Channel::Log, buf: [0; 256], len: 0, locked: false };
    let _ = writeln!(w, "kernel panic: {info}");
    w.flush();
    raw_write(Channel::Exit, &wire::encode_exit(ExitKind::Panic, -1));
    crate::arch::power_off()
}

macro_rules! klog {
    ($($t:tt)*) => { $crate::console::log(format_args!($($t)*)) };
}
pub(crate) use klog;
