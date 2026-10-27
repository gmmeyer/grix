//! Serial console (PL011) carrying framed messages to the host, and the
//! program's stdin from it. See `grix_abi::wire`.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::fmt::{self, Write};
use grix_abi::wire::{self, Channel, ExitKind, Input, InputDecoder};
use spin::Mutex;

use crate::mm::KERNEL_OFFSET;

const UART: u64 = KERNEL_OFFSET + 0x0900_0000;
const UART_DR: u64 = 0x00;
const UART_FR: u64 = 0x18;
const UART_LCR_H: u64 = 0x2c;
const UART_CR: u64 = 0x30;
const UART_IMSC: u64 = 0x38;
const FR_RXFE: u32 = 1 << 4;
const FR_RXFF: u32 = 1 << 6;
const FR_TXFE: u32 = 1 << 7;
/// The PL011's FIFOs (QEMU's are 16 deep too).
const FIFO_DEPTH: usize = 16;
/// Receive and receive-timeout interrupts (the FIFO filling up, or bytes
/// sitting in it).
const INT_RX: u32 = (1 << 4) | (1 << 6);

fn uart(reg: u64) -> *mut u32 {
    (UART + reg) as *mut u32
}

static LOCK: Mutex<()> = Mutex::new(());

/// Set the UART up: 8-bit words, FIFOs on, transmitter and receiver
/// enabled. Done first thing at boot. Turning the FIFOs on empties them,
/// which is harmless because the host sends nothing before Ready.
pub fn init() {
    // SAFETY: PL011 registers, mapped at UART.
    unsafe {
        uart(UART_LCR_H).write_volatile((3 << 5) | (1 << 4));
        uart(UART_CR).write_volatile(1 | (1 << 8) | (1 << 9)); // UARTEN, TXE, RXE
    }
}

/// Send bytes. Every UART register access is a VM exit, so wait for an
/// empty transmit FIFO once per FIFO-full of bytes instead of checking
/// before each one.
fn put_bytes(parts: &[&[u8]]) {
    let mut room = 0;
    for &b in parts.iter().flat_map(|p| p.iter()) {
        if room == 0 {
            // SAFETY: PL011 registers, mapped at UART.
            while unsafe { uart(UART_FR).read_volatile() } & FR_TXFE == 0 {
                core::hint::spin_loop();
            }
            room = FIFO_DEPTH;
        }
        // SAFETY: as above.
        unsafe { uart(UART_DR).write_volatile(b as u32) };
        room -= 1;
    }
}

fn raw_write(ch: Channel, data: &[u8]) {
    // An empty frame (Ready) still gets its header.
    if data.is_empty() {
        put_bytes(&[&wire::frame_header(ch, 0)]);
    }
    for chunk in data.chunks(wire::MAX_FRAME) {
        put_bytes(&[&wire::frame_header(ch, chunk.len()), chunk]);
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

// ---------------------------------------------------------------- stdin

/// stdin bytes received from the host and not read yet. When it's nearly
/// full the UART stops being drained, so QEMU stops reading the host's input:
/// backpressure all the way to whatever feeds the sandbox.
const STDIN_CAPACITY: usize = 64 * 1024;

struct Stdin {
    buf: VecDeque<u8>,
    /// The host said no more is coming (or stdin was never connected).
    eof: bool,
    decoder: Box<InputDecoder>,
    /// Bumped whenever stdin gets data or ends (for edge-triggered epoll).
    version: u64,
}

static STDIN: Mutex<Option<Stdin>> = Mutex::new(None);

/// Connect stdin: with `from_host`, enable the UART's receiver and its
/// interrupt; otherwise stdin is at end-of-file from the start.
pub fn init_stdin(from_host: bool) {
    *STDIN.lock() = Some(Stdin { buf: VecDeque::new(), eof: !from_host, decoder: Box::default(), version: 0 });
    if from_host {
        // The FIFOs are on (see `init`), so QEMU hands over 16 bytes per
        // trip instead of one.
        // SAFETY: PL011 registers, mapped at UART.
        unsafe { uart(UART_IMSC).write_volatile(INT_RX) };
        crate::arch::irq::enable_uart();
        write(Channel::Ready, &[]);
    }
}

/// The UART interrupt: move received frames into the stdin buffer.
pub fn rx_interrupt() {
    if let Some(s) = STDIN.lock().as_mut() {
        drain(s);
    }
}

fn drain(s: &mut Stdin) {
    let Stdin { buf, eof, decoder, version } = s;
    let mut changed = false;
    // Only take bytes while any frames they complete still fit.
    while buf.len() + wire::MAX_FRAME + FIFO_DEPTH <= STDIN_CAPACITY {
        // SAFETY: PL011 registers, mapped at UART.
        let fr = unsafe { uart(UART_FR).read_volatile() };
        if fr & FR_RXFE != 0 {
            break;
        }
        // A full FIFO can be read out without checking FR before each byte.
        let n = if fr & FR_RXFF != 0 { FIFO_DEPTH } else { 1 };
        for _ in 0..n {
            // SAFETY: as above.
            let b = unsafe { uart(UART_DR).read_volatile() } as u8;
            match decoder.push(b) {
                Some((Input::Stdin, data)) => buf.extend(data),
                Some((Input::StdinEof, _)) => *eof = true,
                None => continue,
            }
            changed = true;
        }
    }
    let full = buf.len() + wire::MAX_FRAME + FIFO_DEPTH > STDIN_CAPACITY;
    // Masked while full; stdin_read unmasks it. No ICR write: reading DR
    // clears the receive interrupt, and clearing it here would lose the one
    // for a byte that arrived since FR last said empty.
    // SAFETY: as above.
    unsafe { uart(UART_IMSC).write_volatile(if full { 0 } else { INT_RX }) };
    if changed {
        *version += 1;
        crate::ipc::changed();
    }
}

pub enum StdinRead {
    Data(usize),
    Eof,
    /// Nothing yet, but more may come.
    Empty,
}

/// Take stdin bytes into `out`.
pub fn stdin_read(out: &mut [u8]) -> StdinRead {
    let mut guard = STDIN.lock();
    let Some(s) = guard.as_mut() else { return StdinRead::Eof };
    if s.buf.is_empty() {
        return if s.eof { StdinRead::Eof } else { StdinRead::Empty };
    }
    let n = out.len().min(s.buf.len());
    for (o, b) in out.iter_mut().zip(s.buf.drain(..n)) {
        *o = b;
    }
    if s.buf.is_empty() {
        s.buf = VecDeque::new(); // give the memory back
    }
    // There may be room again for frames waiting in the UART.
    if !s.eof {
        drain(s);
    }
    StdinRead::Data(n)
}

/// (bytes ready to read, readable: data or end-of-file, version)
pub fn stdin_state() -> (usize, bool, u64) {
    STDIN.lock().as_ref().map_or((0, true, 0), |s| (s.buf.len(), !s.buf.is_empty() || s.eof, s.version))
}

/// Could the host still send stdin? Then a thread waiting for input isn't
/// deadlocked.
pub fn stdin_open() -> bool {
    STDIN.lock().as_ref().is_some_and(|s| !s.eof)
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
