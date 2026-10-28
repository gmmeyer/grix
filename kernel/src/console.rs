//! The console: framed messages to the host and the program's stdin from
//! it (format in `grix_abi::wire`). They travel over virtio-console
//! (`virtio.rs`) once it's up. Before that, and for panics, frames go out
//! on the PL011 UART, which needs no memory and no lock.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};
use grix_abi::hostfs::Assembler;
use grix_abi::wire::{self, Channel, ExitKind, Input, InputDecoder};
use spin::Mutex;

use crate::mm::KERNEL_OFFSET;
use crate::virtio;

const UART: u64 = KERNEL_OFFSET + grix_abi::machine::UART;
const UART_DR: u64 = 0x00;
const UART_FR: u64 = 0x18;
const UART_LCR_H: u64 = 0x2c;
const UART_CR: u64 = 0x30;
const FR_TXFE: u32 = 1 << 7;
/// The PL011's FIFOs (QEMU's are 16 deep too).
const FIFO_DEPTH: usize = 16;

fn uart(reg: u64) -> *mut u32 {
    (UART + reg) as *mut u32
}

/// Set the UART up: 8-bit words, FIFOs on, transmitter enabled. Done first
/// thing at boot.
pub fn init() {
    // SAFETY: PL011 registers, mapped at UART.
    unsafe {
        uart(UART_LCR_H).write_volatile((3 << 5) | (1 << 4));
        uart(UART_CR).write_volatile(1 | (1 << 8)); // UARTEN, TXE
    }
}

/// Send bytes on the UART. Every register access is a VM exit, so wait for
/// an empty transmit FIFO once per FIFO-full of bytes instead of checking
/// before each one.
fn uart_put(parts: &[&[u8]]) {
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

/// Split `data` into frames and hand each (header, payload) to `out`.
fn frames(ch: Channel, data: &[u8], mut out: impl FnMut(&[&[u8]])) {
    for chunk in data.chunks(wire::MAX_FRAME) {
        out(&[&wire::frame_header(ch, chunk.len()), chunk]);
    }
}

/// stdin bytes received from the host and not read yet. The host sends no
/// more than the credit it was given (`link::STDIN_WINDOW`, then what the
/// program reads), so the console never stalls on stdin and networking
/// flows past it: backpressure all the way to whatever feeds the sandbox.
const STDIN_CAPACITY: usize = grix_abi::link::STDIN_WINDOW as usize;

struct Stdin {
    buf: VecDeque<u8>,
    /// The host said no more is coming (or stdin was never connected).
    eof: bool,
    decoder: Box<InputDecoder>,
    /// Bumped whenever stdin gets data or ends (for edge-triggered epoll).
    version: u64,
    /// Read since credit was last returned to the host.
    owed: u32,
}

struct Console {
    dev: virtio::Console,
    stdin: Stdin,
    /// Bumped when output room comes back (for edge-triggered epoll).
    out_version: u64,
    /// A live mount's answer, as it arrives and once it's all there.
    fs: Assembler,
    fs_reply: Option<Vec<u8>>,
    /// Networking messages that arrived while waiting for an answer, for
    /// the next `dispatch`.
    deferred: Vec<Vec<u8>>,
    /// Signals from the host, for the scheduler to deliver.
    signals: Vec<u32>,
}

/// Signals queued from the host at most (more are dropped, as a pending
/// standard signal would merge anyway).
const MAX_HOST_SIGNALS: usize = 32;

/// The signals the host sent since last asked.
pub fn take_host_signals() -> Vec<u32> {
    let mut guard = CONSOLE.lock();
    guard.as_mut().map_or_else(Vec::new, |c| core::mem::take(&mut c.signals))
}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

/// Switch to virtio-console. Needs the frame allocator.
pub fn init_virtio() {
    let dev = virtio::Console::probe().expect("no virtio console (QEMU must be started with one)");
    let stdin = Stdin { buf: VecDeque::new(), eof: true, decoder: Box::default(), version: 0, owed: 0 };
    *CONSOLE.lock() = Some(Console {
        dev,
        stdin,
        out_version: 0,
        fs: Assembler::default(),
        fs_reply: None,
        deferred: Vec::new(),
        signals: Vec::new(),
    });
}

pub fn write(ch: Channel, data: &[u8]) {
    let mut guard = CONSOLE.lock();
    match guard.as_mut() {
        Some(c) => frames(ch, data, |parts| c.dev.send(parts)),
        None => frames(ch, data, uart_put),
    }
}

/// The most a program's write puts in one frame: what fills one virtio
/// buffer exactly.
pub const WRITE_CHUNK: usize = virtio::BUF_SIZE - wire::FRAME_HEADER;

/// The most program output the console holds at once.
pub const OUTPUT_CAPACITY: usize = virtio::TX_BUFFERS * WRITE_CHUNK;

/// Is there room for `len` bytes (at most `OUTPUT_CAPACITY`) of program
/// output? If not, the console interrupt calls `ipc::changed` when there
/// may be.
pub fn output_room(len: usize) -> bool {
    let mut guard = CONSOLE.lock();
    guard.as_mut().is_none_or(|c| c.dev.room_for(len.div_ceil(WRITE_CHUNK) * virtio::BUF_SIZE))
}

/// A program's output (at most `WRITE_CHUNK` bytes): sent if there's room,
/// otherwise false, as for `output_room`. Unlike `write`, this never waits
/// for the host.
pub fn try_write(ch: Channel, data: &[u8]) -> bool {
    debug_assert!(data.len() <= WRITE_CHUNK);
    let mut guard = CONSOLE.lock();
    match guard.as_mut() {
        Some(c) => c.dev.try_send(&[&wire::frame_header(ch, data.len()), data]),
        None => {
            frames(ch, data, uart_put);
            true
        }
    }
}

/// (room for a program's write, version) for poll.
pub fn output_state() -> (bool, u64) {
    let mut guard = CONSOLE.lock();
    guard.as_mut().map_or((true, 0), |c| (c.dev.room_for(virtio::BUF_SIZE), c.out_version))
}

pub fn event(ev: &wire::Event) {
    write(Channel::Event, &ev.encode());
}

/// Buffers formatted text into frames without needing the heap.
struct FrameWriter {
    ch: Channel,
    buf: [u8; 256],
    len: usize,
    /// Straight to the UART, without taking the console lock (panics).
    uart: bool,
}

impl FrameWriter {
    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        if self.uart {
            frames(self.ch, &self.buf[..self.len], uart_put);
        } else {
            write(self.ch, &self.buf[..self.len]);
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
    let mut w = FrameWriter { ch: Channel::Log, buf: [0; 256], len: 0, uart: false };
    let _ = w.write_fmt(args);
    w.flush();
}

// ---------------------------------------------------------------- stdin

/// Take the device's interrupt (input, and output room coming back), once
/// the GIC is set up. Without `stdin_from_host`, stdin is at end-of-file
/// from the start.
pub fn start(stdin_from_host: bool) {
    let mut guard = CONSOLE.lock();
    let c = guard.as_mut().expect("console not initialised");
    crate::arch::irq::enable_spi(c.dev.irq);
    if stdin_from_host {
        c.stdin.eof = false;
    }
    // Whatever the host sent while we booted.
    let link = drain(c);
    drop(guard);
    dispatch(link);
}

/// Handle interrupt `id` if it's the console's: move received frames into
/// the stdin buffer, and wake writers when output room comes back.
pub fn interrupt(id: u32) -> bool {
    let mut guard = CONSOLE.lock();
    let Some(c) = guard.as_mut().filter(|c| c.dev.irq == id) else { return false };
    c.dev.ack_interrupt();
    let link = drain(c);
    if c.dev.tx_interrupt() {
        c.out_version += 1;
        crate::ipc::changed();
    }
    drop(guard);
    dispatch(link);
    true
}

/// Take what the host sent: stdin into its buffer, and networking messages
/// out, for `dispatch` once the console lock is released (handling them may
/// send replies).
fn drain(c: &mut Console) -> Vec<Vec<u8>> {
    let Console { dev, stdin, fs, fs_reply, deferred, signals, .. } = c;
    let Stdin { buf, eof, decoder, version, .. } = stdin;
    let mut changed = false;
    let mut link = core::mem::take(deferred);
    dev.receive(|bytes| {
        for &b in bytes {
            match decoder.push(b) {
                Some((Input::Link, msg)) => link.push(msg.to_vec()),
                Some((Input::Signal, &[sig])) if (1..=64).contains(&sig) && signals.len() < MAX_HOST_SIGNALS => {
                    signals.push(sig as u32);
                }
                // Garbled answers are dropped; the request then gets none.
                Some((Input::Fs, msg)) => {
                    if let Some(Ok(reply)) = fs.push(msg) {
                        *fs_reply = Some(reply);
                    }
                }
                // The host keeps within its credit; nothing past it fits.
                Some((Input::Stdin, data)) if !*eof && buf.len() + data.len() <= STDIN_CAPACITY => {
                    buf.extend(data);
                    changed = true;
                }
                Some((Input::StdinEof, _)) if !*eof => {
                    *eof = true;
                    changed = true;
                }
                _ => {}
            }
        }
        true
    });
    if changed {
        *version += 1;
        crate::ipc::changed();
    }
    link
}

fn dispatch(link: Vec<Vec<u8>>) {
    for msg in link {
        crate::inet::from_host(&msg);
    }
}

/// Send a live mount's request (`grix_abi::hostfs`) and wait for the
/// host's answer. The kernel does nothing else meanwhile, with interrupts
/// masked: this keeps file system code synchronous, and the host answers
/// from its own disk. Networking messages that arrive in the meantime wait
/// for the console's interrupt, which stays pending until the program runs
/// again: handling them here could take locks the caller holds.
pub fn host_request(msg: &[u8]) -> Vec<u8> {
    {
        let mut guard = CONSOLE.lock();
        let c = guard.as_mut().expect("live mounts need the virtio console");
        c.fs_reply = None;
        for (more, chunk) in grix_abi::hostfs::frames(msg) {
            c.dev.send(&[&wire::frame_header(Channel::Fs, chunk.len() + 1), &[more], chunk]);
        }
    }
    loop {
        let mut guard = CONSOLE.lock();
        let c = guard.as_mut().unwrap();
        let link = drain(c);
        c.deferred = link;
        if let Some(reply) = c.fs_reply.take() {
            return reply;
        }
        drop(guard);
        core::hint::spin_loop();
    }
}

/// Send a live mount's message that has no answer.
pub fn host_send(msg: &[u8]) {
    let mut guard = CONSOLE.lock();
    let Some(c) = guard.as_mut() else { return };
    for (more, chunk) in grix_abi::hostfs::frames(msg) {
        c.dev.send(&[&wire::frame_header(Channel::Fs, chunk.len() + 1), &[more], chunk]);
    }
}

pub enum StdinRead {
    Data(usize),
    Eof,
    /// Nothing yet, but more may come.
    Empty,
}

/// A program found stdin empty (read or polled it): it waits for input.
static STDIN_WAITED: AtomicBool = AtomicBool::new(false);

pub fn stdin_waited() -> bool {
    STDIN_WAITED.load(Ordering::Relaxed)
}

/// Before a snapshot: take everything the host has sent. True if there was
/// nothing (no input, signal or message, and no frame half-received), so
/// the machine carries nothing of the host's into the snapshot.
pub fn take_all_input() -> bool {
    let mut guard = CONSOLE.lock();
    let Some(c) = guard.as_mut() else { return true };
    c.dev.ack_interrupt();
    let (version, signals) = (c.stdin.version, c.signals.len());
    let link = drain(c);
    let quiet = link.is_empty() && c.stdin.version == version && c.signals.len() == signals && c.stdin.decoder.idle();
    drop(guard);
    dispatch(link);
    quiet
}

/// Take stdin bytes into `out`.
pub fn stdin_read(out: &mut [u8]) -> StdinRead {
    let mut guard = CONSOLE.lock();
    let Some(c) = guard.as_mut() else { return StdinRead::Eof };
    // Pick up anything that arrived since the last interrupt.
    let link = drain(c);
    let s = &mut c.stdin;
    let result = if s.buf.is_empty() {
        if s.eof {
            StdinRead::Eof
        } else {
            STDIN_WAITED.store(true, Ordering::Relaxed);
            StdinRead::Empty
        }
    } else {
        let n = out.len().min(s.buf.len());
        for (o, b) in out.iter_mut().zip(s.buf.drain(..n)) {
            *o = b;
        }
        if s.buf.is_empty() {
            s.buf = VecDeque::new(); // give the memory back
        }
        // Credit for the host, in batches (or once the buffer is empty).
        s.owed += n as u32;
        if !s.eof && (s.owed >= STDIN_CAPACITY as u32 / 4 || s.buf.is_empty()) {
            let msg = grix_abi::link::ToHost::StdinCredit { bytes: core::mem::take(&mut s.owed) }.encode();
            c.dev.send(&[&wire::frame_header(Channel::Link, msg.len()), &msg]);
        }
        StdinRead::Data(n)
    };
    drop(guard);
    dispatch(link);
    result
}

/// (bytes ready to read, readable: data or end-of-file, version)
pub fn stdin_state() -> (usize, bool, u64) {
    let guard = CONSOLE.lock();
    let state = guard.as_ref().map_or((0, true, 0), |c| {
        let s = &c.stdin;
        (s.buf.len(), !s.buf.is_empty() || s.eof, s.version)
    });
    if !state.1 {
        STDIN_WAITED.store(true, Ordering::Relaxed);
    }
    state
}

/// Can the host still wake a thread waiting for I/O, by sending stdin or
/// taking output? Then it isn't deadlocked. Output room that came back
/// (the interrupt for it may still be pending) wakes writers right away.
pub fn host_pending() -> bool {
    let net = crate::inet::host_pending();
    let mut guard = CONSOLE.lock();
    let Some(c) = guard.as_mut() else { return false };
    if c.dev.tx_interrupt() {
        c.out_version += 1;
        crate::ipc::changed();
        return true;
    }
    net || !c.stdin.eof || c.dev.in_flight()
}

/// Report the program's final status. (Exports may follow.)
pub fn report_exit(kind: ExitKind, code: i32) {
    write(Channel::Exit, &wire::encode_exit(kind, code));
}

/// Wait until everything sent has reached the host.
pub fn flush() {
    if let Some(c) = CONSOLE.lock().as_mut() {
        c.dev.flush(|| false);
    }
}

/// Power off once everything sent has reached the host.
pub fn power_off() -> ! {
    flush();
    crate::arch::power_off()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Let the device pass on what was already sent, unless the panic came
    // from inside the console. Bounded: the host may have stopped reading.
    if let Some(mut guard) = CONSOLE.try_lock()
        && let Some(c) = guard.as_mut()
    {
        let give_up = crate::arch::counter() + crate::arch::counter_freq();
        c.dev.flush(|| crate::arch::counter() > give_up);
    }
    let mut w = FrameWriter { ch: Channel::Log, buf: [0; 256], len: 0, uart: true };
    let _ = writeln!(w, "kernel panic: {info}");
    w.flush();
    frames(Channel::Exit, &wire::encode_exit(ExitKind::Panic, -1), uart_put);
    crate::arch::power_off()
}

macro_rules! klog {
    ($($t:tt)*) => { $crate::console::log(format_args!($($t)*)) };
}
pub(crate) use klog;
