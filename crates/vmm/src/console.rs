//! A virtio console (virtio-mmio version 2, multiport) whose port 1 is our
//! stdin and stdout: the framed channel to the host. What the kernel's
//! driver (`kernel/src/virtio.rs`) needs, the way QEMU's
//! `virtio-serial-device` with a `virtserialport` behaves:
//!
//! - Output is held back, not dropped: a transmit buffer goes back to the
//!   guest only once its bytes are written to stdout, so a host that reads
//!   slowly stops the guest's writers (which then block or get EAGAIN).
//! - Input waits for the guest's receive buffers.
//!
//! The control queues carry nothing we need: messages the driver sends are
//! taken and dropped, and we never send any.

use std::fs::File;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::sync::atomic::{Ordering, fence};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use grix_abi::codec::{Reader, Writer};
use grix_abi::machine::{CONSOLE_RX, CONSOLE_TX};

use crate::mem::GuestMemory;

const MAGIC: u32 = 0x7472_6976;
const DEVICE_CONSOLE: u32 = 3;
/// VIRTIO_CONSOLE_F_MULTIPORT (bit 1) and VIRTIO_F_VERSION_1 (bit 32).
const FEATURES: [u32; 2] = [1 << 1, 1];
const STATUS_FEATURES_OK: u32 = 8;
const MAX_PORTS: u32 = 2;
/// Queues: port 0 rx/tx, control rx/tx, port 1 rx/tx.
const QUEUES: usize = 6;
const PORT1_RX: u32 = CONSOLE_RX;
const PORT1_TX: u32 = CONSOLE_TX;
const QUEUE_MAX: u16 = 64;

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
const AVAIL_F_NO_INTERRUPT: u16 = 1;

/// One split virtqueue, as the driver set it up.
#[derive(Clone, Copy, Default)]
struct Queue {
    num: u16,
    ready: bool,
    desc: u64,
    driver: u64,
    device: u64,
    /// Next available-ring entry to take.
    next_avail: u16,
    /// Our used.idx.
    used: u16,
}

#[derive(Default)]
struct State {
    status: u32,
    device_features_sel: u32,
    driver_features: [u32; 2],
    driver_features_sel: u32,
    queue_sel: u32,
    queues: [Queue; QUEUES],
    interrupt_status: u32,
    /// Transmit chains with the writer thread. At most a queue's worth,
    /// whatever the driver claims, so the channel to it never fills; kept
    /// across resets, which the writer's chains outlive.
    tx_in_flight: usize,
    /// Resets so far: the writer drops chains from before the last one.
    epoch: u64,
    /// The reader thread holds input the guest hasn't taken yet.
    input_pending: bool,
}

impl State {
    /// The device as the driver set it up, for a snapshot.
    fn save(&self) -> Vec<u8> {
        let mut w = Writer::new();
        for v in [self.status, self.device_features_sel, self.driver_features[0], self.driver_features[1]] {
            w.u32(v);
        }
        for v in [self.driver_features_sel, self.queue_sel, self.interrupt_status] {
            w.u32(v);
        }
        for q in &self.queues {
            w.u32(q.num as u32);
            w.u8(q.ready as u8);
            for a in [q.desc, q.driver, q.device] {
                w.u64(a);
            }
            w.u32(q.next_avail as u32);
            w.u32(q.used as u32);
        }
        w.buf
    }

    fn load(b: &[u8]) -> Option<State> {
        let mut r = Reader::new(b);
        let mut s = State {
            status: r.u32().ok()?,
            device_features_sel: r.u32().ok()?,
            driver_features: [r.u32().ok()?, r.u32().ok()?],
            driver_features_sel: r.u32().ok()?,
            queue_sel: r.u32().ok()?,
            interrupt_status: r.u32().ok()?,
            ..State::default()
        };
        for q in &mut s.queues {
            let num = r.u32().ok()?;
            q.num = if num.is_power_of_two() && num <= QUEUE_MAX as u32 { num as u16 } else { 0 };
            q.ready = r.u8().ok()? != 0 && q.num != 0;
            (q.desc, q.driver, q.device) = (r.u64().ok()?, r.u64().ok()?, r.u64().ok()?);
            q.next_avail = r.u32().ok()? as u16;
            q.used = r.u32().ok()? as u16;
        }
        r.done().ok()?;
        Some(s)
    }
}

/// A descriptor chain the driver made available: its head and its
/// (address, length, device-writable) parts.
struct Chain {
    head: u16,
    parts: Vec<(u64, u32, bool)>,
}

/// Drives the device's interrupt line (level-triggered).
pub type Line = Box<dyn Fn(bool) + Send + Sync>;

pub struct Console {
    mem: Arc<GuestMemory>,
    state: Mutex<State>,
    /// The guest gave us receive buffers (or set the queue up).
    rx_buffers: Condvar,
    line: Line,
    to_stdout: SyncSender<(u64, Vec<Chain>)>,
    /// The threads move nothing until the VMM has confined itself (`go`):
    /// a restored device's queues are a snapshot file's.
    started: Mutex<bool>,
    start: Condvar,
}

impl Console {
    /// The device, and the threads that move its data: stdin into the
    /// guest, the guest's output to stdout.
    pub fn start(mem: Arc<GuestMemory>, line: Line) -> Arc<Console> {
        Self::start_with(mem, line, State::default())
    }

    /// The device as `save` left it, for a run restored from a snapshot.
    pub fn restore(mem: Arc<GuestMemory>, line: Line, saved: &[u8]) -> Result<Arc<Console>, String> {
        let state = State::load(saved).ok_or("the snapshot's console state is malformed")?;
        let raised = state.interrupt_status != 0;
        let console = Self::start_with(mem, line, state);
        (console.line)(raised);
        Ok(console)
    }

    /// Take a snapshot with `f`, given the device's state, while nothing
    /// moves through the device (the lock keeps the reader and writer from
    /// touching guest memory). `None` if something is on its way (output,
    /// or input the guest hasn't seen: try again later).
    pub fn save_with<R>(&self, f: impl FnOnce(Vec<u8>) -> R) -> Option<R> {
        let s = self.lock();
        if s.tx_in_flight != 0 || s.input_pending || s.interrupt_status != 0 {
            return None;
        }
        let state = s.save();
        Some(f(state))
    }

    fn start_with(mem: Arc<GuestMemory>, line: Line, state: State) -> Arc<Console> {
        // A transmit queue's worth of batches; the guest has only as many
        // buffers anyway.
        let (to_stdout, batches) = sync_channel(QUEUE_MAX as usize);
        let console = Arc::new(Console {
            mem,
            state: Mutex::new(state),
            rx_buffers: Condvar::new(),
            line,
            to_stdout,
            started: Mutex::new(false),
            start: Condvar::new(),
        });
        let c = console.clone();
        std::thread::spawn(move || {
            c.wait_go();
            c.write_out(batches)
        });
        let c = console.clone();
        std::thread::spawn(move || {
            c.wait_go();
            c.read_in()
        });
        console
    }

    /// Let the threads move data: the VMM is confined.
    pub fn go(&self) {
        *self.started.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.start.notify_all();
    }

    fn wait_go(&self) {
        let mut started = self.started.lock().unwrap_or_else(|e| e.into_inner());
        while !*started {
            started = self.start.wait(started).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn read(&self, off: u64) -> u32 {
        let s = self.lock();
        let q = s.queues.get(s.queue_sel as usize);
        match off {
            0x000 => MAGIC,
            0x004 => 2,
            0x008 => DEVICE_CONSOLE,
            0x00c => 0x5849_5247, // "GRIX"
            0x010 => *FEATURES.get(s.device_features_sel as usize).unwrap_or(&0),
            0x034 => q.map_or(0, |_| QUEUE_MAX as u32),
            0x044 => q.is_some_and(|q| q.ready) as u32,
            0x060 => s.interrupt_status,
            0x070 => s.status,
            0x0fc => 0,         // config generation
            0x104 => MAX_PORTS, // config: cols, rows (0), max_nr_ports, emerg_wr
            _ => 0,
        }
    }

    pub fn write(&self, off: u64, v: u32) {
        let mut s = self.lock();
        let sel = s.queue_sel as usize;
        match off {
            0x014 => s.device_features_sel = v,
            0x020 => {
                let i = s.driver_features_sel as usize;
                if let Some(f) = s.driver_features.get_mut(i) {
                    *f = v;
                }
            }
            0x024 => s.driver_features_sel = v,
            0x030 => s.queue_sel = v,
            0x038 => {
                // Fixed once the queue is live.
                if let Some(q) = s.queues.get_mut(sel).filter(|q| !q.ready) {
                    q.num = if v.is_power_of_two() && v <= QUEUE_MAX as u32 { v as u16 } else { 0 };
                }
            }
            0x044 => {
                if let Some(q) = s.queues.get_mut(sel) {
                    q.ready = v == 1 && q.num != 0;
                    q.next_avail = 0;
                    q.used = 0;
                }
                if sel == PORT1_RX as usize {
                    self.rx_buffers.notify_all();
                }
            }
            0x050 => self.notify(&mut s, v),
            0x064 => {
                s.interrupt_status &= !v;
                if s.interrupt_status == 0 {
                    (self.line)(false);
                }
            }
            0x070 => {
                if v == 0 {
                    let (tx_in_flight, epoch) = (s.tx_in_flight, s.epoch + 1);
                    *s = State { tx_in_flight, epoch, ..State::default() };
                    (self.line)(false);
                    return;
                }
                let mut v = v;
                // Only what we offer, and the modern interface.
                let ok =
                    s.driver_features.iter().zip(FEATURES).all(|(d, f)| d & !f == 0) && s.driver_features[1] & 1 != 0;
                if v & STATUS_FEATURES_OK != 0 && !ok {
                    v &= !STATUS_FEATURES_OK;
                }
                s.status = v;
            }
            0x080 | 0x084 | 0x090 | 0x094 | 0x0a0 | 0x0a4 => {
                if let Some(q) = s.queues.get_mut(sel) {
                    let field = match off & !7 {
                        0x080 => &mut q.desc,
                        0x090 => &mut q.driver,
                        _ => &mut q.device,
                    };
                    *field = if off & 4 == 0 {
                        (*field & !0xffff_ffff) | v as u64
                    } else {
                        (*field & 0xffff_ffff) | (v as u64) << 32
                    };
                }
            }
            _ => {}
        }
    }

    /// The driver says queue `index` has new buffers.
    fn notify(&self, s: &mut State, index: u32) {
        match index {
            PORT1_RX => self.rx_buffers.notify_all(),
            PORT1_TX => self.take_output(s),
            // Control messages and port 0 (no one there): taken and dropped.
            i if (i as usize) < QUEUES => {
                while let Some(chain) = self.pop(s, i) {
                    self.push_used(s, i, chain.head, 0);
                }
                self.interrupt_if_wanted(s, i);
            }
            _ => {}
        }
    }

    /// Pass what the driver queued for output to the writer thread, which
    /// hands the buffers back once the bytes are out.
    fn take_output(&self, s: &mut State) {
        let num = s.queues[PORT1_TX as usize].num as usize;
        let mut batch = Vec::new();
        while s.tx_in_flight < num {
            let Some(chain) = self.pop(s, PORT1_TX) else { break };
            s.tx_in_flight += 1;
            batch.push(chain);
        }
        // Never blocks: the channel holds a queue's worth of chains.
        if !batch.is_empty() && self.to_stdout.send((s.epoch, batch)).is_err() {
            std::process::exit(1);
        }
    }

    /// Take the next chain the driver made available on queue `index`.
    fn pop(&self, s: &mut State, index: u32) -> Option<Chain> {
        let q = s.queues.get_mut(index as usize).filter(|q| q.ready && q.num != 0)?;
        let avail_idx = self.mem.read_u16(q.driver.wrapping_add(2))?;
        if avail_idx == q.next_avail {
            return None;
        }
        // The ring entry and descriptors were written before the index.
        fence(Ordering::Acquire);
        let head = self.mem.read_u16(q.driver.wrapping_add(4 + 2 * (q.next_avail % q.num) as u64))?;
        q.next_avail = q.next_avail.wrapping_add(1);
        let mut parts = Vec::new();
        let mut i = head;
        for _ in 0..q.num {
            if i >= q.num {
                return None;
            }
            let d = q.desc.wrapping_add(16 * i as u64);
            let (addr, len) = (self.mem.read_u64(d)?, self.mem.read_u32(d.wrapping_add(8))?);
            let (flags, next) = (self.mem.read_u16(d.wrapping_add(12))?, self.mem.read_u16(d.wrapping_add(14))?);
            parts.push((addr, len, flags & DESC_F_WRITE != 0));
            if flags & DESC_F_NEXT == 0 {
                return Some(Chain { head, parts });
            }
            i = next;
        }
        // A loop: the driver is broken; take nothing from it.
        None
    }

    /// Give chain `head` back with `len` bytes written into it. False if
    /// the queue's memory is bad.
    fn push_used(&self, s: &mut State, index: u32, head: u16, len: u32) -> bool {
        let Some(q) = s.queues.get_mut(index as usize).filter(|q| q.ready && q.num != 0) else { return false };
        let e = q.device.wrapping_add(4 + 8 * (q.used % q.num) as u64);
        let mut elem = [0u8; 8];
        elem[..4].copy_from_slice(&(head as u32).to_le_bytes());
        elem[4..].copy_from_slice(&len.to_le_bytes());
        if !self.mem.write(e, &elem) {
            return false;
        }
        q.used = q.used.wrapping_add(1);
        // The element before the index.
        fence(Ordering::Release);
        self.mem.write_u16(q.device.wrapping_add(2), q.used)
    }

    /// Interrupt unless the driver said not to. Read after the used index
    /// is out: the driver sets the flag, then looks at the used ring, so
    /// one of us sees the other.
    fn interrupt_if_wanted(&self, s: &mut State, index: u32) {
        let Some(q) = s.queues.get(index as usize).filter(|q| q.ready) else { return };
        fence(Ordering::SeqCst);
        if self.mem.read_u16(q.driver).is_some_and(|f| f & AVAIL_F_NO_INTERRUPT == 0) {
            s.interrupt_status |= 1;
            (self.line)(true);
        }
    }

    /// Stdin into the guest's receive buffers, as they come.
    fn read_in(self: Arc<Self>) {
        // SAFETY: fd 0 is ours for the process's life; never closed here.
        let mut stdin = ManuallyDrop::new(unsafe { File::from_raw_fd(0) });
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match stdin.read(&mut buf) {
                // The host holds our stdin open for the whole run: it's gone.
                Ok(0) => std::process::exit(0),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => std::process::exit(0),
            };
            let mut data = &buf[..n];
            let mut s = self.lock();
            s.input_pending = true;
            while !data.is_empty() {
                let Some(chain) = self.pop(&mut s, PORT1_RX) else {
                    s = self.rx_buffers.wait(s).unwrap_or_else(|e| e.into_inner());
                    continue;
                };
                let mut written = 0u32;
                for (addr, len, writable) in chain.parts {
                    if !writable || data.is_empty() {
                        continue;
                    }
                    let k = (len as usize).min(data.len());
                    if !self.mem.write(addr, &data[..k]) {
                        break;
                    }
                    data = &data[k..];
                    written += k as u32;
                }
                self.push_used(&mut s, PORT1_RX, chain.head, written);
                self.interrupt_if_wanted(&mut s, PORT1_RX);
            }
            s.input_pending = false;
        }
    }

    /// The guest's output to stdout, then its buffers back to it.
    fn write_out(self: Arc<Self>, batches: Receiver<(u64, Vec<Chain>)>) {
        // SAFETY: fd 1 is ours for the process's life; never closed here.
        let mut stdout = ManuallyDrop::new(unsafe { File::from_raw_fd(1) });
        // Copied out a piece at a time, whatever lengths the driver claims.
        const PIECE: usize = 64 * 1024;
        let mut out = Vec::with_capacity(PIECE);
        let mut put = |out: &mut Vec<u8>| {
            // The host went away: nothing more to do.
            if stdout.write_all(out).is_err() {
                std::process::exit(1);
            }
            out.clear();
        };
        for (epoch, batch) in batches {
            // From before a reset: the driver has started over without them.
            if epoch != self.lock().epoch {
                let mut s = self.lock();
                s.tx_in_flight = s.tx_in_flight.saturating_sub(batch.len());
                self.take_output(&mut s);
                continue;
            }
            for chain in &batch {
                for &(addr, len, writable) in &chain.parts {
                    // A part is in guest memory, or it's skipped.
                    if writable || !self.mem.contains(addr, len as usize) {
                        continue;
                    }
                    let mut done = 0;
                    while done < len as usize {
                        if out.len() == PIECE {
                            put(&mut out);
                        }
                        let k = (len as usize - done).min(PIECE - out.len());
                        let start = out.len();
                        out.resize(start + k, 0);
                        self.mem.read(addr + done as u64, &mut out[start..]);
                        done += k;
                    }
                }
            }
            put(&mut out);
            let mut s = self.lock();
            if s.epoch == epoch {
                for chain in &batch {
                    self.push_used(&mut s, PORT1_TX, chain.head, 0);
                }
                self.interrupt_if_wanted(&mut s, PORT1_TX);
            }
            s.tx_in_flight = s.tx_in_flight.saturating_sub(batch.len());
            // What the driver queued while we were full.
            self.take_output(&mut s);
        }
    }
}
