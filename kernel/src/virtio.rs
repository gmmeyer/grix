//! virtio-console over virtio-mmio (QEMU `virt`, modern/version 2 only):
//! the fast channel to the host. Frames (`grix_abi::wire`) travel in 4 KiB
//! buffers shared with the device, one notification per batch, where the
//! PL011 costs a VM exit per byte. The UART stays for what must work
//! without this: early boot and panics.
//!
//! QEMU reserves port 0 for `virtconsole`, which drops output the host
//! doesn't read fast enough, so we use port 1 (a `virtserialport`, which
//! waits instead). That needs the multiport feature, and opening the port
//! over the control queue. Its receive queue brings stdin, its transmit
//! queue carries everything the guest says.

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

use grix_abi::machine::{CONSOLE_CONTROL_TX, CONSOLE_PORT, CONSOLE_RX, CONSOLE_TX};

use crate::arch::machine::{VIRTIO_IRQ, VIRTIO_SLOTS, VIRTIO_STRIDE};

use crate::mm::{KERNEL_OFFSET, PAGE_SIZE, frame, p2v};

const MMIO_BASE: u64 = KERNEL_OFFSET + crate::arch::machine::VIRTIO;

const MAGIC: u64 = 0x000;
const VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const DEVICE_FEATURES: u64 = 0x010;
const DEVICE_FEATURES_SEL: u64 = 0x014;
const DRIVER_FEATURES: u64 = 0x020;
const DRIVER_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const STATUS: u64 = 0x070;
const QUEUE_DESC: u64 = 0x080;
const QUEUE_DRIVER: u64 = 0x090;
const QUEUE_DEVICE: u64 = 0x0a0;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
/// VIRTIO_F_VERSION_1 (feature bit 32).
const F_VERSION_1_HI: u32 = 1;
/// VIRTIO_CONSOLE_F_MULTIPORT (feature bit 1).
const F_MULTIPORT: u32 = 1 << 1;
const DEVICE_CONSOLE: u32 = 3;

/// The port we use and its queues. We don't set up the control receive
/// queue: QEMU drops the messages it would put there, and we need none.
const PORT: u32 = CONSOLE_PORT;
const PORT_RX: u32 = CONSOLE_RX;
const PORT_TX: u32 = CONSOLE_TX;
const CONTROL_TX: u32 = CONSOLE_CONTROL_TX;
/// struct virtio_console_control events.
const DEVICE_READY: u16 = 0;
const PORT_READY: u16 = 3;
const PORT_OPEN: u16 = 6;

const DESC_F_WRITE: u16 = 2;
const AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Descriptors per data queue (at most). The rings fit in one page: the
/// descriptor table at 0, the available ring after it, the used ring at 2 KiB.
const QSIZE: u16 = 32;
/// Transmit buffers: how much output can be on its way at once.
pub const TX_BUFFERS: usize = QSIZE as usize;
const AVAIL_OFFSET: u64 = 16 * QSIZE as u64;
const USED_OFFSET: u64 = 2048;
pub const BUF_SIZE: usize = PAGE_SIZE as usize;

fn read(base: u64, off: u64) -> u32 {
    // SAFETY: a register of a virtio-mmio transport (device memory, mapped
    // by boot.S).
    unsafe { ((base + off) as *const u32).read_volatile() }
}

fn write(base: u64, off: u64, v: u32) {
    // SAFETY: as for `read`.
    unsafe { ((base + off) as *mut u32).write_volatile(v) }
}

/// A split virtqueue whose descriptors each own one 4 KiB buffer.
struct Queue {
    index: u32,
    size: u16,
    /// Physical address of the ring page.
    ring: u64,
    /// Physical address of each descriptor's buffer.
    bufs: [u64; QSIZE as usize],
    /// Our copy of avail.idx.
    avail_idx: u16,
    /// used.idx as far as we've processed it.
    used_seen: u16,
}

impl Queue {
    /// Set up queue `index` with `size` (a power of two, at most QSIZE)
    /// descriptors.
    fn new(base: u64, index: u32, size: u16) -> Option<Queue> {
        write(base, QUEUE_SEL, index);
        if read(base, QUEUE_NUM_MAX) < size as u32 || read(base, QUEUE_READY) != 0 {
            return None;
        }
        let ring = frame::alloc()?;
        let mut bufs = [0u64; QSIZE as usize];
        for b in &mut bufs[..size as usize] {
            *b = frame::alloc()?;
        }
        write(base, QUEUE_NUM, size as u32);
        for (reg, off) in [(QUEUE_DESC, 0), (QUEUE_DRIVER, AVAIL_OFFSET), (QUEUE_DEVICE, USED_OFFSET)] {
            write(base, reg, (ring + off) as u32);
            write(base, reg + 4, ((ring + off) >> 32) as u32);
        }
        write(base, QUEUE_READY, 1);
        Some(Queue { index, size, ring, bufs, avail_idx: 0, used_seen: 0 })
    }

    fn at<T>(&self, off: u64) -> *mut T {
        p2v(self.ring + off) as *mut T
    }

    /// Offer descriptor `i` (its buffer, `len` bytes) to the device.
    fn push(&mut self, i: u16, len: u32, flags: u16) {
        let d = 16 * i as u64;
        // SAFETY: descriptor `i` of our ring page, struct virtq_desc
        // {addr: le64, len: le32, flags: le16, next: le16}, then a slot of
        // the available ring {flags, idx, ring[QSIZE]}.
        unsafe {
            self.at::<u64>(d).write_volatile(self.bufs[i as usize]);
            self.at::<u32>(d + 8).write_volatile(len);
            self.at::<u16>(d + 12).write_volatile(flags);
            self.at::<u16>(d + 14).write_volatile(0);
            self.at::<u16>(AVAIL_OFFSET + 4 + 2 * (self.avail_idx % self.size) as u64).write_volatile(i);
        }
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // The device must see the descriptor and ring entry before the index.
        fence(Ordering::SeqCst);
        // SAFETY: avail.idx.
        unsafe { self.at::<u16>(AVAIL_OFFSET + 2).write_volatile(self.avail_idx) };
    }

    fn set_avail_flags(&self, flags: u16) {
        // SAFETY: avail.flags.
        unsafe { self.at::<u16>(AVAIL_OFFSET).write_volatile(flags) };
    }

    fn notify(&self, base: u64) {
        // Ring updates complete before the device is told to look.
        crate::arch::device_barrier();
        write(base, QUEUE_NOTIFY, self.index);
    }

    /// The oldest buffer the device has finished with and we haven't
    /// consumed: (descriptor, bytes the device wrote).
    fn peek_used(&self) -> Option<(u16, u32)> {
        // SAFETY: used.idx, written by the device.
        let idx = unsafe { self.at::<u16>(USED_OFFSET + 2).read_volatile() };
        if idx == self.used_seen {
            return None;
        }
        // Read the element (and its buffer) only after seeing the index.
        fence(Ordering::SeqCst);
        let e = USED_OFFSET + 4 + 8 * (self.used_seen % self.size) as u64;
        // SAFETY: used.ring[...]: {id: le32, len: le32}.
        let (id, len) = unsafe { (self.at::<u32>(e).read_volatile(), self.at::<u32>(e + 4).read_volatile()) };
        Some((id as u16 % self.size, len.min(BUF_SIZE as u32)))
    }

    fn consume_used(&mut self) {
        self.used_seen = self.used_seen.wrapping_add(1);
    }

    /// Send control message `event` (value 1) about port `id` and wait for
    /// the device to take it.
    fn control(&mut self, base: u64, id: u32, event: u16) {
        let msg = self.buf(0);
        msg[..4].copy_from_slice(&id.to_le_bytes());
        msg[4..6].copy_from_slice(&event.to_le_bytes());
        msg[6..8].copy_from_slice(&1u16.to_le_bytes());
        self.push(0, 8, 0);
        self.notify(base);
        while self.peek_used().is_none() {
            core::hint::spin_loop();
        }
        self.consume_used();
    }

    fn buf(&mut self, i: u16) -> &mut [u8] {
        // SAFETY: the frame owned by descriptor `i`, linearly mapped. Only
        // touched while the device doesn't own it.
        unsafe { core::slice::from_raw_parts_mut(p2v(self.bufs[i as usize]) as *mut u8, BUF_SIZE) }
    }
}

/// What the host can still do for output: `Console::output`.
pub enum Output {
    /// Buffers someone waits for came back (as for `tx_interrupt`).
    RoomBack,
    /// Some are still on their way; the device interrupts as they get
    /// through.
    InFlight,
    /// Every buffer is back, and nobody waits for room.
    Idle,
}

pub struct Console {
    base: u64,
    pub irq: u32,
    rx: Queue,
    tx: Queue,
    /// Transmit descriptors the device doesn't have.
    tx_free: Vec<u16>,
    /// The device interrupts when it returns transmit buffers (someone is
    /// waiting for them).
    tx_irq: bool,
}

impl Console {
    /// Find the virtio console and set it up. `None` if there is none.
    pub fn probe() -> Option<Console> {
        let base = (0..VIRTIO_SLOTS).map(|i| MMIO_BASE + i * VIRTIO_STRIDE).find(|&b| {
            read(b, MAGIC) == 0x7472_6976 && read(b, VERSION) == 2 && read(b, DEVICE_ID) == DEVICE_CONSOLE
        })?;
        write(base, STATUS, 0); // reset
        write(base, STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        write(base, DEVICE_FEATURES_SEL, 1);
        if read(base, DEVICE_FEATURES) & F_VERSION_1_HI == 0 {
            return None;
        }
        write(base, DEVICE_FEATURES_SEL, 0);
        if read(base, DEVICE_FEATURES) & F_MULTIPORT == 0 {
            return None;
        }
        write(base, DRIVER_FEATURES_SEL, 0);
        write(base, DRIVER_FEATURES, F_MULTIPORT);
        write(base, DRIVER_FEATURES_SEL, 1);
        write(base, DRIVER_FEATURES, F_VERSION_1_HI);
        write(base, STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        if read(base, STATUS) & STATUS_FEATURES_OK == 0 {
            return None;
        }
        let mut control = Queue::new(base, CONTROL_TX, 1)?;
        let mut rx = Queue::new(base, PORT_RX, QSIZE)?;
        let tx = Queue::new(base, PORT_TX, QSIZE)?;
        // Only receiving needs an interrupt; transmit buffers are reclaimed
        // when they're needed.
        tx.set_avail_flags(AVAIL_F_NO_INTERRUPT);
        control.set_avail_flags(AVAIL_F_NO_INTERRUPT);
        for i in 0..QSIZE {
            rx.push(i, BUF_SIZE as u32, DESC_F_WRITE);
        }
        write(base, STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
        // What Linux's driver says: the device is ready, the port is set up,
        // and a program has it open (until then QEMU passes it no input).
        control.control(base, u32::MAX, DEVICE_READY);
        control.control(base, PORT, PORT_READY);
        control.control(base, PORT, PORT_OPEN);
        rx.notify(base);
        let slot = ((base - MMIO_BASE) / VIRTIO_STRIDE) as u32;
        Some(Console { base, irq: VIRTIO_IRQ + slot, rx, tx, tx_free: (0..QSIZE).rev().collect(), tx_irq: false })
    }

    /// Queue `parts` (encoded frames) for the host, packed into as few
    /// buffers as they fit, with one notification. When every buffer is
    /// with the device this spins until QEMU writes one out to the host, so
    /// it's for the kernel's own messages: programs use `try_send`.
    pub fn send(&mut self, parts: &[&[u8]]) {
        let mut cur: Option<(u16, usize)> = None;
        for &part in parts {
            let mut rest = part;
            while !rest.is_empty() {
                let (i, len) = match cur {
                    Some(c) => c,
                    None => (self.take_tx(), 0),
                };
                let n = rest.len().min(BUF_SIZE - len);
                self.tx.buf(i)[len..len + n].copy_from_slice(&rest[..n]);
                rest = &rest[n..];
                cur = Some((i, len + n));
                if len + n == BUF_SIZE {
                    self.tx.push(i, BUF_SIZE as u32, 0);
                    cur = None;
                }
            }
        }
        if let Some((i, len)) = cur {
            self.tx.push(i, len as u32, 0);
        }
        self.tx.notify(self.base);
    }

    /// Like `send` if `parts` fit in the free buffers. Otherwise send
    /// nothing, have the device interrupt when buffers come back (see
    /// `tx_interrupt`), and return false.
    pub fn try_send(&mut self, parts: &[&[u8]]) -> bool {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        if !self.room_for(len) {
            return false;
        }
        self.send(parts);
        true
    }

    /// Is there room for `len` bytes now? If not, ask for an interrupt
    /// when buffers come back.
    pub fn room_for(&mut self, len: usize) -> bool {
        self.reclaim_tx();
        if self.tx_free.len() * BUF_SIZE >= len {
            return true;
        }
        self.tx_irq = true;
        self.tx.set_avail_flags(0);
        // The device checks the flag after returning a buffer; we look for
        // returned buffers after setting it. One of us sees the other.
        fence(Ordering::SeqCst);
        self.reclaim_tx();
        self.tx_free.len() * BUF_SIZE >= len
    }

    /// What the host can still do for output (for finding deadlocks),
    /// decided from one look at the ring. Asking whether room came back
    /// and then, looking again, whether anything is still in flight would
    /// miss every buffer the device returns in between (the vCPU's thread
    /// preempted there, say): neither, and a writer waiting for them
    /// looks deadlocked.
    pub fn output(&mut self) -> Output {
        let wanted = self.tx_irq;
        // Looks again after asking for the interrupt, if it does.
        let all_back = self.room_for(QSIZE as usize * BUF_SIZE);
        if wanted && self.room_back() {
            Output::RoomBack
        } else if !all_back {
            Output::InFlight
        } else {
            // Nobody waits for room (`room_for` may have asked for it).
            self.tx_irq = false;
            self.tx.set_avail_flags(AVAIL_F_NO_INTERRUPT);
            Output::Idle
        }
    }

    /// After an interrupt: did transmit buffers that someone waits for come
    /// back? Stops those interrupts until they're wanted again.
    pub fn tx_interrupt(&mut self) -> bool {
        self.reclaim_tx();
        self.room_back()
    }

    /// `tx_interrupt` after its look at the ring.
    fn room_back(&mut self) -> bool {
        if !self.tx_irq || self.tx_free.is_empty() {
            return false;
        }
        self.tx_irq = false;
        self.tx.set_avail_flags(AVAIL_F_NO_INTERRUPT);
        true
    }

    fn reclaim_tx(&mut self) {
        while let Some((i, _)) = self.tx.peek_used() {
            self.tx.consume_used();
            self.tx_free.push(i);
        }
    }

    fn take_tx(&mut self) -> u16 {
        self.reclaim_tx();
        if let Some(i) = self.tx_free.pop() {
            return i;
        }
        // Buffers filled by this `send` may not have been announced yet.
        self.tx.notify(self.base);
        loop {
            self.reclaim_tx();
            if let Some(i) = self.tx_free.pop() {
                return i;
            }
            core::hint::spin_loop();
        }
    }

    /// Wait until the device has passed on everything sent (before powering
    /// off, so no output is lost), or until `give_up` says to stop.
    pub fn flush(&mut self, give_up: impl Fn() -> bool) {
        loop {
            self.reclaim_tx();
            if self.tx_free.len() == QSIZE as usize || give_up() {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// Acknowledge the device's interrupt. Done before looking at the rings,
    /// so a buffer used after we look raises it again.
    pub fn ack_interrupt(&mut self) {
        write(self.base, INTERRUPT_ACK, read(self.base, INTERRUPT_STATUS));
    }

    /// Hand received data, oldest first, to `take`, one buffer at a time.
    /// `take` returns false when it has no room: that buffer and the ones
    /// after it stay with us, and the device, out of buffers, stops reading
    /// the host's input.
    pub fn receive(&mut self, mut take: impl FnMut(&[u8]) -> bool) {
        let mut reposted = false;
        while let Some((i, len)) = self.rx.peek_used() {
            if !take(&self.rx.buf(i)[..len as usize]) {
                break;
            }
            self.rx.consume_used();
            self.rx.push(i, BUF_SIZE as u32, DESC_F_WRITE);
            reposted = true;
        }
        if reposted {
            self.rx.notify(self.base);
        }
    }
}
