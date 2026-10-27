//! In-kernel I/O objects: pipes and eventfds, plus the generation counter
//! that tells the scheduler when blocked I/O may have become possible.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub const EPOLLIN: u32 = 0x1;
pub const EPOLLOUT: u32 = 0x4;
pub const EPOLLERR: u32 = 0x8;
pub const EPOLLHUP: u32 = 0x10;

static IO_GEN: AtomicU64 = AtomicU64::new(0);

/// Some pipe/eventfd changed state: threads blocked on I/O should re-check.
pub fn changed() {
    IO_GEN.fetch_add(1, Ordering::Relaxed);
}

pub fn generation() -> u64 {
    IO_GEN.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------- pipes

/// Linux's default pipe capacity.
pub const PIPE_CAPACITY: usize = 64 * 1024;
/// Writes up to this size are atomic.
pub const PIPE_BUF: usize = 4096;

pub struct Pipe {
    /// Its heap allocation is charged to the kernel memory budget (`charge`).
    pub buf: VecDeque<u8>,
    charge: crate::kmem::Charge,
    pub readers: usize,
    pub writers: usize,
    /// Bumped on every state change (for edge-triggered epoll).
    pub version: u64,
}

impl Pipe {
    pub fn space(&self) -> usize {
        PIPE_CAPACITY - self.buf.len()
    }

    /// Could a write add anything now? (Room in the pipe, and in memory.)
    pub fn writable(&self) -> bool {
        self.space() > 0 && (self.buf.capacity() > self.buf.len() || crate::kmem::available() > 0)
    }

    /// Make room for up to `n` more bytes and return how many fit: limited by
    /// the pipe's capacity and by the kernel memory budget.
    pub fn reserve(&mut self, n: usize) -> usize {
        let n = n.min(self.space());
        let spare = self.buf.capacity() - self.buf.len();
        if n <= spare {
            return n;
        }
        let want = self.buf.len() + n;
        if self.charge.resize(want as u64).is_err() {
            return spare;
        }
        self.buf.reserve_exact(n);
        // reserve_exact may round up; charge what was really allocated if we can.
        let _ = self.charge.resize(self.buf.capacity().max(want) as u64);
        n
    }

    /// Give the buffer's memory back once it has been read empty.
    pub fn drained(&mut self) {
        if self.buf.is_empty() && self.buf.capacity() > 0 {
            self.buf = VecDeque::new();
            let _ = self.charge.resize(0);
        }
    }

    pub fn touch(&mut self) {
        self.version += 1;
        changed();
    }
}

/// One end of a pipe. Dropping the last reference to an end closes it.
pub struct PipeEnd {
    pub pipe: Arc<Mutex<Pipe>>,
    pub write: bool,
}

pub fn pipe() -> (PipeEnd, PipeEnd) {
    let p = Arc::new(Mutex::new(Pipe {
        buf: VecDeque::new(),
        charge: crate::kmem::Charge::default(),
        readers: 1,
        writers: 1,
        version: 0,
    }));
    (PipeEnd { pipe: p.clone(), write: false }, PipeEnd { pipe: p, write: true })
}

impl PipeEnd {
    pub fn poll(&self) -> (u32, u64) {
        let p = self.pipe.lock();
        let mask = if self.write {
            (if p.writable() { EPOLLOUT } else { 0 }) | if p.readers == 0 { EPOLLERR } else { 0 }
        } else {
            (if p.buf.is_empty() { 0 } else { EPOLLIN }) | if p.writers == 0 { EPOLLHUP } else { 0 }
        };
        (mask, p.version)
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut p = self.pipe.lock();
        if self.write {
            p.writers -= 1;
        } else {
            p.readers -= 1;
        }
        p.touch();
    }
}

// ---------------------------------------------------------------- eventfd

pub const EVENTFD_MAX: u64 = u64::MAX - 1;

pub struct EventFd {
    pub count: u64,
    pub semaphore: bool,
    pub version: u64,
}

impl EventFd {
    pub fn new(initial: u64, semaphore: bool) -> Arc<Mutex<EventFd>> {
        Arc::new(Mutex::new(EventFd { count: initial, semaphore, version: 0 }))
    }

    pub fn poll(&self) -> (u32, u64) {
        let mask = (if self.count > 0 { EPOLLIN } else { 0 }) | if self.count < EVENTFD_MAX { EPOLLOUT } else { 0 };
        (mask, self.version)
    }

    pub fn touch(&mut self) {
        self.version += 1;
        changed();
    }
}

// ---------------------------------------------------------------- local sockets

/// One end of an AF_UNIX stream socket pair: two pipes, one per direction.
/// `None` once that direction has been shut down.
pub struct SocketEnd {
    pub rx: Option<PipeEnd>,
    pub tx: Option<PipeEnd>,
}

pub fn socketpair() -> (SocketEnd, SocketEnd) {
    let (a_read, a_write) = pipe();
    let (b_read, b_write) = pipe();
    (SocketEnd { rx: Some(a_read), tx: Some(b_write) }, SocketEnd { rx: Some(b_read), tx: Some(a_write) })
}

pub const EPOLLRDHUP: u32 = 0x2000;

impl SocketEnd {
    pub fn poll(&self) -> (u32, u64) {
        let (rmask, rver) = self.rx.as_ref().map_or((EPOLLIN | EPOLLRDHUP, 0), |r| {
            let (m, v) = r.poll();
            // Peer shut down writing: readable (EOF) and RDHUP.
            (if m & EPOLLHUP != 0 { (m & !EPOLLHUP) | EPOLLIN | EPOLLRDHUP } else { m }, v)
        });
        let (wmask, wver) = self.tx.as_ref().map_or((0, 0), |t| t.poll());
        let hup = if rmask & EPOLLRDHUP != 0 && (self.tx.is_none() || wmask & EPOLLERR != 0) { EPOLLHUP } else { 0 };
        (rmask | (wmask & !EPOLLERR) | hup, rver.wrapping_add(wver))
    }
}
