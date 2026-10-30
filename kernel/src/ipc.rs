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
    /// Bytes ever written and read (positions in the stream).
    pub written: u64,
    pub read: u64,
    /// Descriptors passed with SCM_RIGHTS on a stream socket, at the
    /// position of the first byte they came with.
    pub rights: VecDeque<(u64, crate::unix::Rights)>,
    /// An AF_UNIX stream's: who wrote the bytes from each position on (a
    /// run per writer, as Linux keeps credentials per skb), at most
    /// `MAX_CRED_RUNS`, charged to `kmem`.
    pub creds: Option<VecDeque<(u64, crate::unix::Cred)>>,
    creds_charge: crate::kmem::Charge,
}

/// Runs of different writers' bytes one stream holds: a writer whose run
/// would be one too many waits, as on Linux, where each write is an skb
/// charged to the socket's buffer.
pub const MAX_CRED_RUNS: usize = 256;

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

    /// Give the buffer's memory back once it has been read empty, and
    /// forget whose bytes were read.
    pub fn drained(&mut self) {
        if self.buf.is_empty() && self.buf.capacity() > 0 {
            self.buf = VecDeque::new();
            let _ = self.charge.resize(0);
        }
        self.prune_writers();
    }

    pub fn touch(&mut self) {
        self.version += 1;
        changed();
    }

    /// Bytes from `self.written` on come from `cred`: false if that's a
    /// new run there's no room for.
    pub fn note_writer(&mut self, cred: crate::unix::Cred) -> bool {
        let at = self.written;
        let Some(runs) = &mut self.creds else { return true };
        if runs.back().is_some_and(|&(_, c)| c == cred) {
            return true;
        }
        if runs.len() >= MAX_CRED_RUNS {
            return false;
        }
        let bytes = ((runs.len() + 1) * core::mem::size_of::<(u64, crate::unix::Cred)>()) as u64;
        if self.creds_charge.bytes() < bytes && self.creds_charge.resize(bytes.next_power_of_two()).is_err() {
            return false;
        }
        runs.push_back((at, cred));
        true
    }

    /// Who wrote the byte at `self.read`, and where the next writer's
    /// bytes start (None: nothing recorded).
    pub fn writer(&self) -> Option<(crate::unix::Cred, Option<u64>)> {
        let runs = self.creds.as_ref()?;
        let i = runs.iter().rposition(|&(pos, _)| pos <= self.read)?;
        Some((runs[i].1, runs.get(i + 1).map(|&(pos, _)| pos)))
    }

    /// Forget the runs read past.
    fn prune_writers(&mut self) {
        let (read, empty) = (self.read, self.buf.is_empty());
        let Some(runs) = &mut self.creds else { return };
        if empty {
            runs.clear();
        }
        while runs.get(1).is_some_and(|&(pos, _)| pos <= read) {
            runs.pop_front();
        }
        if runs.is_empty() {
            *runs = VecDeque::new();
            let _ = self.creds_charge.resize(0);
        }
    }
}

/// One end of a pipe. Dropping the last reference to an end closes it.
pub struct PipeEnd {
    pub pipe: Arc<Mutex<Pipe>>,
    pub write: bool,
}

fn new_pipe(readers: usize, writers: usize) -> Arc<Mutex<Pipe>> {
    Arc::new(Mutex::new(Pipe {
        buf: VecDeque::new(),
        charge: crate::kmem::Charge::default(),
        readers,
        writers,
        version: 0,
        written: 0,
        read: 0,
        rights: VecDeque::new(),
        creds: None,
        creds_charge: crate::kmem::Charge::default(),
    }))
}

pub fn pipe() -> (PipeEnd, PipeEnd) {
    let p = new_pipe(1, 1);
    (PipeEnd { pipe: p.clone(), write: false }, PipeEnd { pipe: p, write: true })
}

/// A named pipe (FIFO): whatever has it open shares one pipe, which goes,
/// with what's in it, when the last end closes, as on Linux.
#[derive(Default)]
pub struct Fifo {
    pipe: alloc::sync::Weak<Mutex<Pipe>>,
    /// How many times it was opened for reading and for writing: an open
    /// waiting for the other side waits for its count to change (the other
    /// side may have come and gone meanwhile).
    pub opened: [u64; 2],
}

impl Fifo {
    /// The ends open now: (readers, writers).
    pub fn ends(&self) -> (usize, usize) {
        self.pipe.upgrade().map_or((0, 0), |p| {
            let p = p.lock();
            (p.readers, p.writers)
        })
    }

    /// Another end, for reading or writing.
    pub fn open(&mut self, write: bool) -> PipeEnd {
        let pipe = self.pipe.upgrade().unwrap_or_else(|| {
            let p = new_pipe(0, 0);
            self.pipe = Arc::downgrade(&p);
            p
        });
        let mut p = pipe.lock();
        if write {
            p.writers += 1;
        } else {
            p.readers += 1;
        }
        self.opened[write as usize] += 1;
        p.touch();
        drop(p);
        PipeEnd { pipe, write }
    }
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
        // Nobody will read the descriptors passed this way: they close (once
        // the pipe's lock is given back, as one of them may be a socket
        // writing to it).
        let orphaned = if p.readers == 0 { core::mem::take(&mut p.rights) } else { VecDeque::new() };
        p.touch();
        drop(p);
        drop(orphaned);
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
    /// An AF_UNIX stream's names and peer (not a loopback TCP pair's).
    pub unix: Option<alloc::boxed::Box<crate::unix::StreamInfo>>,
}

pub fn socketpair() -> (SocketEnd, SocketEnd) {
    let (a_read, a_write) = pipe();
    let (b_read, b_write) = pipe();
    (
        SocketEnd { rx: Some(a_read), tx: Some(b_write), unix: None },
        SocketEnd { rx: Some(b_read), tx: Some(a_write), unix: None },
    )
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
