//! File descriptor table and open file descriptions.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::errno::*;
use crate::fs::{Content, Dev, Ino};
use crate::ipc::{self, EPOLLIN, EPOLLOUT, EventFd, PipeEnd, SocketEnd};

pub const MAX_FDS: usize = 1024;
/// Open file descriptions in all processes together (Linux's file-max):
/// each takes kernel memory, and descriptor limits are per process.
pub const MAX_OPEN_FILES: usize = 4096;
static OPEN_FILES: AtomicUsize = AtomicUsize::new(0);

pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;

pub enum FileKind {
    /// Not connected to anything yet: reads return EOF.
    Stdin,
    Stdout,
    Stderr,
    Node(Ino),
    Dev(Dev, Ino),
    Pipe(PipeEnd),
    /// AF_UNIX stream socket from socketpair().
    Socket(SocketEnd),
    EventFd(Arc<Mutex<EventFd>>),
    Epoll(Arc<Mutex<Epoll>>),
    /// A /proc or /sys file: contents generated at open.
    Generated(Vec<u8>),
    Inotify(Inotify),
    TimerFd(Arc<Mutex<crate::timer::TimerFd>>),
    /// A NETLINK_ROUTE socket (netlink.rs).
    Netlink(crate::netlink::Netlink),
    /// An AF_UNIX socket of this type that isn't bound or connected (binding
    /// to paths isn't implemented yet). Good for interface ioctls.
    UnixUnbound(u64),
    /// signalfd: reads pending signals in this mask.
    SignalFd(u64),
}

/// Watches are recorded but never fire (yet): the fd is never readable.
#[derive(Default)]
pub struct Inotify {
    pub watches: BTreeMap<i32, Ino>,
    pub next_wd: i32,
}

/// Watches across all inotify instances (Linux's max_user_watches): they
/// take kernel memory.
pub const MAX_WATCHES: u64 = 8192;
pub static WATCHES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

impl Drop for Inotify {
    fn drop(&mut self) {
        WATCHES.fetch_sub(self.watches.len() as u64, core::sync::atomic::Ordering::Relaxed);
    }
}

impl FileKind {
    /// Current readiness (EPOLL* bits) and a counter that changes whenever
    /// the readiness might have (for edge-triggered epoll).
    pub fn poll(&self) -> (u32, u64) {
        match self {
            // stdin is readable with data or at end-of-file; output is
            // writable while the console has buffers free.
            FileKind::Stdin => {
                let (_, readable, version) = crate::console::stdin_state();
                (if readable { EPOLLIN } else { 0 }, version)
            }
            FileKind::Stdout | FileKind::Stderr => {
                let (writable, version) = crate::console::output_state();
                (if writable { EPOLLOUT } else { 0 }, version)
            }
            FileKind::Node(_) | FileKind::Dev(..) | FileKind::Generated(_) => (EPOLLIN | EPOLLOUT, 0),
            FileKind::Inotify(_) => (0, 0),
            FileKind::TimerFd(t) => {
                let mut t = t.lock();
                t.update(crate::time::monotonic_ns());
                (if t.expirations > 0 { EPOLLIN } else { 0 }, t.version)
            }
            FileKind::Pipe(end) => end.poll(),
            FileKind::Netlink(nl) => nl.poll(),
            FileKind::UnixUnbound(_) => (EPOLLOUT | crate::ipc::EPOLLHUP, 0),
            // Depends on the reader's pending signals: see file::poll_kind.
            FileKind::SignalFd(_) => (0, 0),
            FileKind::Socket(s) => s.poll(),
            FileKind::EventFd(e) => e.lock().poll(),
            // Nested epoll is not supported (epoll_ctl refuses it).
            FileKind::Epoll(_) => (0, 0),
        }
    }
}

pub struct OpenFile {
    pub kind: FileKind,
    pub offset: u64,
    /// Access mode and status flags (O_APPEND, O_NONBLOCK, ...).
    pub flags: u32,
    /// Opened with O_PATH: only usable as a dirfd / for fstat.
    pub path_only: bool,
    /// A regular file's contents, held so they outlive an unlink.
    pub content: Option<Content>,
    /// Keeps the node's slot from being reused while this is open (`fs::Fs::pin`).
    pub pin: Option<Arc<()>>,
    /// getdents: the last directory entry returned.
    pub dir_pos: Option<alloc::string::String>,
    /// Kernel memory this file holds (generated /proc contents).
    pub held: Option<crate::kmem::Charge>,
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        OPEN_FILES.fetch_sub(1, Ordering::Relaxed);
    }
}

impl OpenFile {
    pub fn nonblocking(&self) -> bool {
        self.flags & O_NONBLOCK != 0
    }
}

pub type FileRef = Arc<Mutex<OpenFile>>;

/// An epoll instance: the interest list, keyed by fd.
#[derive(Default)]
pub struct Epoll {
    pub interest: BTreeMap<u64, Registration>,
}

pub struct Registration {
    /// Registrations vanish when the file is closed everywhere, as on Linux.
    pub file: Weak<Mutex<OpenFile>>,
    pub events: u32,
    pub data: u64,
    /// Edge-triggered bookkeeping: the file's change counter when last reported.
    pub reported_version: Option<u64>,
}

#[derive(Clone)]
pub struct FdEntry {
    pub file: FileRef,
    pub cloexec: bool,
}

/// A process's descriptors. Forking copies the table; the open files are
/// shared, as on Linux.
#[derive(Clone)]
pub struct FdTable {
    slots: Vec<Option<FdEntry>>,
}

pub fn new_file(kind: FileKind, flags: u32) -> FileRef {
    OPEN_FILES.fetch_add(1, Ordering::Relaxed);
    Arc::new(Mutex::new(OpenFile {
        kind,
        offset: 0,
        flags,
        path_only: false,
        content: None,
        pin: None,
        dir_pos: None,
        held: None,
    }))
}

impl FdTable {
    pub fn with_stdio() -> Self {
        let mut t = FdTable { slots: Vec::new() };
        for (kind, flags) in [(FileKind::Stdin, O_RDONLY), (FileKind::Stdout, O_WRONLY), (FileKind::Stderr, O_WRONLY)] {
            t.slots.push(Some(FdEntry { file: new_file(kind, flags), cloexec: false }));
        }
        t
    }

    /// No descriptors at all (a process that has ended).
    pub fn empty() -> Self {
        ipc::changed();
        FdTable { slots: Vec::new() }
    }

    /// execve: close what's marked close-on-exec.
    pub fn close_on_exec(&mut self) {
        let mut closed = false;
        for s in self.slots.iter_mut() {
            if s.as_ref().is_some_and(|e| e.cloexec) {
                *s = None;
                closed = true;
            }
        }
        if closed {
            ipc::changed();
        }
    }

    fn slot(&self, fd: u64) -> Option<&FdEntry> {
        self.slots.get(usize::try_from(fd as i32).ok()?)?.as_ref()
    }

    pub fn get(&self, fd: u64) -> Result<FileRef, Errno> {
        Ok(self.slot(fd).ok_or(EBADF)?.file.clone())
    }

    pub fn entry_mut(&mut self, fd: u64) -> Result<&mut FdEntry, Errno> {
        let i = usize::try_from(fd as i32).map_err(|_| EBADF)?;
        self.slots.get_mut(i).and_then(|s| s.as_mut()).ok_or(EBADF)
    }

    /// Install at the lowest free descriptor >= `min`. Fails with ENFILE
    /// once there are too many open files everywhere (the new one, already
    /// made, is then dropped by the caller).
    pub fn alloc(&mut self, entry: FdEntry, min: usize) -> Result<u64, Errno> {
        if OPEN_FILES.load(Ordering::Relaxed) > MAX_OPEN_FILES {
            return Err(ENFILE);
        }
        let start = min.min(MAX_FDS);
        let i = (start..MAX_FDS).find(|&i| self.slots.get(i).is_none_or(|s| s.is_none())).ok_or(EMFILE)?;
        if i >= self.slots.len() {
            self.slots.resize(i + 1, None);
        }
        self.slots[i] = Some(entry);
        Ok(i as u64)
    }

    /// Install at exactly `fd`, replacing whatever was there (dup2/dup3).
    pub fn set(&mut self, fd: u64, entry: FdEntry) -> Result<(), Errno> {
        let i = usize::try_from(fd as i32).ok().filter(|&i| i < MAX_FDS).ok_or(EBADF)?;
        if i >= self.slots.len() {
            self.slots.resize(i + 1, None);
        }
        self.slots[i] = Some(entry);
        ipc::changed();
        Ok(())
    }

    pub fn close(&mut self, fd: u64) -> Result<(), Errno> {
        let i = usize::try_from(fd as i32).map_err(|_| EBADF)?;
        match self.slots.get_mut(i) {
            Some(s @ Some(_)) => {
                *s = None;
                ipc::changed();
                Ok(())
            }
            _ => Err(EBADF),
        }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Is there a free descriptor (so open can fail with EMFILE before it creates anything)?
    pub fn has_room(&self) -> bool {
        self.slots.len() < MAX_FDS || self.slots.iter().any(Option::is_none)
    }
}
