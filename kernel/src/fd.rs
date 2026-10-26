//! File descriptor table and open file descriptions.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use spin::Mutex;

use crate::errno::*;
use crate::fs::{Dev, Ino};
use crate::ipc::{self, EPOLLIN, EPOLLOUT, EventFd, PipeEnd};

pub const MAX_FDS: usize = 1024;

pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_NONBLOCK: u32 = 0o4000;

pub enum FileKind {
    /// Not connected to anything yet: reads return EOF.
    Stdin,
    Stdout,
    Stderr,
    Node(Ino),
    Dev(Dev, Ino),
    Pipe(PipeEnd),
    EventFd(Arc<Mutex<EventFd>>),
    Epoll(Arc<Mutex<Epoll>>),
}

impl FileKind {
    /// Current readiness (EPOLL* bits) and a counter that changes whenever
    /// the readiness might have (for edge-triggered epoll).
    pub fn poll(&self) -> (u32, u64) {
        match self {
            // stdin is at EOF and output never blocks.
            FileKind::Stdin => (EPOLLIN, 0),
            FileKind::Stdout | FileKind::Stderr => (EPOLLOUT, 0),
            FileKind::Node(_) | FileKind::Dev(..) => (EPOLLIN | EPOLLOUT, 0),
            FileKind::Pipe(end) => end.poll(),
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

pub struct FdTable {
    slots: Vec<Option<FdEntry>>,
}

pub fn new_file(kind: FileKind, flags: u32) -> FileRef {
    Arc::new(Mutex::new(OpenFile { kind, offset: 0, flags, path_only: false }))
}

impl FdTable {
    pub fn with_stdio() -> Self {
        let mut t = FdTable { slots: Vec::new() };
        for (kind, flags) in [(FileKind::Stdin, O_RDONLY), (FileKind::Stdout, O_WRONLY), (FileKind::Stderr, O_WRONLY)] {
            t.slots.push(Some(FdEntry { file: new_file(kind, flags), cloexec: false }));
        }
        t
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

    /// Install at the lowest free descriptor >= `min`.
    pub fn alloc(&mut self, entry: FdEntry, min: usize) -> Result<u64, Errno> {
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
}
