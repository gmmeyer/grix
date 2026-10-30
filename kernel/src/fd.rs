//! File descriptor table and open file descriptions.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};

use crate::errno::*;
use crate::fs::{Content, Dev, Ino};
use crate::ipc::{self, EPOLLIN, EPOLLOUT, EventFd, PipeEnd, SocketEnd};

/// The most descriptors a table may have (/proc/sys/fs/nr_open), and so
/// RLIMIT_NOFILE's hard limit. A table grows with use, each slot charged
/// to the kernel memory budget, so this is a bound, not what it costs.
pub const MAX_FDS: usize = 65536;
/// RLIMIT_NOFILE's soft limit to start with, as Docker gives (programs
/// that want more raise it to the hard limit, as Redis does).
pub const NOFILE_DEFAULT: usize = 1024;
/// What `n` descriptor slots cost the kernel memory budget: those past
/// the first `NOFILE_DEFAULT`, which every table could always have (the
/// heap was sized for `MAX_PROCESSES` of those).
fn slots_cost(n: usize) -> u64 {
    n.saturating_sub(NOFILE_DEFAULT) as u64 * core::mem::size_of::<Option<FdEntry>>() as u64
}

/// A named pipe's node and the ends this open has: one, or both for
/// O_RDWR (which Linux allows on a FIFO, and never waits).
pub struct FifoFile {
    pub ino: Ino,
    pub read: Option<PipeEnd>,
    pub write: Option<PipeEnd>,
}

impl FifoFile {
    pub fn poll(&self) -> (u32, u64) {
        let (r, w) = (self.read.as_ref().map(PipeEnd::poll), self.write.as_ref().map(PipeEnd::poll));
        let (mask, version) = [r, w].into_iter().flatten().fold((0, 0), |(m, v), (m2, v2)| (m | m2, v.max(v2)));
        (mask, version)
    }
}
/// Open file descriptions in all processes together (Linux's file-max):
/// each takes kernel memory, and descriptor limits are per process.
pub const MAX_OPEN_FILES: usize = 4096;
static OPEN_FILES: AtomicUsize = AtomicUsize::new(0);

/// Open file descriptions now (/proc/sys/fs/file-nr).
pub fn open_files() -> usize {
    OPEN_FILES.load(Ordering::Relaxed)
}

pub const O_ACCMODE: u32 = 0o3;
pub const O_RDONLY: u32 = 0o0;
pub const O_WRONLY: u32 = 0o1;
pub const O_RDWR: u32 = 0o2;
pub const O_APPEND: u32 = 0o2000;
/// FASYNC: signal the owner when I/O becomes possible (fasync.rs).
pub const O_ASYNC: u32 = 0o20000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_CLOEXEC: u32 = 0o2000000;
/// O_CREAT | O_EXCL | O_TRUNC: open's, not the file's.
pub const O_CREAT_EXCL_TRUNC: u32 = 0o100 | 0o200 | 0o1000;

pub enum FileKind {
    /// Not connected to anything yet: reads return EOF.
    Stdin,
    Stdout,
    Stderr,
    Node(Ino),
    Dev(Dev, Ino),
    Pipe(PipeEnd),
    /// A named pipe opened by its path.
    Fifo(FifoFile),
    /// AF_UNIX stream socket from socketpair().
    Socket(SocketEnd),
    EventFd(Arc<Mutex<EventFd>>),
    Epoll(Arc<Mutex<Epoll>>),
    /// A /proc or /sys file: contents generated at open.
    Generated(Vec<u8>),
    Inotify(crate::inotify::Inotify),
    TimerFd(Arc<Mutex<crate::timer::TimerFd>>),
    /// A NETLINK_ROUTE socket (netlink.rs).
    Netlink(crate::netlink::Netlink),
    /// An AF_UNIX socket of this type that isn't bound or connected (binding
    /// to paths isn't implemented yet). Good for interface ioctls.
    UnixUnbound(u64),
    /// signalfd: reads pending signals in this mask.
    SignalFd(u64),
    /// An AF_INET/AF_INET6 socket (inet.rs).
    Inet(crate::inet::Inet),
    /// Either end of a pseudo-terminal, or the console's terminal (tty.rs).
    Pty(crate::tty::PtyEnd),
    /// An AF_UNIX socket that's named, listening, or passes messages
    /// (unix.rs; a connected stream is a `Socket`).
    Unix(crate::unix::SockRef),
    /// A pidfd: refers to process `pid` (pids aren't reused).
    PidFd(u32),
    /// /proc/<pid>/mem, for the process itself: reads and writes at its
    /// virtual addresses (the offset), through `uaccess`.
    ProcMem(u32),
    /// A Landlock ruleset being made (landlock.rs).
    Landlock(crate::landlock::RulesetRef),
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
            FileKind::Node(_) | FileKind::Dev(..) | FileKind::Generated(_) | FileKind::ProcMem(_) => {
                (EPOLLIN | EPOLLOUT, 0)
            }
            FileKind::Inotify(n) => n.poll(),
            FileKind::TimerFd(t) => {
                let mut t = t.lock();
                t.update(crate::time::monotonic_ns());
                (if t.expirations > 0 { EPOLLIN } else { 0 }, t.version)
            }
            FileKind::Pipe(end) => end.poll(),
            FileKind::Fifo(f) => f.poll(),
            FileKind::Netlink(nl) => nl.poll(),
            FileKind::UnixUnbound(_) => (EPOLLOUT | crate::ipc::EPOLLHUP, 0),
            // Depend on the reader's pending signals, or on other
            // processes: see file::poll_kind.
            FileKind::SignalFd(_) | FileKind::PidFd(_) => (0, 0),
            // No poll of its own: Linux's DEFAULT_POLLMASK.
            FileKind::Landlock(_) => (EPOLLIN | EPOLLOUT, 0),
            FileKind::Socket(s) => s.poll(),
            FileKind::Inet(s) => s.poll(),
            FileKind::Pty(end) => {
                let (mask, version) = end.tty.lock().poll(end.master);
                if !end.master && mask & EPOLLIN == 0 {
                    crate::tty::waiting_on(&end.tty);
                }
                (mask, version)
            }
            FileKind::Unix(s) => crate::unix::poll(s),
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
    /// It has taken flock or OFD locks (which go when it closes).
    pub locked: bool,
    /// O_ASYNC's owner and signal (F_SETOWN, F_SETSIG).
    pub fown: crate::fasync::Fown,
    /// A writable /proc comm file: the thread it names (pid, tid).
    pub comm_of: Option<(u32, u32)>,
    /// Rights the opener's Landlock domain refused that matter after the
    /// open (`landlock::TRUNCATE`, `IOCTL_DEV`): Linux's allowed_access,
    /// inverted, so a file opened any other way has them all.
    pub landlock_denied: u16,
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        OPEN_FILES.fetch_sub(1, Ordering::Relaxed);
        if self.locked {
            crate::locks::release_all(crate::locks::Owner::File(self.id()));
        }
    }
}

impl OpenFile {
    pub fn nonblocking(&self) -> bool {
        self.flags & O_NONBLOCK != 0
    }

    /// The open file description, as a lock owner.
    pub fn id(&self) -> usize {
        self as *const OpenFile as usize
    }

    /// The file a lock on this is a lock on: its node (inode numbers are
    /// small, unlike kernel addresses), or the open file itself.
    pub fn lock_key(&self) -> crate::locks::Key {
        match &self.kind {
            FileKind::Node(ino) | FileKind::Dev(_, ino) => *ino,
            FileKind::Pty(end) => end.ino,
            _ => self.id(),
        }
    }
}

pub type FileRef = Arc<Mutex<OpenFile>>;

/// The locks of two different files (`a`'s guard first), always taken in
/// the same order, so two CPUs with the pair the other way round can't
/// each hold what the other wants. One file twice would wait for itself:
/// a caller sees to that first.
pub fn lock_pair<'a>(a: &'a FileRef, b: &'a FileRef) -> (MutexGuard<'a, OpenFile>, MutexGuard<'a, OpenFile>) {
    debug_assert!(!Arc::ptr_eq(a, b), "one file locked twice");
    if Arc::as_ptr(a) < Arc::as_ptr(b) {
        let first = a.lock();
        (first, b.lock())
    } else {
        let first = b.lock();
        (a.lock(), first)
    }
}

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

/// A process's descriptors (Linux's files_struct). Forking copies the
/// table, sharing the open files, as on Linux; processes made with
/// CLONE_FILES share the table itself: this is a handle to it (`share`
/// another, `copy` a table of one's own). Every access is under the big
/// kernel lock, so the mutex is only ever held for a moment, and never
/// while an open file is dropped (which may take other locks).
pub struct FdTable {
    slots: Arc<Mutex<Slots>>,
    /// The process's RLIMIT_NOFILE soft limit (`Process::rlimits` has it
    /// too; prlimit sets both): descriptors at or above it can't be made.
    /// Kept with the process's handle, as a table shared by CLONE_FILES
    /// is limited by each user's own rlimit, as on Linux.
    limit: usize,
}

struct Slots {
    /// The owner of the POSIX record locks taken through it: the table,
    /// not the process, as Linux's fl_owner is the files_struct.
    id: u64,
    entries: Vec<Option<FdEntry>>,
    /// The lowest descriptor that may be free (Linux's next_fd).
    first_free: usize,
    /// `entries`' room, charged to the kernel memory budget: up to a MiB
    /// each, and fork copies tables.
    held: crate::kmem::Charge,
    /// POSIX record locks have been taken through it (they go when it does).
    posix_locks: bool,
}

impl Slots {
    /// Room for descriptors below `n`, charged first (ENOMEM).
    fn grow(&mut self, n: usize) -> Result<(), Errno> {
        if n <= self.entries.len() {
            return Ok(());
        }
        let cap = self.entries.capacity();
        if n > cap {
            // Doubling, but not past the free slots for less than that.
            let most = if n <= NOFILE_DEFAULT { NOFILE_DEFAULT } else { MAX_FDS };
            let want = (cap * 2).clamp(n, most);
            self.held.resize(slots_cost(want))?;
            self.entries.reserve_exact(want - self.entries.len());
        }
        self.entries.resize(n, None);
        Ok(())
    }
}

impl Drop for Slots {
    fn drop(&mut self) {
        if self.posix_locks {
            crate::locks::release_all(crate::locks::Owner::Files(self.id));
        }
    }
}

static NEXT_TABLE: AtomicU64 = AtomicU64::new(1);

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
        locked: false,
        fown: Default::default(),
        comm_of: None,
        landlock_denied: 0,
    }))
}

impl FdTable {
    fn new(entries: Vec<Option<FdEntry>>, held: crate::kmem::Charge, limit: usize) -> Self {
        let id = NEXT_TABLE.fetch_add(1, Ordering::Relaxed);
        let slots = Slots { id, entries, first_free: 0, held, posix_locks: false };
        FdTable { slots: Arc::new(Mutex::new(slots)), limit }
    }

    /// The kernel's own tables of a few descriptors (nothing to charge).
    fn boot(entries: Vec<Option<FdEntry>>) -> Self {
        Self::new(entries, Default::default(), NOFILE_DEFAULT)
    }

    pub fn with_stdio() -> Self {
        let entries = [(FileKind::Stdin, O_RDONLY), (FileKind::Stdout, O_WRONLY), (FileKind::Stderr, O_WRONLY)]
            .into_iter()
            .map(|(kind, flags)| Some(FdEntry { file: new_file(kind, flags), cloexec: false }))
            .collect();
        Self::boot(entries)
    }

    /// TTY mode: stdin, stdout and stderr are one open terminal.
    pub fn with_terminal(file: FileRef) -> Self {
        Self::boot((0..3).map(|_| Some(FdEntry { file: file.clone(), cloexec: false })).collect())
    }

    /// No descriptors at all (a process that has ended).
    pub fn empty() -> Self {
        ipc::changed();
        Self::boot(Vec::new())
    }

    /// The same table (CLONE_FILES).
    pub fn share(&self) -> Self {
        FdTable { slots: self.slots.clone(), limit: self.limit }
    }

    /// A table of its own with the same descriptors (fork, and unsharing),
    /// as far as the last one open (as Linux's dup_fd). It holds no POSIX
    /// locks: they stay with this one. ENOMEM if the budget can't hold it.
    pub fn copy(&self) -> Result<Self, Errno> {
        let t = self.slots.lock();
        let used = t.entries.iter().rposition(Option::is_some).map_or(0, |i| i + 1);
        let held = crate::kmem::Charge::new(slots_cost(used))?;
        let mut entries = Vec::with_capacity(used);
        entries.extend_from_slice(&t.entries[..used]);
        drop(t);
        Ok(Self::new(entries, held, self.limit))
    }

    /// Other processes use this table too.
    pub fn shared(&self) -> bool {
        Arc::strong_count(&self.slots) > 1
    }

    /// Make it a table of this process's own, if it's shared (exec, unshare).
    pub fn unshare(&mut self) -> Result<(), Errno> {
        if self.shared() {
            *self = self.copy()?;
        }
        Ok(())
    }

    /// RLIMIT_NOFILE's soft limit changed (prlimit).
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit.min(MAX_FDS as u64) as usize;
    }

    /// The owner of POSIX record locks taken through it.
    pub fn lock_owner(&self) -> crate::locks::Owner {
        crate::locks::Owner::Files(self.slots.lock().id)
    }

    pub fn posix_locks(&self) -> bool {
        self.slots.lock().posix_locks
    }

    pub fn set_posix_locks(&mut self) {
        self.slots.lock().posix_locks = true;
    }

    /// execve: close what's marked close-on-exec.
    /// What `close_on_exec` will close.
    pub fn cloexec_files(&self) -> Vec<FileRef> {
        self.slots.lock().entries.iter().flatten().filter(|e| e.cloexec).map(|e| e.file.clone()).collect()
    }

    pub fn close_on_exec(&mut self) {
        let mut closed = Vec::new();
        let mut t = self.slots.lock();
        for s in t.entries.iter_mut() {
            if s.as_ref().is_some_and(|e| e.cloexec) {
                closed.extend(s.take());
            }
        }
        t.first_free = 0;
        drop(t);
        if !closed.is_empty() {
            ipc::changed();
        }
    }

    fn index(fd: u64) -> Result<usize, Errno> {
        usize::try_from(fd as i32).map_err(|_| EBADF)
    }

    pub fn get(&self, fd: u64) -> Result<FileRef, Errno> {
        let i = Self::index(fd)?;
        Ok(self.slots.lock().entries.get(i).and_then(|s| s.as_ref()).ok_or(EBADF)?.file.clone())
    }

    pub fn cloexec(&self, fd: u64) -> Result<bool, Errno> {
        let i = Self::index(fd)?;
        Ok(self.slots.lock().entries.get(i).and_then(|s| s.as_ref()).ok_or(EBADF)?.cloexec)
    }

    pub fn set_cloexec(&mut self, fd: u64, on: bool) -> Result<(), Errno> {
        let i = Self::index(fd)?;
        self.slots.lock().entries.get_mut(i).and_then(|s| s.as_mut()).ok_or(EBADF)?.cloexec = on;
        Ok(())
    }

    /// Install at the lowest free descriptor >= `min`, below the
    /// process's RLIMIT_NOFILE (EMFILE). Fails with ENFILE once there are
    /// too many open files everywhere (the new one, already made, is then
    /// dropped by the caller).
    pub fn alloc(&mut self, entry: FdEntry, min: usize) -> Result<u64, Errno> {
        if OPEN_FILES.load(Ordering::Relaxed) > MAX_OPEN_FILES {
            crate::stats::hit(grix_abi::stats::Limit::OpenFiles);
            return Err(ENFILE);
        }
        let limit = self.limit;
        let mut t = self.slots.lock();
        let start = min.max(t.first_free).min(limit);
        let i = (start..limit).find(|&i| t.entries.get(i).is_none_or(|s| s.is_none())).ok_or(EMFILE)?;
        t.grow(i + 1)?;
        t.entries[i] = Some(entry);
        if min <= t.first_free {
            t.first_free = i + 1;
        }
        Ok(i as u64)
    }

    /// The most descriptors this process may have (fcntl's F_DUPFD
    /// refuses to start at or above it).
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Install at exactly `fd`, replacing whatever was there (dup2/dup3).
    /// EBADF at or above RLIMIT_NOFILE, as Linux's ksys_dup3.
    pub fn set(&mut self, fd: u64, entry: FdEntry) -> Result<(), Errno> {
        let i = usize::try_from(fd as i32).ok().filter(|&i| i < self.limit).ok_or(EBADF)?;
        let old = {
            let mut t = self.slots.lock();
            t.grow(i + 1)?;
            t.entries[i].replace(entry)
        };
        drop(old);
        ipc::changed();
        Ok(())
    }

    pub fn close(&mut self, fd: u64) -> Result<(), Errno> {
        let i = Self::index(fd)?;
        let old = {
            let mut t = self.slots.lock();
            let old = t.entries.get_mut(i).and_then(|s| s.take()).ok_or(EBADF)?;
            t.first_free = t.first_free.min(i);
            old
        };
        drop(old);
        ipc::changed();
        Ok(())
    }

    /// The lowest open descriptor at or above `from`.
    pub fn next_open(&self, from: u64) -> Option<u64> {
        let t = self.slots.lock();
        let from = usize::try_from(from).ok()?;
        t.entries.get(from..)?.iter().position(Option::is_some).map(|i| (from + i) as u64)
    }

    pub fn len(&self) -> usize {
        self.slots.lock().entries.len()
    }

    /// Is there a free descriptor (so open can fail with EMFILE before it creates anything)?
    pub fn has_room(&self) -> bool {
        let t = self.slots.lock();
        let free = t.first_free.min(self.limit);
        t.entries.len() < self.limit || t.entries[free..self.limit].iter().any(Option::is_none)
    }
}
