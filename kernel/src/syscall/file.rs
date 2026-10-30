//! File and descriptor syscalls: the filesystem (fs.rs), devices, pipes,
//! sockets, eventfds, epoll and inotify. Changing the filesystem needs
//! `fs_write`; without it the imports are read-only.

use alloc::string::String;
use alloc::vec::Vec;
use grix_abi::policy::Capability;
use grix_abi::wire::Channel;

use super::{require, table::nr};
use crate::console;
use crate::errno::*;
use crate::fd::{
    Epoll, FdEntry, FifoFile, FileKind, O_ACCMODE, O_APPEND, O_ASYNC, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, OpenFile,
    Registration, new_file,
};
use crate::fs::{self, Content, Dev, FileData, Ino, Kind, MAY_READ, MAY_WRITE, ROOT, S_IFIFO, StatInfo};
use crate::procfs::{self, ProcFile};
use crate::{landlock, locks};

const S_IFSOCK: u32 = 0o140000;
use crate::ipc::{self, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT, EVENTFD_MAX, EventFd, PIPE_BUF, PipeEnd};
use crate::process::{Process, WaitOn};
use crate::rng;
use crate::time;
use crate::uaccess::*;
use alloc::sync::Arc;
use spin::Mutex;

const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_SYMLINK_FOLLOW: u64 = 0x400;

const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
use crate::arch::abi::{O_DIRECT, O_DIRECTORY, O_NOFOLLOW};
const O_CLOEXEC: u32 = 0o2000000;
const O_PATH: u32 = 0o10000000;
const O_TMPFILE: u32 = 0o20000000;
/// Status flags that F_SETFL may change.
const SETFL_MASK: u32 = 0o2000 | 0o4000 | O_ASYNC; // O_APPEND | O_NONBLOCK | O_ASYNC

/// Linux caps a single read/write at this many bytes.
const MAX_RW: u64 = 0x7fff_f000;
pub(super) const CHUNK: usize = 4096;

// ---------------------------------------------------------------- paths

fn dir_base(p: &Process, dirfd: u64) -> Result<Ino, Errno> {
    if dirfd as i32 == AT_FDCWD {
        return Ok(p.cwd());
    }
    let f = p.fds.get(dirfd)?;
    let f = f.lock();
    match f.kind {
        FileKind::Node(ino) if fs::lock().is_dir(ino) => Ok(ino),
        _ => Err(ENOTDIR),
    }
}

/// The directory a path is relative to.
pub(super) fn base_of(p: &Process, dirfd: u64, path: &str) -> Result<Ino, Errno> {
    if path.starts_with('/') { Ok(ROOT) } else { dir_base(p, dirfd) }
}

/// Resolve `path` relative to `dirfd`, reporting paths that were not imported.
fn resolve(p: &mut Process, dirfd: u64, path: &str, follow: bool) -> Result<Ino, Errno> {
    let base = base_of(p, dirfd, path)?;
    let r = fs::lock().lookup(base, path, follow);
    if r == Err(ENOENT) {
        p.missing_path(base, path);
    }
    r
}

/// What a path names: a node, or a process's descriptor (`Fs::fd_link`).
enum Named {
    Node(Ino),
    Fd(u32, u64),
}

/// `resolve`, for calls that also take a descriptor's path.
fn resolve_named(p: &mut Process, dirfd: u64, path: &str, follow: bool) -> Result<Named, Errno> {
    let base = base_of(p, dirfd, path)?;
    let r = fs::lock().lookup(base, path, follow);
    if r == Err(ENOENT) {
        if let Some((pid, fd)) = fs::lock().fd_link(base, path, follow) {
            return Ok(Named::Fd(pid, fd));
        }
        p.missing_path(base, path);
    }
    r.map(Named::Node)
}

/// The directory and last component of a path that is being created or removed.
fn parent_of(p: &mut Process, dirfd: u64, path: &str) -> Result<(Ino, String), Errno> {
    let base = base_of(p, dirfd, path)?;
    parent_in(p, base, path)
}

fn parent_in(p: &mut Process, base: Ino, path: &str) -> Result<(Ino, String), Errno> {
    let r = fs::lock().lookup_parent(base, path);
    if r.as_ref().is_err_and(|e| *e == ENOENT) {
        p.missing_path(base, path);
    }
    r
}

/// Is what call `n` (one `fs_write` gates) would change on a read-only
/// live mount? Then it's EROFS, as a read-only filesystem answers, and
/// no denial: `fs_write` wouldn't change it. Only the place named counts
/// (the node, or the directory a name would go in), looked up quietly;
/// anything else, or a path that doesn't resolve, is for the gate.
pub(super) fn read_only_target(p: &mut Process, n: u32, a: [u64; 6]) -> bool {
    let at = AT_FDCWD as i64 as u64;
    // (dirfd, path) pairs to look at; a path of 0 means the descriptor.
    let places: [(u64, u64); 2] = match n {
        nr::unlinkat | nr::mknodat | nr::fchmodat | nr::fchownat | nr::fchmodat2 | nr::utimensat => {
            [(a[0], a[1]), (a[0], a[1])]
        }
        nr::renameat | nr::renameat2 => [(a[0], a[1]), (a[2], a[3])],
        nr::linkat => [(a[2], a[3]), (a[2], a[3])],
        nr::symlinkat => [(a[1], a[2]), (a[1], a[2])],
        nr::truncate | nr::setxattr | nr::lsetxattr | nr::removexattr | nr::lremovexattr => [(at, a[0]), (at, a[0])],
        nr::fchmod | nr::fchown | nr::fsetxattr | nr::fremovexattr => [(a[0], 0), (a[0], 0)],
        #[cfg(target_arch = "x86_64")]
        nr::rmdir | nr::unlink | nr::chmod | nr::chown | nr::lchown | nr::mknod => [(at, a[0]), (at, a[0])],
        #[cfg(target_arch = "x86_64")]
        nr::rename => [(at, a[0]), (at, a[1])],
        #[cfg(target_arch = "x86_64")]
        nr::link | nr::symlink => [(at, a[1]), (at, a[1])],
        _ => return false,
    };
    places.iter().any(|&(dirfd, pathp)| {
        if pathp == 0 {
            return fd_node(p, dirfd).is_ok_and(|ino| fs::lock().read_only(ino));
        }
        let Ok(path) = read_cstr(&mut p.aspace, pathp, PATH_MAX) else { return false };
        let Ok(base) = base_of(p, dirfd, &path) else { return false };
        let mut fs = fs::lock();
        match fs.lookup_parent(base, &path) {
            Ok((dir, name)) => fs.read_only(dir) || fs.child_of(dir, &name).is_some_and(|ino| fs.read_only(ino)),
            Err(_) => false,
        }
    })
}

/// A file's node for *at(fd, "", AT_EMPTY_PATH) and f* calls.
pub(super) fn fd_node(p: &Process, fd: u64) -> Result<Ino, Errno> {
    if fd as i32 == AT_FDCWD {
        return Ok(p.cwd());
    }
    match p.fds.get(fd)?.lock().kind {
        FileKind::Node(ino) | FileKind::Dev(_, ino) | FileKind::Fifo(FifoFile { ino, .. }) => Ok(ino),
        _ => Err(EINVAL),
    }
}

/// `f` of another process, if the caller may look at its descriptors.
fn with_other<T>(p: &Process, pid: u32, f: impl FnOnce(&Process) -> Result<T, Errno>) -> Result<T, Errno> {
    let procs = crate::procs::PROCS.lock();
    let q = procs.others.get(&pid).ok_or(ENOENT)?;
    if !crate::procs::may_inspect(p, q, false) {
        return Err(EACCES);
    }
    f(q)
}

/// The node a path names, for calls that take (dirfd, path, AT_* flags).
fn at_node(p: &mut Process, dirfd: u64, pathp: u64, flags: u64) -> Result<Ino, Errno> {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    if path.is_empty() {
        return if flags & AT_EMPTY_PATH != 0 { fd_node(p, dirfd) } else { Err(ENOENT) };
    }
    if let Some(fd) = procfs::fd_path(&path) {
        return fd_node(p, fd);
    }
    match resolve_named(p, dirfd, &path, flags & AT_SYMLINK_NOFOLLOW == 0)? {
        Named::Node(ino) => Ok(ino),
        Named::Fd(pid, fd) if pid == p.pid => fd_node(p, fd),
        Named::Fd(pid, fd) => with_other(p, pid, |q| fd_node(q, fd).map_err(|_| ENOENT)),
    }
}

/// The node an fd refers to, for *at(fd, "", AT_EMPTY_PATH) and fstat.
fn fd_stat(p: &Process, fd: u64) -> Result<StatInfo, Errno> {
    if fd as i32 == AT_FDCWD {
        return Ok(fs::lock().stat(p.cwd()));
    }
    let f = p.fds.get(fd)?;
    let f = f.lock();
    let boot = time::boot_realtime_ns();
    let anon = |ino: u64, mode: u32, size: u64| StatInfo {
        ino,
        mode,
        nlink: 1,
        uid: p.uid,
        gid: p.gid,
        size,
        blocks: 0,
        rdev: 0,
        atime: boot,
        mtime: boot,
        ctime: boot,
    };
    Ok(match &f.kind {
        FileKind::Stdin | FileKind::Stdout | FileKind::Stderr => anon(0x1000_0000 + fd, S_IFIFO | 0o600, 0),
        FileKind::Node(ino) | FileKind::Dev(_, ino) | FileKind::Fifo(FifoFile { ino, .. }) => fs::lock().stat(*ino),
        FileKind::Pty(end) => fs::lock().stat(end.ino),
        FileKind::Pipe(end) => anon(Arc::as_ptr(&end.pipe) as u64, S_IFIFO | 0o600, 0),
        FileKind::Socket(_)
        | FileKind::Netlink(_)
        | FileKind::UnixUnbound(_)
        | FileKind::Inet(_)
        | FileKind::Unix(_) => anon(0x3000_0000 + fd, S_IFSOCK | 0o777, 0),
        FileKind::Generated(data) => anon(0x4000_0000 + fd, fs::S_IFREG | 0o444, data.len() as u64),
        FileKind::ProcMem(..) => anon(0x4000_0000 + fd, fs::S_IFREG | 0o600, 0),
        // anon_inode files have no type bits on Linux.
        FileKind::EventFd(_)
        | FileKind::Epoll(_)
        | FileKind::Inotify(_)
        | FileKind::TimerFd(_)
        | FileKind::SignalFd(_)
        | FileKind::PidFd(_)
        | FileKind::Landlock(_) => anon(0x2000_0000 + fd, 0o600, 0),
    })
}

fn path_stat(p: &mut Process, dirfd: u64, pathp: u64, flags: u64) -> Result<StatInfo, Errno> {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    if path.is_empty() {
        if flags & AT_EMPTY_PATH != 0 {
            return fd_stat(p, dirfd);
        }
        return Err(ENOENT);
    }
    if let Some(fd) = procfs::fd_path(&path) {
        return fd_stat(p, fd);
    }
    if let Some((pid, fd)) = procfs::other_fd_path(&path) {
        return with_other(p, pid, |q| fd_stat(q, fd).map_err(|_| ENOENT));
    }
    match resolve_named(p, dirfd, &path, flags & AT_SYMLINK_NOFOLLOW == 0)? {
        Named::Node(ino) => Ok(fs::lock().stat(ino)),
        Named::Fd(pid, fd) if pid == p.pid => fd_stat(p, fd),
        Named::Fd(pid, fd) => with_other(p, pid, |q| fd_stat(q, fd).map_err(|_| ENOENT)),
    }
}

// ---------------------------------------------------------------- open/close

/// Changing the filesystem needs `fs_write`. Denials name the path.
fn need_write(p: &mut Process, n: u32, path: &str) -> Result<(), Errno> {
    require(p, n, Capability::FsWrite, path)
}

/// `need_write` for a change in directory `dir`, which on a read-only
/// live mount is EROFS whatever the policy says (`read_only_target`).
fn need_write_in(p: &mut Process, n: u32, dir: Option<Ino>, path: &str) -> Result<(), Errno> {
    if dir.is_some_and(|d| fs::lock().read_only(d)) {
        return Err(EROFS);
    }
    need_write(p, n, path)
}

pub fn openat(p: &mut Process, dirfd: u64, pathp: u64, flags: u64, mode: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    open(p, nr::openat, dirfd, &path, flags as u32, mode as u32, 0)
}

/// `struct open_how`'s size in its first version, and the most of one
/// openat2 reads (copy_struct_from_user: anything past what's known must
/// be zero).
const OPEN_HOW_SIZE_VER0: u64 = 24;
/// Every flag open knows (fs/fcntl.c's VALID_OPEN_FLAGS: O_ACCMODE up to
/// __O_TMPFILE; arm64 and x86_64 use the same bits, in another order).
const VALID_OPEN_FLAGS: u64 = 0o37777703;
/// What O_PATH may come with (O_CLOEXEC is taken off first).
const O_PATH_FLAGS: u32 = O_DIRECTORY | O_NOFOLLOW | O_PATH;
const VALID_RESOLVE_FLAGS: u64 = fs::RESOLVE_NO_XDEV
    | fs::RESOLVE_NO_MAGICLINKS
    | fs::RESOLVE_NO_SYMLINKS
    | fs::RESOLVE_BENEATH
    | fs::RESOLVE_IN_ROOT
    | fs::RESOLVE_CACHED;

/// openat2: openat with `struct open_how { u64 flags, mode, resolve }`,
/// whose flags are checked rather than ignored (fs/open.c's
/// build_open_flags), and `resolve` limiting how the path is walked.
pub fn openat2(p: &mut Process, dirfd: u64, pathp: u64, howp: u64, size: u64) -> SysResult {
    if size < OPEN_HOW_SIZE_VER0 {
        return Err(EINVAL);
    }
    if size > crate::mm::PAGE_SIZE {
        return Err(E2BIG);
    }
    let mut how = [0u8; OPEN_HOW_SIZE_VER0 as usize];
    copy_in(&mut p.aspace, howp, &mut how)?;
    // A newer caller's fields we don't know must be zero.
    let mut at = OPEN_HOW_SIZE_VER0;
    while at < size {
        let mut tail = [0u8; 64];
        let n = (size - at).min(tail.len() as u64);
        copy_in(&mut p.aspace, howp + at, &mut tail[..n as usize])?;
        if tail[..n as usize].iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
        at += n;
    }
    let word = |i: usize| u64::from_le_bytes(how[i * 8..i * 8 + 8].try_into().unwrap());
    let (flags, mode, resolve) = (word(0), word(1), word(2));
    let open_flags = flags & !(O_CLOEXEC as u64);
    if open_flags & !VALID_OPEN_FLAGS != 0 || resolve & !VALID_RESOLVE_FLAGS != 0 {
        return Err(EINVAL);
    }
    let flags = flags as u32;
    if resolve & fs::RESOLVE_BENEATH != 0 && resolve & fs::RESOLVE_IN_ROOT != 0 {
        return Err(EINVAL);
    }
    let creates = flags & (O_CREAT | O_TMPFILE) != 0;
    if (creates && mode & !0o7777 != 0) || (!creates && mode != 0) {
        return Err(EINVAL);
    }
    if flags & (O_DIRECTORY | O_CREAT) == O_DIRECTORY | O_CREAT {
        return Err(EINVAL);
    }
    // O_TMPFILE is __O_TMPFILE | O_DIRECTORY, and for writing.
    if flags & O_TMPFILE != 0 && (flags & O_DIRECTORY == 0 || flags & O_ACCMODE == O_RDONLY) {
        return Err(EINVAL);
    }
    if flags & O_PATH != 0 && flags & !(O_PATH_FLAGS | O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    // Nothing that would create or truncate is tried from the cache.
    if resolve & fs::RESOLVE_CACHED != 0 && flags & (O_TRUNC | O_CREAT | O_TMPFILE) != 0 {
        return Err(EAGAIN);
    }
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    open(p, nr::openat2, dirfd, &path, flags, mode as u32, resolve)
}

/// openat and openat2 (`resolve`, its RESOLVE_* flags, 0 for openat).
/// Calls `n` in denials.
fn open(p: &mut Process, n: u32, dirfd: u64, path: &str, flags: u32, mode: u32, resolve: u64) -> SysResult {
    let acc = flags & O_ACCMODE;
    let cloexec = flags & O_CLOEXEC != 0;
    // /proc/self/fd/N, /dev/stdin, ...: another reference to an open file.
    // (With `resolve`, they're walked to, as anything else, and so are
    // they when they mustn't be followed: they're links.)
    if resolve == 0
        && flags & O_NOFOLLOW == 0
        && flags & (O_CREAT | O_EXCL) != O_CREAT | O_EXCL
        && let Some(fd) = procfs::fd_path(path)
    {
        let file = p.fds.get(fd).map_err(|_| ENOENT)?;
        return p.fds.alloc(FdEntry { file, cloexec }, 0);
    }
    // RESOLVE_IN_ROOT: "/" is the directory too.
    let base = if resolve & fs::RESOLVE_IN_ROOT != 0 { dir_base(p, dirfd)? } else { base_of(p, dirfd, path)? };
    let scope = fs::Scope { flags: resolve, root: base };
    if !p.fds.has_room() {
        return Err(EMFILE); // before creating or truncating anything
    }
    let perm = mode & 0o7777 & !p.umask();
    let landlock = landlock::domain(p);
    if flags & O_TMPFILE == O_TMPFILE {
        if acc == O_RDONLY {
            return Err(EINVAL);
        }
        let dir = fs::lock().lookup_in(base, path, true, &scope).ok();
        need_write_in(p, n, dir, path)?;
        let (ino, content, denied) = {
            let mut fs = fs::lock();
            let dir = fs.lookup_in(base, path, true, &scope)?;
            if !fs.is_dir(dir) {
                return Err(ENOTDIR);
            }
            let (ino, content) = fs.create_unnamed(dir, perm, p.uid, p.gid)?;
            // Opened as a file in `dir`.
            let denied = match &landlock {
                Some(d) => landlock::open_access(d, &fs, ino, dir, acc)?,
                None => 0,
            };
            (ino, content, denied)
        };
        return open_node(p, ino, Some(content), flags, cloexec, denied);
    }
    let creat = flags & O_CREAT != 0;
    let excl = creat && flags & O_EXCL != 0;
    let follow = flags & O_NOFOLLOW == 0 && !excl;
    let found = fs::lock().lookup_in(base, path, follow, &scope);
    // A descriptor reached through a symlink or a relative path.
    if found == Err(ENOENT)
        && let Some((pid, fd)) = fs::lock().fd_link_in(base, path, follow, &scope)
        && pid == p.pid
    {
        // It's a magic link, as Linux's /proc/<pid>/fd/N.
        if excl {
            return Err(EEXIST);
        }
        // Not followed, it's a link: ELOOP, whatever else is asked. O_PATH
        // opens the link itself on Linux, where there's a node for it; here
        // that would be what it leads to, past any RESOLVE_* asked for.
        if !follow && (flags & O_PATH == 0 || resolve != 0) {
            return Err(ELOOP);
        }
        if follow && resolve & (fs::RESOLVE_NO_SYMLINKS | fs::RESOLVE_NO_MAGICLINKS) != 0 {
            return Err(ELOOP);
        }
        if follow && resolve & (fs::RESOLVE_NO_XDEV | fs::RESOLVE_BENEATH | fs::RESOLVE_IN_ROOT) != 0 {
            return Err(EXDEV);
        }
        let file = p.fds.get(fd).map_err(|_| ENOENT)?;
        return p.fds.alloc(FdEntry { file, cloexec }, 0);
    }
    let (ino, created) = match found {
        Ok(_) if excl => return Err(EEXIST),
        Ok(ino) => (ino, false),
        Err(ENOENT) if creat => {
            if flags & O_DIRECTORY != 0 {
                return Err(EINVAL);
            }
            let dir = fs::lock().lookup_parent_in(base, path, &scope).ok().map(|(d, _)| d);
            need_write_in(p, n, dir, path)?;
            match create_file(p, base, path, perm, 0, &scope) {
                Ok(ino) => (ino, true),
                // Made meanwhile, on a live mount's host: open that one.
                Err(EEXIST) => (fs::lock().lookup_in(base, path, flags & O_NOFOLLOW == 0, &scope)?, false),
                Err(e) => return Err(e),
            }
        }
        Err(e) => {
            if e == ENOENT && resolve & fs::RESOLVE_IN_ROOT == 0 {
                p.missing_path(base, path);
            }
            return Err(e);
        }
    };
    if flags & O_PATH != 0 {
        // O_DIRECTORY still means "fail unless it's a directory" (GNU mv
        // asks this way whether its target is one).
        if flags & O_DIRECTORY != 0 && !fs::lock().is_dir(ino) {
            return Err(ENOTDIR);
        }
        let file = new_file(FileKind::Node(ino), O_RDONLY);
        let mut f = file.lock();
        (f.path_only, f.pin) = (true, Some(fs::lock().pin(ino)));
        drop(f);
        return p.fds.alloc(FdEntry { file, cloexec }, 0);
    }
    let writes = acc != O_RDONLY || flags & O_TRUNC != 0;
    // The opener's Landlock domain, checked (after the errors the kind of
    // node gives) as Linux's hook_file_open: the rights refused that
    // matter later, or EACCES.
    let dir = if landlock.is_some() { fs::lock().found_in(ino, base, path, &scope) } else { ROOT };
    let landlock_open = |fs: &fs::Fs| match &landlock {
        Some(d) => landlock::open_access(d, fs, ino, dir, acc),
        None => Ok(0),
    };
    let (content, proc, proc_pid) = {
        let mut fs = fs::lock();
        let proc_pid = fs.proc_pid(ino).filter(|&pid| pid != p.pid);
        fs.revalidate(ino);
        // (A FIFO is written to, never changed.)
        if writes && fs.read_only(ino) && !fs.is_dir(ino) && !matches!(fs.node(ino).kind, Kind::Fifo(_)) {
            return Err(EROFS);
        }
        match &fs.node(ino).kind {
            &Kind::Dev(d @ (Dev::Ptmx | Dev::Pts(_) | Dev::Tty)) => {
                let denied = landlock_open(&fs)?;
                let file = super::tty::open_dev(p, &mut fs, d, ino, flags)?;
                (file.lock().pin, file.lock().landlock_denied) = (Some(fs.pin(ino)), denied);
                drop(fs);
                return p.fds.alloc(FdEntry { file, cloexec }, 0);
            }
            Kind::Dev(d) => {
                let denied = landlock_open(&fs)?;
                let file = new_file(FileKind::Dev(*d, ino), flags & !(O_CLOEXEC | O_CREAT | O_EXCL | O_TRUNC));
                (file.lock().pin, file.lock().landlock_denied) = (Some(fs.pin(ino)), denied);
                drop(fs);
                return p.fds.alloc(FdEntry { file, cloexec }, 0);
            }
            Kind::Symlink(_) => return Err(ELOOP), // O_NOFOLLOW on a symlink
            // A socket is connected to, not opened.
            Kind::Socket(_) => return Err(ENXIO),
            Kind::Fifo(_) if flags & O_DIRECTORY != 0 => return Err(ENOTDIR),
            Kind::Fifo(_) => {
                landlock_open(&fs)?;
                drop(fs);
                return open_fifo(p, ino, flags, cloexec);
            }
            Kind::Dir(_) if writes => return Err(EISDIR),
            // Reading a directory needs read permission, as on Linux; a live
            // mount's must be one the host can list, too.
            Kind::Dir(_) => {
                if !fs.permits(ino, p.uid, p.gid, MAY_READ) {
                    return Err(EACCES);
                }
                landlock_open(&fs)?;
                fs.list_now(ino)?;
                (None, None, None)
            }
            Kind::File(_) | Kind::Unlinked { .. } if flags & O_DIRECTORY != 0 => return Err(ENOTDIR),
            Kind::File(c) => (Some(c.clone()), None, None),
            Kind::Unlinked { .. } => return Err(ENOENT),
            // Another process's memory isn't reachable (invariant 13): as
            // Linux's mem_open without ptrace_may_access(ATTACH).
            Kind::Proc(ProcFile::Mem) if proc_pid.is_some() => return Err(EACCES),
            Kind::Proc(ProcFile::Mem) => {
                let want = if acc != O_WRONLY { MAY_READ } else { 0 } | if writes { MAY_WRITE } else { 0 };
                if !fs.permits(ino, p.uid, p.gid, want) {
                    return Err(EACCES);
                }
                landlock_open(&fs)?;
                drop(fs);
                let file =
                    new_file(FileKind::ProcMem(p.pid, p.aspace.id), flags & !(O_CLOEXEC | O_CREAT | O_EXCL | O_TRUNC));
                return p.fds.alloc(FdEntry { file, cloexec }, 0);
            }
            // A thread's name, for its owner (0644).
            Kind::Proc(f) if writes && procfs::writable(*f) => {
                let want = if acc != O_WRONLY { MAY_READ } else { 0 } | MAY_WRITE;
                if !fs.permits(ino, p.uid, p.gid, want) {
                    return Err(EACCES);
                }
                landlock_open(&fs)?;
                (None, Some(*f), proc_pid)
            }
            Kind::Proc(_) if writes => return Err(EACCES),
            Kind::Proc(f) => {
                landlock_open(&fs)?;
                (None, Some(*f), proc_pid)
            }
        }
    };
    if let Some(f) = proc {
        // Another process's /proc/<pid>: generated from it (kernel state
        // only, never its memory).
        let data = match proc_pid {
            Some(pid) => {
                let procs = crate::procs::PROCS.lock();
                match (procs.others.get(&pid), procs.zombies.get(&pid)) {
                    // Its environment, auxv and smaps only to those who
                    // may inspect it, as Linux's ptrace_may_access.
                    (Some(q), _) if procfs::inspected(f) && !crate::procs::may_inspect(p, q, false) => {
                        return Err(EACCES);
                    }
                    (Some(q), _) => procfs::generate(q, f)?,
                    (None, Some(z)) => procfs::generate_zombie(p, pid, z, f)?,
                    // Reaped just now: its directory is on its way out.
                    (None, None) => return Err(ENOENT),
                }
            }
            None => procfs::generate(p, f)?,
        };
        let held = crate::kmem::Charge::new(data.capacity() as u64)?;
        let file = new_file(FileKind::Generated(data), flags & !(O_CLOEXEC | O_CREAT | O_EXCL | O_TRUNC));
        file.lock().held = Some(held);
        if writes {
            let pid = proc_pid.unwrap_or(p.pid);
            let tid = if let ProcFile::TaskComm(tid) = f { tid } else { pid };
            file.lock().comm_of = Some((pid, tid));
        }
        return p.fds.alloc(FdEntry { file, cloexec }, 0);
    }
    if content.is_some() && !created {
        if writes {
            need_write(p, n, path)?;
        }
        let want = if acc != O_WRONLY { MAY_READ } else { 0 } | if writes { MAY_WRITE } else { 0 };
        if !fs::lock().permits(ino, p.uid, p.gid, want) {
            return Err(EACCES);
        }
    }
    // A new file is checked once made, as on Linux (MAKE_REG let it be
    // made; this open may still fail).
    let denied = if landlock.is_some() && content.is_some() { landlock_open(&fs::lock())? } else { 0 };
    if let Some(c) = &content
        && !created
    {
        // O_TRUNC on a regular file is a truncate (Linux's handle_truncate).
        if flags & O_TRUNC != 0 && denied & landlock::TRUNCATE != 0 {
            return Err(EACCES);
        }
        // A lazy import's file is the sandbox's before it changes.
        if writes {
            fs::lock().copy_up(ino)?;
        }
        // A live mount's file may have grown on the host since.
        let remote = c.lock().remote_id().is_some();
        if flags & O_TRUNC != 0 && (remote || c.lock().len() != 0) {
            note_shared(p, nr::openat, c);
            c.lock().truncate(0)?;
            zap_shared(p, c, 0);
            fs::lock().modified(ino);
        }
    }
    open_node(p, ino, content, flags, cloexec, denied)
}

/// Open a named pipe, as Linux's fifo_open: for reading it waits for a
/// writer, and for writing for a reader, unless O_NONBLOCK (then a writer
/// without a reader gets ENXIO) or O_RDWR. A waiting open's end already
/// counts (`Thread::fifo_wait` keeps it across the re-runs), so two opens
/// waiting for each other both go on.
fn open_fifo(p: &mut Process, ino: Ino, flags: u32, cloexec: bool) -> SysResult {
    let acc = flags & O_ACCMODE;
    let want = match acc {
        O_RDONLY => MAY_READ,
        O_WRONLY => MAY_WRITE,
        O_RDWR => MAY_READ | MAY_WRITE,
        _ => return Err(EINVAL),
    };
    let mut fs = fs::lock();
    if !fs.permits(ino, p.uid, p.gid, want) {
        return Err(EACCES);
    }
    let pin = fs.pin(ino);
    let Kind::Fifo(fifo) = &mut fs.node_mut(ino).kind else { return Err(ENOENT) };
    let (read, write) = if acc == O_RDWR {
        (Some(fifo.open(false)), Some(fifo.open(true)))
    } else {
        let write = acc == O_WRONLY;
        let (readers, writers) = fifo.ends();
        let others = if write { readers } else { writers };
        let end = if flags & O_NONBLOCK != 0 {
            if write && readers == 0 {
                return Err(ENXIO);
            }
            fifo.open(write)
        } else {
            let other = !write as usize;
            let (end, since) = match p.cur().fifo_wait.take() {
                Some(w) if w.ino == ino && w.end.write == write => (w.end, w.since),
                _ => (fifo.open(write), fifo.opened[other]),
            };
            if others == 0 && fifo.opened[other] == since {
                let call = p.cur().call;
                p.cur().fifo_wait = Some(crate::process::FifoWait { ino, end, since, call });
                drop(fs);
                return p.block_io(None, Err(EINTR));
            }
            end
        };
        if write { (None, Some(end)) } else { (Some(end), None) }
    };
    drop(fs);
    let file =
        new_file(FileKind::Fifo(FifoFile { ino, read, write }), flags & !(O_CLOEXEC | O_CREAT | O_EXCL | O_TRUNC));
    file.lock().pin = Some(pin);
    p.fds.alloc(FdEntry { file, cloexec }, 0)
}

fn open_node(p: &mut Process, ino: Ino, content: Option<Content>, flags: u32, cloexec: bool, denied: u16) -> SysResult {
    let file = new_file(FileKind::Node(ino), flags & !(O_CLOEXEC | O_CREAT | O_EXCL | O_TRUNC | O_TMPFILE));
    let pin = fs::lock().pin(ino);
    let mut f = file.lock();
    (f.content, f.pin, f.landlock_denied) = (content, Some(pin), denied);
    drop(f);
    p.fds.alloc(FdEntry { file, cloexec }, 0)
}

/// Create the regular file `path` (which doesn't exist). A dangling symlink
/// in its place is followed, as Linux does for O_CREAT without O_EXCL.
fn create_file(p: &mut Process, base: Ino, path: &str, perm: u32, depth: u32, scope: &fs::Scope) -> Result<Ino, Errno> {
    let (dir, name) =
        if scope.flags == 0 { parent_in(p, base, path)? } else { fs::lock().lookup_parent_in(base, path, scope)? };
    let mut fs = fs::lock();
    if let Ok(link) = fs.lookup(dir, &name, false)
        && matches!(fs.node(link).kind, Kind::Symlink(_))
    {
        if scope.flags & fs::RESOLVE_NO_SYMLINKS != 0 {
            return Err(ELOOP);
        }
        // A zombie's /proc/<pid>/exe leads nowhere (ENOENT).
        let target = fs.link_target(link)?;
        drop(fs);
        return if depth >= 8 { Err(ELOOP) } else { create_file(p, dir, &target, perm, depth + 1, scope) };
    }
    if name.is_empty() || name == "." || name == ".." {
        return Err(EISDIR);
    }
    if let Some(d) = landlock::domain(p)
        && fs.child_of(dir, &name).is_none()
    {
        d.check(&fs, dir, landlock::MAKE_REG)?;
    }
    fs.create(dir, &name, Kind::File(FileData::new(&[])), perm, p.uid, p.gid)
}

/// fsync/fdatasync: a live mount's file is synced on the host; everything
/// else is in memory already.
pub fn fsync(p: &mut Process, fd: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let f = file.lock();
    let id = match (&f.content, &f.kind) {
        (Some(c), _) => c.lock().remote_id(),
        (None, FileKind::Node(ino)) => fs::lock().remote_id(*ino),
        _ => None,
    };
    drop(f);
    if let Some(id) = id {
        crate::hostfs::fsync(id)?;
    }
    Ok(0)
}

pub fn close(p: &mut Process, fd: u64) -> SysResult {
    if let Ok(file) = p.fds.get(fd) {
        closing(p, &file);
    }
    p.fds.close(fd).map(|_| 0)
}

/// A descriptor for `file` is about to close: the process's POSIX record
/// locks on the file go with it, whichever descriptor they were taken
/// through (POSIX's rule). They're its descriptor table's, so with
/// CLONE_FILES a close in either process drops them, as on Linux.
pub(crate) fn closing(p: &Process, file: &crate::fd::FileRef) {
    let f = file.lock();
    // (An O_PATH descriptor doesn't count, as on Linux.)
    if !f.path_only && p.fds.posix_locks() {
        let key = f.lock_key();
        drop(f);
        locks::release(key, p.fds.lock_owner());
    }
}

pub fn close_range(p: &mut Process, first: u64, last: u64, flags: u64) -> SysResult {
    const CLOSE_RANGE_CLOEXEC: u64 = 4;
    if first > last {
        return Err(EINVAL);
    }
    let last = last.min(p.fds.len() as u64);
    for fd in first..=last {
        if flags & CLOSE_RANGE_CLOEXEC != 0 {
            let _ = p.fds.set_cloexec(fd, true);
        } else {
            if let Ok(file) = p.fds.get(fd) {
                closing(p, &file);
            }
            let _ = p.fds.close(fd);
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------- read/write

fn read_into(p: &mut Process, f: &mut OpenFile, buf: u64, count: u64, at: Option<u64>) -> SysResult {
    if f.path_only || f.flags & O_ACCMODE == O_WRONLY {
        return Err(EBADF);
    }
    let count = count.min(MAX_RW);
    let nonblock = f.nonblocking();
    match &f.kind {
        FileKind::Stdin => {
            if count == 0 {
                return Ok(0);
            }
            let mut chunk = [0u8; CHUNK];
            let want = (count as usize).min(CHUNK);
            match console::stdin_read(&mut chunk[..want]) {
                console::StdinRead::Data(n) => copy_out(&mut p.aspace, buf, &chunk[..n]).map(|_| n as u64),
                console::StdinRead::Eof => Ok(0),
                console::StdinRead::Empty => would_block(p, nonblock),
            }
        }
        FileKind::Stdout | FileKind::Stderr | FileKind::Epoll(_) => Err(EBADF),
        FileKind::Inotify(n) => match n.read(count as usize, |b| copy_out(&mut p.aspace, buf, b).map(|_| ())) {
            Some(r) => r.map(|n| n as u64),
            None => would_block(p, nonblock),
        },
        FileKind::UnixUnbound(_) => Err(ENOTCONN),
        FileKind::PidFd(_) | FileKind::Landlock(_) => Err(EINVAL),
        FileKind::SignalFd(mask) => {
            // struct signalfd_siginfo is 128 bytes; read as many as fit.
            if count < 128 {
                return Err(EINVAL);
            }
            let mask = *mask;
            let mut done = 0;
            while done + 128 <= count {
                let Some(si) = crate::signal::dequeue(p, mask) else { break };
                copy_out(&mut p.aspace, buf + done, &crate::signal::signalfd_record(&si))?;
                done += 128;
            }
            if done == 0 {
                return would_block(p, nonblock);
            }
            Ok(done)
        }
        FileKind::Netlink(_) => {
            let FileKind::Netlink(nl) = &mut f.kind else { unreachable!() };
            super::net::netlink_recv(p, nl, &[(buf, count)], 0, nonblock).map(|(n, _)| n)
        }
        FileKind::TimerFd(t) => {
            if count < 8 {
                return Err(EINVAL);
            }
            let ticks = {
                let mut t = t.lock();
                t.update(time::monotonic_ns());
                core::mem::take(&mut t.expirations)
            };
            if ticks == 0 {
                return would_block(p, nonblock);
            }
            // Consumed: the timer re-arms (see timer.rs).
            p.timer_dirty = true;
            crate::sched::deadlines_changed();
            copy_out(&mut p.aspace, buf, &ticks.to_le_bytes()).map(|_| 8)
        }
        &FileKind::ProcMem(pid, mm) => {
            let addr = at.unwrap_or(f.offset);
            let n = proc_mem(p, (pid, mm), addr, buf, count, false)?;
            if at.is_none() {
                f.offset = addr.wrapping_add(n);
            }
            Ok(n)
        }
        FileKind::Generated(data) => {
            let off = (at.unwrap_or(f.offset) as usize).min(data.len());
            let n = (count as usize).min(data.len().saturating_sub(off));
            copy_out(&mut p.aspace, buf, &data[off..off + n])?;
            if at.is_none() {
                f.offset += n as u64;
            }
            Ok(n as u64)
        }
        FileKind::Pipe(end) if end.write => Err(EBADF),
        FileKind::Pipe(end) => pipe_read(p, end, buf, count, nonblock, false),
        FileKind::Fifo(f) => match &f.read {
            Some(end) => pipe_read(p, end, buf, count, nonblock, false),
            None => Err(EBADF),
        },
        FileKind::Pty(end) => super::tty::read(p, end, buf, count, nonblock),
        FileKind::Unix(s) => super::unix::recv_msg(p, s, &[(buf, count)], 0, nonblock).map(|r| r.n),
        FileKind::Socket(s) => match &s.rx {
            // With SO_PASSCRED, one writer's bytes at a time.
            Some(rx) if super::unix::stream_passcred(s) => {
                pipe_read_full(p, rx, buf, count, nonblock, false, &mut Vec::new(), Some(&mut None))
            }
            Some(rx) => pipe_read(p, rx, buf, count, nonblock, false),
            None => Ok(0), // shut down for reading
        },
        FileKind::Inet(s) => super::net::inet_read(p, s, buf, count, nonblock, false).map(|(n, _)| n),
        FileKind::EventFd(e) => {
            if count < 8 {
                return Err(EINVAL);
            }
            let mut ev = e.lock();
            if ev.count == 0 {
                drop(ev);
                return would_block(p, nonblock);
            }
            let v = if ev.semaphore { 1 } else { ev.count };
            copy_out(&mut p.aspace, buf, &v.to_le_bytes())?;
            ev.count -= v;
            ev.touch();
            Ok(8)
        }
        FileKind::Dev(Dev::Null, _) => Ok(0),
        FileKind::Dev(Dev::Zero, _) => zero_out(&mut p.aspace, buf, count).map(|_| count),
        FileKind::Dev(Dev::Random, _) => {
            let mut chunk = [0u8; 256];
            let mut done = 0;
            while done < count {
                let n = (count - done).min(chunk.len() as u64) as usize;
                rng::fill(&mut chunk[..n]);
                copy_out(&mut p.aspace, buf + done, &chunk[..n])?;
                done += n as u64;
            }
            Ok(count)
        }
        // Terminal nodes open as FileKind::Pty.
        FileKind::Dev(Dev::Ptmx | Dev::Pts(_) | Dev::Tty, _) => Err(ENXIO),
        FileKind::Node(_) => match &f.content {
            Some(c) => {
                let n = read_content(p, c, at.unwrap_or(f.offset), buf, count)?;
                if at.is_none() {
                    f.offset += n;
                }
                Ok(n)
            }
            None => Err(EISDIR),
        },
    }
}

/// Copy file bytes to user memory through a kernel buffer, so the contents
/// aren't locked while user pages fault in (they may map this very file).
fn read_content(p: &mut Process, c: &Content, off: u64, buf: u64, count: u64) -> SysResult {
    // A live mount's file: a request to the host per buffer, so a big one.
    let mut big = Vec::new();
    let mut small = [0u8; CHUNK];
    let chunk: &mut [u8] = if c.lock().remote_id().is_some() {
        big.resize(grix_abi::hostfs::IO_MAX, 0);
        &mut big
    } else {
        &mut small
    };
    let mut done = 0u64;
    while done < count {
        let want = (count - done).min(chunk.len() as u64) as usize;
        let n = match c.lock().read_at(off.saturating_add(done), &mut chunk[..want]) {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        if let Err(e) = copy_out(&mut p.aspace, buf + done, &chunk[..n]) {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
        done += n as u64;
    }
    Ok(done)
}

/// The file changes, but a MAP_SHARED mapping of it keeps the copy it took
/// when each page faulted in. Report that rather than pretend.
fn note_shared(p: &mut Process, n: u32, c: &Content) {
    if c.lock().mapped_shared() {
        let (name, _) = super::table::info(n);
        let _ = p.unimplemented(n, name, "changing a file that is mapped MAP_SHARED", EIO);
    }
}

/// Linux's MAX_LFS_FILESIZE.
const MAX_FILE_SIZE: u64 = i64::MAX as u64;

/// Copy user bytes into a file at `off` (see `read_content`).
/// With `append`, at the end of a live mount's file (where the host says
/// the end is). Returns how much was written, and where.
pub(super) fn write_content_at(
    p: &mut Process,
    c: &Content,
    ino: Ino,
    mut off: u64,
    append: bool,
    src: Src,
    count: u64,
) -> Result<(u64, u64), Errno> {
    if off.checked_add(count).is_none_or(|end| end > MAX_FILE_SIZE) {
        return Err(EFBIG);
    }
    c.lock().may_write(off + count)?;
    note_shared(p, nr::write, c);
    let remote = c.lock().remote_id().is_some();
    let mut big = Vec::new();
    let mut small = [0u8; CHUNK];
    let chunk: &mut [u8] = if remote {
        big.resize(grix_abi::hostfs::IO_MAX, 0);
        &mut big
    } else {
        &mut small
    };
    let mut done = 0u64;
    let mut err = None;
    while done < count {
        let n = (count - done).min(chunk.len() as u64) as usize;
        if let Err(e) = src.read(p, done, &mut chunk[..n]) {
            err = Some(e);
            break;
        }
        let wrote = if remote {
            let r = c.lock().write_remote(off + done, append && done == 0, &chunk[..n]);
            r.map(|(k, at)| {
                if append && done == 0 {
                    off = at;
                }
                k
            })
        } else {
            c.lock().write(off + done, &chunk[..n])
        };
        match wrote {
            Ok(k) => done += k as u64,
            Err((k, e)) => {
                done += k as u64;
                err = Some(e);
                break;
            }
        }
    }
    if done > 0 {
        fs::lock().modified(ino);
    }
    match err {
        Some(e) if done == 0 => Err(e),
        _ => Ok((done, off)),
    }
}

/// write/pwrite. `at` is pwrite's offset; O_APPEND overrides it, as on Linux.
fn write_from(p: &mut Process, f: &mut OpenFile, buf: u64, count: u64, at: Option<u64>) -> SysResult {
    if f.path_only || f.flags & O_ACCMODE == O_RDONLY {
        return Err(EBADF);
    }
    let count = count.min(MAX_RW);
    let nonblock = f.nonblocking();
    let ch = match &f.kind {
        FileKind::Stdout => Channel::Stdout,
        FileKind::Stderr => Channel::Stderr,
        FileKind::Dev(..) => return Ok(count),
        FileKind::Node(ino) => {
            let ino = *ino;
            let Some(c) = f.content.clone() else { return Err(EBADF) };
            let append = f.flags & O_APPEND != 0;
            let off = if append { c.lock().len() } else { at.unwrap_or(f.offset) };
            // A live mount's file may have grown on the host: its end is
            // where the host says.
            let (n, off) = write_content_at(p, &c, ino, off, append, Src::User(buf), count)?;
            if at.is_none() {
                f.offset = off + n;
            }
            return Ok(n);
        }
        &FileKind::ProcMem(pid, mm) => {
            let addr = at.unwrap_or(f.offset);
            let n = proc_mem(p, (pid, mm), addr, buf, count, true)?;
            if at.is_none() {
                f.offset = addr.wrapping_add(n);
            }
            return Ok(n);
        }
        FileKind::Generated(_) if f.comm_of.is_some() => {
            let (pid, tid) = f.comm_of.unwrap();
            return comm_write(p, pid, tid, buf, count);
        }
        FileKind::Stdin | FileKind::Epoll(_) | FileKind::Generated(_) | FileKind::Inotify(_) => {
            return Err(EBADF);
        }
        FileKind::TimerFd(_) => return Err(EINVAL),
        FileKind::UnixUnbound(_) => return Err(ENOTCONN),
        FileKind::SignalFd(_) | FileKind::PidFd(_) | FileKind::Landlock(_) => return Err(EINVAL),
        FileKind::Netlink(_) => {
            let FileKind::Netlink(nl) = &mut f.kind else { unreachable!() };
            return super::net::netlink_request(p, nl, &[(buf, count)]);
        }
        FileKind::Pipe(end) if !end.write => return Err(EBADF),
        FileKind::Pipe(end) => return pipe_write(p, end, Src::User(buf), count, nonblock, true),
        FileKind::Fifo(f) => {
            return match &f.write {
                Some(end) => pipe_write(p, end, Src::User(buf), count, nonblock, true),
                None => Err(EBADF),
            };
        }
        FileKind::Pty(end) => return super::tty::write(p, end, buf, count, nonblock),
        FileKind::Unix(s) => {
            return super::unix::send_msg(p, s, &[(buf, count)], 0, nonblock, None, Default::default());
        }
        FileKind::Socket(s) => {
            return match &s.tx {
                Some(tx) => pipe_write(p, tx, Src::User(buf), count, nonblock, true),
                None => {
                    crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a socket that was shut down");
                    Err(EPIPE)
                }
            };
        }
        FileKind::Inet(_) => {
            let FileKind::Inet(s) = &mut f.kind else { unreachable!() };
            return super::net::inet_write(p, s, Src::User(buf), count, nonblock, true, None);
        }
        FileKind::EventFd(e) => {
            if count < 8 {
                return Err(EINVAL);
            }
            let v = read_u64(&mut p.aspace, buf)?;
            if v == u64::MAX {
                return Err(EINVAL);
            }
            let mut ev = e.lock();
            if ev.count.checked_add(v).is_none_or(|s| s > EVENTFD_MAX) {
                drop(ev);
                return would_block(p, nonblock);
            }
            ev.count += v;
            if v > 0 {
                ev.touch();
            }
            return Ok(8);
        }
    };
    stdio_write(p, ch, buf, count, nonblock)
}

/// A write to stdout or stderr, like Linux's to a pipe. Without O_NONBLOCK
/// it returns once all of it is sent, waiting whenever the host is slow to
/// read (`Thread::io_done` carries what's sent across the waits). With it,
/// it takes what fits, or fails with EAGAIN if nothing does.
fn stdio_write(p: &mut Process, ch: Channel, buf: u64, count: u64, nonblock: bool) -> SysResult {
    let mut done = core::mem::take(&mut p.cur().io_done).min(count);
    if done == count {
        return Ok(count);
    }
    // Wait for room for the rest (as much as fits at once), so a slow host
    // gets big batches rather than a wakeup per buffer.
    let need = if nonblock { 1 } else { ((count - done) as usize).min(console::OUTPUT_CAPACITY) };
    let mut chunk = [0u8; console::WRITE_CHUNK];
    let mut room = console::output_room(need);
    while room && done < count {
        let n = (count - done).min(console::WRITE_CHUNK as u64) as usize;
        if let Err(e) = copy_in(&mut p.aspace, buf + done, &mut chunk[..n]) {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
        room = console::try_write(ch, &chunk[..n]);
        done += if room { n as u64 } else { 0 };
    }
    if done == count {
        Ok(count)
    } else if nonblock {
        if done > 0 { Ok(done) } else { Err(EAGAIN) }
    } else {
        p.cur().io_done = done;
        would_block(p, false)
    }
}

/// Read from a pipe (or one direction of a socket). `peek` leaves the data in place.
pub(super) fn pipe_read(p: &mut Process, end: &PipeEnd, buf: u64, count: u64, nonblock: bool, peek: bool) -> SysResult {
    // Descriptors passed this way are dropped (closed) by a plain read.
    pipe_read_rights(p, end, buf, count, nonblock, peek, &mut Vec::new())
}

/// The same, taking the descriptors passed (SCM_RIGHTS) with the bytes
/// read into `rights`. A read stops short of bytes that came with
/// descriptors, so they arrive with the first of them, as on Linux.
pub(super) fn pipe_read_rights(
    p: &mut Process,
    end: &PipeEnd,
    buf: u64,
    count: u64,
    nonblock: bool,
    peek: bool,
    rights: &mut Vec<crate::unix::Rights>,
) -> SysResult {
    pipe_read_full(p, end, buf, count, nonblock, peek, rights, None)
}

/// The same, and with `cred` (an AF_UNIX stream's reader with
/// SO_PASSCRED) only one writer's bytes, as Linux's
/// unix_stream_read_generic never glues different writers' together:
/// their credentials go into `cred`, or, if it has some already (an
/// earlier part of the same recvmsg), only bytes from them are read.
#[allow(clippy::too_many_arguments)]
pub(super) fn pipe_read_full(
    p: &mut Process,
    end: &PipeEnd,
    buf: u64,
    count: u64,
    nonblock: bool,
    peek: bool,
    rights: &mut Vec<crate::unix::Rights>,
    cred: Option<&mut Option<crate::unix::Cred>>,
) -> SysResult {
    let mut pipe = end.pipe.lock();
    if pipe.buf.is_empty() {
        if pipe.writers == 0 {
            return Ok(0);
        }
        drop(pipe);
        return would_block(p, nonblock);
    }
    let mut n = (count as usize).min(pipe.buf.len());
    let at = pipe.read;
    if let Some(cred) = cred
        && let Some((writer, next)) = pipe.writer()
    {
        match cred {
            Some(c) if *c != writer => return Ok(0),
            _ => *cred = Some(writer),
        }
        if let Some(next) = next {
            n = n.min(next.saturating_sub(at).max(1) as usize);
        }
    }
    // Descriptors that came with the first byte read arrive with it.
    let mut take_rights = false;
    if let Some(&(pos, _)) = pipe.rights.front() {
        if pos <= at {
            take_rights = !peek;
            // The next ones, which this read stops short of.
            if let Some(&(next, _)) = pipe.rights.get(1) {
                n = n.min(next.saturating_sub(at).max(1) as usize);
            }
        } else {
            n = n.min((pos - at) as usize);
        }
    }
    // With the pipe held, as `pipe_write` holds it across `copy_in`: another
    // reader on another CPU would otherwise take the same bytes. A fault
    // on the buffer reads files or the host, never a pipe.
    let (front, back) = pipe.buf.as_slices();
    let front_n = front.len().min(n);
    copy_out(&mut p.aspace, buf, &front[..front_n])?;
    if front_n < n {
        copy_out(&mut p.aspace, buf + front_n as u64, &back[..n - front_n])?;
    }
    if take_rights {
        rights.push(pipe.rights.pop_front().unwrap().1);
    }
    if !peek {
        pipe.buf.drain(..n);
        pipe.read += n as u64;
        pipe.drained();
        pipe.touch();
    }
    Ok(n as u64)
}

/// Where written bytes come from: the program's memory, or the kernel's
/// (sendfile's, read from a file).
#[derive(Clone, Copy)]
pub(super) enum Src<'a> {
    User(u64),
    Kernel(&'a [u8]),
}

impl Src<'_> {
    /// Bytes `off..off + out.len()` of it.
    pub(super) fn read(self, p: &mut Process, off: u64, out: &mut [u8]) -> Result<(), Errno> {
        match self {
            Src::User(buf) => copy_in(&mut p.aspace, buf + off, out),
            Src::Kernel(b) => {
                let b = b.get(off as usize..off as usize + out.len()).ok_or(EFAULT)?;
                out.copy_from_slice(b);
                Ok(())
            }
        }
    }
}

/// Write to a pipe (or one direction of a socket).
pub(super) fn pipe_write(
    p: &mut Process,
    end: &PipeEnd,
    src: Src,
    count: u64,
    nonblock: bool,
    sigpipe: bool,
) -> SysResult {
    pipe_write_as(p, end, src, count, nonblock, sigpipe, None)
}

/// The same, as `cred` (SCM_CREDENTIALS) rather than the writer (an
/// AF_UNIX stream keeps who wrote what).
pub(super) fn pipe_write_as(
    p: &mut Process,
    end: &PipeEnd,
    src: Src,
    count: u64,
    nonblock: bool,
    sigpipe: bool,
    cred: Option<crate::unix::Cred>,
) -> SysResult {
    if count == 0 {
        return Ok(0);
    }
    let mut pipe = end.pipe.lock();
    if pipe.readers == 0 {
        drop(pipe);
        if sigpipe {
            crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a pipe with no readers");
        }
        return Err(EPIPE);
    }
    // Writes of up to PIPE_BUF bytes are atomic: wait for room for all of it.
    let need = if count as usize <= PIPE_BUF { count as usize } else { 1 };
    let writer = cred.unwrap_or_else(|| super::unix::sender(p));
    if pipe.reserve(need) < need || !pipe.writer_fits(writer) {
        drop(pipe);
        return would_block(p, nonblock);
    }
    let n = pipe.reserve(count as usize);
    let mut tmp = alloc::vec![0u8; n];
    src.read(p, 0, &mut tmp)?;
    // Only once there are bytes (EFAULT, and nothing to say who wrote).
    pipe.note_writer(writer);
    pipe.buf.extend(tmp);
    pipe.written += n as u64;
    pipe.touch();
    Ok(n as u64)
}

/// EAGAIN for non-blocking files, otherwise block until I/O state changes.
pub(super) fn would_block(p: &mut Process, nonblock: bool) -> SysResult {
    if nonblock {
        return Err(EAGAIN);
    }
    let deadline = p.timeout_deadline(None);
    p.block_io(deadline, Ok(0))
}

pub fn read(p: &mut Process, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    read_into(p, &mut f, buf, count, None)
}

pub fn pread(p: &mut Process, fd: u64, buf: u64, count: u64, off: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    match f.kind {
        FileKind::Node(_) | FileKind::Generated(_) if (off as i64) < 0 => Err(EINVAL),
        FileKind::Node(_) | FileKind::Generated(_) | FileKind::ProcMem(..) => {
            read_into(p, &mut f, buf, count, Some(off))
        }
        FileKind::Dev(..) => read_into(p, &mut f, buf, count, None),
        _ => Err(ESPIPE),
    }
}

pub fn write(p: &mut Process, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    write_from(p, &mut f, buf, count, None)
}

pub fn pwrite(p: &mut Process, fd: u64, buf: u64, count: u64, off: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    match f.kind {
        FileKind::Node(_) if (off as i64) < 0 => Err(EINVAL),
        FileKind::Node(_) | FileKind::ProcMem(..) => write_from(p, &mut f, buf, count, Some(off)),
        FileKind::Dev(..) => write_from(p, &mut f, buf, count, None),
        _ => Err(ESPIPE),
    }
}

pub(super) fn iovecs(p: &mut Process, iov: u64, cnt: u64) -> Result<Vec<(u64, u64)>, Errno> {
    if cnt > 1024 {
        return Err(EINVAL);
    }
    let mut raw = alloc::vec![0u8; cnt as usize * 16];
    copy_in(&mut p.aspace, iov, &mut raw)?;
    Ok(raw
        .chunks(16)
        .map(|c| (u64::from_le_bytes(c[..8].try_into().unwrap()), u64::from_le_bytes(c[8..].try_into().unwrap())))
        .collect())
}

/// readv/writev/preadv/pwritev: one buffer after another until one comes up short.
/// `extra`: status flags (O_NONBLOCK, O_APPEND) for this call only, as
/// preadv2's RWF_NOWAIT and RWF_APPEND.
fn vectored(p: &mut Process, fd: u64, iov: u64, cnt: u64, at: Option<u64>, write: bool, extra: u32) -> SysResult {
    let file = p.fds.get(fd)?;
    // A datagram or seqpacket socket: all of it is one message.
    if let Some(sock) = super::unix::sock_of(&file) {
        if at.is_some() {
            return Err(ESPIPE);
        }
        let nonblock = file.lock().nonblocking() || extra & O_NONBLOCK != 0;
        let bufs = iovecs(p, iov, cnt)?;
        return if write {
            super::unix::send_msg(p, &sock, &bufs, 0, nonblock, None, Default::default())
        } else {
            super::unix::recv_msg(p, &sock, &bufs, 0, nonblock).map(|r| r.n)
        };
    }
    let mut f = file.lock();
    let added = extra & !f.flags;
    f.flags |= added;
    let r = vectored_file(p, &mut f, iov, cnt, at, write);
    f.flags &= !added;
    r
}

fn vectored_file(p: &mut Process, f: &mut OpenFile, iov: u64, cnt: u64, at: Option<u64>, write: bool) -> SysResult {
    if at.is_some() {
        match f.kind {
            FileKind::Node(_) | FileKind::Generated(_) | FileKind::Dev(..) | FileKind::ProcMem(..) => {}
            _ => return Err(ESPIPE),
        }
        if at.is_some_and(|o| (o as i64) < 0) {
            return Err(EINVAL);
        }
    }
    let bufs = iovecs(p, iov, cnt)?;
    vectored_bufs(p, f, bufs, at, write)
}

/// The buffers `bufs`, one after another, until one comes up short.
fn vectored_bufs(p: &mut Process, f: &mut OpenFile, bufs: Vec<(u64, u64)>, at: Option<u64>, write: bool) -> SysResult {
    // A blocking writev to stdout/stderr resumes after what it sent before
    // it waited (`Thread::io_done`), like write.
    let resumes = write && matches!(f.kind, FileKind::Stdout | FileKind::Stderr);
    let mut skip = if resumes { core::mem::take(&mut p.cur().io_done) } else { 0 };
    let mut total = 0;
    for (base, len) in bufs {
        let sent = skip.min(len);
        skip -= sent;
        total += sent;
        if sent == len {
            continue;
        }
        let (base, len) = (base + sent, len - sent);
        let pos = at.map(|o| o + total);
        let r = if write { write_from(p, f, base, len, pos) } else { read_into(p, f, base, len, pos) };
        match r {
            Ok(n) => {
                total += n;
                if n < len {
                    break;
                }
            }
            Err(e) if total == 0 => return Err(e),
            Err(EBLOCKED) if resumes => {
                p.cur().io_done += total;
                return Err(EBLOCKED);
            }
            Err(e) => {
                // Return what got through instead of waiting for the rest.
                if e == EBLOCKED {
                    p.cur().wait = None;
                }
                break;
            }
        }
    }
    Ok(total)
}

/// Does `f` have positions (pread's, lseek's)? Streams don't.
pub(super) fn seekable(f: &OpenFile) -> bool {
    matches!(f.kind, FileKind::Node(_) | FileKind::Generated(_) | FileKind::Dev(..))
}

/// An AIO read or write (`aio`), into or from `bufs`: at `at` on a file
/// with positions, at the stream's own on others (Linux ignores a
/// stream's offset), with `extra` status flags (RWF_APPEND's O_APPEND).
/// It never waits: a request is done before io_submit returns, so a
/// pipe, socket or terminal that isn't ready completes with EAGAIN, as
/// with RWF_NOWAIT (IOCB_CMD_POLL is how to wait for one).
pub(super) fn aio_rw(
    p: &mut Process,
    file: &crate::fd::FileRef,
    bufs: Vec<(u64, u64)>,
    at: Option<u64>,
    write: bool,
    extra: u32,
) -> SysResult {
    // A datagram or seqpacket socket: all the buffers are one message, as
    // in `vectored`.
    let r = if let Some(sock) = super::unix::sock_of(file) {
        if write {
            super::unix::send_msg(p, &sock, &bufs, 0, true, None, Default::default())
        } else {
            super::unix::recv_msg(p, &sock, &bufs, 0, true).map(|r| r.n)
        }
    } else {
        let mut f = file.lock();
        let added = (extra | O_NONBLOCK) & !f.flags;
        f.flags |= added;
        let r = vectored_bufs(p, &mut f, bufs, at, write);
        f.flags &= !added;
        r
    };
    if r == Err(EBLOCKED) {
        p.cur().wait = None;
        return Err(EAGAIN);
    }
    r
}

pub fn readv(p: &mut Process, fd: u64, iov: u64, cnt: u64) -> SysResult {
    vectored(p, fd, iov, cnt, None, false, 0)
}

pub fn writev(p: &mut Process, fd: u64, iov: u64, cnt: u64) -> SysResult {
    vectored(p, fd, iov, cnt, None, true, 0)
}

/// preadv/pwritev. On 64-bit the offset is the first of the two position arguments.
pub fn preadv(p: &mut Process, fd: u64, iov: u64, cnt: u64, off: u64, write: bool) -> SysResult {
    vectored(p, fd, iov, cnt, Some(off), write, 0)
}

/// preadv2/pwritev2 (nginx, cargo): preadv/pwritev, or readv/writev at
/// offset -1, with RWF_* flags. RWF_HIPRI (polling), RWF_DSYNC and
/// RWF_SYNC change nothing (the data is in memory once the call returns);
/// RWF_NOWAIT and RWF_APPEND are O_NONBLOCK and O_APPEND for this call.
pub fn preadv2(p: &mut Process, fd: u64, iov: u64, cnt: u64, off: u64, flags: u64, write: bool) -> SysResult {
    const RWF_HIPRI: u64 = 1;
    const RWF_DSYNC: u64 = 2;
    const RWF_SYNC: u64 = 4;
    const RWF_NOWAIT: u64 = 8;
    const RWF_APPEND: u64 = 0x10;
    if flags & !(RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND) != 0 {
        return Err(EOPNOTSUPP);
    }
    let mut extra = 0;
    if flags & RWF_NOWAIT != 0 {
        extra |= O_NONBLOCK;
    }
    if flags & RWF_APPEND != 0 && write {
        extra |= O_APPEND;
    }
    let at = (off as i64 != -1).then_some(off);
    vectored(p, fd, iov, cnt, at, write, extra)
}

pub fn lseek(p: &mut Process, fd: u64, off: u64, whence: u64) -> SysResult {
    const SEEK_DATA: u64 = 3;
    const SEEK_HOLE: u64 = 4;
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let size = match (&f.kind, &f.content) {
        (FileKind::Node(_), Some(c)) => c.lock().len() as i64,
        // A directory: getdents resumes by name, so only rewinding is meaningful.
        (FileKind::Node(_), None) => {
            if whence != 0 || (off as i64) < 0 {
                return Err(EINVAL);
            }
            f.offset = off;
            if off == 0 {
                f.dir_pos = None;
            }
            return Ok(off);
        }
        (FileKind::Generated(data), _) => data.len() as i64,
        (FileKind::Dev(..), _) => return Ok(0),
        // Any address, as Linux's mem_lseek (unsigned offsets): from the
        // start or from here, no end.
        (FileKind::ProcMem(..), _) => {
            f.offset = match whence {
                0 => off,
                1 => f.offset.wrapping_add(off),
                _ => return Err(EINVAL),
            };
            return Ok(f.offset);
        }
        _ => return Err(ESPIPE),
    };
    let off = off as i64;
    let new = match whence {
        0 => Some(off),
        1 => (f.offset as i64).checked_add(off),
        2 => size.checked_add(off),
        // Files have no holes worth reporting: all data, then the end.
        SEEK_DATA | SEEK_HOLE if off >= size => return Err(ENXIO),
        SEEK_DATA => Some(off),
        SEEK_HOLE => Some(size),
        _ => None,
    };
    match new {
        Some(n) if n >= 0 => {
            f.offset = n as u64;
            Ok(n as u64)
        }
        _ => Err(EINVAL),
    }
}

// ---------------------------------------------------------------- stat

fn split_ns(ns: u64) -> (u64, u64) {
    (ns / 1_000_000_000, ns % 1_000_000_000)
}

pub fn fstat(p: &mut Process, fd: u64, buf: u64) -> SysResult {
    let st = fd_stat(p, fd)?;
    copy_out(&mut p.aspace, buf, &crate::arch::abi::stat(&st)).map(|_| 0)
}

pub fn newfstatat(p: &mut Process, dirfd: u64, pathp: u64, buf: u64, flags: u64) -> SysResult {
    let st = path_stat(p, dirfd, pathp, flags)?;
    copy_out(&mut p.aspace, buf, &crate::arch::abi::stat(&st)).map(|_| 0)
}

pub fn statx(p: &mut Process, dirfd: u64, pathp: u64, flags: u64, buf: u64) -> SysResult {
    let st = path_stat(p, dirfd, pathp, flags)?;
    let mut b = [0u8; 256];
    let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(0, &0x7ffu32.to_le_bytes()); // STATX_BASIC_STATS
    put(4, &4096u32.to_le_bytes());
    put(16, &st.nlink.to_le_bytes());
    put(20, &st.uid.to_le_bytes());
    put(24, &st.gid.to_le_bytes());
    put(28, &(st.mode as u16).to_le_bytes());
    put(32, &st.ino.to_le_bytes());
    put(40, &st.size.to_le_bytes());
    put(48, &st.blocks.to_le_bytes());
    // stx_atime, (stx_btime: not in STATX_BASIC_STATS), stx_ctime, stx_mtime.
    for (off, t) in [(64, st.atime), (96, st.ctime), (112, st.mtime)] {
        let (sec, nsec) = split_ns(t);
        put(off, &sec.to_le_bytes());
        put(off + 8, &(nsec as u32).to_le_bytes());
    }
    put(128, &((st.rdev >> 8) as u32).to_le_bytes());
    put(132, &((st.rdev & 0xff) as u32).to_le_bytes());
    copy_out(&mut p.aspace, buf, &b).map(|_| 0)
}

pub fn faccessat(p: &mut Process, dirfd: u64, pathp: u64, mode: u64, flags: u64) -> SysResult {
    const R_OK: u64 = 4;
    const W_OK: u64 = 2;
    const X_OK: u64 = 1;
    let st = path_stat(p, dirfd, pathp, flags)?;
    if mode & !(R_OK | W_OK | X_OK) != 0 {
        return Err(EINVAL);
    }
    let is_dev = st.mode & 0o170000 == fs::S_IFCHR;
    // Without fs_write the filesystem is mounted read-only, as far as anyone can tell.
    if mode & W_OK != 0 && !is_dev && !p.policy.allows(Capability::FsWrite) {
        return Err(EROFS);
    }
    let is_dir = st.mode & 0o170000 == fs::S_IFDIR;
    if !fs::mode_permits(st.mode, st.uid, st.gid, is_dir, p.uid, p.gid, mode as u32) {
        return Err(EACCES);
    }
    Ok(0)
}

pub fn readlinkat(p: &mut Process, dirfd: u64, pathp: u64, buf: u64, size: u64) -> SysResult {
    if size as i64 <= 0 {
        return Err(EINVAL);
    }
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let target = match (procfs::fd_path(&path), procfs::other_fd_path(&path)) {
        (Some(fd), _) if path.contains("/fd/") => {
            let file = p.fds.get(fd).map_err(|_| ENOENT)?;
            procfs::fd_link(&file.lock().kind, fd)
        }
        (_, Some((pid, fd))) => with_other(p, pid, |q| {
            let file = q.fds.get(fd).map_err(|_| ENOENT)?;
            Ok(procfs::fd_link(&file.lock().kind, fd))
        })?,
        _ => {
            let ino = resolve(p, dirfd, &path, false)?;
            fs::lock().link_target(ino)?
        }
    };
    let n = (target.len() as u64).min(size) as usize;
    copy_out(&mut p.aspace, buf, &target.as_bytes()[..n]).map(|_| n as u64)
}

pub fn getdents64(p: &mut Process, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let FileKind::Node(dir) = f.kind else { return Err(ENOTDIR) };
    let mut fs = fs::lock();
    if !fs.is_dir(dir) {
        return Err(ENOTDIR);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = f.offset;
    let mut cursor = f.dir_pos.clone();
    // /proc/<pid>/fd lists the process's descriptors as symlinks, each
    // at offset fd + 2 (as Linux's proc_readfd_common), found as it goes:
    // a table may have 65536.
    let fd_pid = fs.fd_dir_pid(dir);
    if let Some(pid) = fd_pid.filter(|&pid| pid != p.pid)
        && let Some(q) = crate::procs::PROCS.lock().others.get(&pid)
        && !crate::procs::may_inspect(p, q, false)
    {
        // Another process's, if the caller may look at them (`with_other`).
        return Err(EACCES);
    }
    let next_fd = |from: u64| match fd_pid {
        Some(pid) if pid == p.pid => p.fds.next_open(from),
        Some(pid) => crate::procs::PROCS.lock().others.get(&pid).and_then(|q| q.fds.next_open(from)),
        None => None,
    };
    loop {
        let entry = match pos {
            0 => Some((String::from("."), fs.ino_number(dir), 4)),
            1 => {
                let parent = fs.node(dir).parent;
                Some((String::from(".."), fs.ino_number(parent), 4))
            }
            n if fd_pid.is_some() => next_fd(n - 2).map(|fd| {
                pos = fd + 2;
                (alloc::format!("{fd}"), fs.ino_number(dir), 10)
            }),
            // Resume after the last name returned: entries may have come and
            // gone since (rm -rf unlinks while it reads).
            _ => match fs.dir_next(dir, cursor.as_deref()) {
                Ok(item) => item.map(|it| (it.name, it.ino, it.d_type)),
                // A live mount's directory the host can't list now.
                Err(e) if out.is_empty() => return Err(e),
                Err(_) => None,
            },
        };
        let Some((name, ino, d_type)) = entry else { break };
        // Only a live mount's host could have a longer name: it couldn't be
        // looked up, and its record length wouldn't fit in d_reclen.
        if name.len() > fs::NAME_MAX {
            pos += 1;
            cursor = Some(name);
            continue;
        }
        let reclen = (19 + name.len() + 1).next_multiple_of(8);
        if out.len() + reclen > count as usize {
            if out.is_empty() {
                return Err(EINVAL);
            }
            break;
        }
        let start = out.len();
        out.extend_from_slice(&ino.to_le_bytes());
        out.extend_from_slice(&(pos as i64 + 1).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(d_type);
        out.extend_from_slice(name.as_bytes());
        out.resize(start + reclen, 0);
        pos += 1;
        if pos > 2 {
            cursor = Some(name);
        }
    }
    drop(fs);
    copy_out(&mut p.aspace, buf, &out)?;
    f.offset = pos;
    f.dir_pos = cursor;
    Ok(out.len() as u64)
}

// ---------------------------------------------------------------- cwd

pub fn getcwd(p: &mut Process, buf: u64, size: u64) -> SysResult {
    let cwd = p.cwd();
    let mut path = {
        let fs = fs::lock();
        if fs.node(cwd).nlink == 0 {
            return Err(ENOENT); // the working directory was removed
        }
        fs.path_of(cwd)
    };
    path.push('\0');
    if (size as usize) < path.len() {
        return Err(ERANGE);
    }
    copy_out(&mut p.aspace, buf, path.as_bytes()).map(|_| path.len() as u64)
}

pub fn chdir(p: &mut Process, pathp: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let ino = resolve(p, AT_FDCWD as u64, &path, true)?;
    set_cwd(p, ino)
}

pub fn fchdir(p: &mut Process, fd: u64) -> SysResult {
    let ino = dir_base(p, fd)?;
    set_cwd(p, ino)
}

fn set_cwd(p: &mut Process, ino: Ino) -> SysResult {
    // Every process sharing it (CLONE_FS) has a new /proc/<pid>/cwd.
    let mut pids = alloc::vec![p.pid];
    if p.fs.shared() {
        let procs = crate::procs::PROCS.lock();
        pids.extend(procs.others.values().filter(|q| !q.dead && q.fs.same(&p.fs)).map(|q| q.pid));
    }
    let mut fs = fs::lock();
    if !fs.is_dir(ino) {
        return Err(ENOTDIR);
    }
    let pin = Some(fs.pin(ino));
    p.fs.update(|f| (f.cwd, f.cwd_pin) = (ino, pin));
    let path = fs.path_of(ino);
    for pid in pids {
        fs.proc_set(pid, "cwd", &path);
    }
    Ok(0)
}

// ---------------------------------------------------------------- changing the tree
//
// These are gated by `fs_write` in the syscall table. Removing, renaming
// and creating names follow Linux's checks: permission on the directory,
// the sticky bit, and "." / ".." / "/" being off limits.

pub fn mkdirat(p: &mut Process, dirfd: u64, pathp: u64, mode: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let (dir, name) = parent_of(p, dirfd, &path)?;
    // A name that exists is EEXIST before a read-only filesystem is EROFS,
    // as on Linux: `mkdir -p` (busybox's tries "/" too) and makedirs
    // stop there without fs_write.
    if matches!(name.as_str(), "" | "." | "..") || fs::lock().child_of(dir, &name).is_some() {
        return Err(EEXIST);
    }
    need_write_in(p, nr::mkdirat, Some(dir), &path)?;
    landlock::check(p, dir, landlock::MAKE_DIR)?;
    let perm = mode as u32 & 0o1777 & !p.umask();
    fs::lock().create(dir, &name, Kind::Dir(alloc::collections::BTreeMap::new()), perm, p.uid, p.gid).map(|_| 0)
}

/// mknod: named pipes and regular files. Device nodes would reach
/// devices the sandbox doesn't have, so they're denied whoever asks.
pub fn mknodat(p: &mut Process, dirfd: u64, pathp: u64, mode: u64) -> SysResult {
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFSOCK: u32 = 0o140000;
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let perm = mode as u32 & 0o7777 & !p.umask();
    let kind = match mode as u32 & S_IFMT {
        S_IFIFO => Kind::Fifo(Default::default()),
        0 | S_IFREG => Kind::File(FileData::new(&[])),
        S_IFCHR | S_IFBLK => return p.deny(nr::mknodat, "mknodat", "privileged", &path),
        S_IFSOCK => return p.unimplemented(nr::mknodat, "mknodat", "S_IFSOCK", EPERM),
        _ => return Err(EINVAL),
    };
    let (dir, name) = parent_of(p, dirfd, &path)?;
    let mut fs = fs::lock();
    // A name that's there already is EEXIST first, as on Linux.
    if let Some(d) = landlock::domain_changing(p, &fs, dir)
        && fs.child_of(dir, &name).is_none()
    {
        d.check(&fs, dir, landlock::make_access(&kind))?;
    }
    fs.create(dir, &name, kind, perm, p.uid, p.gid).map(|_| 0)
}

pub fn unlinkat(p: &mut Process, dirfd: u64, pathp: u64, flags: u64) -> SysResult {
    const AT_REMOVEDIR: u64 = 0x200;
    if flags & !AT_REMOVEDIR != 0 {
        return Err(EINVAL);
    }
    let rmdir = flags & AT_REMOVEDIR != 0;
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let (dir, name) = parent_of(p, dirfd, &path)?;
    let mut fs = fs::lock();
    match (name.as_str(), rmdir) {
        ("", true) => return Err(EBUSY),
        (".", true) => return Err(EINVAL),
        ("..", true) => return Err(ENOTEMPTY),
        ("" | "." | "..", false) => return Err(EISDIR),
        _ => {}
    }
    // "file/" names a directory.
    if path.ends_with('/') && fs.child_of(dir, &name).is_some_and(|c| !fs.is_dir(c)) {
        return Err(ENOTDIR);
    }
    // A name that isn't there is ENOENT first, as on Linux.
    if let Some(d) = landlock::domain_changing(p, &fs, dir)
        && fs.child_of(dir, &name).is_some()
    {
        d.check(&fs, dir, if rmdir { landlock::REMOVE_DIR } else { landlock::REMOVE_FILE })?;
    }
    fs.remove(dir, &name, rmdir, p.uid, p.gid).map(|_| 0)
}

pub fn renameat2(p: &mut Process, odirfd: u64, opathp: u64, ndirfd: u64, npathp: u64, flags: u64) -> SysResult {
    const RENAME_NOREPLACE: u64 = 1;
    const RENAME_EXCHANGE: u64 = 2;
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0 || flags == RENAME_NOREPLACE | RENAME_EXCHANGE {
        return Err(EINVAL);
    }
    let opath = read_cstr(&mut p.aspace, opathp, PATH_MAX)?;
    let npath = read_cstr(&mut p.aspace, npathp, PATH_MAX)?;
    // Held so a live mount's directories can't be forgotten in between
    // (looking one up may make room by forgetting others).
    let (odir, oname) = parent_of(p, odirfd, &opath)?;
    let _opin = fs::lock().pin(odir);
    let (ndir, nname) = parent_of(p, ndirfd, &npath)?;
    let _npin = fs::lock().pin(ndir);
    let mut fs = fs::lock();
    if [&oname, &nname].iter().any(|n| matches!(n.as_str(), "" | "." | "..")) {
        return Err(EBUSY);
    }
    let src = fs.child_of(odir, &oname).ok_or(ENOENT)?;
    if (opath.ends_with('/') || npath.ends_with('/')) && !fs.is_dir(src) {
        return Err(ENOTDIR);
    }
    let (noreplace, exchange) = (flags & RENAME_NOREPLACE != 0, flags & RENAME_EXCHANGE != 0);
    // Not when the rename fails first: across mounts, EEXIST, or ENOENT
    // for an exchange.
    if let Some(d) = landlock::domain_changing(p, &fs, ndir) {
        let dst = fs.child_of(ndir, &nname);
        if !(fs.crosses_mount(odir, ndir) || noreplace && dst.is_some() || exchange && dst.is_none()) {
            d.check_refer(&fs, src, odir, ndir, dst, true, exchange)?;
        }
    }
    fs.rename(odir, &oname, ndir, &nname, noreplace, exchange, p.uid, p.gid).map(|_| 0)
}

pub fn linkat(p: &mut Process, odirfd: u64, opathp: u64, ndirfd: u64, npathp: u64, flags: u64) -> SysResult {
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let follow = if flags & AT_SYMLINK_FOLLOW != 0 { 0 } else { AT_SYMLINK_NOFOLLOW };
    let src = at_node(p, odirfd, opathp, (flags & AT_EMPTY_PATH) | follow)?;
    let _pin = fs::lock().pin(src);
    let opath = read_cstr(&mut p.aspace, opathp, PATH_MAX)?;
    // (An empty path is the descriptor's: `found_in` gives its parent.)
    let obase = if opath.is_empty() { ROOT } else { base_of(p, odirfd, &opath)? };
    let npath = read_cstr(&mut p.aspace, npathp, PATH_MAX)?;
    let (dir, name) = parent_of(p, ndirfd, &npath)?;
    let _dpin = fs::lock().pin(dir);
    let mut fs = fs::lock();
    if let Some(d) = landlock::domain_changing(p, &fs, dir)
        && fs.child_of(dir, &name).is_none()
        && !fs.crosses_mount(src, dir)
    {
        // The directory its path went through, as a dentry's parent.
        let odir = fs.found_in(src, obase, &opath, &fs::Scope::NONE);
        d.check_refer(&fs, src, odir, dir, None, false, false)?;
    }
    fs.link(src, dir, &name, p.uid, p.gid).map(|_| 0)
}

pub fn symlinkat(p: &mut Process, targetp: u64, dirfd: u64, pathp: u64) -> SysResult {
    let target = read_cstr(&mut p.aspace, targetp, PATH_MAX)?;
    if target.is_empty() {
        return Err(ENOENT);
    }
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let (dir, name) = parent_of(p, dirfd, &path)?;
    let mut fs = fs::lock();
    if let Some(d) = landlock::domain_changing(p, &fs, dir)
        && fs.child_of(dir, &name).is_none()
    {
        d.check(&fs, dir, landlock::MAKE_SYM)?;
    }
    fs.create(dir, &name, Kind::Symlink(target), 0o777, p.uid, p.gid).map(|_| 0)
}

/// Set a regular file's length, as truncate/ftruncate do.
fn set_len(p: &mut Process, n: u32, c: &Content, ino: Ino, len: u64) -> SysResult {
    if (len as i64) < 0 {
        return Err(EINVAL);
    }
    c.lock().may_resize(len)?;
    note_shared(p, n, c);
    c.lock().truncate(len)?;
    zap_shared(p, c, len);
    fs::lock().modified(ino);
    Ok(0)
}

/// A file shrank: its pages past the end go from every process's shared
/// mappings of it, as on Linux (touching them is SIGBUS). Page tables are
/// the kernel's to change, whichever process they're for; the TLBs are
/// flushed everywhere.
pub(super) fn zap_shared(p: &mut Process, c: &Content, len: u64) {
    if !c.lock().mapped_live() {
        return;
    }
    p.aspace.zap_file(c, len);
    for q in crate::procs::PROCS.lock().others.values_mut() {
        q.aspace.zap_file(c, len);
    }
}

pub fn truncate(p: &mut Process, pathp: u64, len: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let ino = resolve(p, AT_FDCWD as u64, &path, true)?;
    let base = base_of(p, AT_FDCWD as u64, &path)?;
    let mut fs = fs::lock();
    if fs.is_dir(ino) {
        return Err(EISDIR);
    }
    if !fs.permits(ino, p.uid, p.gid, MAY_WRITE) {
        return Err(EACCES);
    }
    if let Some(d) = landlock::domain_changing(p, &fs, ino) {
        let dir = fs.found_in(ino, base, &path, &fs::Scope::NONE);
        d.check_in(&fs, ino, dir, landlock::TRUNCATE)?;
    }
    fs.copy_up(ino)?;
    let c = fs.content(ino).ok_or(EINVAL)?;
    drop(fs);
    set_len(p, nr::truncate, &c, ino, len)
}

/// The regular file an fd opened for writing refers to (ftruncate, fallocate).
fn writable_file(p: &Process, fd: u64, not_file: Errno) -> Result<(Ino, Content), Errno> {
    let file = p.fds.get(fd)?;
    let f = file.lock();
    match (&f.kind, &f.content) {
        (FileKind::Node(ino), Some(c)) if f.flags & O_ACCMODE != O_RDONLY && !f.path_only => Ok((*ino, c.clone())),
        (FileKind::Node(_), Some(_)) => Err(EBADF),
        (FileKind::Pipe(_) | FileKind::Fifo(_) | FileKind::Socket(_) | FileKind::Inet(_), _) => Err(ESPIPE),
        _ => Err(not_file),
    }
}

pub fn ftruncate(p: &mut Process, fd: u64, len: u64) -> SysResult {
    let (ino, c) = writable_file(p, fd, EINVAL).map_err(|e| if e == ESPIPE { EINVAL } else { e })?;
    // Landlock decided at open (hook_file_truncate).
    if p.fds.get(fd)?.lock().landlock_denied & landlock::TRUNCATE != 0 {
        return Err(EACCES);
    }
    set_len(p, nr::ftruncate, &c, ino, len)
}

pub fn fallocate(p: &mut Process, fd: u64, mode: u64, off: u64, len: u64) -> SysResult {
    const FALLOC_FL_KEEP_SIZE: u64 = 1;
    let (off, len) = (off as i64, len as i64);
    if off < 0 || len <= 0 {
        return Err(EINVAL);
    }
    let (ino, c) = writable_file(p, fd, ENODEV)?;
    let end = (off as u64).checked_add(len as u64).filter(|&e| e <= MAX_FILE_SIZE).ok_or(EFBIG)?;
    match mode {
        // Space isn't reserved (pages are allocated when written), but the
        // file grows as if it were.
        0 => {
            if c.lock().len() < end {
                set_len(p, nr::fallocate, &c, ino, end)?;
            }
            Ok(0)
        }
        FALLOC_FL_KEEP_SIZE => Ok(0),
        _ => Err(EOPNOTSUPP),
    }
}

/// chmod: only the owner (or root) may change the mode.
fn set_mode(p: &mut Process, ino: Ino, mode: u64) -> SysResult {
    let mut fs = fs::lock();
    let n = fs.node(ino);
    if n.system || (p.uid != 0 && p.uid != n.uid) {
        return Err(EPERM);
    }
    fs.set_attr(ino, Some(mode as u32 & 0o7777), None, None).map(|_| 0)
}

pub fn fchmod(p: &mut Process, fd: u64, mode: u64) -> SysResult {
    let ino = fd_node(p, fd).map_err(|_| EBADF)?;
    set_mode(p, ino, mode)
}

pub fn fchmodat(p: &mut Process, dirfd: u64, pathp: u64, mode: u64) -> SysResult {
    let ino = at_node(p, dirfd, pathp, 0)?;
    set_mode(p, ino, mode)
}

/// fchmodat with flags (Linux 6.6; glibc 2.39's fchmodat tries it first).
/// Like Linux, a symlink's own mode can't be changed.
pub fn fchmodat2(p: &mut Process, dirfd: u64, pathp: u64, mode: u64, flags: u64) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let ino = at_node(p, dirfd, pathp, flags)?;
    // (EINVAL: it isn't a symlink.)
    if fs::lock().link_target(ino) != Err(EINVAL) {
        return Err(EOPNOTSUPP);
    }
    set_mode(p, ino, mode)
}

/// chown: without privileges a program can only "change" a file it owns to
/// its own uid and its own group, as on Linux. -1 leaves an id alone.
fn set_owner(p: &mut Process, ino: Ino, uid: u64, gid: u64) -> SysResult {
    let (uid, gid) = (uid as u32, gid as u32);
    let mut fs = fs::lock();
    let n = fs.node(ino);
    let new_uid = if uid == u32::MAX { n.uid } else { uid };
    let new_gid = if gid == u32::MAX { n.gid } else { gid };
    if n.system || (p.uid != 0 && (n.uid != p.uid || new_uid != n.uid || (new_gid != n.gid && new_gid != p.gid))) {
        return Err(EPERM);
    }
    // A lazy import's node becomes the sandbox's. A live mount's files
    // belong to whoever owns them on the host; the guest only shows them as
    // the sandbox user's. Only "changes" that change nothing work.
    if (new_uid, new_gid) != (n.uid, n.gid) {
        fs.copy_up(ino)?;
    }
    let n = fs.node(ino);
    if fs.remote_id(ino).is_some() {
        if fs.read_only(ino) {
            return Err(EROFS);
        }
        if (new_uid, new_gid) != (n.uid, n.gid) {
            return Err(EPERM);
        }
    }
    let n = fs.node_mut(ino);
    (n.uid, n.gid) = (new_uid, new_gid);
    fs.changed(ino);
    Ok(0)
}

pub fn fchown(p: &mut Process, fd: u64, uid: u64, gid: u64) -> SysResult {
    let ino = fd_node(p, fd).map_err(|_| EBADF)?;
    set_owner(p, ino, uid, gid)
}

pub fn fchownat(p: &mut Process, dirfd: u64, pathp: u64, uid: u64, gid: u64, flags: u64) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let ino = at_node(p, dirfd, pathp, flags)?;
    set_owner(p, ino, uid, gid)
}

pub fn utimensat(p: &mut Process, dirfd: u64, pathp: u64, times: u64, flags: u64) -> SysResult {
    const UTIME_NOW: u64 = (1 << 30) - 1;
    const UTIME_OMIT: u64 = (1 << 30) - 2;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    // A NULL path means dirfd itself (futimens).
    let ino = if pathp == 0 { fd_node(p, dirfd).map_err(|_| EBADF)? } else { at_node(p, dirfd, pathp, flags)? };
    let now = time::realtime_ns();
    let mut set = [Some(now), Some(now)];
    let mut explicit = false;
    if times != 0 {
        for (i, t) in set.iter_mut().enumerate() {
            let sec = read_u64(&mut p.aspace, times + i as u64 * 16)?;
            let nsec = read_u64(&mut p.aspace, times + i as u64 * 16 + 8)?;
            *t = match nsec {
                UTIME_NOW => Some(now),
                UTIME_OMIT => None,
                n if n < 1_000_000_000 && (sec as i64) >= 0 => {
                    explicit = true;
                    Some(sec.saturating_mul(1_000_000_000).saturating_add(n))
                }
                _ => return Err(EINVAL),
            };
        }
    }
    let mut fs = fs::lock();
    if fs.node(ino).system {
        return Err(EPERM);
    }
    let owner = p.uid == 0 || fs.node(ino).uid == p.uid;
    // Setting explicit times needs ownership; "now" also works with write permission.
    if !owner && (explicit || !fs.permits(ino, p.uid, p.gid, MAY_WRITE)) {
        return Err(if explicit { EPERM } else { EACCES });
    }
    fs.set_attr(ino, None, set[0], set[1]).map(|_| 0)
}

/// The contents behind an fd, for sendfile and copy_file_range.
fn fd_content(p: &Process, fd: u64, write: bool) -> Result<(crate::fd::FileRef, Content, Ino), Errno> {
    let file = p.fds.get(fd)?;
    let f = file.lock();
    let mode_ok = if write { f.flags & O_ACCMODE != O_RDONLY } else { f.flags & O_ACCMODE != O_WRONLY };
    let r = match (&f.kind, &f.content) {
        (FileKind::Node(ino), Some(c)) if mode_ok && !f.path_only => Ok((c.clone(), *ino)),
        (FileKind::Node(_), Some(_)) => Err(EBADF),
        _ => Err(EINVAL),
    };
    drop(f);
    r.map(|(c, ino)| (file, c, ino))
}

/// Copy `len` bytes between files in the kernel. Returns the count copied.
fn copy_contents(src: &Content, mut soff: u64, dst: &Content, dino: Ino, mut doff: u64, len: u64) -> SysResult {
    if doff.checked_add(len).is_none_or(|end| end > MAX_FILE_SIZE) {
        return Err(EFBIG);
    }
    dst.lock().may_write(doff + len)?;
    let mut chunk = [0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let want = (len - done).min(CHUNK as u64) as usize;
        let n = match src.lock().read_at(soff, &mut chunk[..want]) {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        let w = dst.lock().write(doff, &chunk[..n]);
        let k = match w {
            Ok(k) => k,
            Err((k, e)) if done == 0 && k == 0 => return Err(e),
            Err((k, _)) => k,
        } as u64;
        done += k;
        soff += k;
        doff += k;
        if k < n as u64 {
            break;
        }
    }
    if done > 0 {
        fs::lock().modified(dino);
    }
    Ok(done)
}

/// Read an optional `loff_t *` offset argument.
fn offset_arg(p: &mut Process, ptr: u64) -> Result<Option<u64>, Errno> {
    if ptr == 0 {
        return Ok(None);
    }
    let off = read_u64(&mut p.aspace, ptr)?;
    if (off as i64) < 0 {
        return Err(EINVAL);
    }
    Ok(Some(off))
}

/// The most sendfile moves to a pipe or socket at once (a kernel buffer).
const SENDFILE_CHUNK: u64 = 64 * 1024;

/// sendfile from a regular file to a regular file, stdout or stderr, a
/// pipe or FIFO, or a stream socket. Other destinations get EINVAL, which
/// makes callers (Python's shutil, busybox) fall back to read and write.
pub fn sendfile(p: &mut Process, out_fd: u64, in_fd: u64, offp: u64, count: u64) -> SysResult {
    let (in_file, src, _) = fd_content(p, in_fd, false)?;
    let start = match offset_arg(p, offp)? {
        Some(o) => o,
        None => in_file.lock().offset,
    };
    let count = count.min(MAX_RW);
    let out = p.fds.get(out_fd)?;
    let mut o = out.lock();
    if o.flags & O_ACCMODE == O_RDONLY {
        return Err(EBADF);
    }
    let nonblock = o.nonblocking();
    let mut blocked = false;
    let n = match (&o.kind, o.content.clone()) {
        (FileKind::Node(ino), Some(dst)) => {
            let ino = *ino;
            note_shared(p, nr::sendfile, &dst);
            let doff = if o.flags & O_APPEND != 0 { dst.lock().len() } else { o.offset };
            let n = copy_contents(&src, start, &dst, ino, doff, count)?;
            o.offset = doff + n;
            n
        }
        (FileKind::Stdout | FileKind::Stderr, _) => {
            let ch = if matches!(o.kind, FileKind::Stdout) { Channel::Stdout } else { Channel::Stderr };
            let mut chunk = [0u8; console::WRITE_CHUNK];
            let mut done = 0;
            while done < count {
                let want = (count - done).min(console::WRITE_CHUNK as u64) as usize;
                let n = match src.lock().read_at(start + done, &mut chunk[..want]) {
                    Ok(n) => n,
                    Err(e) if done == 0 => return Err(e),
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                if !console::try_write(ch, &chunk[..n]) {
                    blocked = done == 0;
                    break;
                }
                done += n as u64;
            }
            done
        }
        // A pipe or a socket (nginx serves files this way): what a write
        // of the next chunk would take.
        (FileKind::Pipe(_) | FileKind::Fifo(_) | FileKind::Socket(_) | FileKind::Inet(_), _) => {
            let mut data = alloc::vec![0u8; count.min(SENDFILE_CHUNK) as usize];
            let got = src.lock().read_at(start, &mut data)?;
            let data = Src::Kernel(&data[..got]);
            match &mut o.kind {
                _ if got == 0 => 0,
                FileKind::Pipe(end) if end.write => pipe_write(p, end, data, got as u64, nonblock, true)?,
                FileKind::Fifo(FifoFile { write: Some(end), .. }) => {
                    pipe_write(p, end, data, got as u64, nonblock, true)?
                }
                FileKind::Socket(s) => match &s.tx {
                    Some(tx) => pipe_write(p, tx, data, got as u64, nonblock, true)?,
                    None => {
                        crate::signal::raise(
                            p,
                            crate::signal::SIGPIPE,
                            "SIGPIPE: wrote to a socket that was shut down",
                        );
                        return Err(EPIPE);
                    }
                },
                FileKind::Inet(s) => super::net::inet_write(p, s, data, got as u64, nonblock, true, None)?,
                _ => return Err(EBADF),
            }
        }
        _ => return Err(EINVAL),
    };
    drop(o);
    if blocked {
        return would_block(p, nonblock);
    }
    if offp != 0 {
        write_u64(&mut p.aspace, offp, start + n)?;
    } else {
        in_file.lock().offset = start + n;
    }
    Ok(n)
}

pub fn copy_file_range(
    p: &mut Process,
    in_fd: u64,
    offin: u64,
    out_fd: u64,
    offout: u64,
    len: u64,
    flags: u64,
) -> SysResult {
    if flags != 0 {
        return Err(EINVAL);
    }
    let (in_file, src, _) = fd_content(p, in_fd, false)?;
    let (out_file, dst, dino) = fd_content(p, out_fd, true)?;
    if out_file.lock().flags & O_APPEND != 0 {
        return Err(EBADF);
    }
    let soff = offset_arg(p, offin)?.unwrap_or_else(|| in_file.lock().offset);
    let doff = offset_arg(p, offout)?.unwrap_or_else(|| out_file.lock().offset);
    let len = len.min(MAX_RW);
    if Arc::ptr_eq(&src, &dst) && soff < doff.saturating_add(len) && doff < soff.saturating_add(len) {
        return Err(EINVAL); // overlapping ranges of one file
    }
    note_shared(p, nr::copy_file_range, &dst);
    let n = copy_contents(&src, soff, &dst, dino, doff, len)?;
    if offin != 0 {
        write_u64(&mut p.aspace, offin, soff + n)?;
    } else {
        in_file.lock().offset = soff + n;
    }
    if offout != 0 {
        write_u64(&mut p.aspace, offout, doff + n)?;
    } else {
        out_file.lock().offset = doff + n;
    }
    Ok(n)
}

// ---------------------------------------------------------------- descriptors

pub fn dup(p: &mut Process, fd: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    p.fds.alloc(FdEntry { file, cloexec: false }, 0)
}

pub fn dup3(p: &mut Process, old: u64, new: u64, flags: u64) -> SysResult {
    if old == new || flags & !(O_CLOEXEC as u64) != 0 {
        return Err(EINVAL);
    }
    let file = p.fds.get(old)?;
    if let Ok(replaced) = p.fds.get(new) {
        closing(p, &replaced);
    }
    p.fds.set(new, FdEntry { file, cloexec: flags != 0 })?;
    Ok(new)
}

/// flock(2): a whole-file lock held by the open file description.
pub fn flock(p: &mut Process, fd: u64, op: u64) -> SysResult {
    const LOCK_SH: u64 = 1;
    const LOCK_EX: u64 = 2;
    const LOCK_NB: u64 = 4;
    const LOCK_UN: u64 = 8;
    let write = match op & !LOCK_NB {
        LOCK_SH => Some(false),
        LOCK_EX => Some(true),
        LOCK_UN => None,
        _ => return Err(EINVAL),
    };
    let file = p.fds.get(fd)?;
    let (key, id) = {
        let f = file.lock();
        if f.path_only {
            return Err(EBADF);
        }
        (f.lock_key(), f.id())
    };
    match locks::flock(key, locks::Owner::File(id), p.pid, write)? {
        locks::Outcome::Done => {
            file.lock().locked = true;
            Ok(0)
        }
        locks::Outcome::Conflict(_) if op & LOCK_NB != 0 => Err(EAGAIN),
        // Re-run when a lock goes (`locks` says so with ipc::changed).
        locks::Outcome::Conflict(_) => {
            let deadline = p.timeout_deadline(None);
            p.block_io(deadline, Ok(0))
        }
    }
}

const F_SETLKW: u64 = 7;
const F_OFD_SETLKW: u64 = 38;

/// fcntl's record locks: POSIX (F_GETLK, F_SETLK, F_SETLKW: the process
/// holds them) and open file description ones (F_OFD_*: the open file does).
fn record_lock(p: &mut Process, fd: u64, cmd: u64, arg: u64) -> SysResult {
    const F_GETLK: u64 = 5;
    const F_OFD_GETLK: u64 = 36;
    const F_UNLCK: i16 = 2;
    let ofd = matches!(cmd, 36..=38);
    let mut b = [0u8; 32];
    copy_in(&mut p.aspace, arg, &mut b)?;
    // struct flock: l_type, l_whence (i16), l_start, l_len (i64 at 8), l_pid (i32 at 24).
    let ty = i16::from_le_bytes([b[0], b[1]]);
    let whence = i16::from_le_bytes([b[2], b[3]]);
    let start = i64::from_le_bytes(b[8..16].try_into().unwrap());
    let len = i64::from_le_bytes(b[16..24].try_into().unwrap());
    if ofd && i32::from_le_bytes(b[24..28].try_into().unwrap()) != 0 {
        return Err(EINVAL);
    }
    let write = match ty {
        0 => Some(false),
        1 => Some(true),
        F_UNLCK => None,
        _ => return Err(EINVAL),
    };
    let file = p.fds.get(fd)?;
    let (key, id, acc, offset, size) = {
        let f = file.lock();
        if f.path_only {
            return Err(EBADF);
        }
        let size = f.content.as_ref().map_or(0, |c| c.lock().len());
        (f.lock_key(), f.id(), f.flags & O_ACCMODE, f.offset, size)
    };
    let base: i64 = match whence {
        0 => 0,
        1 => offset as i64,
        2 => size as i64,
        _ => return Err(EINVAL),
    };
    let at = base.checked_add(start).ok_or(EOVERFLOW)?;
    // A negative length is the bytes before; zero, everything after.
    let (s, e) = match len {
        0 => (at, None),
        // The last byte must be representable (the end itself may be 2^63).
        l if l > 0 => (at, Some(at.checked_add(l - 1).ok_or(EOVERFLOW)? as u64 + 1)),
        l => (at.checked_add(l).ok_or(EINVAL)?, Some(at as u64)),
    };
    if s < 0 {
        return Err(EINVAL);
    }
    let (s, e) = (s as u64, e.unwrap_or(u64::MAX));
    let owner = if ofd { locks::Owner::File(id) } else { p.fds.lock_owner() };
    if matches!(cmd, F_GETLK | F_OFD_GETLK) {
        let Some(want) = write else { return Err(EINVAL) };
        match locks::conflict(key, owner, want, s, e) {
            Some(l) => {
                b[0..2].copy_from_slice(&(l.write as i16).to_le_bytes());
                b[2..4].copy_from_slice(&0i16.to_le_bytes());
                b[8..16].copy_from_slice(&(l.start as i64).to_le_bytes());
                let n = if l.end == u64::MAX { 0 } else { (l.end - l.start) as i64 };
                b[16..24].copy_from_slice(&n.to_le_bytes());
                // An open file description's lock has no process: -1.
                let pid = if matches!(l.owner, locks::Owner::File(_)) { -1 } else { l.pid as i32 };
                b[24..28].copy_from_slice(&pid.to_le_bytes());
            }
            None => b[0..2].copy_from_slice(&F_UNLCK.to_le_bytes()),
        }
        return copy_out(&mut p.aspace, arg, &b).map(|_| 0);
    }
    if (write == Some(false) && acc == O_WRONLY) || (write == Some(true) && acc == O_RDONLY) {
        return Err(EBADF);
    }
    match locks::set_range(key, owner, p.pid, write, s, e)? {
        locks::Outcome::Done => {
            if ofd {
                file.lock().locked = true;
            } else {
                p.fds.set_posix_locks();
            }
            Ok(0)
        }
        locks::Outcome::Conflict(l) if matches!(cmd, F_SETLKW | F_OFD_SETLKW) => {
            if !ofd && deadlock(p, l) {
                return Err(EDEADLK);
            }
            p.cur().lock_wait = Some((key, s, e, write == Some(true)));
            let deadline = p.timeout_deadline(None);
            p.block_io(deadline, Ok(0))
        }
        locks::Outcome::Conflict(_) => Err(EAGAIN),
    }
}

/// Would waiting for `held` close a circle of processes waiting for each
/// other's POSIX locks (Linux's posix_locks_deadlock)? Each one waits in
/// fcntl(F_SETLKW) for a lock someone in the circle holds. Lock owners are
/// descriptor tables (see `locks`), so a holder is any process using one.
fn deadlock(p: &mut Process, held: locks::Lock) -> bool {
    let me = p.fds.lock_owner();
    let procs = crate::procs::PROCS.lock();
    let mut holder = held.owner;
    for _ in 0..64 {
        if !matches!(holder, locks::Owner::Files(_)) {
            return false;
        }
        if holder == me {
            return true;
        }
        // A thread blocked in F_SETLKW, and what it waits for.
        let waiting = procs.others.values().filter(|q| q.fds.lock_owner() == holder).find_map(|q| {
            q.threads.values().find_map(|t| {
                let blocked = t.wait.is_some() && t.regs.syscall_nr() == nr::fcntl as u64 && t.regs.arg(1) == F_SETLKW;
                blocked.then_some(t.lock_wait).flatten()
            })
        });
        let Some((key, s, e, write)) = waiting else { return false };
        match locks::conflict(key, holder, write, s, e) {
            Some(next) => holder = next.owner,
            None => return false,
        }
    }
    false
}

pub fn fcntl(p: &mut Process, fd: u64, cmd: u64, arg: u64) -> SysResult {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETOWN: u64 = 8;
    const F_GETOWN: u64 = 9;
    const F_SETSIG: u64 = 10;
    const F_GETSIG: u64 = 11;
    const F_SETOWN_EX: u64 = 15;
    const F_GETOWN_EX: u64 = 16;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_SETPIPE_SZ: u64 = 1031;
    const F_GETPIPE_SZ: u64 = 1032;
    const F_ADD_SEALS: u64 = 1033;
    const F_GET_SEALS: u64 = 1034;
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let file = p.fds.get(fd)?;
            // Not at or above RLIMIT_NOFILE (f_dupfd).
            if arg >= p.fds.limit() as u64 {
                return Err(EINVAL);
            }
            p.fds.alloc(FdEntry { file, cloexec: cmd == F_DUPFD_CLOEXEC }, arg as usize)
        }
        F_GETFD => Ok(p.fds.cloexec(fd)? as u64),
        F_SETFD => p.fds.set_cloexec(fd, arg & 1 != 0).map(|_| 0),
        F_GETFL => Ok(p.fds.get(fd)?.lock().flags as u64),
        F_SETFL => {
            let file = p.fds.get(fd)?;
            let mut f = file.lock();
            let was = f.flags;
            f.flags = (f.flags & !SETFL_MASK) | (arg as u32 & SETFL_MASK);
            let on = f.flags & !was & O_ASYNC != 0;
            drop(f);
            if on {
                crate::fasync::watch(&file, fd);
            }
            Ok(0)
        }
        F_SETOWN | F_GETOWN | F_SETSIG | F_GETSIG | F_SETOWN_EX | F_GETOWN_EX => owner(p, fd, cmd, arg),
        F_GETLK | F_SETLK | F_SETLKW | 36..=38 => record_lock(p, fd, cmd, arg),
        // A pipe's capacity (Linux's pipe_fcntl): a power of two pages,
        // at most pipe-max-size, and no less than what it holds.
        F_SETPIPE_SZ | F_GETPIPE_SZ => {
            let file = p.fds.get(fd)?;
            let f = file.lock();
            let end = match &f.kind {
                FileKind::Pipe(end) => end,
                FileKind::Fifo(FifoFile { read: Some(end), .. })
                | FileKind::Fifo(FifoFile { write: Some(end), .. }) => end,
                _ => return Err(EBADF),
            };
            let mut pipe = end.pipe.lock();
            if cmd == F_GETPIPE_SZ {
                return Ok(pipe.capacity as u64);
            }
            let want = (arg as u32 as usize).max(4096);
            let size = want.checked_next_power_of_two().ok_or(EINVAL)?;
            // (Nobody has CAP_SYS_RESOURCE, uid 0 included.)
            if size > ipc::PIPE_MAX_SIZE {
                return Err(EPERM);
            }
            if size < pipe.buf.len() {
                return Err(EBUSY);
            }
            pipe.capacity = size;
            pipe.touch();
            Ok(size as u64)
        }
        // memfd seals: only sealable files (memfds) have them.
        F_ADD_SEALS | F_GET_SEALS => {
            let file = p.fds.get(fd)?;
            let f = file.lock();
            let writable = f.flags & O_ACCMODE != O_RDONLY;
            let c = f.content.clone().ok_or(EINVAL)?;
            drop(f);
            let mut data = c.lock();
            let seals = data.seals.ok_or(EINVAL)?;
            if cmd == F_GET_SEALS {
                return Ok(seals as u64);
            }
            const KNOWN: u32 =
                fs::F_SEAL_SEAL | fs::F_SEAL_SHRINK | fs::F_SEAL_GROW | fs::F_SEAL_WRITE | fs::F_SEAL_FUTURE_WRITE;
            if arg as u32 & !KNOWN != 0 {
                return Err(EINVAL);
            }
            if !writable || seals & fs::F_SEAL_SEAL != 0 {
                return Err(EPERM);
            }
            // Not while a shared mapping may still write it (Linux's
            // mapping_deny_writable).
            if arg as u32 & fs::F_SEAL_WRITE != 0 && data.mapped_writable() {
                return Err(EBUSY);
            }
            data.seals = Some(seals | arg as u32);
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// memfd_create: an anonymous file. No `fs_write` needed: it's memory, not
/// part of the filesystem (but it counts against the same limits).
pub fn memfd_create(p: &mut Process, namep: u64, flags: u64) -> SysResult {
    const MFD_CLOEXEC: u64 = 1;
    const MFD_ALLOW_SEALING: u64 = 2;
    const MFD_HUGETLB: u64 = 4;
    const MFD_NOEXEC_SEAL: u64 = 8;
    const MFD_EXEC: u64 = 0x10;
    // Linux's MFD_NAME_MAX_LEN: NAME_MAX minus "memfd:".
    let name = read_cstr(&mut p.aspace, namep, 250).map_err(|e| if e == ENAMETOOLONG { EINVAL } else { e })?;
    if flags & MFD_HUGETLB != 0 {
        return p.unimplemented(nr::memfd_create, "memfd_create", "MFD_HUGETLB", EINVAL);
    }
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL | MFD_EXEC) != 0 {
        return Err(EINVAL);
    }
    let sealable = flags & (MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL) != 0;
    let seals = if sealable { 0 } else { fs::F_SEAL_SEAL };
    let (ino, content) = fs::lock().create_memfd(&name, seals, p.uid, p.gid)?;
    open_node(p, ino, Some(content), O_RDWR, flags & MFD_CLOEXEC != 0, 0)
}

/// signalfd4: read pending signals in `mask` as signalfd_siginfo records
/// (with fd -1, a new signalfd; otherwise change an existing one's mask).
pub fn signalfd4(p: &mut Process, fd: u64, maskp: u64, size: u64, flags: u64) -> SysResult {
    const SFD_CLOEXEC: u64 = 0o2000000;
    const SFD_NONBLOCK: u64 = 0o4000;
    if size != 8 || flags & !(SFD_CLOEXEC | SFD_NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    let mask = read_u64(&mut p.aspace, maskp)? & !crate::signal::UNBLOCKABLE;
    if fd as i32 != -1 {
        let file = p.fds.get(fd)?;
        let mut f = file.lock();
        let FileKind::SignalFd(m) = &mut f.kind else { return Err(EINVAL) };
        *m = mask;
        // Readers waiting on it may now see a pending signal.
        crate::ipc::changed();
        return Ok(fd);
    }
    let file = new_file(FileKind::SignalFd(mask), O_RDONLY | (flags as u32 & O_NONBLOCK));
    p.uses_signalfd = true;
    p.fds.alloc(FdEntry { file, cloexec: flags & SFD_CLOEXEC != 0 }, 0)
}

/// Readiness of an open file. A signalfd depends on the calling thread's
/// pending signals, which the file itself can't see.
pub(super) fn poll_kind(p: &Process, kind: &FileKind) -> (u32, u64) {
    match kind {
        FileKind::SignalFd(mask) => {
            let pending = crate::signal::pending_for(p, p.current) & mask;
            (if pending != 0 { EPOLLIN } else { 0 }, crate::signal::generation())
        }
        // Readable once the process has ended.
        FileKind::PidFd(pid) => (if crate::procs::ended(p, *pid) { EPOLLIN } else { 0 }, crate::procs::exits()),
        k => k.poll(),
    }
}

/// fcntl's O_ASYNC owner and signal (fasync.rs).
fn owner(p: &mut Process, fd: u64, cmd: u64, arg: u64) -> SysResult {
    use crate::fasync::Owner;
    const F_SETOWN: u64 = 8;
    const F_GETOWN: u64 = 9;
    const F_SETSIG: u64 = 10;
    const F_GETSIG: u64 = 11;
    const F_SETOWN_EX: u64 = 15;
    const F_OWNER_TID: u32 = 0;
    const F_OWNER_PID: u32 = 1;
    const F_OWNER_PGRP: u32 = 2;
    let file = p.fds.get(fd)?;
    let fown = file.lock().fown;
    let owner = match cmd {
        F_GETOWN => {
            // A group is negative, as it was set.
            return Ok(match fown.owner {
                Owner::Process(pid) | Owner::Thread(pid) => pid as u64,
                Owner::Group(pgid) => (pgid as i32).wrapping_neg() as i64 as u64,
                Owner::None => 0,
            });
        }
        F_GETSIG => return Ok(fown.sig as u64),
        F_SETSIG => {
            if arg > 64 {
                return Err(EINVAL);
            }
            file.lock().fown.sig = arg as u32;
            return Ok(0);
        }
        F_SETOWN => match arg as i32 {
            0 => Owner::None,
            pid if pid > 0 => Owner::Process(pid as u32),
            g => Owner::Group(g.unsigned_abs()),
        },
        F_SETOWN_EX => {
            let ty = read_u32(&mut p.aspace, arg)?;
            let pid = read_u32(&mut p.aspace, arg + 4)?;
            match (ty, pid) {
                (_, 0) => Owner::None,
                (F_OWNER_TID, t) => Owner::Thread(t),
                (F_OWNER_PID, pid) => Owner::Process(pid),
                (F_OWNER_PGRP, g) => Owner::Group(g),
                _ => return Err(EINVAL),
            }
        }
        // F_GETOWN_EX
        _ => {
            let (ty, pid) = match fown.owner {
                Owner::Thread(t) => (F_OWNER_TID, t),
                Owner::Process(pid) => (F_OWNER_PID, pid),
                Owner::Group(g) => (F_OWNER_PGRP, g),
                Owner::None => (F_OWNER_PID, 0),
            };
            let mut b = [0u8; 8];
            b[..4].copy_from_slice(&ty.to_le_bytes());
            b[4..].copy_from_slice(&pid.to_le_bytes());
            return copy_out(&mut p.aspace, arg, &b).map(|_| 0);
        }
    };
    let mut f = file.lock();
    f.fown.owner = owner;
    (f.fown.sender, f.fown.sender_uid) = (p.pid, p.uid);
    Ok(0)
}

pub fn ioctl(p: &mut Process, fd: u64, req: u64, arg: u64) -> SysResult {
    const FIONREAD: u64 = 0x541b;
    const FIONBIO: u64 = 0x5421;
    const FIONCLEX: u64 = 0x5450;
    const FIOCLEX: u64 = 0x5451;
    const FIOASYNC: u64 = 0x5452;
    const FIOSETOWN: u64 = 0x8901;
    const SIOCSPGRP: u64 = 0x8902;
    const FIOGETOWN: u64 = 0x8903;
    const SIOCGPGRP: u64 = 0x8904;
    const SIOCGIFCONF: u64 = 0x8912;
    const SIOCETHTOOL: u64 = 0x8946;
    // The command is an unsigned int: C callers may pass it sign-extended.
    let req = req as u32 as u64;
    let file = p.fds.get(fd)?;
    // A device opened without Landlock's IOCTL_DEV (hook_file_ioctl).
    if file.lock().landlock_denied & landlock::IOCTL_DEV != 0 && !landlock::ioctl_exempt(req as u32) {
        return Err(EACCES);
    }
    let pty = match &file.lock().kind {
        FileKind::Pty(end) => Some((end.tty.clone(), end.master)),
        _ => None,
    };
    // FIONBIO, FIOASYNC and FIOCLEX are the descriptor's, as for any file.
    if let Some((tty, master)) = pty
        && !matches!(req, FIONBIO | FIONCLEX | FIOCLEX | FIOASYNC)
    {
        return super::tty::ioctl(p, fd, tty, master, req, arg);
    }
    let file = p.fds.get(fd)?;
    let socket = matches!(
        file.lock().kind,
        FileKind::Socket(_) | FileKind::Netlink(_) | FileKind::UnixUnbound(_) | FileKind::Inet(_) | FileKind::Unix(_)
    );
    // A socket's O_ASYNC owner, as F_SETOWN and F_GETOWN.
    if socket && matches!(req, FIOSETOWN | SIOCSPGRP) {
        let pid = read_u32(&mut p.aspace, arg)?;
        return owner(p, fd, 8, pid as i32 as i64 as u64);
    }
    if socket && matches!(req, FIOGETOWN | SIOCGPGRP) {
        let pid = owner(p, fd, 9, 0)?;
        return write_u32(&mut p.aspace, arg, pid as u32).map(|_| 0);
    }
    if socket && req == SIOCGIFCONF {
        // struct ifconf { int ifc_len; char *ifc_buf; }: an entry for each
        // interface, as many as fit.
        let len = read_u32(&mut p.aspace, arg)? as usize;
        let buf = read_u64(&mut p.aspace, arg + 8)?;
        let entries = crate::netlink::ifconf_entries();
        // With no buffer, report the size needed.
        let fit = if buf == 0 { entries.len() } else { entries.len().min(len / 40) };
        if buf != 0 {
            copy_out(&mut p.aspace, buf, entries[..fit].as_flattened())?;
        }
        return write_u32(&mut p.aspace, arg, (fit * 40) as u32).map(|_| 0);
    }
    if socket && req == SIOCETHTOOL {
        // struct ifreq with ifr_data pointing at the command's structure.
        let mut ifr = [0u8; 40];
        copy_in(&mut p.aspace, arg, &mut ifr)?;
        let data = u64::from_le_bytes(ifr[16..24].try_into().unwrap());
        let cmd = read_u32(&mut p.aspace, data)?;
        let name = ifr[..16].split(|&b| b == 0).next().unwrap_or(&[]);
        let aspace = &mut p.aspace;
        let reply = crate::netlink::ethtool(name, cmd, |off, len| {
            let mut b = alloc::vec![0u8; len];
            copy_in(aspace, data + off as u64, &mut b).map(|_| b)
        })?;
        return copy_out(&mut p.aspace, data, &reply).map(|_| 0);
    }
    if socket && (0x8900..=0x89ff).contains(&req) {
        let mut ifr = [0u8; 40];
        copy_in(&mut p.aspace, arg, &mut ifr)?;
        return match crate::netlink::ifreq_ioctl(req, &mut ifr) {
            Some(r) => r.and_then(|_| copy_out(&mut p.aspace, arg, &ifr)).map(|_| 0),
            None => p.unimplemented(nr::ioctl, "ioctl", &alloc::format!("socket ioctl {req:#x}"), EOPNOTSUPP),
        };
    }
    match req {
        FIONREAD => {
            let avail = match &file.lock().kind {
                FileKind::Pipe(end) if !end.write => end.pipe.lock().buf.len() as u32,
                FileKind::Fifo(FifoFile { read: Some(end), .. }) => end.pipe.lock().buf.len() as u32,
                FileKind::Socket(s) => s.rx.as_ref().map_or(0, |r| r.pipe.lock().buf.len() as u32),
                FileKind::Inet(s) => super::net::inet_available(s) as u32,
                FileKind::Stdin => console::stdin_state().0 as u32,
                FileKind::Inotify(n) => n.available() as u32,
                _ => return Err(ENOTTY),
            };
            write_u32(&mut p.aspace, arg, avail).map(|_| 0)
        }
        FIONBIO => {
            let on = read_u32(&mut p.aspace, arg)? != 0;
            let file = p.fds.get(fd)?;
            let mut f = file.lock();
            f.flags = if on { f.flags | O_NONBLOCK } else { f.flags & !O_NONBLOCK };
            Ok(0)
        }
        FIOCLEX | FIONCLEX => p.fds.set_cloexec(fd, req == FIOCLEX).map(|_| 0),
        // O_ASYNC, as F_SETFL sets it.
        FIOASYNC => {
            let on = read_u32(&mut p.aspace, arg)? != 0;
            let flags = p.fds.get(fd)?.lock().flags;
            fcntl(p, fd, 4, (if on { flags | O_ASYNC } else { flags & !O_ASYNC }) as u64)
        }
        // stdio is not a terminal (TCGETS, TIOCGWINSZ, ...).
        _ => Err(ENOTTY),
    }
}

// ---------------------------------------------------------------- polling

const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLERR: u16 = 0x8;
const POLLHUP: u16 = 0x10;
const POLLNVAL: u16 = 0x20;
const POLLRDNORM: u16 = 0x40;
const POLLWRNORM: u16 = 0x100;

pub(super) fn readiness(p: &Process, fd: u64) -> Result<u32, Errno> {
    Ok(poll_kind(p, &p.fds.get(fd)?.lock().kind).0)
}

/// Relative timeout from a timespec pointer (NULL = forever).
fn timespec_timeout(p: &mut Process, ts: u64) -> Result<Option<u64>, Errno> {
    if ts == 0 { Ok(None) } else { read_timespec_ns(&mut p.aspace, ts).map(Some) }
}

pub fn ppoll(p: &mut Process, fds: u64, nfds: u64, timeout: u64) -> SysResult {
    let timeout = timespec_timeout(p, timeout)?;
    poll_ns(p, fds, nfds, timeout)
}

/// ppoll with its timeout in ns (None = forever), poll's too.
pub fn poll_ns(p: &mut Process, fds: u64, nfds: u64, timeout: Option<u64>) -> SysResult {
    // Up to RLIMIT_NOFILE of them, as Linux's do_sys_poll.
    if nfds > p.fds.limit() as u64 {
        return Err(EINVAL);
    }
    let _held = crate::kmem::Charge::new(nfds * 8)?;
    let mut raw = alloc::vec![0u8; nfds as usize * 8];
    copy_in(&mut p.aspace, fds, &mut raw)?;
    // A re-run after the deadline passed reports what's ready (perhaps
    // nothing) like a zero timeout: revents must be written either way.
    let deadline = p.timeout_deadline(timeout);
    let expired = deadline.is_some_and(|d| d <= crate::time::monotonic_ns());
    let mut ready = 0;
    for c in raw.chunks_mut(8) {
        let fd = i32::from_le_bytes(c[..4].try_into().unwrap());
        let events = u16::from_le_bytes(c[4..6].try_into().unwrap());
        let revents = if fd < 0 {
            0
        } else {
            match readiness(p, fd as u64) {
                Err(_) => POLLNVAL,
                Ok(mask) => {
                    let mut r = mask as u16 & (events | POLLERR | POLLHUP);
                    if mask as u16 & POLLIN != 0 && events & POLLRDNORM != 0 {
                        r |= POLLRDNORM;
                    }
                    if mask as u16 & POLLOUT != 0 && events & POLLWRNORM != 0 {
                        r |= POLLWRNORM;
                    }
                    r
                }
            }
        };
        c[6..8].copy_from_slice(&revents.to_le_bytes());
        if revents != 0 {
            ready += 1;
        }
    }
    if ready > 0 || timeout == Some(0) || expired {
        copy_out(&mut p.aspace, fds, &raw)?;
        return Ok(ready);
    }
    // Nothing to watch and no time limit: musl's pause() on arm64. Only a
    // signal can end it, so say so (it isn't a deadlock: the host may send
    // one).
    if timeout.is_none() && raw.chunks(8).all(|c| i32::from_le_bytes(c[..4].try_into().unwrap()) < 0) {
        return p.block(WaitOn::Signal, None, Ok(0));
    }
    p.block_io_rerun(deadline)
}

pub fn pselect6(p: &mut Process, nfds: u64, rfds: u64, wfds: u64, efds: u64, timeout: u64) -> SysResult {
    let timeout = timespec_timeout(p, timeout)?;
    select_ns(p, nfds, rfds, wfds, efds, timeout)
}

/// pselect6 with its timeout in ns (None = forever), select's too.
pub fn select_ns(p: &mut Process, nfds: u64, rfds: u64, wfds: u64, efds: u64, timeout: Option<u64>) -> SysResult {
    if (nfds as i32) < 0 {
        return Err(EINVAL);
    }
    // Linux's core_sys_select looks no further than the table can reach.
    let nfds = nfds.min(crate::fd::MAX_FDS as u64);
    // As ppoll: after the deadline, the sets come back (cleared if nothing
    // is ready), as Linux returns them.
    let deadline = p.timeout_deadline(timeout);
    let expired = deadline.is_some_and(|d| d <= crate::time::monotonic_ns());
    let words = (nfds as usize).div_ceil(64);
    let mut sets = [alloc::vec![0u64; words], alloc::vec![0u64; words], alloc::vec![0u64; words]];
    for (set, ptr) in sets.iter_mut().zip([rfds, wfds, efds]) {
        if ptr != 0 {
            let mut b = alloc::vec![0u8; words * 8];
            copy_in(&mut p.aspace, ptr, &mut b)?;
            for (w, c) in set.iter_mut().zip(b.chunks(8)) {
                *w = u64::from_le_bytes(c.try_into().unwrap());
            }
        }
    }
    let mut out = [alloc::vec![0u64; words], alloc::vec![0u64; words], alloc::vec![0u64; words]];
    let mut count = 0;
    for fd in 0..nfds as usize {
        let (w, bit) = (fd / 64, 1u64 << (fd % 64));
        let wanted = [0, 1, 2].map(|i| sets[i][w] & bit != 0);
        if !wanted.contains(&true) {
            continue;
        }
        let mask = readiness(p, fd as u64)?;
        let hits = [mask & (EPOLLIN | EPOLLHUP | EPOLLERR) != 0, mask & (EPOLLOUT | EPOLLERR) != 0, false];
        for i in 0..3 {
            if wanted[i] && hits[i] {
                out[i][w] |= bit;
                count += 1;
            }
        }
    }
    if count > 0 || timeout == Some(0) || expired {
        for (set, ptr) in out.iter().zip([rfds, wfds, efds]) {
            if ptr != 0 {
                let b: Vec<u8> = set.iter().flat_map(|w| w.to_le_bytes()).collect();
                copy_out(&mut p.aspace, ptr, &b)?;
            }
        }
        return Ok(count);
    }
    if timeout.is_none() && sets.iter().all(|set| set.iter().all(|&w| w == 0)) {
        return p.block(WaitOn::Signal, None, Ok(0));
    }
    p.block_io_rerun(deadline)
}

// ---------------------------------------------------------------- pipes, eventfd, epoll

pub fn pipe2(p: &mut Process, fdsp: u64, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !(O_CLOEXEC | O_NONBLOCK | O_DIRECT) != 0 {
        return Err(EINVAL);
    }
    let (r, w) = ipc::pipe();
    let status = flags & O_NONBLOCK;
    let cloexec = flags & O_CLOEXEC != 0;
    let rfd = p.fds.alloc(FdEntry { file: new_file(FileKind::Pipe(r), O_RDONLY | status), cloexec }, 0)?;
    let wfd = match p.fds.alloc(FdEntry { file: new_file(FileKind::Pipe(w), O_WRONLY | status), cloexec }, 0) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = p.fds.close(rfd);
            return Err(e);
        }
    };
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&(rfd as i32).to_le_bytes());
    b[4..].copy_from_slice(&(wfd as i32).to_le_bytes());
    if let Err(e) = copy_out(&mut p.aspace, fdsp, &b) {
        let _ = p.fds.close(rfd);
        let _ = p.fds.close(wfd);
        return Err(e);
    }
    Ok(0)
}

pub fn eventfd2(p: &mut Process, initval: u64, flags: u64) -> SysResult {
    const EFD_SEMAPHORE: u32 = 1;
    let flags = flags as u32;
    if flags & !(EFD_SEMAPHORE | O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    let ev = EventFd::new(initval as u32 as u64, flags & EFD_SEMAPHORE != 0);
    let file = new_file(FileKind::EventFd(ev), O_RDWR | (flags & O_NONBLOCK));
    p.fds.alloc(FdEntry { file, cloexec: flags & O_CLOEXEC != 0 }, 0)
}

pub fn epoll_create1(p: &mut Process, flags: u64) -> SysResult {
    if flags as u32 & !O_CLOEXEC != 0 {
        return Err(EINVAL);
    }
    let file = new_file(FileKind::Epoll(Arc::new(Mutex::new(Epoll::default()))), O_RDWR);
    p.fds.alloc(FdEntry { file, cloexec: flags as u32 & O_CLOEXEC != 0 }, 0)
}

const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;

fn epoll_of(p: &Process, epfd: u64) -> Result<Arc<Mutex<Epoll>>, Errno> {
    match &p.fds.get(epfd)?.lock().kind {
        FileKind::Epoll(e) => Ok(e.clone()),
        _ => Err(EINVAL),
    }
}

pub fn epoll_ctl(p: &mut Process, epfd: u64, op: u64, fd: u64, eventp: u64) -> SysResult {
    const ADD: u64 = 1;
    const DEL: u64 = 2;
    const MOD: u64 = 3;
    let ep = epoll_of(p, epfd)?;
    let target = p.fds.get(fd)?;
    if fd as i32 == epfd as i32 {
        return Err(EINVAL);
    }
    match &target.lock().kind {
        // Like Linux: regular files and directories can't be polled.
        FileKind::Node(_) => return Err(EPERM),
        FileKind::Epoll(_) => return p.unimplemented(nr::epoll_ctl, "epoll_ctl", "nested epoll", EINVAL),
        _ => {}
    }
    let (events, data) = if op == DEL {
        (0, 0)
    } else {
        let mut b = [0u8; EPOLL_EVENT];
        copy_in(&mut p.aspace, eventp, &mut b)?;
        crate::arch::abi::epoll_event_get(&b)
    };
    let mut e = ep.lock();
    let key = fd as i32 as u64;
    let live = e.interest.get(&key).is_some_and(|r| r.file.ptr_eq(&Arc::downgrade(&target)));
    match op {
        ADD if live => return Err(EEXIST),
        ADD => {
            e.add(key, Registration { file: Arc::downgrade(&target), events, data, reported_version: None })?;
        }
        DEL if live => e.remove(key),
        MOD if live => {
            let r = e.interest.get_mut(&key).unwrap();
            r.events = events;
            r.data = data;
            r.reported_version = None;
        }
        DEL | MOD => return Err(ENOENT),
        _ => return Err(EINVAL),
    }
    ipc::changed();
    Ok(0)
}

/// The architecture's struct epoll_event.
const EPOLL_EVENT: usize = crate::arch::abi::EPOLL_EVENT;

/// epoll_pwait / epoll_pwait2. `timeout`: None = forever.
pub fn epoll_wait(p: &mut Process, epfd: u64, evp: u64, max: u64, timeout: Option<u64>) -> SysResult {
    let max = max as i32;
    if max <= 0 || max > 1 << 20 {
        return Err(EINVAL);
    }
    let ep = epoll_of(p, epfd)?;
    let mut out: Vec<u8> = Vec::new();
    {
        let mut e = ep.lock();
        let mut dead = Vec::new();
        for (fd, reg) in e.interest.iter_mut() {
            if out.len() / EPOLL_EVENT >= max as usize {
                break;
            }
            let Some(file) = reg.file.upgrade() else {
                dead.push(*fd);
                continue;
            };
            let (mask, version) = poll_kind(p, &file.lock().kind);
            let ready = mask & (reg.events | EPOLLERR | EPOLLHUP);
            if ready == 0 || reg.events & !(EPOLLET | EPOLLONESHOT) == 0 {
                continue;
            }
            if reg.events & EPOLLET != 0 {
                if reg.reported_version == Some(version) {
                    continue;
                }
                reg.reported_version = Some(version);
            }
            if reg.events & EPOLLONESHOT != 0 {
                reg.events &= EPOLLET | EPOLLONESHOT; // disabled until EPOLL_CTL_MOD
            }
            out.extend_from_slice(&crate::arch::abi::epoll_event(ready, reg.data));
        }
        for fd in dead {
            e.remove(fd);
        }
    }
    if !out.is_empty() || timeout == Some(0) {
        copy_out(&mut p.aspace, evp, &out)?;
        return Ok((out.len() / EPOLL_EVENT) as u64);
    }
    let deadline = p.timeout_deadline(timeout);
    p.block_io(deadline, Ok(0))
}

/// epoll_pwait's millisecond timeout: negative means forever.
pub fn ms_timeout(ms: u64) -> Option<u64> {
    let ms = ms as i32;
    (ms >= 0).then(|| ms as u64 * 1_000_000)
}

pub fn epoll_pwait2(p: &mut Process, epfd: u64, evp: u64, max: u64, ts: u64) -> SysResult {
    let timeout = timespec_timeout(p, ts)?;
    epoll_wait(p, epfd, evp, max, timeout)
}

// ---------------------------------------------------------------- statfs, xattrs, inotify

/// struct statfs (arm64): everything lives on one in-memory filesystem,
/// read-only without `fs_write`. Its size is the limit on written data.
fn statfs_bytes(p: &Process) -> [u8; 120] {
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    const ST_RDONLY: u64 = 1;
    let (used, limit) = fs::usage();
    let free = limit.saturating_sub(used);
    let writable = p.policy.allows(Capability::FsWrite);
    let fields = [
        TMPFS_MAGIC,                          // f_type
        4096,                                 // f_bsize
        limit,                                // f_blocks
        free,                                 // f_bfree
        if writable { free } else { 0 },      // f_bavail
        fs::lock().node_count() as u64,       // f_files
        if writable { free } else { 0 },      // f_ffree
        0,                                    // f_fsid
        fs::NAME_MAX as u64,                  // f_namelen
        4096,                                 // f_frsize
        if writable { 0 } else { ST_RDONLY }, // f_flags
    ];
    let mut b = [0u8; 120];
    for (i, v) in fields.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    b
}

pub fn statfs(p: &mut Process, pathp: u64, buf: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    resolve(p, AT_FDCWD as u64, &path, true)?;
    let b = statfs_bytes(p);
    copy_out(&mut p.aspace, buf, &b).map(|_| 0)
}

/// name_to_handle_at: no filesystem here has file handles, so once the
/// path resolves it's EOPNOTSUPP, as Linux answers for a filesystem
/// without export operations (tmpfs before 6.6, procfs, FUSE without
/// them). Callers (systemd, `stat --cached`, overlay tools) fall back to
/// the path. open_by_handle_at stays privileged (CAP_DAC_READ_SEARCH).
pub fn name_to_handle_at(p: &mut Process, dirfd: u64, pathp: u64, flags: u64) -> SysResult {
    const AT_HANDLE_FID: u64 = 0x200;
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH | AT_HANDLE_FID) != 0 {
        return Err(EINVAL);
    }
    let nofollow = if flags & AT_SYMLINK_FOLLOW != 0 { 0 } else { AT_SYMLINK_NOFOLLOW };
    path_stat(p, dirfd, pathp, nofollow | flags & AT_EMPTY_PATH)?;
    Err(EOPNOTSUPP)
}

pub fn fstatfs(p: &mut Process, fd: u64, buf: u64) -> SysResult {
    p.fds.get(fd)?;
    let b = statfs_bytes(p);
    copy_out(&mut p.aspace, buf, &b).map(|_| 0)
}

/// The xattr namespaces Linux knows (fs/xattr.c's handlers).
#[derive(Clone, Copy, PartialEq, Eq)]
enum XattrNs {
    User,
    Trusted,
    Security,
    System,
}

/// An attribute's name: at most XATTR_NAME_MAX bytes, none is ERANGE.
fn xattr_name(p: &mut Process, namep: u64) -> Result<(Vec<u8>, XattrNs), Errno> {
    let name = read_cbytes(&mut p.aspace, namep, fs::XATTR_NAME_MAX + 1).map_err(|e| match e {
        ENAMETOOLONG => ERANGE,
        e => e,
    })?;
    if name.is_empty() {
        return Err(ERANGE);
    }
    // xattr_resolve_name: a namespace's prefix and something after it.
    let spaces: [(&[u8], XattrNs); 4] = [
        (b"user.", XattrNs::User),
        (b"trusted.", XattrNs::Trusted),
        (b"security.", XattrNs::Security),
        (b"system.", XattrNs::System),
    ];
    for (prefix, ns) in spaces {
        if let Some(rest) = name.strip_prefix(prefix) {
            return if rest.is_empty() { Err(EINVAL) } else { Ok((name, ns)) };
        }
    }
    Err(EOPNOTSUPP)
}

/// The node an xattr call is about: a path, followed unless it's an l*
/// call, or a descriptor's file (EBADF for O_PATH, as fdget; EOPNOTSUPP
/// for pipes, sockets and the like, which keep none).
fn xattr_node(p: &mut Process, n: u32, target: u64) -> Result<Ino, Errno> {
    match n {
        nr::fgetxattr | nr::flistxattr | nr::fsetxattr | nr::fremovexattr => {
            let file = p.fds.get(target)?;
            let f = file.lock();
            if f.path_only {
                return Err(EBADF);
            }
            match &f.kind {
                FileKind::Node(ino) | FileKind::Dev(_, ino) | FileKind::Fifo(FifoFile { ino, .. }) => Ok(*ino),
                FileKind::Pty(end) => Ok(end.ino),
                _ => Err(EOPNOTSUPP),
            }
        }
        _ => {
            let nofollow = matches!(n, nr::lgetxattr | nr::llistxattr | nr::lsetxattr | nr::lremovexattr);
            at_node(p, AT_FDCWD as u64, target, if nofollow { AT_SYMLINK_NOFOLLOW } else { 0 })
        }
    }
}

/// May the caller read (or write) attribute `ns` of `ino`? fs/xattr.c's
/// xattr_permission, with what the capability LSM adds for security.*
/// (CAP_SYS_ADMIN; CAP_SETFCAP for security.capability): uid 0 is every
/// capability here, and nothing else is. Neither is anything honoured:
/// they're names and values, as setuid bits are.
fn xattr_permission(p: &Process, fs: &fs::Fs, ino: Ino, ns: XattrNs, write: bool) -> Result<(), Errno> {
    let n = fs.node(ino);
    let refuse = if write { EPERM } else { ENODATA };
    match ns {
        // POSIX ACLs aren't kept.
        XattrNs::System => Err(EOPNOTSUPP),
        XattrNs::Security if write && p.uid != 0 => Err(EPERM),
        XattrNs::Security => Ok(()),
        XattrNs::Trusted if p.uid != 0 => Err(refuse),
        XattrNs::Trusted => Ok(()),
        XattrNs::User => {
            // Only regular files and directories have them.
            let dir = matches!(n.kind, Kind::Dir(_));
            if !dir && !matches!(n.kind, Kind::File(_) | Kind::Unlinked { .. }) {
                return Err(refuse);
            }
            // A sticky directory's, only its owner's (and root's).
            if write && dir && n.perm & fs::S_ISVTX != 0 && p.uid != 0 && p.uid != n.uid {
                return Err(EPERM);
            }
            if !fs.permits(ino, p.uid, p.gid, if write { MAY_WRITE } else { MAY_READ }) {
                return Err(EACCES);
            }
            Ok(())
        }
    }
}

/// setxattr, lsetxattr, fsetxattr.
pub fn setxattr(p: &mut Process, n: u32, target: u64, namep: u64, valuep: u64, size: u64, flags: u64) -> SysResult {
    // setxattr_copy: flags, the name and the value come first.
    if flags & !((fs::XATTR_CREATE | fs::XATTR_REPLACE) as u64) != 0 {
        return Err(EINVAL);
    }
    let (name, ns) = xattr_name(p, namep)?;
    if size > fs::XATTR_SIZE_MAX as u64 {
        return Err(E2BIG);
    }
    let _held = crate::kmem::Charge::new(size)?;
    let mut value = alloc::vec![0u8; size as usize];
    copy_in(&mut p.aspace, valuep, &mut value)?;
    let ino = xattr_node(p, n, target)?;
    let mut fs = fs::lock();
    if fs.xattr_home(ino) == fs::XattrHome::None {
        return Err(EOPNOTSUPP);
    }
    xattr_permission(p, &fs, ino, ns, true)?;
    // cap_convert_nscap: a v2 or v3 vfs_cap_data, nothing else.
    if name == b"security.capability" {
        let rev = value.get(..4).map(|m| u32::from_le_bytes(m.try_into().unwrap()) & 0xff00_0000);
        if !matches!((value.len(), rev), (20, Some(0x0200_0000)) | (24, Some(0x0300_0000))) {
            return Err(EINVAL);
        }
    }
    fs.set_xattr(ino, &name, value, flags as u32).map(|_| 0)
}

/// getxattr, lgetxattr, fgetxattr: the value's length, and the value if
/// `size` has room for it (ERANGE if not; 0 asks only its length).
pub fn getxattr(p: &mut Process, n: u32, target: u64, namep: u64, valuep: u64, size: u64) -> SysResult {
    let ino = xattr_node(p, n, target)?;
    let (name, ns) = xattr_name(p, namep)?;
    let value = {
        let fs = fs::lock();
        match fs.xattr_home(ino) {
            fs::XattrHome::None => return Err(EOPNOTSUPP),
            fs::XattrHome::Lazy => return Err(ENODATA),
            fs::XattrHome::Here => {}
        }
        xattr_permission(p, &fs, ino, ns, false)?;
        fs.xattr(ino, &name)?.to_vec()
    };
    if size != 0 {
        if value.len() as u64 > size {
            return Err(ERANGE);
        }
        copy_out(&mut p.aspace, valuep, &value)?;
    }
    Ok(value.len() as u64)
}

/// listxattr, llistxattr, flistxattr: the names, each NUL-terminated, as
/// for getxattr's value. trusted.* only for root, as Linux's
/// simple_xattr_list; nodes that keep none list none.
pub fn listxattr(p: &mut Process, n: u32, target: u64, listp: u64, size: u64) -> SysResult {
    let ino = xattr_node(p, n, target)?;
    // Names are charged to the metadata budget, one node may have them
    // all, and the list is no use past what can be returned: only that is
    // made (for a size of 0, just its length).
    let room = size.min(fs::XATTR_LIST_MAX as u64);
    let (mut list, mut total) = (Vec::new(), 0);
    {
        let fs = fs::lock();
        if fs.xattr_home(ino) == fs::XattrHome::Here {
            for name in fs.xattr_names(ino) {
                if p.uid == 0 || !name.starts_with(b"trusted.") {
                    total += name.len() as u64 + 1;
                    if total <= room {
                        list.extend_from_slice(name);
                        list.push(0);
                    }
                }
            }
        }
    }
    if size != 0 {
        if total > room {
            // More than any list may be: E2BIG, not "try a bigger buffer".
            return Err(if size >= fs::XATTR_LIST_MAX as u64 { E2BIG } else { ERANGE });
        }
        copy_out(&mut p.aspace, listp, &list)?;
    }
    Ok(total)
}

/// removexattr, lremovexattr, fremovexattr.
pub fn removexattr(p: &mut Process, n: u32, target: u64, namep: u64) -> SysResult {
    let (name, ns) = xattr_name(p, namep)?;
    let ino = xattr_node(p, n, target)?;
    let mut fs = fs::lock();
    match fs.xattr_home(ino) {
        fs::XattrHome::None => return Err(EOPNOTSUPP),
        // Removing what isn't there changes nothing: no copy-up.
        fs::XattrHome::Lazy => {
            xattr_permission(p, &fs, ino, ns, true)?;
            return Err(ENODATA);
        }
        fs::XattrHome::Here => {}
    }
    xattr_permission(p, &fs, ino, ns, true)?;
    fs.remove_xattr(ino, &name).map(|_| 0)
}

pub fn inotify_init1(p: &mut Process, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    let file = new_file(FileKind::Inotify(crate::inotify::Inotify::new()), O_RDONLY | (flags & O_NONBLOCK));
    p.fds.alloc(FdEntry { file, cloexec: flags & O_CLOEXEC != 0 }, 0)
}

pub fn inotify_add_watch(p: &mut Process, fd: u64, pathp: u64, mask: u64) -> SysResult {
    let mask = mask as u32;
    let file = p.fds.get(fd)?;
    if !matches!(file.lock().kind, FileKind::Inotify(_)) {
        return Err(EINVAL);
    }
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let ino = resolve(p, AT_FDCWD as u64, &path, mask & crate::inotify::IN_DONT_FOLLOW == 0)?;
    let (is_dir, remote, pin) = {
        let fs = fs::lock();
        (fs.is_dir(ino), fs.watchable_remote(ino), fs.pin(ino))
    };
    let f = file.lock();
    let FileKind::Inotify(n) = &f.kind else { return Err(EINVAL) };
    n.add_watch(ino, is_dir, remote, pin, mask).map(|wd| wd as u64)
}

pub fn inotify_rm_watch(p: &mut Process, fd: u64, wd: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let f = file.lock();
    let FileKind::Inotify(n) = &f.kind else { return Err(EINVAL) };
    n.rm_watch(wd as i32).map(|_| 0)
}

/// /proc/<pid>/mem: `count` bytes at virtual address `addr` to or from the
/// program's buffer, a page at a time, as far as the mappings allow (EIO if
/// nothing was), as Linux's mem_rw. Only for the process itself: the
/// descriptor of another (inherited across fork) can't reach its memory
/// (invariant 13). Read-only mappings can't be written (Linux's
/// FOLL_FORCE is a debugger's). `of` is the process it was opened in and
/// that process's memory then: once execve has replaced that, there's
/// nothing to read or write (Linux's mem_rw, with mm_users at 0).
fn proc_mem(p: &mut Process, of: (u32, u64), addr: u64, buf: u64, count: u64, write: bool) -> SysResult {
    if of.0 != p.pid {
        return Err(EIO);
    }
    if of.1 != p.aspace.id {
        return Ok(0);
    }
    let mut chunk = [0u8; CHUNK];
    let mut done = 0u64;
    while done < count {
        let Some(at) = addr.checked_add(done) else { break };
        let n = (count - done).min(CHUNK as u64 - at % CHUNK as u64) as usize;
        if write {
            copy_in(&mut p.aspace, buf + done, &mut chunk[..n])?;
            if copy_out(&mut p.aspace, at, &chunk[..n]).is_err() {
                break;
            }
        } else {
            if copy_in(&mut p.aspace, at, &mut chunk[..n]).is_err() {
                break;
            }
            copy_out(&mut p.aspace, buf + done, &chunk[..n])?;
        }
        done += n as u64;
    }
    if done == 0 && count > 0 { Err(EIO) } else { Ok(done) }
}

/// A write to /proc/<pid>/comm or /proc/<pid>/task/<tid>/comm: the
/// thread's new name (at most 15 bytes, as written), for the process's
/// own threads only (Linux's comm_write: EINVAL otherwise).
fn comm_write(p: &mut Process, pid: u32, tid: u32, buf: u64, count: u64) -> SysResult {
    if pid != p.pid {
        return Err(EINVAL);
    }
    if !p.threads.contains_key(&tid) && tid != pid {
        return Err(ESRCH);
    }
    let mut name = [0u8; 16];
    let n = (count as usize).min(15);
    copy_in(&mut p.aspace, buf, &mut name[..n])?;
    p.set_thread_name(tid, name);
    Ok(count)
}
