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
    Epoll, FdEntry, FileKind, O_ACCMODE, O_APPEND, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, OpenFile, Registration,
    new_file,
};
use crate::fs::{self, Content, Dev, FileData, Ino, Kind, MAY_READ, MAY_WRITE, ROOT, S_IFIFO, StatInfo};
use crate::procfs;

const S_IFSOCK: u32 = 0o140000;
use crate::ipc::{self, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT, EVENTFD_MAX, EventFd, PIPE_BUF, PipeEnd};
use crate::process::Process;
use crate::rng;
use crate::time;
use crate::uaccess::*;
use alloc::sync::Arc;
use spin::Mutex;

const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;

const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_DIRECTORY: u32 = 0o40000;
const O_NOFOLLOW: u32 = 0o100000;
const O_CLOEXEC: u32 = 0o2000000;
const O_PATH: u32 = 0o10000000;
const O_TMPFILE: u32 = 0o20000000;
/// Status flags that F_SETFL may change.
const SETFL_MASK: u32 = 0o2000 | 0o4000; // O_APPEND | O_NONBLOCK

/// Linux caps a single read/write at this many bytes.
const MAX_RW: u64 = 0x7fff_f000;
const CHUNK: usize = 4096;

// ---------------------------------------------------------------- paths

fn dir_base(p: &Process, dirfd: u64) -> Result<Ino, Errno> {
    if dirfd as i32 == AT_FDCWD {
        return Ok(p.cwd);
    }
    let f = p.fds.get(dirfd)?;
    let f = f.lock();
    match f.kind {
        FileKind::Node(ino) if fs::lock().is_dir(ino) => Ok(ino),
        _ => Err(ENOTDIR),
    }
}

/// The directory a path is relative to.
fn base_of(p: &Process, dirfd: u64, path: &str) -> Result<Ino, Errno> {
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

/// A file's node for *at(fd, "", AT_EMPTY_PATH) and f* calls.
fn fd_node(p: &Process, fd: u64) -> Result<Ino, Errno> {
    if fd as i32 == AT_FDCWD {
        return Ok(p.cwd);
    }
    match p.fds.get(fd)?.lock().kind {
        FileKind::Node(ino) | FileKind::Dev(_, ino) => Ok(ino),
        _ => Err(EINVAL),
    }
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
    resolve(p, dirfd, &path, flags & AT_SYMLINK_NOFOLLOW == 0)
}

/// The node an fd refers to, for *at(fd, "", AT_EMPTY_PATH) and fstat.
fn fd_stat(p: &Process, fd: u64) -> Result<StatInfo, Errno> {
    if fd as i32 == AT_FDCWD {
        return Ok(fs::lock().stat(p.cwd));
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
        FileKind::Node(ino) | FileKind::Dev(_, ino) => fs::lock().stat(*ino),
        FileKind::Pipe(end) => anon(Arc::as_ptr(&end.pipe) as u64, S_IFIFO | 0o600, 0),
        FileKind::Socket(_) | FileKind::Netlink(_) | FileKind::UnixUnbound(_) => {
            anon(0x3000_0000 + fd, S_IFSOCK | 0o777, 0)
        }
        FileKind::Generated(data) => anon(0x4000_0000 + fd, fs::S_IFREG | 0o444, data.len() as u64),
        // anon_inode files have no type bits on Linux.
        FileKind::EventFd(_)
        | FileKind::Epoll(_)
        | FileKind::Inotify(_)
        | FileKind::TimerFd(_)
        | FileKind::SignalFd(_) => anon(0x2000_0000 + fd, 0o600, 0),
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
    let ino = resolve(p, dirfd, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
    Ok(fs::lock().stat(ino))
}

// ---------------------------------------------------------------- open/close

/// Changing the filesystem needs `fs_write`. Denials name the path.
fn need_write(p: &mut Process, n: u32, path: &str) -> Result<(), Errno> {
    require(p, n, Capability::FsWrite, path)
}

pub fn openat(p: &mut Process, dirfd: u64, pathp: u64, flags: u64, mode: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let flags = flags as u32;
    let acc = flags & O_ACCMODE;
    let cloexec = flags & O_CLOEXEC != 0;
    // /proc/self/fd/N, /dev/stdin, ...: another reference to an open file.
    if let Some(fd) = procfs::fd_path(&path) {
        let file = p.fds.get(fd).map_err(|_| ENOENT)?;
        return p.fds.alloc(FdEntry { file, cloexec }, 0);
    }
    let base = base_of(p, dirfd, &path)?;
    if !p.fds.has_room() {
        return Err(EMFILE); // before creating or truncating anything
    }
    let perm = mode as u32 & 0o7777 & !p.umask;
    if flags & O_TMPFILE == O_TMPFILE {
        if acc == O_RDONLY {
            return Err(EINVAL);
        }
        need_write(p, nr::openat, &path)?;
        let (ino, content) = {
            let mut fs = fs::lock();
            let dir = fs.lookup(base, &path, true)?;
            if !fs.is_dir(dir) {
                return Err(ENOTDIR);
            }
            fs.create_unnamed(dir, perm, p.uid, p.gid)?
        };
        return open_node(p, ino, Some(content), flags, cloexec);
    }
    let creat = flags & O_CREAT != 0;
    let excl = creat && flags & O_EXCL != 0;
    let found = fs::lock().lookup(base, &path, flags & O_NOFOLLOW == 0 && !excl);
    let (ino, created) = match found {
        Ok(_) if excl => return Err(EEXIST),
        Ok(ino) => (ino, false),
        Err(ENOENT) if creat => {
            if flags & O_DIRECTORY != 0 {
                return Err(EINVAL);
            }
            need_write(p, nr::openat, &path)?;
            (create_file(p, base, &path, perm, 0)?, true)
        }
        Err(e) => {
            if e == ENOENT {
                p.missing_path(base, &path);
            }
            return Err(e);
        }
    };
    if flags & O_PATH != 0 {
        let file = new_file(FileKind::Node(ino), O_RDONLY);
        let mut f = file.lock();
        (f.path_only, f.pin) = (true, Some(fs::lock().pin(ino)));
        drop(f);
        return p.fds.alloc(FdEntry { file, cloexec }, 0);
    }
    let writes = acc != O_RDONLY || flags & O_TRUNC != 0;
    let (content, proc) = {
        let fs = fs::lock();
        match &fs.node(ino).kind {
            Kind::Dev(d) => {
                let file = new_file(FileKind::Dev(*d, ino), flags & !(O_CLOEXEC | O_CREAT | O_EXCL | O_TRUNC));
                file.lock().pin = Some(fs.pin(ino));
                drop(fs);
                return p.fds.alloc(FdEntry { file, cloexec }, 0);
            }
            Kind::Symlink(_) => return Err(ELOOP), // O_NOFOLLOW on a symlink
            Kind::Dir(_) if writes => return Err(EISDIR),
            Kind::Dir(_) => (None, None),
            Kind::File(_) | Kind::Unlinked { .. } if flags & O_DIRECTORY != 0 => return Err(ENOTDIR),
            Kind::File(c) => (Some(c.clone()), None),
            Kind::Unlinked { .. } => return Err(ENOENT),
            Kind::Proc(_) if writes => return Err(EACCES),
            Kind::Proc(f) => (None, Some(*f)),
        }
    };
    if let Some(f) = proc {
        let data = procfs::generate(p, f);
        let held = crate::kmem::Charge::new(data.capacity() as u64)?;
        let file = new_file(FileKind::Generated(data), flags & !(O_CLOEXEC | O_CREAT | O_EXCL));
        file.lock().held = Some(held);
        return p.fds.alloc(FdEntry { file, cloexec }, 0);
    }
    if let Some(c) = &content
        && !created
    {
        if writes {
            need_write(p, nr::openat, &path)?;
        }
        let want = if acc != O_WRONLY { MAY_READ } else { 0 } | if writes { MAY_WRITE } else { 0 };
        if !fs::lock().permits(ino, p.uid, p.gid, want) {
            return Err(EACCES);
        }
        if flags & O_TRUNC != 0 && c.lock().len() != 0 {
            note_shared(p, nr::openat, c);
            c.lock().truncate(0);
            fs::lock().modified(ino);
        }
    }
    open_node(p, ino, content, flags, cloexec)
}

fn open_node(p: &mut Process, ino: Ino, content: Option<Content>, flags: u32, cloexec: bool) -> SysResult {
    let file = new_file(FileKind::Node(ino), flags & !(O_CLOEXEC | O_CREAT | O_EXCL | O_TRUNC | O_TMPFILE));
    let pin = fs::lock().pin(ino);
    let mut f = file.lock();
    (f.content, f.pin) = (content, Some(pin));
    drop(f);
    p.fds.alloc(FdEntry { file, cloexec }, 0)
}

/// Create the regular file `path` (which doesn't exist). A dangling symlink
/// in its place is followed, as Linux does for O_CREAT without O_EXCL.
fn create_file(p: &mut Process, base: Ino, path: &str, perm: u32, depth: u32) -> Result<Ino, Errno> {
    let (dir, name) = parent_in(p, base, path)?;
    let mut fs = fs::lock();
    if let Ok(link) = fs.lookup(dir, &name, false)
        && let Kind::Symlink(target) = &fs.node(link).kind
    {
        let target = target.clone();
        drop(fs);
        return if depth >= 8 { Err(ELOOP) } else { create_file(p, dir, &target, perm, depth + 1) };
    }
    if name.is_empty() || name == "." || name == ".." {
        return Err(EISDIR);
    }
    fs.create(dir, &name, Kind::File(FileData::new(&[])), perm, p.uid, p.gid)
}

pub fn close(p: &mut Process, fd: u64) -> SysResult {
    p.fds.close(fd).map(|_| 0)
}

pub fn close_range(p: &mut Process, first: u64, last: u64, flags: u64) -> SysResult {
    const CLOSE_RANGE_CLOEXEC: u64 = 4;
    if first > last {
        return Err(EINVAL);
    }
    let last = last.min(p.fds.len() as u64);
    for fd in first..=last {
        if flags & CLOSE_RANGE_CLOEXEC != 0 {
            if let Ok(e) = p.fds.entry_mut(fd) {
                e.cloexec = true;
            }
        } else {
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
        FileKind::Stdin => Ok(0),
        FileKind::Stdout | FileKind::Stderr | FileKind::Epoll(_) => Err(EBADF),
        FileKind::Inotify(_) => would_block(p, nonblock),
        FileKind::UnixUnbound(_) => Err(ENOTCONN),
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
            copy_out(&mut p.aspace, buf, &ticks.to_le_bytes()).map(|_| 8)
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
        FileKind::Socket(s) => match &s.rx {
            Some(rx) => pipe_read(p, rx, buf, count, nonblock, false),
            None => Ok(0), // shut down for reading
        },
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
    let mut chunk = [0u8; CHUNK];
    let mut done = 0u64;
    while done < count {
        let want = (count - done).min(CHUNK as u64) as usize;
        let n = c.lock().read(off.saturating_add(done), &mut chunk[..want]);
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
fn write_content(p: &mut Process, c: &Content, ino: Ino, off: u64, buf: u64, count: u64) -> SysResult {
    if off.checked_add(count).is_none_or(|end| end > MAX_FILE_SIZE) {
        return Err(EFBIG);
    }
    c.lock().may_write(off + count)?;
    note_shared(p, nr::write, c);
    let mut chunk = [0u8; CHUNK];
    let mut done = 0u64;
    let mut err = None;
    while done < count {
        let n = (count - done).min(CHUNK as u64) as usize;
        if let Err(e) = copy_in(&mut p.aspace, buf + done, &mut chunk[..n]) {
            err = Some(e);
            break;
        }
        match c.lock().write(off + done, &chunk[..n]) {
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
        _ => Ok(done),
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
            let off = if f.flags & O_APPEND != 0 { c.lock().len() } else { at.unwrap_or(f.offset) };
            let n = write_content(p, &c, ino, off, buf, count)?;
            if at.is_none() {
                f.offset = off + n;
            }
            return Ok(n);
        }
        FileKind::Stdin | FileKind::Epoll(_) | FileKind::Generated(_) | FileKind::Inotify(_) => {
            return Err(EBADF);
        }
        FileKind::TimerFd(_) => return Err(EINVAL),
        FileKind::UnixUnbound(_) => return Err(ENOTCONN),
        FileKind::SignalFd(_) => return Err(EINVAL),
        FileKind::Netlink(_) => {
            let FileKind::Netlink(nl) = &mut f.kind else { unreachable!() };
            return super::net::netlink_request(p, nl, &[(buf, count)]);
        }
        FileKind::Pipe(end) if !end.write => return Err(EBADF),
        FileKind::Pipe(end) => return pipe_write(p, end, buf, count, nonblock, true),
        FileKind::Socket(s) => {
            return match &s.tx {
                Some(tx) => pipe_write(p, tx, buf, count, nonblock, true),
                None => {
                    crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a socket that was shut down");
                    Err(EPIPE)
                }
            };
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
    let mut chunk = [0u8; CHUNK];
    let mut done = 0u64;
    while done < count {
        let n = (count - done).min(CHUNK as u64) as usize;
        if let Err(e) = copy_in(&mut p.aspace, buf + done, &mut chunk[..n]) {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
        console::write(ch, &chunk[..n]);
        done += n as u64;
    }
    Ok(count)
}

/// Read from a pipe (or one direction of a socket). `peek` leaves the data in place.
pub(super) fn pipe_read(p: &mut Process, end: &PipeEnd, buf: u64, count: u64, nonblock: bool, peek: bool) -> SysResult {
    let mut pipe = end.pipe.lock();
    if pipe.buf.is_empty() {
        if pipe.writers == 0 {
            return Ok(0);
        }
        drop(pipe);
        return would_block(p, nonblock);
    }
    let n = (count as usize).min(pipe.buf.len());
    let (a, b) = pipe.buf.as_slices();
    let first = n.min(a.len());
    copy_out(&mut p.aspace, buf, &a[..first])?;
    copy_out(&mut p.aspace, buf + first as u64, &b[..n - first])?;
    if !peek {
        pipe.buf.drain(..n);
        pipe.drained();
        pipe.touch();
    }
    Ok(n as u64)
}

/// Write to a pipe (or one direction of a socket).
pub(super) fn pipe_write(
    p: &mut Process,
    end: &PipeEnd,
    buf: u64,
    count: u64,
    nonblock: bool,
    sigpipe: bool,
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
    if pipe.reserve(need) < need {
        drop(pipe);
        return would_block(p, nonblock);
    }
    let n = pipe.reserve(count as usize);
    let mut tmp = alloc::vec![0u8; n];
    copy_in(&mut p.aspace, buf, &mut tmp)?;
    pipe.buf.extend(tmp);
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
        FileKind::Node(_) | FileKind::Generated(_) => read_into(p, &mut f, buf, count, Some(off)),
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
        FileKind::Node(_) => write_from(p, &mut f, buf, count, Some(off)),
        FileKind::Dev(..) => write_from(p, &mut f, buf, count, None),
        _ => Err(ESPIPE),
    }
}

fn iovecs(p: &mut Process, iov: u64, cnt: u64) -> Result<Vec<(u64, u64)>, Errno> {
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
fn vectored(p: &mut Process, fd: u64, iov: u64, cnt: u64, at: Option<u64>, write: bool) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    if at.is_some() {
        match f.kind {
            FileKind::Node(_) | FileKind::Generated(_) | FileKind::Dev(..) => {}
            _ => return Err(ESPIPE),
        }
        if at.is_some_and(|o| (o as i64) < 0) {
            return Err(EINVAL);
        }
    }
    let mut total = 0;
    for (base, len) in iovecs(p, iov, cnt)? {
        let pos = at.map(|o| o + total);
        let r = if write { write_from(p, &mut f, base, len, pos) } else { read_into(p, &mut f, base, len, pos) };
        match r {
            Ok(n) => {
                total += n;
                if n < len {
                    break;
                }
            }
            Err(e) if total == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(total)
}

pub fn readv(p: &mut Process, fd: u64, iov: u64, cnt: u64) -> SysResult {
    vectored(p, fd, iov, cnt, None, false)
}

pub fn writev(p: &mut Process, fd: u64, iov: u64, cnt: u64) -> SysResult {
    vectored(p, fd, iov, cnt, None, true)
}

/// preadv/pwritev. On 64-bit the offset is the first of the two position arguments.
pub fn preadv(p: &mut Process, fd: u64, iov: u64, cnt: u64, off: u64, write: bool) -> SysResult {
    vectored(p, fd, iov, cnt, Some(off), write)
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

fn stat_bytes(st: &StatInfo) -> [u8; 128] {
    let mut b = [0u8; 128];
    let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(0, &1u64.to_le_bytes()); // st_dev
    put(8, &st.ino.to_le_bytes());
    put(16, &st.mode.to_le_bytes());
    put(20, &st.nlink.to_le_bytes());
    put(24, &st.uid.to_le_bytes());
    put(28, &st.gid.to_le_bytes());
    put(32, &st.rdev.to_le_bytes());
    put(48, &st.size.to_le_bytes());
    put(56, &4096u32.to_le_bytes()); // st_blksize
    put(64, &st.blocks.to_le_bytes());
    for (off, t) in [(72, st.atime), (88, st.mtime), (104, st.ctime)] {
        let (sec, nsec) = split_ns(t);
        put(off, &sec.to_le_bytes());
        put(off + 8, &nsec.to_le_bytes());
    }
    b
}

pub fn fstat(p: &mut Process, fd: u64, buf: u64) -> SysResult {
    let st = fd_stat(p, fd)?;
    copy_out(&mut p.aspace, buf, &stat_bytes(&st)).map(|_| 0)
}

pub fn newfstatat(p: &mut Process, dirfd: u64, pathp: u64, buf: u64, flags: u64) -> SysResult {
    let st = path_stat(p, dirfd, pathp, flags)?;
    copy_out(&mut p.aspace, buf, &stat_bytes(&st)).map(|_| 0)
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
    let target = match procfs::fd_path(&path) {
        Some(fd) if path.contains("/fd/") => {
            let file = p.fds.get(fd).map_err(|_| ENOENT)?;
            procfs::fd_link(&file.lock().kind, fd)
        }
        _ => {
            let ino = resolve(p, dirfd, &path, false)?;
            let fs = fs::lock();
            let Kind::Symlink(target) = &fs.node(ino).kind else { return Err(EINVAL) };
            target.clone()
        }
    };
    let n = (target.len() as u64).min(size) as usize;
    copy_out(&mut p.aspace, buf, &target.as_bytes()[..n]).map(|_| n as u64)
}

pub fn getdents64(p: &mut Process, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let FileKind::Node(dir) = f.kind else { return Err(ENOTDIR) };
    let fs = fs::lock();
    if !fs.is_dir(dir) {
        return Err(ENOTDIR);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = f.offset;
    let mut cursor = f.dir_pos.clone();
    // /proc/self/fd lists the live descriptors as symlinks.
    let fd_names: Vec<String> = if dir == fs.fd_dir {
        (0..p.fds.len() as u64).filter(|&fd| p.fds.get(fd).is_ok()).map(|fd| alloc::format!("{fd}")).collect()
    } else {
        Vec::new()
    };
    loop {
        let entry = match pos {
            0 => Some((String::from("."), dir, 4)),
            1 => Some((String::from(".."), fs.node(dir).parent, 4)),
            n if dir == fs.fd_dir => fd_names.get(n as usize - 2).map(|name| (name.clone(), dir, 10)),
            // Resume after the last name returned: entries may have come and
            // gone since (rm -rf unlinks while it reads).
            _ => fs.dir_next(dir, cursor.as_deref()).map(|(name, ino)| (name, ino, fs.d_type(ino))),
        };
        let Some((name, ino, d_type)) = entry else { break };
        let reclen = (19 + name.len() + 1).next_multiple_of(8);
        if out.len() + reclen > count as usize {
            if out.is_empty() {
                return Err(EINVAL);
            }
            break;
        }
        let start = out.len();
        out.extend_from_slice(&(ino as u64 + 1).to_le_bytes());
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
    let mut path = {
        let fs = fs::lock();
        if fs.node(p.cwd).nlink == 0 {
            return Err(ENOENT); // the working directory was removed
        }
        fs.path_of(p.cwd)
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
    let fs = fs::lock();
    if !fs.is_dir(ino) {
        return Err(ENOTDIR);
    }
    (p.cwd, p.cwd_pin) = (ino, Some(fs.pin(ino)));
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
    let perm = mode as u32 & 0o1777 & !p.umask;
    fs::lock().create(dir, &name, Kind::Dir(alloc::collections::BTreeMap::new()), perm, p.uid, p.gid).map(|_| 0)
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
    let (odir, oname) = parent_of(p, odirfd, &opath)?;
    let (ndir, nname) = parent_of(p, ndirfd, &npath)?;
    let mut fs = fs::lock();
    if [&oname, &nname].iter().any(|n| matches!(n.as_str(), "" | "." | "..")) {
        return Err(EBUSY);
    }
    let src = fs.child_of(odir, &oname).ok_or(ENOENT)?;
    if (opath.ends_with('/') || npath.ends_with('/')) && !fs.is_dir(src) {
        return Err(ENOTDIR);
    }
    let (noreplace, exchange) = (flags & RENAME_NOREPLACE != 0, flags & RENAME_EXCHANGE != 0);
    fs.rename(odir, &oname, ndir, &nname, noreplace, exchange, p.uid, p.gid).map(|_| 0)
}

pub fn linkat(p: &mut Process, odirfd: u64, opathp: u64, ndirfd: u64, npathp: u64, flags: u64) -> SysResult {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let follow = if flags & AT_SYMLINK_FOLLOW != 0 { 0 } else { AT_SYMLINK_NOFOLLOW };
    let src = at_node(p, odirfd, opathp, (flags & AT_EMPTY_PATH) | follow)?;
    let npath = read_cstr(&mut p.aspace, npathp, PATH_MAX)?;
    let (dir, name) = parent_of(p, ndirfd, &npath)?;
    fs::lock().link(src, dir, &name, p.uid, p.gid).map(|_| 0)
}

pub fn symlinkat(p: &mut Process, targetp: u64, dirfd: u64, pathp: u64) -> SysResult {
    let target = read_cstr(&mut p.aspace, targetp, PATH_MAX)?;
    if target.is_empty() {
        return Err(ENOENT);
    }
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let (dir, name) = parent_of(p, dirfd, &path)?;
    fs::lock().create(dir, &name, Kind::Symlink(target), 0o777, p.uid, p.gid).map(|_| 0)
}

/// Set a regular file's length, as truncate/ftruncate do.
fn set_len(p: &mut Process, n: u32, c: &Content, ino: Ino, len: u64) -> SysResult {
    if (len as i64) < 0 {
        return Err(EINVAL);
    }
    c.lock().may_resize(len)?;
    note_shared(p, n, c);
    c.lock().truncate(len);
    fs::lock().modified(ino);
    Ok(0)
}

pub fn truncate(p: &mut Process, pathp: u64, len: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let ino = resolve(p, AT_FDCWD as u64, &path, true)?;
    let fs = fs::lock();
    if fs.is_dir(ino) {
        return Err(EISDIR);
    }
    let c = fs.content(ino).ok_or(EINVAL)?;
    if !fs.permits(ino, p.uid, p.gid, MAY_WRITE) {
        return Err(EACCES);
    }
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
        (FileKind::Pipe(_) | FileKind::Socket(_), _) => Err(ESPIPE),
        _ => Err(not_file),
    }
}

pub fn ftruncate(p: &mut Process, fd: u64, len: u64) -> SysResult {
    let (ino, c) = writable_file(p, fd, EINVAL).map_err(|e| if e == ESPIPE { EINVAL } else { e })?;
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
    fs.node_mut(ino).perm = mode as u32 & 0o7777;
    fs.changed(ino);
    Ok(0)
}

pub fn fchmod(p: &mut Process, fd: u64, mode: u64) -> SysResult {
    let ino = fd_node(p, fd).map_err(|_| EBADF)?;
    set_mode(p, ino, mode)
}

pub fn fchmodat(p: &mut Process, dirfd: u64, pathp: u64, mode: u64) -> SysResult {
    let ino = at_node(p, dirfd, pathp, 0)?;
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
    let n = fs.node_mut(ino);
    if let Some(a) = set[0] {
        n.atime = a;
    }
    if let Some(m) = set[1] {
        n.mtime = m;
    }
    if set.iter().any(Option::is_some) {
        fs.changed(ino);
    }
    Ok(0)
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
        let n = src.lock().read(soff, &mut chunk[..want]);
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

/// sendfile from a regular file to a regular file, stdout or stderr. Other
/// destinations get EINVAL, which makes callers (Python's shutil, busybox)
/// fall back to read and write.
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
            let mut chunk = [0u8; CHUNK];
            let mut done = 0;
            while done < count {
                let want = (count - done).min(CHUNK as u64) as usize;
                let n = src.lock().read(start + done, &mut chunk[..want]);
                if n == 0 {
                    break;
                }
                console::write(ch, &chunk[..n]);
                done += n as u64;
            }
            done
        }
        _ => return Err(EINVAL),
    };
    drop(o);
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
    p.fds.set(new, FdEntry { file, cloexec: flags != 0 })?;
    Ok(new)
}

pub fn fcntl(p: &mut Process, fd: u64, cmd: u64, arg: u64) -> SysResult {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETLKW: u64 = 7;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_ADD_SEALS: u64 = 1033;
    const F_GET_SEALS: u64 = 1034;
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let file = p.fds.get(fd)?;
            p.fds.alloc(FdEntry { file, cloexec: cmd == F_DUPFD_CLOEXEC }, arg as usize)
        }
        F_GETFD => Ok(p.fds.entry_mut(fd)?.cloexec as u64),
        F_SETFD => {
            p.fds.entry_mut(fd)?.cloexec = arg & 1 != 0;
            Ok(0)
        }
        F_GETFL => Ok(p.fds.get(fd)?.lock().flags as u64),
        F_SETFL => {
            let file = p.fds.get(fd)?;
            let mut f = file.lock();
            f.flags = (f.flags & !SETFL_MASK) | (arg as u32 & SETFL_MASK);
            Ok(0)
        }
        // Single process: advisory locks always succeed.
        F_SETLK | F_SETLKW => p.fds.get(fd).map(|_| 0),
        F_GETLK => {
            p.fds.get(fd)?;
            copy_out(&mut p.aspace, arg, &2u16.to_le_bytes()).map(|_| 0) // l_type = F_UNLCK
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
    open_node(p, ino, Some(content), O_RDWR, flags & MFD_CLOEXEC != 0)
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
        k => k.poll(),
    }
}

pub fn ioctl(p: &mut Process, fd: u64, req: u64, arg: u64) -> SysResult {
    const FIONREAD: u64 = 0x541b;
    const FIONBIO: u64 = 0x5421;
    const FIONCLEX: u64 = 0x5450;
    const FIOCLEX: u64 = 0x5451;
    const SIOCGIFCONF: u64 = 0x8912;
    let entry = p.fds.entry_mut(fd)?;
    let socket =
        matches!(entry.file.lock().kind, FileKind::Socket(_) | FileKind::Netlink(_) | FileKind::UnixUnbound(_));
    if socket && req == SIOCGIFCONF {
        // struct ifconf { int ifc_len; char *ifc_buf; }: one entry, for lo.
        let len = read_u32(&mut p.aspace, arg)? as usize;
        let buf = read_u64(&mut p.aspace, arg + 8)?;
        let entry = crate::netlink::ifconf_entry();
        // With no buffer, report the size needed.
        let n = if buf == 0 || len >= entry.len() { entry.len() } else { 0 };
        if buf != 0 && n > 0 {
            copy_out(&mut p.aspace, buf, &entry)?;
        }
        return write_u32(&mut p.aspace, arg, n as u32).map(|_| 0);
    }
    if socket && (0x8900..=0x89ff).contains(&req) {
        let mut ifr = [0u8; 40];
        copy_in(&mut p.aspace, arg, &mut ifr)?;
        return match crate::netlink::ifreq_ioctl(req, &mut ifr) {
            Some(r) => r.and_then(|_| copy_out(&mut p.aspace, arg, &ifr)).map(|_| 0),
            None => p.unimplemented(nr::ioctl, "ioctl", &alloc::format!("socket ioctl {req:#x}"), EOPNOTSUPP),
        };
    }
    let entry = p.fds.entry_mut(fd)?;
    match req {
        FIONREAD => {
            let avail = match &entry.file.lock().kind {
                FileKind::Pipe(end) if !end.write => end.pipe.lock().buf.len() as u32,
                FileKind::Socket(s) => s.rx.as_ref().map_or(0, |r| r.pipe.lock().buf.len() as u32),
                FileKind::Stdin => 0,
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
        FIOCLEX | FIONCLEX => {
            entry.cloexec = req == FIOCLEX;
            Ok(0)
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

fn readiness(p: &Process, fd: u64) -> Result<u32, Errno> {
    Ok(poll_kind(p, &p.fds.get(fd)?.lock().kind).0)
}

/// Relative timeout from a timespec pointer (NULL = forever).
fn timespec_timeout(p: &mut Process, ts: u64) -> Result<Option<u64>, Errno> {
    if ts == 0 { Ok(None) } else { read_timespec_ns(&mut p.aspace, ts).map(Some) }
}

pub fn ppoll(p: &mut Process, fds: u64, nfds: u64, timeout: u64) -> SysResult {
    if nfds > 1024 {
        return Err(EINVAL);
    }
    let timeout = timespec_timeout(p, timeout)?;
    let mut raw = alloc::vec![0u8; nfds as usize * 8];
    copy_in(&mut p.aspace, fds, &mut raw)?;
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
    if ready > 0 || timeout == Some(0) {
        copy_out(&mut p.aspace, fds, &raw)?;
        return Ok(ready);
    }
    let deadline = p.timeout_deadline(timeout);
    p.block_io(deadline, Ok(0))
}

pub fn pselect6(p: &mut Process, nfds: u64, rfds: u64, wfds: u64, efds: u64, timeout: u64) -> SysResult {
    if nfds > 1024 {
        return Err(EINVAL);
    }
    let timeout = timespec_timeout(p, timeout)?;
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
    if count > 0 || timeout == Some(0) {
        for (set, ptr) in out.iter().zip([rfds, wfds, efds]) {
            if ptr != 0 {
                let b: Vec<u8> = set.iter().flat_map(|w| w.to_le_bytes()).collect();
                copy_out(&mut p.aspace, ptr, &b)?;
            }
        }
        return Ok(count);
    }
    let deadline = p.timeout_deadline(timeout);
    p.block_io(deadline, Ok(0))
}

// ---------------------------------------------------------------- pipes, eventfd, epoll

const O_DIRECT: u32 = 0o200000;

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
        let mut b = [0u8; 16]; // arm64 struct epoll_event is not packed: u32 events, pad, u64 data
        copy_in(&mut p.aspace, eventp, &mut b)?;
        (u32::from_le_bytes(b[..4].try_into().unwrap()), u64::from_le_bytes(b[8..].try_into().unwrap()))
    };
    let mut e = ep.lock();
    let key = fd as i32 as u64;
    let live = e.interest.get(&key).is_some_and(|r| r.file.ptr_eq(&Arc::downgrade(&target)));
    match op {
        ADD if live => return Err(EEXIST),
        ADD => {
            e.interest
                .insert(key, Registration { file: Arc::downgrade(&target), events, data, reported_version: None });
        }
        DEL if live => {
            e.interest.remove(&key);
        }
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
            if out.len() / 16 >= max as usize {
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
            out.extend_from_slice(&ready.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&reg.data.to_le_bytes());
        }
        for fd in dead {
            e.interest.remove(&fd);
        }
    }
    if !out.is_empty() || timeout == Some(0) {
        copy_out(&mut p.aspace, evp, &out)?;
        return Ok(out.len() as u64 / 16);
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

pub fn fstatfs(p: &mut Process, fd: u64, buf: u64) -> SysResult {
    p.fds.get(fd)?;
    let b = statfs_bytes(p);
    copy_out(&mut p.aspace, buf, &b).map(|_| 0)
}

/// getxattr/lgetxattr/fgetxattr and listxattr/llistxattr/flistxattr: files
/// exist but carry no extended attributes.
pub fn xattr_query(p: &mut Process, n: u32, target: u64, list: bool) -> SysResult {
    match n {
        nr::fgetxattr | nr::flistxattr => {
            p.fds.get(target)?;
        }
        _ => {
            let path = read_cstr(&mut p.aspace, target, PATH_MAX)?;
            let follow = !matches!(n, nr::lgetxattr | nr::llistxattr);
            resolve(p, AT_FDCWD as u64, &path, follow)?;
        }
    }
    if list { Ok(0) } else { Err(ENODATA) }
}

pub fn inotify_init1(p: &mut Process, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    let file = new_file(FileKind::Inotify(crate::fd::Inotify::default()), O_RDONLY | (flags & O_NONBLOCK));
    p.fds.alloc(FdEntry { file, cloexec: flags & O_CLOEXEC != 0 }, 0)
}

pub fn inotify_add_watch(p: &mut Process, fd: u64, pathp: u64, mask: u64) -> SysResult {
    const IN_DONT_FOLLOW: u64 = 0x0200_0000;
    let file = p.fds.get(fd)?;
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let ino = resolve(p, AT_FDCWD as u64, &path, mask & IN_DONT_FOLLOW == 0)?;
    let mut f = file.lock();
    let FileKind::Inotify(n) = &mut f.kind else { return Err(EINVAL) };
    if let Some((&wd, _)) = n.watches.iter().find(|(_, w)| **w == ino) {
        return Ok(wd as u64);
    }
    use core::sync::atomic::Ordering;
    if crate::fd::WATCHES.load(Ordering::Relaxed) >= crate::fd::MAX_WATCHES {
        return Err(ENOSPC);
    }
    crate::fd::WATCHES.fetch_add(1, Ordering::Relaxed);
    n.next_wd += 1;
    n.watches.insert(n.next_wd, ino);
    Ok(n.next_wd as u64)
}

pub fn inotify_rm_watch(p: &mut Process, fd: u64, wd: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let FileKind::Inotify(n) = &mut f.kind else { return Err(EINVAL) };
    n.watches.remove(&(wd as i32)).ok_or(EINVAL)?;
    crate::fd::WATCHES.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    Ok(0)
}
