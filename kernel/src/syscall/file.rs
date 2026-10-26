//! File and descriptor syscalls over the read-only imported filesystem.

use alloc::string::String;
use alloc::vec::Vec;
use grix_abi::policy::Capability;
use grix_abi::wire::Channel;

use super::{require, table::nr};
use crate::console;
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, O_ACCMODE, O_RDONLY, O_WRONLY, OpenFile, new_file};
use crate::fs::{self, Dev, Ino, Kind, ROOT, S_IFIFO, StatInfo};
use crate::process::Process;
use crate::rng;
use crate::time;
use crate::uaccess::*;

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
        FileKind::Node(ino) if fs::get().is_dir(ino) => Ok(ino),
        _ => Err(ENOTDIR),
    }
}

/// Resolve `path` relative to `dirfd`, reporting paths that were not imported.
fn resolve(p: &mut Process, dirfd: u64, path: &str, follow: bool) -> Result<Ino, Errno> {
    let base = if path.starts_with('/') { ROOT } else { dir_base(p, dirfd)? };
    let r = fs::get().lookup(base, path, follow);
    if r == Err(ENOENT) {
        p.missing_path(base, path);
    }
    r
}

/// The node an fd refers to, for *at(fd, "", AT_EMPTY_PATH) and fstat.
fn fd_stat(p: &Process, fd: u64) -> Result<StatInfo, Errno> {
    if fd as i32 == AT_FDCWD {
        return Ok(fs::get().stat(p.cwd));
    }
    let f = p.fds.get(fd)?;
    let kind = f.lock().kind;
    Ok(match kind {
        FileKind::Stdin | FileKind::Stdout | FileKind::Stderr => {
            StatInfo { ino: 0x1000_0000 + fd, mode: S_IFIFO | 0o600, nlink: 1, size: 0, rdev: 0 }
        }
        FileKind::Node(ino) | FileKind::Dev(_, ino) => fs::get().stat(ino),
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
    let ino = resolve(p, dirfd, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
    Ok(fs::get().stat(ino))
}

// ---------------------------------------------------------------- open/close

pub fn openat(p: &mut Process, dirfd: u64, pathp: u64, flags: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let flags = flags as u32;
    let acc = flags & O_ACCMODE;
    let writes = acc != O_RDONLY || flags & O_TRUNC != 0 || flags & O_TMPFILE == O_TMPFILE;
    let fs = fs::get();
    let base = if path.starts_with('/') { ROOT } else { dir_base(p, dirfd)? };
    let found = fs.lookup(base, &path, flags & O_NOFOLLOW == 0);

    let ino = match found {
        Ok(ino) => {
            if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
                return Err(EEXIST);
            }
            ino
        }
        Err(ENOENT) if flags & O_CREAT != 0 => return no_writes(p, &path),
        Err(e) => {
            if e == ENOENT {
                p.missing_path(base, &path);
            }
            return Err(e);
        }
    };
    let node = fs.node(ino);
    if flags & O_PATH != 0 {
        let file = new_file(FileKind::Node(ino), O_RDONLY);
        file.lock().path_only = true;
        return p.fds.alloc(FdEntry { file, cloexec: flags & O_CLOEXEC != 0 }, 0);
    }
    let kind = match node.kind {
        Kind::Dev(d) => FileKind::Dev(d, ino),
        Kind::Symlink(_) => return Err(ELOOP), // O_NOFOLLOW on a symlink
        Kind::Dir(_) if writes => return Err(EISDIR),
        Kind::Dir(_) => FileKind::Node(ino),
        Kind::File(_) if flags & O_DIRECTORY != 0 => return Err(ENOTDIR),
        Kind::File(_) if writes => return no_writes(p, &path),
        Kind::File(_) => FileKind::Node(ino),
    };
    let file = new_file(kind, flags & !(O_CLOEXEC | O_CREAT | O_EXCL | O_TRUNC));
    p.fds.alloc(FdEntry { file, cloexec: flags & O_CLOEXEC != 0 }, 0)
}

/// The imported filesystem is read-only. Writing needs `fs_write`, and even
/// then there is no writable filesystem yet.
fn no_writes(p: &mut Process, path: &str) -> SysResult {
    require(p, nr::openat, Capability::FsWrite, path)?;
    p.unimplemented(nr::openat, "openat", "writable filesystem", EROFS)
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
    match f.kind {
        FileKind::Stdin => Ok(0),
        FileKind::Stdout | FileKind::Stderr => Err(EBADF),
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
        FileKind::Node(ino) => match fs::get().node(ino).kind {
            Kind::File(data) => {
                let off = at.unwrap_or(f.offset);
                let len = data.len() as u64;
                if off >= len {
                    return Ok(0);
                }
                let n = count.min(len - off);
                copy_out(&mut p.aspace, buf, &data[off as usize..(off + n) as usize])?;
                if at.is_none() {
                    f.offset += n;
                }
                Ok(n)
            }
            Kind::Dir(_) => Err(EISDIR),
            _ => Err(EINVAL),
        },
    }
}

fn write_from(p: &mut Process, f: &mut OpenFile, buf: u64, count: u64) -> SysResult {
    if f.path_only || f.flags & O_ACCMODE == O_RDONLY {
        return Err(EBADF);
    }
    let count = count.min(MAX_RW);
    let ch = match f.kind {
        FileKind::Stdout => Channel::Stdout,
        FileKind::Stderr => Channel::Stderr,
        FileKind::Dev(..) => return Ok(count),
        FileKind::Stdin | FileKind::Node(_) => return Err(EBADF),
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

pub fn read(p: &mut Process, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    read_into(p, &mut f, buf, count, None)
}

pub fn pread(p: &mut Process, fd: u64, buf: u64, count: u64, off: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    match f.kind {
        FileKind::Node(_) => read_into(p, &mut f, buf, count, Some(off)),
        FileKind::Dev(..) => read_into(p, &mut f, buf, count, None),
        _ => Err(ESPIPE),
    }
}

pub fn write(p: &mut Process, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    write_from(p, &mut f, buf, count)
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

pub fn readv(p: &mut Process, fd: u64, iov: u64, cnt: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let mut total = 0;
    for (base, len) in iovecs(p, iov, cnt)? {
        match read_into(p, &mut f, base, len, None) {
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

pub fn writev(p: &mut Process, fd: u64, iov: u64, cnt: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let mut total = 0;
    for (base, len) in iovecs(p, iov, cnt)? {
        match write_from(p, &mut f, base, len) {
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

pub fn lseek(p: &mut Process, fd: u64, off: u64, whence: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let size = match f.kind {
        FileKind::Node(ino) => match fs::get().node(ino).kind {
            Kind::File(d) => d.len() as i64,
            _ => 0,
        },
        FileKind::Dev(..) => return Ok(0),
        _ => return Err(ESPIPE),
    };
    let off = off as i64;
    let new = match whence {
        0 => Some(off),
        1 => (f.offset as i64).checked_add(off),
        2 => size.checked_add(off),
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

fn stat_bytes(p: &Process, st: &StatInfo) -> [u8; 128] {
    let now = time::realtime_ns();
    let (sec, nsec) = (now / 1_000_000_000, now % 1_000_000_000);
    let mut b = [0u8; 128];
    let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(0, &1u64.to_le_bytes()); // st_dev
    put(8, &st.ino.to_le_bytes());
    put(16, &st.mode.to_le_bytes());
    put(20, &st.nlink.to_le_bytes());
    put(24, &p.uid.to_le_bytes());
    put(28, &p.gid.to_le_bytes());
    put(32, &st.rdev.to_le_bytes());
    put(48, &st.size.to_le_bytes());
    put(56, &4096u32.to_le_bytes()); // st_blksize
    put(64, &st.size.div_ceil(512).to_le_bytes()); // st_blocks
    for off in [72, 88, 104] {
        put(off, &sec.to_le_bytes());
        put(off + 8, &nsec.to_le_bytes());
    }
    b
}

pub fn fstat(p: &mut Process, fd: u64, buf: u64) -> SysResult {
    let st = fd_stat(p, fd)?;
    let bytes = stat_bytes(p, &st);
    copy_out(&mut p.aspace, buf, &bytes).map(|_| 0)
}

pub fn newfstatat(p: &mut Process, dirfd: u64, pathp: u64, buf: u64, flags: u64) -> SysResult {
    let st = path_stat(p, dirfd, pathp, flags)?;
    let bytes = stat_bytes(p, &st);
    copy_out(&mut p.aspace, buf, &bytes).map(|_| 0)
}

pub fn statx(p: &mut Process, dirfd: u64, pathp: u64, flags: u64, buf: u64) -> SysResult {
    let st = path_stat(p, dirfd, pathp, flags)?;
    let now = time::realtime_ns();
    let mut b = [0u8; 256];
    let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(0, &0x7ffu32.to_le_bytes()); // STATX_BASIC_STATS
    put(4, &4096u32.to_le_bytes());
    put(16, &st.nlink.to_le_bytes());
    put(20, &p.uid.to_le_bytes());
    put(24, &p.gid.to_le_bytes());
    put(28, &(st.mode as u16).to_le_bytes());
    put(32, &st.ino.to_le_bytes());
    put(40, &st.size.to_le_bytes());
    put(48, &st.size.div_ceil(512).to_le_bytes());
    for off in [64, 80, 96, 112] {
        put(off, &(now / 1_000_000_000).to_le_bytes());
        put(off + 8, &((now % 1_000_000_000) as u32).to_le_bytes());
    }
    put(128, &((st.rdev >> 8) as u32).to_le_bytes());
    put(132, &((st.rdev & 0xff) as u32).to_le_bytes());
    copy_out(&mut p.aspace, buf, &b).map(|_| 0)
}

pub fn faccessat(p: &mut Process, dirfd: u64, pathp: u64, mode: u64, flags: u64) -> SysResult {
    let st = path_stat(p, dirfd, pathp, flags)?;
    const X_OK: u64 = 1;
    const W_OK: u64 = 2;
    let is_dev = st.mode & 0o170000 == fs::S_IFCHR;
    if mode & W_OK != 0 && !is_dev {
        return Err(EROFS);
    }
    if mode & X_OK != 0 && st.mode & 0o111 == 0 {
        return Err(EACCES);
    }
    Ok(0)
}

pub fn readlinkat(p: &mut Process, dirfd: u64, pathp: u64, buf: u64, size: u64) -> SysResult {
    if size as i64 <= 0 {
        return Err(EINVAL);
    }
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let ino = resolve(p, dirfd, &path, false)?;
    let Kind::Symlink(target) = &fs::get().node(ino).kind else { return Err(EINVAL) };
    let n = (target.len() as u64).min(size) as usize;
    copy_out(&mut p.aspace, buf, &target.as_bytes()[..n]).map(|_| n as u64)
}

pub fn getdents64(p: &mut Process, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let FileKind::Node(dir) = f.kind else { return Err(ENOTDIR) };
    let fs = fs::get();
    if !fs.is_dir(dir) {
        return Err(ENOTDIR);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = f.offset;
    while let Some((name, ino)) = fs.dir_entry(dir, pos) {
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
        out.push(fs.d_type(ino));
        out.extend_from_slice(name.as_bytes());
        out.resize(start + reclen, 0);
        pos += 1;
    }
    copy_out(&mut p.aspace, buf, &out)?;
    f.offset = pos;
    Ok(out.len() as u64)
}

// ---------------------------------------------------------------- cwd

pub fn getcwd(p: &mut Process, buf: u64, size: u64) -> SysResult {
    let mut path: String = fs::get().path_of(p.cwd);
    path.push('\0');
    if (size as usize) < path.len() {
        return Err(ERANGE);
    }
    copy_out(&mut p.aspace, buf, path.as_bytes()).map(|_| path.len() as u64)
}

pub fn chdir(p: &mut Process, pathp: u64) -> SysResult {
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let ino = resolve(p, AT_FDCWD as u64, &path, true)?;
    if !fs::get().is_dir(ino) {
        return Err(ENOTDIR);
    }
    p.cwd = ino;
    Ok(0)
}

pub fn fchdir(p: &mut Process, fd: u64) -> SysResult {
    p.cwd = dir_base(p, fd)?;
    Ok(0)
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
        _ => Err(EINVAL),
    }
}

pub fn ioctl(p: &mut Process, fd: u64, req: u64, _arg: u64) -> SysResult {
    const FIONBIO: u64 = 0x5421;
    const FIONCLEX: u64 = 0x5450;
    const FIOCLEX: u64 = 0x5451;
    let entry = p.fds.entry_mut(fd)?;
    match req {
        FIONBIO => Ok(0),
        FIOCLEX | FIONCLEX => {
            entry.cloexec = req == FIOCLEX;
            Ok(0)
        }
        // stdio is not a terminal (TCGETS, TIOCGWINSZ, ...).
        _ => Err(ENOTTY),
    }
}

pub fn ppoll(p: &mut Process, fds: u64, nfds: u64, timeout: u64) -> SysResult {
    const POLLIN: u16 = 0x1;
    const POLLOUT: u16 = 0x4;
    const POLLNVAL: u16 = 0x20;
    if nfds > 1024 {
        return Err(EINVAL);
    }
    let mut raw = alloc::vec![0u8; nfds as usize * 8];
    copy_in(&mut p.aspace, fds, &mut raw)?;
    let mut ready = 0;
    for c in raw.chunks_mut(8) {
        let fd = i32::from_le_bytes(c[..4].try_into().unwrap());
        let events = u16::from_le_bytes(c[4..6].try_into().unwrap());
        let revents = if fd < 0 {
            0
        } else {
            match p.fds.get(fd as u64) {
                Err(_) => POLLNVAL,
                // Every file we have is always ready: stdin is at EOF, output never blocks.
                Ok(f) => {
                    let possible = match f.lock().kind {
                        FileKind::Stdin => POLLIN,
                        FileKind::Stdout | FileKind::Stderr => POLLOUT,
                        _ => POLLIN | POLLOUT,
                    };
                    possible & events
                }
            }
        };
        c[6..8].copy_from_slice(&revents.to_le_bytes());
        if revents != 0 {
            ready += 1;
        }
    }
    copy_out(&mut p.aspace, fds, &raw)?;
    if ready == 0 {
        if timeout == 0 {
            // No timeout and nothing can ever become ready: Linux would block forever.
            return p.unimplemented(nr::ppoll, "ppoll", "blocking forever (nothing can become ready)", EINTR);
        }
        let ns = read_timespec_ns(&mut p.aspace, timeout)?;
        time::sleep_ns(ns);
    }
    Ok(ready)
}
