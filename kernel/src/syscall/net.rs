//! Socket syscalls. Only local AF_UNIX stream pairs exist so far
//! (socketpair); creating network sockets is gated by `net`. The per-socket
//! calls here need no capability: they only act on sockets that already exist.

use alloc::vec::Vec;
use grix_abi::policy::Capability;

use super::file::{pipe_read, pipe_write};
use super::{require, table::nr};
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, FileRef, O_NONBLOCK, O_RDWR, new_file};
use crate::ipc;
use crate::process::Process;
use crate::uaccess::*;

const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;
const MSG_PEEK: u64 = 0x2;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const SOL_SOCKET: u64 = 1;
const ENOTSOCK: Errno = Errno(88);
const ENOPROTOOPT: Errno = Errno(92);
const EPROTONOSUPPORT: Errno = Errno(93);
const EISCONN: Errno = Errno(106);

pub fn socketpair(p: &mut Process, domain: u64, ty: u64, _proto: u64, sv: u64) -> SysResult {
    if domain != AF_UNIX {
        require(p, nr::socketpair, Capability::Net, "")?;
        return p.unimplemented(nr::socketpair, "socketpair", "non-AF_UNIX socket pairs", EOPNOTSUPP);
    }
    if ty & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    if ty & 0xf != SOCK_STREAM {
        return p.unimplemented(nr::socketpair, "socketpair", "AF_UNIX datagram/seqpacket sockets", EPROTONOSUPPORT);
    }
    let (a, b) = ipc::socketpair();
    let flags = O_RDWR | if ty & SOCK_NONBLOCK != 0 { O_NONBLOCK } else { 0 };
    let cloexec = ty & SOCK_CLOEXEC != 0;
    let fa = p.fds.alloc(FdEntry { file: new_file(FileKind::Socket(a), flags), cloexec }, 0)?;
    let fb = match p.fds.alloc(FdEntry { file: new_file(FileKind::Socket(b), flags), cloexec }, 0) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = p.fds.close(fa);
            return Err(e);
        }
    };
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&(fa as i32).to_le_bytes());
    buf[4..].copy_from_slice(&(fb as i32).to_le_bytes());
    if let Err(e) = copy_out(&mut p.aspace, sv, &buf) {
        let _ = p.fds.close(fa);
        let _ = p.fds.close(fb);
        return Err(e);
    }
    Ok(0)
}

fn socket(p: &Process, fd: u64) -> Result<FileRef, Errno> {
    let file = p.fds.get(fd)?;
    if !matches!(file.lock().kind, FileKind::Socket(_)) {
        return Err(ENOTSOCK);
    }
    Ok(file)
}

/// Send `len` bytes from `buf`. `addr` must be empty: the socket is connected.
pub fn sendto(p: &mut Process, fd: u64, buf: u64, len: u64, flags: u64, addr: u64) -> SysResult {
    let file = socket(p, fd)?;
    if addr != 0 {
        return Err(EISCONN);
    }
    send(p, &file, buf, len, flags)
}

fn send(p: &mut Process, file: &FileRef, buf: u64, len: u64, flags: u64) -> SysResult {
    let f = file.lock();
    let nonblock = f.nonblocking() || flags & MSG_DONTWAIT != 0;
    let FileKind::Socket(s) = &f.kind else { return Err(ENOTSOCK) };
    match &s.tx {
        Some(tx) => pipe_write(p, tx, buf, len, nonblock, flags & MSG_NOSIGNAL == 0),
        None => {
            if flags & MSG_NOSIGNAL == 0 {
                crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a socket that was shut down");
            }
            Err(EPIPE)
        }
    }
}

fn recv(p: &mut Process, file: &FileRef, buf: u64, len: u64, flags: u64) -> SysResult {
    let f = file.lock();
    let nonblock = f.nonblocking() || flags & MSG_DONTWAIT != 0;
    let FileKind::Socket(s) = &f.kind else { return Err(ENOTSOCK) };
    match &s.rx {
        Some(rx) => pipe_read(p, rx, buf, len, nonblock, flags & MSG_PEEK != 0),
        None => Ok(0),
    }
}

/// The peer of a socket pair is unnamed: report just the address family.
fn unnamed_addr(p: &mut Process, addr: u64, addrlen: u64) -> Result<(), Errno> {
    if addr == 0 || addrlen == 0 {
        return Ok(());
    }
    let room = read_u32(&mut p.aspace, addrlen)?;
    if room >= 2 {
        copy_out(&mut p.aspace, addr, &(AF_UNIX as u16).to_le_bytes())?;
    }
    write_u32(&mut p.aspace, addrlen, 2)
}

pub fn recvfrom(p: &mut Process, fd: u64, buf: u64, len: u64, flags: u64, addr: u64, addrlen: u64) -> SysResult {
    let file = socket(p, fd)?;
    let n = recv(p, &file, buf, len, flags)?;
    unnamed_addr(p, addr, addrlen)?;
    Ok(n)
}

/// struct msghdr (arm64): name, namelen, iov, iovlen, control, controllen, flags.
struct MsgHdr {
    name: u64,
    iov: u64,
    iovlen: u64,
    controllen: u64,
}

fn read_msghdr(p: &mut Process, msg: u64) -> Result<MsgHdr, Errno> {
    let mut b = [0u8; 56];
    copy_in(&mut p.aspace, msg, &mut b)?;
    let w = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    Ok(MsgHdr { name: w(0), iov: w(16), iovlen: w(24), controllen: w(40) })
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

pub fn sendmsg(p: &mut Process, fd: u64, msg: u64, flags: u64) -> SysResult {
    let file = socket(p, fd)?;
    let m = read_msghdr(p, msg)?;
    if m.name != 0 {
        return Err(EISCONN);
    }
    if m.controllen != 0 {
        return p.unimplemented(nr::sendmsg, "sendmsg", "ancillary data (SCM_RIGHTS, ...)", EOPNOTSUPP);
    }
    let mut total = 0;
    for (i, (base, len)) in iovecs(p, m.iov, m.iovlen)?.into_iter().enumerate() {
        // Only the first chunk may block, so a partial result is returned rather than lost.
        let flags = if i == 0 { flags } else { flags | MSG_DONTWAIT };
        match send(p, &file, base, len, flags) {
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

pub fn recvmsg(p: &mut Process, fd: u64, msg: u64, flags: u64) -> SysResult {
    let file = socket(p, fd)?;
    let m = read_msghdr(p, msg)?;
    let mut total = 0;
    for (i, (base, len)) in iovecs(p, m.iov, m.iovlen)?.into_iter().enumerate() {
        let flags = if i == 0 { flags } else { flags | MSG_DONTWAIT };
        match recv(p, &file, base, len, flags) {
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
    // No peer name, no control data, no flags.
    if m.name != 0 {
        write_u32(&mut p.aspace, msg + 8, 0)?;
    }
    write_u64(&mut p.aspace, msg + 40, 0)?;
    write_u32(&mut p.aspace, msg + 48, 0)?;
    Ok(total)
}

pub fn getsockopt(p: &mut Process, fd: u64, level: u64, name: u64, val: u64, len: u64) -> SysResult {
    socket(p, fd)?;
    const SO_TYPE: u64 = 3;
    const SO_ERROR: u64 = 4;
    const SO_SNDBUF: u64 = 7;
    const SO_RCVBUF: u64 = 8;
    const SO_ACCEPTCONN: u64 = 30;
    const SO_DOMAIN: u64 = 39;
    if level != SOL_SOCKET {
        return Err(ENOPROTOOPT);
    }
    let v: u32 = match name {
        SO_TYPE => SOCK_STREAM as u32,
        SO_ERROR | SO_ACCEPTCONN => 0,
        SO_SNDBUF | SO_RCVBUF => ipc::PIPE_CAPACITY as u32,
        SO_DOMAIN => AF_UNIX as u32,
        _ => return Err(ENOPROTOOPT),
    };
    if read_u32(&mut p.aspace, len)? < 4 {
        return Err(EINVAL);
    }
    write_u32(&mut p.aspace, val, v)?;
    write_u32(&mut p.aspace, len, 4).map(|_| 0)
}

/// Common options are accepted and ignored: they don't change local socket pairs.
pub fn setsockopt(p: &mut Process, fd: u64, level: u64, _name: u64) -> SysResult {
    socket(p, fd)?;
    if level != SOL_SOCKET {
        return Err(ENOPROTOOPT);
    }
    Ok(0)
}

pub fn shutdown(p: &mut Process, fd: u64, how: u64) -> SysResult {
    let file = socket(p, fd)?;
    let mut f = file.lock();
    let FileKind::Socket(s) = &mut f.kind else { return Err(ENOTSOCK) };
    match how {
        0 => s.rx = None,
        1 => s.tx = None,
        2 => {
            s.rx = None;
            s.tx = None;
        }
        _ => return Err(EINVAL),
    }
    Ok(0)
}

pub fn getname(p: &mut Process, fd: u64, addr: u64, addrlen: u64) -> SysResult {
    socket(p, fd)?;
    unnamed_addr(p, addr, addrlen).map(|_| 0)
}
