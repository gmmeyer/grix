//! Socket syscalls. Two kinds exist so far: local AF_UNIX stream pairs
//! (socketpair) and NETLINK_ROUTE sockets that describe `lo` (netlink.rs).
//! Creating network sockets is gated by `net`. The per-socket calls here
//! need no capability: they only act on sockets that already exist.

use alloc::vec::Vec;
use grix_abi::policy::Capability;

use super::file::{pipe_read, pipe_write};
use super::{require, table::nr};
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, FileRef, O_NONBLOCK, O_RDWR, new_file};
use crate::ipc;
use crate::netlink::{self, MAX_REQUEST, Netlink};
use crate::process::{PID, Process};
use crate::uaccess::*;

const AF_UNIX: u64 = 1;
const AF_NETLINK: u64 = netlink::AF_NETLINK as u64;
const NETLINK_ROUTE: u64 = 0;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_SEQPACKET: u64 = 5;
const MSG_TRUNC: u64 = 0x20;
const SOL_NETLINK: u64 = 270;
const ESOCKTNOSUPPORT: Errno = Errno(94);
const EAFNOSUPPORT: Errno = Errno(97);
const EMSGSIZE: Errno = Errno(90);
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

/// socket(2). Netlink route sockets only ever describe `lo`, so they need
/// no capability; network sockets need `net` (and aren't implemented yet).
pub fn socket(p: &mut Process, domain: u64, ty: u64, proto: u64) -> SysResult {
    if ty & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let flags = O_RDWR | if ty & SOCK_NONBLOCK != 0 { O_NONBLOCK } else { 0 };
    let cloexec = ty & SOCK_CLOEXEC != 0;
    match domain {
        AF_NETLINK => {
            if !matches!(ty & 0xf, SOCK_RAW | SOCK_DGRAM) {
                return Err(ESOCKTNOSUPPORT);
            }
            if proto != NETLINK_ROUTE {
                return p.unimplemented(
                    nr::socket,
                    "socket",
                    "netlink protocols other than NETLINK_ROUTE",
                    EPROTONOSUPPORT,
                );
            }
            let file = new_file(FileKind::Netlink(Netlink::new(PID as u32)), flags);
            p.fds.alloc(FdEntry { file, cloexec }, 0)
        }
        // Local IPC, so not gated by `net`. Until binding to paths exists the
        // socket can't talk to anything, but interface ioctls work on it
        // (musl's if_nametoindex).
        AF_UNIX => {
            if !matches!(ty & 0xf, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
                return Err(ESOCKTNOSUPPORT);
            }
            let file = new_file(FileKind::UnixUnbound(ty & 0xf), flags);
            p.fds.alloc(FdEntry { file, cloexec }, 0)
        }
        _ => {
            require(p, nr::socket, Capability::Net, "")?;
            p.unimplemented(nr::socket, "socket", "network sockets", EAFNOSUPPORT)
        }
    }
}

fn socket_file(p: &Process, fd: u64) -> Result<FileRef, Errno> {
    let file = p.fds.get(fd)?;
    if !matches!(file.lock().kind, FileKind::Socket(_) | FileKind::Netlink(_) | FileKind::UnixUnbound(_)) {
        return Err(ENOTSOCK);
    }
    Ok(file)
}

fn is_unbound(file: &FileRef) -> bool {
    matches!(file.lock().kind, FileKind::UnixUnbound(_))
}

const UNIX_PATHS: &str = "AF_UNIX sockets bound to paths";

/// connect(2). A netlink socket "connects" to the kernel; socket pairs are
/// already connected.
pub fn connect(p: &mut Process, fd: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    match file.lock().kind {
        FileKind::Netlink(_) => return Ok(0),
        FileKind::Socket(_) => return Err(EISCONN),
        _ => {}
    }
    p.unimplemented(nr::connect, "connect", UNIX_PATHS, EOPNOTSUPP)
}

pub fn listen(p: &mut Process, fd: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    match file.lock().kind {
        FileKind::Netlink(_) => return Err(EOPNOTSUPP),
        FileKind::Socket(_) => return Err(EINVAL),
        _ => {}
    }
    p.unimplemented(nr::listen, "listen", UNIX_PATHS, EOPNOTSUPP)
}

/// accept/accept4: nothing can be listening yet.
pub fn accept(p: &mut Process, fd: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    match file.lock().kind {
        FileKind::Netlink(_) => Err(EOPNOTSUPP),
        _ => Err(EINVAL),
    }
}

fn is_netlink(file: &FileRef) -> bool {
    matches!(file.lock().kind, FileKind::Netlink(_))
}

/// bind(2): only netlink sockets can be bound (to a port id). Socket pairs
/// are already connected.
pub fn bind(p: &mut Process, fd: u64, addr: u64, len: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_unbound(&file) {
        return p.unimplemented(nr::bind, "bind", UNIX_PATHS, EOPNOTSUPP);
    }
    let mut f = file.lock();
    let FileKind::Netlink(nl) = &mut f.kind else { return Err(EINVAL) };
    if len < 12 {
        return Err(EINVAL);
    }
    let mut b = [0u8; 12];
    copy_in(&mut p.aspace, addr, &mut b)?;
    if u16::from_le_bytes([b[0], b[1]]) != netlink::AF_NETLINK {
        return Err(EINVAL);
    }
    let port = u32::from_le_bytes(b[4..8].try_into().unwrap());
    if port != 0 {
        nl.port = port;
    }
    Ok(0)
}

fn netlink_send(p: &mut Process, file: &FileRef, bufs: &[(u64, u64)]) -> SysResult {
    let mut f = file.lock();
    let FileKind::Netlink(nl) = &mut f.kind else { return Err(ENOTSOCK) };
    netlink_request(p, nl, bufs)
}

/// Gather iovecs into one datagram and handle it as a netlink request.
pub(super) fn netlink_request(p: &mut Process, nl: &mut Netlink, bufs: &[(u64, u64)]) -> SysResult {
    let total = bufs.iter().try_fold(0u64, |t, &(_, len)| t.checked_add(len)).ok_or(EINVAL)?;
    if total > MAX_REQUEST as u64 {
        return Err(EMSGSIZE);
    }
    let mut data = alloc::vec![0u8; total as usize];
    let mut at = 0;
    for &(base, len) in bufs {
        copy_in(&mut p.aspace, base, &mut data[at..at + len as usize])?;
        at += len as usize;
    }
    nl.request(&data)?;
    ipc::changed();
    Ok(total)
}

/// Read one reply datagram into `bufs`. Returns (bytes copied, datagram
/// length); the rest of a datagram that doesn't fit is lost, as with any
/// datagram socket, unless peeking.
pub(super) fn netlink_recv(
    p: &mut Process,
    nl: &mut Netlink,
    bufs: &[(u64, u64)],
    flags: u64,
    nonblock: bool,
) -> Result<(u64, u64), Errno> {
    let Some(dgram) = nl.rx.front() else {
        return super::file::would_block(p, nonblock).map(|_| (0, 0));
    };
    let mut done = 0usize;
    for &(base, len) in bufs {
        let n = (len as usize).min(dgram.len() - done);
        copy_out(&mut p.aspace, base, &dgram[done..done + n])?;
        done += n;
    }
    let full = dgram.len() as u64;
    if flags & MSG_PEEK == 0 {
        nl.rx.pop_front();
    }
    Ok((done as u64, full))
}

fn recv_netlink(p: &mut Process, file: &FileRef, bufs: &[(u64, u64)], flags: u64) -> Result<(u64, u64), Errno> {
    let mut f = file.lock();
    let nonblock = flags & MSG_DONTWAIT != 0 || f.nonblocking();
    let FileKind::Netlink(nl) = &mut f.kind else { return Err(ENOTSOCK) };
    netlink_recv(p, nl, bufs, flags, nonblock)
}

/// Write a netlink peer address (the kernel: port 0) to (addr, addrlen).
fn kernel_addr(p: &mut Process, addr: u64, addrlen: u64) -> Result<(), Errno> {
    write_addr(p, addr, addrlen, &netlink::sockaddr(0))
}

fn write_addr(p: &mut Process, addr: u64, addrlen: u64, sa: &[u8]) -> Result<(), Errno> {
    if addr == 0 || addrlen == 0 {
        return Ok(());
    }
    let room = read_u32(&mut p.aspace, addrlen)? as usize;
    copy_out(&mut p.aspace, addr, &sa[..room.min(sa.len())])?;
    write_u32(&mut p.aspace, addrlen, sa.len() as u32)
}

/// Send `len` bytes from `buf`. On a socket pair `addr` must be empty (it's
/// connected); a netlink request always goes to the kernel.
pub fn sendto(p: &mut Process, fd: u64, buf: u64, len: u64, flags: u64, addr: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_netlink(&file) {
        return netlink_send(p, &file, &[(buf, len)]);
    }
    if is_unbound(&file) {
        return if addr != 0 { p.unimplemented(nr::sendto, "sendto", UNIX_PATHS, EOPNOTSUPP) } else { Err(ENOTCONN) };
    }
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
    let file = socket_file(p, fd)?;
    if is_netlink(&file) {
        let (n, full) = recv_netlink(p, &file, &[(buf, len)], flags)?;
        kernel_addr(p, addr, addrlen)?;
        // MSG_TRUNC asks for the datagram's real length.
        return Ok(if flags & MSG_TRUNC != 0 { full } else { n });
    }
    if is_unbound(&file) {
        return Err(ENOTCONN);
    }
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
    let file = socket_file(p, fd)?;
    let m = read_msghdr(p, msg)?;
    if m.controllen != 0 {
        return p.unimplemented(nr::sendmsg, "sendmsg", "ancillary data (SCM_RIGHTS, ...)", EOPNOTSUPP);
    }
    if is_netlink(&file) {
        let bufs = iovecs(p, m.iov, m.iovlen)?;
        return netlink_send(p, &file, &bufs);
    }
    if is_unbound(&file) {
        return if m.name != 0 {
            p.unimplemented(nr::sendmsg, "sendmsg", UNIX_PATHS, EOPNOTSUPP)
        } else {
            Err(ENOTCONN)
        };
    }
    if m.name != 0 {
        return Err(EISCONN);
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
    let file = socket_file(p, fd)?;
    let m = read_msghdr(p, msg)?;
    if is_netlink(&file) {
        let bufs = iovecs(p, m.iov, m.iovlen)?;
        let (n, full) = recv_netlink(p, &file, &bufs, flags)?;
        if m.name != 0 {
            let room = read_u32(&mut p.aspace, msg + 8)? as usize;
            let sa = netlink::sockaddr(0);
            copy_out(&mut p.aspace, m.name, &sa[..room.min(sa.len())])?;
            write_u32(&mut p.aspace, msg + 8, sa.len() as u32)?;
        }
        write_u64(&mut p.aspace, msg + 40, 0)?;
        write_u32(&mut p.aspace, msg + 48, if full > n { MSG_TRUNC as u32 } else { 0 })?;
        return Ok(if flags & MSG_TRUNC != 0 { full } else { n });
    }
    if is_unbound(&file) {
        return Err(ENOTCONN);
    }
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
    let file = socket_file(p, fd)?;
    let netlink = is_netlink(&file);
    let unix_type = match file.lock().kind {
        FileKind::UnixUnbound(ty) => ty,
        _ => SOCK_STREAM,
    };
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
        SO_TYPE if netlink => SOCK_RAW as u32,
        SO_TYPE => unix_type as u32,
        SO_ERROR | SO_ACCEPTCONN => 0,
        SO_SNDBUF | SO_RCVBUF => ipc::PIPE_CAPACITY as u32,
        SO_DOMAIN if netlink => AF_NETLINK as u32,
        SO_DOMAIN => AF_UNIX as u32,
        _ => return Err(ENOPROTOOPT),
    };
    if read_u32(&mut p.aspace, len)? < 4 {
        return Err(EINVAL);
    }
    write_u32(&mut p.aspace, val, v)?;
    write_u32(&mut p.aspace, len, 4).map(|_| 0)
}

/// Common options are accepted and ignored: they don't change local socket
/// pairs, and netlink options (extended acks, strict checking, group
/// membership) don't change what a socket that only knows `lo` says.
pub fn setsockopt(p: &mut Process, fd: u64, level: u64, _name: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if level != SOL_SOCKET && !(level == SOL_NETLINK && is_netlink(&file)) {
        return Err(ENOPROTOOPT);
    }
    Ok(0)
}

pub fn shutdown(p: &mut Process, fd: u64, how: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    let mut f = file.lock();
    match f.kind {
        FileKind::Netlink(_) => return if how <= 2 { Ok(0) } else { Err(EINVAL) },
        FileKind::UnixUnbound(_) => return Err(ENOTCONN),
        _ => {}
    }
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

/// getsockname (`peer` false) and getpeername.
pub fn getname(p: &mut Process, fd: u64, addr: u64, addrlen: u64, peer: bool) -> SysResult {
    let file = socket_file(p, fd)?;
    let port = match &file.lock().kind {
        FileKind::Netlink(nl) => Some(if peer { 0 } else { nl.port }),
        _ => None,
    };
    match port {
        Some(port) => write_addr(p, addr, addrlen, &netlink::sockaddr(port)).map(|_| 0),
        None => unnamed_addr(p, addr, addrlen).map(|_| 0),
    }
}
