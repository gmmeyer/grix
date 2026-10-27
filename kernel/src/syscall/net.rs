//! Socket syscalls: local AF_UNIX stream pairs (socketpair), NETLINK_ROUTE
//! sockets that describe `lo` (netlink.rs), and AF_INET/AF_INET6 sockets
//! whose connections the host makes (inet.rs). Creating network sockets is
//! gated by `net`. The per-socket calls here need no capability: they only
//! act on sockets that already exist.

use alloc::vec::Vec;
use grix_abi::policy::Capability;

use super::file::{pipe_read, pipe_write};
use super::{require, table::nr};
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, FileRef, O_NONBLOCK, O_RDWR, new_file};
use crate::inet::{self, Conn, ConnState, Dns, ECONNREFUSED, Inet, Listener, Pending, SockAddr, State};
use crate::ipc;
use crate::netlink::{self, MAX_REQUEST, Netlink};
use crate::process::Process;
use crate::uaccess::*;
use grix_abi::link::{self, Addr};

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
const ENETUNREACH: Errno = Errno(101);

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
            let file = new_file(FileKind::Netlink(Netlink::new(p.pid)), flags);
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
        AF_INET | AF_INET6 => new_inet(p, domain, ty, proto, flags, cloexec),
        _ => {
            require(p, nr::socket, Capability::Net, "")?;
            p.unimplemented(nr::socket, "socket", "this address family", EAFNOSUPPORT)
        }
    }
}

fn socket_file(p: &Process, fd: u64) -> Result<FileRef, Errno> {
    let file = p.fds.get(fd)?;
    if !matches!(
        file.lock().kind,
        FileKind::Socket(_) | FileKind::Netlink(_) | FileKind::UnixUnbound(_) | FileKind::Inet(_)
    ) {
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
pub fn connect(p: &mut Process, fd: u64, addr: u64, len: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        let mut of = file.lock();
        let nonblock = of.nonblocking();
        let FileKind::Inet(s) = &mut of.kind else { unreachable!() };
        return inet_connect(p, s, nonblock, addr, len);
    }
    match file.lock().kind {
        FileKind::Netlink(_) => return Ok(0),
        FileKind::Socket(_) => return Err(EISCONN),
        _ => {}
    }
    p.unimplemented(nr::connect, "connect", UNIX_PATHS, EOPNOTSUPP)
}

pub fn listen(p: &mut Process, fd: u64, backlog: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        return with_inet(p, fd, |_, s, _| inet_listen(s, backlog))?;
    }
    match file.lock().kind {
        FileKind::Netlink(_) => return Err(EOPNOTSUPP),
        FileKind::Socket(_) => return Err(EINVAL),
        _ => {}
    }
    p.unimplemented(nr::listen, "listen", UNIX_PATHS, EOPNOTSUPP)
}

fn is_netlink(file: &FileRef) -> bool {
    matches!(file.lock().kind, FileKind::Netlink(_))
}

/// bind(2): only netlink sockets can be bound (to a port id). Socket pairs
/// are already connected.
pub fn bind(p: &mut Process, fd: u64, addr: u64, len: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        return with_inet(p, fd, |p, s, _| inet_bind(p, s, addr, len))?;
    }
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
    let Some((dgram, _)) = nl.rx.front() else {
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
pub fn sendto(p: &mut Process, fd: u64, buf: u64, len: u64, flags: u64, addr: u64, addrlen: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        let to = if addr != 0 { Some(read_sockaddr(p, addr, addrlen)?) } else { None };
        return inet_send(p, fd, &[(buf, len)], flags, to);
    }
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
    if is_inet(&file) {
        let (n, from, v6) = inet_recv(p, fd, &[(buf, len)], flags)?;
        if let Some(from) = from {
            write_addr(p, addr, addrlen, &from.encode(v6))?;
        }
        return Ok(n);
    }
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
    if is_inet(&file) {
        let to = if m.name != 0 {
            let len = read_u32(&mut p.aspace, msg + 8)? as u64;
            Some(read_sockaddr(p, m.name, len)?)
        } else {
            None
        };
        let bufs = iovecs(p, m.iov, m.iovlen)?;
        return inet_send(p, fd, &bufs, flags, to);
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
    if is_inet(&file) {
        let bufs = iovecs(p, m.iov, m.iovlen)?;
        let (n, from, v6) = inet_recv(p, fd, &bufs, flags)?;
        if m.name != 0 {
            match from {
                Some(from) => {
                    let sa = from.encode(v6);
                    let room = read_u32(&mut p.aspace, msg + 8)? as usize;
                    copy_out(&mut p.aspace, m.name, &sa[..room.min(sa.len())])?;
                    write_u32(&mut p.aspace, msg + 8, sa.len() as u32)?;
                }
                None => write_u32(&mut p.aspace, msg + 8, 0)?,
            }
        }
        write_u64(&mut p.aspace, msg + 40, 0)?;
        write_u32(&mut p.aspace, msg + 48, 0)?;
        return Ok(n);
    }
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

const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
/// The y2038-safe names (same layout as the old ones on arm64).
const SO_RCVTIMEO_NEW: u64 = 66;
const SO_SNDTIMEO_NEW: u64 = 67;

fn is_timeout(name: u64) -> bool {
    matches!(name, SO_RCVTIMEO | SO_SNDTIMEO | SO_RCVTIMEO_NEW | SO_SNDTIMEO_NEW)
}

pub fn getsockopt(p: &mut Process, fd: u64, level: u64, name: u64, val: u64, len: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) && level == SOL_SOCKET && is_timeout(name) {
        let t = with_inet(
            p,
            fd,
            |_, s, _| if matches!(name, SO_RCVTIMEO | SO_RCVTIMEO_NEW) { s.rcvtimeo } else { s.sndtimeo },
        )?;
        let ns = t.unwrap_or(0);
        if read_u32(&mut p.aspace, len)? < 16 {
            return Err(EINVAL);
        }
        let mut tv = [0u8; 16];
        tv[..8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
        tv[8..].copy_from_slice(&(ns % 1_000_000_000 / 1000).to_le_bytes());
        copy_out(&mut p.aspace, val, &tv)?;
        return write_u32(&mut p.aspace, len, 16).map(|_| 0);
    }
    if is_inet(&file) {
        let v = with_inet(p, fd, |p, s, _| inet_getsockopt(p, s, level, name))??;
        if read_u32(&mut p.aspace, len)? < 4 {
            return Err(EINVAL);
        }
        write_u32(&mut p.aspace, val, v)?;
        return write_u32(&mut p.aspace, len, 4).map(|_| 0);
    }
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
pub fn setsockopt(p: &mut Process, fd: u64, level: u64, name: u64, val: u64, len: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    // TCP and IP options don't change connections the host makes.
    if is_inet(&file) && matches!(level, IPPROTO_IP | IPPROTO_TCP | IPPROTO_IPV6 | IPPROTO_UDP) {
        return Ok(0);
    }
    if is_inet(&file) && level == SOL_SOCKET && is_timeout(name) {
        if len < 16 {
            return Err(EINVAL);
        }
        // A struct timeval (64-bit fields on arm64, for both variants).
        let sec = read_u64(&mut p.aspace, val)? as i64;
        let usec = read_u64(&mut p.aspace, val + 8)? as i64;
        if sec < 0 || !(0..1_000_000).contains(&usec) {
            return Err(EDOM);
        }
        let ns = (sec as u64).saturating_mul(1_000_000_000).saturating_add(usec as u64 * 1000);
        // Zero: no timeout.
        let t = (ns > 0).then_some(ns);
        return with_inet(p, fd, |_, s, _| {
            *if matches!(name, SO_RCVTIMEO | SO_RCVTIMEO_NEW) { &mut s.rcvtimeo } else { &mut s.sndtimeo } = t;
            0
        });
    }
    if level != SOL_SOCKET && !(level == SOL_NETLINK && is_netlink(&file)) {
        return Err(ENOPROTOOPT);
    }
    Ok(0)
}

pub fn shutdown(p: &mut Process, fd: u64, how: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        return with_inet(p, fd, |_, s, _| inet_shutdown(s, how))?;
    }
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
    if is_inet(&file) {
        let (sa, v6) = with_inet(p, fd, |_, s, _| (if peer { s.peer_addr() } else { Some(s.local_addr()) }, s.v6))?;
        let sa = sa.ok_or(Errno(107))?; // ENOTCONN
        return write_addr(p, addr, addrlen, &sa.encode(v6)).map(|_| 0);
    }
    let port = match &file.lock().kind {
        FileKind::Netlink(nl) => Some(if peer { 0 } else { nl.port }),
        _ => None,
    };
    match port {
        Some(port) => write_addr(p, addr, addrlen, &netlink::sockaddr(port)).map(|_| 0),
        None => unnamed_addr(p, addr, addrlen).map(|_| 0),
    }
}

// ---------------------------------------------------------------- AF_INET / AF_INET6 (inet.rs)

const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const IPPROTO_IP: u64 = 0;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;
const IPPROTO_IPV6: u64 = 41;
const EINPROGRESS: Errno = Errno(115);
const EALREADY: Errno = Errno(114);
const EADDRNOTAVAIL: Errno = Errno(99);
const EDESTADDRREQ: Errno = Errno(89);
/// The most a read takes at once (bounded by what's buffered anyway).
const READ_MAX: usize = 64 * 1024;

fn new_inet(p: &mut Process, domain: u64, ty: u64, proto: u64, flags: u32, cloexec: bool) -> SysResult {
    require(p, nr::socket, Capability::Net, "")?;
    let dgram = match (ty & 0xf, proto) {
        (SOCK_STREAM, 0 | IPPROTO_TCP) => false,
        (SOCK_DGRAM, 0 | IPPROTO_UDP) => true,
        (SOCK_STREAM | SOCK_DGRAM, _) => return Err(EPROTONOSUPPORT),
        (SOCK_RAW, _) => return p.unimplemented(nr::socket, "socket", "raw IP sockets", EPROTONOSUPPORT),
        _ => return Err(ESOCKTNOSUPPORT),
    };
    let file = new_file(FileKind::Inet(Inet::new(domain == AF_INET6, dgram)), flags);
    p.fds.alloc(FdEntry { file, cloexec }, 0)
}

fn read_sockaddr(p: &mut Process, addr: u64, len: u64) -> Result<SockAddr, Errno> {
    if !(2..=128).contains(&len) {
        return Err(EINVAL);
    }
    let mut b = alloc::vec![0u8; len as usize];
    copy_in(&mut p.aspace, addr, &mut b)?;
    SockAddr::decode(&b)
}

/// Run `f` on the AF_INET socket at `fd`.
fn with_inet<R>(p: &mut Process, fd: u64, f: impl FnOnce(&mut Process, &mut Inet, u32) -> R) -> Result<R, Errno> {
    let file = socket_file(p, fd)?;
    let mut of = file.lock();
    let flags = of.flags;
    let FileKind::Inet(s) = &mut of.kind else { return Err(ENOTSOCK) };
    Ok(f(p, s, flags))
}

fn is_inet(file: &FileRef) -> bool {
    matches!(file.lock().kind, FileKind::Inet(_))
}

fn inet_bind(p: &mut Process, s: &mut Inet, addr: u64, len: u64) -> SysResult {
    let a = read_sockaddr(p, addr, len)?;
    if s.bound.is_some() || !matches!(s.state, State::Idle) {
        return Err(EINVAL);
    }
    let ours = a.is_unspecified() || a.is_loopback() || a.addr == Addr::V4(link::GUEST_V4);
    if !ours {
        return Err(EADDRNOTAVAIL);
    }
    if !s.dgram && a.port != 0 && Listener::is_bound(a.port) {
        return Err(Errno(98)); // EADDRINUSE
    }
    // Port 0 means one is picked now, as Linux does at bind (getsockname
    // reports it before listen).
    let port = if a.port != 0 {
        a.port
    } else {
        (0..1000).map(|_| inet::ephemeral_port()).find(|&p| !Listener::is_bound(p)).ok_or(Errno(98))?
    };
    s.bound = Some(SockAddr { port, ..a });
    Ok(0)
}

fn inet_listen(s: &mut Inet, backlog: u64) -> SysResult {
    if s.dgram {
        return Err(EOPNOTSUPP);
    }
    match s.state {
        State::Listening(_) => return Ok(0),
        State::Idle => {}
        _ => return Err(EINVAL),
    }
    let unspecified = if s.v6 { SockAddr { addr: Addr::V6([0; 16]), port: 0 } } else { SockAddr::UNSPECIFIED_V4 };
    let bound = s.bound.unwrap_or(unspecified);
    let l = Listener::listen(bound.addr, bound.port, (backlog as i32).max(1) as usize)?;
    s.bound = Some(SockAddr { port: l.lock().port, ..bound });
    s.state = State::Listening(l);
    Ok(0)
}

pub fn accept4(p: &mut Process, fd: u64, addr: u64, addrlen: u64, flags: u64) -> SysResult {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let file = socket_file(p, fd)?;
    let mut of = file.lock();
    let nonblock = of.nonblocking();
    let FileKind::Inet(s) = &mut of.kind else {
        return Err(if matches!(of.kind, FileKind::Netlink(_)) { EOPNOTSUPP } else { EINVAL });
    };
    let State::Listening(l) = &s.state else { return Err(EINVAL) };
    // Leave the connection queued if there's no descriptor for it.
    if !p.fds.has_room() {
        return Err(EMFILE);
    }
    let Some(pending) = l.lock().queue.pop_front() else {
        let timeout = s.rcvtimeo;
        drop(of);
        return wait(p, nonblock, timeout, EAGAIN);
    };
    let v6 = s.v6;
    drop(of);
    let mut new = Inet::new(v6, false);
    let peer = match pending {
        Pending::Local { end, peer, local, .. } => {
            new.bound = Some(local);
            new.state = State::Local { end, local, peer };
            peer
        }
        Pending::Remote(c, _) => {
            let (local, peer) = {
                let c = c.lock();
                (c.local, c.peer)
            };
            new.bound = Some(local);
            new.state = State::Remote(c);
            peer
        }
    };
    let fflags = O_RDWR | if flags & SOCK_NONBLOCK != 0 { O_NONBLOCK } else { 0 };
    let nfd =
        p.fds.alloc(FdEntry { file: new_file(FileKind::Inet(new), fflags), cloexec: flags & SOCK_CLOEXEC != 0 }, 0)?;
    if let Err(e) = write_addr(p, addr, addrlen, &peer.encode(v6)) {
        let _ = p.fds.close(nfd);
        return Err(e);
    }
    Ok(nfd)
}

fn inet_connect(p: &mut Process, s: &mut Inet, nonblock: bool, addr: u64, len: u64) -> SysResult {
    let to = read_sockaddr(p, addr, len)?;
    if s.dgram {
        // Nothing is sent: resolvers and "what's my address" code connect a
        // UDP socket just to see the route. Only DNS goes anywhere (sends
        // elsewhere are reported).
        let ours = if to.is_loopback() { to.addr } else { Addr::V4(link::GUEST_V4) };
        s.bound.get_or_insert(SockAddr { addr: ours, port: inet::ephemeral_port() });
        s.peer = Some(to);
        return Ok(0);
    }
    match &s.state {
        State::Remote(c) => {
            let state = c.lock().state;
            return match state {
                ConnState::Connecting if s.connecting && !nonblock => wait(p, false, s.sndtimeo, EINPROGRESS),
                ConnState::Connecting => Err(EALREADY),
                ConnState::Open if core::mem::take(&mut s.connecting) => Ok(0),
                ConnState::Open => Err(EISCONN),
                ConnState::Failed(e) => {
                    s.connecting = false;
                    s.state = State::Idle;
                    Err(e)
                }
            };
        }
        State::Local { .. } => return Err(EISCONN),
        State::Listening(_) | State::Dns(_) => return Err(EINVAL),
        State::Idle => {}
    }
    if to.is_local() {
        let (end, local) = inet::connect_local(to)?;
        s.state = State::Local { end, local, peer: to };
        return Ok(0);
    }
    if to.is_unspecified() || to.port == 0 {
        return Err(ECONNREFUSED);
    }
    s.state = State::Remote(Conn::connect(to)?);
    if nonblock {
        return Err(EINPROGRESS);
    }
    s.connecting = true;
    wait(p, false, s.sndtimeo, EINPROGRESS)
}

/// Wait for the socket to change, for at most `timeout` (SO_RCVTIMEO or
/// SO_SNDTIMEO); then the call fails with `expired`.
fn wait(p: &mut Process, nonblock: bool, timeout: Option<u64>, expired: Errno) -> SysResult {
    if nonblock {
        return Err(EAGAIN);
    }
    let deadline = p.timeout_deadline(timeout);
    p.block_io(deadline, Err(expired))
}

/// A pipe read or write on a loopback socket, waiting as long as the
/// socket's timeout allows.
fn local_io(
    p: &mut Process,
    nonblock: bool,
    timeout: Option<u64>,
    io: impl FnOnce(&mut Process) -> SysResult,
) -> SysResult {
    match io(p) {
        Err(EAGAIN) => wait(p, nonblock, timeout, EAGAIN),
        r => r,
    }
}

/// Read from a connected stream socket (or a DNS answer from a UDP one).
/// Returns (bytes, where they came from).
pub(super) fn inet_read(
    p: &mut Process,
    s: &Inet,
    buf: u64,
    count: u64,
    nonblock: bool,
    peek: bool,
) -> Result<(u64, Option<SockAddr>), Errno> {
    match &s.state {
        State::Remote(c) => {
            let mut chunk = [0u8; super::file::CHUNK];
            let mut done = 0usize;
            let want = (count as usize).min(READ_MAX);
            let peer = c.lock().peer;
            // Peeking looks at most one chunk.
            while done < want {
                let n = (want - done).min(chunk.len());
                let got = c.lock().read(&mut chunk[..n], peek);
                match got {
                    Some(Ok(0)) => break,
                    Some(Ok(k)) => {
                        copy_out(&mut p.aspace, buf + done as u64, &chunk[..k])?;
                        done += k;
                        if peek || k < n {
                            break;
                        }
                    }
                    Some(Err(e)) if done == 0 => return Err(e),
                    Some(Err(_)) => break,
                    None if done == 0 => return wait(p, nonblock, s.rcvtimeo, EAGAIN).map(|n| (n, None)),
                    None => break,
                }
            }
            Ok((done as u64, Some(peer)))
        }
        State::Local { end, peer, .. } => match &end.rx {
            Some(rx) => local_io(p, nonblock, s.rcvtimeo, |p| pipe_read(p, rx, buf, count, true, peek))
                .map(|n| (n, Some(*peer))),
            None => Ok((0, Some(*peer))),
        },
        State::Dns(d) => {
            let mut d = d.lock();
            let answer = if peek { d.peek() } else { d.answer() };
            let Some(answer) = answer else {
                drop(d);
                return wait(p, nonblock, s.rcvtimeo, EAGAIN).map(|n| (n, None));
            };
            let from = d.server_of(&answer);
            drop(d);
            let n = (count as usize).min(answer.len());
            copy_out(&mut p.aspace, buf, &answer[..n])?;
            Ok((n as u64, Some(from)))
        }
        State::Idle if s.dgram => wait(p, nonblock, s.rcvtimeo, EAGAIN).map(|n| (n, None)),
        State::Idle | State::Listening(_) => Err(ENOTCONN),
    }
}

/// Write to a connected stream socket, or send a datagram (`to`, or where
/// connect pointed it): only DNS queries go anywhere.
pub(super) fn inet_write(
    p: &mut Process,
    s: &mut Inet,
    buf: u64,
    count: u64,
    nonblock: bool,
    sigpipe: bool,
    to: Option<SockAddr>,
) -> SysResult {
    let epipe = |p: &mut Process| {
        if sigpipe {
            crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a connection that was shut down");
        }
        Err(EPIPE)
    };
    if s.dgram {
        let to = to.or(s.peer).ok_or(EDESTADDRREQ)?;
        if to.port != 53 {
            return p.unimplemented(nr::sendto, "sendto", "UDP sockets other than DNS", ENETUNREACH);
        }
        if count > link::MAX_DATA as u64 - 8 {
            return Err(EMSGSIZE);
        }
        let mut q = alloc::vec![0u8; count as usize];
        copy_in(&mut p.aspace, buf, &mut q)?;
        dns_ready(s);
        let State::Dns(d) = &s.state else { return Err(EDESTADDRREQ) };
        let mut d = d.lock();
        d.sent_to(&q, to);
        d.query(&q);
        return Ok(count);
    }
    match &s.state {
        State::Remote(c) => {
            const DATA: usize = crate::console::WRITE_CHUNK - 5;
            let mut chunk = [0u8; DATA];
            let mut done = 0u64;
            while done < count {
                let (id, room) = {
                    let c = c.lock();
                    match c.state {
                        ConnState::Connecting => break,
                        ConnState::Failed(e) if done == 0 => return Err(e),
                        ConnState::Failed(_) => break,
                        ConnState::Open if c.tx_shut && done == 0 => {
                            drop(c);
                            return epipe(p);
                        }
                        ConnState::Open => (c.id, if c.tx_shut { 0 } else { c.tx_credit as usize }),
                    }
                };
                let n = ((count - done) as usize).min(room).min(DATA);
                if n == 0 {
                    break;
                }
                copy_in(&mut p.aspace, buf + done, &mut chunk[..n])?;
                let msg = link::ToHost::Data { id, data: &chunk[..n] }.encode();
                if !crate::console::try_write(grix_abi::wire::Channel::Link, &msg) {
                    break;
                }
                c.lock().sent(n);
                done += n as u64;
            }
            if done > 0 || count == 0 { Ok(done) } else { wait(p, nonblock, s.sndtimeo, EAGAIN) }
        }
        State::Local { end, .. } => match &end.tx {
            Some(tx) => local_io(p, nonblock, s.sndtimeo, |p| pipe_write(p, tx, buf, count, true, sigpipe)),
            None => epipe(p),
        },
        _ => Err(ENOTCONN),
    }
}

pub(super) fn inet_available(s: &Inet) -> usize {
    match &s.state {
        State::Remote(c) => c.lock().available(),
        State::Local { end, .. } => end.rx.as_ref().map_or(0, |r| r.pipe.lock().buf.len()),
        State::Dns(d) => d.lock().peek_len().unwrap_or(0),
        _ => 0,
    }
}

/// A UDP socket about to send: give it its DNS channel.
fn dns_ready(s: &mut Inet) {
    if s.dgram && matches!(s.state, State::Idle) {
        s.state = State::Dns(Dns::new());
    }
}

fn inet_send(p: &mut Process, fd: u64, bufs: &[(u64, u64)], flags: u64, to: Option<SockAddr>) -> SysResult {
    let file = socket_file(p, fd)?;
    let mut of = file.lock();
    let nonblock = of.nonblocking() || flags & MSG_DONTWAIT != 0;
    let FileKind::Inet(s) = &mut of.kind else { return Err(ENOTSOCK) };
    dns_ready(s);
    if s.dgram {
        // One datagram: gather the iovecs.
        let total = bufs.iter().try_fold(0u64, |t, b| t.checked_add(b.1)).ok_or(EINVAL)?;
        if total > link::MAX_DATA as u64 - 8 {
            return Err(EMSGSIZE);
        }
        let mut q = Vec::with_capacity(total as usize);
        for &(base, len) in bufs {
            let at = q.len();
            q.resize(at + len as usize, 0);
            copy_in(&mut p.aspace, base, &mut q[at..])?;
        }
        let dest = to.or(s.peer).ok_or(EDESTADDRREQ)?;
        if dest.port != 53 {
            return p.unimplemented(nr::sendto, "sendto", "UDP sockets other than DNS", ENETUNREACH);
        }
        let State::Dns(d) = &s.state else { return Err(EDESTADDRREQ) };
        let mut d = d.lock();
        d.sent_to(&q, dest);
        d.query(&q);
        return Ok(total);
    }
    let mut total = 0;
    for (i, &(base, len)) in bufs.iter().enumerate() {
        let nonblock = nonblock || i > 0;
        match inet_write(p, s, base, len, nonblock, flags & MSG_NOSIGNAL == 0, None) {
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

fn inet_recv(
    p: &mut Process,
    fd: u64,
    bufs: &[(u64, u64)],
    flags: u64,
) -> Result<(u64, Option<SockAddr>, bool), Errno> {
    let file = socket_file(p, fd)?;
    let of = file.lock();
    let nonblock = of.nonblocking() || flags & MSG_DONTWAIT != 0;
    let FileKind::Inet(s) = &of.kind else { return Err(ENOTSOCK) };
    let peek = flags & MSG_PEEK != 0;
    let v6 = s.v6;
    let mut total = 0;
    let mut from = None;
    for (i, &(base, len)) in bufs.iter().enumerate() {
        let nonblock = nonblock || i > 0;
        match inet_read(p, s, base, len, nonblock, peek) {
            Ok((n, f)) => {
                total += n;
                from = from.or(f);
                // A datagram is read once, into the first buffer.
                if n < len || s.dgram {
                    break;
                }
            }
            Err(e) if total == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok((total, from, v6))
}

fn inet_getsockopt(p: &mut Process, s: &Inet, level: u64, name: u64) -> Result<u32, Errno> {
    const SO_TYPE: u64 = 3;
    const SO_ERROR: u64 = 4;
    const SO_SNDBUF: u64 = 7;
    const SO_RCVBUF: u64 = 8;
    const SO_KEEPALIVE: u64 = 9;
    const SO_REUSEADDR: u64 = 2;
    const SO_ACCEPTCONN: u64 = 30;
    const SO_PROTOCOL: u64 = 38;
    const SO_DOMAIN: u64 = 39;
    const TCP_NODELAY: u64 = 1;
    const IPV6_V6ONLY: u64 = 26;
    let _ = p;
    Ok(match (level, name) {
        (SOL_SOCKET, SO_TYPE) => (if s.dgram { SOCK_DGRAM } else { SOCK_STREAM }) as u32,
        (SOL_SOCKET, SO_ERROR) => match &s.state {
            State::Remote(c) => match c.lock().state {
                ConnState::Failed(e) => e.0,
                _ => 0,
            },
            _ => 0,
        },
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => link::WINDOW,
        (SOL_SOCKET, SO_KEEPALIVE | SO_REUSEADDR) => 0,
        (SOL_SOCKET, SO_ACCEPTCONN) => matches!(s.state, State::Listening(_)) as u32,
        (SOL_SOCKET, SO_PROTOCOL) => (if s.dgram { IPPROTO_UDP } else { IPPROTO_TCP }) as u32,
        (SOL_SOCKET, SO_DOMAIN) => (if s.v6 { AF_INET6 } else { AF_INET }) as u32,
        (IPPROTO_TCP, TCP_NODELAY) => 1,
        (IPPROTO_IPV6, IPV6_V6ONLY) => 0,
        (IPPROTO_TCP | IPPROTO_IP | IPPROTO_IPV6, _) => 0,
        _ => return Err(ENOPROTOOPT),
    })
}

fn inet_shutdown(s: &mut Inet, how: u64) -> SysResult {
    if how > 2 {
        return Err(EINVAL);
    }
    let (rd, wr) = (how != 1, how != 0);
    match &mut s.state {
        State::Remote(c) => {
            let mut c = c.lock();
            if wr {
                c.shutdown_write();
            }
            if rd {
                c.shutdown_read();
            }
        }
        State::Local { end, .. } => {
            if rd {
                end.rx = None;
            }
            if wr {
                end.tx = None;
            }
        }
        State::Listening(_) => {}
        State::Idle | State::Dns(_) => return Err(ENOTCONN),
    }
    Ok(0)
}
