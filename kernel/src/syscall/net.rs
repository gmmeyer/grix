//! Socket syscalls: local AF_UNIX stream pairs (socketpair), NETLINK_ROUTE
//! sockets that describe `lo` (netlink.rs), and AF_INET/AF_INET6 sockets
//! whose connections the host makes (inet.rs). Creating network sockets is
//! gated by `net`. The per-socket calls here need no capability: they only
//! act on sockets that already exist.

use alloc::vec::Vec;
use grix_abi::policy::Capability;

use super::file::{Src, pipe_read, pipe_write};
use super::{require, table::nr};
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, FileRef, O_NONBLOCK, O_RDWR, new_file};
use crate::inet::{self, Conn, ConnState, ECONNREFUSED, Inet, Listener, Pending, SockAddr, State, Udp, UdpRef};
use crate::ipc;
use crate::netlink::{self, MAX_REQUEST, Netlink};
use crate::process::Process;
use crate::uaccess::*;
use grix_abi::link::{self, Addr};

const AF_UNIX: u64 = 1;
const AF_NETLINK: u64 = netlink::AF_NETLINK as u64;
const NETLINK_ROUTE: u64 = 0;
const NETLINK_KOBJECT_UEVENT: u64 = 15;
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
    let (a, b) = super::unix::pair(p, ty & 0xf)?;
    let flags = O_RDWR | if ty & SOCK_NONBLOCK != 0 { O_NONBLOCK } else { 0 };
    let cloexec = ty & SOCK_CLOEXEC != 0;
    let fa = p.fds.alloc(FdEntry { file: new_file(a, flags), cloexec }, 0)?;
    let fb = match p.fds.alloc(FdEntry { file: new_file(b, flags), cloexec }, 0) {
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
            if proto != NETLINK_ROUTE && proto != NETLINK_KOBJECT_UEVENT {
                return p.unimplemented(
                    nr::socket,
                    "socket",
                    "netlink protocols other than NETLINK_ROUTE and NETLINK_KOBJECT_UEVENT",
                    EPROTONOSUPPORT,
                );
            }
            let mut nl = Netlink::new(p.pid);
            nl.uevent = proto == NETLINK_KOBJECT_UEVENT;
            let file = new_file(FileKind::Netlink(nl), flags);
            p.fds.alloc(FdEntry { file, cloexec }, 0)
        }
        // Local IPC, so not gated by `net` (binding to a path needs
        // `fs_write`). Interface ioctls work on it too (musl's
        // if_nametoindex).
        AF_UNIX => {
            if !matches!(ty & 0xf, SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET) {
                return Err(ESOCKTNOSUPPORT);
            }
            let file = new_file(super::unix::new(p, ty & 0xf), flags);
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
        FileKind::Socket(_) | FileKind::Netlink(_) | FileKind::UnixUnbound(_) | FileKind::Inet(_) | FileKind::Unix(_)
    ) {
        return Err(ENOTSOCK);
    }
    Ok(file)
}

fn is_unbound(file: &FileRef) -> bool {
    matches!(file.lock().kind, FileKind::UnixUnbound(_))
}

/// An AF_UNIX socket that isn't a connected stream.
fn is_unix(file: &FileRef) -> bool {
    matches!(file.lock().kind, FileKind::UnixUnbound(_) | FileKind::Unix(_))
}

/// connect(2). A netlink socket "connects" to the kernel; socket pairs are
/// already connected.
pub fn connect(p: &mut Process, fd: u64, addr: u64, len: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        let raw = read_addr_bytes(p, addr, len)?;
        let mut of = file.lock();
        let nonblock = of.nonblocking();
        let FileKind::Inet(s) = &mut of.kind else { unreachable!() };
        return inet_connect(p, s, nonblock, &raw);
    }
    match file.lock().kind {
        FileKind::Netlink(_) => return Ok(0),
        FileKind::Socket(_) => return Err(EISCONN),
        _ => {}
    }
    super::unix::connect(p, &file, addr, len)
}

pub fn listen(p: &mut Process, fd: u64, backlog: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        return with_inet(p, fd, |_, s, _| inet_listen(s))?;
    }
    match file.lock().kind {
        FileKind::Netlink(_) => return Err(EOPNOTSUPP),
        FileKind::Socket(_) => return Err(EINVAL),
        _ => {}
    }
    super::unix::listen(p, &file, backlog)
}

fn is_netlink(file: &FileRef) -> bool {
    matches!(file.lock().kind, FileKind::Netlink(_))
}

/// bind(2): only netlink sockets can be bound (to a port id). Socket pairs
/// are already connected.
pub fn bind(p: &mut Process, fd: u64, addr: u64, len: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        let raw = read_addr_bytes(p, addr, len)?;
        return with_inet(p, fd, |p, s, _| {
            if !s.dgram {
                crate::landlock::check_socket(p, s.v6, &raw, true)?;
            }
            inet_bind(s, &raw)
        })?;
    }
    if is_unix(&file) {
        return super::unix::bind(p, &file, addr, len);
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
    if let Some(sock) = super::unix::sock_of(&file) {
        let to = if addr != 0 { Some(super::unix::resolve_to(p, addr, addrlen)?) } else { None };
        let nonblock = file.lock().nonblocking();
        return super::unix::send_msg(p, &sock, &[(buf, len)], flags, nonblock, to, Default::default());
    }
    if is_unbound(&file) {
        return Err(if addr != 0 { EOPNOTSUPP } else { ENOTCONN });
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
        Some(tx) => pipe_write(p, tx, Src::User(buf), len, nonblock, flags & MSG_NOSIGNAL == 0),
        None => {
            if flags & MSG_NOSIGNAL == 0 {
                crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a socket that was shut down");
            }
            Err(EPIPE)
        }
    }
}

/// `send` with descriptors attached (SCM_RIGHTS on a connected stream),
/// or credentials (SCM_CREDENTIALS).
fn send_rights(
    p: &mut Process,
    file: &FileRef,
    buf: u64,
    len: u64,
    flags: u64,
    r: Option<crate::unix::Rights>,
    cred: Option<crate::unix::Cred>,
) -> SysResult {
    let f = file.lock();
    let nonblock = f.nonblocking() || flags & MSG_DONTWAIT != 0;
    let FileKind::Socket(s) = &f.kind else { return Err(ENOTSOCK) };
    match &s.tx {
        Some(tx) => super::unix::send_stream(p, tx, buf, len, nonblock, flags & MSG_NOSIGNAL == 0, r, cred),
        None => Err(EPIPE),
    }
}

fn recv(p: &mut Process, file: &FileRef, buf: u64, len: u64, flags: u64) -> SysResult {
    let f = file.lock();
    let nonblock = f.nonblocking() || flags & MSG_DONTWAIT != 0;
    let FileKind::Socket(s) = &f.kind else { return Err(ENOTSOCK) };
    let peek = flags & MSG_PEEK != 0;
    match &s.rx {
        // With SO_PASSCRED, one writer's bytes at a time.
        Some(rx) if super::unix::stream_passcred(s) => {
            super::unix::recv_stream(p, rx, buf, len, nonblock, peek, &mut Vec::new(), Some(&mut None))
        }
        Some(rx) => pipe_read(p, rx, buf, len, nonblock, peek),
        None => Ok(0),
    }
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
    if let Some(sock) = super::unix::sock_of(&file) {
        let nonblock = file.lock().nonblocking();
        let r = super::unix::recv_msg(p, &sock, &[(buf, len)], flags, nonblock)?;
        super::unix::write_from(p, addr, addrlen, r.from.as_ref())?;
        return Ok(if flags & MSG_TRUNC != 0 { r.full } else { r.n });
    }
    if is_unbound(&file) {
        return Err(ENOTCONN);
    }
    let n = recv(p, &file, buf, len, flags)?;
    let peer = super::unix::names(&file, true).ok().flatten();
    super::unix::write_from(p, addr, addrlen, peer.as_ref())?;
    Ok(n)
}

/// struct msghdr (arm64): name, namelen, iov, iovlen, control, controllen, flags.
struct MsgHdr {
    name: u64,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
}

fn read_msghdr(p: &mut Process, msg: u64) -> Result<MsgHdr, Errno> {
    let mut b = [0u8; 56];
    copy_in(&mut p.aspace, msg, &mut b)?;
    let w = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    Ok(MsgHdr { name: w(0), iov: w(16), iovlen: w(24), control: w(32), controllen: w(40) })
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
    let unix = is_unix(&file) || matches!(&file.lock().kind, FileKind::Socket(s) if s.unix.is_some());
    if m.controllen != 0 && !unix {
        return p.unimplemented(nr::sendmsg, "sendmsg", "ancillary data on this socket", EOPNOTSUPP);
    }
    let control = if unix { super::unix::read_control(p, m.control, m.controllen)? } else { Default::default() };
    if let Some(sock) = super::unix::sock_of(&file) {
        let to = if m.name != 0 {
            let len = read_u32(&mut p.aspace, msg + 8)? as u64;
            Some(super::unix::resolve_to(p, m.name, len)?)
        } else {
            None
        };
        let bufs = iovecs(p, m.iov, m.iovlen)?;
        let nonblock = file.lock().nonblocking();
        return super::unix::send_msg(p, &sock, &bufs, flags, nonblock, to, control);
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
        return Err(if m.name != 0 { EOPNOTSUPP } else { ENOTCONN });
    }
    if m.name != 0 {
        return Err(EISCONN);
    }
    let mut total = 0;
    // A stream's bytes carry who wrote them: SCM_CREDENTIALS's, or the
    // sender's.
    let cred = control.cred;
    let mut rights = control.rights;
    for (i, (base, len)) in iovecs(p, m.iov, m.iovlen)?.into_iter().enumerate() {
        // Only the first chunk may block, so a partial result is returned rather than lost.
        let flags = if i == 0 { flags } else { flags | MSG_DONTWAIT };
        // Descriptors go with the first byte sent.
        let sent = match rights.take() {
            Some(r) if len > 0 => send_rights(p, &file, base, len, flags, Some(r), cred),
            Some(r) => {
                rights = Some(r);
                Ok(0)
            }
            None if cred.is_some() => send_rights(p, &file, base, len, flags, None, cred),
            None => send(p, &file, base, len, flags),
        };
        match sent {
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

/// struct mmsghdr: a msghdr, then the length sent or received (padded to 64).
const MMSGHDR: u64 = 64;
/// Linux's UIO_MAXIOV: the most messages one call takes.
const MAX_MMSG: u64 = 1024;

/// sendmmsg: sendmsg for each message, stopping at the first that can't go
/// now (only the first may block). glibc's resolver sends its A and AAAA
/// queries this way.
pub fn sendmmsg(p: &mut Process, fd: u64, vec: u64, vlen: u64, flags: u64) -> SysResult {
    let mut sent = 0;
    for i in 0..vlen.min(MAX_MMSG) {
        let msg = vec + i * MMSGHDR;
        let flags = if i == 0 { flags } else { flags | MSG_DONTWAIT };
        match sendmsg(p, fd, msg, flags).and_then(|n| write_u32(&mut p.aspace, msg + 56, n as u32)) {
            Ok(_) => {}
            Err(e) if sent == 0 => return Err(e),
            Err(_) => break,
        }
        sent += 1;
    }
    Ok(sent)
}

/// recvmmsg: recvmsg for each message, waiting only for the first (as with
/// MSG_WAITFORONE; a caller always has to handle fewer than `vlen`, which a
/// timeout gives on Linux too).
pub fn recvmmsg(p: &mut Process, fd: u64, vec: u64, vlen: u64, flags: u64) -> SysResult {
    const MSG_WAITFORONE: u64 = 0x1_0000;
    let flags = flags & !MSG_WAITFORONE;
    let mut got = 0;
    for i in 0..vlen.min(MAX_MMSG) {
        let msg = vec + i * MMSGHDR;
        let flags = if i == 0 { flags } else { flags | MSG_DONTWAIT };
        // Once something was received, an error ends the batch with what
        // was (Linux reports the error on the next call).
        match recvmsg(p, fd, msg, flags).and_then(|n| write_u32(&mut p.aspace, msg + 56, n as u32)) {
            Ok(_) => {}
            Err(e) if got == 0 => return Err(e),
            Err(_) => break,
        }
        got += 1;
    }
    Ok(got)
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
    if let Some(sock) = super::unix::sock_of(&file) {
        let bufs = iovecs(p, m.iov, m.iovlen)?;
        let nonblock = file.lock().nonblocking();
        let r = super::unix::recv_msg(p, &sock, &bufs, flags, nonblock)?;
        let truncated = r.full > r.n;
        let anc = super::unix::Ancillary { rights: r.rights, cred: r.cred };
        super::unix::finish_recvmsg(p, msg, m.name, r.from.as_ref(), anc, flags, truncated)?;
        return Ok(if flags & MSG_TRUNC != 0 { r.full } else { r.n });
    }
    if is_unbound(&file) {
        return Err(ENOTCONN);
    }
    let mut total = 0;
    let mut rights = Vec::new();
    // With SO_PASSCRED, the writer's credentials, and only their bytes.
    let passcred = matches!(&file.lock().kind, FileKind::Socket(s) if super::unix::stream_passcred(s));
    let mut cred = None;
    for (i, (base, len)) in iovecs(p, m.iov, m.iovlen)?.into_iter().enumerate() {
        let flags = if i == 0 { flags } else { flags | MSG_DONTWAIT };
        let before = rights.len();
        let slot = if passcred { Some(&mut cred) } else { None };
        match recv_rights(p, &file, base, len, flags, &mut rights, slot) {
            Ok(n) => {
                total += n;
                // One batch of descriptors per call, as on Linux.
                if n < len || rights.len() > before {
                    break;
                }
            }
            Err(e) if total == 0 => return Err(e),
            Err(_) => break,
        }
    }
    let peer = super::unix::names(&file, true).ok().flatten();
    let anc = super::unix::Ancillary { rights, cred };
    super::unix::finish_recvmsg(p, msg, m.name, peer.as_ref(), anc, flags, false)?;
    Ok(total)
}

/// `recv`, taking descriptors that came with the bytes (and, with `cred`,
/// who wrote them).
fn recv_rights(
    p: &mut Process,
    file: &FileRef,
    buf: u64,
    len: u64,
    flags: u64,
    rights: &mut Vec<crate::unix::Rights>,
    cred: Option<&mut Option<crate::unix::Cred>>,
) -> SysResult {
    let f = file.lock();
    let nonblock = f.nonblocking() || flags & MSG_DONTWAIT != 0;
    let FileKind::Socket(s) = &f.kind else { return Err(ENOTSOCK) };
    match &s.rx {
        Some(rx) => super::unix::recv_stream(p, rx, buf, len, nonblock, flags & MSG_PEEK != 0, rights, cred),
        None => Ok(0),
    }
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
    let (unix_type, listening) = match &file.lock().kind {
        FileKind::UnixUnbound(ty) => (*ty, false),
        FileKind::Unix(s) => {
            let s = s.lock();
            (s.ty, matches!(s.state, crate::unix::State::Listening { .. }))
        }
        _ => (SOCK_STREAM, false),
    };
    const SO_PEERCRED: u64 = 17;
    if level == SOL_SOCKET && name == SO_PEERCRED && !netlink {
        if read_u32(&mut p.aspace, len)? < 12 {
            return Err(EINVAL);
        }
        let cred = super::unix::peer_cred(&file);
        copy_out(&mut p.aspace, val, &cred.bytes())?;
        return write_u32(&mut p.aspace, len, 12).map(|_| 0);
    }
    const SO_TYPE: u64 = 3;
    const SO_ERROR: u64 = 4;
    const SO_SNDBUF: u64 = 7;
    const SO_RCVBUF: u64 = 8;
    const SO_PASSCRED: u64 = 16;
    const SO_ACCEPTCONN: u64 = 30;
    const SO_DOMAIN: u64 = 39;
    if level != SOL_SOCKET {
        return Err(ENOPROTOOPT);
    }
    let v: u32 = match name {
        SO_TYPE if netlink => SOCK_RAW as u32,
        SO_TYPE => unix_type as u32,
        SO_ACCEPTCONN => listening as u32,
        SO_ERROR => 0,
        SO_SNDBUF | SO_RCVBUF => ipc::PIPE_CAPACITY as u32,
        SO_DOMAIN if netlink => AF_NETLINK as u32,
        SO_DOMAIN => AF_UNIX as u32,
        SO_PASSCRED => u32::from(match &file.lock().kind {
            FileKind::Unix(s) => s.lock().passcred,
            FileKind::Socket(end) => super::unix::stream_passcred(end),
            _ => false,
        }),
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
    const IPV6_V6ONLY: u64 = 26;
    // Which listener on a port takes v4 connections (Redis listens on
    // 0.0.0.0 and on [::] with it).
    if is_inet(&file) && (level, name) == (IPPROTO_IPV6, IPV6_V6ONLY) {
        if len < 4 {
            return Err(EINVAL);
        }
        let on = read_u32(&mut p.aspace, val)? != 0;
        return with_inet(p, fd, |_, s, _| {
            if !s.v6 {
                return Err(ENOPROTOOPT);
            }
            if s.bound.is_some() {
                return Err(EINVAL);
            }
            s.v6only = on;
            Ok(0)
        })?;
    }
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
    const SO_PASSCRED: u64 = 16;
    if level == SOL_SOCKET && name == SO_PASSCRED && !is_inet(&file) && !is_netlink(&file) {
        if len < 4 {
            return Err(EINVAL);
        }
        let on = read_u32(&mut p.aspace, val)? != 0;
        // Messages, or a stream's bytes, come with their senders'
        // credentials from now on. A socket not yet bound or connected
        // becomes one that keeps the setting until it is.
        let mut f = file.lock();
        match &mut f.kind {
            FileKind::Unix(s) => s.lock().passcred = on,
            FileKind::Socket(end) => {
                if let Some(info) = end.unix.as_mut() {
                    info.passcred = on;
                }
            }
            &mut FileKind::UnixUnbound(ty) => {
                let sock = crate::unix::Sock::new(ty, crate::unix::State::Idle, super::unix::cred(p));
                sock.lock().passcred = on;
                f.kind = FileKind::Unix(sock);
            }
            _ => {}
        }
    }
    Ok(0)
}

pub fn shutdown(p: &mut Process, fd: u64, how: u64) -> SysResult {
    let file = socket_file(p, fd)?;
    if is_inet(&file) {
        return with_inet(p, fd, |_, s, _| inet_shutdown(s, how))?;
    }
    if let Some(sock) = super::unix::sock_of(&file) {
        return super::unix::shutdown(&sock, how);
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
        None => {
            let name = super::unix::names(&file, peer)?;
            super::unix::write_name(p, addr, addrlen, name.as_ref()).map(|_| 0)
        }
    }
}

// ---------------------------------------------------------------- AF_INET / AF_INET6 (inet.rs)

const AF_UNSPEC: u16 = 0;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const IPPROTO_IP: u64 = 0;
const IPPROTO_ICMP: u64 = 1;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;
const IPPROTO_ICMPV6: u64 = 58;
const IPPROTO_IPV6: u64 = 41;
const EINPROGRESS: Errno = Errno(115);
const EALREADY: Errno = Errno(114);
const EADDRNOTAVAIL: Errno = Errno(99);
const EDESTADDRREQ: Errno = Errno(89);
/// The most a read takes at once (bounded by what's buffered anyway).
const READ_MAX: usize = 64 * 1024;

fn new_inet(p: &mut Process, domain: u64, ty: u64, proto: u64, flags: u32, cloexec: bool) -> SysResult {
    require(p, nr::socket, Capability::Net, "")?;
    let v6 = domain == AF_INET6;
    if proto == if v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP } && matches!(ty & 0xf, SOCK_DGRAM | SOCK_RAW) {
        require(p, nr::socket, Capability::NetRaw, "")?;
        let mut s = Inet::new(v6, true);
        s.icmp = Some(inet::Icmp { raw: ty & 0xf == SOCK_RAW, v6, ident: 0 });
        let file = new_file(FileKind::Inet(s), flags);
        return p.fds.alloc(FdEntry { file, cloexec }, 0);
    }
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

/// A socket address as the program gave it. Read once: another thread can
/// change it meanwhile, so what's checked must be what's used.
fn read_addr_bytes(p: &mut Process, addr: u64, len: u64) -> Result<Vec<u8>, Errno> {
    if !(2..=128).contains(&len) {
        return Err(EINVAL);
    }
    let mut b = alloc::vec![0u8; len as usize];
    copy_in(&mut p.aspace, addr, &mut b)?;
    Ok(b)
}

fn read_sockaddr(p: &mut Process, addr: u64, len: u64) -> Result<SockAddr, Errno> {
    SockAddr::decode(&read_addr_bytes(p, addr, len)?)
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

fn inet_bind(s: &mut Inet, raw: &[u8]) -> SysResult {
    let a = SockAddr::decode(raw)?;
    if !s.dgram && (s.bound.is_some() || !matches!(s.state, State::Idle)) {
        return Err(EINVAL);
    }
    let ours = a.is_unspecified() || a.is_local();
    if !ours {
        return Err(EADDRNOTAVAIL);
    }
    // No ports here, and nothing to take one from.
    if s.icmp.is_some() {
        s.bound = Some(a);
        return Ok(0);
    }
    if s.dgram {
        let u = udp_of(s);
        if u.lock().local.is_some() {
            return Err(EINVAL);
        }
        // Only once it has the port (a failed bind leaves it unbound).
        let local = Udp::bind(&u, a)?;
        s.bound = Some(local);
        s.addr_bound = !a.is_unspecified();
        return Ok(0);
    }
    if a.port != 0 && Listener::conflicts(a.addr, a.port, s.v6only) {
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

fn inet_listen(s: &mut Inet) -> SysResult {
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
    let l = Listener::listen(bound.addr, bound.port, s.v6only)?;
    s.bound = Some(SockAddr { port: l.lock().port, ..bound });
    s.state = State::Listening(l);
    Ok(0)
}

pub fn accept4(p: &mut Process, fd: u64, addr: u64, addrlen: u64, flags: u64) -> SysResult {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let file = socket_file(p, fd)?;
    if let Some(sock) = super::unix::sock_of(&file) {
        let nonblock = file.lock().nonblocking();
        let status = if flags & SOCK_NONBLOCK != 0 { O_NONBLOCK } else { 0 };
        return super::unix::accept(p, &sock, nonblock, addr, addrlen, status, flags & SOCK_CLOEXEC != 0);
    }
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

fn inet_connect(p: &mut Process, s: &mut Inet, nonblock: bool, raw: &[u8]) -> SysResult {
    if s.dgram && u16::from_le_bytes([raw[0], raw[1]]) == AF_UNSPEC {
        // Disconnect, forgetting the address connect chose (glibc's
        // getaddrinfo sorts its answers this way with one socket).
        s.peer = None;
        let u = udp_of(s);
        let mut u = u.lock();
        u.peer = None;
        if !s.addr_bound {
            let any = if s.v6 { Addr::V6([0; 16]) } else { Addr::V4([0; 4]) };
            for a in [s.bound.as_mut(), u.local.as_mut()].into_iter().flatten() {
                a.addr = any;
            }
        }
        return Ok(0);
    }
    if !s.dgram {
        crate::landlock::check_socket(p, s.v6, raw, false)?;
    }
    let to = SockAddr::decode(raw)?.or_loopback();
    if s.dgram {
        // Nothing is sent: resolvers and "what's my address" code connect a
        // UDP socket just to see the route. From now on datagrams come only
        // from there, to the address that route has (a v6 socket's v4
        // one shows as ::ffff:a.b.c.d), unless bind named one.
        let ours = if to.is_local() { to.addr } else { inet::source_for(to.addr) };
        let u = udp_of(s);
        if !s.addr_bound {
            let port = s.bound.map_or(0, |b| b.port);
            s.bound = Some(SockAddr { addr: ours, port });
            if let Some(l) = u.lock().local.as_mut() {
                l.addr = ours;
            }
        }
        // (What an ICMP socket hears from has no port, whatever connect
        // was given.)
        let to = if s.icmp.is_some() { SockAddr { addr: to.addr, port: link::ICMP_PORT } } else { to };
        s.peer = Some(to);
        u.lock().peer = Some(to);
        if s.icmp.is_none() {
            udp_bind(s)?;
        }
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
        State::Listening(_) | State::Udp(_) => return Err(EINVAL),
        State::Idle => {}
    }
    if to.is_local() {
        let (end, local) = inet::connect_local(to)?;
        s.state = State::Local { end, local, peer: to };
        return Ok(0);
    }
    if to.port == 0 {
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
        State::Udp(u) => {
            let datagram = u.lock().pop(peek);
            let Some((from, data)) = datagram else {
                return wait(p, nonblock, s.rcvtimeo, EAGAIN).map(|n| (n, None));
            };
            let n = (count as usize).min(data.len());
            copy_out(&mut p.aspace, buf, &data[..n])?;
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
    src: Src,
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
        if count > link::MAX_UDP as u64 {
            return Err(EMSGSIZE);
        }
        let mut q = alloc::vec![0u8; count as usize];
        src.read(p, 0, &mut q)?;
        return udp_send(p, s, &q, to, nonblock);
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
                src.read(p, done, &mut chunk[..n])?;
                if !inet::write_data(id, &chunk[..n]) {
                    break;
                }
                c.lock().sent(n);
                done += n as u64;
            }
            if done > 0 || count == 0 { Ok(done) } else { wait(p, nonblock, s.sndtimeo, EAGAIN) }
        }
        State::Local { end, .. } => match &end.tx {
            Some(tx) => local_io(p, nonblock, s.sndtimeo, |p| pipe_write(p, tx, src, count, true, sigpipe)),
            None => epipe(p),
        },
        _ => Err(ENOTCONN),
    }
}

pub(super) fn inet_available(s: &Inet) -> usize {
    match &s.state {
        State::Remote(c) => c.lock().available(),
        State::Local { end, .. } => end.rx.as_ref().map_or(0, |r| r.pipe.lock().buf.len()),
        State::Udp(u) => u.lock().peek_len().unwrap_or(0),
        _ => 0,
    }
}

/// A UDP socket's endpoint, made when it's first used.
fn udp_of(s: &mut Inet) -> UdpRef {
    if let State::Udp(u) = &s.state {
        return u.clone();
    }
    let u = Udp::new(s.peer);
    u.lock().icmp = s.icmp;
    s.state = State::Udp(u.clone());
    u
}

/// Give a UDP socket its local address now if it has none (bind did, or
/// Linux does at the first send or connect).
fn udp_bind(s: &mut Inet) -> Result<SockAddr, Errno> {
    let u = udp_of(s);
    let local = u.lock().local;
    if let Some(l) = local {
        return Ok(l);
    }
    let any = if s.v6 { SockAddr { addr: Addr::V6([0; 16]), port: 0 } } else { SockAddr::UNSPECIFIED_V4 };
    let local = Udp::bind(&u, s.bound.unwrap_or(any))?;
    s.bound = Some(local);
    Ok(local)
}

/// Send one UDP datagram to `to`: back to a peer that sent to it through
/// a port forwarded from the host, to a socket of the guest's own, to the
/// host's resolver (DNS), or through the host if it allows `to` (asked the
/// first time; a refusal is EPERM, as a firewall's is).
fn udp_send(p: &mut Process, s: &mut Inet, data: &[u8], to: SockAddr, nonblock: bool) -> SysResult {
    if s.icmp.is_some() {
        return icmp_send(p, s, data, to, nonblock);
    }
    if to.port == 0 {
        return Err(EINVAL);
    }
    let local = udp_bind(s)?;
    let u = udp_of(s);
    let len = data.len() as u64;
    // A reply out of the forwarded port (even to port 53: it's no query).
    // Anywhere else, a forwarded socket is like any other.
    let id = u.lock().id;
    if inet::forward_peer(id, to) {
        u.lock().reply(to, data);
        return Ok(len);
    }
    // (The unspecified address is this host, as on Linux.)
    if to.is_local() || to.is_unspecified() {
        let addr = match to {
            _ if to.is_loopback() => to.addr,
            _ if to.is_unspecified() => {
                if s.v6 {
                    Addr::V6(inet::LOOPBACK_V6)
                } else {
                    Addr::V4([127, 0, 0, 1])
                }
            }
            _ => to.addr,
        };
        let from = SockAddr { addr, port: local.port };
        // Nobody serving DNS here: the host's resolver answers, as it
        // does for every nameserver.
        if !inet::deliver_local(from, to, data) && to.port == 53 {
            u.lock().query(data, to);
        }
        return Ok(len);
    }
    if to.port == 53 {
        u.lock().query(data, to);
        return Ok(len);
    }
    through_host(p, &u, data, to, nonblock)
}

/// Send an ICMP echo request to `to`: answered here for the guest's own
/// addresses and its nameserver, or by way of the host if it allows `to`.
/// Nothing else is sent, for a raw socket either: Linux's ping sockets take
/// only this, and it leaves a host nothing to forge.
fn icmp_send(p: &mut Process, s: &mut Inet, data: &[u8], to: SockAddr, nonblock: bool) -> SysResult {
    let echo = if s.v6 { link::ICMP_ECHO.1 } else { link::ICMP_ECHO.0 };
    if data.len() < 8 || data[0] != echo || data[1] != 0 {
        return Err(EINVAL);
    }
    let u = udp_of(s);
    if let Some(i) = u.lock().icmp.as_mut() {
        i.ident = u16::from_be_bytes([data[4], data[5]]);
    }
    let to = SockAddr { addr: to.addr, port: link::ICMP_PORT }.or_loopback();
    if to.is_local() || to.addr == Addr::V4(link::DNS_V4) {
        let mut reply = data.to_vec();
        reply[0] = if s.v6 { link::ICMP_ECHO_REPLY.1 } else { link::ICMP_ECHO_REPLY.0 };
        u.lock().push_icmp(to, to.addr, &reply);
        return Ok(data.len() as u64);
    }
    through_host(p, &u, data, to, nonblock)
}

/// A datagram for `to` by way of the host, which says first if it may go.
fn through_host(p: &mut Process, u: &UdpRef, data: &[u8], to: SockAddr, nonblock: bool) -> SysResult {
    let len = data.len() as u64;
    let verdict = u.lock().verdict(to);
    match verdict {
        Some(true) => {
            u.lock().send_host(to, data);
            Ok(len)
        }
        Some(false) => Err(EPERM),
        None => {
            let mut g = u.lock();
            // The host was out of room for it when it last asked.
            if core::mem::take(&mut g.busy) && !g.asking_about(to) {
                return Err(ENOBUFS);
            }
            g.ask(to);
            drop(g);
            if nonblock {
                return Err(EAGAIN);
            }
            // Again in a while if the answer is lost.
            let deadline = crate::time::monotonic_ns() + inet::VERDICT_PATIENCE_NS;
            p.block_io_rerun(Some(deadline))
        }
    }
}

fn inet_send(p: &mut Process, fd: u64, bufs: &[(u64, u64)], flags: u64, to: Option<SockAddr>) -> SysResult {
    let file = socket_file(p, fd)?;
    let mut of = file.lock();
    let nonblock = of.nonblocking() || flags & MSG_DONTWAIT != 0;
    let FileKind::Inet(s) = &mut of.kind else { return Err(ENOTSOCK) };
    if s.dgram {
        // One datagram: gather the iovecs.
        let total = bufs.iter().try_fold(0u64, |t, b| t.checked_add(b.1)).ok_or(EINVAL)?;
        if total > link::MAX_UDP as u64 {
            return Err(EMSGSIZE);
        }
        let mut q = Vec::with_capacity(total as usize);
        for &(base, len) in bufs {
            let at = q.len();
            q.resize(at + len as usize, 0);
            copy_in(&mut p.aspace, base, &mut q[at..])?;
        }
        let dest = to.or(s.peer).ok_or(EDESTADDRREQ)?;
        return udp_send(p, s, &q, dest, nonblock);
    }
    let mut total = 0;
    for (i, &(base, len)) in bufs.iter().enumerate() {
        let nonblock = nonblock || i > 0;
        match inet_write(p, s, Src::User(base), len, nonblock, flags & MSG_NOSIGNAL == 0, None) {
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
        (SOL_SOCKET, SO_TYPE) if s.icmp.is_some_and(|i| i.raw) => SOCK_RAW as u32,
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
        (SOL_SOCKET, SO_PROTOCOL) if s.icmp.is_some() => (if s.v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP }) as u32,
        (SOL_SOCKET, SO_PROTOCOL) => (if s.dgram { IPPROTO_UDP } else { IPPROTO_TCP }) as u32,
        (SOL_SOCKET, SO_DOMAIN) => (if s.v6 { AF_INET6 } else { AF_INET }) as u32,
        (IPPROTO_TCP, TCP_NODELAY) => 1,
        (IPPROTO_IPV6, IPV6_V6ONLY) if s.v6 => s.v6only as u32,
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
        State::Idle | State::Udp(_) => return Err(ENOTCONN),
    }
    Ok(0)
}
