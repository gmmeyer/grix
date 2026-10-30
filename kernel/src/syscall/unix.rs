//! AF_UNIX socket syscalls (unix.rs has the sockets): binding to paths
//! and abstract names, listening, connecting and accepting, datagram and
//! seqpacket messages, credentials, and descriptors passed with
//! SCM_RIGHTS.

use alloc::vec::Vec;
use grix_abi::policy::Capability;

use super::file::{base_of, would_block};
use super::{AT_FDCWD, require, table::nr};
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, FileRef, O_RDWR, new_file};
use crate::fs::{self, Kind, MAY_WRITE};
use crate::inet::ECONNREFUSED;
use crate::ipc::PipeEnd;
use crate::process::Process;
use crate::uaccess::*;
use crate::unix::{
    self, Addr, Cred, Incoming, Msg, Name, Rights, SOCK_DGRAM, SOCK_SEQPACKET, SOCK_STREAM, Sock, SockRef, State,
    StreamInfo,
};

const EADDRINUSE: Errno = Errno(98);
const EPROTOTYPE: Errno = Errno(91);
const EMSGSIZE: Errno = Errno(90);
const ENOTCONN: Errno = Errno(107);
const EISCONN: Errno = Errno(106);
const EOPNOTSUPP: Errno = Errno(95);
const EPROTONOSUPPORT: Errno = Errno(93);
const MSG_PEEK: u64 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

pub fn cred(p: &Process) -> Cred {
    Cred { pid: p.pid, uid: p.uid, gid: p.gid }
}

/// The message socket behind a file, if it is one.
pub fn sock_of(file: &FileRef) -> Option<SockRef> {
    match &file.lock().kind {
        FileKind::Unix(s) => Some(s.clone()),
        _ => None,
    }
}

fn read_addr(p: &mut Process, addr: u64, len: u64) -> Result<Addr, Errno> {
    if !(2..=110).contains(&len) {
        return Err(EINVAL);
    }
    let mut b = alloc::vec![0u8; len as usize];
    copy_in(&mut p.aspace, addr, &mut b)?;
    Addr::decode(&b)
}

/// sendto's destination.
pub fn resolve_to(p: &mut Process, addr: u64, len: u64) -> Result<SockRef, Errno> {
    resolve(p, addr, len)
}

/// The socket a program's address names (connect, sendto). A path must
/// lead to a socket node the caller may write to.
fn resolve(p: &mut Process, addr: u64, len: u64) -> Result<SockRef, Errno> {
    match read_addr(p, addr, len)? {
        Addr::Path(path) => {
            let base = base_of(p, AT_FDCWD as u64, &path)?;
            let mut fs = fs::lock();
            let ino = fs.lookup(base, &path, true)?;
            let Kind::Socket(id) = fs.node(ino).kind else { return Err(ECONNREFUSED) };
            if !fs.permits(ino, p.who(), MAY_WRITE) {
                return Err(EACCES);
            }
            drop(fs);
            unix::find_node(id).ok_or(ECONNREFUSED)
        }
        Addr::Abstract(name) => unix::find(&Name::Abstract(name)).ok_or(ECONNREFUSED),
        Addr::Unnamed => Err(EINVAL),
    }
}

/// socketpair(AF_UNIX): connected streams, or message sockets.
pub fn pair(p: &mut Process, ty: u64) -> Result<(FileKind, FileKind), Errno> {
    let me = cred(p);
    match ty {
        SOCK_STREAM => {
            let (mut a, mut b) = unix::stream_pair();
            for end in [&mut a, &mut b] {
                let info = StreamInfo { local: None, peer: None, peer_cred: me, passcred: false };
                end.unix = Some(alloc::boxed::Box::new(info));
            }
            Ok((FileKind::Socket(a), FileKind::Socket(b)))
        }
        SOCK_DGRAM | SOCK_SEQPACKET => {
            let (a, b) = unix::message_pair(ty, me, me);
            Ok((FileKind::Unix(a), FileKind::Unix(b)))
        }
        _ => Err(EPROTONOSUPPORT),
    }
}

/// socket(AF_UNIX): a stream or seqpacket socket is unbound until bind
/// or connect; a datagram socket can send and receive from the start.
pub fn new(p: &Process, ty: u64) -> FileKind {
    match ty {
        SOCK_DGRAM => FileKind::Unix(Sock::new(SOCK_DGRAM, Sock::messages(), cred(p))),
        _ => FileKind::UnixUnbound(ty),
    }
}

pub fn bind(p: &mut Process, file: &FileRef, addr: u64, len: u64) -> SysResult {
    let (ty, existing) = match &file.lock().kind {
        FileKind::UnixUnbound(ty) => (*ty, None),
        FileKind::Unix(s) => (s.lock().ty, Some(s.clone())),
        _ => return Err(EINVAL),
    };
    if let Some(s) = &existing
        && (s.lock().name.is_some() || s.lock().peer_cred.is_some() && s.lock().ty == SOCK_SEQPACKET)
    {
        return Err(EINVAL);
    }
    let name = match read_addr(p, addr, len)? {
        // Just the family: a name of the kernel's choosing (autobind).
        Addr::Unnamed => Name::Abstract(unix::auto_name()),
        Addr::Abstract(a) => {
            if unix::abstract_taken(&a) {
                return Err(EADDRINUSE);
            }
            Name::Abstract(a)
        }
        // A socket node: the filesystem has to be writable.
        Addr::Path(path) => {
            require(p, nr::bind, Capability::FsWrite, &path)?;
            let base = base_of(p, AT_FDCWD as u64, &path)?;
            let id = unix::node_id();
            let perm = 0o777 & !p.umask();
            let mut fs = fs::lock();
            let (dir, leaf) = fs.lookup_parent(base, &path)?;
            if let Some(d) = crate::landlock::domain_changing(p, &fs, dir)
                && fs.child_of(dir, &leaf).is_none()
            {
                d.check(&fs, dir, crate::landlock::MAKE_SOCK)?;
            }
            match fs.create(dir, &leaf, Kind::Socket(id), perm, p.who()) {
                Ok(_) => {}
                Err(EEXIST) => return Err(EADDRINUSE),
                Err(e) => return Err(e),
            }
            Name::Path(path, id)
        }
    };
    let state = if ty == SOCK_DGRAM { Sock::messages() } else { State::Idle };
    let sock = existing.unwrap_or_else(|| Sock::new(ty, state, cred(p)));
    Sock::bind(&sock, name)?;
    file.lock().kind = FileKind::Unix(sock);
    Ok(0)
}

pub fn listen(p: &Process, file: &FileRef, backlog: u64) -> SysResult {
    let Some(sock) = sock_of(file) else {
        // Not bound: nothing to listen on.
        return Err(EINVAL);
    };
    let mut s = sock.lock();
    if s.ty == SOCK_DGRAM {
        return Err(EOPNOTSUPP);
    }
    let backlog = (backlog as usize).clamp(1, 4096);
    match &mut s.state {
        State::Idle => s.state = State::Listening { backlog, queue: Default::default() },
        State::Listening { backlog: b, .. } => *b = backlog,
        State::Messages { .. } => return Err(EINVAL),
    }
    s.cred = cred(p);
    s.touch();
    Ok(0)
}

pub fn connect(p: &mut Process, file: &FileRef, addr: u64, len: u64) -> SysResult {
    let nonblock = file.lock().nonblocking();
    let (ty, me, mine) = match &file.lock().kind {
        FileKind::UnixUnbound(ty) => (*ty, None, None),
        FileKind::Unix(s) => {
            let s2 = s.lock();
            match &s2.state {
                State::Listening { .. } => return Err(EINVAL),
                State::Messages { .. } if s2.ty == SOCK_SEQPACKET => return Err(EISCONN),
                _ => {}
            }
            (s2.ty, s2.name.clone(), Some(s.clone()))
        }
        FileKind::Socket(_) => return Err(EISCONN),
        _ => return Err(EINVAL),
    };
    let target = resolve(p, addr, len)?;
    if target.lock().ty != ty {
        return Err(EPROTOTYPE);
    }
    let blocked = |p: &mut Process| if nonblock { Err(EAGAIN) } else { would_block(p, false) };
    match ty {
        SOCK_STREAM => match unix::connect_stream(&target, me, cred(p)) {
            Ok((mut end, _)) => {
                // SO_PASSCRED set before it connected.
                if let (Some(s), Some(info)) = (&mine, end.unix.as_mut()) {
                    info.passcred = s.lock().passcred;
                }
                file.lock().kind = FileKind::Socket(end);
                Ok(0)
            }
            Err(EAGAIN) => blocked(p),
            Err(e) => Err(e),
        },
        SOCK_SEQPACKET => match unix::connect_packet(&target, me, cred(p)) {
            Ok(sock) => {
                if let Some(s) = &mine {
                    sock.lock().passcred = s.lock().passcred;
                }
                file.lock().kind = FileKind::Unix(sock);
                Ok(0)
            }
            Err(EAGAIN) => blocked(p),
            Err(e) => Err(e),
        },
        // A datagram socket's default destination.
        _ => {
            let sock = mine.ok_or(EINVAL)?;
            let peer_cred = target.lock().cred;
            let mut s = sock.lock();
            if let State::Messages { peer, .. } = &mut s.state {
                *peer = Some(alloc::sync::Arc::downgrade(&target));
            }
            s.peer_cred = Some(peer_cred);
            Ok(0)
        }
    }
}

/// accept4 on a listening AF_UNIX socket.
pub fn accept(
    p: &mut Process,
    sock: &SockRef,
    nonblock: bool,
    addr: u64,
    addrlen: u64,
    flags: u32,
    cloexec: bool,
) -> SysResult {
    if !p.fds.has_room() {
        return Err(EMFILE);
    }
    let mut s = sock.lock();
    let State::Listening { queue, .. } = &mut s.state else { return Err(EINVAL) };
    let Some((incoming, _slot)) = queue.pop_front() else {
        drop(s);
        return would_block(p, nonblock);
    };
    s.touch();
    drop(s);
    let (kind, peer) = match incoming {
        Incoming::Stream(end) => {
            let peer = end.unix.as_ref().and_then(|u| u.peer.clone());
            (FileKind::Socket(end), peer)
        }
        Incoming::Packet(s) => {
            let peer = s.lock().peer().and_then(|q| q.lock().name.clone());
            (FileKind::Unix(s), peer)
        }
    };
    let fd = p.fds.alloc(FdEntry { file: new_file(kind, O_RDWR | flags), cloexec }, 0)?;
    write_name(p, addr, addrlen, peer.as_ref())?;
    Ok(fd)
}

/// A sockaddr_un out to the program (bounded by the room it gave).
pub fn write_name(p: &mut Process, addr: u64, addrlen: u64, name: Option<&Name>) -> Result<(), Errno> {
    if addr == 0 || addrlen == 0 {
        return Ok(());
    }
    let sa = Name::encode(name);
    let room = read_u32(&mut p.aspace, addrlen)? as usize;
    copy_out(&mut p.aspace, addr, &sa[..room.min(sa.len())])?;
    write_u32(&mut p.aspace, addrlen, sa.len() as u32)
}

/// A received message's sender out to the program (recvfrom, recvmsg):
/// nothing at all for an unnamed one, as on Linux.
pub fn write_from(p: &mut Process, addr: u64, addrlen: u64, from: Option<&Name>) -> Result<(), Errno> {
    match from {
        Some(name) => write_name(p, addr, addrlen, Some(name)),
        None if addr != 0 && addrlen != 0 => write_u32(&mut p.aspace, addrlen, 0),
        None => Ok(()),
    }
}

/// getsockname and getpeername of AF_UNIX sockets.
pub fn names(file: &FileRef, peer: bool) -> Result<Option<Name>, Errno> {
    match &file.lock().kind {
        FileKind::Socket(end) => {
            let u = end.unix.as_ref();
            Ok(u.and_then(|u| if peer { u.peer.clone() } else { u.local.clone() }))
        }
        FileKind::Unix(sock) => {
            let s = sock.lock();
            if !peer {
                return Ok(s.name.clone());
            }
            let peer = s.peer().ok_or(ENOTCONN)?;
            // Connected to itself.
            if alloc::sync::Arc::ptr_eq(&peer, sock) {
                return Ok(s.name.clone());
            }
            drop(s);
            let name = peer.lock().name.clone();
            Ok(name)
        }
        FileKind::UnixUnbound(_) if peer => Err(ENOTCONN),
        _ => Ok(None),
    }
}

/// SO_PEERCRED.
pub fn peer_cred(file: &FileRef) -> Cred {
    match &file.lock().kind {
        FileKind::Socket(end) => end.unix.as_ref().map_or(Cred::NOBODY, |u| u.peer_cred),
        FileKind::Unix(s) => s.lock().peer_cred.unwrap_or(Cred::NOBODY),
        _ => Cred::NOBODY,
    }
}

// ---------------------------------------------------------------- ancillary data

/// What sendmsg's control messages carry: descriptors (SCM_RIGHTS), and
/// the credentials to send with them (SCM_CREDENTIALS).
#[derive(Default)]
pub struct Control {
    pub rights: Option<Rights>,
    pub cred: Option<Cred>,
}

/// sendmsg's control messages.
pub fn read_control(p: &mut Process, control: u64, len: u64) -> Result<Control, Errno> {
    if control == 0 || len == 0 {
        return Ok(Control::default());
    }
    if len > 4096 {
        return Err(ENOBUFS);
    }
    let mut b = alloc::vec![0u8; len as usize];
    copy_in(&mut p.aspace, control, &mut b)?;
    let mut files = Vec::new();
    let mut cred = None;
    let mut off = 0;
    while off + 16 <= b.len() {
        // (The length is the program's: no arithmetic on it may wrap.)
        let clen = u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
        let level = i32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap());
        let ty = i32::from_le_bytes(b[off + 12..off + 16].try_into().unwrap());
        if clen < 16 || clen > (b.len() - off) as u64 {
            return Err(EINVAL);
        }
        let clen = clen as usize;
        match (level, ty) {
            (SOL_SOCKET, SCM_RIGHTS) => {
                for c in b[off + 16..off + clen].as_chunks::<4>().0 {
                    let fd = i32::from_le_bytes(*c);
                    files.push(p.fds.get_raw(fd as u64)?);
                    if files.len() > unix::SCM_MAX_FD {
                        return Err(EINVAL);
                    }
                }
            }
            (SOL_SOCKET, SCM_CREDENTIALS) if clen >= 28 => {
                let w = |i: usize| u32::from_le_bytes(b[off + 16 + i * 4..off + 20 + i * 4].try_into().unwrap());
                let (pid, uid, gid) = (w(0), w(1), w(2));
                // Only one's own process and ids, unless privileged (as
                // Linux's scm_check_creds).
                let ids = &p.ids;
                let own_uid = [ids.ruid, p.uid, ids.suid].contains(&uid);
                let own_gid = [ids.rgid, p.gid, ids.sgid].contains(&gid);
                if p.uid != 0 && (pid != p.pid || !own_uid || !own_gid) {
                    return Err(EPERM);
                }
                cred = Some(Cred { pid, uid, gid });
            }
            _ => return Err(EINVAL),
        }
        off += clen.next_multiple_of(8);
    }
    let rights = if files.is_empty() { None } else { Some(Rights::new(files)?) };
    Ok(Control { rights, cred })
}

/// The credentials a message carries unless its sender says otherwise:
/// its process and real ids, as Linux's scm_send.
pub(super) fn sender(p: &Process) -> Cred {
    Cred { pid: p.pid, uid: p.ids.ruid, gid: p.ids.rgid }
}

/// SCM_CREDENTIALS into a recvmsg's control buffer of `room` bytes
/// (nothing if there's no room: MSG_CTRUNC). Returns the length used and
/// the flags.
fn deliver_cred(p: &mut Process, cred: Cred, control: u64, room: u64) -> Result<(u64, u32), Errno> {
    const LEN: u64 = 16 + 12;
    if control == 0 || room < LEN {
        return Ok((0, MSG_CTRUNC));
    }
    let mut b = Vec::with_capacity(LEN as usize);
    b.extend_from_slice(&LEN.to_le_bytes());
    b.extend_from_slice(&SOL_SOCKET.to_le_bytes());
    b.extend_from_slice(&SCM_CREDENTIALS.to_le_bytes());
    b.extend_from_slice(&cred.bytes());
    copy_out(&mut p.aspace, control, &b)?;
    Ok((LEN.next_multiple_of(8).min(room), 0))
}

/// recvmsg: the descriptors received, as new ones in the caller's table
/// and an SCM_RIGHTS message in its control buffer. What doesn't fit is
/// closed and the message marked MSG_CTRUNC, as on Linux. Returns the
/// control length used and the flags.
fn deliver_rights(
    p: &mut Process,
    rights: Vec<Rights>,
    control: u64,
    room: u64,
    cloexec: bool,
) -> Result<(u64, u32), Errno> {
    let files: Vec<FileRef> = rights.into_iter().flat_map(Rights::take).collect();
    if files.is_empty() {
        return Ok((0, 0));
    }
    let fit = if control != 0 && room >= 20 { ((room - 16) / 4) as usize } else { 0 };
    let mut fds = Vec::new();
    for file in files.iter().take(fit) {
        match p.fds.alloc(FdEntry { file: file.clone(), cloexec }, 0) {
            Ok(fd) => fds.push(fd as i32),
            Err(_) => break,
        }
    }
    let flags = if fds.len() < files.len() { MSG_CTRUNC } else { 0 };
    if fds.is_empty() {
        return Ok((0, flags));
    }
    let len = 16 + 4 * fds.len();
    let mut b = Vec::with_capacity(len);
    b.extend_from_slice(&(len as u64).to_le_bytes());
    b.extend_from_slice(&SOL_SOCKET.to_le_bytes());
    b.extend_from_slice(&SCM_RIGHTS.to_le_bytes());
    for fd in &fds {
        b.extend_from_slice(&fd.to_le_bytes());
    }
    copy_out(&mut p.aspace, control, &b)?;
    Ok(((len as u64).next_multiple_of(8).min(room), flags))
}

// ---------------------------------------------------------------- data

/// What a receive got: bytes, the message's whole length (MSG_TRUNC),
/// who sent it, and descriptors.
pub struct Received {
    pub n: u64,
    pub full: u64,
    pub from: Option<Name>,
    pub rights: Vec<Rights>,
    /// The sender's credentials, if the socket has SO_PASSCRED.
    pub cred: Option<Cred>,
}

/// Send on a message socket: to `to`, or its peer.
pub fn send_msg(
    p: &mut Process,
    sock: &SockRef,
    bufs: &[(u64, u64)],
    flags: u64,
    nonblock: bool,
    to: Option<SockRef>,
    control: Control,
) -> SysResult {
    let Control { rights, cred } = control;
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    let (ty, from, wr_shut, peer) = {
        let s = sock.lock();
        let shut = matches!(s.state, State::Messages { wr_shut: true, .. });
        (s.ty, s.name.clone(), shut, s.peer())
    };
    if wr_shut {
        if flags & MSG_NOSIGNAL == 0 {
            crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a socket that was shut down");
        }
        return Err(EPIPE);
    }
    let target = match (to, ty) {
        (Some(_), SOCK_SEQPACKET) => return Err(EISCONN),
        (Some(t), _) => t,
        (None, _) => match peer {
            Some(t) => t,
            // Connected, but the other end closed.
            None if ty == SOCK_DGRAM && sock.lock().peer_cred.is_some() => return Err(ECONNREFUSED),
            None if ty == SOCK_SEQPACKET && matches!(sock.lock().state, State::Messages { eof: true, .. }) => {
                if flags & MSG_NOSIGNAL == 0 {
                    crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a socket whose peer is gone");
                }
                return Err(EPIPE);
            }
            None => return Err(ENOTCONN),
        },
    };
    if target.lock().ty != ty {
        return Err(EPROTOTYPE);
    }
    if rights.as_ref().is_some_and(|r| r.holds(&target)) {
        return Err(Errno(109)); // ETOOMANYREFS: it would hold itself open
    }
    // (The lengths are the program's: their sum mustn't wrap.)
    let len = bufs.iter().try_fold(0u64, |t, b| t.checked_add(b.1)).ok_or(EMSGSIZE)?;
    if len > unix::QUEUE_BYTES as u64 {
        return Err(EMSGSIZE);
    }
    if !target.lock().has_room(len as usize) {
        if !matches!(target.lock().state, State::Messages { .. }) {
            return Err(ECONNREFUSED);
        }
        return if nonblock { Err(EAGAIN) } else { would_block(p, false) };
    }
    let mut data = Vec::new();
    data.try_reserve_exact(len as usize).map_err(|_| ENOMEM)?;
    for &(base, n) in bufs {
        let at = data.len();
        data.resize(at + n as usize, 0);
        copy_in(&mut p.aspace, base, &mut data[at..])?;
    }
    let cred = cred.unwrap_or_else(|| sender(p));
    target.lock().push(Msg { data, from, rights, cred })?;
    Ok(len)
}

/// Receive from a message socket.
pub fn recv_msg(
    p: &mut Process,
    sock: &SockRef,
    bufs: &[(u64, u64)],
    flags: u64,
    nonblock: bool,
) -> Result<Received, Errno> {
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    let mut s = sock.lock();
    let passcred = s.passcred;
    let msg = if flags & MSG_PEEK != 0 {
        match &s.state {
            State::Messages { queue, .. } => queue.front().map(|m| (m.data.clone(), m.from.clone(), None, m.cred)),
            _ => None,
        }
    } else {
        s.pop().map(|m| (m.data, m.from, m.rights, m.cred))
    };
    let Some((data, from, rights, cred)) = msg else {
        let eof = match &s.state {
            State::Messages { eof, .. } => *eof,
            _ => return Err(ENOTCONN),
        };
        if eof {
            return Ok(Received { n: 0, full: 0, from: None, rights: Vec::new(), cred: None });
        }
        drop(s);
        return match would_block(p, nonblock) {
            Err(e) => Err(e),
            Ok(_) => Err(EAGAIN),
        };
    };
    drop(s);
    let mut n = 0usize;
    for &(base, len) in bufs {
        if n >= data.len() {
            break;
        }
        let k = (len as usize).min(data.len() - n);
        copy_out(&mut p.aspace, base, &data[n..n + k])?;
        n += k;
    }
    let cred = passcred.then_some(cred);
    Ok(Received { n: n as u64, full: data.len() as u64, from, rights: rights.into_iter().collect(), cred })
}

/// Send on a connected stream, with descriptors attached to its first
/// byte, and as `cred` (SCM_CREDENTIALS) or the sender.
#[allow(clippy::too_many_arguments)]
pub fn send_stream(
    p: &mut Process,
    tx: &PipeEnd,
    buf: u64,
    len: u64,
    nonblock: bool,
    sigpipe: bool,
    rights: Option<Rights>,
    cred: Option<Cred>,
) -> SysResult {
    if rights.as_ref().is_some_and(|r| r.holds_pipe(&tx.pipe)) {
        return Err(Errno(109)); // ETOOMANYREFS: it would hold itself open
    }
    let at = tx.pipe.lock().written;
    let n = super::file::pipe_write_as(p, tx, super::file::Src::User(buf), len, nonblock, sigpipe, cred)?;
    if let Some(r) = rights
        && n > 0
    {
        tx.pipe.lock().rights.push_back((at, r));
    }
    Ok(n)
}

/// Receive from a connected stream: descriptors that came with the bytes
/// into `rights`, and, with `cred` (SO_PASSCRED), only one writer's bytes,
/// whose credentials it gets (if it has some already, only theirs).
#[allow(clippy::too_many_arguments)]
pub fn recv_stream(
    p: &mut Process,
    rx: &PipeEnd,
    buf: u64,
    len: u64,
    nonblock: bool,
    peek: bool,
    rights: &mut Vec<Rights>,
    cred: Option<&mut Option<Cred>>,
) -> SysResult {
    super::file::pipe_read_full(p, rx, buf, len, nonblock, peek, rights, cred)
}

/// Does this connected stream want its writers' credentials?
pub fn stream_passcred(end: &crate::ipc::SocketEnd) -> bool {
    end.unix.as_ref().is_some_and(|u| u.passcred)
}

/// What comes with received data: descriptors, and the sender's
/// credentials (SO_PASSCRED).
pub struct Ancillary {
    pub rights: Vec<Rights>,
    pub cred: Option<Cred>,
}

/// recvmsg's results into the msghdr: the sender's name, credentials,
/// descriptors, flags.
pub fn finish_recvmsg(
    p: &mut Process,
    msg: u64,
    name: u64,
    from: Option<&Name>,
    anc: Ancillary,
    flags: u64,
    truncated: bool,
) -> Result<(), Errno> {
    let Ancillary { rights, cred } = anc;
    if name != 0 {
        match from {
            Some(_) => {
                let sa = Name::encode(from);
                let room = read_u32(&mut p.aspace, msg + 8)? as usize;
                copy_out(&mut p.aspace, name, &sa[..room.min(sa.len())])?;
                write_u32(&mut p.aspace, msg + 8, sa.len() as u32)?;
            }
            None => write_u32(&mut p.aspace, msg + 8, 0)?,
        }
    }
    let control = read_u64(&mut p.aspace, msg + 32)?;
    let room = read_u64(&mut p.aspace, msg + 40)?;
    // Credentials first, then descriptors, as Linux's scm_recv.
    let (mut used, mut mflags) = match cred {
        Some(c) => deliver_cred(p, c, control, room)?,
        None => (0, 0),
    };
    let at = if used > 0 { control + used } else { control };
    let (more, f) = deliver_rights(p, rights, at, room - used, flags & MSG_CMSG_CLOEXEC != 0)?;
    used += more;
    mflags |= f;
    if truncated {
        mflags |= MSG_TRUNC as u32;
    }
    write_u64(&mut p.aspace, msg + 40, used)?;
    write_u32(&mut p.aspace, msg + 48, mflags)
}

/// shutdown on a message socket.
pub fn shutdown(sock: &SockRef, how: u64) -> SysResult {
    let mut s = sock.lock();
    let peer = s.peer();
    let State::Messages { eof, wr_shut, .. } = &mut s.state else { return Err(ENOTCONN) };
    match how {
        0 => *eof = true,
        1 => *wr_shut = true,
        2 => (*eof, *wr_shut) = (true, true),
        _ => return Err(EINVAL),
    }
    let seqpacket = s.ty == SOCK_SEQPACKET;
    s.touch();
    drop(s);
    // The peer of a seqpacket socket that stopped writing reads end of file.
    if how >= 1
        && seqpacket
        && let Some(peer) = peer
    {
        let mut q = peer.lock();
        if let State::Messages { eof, .. } = &mut q.state {
            *eof = true;
        }
        q.touch();
    }
    Ok(0)
}
