//! AF_UNIX sockets beyond socket pairs: names (a path, which is a socket
//! node in the filesystem, or an abstract name), listening and connecting,
//! datagram and seqpacket sockets (message queues), and descriptors
//! passed with SCM_RIGHTS.
//!
//! A connected stream is a socket pair (`ipc::SocketEnd`, pipes both
//! ways) whichever way it was made. Messages keep their boundaries in a
//! `Sock`'s queue: a datagram socket's, or a seqpacket connection's end.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

use crate::errno::*;
use crate::fd::FileRef;
use crate::inet::{ECONNREFUSED, Slot};
use crate::ipc::{self, EPOLLHUP, EPOLLIN, EPOLLOUT, EPOLLRDHUP, SocketEnd};
use crate::kmem::Charge;

pub const SOCK_STREAM: u64 = 1;
pub const SOCK_DGRAM: u64 = 2;
pub const SOCK_SEQPACKET: u64 = 5;
const AF_UNIX: u16 = 1;

/// Bytes a socket's message queue holds (Linux's default receive buffer).
pub const QUEUE_BYTES: usize = 212_992;
/// Messages it holds (net.unix.max_dgram_qlen).
const QUEUE_MSGS: usize = 512;
/// What a message costs besides its bytes (Linux counts an skb's
/// truesize): so even empty ones fill the queue.
const MSG_OVERHEAD: usize = core::mem::size_of::<Msg>() + 64;
/// Descriptors on their way through sockets, all together (they keep
/// their files open), and in one message (Linux's SCM_MAX_FD).
const MAX_INFLIGHT: usize = 4096;
pub const SCM_MAX_FD: usize = 253;
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);

/// A socket's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Name {
    /// Bound to a path (as given), and the socket node's id there.
    Path(String, u64),
    /// In the abstract namespace (without the leading NUL).
    Abstract(Vec<u8>),
}

impl Name {
    /// struct sockaddr_un, as long as it needs to be.
    pub fn encode(name: Option<&Name>) -> Vec<u8> {
        let mut b = AF_UNIX.to_le_bytes().to_vec();
        match name {
            None => {}
            Some(Name::Path(p, _)) => {
                b.extend_from_slice(p.as_bytes());
                b.push(0);
            }
            Some(Name::Abstract(a)) => {
                b.push(0);
                b.extend_from_slice(a);
            }
        }
        b
    }

    fn key(&self) -> Key {
        match self {
            Name::Path(_, id) => Key::Node(*id),
            Name::Abstract(a) => Key::Abstract(a.clone()),
        }
    }
}

/// An address a program gave: a path to look up, an abstract name, or
/// nothing but the family (bind: pick an abstract name).
pub enum Addr {
    Path(String),
    Abstract(Vec<u8>),
    Unnamed,
}

impl Addr {
    pub fn decode(b: &[u8]) -> Result<Addr, Errno> {
        if b.len() < 2 || u16::from_le_bytes([b[0], b[1]]) != AF_UNIX {
            return Err(EINVAL);
        }
        let rest = &b[2..];
        match rest.first() {
            None => Ok(Addr::Unnamed),
            Some(0) => Ok(Addr::Abstract(rest[1..].to_vec())),
            Some(_) => {
                let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
                let path = core::str::from_utf8(&rest[..end]).map_err(|_| ENOENT)?;
                Ok(Addr::Path(path.into()))
            }
        }
    }
}

/// Who is at the other end (SO_PEERCRED).
#[derive(Clone, Copy, Debug)]
pub struct Cred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Cred {
    /// struct ucred.
    pub fn bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&self.pid.to_le_bytes());
        b[4..8].copy_from_slice(&self.uid.to_le_bytes());
        b[8..].copy_from_slice(&self.gid.to_le_bytes());
        b
    }

    /// An unconnected socket's: nobody.
    pub const NOBODY: Cred = Cred { pid: 0, uid: u32::MAX, gid: u32::MAX };
}

/// A connected stream's names and peer, beside its pipes.
#[derive(Clone, Debug)]
pub struct StreamInfo {
    pub local: Option<Name>,
    pub peer: Option<Name>,
    pub peer_cred: Cred,
}

/// Descriptors in flight (SCM_RIGHTS).
pub struct Rights(pub Vec<FileRef>);

impl Rights {
    pub fn new(files: Vec<FileRef>) -> Result<Rights, Errno> {
        let n = files.len();
        if INFLIGHT.fetch_add(n, Ordering::Relaxed) + n > MAX_INFLIGHT {
            INFLIGHT.fetch_sub(n, Ordering::Relaxed);
            return Err(Errno(109)); // ETOOMANYREFS
        }
        Ok(Rights(files))
    }

    /// Would putting these where `target` reads them hold `target` open
    /// through itself (nothing here collects such cycles, as Linux's
    /// unix_gc does)?
    pub fn holds(&self, target: &SockRef) -> bool {
        self.0.iter().any(|f| matches!(&f.lock().kind, crate::fd::FileKind::Unix(s) if Arc::ptr_eq(s, target)))
    }

    /// The same for a stream: one of them reads from `pipe`.
    pub fn holds_pipe(&self, pipe: &Arc<Mutex<ipc::Pipe>>) -> bool {
        self.0.iter().any(|f| {
            matches!(&f.lock().kind, crate::fd::FileKind::Socket(e) if e.rx.as_ref().is_some_and(|r| Arc::ptr_eq(&r.pipe, pipe)))
        })
    }

    pub fn take(mut self) -> Vec<FileRef> {
        INFLIGHT.fetch_sub(self.0.len(), Ordering::Relaxed);
        core::mem::take(&mut self.0)
    }
}

impl Drop for Rights {
    fn drop(&mut self) {
        INFLIGHT.fetch_sub(self.0.len(), Ordering::Relaxed);
    }
}

/// One datagram or seqpacket message.
pub struct Msg {
    pub data: Vec<u8>,
    pub from: Option<Name>,
    pub rights: Option<Rights>,
}

/// A connection waiting to be accepted.
pub enum Incoming {
    Stream(SocketEnd),
    Packet(Arc<Mutex<Sock>>),
}

pub enum State {
    /// Bound, neither listening nor connected (a stream or seqpacket
    /// socket).
    Idle,
    Listening {
        backlog: usize,
        queue: VecDeque<(Incoming, Slot)>,
    },
    /// Datagram, or a seqpacket connection's end: messages for it, and
    /// where they go without an address (the peer, if connected).
    Messages {
        queue: VecDeque<Msg>,
        bytes: usize,
        charge: Charge,
        peer: Option<Weak<Mutex<Sock>>>,
        /// A seqpacket end whose peer is gone, or that shut down: end of file.
        eof: bool,
        /// shutdown(SHUT_WR).
        wr_shut: bool,
    },
}

/// A named, listening, or message socket.
pub struct Sock {
    pub ty: u64,
    pub name: Option<Name>,
    pub state: State,
    /// The process that made it (bound, listened, or connected).
    pub cred: Cred,
    /// Its peer's, once connected.
    pub peer_cred: Option<Cred>,
    pub version: u64,
}

pub type SockRef = Arc<Mutex<Sock>>;

/// Bound names: socket node ids and abstract names.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Node(u64),
    Abstract(Vec<u8>),
}

static NAMES: Mutex<BTreeMap<Key, Weak<Mutex<Sock>>>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_AUTO: AtomicU64 = AtomicU64::new(0);

/// A new socket node's id (`fs::Kind::Socket`).
pub fn node_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// The socket bound to `name`, if it's still open.
pub fn find(name: &Name) -> Option<SockRef> {
    NAMES.lock().get(&name.key()).and_then(Weak::upgrade)
}

pub fn find_node(id: u64) -> Option<SockRef> {
    NAMES.lock().get(&Key::Node(id)).and_then(Weak::upgrade)
}

pub fn abstract_taken(name: &[u8]) -> bool {
    NAMES.lock().get(&Key::Abstract(name.to_vec())).is_some_and(|w| w.strong_count() > 0)
}

/// An abstract name nobody has (Linux's autobind: five hex digits).
pub fn auto_name() -> Vec<u8> {
    loop {
        let n = NEXT_AUTO.fetch_add(1, Ordering::Relaxed) & 0xfffff;
        let name = alloc::format!("{n:05x}").into_bytes();
        if !abstract_taken(&name) {
            return name;
        }
    }
}

impl Msg {
    /// What it counts against a queue (and the kernel memory budget).
    pub fn cost(&self) -> usize {
        let name = match &self.from {
            Some(Name::Path(p, _)) => p.len(),
            Some(Name::Abstract(a)) => a.len(),
            None => 0,
        };
        self.data.len() + name + MSG_OVERHEAD
    }
}

impl Sock {
    pub fn new(ty: u64, state: State, cred: Cred) -> SockRef {
        Arc::new(Mutex::new(Sock { ty, name: None, state, cred, peer_cred: None, version: 0 }))
    }

    /// An empty message queue (a datagram socket, a seqpacket end).
    pub fn messages() -> State {
        State::Messages {
            queue: VecDeque::new(),
            bytes: 0,
            charge: Charge::default(),
            peer: None,
            eof: false,
            wr_shut: false,
        }
    }

    pub fn touch(&mut self) {
        self.version += 1;
        ipc::changed();
    }

    /// Give `sock` (this one) `name`. EADDRINUSE if it's taken.
    pub fn bind(sock: &SockRef, name: Name) -> Result<(), Errno> {
        let mut names = NAMES.lock();
        names.retain(|_, w| w.strong_count() > 0);
        let key = name.key();
        if names.contains_key(&key) {
            return Err(Errno(98));
        }
        names.insert(key, Arc::downgrade(sock));
        drop(names);
        sock.lock().name = Some(name);
        Ok(())
    }

    /// Room for a message of `len` bytes?
    pub fn has_room(&self, len: usize) -> bool {
        let cost = len + MSG_OVERHEAD;
        match &self.state {
            State::Messages { queue, bytes, .. } => {
                queue.len() < QUEUE_MSGS && (*bytes == 0 || bytes + cost <= QUEUE_BYTES)
            }
            _ => false,
        }
    }

    /// Queue a message (the caller checked `has_room`).
    pub fn push(&mut self, msg: Msg) -> Result<(), Errno> {
        let State::Messages { queue, bytes, charge, .. } = &mut self.state else { return Err(ECONNREFUSED) };
        let cost = msg.cost();
        charge.resize((*bytes + cost) as u64).map_err(|_| Errno(105))?;
        *bytes += cost;
        queue.push_back(msg);
        self.touch();
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Msg> {
        let State::Messages { queue, bytes, charge, .. } = &mut self.state else { return None };
        let msg = queue.pop_front()?;
        *bytes -= msg.cost();
        let _ = charge.resize(*bytes as u64);
        self.touch();
        Some(msg)
    }

    /// The connected peer of a message socket.
    pub fn peer(&self) -> Option<SockRef> {
        match &self.state {
            State::Messages { peer, .. } => peer.as_ref()?.upgrade(),
            _ => None,
        }
    }

    pub fn poll(&self) -> (u32, u64) {
        let mask = match &self.state {
            State::Idle => EPOLLOUT,
            State::Listening { queue, .. } => {
                if queue.is_empty() {
                    0
                } else {
                    EPOLLIN
                }
            }
            State::Messages { queue, eof, peer, wr_shut, .. } => {
                let mut m = if queue.is_empty() { 0 } else { EPOLLIN };
                if *eof {
                    m |= EPOLLIN | EPOLLRDHUP;
                }
                // Writable while the peer has room; its pops change that, so
                // they count in the version (for edge-triggered epoll). A
                // datagram socket may be connected to itself: its lock is
                // already held.
                let peer_state = peer.as_ref().map(|w| {
                    w.upgrade().map(|s| match s.try_lock() {
                        Some(s) => (s.has_room(1), s.version),
                        None => (self.has_room(1), 0),
                    })
                });
                let (writable, peer_version) = match peer_state {
                    None => (!(*eof && self.ty == SOCK_SEQPACKET), 0),
                    Some(None) => (false, 0),
                    Some(Some(state)) => state,
                };
                if writable && !wr_shut {
                    m |= EPOLLOUT;
                }
                // Hung up: the peer is gone, or both directions are shut.
                let peer_gone = matches!(peer_state, Some(None)) || (peer.is_none() && *eof);
                if self.ty == SOCK_SEQPACKET && (peer_gone || (*eof && *wr_shut)) {
                    m |= EPOLLHUP;
                }
                return (m, self.version.wrapping_add(peer_version));
            }
        };
        (mask, self.version)
    }
}

impl Drop for Sock {
    fn drop(&mut self) {
        if let Some(name) = &self.name {
            let mut names = NAMES.lock();
            if names.get(&name.key()).is_some_and(|w| w.strong_count() == 0) {
                names.remove(&name.key());
            }
        }
        // A seqpacket peer sees end of file.
        if let State::Messages { peer: Some(peer), .. } = &self.state
            && self.ty == SOCK_SEQPACKET
            && let Some(peer) = peer.upgrade()
        {
            let mut p = peer.lock();
            if let State::Messages { eof, .. } = &mut p.state {
                *eof = true;
            }
            p.touch();
        }
    }
}

/// A pair of connected message sockets (socketpair, or a seqpacket
/// connection).
pub fn message_pair(ty: u64, a: Cred, b: Cred) -> (SockRef, SockRef) {
    let x = Sock::new(ty, Sock::messages(), a);
    let y = Sock::new(ty, Sock::messages(), b);
    for (s, other, cred) in [(&x, &y, b), (&y, &x, a)] {
        let mut s = s.lock();
        if let State::Messages { peer, .. } = &mut s.state {
            *peer = Some(Arc::downgrade(other));
        }
        s.peer_cred = Some(cred);
    }
    (x, y)
}

/// connect() of a stream socket to `listener`: a socket pair, one end
/// queued for accept. EAGAIN if the queue is full.
pub fn connect_stream(listener: &SockRef, me: Option<Name>, cred: Cred) -> Result<(SocketEnd, StreamInfo), Errno> {
    let mut l = listener.lock();
    let (target, lcred) = (l.name.clone(), l.cred);
    let State::Listening { backlog, queue } = &mut l.state else { return Err(ECONNREFUSED) };
    if queue.len() >= *backlog {
        return Err(EAGAIN);
    }
    let slot = Slot::take().ok_or(EAGAIN)?;
    let (mut ours, mut theirs) = ipc::socketpair();
    let mine = StreamInfo { local: me.clone(), peer: target.clone(), peer_cred: lcred };
    ours.unix = Some(alloc::boxed::Box::new(mine.clone()));
    theirs.unix = Some(alloc::boxed::Box::new(StreamInfo { local: target, peer: me, peer_cred: cred }));
    queue.push_back((Incoming::Stream(theirs), slot));
    l.touch();
    Ok((ours, mine))
}

/// connect() of a seqpacket socket to `listener`: a pair of message
/// sockets, one queued for accept.
pub fn connect_packet(listener: &SockRef, me: Option<Name>, cred: Cred) -> Result<SockRef, Errno> {
    let mut l = listener.lock();
    let (target, lcred) = (l.name.clone(), l.cred);
    let State::Listening { backlog, queue } = &mut l.state else { return Err(ECONNREFUSED) };
    if queue.len() >= *backlog {
        return Err(EAGAIN);
    }
    let slot = Slot::take().ok_or(EAGAIN)?;
    let (ours, theirs) = message_pair(SOCK_SEQPACKET, cred, lcred);
    ours.lock().name = me;
    theirs.lock().name = target;
    queue.push_back((Incoming::Packet(theirs), slot));
    l.touch();
    Ok(ours)
}
