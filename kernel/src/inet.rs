//! Network sockets (AF_INET, AF_INET6) without a TCP/IP stack.
//! - A TCP connection to anywhere but the guest itself is one the host makes
//!   and polices (`grix_abi::link`): data and credit go back and forth in
//!   messages, so no buffer here outgrows `link::WINDOW`.
//! - A connection to the guest's own listener (loopback) is a local socket
//!   pair, as AF_UNIX ones are.
//! - UDP only carries DNS: every query to port 53 goes to the host, which
//!   answers it with its own resolver.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use grix_abi::link::{self, Addr, ToGuest, ToHost, WINDOW};
use spin::{Mutex, Once};

use crate::errno::*;
use crate::ipc::{self, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT, EPOLLRDHUP, SocketEnd};
use crate::kmem::Charge;

pub const ECONNREFUSED: Errno = Errno(111);

/// Connections through the host, all processes together (each holds a
/// receive window of kernel memory).
const MAX_CONNS: usize = 256;
/// DNS answers queued on one socket.
const MAX_ANSWERS: usize = 16;
/// Connections waiting in accept queues, all listeners together (each
/// holds a socket pair or a connection that no descriptor counts yet).
const MAX_PENDING: usize = 1024;
static PENDING: AtomicU32 = AtomicU32::new(0);
/// How long an unanswered DNS query counts as something the host may
/// still answer (it may have dropped it).
const DNS_PATIENCE_NS: u64 = 10_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockAddr {
    pub addr: Addr,
    pub port: u16,
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

impl SockAddr {
    pub const UNSPECIFIED_V4: SockAddr = SockAddr { addr: Addr::V4([0; 4]), port: 0 };

    pub fn v4(addr: [u8; 4], port: u16) -> SockAddr {
        SockAddr { addr: Addr::V4(addr), port }
    }

    /// 127.0.0.0/8 and ::1.
    pub fn is_loopback(&self) -> bool {
        match self.addr {
            Addr::V4(a) => a[0] == 127,
            Addr::V6(a) => a == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }
    }

    /// The guest itself: loopback, or its own address.
    pub fn is_local(&self) -> bool {
        self.is_loopback() || self.addr == Addr::V4(link::GUEST_V4)
    }

    pub fn is_unspecified(&self) -> bool {
        match self.addr {
            Addr::V4(a) => a == [0; 4],
            Addr::V6(a) => a == [0; 16],
        }
    }

    /// A struct sockaddr_in (or sockaddr_in6 for a v6 socket, with v4
    /// addresses mapped into ::ffff:0:0/96). A v6 address can't be told to
    /// a v4 socket: it gets 0.0.0.0.
    pub fn encode(&self, v6: bool) -> Vec<u8> {
        let port = self.port.to_be_bytes();
        match (self.addr, v6) {
            (Addr::V6(_), false) => SockAddr::v4([0; 4], self.port).encode(false),
            (Addr::V4(a), false) => {
                let mut b = alloc::vec![0u8; 16];
                b[..2].copy_from_slice(&AF_INET.to_le_bytes());
                b[2..4].copy_from_slice(&port);
                b[4..8].copy_from_slice(&a);
                b
            }
            (addr, _) => {
                let a = match addr {
                    Addr::V6(a) => a,
                    Addr::V4(v4) => {
                        let mut m = [0u8; 16];
                        m[10] = 0xff;
                        m[11] = 0xff;
                        m[12..].copy_from_slice(&v4);
                        m
                    }
                };
                let mut b = alloc::vec![0u8; 28];
                b[..2].copy_from_slice(&AF_INET6.to_le_bytes());
                b[2..4].copy_from_slice(&port);
                b[8..24].copy_from_slice(&a);
                b
            }
        }
    }

    /// From a struct sockaddr_in / sockaddr_in6 (v4-mapped v6 addresses
    /// become v4 ones).
    pub fn decode(b: &[u8]) -> Result<SockAddr, Errno> {
        let family = u16::from_le_bytes(b.get(..2).ok_or(EINVAL)?.try_into().unwrap());
        let port = u16::from_be_bytes(b.get(2..4).ok_or(EINVAL)?.try_into().unwrap());
        match family {
            AF_INET if b.len() >= 8 => Ok(SockAddr::v4(b[4..8].try_into().unwrap(), port)),
            AF_INET6 if b.len() >= 24 => {
                let a: [u8; 16] = b[8..24].try_into().unwrap();
                if a[..10] == [0; 10] && a[10] == 0xff && a[11] == 0xff {
                    Ok(SockAddr::v4(a[12..].try_into().unwrap(), port))
                } else {
                    Ok(SockAddr { addr: Addr::V6(a), port })
                }
            }
            AF_INET | AF_INET6 => Err(EINVAL),
            _ => Err(Errno(97)), // EAFNOSUPPORT
        }
    }
}

fn send(msg: ToHost) {
    crate::console::write(grix_abi::wire::Channel::Link, &msg.encode());
}

// ---------------------------------------------------------------- connections through the host

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnState {
    Connecting,
    Open,
    /// It couldn't be made, or broke.
    Failed(Errno),
}

/// A TCP connection the host holds for us.
pub struct Conn {
    pub id: u32,
    pub state: ConnState,
    /// Data from the peer, at most WINDOW (charged up front).
    rx: VecDeque<u8>,
    _charge: Charge,
    pub rx_eof: bool,
    /// shutdown(SHUT_RD): reads return 0, and data is dropped.
    pub rx_shut: bool,
    /// Bytes the host has room for.
    pub tx_credit: u32,
    pub tx_shut: bool,
    /// Bytes read since credit was last returned.
    owed: u32,
    pub local: SockAddr,
    pub peer: SockAddr,
    pub version: u64,
}

static CONNS: Mutex<BTreeMap<u32, Weak<Mutex<Conn>>>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_PORT: AtomicU32 = AtomicU32::new(0);

/// A local port for a socket that didn't bind one (32768-60999, Linux's
/// ip_local_port_range).
pub fn ephemeral_port() -> u16 {
    (32768 + NEXT_PORT.fetch_add(1, Ordering::Relaxed) % (61000 - 32768)) as u16
}

impl Conn {
    fn register(c: Conn) -> Result<Arc<Mutex<Conn>>, Errno> {
        let mut conns = CONNS.lock();
        conns.retain(|_, w| w.strong_count() > 0);
        if conns.len() >= MAX_CONNS {
            return Err(Errno(105)); // ENOBUFS
        }
        let id = c.id;
        let c = Arc::new(Mutex::new(c));
        conns.insert(id, Arc::downgrade(&c));
        Ok(c)
    }

    fn new(id: u32, state: ConnState, local: SockAddr, peer: SockAddr) -> Result<Conn, Errno> {
        let charge = Charge::new(WINDOW as u64).map_err(|_| Errno(105))?;
        let tx_credit = if state == ConnState::Open { WINDOW } else { 0 };
        Ok(Conn {
            id,
            state,
            // All of it now: data never outgrows the window, and the
            // charge then matches what's really held.
            rx: VecDeque::with_capacity(WINDOW as usize),
            _charge: charge,
            rx_eof: false,
            rx_shut: false,
            tx_credit,
            tx_shut: false,
            owed: 0,
            local,
            peer,
            version: 0,
        })
    }

    /// Ask the host for a connection to `peer`. It's `Connecting` until the
    /// host answers.
    pub fn connect(peer: SockAddr) -> Result<Arc<Mutex<Conn>>, Errno> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) & !link::HOST_ID;
        let local = SockAddr::v4(link::GUEST_V4, ephemeral_port());
        let c = Conn::register(Conn::new(id, ConnState::Connecting, local, peer)?)?;
        send(ToHost::Connect { id, addr: peer.addr, port: peer.port });
        Ok(c)
    }

    fn touch(&mut self) {
        self.version += 1;
        ipc::changed();
    }

    pub fn available(&self) -> usize {
        self.rx.len()
    }

    /// Take received bytes into `out` (or just look, with `peek`), giving
    /// the host credit for them. `None`: nothing yet, wait.
    pub fn read(&mut self, out: &mut [u8], peek: bool) -> Option<Result<usize, Errno>> {
        if !self.rx.is_empty() && !self.rx_shut {
            let n = out.len().min(self.rx.len());
            for (o, b) in out.iter_mut().zip(self.rx.iter()) {
                *o = *b;
            }
            if !peek {
                self.rx.drain(..n);
                self.owed += n as u32;
                // Hand credit back in batches, or when the buffer runs dry.
                if self.owed >= WINDOW / 4 || self.rx.is_empty() {
                    send(ToHost::Credit { id: self.id, bytes: core::mem::take(&mut self.owed) });
                }
            }
            return Some(Ok(n));
        }
        match self.state {
            _ if self.rx_eof || self.rx_shut => Some(Ok(0)),
            ConnState::Failed(e) => Some(Err(e)),
            _ => None,
        }
    }

    pub fn poll(&self) -> (u32, u64) {
        let mask = match self.state {
            ConnState::Connecting => 0,
            ConnState::Failed(_) => EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
            ConnState::Open => {
                let readable = !self.rx.is_empty() || self.rx_eof || self.rx_shut;
                let mut m = if readable { EPOLLIN } else { 0 };
                if self.rx_eof {
                    m |= EPOLLRDHUP;
                }
                if self.tx_credit > 0 && !self.tx_shut {
                    m |= EPOLLOUT;
                }
                if self.rx_eof && self.tx_shut {
                    m |= EPOLLHUP;
                }
                m
            }
        };
        (mask, self.version)
    }

    /// shutdown(SHUT_WR): the peer sees end-of-file.
    pub fn shutdown_write(&mut self) {
        if !self.tx_shut {
            self.tx_shut = true;
            if self.state == ConnState::Open {
                send(ToHost::Shutdown { id: self.id });
            }
            self.touch();
        }
    }

    pub fn shutdown_read(&mut self) {
        self.rx_shut = true;
        self.rx.clear();
        self.touch();
    }

    /// Note that `n` bytes were sent: they use up credit.
    pub fn sent(&mut self, n: usize) {
        self.tx_credit -= n as u32;
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        CONNS.lock().remove(&self.id);
        send(ToHost::Close { id: self.id });
    }
}

fn conn(id: u32) -> Option<Arc<Mutex<Conn>>> {
    CONNS.lock().get(&id).and_then(Weak::upgrade)
}

// ---------------------------------------------------------------- listeners

/// A place in the accept queues (MAX_PENDING of them in all).
pub struct Slot(());

impl Slot {
    fn take() -> Option<Slot> {
        if PENDING.fetch_add(1, Ordering::Relaxed) as usize >= MAX_PENDING {
            PENDING.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Slot(()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        PENDING.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection waiting to be accepted.
pub enum Pending {
    /// From a socket in the guest: our end, its address and ours.
    Local { end: SocketEnd, peer: SockAddr, local: SockAddr, _slot: Slot },
    /// Through a port forwarded from the host.
    Remote(Arc<Mutex<Conn>>, Slot),
}

pub struct Listener {
    pub port: u16,
    /// What it bound: which loopback connections reach it.
    pub addr: Addr,
    backlog: usize,
    pub queue: VecDeque<Pending>,
    pub version: u64,
}

static LISTENERS: Mutex<BTreeMap<u16, Weak<Mutex<Listener>>>> = Mutex::new(BTreeMap::new());

impl Listener {
    /// Listen on `port` of `addr` (port 0: pick one). EADDRINUSE if
    /// someone already listens there.
    pub fn listen(addr: Addr, port: u16, backlog: usize) -> Result<Arc<Mutex<Listener>>, Errno> {
        let mut listeners = LISTENERS.lock();
        listeners.retain(|_, w| w.strong_count() > 0);
        let port = if port != 0 {
            port
        } else {
            (0..1000).map(|_| ephemeral_port()).find(|p| !listeners.contains_key(p)).ok_or(Errno(98))?
        };
        if listeners.contains_key(&port) {
            return Err(Errno(98)); // EADDRINUSE
        }
        let l = Arc::new(Mutex::new(Listener {
            port,
            addr,
            backlog: backlog.clamp(1, 4096),
            queue: VecDeque::new(),
            version: 0,
        }));
        listeners.insert(port, Arc::downgrade(&l));
        Ok(l)
    }

    pub fn is_bound(port: u16) -> bool {
        LISTENERS.lock().get(&port).is_some_and(|w| w.strong_count() > 0)
    }

    fn push(&mut self, p: Pending) -> Result<(), Pending> {
        if self.queue.len() >= self.backlog {
            return Err(p);
        }
        self.queue.push_back(p);
        self.version += 1;
        ipc::changed();
        Ok(())
    }

    pub fn poll(&self) -> (u32, u64) {
        (if self.queue.is_empty() { 0 } else { EPOLLIN }, self.version)
    }

    /// Does a connection from the guest to `to` reach it? As on Linux: the same
    /// family and address, or the wildcard (a v6 one takes v4 too).
    fn takes(&self, to: SockAddr) -> bool {
        let wildcard = SockAddr { addr: self.addr, port: 0 }.is_unspecified();
        match (self.addr, to.addr) {
            (Addr::V6(_), _) if wildcard => true,
            (Addr::V4(_), Addr::V4(_)) => wildcard || self.addr == to.addr,
            (Addr::V6(a), Addr::V6(b)) => a == b,
            _ => false,
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let mut listeners = LISTENERS.lock();
        if listeners.get(&self.port).is_some_and(|w| w.strong_count() == 0) {
            listeners.remove(&self.port);
        }
    }
}

/// connect() to the guest's own address: a socket pair, one end queued on
/// the listener. ECONNREFUSED if nothing listens there (or its queue is full).
pub fn connect_local(peer: SockAddr) -> Result<(SocketEnd, SockAddr), Errno> {
    let listener = LISTENERS.lock().get(&peer.port).and_then(Weak::upgrade).ok_or(ECONNREFUSED)?;
    if !listener.lock().takes(peer) {
        return Err(ECONNREFUSED);
    }
    let slot = Slot::take().ok_or(ECONNREFUSED)?;
    let local = SockAddr { addr: peer.addr, port: ephemeral_port() };
    let (ours, theirs) = ipc::socketpair();
    listener
        .lock()
        .push(Pending::Local { end: theirs, peer: local, local: peer, _slot: slot })
        .map_err(|_| ECONNREFUSED)?;
    Ok((ours, local))
}

// ---------------------------------------------------------------- DNS

/// A UDP socket's DNS traffic: queries go to the host, answers queue here.
pub struct Dns {
    id: u32,
    answers: VecDeque<Vec<u8>>,
    charge: Charge,
    /// Queries sent and not answered yet, and when the last one went.
    pub waiting: usize,
    last_query_ns: u64,
    /// (DNS id, server) of recent queries.
    servers: Vec<(u16, SockAddr)>,
    pub version: u64,
}

static DNS: Mutex<BTreeMap<u32, Weak<Mutex<Dns>>>> = Mutex::new(BTreeMap::new());

impl Dns {
    pub fn new() -> Arc<Mutex<Dns>> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) & !link::HOST_ID;
        let d = Arc::new(Mutex::new(Dns {
            id,
            answers: VecDeque::new(),
            charge: Charge::default(),
            waiting: 0,
            last_query_ns: 0,
            servers: Vec::new(),
            version: 0,
        }));
        let mut all = DNS.lock();
        all.retain(|_, w| w.strong_count() > 0);
        all.insert(id, Arc::downgrade(&d));
        d
    }

    pub fn query(&mut self, q: &[u8]) {
        self.waiting += 1;
        self.last_query_ns = crate::time::monotonic_ns();
        send(ToHost::Dns { id: self.id, query: q });
    }

    pub fn answer(&mut self) -> Option<Vec<u8>> {
        let a = self.answers.pop_front()?;
        let held = self.answers.iter().map(Vec::len).sum::<usize>();
        let _ = self.charge.resize(held as u64);
        Some(a)
    }

    pub fn peek_len(&self) -> Option<usize> {
        self.answers.front().map(Vec::len)
    }

    pub fn peek(&self) -> Option<Vec<u8>> {
        self.answers.front().cloned()
    }

    pub fn poll(&self) -> (u32, u64) {
        (EPOLLOUT | if self.answers.is_empty() { 0 } else { EPOLLIN }, self.version)
    }
}

// ---------------------------------------------------------------- from the host

/// Guest ports the host forwards connections to (from the boot image).
static FORWARDS: Once<Vec<u16>> = Once::new();

pub fn init(forwards: Vec<u16>) {
    FORWARDS.call_once(|| forwards);
}

/// A message from the host's network proxy.
pub fn from_host(payload: &[u8]) {
    let Ok(msg) = ToGuest::decode(payload) else { return };
    match msg {
        ToGuest::Connected { id } => {
            if let Some(c) = conn(id) {
                let mut c = c.lock();
                if c.state == ConnState::Connecting {
                    c.state = ConnState::Open;
                    c.tx_credit = WINDOW;
                    if c.tx_shut {
                        send(ToHost::Shutdown { id });
                    }
                }
                c.touch();
            }
        }
        ToGuest::Failed { id, errno } => {
            if let Some(c) = conn(id) {
                let mut c = c.lock();
                c.state = ConnState::Failed(Errno(errno.max(1) as u32));
                c.touch();
            }
        }
        ToGuest::Data { id, data } => {
            if let Some(c) = conn(id) {
                let mut c = c.lock();
                // The host keeps within the window it was given; anything
                // past it has nowhere to go.
                let room = (WINDOW as usize).saturating_sub(c.rx.len());
                if !c.rx_shut {
                    c.rx.extend(&data[..data.len().min(room)]);
                }
                c.touch();
            }
        }
        ToGuest::Credit { id, bytes } => {
            if let Some(c) = conn(id) {
                let mut c = c.lock();
                c.tx_credit = c.tx_credit.saturating_add(bytes).min(WINDOW);
                c.touch();
            }
        }
        ToGuest::Eof { id } => {
            if let Some(c) = conn(id) {
                let mut c = c.lock();
                c.rx_eof = true;
                c.touch();
            }
        }
        ToGuest::DnsAnswer { id, answer } => {
            if let Some(d) = DNS.lock().get(&id).and_then(Weak::upgrade) {
                let mut d = d.lock();
                d.waiting = d.waiting.saturating_sub(1);
                let held = d.answers.iter().map(Vec::len).sum::<usize>() + answer.len();
                if d.answers.len() < MAX_ANSWERS && d.charge.resize(held as u64).is_ok() {
                    d.answers.push_back(answer.into());
                }
                d.version += 1;
                ipc::changed();
            }
        }
        ToGuest::Incoming { id, port, peer, peer_port } => {
            let listener = LISTENERS.lock().get(&port).and_then(Weak::upgrade);
            let local = SockAddr::v4(link::GUEST_V4, port);
            let made = Conn::new(id, ConnState::Open, local, SockAddr { addr: peer, port: peer_port });
            match (listener, made.and_then(Conn::register), Slot::take()) {
                // A refused Conn says Close as it's dropped.
                (Some(l), Ok(c), Some(slot)) => {
                    let _ = l.lock().push(Pending::Remote(c, slot));
                }
                (_, Ok(_), _) => {}
                // Nobody listens there (yet), or no room for it.
                (_, Err(_), _) => send(ToHost::Close { id }),
            }
        }
    }
}

/// Could the host still wake a thread waiting on the network: a
/// connection still open or being made, a DNS query unanswered, or a
/// listener on a forwarded port?
pub fn host_pending() -> bool {
    let conns: Vec<_> = CONNS.lock().values().filter_map(Weak::upgrade).collect();
    if conns.iter().any(|c| {
        let c = c.lock();
        match c.state {
            ConnState::Connecting => true,
            ConnState::Open => !c.rx_eof || c.tx_credit < WINDOW,
            ConnState::Failed(_) => false,
        }
    }) {
        return true;
    }
    let now = crate::time::monotonic_ns();
    let dns: Vec<_> = DNS.lock().values().filter_map(Weak::upgrade).collect();
    if dns.iter().any(|d| {
        let d = d.lock();
        d.waiting > 0 && now.saturating_sub(d.last_query_ns) < DNS_PATIENCE_NS
    }) {
        return true;
    }
    let forwards = FORWARDS.get().map_or(&[][..], |f| &f[..]);
    forwards.iter().any(|&p| Listener::is_bound(p))
}

// ---------------------------------------------------------------- sockets

/// What an AF_INET/AF_INET6 socket is connected to.
pub enum State {
    Idle,
    Listening(Arc<Mutex<Listener>>),
    /// Through the host.
    Remote(Arc<Mutex<Conn>>),
    /// To (or accepted from) a socket in the guest.
    Local {
        end: SocketEnd,
        local: SockAddr,
        peer: SockAddr,
    },
    /// A UDP socket that has sent DNS queries.
    Dns(Arc<Mutex<Dns>>),
}

pub struct Inet {
    pub v6: bool,
    pub dgram: bool,
    pub bound: Option<SockAddr>,
    pub state: State,
    /// A blocking connect is waiting: when it re-runs and finds the
    /// connection made, it succeeds (another connect would get EISCONN).
    pub connecting: bool,
    /// UDP: where connect() pointed it.
    pub peer: Option<SockAddr>,
    /// SO_RCVTIMEO and SO_SNDTIMEO, in ns.
    pub rcvtimeo: Option<u64>,
    pub sndtimeo: Option<u64>,
}

impl Inet {
    pub fn new(v6: bool, dgram: bool) -> Inet {
        Inet {
            v6,
            dgram,
            bound: None,
            state: State::Idle,
            connecting: false,
            peer: None,
            rcvtimeo: None,
            sndtimeo: None,
        }
    }

    pub fn poll(&self) -> (u32, u64) {
        match &self.state {
            // Like Linux's tcp_poll for a socket that isn't connected.
            State::Idle if self.dgram => (EPOLLOUT, 0),
            State::Idle => (EPOLLOUT | EPOLLHUP, 0),
            State::Listening(l) => l.lock().poll(),
            State::Remote(c) => c.lock().poll(),
            State::Local { end, .. } => end.poll(),
            State::Dns(d) => d.lock().poll(),
        }
    }

    /// The socket's own address (getsockname).
    pub fn local_addr(&self) -> SockAddr {
        match &self.state {
            State::Remote(c) => c.lock().local,
            State::Local { local, .. } => *local,
            State::Listening(l) => SockAddr { port: l.lock().port, ..self.bound.unwrap_or(SockAddr::UNSPECIFIED_V4) },
            _ => self.bound.unwrap_or(SockAddr::UNSPECIFIED_V4),
        }
    }

    /// The peer's address (getpeername).
    pub fn peer_addr(&self) -> Option<SockAddr> {
        match &self.state {
            State::Remote(c) => {
                let c = c.lock();
                (c.state == ConnState::Open).then_some(c.peer)
            }
            State::Local { peer, .. } => Some(*peer),
            _ => self.peer,
        }
    }
}

impl Dns {
    /// Remember which server a query (by its DNS id) went to, so the
    /// answer appears to come from there: resolvers check.
    pub fn sent_to(&mut self, query: &[u8], server: SockAddr) {
        if let [a, b, ..] = *query {
            self.servers.retain(|(id, _)| *id != u16::from_be_bytes([a, b]));
            if self.servers.len() >= MAX_ANSWERS {
                self.servers.remove(0);
            }
            self.servers.push((u16::from_be_bytes([a, b]), server));
        }
    }

    /// Where the answer `a` came from.
    pub fn server_of(&self, a: &[u8]) -> SockAddr {
        let id = a.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
        self.servers.iter().find(|(q, _)| Some(*q) == id).map_or(SockAddr::v4(link::DNS_V4, 53), |(_, s)| *s)
    }
}
