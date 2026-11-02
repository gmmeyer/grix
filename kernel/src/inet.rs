//! Network sockets (AF_INET, AF_INET6). The `native` stack, described here,
//! has no TCP/IP in the guest; in the `vm` one (`netstack`) the same sockets
//! sit on the guest's own, which takes what would go to the host.
//! - A TCP connection to anywhere but the guest itself is one the host makes
//!   and polices (`grix_abi::link`): data and credit go back and forth in
//!   messages, so no buffer here outgrows `link::WINDOW`.
//! - A connection to the guest's own listener (loopback) is a local socket
//!   pair, as AF_UNIX ones are.
//! - UDP: a query to port 53 goes to the host, which answers it with its
//!   own resolver; a datagram to the guest's own address to the socket
//!   bound there; any other through the host, to destinations its policy
//!   allows (`Udp`). Datagrams to a port forwarded from the host come in
//!   to the socket bound there, and its replies to their senders go back
//!   out the way they came (`forward_peer`).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use grix_abi::link::{self, Addr, ToGuest, ToHost, WINDOW};
use spin::{Mutex, Once};

use crate::errno::*;
use crate::ipc::{self, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT, EPOLLRDHUP, SocketEnd};
use crate::kmem::Charge;
use crate::netstack;

pub const ECONNREFUSED: Errno = Errno(111);

/// Connections through the host, all processes together. Each holds a
/// receive window charged to `kmem`, which is what bounds kernel memory:
/// this bounds what the host's proxy is asked for, two threads each.
const MAX_CONNS: usize = 2048;
/// DNS answers queued on one socket.
const MAX_ANSWERS: usize = 16;
/// Connections waiting in accept queues, all listeners together (each
/// holds a socket pair or a connection that no descriptor counts yet,
/// charged to `kmem`: `PENDING_COST`).
const MAX_PENDING: usize = 16384;
/// A connection's place in a queue, and a socket pair's two pipes.
const PENDING_COST: u64 = (core::mem::size_of::<Pending>() + 2 * core::mem::size_of::<ipc::Pipe>() + 3 * 64) as u64;
static PENDING: AtomicU32 = AtomicU32::new(0);
/// How long an unanswered DNS query counts as something the host may
/// still answer (it may have dropped it).
const DNS_PATIENCE_NS: u64 = 10_000_000_000;

/// ::1.
pub const LOOPBACK_V6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// One of the guest's own addresses on eth0 (10.0.2.15, fd00::15).
pub fn is_own(a: Addr) -> bool {
    a == Addr::V4(link::GUEST_V4) || a == Addr::V6(link::GUEST_V6)
}

/// The guest's address a connection or datagram to `to` (not the guest
/// itself) leaves from, as Linux's route lookup picks it: eth0's IPv6
/// address for an IPv6 destination, its IPv4 one otherwise. What
/// getsockname says matters: RFC 6724's sorting (glibc, Go) compares it
/// with each destination to find which to try first.
pub fn source_for(to: Addr) -> Addr {
    match to {
        Addr::V6(_) if crate::netlink::eth0() => Addr::V6(link::GUEST_V6),
        _ => Addr::V4(link::GUEST_V4),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
        self.is_loopback() || is_own(self.addr)
    }

    /// Where a connect to it goes: the unspecified address means loopback,
    /// as Linux's tcp_v4_connect, tcp_v6_connect and UDP's connect have it.
    pub fn or_loopback(self) -> SockAddr {
        match self.addr {
            Addr::V4([0, 0, 0, 0]) => SockAddr::v4([127, 0, 0, 1], self.port),
            Addr::V6(a) if a == [0; 16] => SockAddr { addr: Addr::V6(LOOPBACK_V6), port: self.port },
            _ => self,
        }
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
    if netstack::active() {
        netstack::handle(msg);
    } else {
        crate::console::write(grix_abi::wire::Channel::Link, &msg.encode());
    }
}

/// What a connection may have on its way to the peer: what's written has
/// to fit in the `vm` stack's socket, or in the host's window.
fn send_window() -> u32 {
    if netstack::active() { netstack::BUFFER as u32 } else { WINDOW }
}

/// `data` for connection `id`, within its credit, or false if there's no
/// room now. (Never for a kernel's own message, which waits for room: a
/// program's write doesn't.)
pub fn write_data(id: u32, data: &[u8]) -> bool {
    if netstack::active() {
        netstack::handle(ToHost::Data { id, data });
        return true;
    }
    crate::console::try_write(grix_abi::wire::Channel::Link, &ToHost::Data { id, data }.encode())
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

/// Connections through the host, and DNS lookups, still going: what a
/// snapshot can't carry (the host's ends don't come with it).
pub fn host_state() -> usize {
    let conns = CONNS.lock().values().filter(|w| w.strong_count() > 0).count() + netstack::sockets();
    let udps = UDPS
        .lock()
        .values()
        .filter_map(Weak::upgrade)
        .filter(|u| {
            let u = u.lock();
            u.waiting > 0 || u.asking > 0 || u.used_host
        })
        .count();
    conns + udps
}

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
            crate::stats::hit(grix_abi::stats::Limit::Connections);
            return Err(Errno(105)); // ENOBUFS
        }
        let id = c.id;
        let c = Arc::new(Mutex::new(c));
        conns.insert(id, Arc::downgrade(&c));
        Ok(c)
    }

    fn new(id: u32, state: ConnState, local: SockAddr, peer: SockAddr) -> Result<Conn, Errno> {
        let charge = Charge::new(WINDOW as u64).map_err(|_| Errno(105))?;
        let tx_credit = if state == ConnState::Open { send_window() } else { 0 };
        // All of it now: data never outgrows the window, and the charge
        // then matches what's really held.
        let mut rx = VecDeque::new();
        rx.try_reserve_exact(WINDOW as usize).map_err(|_| Errno(105))?;
        Ok(Conn {
            id,
            state,
            rx,
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
        let local = SockAddr { addr: source_for(peer.addr), port: ephemeral_port() };
        let c = Conn::register(Conn::new(id, ConnState::Connecting, local, peer)?)?;
        if netstack::active() {
            netstack::connect(id, local, peer);
        } else {
            send(ToHost::Connect { id, addr: peer.addr, port: peer.port });
        }
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
pub struct Slot(#[allow(dead_code)] Charge);

impl Slot {
    pub fn take() -> Option<Slot> {
        let charge = (PENDING.load(Ordering::Relaxed) as usize) < MAX_PENDING;
        let Some(charge) = charge.then(|| Charge::new(PENDING_COST).ok()).flatten() else {
            crate::stats::hit(grix_abi::stats::Limit::Connections);
            return None;
        };
        // Under the kernel lock: check-then-add doesn't race.
        PENDING.fetch_add(1, Ordering::Relaxed);
        Some(Slot(charge))
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
    Remote(Arc<Mutex<Conn>>, #[allow(dead_code)] Slot),
}

pub struct Listener {
    pub port: u16,
    /// What it bound: which loopback connections reach it.
    pub addr: Addr,
    /// IPV6_V6ONLY: a v6 wildcard that leaves v4 to another listener.
    v6only: bool,
    pub queue: VecDeque<Pending>,
    pub version: u64,
}

/// Each port's listeners: one, or a v4 one and a v6 one with IPV6_V6ONLY
/// (as servers that listen on both, like Redis, make them).
static LISTENERS: Mutex<BTreeMap<u16, Vec<Weak<Mutex<Listener>>>>> = Mutex::new(BTreeMap::new());

/// Which families a listener on `addr` takes: (v4, v6). A v6 wildcard
/// takes v4 too unless it's IPV6_V6ONLY.
fn families(addr: Addr, v6only: bool) -> (bool, bool) {
    match addr {
        Addr::V4(_) => (true, false),
        Addr::V6(a) => (a == [0; 16] && !v6only, true),
    }
}

/// The live listeners on `port`.
fn listeners_on(port: u16) -> Vec<Arc<Mutex<Listener>>> {
    LISTENERS.lock().get(&port).map_or(Vec::new(), |v| v.iter().filter_map(Weak::upgrade).collect())
}

impl Listener {
    /// Listen on `port` of `addr` (port 0: pick one). EADDRINUSE if
    /// someone already listens there.
    pub fn listen(addr: Addr, port: u16, v6only: bool) -> Result<Arc<Mutex<Listener>>, Errno> {
        let port = if port != 0 {
            port
        } else {
            (0..1000).map(|_| ephemeral_port()).find(|&p| !Listener::is_bound(p)).ok_or(Errno(98))?
        };
        if Listener::conflicts(addr, port, v6only) {
            return Err(Errno(98)); // EADDRINUSE
        }
        let l = Arc::new(Mutex::new(Listener { port, addr, v6only, queue: VecDeque::new(), version: 0 }));
        let mut listeners = LISTENERS.lock();
        let on = listeners.entry(port).or_default();
        on.retain(|w| w.strong_count() > 0);
        on.push(Arc::downgrade(&l));
        Ok(l)
    }

    pub fn is_bound(port: u16) -> bool {
        !listeners_on(port).is_empty()
    }

    /// Would a listener on `addr`, `port` take connections one there
    /// already does?
    pub fn conflicts(addr: Addr, port: u16, v6only: bool) -> bool {
        let (v4, v6) = families(addr, v6only);
        listeners_on(port).iter().any(|l| {
            let l = l.lock();
            let (lv4, lv6) = families(l.addr, l.v6only);
            (v4 && lv4) || (v6 && lv6)
        })
    }

    /// The listener a connection to `to` reaches.
    fn find(to: SockAddr) -> Option<Arc<Mutex<Listener>>> {
        listeners_on(to.port).into_iter().find(|l| l.lock().takes(to))
    }

    /// Queue a connection. listen's backlog bounds nothing: a queue that
    /// full on Linux has clients wait, never refused, and the program sees
    /// the same from a longer queue (`Slot`s bound them all).
    fn push(&mut self, p: Pending) {
        self.queue.push_back(p);
        self.version += 1;
        ipc::changed();
    }

    pub fn poll(&self) -> (u32, u64) {
        (if self.queue.is_empty() { 0 } else { EPOLLIN }, self.version)
    }

    /// Does a connection from the guest to `to` reach it? As on Linux: the same
    /// family and address, or the wildcard (a v6 one takes v4 too).
    fn takes(&self, to: SockAddr) -> bool {
        let wildcard = SockAddr { addr: self.addr, port: 0 }.is_unspecified();
        match (self.addr, to.addr) {
            (Addr::V6(_), Addr::V4(_)) if wildcard => !self.v6only,
            (Addr::V6(_), Addr::V6(_)) if wildcard => true,
            (Addr::V4(_), Addr::V4(_)) => wildcard || self.addr == to.addr,
            (Addr::V6(a), Addr::V6(b)) => a == b,
            _ => false,
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let mut listeners = LISTENERS.lock();
        if let Some(on) = listeners.get_mut(&self.port) {
            on.retain(|w| w.strong_count() > 0);
            if on.is_empty() {
                listeners.remove(&self.port);
            }
        }
    }
}

/// connect() to the guest's own address: a socket pair, one end queued on
/// the listener. ECONNREFUSED if nothing listens there (or the queues are full).
pub fn connect_local(peer: SockAddr) -> Result<(SocketEnd, SockAddr), Errno> {
    let listener = Listener::find(peer).ok_or(ECONNREFUSED)?;
    let slot = Slot::take().ok_or(ECONNREFUSED)?;
    let local = SockAddr { addr: peer.addr, port: ephemeral_port() };
    let (ours, theirs) = ipc::socketpair();
    listener.lock().push(Pending::Local { end: theirs, peer: local, local: peer, _slot: slot });
    Ok((ours, local))
}

// ---------------------------------------------------------------- UDP

/// Datagrams queued on one socket, and bytes (each counted with an
/// overhead, so empty ones fill it too).
const UDP_QUEUE: usize = 256;
const UDP_BYTES: usize = 212_992;
const DATAGRAM_OVERHEAD: usize = 64;
/// Destinations one socket remembers the host's say on.
const MAX_VERDICTS: usize = 256;
/// A destination's share of the heap (half-empty B-tree nodes).
const VERDICT_COST: u64 = 2 * (core::mem::size_of::<SockAddr>() + 8) as u64;
/// How long an unanswered question to the host counts as asked.
pub const VERDICT_PATIENCE_NS: u64 = 1_000_000_000;

/// A UDP socket's traffic. A DNS query (to port 53 anywhere but the guest
/// itself) goes to the host's resolver; a datagram to the guest's own
/// addresses straight to the socket bound there; any other through the
/// host, to destinations its policy allowed (asked once per destination).
/// What makes a socket an ICMP one (`socket(.., SOCK_DGRAM or SOCK_RAW,
/// IPPROTO_ICMP)`): it's a `Udp` otherwise, as it's asked for and allowed
/// per destination the same way, only with `link::ICMP_PORT`.
#[derive(Clone, Copy, Debug)]
pub struct Icmp {
    /// SOCK_RAW: IPv4's replies are read with their IP header, as Linux's.
    pub raw: bool,
    pub v6: bool,
    /// The identifier of the last request: the host's socket uses its
    /// own, and a program looks for what it sent.
    pub ident: u16,
}

impl Icmp {
    /// What the program reads of echo reply `msg`, from `from` to `to`.
    fn as_read(&self, from: Addr, to: Addr, msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < 8 {
            return None;
        }
        let mut m = msg.to_vec();
        m[4..6].copy_from_slice(&self.ident.to_be_bytes());
        m[2..4].fill(0);
        let sum = match (from, to) {
            // IPv6's covers the addresses, as UDP's does.
            (Addr::V6(a), Addr::V6(b)) => {
                let mut head = alloc::vec::Vec::with_capacity(40);
                head.extend_from_slice(&a);
                head.extend_from_slice(&b);
                head.extend_from_slice(&(m.len() as u32).to_be_bytes());
                head.extend_from_slice(&[0, 0, 0, 58]);
                checksum(&[&head, &m])
            }
            _ => checksum(&[&m]),
        };
        m[2..4].copy_from_slice(&sum.to_be_bytes());
        let (Addr::V4(src), Addr::V4(dst), true) = (from, to, self.raw && !self.v6) else { return Some(m) };
        let mut ip = alloc::vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + m.len()) as u16).to_be_bytes());
        ip[6] = 0x40; // don't fragment
        ip[8] = 64; // the TTL: the host's reply says, and isn't asked
        ip[9] = 1;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        let sum = checksum(&[&ip]);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        ip.extend_from_slice(&m);
        Some(ip)
    }
}

/// The internet checksum of `parts` together, each an even length but the
/// last.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for part in parts {
        for word in part.chunks(2) {
            sum += u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub struct Udp {
    pub id: u32,
    /// Datagrams in, and who sent them.
    rx: VecDeque<(SockAddr, Vec<u8>)>,
    bytes: usize,
    charge: Charge,
    /// DNS queries not answered yet, when the last one went, and (DNS id,
    /// server) of recent ones (resolvers check where an answer came from).
    pub waiting: usize,
    last_query_ns: u64,
    servers: Vec<(u16, SockAddr)>,
    /// The host's say on each destination, and the ones it's deciding
    /// (since when: a lost answer is asked again).
    verdicts: BTreeMap<SockAddr, bool>,
    asked: BTreeMap<SockAddr, u64>,
    /// Both tables' room: small for one socket, but sockets are many.
    known: Charge,
    pub asking: usize,
    /// It asked the host (which may hold a socket for it), and was allowed
    /// somewhere (replies may come any time).
    used_host: bool,
    talking: bool,
    /// The host couldn't take a destination now: the send that asked gets
    /// ENOBUFS.
    pub busy: bool,
    /// Its local address (bound, or picked at its first send).
    pub local: Option<SockAddr>,
    /// connect()ed: datagrams only from there.
    pub peer: Option<SockAddr>,
    /// An ICMP socket, not a UDP one.
    pub icmp: Option<Icmp>,
    pub version: u64,
}

pub type UdpRef = Arc<Mutex<Udp>>;

static UDPS: Mutex<BTreeMap<u32, Weak<Mutex<Udp>>>> = Mutex::new(BTreeMap::new());
/// Local ports, for datagrams from the guest to itself.
static UDP_PORTS: Mutex<BTreeMap<u16, Weak<Mutex<Udp>>>> = Mutex::new(BTreeMap::new());

fn udp(id: u32) -> Option<UdpRef> {
    UDPS.lock().get(&id).and_then(Weak::upgrade)
}

impl Udp {
    pub fn new(peer: Option<SockAddr>) -> UdpRef {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) & !link::HOST_ID;
        let u = Arc::new(Mutex::new(Udp {
            id,
            rx: VecDeque::new(),
            bytes: 0,
            charge: Charge::default(),
            waiting: 0,
            last_query_ns: 0,
            servers: Vec::new(),
            verdicts: BTreeMap::new(),
            asked: BTreeMap::new(),
            known: Charge::default(),
            asking: 0,
            used_host: false,
            talking: false,
            busy: false,
            local: None,
            peer,
            icmp: None,
            version: 0,
        }));
        let mut all = UDPS.lock();
        all.retain(|_, w| w.strong_count() > 0);
        all.insert(id, Arc::downgrade(&u));
        u
    }

    /// Take local address `addr` (port 0: pick one). EADDRINUSE if its
    /// port is taken.
    pub fn bind(this: &UdpRef, addr: SockAddr) -> Result<SockAddr, Errno> {
        let mut ports = UDP_PORTS.lock();
        ports.retain(|_, w| w.strong_count() > 0);
        let port = if addr.port != 0 {
            addr.port
        } else {
            (0..1000).map(|_| ephemeral_port()).find(|p| !ports.contains_key(p)).ok_or(Errno(98))?
        };
        if ports.contains_key(&port) {
            return Err(Errno(98));
        }
        ports.insert(port, Arc::downgrade(this));
        let local = SockAddr { port, ..addr };
        this.lock().local = Some(local);
        Ok(local)
    }

    fn touch(&mut self) {
        self.version += 1;
        ipc::changed();
    }

    /// A datagram in: dropped if the queue is full, or (connected) it's
    /// from somewhere else, as UDP may.
    pub fn push(&mut self, from: SockAddr, data: &[u8]) {
        if self.peer.is_some_and(|p| p != from) {
            return;
        }
        let cost = data.len() + DATAGRAM_OVERHEAD;
        if self.rx.len() >= UDP_QUEUE || (self.bytes > 0 && self.bytes + cost > UDP_BYTES) {
            return;
        }
        if self.charge.resize((self.bytes + cost) as u64).is_err() {
            return;
        }
        self.bytes += cost;
        self.rx.push_back((from, data.to_vec()));
        self.touch();
    }

    /// An echo reply from `from` to the guest's address `to`, for an ICMP
    /// socket.
    pub fn push_icmp(&mut self, from: SockAddr, to: Addr, msg: &[u8]) {
        if let Some(m) = self.icmp.and_then(|i| i.as_read(from.addr, to, msg)) {
            self.push(from, &m);
        }
    }

    /// The next datagram (or a look at it).
    pub fn pop(&mut self, peek: bool) -> Option<(SockAddr, Vec<u8>)> {
        if peek {
            return self.rx.front().cloned();
        }
        let (from, data) = self.rx.pop_front()?;
        self.bytes -= data.len() + DATAGRAM_OVERHEAD;
        let _ = self.charge.resize(self.bytes as u64);
        self.touch();
        Some((from, data))
    }

    pub fn peek_len(&self) -> Option<usize> {
        self.rx.front().map(|d| d.1.len())
    }

    /// A DNS query for the host's resolver, sent to `server`.
    pub fn query(&mut self, q: &[u8], server: SockAddr) {
        if let [a, b, ..] = *q {
            self.servers.retain(|(id, _)| *id != u16::from_be_bytes([a, b]));
            if self.servers.len() >= MAX_ANSWERS {
                self.servers.remove(0);
            }
            self.servers.push((u16::from_be_bytes([a, b]), server));
        }
        self.waiting += 1;
        self.last_query_ns = crate::time::monotonic_ns();
        match self.local.filter(|_| netstack::active()) {
            Some(local) => {
                self.used_host = true;
                netstack::datagram(local.port, server, q);
            }
            None => send(ToHost::Dns { id: self.id, query: q }),
        }
    }

    /// Where the answer `a` came from.
    fn server_of(&self, a: &[u8]) -> SockAddr {
        let id = a.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
        self.servers.iter().find(|(q, _)| Some(*q) == id).map_or(SockAddr::v4(link::DNS_V4, 53), |(_, s)| *s)
    }

    /// What the host said of sending to `to`, if it has.
    pub fn verdict(&self, to: SockAddr) -> Option<bool> {
        // On the guest's own stack it goes, and the gateway's the one to
        // stop it: a firewall's silence, not an answer.
        if netstack::active() {
            return Some(true);
        }
        self.verdicts.get(&to).copied()
    }

    /// Still asking the host about `to`?
    pub fn asking_about(&self, to: SockAddr) -> bool {
        self.asked.contains_key(&to)
    }

    /// Ask the host whether it may send to `to`: once, or again if the
    /// answer is a second late (it may have been lost).
    pub fn ask(&mut self, to: SockAddr) {
        let now = crate::time::monotonic_ns();
        if self.asked.get(&to).is_some_and(|&at| now.saturating_sub(at) < VERDICT_PATIENCE_NS) {
            return;
        }
        if !self.asked.contains_key(&to) && self.asked.len() >= MAX_VERDICTS {
            return;
        }
        if self.verdicts.len() >= MAX_VERDICTS {
            self.verdicts.clear();
        }
        let tables = (self.verdicts.len() + self.asked.len() + 1) as u64;
        if self.known.resize(tables * VERDICT_COST).is_err() {
            self.busy = true;
            return;
        }
        self.used_host = true;
        self.asked.insert(to, now);
        self.asking = self.asked.len();
        send(ToHost::UdpAllow { id: self.id, addr: to.addr, port: to.port });
    }

    /// A datagram to `to`, which the host allowed.
    pub fn send_host(&mut self, to: SockAddr, data: &[u8]) {
        if netstack::active() {
            self.used_host = true;
            self.talking = true;
            match self.local {
                _ if to.port == link::ICMP_PORT => netstack::echo(to.addr, data),
                Some(local) => netstack::datagram(local.port, to, data),
                None => {}
            }
            return;
        }
        send(ToHost::UdpSend { id: self.id, addr: to.addr, port: to.port, data });
    }

    /// A reply to `to`, which sent to this socket through a port forwarded
    /// from the host (`forward_peer`): it leaves from the host's port.
    pub fn reply(&self, to: SockAddr, data: &[u8]) {
        let Some(local) = self.local else { return };
        send(ToHost::UdpReply { port: local.port, addr: to.addr, peer_port: to.port, data });
    }

    /// Writable unless it waits for the host's say (level-triggered loops
    /// would spin on EAGAIN meanwhile).
    pub fn poll(&self) -> (u32, u64) {
        let out = if self.asked.is_empty() { EPOLLOUT } else { 0 };
        (out | if self.rx.is_empty() { 0 } else { EPOLLIN }, self.version)
    }
}

impl Drop for Udp {
    fn drop(&mut self) {
        UDPS.lock().remove(&self.id);
        FORWARD_PEERS.lock().retain(|&(id, _), _| id != self.id);
        if let Some(local) = self.local {
            let mut ports = UDP_PORTS.lock();
            if ports.get(&local.port).is_some_and(|w| w.strong_count() == 0) {
                ports.remove(&local.port);
            }
        }
        if self.used_host {
            send(ToHost::Close { id: self.id });
        }
    }
}

/// A datagram from the guest to itself: to the socket bound at `to`'s
/// port, if one takes it. Returns whether one did.
pub fn deliver_local(from: SockAddr, to: SockAddr, data: &[u8]) -> bool {
    let Some(u) = UDP_PORTS.lock().get(&to.port).and_then(Weak::upgrade) else { return false };
    let mut u = u.lock();
    let takes =
        u.local.is_some_and(|l| l.is_unspecified() || l.addr == to.addr || (l.is_loopback() && to.is_loopback()));
    if takes {
        u.push(from, data);
    }
    takes
}

// ---------------------------------------------------------------- from the host

/// Guest ports the host forwards connections to, and UDP datagrams (from
/// the boot image).
static FORWARDS: Once<Vec<u16>> = Once::new();
static UDP_FORWARDS: Once<Vec<u16>> = Once::new();

pub fn init(forwards: Vec<u16>, udp_forwards: Vec<u16>) {
    FORWARDS.call_once(|| forwards);
    UDP_FORWARDS.call_once(|| udp_forwards);
}

/// Who sent to each socket through a forwarded UDP port (socket id, peer),
/// and when it was last heard (a count): the peers it may reply to through
/// the host's port. The host keeps the same `link::MAX_FORWARD_PEERS`
/// most recent per port, and checks again.
static FORWARD_PEERS: Mutex<BTreeMap<(u32, SockAddr), u64>> = Mutex::new(BTreeMap::new());
static HEARD: AtomicU64 = AtomicU64::new(0);

fn heard_from(id: u32, peer: SockAddr) {
    let mut peers = FORWARD_PEERS.lock();
    let mine = || {
        (id, SockAddr { addr: Addr::V4([0; 4]), port: 0 })
            ..=(id, SockAddr { addr: Addr::V6([0xff; 16]), port: u16::MAX })
    };
    if !peers.contains_key(&(id, peer)) && peers.range(mine()).count() >= link::MAX_FORWARD_PEERS {
        let oldest = peers.range(mine()).min_by_key(|(_, at)| **at).map(|(k, _)| *k);
        if let Some(k) = oldest {
            peers.remove(&k);
        }
    }
    peers.insert((id, peer), HEARD.fetch_add(1, Ordering::Relaxed));
}

/// Did `to` send to UDP socket `id` through a port forwarded from the
/// host (so a reply goes back that way)?
pub fn forward_peer(id: u32, to: SockAddr) -> bool {
    FORWARD_PEERS.lock().contains_key(&(id, to))
}

/// Restored from a snapshot: this run's host has heard from nobody.
pub fn forget_forward_peers() {
    FORWARD_PEERS.lock().clear();
}

/// Is something listening there, for a connection from outside? As
/// `Incoming` says: the guest's own address or all of them, never loopback.
pub fn listening(local: SockAddr) -> bool {
    Listener::find(local).is_some()
}

/// A datagram from the network, for the socket bound at `port`.
pub fn datagram_in(from: SockAddr, port: u16, data: &[u8]) {
    let Some(u) = UDP_PORTS.lock().get(&port).and_then(Weak::upgrade) else { return };
    let mut u = u.lock();
    if from.port == 53 {
        u.waiting = u.waiting.saturating_sub(1);
    }
    u.push(from, data);
}

/// An echo reply from `from` with identifier `ident`, for the ICMP socket
/// that sent the request.
pub fn echo_in(from: Addr, ident: u16, msg: &[u8]) {
    let v6 = matches!(from, Addr::V6(_));
    let udps: Vec<_> = UDPS.lock().values().filter_map(Weak::upgrade).collect();
    if let Some(id) = udps.iter().find_map(|u| {
        let u = u.lock();
        u.icmp.is_some_and(|i| i.ident == ident && i.v6 == v6).then_some(u.id)
    }) {
        deliver(ToGuest::UdpRecv { id, addr: from, port: link::ICMP_PORT, data: msg });
    }
}

/// A message from the host's network proxy.
pub fn from_host(payload: &[u8]) {
    if let Ok(msg) = ToGuest::decode(payload) {
        deliver(msg);
    }
}

/// What the host's proxy said, or the guest's own stack in its place.
pub fn deliver(msg: ToGuest) {
    match msg {
        ToGuest::Connected { id } => {
            if let Some(c) = conn(id) {
                let mut c = c.lock();
                if c.state == ConnState::Connecting {
                    c.state = ConnState::Open;
                    c.tx_credit = send_window();
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
                c.tx_credit = c.tx_credit.saturating_add(bytes).min(send_window());
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
            if let Some(u) = udp(id) {
                let mut u = u.lock();
                u.waiting = u.waiting.saturating_sub(1);
                let from = u.server_of(answer);
                u.push(from, answer);
                u.touch();
            }
        }
        ToGuest::UdpVerdict { id, addr, port, verdict } => {
            if let Some(u) = udp(id) {
                let mut u = u.lock();
                let to = SockAddr { addr, port };
                // Only what it asked about. Busy isn't kept: the next send
                // asks again.
                if u.asked.remove(&to).is_some() {
                    match verdict {
                        link::UDP_ALLOWED => {
                            u.verdicts.insert(to, true);
                            u.talking = true;
                        }
                        link::UDP_REFUSED => {
                            u.verdicts.insert(to, false);
                        }
                        _ => u.busy = true,
                    }
                }
                u.asking = u.asked.len();
                u.touch();
            }
        }
        ToGuest::UdpRecv { id, addr, port, data } => {
            if let Some(u) = udp(id) {
                let mut u = u.lock();
                let from = SockAddr { addr, port };
                match u.icmp {
                    None => u.push(from, data),
                    Some(_) if port == link::ICMP_PORT => {
                        let own = if matches!(addr, Addr::V6(_)) {
                            Addr::V6(link::GUEST_V6)
                        } else {
                            Addr::V4(link::GUEST_V4)
                        };
                        u.push_icmp(from, own, data);
                    }
                    Some(_) => {}
                }
            }
        }
        ToGuest::UdpIncoming { port, peer, peer_port, data } => {
            // To the socket bound at that port on the guest's own address
            // (or any), as a datagram from the network would be.
            let Some(u) = UDP_PORTS.lock().get(&port).and_then(Weak::upgrade) else { return };
            let mut u = u.lock();
            let takes = u.local.is_some_and(|l| l.is_unspecified() || l.addr == Addr::V4(link::GUEST_V4));
            if takes {
                let from = SockAddr { addr: peer, port: peer_port };
                heard_from(u.id, from);
                u.push(from, data);
            }
        }
        ToGuest::Incoming { id, port, peer, peer_port } => {
            let local = SockAddr::v4(link::GUEST_V4, port);
            // From outside: to a listener on the guest's own address or
            // all of them, not one bound to loopback only, which Linux
            // (and Docker's published ports) keep from outside too.
            let listener = Listener::find(local);
            let made = Conn::new(id, ConnState::Open, local, SockAddr { addr: peer, port: peer_port });
            match (listener, made.and_then(Conn::register), Slot::take()) {
                // A refused Conn says Close as it's dropped.
                (Some(l), Ok(c), Some(slot)) => {
                    l.lock().push(Pending::Remote(c, slot));
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
/// listener (or UDP socket) on a forwarded port?
pub fn host_pending() -> bool {
    let conns: Vec<_> = CONNS.lock().values().filter_map(Weak::upgrade).collect();
    if conns.iter().any(|c| {
        let c = c.lock();
        match c.state {
            ConnState::Connecting => true,
            ConnState::Open => !c.rx_eof || c.tx_credit < send_window(),
            ConnState::Failed(_) => false,
        }
    }) {
        return true;
    }
    let now = crate::time::monotonic_ns();
    let udps: Vec<_> = UDPS.lock().values().filter_map(Weak::upgrade).collect();
    if udps.iter().any(|u| {
        let u = u.lock();
        // The host answers each question; datagrams may come any time to a
        // socket that sent through it.
        u.asking > 0 || u.talking || (u.waiting > 0 && now.saturating_sub(u.last_query_ns) < DNS_PATIENCE_NS)
    }) {
        return true;
    }
    let forwards = FORWARDS.get().map_or(&[][..], |f| &f[..]);
    if forwards.iter().any(|&p| Listener::is_bound(p)) {
        return true;
    }
    let udp_forwards = UDP_FORWARDS.get().map_or(&[][..], |f| &f[..]);
    let ports = UDP_PORTS.lock();
    udp_forwards.iter().any(|p| ports.get(p).is_some_and(|w| w.strong_count() > 0))
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
    Udp(UdpRef),
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
    /// IPV6_V6ONLY.
    pub v6only: bool,
    /// UDP: bind named an address, so connect doesn't choose one.
    pub addr_bound: bool,
    /// An ICMP socket, which is a UDP one otherwise.
    pub icmp: Option<Icmp>,
    /// What setsockopt was told.
    pub opts: crate::sockopt::Opts,
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
            v6only: false,
            addr_bound: false,
            icmp: None,
            opts: crate::sockopt::Opts::default(),
        }
    }

    /// What of its options the `vm` stack goes by, for the connection it has.
    pub fn apply_opts(&self) {
        if let State::Remote(c) = &self.state
            && netstack::active()
        {
            netstack::configure(c.lock().id, self.opts.hop_limit(self.v6), self.opts.keepalive());
        }
    }

    /// What `TCP_INFO` says its state is, and how much is on its way.
    pub fn tcp_state(&self) -> (u8, u32) {
        use crate::sockopt::*;
        match &self.state {
            State::Listening(_) => (TCP_LISTEN, 0),
            State::Local { .. } => (TCP_ESTABLISHED, 0),
            State::Remote(c) => {
                let c = c.lock();
                let unacked = send_window().saturating_sub(c.tx_credit);
                match c.state {
                    ConnState::Connecting => (TCP_SYN_SENT, 0),
                    ConnState::Failed(_) => (TCP_CLOSE, 0),
                    ConnState::Open if c.tx_shut => (TCP_FIN_WAIT1, unacked),
                    ConnState::Open if c.rx_eof => (TCP_CLOSE_WAIT, unacked),
                    ConnState::Open => (TCP_ESTABLISHED, unacked),
                }
            }
            _ => (TCP_CLOSE, 0),
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
            State::Udp(u) => u.lock().poll(),
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
