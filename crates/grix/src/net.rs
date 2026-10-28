//! The host end of the guest's networking (`grix_abi::link`). The guest has
//! no TCP/IP stack: the connections it asks for are made here, after the
//! sandbox's policy says yes; connections to forwarded ports are handed to
//! it; its DNS questions are answered with the host's resolver; its UDP
//! datagrams go out from a socket here per guest socket, to destinations
//! the policy allows, and only those destinations' replies come back; and
//! its stdin credit lets more stdin through.
//!
//! What the guest says is untrusted: every message is checked, sizes stay
//! within the credit given, and nothing it sends can make the host buffer
//! more than a window per connection.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use grix_abi::link::{self, Addr, HOST_ID, MAX_DATA, ToGuest, ToHost, WINDOW};
use grix_abi::wire::{self, Input};

use crate::event::GuestEvent;

/// Connections at once (the guest has its own, lower, limit).
const MAX_CONNS: usize = 512;
/// Connects still waiting for the peer.
const MAX_CONNECTING: u32 = 128;
/// DNS lookups in flight; more get SERVFAIL.
const MAX_LOOKUPS: u32 = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Frames waiting for the guest to read them.
const OUTBOX_BYTES: usize = 4 << 20;
/// Denials reported, and addresses remembered with the names they were for.
const MAX_REPORTED: usize = 512;
const MAX_NAMES: usize = 4096;
const ENOBUFS: u16 = 105;
/// UDP sockets at once (each holds a socket here, and a thread per
/// address family), and destinations each may send to.
const MAX_UDP: usize = 64;
const MAX_UDP_DESTS: usize = 256;
/// Threads taking UDP replies in, all sockets together (a closed socket's
/// lives on until its next read times out).
const MAX_UDP_THREADS: u32 = 128;

/// A guest UDP socket's host side.
struct Udp {
    /// Its sockets here, v4 and v6, made when first needed.
    v4: Mutex<Option<Arc<UdpSocket>>>,
    v6: Mutex<Option<Arc<UdpSocket>>>,
    /// Destinations the policy allowed, as the guest names them, to where
    /// they really are (host.grix.internal is the host's loopback); and
    /// back, so only their replies come in.
    allowed: Mutex<HashMap<(Addr, u16), SocketAddr>>,
    reverse: Mutex<HashMap<SocketAddr, (Addr, u16)>>,
    closed: AtomicBool,
}

/// Where the program may connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRule {
    host: Pattern,
    port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pattern {
    /// A domain name, lowercase; `*.example.com` matches its subdomains.
    Name(String),
    /// An address or network.
    Net(IpAddr, u8),
}

/// The rule as `parse` takes it.
impl std::fmt::Display for HostRule {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let host = match &self.host {
            Pattern::Name(n) => n.clone(),
            Pattern::Net(ip, prefix) => format!("{ip}/{prefix}"),
        };
        match self.port {
            Some(port) if host.contains(':') => write!(f, "[{host}]:{port}"),
            Some(port) => write!(f, "{host}:{port}"),
            None => f.write_str(&host),
        }
    }
}

impl HostRule {
    /// `example.com`, `*.example.com`, `1.2.3.4`, `10.0.0.0/8`, `::1`,
    /// `[::1]:80`, each optionally with `:port`.
    pub fn parse(rule: &str) -> Result<HostRule> {
        let rule = rule.trim();
        let (host, port) = if let Some(rest) = rule.strip_prefix('[') {
            let (h, p) = rest.split_once(']').with_context(|| format!("{rule:?}: missing ]"))?;
            (h, p.strip_prefix(':'))
        } else if rule.matches(':').count() == 1 {
            let (h, p) = rule.split_once(':').unwrap();
            (h, Some(p))
        } else {
            (rule, None)
        };
        let port = port.map(|p| p.parse::<u16>().with_context(|| format!("{rule:?}: bad port"))).transpose()?;
        let (addr, prefix) = match host.split_once('/') {
            Some((a, n)) => (a, Some(n.parse::<u8>().with_context(|| format!("{rule:?}: bad prefix length"))?)),
            None => (host, None),
        };
        let pattern = match addr.parse::<IpAddr>() {
            Ok(ip) => {
                let max = if ip.is_ipv4() { 32 } else { 128 };
                let prefix = prefix.unwrap_or(max);
                if prefix > max {
                    bail!("{rule:?}: prefix longer than the address");
                }
                Pattern::Net(ip, prefix)
            }
            Err(_) if prefix.is_some() => bail!("{rule:?}: a network needs an address"),
            Err(_) => {
                let name = host.to_ascii_lowercase();
                let bare = name.strip_prefix("*.").unwrap_or(&name);
                let ok = !bare.is_empty()
                    && bare
                        .split('.')
                        .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
                if !ok {
                    bail!("{rule:?} is not a host name, address or network");
                }
                Pattern::Name(name)
            }
        };
        Ok(HostRule { host: pattern, port })
    }

    fn matches_name(&self, name: &str) -> bool {
        match &self.host {
            Pattern::Name(p) => match p.strip_prefix("*.") {
                Some(base) => name.ends_with(&format!(".{base}")),
                None => name == p,
            },
            Pattern::Net(..) => false,
        }
    }

    fn matches_ip(&self, ip: IpAddr) -> bool {
        match self.host {
            Pattern::Net(net, prefix) => in_net(ip, net, prefix),
            Pattern::Name(_) => false,
        }
    }

    fn port_ok(&self, port: u16) -> bool {
        self.port.is_none_or(|p| p == port)
    }

    /// How specific an address rule is (0 for names).
    fn prefix(&self) -> u8 {
        match self.host {
            Pattern::Net(_, prefix) => prefix,
            Pattern::Name(_) => 0,
        }
    }
}

fn in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    let bits = |ip: IpAddr| -> (u128, u32) {
        match ip {
            IpAddr::V4(a) => (u32::from(a) as u128, 32),
            IpAddr::V6(a) => (u128::from(a), 128),
        }
    };
    let ((a, len), (b, len2)) = (bits(ip), bits(net));
    if len != len2 {
        return false;
    }
    let shift = len - prefix as u32;
    shift >= len || a >> shift == b >> shift
}

/// The sandbox's network policy (see `SandboxBuilder::allow_host` and
/// `forward`).
#[derive(Clone, Debug, Default)]
pub(crate) struct NetPolicy {
    /// The sandbox has the `net` capability. Without it the proxy refuses
    /// everything itself: the guest kernel (which an image may bring) isn't
    /// the only check.
    pub enabled: bool,
    /// None: anywhere but the special addresses below. Some: only these.
    pub allow: Option<Vec<HostRule>>,
    /// Where the host listens, and the guest port it forwards to.
    pub forwards: Vec<(ForwardFrom, u16)>,
}

/// The host side of a forwarded port.
#[derive(Clone, Debug)]
pub(crate) enum ForwardFrom {
    /// Bound for each run.
    Addr(SocketAddr),
    /// Bound once by the caller (so it knows the port), shared by every run.
    Listener(Arc<TcpListener>),
}

fn host_v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(link::HOST_V4))
}

/// The address the guest means. A v4-mapped v6 address is its v4 one, so
/// it gets the same checks.
fn ip_of(a: Addr) -> IpAddr {
    match a {
        Addr::V4(a) => IpAddr::V4(Ipv4Addr::from(a)),
        Addr::V6(a) => Ipv6Addr::from(a).to_canonical(),
    }
}

fn addr_of(ip: IpAddr) -> Addr {
    match ip.to_canonical() {
        IpAddr::V4(a) => Addr::V4(a.octets()),
        IpAddr::V6(a) => Addr::V6(a.octets()),
    }
}

/// Addresses that only a rule for them (or their range) reaches, and the
/// shortest prefix such a rule may have, so a broad rule like `0.0.0.0/0`
/// doesn't open them: loopback, link-local (cloud metadata services live at
/// 169.254.169.254), multicast, broadcast and "this network".
fn special(ip: IpAddr) -> Option<u8> {
    match ip {
        IpAddr::V4(a) if a.is_loopback() || a.octets()[0] == 0 => Some(8),
        IpAddr::V4(a) if a.is_link_local() => Some(16),
        IpAddr::V4(a) if a.is_multicast() => Some(4),
        IpAddr::V4(a) if a.is_broadcast() => Some(32),
        IpAddr::V6(a) if a.is_loopback() || a.is_unspecified() => Some(128),
        IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80 => Some(10),
        IpAddr::V6(a) if a.is_multicast() => Some(8),
        _ => None,
    }
}

impl NetPolicy {
    /// Where a connection to `ip:port` really goes, or why it may not.
    /// `name` is what DNS answered `ip` for, if it did.
    fn check(&self, ip: IpAddr, port: u16, name: Option<&str>) -> Result<SocketAddr, String> {
        let rules = self.allow.as_deref().unwrap_or(&[]);
        let named = |r: &HostRule| r.port_ok(port) && (r.matches_ip(ip) || name.is_some_and(|n| r.matches_name(n)));
        // The host's own services: only for a rule naming exactly that.
        if ip == host_v4() {
            let explicit = rules
                .iter()
                .any(|r| r.port_ok(port) && (r.matches_name(link::HOST_NAME) || r.host == Pattern::Net(host_v4(), 32)));
            return if explicit {
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
            } else {
                Err(format!("{ip}:{port} is the host itself; allow it with allow_host(\"{}:{port}\")", link::HOST_NAME))
            };
        }
        if ip == IpAddr::V4(Ipv4Addr::from(link::DNS_V4)) {
            return Err("DNS over TCP isn't supported".into());
        }
        // The guest's kernel connects its own address itself.
        if ip == IpAddr::V4(Ipv4Addr::from(link::GUEST_V4)) {
            return Err(format!("{ip}:{port} is the guest's own address"));
        }
        if let Some(min) = special(ip)
            && !rules.iter().any(|r| r.port_ok(port) && r.matches_ip(ip) && r.prefix() >= min)
        {
            return Err(format!("{ip}:{port} is a special address; allow it with allow_host(\"{ip}\")"));
        }
        match &self.allow {
            None => Ok(SocketAddr::new(ip, port)),
            Some(rules) if rules.iter().any(named) => Ok(SocketAddr::new(ip, port)),
            Some(_) => Err(match name {
                Some(n) => format!("{ip}:{port} ({n}) isn't in the allow-list"),
                None => format!("{ip}:{port} isn't in the allow-list"),
            }),
        }
    }

    /// May the guest look up `name`? With an allow-list, only names it
    /// covers (so lookups can't carry data out either).
    fn may_resolve(&self, name: &str) -> bool {
        match &self.allow {
            None => true,
            Some(rules) => rules.iter().any(|r| r.matches_name(name)),
        }
    }

    /// Do connections need the names DNS gave their addresses?
    fn has_name_rules(&self) -> bool {
        self.allow.iter().flatten().any(|r| matches!(r.host, Pattern::Name(_)))
    }
}

/// A frame for the guest.
fn frame(msg: ToGuest) -> Vec<u8> {
    let payload = msg.encode();
    let mut f = wire::input_header(Input::Link, payload.len()).to_vec();
    f.extend_from_slice(&payload);
    f
}

/// Frames for the guest's console input, queued for the one thread that
/// writes them to QEMU. Bounded in bytes: if the guest stops reading,
/// producers wait (or, answering what it just said, are dropped) instead
/// of piling frames up here.
pub(crate) struct Outbox {
    q: Mutex<Queue>,
    ready: Condvar,
    room: Condvar,
}

#[derive(Default)]
struct Queue {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
    /// Frames of an urgent answer still at the front.
    urgent: usize,
    closed: bool,
}

impl Outbox {
    pub fn new() -> Arc<Outbox> {
        Arc::new(Outbox { q: Mutex::new(Queue::default()), ready: Condvar::new(), room: Condvar::new() })
    }

    fn push(&self, mut q: MutexGuard<Queue>, frame: Vec<u8>) {
        q.bytes += frame.len();
        q.frames.push_back(frame);
        self.ready.notify_one();
    }

    /// Queue a frame, waiting for room. False once the guest is gone.
    pub fn send(&self, frame: Vec<u8>) -> bool {
        let mut q = self.q.lock().unwrap();
        while !q.closed && q.bytes > 0 && q.bytes + frame.len() > OUTBOX_BYTES {
            q = self.room.wait(q).unwrap();
        }
        if q.closed {
            return false;
        }
        self.push(q, frame);
        true
    }

    /// Queue an answer the guest is waiting for (a live mount's), ahead of
    /// everything else and whatever room there is: it's at most one
    /// message, and the guest does nothing else until it arrives.
    pub fn urgent(&self, frames: Vec<Vec<u8>>) {
        let mut q = self.q.lock().unwrap();
        // A guest that asks again before reading the last answer is
        // misbehaving: it gets nothing more until it does.
        if q.closed || frames.is_empty() || q.urgent > 0 {
            return;
        }
        q.urgent = frames.len();
        for f in frames.into_iter().rev() {
            q.bytes += f.len();
            q.frames.push_front(f);
        }
        self.ready.notify_one();
    }

    /// Queue a signal for the guest whatever room there is (they're tiny,
    /// and the agent sends them).
    pub fn signal(&self, frame: Vec<u8>) {
        let q = self.q.lock().unwrap();
        if !q.closed {
            self.push(q, frame);
        }
    }

    /// Queue a frame if there's room, or drop it.
    fn offer(&self, frame: Vec<u8>) {
        let q = self.q.lock().unwrap();
        if !q.closed && q.bytes + frame.len() <= OUTBOX_BYTES {
            self.push(q, frame);
        }
    }

    /// Queue a frame that may be lost (a datagram) only while the outbox is
    /// under half full, so replies to the guest's own messages always fit.
    fn offer_lossy(&self, frame: Vec<u8>) {
        let q = self.q.lock().unwrap();
        if !q.closed && q.bytes + frame.len() <= OUTBOX_BYTES / 2 {
            self.push(q, frame);
        }
    }

    /// The next frame to write; None once closed.
    pub fn next(&self) -> Option<Vec<u8>> {
        let mut q = self.q.lock().unwrap();
        loop {
            if q.closed {
                return None;
            }
            if let Some(f) = q.frames.pop_front() {
                q.bytes -= f.len();
                q.urgent = q.urgent.saturating_sub(1);
                self.room.notify_all();
                return Some(f);
            }
            q = self.ready.wait(q).unwrap();
        }
    }

    /// The guest is gone: wake everyone.
    pub fn close(&self) {
        self.q.lock().unwrap().closed = true;
        self.ready.notify_all();
        self.room.notify_all();
    }
}

/// One connection, made for the guest or forwarded to it.
struct Conn {
    /// Messages for the writer thread; None once the guest closed it.
    to_peer: Mutex<Option<Sender<ToPeer>>>,
    /// What we may send the guest (it returns credit as it reads).
    credit: Mutex<u32>,
    wake: Condvar,
    /// What the guest may still send us.
    window: Mutex<u32>,
    stream: Mutex<Option<TcpStream>>,
    closed: AtomicBool,
}

enum ToPeer {
    Data(Vec<u8>),
    Shutdown,
}

impl Conn {
    fn new() -> Arc<Conn> {
        Arc::new(Conn {
            to_peer: Mutex::new(None),
            credit: Mutex::new(WINDOW),
            wake: Condvar::new(),
            window: Mutex::new(WINDOW),
            stream: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    fn close(&self) {
        // Under the lock the reader checks it with, so it can't miss the wakeup.
        let credit = self.credit.lock().unwrap();
        self.closed.store(true, Ordering::Relaxed);
        drop(credit);
        self.wake.notify_all();
        *self.to_peer.lock().unwrap() = None;
    }
}

struct Shared {
    policy: NetPolicy,
    outbox: Arc<Outbox>,
    conns: Mutex<HashMap<u32, Arc<Conn>>>,
    udps: Mutex<HashMap<u32, Arc<Udp>>>,
    udp_threads: AtomicU32,
    /// What DNS answered each address for, so name rules cover connections.
    names: Mutex<HashMap<IpAddr, String>>,
    name_rules: bool,
    events: Mutex<Vec<GuestEvent>>,
    reported: Mutex<HashSet<String>>,
    lookups: AtomicU32,
    connecting: AtomicU32,
    stdin_credit: Mutex<u64>,
    stdin_wake: Condvar,
    stop: AtomicBool,
}

impl Shared {
    /// Send from a worker thread, waiting for room.
    fn send(&self, msg: ToGuest) {
        self.outbox.send(frame(msg));
    }

    /// Answer a message from the guest. The thread reading its output
    /// mustn't wait on it to read its input.
    fn reply(&self, msg: ToGuest) {
        self.outbox.offer(frame(msg));
    }

    fn deny(&self, what: &str, detail: String) {
        let mut reported = self.reported.lock().unwrap();
        if reported.len() < MAX_REPORTED && reported.insert(detail.clone()) {
            self.events.lock().unwrap().push(GuestEvent::Denied {
                syscall: what.into(),
                capability: crate::event::NET_POLICY.into(),
                detail,
            });
        }
    }

    /// Networking without the `net` capability: the guest kernel should
    /// have refused it already.
    fn deny_capability(&self, what: &str) {
        let mut reported = self.reported.lock().unwrap();
        if reported.insert(format!("no net: {what}")) {
            self.events.lock().unwrap().push(GuestEvent::Denied {
                syscall: what.into(),
                capability: "net".into(),
                detail: "the sandbox doesn't have the net capability".into(),
            });
        }
    }

    fn remember(&self, name: &str, addrs: &[IpAddr]) {
        if !self.name_rules {
            return;
        }
        let mut names = self.names.lock().unwrap();
        // The guest asks again before it connects, so forgetting is safe.
        if names.len() + addrs.len() > MAX_NAMES {
            names.clear();
        }
        for &a in addrs {
            names.insert(a.to_canonical(), name.to_string());
        }
    }
}

/// The host side of the guest's networking for one run.
pub(crate) struct Proxy {
    shared: Arc<Shared>,
    next_incoming: Arc<AtomicU32>,
    accepting: Mutex<Vec<thread::JoinHandle<()>>>,
}

fn errno(e: &std::io::Error) -> u16 {
    match e.kind() {
        ErrorKind::ConnectionRefused => 111,
        ErrorKind::ConnectionReset => 104,
        ErrorKind::ConnectionAborted => 103,
        ErrorKind::TimedOut => 110,
        ErrorKind::AddrNotAvailable => 99,
        ErrorKind::AddrInUse => 98,
        ErrorKind::BrokenPipe => 32,
        ErrorKind::NotConnected => 107,
        ErrorKind::HostUnreachable => 113,
        ErrorKind::NetworkUnreachable => 101,
        ErrorKind::NetworkDown => 100,
        ErrorKind::PermissionDenied => 13,
        // Only Linux numbers errors as the guest does.
        _ if cfg!(target_os = "linux") => e.raw_os_error().filter(|&n| n > 0 && n < 4096).map_or(111, |n| n as u16),
        _ => 111,
    }
}

impl Proxy {
    /// Listen on the forwarded ports (failing if one can't be had) and get
    /// ready for the guest's messages, which go out through `outbox`.
    pub fn start(policy: NetPolicy, outbox: Arc<Outbox>) -> Result<Proxy> {
        let mut listeners = Vec::new();
        for (from, guest) in &policy.forwards {
            let l = match from {
                ForwardFrom::Addr(host) => {
                    TcpListener::bind(host).with_context(|| format!("forwarding {host} to guest port {guest}"))?
                }
                ForwardFrom::Listener(l) => l.try_clone().context("forwarding a listener")?,
            };
            l.set_nonblocking(true)?;
            listeners.push((l, *guest));
        }
        let shared = Arc::new(Shared {
            name_rules: policy.has_name_rules(),
            policy,
            outbox,
            conns: Mutex::new(HashMap::new()),
            udps: Mutex::new(HashMap::new()),
            udp_threads: AtomicU32::new(0),
            names: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
            reported: Mutex::new(HashSet::new()),
            lookups: AtomicU32::new(0),
            connecting: AtomicU32::new(0),
            stdin_credit: Mutex::new(link::STDIN_WINDOW as u64),
            stdin_wake: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        let proxy = Proxy { shared, next_incoming: Arc::new(AtomicU32::new(1)), accepting: Mutex::new(Vec::new()) };
        for (l, guest) in listeners {
            let shared = proxy.shared.clone();
            let next = proxy.next_incoming.clone();
            let t = thread::Builder::new()
                .spawn(move || accept_loop(&shared, l, guest, &next))
                .context("starting a port forward")?;
            proxy.accepting.lock().unwrap().push(t);
        }
        Ok(proxy)
    }

    /// What the stdin feeder waits on.
    pub fn stdin_gate(&self) -> StdinGate {
        StdinGate(self.shared.clone())
    }

    /// A `Channel::Link` message from the guest.
    pub fn handle(&self, payload: &[u8]) {
        let Ok(msg) = ToHost::decode(payload) else { return };
        let s = &self.shared;
        match msg {
            ToHost::Connect { id, addr, port } => self.connect(id, ip_of(addr), port),
            ToHost::Data { id, data } => {
                let Some(c) = s.conns.lock().unwrap().get(&id).cloned() else { return };
                let mut window = c.window.lock().unwrap();
                // Past its window, the guest is misbehaving: drop the connection.
                if data.len() as u32 > *window {
                    drop(window);
                    self.close(id);
                    s.reply(ToGuest::Failed { id, errno: 104 });
                    return;
                }
                *window -= data.len() as u32;
                if let Some(tx) = c.to_peer.lock().unwrap().as_ref() {
                    let _ = tx.send(ToPeer::Data(data.to_vec()));
                }
            }
            ToHost::Credit { id, bytes } => {
                if let Some(c) = s.conns.lock().unwrap().get(&id) {
                    let mut credit = c.credit.lock().unwrap();
                    *credit = credit.saturating_add(bytes).min(WINDOW);
                    c.wake.notify_all();
                }
            }
            ToHost::Shutdown { id } => {
                if let Some(c) = s.conns.lock().unwrap().get(&id)
                    && let Some(tx) = c.to_peer.lock().unwrap().as_ref()
                {
                    let _ = tx.send(ToPeer::Shutdown);
                }
            }
            ToHost::Close { id } => self.close(id),
            ToHost::Dns { id, query } => self.lookup(id, query),
            ToHost::UdpAllow { id, addr, port } => self.udp_allow(id, addr, port),
            ToHost::UdpSend { id, addr, port, data } => {
                let Some(u) = s.udps.lock().unwrap().get(&id).cloned() else { return };
                let Some(&to) = u.allowed.lock().unwrap().get(&(addr, port)) else { return };
                let sock = if to.is_ipv4() { u.v4.lock().unwrap().clone() } else { u.v6.lock().unwrap().clone() };
                if let Some(sock) = sock {
                    // UDP: lost if it can't go now.
                    let _ = sock.send_to(data, to);
                }
            }
            ToHost::StdinCredit { bytes } => {
                let mut credit = s.stdin_credit.lock().unwrap();
                *credit = (*credit + bytes as u64).min(link::STDIN_WINDOW as u64);
                s.stdin_wake.notify_all();
            }
        }
    }

    fn close(&self, id: u32) {
        if let Some(c) = self.shared.conns.lock().unwrap().remove(&id) {
            c.close();
        }
        if let Some(u) = self.shared.udps.lock().unwrap().remove(&id) {
            u.closed.store(true, Ordering::Relaxed);
        }
    }

    /// May UDP socket `id` send to `addr:port`? The policy decides, as for
    /// a connect; the answer goes back either way.
    fn udp_allow(&self, id: u32, addr: Addr, port: u16) {
        let s = &self.shared;
        let verdict = |verdict| ToGuest::UdpVerdict { id, addr, port, verdict };
        if id & HOST_ID != 0 {
            return;
        }
        if !s.policy.enabled {
            s.deny_capability("sendto");
            return s.reply(verdict(link::UDP_REFUSED));
        }
        let ip = ip_of(addr);
        if ip == IpAddr::V4(Ipv4Addr::from(link::DNS_V4)) {
            s.deny("sendto", format!("{ip}:{port}: the nameserver only answers DNS (port 53)"));
            return s.reply(verdict(link::UDP_REFUSED));
        }
        let name = s.names.lock().unwrap().get(&ip).cloned();
        let to = match s.policy.check(ip, port, name.as_deref()) {
            Ok(to) => to,
            Err(why) => {
                s.deny("sendto", why);
                return s.reply(verdict(link::UDP_REFUSED));
            }
        };
        let u = {
            let mut udps = s.udps.lock().unwrap();
            match udps.get(&id) {
                Some(u) => u.clone(),
                None if udps.len() >= MAX_UDP => {
                    drop(udps);
                    return s.reply(verdict(link::UDP_BUSY));
                }
                None => {
                    let u = Arc::new(Udp {
                        v4: Mutex::new(None),
                        v6: Mutex::new(None),
                        allowed: Mutex::new(HashMap::new()),
                        reverse: Mutex::new(HashMap::new()),
                        closed: AtomicBool::new(false),
                    });
                    udps.insert(id, u.clone());
                    u
                }
            }
        };
        if u.allowed.lock().unwrap().contains_key(&(addr, port)) {
            return s.reply(verdict(link::UDP_ALLOWED));
        }
        if udp_socket(s, id, &u, to.is_ipv4()).is_none() {
            return s.reply(verdict(link::UDP_BUSY));
        }
        let (mut allowed, mut reverse) = (u.allowed.lock().unwrap(), u.reverse.lock().unwrap());
        // As many as the guest remembers: it forgets them all at once too.
        if allowed.len() >= MAX_UDP_DESTS {
            allowed.clear();
            reverse.clear();
        }
        allowed.insert((addr, port), to);
        reverse.insert(to, (addr, port));
        drop((allowed, reverse));
        s.reply(verdict(link::UDP_ALLOWED));
    }

    fn connect(&self, id: u32, ip: IpAddr, port: u16) {
        let s = &self.shared;
        let mut conns = s.conns.lock().unwrap();
        if id & HOST_ID != 0 || conns.contains_key(&id) {
            return;
        }
        if !s.policy.enabled {
            drop(conns);
            s.deny_capability("connect");
            s.reply(ToGuest::Failed { id, errno: 1 }); // EPERM
            return;
        }
        if conns.len() >= MAX_CONNS {
            drop(conns);
            s.reply(ToGuest::Failed { id, errno: ENOBUFS });
            return;
        }
        let name = s.names.lock().unwrap().get(&ip).cloned();
        let target = match s.policy.check(ip, port, name.as_deref()) {
            Ok(t) => t,
            Err(why) => {
                drop(conns);
                s.deny("connect", why);
                s.reply(ToGuest::Failed { id, errno: 1 }); // EPERM
                return;
            }
        };
        // A connect the guest gave up on still waits out its timeout: a
        // bounded number of them.
        if s.connecting.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTING {
            s.connecting.fetch_sub(1, Ordering::Relaxed);
            drop(conns);
            s.reply(ToGuest::Failed { id, errno: ENOBUFS });
            return;
        }
        let c = Conn::new();
        conns.insert(id, c.clone());
        drop(conns);
        let shared = s.clone();
        let spawned = thread::Builder::new().spawn(move || {
            let made = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT);
            shared.connecting.fetch_sub(1, Ordering::Relaxed);
            match made {
                Ok(stream) => run_conn(&shared, id, &c, stream, ToGuest::Connected { id }),
                Err(e) => {
                    if shared.conns.lock().unwrap().remove(&id).is_some() {
                        shared.send(ToGuest::Failed { id, errno: errno(&e) });
                    }
                }
            }
        });
        if spawned.is_err() {
            s.connecting.fetch_sub(1, Ordering::Relaxed);
            s.conns.lock().unwrap().remove(&id);
            s.reply(ToGuest::Failed { id, errno: ENOBUFS });
        }
    }

    fn lookup(&self, id: u32, query: &[u8]) {
        let s = &self.shared;
        let Some(name) = crate::dns::question(query) else { return };
        let query = query.to_vec();
        // The guest's resolver hears at once that this server can't help now.
        let busy = |s: &Shared, query: &[u8]| {
            if let Some(answer) = crate::dns::failure(query) {
                s.reply(ToGuest::DnsAnswer { id, answer: &answer });
            }
        };
        if !s.policy.enabled {
            s.deny_capability("DNS lookup");
            return busy(s, &query);
        }
        if s.lookups.fetch_add(1, Ordering::Relaxed) >= MAX_LOOKUPS {
            s.lookups.fetch_sub(1, Ordering::Relaxed);
            return busy(s, &query);
        }
        let (shared, q) = (s.clone(), query.clone());
        let spawned = thread::Builder::new().spawn(move || {
            let s = shared;
            let addrs: Option<Vec<IpAddr>> = if name == link::HOST_NAME {
                Some(vec![host_v4()])
            } else if !s.policy.may_resolve(&name) {
                s.deny("DNS lookup", format!("{name} isn't in the allow-list"));
                None
            } else if name == "localhost" {
                // The guest's own loopback, as its /etc/hosts says.
                Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)])
            } else {
                (name.as_str(), 0).to_socket_addrs().ok().map(|a| a.map(|a| a.ip()).collect())
            };
            if let Some(addrs) = &addrs {
                s.remember(&name, addrs);
            }
            if let Some(answer) = crate::dns::answer(&q, addrs.as_deref()) {
                s.send(ToGuest::DnsAnswer { id, answer: &answer });
            }
            s.lookups.fetch_sub(1, Ordering::Relaxed);
        });
        if spawned.is_err() {
            s.lookups.fetch_sub(1, Ordering::Relaxed);
            busy(s, &query);
        }
    }

    /// The run is over: close everything, stop listening, and return what
    /// was denied.
    pub fn stop(&self) -> Vec<GuestEvent> {
        let s = &self.shared;
        let credit = s.stdin_credit.lock().unwrap();
        s.stop.store(true, Ordering::Relaxed);
        drop(credit);
        s.stdin_wake.notify_all();
        s.outbox.close();
        for (_, c) in s.conns.lock().unwrap().drain() {
            c.close();
            if let Some(stream) = c.stream.lock().unwrap().as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        for (_, u) in s.udps.lock().unwrap().drain() {
            u.closed.store(true, Ordering::Relaxed);
        }
        // A shared listener's next run mustn't find this one still accepting.
        for t in std::mem::take(&mut *self.accepting.lock().unwrap()) {
            let _ = t.join();
        }
        std::mem::take(&mut *s.events.lock().unwrap())
    }
}

impl Drop for Proxy {
    /// However the run ends (an error, a caller's panic), forwarded ports
    /// are released and connections closed.
    fn drop(&mut self) {
        self.stop();
    }
}

/// stdin may go to the guest only as fast as it gives credit back.
pub(crate) struct StdinGate(Arc<Shared>);

impl StdinGate {
    /// Wait for credit to send up to `n` bytes of stdin; returns how many
    /// may go now (at least 1). None once the run is over.
    pub fn take(&self, n: usize) -> Option<usize> {
        let s = &self.0;
        let mut credit = s.stdin_credit.lock().unwrap();
        loop {
            if s.stop.load(Ordering::Relaxed) {
                return None;
            }
            if *credit > 0 {
                let take = (n as u64).min(*credit);
                *credit -= take;
                return Some(take as usize);
            }
            credit = s.stdin_wake.wait(credit).unwrap();
        }
    }
}

/// Accept connections to a forwarded port and offer them to the guest.
/// UDP socket `id`'s socket here for one address family, made (with a
/// thread taking its replies in) the first time.
fn udp_socket(s: &Arc<Shared>, id: u32, u: &Arc<Udp>, v4: bool) -> Option<Arc<UdpSocket>> {
    let slot = if v4 { &u.v4 } else { &u.v6 };
    let mut slot = slot.lock().unwrap();
    if let Some(sock) = slot.as_ref() {
        return Some(sock.clone());
    }
    if s.udp_threads.fetch_add(1, Ordering::Relaxed) >= MAX_UDP_THREADS {
        s.udp_threads.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    let any: SocketAddr = if v4 { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let made =
        UdpSocket::bind(any).and_then(|sock| sock.set_read_timeout(Some(Duration::from_millis(200))).map(|_| sock));
    let Ok(sock) = made.map(Arc::new) else {
        s.udp_threads.fetch_sub(1, Ordering::Relaxed);
        return None;
    };
    let (shared, udp, rx) = (s.clone(), u.clone(), sock.clone());
    let spawned = thread::Builder::new().spawn(move || {
        // One more than a frame holds: anything that fills it is too big.
        let mut buf = vec![0u8; link::MAX_UDP + 1];
        while !udp.closed.load(Ordering::Relaxed) && !shared.stop.load(Ordering::Relaxed) {
            match rx.recv_from(&mut buf) {
                Ok((n, from)) => {
                    // Only from where the guest sent, and what one frame holds.
                    let from = SocketAddr::new(from.ip().to_canonical(), from.port());
                    let Some(&(addr, port)) = udp.reverse.lock().unwrap().get(&from) else { continue };
                    if n <= link::MAX_UDP {
                        shared.outbox.offer_lossy(frame(ToGuest::UdpRecv { id, addr, port, data: &buf[..n] }));
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                Err(_) => break,
            }
        }
        shared.udp_threads.fetch_sub(1, Ordering::Relaxed);
    });
    if spawned.is_err() {
        s.udp_threads.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    *slot = Some(sock.clone());
    Some(sock)
}

fn accept_loop(s: &Arc<Shared>, listener: TcpListener, guest_port: u16, next: &AtomicU32) {
    while !s.stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let _ = stream.set_nonblocking(false);
                let mut conns = s.conns.lock().unwrap();
                if conns.len() >= MAX_CONNS {
                    continue;
                }
                let id = HOST_ID | (next.fetch_add(1, Ordering::Relaxed) & !HOST_ID);
                let c = Conn::new();
                conns.insert(id, c.clone());
                drop(conns);
                let shared = s.clone();
                let incoming =
                    ToGuest::Incoming { id, port: guest_port, peer: addr_of(peer.ip()), peer_port: peer.port() };
                if thread::Builder::new().spawn(move || run_conn(&shared, id, &c, stream, incoming)).is_err() {
                    s.conns.lock().unwrap().remove(&id);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Move data both ways on an established connection until either side ends
/// it: what the peer sends goes to the guest within its credit, and what the
/// guest sends goes to the peer (and earns it credit back). `announce` tells
/// the guest about it once it's ready for the guest's data.
fn run_conn(s: &Arc<Shared>, id: u32, c: &Arc<Conn>, stream: TcpStream, announce: ToGuest) {
    let _ = stream.set_nodelay(true);
    let (tx, rx) = mpsc::channel();
    let threads = stream.try_clone().ok().zip(stream.try_clone().ok());
    *c.stream.lock().unwrap() = Some(stream);
    *c.to_peer.lock().unwrap() = Some(tx);
    // The guest closed it meanwhile (or the run ended): it hears nothing.
    if c.closed.load(Ordering::Relaxed) {
        *c.to_peer.lock().unwrap() = None;
        return;
    }
    let (shared, conn) = (s.clone(), c.clone());
    let Some((reader, writer)) = threads else {
        return fail(s, id, ENOBUFS);
    };
    if thread::Builder::new().spawn(move || write_loop(&shared, id, &conn, writer, rx)).is_err() {
        return fail(s, id, ENOBUFS);
    }
    s.send(announce);
    read_loop(s, id, c, reader);
}

/// Give up on connection `id`.
fn fail(s: &Shared, id: u32, errno: u16) {
    if let Some(c) = s.conns.lock().unwrap().remove(&id) {
        c.close();
        if let Some(stream) = c.stream.lock().unwrap().as_ref() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
    if id & HOST_ID == 0 {
        s.send(ToGuest::Failed { id, errno });
    }
}

fn read_loop(s: &Shared, id: u32, c: &Conn, mut stream: TcpStream) {
    let mut buf = vec![0u8; MAX_DATA];
    loop {
        let room = {
            let mut credit = c.credit.lock().unwrap();
            while *credit == 0 && !c.closed.load(Ordering::Relaxed) {
                credit = c.wake.wait(credit).unwrap();
            }
            if c.closed.load(Ordering::Relaxed) {
                return;
            }
            *credit as usize
        };
        let want = room.min(buf.len());
        match stream.read(&mut buf[..want]) {
            Ok(0) => {
                if !c.closed.load(Ordering::Relaxed) {
                    s.send(ToGuest::Eof { id });
                }
                return;
            }
            Ok(n) => {
                *c.credit.lock().unwrap() -= n as u32;
                if c.closed.load(Ordering::Relaxed) {
                    return;
                }
                s.send(ToGuest::Data { id, data: &buf[..n] });
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                if !c.closed.load(Ordering::Relaxed) {
                    s.send(ToGuest::Failed { id, errno: errno(&e) });
                }
                return;
            }
        }
    }
}

fn write_loop(s: &Shared, id: u32, c: &Conn, mut stream: TcpStream, rx: Receiver<ToPeer>) {
    for msg in rx {
        match msg {
            ToPeer::Data(data) => {
                if let Err(e) = stream.write_all(&data) {
                    s.send(ToGuest::Failed { id, errno: errno(&e) });
                    break;
                }
                *c.window.lock().unwrap() += data.len() as u32;
                s.send(ToGuest::Credit { id, bytes: data.len() as u32 });
            }
            ToPeer::Shutdown => {
                let _ = stream.shutdown(Shutdown::Write);
            }
        }
    }
    // The guest closed it (and everything it sent went out first).
    let _ = stream.shutdown(Shutdown::Both);
    c.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: &[&str]) -> NetPolicy {
        NetPolicy {
            enabled: true,
            allow: Some(rules.iter().map(|r| HostRule::parse(r).unwrap()).collect()),
            forwards: vec![],
        }
    }

    #[test]
    fn rules_parse_and_match() {
        for bad in ["", "a b", "1.2.3.4/33", "example.com:http", "[::1", "x/8"] {
            assert!(HostRule::parse(bad).is_err(), "{bad:?}");
        }
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let p = policy(&["example.com:443", "*.pypi.org", "10.0.0.0/8", "[2001:db8::]:80"]);
        assert!(p.check(ip("93.184.216.34"), 443, Some("example.com")).is_ok());
        assert!(p.check(ip("93.184.216.34"), 80, Some("example.com")).is_err());
        assert!(p.check(ip("151.101.0.223"), 443, Some("files.pypi.org")).is_ok());
        assert!(p.check(ip("151.101.0.223"), 443, Some("pypi.org")).is_err());
        assert!(p.check(ip("10.1.2.3"), 22, None).is_ok());
        assert!(p.check(ip("2001:db8::"), 80, None).is_ok());
        assert!(p.check(ip("8.8.8.8"), 53, None).is_err());
        assert!(p.may_resolve("x.pypi.org") && !p.may_resolve("evil.com"));
        // No allow-list: anywhere but the host and special addresses.
        let open = NetPolicy::default();
        assert!(open.check(ip("8.8.8.8"), 443, None).is_ok());
        assert!(open.check(ip("10.0.2.2"), 8000, None).is_err());
        assert!(open.check(ip("169.254.169.254"), 80, None).is_err());
        assert!(open.check(ip("::1"), 80, None).is_err());
        assert!(open.may_resolve("anything.example"));
        // The host, when named.
        let host = policy(&["host.grix.internal:8000"]);
        assert_eq!(host.check(ip("10.0.2.2"), 8000, None), Ok("127.0.0.1:8000".parse().unwrap()));
        assert!(host.check(ip("10.0.2.2"), 8001, None).is_err());
        assert!(policy(&["10.0.2.2/32"]).check(ip("10.0.2.2"), 1, None).is_ok());
        // Broad rules don't open the host, special addresses or the guest.
        let broad = policy(&["0.0.0.0/0", "::/0"]);
        assert!(broad.check(ip("10.0.2.2"), 8000, None).is_err());
        assert!(policy(&["10.0.0.0/8"]).check(ip("10.0.2.2"), 8000, None).is_err());
        assert!(broad.check(ip("169.254.169.254"), 80, None).is_err());
        assert!(broad.check(ip("127.0.0.1"), 80, None).is_err());
        assert!(broad.check(ip("fe80::1"), 80, None).is_err());
        assert!(broad.check(ip("10.0.2.15"), 80, None).is_err());
        assert!(broad.check(ip("1.1.1.1"), 443, None).is_ok());
        assert!(policy(&["169.254.169.254"]).check(ip("169.254.169.254"), 80, None).is_ok());
        assert!(policy(&["127.0.0.0/8"]).check(ip("127.0.0.1"), 80, None).is_ok());
        // A v4-mapped address is checked as the v4 one.
        assert_eq!(
            ip_of(Addr::V6("::ffff:169.254.169.254".parse::<Ipv6Addr>().unwrap().octets())),
            ip("169.254.169.254")
        );
        assert!(
            open.check(ip_of(Addr::V6("::ffff:10.0.2.2".parse::<Ipv6Addr>().unwrap().octets())), 80, None).is_err()
        );
    }

    #[test]
    fn outbox_is_bounded() {
        let o = Outbox::new();
        assert!(o.send(vec![0; OUTBOX_BYTES]));
        o.offer(vec![1]);
        assert_eq!(o.next().map(|f| f.len()), Some(OUTBOX_BYTES));
        o.offer(vec![2]);
        assert_eq!(o.next(), Some(vec![2]));
        let o2 = o.clone();
        let t = thread::spawn(move || {
            assert!(o2.send(vec![0; OUTBOX_BYTES]));
            o2.send(vec![3])
        });
        assert_eq!(o.next().map(|f| f.len()), Some(OUTBOX_BYTES));
        assert_eq!(o.next(), Some(vec![3]));
        assert!(t.join().unwrap());
        o.close();
        assert!(!o.send(vec![4]) && o.next().is_none());
    }
}
