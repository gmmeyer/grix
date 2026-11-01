//! The host end of the guest's networking (`grix_abi::link`). The guest has
//! no TCP/IP stack: the connections it asks for are made here, after the
//! sandbox's policy says yes; connections to forwarded ports are handed to
//! it; its DNS questions are answered with the host's resolver; its UDP
//! datagrams go out from a socket here per guest socket, to destinations
//! the policy allows, and only those destinations' replies come back;
//! datagrams to forwarded UDP ports are handed to it, and its replies go
//! back out of those ports, only to peers that sent there; and its stdin
//! credit lets more stdin through.
//!
//! What the guest says is untrusted: every message is checked, sizes stay
//! within the credit given, and nothing it sends can make the host buffer
//! more than a window per connection.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use grix_abi::link::{self, Addr, HOST_ID, MAX_DATA, ToGuest, ToHost, WINDOW};
use grix_abi::wire::{self, Input};

use crate::at::check;
use crate::event::GuestEvent;

/// Connections at once, two threads each (the guest has its own, lower,
/// limit, and a thread that can't be made refuses the connection).
const MAX_CONNS: usize = 4096;
/// Connects still waiting for the peer.
const MAX_CONNECTING: u32 = 128;
/// DNS lookups in flight; more get SERVFAIL.
const MAX_LOOKUPS: u32 = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Frames waiting for the guest to read them.
const OUTBOX_BYTES: usize = 4 << 20;
/// How long what a program wrote gets to reach its peer once it's ended.
pub(crate) const LAST_DATA: Duration = Duration::from_secs(5);
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
/// How often a forwarded UDP port's thread looks up to see if the run is over.
const UDP_FORWARD_TICK: Duration = Duration::from_millis(100);

/// A UDP port forwarded from the host to `guest`.
struct UdpForward {
    guest: u16,
    sock: UdpSocket,
    /// Who sent to it, as the guest sees them, to where they really are,
    /// and when they were last heard (a count): the only peers the guest's
    /// replies may go to, at most `link::MAX_FORWARD_PEERS`.
    peers: Mutex<HashMap<(Addr, u16), (SocketAddr, u64)>>,
    heard: AtomicU64,
}

impl UdpForward {
    fn heard_from(&self, seen: (Addr, u16), real: SocketAddr) {
        let mut peers = self.peers.lock().unwrap();
        if !peers.contains_key(&seen) && peers.len() >= link::MAX_FORWARD_PEERS {
            let oldest = peers.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| *k);
            if let Some(k) = oldest {
                peers.remove(&k);
            }
        }
        peers.insert(seen, (real, self.heard.fetch_add(1, Ordering::Relaxed)));
    }
}

/// A socket here for a guest's echo requests: a ping socket where the host
/// gives this user one (macOS does, and Linux by `net.ipv4.ping_group_range`,
/// to root as to anyone), or else a raw one, which takes root. The host's
/// kernel writes the IP header either way, so a guest can't forge one, and
/// only an echo request is sent.
struct IcmpSocket {
    fd: OwnedFd,
    v4: bool,
    raw: bool,
    /// What's sent has this identifier, not the program's. A raw socket
    /// hears every echo reply the host gets, and this says which are ours.
    ident: u16,
}

/// Each socket's `IcmpSocket::ident`.
static NEXT_IDENT: AtomicU32 = AtomicU32::new(0);

impl IcmpSocket {
    fn open(v4: bool) -> io::Result<IcmpSocket> {
        let (family, proto) =
            if v4 { (libc::AF_INET, libc::IPPROTO_ICMP) } else { (libc::AF_INET6, libc::IPPROTO_ICMPV6) };
        let socket = |ty| {
            // SAFETY: a new descriptor, which we own.
            check(unsafe { libc::socket(family, ty, proto) }).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        };
        let (fd, raw) = match socket(libc::SOCK_DGRAM) {
            Ok(fd) => (fd, false),
            Err(_) => (socket(libc::SOCK_RAW)?, true),
        };
        let wait = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
        let size = std::mem::size_of_val(&wait) as libc::socklen_t;
        // SAFETY: plain calls on a descriptor we hold; `wait` is what's named.
        unsafe {
            check(libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC))?;
            let wait = (&raw const wait).cast();
            check(libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, wait, size))?;
        }
        let ident = NEXT_IDENT.fetch_add(1, Ordering::Relaxed).wrapping_add(std::process::id()) as u16;
        Ok(IcmpSocket { fd, v4, raw, ident })
    }

    /// Send echo request `msg` to `to`, under this socket's identifier.
    fn send(&self, to: IpAddr, msg: &[u8]) {
        let mut m = msg.to_vec();
        m[4..6].copy_from_slice(&self.ident.to_be_bytes());
        // (IPv6's covers the addresses, so the host's kernel does it.)
        if self.v4 {
            m[2..4].fill(0);
            let sum = icmp_checksum(&m);
            m[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        let (addr, len) = sockaddr_of(to);
        // SAFETY: `m` and `addr` are what's named. Lost if it can't go now.
        unsafe {
            libc::sendto(self.fd.as_raw_fd(), m.as_ptr().cast(), m.len(), 0, (&raw const addr).cast(), len);
        }
    }

    /// The next message for this socket, in `buf`: who from, and where in
    /// `buf` it is. None for what's somebody else's.
    fn recv(&self, buf: &mut [u8]) -> io::Result<Option<(IpAddr, std::ops::Range<usize>)>> {
        // SAFETY: zeros are a valid sockaddr_storage.
        let mut from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&from) as libc::socklen_t;
        // SAFETY: `buf` and `from` are what's named, and how big.
        let n = unsafe {
            libc::recvfrom(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0, (&raw mut from).cast(), &mut len)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let Some(ip) = ip_from(&from) else { return Ok(None) };
        // Linux picks a ping socket's replies itself, and has put its own
        // identifier in them; macOS doesn't, and leaves the IP header on.
        let macos = cfg!(target_os = "macos") && !self.raw;
        let header = self.v4 && (self.raw || macos);
        let ident = (self.raw || macos).then_some(self.ident);
        Ok(echo_reply(&buf[..n as usize], self.v4, header, ident).map(|at| (ip, at)))
    }
}

/// Where the echo reply in `packet` is, if it's one and it's ours: all that
/// came off a raw socket, so nothing here is trusted. With `header` it
/// starts with an IPv4 header, and with `ident` it must have that identifier.
fn echo_reply(packet: &[u8], v4: bool, header: bool, ident: Option<u16>) -> Option<std::ops::Range<usize>> {
    let at = if header { (*packet.first()? as usize & 0xf) * 4 } else { 0 };
    let msg = packet.get(at..).filter(|m| m.len() >= 8)?;
    let reply = if v4 { link::ICMP_ECHO_REPLY.0 } else { link::ICMP_ECHO_REPLY.1 };
    if (msg[0], msg[1]) != (reply, 0) || ident.is_some_and(|i| msg[4..6] != i.to_be_bytes()) {
        return None;
    }
    Some(at..packet.len())
}

/// Is `msg` something the host will send for a guest: an echo request?
fn echo_request(msg: &[u8], v4: bool) -> bool {
    let echo = if v4 { link::ICMP_ECHO.0 } else { link::ICMP_ECHO.1 };
    msg.len() >= 8 && msg[0] == echo && msg[1] == 0
}

fn icmp_checksum(msg: &[u8]) -> u16 {
    let mut sum: u32 = msg.chunks(2).map(|w| u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]) as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn sockaddr_of(ip: IpAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: zeros are a valid sockaddr_storage, and it's big enough for
    // either, whose fields are what's written.
    unsafe {
        let mut st: libc::sockaddr_storage = std::mem::zeroed();
        let at = &raw mut st;
        let len = match ip {
            IpAddr::V4(a) => {
                let sa = at.cast::<libc::sockaddr_in>();
                (*sa).sin_family = libc::AF_INET as _;
                (*sa).sin_addr.s_addr = u32::from_ne_bytes(a.octets());
                std::mem::size_of::<libc::sockaddr_in>()
            }
            IpAddr::V6(a) => {
                let sa = at.cast::<libc::sockaddr_in6>();
                (*sa).sin6_family = libc::AF_INET6 as _;
                (*sa).sin6_addr.s6_addr = a.octets();
                std::mem::size_of::<libc::sockaddr_in6>()
            }
        };
        (st, len as libc::socklen_t)
    }
}

fn ip_from(st: &libc::sockaddr_storage) -> Option<IpAddr> {
    let at = std::ptr::from_ref(st);
    // SAFETY: the family says which it is, and it's big enough for either.
    unsafe {
        match st.ss_family as libc::c_int {
            libc::AF_INET => {
                Some(IpAddr::V4(Ipv4Addr::from((*at.cast::<libc::sockaddr_in>()).sin_addr.s_addr.to_ne_bytes())))
            }
            libc::AF_INET6 => {
                Some(IpAddr::V6(Ipv6Addr::from((*at.cast::<libc::sockaddr_in6>()).sin6_addr.s6_addr)).to_canonical())
            }
            _ => None,
        }
    }
}

/// A guest UDP socket's host side.
struct Udp {
    /// Its sockets here, v4 and v6, made when first needed.
    v4: Mutex<Option<Arc<UdpSocket>>>,
    v6: Mutex<Option<Arc<UdpSocket>>>,
    /// Or an ICMP socket's (`link::ICMP_PORT`).
    icmp4: Mutex<Option<Arc<IcmpSocket>>>,
    icmp6: Mutex<Option<Arc<IcmpSocket>>>,
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
    /// And `net_raw`: it may send ICMP echo requests, checked the same way.
    pub icmp: bool,
    /// None: anywhere but the special addresses below. Some: only these.
    pub allow: Option<Vec<HostRule>>,
    /// Where the host listens, and the guest port it forwards to.
    pub forwards: Vec<(ForwardFrom, u16)>,
    /// The same for UDP.
    pub udp_forwards: Vec<(UdpFrom, u16)>,
}

/// The host side of a forwarded port.
#[derive(Clone, Debug)]
pub(crate) enum ForwardFrom {
    /// Bound for each run.
    Addr(SocketAddr),
    /// Bound once by the caller (so it knows the port), shared by every run.
    Listener(Arc<TcpListener>),
}

/// The host side of a forwarded UDP port.
#[derive(Clone, Debug)]
pub(crate) enum UdpFrom {
    /// Bound for each run.
    Addr(SocketAddr),
    /// Bound once by the caller, shared by every run.
    Socket(Arc<UdpSocket>),
}

/// The host side of a forward to `guest_port`: `host` resolved.
pub(crate) fn forward_addr(host: &str, guest_port: u16) -> Result<SocketAddr> {
    let addr = host
        .to_socket_addrs()
        .with_context(|| format!("forward address {host:?}"))?
        .next()
        .with_context(|| format!("forward address {host:?} resolves to nothing"))?;
    if guest_port == 0 {
        bail!("forwarding {host} needs a guest port");
    }
    Ok(addr)
}

/// What `grix run -p` takes: `[ADDR:]HOSTPORT:GUESTPORT`, with Docker's
/// `/udp` (or `/tcp`, the default) after it. The address is 127.0.0.1
/// unless given (`[::1]:53:53/udp` for IPv6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publish {
    /// Where the host listens, `ADDR:PORT`.
    pub host: String,
    pub guest: u16,
    pub udp: bool,
}

impl Publish {
    pub fn parse(spec: &str) -> Result<Publish> {
        let (ports, udp) = match spec.rsplit_once('/') {
            Some((p, "udp")) => (p, true),
            Some((p, "tcp")) => (p, false),
            Some((_, proto)) => bail!("publish {spec:?}: {proto:?} isn't tcp or udp"),
            None => (spec, false),
        };
        let (host, guest) =
            ports.rsplit_once(':').with_context(|| format!("publish {spec:?} must be [ADDR:]HOSTPORT:GUESTPORT"))?;
        let guest: u16 = guest.parse().with_context(|| format!("publish {spec:?}: bad guest port"))?;
        if guest == 0 {
            bail!("publish {spec:?} needs a guest port");
        }
        let host = if host.contains(':') {
            host.to_string()
        } else {
            host.parse::<u16>().with_context(|| format!("publish {spec:?}: bad host port"))?;
            format!("127.0.0.1:{host}")
        };
        Ok(Publish { host, guest, udp })
    }
}

impl std::fmt::Display for Publish {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}{}", self.host, self.guest, if self.udp { "/udp" } else { "" })
    }
}

fn host_v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(link::HOST_V4))
}

fn host_v6() -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(link::HOST_V6))
}

/// The guest's IPv6 network (`link::GUEST_V6`'s): nothing there but the
/// guest and the host.
fn in_guest_v6_net(ip: IpAddr) -> bool {
    in_net(ip, IpAddr::V6(Ipv6Addr::from(link::GUEST_V6)), link::NET_V6_PREFIX)
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

/// What the guest sees as the source of a datagram to a forwarded UDP port,
/// one its reply can name: the host's own loopback is `link::HOST_V4`, as
/// everywhere in the guest (127.0.0.1 there is the guest's own). None for
/// what the guest would take for one of its network's own addresses.
fn guest_view(peer: SocketAddr) -> Option<(Addr, u16)> {
    let ip = peer.ip().to_canonical();
    if ip.is_loopback() {
        return Some((Addr::V4(link::HOST_V4), peer.port()));
    }
    let own = [link::GUEST_V4, link::HOST_V4, link::DNS_V4].map(|a| IpAddr::V4(Ipv4Addr::from(a)));
    if ip.is_unspecified() || own.contains(&ip) || in_guest_v6_net(ip) || peer.port() == 0 {
        return None;
    }
    Some((addr_of(ip), peer.port()))
}

/// The IPv4 address an IPv6 one carries, as something on the way would
/// take it out, and how many of the v6 address's bits come before it.
fn embedded_v4(a: Ipv6Addr) -> Option<(Ipv4Addr, u8)> {
    let (s, o) = (a.segments(), a.octets());
    let low = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    match s {
        // IPv4-compatible (deprecated), SIIT's IPv4-translated, NAT64's
        // well-known prefix.
        [0, 0, 0, 0, 0, 0, ..] | [0, 0, 0, 0, 0xffff, 0, ..] | [0x64, 0xff9b, 0, 0, 0, 0, ..] => Some((low, 96)),
        // 6to4: its relay is the v4 address.
        [0x2002, ..] => Some((Ipv4Addr::new(o[2], o[3], o[4], o[5]), 16)),
        // ISATAP: the interface identifier, under any prefix.
        [_, _, _, _, x, 0x5efe, ..] if x & 0xfdff == 0 => Some((low, 96)),
        _ => None,
    }
}

/// Addresses that only a rule for them (or their range) reaches, and the
/// shortest prefix such a rule may have, so a broad rule like `0.0.0.0/0`
/// doesn't open them: loopback, link-local (cloud metadata services live at
/// 169.254.169.254), multicast, broadcast and "this network", and the
/// metadata services that live elsewhere.
///
/// IPv6's own are the same, with what has no IPv4 twin: unique local
/// addresses (AWS's metadata is fd00:ec2::254, GCP's fd20:ce::254, Oracle's
/// fd00:c1::a9fe:a9fe: no list of them would be complete, so unlike RFC
/// 1918's ranges, the whole of fc00::/7), site-local, Teredo (two v4
/// addresses, one obfuscated) and NAT64's local-use prefix (RFC 8215: its
/// v4 address can be anywhere in it). An address that carries a v4 one is
/// as special as that is, or it would be a way round it.
fn special(ip: IpAddr) -> Option<u8> {
    match ip {
        IpAddr::V4(a) if a.is_loopback() || a.octets()[0] == 0 => Some(8),
        IpAddr::V4(a) if a.is_link_local() => Some(16),
        IpAddr::V4(a) if a.is_multicast() => Some(4),
        IpAddr::V4(a) if a.is_broadcast() => Some(32),
        // Alibaba's metadata service, and Azure's wire server.
        IpAddr::V4(a) if [[100, 100, 100, 200], [168, 63, 129, 16]].contains(&a.octets()) => Some(32),
        IpAddr::V4(_) => None,
        IpAddr::V6(a) if a.is_loopback() || a.is_unspecified() => Some(128),
        IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80 => Some(10),
        IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfec0 => Some(10),
        IpAddr::V6(a) if a.segments()[0] & 0xfe00 == 0xfc00 => Some(7),
        IpAddr::V6(a) if a.is_multicast() => Some(8),
        IpAddr::V6(a) if a.segments()[..2] == [0x2001, 0] => Some(32),
        IpAddr::V6(a) if a.segments()[..3] == [0x64, 0xff9b, 1] => Some(48),
        IpAddr::V6(a) => embedded_v4(a).and_then(|(v4, bits)| Some(bits + special(v4.into())?)),
    }
}

impl NetPolicy {
    /// Where a connection to `ip:port` really goes, or why it may not.
    /// `name` is what DNS answered `ip` for, if it did.
    fn check(&self, ip: IpAddr, port: u16, name: Option<&str>) -> Result<SocketAddr, String> {
        let rules = self.allow.as_deref().unwrap_or(&[]);
        // The host's own services: only for a rule naming exactly that.
        if ip == host_v4() || ip == host_v6() {
            let explicit = rules.iter().any(|r| {
                r.port_ok(port)
                    && (r.matches_name(link::HOST_NAME)
                        || r.host == Pattern::Net(host_v4(), 32)
                        || r.host == Pattern::Net(host_v6(), 128))
            });
            let loopback: IpAddr =
                if ip == host_v4() { Ipv4Addr::LOCALHOST.into() } else { Ipv6Addr::LOCALHOST.into() };
            return if explicit {
                Ok(SocketAddr::new(loopback, port))
            } else {
                Err(format!("{ip}:{port} is the host itself; allow it with allow_host(\"{}:{port}\")", link::HOST_NAME))
            };
        }
        if ip == IpAddr::V4(Ipv4Addr::from(link::DNS_V4)) {
            return Err("DNS over TCP isn't supported".into());
        }
        // The guest's kernel connects its own address itself.
        if ip == IpAddr::V4(Ipv4Addr::from(link::GUEST_V4)) || ip == IpAddr::V6(Ipv6Addr::from(link::GUEST_V6)) {
            return Err(format!("{ip}:{port} is the guest's own address"));
        }
        // The rest of the guest's IPv6 network is no one (and not the
        // host's own fd00::/64, if it has one).
        if in_guest_v6_net(ip) {
            return Err(format!("{ip}:{port} is on the guest's own network, where nothing is"));
        }
        reachable(self.allow.as_deref(), ip, port, name).map(|()| SocketAddr::new(ip, port))
    }

    /// May the guest look up `name`?
    fn may_resolve(&self, name: &str) -> bool {
        may_resolve(self.allow.as_deref(), name)
    }

    /// Do connections need the names DNS gave their addresses?
    fn has_name_rules(&self) -> bool {
        self.allow.iter().flatten().any(|r| matches!(r.host, Pattern::Name(_)))
    }
}

/// May a connection go to `ip:port` (an address DNS gave for `name`, if it
/// did) under `allow` (None: anywhere)? Special addresses only with a rule
/// for them. What the proxy checks of the program's connections, past the
/// guest's own addresses, and the host of those it makes for a build
/// (`oci`'s registry pulls).
pub(crate) fn reachable(allow: Option<&[HostRule]>, ip: IpAddr, port: u16, name: Option<&str>) -> Result<(), String> {
    let ip = ip.to_canonical();
    let rules = allow.unwrap_or(&[]);
    if let Some(min) = special(ip)
        && !rules.iter().any(|r| r.port_ok(port) && r.matches_ip(ip) && r.prefix() >= min)
    {
        return Err(format!("{ip}:{port} is a special address; allow it with allow_host(\"{ip}\")"));
    }
    let named = |r: &HostRule| r.port_ok(port) && (r.matches_ip(ip) || name.is_some_and(|n| r.matches_name(n)));
    match allow {
        None => Ok(()),
        Some(rules) if rules.iter().any(named) => Ok(()),
        Some(_) => Err(match name {
            Some(n) => format!("{ip}:{port} ({n}) isn't in the allow-list"),
            None => format!("{ip}:{port} isn't in the allow-list"),
        }),
    }
}

/// May `name` be looked up under `allow`? With an allow-list, only names
/// it covers (so lookups can't carry data out either).
pub(crate) fn may_resolve(allow: Option<&[HostRule]>, name: &str) -> bool {
    allow.is_none_or(|rules| rules.iter().any(|r| r.matches_name(&name.to_ascii_lowercase())))
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
        self.send_within(frame, OUTBOX_BYTES)
    }

    /// Queue a frame that can wait (a live mount's notice), once the
    /// outbox is under a quarter full: whatever the host's watcher sends,
    /// there's room for answers, stats requests and datagrams
    /// (`offer_lossy`'s half).
    pub fn send_notice(&self, frame: Vec<u8>) -> bool {
        self.send_within(frame, OUTBOX_BYTES / 4)
    }

    fn send_within(&self, frame: Vec<u8>, limit: usize) -> bool {
        let mut q = self.q.lock().unwrap();
        while !q.closed && q.bytes > 0 && q.bytes + frame.len() > limit {
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

    /// Queue a frame that may be lost (a datagram, or a request for stats
    /// the host repeats) only while the outbox is under half full, so
    /// replies to the guest's own messages always fit, and a guest that
    /// never reads can't make it grow. Whether it was.
    pub(crate) fn offer_lossy(&self, frame: Vec<u8>) -> bool {
        let q = self.q.lock().unwrap();
        if !q.closed && q.bytes + frame.len() <= OUTBOX_BYTES / 2 {
            self.push(q, frame);
            return true;
        }
        false
    }

    #[cfg(test)]
    pub(crate) fn q_is_empty(&self) -> bool {
        self.q.lock().unwrap().frames.is_empty()
    }

    /// The next frame if there is one, without waiting.
    #[cfg(test)]
    pub(crate) fn take(&self) -> Option<Vec<u8>> {
        let mut q = self.q.lock().unwrap();
        let f = q.frames.pop_front()?;
        q.bytes -= f.len();
        self.room.notify_all();
        Some(f)
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
    /// What the guest sent for the peer, for the writer thread: bytes, not
    /// messages, so what's held is at most the window however the guest
    /// cuts it up.
    to_peer: Mutex<ToPeer>,
    to_peer_ready: Condvar,
    /// What we may send the guest (it returns credit as it reads).
    credit: Mutex<u32>,
    wake: Condvar,
    /// What the guest may still send us.
    window: Mutex<u32>,
    stream: Mutex<Option<TcpStream>>,
    closed: AtomicBool,
}

#[derive(Default)]
struct ToPeer {
    data: Vec<u8>,
    /// The writer is running: the connection is up.
    open: bool,
    /// The guest shut its side for writing (the peer's goes once `data` is out).
    shutdown: bool,
    /// The guest closed it: the writer sends what's left, and ends.
    closed: bool,
}

impl Conn {
    fn new() -> Arc<Conn> {
        Arc::new(Conn {
            to_peer: Mutex::new(ToPeer::default()),
            to_peer_ready: Condvar::new(),
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
        self.to_peer.lock().unwrap().closed = true;
        self.to_peer_ready.notify_all();
    }
}

struct Shared {
    policy: NetPolicy,
    outbox: Arc<Outbox>,
    conns: Mutex<HashMap<u32, Arc<Conn>>>,
    udps: Mutex<HashMap<u32, Arc<Udp>>>,
    udp_threads: AtomicU32,
    udp_forwards: Vec<Arc<UdpForward>>,
    /// What DNS answered each address for, so name rules cover connections.
    names: Mutex<HashMap<IpAddr, String>>,
    name_rules: bool,
    events: Mutex<Vec<GuestEvent>>,
    /// Each of `events` as it happens.
    on_event: EventHook,
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
            drop(reported);
            self.report(GuestEvent::Denied {
                syscall: what.into(),
                capability: crate::event::NET_POLICY.into(),
                detail,
            });
        }
    }

    /// Networking without the `net` capability: the guest kernel should
    /// have refused it already.
    fn deny_capability(&self, what: &str) {
        self.without("net", what);
    }

    /// What a capability the sandbox hasn't got would be needed for, once.
    fn without(&self, capability: &str, what: &str) {
        let mut reported = self.reported.lock().unwrap();
        if reported.insert(format!("no {capability}: {what}")) {
            drop(reported);
            self.report(GuestEvent::Denied {
                syscall: what.into(),
                capability: capability.into(),
                detail: format!("the sandbox doesn't have the {capability} capability"),
            });
        }
    }

    fn report(&self, e: GuestEvent) {
        (self.on_event)(&e);
        self.events.lock().unwrap().push(e);
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

/// Told of each event the proxy reports, as it happens.
pub(crate) type EventHook = Arc<dyn Fn(&GuestEvent) + Send + Sync>;

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
    pub fn start(policy: NetPolicy, outbox: Arc<Outbox>, on_event: EventHook) -> Result<Proxy> {
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
        let mut udp_forwards = Vec::new();
        for (from, guest) in &policy.udp_forwards {
            let sock = match from {
                UdpFrom::Addr(host) => {
                    UdpSocket::bind(host).with_context(|| format!("forwarding UDP {host} to guest port {guest}"))?
                }
                UdpFrom::Socket(s) => s.try_clone().context("forwarding a UDP socket")?,
            };
            sock.set_read_timeout(Some(UDP_FORWARD_TICK))?;
            udp_forwards.push(Arc::new(UdpForward {
                guest: *guest,
                sock,
                peers: Mutex::new(HashMap::new()),
                heard: AtomicU64::new(0),
            }));
        }
        let shared = Arc::new(Shared {
            name_rules: policy.has_name_rules(),
            policy,
            outbox,
            conns: Mutex::new(HashMap::new()),
            udps: Mutex::new(HashMap::new()),
            udp_threads: AtomicU32::new(0),
            udp_forwards,
            names: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
            on_event,
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
        for f in proxy.shared.udp_forwards.clone() {
            let shared = proxy.shared.clone();
            let t = thread::Builder::new()
                .spawn(move || udp_forward_loop(&shared, &f))
                .context("starting a UDP port forward")?;
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
            // An empty one says nothing.
            ToHost::Data { data: [], .. } => {}
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
                let mut to_peer = c.to_peer.lock().unwrap();
                if to_peer.open && !to_peer.shutdown && !to_peer.closed {
                    *window -= data.len() as u32;
                    to_peer.data.extend_from_slice(data);
                    c.to_peer_ready.notify_all();
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
                if let Some(c) = s.conns.lock().unwrap().get(&id) {
                    c.to_peer.lock().unwrap().shutdown = true;
                    c.to_peer_ready.notify_all();
                }
            }
            ToHost::Close { id } => self.close(id),
            ToHost::Dns { id, query } => self.lookup(id, query),
            ToHost::UdpAllow { id, addr, port } => self.udp_allow(id, addr, port),
            ToHost::UdpSend { id, addr, port, data } => {
                let Some(u) = s.udps.lock().unwrap().get(&id).cloned() else { return };
                let Some(&to) = u.allowed.lock().unwrap().get(&(addr, port)) else { return };
                if port == link::ICMP_PORT {
                    let sock = if to.is_ipv4() { &u.icmp4 } else { &u.icmp6 };
                    let sock = sock.lock().unwrap().clone();
                    // (The guest checked too, but an image brings its own kernel.)
                    if let Some(sock) = sock.filter(|_| s.policy.icmp && echo_request(data, to.is_ipv4())) {
                        sock.send(to.ip(), data);
                    }
                    return;
                }
                let sock = if to.is_ipv4() { u.v4.lock().unwrap().clone() } else { u.v6.lock().unwrap().clone() };
                if let Some(sock) = sock {
                    // UDP: lost if it can't go now.
                    let _ = sock.send_to(data, to);
                }
            }
            ToHost::UdpReply { port, addr, peer_port, data } => self.udp_reply(port, addr, peer_port, data),
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
        let icmp = port == link::ICMP_PORT;
        if icmp && !s.policy.icmp {
            s.without("net_raw", "sendto");
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
                        icmp4: Mutex::new(None),
                        icmp6: Mutex::new(None),
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
        let made =
            if icmp { icmp_socket(s, id, &u, to.is_ipv4()) } else { udp_socket(s, id, &u, to.is_ipv4()).is_some() };
        if !made {
            return s.reply(verdict(if icmp { link::UDP_REFUSED } else { link::UDP_BUSY }));
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

    /// A reply from guest port `port` to `addr:peer_port`: out of the
    /// forwarded port it came in on, if that peer sent there, and nowhere
    /// else (the guest checked too, but an image may bring its own kernel).
    fn udp_reply(&self, port: u16, addr: Addr, peer_port: u16, data: &[u8]) {
        let s = &self.shared;
        if !s.policy.enabled {
            return s.deny_capability("sendto");
        }
        let to = s.udp_forwards.iter().filter(|f| f.guest == port).find_map(|f| {
            let real = f.peers.lock().unwrap().get(&(addr, peer_port)).map(|&(real, _)| real)?;
            Some((f, real))
        });
        match to {
            // UDP: lost if it can't go now.
            Some((f, real)) => drop(f.sock.send_to(data, real)),
            None => s.deny(
                "sendto",
                format!("{}:{peer_port} hasn't sent to forwarded UDP port {port} (lately)", ip_of(addr)),
            ),
        }
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
    /// The program ended. What it wrote is still to reach its peers, as
    /// the kernel it ran on would have seen to on Linux: connections close
    /// the way a guest's `Close` does, with what's held written out first,
    /// for as long as `LAST_DATA` if a peer doesn't read.
    pub fn finish(&self) {
        for (_, c) in self.shared.conns.lock().unwrap().drain() {
            if let Some(stream) = c.stream.lock().unwrap().as_ref() {
                let _ = stream.set_write_timeout(Some(LAST_DATA));
            }
            c.close();
        }
    }

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

/// ICMP socket `id`'s socket here for one address family, made (with a
/// thread taking its replies in) the first time. False if there's none to
/// be had, which is said once as a host can't change that for itself.
fn icmp_socket(s: &Arc<Shared>, id: u32, u: &Arc<Udp>, v4: bool) -> bool {
    let slot = if v4 { &u.icmp4 } else { &u.icmp6 };
    let mut slot = slot.lock().unwrap();
    if slot.is_some() {
        return true;
    }
    if s.udp_threads.fetch_add(1, Ordering::Relaxed) >= MAX_UDP_THREADS {
        s.udp_threads.fetch_sub(1, Ordering::Relaxed);
        return false;
    }
    let sock = match IcmpSocket::open(v4) {
        Ok(sock) => Arc::new(sock),
        Err(e) => {
            s.udp_threads.fetch_sub(1, Ordering::Relaxed);
            s.deny(
                "sendto",
                format!("this host won't give ICMP sockets ({e}): it takes root, or net.ipv4.ping_group_range"),
            );
            return false;
        }
    };
    let (shared, udp, rx) = (s.clone(), u.clone(), sock.clone());
    let spawned = thread::Builder::new().spawn(move || {
        let mut buf = vec![0u8; link::MAX_UDP + 64];
        while !udp.closed.load(Ordering::Relaxed) && !shared.stop.load(Ordering::Relaxed) {
            match rx.recv(&mut buf) {
                Ok(Some((from, at))) => {
                    // Only from where the guest sent, and what one frame holds.
                    let Some(&(addr, port)) = udp.reverse.lock().unwrap().get(&SocketAddr::new(from, 0)) else {
                        continue;
                    };
                    if at.len() <= link::MAX_UDP {
                        shared.outbox.offer_lossy(frame(ToGuest::UdpRecv { id, addr, port, data: &buf[at] }));
                    }
                }
                Ok(None) => {}
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                Err(_) => break,
            }
        }
        shared.udp_threads.fetch_sub(1, Ordering::Relaxed);
    });
    if spawned.is_err() {
        s.udp_threads.fetch_sub(1, Ordering::Relaxed);
        return false;
    }
    *slot = Some(sock);
    true
}

/// Hand datagrams to a forwarded UDP port to the guest, as long as there's
/// room for them (dropped otherwise, as UDP may), remembering who sent
/// them so the guest can reply.
fn udp_forward_loop(s: &Shared, f: &UdpForward) {
    // One more than a frame holds: anything that fills it is too big.
    let mut buf = vec![0u8; link::MAX_UDP + 1];
    while !s.stop.load(Ordering::Relaxed) {
        match f.sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if !s.policy.enabled {
                    s.deny_capability("UDP port forward");
                    continue;
                }
                // Too big for a frame: dropped, as a network that can't
                // fragment it would.
                let Some(seen) = guest_view(from).filter(|_| n <= link::MAX_UDP) else { continue };
                let msg = ToGuest::UdpIncoming { port: f.guest, peer: seen.0, peer_port: seen.1, data: &buf[..n] };
                if s.outbox.offer_lossy(frame(msg)) {
                    f.heard_from(seen, from);
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
            // (An ICMP error for an earlier reply, on some systems.)
            Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
            Err(_) => thread::sleep(UDP_FORWARD_TICK),
        }
    }
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
    let threads = stream.try_clone().ok().zip(stream.try_clone().ok());
    *c.stream.lock().unwrap() = Some(stream);
    c.to_peer.lock().unwrap().open = true;
    // The guest closed it meanwhile (or the run ended): it hears nothing.
    if c.closed.load(Ordering::Relaxed) {
        return;
    }
    let (shared, conn) = (s.clone(), c.clone());
    let Some((reader, writer)) = threads else {
        return fail(s, id, ENOBUFS);
    };
    if thread::Builder::new().spawn(move || write_loop(&shared, id, &conn, writer)).is_err() {
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

fn write_loop(s: &Shared, id: u32, c: &Conn, mut stream: TcpStream) {
    let mut shut = false;
    loop {
        let (data, shutdown, closed) = {
            let mut to_peer = c.to_peer.lock().unwrap();
            while to_peer.data.is_empty() && to_peer.shutdown == shut && !to_peer.closed {
                to_peer = c.to_peer_ready.wait(to_peer).unwrap();
            }
            (std::mem::take(&mut to_peer.data), to_peer.shutdown, to_peer.closed)
        };
        if !data.is_empty() {
            if let Err(e) = stream.write_all(&data) {
                s.send(ToGuest::Failed { id, errno: errno(&e) });
                break;
            }
            *c.window.lock().unwrap() += data.len() as u32;
            s.send(ToGuest::Credit { id, bytes: data.len() as u32 });
        }
        if shutdown && !shut {
            let _ = stream.shutdown(Shutdown::Write);
            shut = true;
        }
        if closed && data.is_empty() {
            break;
        }
    }
    // The guest closed it (and everything it sent went out first).
    let _ = stream.shutdown(Shutdown::Both);
    c.close();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A live mount's notices wait while the outbox is a quarter full, so
    /// a stats request (`offer_lossy`, under half) still goes.
    #[test]
    fn notices_leave_room_for_stats_requests() {
        let out = Outbox::new();
        assert!(out.send(vec![0; OUTBOX_BYTES / 4]));
        let o = out.clone();
        let notice = std::thread::spawn(move || o.send_notice(vec![1; 16]));
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!notice.is_finished());
        assert!(out.offer_lossy(vec![2; 4]));
        assert_eq!(out.next().unwrap().len(), OUTBOX_BYTES / 4);
        assert!(notice.join().unwrap());
        assert_eq!(out.next().unwrap(), [2; 4]);
        assert_eq!(out.next().unwrap(), [1; 16]);
    }

    pub(crate) fn policy(rules: &[&str]) -> NetPolicy {
        NetPolicy {
            enabled: true,
            icmp: false,
            allow: Some(rules.iter().map(|r| HostRule::parse(r).unwrap()).collect()),
            forwards: vec![],
            udp_forwards: vec![],
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
        assert_eq!(host.check(ip("fd00::2"), 8000, None), Ok("[::1]:8000".parse().unwrap()));
        assert!(open.check(ip("fd00::2"), 8000, None).is_err());
        assert!(policy(&["fd00::2/128"]).check(ip("fd00::2"), 1, None).is_ok());
        // Broad rules don't open the host, special addresses or the guest.
        let broad = policy(&["0.0.0.0/0", "::/0"]);
        assert!(broad.check(ip("10.0.2.2"), 8000, None).is_err());
        assert!(policy(&["10.0.0.0/8"]).check(ip("10.0.2.2"), 8000, None).is_err());
        assert!(broad.check(ip("169.254.169.254"), 80, None).is_err());
        assert!(broad.check(ip("127.0.0.1"), 80, None).is_err());
        assert!(broad.check(ip("fe80::1"), 80, None).is_err());
        assert!(broad.check(ip("fd00:ec2::254"), 80, None).is_err());
        assert!(broad.check(ip("10.0.2.15"), 80, None).is_err());
        assert!(broad.check(ip("fd00::15"), 80, None).is_err());
        assert!(broad.check(ip("fd00::7"), 80, None).is_err());
        assert!(policy(&["fc00::/7"]).check(ip("fd00:0:0:1::7"), 80, None).is_ok());
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

    /// What the guest sends a connection's peer is bytes, however it cuts
    /// them up: the host holds at most the window, and an empty message or
    /// a shutdown again holds nothing.
    #[test]
    fn data_for_the_peer_is_bytes_within_the_window() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let proxy = Proxy::start(policy(&["127.0.0.1"]), Outbox::new(), Arc::new(|_| {})).unwrap();
        proxy.handle(&ToHost::Connect { id: 1, addr: Addr::V4([127, 0, 0, 1]), port }.encode());
        let (mut peer, _) = listener.accept().unwrap();
        let conn = loop {
            if let Some(c) = proxy.shared.conns.lock().unwrap().get(&1).cloned()
                && c.to_peer.lock().unwrap().open
            {
                break c;
            }
            thread::sleep(Duration::from_millis(1));
        };
        for _ in 0..100_000 {
            proxy.handle(&ToHost::Data { id: 1, data: &[] }.encode());
        }
        assert_eq!(conn.to_peer.lock().unwrap().data.capacity(), 0);
        assert_eq!(*conn.window.lock().unwrap(), WINDOW);
        // A byte at a time, then a shutdown (many times): the peer gets the
        // bytes, then end-of-file.
        for b in b"hello" {
            proxy.handle(&ToHost::Data { id: 1, data: &[*b] }.encode());
            assert!(conn.to_peer.lock().unwrap().data.len() as u32 <= WINDOW);
        }
        for _ in 0..1000 {
            proxy.handle(&ToHost::Shutdown { id: 1 }.encode());
        }
        peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut got = Vec::new();
        peer.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"hello");
        // Nothing more is taken for a peer that's been shut.
        proxy.handle(&ToHost::Data { id: 1, data: b"more" }.encode());
        assert!(conn.to_peer.lock().unwrap().data.is_empty());
        proxy.stop();
    }

    #[test]
    fn publish_specs() {
        let p = |spec: &str| Publish::parse(spec).map(|p| (p.host, p.guest, p.udp)).ok();
        assert_eq!(p("8080:80"), Some(("127.0.0.1:8080".into(), 80, false)));
        assert_eq!(p("8080:80/tcp"), Some(("127.0.0.1:8080".into(), 80, false)));
        assert_eq!(p("5353:53/udp"), Some(("127.0.0.1:5353".into(), 53, true)));
        assert_eq!(p("0.0.0.0:5353:53/udp"), Some(("0.0.0.0:5353".into(), 53, true)));
        assert_eq!(p("[::1]:5353:53/udp"), Some(("[::1]:5353".into(), 53, true)));
        for bad in ["80", "8080:80/sctp", "8080:http", "x:80", "8080:0/udp", "8080:80/", "8080:70000"] {
            assert!(Publish::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Publish::parse("5353:53/udp").unwrap().to_string(), "127.0.0.1:5353:53/udp");
    }

    /// The `ToGuest` messages in the outbox's frames.
    fn drain(o: &Outbox) -> Vec<Vec<u8>> {
        let mut q = o.q.lock().unwrap();
        q.bytes = 0;
        q.frames.drain(..).map(|f| f[wire::FRAME_HEADER..].to_vec()).collect()
    }

    fn forwarding(enabled: bool) -> (Proxy, Arc<Outbox>, SocketAddr) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let host = sock.local_addr().unwrap();
        let policy =
            NetPolicy { enabled, udp_forwards: vec![(UdpFrom::Socket(Arc::new(sock)), 53)], ..NetPolicy::default() };
        let outbox = Outbox::new();
        (Proxy::start(policy, outbox.clone(), Arc::new(|_| {})).unwrap(), outbox, host)
    }

    fn wait_for(mut f: impl FnMut() -> bool) {
        let started = std::time::Instant::now();
        while !f() {
            assert!(started.elapsed() < Duration::from_secs(10), "timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// Datagrams to a forwarded UDP port go to the guest from where they
    /// came (the host's loopback as the guest knows it), up to a frame's
    /// worth; replies go back from the forwarded port, and only to peers
    /// that sent there, the most recent `MAX_FORWARD_PEERS` of them.
    #[test]
    fn forwarded_udp_and_its_replies() {
        let (proxy, outbox, host) = forwarding(true);
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let port = peer.local_addr().unwrap().port();
        peer.send_to(&[0; link::MAX_UDP + 1], host).unwrap();
        peer.send_to(b"query", host).unwrap();
        let mut got = Vec::new();
        wait_for(|| {
            got.extend(drain(&outbox));
            !got.is_empty()
        });
        let seen = Addr::V4(link::HOST_V4);
        assert_eq!(
            ToGuest::decode(&got[0]),
            Ok(ToGuest::UdpIncoming { port: 53, peer: seen, peer_port: port, data: b"query" })
        );
        assert_eq!(got.len(), 1, "the oversized one isn't carried");
        // A reply to it comes from the forwarded port.
        proxy.handle(&ToHost::UdpReply { port: 53, addr: seen, peer_port: port, data: b"answer" }.encode());
        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (&b"answer"[..], host));
        // Not to a peer that never sent, nor from another guest port.
        for (guest, to) in [(53, port ^ 1), (54, port)] {
            proxy.handle(&ToHost::UdpReply { port: guest, addr: seen, peer_port: to, data: b"no" }.encode());
        }
        peer.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        assert!(peer.recv_from(&mut buf).is_err());
        let events = proxy.stop();
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(
            events.iter().all(|e| matches!(e, GuestEvent::Denied { capability, .. } if capability == "allow_host"))
        );
    }

    #[test]
    fn forwarded_udp_peers_are_capped() {
        let (proxy, outbox, host) = forwarding(true);
        let peers: Vec<_> =
            (0..link::MAX_FORWARD_PEERS + 10).map(|_| UdpSocket::bind("127.0.0.1:0").unwrap()).collect();
        for p in &peers {
            p.send_to(b"hi", host).unwrap();
            // One at a time, so which are the oldest is known.
            let mut n = 0;
            wait_for(|| {
                n += drain(&outbox).len();
                n == 1
            });
        }
        let f = &proxy.shared.udp_forwards[0];
        let remembered = f.peers.lock().unwrap().values().map(|(real, _)| *real).collect::<HashSet<_>>();
        assert_eq!(remembered.len(), link::MAX_FORWARD_PEERS);
        assert!(!remembered.contains(&peers[0].local_addr().unwrap()));
        assert!(remembered.contains(&peers.last().unwrap().local_addr().unwrap()));
        proxy.stop();
    }

    /// What comes off a raw socket is anyone's: only echo replies get out
    /// of it, ours if there's a way to tell, and nothing malformed.
    #[test]
    fn what_an_icmp_socket_lets_through() {
        let reply = |ty: u8, code: u8, id: u16| {
            let mut m = vec![ty, code, 0, 0];
            m.extend_from_slice(&id.to_be_bytes());
            m.extend_from_slice(&[0, 7, b'x']);
            m
        };
        let with_header = |m: Vec<u8>| {
            let mut p = vec![0x45];
            p.resize(20, 0);
            p.extend(m);
            p
        };
        assert_eq!(echo_reply(&reply(0, 0, 9), true, false, None), Some(0..9));
        assert_eq!(echo_reply(&with_header(reply(0, 0, 9)), true, true, Some(9)), Some(20..29));
        assert_eq!(echo_reply(&reply(129, 0, 9), false, false, Some(9)), Some(0..9));
        // Someone else's identifier, on a raw socket that hears everyone's.
        assert_eq!(echo_reply(&with_header(reply(0, 0, 8)), true, true, Some(9)), None);
        // Not an echo reply: a request, an error, the other family's.
        for ty in [8, 3, 11, 129] {
            assert_eq!(echo_reply(&reply(ty, 0, 9), true, false, None), None, "{ty}");
        }
        assert_eq!(echo_reply(&reply(0, 1, 9), true, false, None), None);
        assert_eq!(echo_reply(&reply(0, 0, 9), false, false, None), None);
        // Cut short, or claiming a header bigger than what's there.
        assert_eq!(echo_reply(&reply(0, 0, 9)[..7], true, false, None), None);
        assert_eq!(echo_reply(&[0x4f, 0, 0], true, true, None), None);
        assert_eq!(echo_reply(&[], true, true, None), None);
        // What's sent for a guest.
        assert!(echo_request(&reply(8, 0, 9), true) && echo_request(&reply(128, 0, 9), false));
        for bad in [reply(13, 0, 9), reply(8, 1, 9), reply(128, 0, 9), reply(8, 0, 9)[..7].to_vec()] {
            assert!(!echo_request(&bad, true), "{bad:?}");
        }
    }

    /// The capability and the policy are the proxy's to check: a kernel
    /// that doesn't, because an image brought it, gets a refusal anyway.
    #[test]
    fn icmp_is_refused_by_the_proxy_itself() {
        let ask = |policy: NetPolicy| {
            let outbox = Outbox::new();
            let proxy = Proxy::start(policy, outbox.clone(), Arc::new(|_| {})).unwrap();
            proxy.handle(&ToHost::UdpAllow { id: 1, addr: Addr::V4([192, 0, 2, 1]), port: link::ICMP_PORT }.encode());
            wait_for(|| !outbox.q.lock().unwrap().frames.is_empty());
            let got = drain(&outbox);
            (got, proxy.stop())
        };
        let refused = |got: &[Vec<u8>]| {
            got.iter().any(|f| {
                matches!(ToGuest::decode(f),
                    Ok(ToGuest::UdpVerdict { verdict, .. }) if verdict == link::UDP_REFUSED)
            })
        };
        // No net_raw, though the address is allowed.
        let (got, events) = ask(NetPolicy { icmp: false, ..policy(&["192.0.2.1"]) });
        assert!(refused(&got));
        assert!(
            matches!(&events[..], [GuestEvent::Denied { capability, .. }] if capability == "net_raw"),
            "{events:?}"
        );
        // A rule for a port says nothing of ICMP.
        let (got, events) = ask(NetPolicy { icmp: true, ..policy(&["192.0.2.1:443"]) });
        assert!(refused(&got));
        assert!(matches!(&events[..], [GuestEvent::Denied { .. }]), "{events:?}");
        // Without net at all.
        let (got, _) = ask(NetPolicy { enabled: false, icmp: true, ..policy(&["192.0.2.1"]) });
        assert!(refused(&got));
    }

    /// Without `net`, the proxy neither hands datagrams in nor sends replies.
    #[test]
    fn forwarded_udp_needs_net() {
        let (proxy, outbox, host) = forwarding(false);
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(b"query", host).unwrap();
        wait_for(|| !proxy.shared.events.lock().unwrap().is_empty());
        assert!(drain(&outbox).is_empty());
        let port = peer.local_addr().unwrap().port();
        proxy.handle(
            &ToHost::UdpReply { port: 53, addr: Addr::V4(link::HOST_V4), peer_port: port, data: b"answer" }.encode(),
        );
        let events = proxy.stop();
        assert!(events.iter().all(|e| matches!(e, GuestEvent::Denied { capability, .. } if capability == "net")));
        assert!(proxy.shared.udp_forwards[0].peers.lock().unwrap().is_empty());
    }

    #[test]
    fn what_the_guest_sees_of_a_peer() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let host = Addr::V4(link::HOST_V4);
        assert_eq!(guest_view(a("127.0.0.1:5000")), Some((host, 5000)));
        assert_eq!(guest_view(a("[::1]:5000")), Some((host, 5000)));
        assert_eq!(guest_view(a("192.168.1.9:5000")), Some((Addr::V4([192, 168, 1, 9]), 5000)));
        assert_eq!(guest_view(a("[::ffff:192.168.1.9]:5000")), Some((Addr::V4([192, 168, 1, 9]), 5000)));
        for own in ["10.0.2.15:5000", "10.0.2.2:5000", "10.0.2.3:53", "0.0.0.0:1", "192.168.1.9:0"] {
            assert_eq!(guest_view(a(own)), None, "{own}");
        }
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

    /// IPv6 has as many ways to a metadata service or this machine as IPv4
    /// has, and some of its own: none opens with `net` and no allow-list, or
    /// with a broad rule, and a rule for exactly that does.
    #[test]
    fn special_addresses_in_ipv6_clothes() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let (open, broad) = (NetPolicy::default(), policy(&["0.0.0.0/0", "::/0"]));
        for bad in [
            // Metadata services, on unique local addresses.
            "fd00:ec2::254",
            "fd20:ce::254",
            "fd00:c1::a9fe:a9fe",
            // Any unique local address, and site-local.
            "fc00::1",
            "fdff:ffff::1",
            "fec0::1",
            // v4's special addresses in every way of carrying one.
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "::7f00:1",
            "::a9fe:a9fe",
            "::1:2",
            "::ffff:0:7f00:1",
            "::ffff:0:a9fe:a9fe",
            "2002:a9fe:a9fe::",
            "2002:7f00:1::1",
            "2001:db8::5efe:a9fe:a9fe",
            "2001:db8::200:5efe:7f00:1",
            // Teredo and NAT64's local-use prefix, whatever's in them.
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "64:ff9b:1::a9fe:a9fe",
            "64:ff9b:1:2::1",
            // As v4, and mapped.
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
            // What was special before.
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(open.check(ip(bad), 80, None).is_err(), "{bad}");
            assert!(broad.check(ip(bad), 80, None).is_err(), "{bad} with a broad rule");
            // The same whatever name DNS gave it, and for a pull.
            assert!(open.check(ip(bad), 80, Some("registry.example")).is_err(), "{bad}");
            assert!(reachable(None, ip(bad), 443, Some("registry.example")).is_err(), "{bad}");
            assert!(policy(&[&format!("[{bad}]")]).check(ip(bad), 80, None).is_ok() || bad.contains('.'), "{bad}");
        }
        for fine in ["2600:1f18::1", "2a00:1450:4001::1", "64:ff9b::808:808", "2002:808:808::", "10.1.2.3", "8.8.8.8"] {
            assert!(open.check(ip(fine), 80, None).is_ok(), "{fine}");
        }
        // A rule as narrow as the address's own range opens it, a broader one
        // doesn't.
        assert!(policy(&["fc00::/7"]).check(ip("fd12::1"), 80, None).is_ok());
        assert!(policy(&["64:ff9b::/96"]).check(ip("64:ff9b::a9fe:a9fe"), 80, None).is_err());
        assert!(policy(&["64:ff9b::a9fe:0/112"]).check(ip("64:ff9b::a9fe:a9fe"), 80, None).is_ok());
        assert!(policy(&["2002::/16"]).check(ip("2002:a9fe:a9fe::"), 80, None).is_err());
    }
}
