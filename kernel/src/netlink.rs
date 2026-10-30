//! A NETLINK_ROUTE socket that describes the sandbox's network interfaces:
//! `lo` (127.0.0.1/8 and ::1/128), and with `net` also `eth0` (10.0.2.15/24,
//! the default route via the host, 10.0.2.2). That's what getifaddrs and
//! if_nameindex ask for (Node's os.networkInterfaces, Python's
//! socket.if_nameindex, `ip addr`, `ip route`). It reveals nothing about the
//! host, so it needs no capability. eth0 is no device: it describes the
//! networking the host's proxy does for the guest's sockets (inet.rs), which
//! still decides what they reach; programs that look for a non-loopback
//! interface or a default route before they connect (the Datadog Agent)
//! find one. Requests to change interfaces get EPERM, as for an
//! unprivileged user; other queries get an empty dump.
//!
//! Requests are untrusted bytes: every header is bounds-checked, and replies
//! queue up to a fixed limit (ENOBUFS beyond, as Linux does when a socket's
//! receive buffer overflows).

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use grix_abi::link;

use crate::errno::*;
use crate::ipc::{EPOLLIN, EPOLLOUT};

pub const AF_NETLINK: u16 = 16;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
/// The error message echoes only the request's header.
const NLM_F_CAPPED: u16 = 0x100;

const HDR: usize = 16;
/// Reply bytes waiting to be read on one socket, and per reply datagram.
/// Every request is answered from a few hundred bytes, but a datagram can
/// hold thousands of requests. Replies are also charged to the kernel
/// memory budget, which covers all sockets together.
const MAX_QUEUED_BYTES: usize = 64 * 1024;
const MAX_REPLY: usize = 32 * 1024;
/// The largest request accepted (Linux's default socket buffer is similar).
pub const MAX_REQUEST: usize = 64 * 1024;

const LO_INDEX: u32 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
/// IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP
const LO_FLAGS: u32 = 0x1 | 0x8 | 0x40 | 0x1_0000;

const ETH0_INDEX: u32 = 2;
const ARPHRD_ETHER: u16 = 1;
/// IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST | IFF_LOWER_UP
const ETH0_FLAGS: u32 = 0x1 | 0x2 | 0x40 | 0x1000 | 0x1_0000;
/// Made up, as QEMU's user networking's guest has (no frame ever has it).
pub const ETH0_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const ETH0_MTU: u32 = 1500;
/// The guest's address, its /24 network and the host's.
const ETH0_IP: [u8; 4] = link::GUEST_V4;
const ETH0_MASK: [u8; 4] = [255, 255, 255, 0];
const ETH0_NET: [u8; 4] = [ETH0_IP[0], ETH0_IP[1], ETH0_IP[2], 0];
const ETH0_BROADCAST: [u8; 4] = [ETH0_IP[0], ETH0_IP[1], ETH0_IP[2], 255];
const GATEWAY: [u8; 4] = link::HOST_V4;

/// Is there an eth0 (the program has `net`)? Set once at boot.
static HAS_ETH0: AtomicBool = AtomicBool::new(false);

pub fn init(net: bool) {
    HAS_ETH0.store(net, Ordering::Relaxed);
}

pub fn eth0() -> bool {
    HAS_ETH0.load(Ordering::Relaxed)
}

/// An interface: what each listing says of it.
struct Iface {
    index: u32,
    name: &'static [u8],
    kind: u16,
    flags: u32,
    mac: [u8; 6],
    broadcast: [u8; 6],
    mtu: u32,
    /// IFLA_OPERSTATE: unknown for lo, up for eth0.
    oper: u8,
    ip: [u8; 4],
    mask: [u8; 4],
    prefix: u8,
    /// IPv4 broadcast address (0.0.0.0: none).
    brd: [u8; 4],
}

const LO: Iface = Iface {
    index: LO_INDEX,
    name: b"lo",
    kind: ARPHRD_LOOPBACK,
    flags: LO_FLAGS,
    mac: [0; 6],
    broadcast: [0; 6],
    mtu: 65536,
    oper: 0,
    ip: [127, 0, 0, 1],
    mask: [255, 0, 0, 0],
    prefix: 8,
    brd: [0; 4],
};

const ETH0: Iface = Iface {
    index: ETH0_INDEX,
    name: b"eth0",
    kind: ARPHRD_ETHER,
    flags: ETH0_FLAGS,
    mac: ETH0_MAC,
    broadcast: [0xff; 6],
    mtu: ETH0_MTU,
    oper: 6, // IF_OPER_UP
    ip: ETH0_IP,
    mask: ETH0_MASK,
    prefix: 24,
    brd: ETH0_BROADCAST,
};

/// The interfaces there are, in index order.
fn ifaces() -> &'static [Iface] {
    if eth0() { &[LO, ETH0] } else { &[LO] }
}

fn by_index(index: u32) -> Option<&'static Iface> {
    ifaces().iter().find(|i| i.index == index)
}

fn by_name(name: &[u8]) -> Option<&'static Iface> {
    ifaces().iter().find(|i| i.name == name)
}

pub struct Netlink {
    /// Our port id (nl_pid).
    pub port: u32,
    /// Reply datagrams, oldest first, with the kernel memory they hold.
    pub rx: VecDeque<(Vec<u8>, crate::kmem::Charge)>,
    /// Bumped whenever replies are queued (for edge-triggered epoll).
    pub version: u64,
}

impl Netlink {
    pub fn new(port: u32) -> Self {
        Netlink { port, rx: VecDeque::new(), version: 0 }
    }

    pub fn poll(&self) -> (u32, u64) {
        (if self.rx.is_empty() { EPOLLOUT } else { EPOLLIN | EPOLLOUT }, self.version)
    }

    /// Handle one sent datagram, which may hold several requests, and queue
    /// one reply datagram for it.
    pub fn request(&mut self, data: &[u8]) -> Result<(), Errno> {
        if self.rx.iter().map(|(r, _)| r.capacity()).sum::<usize>() >= MAX_QUEUED_BYTES {
            return Err(ENOBUFS);
        }
        let mut reply = Vec::new();
        let mut off = 0;
        // Requests past the reply limit go unanswered, as if dropped.
        while data.len() - off >= HDR && reply.len() < MAX_REPLY {
            let len = u32_at(data, off) as usize;
            if len < HDR || len > data.len() - off {
                break; // truncated or garbage: ignored, as Linux does
            }
            let msg = &data[off..off + len];
            self.answer(msg, &mut reply);
            off += len.next_multiple_of(4).min(data.len() - off);
        }
        if !reply.is_empty() {
            reply.shrink_to_fit();
            let charge = crate::kmem::Charge::new(reply.capacity() as u64).map_err(|_| ENOBUFS)?;
            self.rx.push_back((reply, charge));
            self.version += 1;
        }
        Ok(())
    }

    fn answer(&self, msg: &[u8], out: &mut Vec<u8>) {
        let (ty, flags, seq) = (u16_at(msg, 4), u16_at(msg, 6), u32_at(msg, 8));
        if flags & NLM_F_REQUEST == 0 {
            return;
        }
        // rtgenmsg/ifinfomsg/ifaddrmsg all start with the address family.
        let family = msg.get(HDR).copied().unwrap_or(0);
        // Either half of NLM_F_DUMP (ROOT or MATCH) asks for a dump, as on Linux.
        let dump = flags & NLM_F_DUMP != 0;
        let result = match ty {
            RTM_GETLINK if dump => {
                for i in ifaces() {
                    self.link(out, seq, NLM_F_MULTI, i);
                }
                self.done(out, seq);
                Ok(())
            }
            RTM_GETLINK => {
                // ifinfomsg.ifi_index, or (with index 0) IFLA_IFNAME/IFLA_ALT_IFNAME.
                let index = msg.get(HDR + 4..HDR + 8).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                let found = match (index, link_name(msg)) {
                    (0, None) => Err(EINVAL),
                    (0, Some(name)) => by_name(name).ok_or(ENODEV),
                    (index, _) => by_index(index).ok_or(ENODEV),
                };
                found.map(|i| self.link(out, seq, 0, i))
            }
            RTM_GETADDR if dump => {
                // By family, then interface, as Linux's dump goes.
                if family == 0 || family == AF_INET {
                    for i in ifaces() {
                        self.addr4(out, seq, i);
                    }
                }
                if family == 0 || family == AF_INET6 {
                    let mut v6 = [0u8; 16];
                    v6[15] = 1;
                    self.addr6(out, seq, &v6);
                }
                self.done(out, seq);
                Ok(())
            }
            // The main table's routes: eth0's network, and the default one
            // through the host.
            RTM_GETROUTE if dump => {
                if eth0() && (family == 0 || family == AF_INET) {
                    self.route(out, seq, Some(GATEWAY));
                    self.route(out, seq, None);
                }
                self.done(out, seq);
                Ok(())
            }
            // rtnetlink types come in fours: NEW, DEL, GET, SET. Other GET
            // dumps (routes, neighbours, rules) have nothing to report.
            16..=127 if ty % 4 == 2 && dump => {
                self.done(out, seq);
                Ok(())
            }
            // NEW/DEL/SET: changing the network needs CAP_NET_ADMIN.
            16..=127 if ty % 4 != 2 => Err(EPERM),
            _ => Err(EOPNOTSUPP),
        };
        match result {
            Err(e) => self.error(out, msg, -(e.0 as i32)),
            Ok(()) if flags & NLM_F_ACK != 0 => self.error(out, msg, 0),
            Ok(()) => {}
        }
    }

    /// One message: header plus `body`, padded to 4 bytes.
    fn message(&self, out: &mut Vec<u8>, ty: u16, flags: u16, seq: u32, body: &[u8]) {
        let len = (HDR + body.len()) as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&self.port.to_le_bytes());
        out.extend_from_slice(body);
        out.resize(out.len().next_multiple_of(4), 0);
    }

    fn link(&self, out: &mut Vec<u8>, seq: u32, flags: u16, i: &Iface) {
        // struct ifinfomsg: family, pad, type, index, flags, change.
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&i.kind.to_le_bytes());
        b.extend_from_slice(&i.index.to_le_bytes());
        b.extend_from_slice(&i.flags.to_le_bytes());
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut name = [0u8; 8];
        name[..i.name.len()].copy_from_slice(i.name);
        attr(&mut b, 3, &name[..=i.name.len()]); // IFLA_IFNAME
        attr(&mut b, 1, &i.mac); // IFLA_ADDRESS
        attr(&mut b, 2, &i.broadcast); // IFLA_BROADCAST
        attr(&mut b, 4, &i.mtu.to_le_bytes()); // IFLA_MTU
        attr(&mut b, 16, &[i.oper]); // IFLA_OPERSTATE
        self.message(out, RTM_NEWLINK, flags, seq, &b);
    }

    fn addr4(&self, out: &mut Vec<u8>, seq: u32, i: &Iface) {
        const IFA_F_PERMANENT: u8 = 0x80;
        const RT_SCOPE_UNIVERSE: u8 = 0;
        const RT_SCOPE_HOST: u8 = 254;
        let scope = if i.index == LO_INDEX { RT_SCOPE_HOST } else { RT_SCOPE_UNIVERSE };
        // struct ifaddrmsg: family, prefixlen, flags, scope, index.
        let mut b = alloc::vec![AF_INET, i.prefix, IFA_F_PERMANENT, scope];
        b.extend_from_slice(&i.index.to_le_bytes());
        attr(&mut b, 1, &i.ip); // IFA_ADDRESS
        attr(&mut b, 2, &i.ip); // IFA_LOCAL
        if i.brd != [0; 4] {
            attr(&mut b, 4, &i.brd); // IFA_BROADCAST
        }
        let mut label = [0u8; 8];
        label[..i.name.len()].copy_from_slice(i.name);
        attr(&mut b, 3, &label[..=i.name.len()]); // IFA_LABEL
        self.message(out, RTM_NEWADDR, NLM_F_MULTI, seq, &b);
    }

    /// lo's IPv6 address (eth0 has none: the host's proxy is reached over
    /// IPv4).
    fn addr6(&self, out: &mut Vec<u8>, seq: u32, ip: &[u8; 16]) {
        const IFA_F_PERMANENT: u8 = 0x80;
        const RT_SCOPE_HOST: u8 = 254;
        let mut b = alloc::vec![AF_INET6, 128, IFA_F_PERMANENT, RT_SCOPE_HOST];
        b.extend_from_slice(&LO_INDEX.to_le_bytes());
        attr(&mut b, 1, ip); // IFA_ADDRESS
        self.message(out, RTM_NEWADDR, NLM_F_MULTI, seq, &b);
    }

    /// A main-table route on eth0: its network (as the kernel adds for an
    /// address), or the default one through `gateway`.
    fn route(&self, out: &mut Vec<u8>, seq: u32, gateway: Option<[u8; 4]>) {
        const RT_TABLE_MAIN: u8 = 254;
        const RTPROT_KERNEL: u8 = 2;
        const RTPROT_BOOT: u8 = 3;
        const RT_SCOPE_UNIVERSE: u8 = 0;
        const RT_SCOPE_LINK: u8 = 253;
        const RTN_UNICAST: u8 = 1;
        // struct rtmsg: family, dst_len, src_len, tos, table, protocol,
        // scope, type, flags.
        let (dst_len, proto, scope) = match gateway {
            Some(_) => (0, RTPROT_BOOT, RT_SCOPE_UNIVERSE),
            None => (24, RTPROT_KERNEL, RT_SCOPE_LINK),
        };
        let mut b = alloc::vec![AF_INET, dst_len, 0, 0, RT_TABLE_MAIN, proto, scope, RTN_UNICAST];
        b.extend_from_slice(&0u32.to_le_bytes());
        attr(&mut b, 15, &(RT_TABLE_MAIN as u32).to_le_bytes()); // RTA_TABLE
        match gateway {
            Some(gw) => attr(&mut b, 5, &gw), // RTA_GATEWAY
            None => {
                attr(&mut b, 1, &ETH0_NET); // RTA_DST
                attr(&mut b, 7, &ETH0_IP); // RTA_PREFSRC
            }
        }
        attr(&mut b, 4, &ETH0_INDEX.to_le_bytes()); // RTA_OIF
        self.message(out, RTM_NEWROUTE, NLM_F_MULTI, seq, &b);
    }

    fn done(&self, out: &mut Vec<u8>, seq: u32) {
        self.message(out, NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_le_bytes());
    }

    /// NLMSG_ERROR: `errno` (negative, or 0 for an ack) and the request's header.
    fn error(&self, out: &mut Vec<u8>, request: &[u8], errno: i32) {
        let mut b = Vec::new();
        b.extend_from_slice(&errno.to_le_bytes());
        b.extend_from_slice(&request[..HDR]);
        self.message(out, NLMSG_ERROR, NLM_F_CAPPED, u32_at(request, 8), &b);
    }
}

/// The interface name in an RTM_GETLINK request's attributes (after the
/// 16-byte ifinfomsg), without its NUL.
fn link_name(msg: &[u8]) -> Option<&[u8]> {
    const IFLA_IFNAME: u16 = 3;
    const IFLA_ALT_IFNAME: u16 = 53;
    let mut off = HDR + 16;
    while msg.len().saturating_sub(off) >= 4 {
        let (len, ty) = (u16_at(msg, off) as usize, u16_at(msg, off + 2));
        if len < 4 || len > msg.len() - off {
            return None;
        }
        if ty == IFLA_IFNAME || ty == IFLA_ALT_IFNAME {
            let name = &msg[off + 4..off + len];
            return Some(name.split(|&b| b == 0).next().unwrap_or(name));
        }
        off += len.next_multiple_of(4);
    }
    None
}

/// struct rtattr: length, type, data (padded to 4 bytes).
fn attr(b: &mut Vec<u8>, ty: u16, data: &[u8]) {
    b.extend_from_slice(&(4 + data.len() as u16).to_le_bytes());
    b.extend_from_slice(&ty.to_le_bytes());
    b.extend_from_slice(data);
    b.resize(b.len().next_multiple_of(4), 0);
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// struct sockaddr_nl for port `port` (0 is the kernel).
pub fn sockaddr(port: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
    b[4..8].copy_from_slice(&port.to_le_bytes());
    b
}

// ---------------------------------------------------------------- /proc/net

/// /proc/net/dev: each interface, with no counts kept.
pub fn proc_net_dev(s: &mut alloc::string::String) {
    use core::fmt::Write;
    s.push_str(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for i in ifaces() {
        let name = core::str::from_utf8(i.name).unwrap_or("");
        let _ = writeln!(
            s,
            "{name:>6}: {:7} {:7} {:4} {:4} {:4} {:5} {:10} {:9} {:8} {:7} {:4} {:4} {:4} {:5} {:7} {:10}",
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        );
    }
}

/// /proc/net/route: the main table's IPv4 routes (none without eth0),
/// each line padded to 127 characters as Linux's fib_route_seq_show
/// pads them, addresses as the u32 in memory (little-endian).
pub fn proc_net_route(s: &mut alloc::string::String) {
    use core::fmt::Write;
    let line = |s: &mut alloc::string::String, text: &str| {
        let _ = writeln!(s, "{text:<127}");
    };
    line(s, "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT");
    if !eth0() {
        return;
    }
    const RTF_UP: u16 = 1;
    const RTF_GATEWAY: u16 = 2;
    let hex = |a: [u8; 4]| u32::from_le_bytes(a);
    for (dst, gw, mask, flags) in
        [([0; 4], GATEWAY, [0; 4], RTF_UP | RTF_GATEWAY), (ETH0_NET, [0; 4], ETH0_MASK, RTF_UP)]
    {
        let text =
            alloc::format!("eth0\t{:08X}\t{:08X}\t{flags:04X}\t0\t0\t0\t{:08X}\t0\t0\t0", hex(dst), hex(gw), hex(mask));
        line(s, &text);
    }
}

// ---------------------------------------------------------------- interface ioctls

/// The old interface ioctls on any socket (struct ifreq: a 16-byte name and
/// a 24-byte union), as musl's if_nametoindex and busybox use them, for
/// the interfaces there are; setting anything needs CAP_NET_ADMIN. `None`
/// for requests this doesn't know.
pub fn ifreq_ioctl(req: u64, ifr: &mut [u8; 40]) -> Option<Result<(), Errno>> {
    const SIOCGIFNAME: u64 = 0x8910;
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCGIFADDR: u64 = 0x8915;
    const SIOCGIFBRDADDR: u64 = 0x8919;
    const SIOCGIFNETMASK: u64 = 0x891b;
    const SIOCGIFMTU: u64 = 0x8921;
    const SIOCGIFHWADDR: u64 = 0x8927;
    const SIOCGIFINDEX: u64 = 0x8933;
    if !(0x8900..=0x89ff).contains(&req) {
        return None;
    }
    let iface = by_name(ifr[..16].split(|&b| b == 0).next().unwrap_or(&[]));
    let data = &mut ifr[16..];
    let sockaddr_in = |data: &mut [u8], ip: [u8; 4]| {
        data.fill(0);
        data[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        data[4..8].copy_from_slice(&ip);
    };
    let result = match req {
        SIOCGIFNAME => {
            let Some(i) = by_index(u32::from_le_bytes(data[..4].try_into().unwrap())) else {
                return Some(Err(ENODEV));
            };
            ifr[..16].fill(0);
            ifr[..i.name.len()].copy_from_slice(i.name);
            Ok(())
        }
        // Everything else names the interface.
        _ if iface.is_none() => Err(ENODEV),
        SIOCGIFINDEX => {
            data[..4].copy_from_slice(&iface.unwrap().index.to_le_bytes());
            Ok(())
        }
        SIOCGIFFLAGS => {
            data[..2].copy_from_slice(&(iface.unwrap().flags as u16).to_le_bytes());
            Ok(())
        }
        SIOCGIFMTU => {
            data[..4].copy_from_slice(&iface.unwrap().mtu.to_le_bytes());
            Ok(())
        }
        SIOCGIFADDR => {
            sockaddr_in(data, iface.unwrap().ip);
            Ok(())
        }
        SIOCGIFNETMASK => {
            sockaddr_in(data, iface.unwrap().mask);
            Ok(())
        }
        SIOCGIFBRDADDR => {
            sockaddr_in(data, iface.unwrap().brd);
            Ok(())
        }
        SIOCGIFHWADDR => {
            let i = iface.unwrap();
            data.fill(0);
            data[..2].copy_from_slice(&i.kind.to_le_bytes());
            data[2..8].copy_from_slice(&i.mac);
            Ok(())
        }
        // SIOCSIFFLAGS, ADDR, DSTADDR, BRDADDR, NETMASK, METRIC, MTU, NAME,
        // HWADDR: changing an interface needs CAP_NET_ADMIN.
        0x8914 | 0x8916 | 0x8918 | 0x891a | 0x891c | 0x891e | 0x8922 | 0x8923 | 0x8924 => Err(EPERM),
        _ => return None,
    };
    Some(result)
}

/// SIOCGIFCONF's entries: each interface and its IPv4 address.
pub fn ifconf_entries() -> Vec<[u8; 40]> {
    ifaces()
        .iter()
        .map(|i| {
            let mut e = [0u8; 40];
            e[..i.name.len()].copy_from_slice(i.name);
            e[16..18].copy_from_slice(&(AF_INET as u16).to_le_bytes());
            e[20..24].copy_from_slice(&i.ip);
            e
        })
        .collect()
}
