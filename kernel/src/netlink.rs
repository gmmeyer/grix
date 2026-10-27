//! A NETLINK_ROUTE socket that describes the sandbox's only network
//! interface, `lo` (127.0.0.1/8 and ::1/128). That's what getifaddrs and
//! if_nameindex ask for (Node's os.networkInterfaces, Python's
//! socket.if_nameindex, `ip addr`). It reveals nothing about the host, so it
//! needs no capability. Requests to change interfaces get EPERM, as for an
//! unprivileged user; other queries get an empty dump.
//!
//! Requests are untrusted bytes: every header is bounds-checked, and replies
//! queue up to a fixed limit (ENOBUFS beyond, as Linux does when a socket's
//! receive buffer overflows).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

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

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
/// The error message echoes only the request's header.
const NLM_F_CAPPED: u16 = 0x100;

const HDR: usize = 16;
/// Reply bytes waiting to be read, and per reply datagram. Every request is
/// answered from a few hundred bytes, but a datagram can hold thousands of
/// requests: this keeps a program from filling the kernel heap.
const MAX_QUEUED_BYTES: usize = 256 * 1024;
const MAX_REPLY: usize = 32 * 1024;
/// The largest request accepted (Linux's default socket buffer is similar).
pub const MAX_REQUEST: usize = 64 * 1024;

const LO_INDEX: u32 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
/// IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP
const LO_FLAGS: u32 = 0x1 | 0x8 | 0x40 | 0x1_0000;

pub struct Netlink {
    /// Our port id (nl_pid).
    pub port: u32,
    /// Reply datagrams, oldest first.
    pub rx: VecDeque<Vec<u8>>,
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
        if self.rx.iter().map(Vec::len).sum::<usize>() >= MAX_QUEUED_BYTES {
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
            self.rx.push_back(reply);
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
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let result = match ty {
            RTM_GETLINK if dump => {
                self.link(out, seq, NLM_F_MULTI);
                self.done(out, seq);
                Ok(())
            }
            RTM_GETLINK => {
                // ifinfomsg.ifi_index: 0 means "by name", which can only be lo.
                let index = msg.get(HDR + 4..HDR + 8).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                if index == 0 || index == LO_INDEX {
                    self.link(out, seq, 0);
                    Ok(())
                } else {
                    Err(ENODEV)
                }
            }
            RTM_GETADDR if dump => {
                if family == 0 || family == AF_INET {
                    self.addr(out, seq, AF_INET, 8, &[127, 0, 0, 1]);
                }
                if family == 0 || family == AF_INET6 {
                    let mut v6 = [0u8; 16];
                    v6[15] = 1;
                    self.addr(out, seq, AF_INET6, 128, &v6);
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

    fn link(&self, out: &mut Vec<u8>, seq: u32, flags: u16) {
        // struct ifinfomsg: family, pad, type, index, flags, change.
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&ARPHRD_LOOPBACK.to_le_bytes());
        b.extend_from_slice(&LO_INDEX.to_le_bytes());
        b.extend_from_slice(&LO_FLAGS.to_le_bytes());
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        attr(&mut b, 3, b"lo\0"); // IFLA_IFNAME
        attr(&mut b, 1, &[0; 6]); // IFLA_ADDRESS
        attr(&mut b, 2, &[0; 6]); // IFLA_BROADCAST
        attr(&mut b, 4, &65536u32.to_le_bytes()); // IFLA_MTU
        attr(&mut b, 16, &[0]); // IFLA_OPERSTATE: unknown, as for lo
        self.message(out, RTM_NEWLINK, flags, seq, &b);
    }

    fn addr(&self, out: &mut Vec<u8>, seq: u32, family: u8, prefix: u8, ip: &[u8]) {
        const IFA_F_PERMANENT: u8 = 0x80;
        const RT_SCOPE_HOST: u8 = 254;
        // struct ifaddrmsg: family, prefixlen, flags, scope, index.
        let mut b = alloc::vec![family, prefix, IFA_F_PERMANENT, RT_SCOPE_HOST];
        b.extend_from_slice(&LO_INDEX.to_le_bytes());
        attr(&mut b, 1, ip); // IFA_ADDRESS
        if family == AF_INET {
            attr(&mut b, 2, ip); // IFA_LOCAL
            attr(&mut b, 3, b"lo\0"); // IFA_LABEL
        }
        self.message(out, RTM_NEWADDR, NLM_F_MULTI, seq, &b);
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

// ---------------------------------------------------------------- interface ioctls

/// The old interface ioctls on any socket (struct ifreq: a 16-byte name and
/// a 24-byte union), as musl's if_nametoindex and busybox use them. Only
/// `lo` exists; setting anything needs CAP_NET_ADMIN. `None` for requests
/// this doesn't know.
pub fn ifreq_ioctl(req: u64, ifr: &mut [u8; 40]) -> Option<Result<(), Errno>> {
    const SIOCGIFNAME: u64 = 0x8910;
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCGIFADDR: u64 = 0x8915;
    const SIOCGIFNETMASK: u64 = 0x891b;
    const SIOCGIFMTU: u64 = 0x8921;
    const SIOCGIFHWADDR: u64 = 0x8927;
    const SIOCGIFINDEX: u64 = 0x8933;
    if !(0x8900..=0x89ff).contains(&req) {
        return None;
    }
    let is_lo = ifr[..16].split(|&b| b == 0).next() == Some(b"lo");
    let data = &mut ifr[16..];
    let result = match req {
        SIOCGIFNAME => {
            if u32::from_le_bytes(data[..4].try_into().unwrap()) != LO_INDEX {
                return Some(Err(ENODEV));
            }
            ifr[..16].fill(0);
            ifr[..2].copy_from_slice(b"lo");
            Ok(())
        }
        // Everything else names the interface.
        _ if !is_lo => Err(ENODEV),
        SIOCGIFINDEX => {
            data[..4].copy_from_slice(&LO_INDEX.to_le_bytes());
            Ok(())
        }
        SIOCGIFFLAGS => {
            data[..2].copy_from_slice(&(LO_FLAGS as u16).to_le_bytes());
            Ok(())
        }
        SIOCGIFMTU => {
            data[..4].copy_from_slice(&65536u32.to_le_bytes());
            Ok(())
        }
        SIOCGIFADDR | SIOCGIFNETMASK => {
            let ip = if req == SIOCGIFADDR { [127, 0, 0, 1] } else { [255, 0, 0, 0] };
            data.fill(0);
            data[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
            data[4..8].copy_from_slice(&ip);
            Ok(())
        }
        SIOCGIFHWADDR => {
            data.fill(0);
            data[..2].copy_from_slice(&ARPHRD_LOOPBACK.to_le_bytes());
            Ok(())
        }
        // SIOCSIFFLAGS, ADDR, DSTADDR, BRDADDR, NETMASK, METRIC, MTU, NAME,
        // HWADDR: changing an interface needs CAP_NET_ADMIN.
        0x8914 | 0x8916 | 0x8918 | 0x891a | 0x891c | 0x891e | 0x8922 | 0x8923 | 0x8924 => Err(EPERM),
        _ => return None,
    };
    Some(result)
}

/// SIOCGIFCONF's single entry: lo and its IPv4 address.
pub fn ifconf_entry() -> [u8; 40] {
    let mut e = [0u8; 40];
    e[..2].copy_from_slice(b"lo");
    e[16..18].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    e[20..24].copy_from_slice(&[127, 0, 0, 1]);
    e
}
