//! Whole IP packets: what the two ends read to find what's in one, and UDP
//! and ICMP, which have no state and no need of a socket. Guest packets are
//! untrusted on the host: everything here is checked and bounded by the
//! buffer it's given.

use alloc::vec;
use alloc::vec::Vec;

use grix_abi::link::{self, Addr};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr,
    Ipv6Address, Ipv6Packet, Ipv6Repr, TcpPacket, UdpPacket,
};

/// An address and port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    pub addr: Addr,
    pub port: u16,
}

/// What an ICMP error says of the packet it's about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreachable {
    /// A rule refused it: the policy's EPERM.
    Prohibited,
    Host,
    Network,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Tcp {
        from: Endpoint,
        to: Endpoint,
        /// The first packet of a connection.
        syn: bool,
    },
    Udp {
        from: Endpoint,
        to: Endpoint,
        data: &'a [u8],
    },
    /// An ICMP echo request or reply: the whole message.
    Echo {
        from: Addr,
        to: Addr,
        request: bool,
        message: &'a [u8],
    },
    /// An ICMP error about a TCP packet from `about.0` to `about.1`.
    Error {
        about: (Endpoint, Endpoint),
        why: Unreachable,
    },
}

const V4_HEADER: usize = 20;
const V6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const TCP: u8 = 6;
/// As much of a packet as an ICMP error quotes: enough to find its ports.
const QUOTE: usize = 8;

fn ports(p: &[u8]) -> Option<(u16, u16)> {
    let (a, b) = (p.get(..2)?, p.get(2..4)?);
    Some((u16::from_be_bytes([a[0], a[1]]), u16::from_be_bytes([b[0], b[1]])))
}

fn tcp_first(p: &[u8]) -> bool {
    TcpPacket::new_checked(p).is_ok_and(|t| t.syn() && !t.ack())
}

/// The endpoints of the TCP packet an ICMP error quotes, as it left. By
/// hand: a quote is cut short, so its own length says more than there is.
fn quoted(ip: &[u8]) -> Option<(Endpoint, Endpoint)> {
    let (from, to, protocol, body) = match ip.first()? >> 4 {
        4 => {
            let header = (*ip.first()? & 0xf) as usize * 4;
            if header < V4_HEADER {
                return None;
            }
            let (a, b): ([u8; 4], [u8; 4]) = (ip.get(12..16)?.try_into().ok()?, ip.get(16..20)?.try_into().ok()?);
            (Addr::V4(a), Addr::V4(b), *ip.get(9)?, ip.get(header..)?)
        }
        6 => {
            let (a, b): ([u8; 16], [u8; 16]) = (ip.get(8..24)?.try_into().ok()?, ip.get(24..40)?.try_into().ok()?);
            (Addr::V6(a), Addr::V6(b), *ip.get(6)?, ip.get(V6_HEADER..)?)
        }
        _ => return None,
    };
    if protocol != TCP {
        return None;
    }
    let (a, b) = ports(body)?;
    Some((Endpoint { addr: from, port: a }, Endpoint { addr: to, port: b }))
}

/// What's in `p`. None for anything that's not whole and well-formed, or
/// isn't one of these: fragments and extension headers among them, which
/// nothing here sends.
pub fn parse(p: &[u8]) -> Option<Packet<'_>> {
    match p.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(p).ok()?;
            if !ip.verify_checksum() || ip.more_frags() || ip.frag_offset() != 0 {
                return None;
            }
            let (src, dst) = (ip.src_addr(), ip.dst_addr());
            let (from, to) = (Addr::V4(src.octets()), Addr::V4(dst.octets()));
            let protocol = ip.next_header();
            let body = &p[ip.header_len() as usize..ip.total_len() as usize];
            match protocol {
                IpProtocol::Tcp => {
                    let (a, b) = ports(body)?;
                    let (from, to) = (Endpoint { addr: from, port: a }, Endpoint { addr: to, port: b });
                    Some(Packet::Tcp { from, to, syn: tcp_first(body) })
                }
                IpProtocol::Udp => {
                    let u = UdpPacket::new_checked(body).ok()?;
                    if !u.verify_checksum(&src.into(), &dst.into()) {
                        return None;
                    }
                    let (from, to) =
                        (Endpoint { addr: from, port: u.src_port() }, Endpoint { addr: to, port: u.dst_port() });
                    Some(Packet::Udp { from, to, data: &body[UDP_HEADER..u.len() as usize] })
                }
                IpProtocol::Icmp => {
                    let m = Icmpv4Packet::new_checked(body).ok()?;
                    if !m.verify_checksum() {
                        return None;
                    }
                    match m.msg_type() {
                        Icmpv4Message::EchoRequest => Some(Packet::Echo { from, to, request: true, message: body }),
                        Icmpv4Message::EchoReply => Some(Packet::Echo { from, to, request: false, message: body }),
                        Icmpv4Message::DstUnreachable => {
                            let why = match m.msg_code() {
                                0 => Unreachable::Network,
                                13 => Unreachable::Prohibited,
                                _ => Unreachable::Host,
                            };
                            Some(Packet::Error { about: quoted(m.data())?, why })
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        6 => {
            let ip = Ipv6Packet::new_checked(p).ok()?;
            let (src, dst) = (ip.src_addr(), ip.dst_addr());
            let (from, to) = (Addr::V6(src.octets()), Addr::V6(dst.octets()));
            let body = ip.payload();
            match ip.next_header() {
                IpProtocol::Tcp => {
                    let (a, b) = ports(body)?;
                    let (from, to) = (Endpoint { addr: from, port: a }, Endpoint { addr: to, port: b });
                    Some(Packet::Tcp { from, to, syn: tcp_first(body) })
                }
                IpProtocol::Udp => {
                    let u = UdpPacket::new_checked(body).ok()?;
                    if !u.verify_checksum(&src.into(), &dst.into()) {
                        return None;
                    }
                    let (from, to) =
                        (Endpoint { addr: from, port: u.src_port() }, Endpoint { addr: to, port: u.dst_port() });
                    Some(Packet::Udp { from, to, data: &body[UDP_HEADER..u.len() as usize] })
                }
                IpProtocol::Icmpv6 => {
                    let m = Icmpv6Packet::new_checked(body).ok()?;
                    if !m.verify_checksum(&src, &dst) {
                        return None;
                    }
                    match m.msg_type() {
                        Icmpv6Message::EchoRequest => Some(Packet::Echo { from, to, request: true, message: body }),
                        Icmpv6Message::EchoReply => Some(Packet::Echo { from, to, request: false, message: body }),
                        Icmpv6Message::DstUnreachable => {
                            let why = match m.msg_code() {
                                0 => Unreachable::Network,
                                1 => Unreachable::Prohibited,
                                _ => Unreachable::Host,
                            };
                            Some(Packet::Error { about: quoted(m.payload())?, why })
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// An IP packet from `from` to `to` around `len` bytes `fill` writes.
/// None if the addresses aren't one family, or it won't fit the link.
fn ip_packet(from: Addr, to: Addr, protocol: IpProtocol, len: usize, fill: impl FnOnce(&mut [u8])) -> Option<Vec<u8>> {
    match (from, to) {
        (Addr::V4(a), Addr::V4(b)) => {
            let total = V4_HEADER + len;
            if total > link::MTU {
                return None;
            }
            let mut p = vec![0; total];
            let repr = Ipv4Repr {
                src_addr: Ipv4Address::from_octets(a),
                dst_addr: Ipv4Address::from_octets(b),
                next_header: protocol,
                payload_len: len,
                hop_limit: 64,
            };
            repr.emit(&mut Ipv4Packet::new_unchecked(&mut p[..]), &ChecksumCapabilities::default());
            fill(&mut p[V4_HEADER..]);
            Some(p)
        }
        (Addr::V6(a), Addr::V6(b)) => {
            let total = V6_HEADER + len;
            if total > link::MTU {
                return None;
            }
            let mut p = vec![0; total];
            let repr = Ipv6Repr {
                src_addr: Ipv6Address::from_octets(a),
                dst_addr: Ipv6Address::from_octets(b),
                next_header: protocol,
                payload_len: len,
                hop_limit: 64,
            };
            repr.emit(&mut Ipv6Packet::new_unchecked(&mut p[..]));
            fill(&mut p[V6_HEADER..]);
            Some(p)
        }
        _ => None,
    }
}

/// A UDP datagram. None if it won't fit the link.
pub fn udp(from: Endpoint, to: Endpoint, data: &[u8]) -> Option<Vec<u8>> {
    let len = UDP_HEADER + data.len();
    ip_packet(from.addr, to.addr, IpProtocol::Udp, len, |b| {
        let (src, dst) = (crate::ip(from.addr), crate::ip(to.addr));
        b[UDP_HEADER..].copy_from_slice(data);
        let mut u = UdpPacket::new_unchecked(&mut *b);
        u.set_src_port(from.port);
        u.set_dst_port(to.port);
        u.set_len(len as u16);
        u.fill_checksum(&src, &dst);
    })
}

/// The ICMP echo `message` (a request or a reply, its type already set),
/// with its checksum made here. None if it isn't one or won't fit.
pub fn echo(from: Addr, to: Addr, message: &[u8]) -> Option<Vec<u8>> {
    if message.len() < 8 {
        return None;
    }
    let protocol = if matches!(from, Addr::V4(_)) { IpProtocol::Icmp } else { IpProtocol::Icmpv6 };
    ip_packet(from, to, protocol, message.len(), |b| {
        b.copy_from_slice(message);
        b[2..4].fill(0);
        match (from, to) {
            (Addr::V6(a), Addr::V6(c)) => {
                let (a, c) = (Ipv6Address::from_octets(a), Ipv6Address::from_octets(c));
                Icmpv6Packet::new_unchecked(&mut *b).fill_checksum(&a, &c);
            }
            _ => Icmpv4Packet::new_unchecked(&mut *b).fill_checksum(),
        }
    })
}

/// The ICMP error saying `original`, a packet that came in, went nowhere.
pub fn error(original: &[u8], why: Unreachable) -> Option<Vec<u8>> {
    let (from, to, header) = match original.first()? >> 4 {
        4 => {
            let p = Ipv4Packet::new_checked(original).ok()?;
            (Addr::V4(p.dst_addr().octets()), Addr::V4(p.src_addr().octets()), p.header_len() as usize)
        }
        6 => {
            let p = Ipv6Packet::new_checked(original).ok()?;
            (Addr::V6(p.dst_addr().octets()), Addr::V6(p.src_addr().octets()), V6_HEADER)
        }
        _ => return None,
    };
    let quote = &original[..original.len().min(header + QUOTE)];
    let v4 = matches!(from, Addr::V4(_));
    let protocol = if v4 { IpProtocol::Icmp } else { IpProtocol::Icmpv6 };
    let (kind, code) = match (v4, why) {
        (true, Unreachable::Network) => (3, 0),
        (true, Unreachable::Host) => (3, 1),
        (true, Unreachable::Prohibited) => (3, 13),
        (false, Unreachable::Network) => (1, 0),
        (false, Unreachable::Prohibited) => (1, 1),
        (false, Unreachable::Host) => (1, 3),
    };
    ip_packet(from, to, protocol, 8 + quote.len(), |b| {
        b[0] = kind;
        b[1] = code;
        b[8..].copy_from_slice(quote);
        match (from, to) {
            (Addr::V6(a), Addr::V6(c)) => {
                let (a, c) = (Ipv6Address::from_octets(a), Ipv6Address::from_octets(c));
                Icmpv6Packet::new_unchecked(&mut *b).fill_checksum(&a, &c);
            }
            _ => Icmpv4Packet::new_unchecked(&mut *b).fill_checksum(),
        }
    })
}

/// A TCP reset answering `original`, a SYN that came in: a refused
/// connection, ECONNREFUSED to whoever sent it.
pub fn reset(original: &[u8]) -> Option<Vec<u8>> {
    let (from, to, body) = match original.first()? >> 4 {
        4 => {
            let p = Ipv4Packet::new_checked(original).ok()?;
            let body = original.get(p.header_len() as usize..)?;
            (Addr::V4(p.dst_addr().octets()), Addr::V4(p.src_addr().octets()), body)
        }
        6 => {
            let p = Ipv6Packet::new_checked(original).ok()?;
            let body = original.get(V6_HEADER..)?;
            (Addr::V6(p.dst_addr().octets()), Addr::V6(p.src_addr().octets()), body)
        }
        _ => return None,
    };
    let syn = TcpPacket::new_checked(body).ok()?;
    let (src_port, dst_port, seq) = (syn.dst_port(), syn.src_port(), syn.seq_number());
    ip_packet(from, to, IpProtocol::Tcp, 20, |b| {
        let (src, dst) = (crate::ip(from), crate::ip(to));
        let mut t = TcpPacket::new_unchecked(&mut *b);
        t.set_src_port(src_port);
        t.set_dst_port(dst_port);
        t.set_ack_number(seq + 1);
        t.set_header_len(20);
        t.clear_flags();
        t.set_rst(true);
        t.set_ack(true);
        t.fill_checksum(&src, &dst);
    })
}

/// A raw socket's `data` as a packet of `protocol`. None if it won't fit.
pub fn raw(from: Addr, to: Addr, protocol: u8, data: &[u8]) -> Option<Vec<u8>> {
    ip_packet(from, to, IpProtocol::from(protocol), data.len(), |b| b.copy_from_slice(data))
}

/// A raw socket's whole packet, with what a kernel fills in of one: its
/// length and checksum. None if it isn't an IPv4 header and what it says.
pub fn with_header(data: &[u8]) -> Option<Vec<u8>> {
    let mut p = data.to_vec();
    if p.len() > link::MTU || p.len() < V4_HEADER || p[0] >> 4 != 4 {
        return None;
    }
    let header = (p[0] & 0xf) as usize * 4;
    if header < V4_HEADER || header > p.len() {
        return None;
    }
    let mut ip = Ipv4Packet::new_unchecked(&mut p[..]);
    ip.set_total_len(data.len() as u16);
    ip.fill_checksum();
    Some(p)
}

/// An IP packet's protocol and addresses, for raw sockets. None if it
/// hasn't got a whole header. IPv6's says where its payload starts too.
pub fn header(p: &[u8]) -> Option<(u8, Addr, Addr, usize)> {
    match p.first()? >> 4 {
        4 => {
            let (a, b): ([u8; 4], [u8; 4]) = (p.get(12..16)?.try_into().ok()?, p.get(16..20)?.try_into().ok()?);
            Some((*p.get(9)?, Addr::V4(a), Addr::V4(b), 0))
        }
        6 => {
            let (a, b): ([u8; 16], [u8; 16]) = (p.get(8..24)?.try_into().ok()?, p.get(24..40)?.try_into().ok()?);
            Some((*p.get(6)?, Addr::V6(a), Addr::V6(b), V6_HEADER))
        }
        _ => None,
    }
}
