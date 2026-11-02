//! The link between the guest kernel and the host for networking and flow
//! control. The guest has no TCP/IP stack: its network sockets are
//! connections the host makes for it (and polices), and its DNS questions
//! go to a virtual nameserver the host answers.
//!
//! Guest to host: [`ToHost`] in `Channel::Link` frames. Host to guest:
//! [`ToGuest`] in `Input::Link` frames. Both sides decode what the other
//! says defensively: the host treats the guest as untrusted.
//!
//! Flow control is by credit, so a full buffer never stalls the console,
//! which carries everything else too. Each side starts out allowed to send
//! [`WINDOW`] bytes on a connection, and may send more as the other side
//! returns credit for what it consumed. stdin works the same way, starting
//! at [`STDIN_WINDOW`].

use alloc::vec::Vec;

use crate::codec::{DecodeError, Reader, Writer};
use crate::wire::MAX_FRAME;

/// What each side may send on a new connection before getting credit back.
pub const WINDOW: u32 = 32 * 1024;
/// stdin the host may send before the guest returns credit.
pub const STDIN_WINDOW: u32 = 64 * 1024;
/// The most data one `Data` message carries.
pub const MAX_DATA: usize = MAX_FRAME - 8;
/// The most of a datagram that one message carries. What's more goes ahead
/// of it in `UdpMore` messages, as many as it takes.
pub const MAX_UDP: usize = MAX_FRAME - 32;
/// The largest datagrams, as IP's length field has it: IPv6's payload is
/// its length and IPv4's has a 20-byte header in there.
pub const MAX_DATAGRAM: usize = 65_535 - 8;
pub const MAX_DATAGRAM_V4: usize = MAX_DATAGRAM - 20;
/// The port in UDP's messages that means ICMP: `UdpAllow`, `UdpSend`,
/// `UdpVerdict` and `UdpRecv` are for a ping socket with it, and their data
/// is an ICMP message without an IP header. No UDP datagram goes to port 0.
pub const ICMP_PORT: u16 = 0;
/// ICMP echo's types, for IPv4 and IPv6.
pub const ICMP_ECHO: (u8, u8) = (8, 128);
pub const ICMP_ECHO_REPLY: (u8, u8) = (0, 129);
/// Peers each UDP port forwarded from the host remembers (the most recent
/// senders), the only ones the guest may reply to through it.
pub const MAX_FORWARD_PEERS: usize = 256;

/// `UdpVerdict`s: the policy refuses the destination; allows it; or the
/// host can't take it now (out of sockets or threads: ask again later).
pub const UDP_REFUSED: u8 = 0;
pub const UDP_ALLOWED: u8 = 1;
pub const UDP_BUSY: u8 = 2;

/// The guest's address on its one network.
pub const GUEST_V4: [u8; 4] = [10, 0, 2, 15];
/// The host's own loopback services, as the guest reaches them (what QEMU's
/// user networking calls the gateway). Only allowed when named explicitly.
pub const HOST_V4: [u8; 4] = [10, 0, 2, 2];
/// The virtual nameserver (`/etc/resolv.conf`).
pub const DNS_V4: [u8; 4] = [10, 0, 2, 3];
/// The guest's IPv6 address and the host's, on a unique local network
/// (fd00::/64, as slirp4netns and Podman lay theirs out). A ULA source
/// makes RFC 6724's address selection (glibc, musl, Go) prefer IPv4 for
/// anything global, as the policy table's labels differ, while programs
/// that look for an IPv6 address before listening on `[::]` find one. The
/// host's proxy carries IPv6 connections where the host has a route.
pub const GUEST_V6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15];
/// `HOST_V4`'s IPv6 twin: the host's own loopback, only when named.
pub const HOST_V6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
/// The length of the network's prefix.
pub const NET_V6_PREFIX: u8 = 64;
/// A name for `HOST_V4`.
/// The largest IP packet on the `vm` network stack's link: a frame each, in
/// one of the console's buffers, as nothing here is a real Ethernet.
pub const MTU: usize = crate::wire::MAX_FRAME - crate::wire::FRAME_HEADER;

pub const HOST_NAME: &str = "host.grix.internal";

/// Ids of connections the host opens (to forwarded ports) have this bit
/// set; the guest picks the others.
pub const HOST_ID: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// Is this `ToHost` message the guest's credit for stdin?
pub fn is_stdin_credit(msg: &[u8]) -> bool {
    matches!(ToHost::decode(msg), Ok(ToHost::StdinCredit { .. }))
}

impl Addr {
    fn put(&self, w: &mut Writer) {
        match self {
            Addr::V4(a) => {
                w.u8(4);
                w.raw(a);
            }
            Addr::V6(a) => {
                w.u8(6);
                w.raw(a);
            }
        }
    }

    fn get(r: &mut Reader) -> Result<Addr, DecodeError> {
        Ok(match r.u8()? {
            4 => Addr::V4(r.take(4)?.try_into().unwrap()),
            6 => Addr::V6(r.take(16)?.try_into().unwrap()),
            _ => return Err(DecodeError),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToHost<'a> {
    /// Open a TCP connection; the answer is `Connected` or `Failed`.
    Connect { id: u32, addr: Addr, port: u16 },
    /// Bytes for the connection's peer, within the credit the host gave.
    Data { id: u32, data: &'a [u8] },
    /// The guest consumed this much of what the host sent on `id`.
    Credit { id: u32, bytes: u32 },
    /// The guest won't send more on `id` (shutdown for writing).
    Shutdown { id: u32 },
    /// The guest is done with `id` (or refuses an `Incoming` one).
    Close { id: u32 },
    /// A DNS query (a UDP payload) for the virtual nameserver. The answer
    /// comes back with the same id.
    Dns { id: u32, query: &'a [u8] },
    /// The program read this much stdin.
    StdinCredit { bytes: u32 },
    /// May UDP socket `id` send to `addr:port`? The answer is `UdpVerdict`.
    UdpAllow { id: u32, addr: Addr, port: u16 },
    /// A datagram from socket `id` to a destination the host allowed.
    UdpSend { id: u32, addr: Addr, port: u16, data: &'a [u8] },
    /// A reply from guest port `port`, forwarded from the host, to
    /// `addr:peer_port`, which sent to it (`ToGuest::UdpIncoming`): it goes
    /// out from the forwarded port, and only to such a peer.
    UdpReply { port: u16, addr: Addr, peer_port: u16, data: &'a [u8] },
    /// The start of the datagram the next `UdpSend` or `UdpReply` ends.
    UdpMore { data: &'a [u8] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToGuest<'a> {
    Connected {
        id: u32,
    },
    /// The connection couldn't be made, or broke: a Linux errno.
    Failed {
        id: u32,
        errno: u16,
    },
    Data {
        id: u32,
        data: &'a [u8],
    },
    /// The host passed on this much of what the guest sent on `id`.
    Credit {
        id: u32,
        bytes: u32,
    },
    /// The peer won't send more.
    Eof {
        id: u32,
    },
    DnsAnswer {
        id: u32,
        answer: &'a [u8],
    },
    /// Someone connected to the host side of a forwarded port: connection
    /// `id` (with `HOST_ID` set) for guest port `port`, from `peer`.
    Incoming {
        id: u32,
        port: u16,
        peer: Addr,
        peer_port: u16,
    },
    /// Whether UDP socket `id` may send to `addr:port`: `UDP_ALLOWED`,
    /// `UDP_REFUSED` or `UDP_BUSY`.
    UdpVerdict {
        id: u32,
        addr: Addr,
        port: u16,
        verdict: u8,
    },
    /// A datagram for UDP socket `id` from `addr:port` (a destination it
    /// sent to). `more` bytes of it follow in `UdpMore`s.
    UdpRecv {
        id: u32,
        addr: Addr,
        port: u16,
        more: u32,
        data: &'a [u8],
    },
    /// A datagram to a UDP port forwarded from the host, for the guest
    /// socket bound at `port`, from `peer:peer_port` (as the guest sees
    /// it: the host's own loopback is `HOST_V4`).
    UdpIncoming {
        port: u16,
        peer: Addr,
        peer_port: u16,
        more: u32,
        data: &'a [u8],
    },
    /// The next of the bytes a `UdpRecv` or `UdpIncoming` said would follow.
    /// A guest may lose any datagram's message under load, so it's the first
    /// that says how much there is, and nothing comes of a part of one.
    UdpMore {
        data: &'a [u8],
    },
}

/// Where a datagram that takes more than one message is going.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Socket { id: u32, addr: Addr, port: u16 },
    Forwarded { port: u16, peer: Addr, peer_port: u16 },
}

impl Bound {
    /// All of a datagram's data, as one message.
    pub fn message(self, data: &[u8]) -> ToGuest<'_> {
        match self {
            Bound::Socket { id, addr, port } => ToGuest::UdpRecv { id, addr, port, more: 0, data },
            Bound::Forwarded { port, peer, peer_port } => ToGuest::UdpIncoming { port, peer, peer_port, more: 0, data },
        }
    }
}

/// A long datagram coming in, at most one at a time: the host queues a
/// datagram's messages together, so a new one means the last has lost a part.
#[derive(Default)]
pub struct Arriving {
    now: Option<(Bound, Vec<u8>, usize)>,
}

impl Arriving {
    pub const fn new() -> Arriving {
        Arriving { now: None }
    }

    fn start(&mut self, to: Bound, more: u32, data: &[u8]) {
        self.now = None;
        let (more, mut held) = (more as usize, Vec::new());
        if more + data.len() <= MAX_DATAGRAM && held.try_reserve_exact(more + data.len()).is_ok() {
            held.extend_from_slice(data);
            self.now = Some((to, held, more));
        }
    }

    /// Take a message with `more` to it, or a `UdpMore`: the whole datagram
    /// if that was the last of it.
    pub fn add(&mut self, msg: &ToGuest) -> Option<(Bound, Vec<u8>)> {
        match *msg {
            ToGuest::UdpRecv { id, addr, port, more, data } => self.start(Bound::Socket { id, addr, port }, more, data),
            ToGuest::UdpIncoming { port, peer, peer_port, more, data } => {
                self.start(Bound::Forwarded { port, peer, peer_port }, more, data)
            }
            ToGuest::UdpMore { data } => {
                let (_, held, more) = self.now.as_mut()?;
                if data.len() > *more {
                    self.now = None;
                    return None;
                }
                held.extend_from_slice(data);
                *more -= data.len();
                if *more == 0 {
                    return self.now.take().map(|(to, held, _)| (to, held));
                }
            }
            _ => {}
        }
        None
    }
}

impl<'a> ToHost<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match *self {
            ToHost::Connect { id, addr, port } => {
                w.u8(1);
                w.u32(id);
                addr.put(&mut w);
                w.raw(&port.to_le_bytes());
            }
            ToHost::Data { id, data } => {
                w.u8(2);
                w.u32(id);
                w.raw(data);
            }
            ToHost::Credit { id, bytes } => {
                w.u8(3);
                w.u32(id);
                w.u32(bytes);
            }
            ToHost::Shutdown { id } => {
                w.u8(4);
                w.u32(id);
            }
            ToHost::Close { id } => {
                w.u8(5);
                w.u32(id);
            }
            ToHost::Dns { id, query } => {
                w.u8(6);
                w.u32(id);
                w.raw(query);
            }
            ToHost::StdinCredit { bytes } => {
                w.u8(7);
                w.u32(bytes);
            }
            ToHost::UdpAllow { id, addr, port } => {
                w.u8(8);
                w.u32(id);
                addr.put(&mut w);
                w.raw(&port.to_le_bytes());
            }
            ToHost::UdpSend { id, addr, port, data } => {
                w.u8(9);
                w.u32(id);
                addr.put(&mut w);
                w.raw(&port.to_le_bytes());
                w.raw(data);
            }
            ToHost::UdpReply { port, addr, peer_port, data } => {
                w.u8(10);
                w.raw(&port.to_le_bytes());
                addr.put(&mut w);
                w.raw(&peer_port.to_le_bytes());
                w.raw(data);
            }
            ToHost::UdpMore { data } => {
                w.u8(11);
                w.raw(data);
            }
        }
        w.buf
    }

    pub fn decode(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let msg = match r.u8()? {
            1 => {
                let id = r.u32()?;
                let addr = Addr::get(&mut r)?;
                ToHost::Connect { id, addr, port: u16::from_le_bytes(r.take(2)?.try_into().unwrap()) }
            }
            2 => ToHost::Data { id: r.u32()?, data: r.rest() },
            3 => ToHost::Credit { id: r.u32()?, bytes: r.u32()? },
            4 => ToHost::Shutdown { id: r.u32()? },
            5 => ToHost::Close { id: r.u32()? },
            6 => ToHost::Dns { id: r.u32()?, query: r.rest() },
            7 => ToHost::StdinCredit { bytes: r.u32()? },
            8 => {
                let id = r.u32()?;
                let addr = Addr::get(&mut r)?;
                ToHost::UdpAllow { id, addr, port: u16::from_le_bytes(r.take(2)?.try_into().unwrap()) }
            }
            9 => {
                let id = r.u32()?;
                let addr = Addr::get(&mut r)?;
                let port = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
                ToHost::UdpSend { id, addr, port, data: r.rest() }
            }
            10 => {
                let port = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
                let addr = Addr::get(&mut r)?;
                let peer_port = u16::from_le_bytes(r.take(2)?.try_into().unwrap());
                ToHost::UdpReply { port, addr, peer_port, data: r.rest() }
            }
            11 => ToHost::UdpMore { data: r.rest() },
            _ => return Err(DecodeError),
        };
        r.done()?;
        Ok(msg)
    }
}

/// Is this encoded `ToGuest` a datagram? Those may be lost, and nothing
/// but the sender's pace bounds them, where a connection's data has its
/// window, paid for when the connection was made.
pub fn is_datagram(msg: &[u8]) -> bool {
    matches!(msg.first(), Some(9..=11))
}

impl<'a> ToGuest<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match *self {
            ToGuest::Connected { id } => {
                w.u8(1);
                w.u32(id);
            }
            ToGuest::Failed { id, errno } => {
                w.u8(2);
                w.u32(id);
                w.raw(&errno.to_le_bytes());
            }
            ToGuest::Data { id, data } => {
                w.u8(3);
                w.u32(id);
                w.raw(data);
            }
            ToGuest::Credit { id, bytes } => {
                w.u8(4);
                w.u32(id);
                w.u32(bytes);
            }
            ToGuest::Eof { id } => {
                w.u8(5);
                w.u32(id);
            }
            ToGuest::DnsAnswer { id, answer } => {
                w.u8(6);
                w.u32(id);
                w.raw(answer);
            }
            ToGuest::UdpVerdict { id, addr, port, verdict } => {
                w.u8(8);
                w.u32(id);
                addr.put(&mut w);
                w.raw(&port.to_le_bytes());
                w.u8(verdict);
            }
            ToGuest::UdpRecv { id, addr, port, more, data } => {
                w.u8(9);
                w.u32(id);
                addr.put(&mut w);
                w.raw(&port.to_le_bytes());
                w.u32(more);
                w.raw(data);
            }
            ToGuest::Incoming { id, port, peer, peer_port } => {
                w.u8(7);
                w.u32(id);
                w.raw(&port.to_le_bytes());
                peer.put(&mut w);
                w.raw(&peer_port.to_le_bytes());
            }
            ToGuest::UdpIncoming { port, peer, peer_port, more, data } => {
                w.u8(10);
                w.raw(&port.to_le_bytes());
                peer.put(&mut w);
                w.raw(&peer_port.to_le_bytes());
                w.u32(more);
                w.raw(data);
            }
            ToGuest::UdpMore { data } => {
                w.u8(11);
                w.raw(data);
            }
        }
        w.buf
    }

    pub fn decode(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let u16_at =
            |r: &mut Reader<'a>| -> Result<u16, DecodeError> { Ok(u16::from_le_bytes(r.take(2)?.try_into().unwrap())) };
        let msg = match r.u8()? {
            1 => ToGuest::Connected { id: r.u32()? },
            2 => ToGuest::Failed { id: r.u32()?, errno: u16_at(&mut r)? },
            3 => ToGuest::Data { id: r.u32()?, data: r.rest() },
            4 => ToGuest::Credit { id: r.u32()?, bytes: r.u32()? },
            5 => ToGuest::Eof { id: r.u32()? },
            6 => ToGuest::DnsAnswer { id: r.u32()?, answer: r.rest() },
            7 => {
                let id = r.u32()?;
                let port = u16_at(&mut r)?;
                let peer = Addr::get(&mut r)?;
                ToGuest::Incoming { id, port, peer, peer_port: u16_at(&mut r)? }
            }
            8 => {
                let id = r.u32()?;
                let addr = Addr::get(&mut r)?;
                let port = u16_at(&mut r)?;
                ToGuest::UdpVerdict { id, addr, port, verdict: r.u8()? }
            }
            9 => {
                let id = r.u32()?;
                let addr = Addr::get(&mut r)?;
                let port = u16_at(&mut r)?;
                let more = r.u32()?;
                ToGuest::UdpRecv { id, addr, port, more, data: r.rest() }
            }
            10 => {
                let port = u16_at(&mut r)?;
                let peer = Addr::get(&mut r)?;
                let peer_port = u16_at(&mut r)?;
                let more = r.u32()?;
                ToGuest::UdpIncoming { port, peer, peer_port, more, data: r.rest() }
            }
            11 => ToGuest::UdpMore { data: r.rest() },
            _ => return Err(DecodeError),
        };
        r.done()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_stdin_credit_is_stdin_credit() {
        assert!(is_stdin_credit(&ToHost::StdinCredit { bytes: 1 }.encode()));
        assert!(!is_stdin_credit(&ToHost::Credit { id: 1, bytes: 1 }.encode()));
        assert!(!is_stdin_credit(&ToHost::Connect { id: 1, addr: Addr::V4([1, 1, 1, 1]), port: 80 }.encode()));
        assert!(!is_stdin_credit(&[]));
    }

    #[test]
    fn only_datagrams_are_datagrams() {
        let (peer, data) = (Addr::V4([1, 2, 3, 4]), &b"d"[..]);
        assert!(is_datagram(&ToGuest::UdpRecv { id: 1, addr: peer, port: 2, more: 0, data }.encode()));
        assert!(is_datagram(&ToGuest::UdpIncoming { port: 2, peer, peer_port: 3, more: 0, data }.encode()));
        assert!(is_datagram(&ToGuest::UdpMore { data }.encode()));
        assert!(!is_datagram(&ToGuest::Data { id: 1, data }.encode()));
        assert!(!is_datagram(&ToGuest::Incoming { id: 1, port: 2, peer, peer_port: 3 }.encode()));
        assert!(!is_datagram(&[]));
    }

    /// A long datagram is all of it or nothing, whichever message is lost.
    #[test]
    fn a_long_datagram_is_all_there() {
        let (addr, data) = (Addr::V4([1, 2, 3, 4]), &[7u8; 10][..]);
        let first = ToGuest::UdpRecv { id: 1, addr, port: 2, more: 20, data };
        let more = ToGuest::UdpMore { data };
        let mut a = Arriving::default();
        assert_eq!(a.add(&first), None);
        assert_eq!(a.add(&more), None);
        let (to, whole) = a.add(&more).unwrap();
        assert_eq!((to, whole.len()), (Bound::Socket { id: 1, addr, port: 2 }, 30));
        // Its start went, or the rest of it never came and another began.
        assert_eq!(a.add(&more), None);
        assert_eq!(a.add(&first), None);
        assert_eq!(a.add(&more), None);
        assert_eq!(a.add(&first), None);
        assert_eq!(a.add(&more), None);
        assert_eq!(a.add(&more).map(|w| w.1.len()), Some(30));
        // Too much, of what it said or of what a datagram can be.
        assert_eq!(a.add(&ToGuest::UdpRecv { id: 1, addr, port: 2, more: 5, data }), None);
        assert_eq!(a.add(&more), None);
        assert_eq!(a.add(&ToGuest::UdpMore { data: &data[..5] }), None);
        let huge = MAX_DATAGRAM as u32;
        assert_eq!(a.add(&ToGuest::UdpRecv { id: 1, addr, port: 2, more: huge, data }), None);
        assert_eq!(a.add(&ToGuest::UdpMore { data: &[0; 1 << 16] }), None);
        assert_eq!(a.add(&ToGuest::UdpRecv { id: 1, addr, port: 2, more: u32::MAX, data }), None);
    }

    #[test]
    fn roundtrip_and_reject_garbage() {
        let to_host = [
            ToHost::Connect { id: 3, addr: Addr::V6([7; 16]), port: 443 },
            ToHost::Data { id: 3, data: b"GET /" },
            ToHost::Credit { id: 3, bytes: 900 },
            ToHost::Shutdown { id: 3 },
            ToHost::Close { id: 3 },
            ToHost::Dns { id: 9, query: &[1, 2, 3] },
            ToHost::StdinCredit { bytes: 5 },
            ToHost::UdpAllow { id: 4, addr: Addr::V4([8, 8, 8, 8]), port: 123 },
            ToHost::UdpSend { id: 4, addr: Addr::V6([1; 16]), port: 9, data: b"ntp" },
            ToHost::UdpReply { port: 53, addr: Addr::V4(HOST_V4), peer_port: 40000, data: b"answer" },
            ToHost::UdpReply { port: 53, addr: Addr::V6([2; 16]), peer_port: 1, data: b"" },
        ];
        for m in to_host {
            assert_eq!(ToHost::decode(&m.encode()), Ok(m));
        }
        let to_guest = [
            ToGuest::Connected { id: 3 },
            ToGuest::Failed { id: 3, errno: 111 },
            ToGuest::Data { id: 3, data: b"HTTP/1.1" },
            ToGuest::Credit { id: 3, bytes: 1 },
            ToGuest::Eof { id: 3 },
            ToGuest::DnsAnswer { id: 9, answer: &[4] },
            ToGuest::Incoming { id: HOST_ID | 1, port: 8000, peer: Addr::V4([127, 0, 0, 1]), peer_port: 5555 },
            ToGuest::UdpVerdict { id: 4, addr: Addr::V4([8, 8, 8, 8]), port: 123, verdict: UDP_ALLOWED },
            ToGuest::UdpRecv { id: 4, addr: Addr::V4([8, 8, 8, 8]), port: 123, more: 0, data: b"time" },
            ToGuest::UdpIncoming { port: 53, peer: Addr::V4(HOST_V4), peer_port: 40000, more: 0, data: b"query" },
            ToGuest::UdpIncoming { port: 53, peer: Addr::V6([3; 16]), peer_port: 2, more: 9, data: b"" },
        ];
        for m in to_guest {
            assert_eq!(ToGuest::decode(&m.encode()), Ok(m));
        }
        for bad in [&[][..], &[0], &[1, 0, 0], &[1, 0, 0, 0, 0, 5, 0], &[3, 0, 0, 0, 0, 0, 0, 0, 0, 9]] {
            assert!(ToHost::decode(bad).is_err(), "{bad:?}");
        }
        assert!(ToGuest::decode(&[7, 1, 0, 0, 0, 1, 0, 4, 1]).is_err());
        // A forwarded datagram needs a whole address and port.
        assert!(ToGuest::decode(&[10, 53, 0, 4, 10, 0, 2]).is_err());
        assert!(ToHost::decode(&[10, 53, 0, 5, 0]).is_err());
    }
}
