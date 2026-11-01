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
/// The largest UDP datagram that goes through the host (one frame).
/// Bigger ones aren't carried: the guest's sends fail with EMSGSIZE, and
/// the host drops what comes in, as a network that can't fragment would.
pub const MAX_UDP: usize = MAX_FRAME - 32;
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
pub const HOST_NAME: &str = "host.grix.internal";

/// Ids of connections the host opens (to forwarded ports) have this bit
/// set; the guest picks the others.
pub const HOST_ID: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
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
    /// sent to).
    UdpRecv {
        id: u32,
        addr: Addr,
        port: u16,
        data: &'a [u8],
    },
    /// A datagram to a UDP port forwarded from the host, for the guest
    /// socket bound at `port`, from `peer:peer_port` (as the guest sees
    /// it: the host's own loopback is `HOST_V4`).
    UdpIncoming {
        port: u16,
        peer: Addr,
        peer_port: u16,
        data: &'a [u8],
    },
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
    matches!(msg.first(), Some(9 | 10))
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
            ToGuest::UdpRecv { id, addr, port, data } => {
                w.u8(9);
                w.u32(id);
                addr.put(&mut w);
                w.raw(&port.to_le_bytes());
                w.raw(data);
            }
            ToGuest::Incoming { id, port, peer, peer_port } => {
                w.u8(7);
                w.u32(id);
                w.raw(&port.to_le_bytes());
                peer.put(&mut w);
                w.raw(&peer_port.to_le_bytes());
            }
            ToGuest::UdpIncoming { port, peer, peer_port, data } => {
                w.u8(10);
                w.raw(&port.to_le_bytes());
                peer.put(&mut w);
                w.raw(&peer_port.to_le_bytes());
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
                ToGuest::UdpRecv { id, addr, port, data: r.rest() }
            }
            10 => {
                let port = u16_at(&mut r)?;
                let peer = Addr::get(&mut r)?;
                let peer_port = u16_at(&mut r)?;
                ToGuest::UdpIncoming { port, peer, peer_port, data: r.rest() }
            }
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
    fn only_datagrams_are_datagrams() {
        let (peer, data) = (Addr::V4([1, 2, 3, 4]), &b"d"[..]);
        assert!(is_datagram(&ToGuest::UdpRecv { id: 1, addr: peer, port: 2, data }.encode()));
        assert!(is_datagram(&ToGuest::UdpIncoming { port: 2, peer, peer_port: 3, data }.encode()));
        assert!(!is_datagram(&ToGuest::Data { id: 1, data }.encode()));
        assert!(!is_datagram(&ToGuest::Incoming { id: 1, port: 2, peer, peer_port: 3 }.encode()));
        assert!(!is_datagram(&[]));
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
            ToGuest::UdpRecv { id: 4, addr: Addr::V4([8, 8, 8, 8]), port: 123, data: b"time" },
            ToGuest::UdpIncoming { port: 53, peer: Addr::V4(HOST_V4), peer_port: 40000, data: b"query" },
            ToGuest::UdpIncoming { port: 53, peer: Addr::V6([3; 16]), peer_port: 2, data: b"" },
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
