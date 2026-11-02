//! The `vm` network stack: TCP/IP that runs in the guest, on a link that's
//! IP packets on the console (`Channel::Packet`, `Input::Packet`), so the
//! machine has no more devices than it had.
//!
//! The two ends are the same code. `Stack` turns reads and writes on
//! connections into packets and back. The guest's kernel has its sockets on
//! one, in place of the messages they send the host in the `native` stack;
//! the host's gateway has one that answers for every address, and turns what
//! comes out of it back into those messages for the proxy, which checks the
//! policy and makes the real connections. So nothing a guest sends leaves as
//! the packet it sent, and the proxy decides as it always has.
//!
//! UDP and ICMP have no state to keep here: `packet` builds and parses them.
#![no_std]
extern crate alloc;

pub mod packet;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;

use grix_abi::link::{self, Addr, MAX_DATA, WINDOW};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address};

pub use packet::{Endpoint, Packet};

/// Packets held each way between `poll`s: a link that's full is a link
/// that's full, and TCP sends again.
const QUEUE: usize = 64;
/// A handshake nobody finishes, or a closed connection's peer that's gone.
const PATIENCE: Duration = Duration::from_secs(60);

fn instant(ms: u64) -> Instant {
    Instant::from_millis(ms as i64)
}

pub fn ip(a: Addr) -> IpAddress {
    match a {
        Addr::V4(a) => IpAddress::Ipv4(Ipv4Address::from_octets(a)),
        Addr::V6(a) => IpAddress::Ipv6(Ipv6Address::from_octets(a)),
    }
}

pub fn addr(a: IpAddress) -> Addr {
    match a {
        IpAddress::Ipv4(a) => Addr::V4(a.octets()),
        IpAddress::Ipv6(a) => Addr::V6(a.octets()),
    }
}

fn endpoint(e: Endpoint) -> IpEndpoint {
    IpEndpoint::new(ip(e.addr), e.port)
}

/// Packets on their way in and out.
#[derive(Default)]
struct Wire {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct In(Vec<u8>);
struct Out<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for In {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Out<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut p = vec![0; len];
        let r = f(&mut p);
        self.0.push_back(p);
        r
    }
}

impl Device for Wire {
    type RxToken<'a> = In;
    type TxToken<'a> = Out<'a>;

    fn receive(&mut self, _: Instant) -> Option<(In, Out<'_>)> {
        // (A token to answer with, even when there's no room: the answer is
        // then one packet more, not a stalled link.)
        let p = self.rx.pop_front()?;
        Some((In(p), Out(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Out<'_>> {
        (self.tx.len() < QUEUE).then_some(Out(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = link::MTU;
        c
    }
}

/// What a connection did, for the code on top to pass on.
#[derive(Debug, PartialEq, Eq)]
pub enum Note<'a> {
    /// The handshake's done.
    Connected { id: u32 },
    /// It never was: the peer refused, or it timed out.
    Refused { id: u32 },
    /// A connection that was made broke.
    Reset { id: u32 },
    /// Bytes from the peer, within the credit given.
    Data { id: u32, data: &'a [u8] },
    /// The peer won't send more.
    Eof { id: u32 },
    /// This much that was written has gone, so as much can be written again.
    Room { id: u32, bytes: u32 },
    /// Both sides said goodbye: only `close` is left.
    Done { id: u32 },
}

/// Why a connection or a listen couldn't be had.
#[derive(Debug, PartialEq, Eq)]
pub struct Full;

struct Flow {
    socket: SocketHandle,
    /// Bytes whoever's on top has room for.
    credit: u32,
    /// In the socket's send buffer when last looked at.
    queued: usize,
    connected: bool,
    /// `Note::Eof` was given.
    eof: bool,
    /// Its side was shut down.
    shut: bool,
    /// `Note::Refused` or `Reset` was given: only `close` is left.
    over: bool,
}

/// Where a stack is, and who it sends everything to.
pub struct Identity {
    pub v4: [u8; 4],
    pub v6: [u8; 16],
    pub peer_v4: [u8; 4],
    pub peer_v6: [u8; 16],
    /// Answer for every address (the gateway), not just these.
    pub any_address: bool,
}

pub struct Stack {
    iface: Interface,
    wire: Wire,
    sockets: SocketSet<'static>,
    flows: BTreeMap<u32, Flow>,
    /// Sockets nobody's on top of any more, finishing what they were doing.
    closing: Vec<SocketHandle>,
    /// `sockets`' slots: never more, as a socket set's growth can't fail
    /// cleanly and a kernel's heap can't take that.
    capacity: usize,
    /// Bytes in each of a socket's two buffers. What's written has to fit
    /// (`Note::Room` says when more does); what's read is the reader's.
    buffer: usize,
}

impl Stack {
    /// A stack for at most `capacity` flows, with `buffer` bytes each way
    /// in each. `seed` is for what TCP picks.
    pub fn new(identity: &Identity, capacity: usize, buffer: usize, seed: u64, now_ms: u64) -> Stack {
        let mut wire = Wire::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut wire, instant(now_ms));
        iface.update_ip_addrs(|a| {
            let v4 = IpAddress::Ipv4(Ipv4Address::from_octets(identity.v4));
            let v6 = IpAddress::Ipv6(Ipv6Address::from_octets(identity.v6));
            // Room for both is `Interface`'s to have: two is its default.
            let _ = a.push(IpCidr::new(v4, 24));
            let _ = a.push(IpCidr::new(v6, link::NET_V6_PREFIX));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::from_octets(identity.peer_v4));
        let _ = iface.routes_mut().add_default_ipv6_route(Ipv6Address::from_octets(identity.peer_v6));
        iface.set_any_ip(identity.any_address);
        let sockets = SocketSet::new((0..capacity).map(|_| SocketStorage::EMPTY).collect::<Vec<_>>());
        Stack { iface, wire, sockets, flows: BTreeMap::new(), closing: Vec::new(), capacity, buffer }
    }

    /// Sockets in use, the ones closing too: what a caller's budget pays for.
    pub fn in_use(&self) -> usize {
        self.flows.len() + self.closing.len()
    }

    fn socket(&self) -> Result<tcp::Socket<'static>, Full> {
        let buffer = || -> Result<Vec<u8>, Full> {
            let mut b = Vec::new();
            b.try_reserve_exact(self.buffer).map_err(|_| Full)?;
            b.resize(self.buffer, 0);
            Ok(b)
        };
        let mut s = tcp::Socket::new(tcp::SocketBuffer::new(buffer()?), tcp::SocketBuffer::new(buffer()?));
        // Two stacks in a row, and a program that asked for a small write
        // meant one: waiting to fill a segment only costs here.
        s.set_nagle_enabled(false);
        Ok(s)
    }

    fn add(&mut self, id: u32, socket: tcp::Socket<'static>) -> Result<(), Full> {
        if self.in_use() >= self.capacity {
            return Err(Full);
        }
        let socket = self.sockets.add(socket);
        let flow = Flow { socket, credit: WINDOW, queued: 0, connected: false, eof: false, shut: false, over: false };
        self.flows.insert(id, flow);
        Ok(())
    }

    /// Start a connection from `local` to `peer`.
    pub fn connect(&mut self, id: u32, local: Endpoint, peer: Endpoint) -> Result<(), Full> {
        let mut s = self.socket()?;
        s.connect(self.iface.context(), endpoint(peer), endpoint(local)).map_err(|_| Full)?;
        self.add(id, s)
    }

    /// Take `syn`, the first packet of a connection to `local`, as flow `id`.
    pub fn accept(&mut self, id: u32, local: Endpoint, syn: Vec<u8>, now_ms: u64) -> Result<(), Full> {
        let mut s = self.socket()?;
        let at = IpListenEndpoint { addr: Some(ip(local.addr)), port: local.port };
        s.listen(at).map_err(|_| Full)?;
        // Nobody may finish a handshake and leave the slot held for ever.
        s.set_timeout(Some(PATIENCE));
        self.add(id, s)?;
        self.wire.rx.push_back(syn);
        // Now: a listening socket takes the next SYN for that address, and
        // that has to be this one.
        self.step(now_ms);
        Ok(())
    }

    /// The flow between these two, if there is one.
    pub fn flow(&self, local: Endpoint, peer: Endpoint) -> Option<u32> {
        let (local, peer) = (endpoint(local), endpoint(peer));
        self.flows
            .iter()
            .find(|(_, f)| {
                let s = self.sockets.get::<tcp::Socket>(f.socket);
                s.local_endpoint() == Some(local) && s.remote_endpoint() == Some(peer)
            })
            .map(|(id, _)| *id)
    }

    /// A flow's hop limit, and seconds between keepalives if it has them.
    pub fn configure(&mut self, id: u32, hop_limit: Option<u8>, keepalive_secs: Option<u32>) {
        if let Some(f) = self.flows.get(&id) {
            let s = self.sockets.get_mut::<tcp::Socket>(f.socket);
            s.set_hop_limit(hop_limit);
            s.set_keep_alive(keepalive_secs.map(|n| Duration::from_secs(n as u64)));
        }
    }

    /// Hand the peer `data`: whatever fits, and the rest is the caller's to
    /// keep (`Room` says when). The sender's credit keeps it from happening.
    pub fn write(&mut self, id: u32, data: &[u8]) -> usize {
        let Some(f) = self.flows.get_mut(&id) else { return 0 };
        let s = self.sockets.get_mut::<tcp::Socket>(f.socket);
        let n = s.send_slice(data).unwrap_or(0);
        f.queued = s.send_queue();
        n
    }

    /// The reader has `bytes` more room.
    pub fn credit(&mut self, id: u32, bytes: u32) {
        if let Some(f) = self.flows.get_mut(&id) {
            f.credit = f.credit.saturating_add(bytes).min(WINDOW);
        }
    }

    /// No more to write: the peer gets a FIN after what's queued.
    pub fn shutdown(&mut self, id: u32) {
        if let Some(f) = self.flows.get_mut(&id) {
            f.shut = true;
            self.sockets.get_mut::<tcp::Socket>(f.socket).close();
        }
    }

    /// Whoever's on top is gone. A socket with data nobody read resets,
    /// as Linux's does; any other says goodbye, and goes when that's over.
    pub fn close(&mut self, id: u32) {
        let Some(f) = self.flows.remove(&id) else { return };
        let s = self.sockets.get_mut::<tcp::Socket>(f.socket);
        if s.recv_queue() > 0 {
            s.abort();
        } else {
            s.close();
        }
        s.set_timeout(Some(PATIENCE));
        self.closing.push(f.socket);
    }

    /// End flow `id` now, the peer told with a reset.
    pub fn abort(&mut self, id: u32) {
        if let Some(f) = self.flows.get_mut(&id) {
            self.sockets.get_mut::<tcp::Socket>(f.socket).abort();
        }
        self.close(id);
    }

    /// A packet from the link. False if there's no room for it: it's lost.
    pub fn receive(&mut self, packet: Vec<u8>) -> bool {
        if self.wire.rx.len() >= QUEUE {
            return false;
        }
        self.wire.rx.push_back(packet);
        true
    }

    /// A packet for the link, made by something other than a socket.
    /// False if there's no room: it's lost.
    pub fn transmit(&mut self, packet: Vec<u8>) -> bool {
        if self.wire.tx.len() >= QUEUE {
            return false;
        }
        self.wire.tx.push_back(packet);
        true
    }

    /// Give packets to `send` while it takes them.
    pub fn take_packets(&mut self, mut send: impl FnMut(&[u8]) -> bool) {
        while let Some(p) = self.wire.tx.front() {
            if !send(p) {
                return;
            }
            self.wire.tx.pop_front();
        }
    }

    fn step(&mut self, now_ms: u64) {
        let _ = self.iface.poll(instant(now_ms), &mut self.wire, &mut self.sockets);
    }

    /// Move everything on, and say what happened. True if it should be
    /// called again once what it said is dealt with: a flow's data waits
    /// for the `Connected` before it, which whoever's on top may have to
    /// act on first, or the data has nowhere to go.
    pub fn poll(&mut self, now_ms: u64, mut note: impl FnMut(Note<'_>)) -> bool {
        self.step(now_ms);
        let (mut read, mut again) = (false, false);
        for (&id, f) in self.flows.iter_mut() {
            let s = self.sockets.get_mut::<tcp::Socket>(f.socket);
            if !f.connected && !f.over && s.may_send() {
                f.connected = true;
                note(Note::Connected { id });
                again = true;
                continue;
            }
            let queued = s.send_queue();
            if queued < f.queued {
                note(Note::Room { id, bytes: (f.queued - queued) as u32 });
            }
            f.queued = queued;
            while f.credit > 0 && s.can_recv() {
                let room = (f.credit as usize).min(MAX_DATA);
                let took = s.recv(|b| {
                    let n = b.len().min(room);
                    note(Note::Data { id, data: &b[..n] });
                    (n, n)
                });
                let Ok(n) = took else { break };
                f.credit -= n as u32;
                read = true;
            }
            if f.connected && !f.eof && !s.may_recv() && s.recv_queue() == 0 {
                f.eof = true;
                // (A reset isn't an end of file, and it's said below.)
                if s.is_open() || f.shut {
                    note(Note::Eof { id });
                }
            }
            if !f.over && !s.is_open() {
                f.over = true;
                note(match (f.connected, f.eof && f.shut) {
                    (_, true) => Note::Done { id },
                    (true, false) => Note::Reset { id },
                    (false, false) => Note::Refused { id },
                });
            }
        }
        // What was read makes room, and the peer should hear of it.
        if read {
            self.step(now_ms);
        }
        let sockets = &mut self.sockets;
        self.closing.retain(|&h| {
            // (TIME-WAIT included: nobody here reuses a port soon.)
            let open = sockets.get::<tcp::Socket>(h).is_open();
            if !open {
                sockets.remove(h);
            }
            open
        });
        again
    }

    /// When `poll` is next wanted if nothing comes in: a retransmission, a
    /// delayed ACK. None: only when something does.
    pub fn next_poll(&mut self, now_ms: u64) -> Option<u64> {
        let at = self.iface.poll_at(instant(now_ms), &self.sockets)?;
        Some(at.total_millis().max(0) as u64)
    }

    /// Has everything that came in been taken?
    pub fn drained(&self) -> bool {
        self.wire.rx.is_empty()
            && self.flows.values().all(|f| self.sockets.get::<tcp::Socket>(f.socket).recv_queue() == 0)
    }

    /// Is everything written acknowledged, and nothing waiting for the link?
    pub fn flushed(&self) -> bool {
        let done = |h: SocketHandle| {
            let s = self.sockets.get::<tcp::Socket>(h);
            s.send_queue() == 0 || !s.is_open()
        };
        self.wire.tx.is_empty() && self.flows.values().all(|f| done(f.socket)) && self.closing.iter().all(|&h| done(h))
    }
}
