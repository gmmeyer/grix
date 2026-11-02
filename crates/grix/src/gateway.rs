//! The `vm` network stack's end on the host: a stack that answers for every
//! address, with whatever comes out of it turned back into the messages the
//! `native` stack's sockets send the proxy. So the proxy still makes every
//! connection and checks everything it checks: what a guest puts in a packet
//! reaches this and stops here, and only the bytes or the question go on.
//!
//! A connection: the guest's SYN waits here while the proxy connects (or
//! refuses, and the guest's told why), and only then is it answered, so
//! `connect` means what it means in the `native` stack. UDP and ICMP are a
//! socket per source port or echo identifier, each destination asked about
//! once, as a guest's own socket would. Packets are untrusted: the source
//! must be the guest, and what's kept for them is bounded.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use grix_abi::link::{self, Addr, ToGuest, ToHost};
use grix_abi::wire::{self, Input};
use grix_netstack::packet::{self, Unreachable};
use grix_netstack::{Endpoint, Identity, Note, Packet, Stack};

use crate::net::{LAST_DATA, Outbox, Proxy};

/// Connections at once: as many as a guest may have.
const FLOWS: usize = 2048;
/// Sockets kept for UDP and echoes; the longest unused goes first.
const SOCKETS: usize = 1024;
/// Destinations remembered per socket.
const DESTINATIONS: usize = 256;
/// Bytes of datagrams held while the proxy decides on their destination.
const HELD_BYTES: usize = 1 << 20;
/// DNS queries a socket remembers the server of, as `inet::MAX_ANSWERS`.
const SERVERS: usize = 16;
/// Work waiting for this thread.
const QUEUE: usize = 1024;
/// Waiting for nothing: there's always something to look at by then.
const IDLE: Duration = Duration::from_secs(1);

const EPERM: u16 = 1;
const EACCES: u16 = 13;
const ENETUNREACH: u16 = 101;
const ECONNREFUSED: u16 = 111;

enum Work {
    Packet(Vec<u8>),
    Proxy(Vec<u8>),
    /// And is what the guest sent still to go on?
    Stop(bool),
    #[cfg(test)]
    Panic,
}

pub(crate) struct Gateway {
    work: SyncSender<Work>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Gateway {
    /// Stand between the guest and `proxy`, whose messages for the guest
    /// come out of `from_proxy`. Packets for it go out through `to_guest`.
    pub fn start(proxy: Arc<Proxy>, from_proxy: Arc<Outbox>, to_guest: Arc<Outbox>) -> Result<Gateway> {
        let (work, inbox) = mpsc::sync_channel(QUEUE);
        let messages = work.clone();
        // It may wait: the proxy's workers do, for room, as they would for
        // the guest. `Proxy::handle`, which this thread calls, never does.
        thread::Builder::new()
            .spawn(move || {
                while let Some(frame) = from_proxy.next() {
                    if messages.send(Work::Proxy(frame)).is_err() {
                        break;
                    }
                }
            })
            .context("starting the network gateway")?;
        // Nothing here's secret: this link is the guest and us.
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).map_or(1, |t| t.as_nanos() as u64);
        let identity = Identity {
            v4: link::HOST_V4,
            v6: link::HOST_V6,
            peer_v4: link::GUEST_V4,
            peer_v6: link::GUEST_V6,
            any_address: true,
        };
        let state = State {
            stack: Stack::new(&identity, FLOWS, link::WINDOW as usize, seed, 0),
            proxy,
            to_guest,
            start: Instant::now(),
            next_id: 1,
            flows: HashMap::new(),
            ends: HashMap::new(),
            held: HashMap::new(),
            early: HashMap::new(),
            sources: HashMap::new(),
            sockets: HashMap::new(),
            peers: VecDeque::new(),
            held_bytes: 0,
            tick: 0,
            reassembly: packet::Reassembly::default(),
            next_ip_id: 0,
            arriving: link::Arriving::default(),
        };
        let thread = thread::Builder::new().spawn(move || state.run(inbox)).context("starting the network gateway")?;
        Ok(Gateway { work, thread: Mutex::new(Some(thread)) })
    }

    /// A packet from the guest: lost if there's no room, as on any link.
    pub fn packet(&self, p: &[u8]) {
        let _ = self.work.try_send(Work::Packet(p.to_vec()));
    }

    /// Stop, the proxy still there: with `finished`, the program ended, and
    /// what it sent goes on first.
    pub fn stop(&self, finished: bool) {
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = self.work.send(Work::Stop(finished));
            let _ = t.join();
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop(false);
    }
}

/// What the peer sent before the guest finished its side of the handshake:
/// within the window, as the proxy keeps to it.
#[derive(Default)]
struct Early {
    data: Vec<u8>,
    eof: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    Port(u16),
    Echo { v6: bool, ident: u16 },
}

enum Verdict {
    /// The proxy's deciding: these wait for its answer.
    Asked(Vec<Vec<u8>>),
    Allowed,
    Refused,
}

struct Socket {
    source: Source,
    used: u64,
    verdicts: HashMap<Endpoint, Verdict>,
    /// (DNS id, server): an answer comes from where it was asked.
    servers: VecDeque<(u16, Endpoint)>,
}

struct State {
    stack: Stack,
    proxy: Arc<Proxy>,
    to_guest: Arc<Outbox>,
    start: Instant,
    next_id: u32,
    /// Connections by their ends, the guest's first.
    flows: HashMap<(Endpoint, Endpoint), u32>,
    ends: HashMap<u32, (Endpoint, Endpoint)>,
    /// First packets of connections the proxy's making.
    held: HashMap<u32, Vec<u8>>,
    early: HashMap<u32, Early>,
    sources: HashMap<Source, u32>,
    sockets: HashMap<u32, Socket>,
    /// (guest port, sender) of the last datagrams through forwarded ports:
    /// what goes back to them is a `UdpReply`.
    peers: VecDeque<(u16, Endpoint)>,
    held_bytes: usize,
    /// Fragments from the guest, and what tells this end's apart.
    reassembly: packet::Reassembly,
    next_ip_id: u32,
    /// A datagram from the proxy, which is a message or a few.
    arriving: link::Arriving,
    tick: u64,
}

fn own(to: Addr) -> Addr {
    if matches!(to, Addr::V6(_)) { Addr::V6(link::GUEST_V6) } else { Addr::V4(link::GUEST_V4) }
}

fn is_guest(a: Addr) -> bool {
    a == Addr::V4(link::GUEST_V4) || a == Addr::V6(link::GUEST_V6)
}

impl State {
    fn ask(&self, msg: ToHost) {
        self.proxy.handle(&msg.encode());
    }

    fn ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// The TCP stack is a library's, with panics of its own (its sequence
    /// numbers' arithmetic), and what it's given is a guest's to say. All
    /// that comes of one is that this sandbox has no more network, and
    /// it's told so: the host goes on, and so does the proxy's cleaning up.
    fn run(mut self, inbox: Receiver<Work>) {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.serve(&inbox))).is_ok() {
            return;
        }
        self.proxy.refuse("network", "the gateway's TCP stack failed: the sandbox's network has stopped".into());
        // Nobody's told to stop sending, so what they send goes nowhere.
        for work in inbox.iter() {
            if matches!(work, Work::Stop(_)) {
                return;
            }
        }
    }

    fn serve(&mut self, inbox: &Receiver<Work>) {
        loop {
            let now = self.ms();
            let wait = match self.stack.next_poll(now) {
                Some(at) => Duration::from_millis(at.saturating_sub(now)).min(IDLE),
                None => IDLE,
            };
            let first = match inbox.recv_timeout(wait) {
                Ok(w) => Some(w),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => return,
            };
            let mut next = first;
            // A batch, so one poll takes what's come in together.
            for _ in 0..QUEUE {
                match next {
                    Some(Work::Packet(p)) => self.on_packet(p),
                    Some(Work::Proxy(f)) => {
                        if let Ok(msg) = ToGuest::decode(f.get(wire::FRAME_HEADER..).unwrap_or(&[])) {
                            self.on_message(msg);
                        }
                    }
                    Some(Work::Stop(true)) => return self.finish(inbox),
                    Some(Work::Stop(false)) => return,
                    #[cfg(test)]
                    Some(Work::Panic) => panic!("as the TCP stack might"),
                    None => break,
                }
                next = inbox.try_recv().ok();
            }
            self.advance();
        }
    }

    /// The program ended. What it sent is still to reach its peers, as the
    /// kernel would have seen to on Linux: the stack's data goes to the
    /// proxy as fast as they take it (`Proxy::finish` does the rest).
    fn finish(&mut self, inbox: &Receiver<Work>) {
        let end = Instant::now() + LAST_DATA;
        self.advance();
        while !self.stack.drained() && Instant::now() < end {
            if let Ok(Work::Proxy(f)) = inbox.recv_timeout(Duration::from_millis(10))
                && let Ok(msg) = ToGuest::decode(f.get(wire::FRAME_HEADER..).unwrap_or(&[]))
            {
                self.on_message(msg);
            }
            self.advance();
        }
    }

    /// Move the stack on and pass on what it did.
    fn advance(&mut self) {
        loop {
            let (mut made, mut over) = (Vec::new(), Vec::new());
            let (now, proxy) = (self.ms(), &self.proxy);
            let again = self.stack.poll(now, |note| match note {
                Note::Data { id, data } => proxy.handle(&ToHost::Data { id, data }.encode()),
                Note::Room { id, bytes } => proxy.handle(&ToHost::Credit { id, bytes }.encode()),
                Note::Eof { id } => proxy.handle(&ToHost::Shutdown { id }.encode()),
                Note::Connected { id } => made.push(id),
                Note::Refused { id } | Note::Reset { id } | Note::Done { id } => over.push(id),
            });
            for id in made {
                if let Some(e) = self.early.remove(&id) {
                    self.stack.write(id, &e.data);
                    if e.eof {
                        self.stack.shutdown(id);
                    }
                }
            }
            for id in over {
                self.ask(ToHost::Close { id });
                self.forget(id);
            }
            if !again {
                break;
            }
        }
        let to_guest = &self.to_guest;
        self.stack.take_packets(|p| {
            let mut f = wire::input_header(Input::Packet, p.len()).to_vec();
            f.extend_from_slice(p);
            to_guest.offer_lossy(f)
        });
    }

    fn forget(&mut self, id: u32) {
        self.stack.close(id);
        self.held.remove(&id);
        self.early.remove(&id);
        if let Some(ends) = self.ends.remove(&id) {
            self.flows.remove(&ends);
        }
    }

    fn id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1) & !link::HOST_ID;
        id
    }

    /// `p` to the guest, in pieces if it won't fit the link.
    fn transmit(&mut self, p: Vec<u8>) {
        self.next_ip_id = self.next_ip_id.wrapping_add(1);
        for piece in packet::fragments(p, self.next_ip_id).unwrap_or_default() {
            self.stack.transmit(piece);
        }
    }

    fn on_packet(&mut self, p: Vec<u8>) {
        let Some(p) = self.reassembly.add(p) else { return };
        // A guest may say what it likes in a packet, with a raw socket or a
        // kernel of its own. It goes no further than this, and it's said so.
        if let Some((protocol, from, ..)) = packet::header(&p) {
            if !is_guest(from) {
                return self.proxy.refuse("sendto", format!("a packet from {from:?}, which isn't the sandbox"));
            }
            if !matches!(protocol, 1 | 6 | 17 | 58) {
                return self.proxy.refuse("sendto", format!("IP protocol {protocol}: only TCP, UDP and ping leave"));
            }
        }
        match packet::parse(&p) {
            Some(Packet::Tcp { from, to, syn }) if is_guest(from.addr) => match self.flows.get(&(from, to)) {
                // It sent its SYN again: the proxy's still connecting.
                Some(id) if self.held.contains_key(id) => {}
                Some(_) => {
                    self.stack.receive(p);
                }
                None if syn && self.flows.len() < FLOWS => {
                    let id = self.id();
                    self.flows.insert((from, to), id);
                    self.ends.insert(id, (from, to));
                    self.held.insert(id, p);
                    self.ask(ToHost::Connect { id, addr: to.addr, port: to.port });
                }
                None if syn => {
                    if let Some(refused) = packet::reset(&p) {
                        self.transmit(refused);
                    }
                }
                // No such connection: the stack says so.
                None => {
                    self.stack.receive(p);
                }
            },
            Some(Packet::Udp { from, to, data }) if is_guest(from.addr) => self.datagram(from, to, data),
            Some(Packet::Echo { from, to, request: true, message }) if is_guest(from) && message.len() >= 8 => {
                let v6 = matches!(from, Addr::V6(_));
                let ident = u16::from_be_bytes([message[4], message[5]]);
                let id = self.socket(Source::Echo { v6, ident });
                self.checked(id, Endpoint { addr: to, port: link::ICMP_PORT }, message);
            }
            _ => {}
        }
    }

    fn datagram(&mut self, from: Endpoint, to: Endpoint, data: &[u8]) {
        let id = self.socket(Source::Port(from.port));
        // A reply out of the forwarded port, even to port 53: it's no query.
        if self.peers.contains(&(from.port, to)) {
            return self.ask(ToHost::UdpReply { port: from.port, addr: to.addr, peer_port: to.port, data });
        }
        if to.port == 53 {
            if let (Some(s), [a, b, ..]) = (self.sockets.get_mut(&id), data) {
                let query = u16::from_be_bytes([*a, *b]);
                s.servers.retain(|(q, _)| *q != query);
                if s.servers.len() >= SERVERS {
                    s.servers.pop_front();
                }
                s.servers.push_back((query, to));
            }
            return self.ask(ToHost::Dns { id, query: data });
        }
        self.checked(id, to, data);
    }

    /// Send `data` on socket `id` if the proxy allows `to`, asked once.
    fn checked(&mut self, id: u32, to: Endpoint, data: &[u8]) {
        let Some(s) = self.sockets.get_mut(&id) else { return };
        match s.verdicts.get_mut(&to) {
            Some(Verdict::Allowed) => self.ask(ToHost::UdpSend { id, addr: to.addr, port: to.port, data }),
            Some(Verdict::Refused) => {}
            Some(Verdict::Asked(waiting)) => {
                if self.held_bytes + data.len() <= HELD_BYTES {
                    self.held_bytes += data.len();
                    waiting.push(data.to_vec());
                }
            }
            None => {
                if s.verdicts.len() >= DESTINATIONS {
                    let dropped: usize = s.verdicts.values().map(held).sum();
                    self.held_bytes -= dropped;
                    s.verdicts.clear();
                }
                s.verdicts.insert(to, Verdict::Asked(vec![data.to_vec()]));
                self.held_bytes += data.len();
                self.ask(ToHost::UdpAllow { id, addr: to.addr, port: to.port });
            }
        }
    }

    /// The socket for `source`, made if it has to be.
    fn socket(&mut self, source: Source) -> u32 {
        self.tick += 1;
        let tick = self.tick;
        if let Some(&id) = self.sources.get(&source) {
            if let Some(s) = self.sockets.get_mut(&id) {
                s.used = tick;
            }
            return id;
        }
        if self.sockets.len() >= SOCKETS
            && let Some((&old, _)) = self.sockets.iter().min_by_key(|(_, s)| s.used)
            && let Some(s) = self.sockets.remove(&old)
        {
            self.held_bytes -= s.verdicts.values().map(held).sum::<usize>();
            self.sources.remove(&s.source);
            self.ask(ToHost::Close { id: old });
        }
        let id = self.id();
        self.sources.insert(source, id);
        let socket = Socket { source, used: tick, verdicts: HashMap::new(), servers: VecDeque::new() };
        self.sockets.insert(id, socket);
        id
    }

    fn on_message(&mut self, msg: ToGuest) {
        match msg {
            ToGuest::Connected { id } => {
                let (Some(syn), Some(&(_, to))) = (self.held.remove(&id), self.ends.get(&id)) else { return };
                self.early.insert(id, Early::default());
                if self.stack.accept(id, to, syn.clone(), self.ms()).is_err() {
                    if let Some(refused) = packet::reset(&syn) {
                        self.transmit(refused);
                    }
                    self.ask(ToHost::Close { id });
                    self.forget(id);
                }
            }
            ToGuest::Failed { id, errno } => match self.held.remove(&id) {
                Some(syn) => {
                    let answer = match errno {
                        ECONNREFUSED => packet::reset(&syn),
                        EPERM | EACCES => packet::error(&syn, Unreachable::Prohibited),
                        ENETUNREACH => packet::error(&syn, Unreachable::Network),
                        _ => packet::error(&syn, Unreachable::Host),
                    };
                    if let Some(p) = answer {
                        self.transmit(p);
                    }
                    self.forget(id);
                }
                None => {
                    self.stack.abort(id);
                    self.forget(id);
                }
            },
            ToGuest::Data { id, data } => match self.early.get_mut(&id) {
                Some(e) => e.data.extend_from_slice(data),
                None => {
                    self.stack.write(id, data);
                }
            },
            ToGuest::Credit { id, bytes } => self.stack.credit(id, bytes),
            ToGuest::Eof { id } => match self.early.get_mut(&id) {
                Some(e) => e.eof = true,
                None => self.stack.shutdown(id),
            },
            ToGuest::Incoming { id, port, peer, peer_port } => {
                let (guest, peer) = (Endpoint { addr: own(peer), port }, Endpoint { addr: peer, port: peer_port });
                if self.stack.connect(id, peer, guest).is_err() {
                    return self.ask(ToHost::Close { id });
                }
                self.flows.insert((guest, peer), id);
                self.ends.insert(id, (guest, peer));
                self.early.insert(id, Early::default());
            }
            ToGuest::DnsAnswer { id, answer } => {
                let Some(s) = self.sockets.get(&id) else { return };
                let Source::Port(port) = s.source else { return };
                let query = answer.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
                let dns = Endpoint { addr: Addr::V4(link::DNS_V4), port: 53 };
                let server = s.servers.iter().find(|(q, _)| Some(*q) == query).map_or(dns, |(_, e)| *e);
                let p = packet::udp(server, Endpoint { addr: own(server.addr), port }, answer);
                if let Some(p) = p {
                    self.transmit(p);
                }
            }
            ToGuest::UdpVerdict { id, addr, port, verdict } => {
                let Some(s) = self.sockets.get_mut(&id) else { return };
                let to = Endpoint { addr, port };
                let Some(Verdict::Asked(_)) = s.verdicts.get(&to) else { return };
                let now = match verdict {
                    link::UDP_ALLOWED => Some(Verdict::Allowed),
                    link::UDP_REFUSED => Some(Verdict::Refused),
                    // No room for it now: the next one asks again.
                    _ => None,
                };
                let was = match now {
                    Some(v) => s.verdicts.insert(to, v),
                    None => s.verdicts.remove(&to),
                };
                let Some(Verdict::Asked(waiting)) = was else { return };
                self.held_bytes -= waiting.iter().map(Vec::len).sum::<usize>();
                if verdict == link::UDP_ALLOWED {
                    for data in waiting {
                        self.ask(ToHost::UdpSend { id, addr, port, data: &data });
                    }
                }
            }
            ToGuest::UdpRecv { more: 1.., .. } | ToGuest::UdpIncoming { more: 1.., .. } | ToGuest::UdpMore { .. } => {
                if let Some((to, data)) = self.arriving.add(&msg) {
                    self.on_message(to.message(&data));
                }
            }
            ToGuest::UdpRecv { id, addr, port, data, .. } => {
                let Some(s) = self.sockets.get(&id) else { return };
                let p = match s.source {
                    Source::Echo { ident, .. } if port == link::ICMP_PORT && data.len() >= 8 => {
                        // The identifier was the host's socket's.
                        let mut m = data.to_vec();
                        m[4..6].copy_from_slice(&ident.to_be_bytes());
                        packet::echo(addr, own(addr), &m)
                    }
                    Source::Port(guest) if port != link::ICMP_PORT => {
                        packet::udp(Endpoint { addr, port }, Endpoint { addr: own(addr), port: guest }, data)
                    }
                    _ => None,
                };
                if let Some(p) = p {
                    self.transmit(p);
                }
            }
            ToGuest::UdpIncoming { port, peer, peer_port, data, .. } => {
                let peer = Endpoint { addr: peer, port: peer_port };
                if !self.peers.contains(&(port, peer)) {
                    if self.peers.len() >= link::MAX_FORWARD_PEERS {
                        self.peers.pop_front();
                    }
                    self.peers.push_back((port, peer));
                }
                if let Some(p) = packet::udp(peer, Endpoint { addr: own(peer.addr), port }, data) {
                    self.transmit(p);
                }
            }
        }
    }
}

/// What a verdict holds for a guest.
fn held(v: &Verdict) -> usize {
    match v {
        Verdict::Asked(waiting) => waiting.iter().map(Vec::len).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{NetPolicy, tests::policy};
    use grix_netstack::packet::Unreachable;
    use std::net::{TcpListener, UdpSocket};

    const GUEST: Addr = Addr::V4(link::GUEST_V4);

    fn start(p: NetPolicy) -> (Gateway, Arc<Outbox>) {
        let (g, out, _) = started(p);
        (g, out)
    }

    fn started(p: NetPolicy) -> (Gateway, Arc<Outbox>, Arc<Proxy>) {
        let (messages, to_guest) = (Outbox::new(), Outbox::new());
        let proxy = Arc::new(Proxy::start(p, messages.clone(), Arc::new(|_| {})).unwrap());
        (Gateway::start(proxy.clone(), messages, to_guest.clone()).unwrap(), to_guest, proxy)
    }

    /// A panic in the stack, which is a library's, is the end of this
    /// sandbox's network and nothing else, and it's reported.
    #[test]
    fn a_panic_in_the_stack_stays_there() {
        let (gateway, _, proxy) = started(policy(&["127.0.0.1"]));
        gateway.work.send(Work::Panic).unwrap();
        // It still takes what's sent, and it still stops.
        gateway.packet(&[0x45, 0, 0, 20]);
        gateway.stop(false);
        let events = proxy.stop();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, crate::GuestEvent::Denied { detail, .. } if detail.contains("TCP stack"))),
            "{events:?}"
        );
    }

    /// The next packet for the guest, within a few seconds. (By looking, not
    /// with a thread in `next`: one left there when this gives up would take
    /// the next packet to nobody.)
    fn packet_for_guest(out: &Arc<Outbox>) -> Option<Vec<u8>> {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if let Some(f) = out.take() {
                return Some(f[wire::FRAME_HEADER..].to_vec());
            }
            thread::sleep(Duration::from_millis(1));
        }
        None
    }

    /// A SYN, as a guest's stack would send it.
    fn syn(from: Endpoint, to: Endpoint) -> Vec<u8> {
        let mut p = packet::udp(from, to, &[0; 12]).unwrap();
        let header = if matches!(from.addr, Addr::V4(_)) { 20 } else { 40 };
        p[9] = 6;
        let mut t = vec![0; 20];
        t[..4].copy_from_slice(&p[header..header + 4]);
        t[12] = 5 << 4;
        t[13] = 2;
        p.truncate(header);
        p.extend(t);
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[10..12].fill(0);
        let mut sum = 0u32;
        for w in p[..20].chunks(2) {
            sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        let sum = !((sum & 0xffff) + (sum >> 16)) as u16;
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p
    }

    #[test]
    fn what_the_policy_refuses_the_guest_hears() {
        let (g, out) = start(policy(&["example.com"]));
        let (from, to) = (Endpoint { addr: GUEST, port: 40000 }, Endpoint { addr: Addr::V4([192, 0, 2, 1]), port: 80 });
        g.packet(&syn(from, to));
        let answer = packet_for_guest(&out).expect("an answer");
        assert_eq!(packet::parse(&answer), Some(Packet::Error { about: (from, to), why: Unreachable::Prohibited }));
    }

    /// A compromised guest can say it's anyone: nothing that doesn't come
    /// from its own address gets as far as asking the proxy, which would
    /// have a socket make a connection for it.
    #[test]
    fn a_forged_source_goes_nowhere() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let (g, out) = start(policy(&["host.grix.internal"]));
        let host = Addr::V4(link::HOST_V4);
        let forged = Endpoint { addr: Addr::V4([198, 51, 100, 7]), port: 40000 };
        g.packet(&syn(forged, Endpoint { addr: host, port }));
        g.packet(&packet::udp(forged, Endpoint { addr: host, port: udp_port }, b"x").unwrap());
        g.packet(&packet::echo(forged.addr, host, &[8, 0, 0, 0, 0, 1, 0, 1]).unwrap());
        thread::sleep(Duration::from_millis(300));
        assert!(listener.accept().is_err(), "a forged SYN made a connection");
        assert!(udp.recv(&mut [0; 8]).is_err(), "a forged datagram was sent");
        assert!(out.q_is_empty());
        // The same from the guest does get there: that's what was kept out.
        let guest = Endpoint { addr: GUEST, port: 40001 };
        g.packet(&syn(guest, Endpoint { addr: host, port }));
        g.packet(&packet::udp(guest, Endpoint { addr: host, port: udp_port }, b"x").unwrap());
        let started = Instant::now();
        while listener.accept().is_err() {
            assert!(started.elapsed() < Duration::from_secs(5), "the guest's own SYN didn't connect");
            thread::sleep(Duration::from_millis(5));
        }
        while udp.recv(&mut [0; 8]).is_err() {
            assert!(started.elapsed() < Duration::from_secs(5), "the guest's own datagram wasn't sent");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// What a raw socket or a guest's own kernel can put on the link, and
    /// doesn't leave: it stops here, and it's reported.
    #[test]
    fn what_cant_leave_is_said_to_have_stopped() {
        let (g, _out, proxy) = started(policy(&["example.com"]));
        let guest = Addr::V4(link::GUEST_V4);
        let host = Addr::V4([192, 0, 2, 1]);
        g.packet(&packet::raw(guest, host, 253, b"mine").unwrap());
        g.packet(&packet::raw(Addr::V4([198, 51, 100, 7]), host, 17, b"forged").unwrap());
        g.stop(false);
        let events = proxy.stop();
        let said: Vec<String> = events.iter().map(|e| e.to_string()).collect();
        assert_eq!(said.len(), 2, "{said:?}");
        assert!(said[0].contains("IP protocol 253"), "{said:?}");
        assert!(said[1].contains("isn't the sandbox"), "{said:?}");
    }

    /// Datagrams to more destinations than it remembers, each waiting on
    /// the proxy, and garbage of every length: it's still there afterwards.
    #[test]
    fn a_flood_leaves_it_standing() {
        let (g, out) = start(policy(&["example.com"]));
        let from = Endpoint { addr: GUEST, port: 5000 };
        for i in 0..2000u32 {
            let to = Endpoint { addr: Addr::V4([192, 0, 2, (i % 250) as u8]), port: 1000 + (i % 300) as u16 };
            g.packet(&packet::udp(from, to, &[0; 2000]).unwrap());
        }
        let mut seed = 7u32;
        for _ in 0..2000 {
            let mut p = vec![0u8; (seed % 200) as usize];
            for b in p.iter_mut() {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                *b = (seed >> 24) as u8;
            }
            g.packet(&p);
        }
        // The queue may have lost some of that, and a SYN sent once could
        // be lost too: as any stack would, send it again.
        let (from, to) = (Endpoint { addr: GUEST, port: 40000 }, Endpoint { addr: Addr::V4([192, 0, 2, 1]), port: 80 });
        let answer = (0..20).find_map(|_| {
            g.packet(&syn(from, to));
            packet_for_guest(&out)
        });
        assert!(answer.is_some_and(|a| matches!(packet::parse(&a), Some(Packet::Error { .. }))));
    }
}
