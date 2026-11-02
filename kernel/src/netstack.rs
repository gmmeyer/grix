//! The `vm` network stack's end in the guest: sockets on TCP/IP here
//! (`grix_netstack`) in place of the host's proxy, with IP packets on the
//! console. `inet` keeps its sockets as they are, and this takes what it
//! would tell the host and answers what the host would.
//!
//! Nothing here decides what's allowed: the gateway at the other end asks
//! the proxy, as the `native` stack's messages do.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use grix_abi::link::{self, Addr, ToGuest, ToHost};
use grix_abi::wire::Channel;
use grix_netstack::packet::{self, Unreachable};
use grix_netstack::{Endpoint, Identity, Note, Packet, Stack};
use spin::Mutex;

use crate::inet::{self, SockAddr};
use crate::kmem::Charge;
use crate::{console, ipc, sched, time};

/// Sockets at once. Their slots are made up front, which is what a socket
/// set wants if it's never to grow, and costs only those who ask for this
/// stack. `inet::MAX_CONNS` and `kmem` come first for most programs.
const FLOWS: usize = 1024;
/// Bytes in each of a socket's two buffers, which is what limits how many
/// `kmem` can pay for. Less than `link::WINDOW`: `inet::Conn` holds what's
/// read anyway, and at this link's round trip a window this size is plenty.
pub const BUFFER: usize = 16 * 1024;
const FLOW_BYTES: usize = 2 * BUFFER;
/// How long the program's end waits for what it wrote to be acknowledged.
const FLUSH_NS: u64 = 2_000_000_000;

const ECONNREFUSED: u16 = 111;
const ECONNRESET: u16 = 104;
const ENOBUFS: u16 = 105;
const EPERM: u16 = 1;
const EHOSTUNREACH: u16 = 113;
const ENETUNREACH: u16 = 101;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static STACK: Mutex<Option<Guest>> = Mutex::new(None);
/// Something for `service` to do: it's looked at on every I/O change, most
/// of them nothing to do with this.
static WORK: AtomicBool = AtomicBool::new(false);
/// The console had no room for a packet.
static BACKED_UP: AtomicBool = AtomicBool::new(false);
/// When it's wanted next if nothing happens (ns; 0: never).
static NEXT: AtomicU64 = AtomicU64::new(0);
static SOCKETS: AtomicUsize = AtomicUsize::new(0);
static NEXT_INCOMING: AtomicU32 = AtomicU32::new(1);

struct Guest {
    stack: Stack,
    /// What `stack`'s sockets take from `kmem`.
    charge: Charge,
    /// Connections from outside, until they're made and `inet` can have
    /// them: their local port and peer.
    accepted: BTreeMap<u32, (u16, SockAddr)>,
    /// Fragments from the gateway, and what tells this end's apart.
    reassembly: packet::Reassembly,
    next_ip_id: u32,
    /// What can't be said with `STACK` held, as it may send something back.
    later: Vec<ToGuest<'static>>,
    /// Handshakes from outside that came to nothing: no `Conn` holds them,
    /// so nothing else closes them.
    failed: Vec<u32>,
}

fn now_ms() -> u64 {
    time::monotonic_ns() / 1_000_000
}

fn endpoint(a: SockAddr) -> Endpoint {
    Endpoint { addr: a.addr, port: a.port }
}

fn sockaddr(e: Endpoint) -> SockAddr {
    SockAddr { addr: e.addr, port: e.port }
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Sockets still going: what a snapshot can't carry, as the gateway's ends
/// don't come with it.
pub fn sockets() -> usize {
    SOCKETS.load(Ordering::Relaxed)
}

pub fn init() {
    let mut seed = [0; 8];
    crate::rng::fill(&mut seed);
    let identity = Identity {
        v4: link::GUEST_V4,
        v6: link::GUEST_V6,
        peer_v4: link::HOST_V4,
        peer_v6: link::HOST_V6,
        any_address: false,
    };
    let stack = Stack::new(&identity, FLOWS, BUFFER, u64::from_le_bytes(seed), now_ms());
    *STACK.lock() = Some(Guest {
        stack,
        charge: Charge::default(),
        accepted: BTreeMap::new(),
        reassembly: packet::Reassembly::default(),
        next_ip_id: 0,
        later: Vec::new(),
        failed: Vec::new(),
    });
    ACTIVE.store(true, Ordering::Relaxed);
}

/// There's something to do: `service` runs before anyone decides what can
/// run next, as for anything else that moves I/O.
fn poke() {
    WORK.store(true, Ordering::Relaxed);
    ipc::changed();
}

impl Guest {
    /// Pay for one more socket.
    fn room(&mut self) -> bool {
        self.charge.resize((self.stack.in_use() + 1) as u64 * FLOW_BYTES as u64).is_ok()
    }

    /// True if it's to be called again, once `later` is seen to.
    fn poll(&mut self) -> bool {
        let Guest { stack, accepted, later, failed, .. } = self;
        let again = stack.poll(now_ms(), |note| match note {
            // (Only this goes at once: what's read could otherwise pile up
            // here, and it sends nothing back.)
            Note::Data { id, data } => inet::deliver(ToGuest::Data { id, data }),
            Note::Connected { id } => later.push(match accepted.remove(&id) {
                Some((port, peer)) => ToGuest::Incoming { id, port, peer: peer.addr, peer_port: peer.port },
                None => ToGuest::Connected { id },
            }),
            Note::Refused { id } if accepted.remove(&id).is_some() => failed.push(id),
            Note::Refused { id } => later.push(ToGuest::Failed { id, errno: ECONNREFUSED }),
            Note::Reset { id } => later.push(ToGuest::Failed { id, errno: ECONNRESET }),
            Note::Eof { id } => later.push(ToGuest::Eof { id }),
            Note::Room { id, bytes } => later.push(ToGuest::Credit { id, bytes }),
            Note::Done { .. } => {}
        });
        for id in failed.drain(..) {
            stack.close(id);
        }
        again
    }
}

/// What `inet` would tell the host about a connection. (It may hold the
/// connection's lock: everything that answers waits for `service`.)
pub fn handle(msg: ToHost) {
    let mut guard = STACK.lock();
    let Some(g) = guard.as_mut() else { return };
    match msg {
        ToHost::Data { id, data } => {
            g.stack.write(id, data);
        }
        ToHost::Credit { id, bytes } => g.stack.credit(id, bytes),
        ToHost::Shutdown { id } => g.stack.shutdown(id),
        ToHost::Close { id } => g.stack.close(id),
        _ => return,
    }
    drop(guard);
    poke();
}

/// Connection `id` from `local` to `peer`.
pub fn connect(id: u32, local: SockAddr, peer: SockAddr) {
    let mut guard = STACK.lock();
    let Some(g) = guard.as_mut() else { return };
    if !g.room() || g.stack.connect(id, endpoint(local), endpoint(peer)).is_err() {
        g.later.push(ToGuest::Failed { id, errno: ENOBUFS });
    }
    drop(guard);
    poke();
}

/// What of a socket's options mean anything to connection `id`.
pub fn configure(id: u32, hop_limit: Option<u8>, keepalive_secs: Option<u32>) {
    if let Some(g) = STACK.lock().as_mut() {
        g.stack.configure(id, hop_limit, keepalive_secs);
    }
    poke();
}

fn own(to: Addr) -> Addr {
    if matches!(to, Addr::V6(_)) { Addr::V6(link::GUEST_V6) } else { Addr::V4(link::GUEST_V4) }
}

fn transmit(p: Option<Vec<u8>>) {
    let mut guard = STACK.lock();
    let (Some(g), Some(p)) = (guard.as_mut(), p) else { return };
    g.next_ip_id = g.next_ip_id.wrapping_add(1);
    // No room: lost, as on any link.
    for piece in packet::fragments(p, g.next_ip_id).unwrap_or_default() {
        g.stack.transmit(piece);
    }
    drop(guard);
    poke();
}

/// A UDP datagram from port `port` here to `to`.
pub fn datagram(port: u16, to: SockAddr, data: &[u8]) {
    let from = Endpoint { addr: own(to.addr), port };
    transmit(packet::udp(from, endpoint(to), data));
}

/// The ICMP echo request `message` to `to`.
pub fn echo(to: Addr, message: &[u8]) {
    transmit(packet::echo(own(to), to, message));
}

/// A raw socket's packet, ready to go: to the guest's own raw sockets (and
/// a UDP one, as it's a datagram) if that's where it's for, and otherwise
/// out, where the gateway has the last word on it.
pub fn raw_out(p: Vec<u8>) {
    let Some((_, _, to, _)) = packet::header(&p) else { return };
    if !(SockAddr { addr: to, port: 0 }).is_local() {
        return transmit(Some(p));
    }
    inet::raw_in(&p);
    if let Some(Packet::Udp { from, to, data }) = packet::parse(&p) {
        inet::deliver_local(sockaddr(from), sockaddr(to), data);
    }
}

/// A packet from the host.
pub fn received(p: Vec<u8>) {
    let whole = STACK.lock().as_mut().and_then(|g| g.reassembly.add(p));
    let Some(p) = whole else { return };
    inet::raw_in(&p);
    match packet::parse(&p) {
        Some(Packet::Tcp { from, to, syn }) => {
            let listening = syn && inet::listening(sockaddr(to));
            let mut guard = STACK.lock();
            let Some(g) = guard.as_mut() else { return };
            if listening && g.stack.flow(to, from).is_none() {
                let id = NEXT_INCOMING.fetch_add(1, Ordering::Relaxed) | link::HOST_ID;
                if g.room() && g.stack.accept(id, to, p.clone(), now_ms()).is_ok() {
                    g.accepted.insert(id, (to.port, sockaddr(from)));
                }
            } else {
                g.stack.receive(p);
            }
            drop(guard);
            poke();
        }
        Some(Packet::Udp { from, to, data }) => inet::datagram_in(sockaddr(from), to.port, data),
        Some(Packet::Echo { from, request: false, message, .. }) if message.len() >= 8 => {
            inet::echo_in(from, u16::from_be_bytes([message[4], message[5]]), message);
        }
        // What the gateway says of a connection it couldn't make: a refusal
        // that isn't a reset, so the program hears why.
        Some(Packet::Error { about: (from, to), why }) => {
            let mut guard = STACK.lock();
            let Some(g) = guard.as_mut() else { return };
            if let Some(id) = g.stack.flow(from, to) {
                let errno = match why {
                    Unreachable::Prohibited => EPERM,
                    Unreachable::Host => EHOSTUNREACH,
                    Unreachable::Network => ENETUNREACH,
                };
                g.later.push(ToGuest::Failed { id, errno });
                g.stack.abort(id);
            }
            drop(guard);
            poke();
        }
        _ => {}
    }
}

/// Move the stack on, if there's a reason to. From `sched::poll`, so
/// nobody decides what can run until what the network brought is seen.
pub fn service() {
    if !active() {
        return;
    }
    let due = NEXT.load(Ordering::Relaxed);
    let late = due != 0 && time::monotonic_ns() >= due;
    if !WORK.swap(false, Ordering::Relaxed) && !late && !BACKED_UP.load(Ordering::Relaxed) {
        return;
    }
    let next = loop {
        let mut guard = STACK.lock();
        let Some(g) = guard.as_mut() else { return };
        let again = g.poll();
        let mut room = true;
        g.stack.take_packets(|p| {
            room = console::try_write(Channel::Packet, p);
            room
        });
        BACKED_UP.store(!room, Ordering::Relaxed);
        let now = now_ms();
        let next = g.stack.next_poll(now);
        let used = g.stack.in_use();
        SOCKETS.store(used, Ordering::Relaxed);
        // (Smaller always fits.)
        let _ = g.charge.resize(used as u64 * FLOW_BYTES as u64);
        let later = core::mem::take(&mut g.later);
        drop(guard);
        let quiet = later.is_empty();
        for msg in later {
            inet::deliver(msg);
        }
        if quiet && !again && !WORK.swap(false, Ordering::Relaxed) {
            break next;
        }
    };
    let next = next.map_or(0, |ms| ms.saturating_mul(1_000_000));
    NEXT.store(next, Ordering::Relaxed);
    if next != 0 {
        // Nobody may sleep past it: `sched::EARLIEST` is no later than this.
        sched::deadline_at(next);
        sched::timer_changed();
    }
}

/// When `service` wants to run if nothing happens.
pub fn deadline() -> Option<u64> {
    Some(NEXT.load(Ordering::Relaxed)).filter(|&d| d != 0)
}

/// The program has ended, and the machine's about to. Whatever it wrote
/// that the gateway hasn't acknowledged goes before that, as it would have
/// gone out on Linux after its end. With interrupts masked: nothing else
/// is going to bring the acknowledgements.
pub fn flush() {
    if !active() {
        return;
    }
    let end = time::monotonic_ns() + FLUSH_NS;
    while time::monotonic_ns() < end {
        console::pump();
        WORK.store(true, Ordering::Relaxed);
        service();
        if STACK.lock().as_ref().is_none_or(|g| g.stack.flushed()) {
            return;
        }
        core::hint::spin_loop();
    }
}
