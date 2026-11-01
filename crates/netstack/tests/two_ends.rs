//! Two stacks wired back to back, as the guest's and the gateway's are, with
//! nothing else: what the design rests on, before a VM comes into it.
use grix_abi::link::{self, Addr};
use grix_netstack::packet::{self, Unreachable};
use grix_netstack::{Endpoint, Identity, Note, Packet, Stack};

const GUEST: Identity = Identity {
    v4: link::GUEST_V4,
    v6: link::GUEST_V6,
    peer_v4: link::HOST_V4,
    peer_v6: link::HOST_V6,
    any_address: false,
};
const GATEWAY: Identity = Identity {
    v4: link::HOST_V4,
    v6: link::HOST_V6,
    peer_v4: link::GUEST_V4,
    peer_v6: link::GUEST_V6,
    any_address: true,
};

fn v4(a: [u8; 4], port: u16) -> Endpoint {
    Endpoint { addr: Addr::V4(a), port }
}

fn v6(a: [u8; 16], port: u16) -> Endpoint {
    Endpoint { addr: Addr::V6(a), port }
}

#[derive(Debug, Default)]
struct Heard {
    connected: Vec<u32>,
    refused: Vec<u32>,
    reset: Vec<u32>,
    eof: Vec<u32>,
    done: Vec<u32>,
    room: u64,
    data: Vec<u8>,
}

impl Heard {
    fn note(&mut self, n: Note<'_>) {
        match n {
            Note::Connected { id } => self.connected.push(id),
            Note::Refused { id } => self.refused.push(id),
            Note::Reset { id } => self.reset.push(id),
            Note::Eof { id } => self.eof.push(id),
            Note::Room { bytes, .. } => self.room += bytes as u64,
            Note::Done { id } => self.done.push(id),
            Note::Data { data, .. } => self.data.extend_from_slice(data),
        }
    }
}

struct Net {
    guest: Stack,
    gateway: Stack,
    ms: u64,
    heard_guest: Heard,
    heard_gateway: Heard,
    /// Packets the guest sent that no flow took yet, as the gateway holds
    /// a SYN until the proxy has connected.
    syns: Vec<Vec<u8>>,
}

impl Net {
    fn new() -> Net {
        Net {
            guest: Stack::new(&GUEST, 32, link::WINDOW as usize, 1, 0),
            gateway: Stack::new(&GATEWAY, 32, link::WINDOW as usize, 2, 0),
            ms: 0,
            heard_guest: Heard::default(),
            heard_gateway: Heard::default(),
            syns: Vec::new(),
        }
    }

    /// Move things along until nothing moves: `ms` passes each round.
    fn run(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.ms += 5;
            let (now, g, h) = (self.ms, &mut self.heard_guest, &mut self.heard_gateway);
            self.guest.poll(now, |n| g.note(n));
            let mut up = Vec::new();
            self.guest.take_packets(|p| {
                up.push(p.to_vec());
                true
            });
            for p in up {
                match packet::parse(&p) {
                    Some(Packet::Tcp { from, to, syn: true }) if self.gateway.flow(to, from).is_none() => {
                        self.syns.push(p);
                    }
                    Some(Packet::Tcp { .. }) => assert!(self.gateway.receive(p)),
                    other => panic!("{other:?}"),
                }
            }
            self.gateway.poll(now, |n| h.note(n));
            let mut down = Vec::new();
            self.gateway.take_packets(|p| {
                down.push(p.to_vec());
                true
            });
            for p in down {
                assert!(self.guest.receive(p));
            }
        }
    }
}

const DEST: Endpoint = Endpoint { addr: Addr::V4([93, 184, 216, 34]), port: 80 };

/// A connection to an address the gateway doesn't have, as every one is.
fn connected() -> Net {
    let mut n = Net::new();
    n.guest.connect(1, v4(link::GUEST_V4, 40000), DEST).unwrap();
    n.run(2);
    let syn = n.syns.pop().expect("a SYN came out");
    assert_eq!(packet::parse(&syn), Some(Packet::Tcp { from: v4(link::GUEST_V4, 40000), to: DEST, syn: true }));
    // The handshake waits on the gateway: nothing's finished yet.
    assert!(n.heard_guest.connected.is_empty());
    n.gateway.accept(7, DEST, syn, n.ms).unwrap();
    n.run(4);
    assert_eq!(n.heard_guest.connected, [1]);
    assert_eq!(n.heard_gateway.connected, [7]);
    n
}

#[test]
fn a_connection_to_any_address_carries_data_both_ways() {
    let mut n = connected();
    assert_eq!(n.guest.write(1, b"GET / HTTP/1.0\r\n\r\n"), 18);
    assert_eq!(n.gateway.write(7, b"HTTP/1.0 200 OK\r\n\r\n"), 19);
    n.run(8);
    assert_eq!(n.heard_gateway.data, b"GET / HTTP/1.0\r\n\r\n");
    assert_eq!(n.heard_guest.data, b"HTTP/1.0 200 OK\r\n\r\n");
    assert_eq!(n.heard_guest.room, 18);
    assert_eq!(n.heard_gateway.room, 19);
    assert!(n.guest.flushed());
}

#[test]
fn more_than_a_window_gets_through_as_it_is_read() {
    let mut n = connected();
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    let mut sent = 0;
    let mut given = 0;
    for _ in 0..4000 {
        sent += n.guest.write(1, &data[sent..]);
        n.run(1);
        // The reader takes its time: only what it's read gets more credit.
        let read = n.heard_gateway.data.len() as u64;
        if read > given {
            n.gateway.credit(7, (read - given) as u32);
            given = read;
        }
        if n.heard_gateway.data.len() == data.len() {
            break;
        }
    }
    assert_eq!(n.heard_gateway.data.len(), data.len());
    assert!(n.heard_gateway.data == data);
}

#[test]
fn credit_holds_data_back() {
    let mut n = connected();
    let data = vec![7u8; 4 * link::WINDOW as usize];
    let mut sent = 0;
    for _ in 0..200 {
        sent += n.guest.write(1, &data[sent..]);
        n.run(1);
    }
    // One window with the reader, one in each socket, and the last still
    // with the writer.
    assert_eq!(n.heard_gateway.data.len(), link::WINDOW as usize);
    assert!(sent < data.len());
}

/// Smaller sockets than the window: what fits is what's taken, and the
/// rest is the writer's until there's room.
#[test]
fn a_small_buffer_takes_what_fits() {
    let mut n = Net::new();
    n.guest = Stack::new(&GUEST, 32, 1024, 1, 0);
    n.guest.connect(1, v4(link::GUEST_V4, 40000), DEST).unwrap();
    n.run(2);
    let syn = n.syns.pop().unwrap();
    n.gateway.accept(7, DEST, syn, n.ms).unwrap();
    n.run(4);
    assert_eq!(n.guest.write(1, &[1; 5000]), 1024);
    n.run(6);
    assert_eq!(n.heard_gateway.data.len(), 1024);
    assert_eq!(n.heard_guest.room, 1024);
    assert_eq!(n.guest.write(1, &[1; 5000]), 1024);
}

#[test]
fn ends_of_file_each_way() {
    let mut n = connected();
    n.guest.write(1, b"last words");
    n.guest.shutdown(1);
    n.run(6);
    assert_eq!(n.heard_gateway.data, b"last words");
    assert_eq!(n.heard_gateway.eof, [7]);
    assert!(n.heard_guest.eof.is_empty());
    // The other way still works.
    n.gateway.write(7, b"goodbye");
    n.gateway.shutdown(7);
    n.run(6);
    assert_eq!(n.heard_guest.data, b"goodbye");
    assert_eq!(n.heard_guest.eof, [1]);
    // A clean end is no reset, and whoever's on top hears it's over.
    assert!(n.heard_guest.reset.is_empty() && n.heard_gateway.reset.is_empty());
    assert_eq!((&n.heard_guest.done[..], &n.heard_gateway.done[..]), (&[1][..], &[7][..]));
    n.guest.close(1);
    n.gateway.close(7);
    n.run(4);
    assert_eq!((n.guest.in_use(), n.gateway.in_use()), (0, 0));
}

#[test]
fn a_reset_breaks_a_made_connection() {
    let mut n = connected();
    n.gateway.abort(7);
    n.run(4);
    assert_eq!(n.heard_guest.reset, [1]);
    assert!(n.heard_guest.eof.is_empty(), "{:?}", n.heard_guest);
}

#[test]
fn a_reset_to_the_syn_refuses_it() {
    let mut n = Net::new();
    n.guest.connect(1, v4(link::GUEST_V4, 40000), DEST).unwrap();
    n.run(2);
    let syn = n.syns.pop().unwrap();
    assert!(n.guest.receive(packet::reset(&syn).unwrap()));
    n.run(2);
    assert_eq!(n.heard_guest.refused, [1]);
}

#[test]
fn an_icmp_error_names_the_flow_it_is_about() {
    let mut n = Net::new();
    let from = v4(link::GUEST_V4, 40000);
    n.guest.connect(1, from, DEST).unwrap();
    n.run(2);
    let syn = n.syns.pop().unwrap();
    let error = packet::error(&syn, Unreachable::Prohibited).unwrap();
    let Some(Packet::Error { about, why }) = packet::parse(&error) else { panic!() };
    assert_eq!((about, why), ((from, DEST), Unreachable::Prohibited));
    assert_eq!(n.guest.flow(about.0, about.1), Some(1));
}

#[test]
fn ipv6_too() {
    let mut n = Net::new();
    let to = v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7], 443);
    n.guest.connect(1, v6(link::GUEST_V6, 40001), to).unwrap();
    n.run(2);
    let syn = n.syns.pop().unwrap();
    n.gateway.accept(9, to, syn, n.ms).unwrap();
    n.run(4);
    assert_eq!(n.heard_guest.connected, [1]);
    n.guest.write(1, b"six");
    n.run(4);
    assert_eq!(n.heard_gateway.data, b"six");
}

/// The way a forwarded port arrives: the gateway opens it, from wherever
/// the peer really is, and the guest finds a listener for the SYN.
#[test]
fn a_connection_to_the_guest() {
    let mut n = Net::new();
    let (peer, port) = (v4([203, 0, 113, 9], 5555), v4(link::GUEST_V4, 8080));
    n.gateway.connect(3, peer, port).unwrap();
    n.ms += 5;
    n.gateway.poll(n.ms, |_| {});
    let mut syn = None;
    n.gateway.take_packets(|p| {
        syn = Some(p.to_vec());
        true
    });
    let syn = syn.expect("a SYN came out");
    assert_eq!(packet::parse(&syn), Some(Packet::Tcp { from: peer, to: port, syn: true }));
    n.guest.accept(11, port, syn, n.ms).unwrap();
    n.run(4);
    assert_eq!(n.heard_guest.connected, [11]);
    n.guest.write(11, b"served");
    n.run(4);
    assert_eq!(n.heard_gateway.data, b"served");
}

/// Data right behind the handshake's last ACK: whoever's on top has to hear
/// of the connection before its first bytes, or they've nowhere to go.
#[test]
fn nothing_comes_before_connected() {
    let mut n = Net::new();
    let (peer, port) = (v4([203, 0, 113, 9], 5555), v4(link::GUEST_V4, 8080));
    n.gateway.connect(3, peer, port).unwrap();
    n.ms += 5;
    n.gateway.poll(n.ms, |_| {});
    let mut syn = None;
    n.gateway.take_packets(|p| {
        syn = Some(p.to_vec());
        true
    });
    n.guest.accept(11, port, syn.unwrap(), n.ms).unwrap();
    let mut synack = Vec::new();
    n.guest.take_packets(|p| {
        synack.push(p.to_vec());
        true
    });
    n.guest.poll(n.ms, |_| {});
    n.guest.take_packets(|p| {
        synack.push(p.to_vec());
        true
    });
    for p in synack {
        n.gateway.receive(p);
    }
    // The gateway's finished its side, and writes at once.
    n.ms += 5;
    let again = n.gateway.poll(n.ms, |_| {});
    assert!(again);
    n.gateway.write(3, b"first");
    n.gateway.poll(n.ms, |_| {});
    let mut down = Vec::new();
    n.gateway.take_packets(|p| {
        down.push(p.to_vec());
        true
    });
    assert!(down.len() >= 2, "the ACK and the data together");
    for p in down {
        n.guest.receive(p);
    }
    let mut order = Vec::new();
    let again = n.guest.poll(n.ms + 5, |note| order.push(format!("{note:?}")));
    assert!(again && order.iter().all(|o| !o.contains("Data")), "{order:?}");
    assert!(order.iter().any(|o| o.contains("Connected")), "{order:?}");
    let mut data = Vec::new();
    n.guest.poll(n.ms + 5, |note| {
        if let Note::Data { data: d, .. } = note {
            data.extend_from_slice(d);
        }
    });
    assert_eq!(data, b"first");
}

#[test]
fn slots_run_out_cleanly() {
    let mut n = Net::new();
    for i in 0..32 {
        n.guest.connect(i, v4(link::GUEST_V4, 40000 + i as u16), DEST).unwrap();
    }
    assert!(n.guest.connect(99, v4(link::GUEST_V4, 41000), DEST).is_err());
    n.guest.close(0);
    n.run(2);
    assert_eq!(n.guest.in_use(), 31);
    assert!(n.guest.connect(99, v4(link::GUEST_V4, 41000), DEST).is_ok());
}

#[test]
fn udp_and_echoes_are_what_they_say() {
    let (a, b) = (v4(link::GUEST_V4, 5353), v4([1, 1, 1, 1], 53));
    let p = packet::udp(a, b, b"query").unwrap();
    assert_eq!(packet::parse(&p), Some(Packet::Udp { from: a, to: b, data: b"query" }));
    let (a, b) = (v6(link::GUEST_V6, 5353), v6(link::HOST_V6, 53));
    let p = packet::udp(a, b, b"six").unwrap();
    assert_eq!(packet::parse(&p), Some(Packet::Udp { from: a, to: b, data: b"six" }));
    // A corrupted one is no packet at all.
    let mut bad = p.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(packet::parse(&bad), None);
    let m = [8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p'];
    let (from, to) = (Addr::V4(link::GUEST_V4), Addr::V4([1, 1, 1, 1]));
    let p = packet::echo(from, to, &m).unwrap();
    let Some(Packet::Echo { from: f, to: t, request: true, message }) = packet::parse(&p) else { panic!() };
    assert_eq!((f, t, &message[4..]), (from, to, &m[4..]));
    let m = [129, 0, 0, 0, 0x12, 0x34, 0, 1];
    let (from, to) = (Addr::V6(link::HOST_V6), Addr::V6(link::GUEST_V6));
    let p = packet::echo(from, to, &m).unwrap();
    assert!(matches!(packet::parse(&p), Some(Packet::Echo { request: false, .. })));
    // Too much for the link, and mixed families.
    assert_eq!(packet::udp(a, a, &vec![0; link::MTU]), None);
    assert_eq!(packet::udp(a, v4([1, 1, 1, 1], 1), b""), None);
}

#[test]
fn garbage_is_nothing() {
    // Every length of a good packet cut short, and each byte of it wrong:
    // whatever it is, it doesn't panic.
    let p = packet::udp(v4(link::GUEST_V4, 1), v4([1, 1, 1, 1], 2), b"some data here").unwrap();
    for n in 0..p.len() {
        let _ = packet::parse(&p[..n]);
    }
    for i in 0..p.len() {
        for x in [0x00, 0x01, 0x40, 0x60, 0x80, 0xff] {
            let mut q = p.clone();
            q[i] ^= x;
            let _ = packet::parse(&q);
            let _ = packet::error(&q, Unreachable::Host);
            let _ = packet::reset(&q);
        }
    }
    let mut seed = 0x1234_5678u32;
    for _ in 0..20_000 {
        let mut q = vec![0u8; (seed % 80) as usize];
        for b in q.iter_mut() {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (seed >> 24) as u8;
        }
        let _ = packet::parse(&q);
        let _ = packet::error(&q, Unreachable::Network);
        let _ = packet::reset(&q);
    }
}
