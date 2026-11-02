//! Socket options, as an AF_INET socket keeps them: what's set reads back
//! with Linux's defaults and checks, on either network stack. Most change
//! nothing here: on `native` the connection is the host's, and on `vm` only
//! some mean anything to the stack (`netstack::configure`). Saying so is what
//! a program gets: it isn't told an option took that it can't read back.

use crate::errno::*;

pub const ENOPROTOOPT: Errno = Errno(92);

pub const SOL_SOCKET: u64 = 1;
pub const IPPROTO_IP: u64 = 0;
pub const IPPROTO_TCP: u64 = 6;
pub const IPPROTO_UDP: u64 = 17;
pub const IPPROTO_IPV6: u64 = 41;

const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_PRIORITY: u64 = 12;
pub const SO_LINGER: u64 = 13;
pub const TCP_NODELAY: u64 = 1;
pub const TCP_MAXSEG: u64 = 2;
const TCP_KEEPIDLE: u64 = 4;
const TCP_KEEPINTVL: u64 = 5;
const TCP_KEEPCNT: u64 = 6;
const TCP_SYNCNT: u64 = 7;
const TCP_LINGER2: u64 = 8;
pub const TCP_INFO: u64 = 11;
const TCP_QUICKACK: u64 = 12;
pub const TCP_CONGESTION: u64 = 13;
const IP_TOS: u64 = 1;
pub const IP_TTL: u64 = 2;
pub const IPV6_UNICAST_HOPS: u64 = 16;
const IPV6_TCLASS: u64 = 67;

/// Linux's net.core.[rw]mem_max and what it keeps at least.
const BUF_MAX: i32 = 212_992;
const RCVBUF_MIN: i32 = 2304;
const SNDBUF_MIN: i32 = 4608;
const TCP_RCVBUF: i32 = 131_072;
const TCP_SNDBUF: i32 = 16_384;
/// The default TTL and hop limit, as a process sees them.
pub const DEFAULT_HOPS: i32 = 64;
const TCP_KEEP_MAX: i32 = 32767;
const TCP_KEEPCNT_MAX: i32 = 127;

/// Options set at once on a socket. Fixed, so a program with many sockets
/// makes no more of the kernel's heap for this than it does for sockets.
const MAX_SET: usize = 16;

#[derive(Clone, Copy)]
pub struct Opts {
    set: [(u64, u64, i32); MAX_SET],
    used: usize,
    linger: (i32, i32),
}

impl Default for Opts {
    fn default() -> Self {
        Opts { set: [(0, 0, 0); MAX_SET], used: 0, linger: (0, 0) }
    }
}

/// What an option is.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// On or off: any true value reads back as 1.
    Flag,
    /// A number between these, with this default.
    Number(i32, i32, i32),
    /// A TTL or hop limit: -1 is the default again.
    Hops(i32),
    /// A buffer's size, kept doubled.
    Buffer(i32),
}

/// What `name` at `level` is for a socket like this. None: nothing Linux
/// has, or nothing for this kind of socket.
fn kind(level: u64, name: u64, dgram: bool, v6: bool) -> Option<Kind> {
    use Kind::*;
    let tcp = !dgram;
    Some(match (level, name) {
        (SOL_SOCKET, SO_SNDBUF) => Buffer(SNDBUF_MIN),
        (SOL_SOCKET, SO_RCVBUF) => Buffer(RCVBUF_MIN),
        (SOL_SOCKET, SO_PRIORITY) => Number(0, 0, 6),
        // SO_DEBUG, REUSEADDR, DONTROUTE, BROADCAST, KEEPALIVE, OOBINLINE,
        // NO_CHECK, REUSEPORT, and the ways to ask for timestamps and more
        // about a message.
        (SOL_SOCKET, 1 | 2 | 5 | 6 | 9 | 10 | 11 | 15 | 29 | 35 | 40 | 41 | 46 | 47 | 60 | 63 | 64) => Flag,
        // BSDCOMPAT, MARK, BUSY_POLL, INCOMING_CPU, ZEROCOPY and others that
        // are a number, stored.
        (SOL_SOCKET, 14 | 18 | 19 | 36 | 37 | 42 | 43 | 44 | 45 | 48 | 49 | 50 | 51 | 52 | 56 | 58 | 69) => {
            Number(0, i32::MIN, i32::MAX)
        }
        (IPPROTO_TCP, TCP_NODELAY) if tcp => Flag,
        (IPPROTO_TCP, TCP_KEEPIDLE) if tcp => Number(7200, 1, TCP_KEEP_MAX),
        (IPPROTO_TCP, TCP_KEEPINTVL) if tcp => Number(75, 1, TCP_KEEP_MAX),
        (IPPROTO_TCP, TCP_KEEPCNT) if tcp => Number(9, 1, TCP_KEEPCNT_MAX),
        (IPPROTO_TCP, TCP_SYNCNT) if tcp => Number(6, 1, 255),
        (IPPROTO_TCP, TCP_LINGER2) if tcp => Number(60, -1, i32::MAX),
        (IPPROTO_TCP, TCP_QUICKACK) if tcp => Number(1, 0, 1),
        // TCP_CORK, and those that are flags.
        (IPPROTO_TCP, 3 | 14 | 19 | 24 | 26 | 27 | 28 | 30 | 33 | 35 | 36 | 37) if tcp => Flag,
        // DEFER_ACCEPT, WINDOW_CLAMP, USER_TIMEOUT, FASTOPEN, NOTSENT_LOWAT.
        (IPPROTO_TCP, 9 | 10 | 18 | 23 | 25) if tcp => Number(0, 0, i32::MAX),
        (IPPROTO_UDP, 1 | 100 | 102 | 104) if dgram => Flag,
        (IPPROTO_UDP, 103) if dgram => Number(0, 0, 65535),
        (IPPROTO_IP, IP_TOS) => Number(0, 0, 255),
        (IPPROTO_IP, IP_TTL) => Hops(1),
        // Flags for what comes with a message or how it's sent.
        (IPPROTO_IP, 3 | 4 | 6 | 7 | 8 | 11 | 12 | 13 | 15 | 18 | 24 | 49) => Flag,
        // IP_MTU_DISCOVER, IP_MULTICAST_TTL and LOOP.
        (IPPROTO_IP, 10) => Number(1, 0, 5),
        (IPPROTO_IP, 33) => Number(1, 0, 255),
        (IPPROTO_IP, 34) => Flag,
        (IPPROTO_IPV6, IPV6_UNICAST_HOPS) if v6 => Hops(0),
        (IPPROTO_IPV6, IPV6_TCLASS) if v6 => Number(0, -1, 255),
        (IPPROTO_IPV6, 18 | 19) if v6 => Number(1, -1, 255),
        // RECVERR, RECVPKTINFO and the rest that ask for more with a message.
        (IPPROTO_IPV6, 25 | 49 | 51 | 53 | 55 | 58 | 66 | 74 | 76) if v6 => Flag,
        (IPPROTO_IPV6, 23) if v6 => Number(1, 0, 5),
        _ => return None,
    })
}

impl Opts {
    fn stored(&self, level: u64, name: u64) -> Option<i32> {
        self.set[..self.used].iter().find(|(l, n, _)| (*l, *n) == (level, name)).map(|e| e.2)
    }

    fn store(&mut self, level: u64, name: u64, value: i32) -> Result<(), Errno> {
        if let Some(e) = self.set[..self.used].iter_mut().find(|(l, n, _)| (*l, *n) == (level, name)) {
            e.2 = value;
            return Ok(());
        }
        if self.used == MAX_SET {
            return Err(ENOBUFS);
        }
        self.set[self.used] = (level, name, value);
        self.used += 1;
        Ok(())
    }

    /// `setsockopt` of an int-sized option.
    pub fn set(&mut self, level: u64, name: u64, value: i32, dgram: bool, v6: bool) -> Result<(), Errno> {
        let k = kind(level, name, dgram, v6).ok_or(ENOPROTOOPT)?;
        let value = match k {
            Kind::Flag => (value != 0) as i32,
            Kind::Number(_, min, max) if !(min..=max).contains(&value) => return Err(EINVAL),
            Kind::Number(..) => value,
            Kind::Hops(_) if value == -1 => DEFAULT_HOPS,
            Kind::Hops(min) if !(min..=255).contains(&value) => return Err(EINVAL),
            Kind::Hops(_) => value,
            Kind::Buffer(least) => value.clamp(0, BUF_MAX).saturating_mul(2).max(least),
        };
        self.store(level, name, value)
    }

    /// `getsockopt` of an int-sized option.
    pub fn get(&self, level: u64, name: u64, dgram: bool, v6: bool) -> Result<i32, Errno> {
        let k = kind(level, name, dgram, v6).ok_or(ENOPROTOOPT)?;
        Ok(self.stored(level, name).unwrap_or(match k {
            Kind::Flag => 0,
            Kind::Number(default, ..) => default,
            Kind::Hops(_) => DEFAULT_HOPS,
            Kind::Buffer(SNDBUF_MIN) if dgram => BUF_MAX,
            Kind::Buffer(_) if dgram => BUF_MAX,
            Kind::Buffer(SNDBUF_MIN) => TCP_SNDBUF,
            Kind::Buffer(_) => TCP_RCVBUF,
        }))
    }

    pub fn set_linger(&mut self, on: i32, seconds: i32) {
        self.linger = (on, seconds);
    }

    pub fn linger(&self) -> (i32, i32) {
        self.linger
    }

    /// The TTL or hop limit asked for.
    pub fn hop_limit(&self, v6: bool) -> Option<u8> {
        let (level, name) = if v6 { (IPPROTO_IPV6, IPV6_UNICAST_HOPS) } else { (IPPROTO_IP, IP_TTL) };
        self.stored(level, name).filter(|&h| h != DEFAULT_HOPS).map(|h| h as u8)
    }

    /// Seconds between keepalives, if they're on.
    pub fn keepalive(&self) -> Option<u32> {
        (self.stored(SOL_SOCKET, SO_KEEPALIVE).unwrap_or(0) != 0)
            .then(|| self.stored(IPPROTO_TCP, TCP_KEEPIDLE).unwrap_or(7200) as u32)
    }
}

/// `struct tcp_info`, the part of it there's anything to say in. Linux's
/// grew over time and whoever reads it asks for what it knows.
pub const TCP_INFO_BYTES: usize = 104;

/// Linux's TCP_ESTABLISHED and the rest.
pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_SYN_SENT: u8 = 2;
pub const TCP_FIN_WAIT1: u8 = 4;
pub const TCP_FIN_WAIT2: u8 = 5;
pub const TCP_CLOSE: u8 = 7;
pub const TCP_CLOSE_WAIT: u8 = 8;
pub const TCP_LAST_ACK: u8 = 9;
pub const TCP_LISTEN: u8 = 10;

/// TCP_INFO for a connection in `state`, sending segments of `mss`.
pub fn tcp_info(state: u8, mss: u32, unacked: u32) -> [u8; TCP_INFO_BYTES] {
    const RTO_US: u32 = 200_000;
    let mut b = [0u8; TCP_INFO_BYTES];
    b[0] = state;
    let mut put = |at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put(8, RTO_US);
    put(16, mss);
    put(20, mss);
    put(24, unacked);
    b
}
