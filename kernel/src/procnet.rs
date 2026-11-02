//! /proc/net's socket tables, in Linux's layouts: netstat, lsof and psutil
//! read them by column. A socket's inode there is fstat's, and it's how
//! they get from a connection to a process (`socket:[N]` in /proc/<pid>/fd).
//! What Linux keeps and this has no use for, timers, retransmits and
//! pointers, is a constant. A connection whose socket has closed goes at
//! once: nothing is left to linger in TIME_WAIT.

use alloc::format;
use alloc::string::String;
use core::fmt::Write;
use grix_abi::link::Addr;

use crate::errno::{ENOMEM, Errno};
use crate::inet::{self, Dgram, DgramRow, SockAddr, TcpRow};
use crate::sockopt::{TCP_CLOSE, TCP_ESTABLISHED, TCP_LISTEN};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
    Raw,
    Raw6,
    Icmp,
    Icmp6,
    Unix,
    Sockstat,
    Sockstat6,
}

const COLUMNS: &str = "st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
const NAMES_V4: &str = "local_address rem_address  ";
const NAMES_V6: &str = "local_address                         remote_address                       ";
/// Linux pads a line of these out to a fixed length (`seq_pad`).
const TCP_LINE: usize = 149;
const DGRAM_LINE: usize = 127;
/// The longest line of any table, name aside.
const LINE: usize = 200;

/// `s` has room for another line, or the read fails: there can be as many
/// as sockets, which a program decides.
fn room(s: &mut String) -> Result<(), Errno> {
    s.try_reserve(LINE).map_err(|_| ENOMEM)
}

fn pad(s: &mut String, start: usize, width: usize) {
    while s.len() - start < width {
        s.push(' ');
    }
    s.push('\n');
}

/// An address as Linux prints one: each 32-bit word as a number, so its
/// bytes come out backwards on a little-endian machine. An AF_INET6
/// socket's IPv4 address is a mapped one.
fn address(s: &mut String, a: SockAddr, v6: bool) {
    let words = |s: &mut String, b: &[u8]| {
        for w in b.as_chunks::<4>().0 {
            let _ = write!(s, "{:08X}", u32::from_le_bytes(*w));
        }
    };
    match a.addr {
        _ if v6 && a.is_unspecified() => words(s, &[0; 16]),
        Addr::V4(b) if v6 => {
            words(s, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
            words(s, &b);
        }
        Addr::V4(b) => words(s, &b),
        Addr::V6(b) => words(s, &b),
    }
    let _ = write!(s, ":{:04X}", a.port);
}

fn tcp(s: &mut String, sl: usize, r: &TcpRow) {
    let start = s.len();
    let _ = write!(s, "{sl:4}: ");
    address(s, r.local, r.sock.v6);
    s.push(' ');
    address(s, r.peer, r.sock.v6);
    let (refs, rto, ato, ssthresh) = if r.state == TCP_LISTEN { (1, 100, 0, 0) } else { (2, 20, 4, -1) };
    let _ = write!(
        s,
        " {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {} {refs} {:016x} {rto} {ato} 0 10 {ssthresh}",
        r.state, r.tx, r.rx, r.sock.uid, 0, r.sock.ino, 0
    );
    if r.sock.v6 {
        s.push('\n');
    } else {
        pad(s, start, TCP_LINE);
    }
}

fn dgram(s: &mut String, sl: usize, r: &DgramRow, width: usize) {
    let start = s.len();
    let _ = write!(s, "{sl:width$}: ", width = if r.kind == Dgram::Raw { 4 } else { 5 });
    address(s, r.local, r.sock.v6);
    s.push(' ');
    address(s, r.peer.unwrap_or(SockAddr::UNSPECIFIED_V4), r.sock.v6);
    let state = if r.peer.is_some() { TCP_ESTABLISHED } else { TCP_CLOSE };
    let _ = write!(
        s,
        " {state:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {} 2 {:016x} 0",
        0, r.rx, r.sock.uid, 0, r.sock.ino, 0
    );
    if r.sock.v6 || r.kind == Dgram::Raw {
        s.push('\n');
    } else {
        pad(s, start, width);
    }
}

fn tcp_table(s: &mut String, v6: bool) -> Result<(), Errno> {
    let start = s.len();
    let names = if v6 { NAMES_V6 } else { NAMES_V4 };
    let _ = write!(s, "  sl  {names} {COLUMNS}");
    if v6 {
        s.push('\n');
    } else {
        pad(s, start, TCP_LINE);
    }
    let mut sl = 0;
    inet::each_tcp(|r| {
        if r.sock.v6 == v6 {
            room(s)?;
            tcp(s, sl, &r);
            sl += 1;
        }
        Ok(())
    })
}

fn dgram_table(s: &mut String, kind: Dgram, v6: bool) -> Result<(), Errno> {
    let start = s.len();
    let names = if v6 { NAMES_V6 } else { NAMES_V4 };
    // UDP's has a space more than the rest, and raw's isn't padded.
    let sl = if kind == Dgram::Udp && !v6 { "   sl" } else { "  sl" };
    let _ = write!(s, "{sl}  {names} {COLUMNS} ref pointer drops");
    if v6 || kind == Dgram::Raw {
        s.push('\n');
    } else {
        pad(s, start, DGRAM_LINE);
    }
    let mut sl = 0;
    inet::each_dgram(|r| {
        if r.sock.v6 == v6 && r.kind == kind {
            room(s)?;
            dgram(s, sl, &r, DGRAM_LINE);
            sl += 1;
        }
        Ok(())
    })
}

fn unix_table(s: &mut String) -> Result<(), Errno> {
    const ACCEPTCON: u32 = 1 << 16;
    const UNCONNECTED: u32 = 1;
    const CONNECTED: u32 = 3;
    s.push_str("Num       RefCount Protocol Flags    Type St Inode Path\n");
    crate::unix::each_named(|ino, ty, listening, connected, name| {
        room(s)?;
        s.try_reserve(name.len()).map_err(|_| ENOMEM)?;
        let flags = if listening { ACCEPTCON } else { 0 };
        let st = if connected { CONNECTED } else { UNCONNECTED };
        let _ = writeln!(s, "{:016x}: 00000002 00000000 {flags:08X} {ty:04X} {st:02X} {ino:5} {name}", 0);
        Ok(())
    })
}

/// How many sockets of each kind are in use: (TCP, UDP, raw) for each
/// family, and all of them. Linux's own count takes in sockets nothing has
/// bound; these are the ones in its tables.
fn counts() -> Result<([u32; 3], [u32; 3], u32), Errno> {
    let (mut v4, mut v6) = ([0; 3], [0; 3]);
    let family = |v4: &'_ mut [u32; 3], v6: &'_ mut [u32; 3], is_v6: bool, kind: usize| {
        if is_v6 {
            v6[kind] += 1;
        } else {
            v4[kind] += 1;
        }
    };
    inet::each_tcp(|r| {
        family(&mut v4, &mut v6, r.sock.v6, 0);
        Ok(())
    })?;
    inet::each_dgram(|r| {
        if r.kind != Dgram::Icmp {
            family(&mut v4, &mut v6, r.sock.v6, if r.kind == Dgram::Udp { 1 } else { 2 });
        }
        Ok(())
    })?;
    let mut unix = 0;
    crate::unix::each_named(|_, _, _, _, _| {
        unix += 1;
        Ok(())
    })?;
    let all = v4.iter().chain(&v6).sum::<u32>() + unix;
    Ok((v4, v6, all))
}

fn sockstat(s: &mut String) -> Result<(), Errno> {
    let ([tcp, udp, raw], _, all) = counts()?;
    s.push_str(&format!(
        "sockets: used {all}\nTCP: inuse {tcp} orphan 0 tw 0 alloc {tcp} mem 0\nUDP: inuse {udp} mem 0\n\
         UDPLITE: inuse 0\nRAW: inuse {raw}\nFRAG: inuse 0 memory 0\n"
    ));
    Ok(())
}

fn sockstat6(s: &mut String) -> Result<(), Errno> {
    let (_, [tcp, udp, raw], _) = counts()?;
    s.push_str(&format!(
        "TCP6: inuse {tcp}\nUDP6: inuse {udp}\nUDPLITE6: inuse 0\nRAW6: inuse {raw}\nFRAG6: inuse 0 memory 0\n"
    ));
    Ok(())
}

pub fn generate(table: Table, s: &mut String) -> Result<(), Errno> {
    match table {
        Table::Tcp => tcp_table(s, false),
        Table::Tcp6 => tcp_table(s, true),
        Table::Udp => dgram_table(s, Dgram::Udp, false),
        Table::Udp6 => dgram_table(s, Dgram::Udp, true),
        Table::Raw => dgram_table(s, Dgram::Raw, false),
        Table::Raw6 => dgram_table(s, Dgram::Raw, true),
        Table::Icmp => dgram_table(s, Dgram::Icmp, false),
        Table::Icmp6 => dgram_table(s, Dgram::Icmp, true),
        Table::Unix => unix_table(s),
        Table::Sockstat => sockstat(s),
        Table::Sockstat6 => sockstat6(s),
    }
}
