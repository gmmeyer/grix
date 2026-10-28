//! Terminals: pseudo-terminal pairs (/dev/ptmx and /dev/pts/N) with
//! Linux's N_TTY line discipline, and in TTY mode the console's terminal
//! (/dev/pts/0, whose master side is the host).
//!
//! A `Tty` is both ends of a pair. What the master writes (or the host
//! types) goes through `receive`: signals for the ISIG characters, line
//! editing in canonical mode, echo, and then it is the slave's to read.
//! What the slave writes goes through `output` (OPOST) to what the master
//! reads (or the host gets). The line discipline touches no process: it
//! says which signals to send, and the caller sends them with the process
//! table in hand (`signal_group`).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::errno::*;
use crate::fd::FileKind;
use crate::fs::Ino;
use crate::ipc::{EPOLLHUP, EPOLLIN, EPOLLOUT};
use crate::process::Process;
use crate::procs::Procs;
use crate::signal::{self, SIGCONT, SIGTSTP, SigInfo, Target};

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGWINCH: u32 = 28;

// c_cc indices (asm-generic termbits.h).
pub const NCCS: usize = 19;
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
const VSTART: usize = 8;
const VSTOP: usize = 9;
const VSUSP: usize = 10;
const VEOL: usize = 11;
const VREPRINT: usize = 12;
const VWERASE: usize = 14;
const VLNEXT: usize = 15;
const VEOL2: usize = 16;

// c_iflag
const ISTRIP: u32 = 0x20;
const INLCR: u32 = 0x40;
const IGNCR: u32 = 0x80;
const ICRNL: u32 = 0x100;
const IUCLC: u32 = 0x200;
const IXON: u32 = 0x400;
const IXANY: u32 = 0x800;
const IMAXBEL: u32 = 0x2000;
pub const IUTF8: u32 = 0x4000;
// c_oflag
const OPOST: u32 = 0x1;
const OLCUC: u32 = 0x2;
const ONLCR: u32 = 0x4;
const OCRNL: u32 = 0x8;
const ONOCR: u32 = 0x10;
const ONLRET: u32 = 0x20;
const TABDLY: u32 = 0x1800;
const XTABS: u32 = 0x1800;
// c_cflag
const B38400: u32 = 0xf;
const CS8: u32 = 0x30;
const CREAD: u32 = 0x80;
// c_lflag
const ISIG: u32 = 0x1;
pub const ICANON: u32 = 0x2;
const ECHO: u32 = 0x8;
const ECHOE: u32 = 0x10;
const ECHOK: u32 = 0x20;
const ECHONL: u32 = 0x40;
const NOFLSH: u32 = 0x80;
pub const TOSTOP: u32 = 0x100;
const ECHOCTL: u32 = 0x200;
const ECHOKE: u32 = 0x800;
const IEXTEN: u32 = 0x8000;

/// struct termios2 (struct termios is its first 36 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; NCCS],
    pub ispeed: u32,
    pub ospeed: u32,
}

pub const TERMIOS_SIZE: usize = 36;
pub const TERMIOS2_SIZE: usize = 44;

impl Termios {
    /// A pty slave's settings when it's made (Linux's tty_std_termios,
    /// without HUPCL as for ptys): canonical, echoing, signals, CR to NL
    /// on input and NL to CR NL on output. INIT_C_CC: ^C ^\ DEL ^U ^D,
    /// VMIN 1, ^Q ^S ^Z, ^R ^O ^W ^V.
    pub const fn slave() -> Termios {
        let mut cc = [0u8; NCCS];
        let init = *b"\x03\x1c\x7f\x15\x04\x00\x01\x00\x11\x13\x1a\x00\x12\x0f\x17\x16\x00";
        let mut i = 0;
        while i < init.len() {
            cc[i] = init[i];
            i += 1;
        }
        Termios {
            iflag: ICRNL | IXON,
            oflag: OPOST | ONLCR,
            cflag: B38400 | CS8 | CREAD,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            line: 0,
            cc,
            ispeed: 38400,
            ospeed: 38400,
        }
    }

    pub fn bytes(&self) -> [u8; TERMIOS2_SIZE] {
        let mut b = [0u8; TERMIOS2_SIZE];
        for (i, v) in [self.iflag, self.oflag, self.cflag, self.lflag].iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[16] = self.line;
        b[17..17 + NCCS].copy_from_slice(&self.cc);
        b[36..40].copy_from_slice(&self.ispeed.to_le_bytes());
        b[40..44].copy_from_slice(&self.ospeed.to_le_bytes());
        b
    }

    /// From a struct termios (36 bytes; the speeds stay `old`'s) or termios2.
    pub fn from_bytes(b: &[u8], old: &Termios) -> Termios {
        let u = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let mut cc = [0u8; NCCS];
        cc.copy_from_slice(&b[17..17 + NCCS]);
        let (ispeed, ospeed) = if b.len() >= TERMIOS2_SIZE { (u(36), u(40)) } else { (old.ispeed, old.ospeed) };
        Termios { iflag: u(0), oflag: u(4), cflag: u(8), lflag: u(12), line: b[16], cc, ispeed, ospeed }
    }

    fn is(&self, c: u8, which: usize) -> bool {
        // A NUL entry disables it (_POSIX_VDISABLE).
        self.cc[which] != 0 && self.cc[which] == c
    }
}

/// N_TTY_BUF_SIZE: input the slave hasn't read, and the longest line.
const INPUT_MAX: usize = 4096;
/// Output the master hasn't read.
const OUTPUT_MAX: usize = 16384;
/// Complete lines waiting (an end-of-file is one, of no bytes).
const LINES_MAX: usize = 4096;
/// Pseudo-terminals at once (Linux's kernel.pty.max is 4096). Each holds
/// its buffers' worth of kernel memory.
pub const MAX_PTYS: usize = 64;
const TTY_MEMORY: u64 = (INPUT_MAX + OUTPUT_MAX + LINES_MAX * 2 + 1024) as u64;

/// Both ends of a pair. The settings, window size and process groups are
/// the slave's; ioctls on the master act on them too, as on Linux.
pub struct Tty {
    pub index: u32,
    pub termios: Termios,
    /// struct winsize: rows, columns, x and y pixels.
    pub winsize: [u16; 4],
    /// Input the slave hasn't read. In canonical mode the first `canon`
    /// bytes are complete lines (`lines`); the rest is the line being edited.
    input: VecDeque<u8>,
    lines: VecDeque<u16>,
    canon: usize,
    /// The next character is taken literally (VLNEXT).
    lnext: bool,
    /// The output column, and where the line being edited started (for
    /// erasing tabs).
    column: usize,
    canon_col: usize,
    /// Output toward the master side.
    output: VecDeque<u8>,
    /// Output stopped with VSTOP (IXON).
    stopped: bool,
    /// The session whose controlling terminal this is, and its foreground
    /// process group (0: none).
    pub session: u32,
    pub fg: u32,
    pub master_open: bool,
    slaves: usize,
    /// A slave was opened: once they're all closed, the master gets EIO.
    slave_opened: bool,
    /// The slave can't be opened until TIOCSPTLCK unlocks it.
    pub locked: bool,
    /// TIOCEXCL: no more opens of the slave.
    pub exclusive: bool,
    pub version: u64,
    _charge: crate::kmem::Charge,
}

pub type TtyRef = Arc<Mutex<Tty>>;

/// The pseudo-terminals in existence, by index. A pair lasts while either
/// end is open (or it's someone's controlling terminal); its /dev/pts entry
/// while the master is.
static PTYS: Mutex<BTreeMap<u32, alloc::sync::Weak<Mutex<Tty>>>> = Mutex::new(BTreeMap::new());

impl Tty {
    fn new(index: u32, console: bool) -> Result<Tty, Errno> {
        let charge = crate::kmem::Charge::new(TTY_MEMORY)?;
        let mut termios = Termios::slave();
        if console {
            // The host's terminal speaks UTF-8.
            termios.iflag |= IUTF8;
        }
        Ok(Tty {
            index,
            termios,
            winsize: [24, 80, 0, 0],
            input: VecDeque::with_capacity(INPUT_MAX),
            lines: VecDeque::new(),
            canon: 0,
            lnext: false,
            column: 0,
            canon_col: 0,
            output: VecDeque::with_capacity(OUTPUT_MAX),
            stopped: false,
            session: 0,
            fg: 0,
            master_open: true,
            slaves: 0,
            slave_opened: console,
            locked: !console,
            exclusive: false,
            version: 0,
            _charge: charge,
        })
    }

    pub fn touch(&mut self) {
        self.version += 1;
        crate::ipc::changed();
    }

    fn canonical(&self) -> bool {
        self.termios.lflag & ICANON != 0
    }

    /// The master side is gone: the slave reads end-of-file and can't write.
    pub fn hung_up(&self) -> bool {
        !self.master_open
    }

    /// Every slave was closed (after one was opened).
    pub fn slave_closed(&self) -> bool {
        self.slave_opened && self.slaves == 0
    }

    // ------------------------------------------------------------ input

    /// Bytes from the master side (or the host). Returns how many were
    /// taken (the rest waits for room) and the signals to send: (process
    /// group, signal).
    pub fn receive(&mut self, data: &[u8]) -> (usize, Vec<(u32, u32)>) {
        let mut sigs = Vec::new();
        let mut used = 0;
        for &c in data {
            if self.input.len() >= INPUT_MAX {
                break;
            }
            used += 1;
            self.receive_char(c, &mut sigs);
        }
        if used > 0 {
            self.touch();
        }
        (used, sigs)
    }

    /// Room for more input.
    pub fn input_room(&self) -> usize {
        INPUT_MAX - self.input.len()
    }

    fn receive_char(&mut self, c: u8, sigs: &mut Vec<(u32, u32)>) {
        let t = self.termios;
        let (iflag, lflag) = (t.iflag, t.lflag);
        let mut c = if iflag & ISTRIP != 0 { c & 0x7f } else { c };
        if iflag & IUCLC != 0 && lflag & IEXTEN != 0 {
            c = c.to_ascii_lowercase();
        }
        if core::mem::take(&mut self.lnext) {
            self.put(c);
            return;
        }
        if iflag & IXON != 0 {
            if t.is(c, VSTART) {
                self.stopped = false;
                return;
            }
            if t.is(c, VSTOP) {
                self.stopped = true;
                return;
            }
            if iflag & IXANY != 0 {
                self.stopped = false;
            }
        }
        if lflag & ISIG != 0 {
            let sig = [(VINTR, SIGINT), (VQUIT, SIGQUIT), (VSUSP, SIGTSTP)].into_iter().find(|&(i, _)| t.is(c, i));
            if let Some((_, sig)) = sig {
                if self.fg != 0 {
                    sigs.push((self.fg, sig));
                }
                if lflag & NOFLSH == 0 {
                    self.flush_input();
                    self.output.clear();
                }
                if iflag & IXON != 0 {
                    self.stopped = false;
                }
                if lflag & ECHO != 0 {
                    self.echo(c);
                }
                return;
            }
        }
        // A CR or NL these flags map takes n_tty's special path, where a
        // newline echoes as one even outside canonical mode (a ^J typed
        // there echoes as ^J).
        let mapped = (c == b'\r' && iflag & (IGNCR | ICRNL) != 0) || (c == b'\n' && iflag & INLCR != 0);
        if c == b'\r' {
            if iflag & IGNCR != 0 {
                return;
            }
            if iflag & ICRNL != 0 {
                c = b'\n';
            }
        } else if c == b'\n' && iflag & INLCR != 0 {
            c = b'\r';
        }
        if lflag & ICANON != 0 {
            let iexten = lflag & IEXTEN != 0;
            if t.is(c, VERASE) {
                return self.erase(Erase::Char);
            }
            if t.is(c, VKILL) {
                return self.erase(Erase::Line);
            }
            if iexten && t.is(c, VWERASE) {
                return self.erase(Erase::Word);
            }
            if iexten && t.is(c, VLNEXT) {
                self.lnext = true;
                if lflag & ECHO != 0 && lflag & ECHOCTL != 0 {
                    self.raw(b"^\x08");
                }
                return;
            }
            if iexten && lflag & ECHO != 0 && t.is(c, VREPRINT) {
                self.echo(c);
                self.out(b'\n');
                let line: Vec<u8> = self.input.range(self.canon..).copied().collect();
                self.canon_col = self.column;
                for b in line {
                    self.echo(b);
                }
                return;
            }
            if c == b'\n' {
                if lflag & (ECHO | ECHONL) != 0 {
                    self.out(b'\n');
                }
                self.input.push_back(c);
                return self.end_line();
            }
            // End-of-file ends the line without being part of it.
            if t.is(c, VEOF) {
                return self.end_line();
            }
            if t.is(c, VEOL) || iexten && t.is(c, VEOL2) {
                if lflag & ECHO != 0 {
                    self.echo(c);
                }
                self.input.push_back(c);
                return self.end_line();
            }
            // A full line takes nothing more but its end.
            if self.input.len() - self.canon >= INPUT_MAX - 1 {
                if iflag & IMAXBEL != 0 && lflag & ECHO != 0 {
                    self.raw(b"\x07");
                }
                return;
            }
        } else if mapped && c == b'\n' {
            if lflag & ECHO != 0 {
                self.out(b'\n');
            }
            self.input.push_back(c);
            return;
        }
        self.put(c);
    }

    /// An ordinary character: echoed, and in the input.
    fn put(&mut self, c: u8) {
        if self.termios.lflag & ECHO != 0 {
            if self.input.len() == self.canon {
                self.canon_col = self.column;
            }
            self.echo(c);
        }
        self.input.push_back(c);
    }

    fn end_line(&mut self) {
        if self.lines.len() >= LINES_MAX {
            return;
        }
        let len = self.input.len() - self.canon;
        self.lines.push_back(len as u16);
        self.canon = self.input.len();
    }

    fn flush_input(&mut self) {
        self.input.clear();
        self.lines.clear();
        self.canon = 0;
        self.lnext = false;
    }

    fn erase(&mut self, kind: Erase) {
        let t = self.termios;
        let lflag = t.lflag;
        if self.input.len() == self.canon {
            return;
        }
        let echo = lflag & ECHO != 0;
        if kind == Erase::Line && (!echo || lflag & (ECHOK | ECHOKE | ECHOE) != (ECHOK | ECHOKE | ECHOE)) {
            self.input.truncate(self.canon);
            if echo {
                self.echo(t.cc[VKILL]);
                if lflag & ECHOK != 0 {
                    self.out(b'\n');
                }
            }
            return;
        }
        let mut seen_alnum = false;
        while self.input.len() > self.canon {
            // One character: with IUTF8, a lead byte and its continuation bytes.
            let mut len = 1;
            if t.iflag & IUTF8 != 0 {
                while len < self.input.len() - self.canon && is_continuation(self.input[self.input.len() - len]) {
                    len += 1;
                }
            }
            let c = self.input[self.input.len() - len];
            if kind == Erase::Word {
                if c.is_ascii_alphanumeric() || c == b'_' {
                    seen_alnum = true;
                } else if seen_alnum {
                    break;
                }
            }
            self.input.truncate(self.input.len() - len);
            if echo {
                if kind == Erase::Char && lflag & ECHOE == 0 {
                    self.echo(t.cc[VERASE]);
                } else if c == b'\t' {
                    // Back to where the rest of the line ends.
                    let rest: Vec<u8> = self.input.range(self.canon..).copied().collect();
                    let col = rest.iter().fold(self.canon_col, |col, &b| advance(col, b, lflag & ECHOCTL != 0));
                    for _ in col..self.column {
                        self.raw(b"\x08");
                    }
                } else {
                    let width = if is_cntrl(c) { if lflag & ECHOCTL != 0 { 2 } else { 0 } } else { 1 };
                    for _ in 0..width {
                        self.raw(b"\x08 \x08");
                    }
                }
            }
            if kind == Erase::Char {
                break;
            }
        }
    }

    // ------------------------------------------------------------ output

    /// Echo `c`: control characters as ^X with ECHOCTL.
    fn echo(&mut self, c: u8) {
        if self.termios.lflag & ECHOCTL != 0 && is_cntrl(c) && c != b'\t' {
            self.raw(&[b'^', c ^ 0x40]);
        } else {
            self.out(c);
        }
    }

    /// Bytes as they are (the column moves for the printable ones).
    fn raw(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.output.len() >= OUTPUT_MAX {
                return;
            }
            match b {
                0x08 => self.column = self.column.saturating_sub(1),
                _ if !is_cntrl(b) => self.column += 1,
                _ => {}
            }
            self.output.push_back(b);
        }
    }

    /// One byte of output, processed as OPOST says.
    fn out(&mut self, c: u8) {
        let oflag = self.termios.oflag;
        let push = |t: &mut Tty, b: u8| {
            if t.output.len() < OUTPUT_MAX {
                t.output.push_back(b);
            }
        };
        if oflag & OPOST == 0 {
            return push(self, c);
        }
        match c {
            b'\n' => {
                if oflag & ONLRET != 0 {
                    self.column = 0;
                }
                if oflag & ONLCR != 0 {
                    self.column = 0;
                    push(self, b'\r');
                }
                push(self, b'\n');
            }
            b'\r' => {
                if oflag & ONOCR != 0 && self.column == 0 {
                    return;
                }
                if oflag & OCRNL != 0 {
                    if oflag & ONLRET != 0 {
                        self.column = 0;
                    }
                    return push(self, b'\n');
                }
                self.column = 0;
                push(self, b'\r');
            }
            b'\t' => {
                let spaces = 8 - (self.column & 7);
                if oflag & TABDLY == XTABS {
                    for _ in 0..spaces {
                        push(self, b' ');
                    }
                } else {
                    push(self, b'\t');
                }
                self.column += spaces;
            }
            0x08 => {
                self.column = self.column.saturating_sub(1);
                push(self, c);
            }
            _ => {
                let c = if oflag & OLCUC != 0 { c.to_ascii_uppercase() } else { c };
                if !is_cntrl(c) && !(self.termios.iflag & IUTF8 != 0 && is_continuation(c)) {
                    self.column += 1;
                }
                push(self, c);
            }
        }
    }

    /// Room for the slave to write (a tab may take 8).
    fn output_room(&self) -> bool {
        self.output.len() + 8 <= OUTPUT_MAX
    }

    /// What the slave writes. Returns how many bytes were taken.
    pub fn write_slave(&mut self, data: &[u8]) -> usize {
        let mut n = 0;
        while n < data.len() && self.output_room() {
            self.out(data[n]);
            n += 1;
        }
        if n > 0 {
            self.touch();
        }
        n
    }

    /// Up to `max` bytes for the master side.
    pub fn take_output(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.output.len());
        let out: Vec<u8> = self.output.drain(..n).collect();
        if n > 0 {
            self.touch();
        }
        out
    }

    pub fn output_len(&self) -> usize {
        self.output.len()
    }

    // ------------------------------------------------------------ the slave reading

    /// Input ready to read: complete lines in canonical mode, `min` bytes
    /// otherwise.
    pub fn readable(&self, min: usize) -> bool {
        if self.canonical() { !self.lines.is_empty() } else { self.input.len() >= min.max(1) }
    }

    /// Canonical mode: the next line, or its first `max` bytes. An
    /// end-of-file is an empty one.
    pub fn take_line(&mut self, max: usize) -> Option<Vec<u8>> {
        let len = *self.lines.front()? as usize;
        let n = len.min(max);
        let data: Vec<u8> = self.input.drain(..n).collect();
        self.canon -= n;
        if n == len {
            self.lines.pop_front();
        } else {
            self.lines[0] -= n as u16;
        }
        self.touch();
        Some(data)
    }

    /// Non-canonical mode: up to `max` bytes.
    pub fn take_input(&mut self, max: usize) -> Vec<u8> {
        let n = max.min(self.input.len());
        let data: Vec<u8> = self.input.drain(..n).collect();
        if n > 0 {
            self.touch();
        }
        data
    }

    /// Bytes a read could return now (FIONREAD): complete lines' in
    /// canonical mode.
    pub fn available(&self) -> usize {
        if self.canonical() { self.canon } else { self.input.len() }
    }

    pub fn output_stopped(&self) -> bool {
        self.stopped
    }

    // ------------------------------------------------------------ settings

    /// New settings. Switching canonical mode off makes everything
    /// readable; on, what's there becomes the line being edited.
    pub fn set_termios(&mut self, new: Termios) {
        if (new.lflag ^ self.termios.lflag) & ICANON != 0 {
            self.lines.clear();
            self.canon = 0;
            self.canon_col = self.column;
        }
        if new.iflag & IXON == 0 {
            self.stopped = false;
        }
        self.termios = new;
        self.touch();
    }

    /// TCFLSH: throw away unread input, unread output, or both.
    pub fn flush(&mut self, input: bool, output: bool) {
        if input {
            self.flush_input();
        }
        if output {
            self.output.clear();
        }
        self.touch();
    }

    /// TCXONC: suspend or restart output (TCOOFF, TCOON).
    pub fn set_stopped(&mut self, stopped: bool) {
        self.stopped = stopped;
        self.touch();
    }

    /// TCXONC's TCIOFF and TCION: send VSTOP or VSTART to the master.
    pub fn send_char(&mut self, start: bool) {
        let c = self.termios.cc[if start { VSTART } else { VSTOP }];
        if c != 0 && self.output.len() < OUTPUT_MAX {
            self.output.push_back(c);
            self.touch();
        }
    }

    /// Bytes the master wrote that the slave hasn't read (TIOCOUTQ on it).
    pub fn input_len(&self) -> usize {
        self.input.len()
    }

    /// TIOCSWINSZ: the process group to send SIGWINCH, if it changed.
    pub fn set_winsize(&mut self, ws: [u16; 4]) -> Option<u32> {
        if ws == self.winsize {
            return None;
        }
        self.winsize = ws;
        (self.fg != 0).then_some(self.fg)
    }

    // ------------------------------------------------------------ readiness

    pub fn poll(&self, master: bool) -> (u32, u64) {
        let mask = if master {
            (if self.output.is_empty() && !self.slave_closed() { 0 } else { EPOLLIN })
                | if self.input.len() < INPUT_MAX { EPOLLOUT } else { 0 }
                | if self.slave_closed() { EPOLLHUP } else { 0 }
        } else if self.hung_up() {
            EPOLLIN | EPOLLOUT | EPOLLHUP
        } else {
            // A read waits for VMIN bytes unless VTIME is set (n_tty_poll).
            let t = &self.termios;
            let min = if t.cc[VTIME] != 0 { 1 } else { t.cc[VMIN] as usize };
            (if self.readable(min) { EPOLLIN } else { 0 })
                | if self.output_room() && !self.stopped { EPOLLOUT } else { 0 }
        };
        (mask, self.version)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Erase {
    Char,
    Word,
    Line,
}

fn is_cntrl(c: u8) -> bool {
    c < 0x20 || c == 0x7f
}

fn is_continuation(c: u8) -> bool {
    c & 0xc0 == 0x80
}

/// The column after echoing `c` at `col`.
fn advance(col: usize, c: u8, echoctl: bool) -> usize {
    match c {
        b'\t' => col + 8 - (col & 7),
        _ if is_continuation(c) => col,
        _ if is_cntrl(c) => col + if echoctl { 2 } else { 0 },
        _ => col + 1,
    }
}

// ---------------------------------------------------------------- the files

/// An open end of a pseudo-terminal pair (or of the console's terminal),
/// and the /dev node it was opened through.
pub struct PtyEnd {
    pub tty: TtyRef,
    pub master: bool,
    pub ino: Ino,
}

impl PtyEnd {
    pub fn new(tty: TtyRef, master: bool, ino: Ino) -> PtyEnd {
        if !master {
            let mut t = tty.lock();
            t.slaves += 1;
            t.slave_opened = true;
        }
        PtyEnd { tty, master, ino }
    }
}

impl Drop for PtyEnd {
    fn drop(&mut self) {
        let mut t = self.tty.lock();
        if self.master {
            // devpts forgets the slave, and the session's terminal hangs up.
            t.master_open = false;
            PENDING.lock().push(Pending::Hangup(self.tty.clone(), t.index));
            WORK.store(true, Ordering::Relaxed);
        } else {
            t.slaves -= 1;
        }
        t.touch();
    }
}

/// /dev/ptmx: a new pair, the slave locked until TIOCSPTLCK. Its index is
/// the lowest free one.
pub fn new_pair(console: bool) -> Result<TtyRef, Errno> {
    let mut ptys = PTYS.lock();
    ptys.retain(|_, t| t.strong_count() > 0);
    if ptys.len() >= MAX_PTYS {
        return Err(ENOSPC);
    }
    let index = (0..).find(|i| !ptys.contains_key(i)).unwrap();
    let tty = Arc::new(Mutex::new(Tty::new(index, console)?));
    ptys.insert(index, Arc::downgrade(&tty));
    Ok(tty)
}

/// The pair with this index, if it still has an open master.
pub fn get(index: u32) -> Option<TtyRef> {
    let tty = PTYS.lock().get(&index)?.upgrade()?;
    let open = tty.lock().master_open;
    open.then_some(tty)
}

// ---------------------------------------------------------------- TTY mode

/// TTY mode's terminal: /dev/pts/0, its master side the host.
static CONSOLE_TTY: Mutex<Option<TtyRef>> = Mutex::new(None);

/// Make the console's terminal at boot, and the slave the program's stdio
/// is (owned by the program's user, as login would make it).
pub fn console_terminal(rows: u16, cols: u16, uid: u32, gid: u32) -> (TtyRef, crate::fd::FileRef) {
    let tty = new_pair(true).expect("the console's terminal at boot");
    tty.lock().winsize = [rows, cols, 0, 0];
    let index = tty.lock().index;
    let ino = crate::fs::lock().pts_show(index, (uid, gid));
    let file = crate::fd::new_file(FileKind::Pty(PtyEnd::new(tty.clone(), false, ino)), crate::fd::O_RDWR);
    *CONSOLE_TTY.lock() = Some(tty.clone());
    (tty, file)
}

/// The host's stdin ended and the terminal was told.
static HOST_EOF: AtomicBool = AtomicBool::new(false);

/// Move what the host typed into the console's terminal (as far as it has
/// room: the rest waits in the console, and the host for credit), what
/// the terminal shows out to the host (as far as the console has room),
/// and a new size in. When the host's stdin ends, a canonical-mode reader
/// gets end-of-file, as util-linux's script gives it (VEOF, twice if a
/// line was being typed); in raw mode nothing more comes.
/// Is `tty` the console's terminal (TTY mode's /dev/pts/0)?
pub fn is_console(tty: &TtyRef) -> bool {
    CONSOLE_TTY.lock().as_ref().is_some_and(|c| Arc::ptr_eq(c, tty))
}

/// The program found its terminal with nothing to read: in TTY mode,
/// that's waiting for the host's input (a snapshot's moment).
pub fn waiting_on(tty: &TtyRef) {
    if is_console(tty) {
        crate::console::mark_stdin_waited();
    }
}

fn pump(cur: &mut Process, procs: &mut Procs) {
    let Some(tty) = CONSOLE_TTY.lock().clone() else { return };
    if let Some((rows, cols)) = crate::console::take_resize() {
        let fg = tty.lock().set_winsize([rows, cols, 0, 0]);
        if let Some(fg) = fg {
            signal_group(Some(&mut *cur), procs, fg, SIGWINCH);
        }
    }
    let mut buf = [0u8; 1024];
    loop {
        let room = tty.lock().input_room().min(buf.len());
        if room == 0 || tty.lock().hung_up() {
            break;
        }
        match crate::console::stdin_take(&mut buf[..room], false) {
            crate::console::StdinRead::Data(n) => {
                let (_, sigs) = tty.lock().receive(&buf[..n]);
                for (pgrp, sig) in sigs {
                    signal_group(Some(&mut *cur), procs, pgrp, sig);
                }
            }
            crate::console::StdinRead::Empty => break,
            crate::console::StdinRead::Eof => {
                if !HOST_EOF.swap(true, Ordering::Relaxed) {
                    let mut t = tty.lock();
                    if t.canonical() && t.termios.cc[VEOF] != 0 {
                        let eof = t.termios.cc[VEOF];
                        let times = if t.input.len() > t.canon { 2 } else { 1 };
                        for _ in 0..times {
                            t.receive(&[eof]);
                        }
                    }
                }
                break;
            }
        }
    }
    send_output(&tty, false);
}

/// The terminal's output to the host: what fits now, or (`wait`) all of it.
fn send_output(tty: &TtyRef, wait: bool) {
    loop {
        let chunk = {
            let t = tty.lock();
            let n = t.output_len().min(crate::console::WRITE_CHUNK);
            if n == 0 {
                return;
            }
            t.output.range(..n).copied().collect::<Vec<u8>>()
        };
        if wait {
            crate::console::write(grix_abi::wire::Channel::Stdout, &chunk);
        } else if !crate::console::output_room(chunk.len())
            || !crate::console::try_write(grix_abi::wire::Channel::Stdout, &chunk)
        {
            return;
        }
        tty.lock().take_output(chunk.len());
    }
}

/// The program ended: what the terminal has left goes to the host first.
pub fn flush_console() {
    let tty = CONSOLE_TTY.try_lock().and_then(|t| t.clone());
    if let Some(tty) = tty
        && tty.try_lock().is_some()
    {
        send_output(&tty, true);
    }
}

// ---------------------------------------------------------------- work for later

/// What closing a master leaves to do that needs the process table or the
/// filesystem: done by `service`, from `procs::reap_others`.
enum Pending {
    Hangup(TtyRef, u32),
}

static PENDING: Mutex<Vec<Pending>> = Mutex::new(Vec::new());
static WORK: AtomicBool = AtomicBool::new(false);

/// Hang up the terminals whose master closed (Linux's tty_vhangup of the
/// slave): its session leader gets SIGHUP and SIGCONT, and nobody in the
/// session has it as controlling terminal any more. Its /dev/pts entry goes.
pub fn service(cur: &mut Process, procs: &mut Procs) {
    pump(cur, procs);
    if !WORK.swap(false, Ordering::Relaxed) {
        return;
    }
    let pending = core::mem::take(&mut *PENDING.lock());
    for Pending::Hangup(tty, index) in pending {
        let session = core::mem::take(&mut tty.lock().session);
        tty.lock().fg = 0;
        if session != 0 {
            for q in procs.all(&mut *cur) {
                if q.ctty.as_ref().is_some_and(|t| Arc::ptr_eq(t, &tty)) {
                    q.ctty = None;
                }
                if q.pid == session {
                    send(q, SIGHUP);
                    send(q, SIGCONT);
                }
            }
        }
        if let Some(mut fs) = crate::fs::try_lock() {
            fs.pts_hide(index);
        }
    }
}

fn send(q: &mut Process, sig: u32) {
    let info = SigInfo::sent(sig, signal::SI_USER, 0, 0, "a signal from the terminal");
    let _ = signal::send(q, Target::Process, info);
}

/// Every live process: the running one (`cur`, if it isn't the one being
/// finished off) and the others.
fn each<'a>(cur: Option<&'a mut Process>, procs: &'a mut Procs) -> impl Iterator<Item = &'a mut Process> {
    cur.into_iter().filter(|p| !p.dead).chain(procs.others.values_mut())
}

/// Send `sig` to every process in group `pgrp`, as the terminal does.
pub fn signal_group(cur: Option<&mut Process>, procs: &mut Procs, pgrp: u32, sig: u32) {
    for q in each(cur, procs) {
        if q.pgid == pgrp {
            send(q, sig);
        }
    }
}

/// The same, from a syscall (the process table isn't held).
pub fn signal_group_now(p: &mut Process, pgrp: u32, sig: u32) {
    let mut procs = crate::procs::PROCS.lock();
    signal_group(Some(&mut *p), &mut procs, pgrp, sig);
    p.timer_dirty = true;
}

/// The session leader `leader` (with terminal `tty`) ended, or gave its
/// terminal up (TIOCNOTTY): the foreground group gets SIGHUP (and SIGCONT
/// unless it ended), and the session has no controlling terminal any more
/// (Linux's disassociate_ctty).
pub fn disassociate(mut cur: Option<&mut Process>, procs: &mut Procs, tty: &TtyRef, session: u32, on_exit: bool) {
    let fg = {
        let mut t = tty.lock();
        if t.session != session {
            return;
        }
        t.session = 0;
        core::mem::take(&mut t.fg)
    };
    if fg != 0 {
        signal_group(cur.as_deref_mut(), procs, fg, SIGHUP);
        if !on_exit {
            signal_group(cur.as_deref_mut(), procs, fg, SIGCONT);
        }
    }
    for q in each(cur, procs) {
        if q.sid == session {
            q.ctty = None;
        }
    }
}

/// Is `tty` the controlling terminal of `p`?
pub fn is_ctty(p: &Process, tty: &TtyRef) -> bool {
    p.ctty.as_ref().is_some_and(|c| Arc::ptr_eq(c, tty))
}

/// Opening a terminal (not the master) without O_NOCTTY makes it the
/// controlling terminal of a session leader that has none, if it isn't
/// another session's (Linux's tty_open_proc_set_tty).
pub fn maybe_acquire(p: &mut Process, tty: &TtyRef, noctty: bool) {
    if noctty || p.pid != p.sid || p.ctty.is_some() {
        return;
    }
    let mut t = tty.lock();
    if t.session == 0 && !t.hung_up() {
        (t.session, t.fg) = (p.sid, p.pgid);
        drop(t);
        p.ctty = Some(tty.clone());
    }
}
