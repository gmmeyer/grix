//! Host <-> guest protocol over the console (virtio, or the serial port
//! before that is up and for panics).
//!
//! Every byte the guest sends is part of a frame:
//! `[FRAME_MAGIC, channel, len_lo, len_hi, payload...]` with `len <= MAX_FRAME`.
//! The host must treat this stream as untrusted: a compromised guest can send
//! anything, so the decoder resynchronizes on garbage and bounds every length.
//!
//! The host sends frames of the same shape into the console's input
//! ([`Input`]): the program's stdin, then its end.

use alloc::vec::Vec;

use crate::codec::{DecodeError, Reader, Writer};

pub const FRAME_MAGIC: u8 = 0xA5;
pub const FRAME_HEADER: usize = 4;
pub const MAX_FRAME: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    Stdout = 1,
    Stderr = 2,
    /// Kernel diagnostics (free-form UTF-8).
    Log = 3,
    /// An encoded [`Event`].
    Event = 4,
    /// Final status; see [`encode_exit`].
    Exit = 5,
    /// Exported directories, after the final status; see [`ExportMsg`].
    Export = 6,
    /// Networking and flow control: `link::ToHost`.
    Link = 7,
    /// Live mounts: `hostfs::Request`s, a frame of a message each.
    Fs = 8,
}

impl Channel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Stdout),
            2 => Some(Self::Stderr),
            3 => Some(Self::Log),
            4 => Some(Self::Event),
            5 => Some(Self::Exit),
            6 => Some(Self::Export),
            7 => Some(Self::Link),
            8 => Some(Self::Fs),
            _ => None,
        }
    }
}

pub fn frame_header(ch: Channel, len: usize) -> [u8; FRAME_HEADER] {
    debug_assert!(len <= MAX_FRAME);
    [FRAME_MAGIC, ch as u8, len as u8, (len >> 8) as u8]
}

/// Host -> guest frame kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Input {
    /// Bytes for the program's stdin.
    Stdin = 1,
    /// stdin has ended: reads return 0 once the data is used up.
    StdinEof = 2,
    /// Networking: `link::ToGuest`.
    Link = 3,
    /// Live mounts: `hostfs::Reply`s, a frame of a message each.
    Fs = 4,
    /// A signal for the program's process group: one byte, 1-64.
    Signal = 5,
    /// TTY mode: the host's terminal changed size. Rows then columns, u16
    /// little-endian each.
    Resize = 6,
}

impl Input {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Stdin),
            2 => Some(Self::StdinEof),
            3 => Some(Self::Link),
            4 => Some(Self::Fs),
            5 => Some(Self::Signal),
            6 => Some(Self::Resize),
            _ => None,
        }
    }
}

pub fn input_header(kind: Input, len: usize) -> [u8; FRAME_HEADER] {
    debug_assert!(len <= MAX_FRAME);
    [FRAME_MAGIC, kind as u8, len as u8, (len >> 8) as u8]
}

/// Byte-at-a-time decoder for host -> guest frames (guest side, no heap
/// beyond its fixed buffer). Bytes that don't form a frame are skipped.
pub struct InputDecoder {
    header: [u8; FRAME_HEADER],
    have: usize,
    payload: [u8; MAX_FRAME],
    len: usize,
}

impl Default for InputDecoder {
    fn default() -> Self {
        InputDecoder { header: [0; FRAME_HEADER], have: 0, payload: [0; MAX_FRAME], len: 0 }
    }
}

impl InputDecoder {
    /// Between frames (nothing of one taken yet).
    pub fn idle(&self) -> bool {
        self.have == 0
    }

    /// Feed one byte. Returns a complete frame when this byte ends one.
    pub fn push(&mut self, b: u8) -> Option<(Input, &[u8])> {
        if self.have < FRAME_HEADER {
            if self.have == 0 && b != FRAME_MAGIC {
                return None;
            }
            self.header[self.have] = b;
            self.have += 1;
            if self.have < FRAME_HEADER {
                return None;
            }
            let len = self.header[2] as usize | (self.header[3] as usize) << 8;
            if Input::from_u8(self.header[1]).is_none() || len > MAX_FRAME {
                self.have = 0;
                return None;
            }
            self.len = len;
            if len > 0 {
                return None;
            }
        } else {
            self.payload[self.have - FRAME_HEADER] = b;
            self.have += 1;
            if self.have - FRAME_HEADER < self.len {
                return None;
            }
        }
        self.have = 0;
        Some((Input::from_u8(self.header[1]).unwrap(), &self.payload[..self.len]))
    }

    /// Is a frame partly received?
    pub fn partial(&self) -> bool {
        self.have > 0
    }
}

/// Incremental frame decoder (host side).
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    /// Bytes skipped because they were not part of a valid frame.
    pub garbage: usize,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, data: &[u8], mut on_frame: impl FnMut(Channel, &[u8])) {
        self.buf.extend_from_slice(data);
        let buf = &self.buf;
        let mut pos = 0;
        loop {
            while pos < buf.len() && buf[pos] != FRAME_MAGIC {
                pos += 1;
                self.garbage += 1;
            }
            if buf.len() - pos < FRAME_HEADER {
                break;
            }
            let len = buf[pos + 2] as usize | (buf[pos + 3] as usize) << 8;
            let Some(ch) = Channel::from_u8(buf[pos + 1]).filter(|_| len <= MAX_FRAME) else {
                pos += 1;
                self.garbage += 1;
                continue;
            };
            if buf.len() - pos - FRAME_HEADER < len {
                break;
            }
            on_frame(ch, &buf[pos + FRAME_HEADER..pos + FRAME_HEADER + len]);
            pos += FRAME_HEADER + len;
        }
        self.buf.drain(..pos);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitKind {
    /// Program called exit; code is its exit status.
    Exited = 0,
    /// Program was terminated by a signal; code is the signal number.
    Signaled = 1,
    /// The guest kernel panicked.
    Panic = 2,
}

pub fn encode_exit(kind: ExitKind, code: i32) -> [u8; 5] {
    let c = code.to_le_bytes();
    [kind as u8, c[0], c[1], c[2], c[3]]
}

pub fn decode_exit(buf: &[u8]) -> Option<(ExitKind, i32)> {
    let [k, a, b, c, d] = *buf else { return None };
    let kind = match k {
        0 => ExitKind::Exited,
        1 => ExitKind::Signaled,
        2 => ExitKind::Panic,
        _ => return None,
    };
    Some((kind, i32::from_le_bytes([a, b, c, d])))
}

/// What an exported entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExportKind {
    Dir = 0,
    File = 1,
    Symlink = 2,
    /// In a mount's changes: the path (and everything under it) is gone.
    /// No contents; mode and mtime are 0.
    Removed = 3,
}

/// The longest path an export entry may have (relative to its directory).
/// Deeper entries are left out, and the export is marked truncated.
pub const MAX_EXPORT_PATH: usize = 4096;

/// What an entry counts against `Image::export_budget`: its path, its
/// contents, and a little for the host's bookkeeping. Both sides use this,
/// so the guest leaves out exactly what the host wouldn't take.
pub fn export_cost(path_len: usize, data_len: u64) -> u64 {
    (path_len as u64).saturating_add(data_len).saturating_add(256)
}

/// [`Channel::Export`] messages: the directories the host asked for
/// (`Image::exports`, then `Image::mounts`), sent when the program ends,
/// after its status. For each directory in order, `Root`, then an `Entry`
/// for everything under it (parents before children); for a mount, only
/// what changed, then `Removed` entries for what's gone. Each `Entry` is followed by `Data` messages
/// carrying exactly its path (relative to the directory, `/`-separated) and
/// then its contents (file bytes or link target). `Done` ends the export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportMsg<'a> {
    /// Directory `index` of `Image::exports` followed by `Image::mounts`;
    /// `found` if it exists and is a directory.
    Root {
        index: u32,
        found: bool,
    },
    Entry {
        kind: ExportKind,
        mode: u32,
        mtime_ns: u64,
        path_len: u32,
        data_len: u64,
    },
    Data(&'a [u8]),
    /// Something in the current directory was left out: over the budget or
    /// `MAX_EXPORT_PATH`.
    Truncated,
    /// Something in the current directory couldn't be read (the program
    /// ended in the middle of changing it).
    Skipped,
    Done,
}

impl<'a> ExportMsg<'a> {
    /// The first byte of a `Data` message, followed by the bytes themselves
    /// (so the guest can build one in place).
    pub const DATA_TAG: u8 = 2;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match *self {
            ExportMsg::Root { index, found } => {
                w.u8(0);
                w.u32(index);
                w.u8(found as u8);
            }
            ExportMsg::Entry { kind, mode, mtime_ns, path_len, data_len } => {
                w.u8(1);
                w.u8(kind as u8);
                w.u32(mode);
                w.u64(mtime_ns);
                w.u32(path_len);
                w.u64(data_len);
            }
            ExportMsg::Data(bytes) => {
                w.u8(Self::DATA_TAG);
                w.raw(bytes);
            }
            ExportMsg::Done => w.u8(3),
            ExportMsg::Truncated => w.u8(4),
            ExportMsg::Skipped => w.u8(5),
        }
        w.buf
    }

    pub fn decode(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let msg = match r.u8()? {
            0 => ExportMsg::Root { index: r.u32()?, found: r.u8()? != 0 },
            1 => {
                let kind = match r.u8()? {
                    0 => ExportKind::Dir,
                    1 => ExportKind::File,
                    2 => ExportKind::Symlink,
                    3 => ExportKind::Removed,
                    _ => return Err(DecodeError),
                };
                ExportMsg::Entry { kind, mode: r.u32()?, mtime_ns: r.u64()?, path_len: r.u32()?, data_len: r.u64()? }
            }
            Self::DATA_TAG => return Ok(ExportMsg::Data(&buf[1..])),
            3 => ExportMsg::Done,
            4 => ExportMsg::Truncated,
            5 => ExportMsg::Skipped,
            _ => return Err(DecodeError),
        };
        if r.remaining() != 0 {
            return Err(DecodeError);
        }
        Ok(msg)
    }
}

/// Things the guest kernel reports so the caller can see what a program tried to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A syscall needed a capability that was not granted.
    Denied { nr: u32, syscall: &'a str, capability: &'a str, detail: &'a str },
    /// The program used kernel functionality that does not exist yet.
    Unimplemented { nr: u32, syscall: &'a str, detail: &'a str },
    /// The program looked for a path that was not imported.
    MissingPath { path: &'a str },
    /// The program was killed by a fault or signal.
    Fault { signal: u32, addr: u64, pc: u64, detail: &'a str },
    /// The initial exec failed (missing binary, bad ELF, ...).
    ExecFailed { path: &'a str, reason: &'a str },
    /// The program (init) stopped: a stop signal's default action.
    Stopped { signal: u32 },
    /// The program continued (SIGCONT) after stopping.
    Continued,
}

impl<'a> Event<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match *self {
            Event::Denied { nr, syscall, capability, detail } => {
                w.u8(0);
                w.u32(nr);
                w.str(syscall);
                w.str(capability);
                w.str(detail);
            }
            Event::Unimplemented { nr, syscall, detail } => {
                w.u8(1);
                w.u32(nr);
                w.str(syscall);
                w.str(detail);
            }
            Event::MissingPath { path } => {
                w.u8(2);
                w.str(path);
            }
            Event::Fault { signal, addr, pc, detail } => {
                w.u8(3);
                w.u32(signal);
                w.u64(addr);
                w.u64(pc);
                w.str(detail);
            }
            Event::ExecFailed { path, reason } => {
                w.u8(4);
                w.str(path);
                w.str(reason);
            }
            Event::Stopped { signal } => {
                w.u8(5);
                w.u32(signal);
            }
            Event::Continued => w.u8(6),
        }
        w.buf
    }

    pub fn decode(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let ev = match r.u8()? {
            0 => Event::Denied { nr: r.u32()?, syscall: r.str()?, capability: r.str()?, detail: r.str()? },
            1 => Event::Unimplemented { nr: r.u32()?, syscall: r.str()?, detail: r.str()? },
            2 => Event::MissingPath { path: r.str()? },
            3 => Event::Fault { signal: r.u32()?, addr: r.u64()?, pc: r.u64()?, detail: r.str()? },
            4 => Event::ExecFailed { path: r.str()?, reason: r.str()? },
            5 => Event::Stopped { signal: r.u32()? },
            6 => Event::Continued,
            _ => return Err(DecodeError),
        };
        r.done()?;
        Ok(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn frame(ch: Channel, data: &[u8]) -> Vec<u8> {
        let mut v = frame_header(ch, data.len()).to_vec();
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn export_messages_roundtrip_and_reject_garbage() {
        let msgs = [
            ExportMsg::Root { index: 3, found: true },
            ExportMsg::Entry { kind: ExportKind::Symlink, mode: 0o777, mtime_ns: 5, path_len: 4, data_len: 9 },
            ExportMsg::Data(b"a/b/c"),
            ExportMsg::Data(b""),
            ExportMsg::Truncated,
            ExportMsg::Skipped,
            ExportMsg::Done,
        ];
        for m in msgs {
            assert_eq!(ExportMsg::decode(&m.encode()), Ok(m));
        }
        assert!(ExportMsg::decode(&[]).is_err());
        assert!(ExportMsg::decode(&[9]).is_err());
        assert!(ExportMsg::decode(&[1, 7, 0, 0, 0, 0]).is_err()); // bad kind, short
        let mut long = ExportMsg::Done.encode();
        long.push(0);
        assert!(ExportMsg::decode(&long).is_err());
    }

    #[test]
    fn decodes_split_frames_and_skips_garbage() {
        let mut stream = vec![0x00, 0x13, FRAME_MAGIC, 0x77]; // garbage, incl. a bogus header
        stream.extend(frame(Channel::Stdout, b"hello"));
        stream.extend(frame(Channel::Exit, &encode_exit(ExitKind::Exited, 3)));
        let mut d = FrameDecoder::new();
        let mut got = vec![];
        for chunk in stream.chunks(3) {
            d.push(chunk, |ch, p| got.push((ch, p.to_vec())));
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], (Channel::Stdout, b"hello".to_vec()));
        assert_eq!(decode_exit(&got[1].1), Some((ExitKind::Exited, 3)));
        assert!(d.garbage >= 2);
    }

    #[test]
    fn decodes_input_frames() {
        let mut stream = vec![0x42, FRAME_MAGIC, 9, 0, 0]; // garbage and a bad kind
        stream.extend(input_header(Input::Stdin, 3));
        stream.extend(b"abc");
        stream.extend(input_header(Input::StdinEof, 0));
        let mut d = InputDecoder::default();
        let mut got = vec![];
        for b in stream {
            if let Some((k, p)) = d.push(b) {
                got.push((k, p.to_vec()));
            }
        }
        assert_eq!(got, [(Input::Stdin, b"abc".to_vec()), (Input::StdinEof, vec![])]);
        assert!(!d.partial());
    }

    #[test]
    fn event_roundtrip() {
        let evs = [
            Event::Denied { nr: 198, syscall: "socket", capability: "net", detail: "" },
            Event::Unimplemented { nr: 1, syscall: "x", detail: "y" },
            Event::MissingPath { path: "/etc/passwd" },
            Event::Fault { signal: 11, addr: 8, pc: 0x1000, detail: "write" },
            Event::ExecFailed { path: "/bin/x", reason: "not found" },
            Event::Stopped { signal: 20 },
            Event::Continued,
        ];
        for e in evs {
            assert_eq!(Event::decode(&e.encode()).unwrap(), e);
            // Anything after it is garbage, as for every other message.
            let mut more = e.encode();
            more.push(0);
            assert!(Event::decode(&more).is_err(), "{e:?}");
        }
    }
}
