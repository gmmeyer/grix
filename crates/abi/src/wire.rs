//! Guest -> host protocol over the serial console.
//!
//! Every byte the guest sends is part of a frame:
//! `[FRAME_MAGIC, channel, len_lo, len_hi, payload...]` with `len <= MAX_FRAME`.
//! The host must treat this stream as untrusted: a compromised guest can send
//! anything, so the decoder resynchronizes on garbage and bounds every length.

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
}

impl Channel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Stdout),
            2 => Some(Self::Stderr),
            3 => Some(Self::Log),
            4 => Some(Self::Event),
            5 => Some(Self::Exit),
            _ => None,
        }
    }
}

pub fn frame_header(ch: Channel, len: usize) -> [u8; FRAME_HEADER] {
    debug_assert!(len <= MAX_FRAME);
    [FRAME_MAGIC, ch as u8, len as u8, (len >> 8) as u8]
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
            _ => return Err(DecodeError),
        };
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
    fn event_roundtrip() {
        let evs = [
            Event::Denied { nr: 198, syscall: "socket", capability: "net", detail: "" },
            Event::Unimplemented { nr: 1, syscall: "x", detail: "y" },
            Event::MissingPath { path: "/etc/passwd" },
            Event::Fault { signal: 11, addr: 8, pc: 0x1000, detail: "write" },
            Event::ExecFailed { path: "/bin/x", reason: "not found" },
        ];
        for e in evs {
            assert_eq!(Event::decode(&e.encode()).unwrap(), e);
        }
    }
}
