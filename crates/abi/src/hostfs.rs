//! Live mounts: the guest kernel's file system requests for host
//! directories, and the host's answers. Nothing of a live mount is in the
//! boot image. The guest asks for directory listings and file bytes as the
//! program needs them, and every change it makes goes straight to the host.
//!
//! Guest to host: a [`Request`] on `Channel::Fs`. Host to guest: the
//! [`Reply`] on `Input::Fs`. The guest has one request outstanding at a
//! time and waits for its answer. A message can be longer than a frame:
//! each frame's payload starts with a byte saying whether more of the
//! message follows ([`frames`], [`Assembler`]).
//!
//! The host names files with ids. Ids 1 to n are the roots of the image's
//! live mounts, in order; the host gives out the rest in listings and when
//! the guest creates something. The host treats every request as untrusted:
//! it never leaves a mount, never follows a link, and checks every name.
//!
//! Watches: for inotify, the guest asks the host to watch a node
//! ([`Request::Watch`]) and the host tells it what changes there, unasked,
//! as [`Notice`]s on `Input::FsEvent` (one per frame, so they never mix
//! with an answer), until the guest lets go of it ([`Request::Unwatch`]).

use alloc::vec::Vec;

use crate::codec::{DecodeError, Reader, Writer};
use crate::wire::MAX_FRAME;

/// The longest message either side accepts.
pub const MAX_MESSAGE: usize = 256 * 1024;
/// The most bytes one `Read` asks for or one `Write` carries.
pub const IO_MAX: usize = 64 * 1024;
/// Entries per `Listed` reply; the guest asks for more after the last.
pub const LIST_MAX: usize = 256;
/// The longest name a [`Notice`] carries (Linux's NAME_MAX).
pub const NAME_MAX: usize = 255;
/// Nodes the host watches for a run at most; it refuses more (ENOSPC).
pub const MAX_WATCHES: usize = 8192;

/// inotify's event bits, as Linux has them: what a [`Notice`] says.
pub mod mask {
    pub const IN_ACCESS: u32 = 0x1;
    pub const IN_MODIFY: u32 = 0x2;
    pub const IN_ATTRIB: u32 = 0x4;
    pub const IN_CLOSE_WRITE: u32 = 0x8;
    pub const IN_CLOSE_NOWRITE: u32 = 0x10;
    pub const IN_OPEN: u32 = 0x20;
    pub const IN_MOVED_FROM: u32 = 0x40;
    pub const IN_MOVED_TO: u32 = 0x80;
    pub const IN_CREATE: u32 = 0x100;
    pub const IN_DELETE: u32 = 0x200;
    pub const IN_DELETE_SELF: u32 = 0x400;
    pub const IN_MOVE_SELF: u32 = 0x800;
    pub const IN_UNMOUNT: u32 = 0x2000;
    pub const IN_Q_OVERFLOW: u32 = 0x4000;
    pub const IN_IGNORED: u32 = 0x8000;
    pub const IN_ISDIR: u32 = 0x4000_0000;
    /// The changes a host reports. Not opens, reads or closes: the host's
    /// own file server makes those for every request.
    pub const HOST_EVENTS: u32 = IN_MODIFY
        | IN_ATTRIB
        | IN_CLOSE_WRITE
        | IN_MOVED_FROM
        | IN_MOVED_TO
        | IN_CREATE
        | IN_DELETE
        | IN_DELETE_SELF
        | IN_MOVE_SELF;
    /// What a notice may carry: those, and what Linux sends unasked.
    pub const NOTICE: u32 = HOST_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED | IN_ISDIR;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FileType {
    File = 0,
    Dir = 1,
    Symlink = 2,
}

impl FileType {
    fn get(r: &mut Reader) -> Result<FileType, DecodeError> {
        Ok(match r.u8()? {
            0 => FileType::File,
            1 => FileType::Dir,
            2 => FileType::Symlink,
            _ => return Err(DecodeError),
        })
    }
}

/// A file's attributes, as the host has them. Times are ns since the Unix
/// epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    pub ty: FileType,
    /// Permission bits, with setuid, setgid and sticky.
    pub mode: u32,
    pub size: u64,
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
}

impl Attr {
    pub fn put(&self, w: &mut Writer) {
        w.u8(self.ty as u8);
        w.u32(self.mode);
        w.u64(self.size);
        w.u64(self.atime_ns);
        w.u64(self.mtime_ns);
        w.u64(self.ctime_ns);
    }

    pub fn get(r: &mut Reader) -> Result<Attr, DecodeError> {
        Ok(Attr {
            ty: FileType::get(r)?,
            mode: r.u32()?,
            size: r.u64()?,
            atime_ns: r.u64()?,
            mtime_ns: r.u64()?,
            ctime_ns: r.u64()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// The entries of directory `dir` after `after` (all of them for ""),
    /// in name order.
    List {
        dir: u64,
        after: &'a str,
    },
    Stat {
        id: u64,
    },
    /// Up to `len` (at most `IO_MAX`) bytes at `off`.
    Read {
        id: u64,
        off: u64,
        len: u32,
    },
    /// `data` at `off`, or at the end with `append`.
    Write {
        id: u64,
        off: u64,
        append: bool,
        data: &'a [u8],
    },
    SetLen {
        id: u64,
        len: u64,
    },
    /// A file (created exclusively), directory or symbolic link (to
    /// `target`) named `name` in `dir`.
    Create {
        dir: u64,
        name: &'a str,
        ty: FileType,
        mode: u32,
        target: &'a str,
    },
    /// unlink, or rmdir with `is_dir`.
    Remove {
        dir: u64,
        name: &'a str,
        is_dir: bool,
    },
    /// Within one mount. With `noreplace`, fail if `to` exists; with
    /// `exchange`, swap the two (both must exist).
    Rename {
        from_dir: u64,
        from: &'a str,
        to_dir: u64,
        to: &'a str,
        noreplace: bool,
        exchange: bool,
    },
    SetAttr {
        id: u64,
        mode: Option<u32>,
        atime_ns: Option<u64>,
        mtime_ns: Option<u64>,
    },
    /// A file's data, or a directory's entries, to the host's disk.
    Fsync {
        id: u64,
    },
    /// Just `name` in `dir` (for directories too big to list in full).
    Lookup {
        dir: u64,
        name: &'a str,
    },
    /// The guest is done with `id`, a file it removed while it had it
    /// open: the host can let go of it too. No answer.
    Forget {
        id: u64,
    },
    /// Report changes to `id` (a file, or a directory and its entries) as
    /// [`Notice`]s from now on. `Done`, or an errno (ENOSPC past
    /// `MAX_WATCHES`).
    Watch {
        id: u64,
    },
    /// No more notices about `id`. No answer.
    Unwatch {
        id: u64,
    },
    /// Another name, `name` in `dir`, for `id` (not a directory), within
    /// one mount: `Created` with the new name's id.
    Link {
        id: u64,
        dir: u64,
        name: &'a str,
    },
    /// The guest has `id`, a file, open or mapped (`write`: for writing
    /// too): hold on to the file it is now, until `Unpin`, whatever happens
    /// to its name. No answer: if it can't, `id` goes on meaning its name.
    Pin {
        id: u64,
        write: bool,
    },
    /// The guest has let go of `id`. No answer.
    Unpin {
        id: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListEntry<'a> {
    pub name: &'a str,
    pub id: u64,
    pub attr: Attr,
    /// A link's target ("" for anything else).
    pub target: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply<'a> {
    /// A Linux errno.
    Err(u16),
    /// The directory's own attributes and up to `LIST_MAX` entries; `more`
    /// if there are entries after the last.
    Listed {
        dir: Attr,
        entries: Vec<ListEntry<'a>>,
        more: bool,
    },
    Attr(Attr),
    Data(&'a [u8]),
    /// Bytes written, and the file's size after.
    Written {
        n: u32,
        size: u64,
    },
    Created {
        id: u64,
        attr: Attr,
    },
    Done,
    /// What `Lookup` found.
    Found {
        id: u64,
        attr: Attr,
        target: &'a str,
    },
}

fn opt(w: &mut Writer, v: Option<u64>) {
    match v {
        Some(v) => {
            w.u8(1);
            w.u64(v);
        }
        None => w.u8(0),
    }
}

fn get_opt(r: &mut Reader) -> Result<Option<u64>, DecodeError> {
    Ok(match r.u8()? {
        0 => None,
        1 => Some(r.u64()?),
        _ => return Err(DecodeError),
    })
}

fn get_str<'a>(r: &mut Reader<'a>) -> Result<&'a str, DecodeError> {
    let len = r.u32()? as usize;
    core::str::from_utf8(r.take(len)?).map_err(|_| DecodeError)
}

fn put_str(w: &mut Writer, s: &str) {
    w.u32(s.len() as u32);
    w.raw(s.as_bytes());
}

impl<'a> Request<'a> {
    /// The message for request number `seq`.
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(seq);
        match *self {
            Request::List { dir, after } => {
                w.u8(1);
                w.u64(dir);
                put_str(&mut w, after);
            }
            Request::Stat { id } => {
                w.u8(2);
                w.u64(id);
            }
            Request::Read { id, off, len } => {
                w.u8(3);
                w.u64(id);
                w.u64(off);
                w.u32(len);
            }
            Request::Write { id, off, append, data } => {
                w.u8(4);
                w.u64(id);
                w.u64(off);
                w.u8(append as u8);
                w.raw(data);
            }
            Request::SetLen { id, len } => {
                w.u8(5);
                w.u64(id);
                w.u64(len);
            }
            Request::Create { dir, name, ty, mode, target } => {
                w.u8(6);
                w.u64(dir);
                put_str(&mut w, name);
                w.u8(ty as u8);
                w.u32(mode);
                put_str(&mut w, target);
            }
            Request::Remove { dir, name, is_dir } => {
                w.u8(7);
                w.u64(dir);
                put_str(&mut w, name);
                w.u8(is_dir as u8);
            }
            Request::Rename { from_dir, from, to_dir, to, noreplace, exchange } => {
                w.u8(8);
                w.u64(from_dir);
                put_str(&mut w, from);
                w.u64(to_dir);
                put_str(&mut w, to);
                w.u8(noreplace as u8 | (exchange as u8) << 1);
            }
            Request::SetAttr { id, mode, atime_ns, mtime_ns } => {
                w.u8(9);
                w.u64(id);
                opt(&mut w, mode.map(u64::from));
                opt(&mut w, atime_ns);
                opt(&mut w, mtime_ns);
            }
            Request::Fsync { id } => {
                w.u8(10);
                w.u64(id);
            }
            Request::Lookup { dir, name } => {
                w.u8(11);
                w.u64(dir);
                put_str(&mut w, name);
            }
            Request::Forget { id } => {
                w.u8(12);
                w.u64(id);
            }
            Request::Watch { id } => {
                w.u8(13);
                w.u64(id);
            }
            Request::Pin { id, write } => {
                w.u8(16);
                w.u64(id);
                w.u8(write as u8);
            }
            Request::Unpin { id } => {
                w.u8(17);
                w.u64(id);
            }
            Request::Unwatch { id } => {
                w.u8(14);
                w.u64(id);
            }
            Request::Link { id, dir, name } => {
                w.u8(15);
                w.u64(id);
                w.u64(dir);
                put_str(&mut w, name);
            }
        }
        w.buf
    }

    /// (seq, request)
    pub fn decode(buf: &'a [u8]) -> Result<(u32, Self), DecodeError> {
        let mut r = Reader::new(buf);
        let seq = r.u32()?;
        let req = match r.u8()? {
            1 => Request::List { dir: r.u64()?, after: get_str(&mut r)? },
            2 => Request::Stat { id: r.u64()? },
            3 => Request::Read { id: r.u64()?, off: r.u64()?, len: r.u32()? },
            4 => {
                let (id, off) = (r.u64()?, r.u64()?);
                let append = r.u8()? != 0;
                Request::Write { id, off, append, data: r.rest() }
            }
            5 => Request::SetLen { id: r.u64()?, len: r.u64()? },
            6 => {
                let dir = r.u64()?;
                let name = get_str(&mut r)?;
                let ty = FileType::get(&mut r)?;
                Request::Create { dir, name, ty, mode: r.u32()?, target: get_str(&mut r)? }
            }
            7 => Request::Remove { dir: r.u64()?, name: get_str(&mut r)?, is_dir: r.u8()? != 0 },
            8 => {
                let from_dir = r.u64()?;
                let from = get_str(&mut r)?;
                let to_dir = r.u64()?;
                let to = get_str(&mut r)?;
                let flags = r.u8()?;
                if flags > 3 {
                    return Err(DecodeError);
                }
                Request::Rename { from_dir, from, to_dir, to, noreplace: flags & 1 != 0, exchange: flags & 2 != 0 }
            }
            9 => {
                let id = r.u64()?;
                let mode = get_opt(&mut r)?.map(|m| u32::try_from(m).map_err(|_| DecodeError)).transpose()?;
                Request::SetAttr { id, mode, atime_ns: get_opt(&mut r)?, mtime_ns: get_opt(&mut r)? }
            }
            10 => Request::Fsync { id: r.u64()? },
            11 => Request::Lookup { dir: r.u64()?, name: get_str(&mut r)? },
            12 => Request::Forget { id: r.u64()? },
            13 => Request::Watch { id: r.u64()? },
            14 => Request::Unwatch { id: r.u64()? },
            15 => Request::Link { id: r.u64()?, dir: r.u64()?, name: get_str(&mut r)? },
            16 => Request::Pin { id: r.u64()?, write: r.u8()? != 0 },
            17 => Request::Unpin { id: r.u64()? },
            _ => return Err(DecodeError),
        };
        r.done()?;
        Ok((seq, req))
    }
}

impl<'a> Reply<'a> {
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(seq);
        match self {
            Reply::Err(errno) => {
                w.u8(0);
                w.u32(*errno as u32);
            }
            Reply::Listed { dir, entries, more } => {
                w.u8(1);
                dir.put(&mut w);
                w.u8(*more as u8);
                w.u32(entries.len() as u32);
                for e in entries {
                    put_str(&mut w, e.name);
                    w.u64(e.id);
                    e.attr.put(&mut w);
                    put_str(&mut w, e.target);
                }
            }
            Reply::Attr(a) => {
                w.u8(2);
                a.put(&mut w);
            }
            Reply::Data(d) => {
                w.u8(3);
                w.raw(d);
            }
            Reply::Written { n, size } => {
                w.u8(4);
                w.u32(*n);
                w.u64(*size);
            }
            Reply::Created { id, attr } => {
                w.u8(5);
                w.u64(*id);
                attr.put(&mut w);
            }
            Reply::Done => w.u8(6),
            Reply::Found { id, attr, target } => {
                w.u8(7);
                w.u64(*id);
                attr.put(&mut w);
                put_str(&mut w, target);
            }
        }
        w.buf
    }

    /// (seq, reply)
    pub fn decode(buf: &'a [u8]) -> Result<(u32, Self), DecodeError> {
        let mut r = Reader::new(buf);
        let seq = r.u32()?;
        let reply = match r.u8()? {
            0 => Reply::Err(u16::try_from(r.u32()?).map_err(|_| DecodeError)?),
            1 => {
                let dir = Attr::get(&mut r)?;
                let more = r.u8()? != 0;
                let n = r.u32()? as usize;
                if n > LIST_MAX {
                    return Err(DecodeError);
                }
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    let name = get_str(&mut r)?;
                    let id = r.u64()?;
                    let attr = Attr::get(&mut r)?;
                    entries.push(ListEntry { name, id, attr, target: get_str(&mut r)? });
                }
                Reply::Listed { dir, entries, more }
            }
            2 => Reply::Attr(Attr::get(&mut r)?),
            3 => Reply::Data(r.rest()),
            4 => Reply::Written { n: r.u32()?, size: r.u64()? },
            5 => Reply::Created { id: r.u64()?, attr: Attr::get(&mut r)? },
            6 => Reply::Done,
            7 => {
                let id = r.u64()?;
                let attr = Attr::get(&mut r)?;
                Reply::Found { id, attr, target: get_str(&mut r)? }
            }
            _ => return Err(DecodeError),
        };
        r.done()?;
        Ok((seq, reply))
    }
}

/// A change the host saw in watched node `id`: inotify's `mask` (only
/// `mask::NOTICE` bits) and `cookie` (pairing a rename's two halves, or 0),
/// and the entry's `name` for a directory's entry ("" for the node itself).
/// Id 0 with `IN_Q_OVERFLOW`: the host lost track, notices were dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notice<'a> {
    pub id: u64,
    pub mask: u32,
    pub cookie: u32,
    pub name: &'a str,
}

impl<'a> Notice<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.id);
        w.u32(self.mask);
        w.u32(self.cookie);
        put_str(&mut w, self.name);
        w.buf
    }

    /// Only what a host may say: known bits, and a plain name of at most
    /// `NAME_MAX` bytes.
    pub fn decode(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(buf);
        let n = Notice { id: r.u64()?, mask: r.u32()?, cookie: r.u32()?, name: get_str(&mut r)? };
        r.done()?;
        let plain = n.name.is_empty() || (n.name != "." && n.name != ".." && !n.name.contains(['/', '\0']));
        if n.mask & !mask::NOTICE != 0 || n.name.len() > NAME_MAX || !plain {
            return Err(DecodeError);
        }
        Ok(n)
    }
}

/// The frame payloads carrying `msg`: each starts with 1 if more of the
/// message follows, 0 for the last.
pub fn frames(msg: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let n = msg.len().div_ceil(MAX_FRAME - 1).max(1);
    (0..n).map(move |i| {
        let chunk = &msg[(i * (MAX_FRAME - 1)).min(msg.len())..((i + 1) * (MAX_FRAME - 1)).min(msg.len())];
        ((i + 1 < n) as u8, chunk)
    })
}

/// Puts a message back together from frame payloads.
#[derive(Default)]
pub struct Assembler {
    buf: Vec<u8>,
    /// Over `MAX_MESSAGE` or malformed: dropped up to its last frame.
    bad: bool,
}

impl Assembler {
    /// The whole message, once its last frame is in; `Err` for one that was
    /// too long or empty.
    pub fn push(&mut self, payload: &[u8]) -> Option<Result<Vec<u8>, DecodeError>> {
        let Some((&more, chunk)) = payload.split_first() else {
            self.bad = true;
            return None;
        };
        if self.buf.len() + chunk.len() > MAX_MESSAGE || more > 1 {
            self.bad = true;
        }
        // What's held here reaches MAX_MESSAGE, and the guest's heap may
        // have no such hole.
        if !self.bad && self.buf.try_reserve(chunk.len()).is_err() {
            self.bad = true;
        }
        if !self.bad {
            self.buf.extend_from_slice(chunk);
        }
        if more == 1 {
            return None;
        }
        let msg = core::mem::take(&mut self.buf);
        Some(if core::mem::take(&mut self.bad) { Err(DecodeError) } else { Ok(msg) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const A: Attr = Attr { ty: FileType::File, mode: 0o644, size: 3, atime_ns: 1, mtime_ns: 2, ctime_ns: 3 };

    #[test]
    fn roundtrip() {
        let reqs = [
            Request::List { dir: 1, after: "b" },
            Request::Stat { id: 9 },
            Request::Read { id: 9, off: 4096, len: 100 },
            Request::Write { id: 9, off: 0, append: true, data: b"hi" },
            Request::SetLen { id: 9, len: 0 },
            Request::Create { dir: 1, name: "l", ty: FileType::Symlink, mode: 0o777, target: "x" },
            Request::Remove { dir: 1, name: "d", is_dir: true },
            Request::Rename { from_dir: 1, from: "a", to_dir: 2, to: "b", noreplace: true, exchange: false },
            Request::Rename { from_dir: 1, from: "a", to_dir: 2, to: "b", noreplace: false, exchange: true },
            Request::Link { id: 9, dir: 1, name: "again" },
            Request::SetAttr { id: 9, mode: Some(0o600), atime_ns: None, mtime_ns: Some(5) },
            Request::Fsync { id: 9 },
            Request::Lookup { dir: 1, name: "x" },
            Request::Forget { id: 9 },
            Request::Watch { id: 9 },
            Request::Unwatch { id: 9 },
            Request::Pin { id: 9, write: true },
            Request::Pin { id: 9, write: false },
            Request::Unpin { id: 9 },
        ];
        for r in reqs {
            assert_eq!(Request::decode(&r.encode(7)), Ok((7, r)));
        }
        let replies = [
            Reply::Err(2),
            Reply::Listed { dir: A, entries: vec![ListEntry { name: "a", id: 3, attr: A, target: "" }], more: true },
            Reply::Attr(A),
            Reply::Data(b"abc"),
            Reply::Written { n: 2, size: 5 },
            Reply::Created { id: 4, attr: A },
            Reply::Done,
            Reply::Found { id: 5, attr: A, target: "t" },
        ];
        for r in replies {
            assert_eq!(Reply::decode(&r.encode(3)), Ok((3, r)));
        }
        assert!(Request::decode(&[0, 0, 0, 0, 99]).is_err());
        assert!(Reply::decode(&[0, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn notices_say_only_what_a_host_may() {
        let n = Notice { id: 3, mask: mask::IN_CREATE | mask::IN_ISDIR, cookie: 0, name: "d" };
        assert_eq!(Notice::decode(&n.encode()), Ok(n));
        let n = Notice { id: 3, mask: mask::IN_DELETE_SELF, cookie: 0, name: "" };
        assert_eq!(Notice::decode(&n.encode()), Ok(n));
        let long = "x".repeat(NAME_MAX + 1);
        for bad in [
            Notice { id: 3, mask: mask::IN_OPEN, cookie: 0, name: "a" },
            Notice { id: 3, mask: 1 << 20, cookie: 0, name: "a" },
            Notice { id: 3, mask: mask::IN_CREATE, cookie: 0, name: ".." },
            Notice { id: 3, mask: mask::IN_CREATE, cookie: 0, name: "a/b" },
            Notice { id: 3, mask: mask::IN_CREATE, cookie: 0, name: "a\0" },
            Notice { id: 3, mask: mask::IN_CREATE, cookie: 0, name: &long },
        ] {
            assert!(Notice::decode(&bad.encode()).is_err(), "{bad:?}");
        }
        assert!(Notice::decode(&[1, 2, 3]).is_err());
    }

    #[test]
    fn messages_span_frames() {
        let msg: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let mut a = Assembler::default();
        let mut out = None;
        for (more, chunk) in frames(&msg) {
            let mut payload = vec![more];
            payload.extend_from_slice(chunk);
            assert!(payload.len() <= MAX_FRAME);
            out = a.push(&payload);
        }
        assert_eq!(out, Some(Ok(msg)));
        // An empty message is one frame; a bad flag spoils the message.
        assert_eq!(frames(&[]).count(), 1);
        assert_eq!(a.push(&[0]), Some(Ok(vec![])));
        assert_eq!(a.push(&[7, 1]), Some(Err(DecodeError)));
        assert_eq!(a.push(&[0, 1]), Some(Ok(vec![1])));
    }
}
