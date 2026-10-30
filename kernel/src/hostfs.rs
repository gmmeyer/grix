//! Live mounts, the guest's side (`grix_abi::hostfs`): requests to the host
//! for directory listings, file bytes and changes. `fs.rs` keeps the nodes;
//! this only talks to the host, one request at a time (`console::host_request`).
//!
//! Reads go to the host every time, except that each one asks for up to
//! `IO_MAX` bytes and a few recent answers are kept for a moment, so small
//! sequential reads and page faults don't each cost a round trip. Writes
//! (and anything else that changes a file) drop what's kept of it.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use grix_abi::hostfs::{Attr, FileType, IO_MAX, Reply, Request};
use spin::Mutex;

use crate::console::{self, klog};
use crate::errno::*;

static SEQ: AtomicU32 = AtomicU32::new(1);

/// How long what the host said stays good: attributes, listings and kept
/// reads. Changes on the host show up after this.
pub const FRESH_NS: u64 = 1_000_000_000;

/// Send `req` and decode the answer with `f` (which sees errors too).
fn call<T>(req: &Request, f: impl FnOnce(Reply) -> Result<T, Errno>) -> Result<T, Errno> {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let msg = console::host_request(&req.encode(seq));
    match Reply::decode(&msg) {
        Ok((s, Reply::Err(errno))) if s == seq => Err(Errno(errno.max(1) as u32)),
        Ok((s, reply)) if s == seq => f(reply),
        _ => {
            klog!("hostfs: bad answer from the host\n");
            Err(EIO)
        }
    }
}

fn unexpected<T>() -> Result<T, Errno> {
    klog!("hostfs: unexpected answer from the host\n");
    Err(EIO)
}

pub struct Entry {
    pub name: String,
    pub id: u64,
    pub attr: Attr,
    pub target: String,
}

/// Directory `dir`'s attributes and up to a page of its entries after
/// `after`, in name order; and whether there are more.
pub fn list(dir: u64, after: &str) -> Result<(Attr, Vec<Entry>, bool), Errno> {
    call(&Request::List { dir, after }, |r| match r {
        Reply::Listed { dir, entries, more } => {
            let entries = entries
                .into_iter()
                .map(|e| Entry { name: e.name.to_string(), id: e.id, attr: e.attr, target: e.target.to_string() })
                .collect();
            Ok((dir, entries, more))
        }
        _ => unexpected(),
    })
}

pub fn stat(id: u64) -> Result<Attr, Errno> {
    call(&Request::Stat { id }, |r| match r {
        Reply::Attr(a) => Ok(a),
        _ => unexpected(),
    })
}

/// A recent read: `data` is file `id`'s bytes at `off`.
struct Kept {
    id: u64,
    off: u64,
    data: Vec<u8>,
    at: u64,
}

/// A few recent reads, the most recent last.
static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());
const KEEP: usize = 4;

/// Drop what's kept of file `id` (it's changing).
fn drop_kept(id: u64) {
    KEPT.lock().retain(|k| k.id != id);
}

/// Tell the host the guest is done with `id`, a file it removed while it
/// was open (the host kept it open too).
pub fn release(id: u64) {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    console::host_send(&Request::Forget { id }.encode(seq));
}

/// Just `name` in directory `dir`.
pub fn lookup(dir: u64, name: &str) -> Result<Entry, Errno> {
    call(&Request::Lookup { dir, name }, |r| match r {
        Reply::Found { id, attr, target } => Ok(Entry { name: name.to_string(), id, attr, target: target.to_string() }),
        _ => unexpected(),
    })
}

/// Ask the host to report changes to `id` (`grix_abi::hostfs::Notice`).
pub fn watch(id: u64) -> Result<(), Errno> {
    done(&Request::Watch { id })
}

/// The host can stop reporting changes to `id`.
pub fn unwatch(id: u64) {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    console::host_send(&Request::Unwatch { id }.encode(seq));
}

/// What was read ahead goes (a restored snapshot, or the host said files
/// changed: it may be old).
pub fn forget_kept() {
    KEPT.lock().clear();
}

/// Bytes of file `id` at `off` into `out`; fewer at the end of the file.
pub fn read(id: u64, off: u64, out: &mut [u8]) -> Result<usize, Errno> {
    let now = crate::time::monotonic_ns();
    let mut done = 0;
    while done < out.len() {
        let pos = off + done as u64;
        {
            let mut kept = KEPT.lock();
            kept.retain(|k| now.saturating_sub(k.at) < FRESH_NS);
            if let Some(k) = kept.iter().find(|k| k.id == id && k.off <= pos && pos < k.off + k.data.len() as u64) {
                let from = (pos - k.off) as usize;
                let n = (out.len() - done).min(k.data.len() - from);
                out[done..done + n].copy_from_slice(&k.data[from..from + n]);
                done += n;
                continue;
            }
        }
        let want = (out.len() - done).clamp(IO_MAX / 4, IO_MAX);
        let data = call(&Request::Read { id, off: pos, len: want as u32 }, |r| match r {
            Reply::Data(d) if d.len() <= want => Ok(d.to_vec()),
            _ => unexpected(),
        })?;
        let n = (out.len() - done).min(data.len());
        out[done..done + n].copy_from_slice(&data[..n]);
        done += n;
        let end = data.len() < want;
        let mut kept = KEPT.lock();
        if kept.len() >= KEEP {
            kept.remove(0);
        }
        kept.push(Kept { id, off: pos, data, at: now });
        if end {
            break;
        }
    }
    Ok(done)
}

/// Write `data` (at most `IO_MAX` bytes) at `off`, or at the end. Returns
/// how much was written and the file's size after.
pub fn write(id: u64, off: u64, append: bool, data: &[u8]) -> Result<(usize, u64), Errno> {
    drop_kept(id);
    call(&Request::Write { id, off, append, data }, |r| match r {
        Reply::Written { n, size } if n as usize <= data.len() => Ok((n as usize, size)),
        _ => unexpected(),
    })
}

fn done(req: &Request) -> Result<(), Errno> {
    call(req, |r| match r {
        Reply::Done => Ok(()),
        _ => unexpected(),
    })
}

pub fn set_len(id: u64, len: u64) -> Result<(), Errno> {
    drop_kept(id);
    done(&Request::SetLen { id, len })
}

pub fn fsync(id: u64) -> Result<(), Errno> {
    done(&Request::Fsync { id })
}

/// Create `name` in `dir`: (its id, its attributes).
pub fn create(dir: u64, name: &str, ty: FileType, mode: u32, target: &str) -> Result<(u64, Attr), Errno> {
    call(&Request::Create { dir, name, ty, mode, target }, |r| match r {
        Reply::Created { id, attr } => Ok((id, attr)),
        _ => unexpected(),
    })
}

pub fn remove(dir: u64, name: &str, is_dir: bool) -> Result<(), Errno> {
    done(&Request::Remove { dir, name, is_dir })
}

pub fn rename(from_dir: u64, from: &str, to_dir: u64, to: &str, noreplace: bool, exchange: bool) -> Result<(), Errno> {
    done(&Request::Rename { from_dir, from, to_dir, to, noreplace, exchange })
}

/// Another name for `id`: `name` in `dir` (its id, its attributes).
pub fn link(id: u64, dir: u64, name: &str) -> Result<(u64, Attr), Errno> {
    call(&Request::Link { id, dir, name }, |r| match r {
        Reply::Created { id, attr } => Ok((id, attr)),
        _ => unexpected(),
    })
}

pub fn set_attr(id: u64, mode: Option<u32>, atime_ns: Option<u64>, mtime_ns: Option<u64>) -> Result<Attr, Errno> {
    drop_kept(id);
    call(&Request::SetAttr { id, mode, atime_ns, mtime_ns }, |r| match r {
        Reply::Attr(a) => Ok(a),
        _ => unexpected(),
    })
}
