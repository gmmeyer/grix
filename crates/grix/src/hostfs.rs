//! The host end of live mounts (`grix_abi::hostfs`): a small file server
//! for the guest kernel, confined to the mounted directories.
//!
//! Every request is untrusted. Paths are never built as strings: each one
//! is walked from the mount's directory with `openat` and `O_NOFOLLOW`, one
//! checked name at a time, so no link (the program's or anyone's) can lead
//! out of the mount. Read-only mounts refuse every change.
//!
//! Nodes the guest's inotify watches are watched on the host too
//! (`watch.rs`), through descriptors opened the same way; lazy imports
//! never change for the guest, so they aren't.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use grix_abi::hostfs::{self, Assembler, Attr, FileType, IO_MAX, LIST_MAX, ListEntry, MAX_MESSAGE, Reply, Request};
use grix_abi::wire::{self, Input};

use crate::at::{check, openat, read_dir, readlink_at, rename, stat_at, stat_fd};

/// A directory mounted live.
#[derive(Clone, Debug)]
pub(crate) struct LiveMount {
    /// Canonical.
    pub host: PathBuf,
    pub guest: String,
    pub writable: bool,
    /// A lazy import: read-only here, and each file's bytes must stay what
    /// they were when the guest first saw it (size and modification time),
    /// or reading it fails with EIO rather than mixing old and new.
    pub lazy: bool,
}

// Linux errnos, as the guest wants them.
const EPERM: u16 = 1;
const EIO: u16 = 5;
const ENOMEM: u16 = 12;
const EXDEV: u16 = 18;
const EISDIR: u16 = 21;
const EINVAL: u16 = 22;
const EROFS: u16 = 30;
const ENAMETOOLONG: u16 = 36;
const EOPNOTSUPP: u16 = 95;
const ESTALE: u16 = 116;

/// Ids the host keeps track of (everything listed or created), and their
/// names' bytes (each name is kept twice): a tree of long names reaches
/// the second first, so the host's memory is bounded either way.
const MAX_IDS: usize = 1_000_000;
const MAX_ID_BYTES: usize = 64 << 20;
/// `Server::save`'s format.
const STATE_VERSION: u32 = 1;
/// Directory entries of lazy imports kept as first listed, and their names'
/// and link targets' bytes.
const MAX_FROZEN: usize = 4_000_000;
const MAX_FROZEN_BYTES: usize = 64 << 20;
/// Files kept open between requests.
const OPEN_FILES: usize = 32;
/// Files the guest removed while it may still have them open.
const KEPT_OPEN: usize = 128;

/// A host error as a Linux errno.
pub(crate) fn linux_errno(e: &io::Error) -> u16 {
    let Some(raw) = e.raw_os_error() else { return EIO };
    if cfg!(target_os = "linux") {
        return raw as u16;
    }
    match raw {
        libc::EPERM => 1,
        libc::ENOENT => 2,
        libc::EIO => 5,
        libc::EBADF => 9,
        libc::ENOMEM => 12,
        libc::EACCES => 13,
        libc::EBUSY => 16,
        libc::EEXIST => 17,
        libc::EXDEV => 18,
        libc::ENOTDIR => 20,
        libc::EISDIR => 21,
        libc::EINVAL => 22,
        libc::ETXTBSY => 26,
        libc::EFBIG => 27,
        libc::ENOSPC => 28,
        libc::EROFS => 30,
        libc::EMLINK => 31,
        libc::ENAMETOOLONG => 36,
        libc::ENOTEMPTY => 39,
        libc::ELOOP => 40,
        // The same number on Linux, two on macOS.
        #[allow(unreachable_patterns)]
        libc::ENOTSUP | libc::EOPNOTSUPP => 95,
        libc::EDQUOT => 122,
        _ => EIO,
    }
}

fn err(e: io::Error) -> u16 {
    linux_errno(&e)
}

/// A name the guest may use: one plain component.
fn cname(name: &str) -> Result<CString, u16> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(EINVAL);
    }
    if name.len() > 255 {
        return Err(ENAMETOOLONG);
    }
    CString::new(name).map_err(|_| EINVAL)
}

fn ns(sec: i64, nsec: i64) -> u64 {
    (sec.max(0) as u64).saturating_mul(1_000_000_000).saturating_add(nsec.max(0) as u64)
}

/// The guest's view of `st`; None for what it can't see (sockets, FIFOs,
/// devices). (The casts are for the field types that differ by platform.)
#[allow(clippy::unnecessary_cast)]
fn attr_of(st: &libc::stat) -> Option<Attr> {
    let fmt = st.st_mode as u32 & libc::S_IFMT as u32;
    let ty = if fmt == libc::S_IFREG as u32 {
        FileType::File
    } else if fmt == libc::S_IFDIR as u32 {
        FileType::Dir
    } else if fmt == libc::S_IFLNK as u32 {
        FileType::Symlink
    } else {
        return None;
    };
    Some(Attr {
        ty,
        mode: st.st_mode as u32 & 0o7777,
        size: st.st_size as u64,
        atime_ns: ns(st.st_atime as i64, st.st_atime_nsec as i64),
        mtime_ns: ns(st.st_mtime as i64, st.st_mtime_nsec as i64),
        ctime_ns: ns(st.st_ctime as i64, st.st_ctime_nsec as i64),
    })
}

/// A directory's entries the guest can see, sorted: (name, attributes,
/// link target).
fn read_entries(d: RawFd) -> Result<Vec<(String, Attr, String)>, u16> {
    let mut entries = Vec::new();
    for name in read_dir(d).map_err(err)? {
        // Names the guest can't hold, and things it can't see, are left out.
        let Ok(s) = name.to_str() else { continue };
        if s.len() > 255 {
            continue;
        }
        let Ok(st) = stat_at(d, &name) else { continue };
        let Some(attr) = attr_of(&st) else { continue };
        let target = match attr.ty {
            FileType::Symlink => match readlink_at(d, &name).map(String::from_utf8) {
                Ok(Ok(t)) if !t.is_empty() => t,
                _ => continue,
            },
            _ => String::new(),
        };
        entries.push((s.to_string(), attr, target));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

struct Node {
    parent: u64,
    name: String,
}

/// One listed directory's entries, sorted, kept while the guest pages
/// through them.
struct Listing {
    dir: u64,
    entries: Vec<(String, Attr, String)>,
}

pub(crate) struct Server {
    /// Each mount's directory, and whether it's writable. Mount i's root
    /// has id i + 1.
    roots: Vec<(OwnedFd, bool)>,
    /// Which mounts are lazy imports, and what the guest first saw of
    /// them: each node's attributes, and each directory's entries (up to
    /// `MAX_FROZEN` in all, beyond which directories are read as they are).
    lazy: Vec<bool>,
    attrs: HashMap<u64, Attr>,
    frozen: HashMap<u64, Vec<(String, Attr, String)>>,
    frozen_entries: usize,
    frozen_bytes: usize,
    nodes: HashMap<u64, Node>,
    /// Bytes of `nodes`' names.
    id_bytes: usize,
    by_name: HashMap<(u64, String), u64>,
    next_id: u64,
    /// (id, writable, descriptor), most recently used last.
    files: Vec<(u64, bool, OwnedFd)>,
    /// Files the guest removed, or renamed something over, kept open (id,
    /// writable, descriptor) so it can go on using them as on Linux, until
    /// it says it's done with them (`Forget`) or room is needed.
    kept: VecDeque<(u64, bool, OwnedFd)>,
    listing: Option<Listing>,
    assembler: Assembler,
    /// Where notices of watched nodes' changes go (frames for the guest),
    /// and the watcher, once something is watched.
    notices: Option<NoticeSink>,
    watcher: Option<crate::watch::Watcher>,
}

/// Sends a frame to the guest; false once it's gone.
pub(crate) type NoticeSink = std::sync::Arc<dyn Fn(Vec<u8>) -> bool + Send + Sync>;

impl Server {
    pub fn new(mounts: &[LiveMount]) -> Result<Server> {
        let mut roots = Vec::new();
        for m in mounts {
            // Walked down to like everything in it: a link swapped in on
            // the way since it was made canonical can't move the mount.
            let fd = crate::at::open_dir(&m.host).with_context(|| format!("mounting {}", m.host.display()))?;
            roots.push((fd, m.writable && !m.lazy));
        }
        Ok(Server {
            next_id: roots.len() as u64 + 1,
            roots,
            lazy: mounts.iter().map(|m| m.lazy).collect(),
            attrs: HashMap::new(),
            frozen: HashMap::new(),
            frozen_entries: 0,
            frozen_bytes: 0,
            nodes: HashMap::new(),
            id_bytes: 0,
            by_name: HashMap::new(),
            files: Vec::new(),
            kept: VecDeque::new(),
            listing: None,
            assembler: Assembler::default(),
            notices: None,
            watcher: None,
        })
    }

    /// Changes to watched nodes go to the guest through `send`.
    pub fn notify(&mut self, send: NoticeSink) {
        self.notices = Some(send);
    }

    /// What a snapshot keeps of the server, for runs restored from it:
    /// the ids it gave out (each a name in its parent), and what the guest
    /// first saw of lazy imports. Not open files: they're opened again.
    pub fn save(&self) -> Vec<u8> {
        use grix_abi::codec::Writer;
        let mut w = Writer::default();
        w.u32(STATE_VERSION);
        w.u32(self.roots.len() as u32);
        w.u64(self.next_id);
        let mut nodes: Vec<(&u64, &Node)> = self.nodes.iter().collect();
        nodes.sort_by_key(|(id, _)| **id);
        w.u32(nodes.len() as u32);
        for (id, n) in nodes {
            w.u64(*id);
            w.u64(n.parent);
            w.str(&n.name);
        }
        // In order of id, so the same state saves the same.
        let mut attrs: Vec<(&u64, &Attr)> = self.attrs.iter().collect();
        attrs.sort_by_key(|(id, _)| **id);
        w.u32(attrs.len() as u32);
        for (id, a) in attrs {
            w.u64(*id);
            a.put(&mut w);
        }
        let mut frozen: Vec<_> = self.frozen.iter().collect();
        frozen.sort_by_key(|(id, _)| **id);
        w.u32(frozen.len() as u32);
        for (dir, entries) in frozen {
            w.u64(*dir);
            w.u32(entries.len() as u32);
            for (name, attr, target) in entries {
                w.str(name);
                attr.put(&mut w);
                w.str(target);
            }
        }
        w.buf
    }

    /// A server for `mounts` that goes on from `state` (`save`'s). It may
    /// come from anyone's snapshot file: every name is one plain component,
    /// every id's parent came before it, and nothing exceeds the limits, or
    /// it's refused.
    pub fn restore(mounts: &[LiveMount], state: &[u8]) -> Result<Server> {
        use grix_abi::codec::Reader;
        let mut s = Server::new(mounts)?;
        let bad = |what: &str| anyhow::anyhow!("the snapshot's mount state is bad ({what})");
        let mut r = Reader::new(state);
        let d = |_| bad("cut off");
        if r.u32().map_err(d)? != STATE_VERSION {
            return Err(bad("version"));
        }
        if r.u32().map_err(d)? as usize != s.roots.len() {
            bail!("the snapshot had another number of live mounts");
        }
        let roots = s.roots.len() as u64;
        let next_id = r.u64().map_err(d)?;
        let n = r.u32().map_err(d)? as usize;
        if n > MAX_IDS || next_id > roots + 1 + MAX_IDS as u64 * 4 {
            return Err(bad("too many ids"));
        }
        let mut last = roots;
        for _ in 0..n {
            let (id, parent) = (r.u64().map_err(d)?, r.u64().map_err(d)?);
            let name = r.str().map_err(d)?;
            cname(name).map_err(|_| bad("a name"))?;
            // Sorted, and each after the one it's in.
            if id <= last || id >= next_id || parent >= id || (parent > roots && !s.nodes.contains_key(&parent)) {
                return Err(bad("an id"));
            }
            if parent == 0 || s.by_name.insert((parent, name.to_string()), id).is_some() {
                return Err(bad("a parent"));
            }
            s.id_bytes += name.len();
            if s.id_bytes > MAX_ID_BYTES {
                return Err(bad("too many ids"));
            }
            s.nodes.insert(id, Node { parent, name: name.to_string() });
            last = id;
        }
        s.next_id = next_id.max(roots + 1);
        let known = |s: &Server, id: u64| (1..=roots).contains(&id) || s.nodes.contains_key(&id);
        let n = r.u32().map_err(d)? as usize;
        if n > MAX_IDS {
            return Err(bad("too many attributes"));
        }
        for _ in 0..n {
            let id = r.u64().map_err(d)?;
            let a = Attr::get(&mut r).map_err(d)?;
            if !known(&s, id) || !s.is_lazy(id) {
                return Err(bad("an attribute"));
            }
            s.attrs.insert(id, a);
        }
        let n = r.u32().map_err(d)? as usize;
        for _ in 0..n {
            let dir = r.u64().map_err(d)?;
            let count = r.u32().map_err(d)? as usize;
            if !known(&s, dir) || !s.is_lazy(dir) || s.frozen_entries + count > MAX_FROZEN {
                return Err(bad("a listing"));
            }
            let mut entries = Vec::with_capacity(count.min(4096));
            for _ in 0..count {
                let name = r.str().map_err(d)?;
                cname(name).map_err(|_| bad("a listed name"))?;
                let attr = Attr::get(&mut r).map_err(d)?;
                let target = r.str().map_err(d)?;
                s.frozen_bytes += name.len() + target.len();
                if s.frozen_bytes > MAX_FROZEN_BYTES {
                    return Err(bad("a listing"));
                }
                entries.push((name.to_string(), attr, target.to_string()));
            }
            s.frozen_entries += count;
            s.frozen.insert(dir, entries);
        }
        r.done().map_err(d)?;
        Ok(s)
    }

    /// A `Channel::Fs` frame from the guest. Returns the frames of the
    /// reply, once a whole request has arrived.
    pub fn handle(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let Some(msg) = self.assembler.push(payload) else { return Vec::new() };
        let reply = match msg.as_deref().map_err(|_| ()).and_then(|m| Request::decode(m).map_err(|_| ())) {
            // One way: the guest doesn't wait for an answer.
            Ok((_, Request::Forget { id })) => {
                self.kept.retain(|k| k.0 != id);
                return Vec::new();
            }
            Ok((_, Request::Unwatch { id })) => {
                if let Some(w) = &self.watcher {
                    w.remove(id);
                }
                return Vec::new();
            }
            Ok((seq, req)) => match self.serve(req) {
                Ok(bytes) => {
                    let mut b = seq.to_le_bytes().to_vec();
                    b.extend_from_slice(&bytes[4..]);
                    b
                }
                Err(errno) => Reply::Err(errno).encode(seq),
            },
            // Garbled: answer what it seems to be, so the guest doesn't wait.
            Err(()) => {
                let seq = msg.ok().and_then(|m| m.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())));
                Reply::Err(EINVAL).encode(seq.unwrap_or(0))
            }
        };
        hostfs::frames(&reply)
            .map(|(more, chunk)| {
                let mut f = wire::input_header(Input::Fs, chunk.len() + 1).to_vec();
                f.push(more);
                f.extend_from_slice(chunk);
                f
            })
            .collect()
    }

    /// Serve one request: its encoded reply (with a placeholder sequence
    /// number), or an errno.
    fn serve(&mut self, req: Request) -> Result<Vec<u8>, u16> {
        let ok = |r: Reply| Ok(r.encode(0));
        match req {
            Request::List { dir, after } => self.list(dir, after),
            Request::Stat { id } => {
                let attr = self.stat(id)?;
                ok(Reply::Attr(self.saw(id, &attr)))
            }
            Request::Read { id, off, len } => {
                let fd = self.file(id, false)?;
                self.unchanged(id, fd)?;
                let mut buf = vec![0u8; (len as usize).min(IO_MAX)];
                let mut done = 0;
                while done < buf.len() {
                    // SAFETY: pread writes into the rest of `buf`.
                    let n = unsafe {
                        libc::pread(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done, (off + done as u64) as i64)
                    };
                    match n {
                        0 => break,
                        n if n < 0 => {
                            let e = io::Error::last_os_error();
                            if e.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            return Err(err(e));
                        }
                        n => done += n as usize,
                    }
                }
                ok(Reply::Data(&buf[..done]))
            }
            Request::Write { id, off, append, data } => {
                self.writable(id)?;
                if data.len() > IO_MAX {
                    return Err(EINVAL);
                }
                let fd = self.file(id, true)?;
                let off = if append { stat_fd(fd).map_err(err)?.st_size as u64 } else { off };
                let mut done = 0;
                while done < data.len() {
                    // SAFETY: pwrite reads from the rest of `data`.
                    let n = unsafe {
                        libc::pwrite(fd, data[done..].as_ptr().cast(), data.len() - done, (off + done as u64) as i64)
                    };
                    if n < 0 {
                        let e = io::Error::last_os_error();
                        if e.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        if done > 0 {
                            break;
                        }
                        return Err(err(e));
                    }
                    done += n as usize;
                }
                let size = stat_fd(fd).map_err(err)?.st_size as u64;
                ok(Reply::Written { n: done as u32, size })
            }
            Request::SetLen { id, len } => {
                self.writable(id)?;
                let fd = self.file(id, true)?;
                // SAFETY: ftruncate on a descriptor we hold.
                check(unsafe { libc::ftruncate(fd, len.min(i64::MAX as u64) as i64) }).map_err(err)?;
                ok(Reply::Done)
            }
            Request::Create { dir, name, ty, mode, target } => {
                self.writable(dir)?;
                let c = cname(name)?;
                let d = self.dir(dir)?;
                // No setuid or setgid from the sandbox; the host's umask applies.
                let mode = mode & 0o1777;
                match ty {
                    FileType::File => {
                        openat(d.as_raw_fd(), &c, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, mode)
                            .map_err(err)?;
                    }
                    // SAFETY: plain calls on a descriptor we hold and checked names.
                    FileType::Dir => {
                        check(unsafe { libc::mkdirat(d.as_raw_fd(), c.as_ptr(), mode as libc::mode_t) })
                            .map_err(err)?;
                    }
                    FileType::Symlink => {
                        if target.is_empty() || target.len() > 4095 {
                            return Err(EINVAL);
                        }
                        let t = CString::new(target).map_err(|_| EINVAL)?;
                        check(unsafe { libc::symlinkat(t.as_ptr(), d.as_raw_fd(), c.as_ptr()) }).map_err(err)?;
                    }
                }
                let attr = stat_at(d.as_raw_fd(), &c).map_err(err).and_then(|st| attr_of(&st).ok_or(EIO))?;
                let id = self.id(dir, name)?;
                self.saw(id, &attr);
                ok(Reply::Created { id, attr })
            }
            Request::Remove { dir, name, is_dir } => {
                self.writable(dir)?;
                let c = cname(name)?;
                let d = self.dir(dir)?;
                let keep = if is_dir { None } else { self.open_to_keep(dir, name, d.as_raw_fd(), &c) };
                let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
                // SAFETY: unlinkat never follows a link in the last component.
                check(unsafe { libc::unlinkat(d.as_raw_fd(), c.as_ptr(), flags) }).map_err(err)?;
                self.keep(keep);
                self.forget(dir, name);
                ok(Reply::Done)
            }
            Request::Rename { from_dir, from, to_dir, to, noreplace, exchange } => {
                self.writable(from_dir)?;
                if self.mount_of(from_dir)? != self.mount_of(to_dir)? {
                    return Err(EXDEV);
                }
                let (cf, ct) = (cname(from)?, cname(to)?);
                let (df, dt) = (self.dir(from_dir)?, self.dir(to_dir)?);
                if exchange {
                    rename(df.as_raw_fd(), &cf, dt.as_raw_fd(), &ct, false, true).map_err(err)?;
                    // Each id now names what the other did.
                    let a = self.by_name.remove(&(from_dir, from.to_string()));
                    let b = self.by_name.remove(&(to_dir, to.to_string()));
                    for (id, dir, name) in [(a, to_dir, to), (b, from_dir, from)] {
                        if let Some(id) = id {
                            self.nodes.insert(id, Node { parent: dir, name: name.to_string() });
                            self.by_name.insert((dir, name.to_string()), id);
                        }
                    }
                    return ok(Reply::Done);
                }
                let keep = if noreplace { None } else { self.open_to_keep(to_dir, to, dt.as_raw_fd(), &ct) };
                rename(df.as_raw_fd(), &cf, dt.as_raw_fd(), &ct, noreplace, false).map_err(err)?;
                self.keep(keep);
                self.forget(to_dir, to);
                if let Some(id) = self.by_name.remove(&(from_dir, from.to_string())) {
                    self.id_bytes = (self.id_bytes + to.len()).saturating_sub(from.len());
                    self.nodes.insert(id, Node { parent: to_dir, name: to.to_string() });
                    self.by_name.insert((to_dir, to.to_string()), id);
                }
                ok(Reply::Done)
            }
            Request::Link { id, dir, name } => {
                self.writable(dir)?;
                if self.mount_of(id)? != self.mount_of(dir)? {
                    return Err(EXDEV);
                }
                // A mount's root is a directory: no links to those.
                let (pd, pname) = self.parent(id)?.ok_or(EPERM)?;
                let c = cname(name)?;
                let d = self.dir(dir)?;
                // SAFETY: linkat on descriptors we hold and checked names;
                // without AT_SYMLINK_FOLLOW it links a link, not its target.
                check(unsafe { libc::linkat(pd.as_raw_fd(), pname.as_ptr(), d.as_raw_fd(), c.as_ptr(), 0) })
                    .map_err(err)?;
                let attr = stat_at(d.as_raw_fd(), &c).map_err(err).and_then(|st| attr_of(&st).ok_or(EIO))?;
                let id = self.id(dir, name)?;
                self.saw(id, &attr);
                ok(Reply::Created { id, attr })
            }
            Request::SetAttr { id, mode, atime_ns, mtime_ns } => {
                self.writable(id)?;
                let fd = self.open_node(id)?;
                if let Some(mode) = mode {
                    // SAFETY: fchmod on a descriptor we hold.
                    check(unsafe { libc::fchmod(fd.as_raw_fd(), (mode & 0o1777) as libc::mode_t) }).map_err(err)?;
                }
                if atime_ns.is_some() || mtime_ns.is_some() {
                    let t = |v: Option<u64>| match v {
                        Some(ns) => {
                            libc::timespec { tv_sec: (ns / 1_000_000_000) as _, tv_nsec: (ns % 1_000_000_000) as _ }
                        }
                        None => libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT as _ },
                    };
                    let times = [t(atime_ns), t(mtime_ns)];
                    // SAFETY: futimens reads two timespecs.
                    check(unsafe { libc::futimens(fd.as_raw_fd(), times.as_ptr()) }).map_err(err)?;
                }
                let st = stat_fd(fd.as_raw_fd()).map_err(err)?;
                ok(Reply::Attr(attr_of(&st).ok_or(EIO)?))
            }
            Request::Fsync { id } => {
                // SAFETY: fsync on descriptors we hold.
                if self.kept.iter().all(|k| k.0 != id) && self.stat(id)?.ty == FileType::Dir {
                    let d = self.dir(id)?;
                    check(unsafe { libc::fsync(d.as_raw_fd()) }).map_err(err)?;
                } else {
                    let writable = self.writable(id).is_ok();
                    let fd = self.file(id, writable)?;
                    check(unsafe { libc::fsync(fd) }).map_err(err)?;
                }
                ok(Reply::Done)
            }
            // A lazy import's: from its directory as first listed.
            Request::Lookup { dir, name } if self.is_lazy(dir) => {
                cname(name)?;
                let find = |entries: &[(String, Attr, String)]| {
                    let i = entries.binary_search_by(|e| e.0.as_str().cmp(name)).map_err(|_| 2u16)?;
                    Ok::<_, u16>((entries[i].1, entries[i].2.clone()))
                };
                let (attr, target) = match self.frozen.get(&dir) {
                    Some(entries) => find(entries)?,
                    None => {
                        let d = self.dir(dir)?;
                        find(&self.entries(dir, d.as_raw_fd())?)?
                    }
                };
                let id = self.id(dir, name)?;
                let attr = self.saw(id, &attr);
                ok(Reply::Found { id, attr, target: &target })
            }
            Request::Lookup { dir, name } => {
                let c = cname(name)?;
                let d = self.dir(dir)?;
                let st = stat_at(d.as_raw_fd(), &c).map_err(err)?;
                // What the guest can't see isn't there.
                let attr = attr_of(&st).ok_or(2u16)?;
                let target = match attr.ty {
                    FileType::Symlink => readlink_at(d.as_raw_fd(), &c)
                        .ok()
                        .and_then(|t| String::from_utf8(t).ok())
                        .filter(|t| !t.is_empty())
                        .ok_or(2u16)?,
                    _ => String::new(),
                };
                let id = self.id(dir, name)?;
                ok(Reply::Found { id, attr, target: &target })
            }
            Request::Watch { id } => {
                // A lazy import stays as the guest first saw it: nothing
                // there changes for it.
                if self.is_lazy(id) {
                    return Err(EINVAL);
                }
                let fd = self.open_node(id)?;
                self.watcher()?.add(id, fd)?;
                ok(Reply::Done)
            }
            Request::Forget { .. } | Request::Unwatch { .. } => unreachable!("handled without an answer"),
        }
    }

    /// `name` in `dir` is about to be removed or replaced: if it's a file
    /// the guest knows, open it, to keep once that's done (`keep`).
    fn open_to_keep(&mut self, dir: u64, name: &str, dirfd: RawFd, c: &CStr) -> Option<(u64, bool, OwnedFd)> {
        let &id = self.by_name.get(&(dir, name.to_string()))?;
        let writable = self.writable(dir).is_ok();
        let access = if writable { libc::O_RDWR } else { libc::O_RDONLY };
        let fd = openat(dirfd, c, access | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0).ok()?;
        let is_file = stat_fd(fd.as_raw_fd()).ok().and_then(|st| attr_of(&st)).map(|a| a.ty) == Some(FileType::File);
        is_file.then_some((id, writable, fd))
    }

    fn keep(&mut self, file: Option<(u64, bool, OwnedFd)>) {
        let Some(file) = file else { return };
        if self.kept.len() >= KEPT_OPEN {
            self.kept.pop_front();
        }
        self.kept.push_back(file);
    }

    fn mount_of(&self, mut id: u64) -> Result<usize, u16> {
        // Ids form a tree under the roots; the depth bound is only a guard.
        for _ in 0..4096 {
            if id >= 1 && id <= self.roots.len() as u64 {
                return Ok(id as usize - 1);
            }
            id = self.nodes.get(&id).ok_or(ESTALE)?.parent;
        }
        Err(ESTALE)
    }

    fn writable(&self, id: u64) -> Result<(), u16> {
        if let Some(k) = self.kept.iter().find(|k| k.0 == id) {
            return if k.1 { Ok(()) } else { Err(EROFS) };
        }
        if self.roots[self.mount_of(id)?].1 { Ok(()) } else { Err(EROFS) }
    }

    /// The names from the mount's root down to `id`.
    fn names(&self, mut id: u64) -> Result<(usize, Vec<&str>), u16> {
        let mut names = Vec::new();
        while id > self.roots.len() as u64 {
            let n = self.nodes.get(&id).ok_or(ESTALE)?;
            names.push(n.name.as_str());
            id = n.parent;
            if names.len() > 4096 {
                return Err(ESTALE);
            }
        }
        if id == 0 {
            return Err(ESTALE);
        }
        names.reverse();
        Ok((id as usize - 1, names))
    }

    /// Directory `id`, opened by walking down from its mount without
    /// following any link.
    fn dir(&self, id: u64) -> Result<OwnedFd, u16> {
        let (mount, names) = self.names(id)?;
        let root = self.roots[mount].0.as_raw_fd();
        let mut fd = openat(root, c".", libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(err)?;
        for name in names {
            let c = cname(name)?;
            fd = openat(fd.as_raw_fd(), &c, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0).map_err(err)?;
        }
        Ok(fd)
    }

    /// The directory holding `id`, and its name there (None for a root).
    fn parent(&self, id: u64) -> Result<Option<(OwnedFd, CString)>, u16> {
        if id >= 1 && id <= self.roots.len() as u64 {
            return Ok(None);
        }
        let n = self.nodes.get(&id).ok_or(ESTALE)?;
        Ok(Some((self.dir(n.parent)?, cname(&n.name)?)))
    }

    fn stat(&self, id: u64) -> Result<Attr, u16> {
        if let Some(k) = self.kept.iter().find(|k| k.0 == id) {
            return stat_fd(k.2.as_raw_fd()).map_err(err).and_then(|st| attr_of(&st).ok_or(ESTALE));
        }
        let st = match self.parent(id)? {
            Some((d, name)) => stat_at(d.as_raw_fd(), &name),
            None => stat_fd(self.dir(id)?.as_raw_fd()),
        }
        .map_err(err)?;
        attr_of(&st).ok_or(ESTALE)
    }

    /// Node `id` opened for fchmod/futimens: a directory or regular file,
    /// never through a link.
    fn open_node(&self, id: u64) -> Result<OwnedFd, u16> {
        let Some((d, name)) = self.parent(id)? else { return self.dir(id) };
        let st = stat_at(d.as_raw_fd(), &name).map_err(err)?;
        match attr_of(&st).map(|a| a.ty) {
            Some(FileType::Dir) => {
                openat(d.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0).map_err(err)
            }
            Some(FileType::File) => {
                openat(d.as_raw_fd(), &name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0).map_err(err)
            }
            _ => Err(EOPNOTSUPP),
        }
    }

    /// Regular file `id`, open for reading (and writing), kept open for the
    /// next request.
    fn file(&mut self, id: u64, write: bool) -> Result<RawFd, u16> {
        if let Some(k) = self.kept.iter().find(|k| k.0 == id) {
            return if write && !k.1 { Err(EROFS) } else { Ok(k.2.as_raw_fd()) };
        }
        if let Some(i) = self.files.iter().position(|&(f, w, _)| f == id && (w || !write)) {
            let entry = self.files.remove(i);
            self.files.push(entry);
            return Ok(self.files.last().unwrap().2.as_raw_fd());
        }
        let (d, name) = self.parent(id)?.ok_or(EISDIR)?;
        let access = if write { libc::O_RDWR } else { libc::O_RDONLY };
        // Non-blocking, so a FIFO put there on the host can't hang us.
        let fd = openat(d.as_raw_fd(), &name, access | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0).map_err(err)?;
        let st = stat_fd(fd.as_raw_fd()).map_err(err)?;
        if attr_of(&st).map(|a| a.ty) != Some(FileType::File) {
            return Err(EISDIR);
        }
        if self.files.len() >= OPEN_FILES {
            self.files.remove(0);
        }
        self.files.push((id, write, fd));
        Ok(self.files.last().unwrap().2.as_raw_fd())
    }

    /// The watcher, started the first time it's needed.
    fn watcher(&mut self) -> Result<&crate::watch::Watcher, u16> {
        if self.watcher.is_none() {
            let send = self.notices.clone().ok_or(EOPNOTSUPP)?;
            let sink = Box::new(move |notice: Vec<u8>| {
                let mut f = wire::input_header(Input::FsEvent, notice.len()).to_vec();
                f.extend_from_slice(&notice);
                send(f)
            });
            self.watcher = Some(crate::watch::Watcher::new(sink).map_err(err)?);
        }
        Ok(self.watcher.as_ref().unwrap())
    }

    fn is_lazy(&self, id: u64) -> bool {
        self.mount_of(id).is_ok_and(|m| self.lazy[m])
    }

    /// A lazy import's node, as the guest first saw it: what it's told of
    /// it from now on.
    fn saw(&mut self, id: u64, attr: &Attr) -> Attr {
        if !self.is_lazy(id) {
            return *attr;
        }
        *self.attrs.entry(id).or_insert(*attr)
    }

    /// A lazy import's file must still be what the guest first saw.
    fn unchanged(&mut self, id: u64, fd: RawFd) -> Result<(), u16> {
        if !self.is_lazy(id) {
            return Ok(());
        }
        let now = stat_fd(fd).map_err(err).and_then(|st| attr_of(&st).ok_or(EIO))?;
        let first = self.saw(id, &now);
        if (first.size, first.mtime_ns) == (now.size, now.mtime_ns) { Ok(()) } else { Err(EIO) }
    }

    /// The entries of directory `dir`, sorted: as first listed, for a lazy
    /// import's (while there's room to keep them).
    fn entries(&mut self, dir: u64, d: RawFd) -> Result<Vec<(String, Attr, String)>, u16> {
        if let Some(e) = self.frozen.get(&dir) {
            return Ok(e.clone());
        }
        let entries = read_entries(d)?;
        let bytes: usize = entries.iter().map(|(name, _, target)| name.len() + target.len()).sum();
        if self.is_lazy(dir)
            && self.frozen_entries + entries.len() <= MAX_FROZEN
            && self.frozen_bytes + bytes <= MAX_FROZEN_BYTES
        {
            self.frozen_entries += entries.len();
            self.frozen_bytes += bytes;
            self.frozen.insert(dir, entries.clone());
        }
        Ok(entries)
    }

    /// The id of `name` in `dir`, given out now if it has none.
    fn id(&mut self, dir: u64, name: &str) -> Result<u64, u16> {
        if let Some(&id) = self.by_name.get(&(dir, name.to_string())) {
            return Ok(id);
        }
        if self.nodes.len() >= MAX_IDS || self.id_bytes + name.len() > MAX_ID_BYTES {
            return Err(ENOMEM);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.id_bytes += name.len();
        self.nodes.insert(id, Node { parent: dir, name: name.to_string() });
        self.by_name.insert((dir, name.to_string()), id);
        Ok(id)
    }

    /// `name` in `dir` is gone: its id is stale (open files stay open).
    fn forget(&mut self, dir: u64, name: &str) {
        if let Some(id) = self.by_name.remove(&(dir, name.to_string())) {
            self.nodes.remove(&id);
            self.id_bytes = self.id_bytes.saturating_sub(name.len());
        }
        if self.listing.as_ref().is_some_and(|l| l.dir == dir) {
            self.listing = None;
        }
    }

    fn list(&mut self, dir: u64, after: &str) -> Result<Vec<u8>, u16> {
        let d = self.dir(dir)?;
        let dir_attr = stat_fd(d.as_raw_fd()).map_err(err).and_then(|st| attr_of(&st).ok_or(EIO))?;
        let dir_attr = self.saw(dir, &dir_attr);
        // A new listing starts at "": read the directory then.
        if after.is_empty() || self.listing.as_ref().is_none_or(|l| l.dir != dir) {
            let entries = self.entries(dir, d.as_raw_fd())?;
            self.listing = Some(Listing { dir, entries });
        }
        let listing = self.listing.take().unwrap();
        let start = listing.entries.partition_point(|e| e.0.as_str() <= after);
        let mut size = 0;
        let mut end = start;
        while end < listing.entries.len() && end - start < LIST_MAX {
            let (name, _, target) = &listing.entries[end];
            size += name.len() + target.len() + 64;
            if size > MAX_MESSAGE - 4096 {
                break;
            }
            end += 1;
        }
        let mut ids = Vec::with_capacity(end - start);
        let mut attrs = Vec::with_capacity(end - start);
        for (name, attr, _) in &listing.entries[start..end] {
            let id = self.id(dir, name)?;
            attrs.push(self.saw(id, attr));
            ids.push(id);
        }
        let entries = listing.entries[start..end]
            .iter()
            .zip(ids)
            .zip(attrs)
            .map(|(((name, _, target), id), attr)| ListEntry { name, id, attr, target })
            .collect();
        let more = end < listing.entries.len();
        let bytes = Reply::Listed { dir: dir_attr, entries, more }.encode(0);
        if more {
            self.listing = Some(listing);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(s: &mut Server, r: Request) -> Vec<u8> {
        let mut out = None;
        let msg = r.encode(7);
        for (more, chunk) in hostfs::frames(&msg) {
            let mut p = vec![more];
            p.extend_from_slice(chunk);
            let frames = s.handle(&p);
            if !frames.is_empty() {
                let mut a = Assembler::default();
                for f in frames {
                    out = a.push(&f[wire::FRAME_HEADER..]).map(|m| m.unwrap());
                }
            }
        }
        out.expect("a reply")
    }

    /// Long names run out of room before the count does: what the host
    /// keeps for the guest is bounded in bytes.
    #[test]
    fn ids_are_bounded_in_bytes() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-ids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let m = LiveMount { host: root.canonicalize().unwrap(), guest: "/m".into(), writable: true, lazy: false };
        let mut s = Server::new(&[m]).unwrap();
        let long = |i: usize| format!("{i:0>255}");
        let mut n = 0;
        while s.id(1, &long(n)).is_ok() {
            n += 1;
        }
        assert!(n < MAX_IDS && n == MAX_ID_BYTES / 255, "{n}");
        assert_eq!(s.id(1, &long(n)), Err(ENOMEM));
        s.forget(1, &long(0));
        assert!(s.id(1, &long(n)).is_ok());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn mounts_the_directory_named_only() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("real/m")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let root = root.canonicalize().unwrap();
        let m = |host: PathBuf| LiveMount { host, guest: "/m".into(), writable: true, lazy: false };
        assert!(Server::new(&[m(root.join("real/m"))]).is_ok());
        // A link on the way there (swapped in since the path was made
        // canonical) isn't followed.
        assert!(Server::new(&[m(root.join("link/m"))]).is_err());
        assert!(Server::new(&[m(root.join("link"))]).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serves_inside_the_mount_only() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("m/sub")).unwrap();
        std::fs::write(root.join("m/a.txt"), "hello").unwrap();
        std::fs::write(root.join("secret"), "no").unwrap();
        std::os::unix::fs::symlink(root.join("secret"), root.join("m/out")).unwrap();
        let m =
            LiveMount { host: root.join("m").canonicalize().unwrap(), guest: "/m".into(), writable: true, lazy: false };
        let mut s = Server::new(&[m]).unwrap();

        let r = req(&mut s, Request::List { dir: 1, after: "" });
        let (_, Reply::Listed { entries, more: false, .. }) = Reply::decode(&r).unwrap() else { panic!() };
        let names: Vec<_> = entries.iter().map(|e| (e.name, e.attr.ty, e.target)).collect();
        let out = root.join("secret");
        assert_eq!(
            names,
            [
                ("a.txt", FileType::File, ""),
                ("out", FileType::Symlink, out.to_str().unwrap()),
                ("sub", FileType::Dir, "")
            ]
        );
        let (a, link) = (entries[0].id, entries[1].id);
        let r = req(&mut s, Request::Read { id: a, off: 1, len: 100 });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Data(b"ello"));
        // Reading or writing through the link fails: it isn't followed.
        let r = req(&mut s, Request::Read { id: link, off: 0, len: 100 });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Err(_)));
        let r = req(&mut s, Request::Write { id: link, off: 0, append: false, data: b"x" });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Err(_)));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "no");
        // Bad names, and unknown ids.
        for name in ["..", "a/b", "", "."] {
            let r = req(&mut s, Request::Create { dir: 1, name, ty: FileType::File, mode: 0o644, target: "" });
            assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(EINVAL), "{name:?}");
        }
        let r = req(&mut s, Request::Stat { id: 999 });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(ESTALE));

        // Create, write, append, rename, remove.
        let r = req(&mut s, Request::Create { dir: 1, name: "n", ty: FileType::File, mode: 0o644, target: "" });
        let (_, Reply::Created { id, .. }) = Reply::decode(&r).unwrap() else { panic!() };
        req(&mut s, Request::Write { id, off: 0, append: false, data: b"abc" });
        let r = req(&mut s, Request::Write { id, off: 0, append: true, data: b"def" });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Written { n: 3, size: 6 });
        req(
            &mut s,
            Request::Rename { from_dir: 1, from: "n", to_dir: 1, to: "renamed", noreplace: true, exchange: false },
        );
        assert_eq!(std::fs::read_to_string(root.join("m/renamed")).unwrap(), "abcdef");
        let r = req(&mut s, Request::Stat { id });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Attr(Attr { size: 6, .. })));
        let r = req(
            &mut s,
            Request::Rename { from_dir: 1, from: "renamed", to_dir: 1, to: "a.txt", noreplace: true, exchange: false },
        );
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Err(_)));
        // Another name for it, made on the host, and the two swapped.
        let r = req(&mut s, Request::Link { id, dir: 1, name: "hard" });
        let (_, Reply::Created { id: hard, .. }) = Reply::decode(&r).unwrap() else { panic!() };
        assert_ne!(hard, id);
        assert_eq!(std::fs::read_to_string(root.join("m/hard")).unwrap(), "abcdef");
        for bad in ["..", "a/b", ""] {
            let r = req(&mut s, Request::Link { id, dir: 1, name: bad });
            assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Err(_)), "{bad:?}");
        }
        // A link to a link is to the link, never what it points at.
        let r = req(&mut s, Request::Link { id: link, dir: 1, name: "out2" });
        assert!(matches!(
            Reply::decode(&r).unwrap().1,
            Reply::Created { attr: Attr { ty: FileType::Symlink, .. }, .. }
        ));
        assert_eq!(std::fs::read_link(root.join("m/out2")).unwrap(), root.join("secret"));
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(root.join("secret")).unwrap().nlink(), 1);
        }
        req(&mut s, Request::Remove { dir: 1, name: "out2", is_dir: false });
        // Not a mount's root, a directory.
        let r = req(&mut s, Request::Link { id: 1, dir: 1, name: "root" });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(EPERM));
        let r = req(
            &mut s,
            Request::Rename { from_dir: 1, from: "renamed", to_dir: 1, to: "a.txt", noreplace: false, exchange: true },
        );
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Done);
        assert_eq!(std::fs::read_to_string(root.join("m/a.txt")).unwrap(), "abcdef");
        let r = req(&mut s, Request::Stat { id });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Attr(Attr { size: 6, .. })));
        req(
            &mut s,
            Request::Rename { from_dir: 1, from: "renamed", to_dir: 1, to: "a.txt", noreplace: false, exchange: true },
        );
        req(&mut s, Request::Remove { dir: 1, name: "hard", is_dir: false });
        req(&mut s, Request::Remove { dir: 1, name: "renamed", is_dir: false });
        assert!(!root.join("m/renamed").exists());

        // A read-only mount refuses changes.
        let ro = LiveMount {
            host: root.join("m").canonicalize().unwrap(),
            guest: "/m".into(),
            writable: false,
            lazy: false,
        };
        let mut s = Server::new(&[ro]).unwrap();
        let r = req(&mut s, Request::Create { dir: 1, name: "x", ty: FileType::Dir, mode: 0o755, target: "" });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(EROFS));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn lazy_imports_stay_as_first_seen() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-lazy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a"), "first").unwrap();
        let m = LiveMount { host: root.canonicalize().unwrap(), guest: "/m".into(), writable: false, lazy: true };
        let mut s = Server::new(&[m]).unwrap();
        let names = |s: &mut Server| match Reply::decode(&req(s, Request::List { dir: 1, after: "" })).unwrap().1 {
            Reply::Listed { entries, .. } => {
                entries.iter().map(|e| (e.name.to_string(), e.id, e.attr.size)).collect::<Vec<_>>()
            }
            r => panic!("{r:?}"),
        };
        let first = names(&mut s);
        assert_eq!(first.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["a"]);
        let a = first[0].1;
        // Never written there.
        let r = req(&mut s, Request::Write { id: a, off: 0, append: false, data: b"x" });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(EROFS));
        // Changes on the host don't show; a changed file reads as EIO.
        std::fs::write(root.join("b"), "new").unwrap();
        std::fs::write(root.join("a"), "changed!").unwrap();
        assert_eq!(names(&mut s), first);
        let r = req(&mut s, Request::Lookup { dir: 1, name: "b" });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(2));
        let r = req(&mut s, Request::Stat { id: a });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Attr(attr) if attr.size == 5));
        let r = req(&mut s, Request::Read { id: a, off: 0, len: 100 });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(EIO));
        // Saved in a snapshot and restored: the same ids, and the same view.
        let m = || LiveMount { host: root.canonicalize().unwrap(), guest: "/m".into(), writable: false, lazy: true };
        let state = s.save();
        let mut back = Server::restore(&[m()], &state).unwrap();
        assert_eq!(names(&mut back), first);
        let r = req(&mut back, Request::Read { id: a, off: 0, len: 100 });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(EIO));
        assert_eq!(back.save(), state);
        // A file from anyone: names that would leave the mount, ids out of
        // order or unknown, too many mounts, or garbage are refused.
        use grix_abi::codec::Writer;
        let crafted = |nodes: &[(u64, u64, &str)], roots: u32| {
            let mut w = Writer::default();
            w.u32(STATE_VERSION);
            w.u32(roots);
            w.u64(100);
            w.u32(nodes.len() as u32);
            for (id, parent, name) in nodes {
                w.u64(*id);
                w.u64(*parent);
                w.str(name);
            }
            w.u32(0);
            w.u32(0);
            w.buf
        };
        assert!(Server::restore(&[m()], &crafted(&[(2, 1, "ok"), (3, 2, "fine")], 1)).is_ok());
        for bad in [
            crafted(&[(2, 1, "..")], 1),
            crafted(&[(2, 1, "a/b")], 1),
            crafted(&[(3, 1, "a"), (2, 3, "b")], 1),
            crafted(&[(2, 7, "a")], 1),
            crafted(&[(2, 1, "a"), (3, 1, "a")], 1),
            crafted(&[(2, 1, "a")], 2),
            vec![1, 2, 3],
        ] {
            assert!(Server::restore(&[m()], &bad).is_err());
        }
        std::fs::remove_dir_all(&root).unwrap();
    }
}
