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

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use grix_abi::hostfs::{self, Assembler, Attr, FileType, IO_MAX, LIST_MAX, ListEntry, MAX_MESSAGE, Reply, Request};
use grix_abi::wire::{self, Input};

use crate::at::{check, each_name, openat, readlink_at, rename, stat_at, stat_fd};

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
/// Entries of a directory held while the guest pages through them, and
/// their names' and link targets' bytes; a bigger one is read on from
/// where the guest is, once those run out.
#[cfg(not(test))]
const MAX_LISTED: usize = 64 * 1024;
#[cfg(not(test))]
const MAX_LISTED_BYTES: usize = 64 << 20;
#[cfg(test)]
const MAX_LISTED: usize = 64;
#[cfg(test)]
const MAX_LISTED_BYTES: usize = 8192;
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

/// A directory entry the guest can see: (name, attributes, link target).
type Entry = (String, Attr, String);

/// The first names in directory `d` past `after`, at most `max` of them
/// and `max_bytes` of their bytes; and whether that's all of them.
fn names_past(d: RawFd, after: &str, max: usize, max_bytes: usize) -> Result<(BTreeSet<String>, bool), u16> {
    let (mut names, mut bytes, mut whole) = (BTreeSet::new(), 0, true);
    each_name(d, |name| {
        // Names the guest can't hold are left out.
        let Ok(s) = name.to_str() else { return true };
        if s.len() > 255 || s <= after {
            return true;
        }
        bytes += s.len();
        names.insert(s.to_string());
        while names.len() > max || bytes > max_bytes {
            whole = false;
            bytes -= names.pop_last().map_or(0, |last| last.len());
        }
        true
    })
    .map_err(err)?;
    Ok((names, whole))
}

/// The first of directory `d`'s entries past `after` that the guest can
/// see, sorted, at most `max` and `max_bytes` of names and targets; and
/// whether that's the last of them.
/// What's in a directory is the guest's to fill on a writable mount, so
/// the host never holds all of it. Empty only at the end, which is what
/// an empty page means to the guest.
fn read_entries(d: RawFd, after: &str, max: usize, max_bytes: usize) -> Result<(Vec<Entry>, bool), u16> {
    let mut after = after.to_string();
    loop {
        let (names, whole) = names_past(d, &after, max, max_bytes)?;
        let (mut entries, mut bytes) = (Vec::new(), 0);
        for name in &names {
            let Ok(c) = CString::new(name.as_str()) else { continue };
            let Ok((attr, target)) = look_up(d, &c) else { continue };
            bytes += name.len() + target.len();
            if bytes > max_bytes && !entries.is_empty() {
                return Ok((entries, false));
            }
            entries.push((name.clone(), attr, target));
        }
        match names.last() {
            Some(last) if entries.is_empty() && !whole => after = last.clone(),
            _ => return Ok((entries, whole)),
        }
    }
}

/// `name` in directory `d` as it is now, if the guest can see it: its
/// attributes and link target.
fn look_up(d: RawFd, name: &CStr) -> Result<(Attr, String), u16> {
    let st = stat_at(d, name).map_err(err)?;
    // What the guest can't see isn't there.
    let attr = attr_of(&st).ok_or(2u16)?;
    let target = match attr.ty {
        FileType::Symlink => {
            readlink_at(d, name).ok().and_then(|t| String::from_utf8(t).ok()).filter(|t| !t.is_empty()).ok_or(2u16)?
        }
        _ => String::new(),
    };
    Ok((attr, target))
}

struct Node {
    parent: u64,
    name: String,
}

/// One listed directory's entries, sorted, kept while the guest pages
/// through them.
struct Listing {
    dir: u64,
    entries: Vec<Entry>,
    /// They go on to the directory's end: if not, more are read once
    /// they've run out.
    whole: bool,
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
    frozen: HashMap<u64, Vec<Entry>>,
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

    /// The ids that lead up to a mount's root, of `nodes`: a removed
    /// directory's id goes, but those of what was in it stay until they're
    /// looked at, and a file's state can say anything.
    fn reachable(roots: u64, nodes: &HashMap<u64, Node>) -> HashSet<u64> {
        let mut good = HashSet::new();
        let mut bad = HashSet::new();
        for &start in nodes.keys() {
            let (mut path, mut seen, mut at) = (Vec::new(), HashSet::new(), start);
            let ok = loop {
                if (1..=roots).contains(&at) || good.contains(&at) {
                    break true;
                }
                // Gone, known not to lead anywhere, or seen on this walk.
                if bad.contains(&at) || !seen.insert(at) {
                    break false;
                }
                let Some(n) = nodes.get(&at) else { break false };
                path.push(at);
                at = n.parent;
            };
            if ok { good.extend(path) } else { bad.extend(path) }
        }
        good
    }

    /// What a snapshot keeps of the server, for runs restored from it:
    /// the ids it gave out that still lead somewhere (each a name in its
    /// parent), and what the guest first saw of lazy imports. Not open
    /// files: they're opened again. Parents can come after their children:
    /// a file moved into a newer directory.
    pub fn save(&self) -> Vec<u8> {
        use grix_abi::codec::Writer;
        let mut w = Writer::default();
        w.u32(STATE_VERSION);
        w.u32(self.roots.len() as u32);
        w.u64(self.next_id);
        let roots = self.roots.len() as u64;
        let live = Self::reachable(roots, &self.nodes);
        let kept = |id: u64| id <= roots || live.contains(&id);
        let mut nodes: Vec<(&u64, &Node)> = self.nodes.iter().filter(|(id, _)| kept(**id)).collect();
        nodes.sort_by_key(|(id, _)| **id);
        w.u32(nodes.len() as u32);
        for (id, n) in nodes {
            w.u64(*id);
            w.u64(n.parent);
            w.str(&n.name);
        }
        // In order of id, so the same state saves the same.
        let mut attrs: Vec<(&u64, &Attr)> = self.attrs.iter().filter(|(id, _)| kept(**id)).collect();
        attrs.sort_by_key(|(id, _)| **id);
        w.u32(attrs.len() as u32);
        for (id, a) in attrs {
            w.u64(*id);
            a.put(&mut w);
        }
        let mut frozen: Vec<_> = self.frozen.iter().filter(|(id, _)| kept(**id)).collect();
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
    /// every id leads up to a mount's root (no parent missing, no circles),
    /// and nothing exceeds the limits, or it's refused.
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
            // Sorted. (Its parent may come later: `reachable` looks, below.)
            if id <= last || id >= next_id || parent == id {
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
        if Self::reachable(roots, &s.nodes).len() != s.nodes.len() {
            return Err(bad("a parent"));
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
                self.id_room(dir, name)?;
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
                // What the host keeps for the guest stays bounded, as for a
                // new id: the name an id takes, and the one it leaves.
                let known = |dir, name: &str| self.by_name.contains_key(&(dir, name.to_string()));
                let changes = match (known(from_dir, from), known(to_dir, to)) {
                    (true, true) if exchange => None,
                    (true, _) => Some((to, from)),
                    (false, true) if exchange => Some((from, to)),
                    _ => None,
                };
                if changes.is_some_and(|(new, old)| self.id_bytes + new.len() > MAX_ID_BYTES + old.len()) {
                    return Err(ENOMEM);
                }
                if exchange {
                    rename(df.as_raw_fd(), &cf, dt.as_raw_fd(), &ct, false, true).map_err(err)?;
                    // Each id now names what the other did.
                    let a = self.by_name.remove(&(from_dir, from.to_string()));
                    let b = self.by_name.remove(&(to_dir, to.to_string()));
                    for (id, dir, name, was) in [(a, to_dir, to, from), (b, from_dir, from, to)] {
                        if let Some(id) = id {
                            self.id_bytes = (self.id_bytes + name.len()).saturating_sub(was.len());
                            self.nodes.insert(id, Node { parent: dir, name: name.to_string() });
                            self.by_name.insert((dir, name.to_string()), id);
                        }
                    }
                    return ok(Reply::Done);
                }
                // Onto itself: nothing happens, and the id stays (it has to
                // be there, or noreplace's EEXIST; the host says).
                if (from_dir, from) == (to_dir, to) {
                    rename(df.as_raw_fd(), &cf, dt.as_raw_fd(), &ct, noreplace, false).map_err(err)?;
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
                self.id_room(dir, name)?;
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
                let c = cname(name)?;
                let find = |entries: &[Entry]| {
                    let i = entries.binary_search_by(|e| e.0.as_str().cmp(name)).map_err(|_| 2u16)?;
                    Ok::<_, u16>((entries[i].1, entries[i].2.clone()))
                };
                let (attr, target) = match self.frozen.get(&dir) {
                    Some(entries) => find(entries)?,
                    None => {
                        let d = self.dir(dir)?;
                        match self.entries(dir, d.as_raw_fd(), "")? {
                            (entries, true) => find(&entries)?,
                            // Not all of it: as it is, as one too big to
                            // keep is read.
                            _ => look_up(d.as_raw_fd(), &c)?,
                        }
                    }
                };
                let id = self.id(dir, name)?;
                let attr = self.saw(id, &attr);
                ok(Reply::Found { id, attr, target: &target })
            }
            Request::Lookup { dir, name } => {
                let c = cname(name)?;
                let d = self.dir(dir)?;
                let (attr, target) = look_up(d.as_raw_fd(), &c)?;
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

    /// The entries of directory `dir` past `after`, sorted, and whether
    /// they go on to its end: as first listed, for a lazy import's (while
    /// there's room to keep them).
    fn entries(&mut self, dir: u64, d: RawFd, after: &str) -> Result<(Vec<Entry>, bool), u16> {
        if let Some(e) = self.frozen.get(&dir) {
            return Ok((e.clone(), true));
        }
        // A lazy import's are looked at for what can be kept of them.
        let lazy = self.is_lazy(dir);
        let (room, room_bytes) =
            (MAX_FROZEN.saturating_sub(self.frozen_entries), MAX_FROZEN_BYTES.saturating_sub(self.frozen_bytes));
        let (max, max_bytes) = if lazy {
            (room.max(MAX_LISTED), room_bytes.max(MAX_LISTED_BYTES))
        } else {
            (MAX_LISTED, MAX_LISTED_BYTES)
        };
        let (entries, whole) = read_entries(d, after, max, max_bytes)?;
        let bytes: usize = entries.iter().map(|(name, _, target)| name.len() + target.len()).sum();
        if lazy && whole && after.is_empty() && entries.len() <= room && bytes <= room_bytes {
            self.frozen_entries += entries.len();
            self.frozen_bytes += bytes;
            self.frozen.insert(dir, entries.clone());
        }
        Ok((entries, whole))
    }

    /// Is there room for an id for `name` in `dir`? Asked before a change
    /// on the host too: an error after it wouldn't undo it, and the guest
    /// would have been told it never happened.
    fn id_room(&self, dir: u64, name: &str) -> Result<(), u16> {
        let full = self.nodes.len() >= MAX_IDS || self.id_bytes + name.len() > MAX_ID_BYTES;
        if full && !self.by_name.contains_key(&(dir, name.to_string())) { Err(ENOMEM) } else { Ok(()) }
    }

    /// The id of `name` in `dir`, given out now if it has none.
    fn id(&mut self, dir: u64, name: &str) -> Result<u64, u16> {
        if let Some(&id) = self.by_name.get(&(dir, name.to_string())) {
            return Ok(id);
        }
        self.id_room(dir, name)?;
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
        // A new listing starts at "": read the directory then, and on from
        // `after` when what was read has run out.
        let held = self.listing.take().filter(|l| {
            let left = l.whole || l.entries.last().is_some_and(|e| e.0.as_str() > after);
            !after.is_empty() && l.dir == dir && left
        });
        let listing = match held {
            Some(l) => l,
            None => {
                let (entries, whole) = self.entries(dir, d.as_raw_fd(), after)?;
                Listing { dir, entries, whole }
            }
        };
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
        let more = end < listing.entries.len() || !listing.whole;
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

    /// Out of ids, nothing happens on the host: the guest is told it
    /// didn't, and an id is what it would need to take it back.
    #[test]
    fn nothing_is_made_without_an_id() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-no-ids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("old"), "").unwrap();
        let m = LiveMount { host: root.canonicalize().unwrap(), guest: "/m".into(), writable: true, lazy: false };
        let mut s = Server::new(&[m]).unwrap();
        let old = s.id(1, "old").unwrap();
        s.id_bytes = MAX_ID_BYTES;
        for (name, ty, target) in [("f", FileType::File, ""), ("d", FileType::Dir, ""), ("l", FileType::Symlink, "old")]
        {
            let r = req(&mut s, Request::Create { dir: 1, name, ty, mode: 0o644, target });
            assert!(matches!(Reply::decode(&r), Ok((_, Reply::Err(ENOMEM)))), "{name}");
            assert!(std::fs::symlink_metadata(root.join(name)).is_err(), "{name} was made");
        }
        let r = req(&mut s, Request::Link { id: old, dir: 1, name: "hard" });
        assert!(matches!(Reply::decode(&r), Ok((_, Reply::Err(ENOMEM)))));
        assert!(!root.join("hard").exists());
        // A name that has one needs none: it's free again once it's gone
        // on the host, whoever removed it.
        std::fs::remove_file(root.join("old")).unwrap();
        let r = req(&mut s, Request::Create { dir: 1, name: "old", ty: FileType::File, mode: 0o644, target: "" });
        assert!(matches!(Reply::decode(&r), Ok((_, Reply::Created { id, .. })) if id == old));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// All of a directory's names, as the guest pages through them: what
    /// `list_remote` does. Every page but the last has something in it, or
    /// the guest would take it for the end.
    fn page_through(s: &mut Server, dir: u64) -> Vec<String> {
        let (mut names, mut after) = (Vec::new(), String::new());
        loop {
            let r = req(s, Request::List { dir, after: &after });
            let Ok((_, Reply::Listed { entries, more, .. })) = Reply::decode(&r) else { panic!() };
            names.extend(entries.iter().map(|e| e.name.to_string()));
            if !more {
                return names;
            }
            after = entries.last().expect("a page with something in it").name.to_string();
            let held = s.listing.as_ref().map_or(0, |l| l.entries.len());
            assert!(held <= MAX_LISTED, "{held} held");
        }
    }

    /// A directory the guest filled can't make the host hold it all, and
    /// doesn't stop working for being big: the kernel's budget runs out
    /// first, and then its names are looked up, and listed, by the page.
    #[test]
    fn listings_are_bounded() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-listed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["fits", "many", "long", "unseen"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        let fits = sorted((0..MAX_LISTED).map(|i| i.to_string()).collect());
        let many = sorted((0..MAX_LISTED * 5 / 2).map(|i| i.to_string()).collect());
        for name in &fits {
            std::fs::write(root.join("fits").join(name), "").unwrap();
        }
        for name in &many {
            std::fs::write(root.join("many").join(name), "").unwrap();
        }
        // Few entries, but long link targets (macOS takes 1023 bytes at most).
        let long = sorted((0..MAX_LISTED_BYTES / 500 * 3).map(|i| i.to_string()).collect());
        for name in &long {
            std::os::unix::fs::symlink("t".repeat(500), root.join("long").join(name)).unwrap();
        }
        // More than can be held that the guest can't see, before what it can.
        for i in 0..MAX_LISTED * 2 {
            let c = CString::new(root.join(format!("unseen/a{i:04}")).to_str().unwrap()).unwrap();
            // SAFETY: a NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        }
        std::fs::write(root.join("unseen/z"), "").unwrap();
        let host = root.canonicalize().unwrap();
        for lazy in [false, true] {
            let m = LiveMount { host: host.clone(), guest: "/m".into(), writable: !lazy, lazy };
            let mut s = Server::new(&[m]).unwrap();
            if lazy {
                // Nothing left to keep them with.
                (s.frozen_entries, s.frozen_bytes) = (MAX_FROZEN, MAX_FROZEN_BYTES);
            }
            let dir = |s: &mut Server, name| match Reply::decode(&req(s, Request::Lookup { dir: 1, name })) {
                Ok((_, Reply::Found { id, .. })) => id,
                other => panic!("{other:?}"),
            };
            let (d, want) = (dir(&mut s, "fits"), &fits);
            assert_eq!(&page_through(&mut s, d), want);
            assert!(s.listing.is_none());
            let (d, want) = (dir(&mut s, "many"), &many);
            assert_eq!(&page_through(&mut s, d), want);
            // Past what any one read holds, and not there.
            let r = req(&mut s, Request::Lookup { dir: d, name: many.last().unwrap() });
            assert!(matches!(Reply::decode(&r), Ok((_, Reply::Found { .. }))));
            let r = req(&mut s, Request::Lookup { dir: d, name: "nothing" });
            assert!(matches!(Reply::decode(&r), Ok((_, Reply::Err(2)))));
            let (d, want) = (dir(&mut s, "long"), &long);
            assert_eq!(&page_through(&mut s, d), want);
            let d = dir(&mut s, "unseen");
            assert_eq!(page_through(&mut s, d), ["z"]);
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A lazy import's directory bigger than a listing's window is still
    /// kept as first seen, while there's room.
    #[test]
    fn big_lazy_directories_are_still_kept() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-big-lazy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for i in 0..MAX_LISTED * 2 {
            std::fs::write(root.join(format!("f{i}")), "").unwrap();
        }
        let m = LiveMount { host: root.canonicalize().unwrap(), guest: "/m".into(), writable: false, lazy: true };
        let mut s = Server::new(&[m]).unwrap();
        assert_eq!(page_through(&mut s, 1).len(), MAX_LISTED * 2);
        assert_eq!(s.frozen.get(&1).map(Vec::len), Some(MAX_LISTED * 2));
        // As first listed, whatever's there now.
        std::fs::remove_file(root.join("f0")).unwrap();
        std::fs::write(root.join("new"), "").unwrap();
        let names = page_through(&mut s, 1);
        assert!(names.contains(&"f0".to_string()) && !names.contains(&"new".to_string()));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A rename can't take what's kept past the bound either.
    #[test]
    fn renames_stay_within_ids_bytes() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-renamed-ids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("s"), "").unwrap();
        let m = LiveMount { host: root.canonicalize().unwrap(), guest: "/m".into(), writable: true, lazy: false };
        let mut s = Server::new(&[m]).unwrap();
        s.id(1, "s").unwrap();
        s.id_bytes = MAX_ID_BYTES;
        let long = "l".repeat(255);
        let r = Request::Rename { from_dir: 1, from: "s", to_dir: 1, to: &long, noreplace: false, exchange: false };
        let reply = req(&mut s, r);
        assert!(matches!(Reply::decode(&reply), Ok((_, Reply::Err(ENOMEM)))));
        assert!(root.join("s").exists() && s.id_bytes == MAX_ID_BYTES);
        s.id_bytes = 1;
        let r = Request::Rename { from_dir: 1, from: "s", to_dir: 1, to: &long, noreplace: false, exchange: false };
        req(&mut s, r);
        assert!(root.join(&long).exists() && s.id_bytes == 255);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Cycles in a saved state (a file may come from anyone) cost a walk
    /// each, not the whole table each.
    #[test]
    fn cycles_in_saved_nodes_are_seen_at_once() {
        let mut nodes = HashMap::new();
        for i in 0..40_000u64 {
            let at = 10 + i * 2;
            nodes.insert(at, Node { parent: at + 1, name: "a".into() });
            nodes.insert(at + 1, Node { parent: at, name: "b".into() });
        }
        let started = std::time::Instant::now();
        assert!(Server::reachable(1, &nodes).is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "{:?}", started.elapsed());
    }

    /// An id that takes a longer name by RENAME_EXCHANGE counts it: a short
    /// name swapped with a long one the host has but gave no id, over and
    /// over, is what a hostile kernel would keep the host's memory with.
    #[test]
    fn exchanges_count_ids_bytes() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let long = "l".repeat(255);
        std::fs::write(root.join("s"), "").unwrap();
        std::fs::write(root.join(&long), "").unwrap();
        let m = LiveMount { host: root.canonicalize().unwrap(), guest: "/m".into(), writable: true, lazy: false };
        let mut s = Server::new(&[m]).unwrap();
        let swap = |s: &mut Server, from: &str, to: &str| {
            let r = Request::Rename { from_dir: 1, from, to_dir: 1, to, noreplace: false, exchange: true };
            req(s, r);
        };
        let id = s.id(1, "s").unwrap();
        assert_eq!(s.id_bytes, 1);
        swap(&mut s, "s", &long);
        assert_eq!(s.by_name.get(&(1, long.clone())), Some(&id));
        assert_eq!(s.id_bytes, 255);
        // Both known: the two together stay what they were.
        s.id(1, "s").unwrap();
        assert_eq!(s.id_bytes, 256);
        swap(&mut s, "s", &long);
        assert_eq!(s.id_bytes, 256);
        s.forget(1, &long);
        s.forget(1, "s");
        assert_eq!(s.id_bytes, 0);
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

    fn known_id(r: &[u8]) -> u64 {
        match Reply::decode(r).unwrap().1 {
            Reply::Created { id, .. } | Reply::Found { id, .. } => id,
            other => panic!("{other:?}"),
        }
    }

    fn scratch(name: &str) -> (PathBuf, impl Fn() -> LiveMount) {
        let root = std::env::temp_dir().join(format!("grix-hostfs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let host = root.canonicalize().unwrap();
        let mount = move || LiveMount { host: host.clone(), guest: "/m".into(), writable: true, lazy: false };
        (root, mount)
    }

    #[test]
    fn restore_takes_a_rename_into_a_newer_directory() {
        // A file older than the directory it's in now: its parent's id
        // comes after its own.
        let (root, m) = scratch("rename");
        let mut s = Server::new(&[m()]).unwrap();
        let file = Request::Create { dir: 1, name: "a", ty: FileType::File, mode: 0o644, target: "" };
        let a = known_id(&req(&mut s, file));
        let z =
            known_id(&req(&mut s, Request::Create { dir: 1, name: "z", ty: FileType::Dir, mode: 0o755, target: "" }));
        assert!(a < z);
        req(&mut s, Request::Rename { from_dir: 1, from: "a", to_dir: z, to: "a", noreplace: false, exchange: false });
        let mut back = Server::restore(&[m()], &s.save()).unwrap();
        let r = req(&mut back, Request::Stat { id: a });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Attr(_)));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn restore_takes_what_a_removed_directory_leaves() {
        // The guest knew d/f; f went on the host, d in the guest: f's id
        // stays with no parent, and leads nowhere after a restore either.
        let (root, m) = scratch("orphan");
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::write(root.join("d/f"), "x").unwrap();
        let mut s = Server::new(&[m()]).unwrap();
        let d = known_id(&req(&mut s, Request::Lookup { dir: 1, name: "d" }));
        let f = known_id(&req(&mut s, Request::Lookup { dir: d, name: "f" }));
        std::fs::remove_file(root.join("d/f")).unwrap();
        req(&mut s, Request::Remove { dir: 1, name: "d", is_dir: true });
        let mut back = Server::restore(&[m()], &s.save()).unwrap();
        let r = req(&mut back, Request::Stat { id: f });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Err(_)));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A state as `save` writes it, of these ids.
    fn state(next_id: u64, ids: &[(u64, u64, &str)]) -> Vec<u8> {
        let mut w = grix_abi::codec::Writer::default();
        w.u32(STATE_VERSION);
        w.u32(1);
        w.u64(next_id);
        w.u32(ids.len() as u32);
        for (id, parent, name) in ids {
            w.u64(*id);
            w.u64(*parent);
            w.str(name);
        }
        w.u32(0);
        w.u32(0);
        w.buf
    }

    #[test]
    fn restore_refuses_a_hostile_state() {
        let (root, m) = scratch("hostile");
        let good = Server::restore(&[m()], &state(5, &[(2, 1, "a"), (3, 4, "b"), (4, 1, "c")]));
        assert!(good.is_ok(), "a parent after its child is fine");
        for (what, bad) in [
            ("a circle", state(5, &[(2, 3, "a"), (3, 2, "b")])),
            ("its own parent", state(5, &[(2, 2, "a")])),
            ("a circle under a good id", state(6, &[(2, 1, "a"), (3, 4, "b"), (4, 3, "c")])),
            ("an unknown parent", state(5, &[(2, 9, "a")])),
            ("no parent", state(5, &[(2, 0, "a")])),
            ("a path as a name", state(5, &[(2, 1, "a/b")])),
            ("dot dot", state(5, &[(2, 1, "..")])),
            ("an empty name", state(5, &[(2, 1, "")])),
            ("two ids for one name", state(5, &[(2, 1, "a"), (3, 1, "a")])),
            ("out of order", state(5, &[(3, 1, "a"), (2, 1, "b")])),
            ("an id past the next", state(3, &[(3, 1, "a")])),
            ("a mount's root", state(5, &[(1, 1, "a")])),
        ] {
            assert!(Server::restore(&[m()], &bad).is_err(), "{what}");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_rename_onto_itself_keeps_the_id() {
        let (root, m) = scratch("self");
        std::fs::write(root.join("a"), "x").unwrap();
        let mut s = Server::new(&[m()]).unwrap();
        let a = known_id(&req(&mut s, Request::Lookup { dir: 1, name: "a" }));
        let same = Request::Rename { from_dir: 1, from: "a", to_dir: 1, to: "a", noreplace: false, exchange: false };
        assert_eq!(Reply::decode(&req(&mut s, same)).unwrap().1, Reply::Done);
        let r = req(&mut s, Request::Stat { id: a });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Attr(_)), "{:?}", Reply::decode(&r).unwrap().1);
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
