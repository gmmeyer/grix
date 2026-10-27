//! The host end of live mounts (`grix_abi::hostfs`): a small file server
//! for the guest kernel, confined to the mounted directories.
//!
//! Every request is untrusted. Paths are never built as strings: each one
//! is walked from the mount's directory with `openat` and `O_NOFOLLOW`, one
//! checked name at a time, so no link (the program's or anyone's) can lead
//! out of the mount. Read-only mounts refuse every change.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use anyhow::{Context, Result};
use grix_abi::hostfs::{self, Assembler, Attr, FileType, IO_MAX, LIST_MAX, ListEntry, MAX_MESSAGE, Reply, Request};
use grix_abi::wire::{self, Input};

/// A directory mounted live.
#[derive(Clone, Debug)]
pub(crate) struct LiveMount {
    /// Canonical.
    pub host: PathBuf,
    pub guest: String,
    pub writable: bool,
}

// Linux errnos, as the guest wants them.
const EIO: u16 = 5;
const ENOMEM: u16 = 12;
const EXDEV: u16 = 18;
const EISDIR: u16 = 21;
const EINVAL: u16 = 22;
const EROFS: u16 = 30;
const ENAMETOOLONG: u16 = 36;
const EOPNOTSUPP: u16 = 95;
const ESTALE: u16 = 116;

/// Ids the host keeps track of (everything listed or created).
const MAX_IDS: usize = 1_000_000;
/// Files kept open between requests.
const OPEN_FILES: usize = 32;
/// Files the guest removed while it may still have them open.
const KEPT_OPEN: usize = 128;

/// A host error as a Linux errno.
fn linux_errno(e: &io::Error) -> u16 {
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
        libc::ENOTSUP | libc::EOPNOTSUPP => 95,
        libc::EDQUOT => 122,
        _ => EIO,
    }
}

fn err(e: io::Error) -> u16 {
    linux_errno(&e)
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
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

fn openat(dir: RawFd, name: &CStr, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated; the result is a new descriptor we own.
    let fd = check(unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: fstat fills `st`, a plain C struct.
    let mut st = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

fn stat_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: as for stat_fd; AT_SYMLINK_NOFOLLOW never follows a link.
    let mut st = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(st)
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

fn readlink_at(dir: RawFd, name: &CStr) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: readlinkat writes at most buf.len() bytes.
    let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// The names in directory `dir` (not `.` or `..`).
fn read_dir(dir: RawFd) -> io::Result<Vec<CString>> {
    // fdopendir takes the descriptor over, so give it a copy.
    // SAFETY: dup of a descriptor we hold; fdopendir owns the copy, and
    // closedir closes it.
    let copy = check(unsafe { libc::dup(dir) })?;
    let d = unsafe { libc::fdopendir(copy) };
    if d.is_null() {
        let e = io::Error::last_os_error();
        unsafe { libc::close(copy) };
        return Err(e);
    }
    // From the start, whatever the shared offset was.
    unsafe { libc::rewinddir(d) };
    let mut names = Vec::new();
    loop {
        // SAFETY: readdir's entry is valid until the next call on `d`.
        let e = unsafe { libc::readdir(d) };
        if e.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    unsafe { libc::closedir(d) };
    Ok(names)
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
    nodes: HashMap<u64, Node>,
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
}

impl Server {
    pub fn new(mounts: &[LiveMount]) -> Result<Server> {
        let mut roots = Vec::new();
        for m in mounts {
            let path = CString::new(m.host.as_os_str().as_encoded_bytes())?;
            let fd = openat(libc::AT_FDCWD, &path, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .with_context(|| format!("mounting {}", m.host.display()))?;
            roots.push((fd, m.writable));
        }
        Ok(Server {
            next_id: roots.len() as u64 + 1,
            roots,
            nodes: HashMap::new(),
            by_name: HashMap::new(),
            files: Vec::new(),
            kept: VecDeque::new(),
            listing: None,
            assembler: Assembler::default(),
        })
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
            Request::Stat { id } => ok(Reply::Attr(self.stat(id)?)),
            Request::Read { id, off, len } => {
                let fd = self.file(id, false)?;
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
            Request::Rename { from_dir, from, to_dir, to, noreplace } => {
                self.writable(from_dir)?;
                if self.mount_of(from_dir)? != self.mount_of(to_dir)? {
                    return Err(EXDEV);
                }
                let (cf, ct) = (cname(from)?, cname(to)?);
                let (df, dt) = (self.dir(from_dir)?, self.dir(to_dir)?);
                let keep = if noreplace { None } else { self.open_to_keep(to_dir, to, dt.as_raw_fd(), &ct) };
                rename(df.as_raw_fd(), &cf, dt.as_raw_fd(), &ct, noreplace).map_err(err)?;
                self.keep(keep);
                self.forget(to_dir, to);
                if let Some(id) = self.by_name.remove(&(from_dir, from.to_string())) {
                    self.nodes.insert(id, Node { parent: to_dir, name: to.to_string() });
                    self.by_name.insert((to_dir, to.to_string()), id);
                }
                ok(Reply::Done)
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
                        Some(ns) => libc::timespec {
                            tv_sec: (ns / 1_000_000_000) as libc::time_t,
                            tv_nsec: (ns % 1_000_000_000) as _,
                        },
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
            Request::Forget { .. } => unreachable!("handled without an answer"),
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

    /// The id of `name` in `dir`, given out now if it has none.
    fn id(&mut self, dir: u64, name: &str) -> Result<u64, u16> {
        if let Some(&id) = self.by_name.get(&(dir, name.to_string())) {
            return Ok(id);
        }
        if self.nodes.len() >= MAX_IDS {
            return Err(ENOMEM);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(id, Node { parent: dir, name: name.to_string() });
        self.by_name.insert((dir, name.to_string()), id);
        Ok(id)
    }

    /// `name` in `dir` is gone: its id is stale (open files stay open).
    fn forget(&mut self, dir: u64, name: &str) {
        if let Some(id) = self.by_name.remove(&(dir, name.to_string())) {
            self.nodes.remove(&id);
        }
        if self.listing.as_ref().is_some_and(|l| l.dir == dir) {
            self.listing = None;
        }
    }

    fn list(&mut self, dir: u64, after: &str) -> Result<Vec<u8>, u16> {
        let d = self.dir(dir)?;
        let dir_attr = stat_fd(d.as_raw_fd()).map_err(err).and_then(|st| attr_of(&st).ok_or(EIO))?;
        // A new listing starts at "": read the directory then.
        if after.is_empty() || self.listing.as_ref().is_none_or(|l| l.dir != dir) {
            let mut entries = Vec::new();
            for name in read_dir(d.as_raw_fd()).map_err(err)? {
                // Names the guest can't hold, and things it can't see, are left out.
                let Ok(s) = name.to_str() else { continue };
                if s.len() > 255 {
                    continue;
                }
                let Ok(st) = stat_at(d.as_raw_fd(), &name) else { continue };
                let Some(attr) = attr_of(&st) else { continue };
                let target = match attr.ty {
                    FileType::Symlink => match readlink_at(d.as_raw_fd(), &name).map(String::from_utf8) {
                        Ok(Ok(t)) if !t.is_empty() => t,
                        _ => continue,
                    },
                    _ => String::new(),
                };
                entries.push((s.to_string(), attr, target));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
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
        for (name, ..) in &listing.entries[start..end] {
            ids.push(self.id(dir, name)?);
        }
        let entries = listing.entries[start..end]
            .iter()
            .zip(ids)
            .map(|((name, attr, target), id)| ListEntry { name, id, attr: *attr, target })
            .collect();
        let more = end < listing.entries.len();
        let bytes = Reply::Listed { dir: dir_attr, entries, more }.encode(0);
        if more {
            self.listing = Some(listing);
        }
        Ok(bytes)
    }
}

/// rename, or with `noreplace` fail if `to` exists.
fn rename(from_dir: RawFd, from: &CStr, to_dir: RawFd, to: &CStr, noreplace: bool) -> io::Result<()> {
    // SAFETY: renameat and its variants on descriptors we hold and checked
    // names; none follows a link in the last component.
    let r = if !noreplace {
        unsafe { libc::renameat(from_dir, from.as_ptr(), to_dir, to.as_ptr()) }
    } else {
        #[cfg(target_os = "linux")]
        let r = unsafe { libc::renameat2(from_dir, from.as_ptr(), to_dir, to.as_ptr(), libc::RENAME_NOREPLACE) };
        #[cfg(target_os = "macos")]
        let r = unsafe { libc::renameatx_np(from_dir, from.as_ptr(), to_dir, to.as_ptr(), libc::RENAME_EXCL) };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let r = {
            let _ = (from_dir, from, to_dir, to);
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        };
        r
    };
    check(r).map(|_| ())
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

    #[test]
    fn serves_inside_the_mount_only() {
        let root = std::env::temp_dir().join(format!("grix-hostfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("m/sub")).unwrap();
        std::fs::write(root.join("m/a.txt"), "hello").unwrap();
        std::fs::write(root.join("secret"), "no").unwrap();
        std::os::unix::fs::symlink(root.join("secret"), root.join("m/out")).unwrap();
        let m = LiveMount { host: root.join("m").canonicalize().unwrap(), guest: "/m".into(), writable: true };
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
        req(&mut s, Request::Rename { from_dir: 1, from: "n", to_dir: 1, to: "renamed", noreplace: true });
        assert_eq!(std::fs::read_to_string(root.join("m/renamed")).unwrap(), "abcdef");
        let r = req(&mut s, Request::Stat { id });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Attr(Attr { size: 6, .. })));
        let r = req(&mut s, Request::Rename { from_dir: 1, from: "renamed", to_dir: 1, to: "a.txt", noreplace: true });
        assert!(matches!(Reply::decode(&r).unwrap().1, Reply::Err(_)));
        req(&mut s, Request::Remove { dir: 1, name: "renamed", is_dir: false });
        assert!(!root.join("m/renamed").exists());

        // A read-only mount refuses changes.
        let ro = LiveMount { host: root.join("m").canonicalize().unwrap(), guest: "/m".into(), writable: false };
        let mut s = Server::new(&[ro]).unwrap();
        let r = req(&mut s, Request::Create { dir: 1, name: "x", ty: FileType::Dir, mode: 0o755, target: "" });
        assert_eq!(Reply::decode(&r).unwrap().1, Reply::Err(EROFS));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
