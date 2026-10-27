//! The filesystem the program sees: exactly the files the host imported,
//! plus synthetic nodes: /dev, /proc and /sys (see procfs.rs), and
//! /etc/passwd + /etc/group describing the sandbox user unless imported.
//!
//! With `fs_write` the whole tree is writable, like a tmpfs layered over
//! the imports. Imported contents are referenced in place from the boot
//! image; the first write to a page copies it into a frame of guest memory.
//! Nothing ever reaches the host. Written pages are bounded by a size limit
//! (`set_limit`, like tmpfs's `size=`) and the kernel memory that names and
//! nodes take by a metadata budget (like `nr_inodes`), so a program can fill
//! the filesystem but not the kernel heap.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Bound;
use core::sync::atomic::{AtomicU64, Ordering};
use grix_abi::image::{Entry, EntryKind};
use spin::{Mutex, MutexGuard};

use crate::errno::*;
use crate::mm::{PAGE_SIZE, frame, p2v};
use crate::procfs::{self, ProcFile};

pub type Ino = usize;
pub const ROOT: Ino = 0;
/// Symlinks followed in one lookup before ELOOP, as on Linux.
const MAX_SYMLINKS: u32 = 40;
pub const NAME_MAX: usize = 255;

pub const S_IFIFO: u32 = 0o010000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_ISVTX: u32 = 0o1000;

pub const MAY_READ: u32 = 4;
pub const MAY_WRITE: u32 = 2;
pub const MAY_EXEC: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dev {
    Null,
    Zero,
    Random,
}

// ---------------------------------------------------------------- limits

/// Pages of written file data, against the size limit.
static PAGES_USED: AtomicU64 = AtomicU64::new(0);
static PAGES_LIMIT: AtomicU64 = AtomicU64::new(0);
/// Kernel heap bytes (estimated) taken by nodes and names the program
/// created. The heap is 32 MiB and an allocation failure there is a kernel
/// panic, so this stays well below it.
static META_USED: AtomicU64 = AtomicU64::new(0);
const META_LIMIT: u64 = 12 << 20;
/// Estimated heap cost of a node (the boxed Node, its pin) and of a directory
/// entry (B-tree slot), on top of the bytes of names and symlink targets.
const NODE_COST: u64 = core::mem::size_of::<Node>() as u64 + 64;
const ENTRY_COST: u64 = 64;

/// Limit written file data to `pages` pages of guest memory.
pub fn set_limit(pages: u64) {
    PAGES_LIMIT.store(pages, Ordering::Relaxed);
}

/// (pages of file data in use, the limit)
pub fn usage() -> (u64, u64) {
    (PAGES_USED.load(Ordering::Relaxed), PAGES_LIMIT.load(Ordering::Relaxed))
}

fn charge(bytes: u64) -> Result<(), Errno> {
    if META_USED.load(Ordering::Relaxed) + bytes > META_LIMIT {
        return Err(ENOSPC);
    }
    META_USED.fetch_add(bytes, Ordering::Relaxed);
    Ok(())
}

fn release(bytes: u64) {
    // One CPU and no preemption in the kernel: load-then-store doesn't race.
    META_USED.store(META_USED.load(Ordering::Relaxed).saturating_sub(bytes), Ordering::Relaxed);
}

fn entry_cost(name: &str) -> u64 {
    // The name is stored twice: as the directory's key and as the node's name.
    ENTRY_COST + 2 * name.len() as u64
}

// ---------------------------------------------------------------- file contents

/// A regular file's bytes: the imported contents (`base`), shadowed page by
/// page by frames holding written data. Bytes past both read as zero.
pub struct FileData {
    base: &'static [u8],
    /// Page index -> physical address of a frame owned by this file.
    pages: BTreeMap<u64, u64>,
    len: u64,
    /// MAP_SHARED mappings of this file, which see a copy taken when each
    /// page faulted in (writes don't reach them yet).
    shared_maps: Vec<Weak<()>>,
}

pub type Content = Arc<Mutex<FileData>>;

impl core::fmt::Debug for FileData {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "FileData {{ len: {}, pages: {} }}", self.len, self.pages.len())
    }
}

impl FileData {
    pub fn new(base: &'static [u8]) -> Content {
        Arc::new(Mutex::new(FileData { base, pages: BTreeMap::new(), len: base.len() as u64, shared_maps: Vec::new() }))
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    /// The imported bytes, if the file was never changed. Exec and mmap use
    /// them directly.
    pub fn image(&self) -> Option<&'static [u8]> {
        (self.pages.is_empty() && self.len == self.base.len() as u64).then_some(self.base)
    }

    /// Register a MAP_SHARED mapping; it lasts as long as the token.
    pub fn map_shared(&mut self) -> Arc<()> {
        self.shared_maps.retain(|w| w.strong_count() > 0);
        let token = Arc::new(());
        self.shared_maps.push(Arc::downgrade(&token));
        token
    }

    /// Would a change now be missed by a MAP_SHARED mapping?
    pub fn mapped_shared(&self) -> bool {
        self.shared_maps.iter().any(|w| w.strong_count() > 0)
    }

    /// Copy the bytes at `off` into `out`; returns how many there were.
    pub fn read(&self, off: u64, out: &mut [u8]) -> usize {
        if off >= self.len {
            return 0;
        }
        let n = (out.len() as u64).min(self.len - off) as usize;
        let mut done = 0;
        while done < n {
            let pos = off + done as u64;
            let (idx, in_page) = (pos / PAGE_SIZE, (pos % PAGE_SIZE) as usize);
            let k = (n - done).min(PAGE_SIZE as usize - in_page);
            let dst = &mut out[done..done + k];
            match self.pages.get(&idx) {
                Some(&pa) => dst.copy_from_slice(&page(pa)[in_page..in_page + k]),
                None => {
                    let from = (pos as usize).min(self.base.len());
                    let avail = (self.base.len() - from).min(k);
                    dst[..avail].copy_from_slice(&self.base[from..from + avail]);
                    dst[avail..].fill(0);
                }
            }
            done += k;
        }
        n
    }

    /// The frame for page `idx`, allocating it (with the imported bytes) on first write.
    fn page_mut(&mut self, idx: u64) -> Result<&'static mut [u8], Errno> {
        if let Some(&pa) = self.pages.get(&idx) {
            return Ok(page_mut(pa));
        }
        let (used, limit) = usage();
        if used >= limit {
            return Err(ENOSPC);
        }
        let pa = frame::alloc().ok_or(ENOSPC)?;
        PAGES_USED.fetch_add(1, Ordering::Relaxed);
        let p = page_mut(pa);
        let start = ((idx * PAGE_SIZE) as usize).min(self.base.len());
        let end = (start + PAGE_SIZE as usize).min(self.base.len());
        p[..end - start].copy_from_slice(&self.base[start..end]);
        self.pages.insert(idx, pa);
        Ok(p)
    }

    /// Write `data` at `off`, growing the file. On ENOSPC part of it may have
    /// been written; the error carries how much.
    pub fn write(&mut self, off: u64, data: &[u8]) -> Result<usize, (usize, Errno)> {
        let mut done = 0;
        while done < data.len() {
            let pos = off + done as u64;
            let (idx, in_page) = (pos / PAGE_SIZE, (pos % PAGE_SIZE) as usize);
            let k = (data.len() - done).min(PAGE_SIZE as usize - in_page);
            match self.page_mut(idx) {
                Ok(p) => p[in_page..in_page + k].copy_from_slice(&data[done..done + k]),
                Err(e) => return Err((done, e)),
            }
            done += k;
            self.len = self.len.max(pos + k as u64);
        }
        Ok(done)
    }

    /// Set the length. Growing adds zeros (without allocating); shrinking
    /// frees whole pages and zeroes the rest of the last one, so a later
    /// extension reads zeros.
    pub fn truncate(&mut self, len: u64) {
        if len < self.len {
            let keep = len.div_ceil(PAGE_SIZE);
            for (_, pa) in self.pages.split_off(&keep) {
                free_page(pa);
            }
            if !len.is_multiple_of(PAGE_SIZE)
                && let Some(&pa) = self.pages.get(&(len / PAGE_SIZE))
            {
                page_mut(pa)[(len % PAGE_SIZE) as usize..].fill(0);
            }
            self.base = &self.base[..self.base.len().min(len as usize)];
        }
        self.len = len;
    }
}

impl Drop for FileData {
    fn drop(&mut self) {
        for &pa in self.pages.values() {
            free_page(pa);
        }
    }
}

fn page(pa: u64) -> &'static [u8] {
    // SAFETY: `pa` is a frame owned by a FileData, mapped linearly; the
    // kernel runs on one CPU and the owner is locked.
    unsafe { core::slice::from_raw_parts(p2v(pa) as *const u8, PAGE_SIZE as usize) }
}

fn page_mut(pa: u64) -> &'static mut [u8] {
    // SAFETY: as for `page`, and the owner is locked mutably.
    unsafe { core::slice::from_raw_parts_mut(p2v(pa) as *mut u8, PAGE_SIZE as usize) }
}

fn free_page(pa: u64) {
    frame::free(pa);
    PAGES_USED.fetch_sub(1, Ordering::Relaxed);
}

/// Unix permission check (`MAY_*` bits) of a node with `mode`, owned by
/// `owner`/`group`, for `uid`/`gid`. Root passes, except for executing a
/// file with no execute bit at all.
pub fn mode_permits(mode: u32, owner: u32, group: u32, is_dir: bool, uid: u32, gid: u32, want: u32) -> bool {
    if uid == 0 {
        return want & MAY_EXEC == 0 || mode & 0o111 != 0 || is_dir;
    }
    let bits = if uid == owner {
        mode >> 6
    } else if gid == group {
        mode >> 3
    } else {
        mode
    };
    bits & 7 & want == want
}

// ---------------------------------------------------------------- nodes

pub enum Kind {
    File(Content),
    /// A file with no names left. Open descriptors hold the contents.
    /// `linkable` (O_TMPFILE) files may get a name with linkat.
    Unlinked {
        data: Weak<Mutex<FileData>>,
        linkable: bool,
    },
    Dir(BTreeMap<String, Ino>),
    Symlink(String),
    Dev(Dev),
    /// Generated when opened.
    Proc(ProcFile),
}

pub struct Node {
    pub kind: Kind,
    /// Permission bits, with setuid/setgid/sticky.
    pub perm: u32,
    pub uid: u32,
    pub gid: u32,
    pub parent: Ino,
    pub name: String,
    /// Names of this node. Directories use 1 while linked and 0 once removed.
    pub nlink: u32,
    /// Created or (for directories) changed by the program, rather than
    /// imported or generated as it was at boot.
    pub changed: bool,
    /// Part of /dev, /proc or /sys: nothing in it can be created, removed,
    /// renamed or have its attributes changed (as with devtmpfs for a
    /// non-root user, and procfs).
    pub system: bool,
    /// Realtime nanoseconds.
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    /// Held by open descriptors and the working directory: an unlinked
    /// node's slot is only reused once nothing refers to it.
    pin: Arc<()>,
}

impl Node {
    fn new(kind: Kind, perm: u32, owner: (u32, u32), parent: Ino, name: &str, time: u64) -> Node {
        Node {
            kind,
            perm,
            uid: owner.0,
            gid: owner.1,
            parent,
            name: name.into(),
            nlink: 1,
            changed: false,
            system: false,
            atime: time,
            mtime: time,
            ctime: time,
            pin: Arc::new(()),
        }
    }

    /// Heap bytes counted against the metadata budget, besides its names.
    fn cost(&self) -> u64 {
        NODE_COST + if let Kind::Symlink(t) = &self.kind { t.len() as u64 } else { 0 }
    }
}

pub struct StatInfo {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub blocks: u64,
    pub rdev: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

pub struct Fs {
    /// Boxed so growing the table doesn't need room for two copies of every
    /// node at once on the small kernel heap.
    #[allow(clippy::vec_box)]
    nodes: Vec<Box<Node>>,
    /// Removed nodes, whose slots are reused once nothing refers to them.
    orphans: Vec<Ino>,
    /// Reclaimed slots ready for new nodes.
    free: Vec<Ino>,
    /// `/proc/1/fd`, whose entries are the live descriptors.
    pub fd_dir: Ino,
}

static FS: Mutex<Option<Fs>> = Mutex::new(None);

/// Make `fs` the filesystem. Done once, after exec resolved the program.
pub fn install(fs: Fs) {
    *FS.lock() = Some(fs);
}

pub struct FsGuard(MutexGuard<'static, Option<Fs>>);

impl core::ops::Deref for FsGuard {
    type Target = Fs;
    fn deref(&self) -> &Fs {
        self.0.as_ref().unwrap()
    }
}

impl core::ops::DerefMut for FsGuard {
    fn deref_mut(&mut self) -> &mut Fs {
        self.0.as_mut().unwrap()
    }
}

/// The filesystem. One CPU and no preemption in the kernel, so the lock is
/// never contended: failing to take it means it is already held further up
/// the call stack, a kernel bug that would otherwise hang.
pub fn lock() -> FsGuard {
    let g = FS.try_lock().expect("filesystem lock taken twice");
    assert!(g.is_some(), "fs not initialised");
    FsGuard(g)
}

fn leak(s: String) -> &'static [u8] {
    alloc::boxed::Box::leak(s.into_boxed_str()).as_bytes()
}

impl Fs {
    pub fn build(entries: &[Entry<'static>], uid: u32, gid: u32) -> Fs {
        let now = crate::time::realtime_ns();
        // The sandbox user owns the root and everything imported, so a program
        // can create files next to its inputs. System parts (/dev, /proc,
        // /sys, generated /etc files) belong to root, and /tmp is 1777.
        let root = Node::new(Kind::Dir(BTreeMap::new()), 0o755, (uid, gid), ROOT, "", now);
        let mut fs = Fs { nodes: vec![Box::new(root)], orphans: Vec::new(), free: Vec::new(), fd_dir: ROOT };
        for e in entries {
            let path = e.path.trim_end_matches('/');
            if path.is_empty() {
                fs.nodes[ROOT].perm = e.mode & 0o7777;
                continue;
            }
            let Some(slash) = path.rfind('/') else { continue };
            let name = &path[slash + 1..];
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let parent = fs.mkdir_owned(&path[..slash], (uid, gid));
            let kind = match e.kind {
                EntryKind::File => Kind::File(FileData::new(e.data)),
                EntryKind::Dir => Kind::Dir(BTreeMap::new()),
                EntryKind::Symlink => Kind::Symlink(String::from_utf8_lossy(e.data).into_owned()),
            };
            let ino = fs.insert(parent, name, kind, e.mode & 0o7777);
            (fs.nodes[ino].uid, fs.nodes[ino].gid) = (uid, gid);
        }
        let dev = fs.mkdir_p("/dev");
        fs.insert(dev, "null", Kind::Dev(Dev::Null), 0o666);
        fs.insert(dev, "zero", Kind::Dev(Dev::Zero), 0o666);
        fs.insert(dev, "random", Kind::Dev(Dev::Random), 0o666);
        fs.insert(dev, "urandom", Kind::Dev(Dev::Random), 0o666);
        fs.insert(dev, "fd", Kind::Symlink("/proc/self/fd".into()), 0o777);
        for (i, name) in ["stdin", "stdout", "stderr"].iter().enumerate() {
            fs.insert(dev, name, Kind::Symlink(alloc::format!("/proc/self/fd/{i}")), 0o777);
        }

        let pid_dir = fs.mkdir_p("/proc/1");
        fs.fd_dir = fs.insert(pid_dir, "fd", Kind::Dir(BTreeMap::new()), 0o500);
        let proc = fs.mkdir_p("/proc");
        fs.insert(proc, "self", Kind::Symlink("1".into()), 0o777);
        fs.insert(proc, "thread-self", Kind::Symlink("1".into()), 0o777);
        fs.insert(proc, "mounts", Kind::Symlink("self/mounts".into()), 0o777);
        for &(path, file) in procfs::FILES {
            let (dir, name) = path.rsplit_once('/').unwrap();
            let parent = fs.mkdir_p(dir);
            fs.insert(parent, name, Kind::Proc(file), 0o444);
        }
        // /proc/<pid> belongs to the process's user (ps reads its owner from there).
        fs.nodes[pid_dir].perm = 0o555;
        fs.walk_tree(pid_dir, &mut |n| (n.uid, n.gid) = (uid, gid));
        for top in ["/dev", "/proc", "/sys"] {
            if let Ok(ino) = fs.lookup(ROOT, top, false) {
                fs.walk_tree(ino, &mut |n| n.system = true);
            }
        }
        // /dev/shm is an ordinary tmpfs (shm_open, POSIX semaphores).
        let shm = fs.mkdir_p("/dev/shm");
        (fs.nodes[shm].perm, fs.nodes[shm].system) = (0o1777, false);

        // Describe the sandbox user unless the host imported its own files.
        if fs.lookup(ROOT, "/etc/passwd", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            let passwd = alloc::format!(
                "root:x:0:0:root:/root:/sbin/nologin\ngrix:x:{uid}:{gid}:grix:/home/grix:/bin/sh\n\
                 nobody:x:65534:65534:nobody:/:/sbin/nologin\n"
            );
            fs.insert(etc, "passwd", Kind::File(FileData::new(leak(passwd))), 0o644);
            fs.mkdir_p("/home");
            fs.mkdir_owned("/home/grix", (uid, gid));
        }
        if fs.lookup(ROOT, "/etc/group", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            let group = alloc::format!("root:x:0:\ngrix:x:{gid}:\nnobody:x:65534:\n");
            fs.insert(etc, "group", Kind::File(FileData::new(leak(group))), 0o644);
        }
        if fs.lookup(ROOT, "/etc/mtab", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            fs.insert(etc, "mtab", Kind::Symlink("/proc/self/mounts".into()), 0o777);
        }
        let tmp = fs.mkdir_p("/tmp");
        if fs.nodes[tmp].uid == 0 {
            fs.nodes[tmp].perm = 0o1777;
        }
        fs
    }

    fn walk_tree(&mut self, ino: Ino, f: &mut dyn FnMut(&mut Node)) {
        f(&mut self.nodes[ino]);
        if let Kind::Dir(children) = &self.nodes[ino].kind {
            for child in children.values().copied().collect::<Vec<_>>() {
                self.walk_tree(child, f);
            }
        }
    }

    /// `/proc/self/exe` points at the program actually running (the
    /// interpreter, for `#!` scripts).
    pub fn set_exe(&mut self, path: &str) {
        let pid_dir = self.mkdir_p("/proc/1");
        let exe = self.insert(pid_dir, "exe", Kind::Symlink(path.into()), 0o777);
        let owner = &self.nodes[pid_dir];
        let (uid, gid) = (owner.uid, owner.gid);
        let n = &mut self.nodes[exe];
        (n.uid, n.gid, n.system) = (uid, gid, true);
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len() - self.orphans.len() - self.free.len()
    }

    fn child(&self, dir: Ino, name: &str) -> Option<Ino> {
        match &self.nodes[dir].kind {
            Kind::Dir(children) => children.get(name).copied(),
            _ => None,
        }
    }

    /// Directories the kernel makes on its own belong to root, like the
    /// system directories they stand for.
    fn mkdir_p(&mut self, path: &str) -> Ino {
        self.mkdir_owned(path, (0, 0))
    }

    /// Make the directories in `path` that don't exist yet, owned by `owner`.
    fn mkdir_owned(&mut self, path: &str, owner: (u32, u32)) -> Ino {
        let mut cur = ROOT;
        for c in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            cur = match self.child(cur, c) {
                Some(i) if self.is_dir(i) => i,
                _ => {
                    let dir = self.insert(cur, c, Kind::Dir(BTreeMap::new()), 0o755);
                    (self.nodes[dir].uid, self.nodes[dir].gid) = owner;
                    dir
                }
            };
        }
        cur
    }

    /// Add or replace a node at build time (root-owned). Imports count
    /// against the metadata budget, since they use the same heap, but are
    /// never refused: the host chose them.
    fn insert(&mut self, parent: Ino, name: &str, kind: Kind, perm: u32) -> Ino {
        if let Some(existing) = self.child(parent, name) {
            let node = &mut self.nodes[existing];
            if !(matches!(node.kind, Kind::Dir(_)) && matches!(kind, Kind::Dir(_))) {
                node.kind = kind;
            }
            node.perm = perm;
            return existing;
        }
        let t = self.nodes[parent].mtime;
        let ino = self.nodes.len();
        let node = Node::new(kind, perm, (0, 0), parent, name, t);
        META_USED.fetch_add(node.cost() + entry_cost(name), Ordering::Relaxed);
        self.nodes.push(Box::new(node));
        if let Kind::Dir(children) = &mut self.nodes[parent].kind {
            children.insert(name.into(), ino);
        }
        ino
    }

    pub fn node(&self, ino: Ino) -> &Node {
        &self.nodes[ino]
    }

    pub fn node_mut(&mut self, ino: Ino) -> &mut Node {
        &mut self.nodes[ino]
    }

    pub fn is_dir(&self, ino: Ino) -> bool {
        matches!(self.nodes[ino].kind, Kind::Dir(_))
    }

    /// A reference that keeps `ino` from being reused after it's removed
    /// (open descriptors, the working directory).
    pub fn pin(&self, ino: Ino) -> Arc<()> {
        self.nodes[ino].pin.clone()
    }

    /// A regular file's contents.
    pub fn content(&self, ino: Ino) -> Option<Content> {
        match &self.nodes[ino].kind {
            Kind::File(c) => Some(c.clone()),
            Kind::Unlinked { data, .. } => data.upgrade(),
            _ => None,
        }
    }

    /// Resolve `path` relative to directory `start`.
    pub fn lookup(&self, start: Ino, path: &str, follow_last: bool) -> Result<Ino, Errno> {
        let mut links = 0;
        self.walk(start, path, follow_last, &mut links)
    }

    /// `links` counts every symlink followed in the whole lookup, so a chain
    /// of links that each expand into several more can't make it exponential.
    fn walk(&self, start: Ino, path: &str, follow_last: bool, links: &mut u32) -> Result<Ino, Errno> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let mut cur = if path.starts_with('/') { ROOT } else { start };
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let must_be_dir = path.ends_with('/');
        for (i, c) in comps.iter().enumerate() {
            let last = i + 1 == comps.len();
            let Kind::Dir(children) = &self.nodes[cur].kind else { return Err(ENOTDIR) };
            match *c {
                "." => {}
                ".." => cur = self.nodes[cur].parent,
                name => {
                    let child = *children.get(name).ok_or(if name.len() > NAME_MAX { ENAMETOOLONG } else { ENOENT })?;
                    if let Kind::Symlink(target) = &self.nodes[child].kind
                        && (!last || follow_last || must_be_dir)
                    {
                        *links += 1;
                        if *links > MAX_SYMLINKS {
                            return Err(ELOOP);
                        }
                        cur = self.walk(cur, target, true, links)?;
                        continue;
                    }
                    cur = child;
                }
            }
        }
        if must_be_dir && !self.is_dir(cur) {
            return Err(ENOTDIR);
        }
        Ok(cur)
    }

    /// Split `path` into its parent directory (resolved) and last component,
    /// for calls that create or remove a name. The root has no last
    /// component (""); a trailing slash is allowed.
    pub fn lookup_parent(&self, start: Ino, path: &str) -> Result<(Ino, String), Errno> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let trimmed = path.trim_end_matches('/');
        let (dir, name) = match trimmed.rsplit_once('/') {
            Some(("", name)) => (ROOT, name),
            Some((dir, name)) => (self.lookup(start, dir, true)?, name),
            None if trimmed.is_empty() => (ROOT, ""),
            None => (if path.starts_with('/') { ROOT } else { start }, trimmed),
        };
        if !self.is_dir(dir) {
            return Err(ENOTDIR);
        }
        if name.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        Ok((dir, name.into()))
    }

    /// Absolute path of a node.
    pub fn path_of(&self, mut ino: Ino) -> String {
        let mut parts = Vec::new();
        while ino != ROOT {
            parts.push(self.nodes[ino].name.as_str());
            ino = self.nodes[ino].parent;
        }
        if parts.is_empty() {
            return "/".into();
        }
        let mut s = String::new();
        for p in parts.iter().rev() {
            s.push('/');
            s.push_str(p);
        }
        s
    }

    pub fn stat(&self, ino: Ino) -> StatInfo {
        let n = &self.nodes[ino];
        let (ty, size, nlink, rdev) = match &n.kind {
            Kind::File(c) => (S_IFREG, c.lock().len(), n.nlink, 0),
            Kind::Unlinked { data, .. } => (S_IFREG, data.upgrade().map_or(0, |c| c.lock().len()), 0, 0),
            // Over-counting subdirectories is safe for find's leaf optimisation.
            Kind::Dir(c) if n.nlink > 0 => (S_IFDIR, 4096, 2 + c.len() as u32, 0),
            Kind::Dir(_) => (S_IFDIR, 4096, 0, 0),
            Kind::Symlink(t) => (S_IFLNK, t.len() as u64, n.nlink, 0),
            Kind::Dev(d) => {
                let minor = match d {
                    Dev::Null => 3,
                    Dev::Zero => 5,
                    Dev::Random => 9,
                };
                (S_IFCHR, 0, 1, (1 << 8) | minor)
            }
            Kind::Proc(_) => (S_IFREG, 0, 1, 0),
        };
        StatInfo {
            ino: ino as u64 + 1,
            mode: ty | n.perm,
            nlink,
            uid: n.uid,
            gid: n.gid,
            size,
            blocks: size.div_ceil(512),
            rdev,
            atime: n.atime,
            mtime: n.mtime,
            ctime: n.ctime,
        }
    }

    /// The child after `after` in name order (the first one for `None`), for
    /// getdents. A name cursor stays correct while entries come and go.
    pub fn dir_next(&self, dir: Ino, after: Option<&str>) -> Option<(String, Ino)> {
        let Kind::Dir(children) = &self.nodes[dir].kind else { return None };
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        children.range::<str, _>((lower, Bound::Unbounded)).next().map(|(k, v)| (k.clone(), *v))
    }

    /// Linux d_type for a node.
    pub fn d_type(&self, ino: Ino) -> u8 {
        match self.nodes[ino].kind {
            Kind::File(_) | Kind::Unlinked { .. } | Kind::Proc(_) => 8,
            Kind::Dir(_) => 4,
            Kind::Symlink(_) => 10,
            Kind::Dev(_) => 2,
        }
    }

    // ------------------------------------------------------------ permissions and changes

    /// Unix permission check for the sandbox user (`MAY_*` bits).
    pub fn permits(&self, ino: Ino, uid: u32, gid: u32, want: u32) -> bool {
        let n = &self.nodes[ino];
        mode_permits(n.perm, n.uid, n.gid, self.is_dir(ino), uid, gid, want)
    }

    /// May `uid` add or remove names in `dir`? Sticky directories (like
    /// /tmp) also require owning the entry or the directory to remove it.
    fn may_change(&self, dir: Ino, victim: Option<Ino>, uid: u32, gid: u32) -> Result<(), Errno> {
        if self.nodes[dir].system || !self.permits(dir, uid, gid, MAY_WRITE | MAY_EXEC) {
            return Err(EACCES);
        }
        if let Some(v) = victim
            && self.nodes[dir].perm & S_ISVTX != 0
            && uid != 0
            && uid != self.nodes[v].uid
            && uid != self.nodes[dir].uid
        {
            return Err(EPERM);
        }
        Ok(())
    }

    /// A file's contents changed (write, truncate).
    pub fn modified(&mut self, ino: Ino) {
        let now = crate::time::realtime_ns();
        let n = &mut self.nodes[ino];
        (n.mtime, n.ctime) = (now, now);
    }

    /// A node's metadata changed (chmod, chown, utimensat).
    pub fn changed(&mut self, ino: Ino) {
        self.nodes[ino].ctime = crate::time::realtime_ns();
    }

    pub fn child_of(&self, dir: Ino, name: &str) -> Option<Ino> {
        self.child(dir, name)
    }

    fn touch_dir(&mut self, dir: Ino) {
        let now = crate::time::realtime_ns();
        let d = &mut self.nodes[dir];
        (d.mtime, d.ctime, d.changed) = (now, now, true);
    }

    /// Is a failed lookup of `path` worth reporting as "not imported"? Not
    /// when the deepest directory that exists was made or changed by the
    /// program itself, or is a sticky scratch directory like /tmp: then the
    /// name is the program's business (a file it deleted, or is checking for
    /// before creating it).
    pub fn missing_is_import_gap(&self, base: Ino, path: &str) -> bool {
        let gap = |ino: Ino| !self.nodes[ino].changed && self.nodes[ino].perm & S_ISVTX == 0;
        let mut p = path.trim_end_matches('/');
        loop {
            match p.rsplit_once('/') {
                Some((dir, _)) => {
                    let dir = if dir.is_empty() { "/" } else { dir };
                    if let Ok(ino) = self.lookup(base, dir, true) {
                        return gap(ino);
                    }
                    p = dir.trim_end_matches('/');
                }
                None => return gap(base),
            }
        }
    }

    /// Free the slots of removed nodes that nothing refers to any more.
    fn reclaim(&mut self) {
        let mut i = 0;
        while i < self.orphans.len() {
            let ino = self.orphans[i];
            if Arc::strong_count(&self.nodes[ino].pin) > 1 {
                i += 1;
                continue;
            }
            self.orphans.swap_remove(i);
            release(self.nodes[ino].cost());
            // Dropping the node drops its contents (unlinked files have none
            // left by now) and its name.
            *self.nodes[ino] = Node::new(Kind::Unlinked { data: Weak::new(), linkable: false }, 0, (0, 0), ROOT, "", 0);
            self.nodes[ino].nlink = 0;
            self.free.push(ino);
        }
    }

    /// A slot for a new node, which has been charged for.
    fn alloc_node(&mut self, node: Node) -> Ino {
        match self.free.pop() {
            Some(ino) => {
                *self.nodes[ino] = node;
                ino
            }
            None => {
                self.nodes.push(Box::new(node));
                self.nodes.len() - 1
            }
        }
    }

    /// Create `name` in `dir`, owned by `uid`/`gid`. `name` must be new.
    pub fn create(&mut self, dir: Ino, name: &str, kind: Kind, perm: u32, uid: u32, gid: u32) -> Result<Ino, Errno> {
        if self.nodes[dir].nlink == 0 {
            return Err(ENOENT); // the directory was removed
        }
        if name.is_empty() || name == "." || name == ".." || self.child(dir, name).is_some() {
            return Err(EEXIST);
        }
        self.may_change(dir, None, uid, gid)?;
        let mut node = Node::new(kind, perm, (uid, gid), dir, name, crate::time::realtime_ns());
        node.changed = true;
        self.reclaim();
        charge(node.cost() + entry_cost(name))?;
        let ino = self.alloc_node(node);
        let Kind::Dir(children) = &mut self.nodes[dir].kind else { unreachable!() };
        children.insert(name.into(), ino);
        self.touch_dir(dir);
        Ok(ino)
    }

    /// An unnamed file in `dir` (O_TMPFILE). It goes away when its last
    /// descriptor closes, unless linkat gives it a name.
    pub fn create_unnamed(&mut self, dir: Ino, perm: u32, uid: u32, gid: u32) -> Result<(Ino, Content), Errno> {
        self.may_change(dir, None, uid, gid)?;
        let content = FileData::new(&[]);
        let kind = Kind::Unlinked { data: Arc::downgrade(&content), linkable: true };
        let mut node = Node::new(kind, perm, (uid, gid), dir, "", crate::time::realtime_ns());
        (node.nlink, node.changed) = (0, true);
        self.reclaim();
        charge(node.cost())?;
        let ino = self.alloc_node(node);
        self.orphans.push(ino);
        Ok((ino, content))
    }

    /// Drop one name of `ino` (already removed from its directory).
    fn drop_name(&mut self, ino: Ino) {
        let now = crate::time::realtime_ns();
        let n = &mut self.nodes[ino];
        n.nlink = n.nlink.saturating_sub(1);
        n.ctime = now;
        if matches!(n.kind, Kind::Dir(_)) {
            n.nlink = 0;
        }
        if n.nlink > 0 {
            return;
        }
        if let Kind::File(c) = &n.kind {
            // Open descriptors keep the contents alive; nothing else does.
            n.kind = Kind::Unlinked { data: Arc::downgrade(c), linkable: false };
        }
        self.orphans.push(ino);
    }

    /// unlink / rmdir `name` in `dir`.
    pub fn remove(&mut self, dir: Ino, name: &str, rmdir: bool, uid: u32, gid: u32) -> Result<(), Errno> {
        let ino = self.child(dir, name).ok_or(ENOENT)?;
        match (&self.nodes[ino].kind, rmdir) {
            (Kind::Dir(c), true) if !c.is_empty() => return Err(ENOTEMPTY),
            (Kind::Dir(_), true) => {}
            (Kind::Dir(_), false) => return Err(EISDIR),
            (_, true) => return Err(ENOTDIR),
            (_, false) => {}
        }
        self.may_change(dir, Some(ino), uid, gid)?;
        let Kind::Dir(children) = &mut self.nodes[dir].kind else { unreachable!() };
        children.remove(name);
        release(entry_cost(name));
        self.touch_dir(dir);
        self.drop_name(ino);
        Ok(())
    }

    /// Give `ino` (not a directory) another name.
    pub fn link(&mut self, ino: Ino, dir: Ino, name: &str, uid: u32, gid: u32) -> Result<(), Errno> {
        if self.is_dir(ino) {
            return Err(EPERM);
        }
        if self.nodes[dir].nlink == 0 {
            return Err(ENOENT);
        }
        if name.is_empty() || name == "." || name == ".." || self.child(dir, name).is_some() {
            return Err(EEXIST);
        }
        if self.nodes[ino].system {
            return Err(EPERM);
        }
        self.may_change(dir, None, uid, gid)?;
        let revive = match &self.nodes[ino].kind {
            // An O_TMPFILE file getting its first name. Other unlinked files
            // stay gone, as on Linux.
            Kind::Unlinked { data, linkable: true } => Some(data.upgrade().ok_or(ENOENT)?),
            Kind::Unlinked { .. } => return Err(ENOENT),
            _ if self.nodes[ino].nlink == 0 => return Err(ENOENT),
            _ => None,
        };
        charge(entry_cost(name))?;
        if let Some(c) = revive {
            self.orphans.retain(|&o| o != ino);
            let n = &mut self.nodes[ino];
            (n.kind, n.parent, n.name) = (Kind::File(c), dir, name.into());
        }
        let Kind::Dir(children) = &mut self.nodes[dir].kind else { unreachable!() };
        children.insert(name.into(), ino);
        let now = crate::time::realtime_ns();
        let n = &mut self.nodes[ino];
        n.nlink += 1;
        n.ctime = now;
        self.touch_dir(dir);
        Ok(())
    }

    /// renameat2. `noreplace` and `exchange` are RENAME_NOREPLACE / RENAME_EXCHANGE.
    #[allow(clippy::too_many_arguments)]
    pub fn rename(
        &mut self,
        odir: Ino,
        oname: &str,
        ndir: Ino,
        nname: &str,
        noreplace: bool,
        exchange: bool,
        uid: u32,
        gid: u32,
    ) -> Result<(), Errno> {
        let src = self.child(odir, oname).ok_or(ENOENT)?;
        let dst = self.child(ndir, nname);
        if self.nodes[ndir].nlink == 0 {
            return Err(ENOENT);
        }
        self.may_change(odir, Some(src), uid, gid)?;
        self.may_change(ndir, dst, uid, gid)?;
        // A directory can't move into itself or its own subtree.
        for (moving, into) in [(Some(src), ndir), (dst.filter(|_| exchange), odir)] {
            if let Some(m) = moving.filter(|&m| self.is_dir(m)) {
                let mut d = into;
                loop {
                    if d == m {
                        return Err(EINVAL);
                    }
                    if d == ROOT {
                        break;
                    }
                    d = self.nodes[d].parent;
                }
            }
        }
        if exchange {
            let dst = dst.ok_or(ENOENT)?;
            for (dir, name, ino) in [(odir, oname, dst), (ndir, nname, src)] {
                let Kind::Dir(children) = &mut self.nodes[dir].kind else { unreachable!() };
                children.insert(name.into(), ino);
                (self.nodes[ino].parent, self.nodes[ino].name) = (dir, name.into());
            }
        } else {
            match dst {
                Some(_) if noreplace => return Err(EEXIST),
                Some(dst) if dst == src => return Ok(()), // two names of one file: nothing to do
                Some(dst) => {
                    match (self.is_dir(src), &self.nodes[dst].kind) {
                        (true, Kind::Dir(c)) if !c.is_empty() => return Err(ENOTEMPTY),
                        (true, Kind::Dir(_)) => {}
                        (true, _) => return Err(ENOTDIR),
                        (false, Kind::Dir(_)) => return Err(EISDIR),
                        (false, _) => {}
                    }
                    // The new name's entry is reused for src.
                    self.drop_name(dst);
                }
                None => charge(entry_cost(nname))?,
            }
            let Kind::Dir(children) = &mut self.nodes[odir].kind else { unreachable!() };
            children.remove(oname);
            release(entry_cost(oname));
            let Kind::Dir(children) = &mut self.nodes[ndir].kind else { unreachable!() };
            children.insert(nname.into(), src);
            (self.nodes[src].parent, self.nodes[src].name) = (ndir, nname.into());
        }
        let now = crate::time::realtime_ns();
        self.nodes[src].ctime = now;
        self.touch_dir(odir);
        self.touch_dir(ndir);
        Ok(())
    }
}
