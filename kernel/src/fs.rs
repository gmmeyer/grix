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
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Bound;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use grix_abi::hostfs::{Attr, FileType};
use grix_abi::stats::{Limit, Resource};
use grix_abi::image::{Entry, EntryKind, LiveMount};
use spin::{Mutex, MutexGuard};

use crate::console::klog;
use crate::errno::*;
use crate::hostfs;
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
pub const S_IFSOCK: u32 = 0o140000;
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
    /// /dev/ptmx: opening it makes a pseudo-terminal pair (tty.rs).
    Ptmx,
    /// /dev/pts/N: a pair's slave.
    Pts(u32),
    /// /dev/tty: the caller's controlling terminal.
    Tty,
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

/// (bytes of names and nodes in use, the limit)
pub fn meta_usage() -> (u64, u64) {
    (META_USED.load(Ordering::Relaxed), META_LIMIT)
}

fn charge(bytes: u64) -> Result<(), Errno> {
    if META_USED.load(Ordering::Relaxed) + bytes > META_LIMIT {
        crate::stats::hit(Limit::FileMetadata);
        return Err(ENOSPC);
    }
    let now = META_USED.fetch_add(bytes, Ordering::Relaxed) + bytes;
    crate::stats::peak(Resource::FileMetadata, now);
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
    /// A live mount's file's MAP_SHARED mappings, which see a copy taken
    /// when each page faulted in (writes don't reach them).
    shared_maps: Vec<Weak<()>>,
    /// MAP_SHARED mappings of a file in the sandbox, which map its pages,
    /// and those of them that may write (memfd seals refuse F_SEAL_WRITE
    /// while there are any).
    live_maps: Vec<Weak<()>>,
    writable_maps: Vec<Weak<()>>,
    /// Pages a shared mapping read before the file had a frame for them:
    /// it got a read-only copy, which must go once there's a frame
    /// (`STALE`).
    copied: alloc::collections::BTreeSet<u64>,
    /// memfd seals (F_SEAL_*); `None` for files that can't be sealed.
    pub seals: Option<u32>,
    /// A live mount's file: the host's id for it. Its bytes are on the host
    /// (`len` is its size as last heard).
    remote: Option<u64>,
    /// A live mount's file the program removed (or replaced) while it had
    /// it: the host keeps it open until this goes.
    pub unlinked: bool,
    /// A lazy import's file copied up: the sandbox's now, its bytes still
    /// read from the host until the first write or truncate brings them in
    /// (`make_local`).
    cow: bool,
}

pub const F_SEAL_SEAL: u32 = 1;
pub const F_SEAL_SHRINK: u32 = 2;
pub const F_SEAL_GROW: u32 = 4;
pub const F_SEAL_WRITE: u32 = 8;
pub const F_SEAL_FUTURE_WRITE: u32 = 16;

pub type Content = Arc<Mutex<FileData>>;

impl core::fmt::Debug for FileData {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "FileData {{ len: {}, pages: {} }}", self.len, self.pages.len())
    }
}

impl FileData {
    pub fn new(base: &'static [u8]) -> Content {
        Arc::new(Mutex::new(FileData {
            base,
            pages: BTreeMap::new(),
            len: base.len() as u64,
            shared_maps: Vec::new(),
            live_maps: Vec::new(),
            writable_maps: Vec::new(),
            copied: alloc::collections::BTreeSet::new(),
            seals: None,
            remote: None,
            unlinked: false,
            cow: false,
        }))
    }

    /// A live mount's file `id`, `size` bytes long.
    pub fn remote(id: u64, size: u64) -> Content {
        Arc::new(Mutex::new(FileData {
            base: &[],
            pages: BTreeMap::new(),
            len: size,
            shared_maps: Vec::new(),
            live_maps: Vec::new(),
            writable_maps: Vec::new(),
            copied: alloc::collections::BTreeSet::new(),
            seals: None,
            remote: Some(id),
            unlinked: false,
            cow: false,
        }))
    }

    /// The host's id for a live mount's file (not a copied-up one's: that
    /// is the sandbox's, though its bytes may still be read from there).
    pub fn remote_id(&self) -> Option<u64> {
        self.remote.filter(|_| !self.cow)
    }

    /// A lazy import's file is copied up: the sandbox's from now on.
    pub fn adopt(&mut self) {
        self.cow = self.remote.is_some();
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    /// The imported bytes, if the file was never changed. Exec and mmap use
    /// them directly.
    pub fn image(&self) -> Option<&'static [u8]> {
        (self.remote.is_none() && self.pages.is_empty() && self.len == self.base.len() as u64).then_some(self.base)
    }

    /// May bytes be written up to offset `end`? Seals forbid writing at all,
    /// or growing.
    pub fn may_write(&self, end: u64) -> Result<(), Errno> {
        let seals = self.seals.unwrap_or(0);
        if seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 || (seals & F_SEAL_GROW != 0 && end > self.len) {
            return Err(EPERM);
        }
        Ok(())
    }

    /// May the length change to `len`?
    pub fn may_resize(&self, len: u64) -> Result<(), Errno> {
        let seals = self.seals.unwrap_or(0);
        if (seals & F_SEAL_SHRINK != 0 && len < self.len) || (seals & F_SEAL_GROW != 0 && len > self.len) {
            return Err(EPERM);
        }
        Ok(())
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

    /// Register a MAP_SHARED mapping of the file's own pages (`writable`:
    /// one that may write, now or after mprotect).
    pub fn map_live(&mut self, writable: bool) -> Arc<()> {
        self.live_maps.retain(|w| w.strong_count() > 0);
        self.writable_maps.retain(|w| w.strong_count() > 0);
        let token = Arc::new(());
        self.live_maps.push(Arc::downgrade(&token));
        if writable {
            self.writable_maps.push(Arc::downgrade(&token));
        }
        token
    }

    /// Is the file mapped MAP_SHARED by a mapping that may write?
    pub fn mapped_writable(&self) -> bool {
        self.writable_maps.iter().any(|w| w.strong_count() > 0)
    }

    /// This file, as `STALE` names it.
    pub fn id(&self) -> usize {
        self as *const FileData as usize
    }

    /// A shared mapping took a read-only copy of page `idx`.
    pub fn copied_page(&mut self, idx: u64) {
        self.copied.insert(idx);
    }

    /// Is the file's memory mapped MAP_SHARED anywhere?
    pub fn mapped_live(&self) -> bool {
        self.live_maps.iter().any(|w| w.strong_count() > 0)
    }

    /// Copy the bytes at `off` into `out`; returns how many there were. A
    /// live mount's file that can't be read reads as ended (and is logged);
    /// `read_at` says why.
    pub fn read(&self, off: u64, out: &mut [u8]) -> usize {
        self.read_at(off, out).unwrap_or_else(|e| {
            klog!("reading a mounted file: errno {}\n", e.0);
            0
        })
    }

    pub fn read_at(&self, off: u64, out: &mut [u8]) -> Result<usize, Errno> {
        if let Some(id) = self.remote {
            return hostfs::read(id, off, out);
        }
        Ok(self.read_local(off, out))
    }

    fn read_local(&self, off: u64, out: &mut [u8]) -> usize {
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
        self.frame_of(idx).map(page_mut)
    }

    /// Page `idx`'s frame for a shared mapping (which takes its own
    /// reference). A write makes it if need be; a read of a page the file
    /// has no frame for gets None (the mapping takes a read-only copy, so
    /// reading an import doesn't use up file space). Past the end of the
    /// file there's none (SIGBUS); a live mount's file has no frames.
    pub fn shared_frame(&mut self, idx: u64, write: bool) -> Result<Option<u64>, crate::mm::aspace::FaultError> {
        use crate::mm::aspace::FaultError;
        if (self.remote.is_some() && !self.cow) || idx.saturating_mul(PAGE_SIZE) >= self.len {
            return Err(FaultError::PastEnd);
        }
        if write && self.cow {
            self.make_local(u64::MAX).map_err(|_| FaultError::Io)?;
        }
        match self.pages.get(&idx) {
            Some(&pa) => Ok(Some(pa)),
            None if write => self.frame_of(idx).map(Some).map_err(|_| FaultError::Io),
            None => Ok(None),
        }
    }

    fn frame_of(&mut self, idx: u64) -> Result<u64, Errno> {
        if let Some(&pa) = self.pages.get(&idx) {
            return Ok(pa);
        }
        let (used, limit) = usage();
        if used >= limit {
            crate::stats::hit(Limit::FileData);
            return Err(ENOSPC);
        }
        let pa = frame::alloc().ok_or(ENOSPC)?;
        let pages = PAGES_USED.fetch_add(1, Ordering::Relaxed) + 1;
        crate::stats::peak(Resource::FileData, pages * PAGE_SIZE);
        let p = page_mut(pa);
        let start = ((idx * PAGE_SIZE) as usize).min(self.base.len());
        let end = (start + PAGE_SIZE as usize).min(self.base.len());
        p[..end - start].copy_from_slice(&self.base[start..end]);
        self.pages.insert(idx, pa);
        if self.copied.remove(&idx) {
            STALE.lock().push((self.id(), idx));
            STALE_ANY.store(true, Ordering::Relaxed);
        }
        Ok(pa)
    }

    /// Write `data` at `off`, growing the file. On ENOSPC part of it may have
    /// been written; the error carries how much.
    pub fn write(&mut self, off: u64, data: &[u8]) -> Result<usize, (usize, Errno)> {
        if self.remote.is_some() {
            if !self.cow {
                return self.write_remote(off, false, data).map(|(n, _)| n);
            }
            self.make_local(u64::MAX).map_err(|e| (0, e))?;
        }
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

    /// A live mount's file: write `data` at `off`, or at its end with
    /// `append`. Returns how much was written and where it started.
    pub fn write_remote(&mut self, off: u64, append: bool, data: &[u8]) -> Result<(usize, u64), (usize, Errno)> {
        let Some(id) = self.remote else { return Err((0, EINVAL)) };
        let mut done = 0;
        let mut start = off;
        while done < data.len() {
            let chunk = &data[done..(done + grix_abi::hostfs::IO_MAX).min(data.len())];
            // An append goes where the host's end is; the rest follows it.
            let first_append = append && done == 0;
            match hostfs::write(id, start + done as u64, first_append, chunk) {
                Ok((n, size)) => {
                    if first_append {
                        start = size.saturating_sub(n as u64);
                    }
                    self.len = size;
                    done += n;
                    if n < chunk.len() {
                        break;
                    }
                }
                Err(e) => return Err((done, e)),
            }
        }
        Ok((done, start))
    }

    /// A lazy import's file becomes the sandbox's: its bytes read in from
    /// the host (the first `keep` of them). On failure it stays as it was.
    pub fn make_local(&mut self, keep: u64) -> Result<(), Errno> {
        let Some(id) = self.remote else { return Ok(()) };
        let (old_len, len) = (self.len, self.len.min(keep));
        self.remote = None;
        self.cow = false;
        self.base = &[];
        let mut buf = alloc::vec![0u8; grix_abi::hostfs::IO_MAX];
        let mut off = 0;
        let result = loop {
            if off >= len {
                break Ok(());
            }
            let want = ((len - off) as usize).min(buf.len());
            match hostfs::read(id, off, &mut buf[..want]) {
                Ok(0) => break Ok(()),
                Ok(n) => match self.write(off, &buf[..n]) {
                    Ok(_) => off += n as u64,
                    Err((_, e)) => break Err(e),
                },
                Err(e) => break Err(e),
            }
        };
        match result {
            Ok(()) => {
                self.len = off;
                Ok(())
            }
            Err(e) => {
                for (_, pa) in core::mem::take(&mut self.pages) {
                    free_page(pa);
                }
                (self.remote, self.len, self.cow) = (Some(id), old_len, true);
                Err(e)
            }
        }
    }

    /// The size the host says a live mount's file has.
    pub fn set_size(&mut self, size: u64) {
        if self.remote.is_some() && !self.cow {
            self.len = size;
        }
    }

    /// Set the length. Growing adds zeros (without allocating); shrinking
    /// frees whole pages and zeroes the rest of the last one, so a later
    /// extension reads zeros.
    pub fn truncate(&mut self, len: u64) -> Result<(), Errno> {
        // (The mappings' copies past the end go with `zap_file`.)
        let keep = len.div_ceil(PAGE_SIZE);
        let _ = self.copied.split_off(&keep);
        if let Some(id) = self.remote {
            if !self.cow {
                hostfs::set_len(id, len)?;
                self.len = len;
                return Ok(());
            }
            // Only what stays is read in.
            self.make_local(len)?;
        }
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
        Ok(())
    }
}

impl Drop for FileData {
    fn drop(&mut self) {
        for &pa in self.pages.values() {
            free_page(pa);
        }
        if let Some(id) = self.remote.filter(|_| self.unlinked) {
            hostfs::release(id);
        }
    }
}

/// Pages (file, index) that got a frame while shared mappings had
/// read-only copies of them: `procs::zap_stale` takes the copies out, so
/// they fault onto the frame.
static STALE: Mutex<Vec<(usize, u64)>> = Mutex::new(Vec::new());
static STALE_ANY: AtomicBool = AtomicBool::new(false);

pub fn take_stale() -> Vec<(usize, u64)> {
    if !STALE_ANY.swap(false, Ordering::Relaxed) {
        return Vec::new();
    }
    core::mem::take(&mut *STALE.lock())
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
    /// An AF_UNIX socket's name (`unix::node_id`): connect finds the
    /// socket bound to it.
    Socket(u64),
    /// A named pipe (mkfifo).
    Fifo(crate::ipc::Fifo),
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
    /// A directory mounted from the host: it can't be removed or renamed
    /// (EBUSY, as on Linux), so its changes always have a place to go.
    pub mount_point: bool,
    /// Part of a live mount: the host has it.
    pub remote: Option<Box<Remote>>,
    /// Made by the kernel at boot, not imported (`/etc/passwd`, `/tmp`, ...).
    pub generated: bool,
    /// A lazy import's node copied into the sandbox: the inode number it
    /// had as the host's (so it doesn't change).
    pub host_ino: u64,
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
            mount_point: false,
            remote: None,
            generated: false,
            host_ino: 0,
            atime: time,
            mtime: time,
            ctime: time,
            pin: Arc::new(()),
        }
    }

    /// Heap bytes counted against the metadata budget, besides its names.
    fn cost(&self) -> u64 {
        let remote = if self.remote.is_some() { REMOTE_COST } else { 0 };
        NODE_COST + remote + if let Kind::Symlink(t) = &self.kind { t.len() as u64 } else { 0 }
    }
}

/// A node of a live mount.
pub struct Remote {
    /// The host's id for it.
    pub id: u64,
    /// Which live mount (`Image::live_mounts`).
    pub mount: usize,
    pub writable: bool,
    /// When its attributes were last heard from the host, in monotonic
    /// ns; 0 for never.
    pub fetched: u64,
    /// A directory whose entries are all in the tree, and since when.
    pub listed: bool,
    pub listed_at: u64,
    /// A directory with more entries than the kernel can hold: its names
    /// are looked up one at a time, and getdents reads it from the host.
    pub large: bool,
}

impl Remote {
    fn new(id: u64, mount: usize, writable: bool, fetched: u64) -> Box<Remote> {
        Box::new(Remote { id, mount, writable, fetched, listed: false, listed_at: 0, large: false })
    }
}

/// An entry of a directory, for getdents.
#[derive(Clone)]
pub struct DirItem {
    pub name: String,
    /// The inode number (`Fs::ino_number`).
    pub ino: u64,
    pub d_type: u8,
}

/// A page of a large live directory, as the host listed it after `from`.
struct Page {
    dir: Ino,
    from: String,
    items: Vec<DirItem>,
    more: bool,
    at: u64,
}

fn d_type_of(ty: FileType) -> u8 {
    match ty {
        FileType::File => 8,
        FileType::Dir => 4,
        FileType::Symlink => 10,
    }
}

/// The `Remote` and its share of `Fs::remote_files`.
const REMOTE_COST: u64 = core::mem::size_of::<Remote>() as u64 + 64;

/// Inode numbers for live mounts' files: the host's ids, which stay the
/// same even when the guest forgets a node and lists it again.
const REMOTE_INO: u64 = 1 << 40;

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
    /// /proc, its `self` and `thread-self` links (whose targets are the
    /// running process's pid), each process's directory, and the `fd`
    /// directories (their entries are that process's descriptors).
    proc_dir: Ino,
    self_links: [Ino; 2],
    pid_dirs: BTreeMap<u32, Ino>,
    dir_pids: BTreeMap<Ino, u32>,
    fd_dirs: BTreeMap<Ino, u32>,
    /// Zombies' directories: their `exe`, `cwd` and `root` lead nowhere.
    zombie_dirs: BTreeSet<Ino>,
    /// `/dev/pts`, and the nodes of the pseudo-terminals ever made: each
    /// index keeps its node, linked there while its master is open.
    pts_dir: Ino,
    pts_nodes: BTreeMap<u32, Ino>,
    /// The last page read of a large live directory.
    page: Option<Page>,
    /// A live mount's files' contents by host id, so a node made again for
    /// a file (after the kernel forgot it) shares what open descriptors and
    /// mappings still hold.
    remote_files: BTreeMap<u64, Weak<Mutex<FileData>>>,
    /// Which live mounts are lazy imports (`LiveMount::lazy`).
    lazy: Vec<bool>,
}

static FS: Mutex<Option<Fs>> = Mutex::new(None);

/// Processes that ended (or were reaped) while the filesystem was busy:
/// their /proc directories change at the next chance, in order. `true`:
/// the directory goes; `false`: it stays, a zombie's.
static PROC_ENDED: Mutex<Vec<(u32, bool)>> = Mutex::new(Vec::new());

/// Process `pid` ended, or its zombie was reaped: its /proc/<pid> goes
/// (now, or once the filesystem is free).
pub fn proc_gone(pid: u32) {
    proc_ended(pid, true);
}

/// Process `pid` ended and is a zombie: its /proc/<pid> stays until it's
/// reaped (`proc_gone`), as on Linux, with what a zombie still has.
pub fn proc_zombie(pid: u32) {
    proc_ended(pid, false);
}

fn proc_ended(pid: u32, gone: bool) {
    let mut ended = PROC_ENDED.lock();
    ended.push((pid, gone));
    if let Some(mut fs) = try_lock() {
        fs.proc_apply(&mut ended);
    }
}

/// Live mounts' nodes the host said changed (watched directories and an
/// entry's name, "" for the node itself), until the filesystem is free to
/// fetch them again; `HOST_CHANGED_ALL` for everything (too many, or
/// notices were lost).
static HOST_CHANGED: Mutex<Vec<(Ino, String)>> = Mutex::new(Vec::new());
static HOST_CHANGED_ANY: AtomicBool = AtomicBool::new(false);
static HOST_CHANGED_ALL: AtomicBool = AtomicBool::new(false);
const HOST_CHANGED_MAX: usize = 256;

/// The host said `what` changed (node and name), or that anything may
/// have (None): what the kernel has of it is fetched again before it's
/// next used, now or once the filesystem is free.
pub fn host_changed(what: Option<(Ino, &str)>) {
    {
        let mut pending = HOST_CHANGED.lock();
        match what {
            Some((ino, name)) if pending.len() < HOST_CHANGED_MAX => {
                if !pending.iter().any(|(i, n)| *i == ino && n == name) {
                    pending.push((ino, name.into()));
                }
            }
            _ => HOST_CHANGED_ALL.store(true, Ordering::Relaxed),
        }
        HOST_CHANGED_ANY.store(true, Ordering::Relaxed);
    }
    // What was read ahead may be the old bytes.
    hostfs::forget_kept();
    if let Some(mut fs) = try_lock() {
        fs.apply_host_changes();
    }
}

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

/// The filesystem, unless it isn't built yet or is held further up the call
/// stack (for code that may run in the middle of a filesystem operation).
pub fn try_lock() -> Option<FsGuard> {
    FS.try_lock().filter(|g| g.is_some()).map(FsGuard)
}

/// The filesystem. One CPU and no preemption in the kernel, so the lock is
/// never contended: failing to take it means it is already held further up
/// the call stack, a kernel bug that would otherwise hang.
pub fn lock() -> FsGuard {
    let g = FS.try_lock().expect("filesystem lock taken twice");
    assert!(g.is_some(), "fs not initialised");
    let mut g = FsGuard(g);
    if HOST_CHANGED_ANY.load(Ordering::Relaxed) {
        g.apply_host_changes();
    }
    g
}

/// A TZif (version 2) file for UTC, the same 114 bytes as zoneinfo's `UTC`:
/// a header and one zero-offset type named "UTC" for each of the 32- and
/// 64-bit sections, then the POSIX TZ footer.
static UTC_TZIF: [u8; 114] = {
    let mut f = [0u8; 114];
    let section = 44 + 10;
    let mut s = 0;
    while s < 2 {
        let at = s * section;
        let magic = *b"TZif2";
        let mut i = 0;
        while i < 5 {
            f[at + i] = magic[i];
            i += 1;
        }
        f[at + 39] = 1; // typecnt
        f[at + 43] = 4; // charcnt
        // ttinfo {utoff 0, isdst 0, desigidx 0} is zeros; then the name.
        f[at + 50] = b'U';
        f[at + 51] = b'T';
        f[at + 52] = b'C';
        s += 1;
    }
    let footer = *b"\nUTC0\n";
    let mut i = 0;
    while i < 6 {
        f[108 + i] = footer[i];
        i += 1;
    }
    f
};

fn leak(s: String) -> &'static [u8] {
    alloc::boxed::Box::leak(s.into_boxed_str()).as_bytes()
}

impl Fs {
    pub fn build(
        entries: &[Entry<'static>],
        mounts: &[&str],
        live: &[LiveMount],
        (uid, gid): (u32, u32),
        cpus: u32,
    ) -> Fs {
        let now = crate::time::realtime_ns();
        // The sandbox user owns the root and everything imported, so a program
        // can create files next to its inputs. System parts (/dev, /proc,
        // /sys, generated /etc files) belong to root, and /tmp is 1777.
        let root = Node::new(Kind::Dir(BTreeMap::new()), 0o755, (uid, gid), ROOT, "", now);
        let mut fs = Fs {
            nodes: vec![Box::new(root)],
            orphans: Vec::new(),
            free: Vec::new(),
            proc_dir: ROOT,
            self_links: [ROOT; 2],
            pid_dirs: BTreeMap::new(),
            dir_pids: BTreeMap::new(),
            fd_dirs: BTreeMap::new(),
            zombie_dirs: BTreeSet::new(),
            pts_dir: ROOT,
            pts_nodes: BTreeMap::new(),
            page: None,
            remote_files: BTreeMap::new(),
            lazy: Vec::new(),
        };
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
            let n = &mut fs.nodes[ino];
            (n.uid, n.gid) = (uid, gid);
            if e.mtime_ns != 0 {
                (n.atime, n.mtime, n.ctime) = (e.mtime_ns, e.mtime_ns, e.mtime_ns);
            }
        }
        // What comes after the imports is the kernel's own.
        let imported = fs.nodes.len();
        let dev = fs.mkdir_p("/dev");
        fs.insert(dev, "null", Kind::Dev(Dev::Null), 0o666);
        fs.insert(dev, "zero", Kind::Dev(Dev::Zero), 0o666);
        fs.insert(dev, "random", Kind::Dev(Dev::Random), 0o666);
        fs.insert(dev, "urandom", Kind::Dev(Dev::Random), 0o666);
        fs.insert(dev, "fd", Kind::Symlink("/proc/self/fd".into()), 0o777);
        fs.insert(dev, "ptmx", Kind::Dev(Dev::Ptmx), 0o666);
        fs.insert(dev, "tty", Kind::Dev(Dev::Tty), 0o666);
        fs.pts_dir = fs.insert(dev, "pts", Kind::Dir(BTreeMap::new()), 0o755);
        for (i, name) in ["stdin", "stdout", "stderr"].iter().enumerate() {
            fs.insert(dev, name, Kind::Symlink(alloc::format!("/proc/self/fd/{i}")), 0o777);
        }

        let proc = fs.mkdir_p("/proc");
        fs.proc_dir = proc;
        fs.self_links[0] = fs.insert(proc, "self", Kind::Symlink("1".into()), 0o777);
        fs.self_links[1] = fs.insert(proc, "thread-self", Kind::Symlink("1".into()), 0o777);
        fs.insert(proc, "mounts", Kind::Symlink("self/mounts".into()), 0o777);
        for &(path, file) in procfs::FILES {
            let (dir, name) = path.rsplit_once('/').unwrap();
            let parent = fs.mkdir_p(dir);
            fs.insert(parent, name, Kind::Proc(file), 0o444);
        }
        // Each CPU its own core in one package, as a VM's usually are.
        for cpu in 0..cpus {
            let dir = fs.mkdir_p(&alloc::format!("/sys/devices/system/cpu/cpu{cpu}/topology"));
            fs.insert(dir, "core_id", Kind::Proc(ProcFile::CoreId(cpu)), 0o444);
            fs.insert(dir, "physical_package_id", Kind::Proc(ProcFile::Text("0\n")), 0o444);
        }
        for top in ["/dev", "/proc", "/sys"] {
            if let Ok(ino) = fs.lookup(ROOT, top, false) {
                fs.walk_tree(ino, &mut |n| n.system = true);
            }
        }
        // /dev/shm is an ordinary tmpfs (shm_open, POSIX semaphores).
        let shm = fs.mkdir_p("/dev/shm");
        (fs.nodes[shm].perm, fs.nodes[shm].system) = (0o1777, false);

        // Nothing of the kernel's own goes in a mounted directory: it would
        // be sent back to the host as the program's.
        let inside = |path: &str, m: &str| path == m || path.strip_prefix(m).is_some_and(|rest| rest.starts_with('/'));
        let mounted = |path: &str| mounts.iter().any(|m| inside(path, m)) || live.iter().any(|m| inside(path, m.path));
        for (i, m) in live.iter().enumerate() {
            let ino = fs.mkdir_owned(m.path, (uid, gid));
            let n = &mut fs.nodes[ino];
            n.mount_point = true;
            n.remote = Some(Remote::new(i as u64 + 1, i, m.writable && !m.lazy, 0));
            fs.lazy.push(m.lazy);
        }
        // Describe the sandbox user unless the host imported its own files.
        if !mounted("/etc/passwd") && fs.lookup(ROOT, "/etc/passwd", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            let passwd = alloc::format!(
                "root:x:0:0:root:/root:/sbin/nologin\ngrix:x:{uid}:{gid}:grix:/home/grix:/bin/sh\n\
                 nobody:x:65534:65534:nobody:/:/sbin/nologin\n"
            );
            fs.insert(etc, "passwd", Kind::File(FileData::new(leak(passwd))), 0o644);
            if !mounted("/home/grix") {
                fs.mkdir_p("/home");
                fs.mkdir_owned("/home/grix", (uid, gid));
            }
        }
        if !mounted("/etc/group") && fs.lookup(ROOT, "/etc/group", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            let group = alloc::format!("root:x:0:\ngrix:x:{gid}:\nnobody:x:65534:\n");
            fs.insert(etc, "group", Kind::File(FileData::new(leak(group))), 0o644);
        }
        // No timezone was imported: say UTC explicitly, as musl and glibc
        // would assume anyway.
        if !mounted("/etc/localtime") && fs.lookup(ROOT, "/etc/localtime", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            fs.insert(etc, "localtime", Kind::File(FileData::new(&UTC_TZIF)), 0o644);
        }
        // Name resolution: the virtual nameserver (whatever server a
        // program asks, the host answers: see inet.rs), and the usual
        // local names plus the host's. Docker images carry these two as
        // empty files, which Docker replaces at run time: an empty one is
        // as good as none.
        if !mounted("/etc/resolv.conf") && fs.placeholder("/etc/resolv.conf") {
            let etc = fs.mkdir_p("/etc");
            let [a, b, c, d] = grix_abi::link::DNS_V4;
            let text = alloc::format!("nameserver {a}.{b}.{c}.{d}\n");
            let ino = fs.insert(etc, "resolv.conf", Kind::File(FileData::new(leak(text))), 0o644);
            fs.nodes[ino].generated = true;
        }
        if !mounted("/etc/hosts") && fs.placeholder("/etc/hosts") {
            let etc = fs.mkdir_p("/etc");
            // The sandbox's own name too, as Docker writes it: programs
            // look up their hostname (Java, Python's getfqdn, the Datadog
            // Agent), and it shouldn't go to the host's resolver.
            let [a, b, c, d] = grix_abi::link::HOST_V4;
            let [e, f, g, h] = grix_abi::link::GUEST_V4;
            let text = alloc::format!(
                "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n{a}.{b}.{c}.{d}\t{}\n\
                 {e}.{f}.{g}.{h}\t{}\n",
                grix_abi::link::HOST_NAME,
                procfs::HOSTNAME
            );
            let ino = fs.insert(etc, "hosts", Kind::File(FileData::new(leak(text))), 0o644);
            fs.nodes[ino].generated = true;
        }
        if !mounted("/etc/mtab") && fs.lookup(ROOT, "/etc/mtab", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            fs.insert(etc, "mtab", Kind::Symlink("/proc/self/mounts".into()), 0o777);
        }
        let tmp = fs.mkdir_p("/tmp");
        if fs.nodes[tmp].uid == 0 {
            fs.nodes[tmp].perm = 0o1777;
        }
        for n in &mut fs.nodes[imported..] {
            n.generated = !n.system && n.remote.is_none();
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

    /// A new process's /proc/<pid>, owned by its user (ps reads the owner
    /// from there): its files, `fd/`, and `exe` (the program actually
    /// running: the interpreter, for `#!` scripts), `cwd` and `root`.
    /// Without room for it (the metadata budget), there's none.
    pub fn proc_add(&mut self, pid: u32, owner: (u32, u32), exe: &str, cwd: &str) {
        self.proc_apply(&mut PROC_ENDED.lock());
        self.proc_remove(pid);
        let made = (|| -> Result<(), Errno> {
            let dir =
                self.add_node(self.proc_dir, &alloc::format!("{pid}"), Kind::Dir(BTreeMap::new()), 0o555, owner)?;
            self.pid_dirs.insert(pid, dir);
            self.dir_pids.insert(dir, pid);
            for &(name, file) in procfs::PID_FILES {
                self.add_node(dir, name, Kind::Proc(file), 0o444, owner)?;
            }
            let fd = self.add_node(dir, "fd", Kind::Dir(BTreeMap::new()), 0o500, owner)?;
            self.fd_dirs.insert(fd, pid);
            for (name, target) in [("exe", exe), ("cwd", cwd), ("root", "/")] {
                self.add_node(dir, name, Kind::Symlink(target.into()), 0o777, owner)?;
            }
            Ok(())
        })();
        if made.is_err() {
            self.proc_remove(pid);
        }
    }

    /// A node of the kernel's own (in /proc), counted against the metadata
    /// budget, in a slot that's reused once it's gone.
    fn add_node(&mut self, dir: Ino, name: &str, kind: Kind, perm: u32, owner: (u32, u32)) -> Result<Ino, Errno> {
        let mut node = Node::new(kind, perm, owner, dir, name, crate::time::realtime_ns());
        node.system = true;
        self.reclaim();
        charge(node.cost() + entry_cost(name))?;
        let ino = self.alloc_node(node);
        if let Kind::Dir(children) = &mut self.nodes[dir].kind {
            children.insert(name.into(), ino);
        }
        Ok(ino)
    }

    /// /proc/<pid>/`name` (exe, cwd) now leads to `target`.
    pub fn proc_set(&mut self, pid: u32, name: &str, target: &str) {
        let Some(&dir) = self.pid_dirs.get(&pid) else { return };
        let Some(link) = self.child(dir, name) else { return };
        if let Kind::Symlink(t) = &mut self.nodes[link].kind {
            if charge(target.len() as u64).is_err() {
                return;
            }
            release(t.len() as u64);
            *t = target.into();
        }
    }

    /// /proc/<pid> belongs to the process's effective user, as on Linux.
    pub fn proc_owner(&mut self, pid: u32, owner: (u32, u32)) {
        if let Some(&dir) = self.pid_dirs.get(&pid) {
            self.walk_tree(dir, &mut |n| (n.uid, n.gid) = owner);
        }
    }

    /// What `proc_gone` and `proc_zombie` put off.
    fn proc_apply(&mut self, ended: &mut Vec<(u32, bool)>) {
        for (pid, gone) in core::mem::take(ended) {
            if gone {
                self.proc_remove(pid);
            } else if let Some(&dir) = self.pid_dirs.get(&pid) {
                self.zombie_dirs.insert(dir);
            }
        }
    }

    /// Process `pid` is gone: so is /proc/<pid>.
    pub fn proc_remove(&mut self, pid: u32) {
        let Some(dir) = self.pid_dirs.remove(&pid) else { return };
        self.dir_pids.remove(&dir);
        self.zombie_dirs.remove(&dir);
        self.remove_tree(dir);
        if let Kind::Dir(children) = &mut self.nodes[self.proc_dir].kind {
            children.remove(&alloc::format!("{pid}"));
        }
        release(entry_cost(&alloc::format!("{pid}")));
        self.drop_name(dir);
    }

    /// Unlink everything below `dir` (open descriptors keep their nodes).
    fn remove_tree(&mut self, dir: Ino) {
        let Kind::Dir(children) = &mut self.nodes[dir].kind else { return };
        for (name, child) in core::mem::take(children) {
            self.fd_dirs.remove(&child);
            self.remove_tree(child);
            release(entry_cost(&name));
            self.drop_name(child);
        }
    }

    /// The process a /proc/<pid> file describes (None: the caller).
    pub fn proc_pid(&self, ino: Ino) -> Option<u32> {
        self.dir_pids.get(&self.nodes[ino].parent).copied()
    }

    /// The process whose descriptors a /proc/<pid>/fd directory lists.
    pub fn fd_dir_pid(&self, ino: Ino) -> Option<u32> {
        self.fd_dirs.get(&ino).copied()
    }

    /// A symlink's target: `/proc/self` and `thread-self` lead to the
    /// running process's directory. EINVAL if it isn't one; ENOENT for a
    /// zombie's `exe`, `cwd` and `root`, as on Linux, where it has no
    /// memory or filesystem context left to name.
    pub fn link_target(&self, ino: Ino) -> Result<String, Errno> {
        if self.self_links.contains(&ino) {
            return Ok(alloc::format!("{}", crate::process::current_pid()));
        }
        match &self.nodes[ino].kind {
            Kind::Symlink(_) if self.zombie_dirs.contains(&self.nodes[ino].parent) => Err(ENOENT),
            Kind::Symlink(t) => Ok(t.clone()),
            _ => Err(EINVAL),
        }
    }

    /// Make the directory at `path` a mount point.
    pub fn mark_mount(&mut self, path: &str) {
        if let Ok(ino) = self.lookup(ROOT, path, false)
            && self.is_dir(ino)
        {
            self.nodes[ino].mount_point = true;
        }
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
    /// Is `path` missing, or an empty regular file (an image's
    /// placeholder), so the kernel should supply it?
    fn placeholder(&mut self, path: &str) -> bool {
        match self.lookup(ROOT, path, false) {
            Err(_) => true,
            Ok(ino) => matches!(&self.nodes[ino].kind, Kind::File(c) if c.lock().image().is_some_and(<[u8]>::is_empty)),
        }
    }

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

    /// A pseudo-terminal's slave appears as /dev/pts/N, owned by whoever
    /// opened the master (devpts). Returns its node.
    pub fn pts_show(&mut self, index: u32, owner: (u32, u32)) -> Ino {
        let name = alloc::format!("{index}");
        let now = crate::time::realtime_ns();
        let ino = match self.pts_nodes.get(&index) {
            Some(&ino) => {
                if let Kind::Dir(children) = &mut self.nodes[self.pts_dir].kind {
                    children.insert(name, ino);
                }
                ino
            }
            None => {
                let ino = self.insert(self.pts_dir, &name, Kind::Dev(Dev::Pts(index)), 0o620);
                self.pts_nodes.insert(index, ino);
                ino
            }
        };
        let n = &mut self.nodes[ino];
        (n.uid, n.gid, n.perm, n.nlink, n.system) = (owner.0, owner.1, 0o620, 1, true);
        (n.atime, n.mtime, n.ctime) = (now, now, now);
        ino
    }

    /// Its master closed: /dev/pts/N goes (open slaves keep the node).
    pub fn pts_hide(&mut self, index: u32) {
        let Some(&ino) = self.pts_nodes.get(&index) else { return };
        if let Kind::Dir(children) = &mut self.nodes[self.pts_dir].kind
            && children.get(&alloc::format!("{index}")) == Some(&ino)
        {
            children.remove(&alloc::format!("{index}"));
        }
        self.nodes[ino].nlink = 0;
    }

    /// The node of /dev/pts/N, while it's there.
    pub fn pts_node(&self, index: u32) -> Option<Ino> {
        self.pts_nodes.get(&index).copied().filter(|&ino| self.nodes[ino].nlink > 0)
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
    pub fn lookup(&mut self, start: Ino, path: &str, follow_last: bool) -> Result<Ino, Errno> {
        let mut links = 0;
        self.walk(start, path, follow_last, &mut links)
    }

    /// `links` counts every symlink followed in the whole lookup, so a chain
    /// of links that each expand into several more can't make it exponential.
    fn walk(&mut self, start: Ino, path: &str, follow_last: bool, links: &mut u32) -> Result<Ino, Errno> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let mut cur = if path.starts_with('/') { ROOT } else { start };
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let must_be_dir = path.ends_with('/');
        for (i, c) in comps.iter().enumerate() {
            let last = i + 1 == comps.len();
            if !self.is_dir(cur) {
                return Err(ENOTDIR);
            }
            match *c {
                "." => {}
                ".." => cur = self.nodes[cur].parent,
                name => {
                    let child =
                        self.find_child(cur, name)?.ok_or(if name.len() > NAME_MAX { ENAMETOOLONG } else { ENOENT })?;
                    if matches!(self.nodes[child].kind, Kind::Symlink(_)) && (!last || follow_last || must_be_dir) {
                        *links += 1;
                        if *links > MAX_SYMLINKS {
                            return Err(ELOOP);
                        }
                        let target = self.link_target(child)?;
                        cur = self.walk(cur, &target, true, links)?;
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
    pub fn lookup_parent(&mut self, start: Ino, path: &str) -> Result<(Ino, String), Errno> {
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

    pub fn stat(&mut self, ino: Ino) -> StatInfo {
        // What the host has now, give or take a second. If it can't say,
        // what it said last.
        let _ = self.refresh(ino);
        let n = &self.nodes[ino];
        let (ty, size, nlink, rdev) = match &n.kind {
            Kind::File(c) => (S_IFREG, c.lock().len(), n.nlink, 0),
            Kind::Unlinked { data, .. } => (S_IFREG, data.upgrade().map_or(0, |c| c.lock().len()), 0, 0),
            // Over-counting subdirectories is safe for find's leaf optimisation.
            Kind::Dir(c) if n.nlink > 0 => (S_IFDIR, 4096, 2 + c.len() as u32, 0),
            Kind::Dir(_) => (S_IFDIR, 4096, 0, 0),
            Kind::Symlink(t) => (S_IFLNK, t.len() as u64, n.nlink, 0),
            Kind::Dev(d) => {
                let (major, minor) = match d {
                    Dev::Null => (1, 3),
                    Dev::Zero => (1, 5),
                    Dev::Random => (1, 9),
                    Dev::Tty => (5, 0),
                    Dev::Ptmx => (5, 2),
                    Dev::Pts(n) => (136, *n),
                };
                // Linux's new_encode_dev.
                (S_IFCHR, 0, 1, ((minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)) as u64)
            }
            Kind::Proc(_) => (S_IFREG, 0, 1, 0),
            Kind::Socket(_) => (S_IFSOCK, 0, n.nlink, 0),
            Kind::Fifo(_) => (S_IFIFO, 0, n.nlink, 0),
        };
        StatInfo {
            ino: self.ino_number(ino),
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
    pub fn dir_next(&mut self, dir: Ino, after: Option<&str>) -> Result<Option<DirItem>, Errno> {
        self.ensure(dir)?;
        if let Some(r) = self.nodes[dir].remote.as_deref()
            && r.large
        {
            return self.large_next(dir, r.id, after.unwrap_or(""));
        }
        let Kind::Dir(children) = &self.nodes[dir].kind else { return Ok(None) };
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        let next = children.range::<str, _>((lower, Bound::Unbounded)).next().map(|(k, v)| (k.clone(), *v));
        Ok(next.map(|(name, ino)| DirItem { name, ino: self.ino_number(ino), d_type: self.d_type(ino) }))
    }

    /// Before a live directory is opened: its entries, so an error shows
    /// now rather than as an empty directory.
    pub fn list_now(&mut self, dir: Ino) -> Result<(), Errno> {
        self.ensure(dir)
    }

    /// The inode number `stat` and `getdents` give `ino`. A live mount's
    /// node has the host's id, which stays the same while the kernel
    /// forgets and finds it again.
    pub fn ino_number(&self, ino: Ino) -> u64 {
        let n = &self.nodes[ino];
        match &n.remote {
            Some(r) => REMOTE_INO + r.id,
            None if n.host_ino != 0 => n.host_ino,
            None => ino as u64 + 1,
        }
    }

    /// The host's id for `ino` if the host can watch it for inotify: a
    /// live mount's file or directory, but not a lazy import's (which
    /// never changes for the guest).
    pub fn watchable_remote(&self, ino: Ino) -> Option<u64> {
        let n = &self.nodes[ino];
        let r = n.remote.as_deref().filter(|r| !self.lazy[r.mount])?;
        matches!(n.kind, Kind::Dir(_) | Kind::File(_)).then_some(r.id)
    }

    /// The host id of a live mount's node.
    pub fn remote_id(&self, ino: Ino) -> Option<u64> {
        self.nodes[ino].remote.as_ref().map(|r| r.id)
    }

    /// Linux d_type for a node.
    pub fn d_type(&self, ino: Ino) -> u8 {
        match self.nodes[ino].kind {
            Kind::File(_) | Kind::Unlinked { .. } | Kind::Proc(_) => 8,
            Kind::Dir(_) => 4,
            Kind::Symlink(_) => 10,
            Kind::Dev(_) => 2,
            Kind::Socket(_) => 12,
            Kind::Fifo(_) => 1,
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
        if victim.is_some_and(|v| self.nodes[v].mount_point) {
            return Err(EBUSY);
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

    pub fn child_of(&mut self, dir: Ino, name: &str) -> Option<Ino> {
        self.find_child(dir, name).ok().flatten()
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
    pub fn missing_is_import_gap(&mut self, base: Ino, path: &str) -> bool {
        // A live mount has whatever the host has: nothing there is missing;
        // nor in /dev/pts or /proc/<pid>, whose entries come and go.
        let gap = |fs: &Fs, ino: Ino| {
            let n = &fs.nodes[ino];
            !n.changed
                && n.perm & S_ISVTX == 0
                && n.remote.is_none()
                && n.host_ino == 0
                && ino != fs.pts_dir
                && !fs.dir_pids.contains_key(&ino)
                && !fs.fd_dirs.contains_key(&ino)
        };
        let mut p = path.trim_end_matches('/');
        loop {
            match p.rsplit_once('/') {
                Some((dir, name)) => {
                    let dir = if dir.is_empty() { "/" } else { dir };
                    if let Ok(ino) = self.lookup(base, dir, true) {
                        // A process that has ended (or never was).
                        if ino == self.proc_dir && name.parse::<u32>().is_ok() {
                            return false;
                        }
                        return gap(self, ino);
                    }
                    p = dir.trim_end_matches('/');
                }
                None => return gap(self, base),
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
        // A lazy import's directory: what would fail fails before anything
        // is copied up.
        if self.is_lazy(dir) {
            if name.is_empty() || name == "." || name == ".." || self.find_child(dir, name)?.is_some() {
                return Err(EEXIST);
            }
            self.may_change(dir, None, uid, gid)?;
            self.copy_up(dir)?;
        }
        if self.nodes[dir].remote.is_some() {
            return self.create_remote(dir, name, kind, perm, uid, gid);
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
        // As on Linux for a filesystem that can't do O_TMPFILE.
        if self.nodes[dir].remote.is_some() {
            return Err(EOPNOTSUPP);
        }
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

    /// memfd_create: an anonymous file that only ever lives in descriptors.
    /// It isn't in the tree, so it needs no directory permission (or
    /// `fs_write`), but its pages and node count against the same limits.
    pub fn create_memfd(&mut self, name: &str, seals: u32, uid: u32, gid: u32) -> Result<(Ino, Content), Errno> {
        let content = FileData::new(&[]);
        content.lock().seals = Some(seals);
        let kind = Kind::Unlinked { data: Arc::downgrade(&content), linkable: false };
        // /proc/self/fd shows it as Linux does.
        let label = alloc::format!("memfd:{name} (deleted)");
        let mut node = Node::new(kind, 0o777, (uid, gid), ROOT, &label, crate::time::realtime_ns());
        (node.nlink, node.changed) = (0, true);
        self.reclaim();
        charge(node.cost() + label.len() as u64)?;
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
        if self.is_lazy(dir) {
            let ino = self.find_child(dir, name)?.ok_or(ENOENT)?;
            match (self.is_dir(ino), rmdir) {
                (true, false) => return Err(EISDIR),
                (false, true) => return Err(ENOTDIR),
                _ => {}
            }
            self.may_change(dir, Some(ino), uid, gid)?;
            if rmdir && self.is_lazy(ino) && !self.lazy_dir_empty(ino)? {
                return Err(ENOTEMPTY);
            }
            self.copy_up(dir)?;
        }
        let ino = self.find_child(dir, name)?.ok_or(ENOENT)?;
        // A lazy import's directory in a directory already copied up: its
        // entries may not all be known here.
        if rmdir && self.is_lazy(ino) && !self.lazy_dir_empty(ino)? {
            return Err(ENOTEMPTY);
        }
        let remote = self.nodes[dir].remote.as_ref().map(|r| (r.id, r.writable));
        match (&self.nodes[ino].kind, rmdir) {
            // The host knows whether a live mount's directory is empty.
            (Kind::Dir(c), true) if !c.is_empty() && remote.is_none() => return Err(ENOTEMPTY),
            (Kind::Dir(_), true) => {}
            (Kind::Dir(_), false) => return Err(EISDIR),
            (_, true) => return Err(ENOTDIR),
            (_, false) => {}
        }
        self.may_change(dir, Some(ino), uid, gid)?;
        if let Some((id, writable)) = remote {
            if !writable {
                return Err(EROFS);
            }
            hostfs::remove(id, name, rmdir)?;
            self.unlink_child(dir, name, ino, true);
            self.touch_dir(dir);
            return Ok(());
        }
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
        if self.is_lazy(dir) || self.is_lazy(ino) {
            if self.find_child(dir, name)?.is_some() {
                return Err(EEXIST);
            }
            self.may_change(dir, None, uid, gid)?;
            self.copy_up(dir)?;
            self.copy_up(ino)?;
        }
        // Live mounts don't do hard links (EPERM, as on Linux for a
        // filesystem that can't), and nothing links across a mount.
        match (self.nodes[ino].remote.as_ref(), self.nodes[dir].remote.as_ref()) {
            (None, None) => {}
            (Some(a), Some(b)) if a.mount == b.mount => return Err(EPERM),
            _ => return Err(EXDEV),
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
        if self.is_lazy(odir) || self.is_lazy(ndir) {
            let src = self.find_child(odir, oname)?.ok_or(ENOENT)?;
            let _src = self.pin(src);
            let dst = self.find_child(ndir, nname)?;
            self.may_change(odir, Some(src), uid, gid)?;
            self.may_change(ndir, dst, uid, gid)?;
            // Replacing a lazy import's directory: only an empty one.
            if let Some(d) = dst.filter(|&d| self.is_dir(d) && self.is_lazy(d))
                && self.is_dir(src)
                && !self.lazy_dir_empty(d)?
            {
                return Err(ENOTEMPTY);
            }
            self.copy_up(odir)?;
            self.copy_up(ndir)?;
        }
        let src = self.find_child(odir, oname)?.ok_or(ENOENT)?;
        // Finding the destination may make room by forgetting idle nodes.
        let _src = self.pin(src);
        let dst = self.find_child(ndir, nname)?;
        if let Some(d) = dst.filter(|&d| self.is_dir(d) && self.is_lazy(d))
            && self.is_dir(src)
            && !self.lazy_dir_empty(d)?
        {
            return Err(ENOTEMPTY);
        }
        if self.nodes[ndir].nlink == 0 {
            return Err(ENOENT);
        }
        // Within one live mount, or not touching one at all.
        let remote = match (self.nodes[odir].remote.as_ref(), self.nodes[ndir].remote.as_ref()) {
            (None, None) => None,
            (Some(a), Some(b)) if a.mount == b.mount => Some((a.id, b.id, a.writable)),
            _ => return Err(EXDEV),
        };
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
        if let Some((oid, nid, writable)) = remote {
            if !writable {
                return Err(EROFS);
            }
            if exchange {
                return Err(EINVAL);
            }
            match dst {
                Some(_) if noreplace => return Err(EEXIST),
                Some(dst) if dst == src => return Ok(()),
                Some(dst) => match (self.is_dir(src), self.is_dir(dst)) {
                    (true, false) => return Err(ENOTDIR),
                    (false, true) => return Err(EISDIR),
                    _ => {}
                },
                None => {}
            }
            charge(entry_cost(nname))?;
            if let Err(e) = hostfs::rename(oid, oname, nid, nname, noreplace) {
                release(entry_cost(nname));
                return Err(e);
            }
            if let Some(dst) = dst {
                // Its entry is replaced below; only the node goes.
                self.forget_children(dst);
                if let Kind::File(c) = &self.nodes[dst].kind {
                    c.lock().unlinked = true;
                }
                let Kind::Dir(children) = &mut self.nodes[ndir].kind else { unreachable!() };
                children.remove(nname);
                release(entry_cost(nname));
                self.drop_name(dst);
            }
            let Kind::Dir(children) = &mut self.nodes[odir].kind else { unreachable!() };
            children.remove(oname);
            release(entry_cost(oname));
            let Kind::Dir(children) = &mut self.nodes[ndir].kind else { unreachable!() };
            children.insert(nname.into(), src);
            (self.nodes[src].parent, self.nodes[src].name) = (ndir, nname.into());
            let now = crate::time::realtime_ns();
            self.nodes[src].ctime = now;
            self.touch_dir(odir);
            self.touch_dir(ndir);
            return Ok(());
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

// ---------------------------------------------------------------- live mounts

/// Was a live mount's node fetched (at monotonic `at`; 0: never, or
/// forgotten) recently enough to go on as it was?
fn recent(at: u64) -> bool {
    at != 0 && crate::time::monotonic_ns().saturating_sub(at) < hostfs::FRESH_NS
}

impl Fs {
    /// Restored from a snapshot: what live mounts' nodes were like before
    /// may have changed on the host while it sat there (monotonic time
    /// doesn't count that), so it's fetched again. Lazy imports stay as
    /// first seen: the host remembers that too.
    pub fn forget_live(&mut self) {
        let lazy = self.lazy.clone();
        for n in self.nodes.iter_mut() {
            if let Some(r) = n.remote.as_deref_mut()
                && !lazy[r.mount]
            {
                r.fetched = 0;
                r.listed_at = 0;
            }
        }
        self.page = None;
        hostfs::forget_kept();
    }

    /// What the host said changed (`host_changed`) is fetched again when
    /// next used: a watched directory's entries, and the entry named.
    fn apply_host_changes(&mut self) {
        let pending = core::mem::take(&mut *HOST_CHANGED.lock());
        HOST_CHANGED_ANY.store(false, Ordering::Relaxed);
        if HOST_CHANGED_ALL.swap(false, Ordering::Relaxed) {
            self.forget_live();
            return;
        }
        for (ino, name) in pending {
            let Some(n) = self.nodes.get(ino).filter(|n| n.remote.is_some()) else { continue };
            let child = match &n.kind {
                Kind::Dir(children) if !name.is_empty() => children.get(&name).copied(),
                _ => None,
            };
            if self.page.as_ref().is_some_and(|p| p.dir == ino) {
                self.page = None;
            }
            for i in [Some(ino), child].into_iter().flatten() {
                if let Some(r) = self.nodes[i].remote.as_deref_mut()
                    && !self.lazy[r.mount]
                {
                    (r.fetched, r.listed_at) = (0, 0);
                }
            }
        }
    }

    /// Before using directory `dir`'s entries: for a live mount's, have
    /// them from the host, and recently.
    fn ensure(&mut self, dir: Ino) -> Result<(), Errno> {
        let n = &self.nodes[dir];
        let Some(r) = n.remote.as_deref() else { return Ok(()) };
        // A lazy import's directory, once listed, stays as it was.
        let fresh = r.listed && (self.lazy[r.mount] || recent(r.listed_at));
        if fresh || r.large || n.nlink == 0 || !matches!(n.kind, Kind::Dir(_)) {
            return Ok(());
        }
        self.list_remote(dir)
    }

    /// For `stat`: a live mount's node as the host has it now (give or take
    /// `FRESH_NS`).
    fn refresh(&mut self, ino: Ino) -> Result<(), Errno> {
        let Some(r) = self.nodes[ino].remote.as_deref() else { return Ok(()) };
        if self.is_dir(ino) {
            return self.ensure(ino);
        }
        let frozen = self.lazy[r.mount] && r.fetched != 0;
        if frozen || recent(r.fetched) || self.nodes[ino].nlink == 0 {
            return Ok(());
        }
        let id = r.id;
        match hostfs::stat(id) {
            Ok(attr) if attr.ty == self.file_type(ino) => {
                self.apply_attr(ino, &attr);
                Ok(())
            }
            // Gone or replaced on the host: the directory's next listing
            // drops it.
            result => {
                let parent = self.nodes[ino].parent;
                if let Some(p) = self.nodes[parent].remote.as_deref_mut() {
                    p.listed_at = 0;
                }
                result.map(|_| ())
            }
        }
    }

    fn file_type(&self, ino: Ino) -> FileType {
        match self.nodes[ino].kind {
            Kind::Dir(_) => FileType::Dir,
            Kind::Symlink(_) => FileType::Symlink,
            _ => FileType::File,
        }
    }

    fn apply_attr(&mut self, ino: Ino, attr: &Attr) {
        let n = &mut self.nodes[ino];
        n.perm = attr.mode & 0o7777;
        (n.atime, n.mtime, n.ctime) = (attr.atime_ns, attr.mtime_ns, attr.ctime_ns);
        if let Kind::File(c) = &n.kind {
            c.lock().set_size(attr.size);
        }
        if let Some(r) = n.remote.as_deref_mut() {
            r.fetched = crate::time::monotonic_ns();
        }
    }

    /// Bring live directory `dir`'s entries in line with the host's, a page
    /// at a time: nodes the host still has (by id) stay, with what they are
    /// now, so open files and the working directory keep theirs.
    fn list_remote(&mut self, dir: Ino) -> Result<(), Errno> {
        // Busy while it's listed: making room mustn't forget it.
        let _busy = self.pin(dir);
        let r = self.nodes[dir].remote.as_deref().unwrap();
        let (id, mount, writable) = (r.id, r.mount, r.writable);
        let mut after = String::new();
        loop {
            let (attr, entries, more) = hostfs::list(id, &after)?;
            self.apply_attr(dir, &attr);
            let last = if more { entries.last().map(|e| e.name.clone()) } else { None };
            // What's in this page's range of names but not in the page.
            let lo = if after.is_empty() { Bound::Unbounded } else { Bound::Excluded(after.as_str()) };
            let hi = last.as_deref().map_or(Bound::Unbounded, Bound::Included);
            let Kind::Dir(children) = &self.nodes[dir].kind else { return Err(ENOTDIR) };
            let gone: Vec<(String, Ino)> = children
                .range::<str, _>((lo, hi))
                .filter(|&(name, &ino)| {
                    let same = |e: &hostfs::Entry| {
                        self.nodes[ino].remote.as_ref().is_some_and(|r| r.id == e.id)
                            && self.file_type(ino) == e.attr.ty
                    };
                    entries.binary_search_by(|e| e.name.as_str().cmp(name)).map_or(true, |i| !same(&entries[i]))
                })
                .map(|(name, &ino)| (name.clone(), ino))
                .collect();
            for (name, ino) in gone {
                self.unlink_child(dir, &name, ino, false);
            }
            for e in &entries {
                match self.child(dir, &e.name) {
                    Some(ino) => {
                        self.apply_attr(ino, &e.attr);
                        if let Kind::Symlink(t) = &mut self.nodes[ino].kind
                            && *t != e.target
                        {
                            release(t.len() as u64);
                            charge(e.target.len() as u64).ok();
                            *t = e.target.clone();
                        }
                    }
                    None => match self.new_remote(dir, e, mount, writable) {
                        Ok(_) => {}
                        // More than the kernel can hold, even after making
                        // room: look its names up one at a time instead.
                        Err(ENOMEM) => {
                            let r = self.nodes[dir].remote.as_deref_mut().unwrap();
                            (r.large, r.listed) = (true, false);
                            return Ok(());
                        }
                        Err(err) => return Err(err),
                    },
                }
            }
            match last {
                Some(l) => after = l,
                None => break,
            }
        }
        let r = self.nodes[dir].remote.as_deref_mut().unwrap();
        (r.listed, r.listed_at) = (true, crate::time::monotonic_ns());
        Ok(())
    }

    /// A node for what the host listed (or just created) in `dir`.
    fn new_remote(&mut self, dir: Ino, e: &hostfs::Entry, mount: usize, writable: bool) -> Result<Ino, Errno> {
        let kind = match e.attr.ty {
            FileType::File => {
                let c = match self.remote_files.get(&e.id).and_then(Weak::upgrade) {
                    Some(c) => {
                        c.lock().set_size(e.attr.size);
                        c
                    }
                    None => {
                        let c = FileData::remote(e.id, e.attr.size);
                        self.remote_files.insert(e.id, Arc::downgrade(&c));
                        c
                    }
                };
                Kind::File(c)
            }
            FileType::Dir => Kind::Dir(BTreeMap::new()),
            FileType::Symlink => Kind::Symlink(e.target.clone()),
        };
        let owner = (self.nodes[dir].uid, self.nodes[dir].gid);
        let mut node = Node::new(kind, e.attr.mode & 0o7777, owner, dir, &e.name, e.attr.mtime_ns);
        (node.atime, node.ctime) = (e.attr.atime_ns, e.attr.ctime_ns);
        let fetched = crate::time::monotonic_ns();
        node.remote = Some(Remote::new(e.id, mount, writable, fetched));
        let cost = node.cost() + entry_cost(&e.name);
        self.reclaim();
        if charge(cost).is_err() {
            // Make room by forgetting other directories' entries (the host
            // still has them), then try once more.
            self.evict(dir);
            charge(cost).map_err(|_| ENOMEM)?;
        }
        let ino = self.alloc_node(node);
        let Kind::Dir(children) = &mut self.nodes[dir].kind else { unreachable!() };
        children.insert(e.name.clone(), ino);
        Ok(ino)
    }

    /// `name` (node `ino`) is gone from live directory `dir`: removed by the
    /// program (`removed`, so the host is keeping it open for it) or found
    /// gone.
    fn unlink_child(&mut self, dir: Ino, name: &str, ino: Ino, removed: bool) {
        if removed && let Kind::File(c) = &self.nodes[ino].kind {
            c.lock().unlinked = true;
        }
        self.forget_children(ino);
        if let Kind::Dir(children) = &mut self.nodes[dir].kind {
            children.remove(name);
        }
        release(entry_cost(name));
        self.drop_name(ino);
    }

    /// Drop a live directory's entries from the tree (they're gone, or
    /// just not needed); it's listed again when next used.
    fn forget_children(&mut self, dir: Ino) {
        let Some(r) = self.nodes[dir].remote.as_deref_mut() else { return };
        r.listed = false;
        let Kind::Dir(children) = &mut self.nodes[dir].kind else { return };
        for (name, ino) in core::mem::take(children) {
            self.forget_children(ino);
            release(entry_cost(&name));
            self.drop_name(ino);
        }
    }

    /// Forget the entries of live directories nothing is using (no open
    /// files or working directories in them, nothing listed below), except
    /// `keep` and its parents.
    fn evict(&mut self, keep: Ino) {
        let mut ancestors = Vec::new();
        let mut a = keep;
        loop {
            ancestors.push(a);
            if a == ROOT {
                break;
            }
            a = self.nodes[a].parent;
        }
        let idle = |fs: &Fs, c: Ino| {
            let c = &fs.nodes[c];
            Arc::strong_count(&c.pin) == 1 && !c.remote.as_ref().is_some_and(|r| r.listed || r.large)
        };
        for ino in 0..self.nodes.len() {
            let n = &self.nodes[ino];
            let (Some(r), Kind::Dir(children)) = (n.remote.as_deref(), &n.kind) else { continue };
            // A large directory's entries are single lookups: any idle one
            // can go, even from `keep`, but not the way to `keep`.
            if r.large {
                let gone: Vec<(String, Ino)> = children
                    .iter()
                    .filter(|&(_, &c)| idle(self, c) && !ancestors.contains(&c))
                    .map(|(k, &c)| (k.clone(), c))
                    .collect();
                for (name, c) in gone {
                    self.unlink_child(ino, &name, c, false);
                }
                continue;
            }
            if !r.listed || ancestors.contains(&ino) {
                continue;
            }
            if children.values().all(|&c| idle(self, c)) {
                self.forget_children(ino);
            }
        }
        self.reclaim();
        self.remote_files.retain(|_, w| w.strong_count() > 0);
    }

    fn create_remote(&mut self, dir: Ino, name: &str, kind: Kind, perm: u32, uid: u32, gid: u32) -> Result<Ino, Errno> {
        let r = self.nodes[dir].remote.as_deref().unwrap();
        let (id, mount, writable) = (r.id, r.mount, r.writable);
        if !writable {
            return Err(EROFS);
        }
        if name.is_empty() || name == "." || name == ".." {
            return Err(EEXIST);
        }
        self.may_change(dir, None, uid, gid)?;
        let (ty, target) = match &kind {
            Kind::File(_) => (FileType::File, ""),
            Kind::Dir(_) => (FileType::Dir, ""),
            Kind::Symlink(t) => (FileType::Symlink, t.as_str()),
            // Device nodes, FIFOs.
            _ => return Err(EPERM),
        };
        if self.find_child(dir, name)?.is_some() {
            return Err(EEXIST);
        }
        let (cid, attr) = match hostfs::create(id, name, ty, perm, target) {
            Ok(made) => made,
            Err(e) => {
                // Made on the host since the last listing, perhaps.
                if e == EEXIST
                    && let Some(r) = self.nodes[dir].remote.as_deref_mut()
                {
                    r.listed_at = 0;
                }
                return Err(e);
            }
        };
        let e = hostfs::Entry { name: name.into(), id: cid, attr, target: target.into() };
        let ino = match self.new_remote(dir, &e, mount, writable) {
            Ok(ino) => ino,
            Err(err) => {
                // The host has it; the next listing brings it in.
                if let Some(r) = self.nodes[dir].remote.as_deref_mut() {
                    r.listed_at = 0;
                }
                return Err(err);
            }
        };
        self.nodes[ino].changed = true;
        self.touch_dir(dir);
        Ok(ino)
    }

    /// Before opening a live mount's file: its size and attributes as the
    /// host has them now (give or take `FRESH_NS`).
    pub fn revalidate(&mut self, ino: Ino) {
        let _ = self.refresh(ino);
    }

    /// Is `ino` in a read-only live mount? (A lazy import's can be
    /// written, once copied up.)
    pub fn read_only(&self, ino: Ino) -> bool {
        self.nodes[ino].remote.as_ref().is_some_and(|r| !r.writable && !self.lazy[r.mount])
    }

    /// Is `ino` still the host's, in a lazy import?
    fn is_lazy(&self, ino: Ino) -> bool {
        self.nodes[ino].remote.as_ref().is_some_and(|r| self.lazy[r.mount])
    }

    /// Before the program changes `ino` (or, for a directory, what's in
    /// it): if it's still a lazy import's, make it the sandbox's own, and
    /// every directory above it up to the mount. A file's bytes are read
    /// in when it's first written (they count as written data; a truncate
    /// reads only what stays), a directory's entries all listed (their
    /// nodes stay the host's until changed). From then on the changes stay
    /// in the sandbox, as for imports.
    pub fn copy_up(&mut self, ino: Ino) -> Result<(), Errno> {
        let mut chain = Vec::new();
        let mut n = ino;
        while self.is_lazy(n) {
            chain.push(n);
            if self.nodes[n].mount_point {
                break;
            }
            n = self.nodes[n].parent;
        }
        for &n in chain.iter().rev() {
            let _busy = self.pin(n);
            let id = self.nodes[n].remote.as_ref().unwrap().id;
            match &self.nodes[n].kind {
                Kind::Dir(_) => {
                    self.ensure(n)?;
                    // Too many entries to hold them all.
                    if self.nodes[n].remote.as_ref().is_some_and(|r| r.large || !r.listed) {
                        return Err(ENOSPC);
                    }
                }
                // Its bytes come in when it's written (or truncated).
                Kind::File(c) => {
                    c.lock().adopt();
                    self.remote_files.remove(&id);
                }
                _ => {}
            }
            let node = &mut self.nodes[n];
            node.remote = None;
            node.host_ino = REMOTE_INO + id;
            // What `new_remote` charged for the host's side (a mount's root
            // never was).
            if !node.mount_point {
                release(REMOTE_COST);
            }
        }
        Ok(())
    }

    /// Is a lazy import's directory empty (on the host, as first seen)?
    fn lazy_dir_empty(&mut self, dir: Ino) -> Result<bool, Errno> {
        self.ensure(dir)?;
        let r = self.nodes[dir].remote.as_deref().unwrap();
        if r.large || !r.listed {
            let (_, entries, _) = hostfs::list(r.id, "")?;
            return Ok(entries.is_empty());
        }
        Ok(matches!(&self.nodes[dir].kind, Kind::Dir(c) if c.is_empty()))
    }

    /// chmod and utimensat: the mode and times (None leaves one alone),
    /// changed on the host first for a live mount's node.
    pub fn set_attr(
        &mut self,
        ino: Ino,
        mode: Option<u32>,
        atime: Option<u64>,
        mtime: Option<u64>,
    ) -> Result<(), Errno> {
        if mode.is_none() && atime.is_none() && mtime.is_none() {
            return Ok(());
        }
        self.copy_up(ino)?;
        if let Some(r) = self.nodes[ino].remote.as_deref() {
            if !r.writable {
                return Err(EROFS);
            }
            let id = r.id;
            let attr = hostfs::set_attr(id, mode, atime, mtime)?;
            self.apply_attr(ino, &attr);
            return Ok(());
        }
        let n = &mut self.nodes[ino];
        if let Some(m) = mode {
            n.perm = m & 0o7777;
        }
        if let Some(a) = atime {
            n.atime = a;
        }
        if let Some(m) = mtime {
            n.mtime = m;
        }
        if mode.is_some() || atime.is_some() || mtime.is_some() {
            self.changed(ino);
        }
        Ok(())
    }

    /// `name` in `dir`, for a lookup: in a live directory, as the host has
    /// it now (give or take `FRESH_NS`).
    fn find_child(&mut self, dir: Ino, name: &str) -> Result<Option<Ino>, Errno> {
        self.ensure(dir)?;
        let child = self.child(dir, name);
        let Some(r) = self.nodes[dir].remote.as_deref().filter(|r| r.large) else { return Ok(child) };
        let (id, mount, writable) = (r.id, r.mount, r.writable);
        let lazy = self.lazy[mount];
        if let Some(c) = child
            && self.nodes[c].remote.as_ref().is_some_and(|r| lazy || recent(r.fetched))
        {
            return Ok(Some(c));
        }
        match hostfs::lookup(id, name) {
            Ok(e) => {
                if let Some(c) = child {
                    let same = self.nodes[c].remote.as_ref().is_some_and(|r| r.id == e.id)
                        && self.file_type(c) == e.attr.ty
                        && !matches!(&self.nodes[c].kind, Kind::Symlink(t) if *t != e.target);
                    if same {
                        self.apply_attr(c, &e.attr);
                        return Ok(Some(c));
                    }
                    self.unlink_child(dir, name, c, false);
                }
                self.new_remote(dir, &e, mount, writable).map(Some)
            }
            Err(ENOENT) => {
                if let Some(c) = child {
                    self.unlink_child(dir, name, c, false);
                }
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// getdents in a large live directory: the entry after `after`, from
    /// the host a page at a time.
    fn large_next(&mut self, dir: Ino, id: u64, after: &str) -> Result<Option<DirItem>, Errno> {
        let now = crate::time::monotonic_ns();
        if let Some(p) = &self.page
            && p.dir == dir
            && p.from.as_str() <= after
            && now.saturating_sub(p.at) < hostfs::FRESH_NS
        {
            if let Some(item) = p.items.iter().find(|it| it.name.as_str() > after) {
                return Ok(Some(item.clone()));
            }
            if !p.more {
                return Ok(None);
            }
        }
        let (_, entries, more) = hostfs::list(id, after)?;
        // What a program reads it usually stats next: keep the page's
        // entries as nodes too, while there's room (making room by
        // forgetting idle ones, which are only a cache here).
        let r = self.nodes[dir].remote.as_deref().unwrap();
        let (mount, writable) = (r.mount, r.writable);
        for e in &entries {
            match self.child(dir, &e.name) {
                // (A lazy import's nodes stay as first seen.)
                Some(c)
                    if self.nodes[c].remote.as_ref().is_some_and(|r| r.id == e.id)
                        && self.file_type(c) == e.attr.ty =>
                {
                    if !self.lazy[mount] {
                        self.apply_attr(c, &e.attr)
                    }
                }
                Some(_) => {}
                None => {
                    if self.new_remote(dir, e, mount, writable).is_err() {
                        break;
                    }
                }
            }
        }
        let items: Vec<DirItem> = entries
            .into_iter()
            .map(|e| DirItem { name: e.name, ino: REMOTE_INO + e.id, d_type: d_type_of(e.attr.ty) })
            .collect();
        let first = items.first().cloned();
        self.page = Some(Page { dir, from: after.into(), items, more, at: now });
        Ok(first)
    }
}
