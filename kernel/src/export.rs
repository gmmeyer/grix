//! Sending the directories the host asked for (`Image::exports`) back to it
//! when the program ends: the agent's results. See `wire::ExportMsg`. For a
//! directory mounted from the host (`Image::mounts`), only what changed goes
//! back: entries that differ from what the host imported, and the paths
//! that are gone, which the host then applies to its directory.
//!
//! The walk allocates nothing per entry (names are borrowed from the locked
//! filesystem), and what it sends is bounded twice: by the host's budget,
//! counted the same way the host counts it, and by `MAX_EXPORT_PATH`, which
//! also bounds the walk's depth.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Bound;
use grix_abi::image::{Entry, EntryKind};
use grix_abi::wire::{Channel, ExportKind, ExportMsg, MAX_EXPORT_PATH, export_cost};
use spin::Once;

use crate::console::{self, klog};
use crate::fs::{self, Content, Fs, Ino, Kind, Node, ROOT};

struct Root {
    path: &'static str,
    /// For a mount: what the host imported under it (indices into
    /// `Config::entries`), sorted by path.
    imported: Option<Vec<u32>>,
}

struct Config {
    roots: Vec<Root>,
    budget: u64,
    entries: &'static [Entry<'static>],
}

/// An imported entry's path relative to the mount at `root`.
fn rel(e: &Entry<'static>, root: &str) -> &'static str {
    &e.path[root.len() + 1..]
}

static CONFIG: Once<Config> = Once::new();

/// Remember what to export, and the most it may cost (from the boot image).
pub fn init(exports: &[&'static str], mounts: &[&'static str], entries: &'static [Entry<'static>], budget: u64) {
    let mut roots: Vec<Root> = exports.iter().map(|&path| Root { path, imported: None }).collect();
    for &path in mounts {
        let inside = |e: &Entry| e.path.strip_prefix(path).is_some_and(|r| r.len() > 1 && r.starts_with('/'));
        let mut imported: Vec<u32> = (0..entries.len() as u32).filter(|&i| inside(&entries[i as usize])).collect();
        imported.sort_unstable_by(|&a, &b| entries[a as usize].path.cmp(entries[b as usize].path));
        roots.push(Root { path, imported: Some(imported) });
    }
    CONFIG.call_once(|| Config { roots, budget, entries });
}

/// Send every export, then `Done`. The host reads each directory's state as
/// it is now, so this runs once the program can't change it any more.
pub fn send() {
    let Some(cfg) = CONFIG.get().filter(|c| !c.roots.is_empty()) else { return };
    // Not yet built (exec failed early), or the program ended inside a
    // filesystem operation: nothing to read now, and the host reports the
    // exports as incomplete.
    let Some(mut fs) = fs::try_lock() else {
        klog!("export skipped: the filesystem isn't available\n");
        return;
    };
    let mut walk = Walk {
        budget: cfg.budget,
        data: Data::new(),
        truncated: false,
        skipped: false,
        entries: cfg.entries,
        root: "",
        imported: &[],
        seen: Vec::new(),
        scratch: Vec::new(),
    };
    for (index, root) in cfg.roots.iter().enumerate() {
        let dir = fs.lookup(ROOT, root.path, true).ok().filter(|&ino| fs.is_dir(ino));
        message(&ExportMsg::Root { index: index as u32, found: dir.is_some() });
        walk.root = root.path;
        walk.imported = root.imported.as_deref().unwrap_or(&[]);
        walk.seen = alloc::vec![false; walk.imported.len()];
        if let Some(dir) = dir {
            walk.tree(&fs, dir, root.imported.is_some());
            if root.imported.is_some() {
                walk.removed();
            }
        }
        if core::mem::take(&mut walk.truncated) {
            message(&ExportMsg::Truncated);
        }
        if core::mem::take(&mut walk.skipped) {
            message(&ExportMsg::Skipped);
        }
    }
    message(&ExportMsg::Done);
}

fn message(m: &ExportMsg) {
    console::write(Channel::Export, &m.encode());
}

struct Walk<'a> {
    /// What may still be sent, in `export_cost` units.
    budget: u64,
    data: Data,
    /// Something was left out (budget, path length) or couldn't be read.
    truncated: bool,
    skipped: bool,
    /// A mount (its path), its imported entries, and which of them are
    /// still there.
    entries: &'static [Entry<'static>],
    root: &'static str,
    imported: &'a [u32],
    seen: Vec<bool>,
    /// For comparing written files with what was imported.
    scratch: Vec<u8>,
}

impl Walk<'_> {
    /// Everything under directory `root`, depth first, parents before
    /// children. An entry that doesn't fit is left out (a directory with
    /// everything in it), and smaller ones after it still go. With
    /// `changes`, only what differs from `imported` is sent.
    fn tree(&mut self, fs: &Fs, root: Ino, changes: bool) {
        let mut path = String::with_capacity(MAX_EXPORT_PATH);
        // Directories being walked: (ino, length of `path` without its
        // name, the last child visited). At most MAX_EXPORT_PATH / 2 deep.
        let mut stack: Vec<(Ino, usize, Option<&str>)> = alloc::vec![(root, 0, None)];
        while let Some((dir, _, last)) = stack.last_mut() {
            let Kind::Dir(children) = &fs.node(*dir).kind else { unreachable!("only directories are walked") };
            let next = match last {
                None => children.iter().next(),
                Some(l) => children.range::<str, _>((Bound::Excluded(*l), Bound::Unbounded)).next(),
            };
            let Some((name, &ino)) = next else {
                let (_, parent_len, _) = stack.pop().unwrap();
                path.truncate(parent_len);
                continue;
            };
            *last = Some(name.as_str());
            let parent_len = path.len();
            let node = fs.node(ino);
            // /dev, /proc and /sys aren't the program's files, and a live
            // mount's are on the host already.
            if node.system || node.remote.is_some() {
                continue;
            }
            if parent_len + 1 + name.len() > MAX_EXPORT_PATH {
                self.truncated = true;
                continue;
            }
            if parent_len > 0 {
                path.push('/');
            }
            path.push_str(name);
            let send = !changes || !self.unchanged(node, &path);
            match &node.kind {
                Kind::Dir(_) => {
                    // A mount's directories are always walked: what's in
                    // them is only gone if it isn't found.
                    if (send && self.entry(ExportKind::Dir, node, &path, 0)) || changes {
                        self.data.flush();
                        stack.push((ino, parent_len, None));
                        continue;
                    }
                }
                Kind::File(c) if send => self.file(node, &path, c),
                Kind::Symlink(target) if send => self.symlink(node, &path, target),
                _ => {}
            }
            path.truncate(parent_len);
        }
    }

    /// Is `node`, at `path` in a mount, just as the host imported it? Marks
    /// the imported entry at `path` as still there either way: if it
    /// changed, sending the new one replaces it.
    fn unchanged(&mut self, node: &Node, path: &str) -> bool {
        let Ok(i) = self.find(path) else { return false };
        self.seen[i] = true;
        let e = &self.entries[self.imported[i] as usize];
        match (&node.kind, e.kind) {
            (Kind::Dir(_), EntryKind::Dir) => node.perm == e.mode & 0o7777,
            (Kind::Symlink(t), EntryKind::Symlink) => t.as_bytes() == e.data,
            // A second name is new to the host, so both get sent.
            (Kind::File(c), EntryKind::File) => {
                node.perm == e.mode & 0o7777
                    && node.mtime == e.mtime_ns
                    && node.nlink == 1
                    && self.same_bytes(c, e.data)
            }
            _ => false,
        }
    }

    /// The index in `imported` of the entry at `path` (relative).
    fn find(&self, path: &str) -> Result<usize, usize> {
        self.imported.binary_search_by(|&i| rel(&self.entries[i as usize], self.root).cmp(path))
    }

    fn same_bytes(&mut self, content: &Content, data: &[u8]) -> bool {
        let Some(c) = content.try_lock() else { return false };
        if let Some(base) = c.image() {
            return core::ptr::eq(base, data);
        }
        if c.len() != data.len() as u64 {
            return false;
        }
        // Written to, perhaps with the same bytes.
        self.scratch.resize(4096, 0);
        let mut off = 0;
        while off < data.len() {
            let n = c.read(off as u64, &mut self.scratch);
            if n == 0 || self.scratch[..n] != data[off..off + n] {
                return false;
            }
            off += n;
        }
        true
    }

    /// `Removed` for what the host imported into a mount that's no longer
    /// at its path: only the topmost of what's gone, since a directory goes
    /// with everything in it.
    fn removed(&mut self) {
        for i in 0..self.imported.len() {
            if self.seen[i] {
                continue;
            }
            let path = rel(&self.entries[self.imported[i] as usize], self.root);
            if let Some((parent, _)) = path.rsplit_once('/')
                && self.find(parent).is_ok_and(|j| !self.seen[j])
            {
                continue;
            }
            let cost = export_cost(path.len(), 0);
            if path.len() > MAX_EXPORT_PATH || cost > self.budget {
                self.truncated = true;
                continue;
            }
            self.budget -= cost;
            message(&ExportMsg::Entry {
                kind: ExportKind::Removed,
                mode: 0,
                mtime_ns: 0,
                path_len: path.len() as u32,
                data_len: 0,
            });
            self.data.put(path.as_bytes());
            self.data.flush();
        }
    }

    /// Start an entry (sending its path) if it fits in the budget.
    fn entry(&mut self, kind: ExportKind, node: &Node, path: &str, data_len: u64) -> bool {
        let cost = export_cost(path.len(), data_len);
        if cost > self.budget {
            self.truncated = true;
            return false;
        }
        self.budget -= cost;
        message(&ExportMsg::Entry {
            kind,
            mode: node.perm,
            mtime_ns: node.mtime,
            path_len: path.len() as u32,
            data_len,
        });
        self.data.put(path.as_bytes());
        true
    }

    fn symlink(&mut self, node: &Node, path: &str, target: &str) {
        if self.entry(ExportKind::Symlink, node, path, target.len() as u64) {
            self.data.put(target.as_bytes());
            self.data.flush();
        }
    }

    fn file(&mut self, node: &Node, path: &str, content: &Content) {
        // Held further up only if the program ended in the middle of a write.
        let Some(c) = content.try_lock() else {
            self.skipped = true;
            return;
        };
        if !self.entry(ExportKind::File, node, path, c.len()) {
            return;
        }
        let mut off = 0;
        while off < c.len() {
            let n = c.read(off, self.data.spare());
            self.data.used(n);
            off += n as u64;
        }
        self.data.flush();
    }
}

/// Builds `Data` messages in place, each filling one console buffer.
struct Data {
    buf: [u8; console::WRITE_CHUNK],
    len: usize,
}

impl Data {
    fn new() -> Data {
        let mut buf = [0; console::WRITE_CHUNK];
        buf[0] = ExportMsg::DATA_TAG;
        Data { buf, len: 1 }
    }

    fn put(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let spare = self.spare();
            let n = spare.len().min(bytes.len());
            spare[..n].copy_from_slice(&bytes[..n]);
            self.used(n);
            bytes = &bytes[n..];
        }
    }

    /// Room for more bytes (sending what's there first if it's full).
    fn spare(&mut self) -> &mut [u8] {
        if self.len == self.buf.len() {
            self.flush();
        }
        &mut self.buf[self.len..]
    }

    fn used(&mut self, n: usize) {
        self.len += n;
    }

    fn flush(&mut self) {
        if self.len > 1 {
            console::write(Channel::Export, &self.buf[..self.len]);
            self.len = 1;
        }
    }
}
