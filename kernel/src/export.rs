//! Sending the directories the host asked for (`Image::exports`) back to it
//! when the program ends: the agent's results. See `wire::ExportMsg`.
//!
//! The walk allocates nothing per entry (names are borrowed from the locked
//! filesystem), and what it sends is bounded twice: by the host's budget,
//! counted the same way the host counts it, and by `MAX_EXPORT_PATH`, which
//! also bounds the walk's depth.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Bound;
use grix_abi::wire::{Channel, ExportKind, ExportMsg, MAX_EXPORT_PATH, export_cost};
use spin::Once;

use crate::console::{self, klog};
use crate::fs::{self, Content, Fs, Ino, Kind, Node, ROOT};

struct Config {
    roots: Vec<&'static str>,
    budget: u64,
}

static CONFIG: Once<Config> = Once::new();

/// Remember what to export, and the most it may cost (from the boot image).
pub fn init(roots: Vec<&'static str>, budget: u64) {
    CONFIG.call_once(|| Config { roots, budget });
}

/// Send every export, then `Done`. The host reads each directory's state as
/// it is now, so this runs once the program can't change it any more.
pub fn send() {
    let Some(cfg) = CONFIG.get().filter(|c| !c.roots.is_empty()) else { return };
    // Not yet built (exec failed early), or the program ended inside a
    // filesystem operation: nothing to read now, and the host reports the
    // exports as incomplete.
    let Some(fs) = fs::try_lock() else {
        klog!("export skipped: the filesystem isn't available\n");
        return;
    };
    let mut walk = Walk { budget: cfg.budget, data: Data::new(), truncated: false, skipped: false };
    for (index, path) in cfg.roots.iter().enumerate() {
        let root = fs.lookup(ROOT, path, true).ok().filter(|&ino| fs.is_dir(ino));
        message(&ExportMsg::Root { index: index as u32, found: root.is_some() });
        if let Some(root) = root {
            walk.tree(&fs, root);
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

struct Walk {
    /// What may still be sent, in `export_cost` units.
    budget: u64,
    data: Data,
    /// Something was left out (budget, path length) or couldn't be read.
    truncated: bool,
    skipped: bool,
}

impl Walk {
    /// Everything under directory `root`, depth first, parents before
    /// children. An entry that doesn't fit is left out (a directory with
    /// everything in it), and smaller ones after it still go.
    fn tree(&mut self, fs: &Fs, root: Ino) {
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
            // /dev, /proc and /sys aren't the program's files.
            if node.system {
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
            match &node.kind {
                Kind::Dir(_) => {
                    if self.entry(ExportKind::Dir, node, &path, 0) {
                        self.data.flush();
                        stack.push((ino, parent_len, None));
                        continue;
                    }
                }
                Kind::File(c) => self.file(node, &path, c),
                Kind::Symlink(target) => self.symlink(node, &path, target),
                _ => {}
            }
            path.truncate(parent_len);
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
