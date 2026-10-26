//! The filesystem the program sees: exactly the files the host imported,
//! plus synthetic nodes: /dev, /proc and /sys (see procfs.rs), and
//! /etc/passwd + /etc/group describing the sandbox user unless imported.
//! File contents are referenced in place from the boot image.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use grix_abi::image::{Entry, EntryKind};
use spin::Once;

use crate::errno::*;
use crate::procfs::{self, ProcFile};

pub type Ino = usize;
pub const ROOT: Ino = 0;
const MAX_SYMLINKS: u32 = 40;

pub const S_IFIFO: u32 = 0o010000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dev {
    Null,
    Zero,
    Random,
}

pub enum Kind {
    File(&'static [u8]),
    Dir(BTreeMap<String, Ino>),
    Symlink(String),
    Dev(Dev),
    /// Generated when opened.
    Proc(ProcFile),
}

pub struct Node {
    pub kind: Kind,
    pub perm: u32,
    pub parent: Ino,
    pub name: String,
}

pub struct StatInfo {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub size: u64,
    pub rdev: u64,
}

pub struct Fs {
    nodes: Vec<Node>,
    /// `/proc/1/fd`, whose entries are the live descriptors.
    pub fd_dir: Ino,
}

static FS: Once<Fs> = Once::new();

/// Make `fs` the filesystem. Done once, after exec resolved the program.
pub fn install(fs: Fs) {
    FS.call_once(|| fs);
}

fn leak(s: String) -> &'static [u8] {
    alloc::boxed::Box::leak(s.into_boxed_str()).as_bytes()
}

pub fn get() -> &'static Fs {
    FS.get().expect("fs not initialised")
}

impl Fs {
    pub fn build(entries: &[Entry<'static>], uid: u32, gid: u32) -> Fs {
        let root = Node { kind: Kind::Dir(BTreeMap::new()), perm: 0o755, parent: ROOT, name: String::new() };
        let mut fs = Fs { nodes: vec![root], fd_dir: ROOT };
        for e in entries {
            let path = e.path.trim_end_matches('/');
            let Some(slash) = path.rfind('/') else { continue };
            let name = &path[slash + 1..];
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let parent = fs.mkdir_p(&path[..slash]);
            let kind = match e.kind {
                EntryKind::File => Kind::File(e.data),
                EntryKind::Dir => Kind::Dir(BTreeMap::new()),
                EntryKind::Symlink => Kind::Symlink(String::from_utf8_lossy(e.data).into_owned()),
            };
            fs.insert(parent, name, kind, e.mode & 0o7777);
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
        fs.mkdir_p("/dev/shm");

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

        // Describe the sandbox user unless the host imported its own files.
        if fs.lookup(ROOT, "/etc/passwd", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            let passwd = alloc::format!(
                "root:x:0:0:root:/root:/sbin/nologin\ngrix:x:{uid}:{gid}:grix:/home/grix:/bin/sh\n\
                 nobody:x:65534:65534:nobody:/:/sbin/nologin\n"
            );
            fs.insert(etc, "passwd", Kind::File(leak(passwd)), 0o644);
            fs.mkdir_p("/home/grix");
        }
        if fs.lookup(ROOT, "/etc/group", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            let group = alloc::format!("root:x:0:\ngrix:x:{gid}:\nnobody:x:65534:\n");
            fs.insert(etc, "group", Kind::File(leak(group)), 0o644);
        }
        if fs.lookup(ROOT, "/etc/mtab", false).is_err() {
            let etc = fs.mkdir_p("/etc");
            fs.insert(etc, "mtab", Kind::Symlink("/proc/self/mounts".into()), 0o777);
        }
        fs.mkdir_p("/tmp");
        fs
    }

    /// `/proc/self/exe` points at the program actually running (the
    /// interpreter, for `#!` scripts).
    pub fn set_exe(&mut self, path: &str) {
        let pid_dir = self.mkdir_p("/proc/1");
        self.insert(pid_dir, "exe", Kind::Symlink(path.into()), 0o777);
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn child(&self, dir: Ino, name: &str) -> Option<Ino> {
        match &self.nodes[dir].kind {
            Kind::Dir(children) => children.get(name).copied(),
            _ => None,
        }
    }

    fn mkdir_p(&mut self, path: &str) -> Ino {
        let mut cur = ROOT;
        for c in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            cur = match self.child(cur, c) {
                Some(i) if self.is_dir(i) => i,
                _ => self.insert(cur, c, Kind::Dir(BTreeMap::new()), 0o755),
            };
        }
        cur
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
        let ino = self.nodes.len();
        self.nodes.push(Node { kind, perm, parent, name: name.into() });
        if let Kind::Dir(children) = &mut self.nodes[parent].kind {
            children.insert(name.into(), ino);
        }
        ino
    }

    pub fn node(&self, ino: Ino) -> &Node {
        &self.nodes[ino]
    }

    pub fn is_dir(&self, ino: Ino) -> bool {
        matches!(self.nodes[ino].kind, Kind::Dir(_))
    }

    /// Resolve `path` relative to directory `start`.
    pub fn lookup(&self, start: Ino, path: &str, follow_last: bool) -> Result<Ino, Errno> {
        self.walk(start, path, follow_last, 0)
    }

    fn walk(&self, start: Ino, path: &str, follow_last: bool, depth: u32) -> Result<Ino, Errno> {
        if depth > MAX_SYMLINKS {
            return Err(ELOOP);
        }
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
                    let child = *children.get(name).ok_or(ENOENT)?;
                    if let Kind::Symlink(target) = &self.nodes[child].kind
                        && (!last || follow_last || must_be_dir)
                    {
                        cur = self.walk(cur, target, true, depth + 1)?;
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
            Kind::File(d) => (S_IFREG, d.len() as u64, 1, 0),
            Kind::Dir(c) => (S_IFDIR, 4096, 2 + c.len() as u32, 0),
            Kind::Symlink(t) => (S_IFLNK, t.len() as u64, 1, 0),
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
        StatInfo { ino: ino as u64 + 1, mode: ty | n.perm, nlink, size, rdev }
    }

    /// Directory entries in getdents order: ".", "..", then children sorted by name.
    pub fn dir_entry(&self, dir: Ino, pos: u64) -> Option<(&str, Ino)> {
        let Kind::Dir(children) = &self.nodes[dir].kind else { return None };
        match pos {
            0 => Some((".", dir)),
            1 => Some(("..", self.nodes[dir].parent)),
            n => children.iter().nth((n - 2) as usize).map(|(k, v)| (k.as_str(), *v)),
        }
    }

    /// Linux d_type for a node.
    pub fn d_type(&self, ino: Ino) -> u8 {
        match self.nodes[ino].kind {
            Kind::File(_) | Kind::Proc(_) => 8,
            Kind::Dir(_) => 4,
            Kind::Symlink(_) => 10,
            Kind::Dev(_) => 2,
        }
    }
}
