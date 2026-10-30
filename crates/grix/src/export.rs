//! Directories the program wrote, sent back when it ends (the agent's
//! results): collecting them from the guest, and writing them to the host.
//!
//! Everything here comes from the guest, so it's checked: sizes count
//! against a budget, paths must stay inside their directory, and writing
//! never follows a link or touches anything it didn't create.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use grix_abi::wire::{ExportKind, ExportMsg, MAX_EXPORT_PATH, export_cost};
use serde::Serialize;

/// One directory given to [`SandboxBuilder::export`](crate::SandboxBuilder::export),
/// as the program left it.
#[derive(Clone, Debug, Serialize)]
pub struct Export {
    /// The directory in the sandbox.
    pub dir: String,
    pub state: ExportState,
    /// Everything under `dir`, parents before children.
    #[serde(serialize_with = "summaries")]
    pub entries: Vec<ExportEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportState {
    /// All of it.
    Complete,
    /// It didn't exist (or wasn't a directory) when the program ended.
    Missing,
    /// Some entries were left out: over
    /// [`max_export`](crate::SandboxBuilder::max_export) (the rest, and
    /// smaller entries after, are there), or nested deeper than 4096 bytes
    /// of path.
    Truncated,
    /// The run ended before the guest sent it all (timeout, kernel panic,
    /// a garbled stream), or the program ended in the middle of changing a
    /// file there. `entries` has what arrived.
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportEntry {
    /// Relative to the exported directory, `/`-separated; every component is
    /// a plain name (no `.`, `..` or empty ones).
    pub path: String,
    /// Permission bits, including setuid, setgid and sticky.
    pub mode: u32,
    pub mtime: SystemTime,
    pub content: ExportContent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportContent {
    Dir,
    File(Vec<u8>),
    /// A symbolic link and its target, which may point anywhere.
    Symlink(String),
}

fn summaries<S: serde::Serializer>(entries: &[ExportEntry], s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Summary<'a> {
        path: &'a str,
        kind: &'static str,
        mode: u32,
        size: usize,
    }
    s.collect_seq(entries.iter().map(|e| {
        let (kind, size) = match &e.content {
            ExportContent::Dir => ("dir", 0),
            ExportContent::File(data) => ("file", data.len()),
            ExportContent::Symlink(target) => ("symlink", target.len()),
        };
        Summary { path: &e.path, kind, mode: e.mode, size }
    }))
}

/// What [`Export::write_to_with`] makes of symbolic links.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Links {
    /// As they are, wherever they point (they're never followed while
    /// writing, but whatever reads the tree later may).
    #[default]
    Any,
    /// Only links that stay inside the exported tree: a relative target
    /// that, followed through the tree's own links, never leaves it, as
    /// Python tarfile's `data` filter allows. A target that goes on with
    /// `..` from a name the tree doesn't have as a directory or link is
    /// refused too (a dangling path's, say): the host may fold case or
    /// normalise Unicode, and take that name for another. Anything else
    /// fails the whole export before it's written.
    Inside,
}

/// Where `target`, the target of the link at `link`, leads in the tree
/// whose links are `links` and directories `dirs`: `None` if it leaves
/// the tree, is absolute, or goes through more than 40 links (Linux's
/// limit), or if `..` follows a name that's neither. Names are the
/// tree's exactly and a host's filesystem may see them otherwise, so
/// such a name may be a link here, say `UP` for `up -> ..`, and `..` from
/// it could be anywhere. Without `..` it can only go down or through
/// links, each of which stays inside from where it really is. (The other
/// way, two names of the tree that a host sees as one can't both be
/// written, which fails the export.)
fn resolve_inside(
    links: &BTreeMap<&str, &str>,
    dirs: &BTreeSet<&str>,
    link: &str,
    target: &str,
) -> Option<Vec<String>> {
    let mut at: Vec<String> = link.split('/').map(String::from).collect();
    at.pop();
    let mut pending: Vec<String> = Vec::new();
    let push_target = |pending: &mut Vec<String>, t: &str| -> bool {
        if t.starts_with('/') {
            return false;
        }
        pending.extend(t.split('/').rev().map(String::from));
        true
    };
    if !push_target(&mut pending, target) {
        return None;
    }
    let mut hops = 0;
    while let Some(c) = pending.pop() {
        match c.as_str() {
            "" | "." => {}
            ".." => {
                at.pop()?;
            }
            name => {
                at.push(name.to_string());
                let here = at.join("/");
                if let Some(t) = links.get(here.as_str()) {
                    hops += 1;
                    if hops > 40 || !push_target(&mut pending, t) {
                        return None;
                    }
                    at.pop();
                } else if !dirs.contains(here.as_str()) {
                    return (!pending.iter().any(|c| c == "..")).then_some(at);
                }
            }
        }
    }
    Some(at)
}

/// A path the guest may name inside an export: plain components only.
fn valid_path(path: &str) -> bool {
    !path.is_empty() && path.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains('\0'))
}

impl Export {
    /// Check that `dest` can take an export: it doesn't exist yet but its
    /// parent does, or it's an empty directory (not a link to one). Worth
    /// doing before a run, so its results have somewhere to go.
    pub fn check_destination(dest: impl AsRef<Path>) -> Result<()> {
        let dest = dest.as_ref();
        if dest.file_name().is_none() {
            bail!("{} can't be an export destination (it needs a name)", dest.display());
        }
        match fs::symlink_metadata(dest) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let parent = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
                if !parent.is_dir() {
                    bail!("{}: {} isn't a directory", dest.display(), parent.display());
                }
                Ok(())
            }
            Err(e) => Err(e).with_context(|| format!("checking {}", dest.display())),
            Ok(m) if !m.is_dir() => bail!("{} exists and isn't a directory", dest.display()),
            Ok(_) if fs::read_dir(dest)?.next().is_some() => bail!("{} isn't empty", dest.display()),
            Ok(_) => Ok(()),
        }
    }

    /// Recreate the directory at `dest` on the host (see
    /// [`check_destination`](Export::check_destination)). Files and
    /// directories get the exported mtimes and permission bits, less
    /// setuid, setgid, sticky and group/other write (as with a umask of
    /// 022). Symbolic links are created as they are, and nothing is ever
    /// written through one. The tree is built next to `dest` and renamed
    /// into place, so if anything fails (say, two names a case-insensitive
    /// filesystem sees as one) nothing is left behind.
    pub fn write_to(&self, dest: impl AsRef<Path>) -> Result<()> {
        self.write_to_with(dest, Links::Any)
    }

    /// [`write_to`](Export::write_to), with `links` saying which symbolic
    /// links may be written: with [`Links::Inside`], a link that is
    /// absolute or leads out of the tree (`../..`, or through another of
    /// its links) fails the export, and nothing is written.
    pub fn write_to_with(&self, dest: impl AsRef<Path>, links: Links) -> Result<()> {
        let dest = dest.as_ref();
        // Check the whole tree first: every parent is a directory listed
        // before it, and nothing appears twice.
        let mut dirs = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for e in &self.entries {
            if !valid_path(&e.path) || !seen.insert(e.path.as_str()) {
                bail!("export of {} has a bad or repeated path {:?}", self.dir, e.path);
            }
            if let Some((parent, _)) = e.path.rsplit_once('/')
                && !dirs.contains(parent)
            {
                bail!("export of {} lists {:?} without its directory", self.dir, e.path);
            }
            match &e.content {
                ExportContent::Dir => {
                    dirs.insert(e.path.as_str());
                }
                ExportContent::Symlink(t) if t.is_empty() || t.contains('\0') => {
                    bail!("export of {} has a bad link target at {:?}", self.dir, e.path)
                }
                _ => {}
            }
        }
        if links == Links::Inside {
            let all: BTreeMap<&str, &str> = self
                .entries
                .iter()
                .filter_map(|e| match &e.content {
                    ExportContent::Symlink(t) => Some((e.path.as_str(), t.as_str())),
                    _ => None,
                })
                .collect();
            for (path, target) in &all {
                if resolve_inside(&all, &dirs, path, target).is_none() {
                    bail!("export of {} has a link {path:?} to {target:?}, outside it", self.dir);
                }
            }
        }
        Self::check_destination(dest)?;
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let name = dest.file_name().unwrap().to_string_lossy();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dest.with_file_name(format!(".{name}.grix-{}-{n}", std::process::id()));
        fs::create_dir(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        let result = self
            .write_tree(&tmp)
            .and_then(|()| fs::rename(&tmp, dest).with_context(|| format!("moving it to {}", dest.display())));
        if result.is_err() {
            remove_tree(&tmp);
        }
        result
    }

    fn write_tree(&self, root: &Path) -> Result<()> {
        let perm = |mode: u32| fs::Permissions::from_mode(mode & 0o755);
        let mut dir_times = Vec::new();
        for e in &self.entries {
            let path = root.join(&e.path);
            match &e.content {
                ExportContent::Dir => {
                    fs::create_dir(&path).with_context(|| format!("creating {}", path.display()))?;
                    dir_times.push((path, perm(e.mode), e.mtime));
                }
                ExportContent::File(data) => {
                    // create_new: never through an existing name or link.
                    let mut f = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path)
                        .with_context(|| format!("creating {}", path.display()))?;
                    f.write_all(data).with_context(|| format!("writing {}", path.display()))?;
                    f.set_modified(e.mtime)?;
                    f.set_permissions(perm(e.mode))?;
                }
                ExportContent::Symlink(_) => {}
            }
        }
        for e in &self.entries {
            if let ExportContent::Symlink(target) = &e.content {
                let path = root.join(&e.path);
                std::os::unix::fs::symlink(target, &path).with_context(|| format!("creating {}", path.display()))?;
            }
        }
        // Directories last, deepest first: a read-only one would stop
        // anything being created in it, and creating changes its mtime.
        for (path, perm, mtime) in dir_times.into_iter().rev() {
            fs::File::open(&path)?.set_modified(mtime)?;
            fs::set_permissions(&path, perm)?;
        }
        Ok(())
    }
}

/// Remove a half-built tree, making its directories writable first.
fn remove_tree(path: &Path) {
    fn writable(dir: &Path) {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                writable(&entry.path());
            }
        }
    }
    writable(path);
    let _ = fs::remove_dir_all(path);
}

/// An entry whose path and contents are still arriving.
struct Pending {
    kind: ExportKind,
    mode: u32,
    mtime_ns: u64,
    path_len: usize,
    data_len: usize,
    path: Vec<u8>,
    data: Vec<u8>,
    /// Over the budget: count the bytes off without keeping them.
    keep: bool,
    received: usize,
}

/// What changed in a mounted directory: entries that are new or differ
/// from what was imported, and the paths that are gone.
pub(crate) struct Changes {
    pub state: ExportState,
    pub entries: Vec<ExportEntry>,
    pub removed: Vec<String>,
}

/// Turns the guest's `Channel::Export` messages into [`Export`]s, and the
/// changes in mounts.
pub(crate) struct Collector {
    /// The exports, then the mounts.
    exports: Vec<Export>,
    removed: Vec<Vec<String>>,
    first_mount: usize,
    /// What may still be kept, in `wire::export_cost` units. The guest
    /// counts the same way and leaves out what wouldn't fit, so running out
    /// here means it didn't.
    budget: u64,
    current: Option<usize>,
    /// The guest couldn't read something in the current directory.
    skipped: bool,
    pending: Option<Pending>,
    /// Over the budget: keep nothing more.
    full: bool,
    /// Done arrived, or the stream went wrong: ignore everything else.
    ended: bool,
    done: bool,
}

impl Collector {
    pub fn new(dirs: &[String], mounts: &[String], budget: u64) -> Collector {
        let exports: Vec<Export> = dirs
            .iter()
            .chain(mounts)
            .map(|d| Export { dir: d.clone(), state: ExportState::Incomplete, entries: Vec::new() })
            .collect();
        Collector {
            removed: vec![Vec::new(); exports.len()],
            first_mount: dirs.len(),
            exports,
            budget,
            current: None,
            skipped: false,
            pending: None,
            full: false,
            ended: false,
            done: false,
        }
    }

    pub fn push(&mut self, payload: &[u8]) {
        if self.ended || self.handle(payload).is_none() {
            // Garbled: what arrived so far stays, the rest is incomplete.
            self.ended = true;
        }
    }

    /// `None` when the stream breaks the protocol.
    fn handle(&mut self, payload: &[u8]) -> Option<()> {
        let msg = ExportMsg::decode(payload).ok()?;
        if self.pending.is_some() && !matches!(msg, ExportMsg::Data(_)) {
            return None;
        }
        match msg {
            ExportMsg::Root { index, found } => {
                let index = index as usize;
                // In order, each once.
                if index >= self.exports.len() || self.current.is_some_and(|c| index <= c) {
                    return None;
                }
                self.finish_current();
                self.current = Some(index);
                self.skipped = false;
                if !found {
                    self.exports[index].state = ExportState::Missing;
                }
            }
            ExportMsg::Entry { kind, mode, mtime_ns, path_len, data_len } => {
                let cur = self.current?;
                let path_len = path_len as usize;
                let data_len = usize::try_from(data_len).ok()?;
                let empty = matches!(kind, ExportKind::Dir | ExportKind::Removed);
                // (A length no entry can have, and the sums below can't wrap.)
                if self.exports[cur].state == ExportState::Missing
                    || path_len == 0
                    || path_len > MAX_EXPORT_PATH
                    || path_len.checked_add(data_len).is_none()
                    || (empty && data_len != 0)
                    || (kind == ExportKind::Removed && cur < self.first_mount)
                {
                    return None;
                }
                let cost = export_cost(path_len, data_len as u64);
                let mut data = Vec::new();
                let keep = !self.full && cost <= self.budget && data.try_reserve_exact(data_len).is_ok();
                if keep {
                    self.budget -= cost;
                } else {
                    self.full = true;
                    self.exports[cur].state = ExportState::Truncated;
                }
                let path = Vec::with_capacity(path_len);
                self.pending =
                    Some(Pending { kind, mode, mtime_ns, path_len, data_len, path, data, keep, received: 0 });
            }
            ExportMsg::Data(bytes) => {
                let p = self.pending.as_mut()?;
                if bytes.len() > p.path_len + p.data_len - p.received {
                    return None;
                }
                let to_path = bytes.len().min(p.path_len - p.path.len());
                p.path.extend_from_slice(&bytes[..to_path]);
                if p.keep {
                    p.data.extend_from_slice(&bytes[to_path..]);
                }
                p.received += bytes.len();
                if p.received == p.path_len + p.data_len {
                    let p = self.pending.take().unwrap();
                    if p.keep {
                        self.add(p)?;
                    }
                }
            }
            ExportMsg::Truncated => {
                let cur = self.current?;
                if self.exports[cur].state != ExportState::Missing {
                    self.exports[cur].state = ExportState::Truncated;
                }
            }
            ExportMsg::Skipped => {
                self.current?;
                self.skipped = true;
            }
            ExportMsg::Done => {
                self.finish_current();
                self.done = true;
                self.ended = true;
            }
        }
        Some(())
    }

    /// Add an entry whose bytes have all arrived to its export.
    fn add(&mut self, p: Pending) -> Option<()> {
        let path = String::from_utf8(p.path).ok().filter(|s| valid_path(s))?;
        let cur = self.current?;
        let content = match p.kind {
            ExportKind::Dir => ExportContent::Dir,
            ExportKind::File => ExportContent::File(p.data),
            ExportKind::Symlink => ExportContent::Symlink(String::from_utf8(p.data).ok()?),
            ExportKind::Removed => {
                self.removed[cur].push(path);
                return Some(());
            }
        };
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_nanos(p.mtime_ns);
        self.exports[cur].entries.push(ExportEntry { path, mode: p.mode & 0o7777, mtime, content });
        Some(())
    }

    /// The current directory has all been sent.
    fn finish_current(&mut self) {
        if let Some(cur) = self.current
            && self.exports[cur].state == ExportState::Incomplete
            && !self.skipped
        {
            self.exports[cur].state = ExportState::Complete;
        }
    }

    /// The exports, and the mounts' changes.
    pub fn finish(mut self) -> (Vec<Export>, Vec<Changes>) {
        if !self.done
            && let Some(cur) = self.current
            && self.exports[cur].state == ExportState::Truncated
        {
            // Cut off while being sent: more is missing than the limit.
            self.exports[cur].state = ExportState::Incomplete;
        }
        let mounts = self.exports.split_off(self.first_mount);
        let removed = self.removed.split_off(self.first_mount);
        let changes = mounts
            .into_iter()
            .zip(removed)
            .map(|(e, removed)| Changes { state: e.state, entries: e.entries, removed })
            .collect();
        (self.exports, changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: ExportKind, path: &str, data: &[u8]) -> Vec<Vec<u8>> {
        let mut v = vec![
            ExportMsg::Entry {
                kind,
                mode: 0o644,
                mtime_ns: 7,
                path_len: path.len() as u32,
                data_len: data.len() as u64,
            }
            .encode(),
        ];
        let mut bytes = path.as_bytes().to_vec();
        bytes.extend_from_slice(data);
        for chunk in bytes.chunks(3) {
            v.push(ExportMsg::Data(chunk).encode());
        }
        v
    }

    fn collect(dirs: &[&str], budget: u64, msgs: &[Vec<u8>]) -> Vec<Export> {
        let dirs: Vec<String> = dirs.iter().map(|d| d.to_string()).collect();
        let mut c = Collector::new(&dirs, &[], budget);
        for m in msgs {
            c.push(m);
        }
        c.finish().0
    }

    #[test]
    fn collects_a_mounts_changes() {
        let msgs = stream(vec![
            vec![ExportMsg::Root { index: 0, found: true }.encode()],
            entry(ExportKind::File, "a", b"x"),
            vec![ExportMsg::Root { index: 1, found: true }.encode()],
            entry(ExportKind::File, "src/new.rs", b"fn main() {}"),
            entry(ExportKind::Removed, "old", b""),
            vec![ExportMsg::Done.encode()],
        ]);
        let mut c = Collector::new(&["/out".into()], &["/work".into()], 1 << 20);
        for m in &msgs {
            c.push(m);
        }
        let (exports, changes) = c.finish();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].entries.len(), 1);
        assert_eq!(changes[0].state, ExportState::Complete);
        assert_eq!(changes[0].entries[0].path, "src/new.rs");
        assert_eq!(changes[0].removed, ["old"]);
        // Removed only belongs in a mount.
        let bad = stream(vec![
            vec![ExportMsg::Root { index: 0, found: true }.encode()],
            entry(ExportKind::Removed, "x", b""),
        ]);
        assert_eq!(collect(&["/out"], 1 << 20, &bad)[0].state, ExportState::Incomplete);
    }

    fn stream(parts: Vec<Vec<Vec<u8>>>) -> Vec<Vec<u8>> {
        parts.into_iter().flatten().collect()
    }

    #[test]
    fn collects_directories_in_order() {
        let msgs = stream(vec![
            vec![ExportMsg::Root { index: 0, found: true }.encode()],
            entry(ExportKind::Dir, "sub", b""),
            entry(ExportKind::File, "sub/a.txt", b"hello world"),
            entry(ExportKind::Symlink, "link", b"sub/a.txt"),
            vec![ExportMsg::Root { index: 1, found: false }.encode(), ExportMsg::Done.encode()],
        ]);
        let ex = collect(&["/out", "/nope"], 1 << 20, &msgs);
        assert_eq!(ex[0].state, ExportState::Complete);
        let paths: Vec<_> = ex[0].entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["sub", "sub/a.txt", "link"]);
        assert_eq!(ex[0].entries[1].content, ExportContent::File(b"hello world".to_vec()));
        assert_eq!(ex[0].entries[2].content, ExportContent::Symlink("sub/a.txt".into()));
        assert_eq!(ex[1].state, ExportState::Missing);
        // Cut off before Done: incomplete.
        let ex = collect(&["/out", "/nope"], 1 << 20, &msgs[..msgs.len() - 2]);
        assert_eq!(ex[0].state, ExportState::Incomplete);
        assert_eq!(ex[1].state, ExportState::Incomplete);
    }

    #[test]
    fn budget_truncates_but_keeps_following_the_stream() {
        let msgs = stream(vec![
            vec![ExportMsg::Root { index: 0, found: true }.encode()],
            entry(ExportKind::File, "small", b"x"),
            entry(ExportKind::File, "big", &[0; 1000]),
            entry(ExportKind::File, "after", b"y"),
            vec![ExportMsg::Root { index: 1, found: true }.encode()],
            entry(ExportKind::File, "second", b"z"),
            vec![ExportMsg::Done.encode()],
        ]);
        // Room for "small" (262 units) only.
        let ex = collect(&["/a", "/b"], 600, &msgs);
        assert_eq!(ex[0].state, ExportState::Truncated);
        assert_eq!(ex[0].entries.len(), 1);
        assert_eq!(ex[1].state, ExportState::Truncated);
        assert!(ex[1].entries.is_empty());
    }

    #[test]
    fn guest_markers() {
        let msgs = |marker: ExportMsg| {
            stream(vec![
                vec![ExportMsg::Root { index: 0, found: true }.encode()],
                entry(ExportKind::File, "kept", b"x"),
                vec![marker.encode(), ExportMsg::Done.encode()],
            ])
        };
        let ex = collect(&["/out"], 1 << 20, &msgs(ExportMsg::Truncated));
        assert_eq!((ex[0].state, ex[0].entries.len()), (ExportState::Truncated, 1));
        let ex = collect(&["/out"], 1 << 20, &msgs(ExportMsg::Skipped));
        assert_eq!((ex[0].state, ex[0].entries.len()), (ExportState::Incomplete, 1));
    }

    #[test]
    fn rejects_bad_paths_and_garbage() {
        for bad in ["../escape", "/abs", "a//b", "a/./b", "", "a/\0"] {
            let msgs = stream(vec![
                vec![ExportMsg::Root { index: 0, found: true }.encode()],
                entry(ExportKind::File, bad, b"x"),
                vec![ExportMsg::Done.encode()],
            ]);
            let ex = collect(&["/out"], 1 << 20, &msgs);
            assert_eq!(ex[0].state, ExportState::Incomplete, "{bad:?}");
            assert!(ex[0].entries.is_empty(), "{bad:?}");
        }
        // Data past the declared length, roots out of order, entries before
        // a root, absurd lengths, random bytes: no panic, nothing kept after.
        let over = stream(vec![
            vec![ExportMsg::Root { index: 0, found: true }.encode()],
            vec![ExportMsg::Entry { kind: ExportKind::File, mode: 0, mtime_ns: 0, path_len: 1, data_len: 1 }.encode()],
            vec![ExportMsg::Data(b"abc").encode()],
        ]);
        assert_eq!(collect(&["/out"], 1 << 20, &over)[0].state, ExportState::Incomplete);
        let huge = vec![
            ExportMsg::Root { index: 0, found: true }.encode(),
            ExportMsg::Entry { kind: ExportKind::File, mode: 0, mtime_ns: 0, path_len: u32::MAX, data_len: u64::MAX }
                .encode(),
        ];
        assert_eq!(collect(&["/out"], 1 << 20, &huge)[0].state, ExportState::Incomplete);
        // Lengths whose sum wraps (a panic, in a debug build).
        let wraps = stream(vec![
            vec![ExportMsg::Root { index: 0, found: true }.encode()],
            vec![
                ExportMsg::Entry { kind: ExportKind::File, mode: 0, mtime_ns: 0, path_len: 1, data_len: u64::MAX }
                    .encode(),
            ],
            vec![ExportMsg::Data(b"ab").encode()],
        ]);
        assert_eq!(collect(&["/out"], 1 << 20, &wraps)[0].state, ExportState::Incomplete);
        let early = vec![ExportMsg::Data(b"x").encode(), ExportMsg::Root { index: 5, found: true }.encode()];
        assert_eq!(collect(&["/out"], 1 << 20, &early)[0].state, ExportState::Incomplete);
        let mut x: u32 = 1;
        let noise: Vec<Vec<u8>> = (0..2000)
            .map(|_| {
                (0..(x % 40))
                    .map(|_| {
                        x = x.wrapping_mul(1103515245).wrapping_add(12345);
                        (x >> 16) as u8 % 4
                    })
                    .collect()
            })
            .collect();
        collect(&["/out", "/b"], 1 << 20, &noise);
    }

    #[test]
    fn writes_a_tree_without_following_links() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let e = |path: &str, mode, content| ExportEntry { path: path.into(), mode, mtime: t, content };
        let export = Export {
            dir: "/out".into(),
            state: ExportState::Complete,
            entries: vec![
                e("ro", 0o555, ExportContent::Dir),
                e("ro/x.sh", 0o4755, ExportContent::File(b"#!/bin/sh\n".to_vec())),
                e("up", 0o777, ExportContent::Symlink("..".into())),
                e("open", 0o777, ExportContent::File(vec![])),
            ],
        };
        let base = std::env::temp_dir().join(format!("grix-export-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        export.write_to(&base).unwrap();
        let meta = fs::metadata(base.join("ro/x.sh")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o755);
        assert_eq!(meta.modified().unwrap(), t);
        assert_eq!(fs::read(base.join("ro/x.sh")).unwrap(), b"#!/bin/sh\n");
        assert_eq!(fs::metadata(base.join("ro")).unwrap().permissions().mode() & 0o777, 0o555);
        assert_eq!(fs::read_link(base.join("up")).unwrap(), Path::new(".."));
        assert_eq!(fs::metadata(base.join("open")).unwrap().permissions().mode() & 0o777, 0o755);
        // Not into a directory that has anything in it.
        assert!(export.write_to(&base).is_err());
        // A file under a link, or a path the guest shouldn't send, is refused
        // before anything is written.
        for bad in [
            vec![
                e("up", 0o777, ExportContent::Symlink("/etc".into())),
                e("up/passwd", 0o644, ExportContent::File(vec![])),
            ],
            vec![e("../x", 0o644, ExportContent::File(vec![]))],
            vec![e("a", 0o644, ExportContent::File(vec![])), e("a", 0o644, ExportContent::File(vec![]))],
        ] {
            let dest = base.join("bad");
            let ex = Export { dir: "/out".into(), state: ExportState::Complete, entries: bad };
            assert!(ex.write_to(&dest).is_err());
            assert!(!dest.exists());
        }
        // Failing partway (a name too long for the host) leaves nothing.
        let long = "n".repeat(300);
        let ex = Export {
            dir: "/out".into(),
            state: ExportState::Complete,
            entries: vec![
                e("ok", 0o755, ExportContent::Dir),
                e(&format!("ok/{long}"), 0o644, ExportContent::File(vec![])),
            ],
        };
        let dest = base.join("partial");
        assert!(ex.write_to(&dest).is_err());
        assert!(!dest.exists());
        let leftovers: Vec<_> = fs::read_dir(&base).unwrap().flatten().map(|e| e.file_name()).collect();
        assert!(leftovers.iter().all(|n| !n.to_string_lossy().contains("grix-")), "{leftovers:?}");
        // Destinations: the parent must exist, and a link isn't one.
        assert!(Export::check_destination(base.join("no/such")).is_err());
        std::os::unix::fs::symlink(&base, base.join("alias")).unwrap();
        assert!(Export::check_destination(base.join("alias")).is_err());
        assert!(Export::check_destination(base.join("fresh")).is_ok());
        fs::set_permissions(base.join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn links_inside_only() {
        let t = SystemTime::UNIX_EPOCH;
        let e = |path: &str, content| ExportEntry { path: path.into(), mode: 0o755, mtime: t, content };
        let link = |path: &str, target: &str| e(path, ExportContent::Symlink(target.into()));
        let tree = |more: Vec<ExportEntry>| {
            let mut entries = vec![e("d", ExportContent::Dir), e("d/e", ExportContent::Dir)];
            entries.extend(more);
            Export { dir: "/out".into(), state: ExportState::Complete, entries }
        };
        let base = std::env::temp_dir().join(format!("grix-export-links-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base).unwrap();
        let fine = [
            link("a", "d"),
            link("d/e/up", "../.."),
            link("d/b", "e/../../a/e"),
            link("d/e/c", "../../d/b/up/d"),
            link("dangling", "d/nothing/e"),
            link("dot", "."),
        ];
        let ok = tree(fine.to_vec());
        ok.write_to_with(base.join("ok"), Links::Inside).unwrap();
        assert_eq!(fs::read_link(base.join("ok/d/e/up")).unwrap(), Path::new("../.."));
        for bad in [
            vec![link("a", "/etc/passwd")],
            vec![link("a", "..")],
            vec![link("d/e/x", "../../../x")],
            // Out through another link: each alone looks harmless.
            vec![link("d/up", ".."), link("d/e/out", "../up/..")],
            vec![link("d/e/up", "../.."), link("x", "d/e/up/..")],
            // A loop never resolves.
            vec![link("p", "q"), link("q", "p")],
            // A host that folds case takes `UP` for the link `up`, which
            // the tree's names don't say: from a name the tree doesn't
            // have, `..` could lead anywhere.
            vec![link("d/up", ".."), link("d/x", "UP/../secret")],
            vec![link("d/x", "nothing/../e")],
            vec![link("d/e/up", "../.."), link("x", "d/e/UP/..")],
            // Through a link, the same.
            vec![link("d/up", ".."), link("d/y", "x/.."), link("d/x", "UP")],
            // A file isn't a directory to go back from either.
            vec![link("d/x", "../f/../..")],
        ] {
            let dest = base.join("bad");
            let ex = tree(bad.clone());
            assert!(ex.write_to_with(&dest, Links::Inside).is_err(), "{bad:?}");
            assert!(!dest.exists());
            // As they are, they're written.
            ex.write_to(&dest).unwrap();
            fs::remove_dir_all(&dest).unwrap();
        }
        fs::remove_dir_all(&base).unwrap();
    }
}
