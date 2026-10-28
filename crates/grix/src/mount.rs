//! Directories mounted read-write from the host
//! ([`SandboxBuilder::mount`](crate::SandboxBuilder::mount)). Each run
//! imports the directory as it is then. When the program ends, the guest
//! sends what changed (entries that are new or differ, and the paths that
//! are gone), and this applies it to the host directory.
//!
//! The changes come from the guest, so applying them trusts nothing in
//! them. Every path stays inside the directory and is reached through real
//! directories only, never through a link: each is opened from the one
//! above it (`crate::at`), so a directory something else swaps for a link
//! meanwhile can't send a change elsewhere. Files and links are replaced by
//! renaming a new one into place. Anything that changed on the host during
//! the run is left as the host has it and reported as a conflict.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use grix_abi::wire::MAX_EXPORT_PATH;
use serde::Serialize;

use crate::at::{self, Kind};
use crate::export::{Changes, ExportContent, ExportEntry, ExportState};
use crate::image::{self, Node};

#[derive(Clone, Debug)]
pub(crate) struct Mount {
    /// Canonical, so no link on the way to it can change where it is.
    pub host: PathBuf,
    pub guest: String,
}

/// What a path on the host was when it was imported, or is now.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Snap {
    Dir,
    /// The inode and ctime catch changes that keep the size and mtime
    /// (`cp -p`, `touch -r`, coarse timestamps).
    File {
        len: u64,
        mtime_ns: u64,
        mode: u32,
        ino: u64,
        ctime_ns: i128,
    },
    Symlink(PathBuf),
    /// Something the guest never saw: a socket, FIFO or device.
    Other,
}

/// What `name` in `dir` is now, if anything.
#[allow(clippy::unnecessary_cast)]
fn current(dir: RawFd, name: &CStr) -> io::Result<Option<Snap>> {
    let st = match at::stat_at(dir, name) {
        Ok(st) => st,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(Some(match at::kind(&st) {
        Kind::Dir => Snap::Dir,
        Kind::File => Snap::File {
            len: st.st_size as u64,
            mtime_ns: at::mtime_ns(&st),
            mode: at::mode(&st),
            ino: st.st_ino as u64,
            ctime_ns: at::ctime_ns(&st),
        },
        Kind::Symlink => {
            Snap::Symlink(PathBuf::from(OsStr::from_bytes(&at::readlink_at(dir, name).unwrap_or_default())))
        }
        Kind::Other => Snap::Other,
    }))
}

/// A mount as imported for one run.
pub(crate) struct Imported {
    pub files: BTreeMap<String, Node>,
    /// Relative path -> what it was on the host.
    snaps: HashMap<String, Snap>,
    /// Which directory it was.
    root: (u64, u64),
}

impl Mount {
    #[allow(clippy::unnecessary_cast)]
    pub fn import(&self) -> Result<Imported> {
        let mut files = BTreeMap::new();
        let mut stamps = HashMap::new();
        let mut root = None;
        image::import_with(&mut files, &self.host, &self.guest, &mut |path, st| {
            if path == self.guest {
                root = Some(at::identity(st));
            }
            stamps.insert(path.to_string(), (st.st_ino as u64, at::ctime_ns(st)));
        })?;
        let Some(root) = root.filter(|_| matches!(files.get(&self.guest), Some(Node::Dir { .. }))) else {
            bail!("mounting {}: not a directory any more", self.host.display());
        };
        let prefix = format!("{}/", self.guest);
        let mut snaps = HashMap::new();
        for (p, n) in &files {
            let Some(rel) = p.strip_prefix(&prefix) else { continue };
            // Its changes couldn't come back (the guest leaves such paths
            // out), so every run would end with nothing applied.
            if rel.len() > MAX_EXPORT_PATH {
                bail!("mounting {}: {rel:?} is nested too deep (over {MAX_EXPORT_PATH} bytes)", self.host.display());
            }
            let snap = match n {
                &Node::File { ref data, mode, mtime_ns } => {
                    let (ino, ctime_ns) = stamps.get(p).copied().unwrap_or_default();
                    Snap::File { len: data.len() as u64, mtime_ns, mode, ino, ctime_ns }
                }
                Node::Dir { .. } => Snap::Dir,
                Node::Symlink { target, .. } => Snap::Symlink(target.into()),
            };
            snaps.insert(rel.to_string(), snap);
        }
        Ok(Imported { files, snaps, root })
    }
}

/// What a run did to a mounted directory.
#[derive(Clone, Debug, Serialize)]
pub struct MountChanges {
    /// The directory on the host.
    pub host: PathBuf,
    /// Where the program saw it.
    pub guest: String,
    pub state: MountState,
    /// Paths (relative to `host`) created or replaced.
    pub written: Vec<String>,
    /// Paths removed, with everything in them.
    pub removed: Vec<String>,
    /// Paths the program changed that changed on the host too during the
    /// run (or are inside one that did): left as the host has them.
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountState {
    /// The program's changes are on the host, except `conflicts`.
    Applied,
    /// Nothing changed on the host, because the program's changes didn't
    /// all arrive: the run timed out or the kernel panicked, they were over
    /// [`max_export`](crate::SandboxBuilder::max_export), or the program
    /// ended in the middle of changing a file.
    NotApplied,
    /// Applying them stopped at an error; `written` and `removed` say how
    /// far it got.
    Failed(String),
}

impl Imported {
    /// Apply what the program changed in mount `m` to the host directory.
    pub fn apply(&self, m: &Mount, changes: Changes) -> MountChanges {
        let mut out = MountChanges {
            host: m.host.clone(),
            guest: m.guest.clone(),
            state: MountState::Applied,
            written: Vec::new(),
            removed: Vec::new(),
            conflicts: Vec::new(),
        };
        if changes.state != ExportState::Complete {
            out.state = MountState::NotApplied;
            return out;
        }
        if let Err(e) = check(&changes) {
            out.state = MountState::Failed(format!("{e:#}"));
            return out;
        }
        // Still the directory it was, and reached by the same real
        // directories (nothing below looks above it).
        let root = at::open_dir(&m.host)
            .ok()
            .filter(|fd| at::stat_fd(fd.as_raw_fd()).is_ok_and(|st| at::identity(&st) == self.root));
        let Some(root) = root else {
            out.state = MountState::Failed(format!("{} isn't the mounted directory any more", m.host.display()));
            return out;
        };
        let mut a = Apply { root, host: &m.host, snaps: &self.snaps, out: &mut out, dir_modes: Vec::new() };
        if let Err(e) = a.run(&changes) {
            out.state = MountState::Failed(format!("{e:#}"));
        }
        out
    }
}

/// Reject a change set no guest kernel would send: a path twice, or
/// something written inside what's removed or inside a file or link. (Each
/// path was already checked to be relative, with plain names only.)
fn check(c: &Changes) -> Result<()> {
    let mut seen = HashSet::new();
    for p in c.entries.iter().map(|e| e.path.as_str()).chain(c.removed.iter().map(String::as_str)) {
        if !seen.insert(p) {
            bail!("the changes name {p:?} twice");
        }
    }
    let removed: HashSet<&str> = c.removed.iter().map(String::as_str).collect();
    let not_dirs: HashSet<&str> =
        c.entries.iter().filter(|e| !matches!(e.content, ExportContent::Dir)).map(|e| e.path.as_str()).collect();
    for e in &c.entries {
        let mut p = e.path.as_str();
        while let Some((parent, _)) = p.rsplit_once('/') {
            if removed.contains(parent) || not_dirs.contains(parent) {
                bail!("the changes write {:?} inside {parent:?}, which isn't a directory", e.path);
            }
            p = parent;
        }
    }
    Ok(())
}

struct Apply<'a> {
    /// The mount's directory, `host`.
    root: OwnedFd,
    host: &'a Path,
    snaps: &'a HashMap<String, Snap>,
    out: &'a mut MountChanges,
    /// Directories' modes, set last: a read-only one would stop anything
    /// being created in it.
    dir_modes: Vec<(String, u32)>,
}

/// A directory of the mount and a name in it.
struct At {
    dir: OwnedFd,
    name: CString,
}

impl At {
    fn fd(&self) -> RawFd {
        self.dir.as_raw_fd()
    }
}

/// Every path in the changes has plain names only (`export::valid_path`),
/// which may still hold a NUL.
fn cname(name: &str) -> io::Result<CString> {
    at::cname(OsStr::new(name))
}

impl Apply<'_> {
    fn run(&mut self, c: &Changes) -> Result<()> {
        // Removals first, so a name freed by a rename (or by a case change,
        // on a case-insensitive filesystem) can be taken again.
        for rel in &c.removed {
            self.remove(rel).with_context(|| format!("removing {rel}"))?;
        }
        for e in &c.entries {
            self.write(e).with_context(|| format!("writing {}", e.path))?;
        }
        for (rel, mode) in std::mem::take(&mut self.dir_modes).into_iter().rev() {
            // The directory itself, opened: never what a link points at.
            let Some(at) = self.resolve(&rel)? else { continue };
            let Ok(d) = at::open_dir_at(at.fd(), &at.name) else { continue };
            fs::File::from(d)
                .set_permissions(fs::Permissions::from_mode(mode & 0o755))
                .with_context(|| format!("setting the mode of {}", self.host.join(&rel).display()))?;
        }
        Ok(())
    }

    /// The directory `rel` is in, if every directory on the way there is a
    /// real directory (not a link to one), opened by walking down to it.
    fn resolve(&self, rel: &str) -> io::Result<Option<At>> {
        let (dirs, name) = match rel.rsplit_once('/') {
            Some((dirs, name)) => (Some(dirs), name),
            None => (None, rel),
        };
        let mut dir = at::openat(self.root.as_raw_fd(), c".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        for c in dirs.into_iter().flat_map(|d| d.split('/')) {
            dir = match at::open_dir_at(dir.as_raw_fd(), &cname(c)?) {
                Ok(d) => d,
                Err(e) if at::not_a_dir(&e) => return Ok(None),
                Err(e) => return Err(e),
            };
        }
        Ok(Some(At { dir, name: cname(name)? }))
    }

    fn conflict(&mut self, rel: &str) {
        self.out.conflicts.push(rel.to_string());
    }

    fn remove(&mut self, rel: &str) -> io::Result<()> {
        // Gone already, with the directory it was in or by itself.
        let Some(at) = self.resolve(rel)? else { return Ok(()) };
        if current(at.fd(), &at.name)?.is_none() {
            return Ok(());
        }
        if self.remove_matching(rel, at.fd(), &at.name)? {
            self.out.removed.push(rel.to_string());
        }
        Ok(())
    }

    /// Remove `name` in `dir` and, for a directory, what's in it, as far as
    /// it's what was imported (`rel`). Returns whether it's all gone.
    fn remove_matching(&mut self, rel: &str, dir: RawFd, name: &CStr) -> io::Result<bool> {
        let now = current(dir, name)?;
        let was = self.snaps.get(rel);
        match (&now, was) {
            (None, _) => Ok(true),
            (Some(Snap::Dir), Some(Snap::Dir)) => {
                let sub = match at::open_dir_at(dir, name) {
                    Ok(d) => d,
                    // Not a directory any more: changed meanwhile.
                    Err(e) if at::not_a_dir(&e) => {
                        self.conflict(rel);
                        return Ok(false);
                    }
                    Err(e) => return Err(e),
                };
                let mut all = true;
                for entry in at::read_dir(sub.as_raw_fd())? {
                    let Ok(n) = entry.to_str() else {
                        self.conflict(&format!("{rel}/{}", entry.to_string_lossy()));
                        all = false;
                        continue;
                    };
                    all &= self.remove_matching(&format!("{rel}/{n}"), sub.as_raw_fd(), &entry)?;
                }
                if all {
                    at::remove_at(dir, name, true)?;
                }
                Ok(all)
            }
            (Some(n), Some(w)) if n == w => {
                at::remove_at(dir, name, false)?;
                Ok(true)
            }
            _ => {
                self.conflict(rel);
                Ok(false)
            }
        }
    }

    fn write(&mut self, e: &ExportEntry) -> Result<()> {
        let rel = e.path.as_str();
        let path = self.host.join(rel);
        let Some(at) = self.resolve(rel)? else {
            // Its directory changed on the host, or wasn't made here.
            self.conflict(rel);
            return Ok(());
        };
        let now = current(at.fd(), &at.name)?;
        let was = self.snaps.get(rel);
        if let ExportContent::Dir = e.content {
            match &now {
                // There already, or made on the host too: the same thing.
                Some(Snap::Dir) => {}
                n if n.as_ref() == was => {
                    if n.is_some() && !self.remove_matching(rel, at.fd(), &at.name)? {
                        return Ok(());
                    }
                    at::mkdir_at(at.fd(), &at.name, 0o777).with_context(|| format!("creating {}", path.display()))?;
                }
                _ => {
                    self.conflict(rel);
                    return Ok(());
                }
            }
            self.dir_modes.push((rel.to_string(), e.mode));
            self.out.written.push(rel.to_string());
            return Ok(());
        }
        if now.as_ref() != was {
            self.conflict(rel);
            return Ok(());
        }
        if matches!(now, Some(Snap::Dir)) && !self.remove_matching(rel, at.fd(), &at.name)? {
            return Ok(());
        }
        // A new file or link next to it, renamed over it: never written
        // through a link, and never half-written.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = cname(&format!(".grix-{}-{n}.tmp", std::process::id()))?;
        let made = match &e.content {
            ExportContent::File(data) => {
                // Group and other write only if the file had them.
                let keep = match was {
                    Some(Snap::File { mode, .. }) => mode & 0o022,
                    _ => 0,
                };
                write_file(at.fd(), &tmp, data, e, (e.mode & 0o755) | (e.mode & keep))
            }
            ExportContent::Symlink(target) => cname(target).and_then(|target| at::symlink_at(&target, at.fd(), &tmp)),
            ExportContent::Dir => unreachable!(),
        };
        let made = made.and_then(|()| at::rename(at.fd(), &tmp, at.fd(), &at.name, false));
        if let Err(err) = made {
            let _ = at::remove_at(at.fd(), &tmp, false);
            return Err(err).with_context(|| format!("replacing {}", path.display()));
        }
        self.out.written.push(rel.to_string());
        Ok(())
    }
}

fn write_file(dir: RawFd, name: &CStr, data: &[u8], e: &ExportEntry, mode: u32) -> io::Result<()> {
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
    let mut f = fs::File::from(at::openat(dir, name, flags, 0o600)?);
    f.write_all(data)?;
    f.set_modified(e.mtime)?;
    f.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn tempdir() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "grix-mount-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&d).unwrap();
        d.canonicalize().unwrap()
    }

    fn file(path: &str, data: &str) -> ExportEntry {
        ExportEntry {
            path: path.into(),
            mode: 0o644,
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            content: ExportContent::File(data.as_bytes().to_vec()),
        }
    }

    fn dir(path: &str) -> ExportEntry {
        ExportEntry { path: path.into(), mode: 0o755, mtime: SystemTime::UNIX_EPOCH, content: ExportContent::Dir }
    }

    fn changes(entries: Vec<ExportEntry>, removed: &[&str]) -> Changes {
        Changes { state: ExportState::Complete, entries, removed: removed.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn applies_changes_and_keeps_conflicts() {
        let root = tempdir();
        fs::write(root.join("keep.txt"), "keep").unwrap();
        fs::write(root.join("edit.txt"), "old").unwrap();
        fs::write(root.join("gone.txt"), "x").unwrap();
        fs::write(root.join("raced.txt"), "host").unwrap();
        fs::create_dir(root.join("olddir")).unwrap();
        fs::write(root.join("olddir/f"), "f").unwrap();
        let m = Mount { host: root.clone(), guest: "/work".into() };
        let imported = m.import().unwrap();
        // Meanwhile, on the host:
        fs::write(root.join("raced.txt"), "host changed it").unwrap();
        fs::write(root.join("olddir/new-on-host"), "!").unwrap();

        let c = changes(
            vec![file("edit.txt", "new"), file("raced.txt", "guest"), dir("src"), file("src/main.rs", "fn main() {}")],
            &["gone.txt", "olddir"],
        );
        let out = imported.apply(&m, c);
        assert_eq!(out.state, MountState::Applied);
        assert_eq!(fs::read_to_string(root.join("keep.txt")).unwrap(), "keep");
        assert_eq!(fs::read_to_string(root.join("edit.txt")).unwrap(), "new");
        assert_eq!(fs::read_to_string(root.join("src/main.rs")).unwrap(), "fn main() {}");
        assert!(!root.join("gone.txt").exists());
        // What changed on the host stays.
        assert_eq!(fs::read_to_string(root.join("raced.txt")).unwrap(), "host changed it");
        assert!(!root.join("olddir/f").exists() && root.join("olddir/new-on-host").exists());
        assert_eq!(out.conflicts, ["olddir/new-on-host", "raced.txt"]);
        assert_eq!(out.removed, ["gone.txt"]);
        assert_eq!(out.written, ["edit.txt", "src", "src/main.rs"]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn never_writes_through_links() {
        let root = tempdir();
        let outside = tempdir();
        fs::create_dir(root.join("d")).unwrap();
        let m = Mount { host: root.clone(), guest: "/work".into() };
        let imported = m.import().unwrap();
        // The guest says: replace d with a link outside, then write into
        // it. No kernel sends that.
        let mut link = file("d", "");
        link.content = ExportContent::Symlink(outside.to_string_lossy().into());
        let out = imported.apply(&m, changes(vec![link.clone(), file("d/evil", "x")], &[]));
        assert!(matches!(out.state, MountState::Failed(_)));
        assert!(fs::symlink_metadata(root.join("d")).unwrap().is_dir());
        // The link alone is fine; writing through it later isn't.
        let out = imported.apply(&m, changes(vec![link], &[]));
        assert_eq!(out.state, MountState::Applied);
        assert!(fs::symlink_metadata(root.join("d")).unwrap().file_type().is_symlink());
        let out = imported.apply(&m, changes(vec![file("d/evil", "x")], &[]));
        assert_eq!((out.state, out.conflicts), (MountState::Applied, vec!["d/evil".to_string()]));
        assert!(!outside.join("evil").exists());
        // Repeated paths and writes inside removals are refused outright.
        let out = imported.apply(&m, changes(vec![file("a", "1"), file("a", "2")], &[]));
        assert!(matches!(out.state, MountState::Failed(_)));
        let out = imported.apply(&m, changes(vec![file("d/x", "1")], &["d"]));
        assert!(matches!(out.state, MountState::Failed(_)));
        let out = imported.apply(&m, changes(vec![file("f", "1"), dir("f/g")], &[]));
        assert!(matches!(out.state, MountState::Failed(_)));
        assert!(!root.join("f").exists());
        let mut partial = changes(vec![file("a", "1")], &[]);
        partial.state = ExportState::Truncated;
        assert_eq!(imported.apply(&m, partial).state, MountState::NotApplied);
        assert!(!root.join("a").exists());
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn a_directory_swapped_for_a_link_meanwhile_leads_nowhere() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        let root = tempdir();
        let outside = tempdir();
        fs::create_dir(root.join("d")).unwrap();
        let m = Mount { host: root.clone(), guest: "/work".into() };
        let imported = m.import().unwrap();
        // Something else with the directory (another run's live mount)
        // keeps swapping d for a link outside and back.
        let stop = Arc::new(AtomicBool::new(false));
        let swapper = {
            let (root, outside, stop) = (root.clone(), outside.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = fs::rename(root.join("d"), root.join("real"));
                    let _ = std::os::unix::fs::symlink(&outside, root.join("d"));
                    let _ = fs::remove_file(root.join("d"));
                    let _ = fs::rename(root.join("real"), root.join("d"));
                }
            })
        };
        let mut written = Vec::new();
        for i in 0..500 {
            let out = imported.apply(&m, changes(vec![file(&format!("d/f{i}"), "x")], &[]));
            written.extend(out.written);
        }
        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();
        let escaped: Vec<_> = fs::read_dir(&outside).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(escaped.is_empty(), "written outside the mount: {escaped:?}");
        for w in &written {
            assert!(root.join(w).exists(), "{w} was written, but isn't there");
        }
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn applies_to_the_directory_imported_only() {
        let base = tempdir();
        let root = base.join("m");
        fs::create_dir(&root).unwrap();
        let m = Mount { host: root.clone(), guest: "/work".into() };
        let imported = m.import().unwrap();
        // Another directory by that name now,
        fs::rename(&root, base.join("old")).unwrap();
        fs::create_dir(&root).unwrap();
        let out = imported.apply(&m, changes(vec![file("a", "1")], &[]));
        assert!(matches!(out.state, MountState::Failed(_)), "{out:?}");
        // or a link to the one it was.
        fs::remove_dir(&root).unwrap();
        std::os::unix::fs::symlink(base.join("old"), &root).unwrap();
        let out = imported.apply(&m, changes(vec![file("a", "1")], &[]));
        assert!(matches!(out.state, MountState::Failed(_)), "{out:?}");
        assert!(!root.join("a").exists() && !base.join("old/a").exists());
        assert!(m.import().is_err());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn replaces_kinds() {
        let root = tempdir();
        fs::write(root.join("was-file"), "x").unwrap();
        fs::create_dir(root.join("was-dir")).unwrap();
        fs::write(root.join("was-dir/inside"), "y").unwrap();
        let m = Mount { host: root.clone(), guest: "/work".into() };
        let imported = m.import().unwrap();
        let c = changes(
            vec![dir("was-file"), file("was-file/child", "c"), file("was-dir", "now a file")],
            &["was-dir/inside"],
        );
        let out = imported.apply(&m, c);
        assert_eq!(out.state, MountState::Applied, "{out:?}");
        assert!(out.conflicts.is_empty(), "{out:?}");
        assert_eq!(fs::read_to_string(root.join("was-file/child")).unwrap(), "c");
        assert_eq!(fs::read_to_string(root.join("was-dir")).unwrap(), "now a file");
        fs::remove_dir_all(&root).unwrap();
    }
}
