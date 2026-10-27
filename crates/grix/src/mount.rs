//! Directories mounted read-write from the host
//! ([`SandboxBuilder::mount`](crate::SandboxBuilder::mount)). Each run
//! imports the directory as it is then. When the program ends, the guest
//! sends what changed (entries that are new or differ, and the paths that
//! are gone), and this applies it to the host directory.
//!
//! The changes come from the guest, so applying them trusts nothing in
//! them. Every path stays inside the directory and is reached through real
//! directories only, never through a link. Files and links are replaced by
//! renaming a new one into place. Anything that changed on the host during
//! the run is left as the host has it and reported as a conflict.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use grix_abi::wire::MAX_EXPORT_PATH;
use serde::Serialize;

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

fn snap_of(meta: &fs::Metadata, path: &Path) -> Snap {
    let ft = meta.file_type();
    if ft.is_dir() {
        Snap::Dir
    } else if ft.is_file() {
        Snap::File {
            len: meta.len(),
            mtime_ns: image::mtime_of(meta),
            mode: meta.permissions().mode() & 0o7777,
            ino: meta.ino(),
            ctime_ns: ctime_ns(meta),
        }
    } else if ft.is_symlink() {
        Snap::Symlink(fs::read_link(path).unwrap_or_default())
    } else {
        Snap::Other
    }
}

fn ctime_ns(meta: &fs::Metadata) -> i128 {
    meta.ctime() as i128 * 1_000_000_000 + meta.ctime_nsec() as i128
}

fn current(path: &Path) -> io::Result<Option<Snap>> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(snap_of(&m, path))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// A mount as imported for one run.
pub(crate) struct Imported {
    pub files: BTreeMap<String, Node>,
    /// Relative path -> what it was on the host.
    snaps: HashMap<String, Snap>,
}

impl Mount {
    pub fn import(&self) -> Result<Imported> {
        if !fs::symlink_metadata(&self.host).is_ok_and(|m| m.is_dir()) {
            bail!("mounting {}: not a directory any more", self.host.display());
        }
        let mut files = BTreeMap::new();
        let mut stamps = HashMap::new();
        image::import_with(&mut files, &self.host, &self.guest, &mut |path, meta| {
            stamps.insert(path.to_string(), (meta.ino(), ctime_ns(meta)));
        })?;
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
        Ok(Imported { files, snaps })
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
        // Still the directory it was (nothing below checks above it).
        if !fs::symlink_metadata(&m.host).is_ok_and(|md| md.is_dir())
            || m.host.canonicalize().ok().as_deref() != Some(m.host.as_path())
        {
            out.state = MountState::Failed(format!("{} isn't the mounted directory any more", m.host.display()));
            return out;
        }
        let mut a = Apply { root: &m.host, snaps: &self.snaps, out: &mut out, dir_modes: Vec::new() };
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
    root: &'a Path,
    snaps: &'a HashMap<String, Snap>,
    out: &'a mut MountChanges,
    /// Directories' modes, set last: a read-only one would stop anything
    /// being created in it.
    dir_modes: Vec<(String, u32)>,
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
            // set_permissions follows links: check again that this is the
            // real directory it was.
            let Some(path) = self.resolve(&rel)? else { continue };
            if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(mode & 0o755))
                .with_context(|| format!("setting the mode of {}", path.display()))?;
        }
        Ok(())
    }

    /// The host path for `rel`, if every directory on the way there is a
    /// real directory (not a link to one).
    fn resolve(&self, rel: &str) -> io::Result<Option<PathBuf>> {
        let mut path = self.root.to_path_buf();
        let (dirs, name) = match rel.rsplit_once('/') {
            Some((dirs, name)) => (Some(dirs), name),
            None => (None, rel),
        };
        for c in dirs.into_iter().flat_map(|d| d.split('/')) {
            path.push(c);
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => return Ok(None),
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        path.push(name);
        Ok(Some(path))
    }

    fn conflict(&mut self, rel: &str) {
        self.out.conflicts.push(rel.to_string());
    }

    fn remove(&mut self, rel: &str) -> io::Result<()> {
        // Gone already, with the directory it was in or by itself.
        let Some(path) = self.resolve(rel)? else { return Ok(()) };
        if current(&path)?.is_none() {
            return Ok(());
        }
        if self.remove_matching(rel, &path)? {
            self.out.removed.push(rel.to_string());
        }
        Ok(())
    }

    /// Remove `path` and, for a directory, what's in it, as far as it's
    /// what was imported. Returns whether it's all gone.
    fn remove_matching(&mut self, rel: &str, path: &Path) -> io::Result<bool> {
        let now = current(path)?;
        let was = self.snaps.get(rel);
        match (&now, was) {
            (None, _) => Ok(true),
            (Some(Snap::Dir), Some(Snap::Dir)) => {
                let mut all = true;
                for entry in fs::read_dir(path)? {
                    let name = entry?.file_name();
                    let Some(name) = name.to_str() else {
                        self.conflict(&format!("{rel}/{}", name.to_string_lossy()));
                        all = false;
                        continue;
                    };
                    all &= self.remove_matching(&format!("{rel}/{name}"), &path.join(name))?;
                }
                if all {
                    fs::remove_dir(path)?;
                }
                Ok(all)
            }
            (Some(n), Some(w)) if n == w => {
                fs::remove_file(path)?;
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
        let Some(path) = self.resolve(rel)? else {
            // Its directory changed on the host, or wasn't made here.
            self.conflict(rel);
            return Ok(());
        };
        let now = current(&path)?;
        let was = self.snaps.get(rel);
        if let ExportContent::Dir = e.content {
            match &now {
                // There already, or made on the host too: the same thing.
                Some(Snap::Dir) => {}
                n if n.as_ref() == was => {
                    if n.is_some() && !self.remove_matching(rel, &path)? {
                        return Ok(());
                    }
                    fs::create_dir(&path).with_context(|| format!("creating {}", path.display()))?;
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
        if matches!(now, Some(Snap::Dir)) && !self.remove_matching(rel, &path)? {
            return Ok(());
        }
        // A new file or link next to it, renamed over it: never written
        // through a link, and never half-written.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_file_name(format!(".grix-{}-{n}.tmp", std::process::id()));
        let made = match &e.content {
            ExportContent::File(data) => {
                // Group and other write only if the file had them.
                let keep = match was {
                    Some(Snap::File { mode, .. }) => mode & 0o022,
                    _ => 0,
                };
                write_file(&tmp, data, e, (e.mode & 0o755) | (e.mode & keep))
            }
            ExportContent::Symlink(target) => std::os::unix::fs::symlink(target, &tmp),
            ExportContent::Dir => unreachable!(),
        };
        let made = made.and_then(|()| fs::rename(&tmp, &path));
        if let Err(err) = made {
            let _ = fs::remove_file(&tmp);
            return Err(err).with_context(|| format!("replacing {}", path.display()));
        }
        self.out.written.push(rel.to_string());
        Ok(())
    }
}

fn write_file(path: &Path, data: &[u8], e: &ExportEntry, mode: u32) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
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
