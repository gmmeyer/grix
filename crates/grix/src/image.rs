//! Collecting imports and encoding the boot image.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use grix_abi::image::{Entry, EntryKind};

use crate::at::{self, Kind};

/// An imported file, directory or link. `mtime_ns` is its modification
/// time in ns since the Unix epoch, as the host has it.
#[derive(Clone, Debug)]
pub(crate) enum Node {
    File { data: Vec<u8>, mode: u32, mtime_ns: u64, owner: Owner },
    Dir { mode: u32, mtime_ns: u64, owner: Owner },
    Symlink { target: String, mtime_ns: u64, owner: Owner },
}

/// Whose a node is: the (uid, gid) an image's layer or build step gave it, or
/// None for the sandbox's own user, as anything imported from the host is.
pub(crate) type Owner = Option<(u32, u32)>;

/// A time as ns since the Unix epoch (0 before it).
pub(crate) fn ns(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

pub(crate) fn now_ns() -> u64 {
    ns(SystemTime::now())
}

/// Paths the guest kernel provides itself.
const RESERVED: &[&str] = &["/dev", "/proc", "/sys"];

/// Check and normalize an absolute guest path.
pub(crate) fn guest_path(p: &str) -> Result<String> {
    if !p.starts_with('/') {
        bail!("guest path {p:?} must be absolute");
    }
    let parts: Vec<&str> = p.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    if parts.contains(&"..") {
        bail!("guest path {p:?} must not contain `..`");
    }
    let norm = format!("/{}", parts.join("/"));
    if RESERVED.iter().any(|r| norm == *r || norm.starts_with(&format!("{r}/"))) {
        bail!("guest path {p:?} is reserved by the sandbox");
    }
    Ok(norm)
}

/// `host` with its directories resolved (the last name may still be a
/// link, which imports as one): the path [`import`] wants, for a path
/// given by whoever runs grix, links and all.
pub(crate) fn real_dirs(host: &Path) -> Result<PathBuf> {
    let missing = || format!("{} does not exist", host.display());
    match (host.parent(), host.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
            Ok(parent.canonicalize().with_context(missing)?.join(name))
        }
        _ => host.canonicalize().with_context(missing),
    }
}

/// Import a host file, directory (recursively) or symlink at `guest`.
/// `host`'s directories must be real ones ([`real_dirs`]): nothing
/// resolves it again, and nothing on the way to it or in it is followed
/// if it's a link, so whatever is swapped in while it's read (or since it
/// was checked) can't lead anywhere else.
pub(crate) fn import(files: &mut BTreeMap<String, Node>, host: &Path, guest: &str) -> Result<()> {
    import_with(files, host, guest, &mut |_, _| {})
}

pub(crate) fn import_with(
    files: &mut BTreeMap<String, Node>,
    host: &Path,
    guest: &str,
    seen: &mut dyn FnMut(&str, &libc::stat),
) -> Result<()> {
    let guest = guest_path(guest)?;
    let (dir, name) = at::open_parent(host).with_context(|| format!("{} does not exist", host.display()))?;
    import_at(files, dir.as_raw_fd(), &name, host, &guest, seen)
        .with_context(|| format!("importing {}", host.display()))
}

/// Import `name` in `dir` (which is `host`).
fn import_at(
    files: &mut BTreeMap<String, Node>,
    dir: RawFd,
    name: &CStr,
    host: &Path,
    guest: &str,
    seen: &mut dyn FnMut(&str, &libc::stat),
) -> Result<()> {
    let st = at::stat_at(dir, name).with_context(|| format!("{} does not exist", host.display()))?;
    match at::kind(&st) {
        Kind::Symlink => {
            let target = String::from_utf8(at::readlink_at(dir, name)?)
                .ok()
                .with_context(|| format!("non UTF-8 symlink {}", host.display()))?;
            seen(guest, &st);
            files.insert(guest.into(), Node::Symlink { target, mtime_ns: at::mtime_ns(&st), owner: None });
        }
        Kind::Dir => {
            // What's opened is what's described and listed, whatever has
            // the name by now.
            let d = at::open_dir_at(dir, name)?;
            let st = at::stat_fd(d.as_raw_fd())?;
            seen(guest, &st);
            if guest != "/" {
                files.insert(guest.into(), Node::Dir { mode: at::mode(&st), mtime_ns: at::mtime_ns(&st), owner: None });
            }
            for child in at::read_dir(d.as_raw_fd())? {
                let n = child.to_str().with_context(|| format!("non UTF-8 file name in {}", host.display()))?;
                let g = if guest == "/" { format!("/{n}") } else { format!("{guest}/{n}") };
                import_at(files, d.as_raw_fd(), &child, &host.join(n), &g, seen)?;
            }
        }
        Kind::File => {
            // O_NONBLOCK: by now it may be a FIFO, whose open would wait.
            let mut f = fs::File::from(at::openat(dir, name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)?);
            let st = at::stat_fd(f.as_raw_fd())?;
            if at::kind(&st) != Kind::File {
                return Ok(());
            }
            seen(guest, &st);
            let mut data = Vec::new();
            f.read_to_end(&mut data)?;
            files.insert(
                guest.into(),
                Node::File { data, mode: at::mode(&st), mtime_ns: at::mtime_ns(&st), owner: None },
            );
        }
        // Sockets, FIFOs and device nodes are skipped.
        Kind::Other => {}
    }
    Ok(())
}

pub(crate) fn entries(files: &BTreeMap<String, Node>) -> Vec<Entry<'_>> {
    files
        .iter()
        .map(|(path, node)| match node {
            &Node::File { ref data, mode, mtime_ns, owner } => {
                Entry { path, kind: EntryKind::File, mode, mtime_ns, owner, data }
            }
            &Node::Dir { mode, mtime_ns, owner } => {
                Entry { path, kind: EntryKind::Dir, mode, mtime_ns, owner, data: &[] }
            }
            Node::Symlink { target, mtime_ns, owner } => Entry {
                path,
                kind: EntryKind::Symlink,
                mode: 0o777,
                mtime_ns: *mtime_ns,
                owner: *owner,
                data: target.as_bytes(),
            },
        })
        .collect()
}

pub(crate) fn imported_bytes(files: &BTreeMap<String, Node>) -> u64 {
    files
        .iter()
        .map(|(p, n)| {
            p.len() as u64
                + match n {
                    Node::File { data, .. } => data.len() as u64,
                    Node::Symlink { target, .. } => target.len() as u64,
                    Node::Dir { .. } => 0,
                }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "grix-image-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn imports_never_follow_what_is_swapped_in() {
        let root = tempdir();
        let outside = tempdir();
        fs::write(outside.join("secret"), "OUTSIDE").unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/f"), "inside").unwrap();
        fs::write(root.join("g"), "inside").unwrap();
        let mut files = BTreeMap::new();
        // Each, once it's been looked at, becomes a link out: the file
        // before it's read, the directory before it's listed.
        import_with(&mut files, &root, "/m", &mut |path, _| match path {
            "/m/g" => {
                fs::remove_file(root.join("g")).unwrap();
                symlink(outside.join("secret"), root.join("g")).unwrap();
            }
            "/m/sub" => {
                fs::rename(root.join("sub"), root.join("moved")).unwrap();
                symlink(&outside, root.join("sub")).unwrap();
            }
            _ => {}
        })
        .unwrap();
        let data = |files: &BTreeMap<String, Node>, p: &str| match files.get(p) {
            Some(Node::File { data, .. }) => Some(String::from_utf8_lossy(data).into_owned()),
            _ => None,
        };
        assert_eq!(data(&files, "/m/g").as_deref(), Some("inside"));
        assert_eq!(data(&files, "/m/sub/f").as_deref(), Some("inside"));
        assert!(!files.contains_key("/m/sub/secret"), "{:?}", files.keys());
        // A link on the way to the import fails it, unless resolved first;
        // a link as the last name is imported as one.
        symlink(root.join("moved"), root.join("dirlink")).unwrap();
        assert!(import(&mut files, &root.join("dirlink/f"), "/x").is_err());
        import(&mut files, &real_dirs(&root.join("dirlink/f")).unwrap(), "/x").unwrap();
        assert_eq!(data(&files, "/x").as_deref(), Some("inside"));
        import(&mut files, &real_dirs(&root.join("dirlink")).unwrap(), "/y").unwrap();
        assert!(matches!(files.get("/y"), Some(Node::Symlink { .. })));
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn guest_paths_are_normalized_and_checked() {
        assert_eq!(guest_path("/bin//x/./y").unwrap(), "/bin/x/y");
        assert_eq!(guest_path("/").unwrap(), "/");
        assert!(guest_path("bin/x").is_err());
        assert!(guest_path("/a/../b").is_err());
        assert!(guest_path("/dev/null").is_err());
        assert!(guest_path("/proc").is_err());
        assert!(guest_path("/devices").is_ok());
    }
}
