//! Collecting imports and encoding the boot image.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use grix_abi::image::{Entry, EntryKind};

/// An imported file, directory or link. `mtime_ns` is its modification
/// time in ns since the Unix epoch, as the host has it.
#[derive(Clone, Debug)]
pub(crate) enum Node {
    File { data: Vec<u8>, mode: u32, mtime_ns: u64 },
    Dir { mode: u32, mtime_ns: u64 },
    Symlink { target: String, mtime_ns: u64 },
}

/// A time as ns since the Unix epoch (0 before it).
pub(crate) fn ns(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

pub(crate) fn now_ns() -> u64 {
    ns(SystemTime::now())
}

/// A file's modification time in ns (0 if the host can't say).
pub(crate) fn mtime_of(meta: &fs::Metadata) -> u64 {
    meta.modified().map_or(0, ns)
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

/// Import a host file, directory (recursively) or symlink at `guest`.
pub(crate) fn import(files: &mut BTreeMap<String, Node>, host: &Path, guest: &str) -> Result<()> {
    import_with(files, host, guest, &mut |_, _| {})
}

/// Like [`import`], also passing each guest path's host metadata to `seen`.
pub(crate) fn import_with(
    files: &mut BTreeMap<String, Node>,
    host: &Path,
    guest: &str,
    seen: &mut dyn FnMut(&str, &fs::Metadata),
) -> Result<()> {
    let guest = guest_path(guest)?;
    import_at(files, host, &guest, seen).with_context(|| format!("importing {}", host.display()))
}

fn import_at(
    files: &mut BTreeMap<String, Node>,
    host: &Path,
    guest: &str,
    seen: &mut dyn FnMut(&str, &fs::Metadata),
) -> Result<()> {
    let meta = fs::symlink_metadata(host).with_context(|| format!("{} does not exist", host.display()))?;
    seen(guest, &meta);
    let mode = meta.permissions().mode() & 0o7777;
    let mtime_ns = mtime_of(&meta);
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(host)?;
        let target = target.to_str().with_context(|| format!("non UTF-8 symlink {}", host.display()))?;
        files.insert(guest.into(), Node::Symlink { target: target.into(), mtime_ns });
    } else if ft.is_dir() {
        if guest != "/" {
            files.insert(guest.into(), Node::Dir { mode, mtime_ns });
        }
        for entry in fs::read_dir(host)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().with_context(|| format!("non UTF-8 file name in {}", host.display()))?;
            let child = if guest == "/" { format!("/{name}") } else { format!("{guest}/{name}") };
            import_at(files, &entry.path(), &child, seen)?;
        }
    } else if ft.is_file() {
        let data = fs::read(host)?;
        files.insert(guest.into(), Node::File { data, mode, mtime_ns });
    }
    // Sockets, FIFOs and device nodes are skipped.
    Ok(())
}

pub(crate) fn entries(files: &BTreeMap<String, Node>) -> Vec<Entry<'_>> {
    files
        .iter()
        .map(|(path, node)| match node {
            &Node::File { ref data, mode, mtime_ns } => Entry { path, kind: EntryKind::File, mode, mtime_ns, data },
            &Node::Dir { mode, mtime_ns } => Entry { path, kind: EntryKind::Dir, mode, mtime_ns, data: &[] },
            Node::Symlink { target, mtime_ns } => {
                Entry { path, kind: EntryKind::Symlink, mode: 0o777, mtime_ns: *mtime_ns, data: target.as_bytes() }
            }
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
