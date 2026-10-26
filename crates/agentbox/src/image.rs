//! Collecting imports and encoding the boot image.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use agentbox_abi::image::{Entry, EntryKind};
use anyhow::{Context, Result, bail};

#[derive(Clone, Debug)]
pub(crate) enum Node {
    File { data: Vec<u8>, mode: u32 },
    Dir { mode: u32 },
    Symlink { target: String },
}

/// Paths the guest kernel provides itself.
const RESERVED: &[&str] = &["/dev", "/proc"];

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
    let guest = guest_path(guest)?;
    import_at(files, host, &guest).with_context(|| format!("importing {}", host.display()))
}

fn import_at(files: &mut BTreeMap<String, Node>, host: &Path, guest: &str) -> Result<()> {
    let meta = fs::symlink_metadata(host).with_context(|| format!("{} does not exist", host.display()))?;
    let mode = meta.permissions().mode() & 0o7777;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(host)?;
        let target = target.to_str().with_context(|| format!("non UTF-8 symlink {}", host.display()))?;
        files.insert(guest.into(), Node::Symlink { target: target.into() });
    } else if ft.is_dir() {
        if guest != "/" {
            files.insert(guest.into(), Node::Dir { mode });
        }
        for entry in fs::read_dir(host)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().with_context(|| format!("non UTF-8 file name in {}", host.display()))?;
            let child = if guest == "/" { format!("/{name}") } else { format!("{guest}/{name}") };
            import_at(files, &entry.path(), &child)?;
        }
    } else if ft.is_file() {
        let data = fs::read(host)?;
        files.insert(guest.into(), Node::File { data, mode });
    }
    // Sockets, FIFOs and device nodes are skipped.
    Ok(())
}

pub(crate) fn entries(files: &BTreeMap<String, Node>) -> Vec<Entry<'_>> {
    files
        .iter()
        .map(|(path, node)| match node {
            Node::File { data, mode } => Entry { path, kind: EntryKind::File, mode: *mode, data },
            Node::Dir { mode } => Entry { path, kind: EntryKind::Dir, mode: *mode, data: &[] },
            Node::Symlink { target } => Entry { path, kind: EntryKind::Symlink, mode: 0o777, data: target.as_bytes() },
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
                    Node::Symlink { target } => target.len() as u64,
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
