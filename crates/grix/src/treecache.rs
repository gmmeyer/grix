//! File trees kept for later builds (`~/.cache/grix/trees`): what an
//! image's layers add up to, by its manifest's digest, so a base isn't
//! downloaded, unpacked and layered again; and what a build step left, by
//! everything that went into it, so an unchanged step doesn't run again.
//!
//! Each tree is one file: the SHA-256 of the rest (in hex, then a newline)
//! and an uncompressed tar of the tree, written privately and renamed into
//! place. A tree is used only if it's all there and matches its hash.
//! Using one marks it recently used; past `GRIX_TREE_CACHE_MB` (10 GiB by
//! default) the least recently used go.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::container::{append_files, random_suffix, read_node};
use crate::image::{self, Node};

const DEFAULT_LIMIT_MB: u64 = 10 << 10;

fn dir() -> Result<PathBuf> {
    crate::container::private_cache("trees")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A key from what goes into it: `kind` and each part, unambiguously.
pub(crate) fn key(kind: &str, parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    hex(&h.finalize())
}

/// What a tree holds, for keys: every path, its kind, mode and contents,
/// but not its times (a file written again with the same bytes is the
/// same file to a build).
fn update_owner(h: &mut Sha256, owner: &crate::image::Owner) {
    h.update([owner.is_some() as u8]);
    let (uid, gid) = owner.unwrap_or((0, 0));
    h.update(uid.to_le_bytes());
    h.update(gid.to_le_bytes());
}

pub(crate) fn tree_hash(files: &BTreeMap<String, Node>) -> String {
    let mut h = Sha256::new();
    for (path, node) in files {
        h.update((path.len() as u64).to_le_bytes());
        h.update(path.as_bytes());
        match node {
            Node::File { data, mode, owner, .. } => {
                h.update(b"f");
                h.update(mode.to_le_bytes());
                update_owner(&mut h, owner);
                h.update((data.len() as u64).to_le_bytes());
                h.update(data);
            }
            Node::Dir { mode, owner, .. } => {
                h.update(b"d");
                h.update(mode.to_le_bytes());
                update_owner(&mut h, owner);
            }
            Node::Symlink { target, owner, .. } => {
                h.update(b"l");
                update_owner(&mut h, owner);
                h.update((target.len() as u64).to_le_bytes());
                h.update(target.as_bytes());
            }
        }
    }
    hex(&h.finalize())
}

/// The tree kept under `key`, if there's a good one.
pub(crate) fn get(key: &str) -> Option<BTreeMap<String, Node>> {
    let path = dir().ok()?.join(format!("{key}.tar"));
    let file = File::open(&path).ok()?;
    match read(file) {
        Ok(files) => {
            let _ = File::options().write(true).open(&path).and_then(|f| f.set_modified(SystemTime::now()));
            Some(files)
        }
        Err(_) => {
            // Cut off or corrupted: it's made again.
            let _ = fs::remove_file(&path);
            None
        }
    }
}

fn read(file: File) -> Result<BTreeMap<String, Node>> {
    let mut r = BufReader::new(file);
    let mut want = [0u8; 65];
    r.read_exact(&mut want)?;
    let want = std::str::from_utf8(&want[..64])?.to_string();
    let mut hashing = Hashing { inner: r, hasher: Sha256::new() };
    let mut files = BTreeMap::new();
    {
        let mut ar = tar::Archive::new(&mut hashing);
        let (mut bytes, mut count) = (0u64, 0usize);
        for entry in ar.entries()? {
            let mut entry = entry?;
            let name = entry.path()?.to_string_lossy().into_owned();
            let rel = name.strip_prefix("tree/").context("not a cached tree")?.trim_end_matches('/');
            let path = image::guest_path(&format!("/{rel}"))?;
            if let Some(node) = read_node(&mut entry, &mut bytes, &mut count)? {
                files.insert(path, node);
            }
        }
    }
    std::io::copy(&mut hashing, &mut std::io::sink())?;
    if hex(&hashing.hasher.finalize()) != want {
        bail!("the cached tree doesn't match its hash");
    }
    Ok(files)
}

struct Hashing<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Keep `files` under `key`. Failing to is only a missed chance to save
/// time later, so callers may ignore the error.
pub(crate) fn put(key: &str, files: &BTreeMap<String, Node>) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    let dir = dir()?;
    let tmp = dir.join(format!("{key}.tmp-{}", random_suffix()));
    let result = (|| -> Result<()> {
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?
        };
        // The hash goes first, once the tar after it is written.
        file.write_all(&[b'\n'; 65])?;
        let mut out = HashingWriter { inner: BufWriter::new(file), hasher: Sha256::new() };
        let mut tar = tar::Builder::new(&mut out);
        append_files(&mut tar, "tree", files)?;
        tar.finish()?;
        drop(tar);
        let hash = hex(&out.hasher.finalize());
        let mut file = out.inner.into_inner().context("writing a cached tree")?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{hash}")?;
        file.sync_all()?;
        fs::rename(&tmp, dir.join(format!("{key}.tar")))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    prune(&dir);
    Ok(())
}

/// Remove the least recently used trees past the limit, and what writers
/// that didn't finish left (an hour on).
fn prune(dir: &std::path::Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        let stale = |e: &fs::DirEntry| {
            e.file_name().to_string_lossy().contains(".tmp-")
                && e.metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| t.elapsed().is_ok_and(|age| age.as_secs() > 3600))
        };
        for e in entries.filter_map(|e| e.ok()).filter(stale) {
            let _ = fs::remove_file(e.path());
        }
    }
    let limit =
        std::env::var("GRIX_TREE_CACHE_MB").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(DEFAULT_LIMIT_MB) << 20;
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut trees: Vec<(SystemTime, u64, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "tar"))
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            Some((m.modified().ok()?, m.len(), e.path()))
        })
        .collect();
    let mut total: u64 = trees.iter().map(|t| t.1).sum();
    trees.sort();
    for (_, len, path) in trees {
        if total <= limit {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            total -= len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trees_round_trip_and_bad_ones_go() {
        let mut files = BTreeMap::new();
        files.insert("/etc".to_string(), Node::Dir { mode: 0o755, mtime_ns: 1_000_000_000, owner: None });
        files.insert(
            "/etc/a".to_string(),
            Node::File { data: b"hello".to_vec(), mode: 0o600, mtime_ns: 0, owner: None },
        );
        files.insert("/l".to_string(), Node::Symlink { target: "etc/a".into(), mtime_ns: 0, owner: Some((5, 6)) });
        let key = key("test", &[random_suffix().as_bytes()]);
        put(&key, &files).unwrap();
        let back = get(&key).unwrap();
        assert_eq!(tree_hash(&back), tree_hash(&files));
        assert!(matches!(back.get("/etc/a"), Some(Node::File { data, mode: 0o600, .. }) if data == b"hello"));
        // Times don't count; contents and modes do.
        let mut later = files.clone();
        later.insert("/etc/a".into(), Node::File { data: b"hello".to_vec(), mode: 0o600, mtime_ns: 5, owner: None });
        assert_eq!(tree_hash(&later), tree_hash(&files));
        later.insert("/etc/a".into(), Node::File { data: b"hello".to_vec(), mode: 0o644, mtime_ns: 5, owner: None });
        assert_ne!(tree_hash(&later), tree_hash(&files));
        // A corrupted tree isn't used, and goes.
        let path = dir().unwrap().join(format!("{key}.tar"));
        let mut data = fs::read(&path).unwrap();
        let n = data.len();
        data[n - 600] ^= 1;
        fs::write(&path, &data).unwrap();
        assert!(get(&key).is_none());
        assert!(!path.exists());
    }
}
