//! grix images: a file tree, the settings to run it with, and the grix
//! kernel it goes with, in one file you can copy around. The file is a
//! gzipped tar of `grix-image.json`, `kernel` and `rootfs/...`.
//!
//! `grix build` makes images from a Grixfile ([`crate::build`]): a Docker or
//! OCI image, files, and build steps. `grix run --image` and
//! [`SandboxBuilder::image`](crate::SandboxBuilder::image) run them.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use grix_abi::ABI_VERSION;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::image::{self, Node};
use crate::sandbox::Arch;

/// A grix image.
#[derive(Clone)]
pub struct Image {
    pub config: ImageConfig,
    pub(crate) files: BTreeMap<String, Node>,
    kernel: Vec<u8>,
}

/// How an image runs, unless the runner says otherwise.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
    /// What runs when no command is given.
    #[serde(default)]
    pub command: Vec<String>,
    /// `KEY=VALUE`, in order.
    #[serde(default)]
    pub env: Vec<String>,
    pub cwd: Option<String>,
    /// Capabilities the program needs; running the image grants them.
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub memory_mb: Option<u64>,
    /// Where its files came from: the Docker/OCI image (and its digest).
    pub source: Option<String>,
    /// Who the program runs as: `uid[:gid]`, or names from the image's
    /// /etc/passwd and /etc/group (Docker's `User`). None: grix's default
    /// (1000:1000).
    #[serde(default)]
    pub user: Option<String>,
}

/// The uid and gid `spec` (`user[:group]`, numbers or names) names in
/// `files`' /etc/passwd and /etc/group, as Docker resolves `User`: a user
/// without a group gets its passwd entry's group (0 if it has none).
pub(crate) fn resolve_user(
    spec: &str,
    files: &std::collections::BTreeMap<String, crate::image::Node>,
) -> Result<(u32, u32)> {
    let table = |path: &str| -> Vec<Vec<String>> {
        match files.get(path) {
            Some(crate::image::Node::File { data, .. }) => String::from_utf8_lossy(data)
                .lines()
                .filter(|l| !l.starts_with('#'))
                .map(|l| l.split(':').map(String::from).collect())
                .collect(),
            _ => Vec::new(),
        }
    };
    let (passwd, group) = (table("/etc/passwd"), table("/etc/group"));
    let (user, grp) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let entry = passwd.iter().find(|e| e.len() > 3 && (e[0] == user || e[2] == user));
    let uid = match user.parse::<u32>() {
        Ok(n) => n,
        Err(_) => entry
            .and_then(|e| e[2].parse().ok())
            .with_context(|| format!("user {user:?} isn't in the image's /etc/passwd"))?,
    };
    let gid = match grp {
        Some(g) => match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => group
                .iter()
                .find(|e| e.len() > 2 && e[0] == g)
                .and_then(|e| e[2].parse().ok())
                .with_context(|| format!("group {g:?} isn't in the image's /etc/group"))?,
        },
        None => entry.and_then(|e| e[3].parse().ok()).unwrap_or(0),
    };
    Ok((uid, gid))
}

/// `uid`'s home directory in `files`' /etc/passwd, as Docker sets HOME:
/// `/` if it has no entry there.
pub(crate) fn home_dir(uid: u32, files: &BTreeMap<String, Node>) -> String {
    let Some(Node::File { data, .. }) = files.get("/etc/passwd") else { return "/".into() };
    String::from_utf8_lossy(data)
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|e| e.len() > 5 && e[2].parse() == Ok(uid) && !e[5].is_empty())
        .map_or_else(|| "/".into(), |e| e[5].to_string())
}

#[derive(Serialize, Deserialize)]
struct Header {
    abi: u32,
    created_by: String,
    config: ImageConfig,
}

/// The most an image's kernel may be.
const MAX_KERNEL: u64 = 256 << 20;
/// The most an image's files may hold, and how many: more than can boot.
const MAX_BYTES: u64 = grix_abi::image::LOW_RAM;
const MAX_FILES: usize = 1_000_000;

/// A kernel that speaks this host's ABI (its marker says).
pub(crate) fn check_kernel(kernel: &[u8]) -> Result<()> {
    match grix_abi::kernel_abi(kernel) {
        Some(v) if v == ABI_VERSION => Ok(()),
        Some(v) => bail!("it speaks grix ABI {v}, and this grix speaks {ABI_VERSION}: rebuild it"),
        None => bail!("it isn't a grix kernel (no ABI marker)"),
    }
}

/// Where a command name is looked for: Docker's default PATH.
const PATH: [&str; 6] = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// Check that the programs an image runs first (its command's, and
/// /bin/sh, which build steps and most images' scripts use) are `arch`'s,
/// as its kernel is: the kernel runs nothing else. x86_64 programs pass
/// in an arm64 image, which may run them with a translator
/// (`SandboxBuilder::x86_64`). Programs that aren't there, scripts and
/// ELF files for neither architecture are the kernel's to refuse.
pub(crate) fn check_programs(files: &BTreeMap<String, Node>, command: &[String], arch: Arch) -> Result<()> {
    let mut paths: Vec<String> = Vec::new();
    match command.first() {
        Some(p) if p.starts_with('/') => paths.push(p.clone()),
        Some(name) if !name.contains('/') => paths.extend(
            PATH.iter().map(|d| format!("{d}/{name}")).find(|p| matches!(follow(files, p), Some(Node::File { .. }))),
        ),
        _ => {}
    }
    paths.push("/bin/sh".into());
    for path in paths {
        let Some(Node::File { data, .. }) = follow(files, &path) else { continue };
        let Some(program) = Arch::of_elf(data) else { continue };
        if program != arch && !(arch == Arch::Aarch64 && program == Arch::X86_64) {
            bail!(
                "{path} is an {program} program, and the image's kernel is {arch}'s: an image's programs and \
                 kernel must be for the same architecture (build it for {program}: `grix build --arch {program}`)"
            );
        }
    }
    Ok(())
}

/// The node `path` leads to in `files`, through symbolic links.
fn follow<'a>(files: &'a BTreeMap<String, Node>, path: &str) -> Option<&'a Node> {
    let mut path = path.to_string();
    // As Linux's limit on links followed.
    for _ in 0..40 {
        match files.get(&path)? {
            Node::Symlink { target, .. } => {
                let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
                let joined = if target.starts_with('/') { target.clone() } else { format!("{dir}/{target}") };
                path = normalize(&joined)?;
            }
            node => return Some(node),
        }
    }
    None
}

/// `path` with `.`, `..` and repeated slashes resolved (not links).
fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// Eight random bytes in hex, for names nobody can guess or collide with.
pub(crate) fn random_suffix() -> String {
    let mut b = [0u8; 8];
    if File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        b = (t.as_nanos() as u64 ^ (std::process::id() as u64) << 32).to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Image {
    pub(crate) fn new(files: BTreeMap<String, Node>, config: ImageConfig, kernel: Vec<u8>) -> Image {
        Image { config, files, kernel }
    }

    /// Read an image file.
    pub fn open(path: impl AsRef<Path>) -> Result<Image> {
        let path = path.as_ref();
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        // However it's packed, no more than an image may hold comes out.
        let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f).take(MAX_BYTES + MAX_KERNEL + (64 << 20)));
        let (mut header, mut kernel, mut files) = (None, None, BTreeMap::new());
        let (mut total_bytes, mut total_files) = (0u64, 0usize);
        for entry in ar.entries().with_context(|| format!("{} isn't a grix image", path.display()))? {
            let mut entry = entry?;
            let name = entry.path()?.to_string_lossy().into_owned();
            match name.as_str() {
                "grix-image.json" => {
                    let mut data = Vec::new();
                    (&mut entry).take(1 << 20).read_to_end(&mut data)?;
                    let h: Header = serde_json::from_slice(&data).context("grix-image.json")?;
                    if h.abi != ABI_VERSION {
                        bail!(
                            "{} was built for grix ABI {}, and this grix speaks {ABI_VERSION}: rebuild it",
                            path.display(),
                            h.abi
                        );
                    }
                    header = Some(h);
                }
                "kernel" => {
                    let mut data = Vec::new();
                    (&mut entry).take(MAX_KERNEL + 1).read_to_end(&mut data)?;
                    if data.len() as u64 > MAX_KERNEL {
                        bail!("the image's kernel is too big");
                    }
                    kernel = Some(data);
                }
                _ => {
                    let Some(rel) = name.strip_prefix("rootfs/").map(|r| r.trim_end_matches('/')) else { continue };
                    if rel.is_empty() {
                        continue;
                    }
                    // An image may come from anywhere: plain names only.
                    let path = image::guest_path(&format!("/{rel}")).with_context(|| format!("bad path {name:?}"))?;
                    if let Some(node) = read_node(&mut entry, &mut total_bytes, &mut total_files)? {
                        files.insert(path, node);
                    }
                }
            }
        }
        let header = header.with_context(|| format!("{} has no grix-image.json", path.display()))?;
        let kernel = kernel.with_context(|| format!("{} has no kernel", path.display()))?;
        check_kernel(&kernel).with_context(|| format!("{}'s kernel", path.display()))?;
        Ok(Image { config: header.config, files, kernel })
    }

    /// Write the image to `path` (replacing it all at once).
    pub fn write_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let tmp = path.with_extension(format!("tmp-{}", random_suffix()));
        let result = self.write_file(&tmp).and_then(|()| Ok(fs::rename(&tmp, path)?));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.with_context(|| format!("writing {}", path.display()))
    }

    fn write_file(&self, path: &Path) -> Result<()> {
        let gz = flate2::write::GzEncoder::new(File::create(path)?, flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        let header = Header {
            abi: ABI_VERSION,
            created_by: format!("grix {}", env!("CARGO_PKG_VERSION")),
            config: self.config.clone(),
        };
        let meta = serde_json::to_vec_pretty(&header)?;
        let file = |len: usize, mode: u32, mtime_ns: u64| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(len as u64);
            h.set_mode(mode);
            h.set_mtime(mtime_ns / 1_000_000_000);
            h
        };
        b.append_data(&mut file(meta.len(), 0o644, 0), "grix-image.json", &meta[..])?;
        b.append_data(&mut file(self.kernel.len(), 0o644, 0), "kernel", &self.kernel[..])?;
        append_files(&mut b, "rootfs", &self.files)?;
        b.into_inner()?.finish()?.flush()?;
        Ok(())
    }

    pub(crate) fn kernel_bytes(&self) -> &[u8] {
        &self.kernel
    }

    /// What the image is for: its kernel's architecture (the ELF file's
    /// machine), which its programs share.
    pub fn arch(&self) -> Result<Arch> {
        Arch::of_elf(&self.kernel).context("the image's kernel isn't an arm64 or x86_64 ELF file")
    }

    /// Files, directories and links in the image, and the bytes of their
    /// contents.
    pub fn size(&self) -> (usize, u64) {
        (self.files.len(), image::imported_bytes(&self.files))
    }

    /// The image's kernel as a file (kept in `~/.cache/grix/kernels`, by
    /// its digest), for QEMU to load.
    pub(crate) fn kernel_path(&self) -> Result<PathBuf> {
        let digest: String = Sha256::digest(&self.kernel).iter().map(|b| format!("{b:02x}")).collect();
        let dir = cache_dir()?.join("kernels");
        fs::create_dir_all(&dir)?;
        let path = dir.join(&digest);
        // What's cached is used only if it's still what it should be.
        let good = fs::read(&path)
            .is_ok_and(|k| Sha256::digest(&k).iter().map(|b| format!("{b:02x}")).collect::<String>() == digest);
        if !good {
            let tmp = dir.join(format!("{digest}.tmp-{}", random_suffix()));
            fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?.write_all(&self.kernel)?;
            fs::rename(&tmp, &path)?;
        }
        Ok(path)
    }
}

/// Write `files` to a tar, under `prefix`.
pub(crate) fn append_files<W: Write>(
    b: &mut tar::Builder<W>,
    prefix: &str,
    files: &BTreeMap<String, Node>,
) -> Result<()> {
    for (p, node) in files {
        let name = format!("{prefix}{p}");
        let mut h = tar::Header::new_gnu();
        match node {
            Node::File { data, mode, mtime_ns } => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(data.len() as u64);
                h.set_mode(*mode);
                h.set_mtime(mtime_ns / 1_000_000_000);
                b.append_data(&mut h, &name, &data[..])?
            }
            Node::Dir { mode, mtime_ns } => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                h.set_mode(*mode);
                h.set_mtime(mtime_ns / 1_000_000_000);
                b.append_data(&mut h, &name, &[][..])?;
            }
            Node::Symlink { target, mtime_ns } => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                h.set_mode(0o777);
                h.set_mtime(mtime_ns / 1_000_000_000);
                b.append_link(&mut h, &name, target)?;
            }
        }
    }
    Ok(())
}

/// The node a tar entry (of `append_files`) holds, counting it against the
/// limits on what an image may hold. None: a kind images don't have.
pub(crate) fn read_node<R: Read>(
    entry: &mut tar::Entry<R>,
    total_bytes: &mut u64,
    total_files: &mut usize,
) -> Result<Option<Node>> {
    *total_files += 1;
    if *total_files > MAX_FILES {
        bail!("the image has more than {MAX_FILES} entries");
    }
    let h = entry.header();
    // Not setuid or setgid, as an OCI image's layers: an image may be
    // anyone's, and nothing in the sandbox honours them.
    let mode = h.mode().unwrap_or(0o644) & 0o1777;
    let mtime_ns = h.mtime().unwrap_or(0).saturating_mul(1_000_000_000);
    Ok(Some(match h.entry_type() {
        tar::EntryType::Directory => Node::Dir { mode, mtime_ns },
        tar::EntryType::Symlink => {
            let target = entry.link_name()?.context("link without a target")?;
            Node::Symlink { target: target.to_string_lossy().into_owned(), mtime_ns }
        }
        tar::EntryType::Regular => {
            let size = h.size()?;
            *total_bytes = total_bytes.saturating_add(size);
            if *total_bytes > MAX_BYTES {
                bail!("the image is bigger than grix can run");
            }
            let mut data = Vec::with_capacity(size.min(1 << 20) as usize);
            (&mut *entry).take(size).read_to_end(&mut data)?;
            Node::File { data, mode, mtime_ns }
        }
        _ => return Ok(None),
    }))
}

/// `cache_dir()/name`, made private (0700, the cache directory too): it
/// may hold private images.
pub(crate) fn private_cache(name: &str) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let root = cache_dir()?;
    let dir = root.join(name);
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    for d in [&root, &dir] {
        if fs::metadata(d)?.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(dir)
}

pub(crate) fn cache_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("GRIX_CACHE") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").context("HOME isn't set")?;
    Ok(Path::new(&home).join(".cache/grix"))
}
