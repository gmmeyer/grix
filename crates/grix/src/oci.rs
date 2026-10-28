//! Docker and OCI images as the files of a grix image. They can be pulled
//! from a registry (Docker Hub, GHCR, ...), read from an OCI image layout
//! directory, or read from a `docker save` archive.
//!
//! The image for linux/arm64 is picked and its layers (tar, gzip or zstd)
//! are applied in order, whiteouts included. Its config gives the command,
//! environment and working directory. Every blob is checked against its
//! digest, and blobs from a registry are cached by digest
//! (`~/.cache/grix/oci`), and so is what an image's layers add up to
//! (`treecache`). Registries that want a login get one from `auth`.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::auth::{Credential, Store};
use crate::image::{self, Node};
use crate::treecache;

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// The most a manifest, index or config may be.
const MAX_JSON: u64 = 4 << 20;
/// The most an image's files may hold in all, and how many there may be,
/// unpacked: more than any sandbox can boot (`image::MAX_RAM`), and a
/// bound on what a malicious layer can make the host allocate.
const MAX_BYTES: u64 = grix_abi::image::MAX_RAM;
const MAX_FILES: usize = 1_000_000;

/// What an image's layers have added up to so far.
#[derive(Default)]
pub(crate) struct Totals {
    bytes: u64,
    files: usize,
}

/// What a Docker/OCI image says to run, and how.
#[derive(Clone, Debug, Default)]
pub(crate) struct OciConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    /// `KEY=VALUE`.
    pub env: Vec<String>,
    pub cwd: Option<String>,
    /// Who it runs as (`uid[:gid]` or names); empty: root.
    pub user: String,
}

/// An image's files and config.
pub(crate) struct Pulled {
    pub files: BTreeMap<String, Node>,
    pub config: OciConfig,
    /// The manifest's digest.
    pub digest: String,
}

/// Where an image comes from: `oci:DIR` (an OCI image layout),
/// `docker-archive:FILE` (`docker save` output), `docker:NAME` (an image
/// in the local Docker daemon, through `docker save`), or a registry
/// reference such as `alpine:3.21`, `python:3.12-alpine` or
/// `ghcr.io/owner/repo@sha256:...`. Relative paths are taken from `base`.
/// With `credentials`, a registry that asks for a login gets the user's.
pub(crate) fn load(source: &str, base: &Path, credentials: bool) -> Result<Pulled> {
    load_with(source, base, if credentials { Store::user() } else { Store::none() })
}

fn load_with(source: &str, base: &Path, store: Store) -> Result<Pulled> {
    let resolve = |p: &str| if Path::new(p).is_absolute() { PathBuf::from(p) } else { base.join(p) };
    if let Some(dir) = source.strip_prefix("oci:") {
        return Layout::open(&resolve(dir))?.load();
    }
    if let Some(file) = source.strip_prefix("docker-archive:") {
        return load_archive(&resolve(file));
    }
    if let Some(name) = source.strip_prefix("docker:") {
        let tmp = tempdir("docker-save")?;
        let tar = tmp.path.join("image.tar");
        let status = std::process::Command::new("docker")
            .args(["save", "--platform", "linux/arm64", "-o"])
            .arg(&tar)
            .arg(name)
            .status()
            .context("running docker save")?;
        if !status.success() {
            bail!("docker save {name} failed");
        }
        return load_archive(&tar);
    }
    let reference = Reference::parse(source)?;
    let mut registry = Registry::new(&reference, store)?;
    let manifest_digest = registry.resolve(&reference.tag_or_digest)?;
    let layout = Layout::cache()?;
    let (manifest, digest) = registry.manifest(&manifest_digest, &layout)?;
    layout.load_manifest(&manifest, digest, &mut |d, size| registry.fetch_blob(d, size, &layout))
}

/// Pull `reference` (a registry reference such as `alpine:3.21`; its
/// linux/arm64 image) into an OCI image layout at `dir`, for offline use.
/// Returns the manifest's digest.
pub fn pull_to_layout(source: &str, dir: &Path) -> Result<String> {
    let reference = Reference::parse(source)?;
    let mut registry = Registry::new(&reference, Store::user())?;
    let digest = registry.resolve(&reference.tag_or_digest)?;
    let cache = Layout::cache()?;
    let (manifest, digest) = registry.manifest(&digest, &cache)?;
    let out = Layout { dir: dir.to_path_buf() };
    fs::create_dir_all(dir.join("blobs/sha256"))?;
    fs::write(dir.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#)?;
    let mut copy = |d: &str, size: Option<u64>| -> Result<()> {
        registry.fetch_blob(d, size, &cache)?;
        fs::copy(cache.blob_path(d)?, out.blob_path(d)?)?;
        Ok(())
    };
    copy(&digest, None)?;
    let m: Value = serde_json::from_slice(&fs::read(out.blob_path(&digest)?)?)?;
    let config = m["config"]["digest"].as_str().context("manifest without a config")?;
    copy(config, m["config"]["size"].as_u64())?;
    for l in m["layers"].as_array().context("manifest without layers")? {
        copy(l["digest"].as_str().context("layer without a digest")?, l["size"].as_u64())?;
    }
    let size = fs::metadata(out.blob_path(&digest)?)?.len();
    let index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": manifest_type(&manifest),
            "digest": digest,
            "size": size,
            "platform": {"architecture": "arm64", "os": "linux"},
            "annotations": {"org.opencontainers.image.ref.name": source},
        }],
    });
    fs::write(dir.join("index.json"), serde_json::to_vec_pretty(&index)?)?;
    Ok(digest)
}

fn manifest_type(m: &Value) -> &str {
    m["mediaType"].as_str().unwrap_or(OCI_MANIFEST)
}

// ---------------------------------------------------------------- references

struct Reference {
    /// As used in URLs: `registry-1.docker.io`.
    host: String,
    /// `library/alpine`.
    repo: String,
    /// `3.21` or `sha256:...`.
    tag_or_digest: String,
}

impl Reference {
    fn parse(s: &str) -> Result<Reference> {
        let (name, tag) = match s.split_once('@') {
            Some((n, d)) => (n, d.to_string()),
            None => match s.rsplit_once(':') {
                // A colon after the last slash is a tag, not a port.
                Some((n, t)) if !t.contains('/') => (n, t.to_string()),
                _ => (s, "latest".to_string()),
            },
        };
        let (host, repo) = match name.split_once('/') {
            Some((h, r)) if h.contains('.') || h.contains(':') || h == "localhost" => (h.to_string(), r.to_string()),
            _ => ("docker.io".to_string(), name.to_string()),
        };
        let (host, repo) = if host == "docker.io" {
            let repo = if repo.contains('/') { repo } else { format!("library/{repo}") };
            ("registry-1.docker.io".to_string(), repo)
        } else {
            (host, repo)
        };
        let ok = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-/".contains(c);
        if repo.is_empty() || !repo.chars().all(ok) {
            bail!("{s:?} isn't an image reference");
        }
        if tag.is_empty() || tag.contains('/') {
            bail!("{s:?} has a bad tag");
        }
        Ok(Reference { host, repo, tag_or_digest: tag })
    }
}

fn check_digest(d: &str) -> Result<&str> {
    let hex = d.strip_prefix("sha256:").with_context(|| format!("unsupported digest {d:?}"))?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("bad digest {d:?}");
    }
    Ok(hex)
}

// ---------------------------------------------------------------- layouts

/// An OCI image layout: `index.json` and `blobs/sha256/...` (also the
/// shape of the blob cache).
struct Layout {
    dir: PathBuf,
}

impl Layout {
    fn open(dir: &Path) -> Result<Layout> {
        if !dir.join("index.json").is_file() {
            bail!("{} isn't an OCI image layout (no index.json)", dir.display());
        }
        Ok(Layout { dir: dir.to_path_buf() })
    }

    fn cache() -> Result<Layout> {
        let dir = crate::container::cache_dir()?.join("oci");
        fs::create_dir_all(dir.join("blobs/sha256"))?;
        Ok(Layout { dir })
    }

    fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        Ok(self.dir.join("blobs/sha256").join(check_digest(digest)?))
    }

    /// A blob's bytes, checked against its digest.
    fn json(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(digest)?;
        let data = read_limited(File::open(&path).with_context(|| format!("blob {digest} is missing"))?, MAX_JSON)?;
        if sha256(&data) != check_digest(digest)? {
            bail!("blob {digest} doesn't match its digest");
        }
        Ok(data)
    }

    /// The image for linux/arm64 in this layout.
    fn load(&self) -> Result<Pulled> {
        let index: Value = serde_json::from_slice(&read_limited(File::open(self.dir.join("index.json"))?, MAX_JSON)?)?;
        let mut digest = pick_platform(&index)?;
        let mut manifest: Value = serde_json::from_slice(&self.json(&digest)?)?;
        // An index may point at another index.
        if manifest.get("manifests").is_some() {
            digest = pick_platform(&manifest)?;
            manifest = serde_json::from_slice(&self.json(&digest)?)?;
        }
        self.load_manifest(&manifest, digest, &mut |d, _| {
            self.blob_path(d)?;
            Ok(())
        })
    }

    /// Apply `manifest`'s layers; `fetch` makes sure a blob is in the
    /// layout first.
    fn load_manifest(
        &self,
        manifest: &Value,
        digest: String,
        fetch: &mut dyn FnMut(&str, Option<u64>) -> Result<()>,
    ) -> Result<Pulled> {
        let config_digest = manifest["config"]["digest"].as_str().context("manifest without a config")?;
        fetch(config_digest, manifest["config"]["size"].as_u64())?;
        let config = parse_config(&self.json(config_digest)?)?;
        // The layers, applied before: nothing to fetch or unpack.
        let key = treecache::key("applied-layers-v1", &[digest.as_bytes()]);
        if let Some(files) = treecache::get(&key) {
            return Ok(Pulled { files, config, digest });
        }
        let (mut files, mut totals) = (BTreeMap::new(), Totals::default());
        for layer in manifest["layers"].as_array().context("manifest without layers")? {
            let d = layer["digest"].as_str().context("layer without a digest")?;
            fetch(d, layer["size"].as_u64())?;
            // Checked as it's read: what's applied is what was checked.
            let mut blob = Hashing::new(File::open(self.blob_path(d)?)?);
            apply_layer(&mut files, &mut blob, &mut totals).with_context(|| format!("applying layer {d}"))?;
            if blob.finish()? != check_digest(d)? {
                bail!("layer {d} doesn't match its digest");
            }
        }
        // Only a chance to save time later.
        let _ = treecache::put(&key, &files);
        Ok(Pulled { files, config, digest })
    }
}

/// The linux/arm64 manifest in an index.
fn pick_platform(index: &Value) -> Result<String> {
    let manifests = index["manifests"].as_array().context("index without manifests")?;
    let arm64 = |m: &&Value| {
        let p = &m["platform"];
        // Without a platform, an index of one is taken as it is.
        (p.is_null() && manifests.len() == 1)
            || (p["architecture"] == "arm64" && p["os"] == "linux" && p["variant"].as_str().is_none_or(|v| v == "v8"))
    };
    match manifests.iter().find(arm64) {
        Some(m) => Ok(m["digest"].as_str().context("manifest without a digest")?.to_string()),
        None => {
            let have: Vec<String> = manifests
                .iter()
                .map(|m| {
                    format!(
                        "{}/{}",
                        m["platform"]["os"].as_str().unwrap_or("?"),
                        m["platform"]["architecture"].as_str().unwrap_or("?")
                    )
                })
                .collect();
            bail!("no linux/arm64 image (there's {})", have.join(", "))
        }
    }
}

fn parse_config(data: &[u8]) -> Result<OciConfig> {
    let v: Value = serde_json::from_slice(data).context("image config")?;
    if let Some(arch) = v["architecture"].as_str()
        && arch != "arm64"
    {
        bail!("the image is for {arch}; grix runs arm64 programs");
    }
    let c = &v["config"];
    let strings = |v: &Value| -> Vec<String> {
        v.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default()
    };
    Ok(OciConfig {
        entrypoint: strings(&c["Entrypoint"]),
        cmd: strings(&c["Cmd"]),
        env: strings(&c["Env"]),
        cwd: c["WorkingDir"].as_str().filter(|s| !s.is_empty()).map(String::from),
        user: c["User"].as_str().unwrap_or("").to_string(),
    })
}

// ---------------------------------------------------------------- docker save

fn load_archive(tar_path: &Path) -> Result<Pulled> {
    let tmp = tempdir("archive")?;
    let mut ar = tar::Archive::new(File::open(tar_path).with_context(|| format!("opening {}", tar_path.display()))?);
    // Plain names only: it's extracted to read it, not trusted.
    for entry in ar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
            continue;
        }
        if entry.header().entry_type().is_file() {
            let dest = tmp.path.join(&path);
            fs::create_dir_all(dest.parent().unwrap())?;
            std::io::copy(&mut entry, &mut File::create(&dest)?)?;
        }
    }
    // Newer Docker saves an OCI layout.
    if tmp.path.join("index.json").is_file() {
        return Layout::open(&tmp.path)?.load();
    }
    // The classic format: manifest.json names a config file and layer tars.
    let manifest: Value =
        serde_json::from_slice(&fs::read(tmp.path.join("manifest.json")).context("no manifest.json")?)?;
    let m = manifest.as_array().and_then(|a| a.first()).context("empty manifest.json")?;
    let plain = |v: &Value| -> Result<PathBuf> {
        let p = Path::new(v.as_str().context("bad manifest.json")?);
        if p.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
            bail!("bad path in manifest.json");
        }
        Ok(tmp.path.join(p))
    };
    let config_bytes = read_limited(File::open(plain(&m["Config"])?)?, MAX_JSON)?;
    let config = parse_config(&config_bytes)?;
    // The config lists each layer's digest, uncompressed: check them.
    let diff_ids: Vec<String> = serde_json::from_slice::<Value>(&config_bytes)?["rootfs"]["diff_ids"]
        .as_array()
        .map(|a| a.iter().filter_map(|d| d.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let (mut files, mut totals) = (BTreeMap::new(), Totals::default());
    for (i, layer) in m["Layers"].as_array().context("manifest.json without layers")?.iter().enumerate() {
        let mut blob = Hashing::new(File::open(plain(layer)?)?);
        let compressed = apply_layer(&mut files, &mut blob, &mut totals)?;
        let hash = blob.finish()?;
        if let Some(d) = diff_ids.get(i)
            && !compressed
            && hash != check_digest(d)?
        {
            bail!("layer {} doesn't match its digest", i + 1);
        }
    }
    Ok(Pulled { files, config, digest: String::new() })
}

// ---------------------------------------------------------------- layers

/// Apply one layer (a tar: plain, gzipped or zstd-compressed) to `files`:
/// OCI whiteouts (`.wh.NAME`, `.wh..wh..opq`) remove what lower layers
/// had. Returns whether it was compressed.
pub(crate) fn apply_layer(
    files: &mut BTreeMap<String, Node>,
    data: &mut dyn Read,
    totals: &mut Totals,
) -> Result<bool> {
    let mut r = BufReader::new(data);
    let head = r.fill_buf()?;
    let (gzipped, zstd) = (head.starts_with(&[0x1f, 0x8b]), head.starts_with(&ZSTD_MAGIC));
    let reader: Box<dyn Read> = if gzipped {
        Box::new(flate2::read::MultiGzDecoder::new(r))
    } else if zstd {
        Box::new(Zstd { source: r, decoder: ruzstd::decoding::FrameDecoder::new(), in_frame: false })
    } else {
        Box::new(r)
    };
    // However it's packed, no more than an image may hold comes out.
    let mut ar = tar::Archive::new(reader.take(MAX_BYTES + (64 << 20)));
    // What this layer added: an opaque marker hides only lower layers.
    let mut added = std::collections::HashSet::new();
    for entry in ar.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.to_string_lossy().into_owned();
        let rel = raw.trim_start_matches("./").trim_end_matches('/');
        if rel.is_empty() || rel == "." {
            continue;
        }
        let Ok(path) = image::guest_path(&format!("/{rel}")) else {
            // /dev, /proc and /sys are the kernel's; `..` is refused.
            if rel.split('/').any(|c| c == "..") {
                bail!("layer entry {raw:?} leaves the image");
            }
            continue;
        };
        let (dir, name) = path.rsplit_once('/').unwrap();
        let dir = if dir.is_empty() { "/" } else { dir };
        if name == ".wh..wh..opq" {
            let prefix = if dir == "/" { "/".to_string() } else { format!("{dir}/") };
            let lower: Vec<String> = files
                .range(prefix.clone()..)
                .take_while(|(k, _)| k.starts_with(&prefix))
                .map(|(k, _)| k.clone())
                .collect();
            for k in lower.into_iter().filter(|k| !added.contains(k)) {
                files.remove(&k);
            }
            continue;
        }
        if let Some(gone) = name.strip_prefix(".wh.") {
            let target = if dir == "/" { format!("/{gone}") } else { format!("{dir}/{gone}") };
            remove_tree(files, &target);
            continue;
        }
        let header = entry.header();
        let mode = header.mode().unwrap_or(0o644) & 0o7777;
        let mtime_ns = header.mtime().unwrap_or(0).saturating_mul(1_000_000_000);
        let node = match header.entry_type() {
            tar::EntryType::Directory => Node::Dir { mode, mtime_ns },
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let size = header.size()?;
                if totals.bytes.saturating_add(size) > MAX_BYTES {
                    bail!("the image is bigger than grix can run ({} GiB)", MAX_BYTES >> 30);
                }
                totals.bytes += size;
                let mut data = Vec::with_capacity(size.min(1 << 20) as usize);
                (&mut entry).take(size).read_to_end(&mut data)?;
                Node::File { data, mode, mtime_ns }
            }
            tar::EntryType::Symlink => {
                let target = entry.link_name()?.context("symlink without a target")?.to_string_lossy().into_owned();
                Node::Symlink { target, mtime_ns }
            }
            // A hard link: a copy of what it links to (grix's imports have
            // no hard links).
            tar::EntryType::Link => {
                let target = entry.link_name()?.context("link without a target")?.to_string_lossy().into_owned();
                let target = format!("/{}", target.trim_start_matches("./").trim_start_matches('/'));
                match files.get(&target) {
                    Some(n @ Node::File { .. }) => n.clone(),
                    _ => continue,
                }
            }
            // Devices, FIFOs: the guest has its own /dev.
            _ => continue,
        };
        // Whatever was there goes, unless a directory stays a directory.
        match (files.get(&path), &node) {
            (Some(Node::Dir { .. }), Node::Dir { .. }) => {}
            (Some(_), _) => remove_tree(files, &path),
            _ => {}
        }
        totals.files += 1;
        if totals.files > MAX_FILES {
            bail!("the image has more than {MAX_FILES} entries");
        }
        added.insert(path.clone());
        files.insert(path, node);
    }
    Ok(gzipped || zstd)
}

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// zstd, frame after frame (as parallel compressors write it), skipping
/// skippable frames. A frame's window is capped at ruzstd's default (128
/// MiB, zstd's own default limit), so a layer can't make it allocate more.
struct Zstd<R: BufRead> {
    source: R,
    decoder: ruzstd::decoding::FrameDecoder,
    in_frame: bool,
}

impl<R: BufRead> Read for Zstd<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use ruzstd::decoding::BlockDecodingStrategy;
        use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.in_frame {
                if self.source.fill_buf()?.is_empty() {
                    return Ok(0);
                }
                match self.decoder.init(&mut self.source) {
                    Ok(()) => self.in_frame = true,
                    Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                        length, ..
                    })) => {
                        let want = u64::from(length);
                        let skipped = std::io::copy(&mut (&mut self.source).take(want), &mut std::io::sink())?;
                        if skipped < want {
                            return Err(std::io::ErrorKind::UnexpectedEof.into());
                        }
                        continue;
                    }
                    Err(e) => return Err(std::io::Error::other(e)),
                }
            }
            let d = &mut self.decoder;
            while d.can_collect() == 0 && !d.is_finished() {
                d.decode_blocks(&mut self.source, BlockDecodingStrategy::UptoBlocks(1))
                    .map_err(std::io::Error::other)?;
            }
            let n = d.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            // That frame is done; another may follow.
            self.in_frame = false;
        }
    }
}

/// A reader that hashes what goes through it.
struct Hashing<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Hashing<R> {
    fn new(inner: R) -> Self {
        Hashing { inner, hasher: Sha256::new() }
    }

    /// Read the rest (what a tar reader leaves after its end), and the hash.
    fn finish(mut self) -> Result<String> {
        std::io::copy(&mut self, &mut std::io::sink())?;
        Ok(hex(&self.hasher.finalize()))
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

fn remove_tree(files: &mut BTreeMap<String, Node>, path: &str) {
    files.remove(path);
    let prefix = format!("{path}/");
    let under: Vec<String> =
        files.range(prefix.clone()..).take_while(|(k, _)| k.starts_with(&prefix)).map(|(k, _)| k.clone()).collect();
    for k in under {
        files.remove(&k);
    }
}

// ---------------------------------------------------------------- registries

struct Registry {
    agent: ureq::Agent,
    host: String,
    repo: String,
    /// `https`, or `http` for a registry on this machine that doesn't
    /// speak TLS (as Docker allows for one).
    scheme: &'static str,
    /// What goes in Authorization: a token, or a login (Basic).
    auth: Option<String>,
    store: Store,
    /// The login for this registry, once looked up.
    credential: Option<Option<Credential>>,
}

/// Is `host` (`name[:port]`, `[v6]:port`) this machine?
fn loopback(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.split(':').next().unwrap_or(""),
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
}

impl Registry {
    fn new(r: &Reference, store: Store) -> Result<Registry> {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(120))
            .build();
        Ok(Registry {
            agent,
            host: r.host.clone(),
            repo: r.repo.clone(),
            scheme: "https",
            auth: None,
            store,
            credential: None,
        })
    }

    /// May this registry send us to `url` (a redirect, a token service)?
    /// Over TLS only: what comes back is checked by digest, but a
    /// plain-HTTP hop could still be steered at local services (and would
    /// carry a login in the clear). A registry on this machine without
    /// TLS may send us elsewhere on it.
    fn may_reach(&self, url: &str) -> bool {
        url.starts_with("https://")
            || (self.scheme == "http"
                && url.strip_prefix("http://").is_some_and(|rest| loopback(rest.split('/').next().unwrap_or(""))))
    }

    /// The user's login for this registry, looked up once.
    fn credential(&mut self) -> Result<Option<Credential>> {
        if self.credential.is_none() {
            self.credential = Some(self.store.lookup(&self.host)?);
        }
        Ok(self.credential.clone().flatten())
    }

    /// The registry as `grix login` takes it.
    fn login_name(&self) -> &str {
        if self.host == "registry-1.docker.io" { "docker.io" } else { &self.host }
    }

    /// GET `/v2/<repo>/<path>`, logging in if the registry asks, and
    /// following redirects (without the token or login: they go to storage
    /// elsewhere).
    fn get(&mut self, path: &str, accept: &str) -> Result<ureq::Response> {
        let (mut authenticated, mut tried_http) = (false, false);
        loop {
            let url = format!("{}://{}/v2/{}/{path}", self.scheme, self.host, self.repo);
            let mut req = self.agent.get(&url).set("Accept", accept);
            if let Some(a) = &self.auth {
                req = req.set("Authorization", a);
            }
            let resp = match req.call() {
                Ok(r) => r,
                Err(ureq::Error::Status(401, r)) if !authenticated => {
                    authenticated = true;
                    let challenge = r.header("www-authenticate").context("401 without a challenge")?.to_string();
                    self.auth = Some(self.authenticate(&challenge)?);
                    continue;
                }
                Err(ureq::Error::Status(401, _)) => {
                    let name = self.login_name().to_string();
                    if self.credential()?.is_some() {
                        bail!("{url}: not authorized, with the login for {name}");
                    }
                    bail!("{url}: not authorized (if the image is private, log in first: `grix login {name}`)");
                }
                Err(ureq::Error::Status(code, _)) => bail!("{url}: HTTP {code}"),
                Err(ureq::Error::Transport(_)) if self.scheme == "https" && loopback(&self.host) && !tried_http => {
                    tried_http = true;
                    self.scheme = "http";
                    continue;
                }
                Err(e) => return Err(anyhow::Error::new(e).context(url)),
            };
            let mut resp = resp;
            for _ in 0..5 {
                if !(300..400).contains(&resp.status()) {
                    return Ok(resp);
                }
                let to = resp.header("location").context("redirect without a location")?.to_string();
                let to = if to.starts_with('/') { format!("{}://{}{to}", self.scheme, self.host) } else { to };
                if !self.may_reach(&to) {
                    bail!("{url}: redirected to {to}, which isn't https");
                }
                resp = match self.agent.get(&to).call() {
                    Ok(r) => r,
                    Err(ureq::Error::Status(code, _)) => bail!("{to}: HTTP {code}"),
                    Err(e) => return Err(e.into()),
                };
            }
            bail!("{url}: too many redirects");
        }
    }

    /// What to send as Authorization, as the registry's challenge asks: a
    /// token from its token service (anonymous, or with the user's login),
    /// or the login itself.
    fn authenticate(&mut self, challenge: &str) -> Result<String> {
        let credential = self.credential()?;
        let (scheme, params) = challenge.trim().split_once(' ').unwrap_or((challenge.trim(), ""));
        if scheme.eq_ignore_ascii_case("basic") {
            return match credential.as_ref().and_then(Credential::basic_header) {
                Some(h) => Ok(h),
                None => bail!("{} wants a login: `grix login {}`", self.host, self.login_name()),
            };
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            bail!("unsupported registry authentication {scheme:?}");
        }
        let mut fields = BTreeMap::new();
        for part in params.split(',') {
            if let Some((k, v)) = part.trim().split_once('=') {
                fields.insert(k.to_string(), v.trim_matches('"').to_string());
            }
        }
        let realm = fields.get("realm").context("challenge without a realm")?.clone();
        if !self.may_reach(&realm) {
            bail!("the registry's token service {realm} isn't https");
        }
        let scope = fields.get("scope").cloned().unwrap_or_else(|| format!("repository:{}:pull", self.repo));
        let service = fields.get("service").cloned();
        let answer = match &credential {
            // OAuth2, as Docker does with an identity token.
            Some(Credential::IdentityToken(token)) => {
                let mut form = vec![
                    ("grant_type", "refresh_token"),
                    ("refresh_token", token.as_str()),
                    ("client_id", "grix"),
                    ("scope", scope.as_str()),
                ];
                if let Some(s) = &service {
                    form.push(("service", s.as_str()));
                }
                self.agent.post(&realm).send_form(&form)
            }
            _ => {
                let mut req = self.agent.get(&realm).query("scope", &scope);
                if let Some(s) = &service {
                    req = req.query("service", s);
                }
                if let Some(h) = credential.as_ref().and_then(Credential::basic_header) {
                    req = req.set("Authorization", &h);
                }
                req.call()
            }
        };
        let resp = match answer {
            Ok(r) => r,
            Err(ureq::Error::Status(code, _)) if credential.is_some() => {
                bail!("{realm}: HTTP {code} for the login for {}", self.login_name())
            }
            Err(ureq::Error::Status(code, _)) => bail!("{realm}: HTTP {code}"),
            Err(e) => return Err(anyhow::Error::new(e).context(realm)),
        };
        let body: Value = serde_json::from_slice(&read_limited(resp.into_reader(), MAX_JSON)?)?;
        let token = body["token"].as_str().or(body["access_token"].as_str()).context("no token in the answer")?;
        Ok(format!("Bearer {token}"))
    }

    /// The digest of the linux/arm64 manifest that `tag` names.
    fn resolve(&mut self, tag: &str) -> Result<String> {
        let accept = [OCI_INDEX, DOCKER_LIST, OCI_MANIFEST, DOCKER_MANIFEST].join(", ");
        let resp = self.get(&format!("manifests/{tag}"), &accept)?;
        let body = read_limited(resp.into_reader(), MAX_JSON)?;
        if tag.starts_with("sha256:") && sha256(&body) != check_digest(tag)? {
            bail!("manifest {tag} doesn't match its digest");
        }
        let v: Value = serde_json::from_slice(&body)?;
        if v.get("manifests").is_some() { pick_platform(&v) } else { Ok(format!("sha256:{}", sha256(&body))) }
    }

    /// Manifest `digest`, kept in `cache`.
    fn manifest(&mut self, digest: &str, cache: &Layout) -> Result<(Value, String)> {
        self.fetch_blob_as(digest, None, cache, &format!("manifests/{digest}"))?;
        let v: Value = serde_json::from_slice(&cache.json(digest)?)?;
        if v.get("manifests").is_some() {
            bail!("{digest} is an index, not an image");
        }
        Ok((v, digest.to_string()))
    }

    fn fetch_blob(&mut self, digest: &str, size: Option<u64>, cache: &Layout) -> Result<()> {
        self.fetch_blob_as(digest, size, cache, &format!("blobs/{digest}"))
    }

    /// Download a blob into the cache unless it's there, checking its size
    /// and digest on the way.
    fn fetch_blob_as(&mut self, digest: &str, size: Option<u64>, cache: &Layout, path: &str) -> Result<()> {
        let dest = cache.blob_path(digest)?;
        if dest.is_file() {
            // A bad blob in the cache (cut off, corrupted) is fetched again.
            if verify_file(&dest, digest).is_ok() {
                return Ok(());
            }
            let _ = fs::remove_file(&dest);
        }
        let accept = [OCI_MANIFEST, DOCKER_MANIFEST, "*/*"].join(", ");
        let resp = self.get(path, &accept)?;
        let tmp = dest.with_extension(format!("part-{}", crate::container::random_suffix()));
        let mut out = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let mut hasher = Sha256::new();
        // Without a size from a manifest, it's a manifest itself.
        let limit = size.unwrap_or(MAX_JSON).min(MAX_BYTES);
        let mut reader = resp.into_reader().take(limit.saturating_add(1));
        let mut buf = vec![0u8; 1 << 16];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            total += n as u64;
        }
        drop(out);
        let ok = hex(&hasher.finalize()) == check_digest(digest)? && size.is_none_or(|s| s == total) && total <= limit;
        if !ok {
            let _ = fs::remove_file(&tmp);
            bail!("blob {digest} from {} doesn't match its digest", self.host);
        }
        fs::rename(&tmp, &dest)?;
        Ok(())
    }
}

// ---------------------------------------------------------------- helpers

fn read_limited(r: impl Read, max: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    r.take(max + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        bail!("more than {max} bytes");
    }
    Ok(data)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn verify_file(path: &Path, digest: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut File::open(path)?, &mut hasher)?;
    if hex(&hasher.finalize()) != check_digest(digest)? {
        bail!("blob {digest} doesn't match its digest");
    }
    Ok(())
}

/// A directory removed when dropped.
struct TempDir {
    path: PathBuf,
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A new private directory: a random name, made here (never one that
/// someone else made first), mode 0700.
fn tempdir(what: &str) -> Result<TempDir> {
    use std::os::unix::fs::DirBuilderExt;
    let path = std::env::temp_dir().join(format!("grix-{what}-{}", crate::container::random_suffix()));
    fs::DirBuilder::new().mode(0o700).create(&path).with_context(|| format!("creating {}", path.display()))?;
    Ok(TempDir { path })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::random_suffix;

    fn layer(entries: &[(&str, Option<&str>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut h = tar::Header::new_gnu();
            match content {
                Some(c) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(c.len() as u64);
                    h.set_mode(0o644);
                    b.append_data(&mut h, path, c.as_bytes()).unwrap();
                }
                None => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_size(0);
                    h.set_mode(0o755);
                    b.append_data(&mut h, path, &[][..]).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn layers_and_whiteouts() {
        let mut files = BTreeMap::new();
        let mut t = Totals::default();
        apply_layer(
            &mut files,
            &mut &layer(&[
                ("etc/", None),
                ("etc/a", Some("1")),
                ("etc/b", Some("2")),
                ("opt/", None),
                ("opt/x", Some("x")),
            ])[..],
            &mut t,
        )
        .unwrap();
        apply_layer(
            &mut files,
            &mut &layer(&[
                ("etc/.wh.a", Some("")),
                ("opt/new", Some("n")),
                ("opt/.wh..wh..opq", Some("")),
                ("dev/null", Some("")),
            ])[..],
            &mut t,
        )
        .unwrap();
        let paths: Vec<&str> = files.keys().map(String::as_str).collect();
        assert_eq!(paths, ["/etc", "/etc/b", "/opt", "/opt/new"]);
        // A path leaving the image (written by hand: the tar crate won't).
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..7].copy_from_slice(b"../evil");
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        let mut b = tar::Builder::new(Vec::new());
        b.append(&h, &b"x"[..]).unwrap();
        assert!(apply_layer(&mut files, &mut &b.into_inner().unwrap()[..], &mut t).is_err());
    }

    #[test]
    fn docker_save_archives() {
        // The classic `docker save` layout: manifest.json, a config, layer tars.
        let config =
            br#"{"architecture":"arm64","os":"linux","config":{"Env":["A=1"],"Cmd":["/bin/x"],"WorkingDir":"/w"}}"#;
        let manifest = br#"[{"Config":"cfg.json","RepoTags":["t:1"],"Layers":["l1/layer.tar"]}]"#;
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in [
            ("manifest.json", &manifest[..]),
            ("cfg.json", &config[..]),
            ("l1/layer.tar", &layer(&[("w/", None), ("w/f", Some("hi"))])[..]),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, name, data).unwrap();
        }
        let dir = tempdir("test").unwrap();
        let path = dir.path.join("image.tar");
        fs::write(&path, b.into_inner().unwrap()).unwrap();
        let p = load_archive(&path).unwrap();
        assert_eq!(p.config.cmd, ["/bin/x"]);
        assert_eq!((p.config.env, p.config.cwd.as_deref()), (vec!["A=1".to_string()], Some("/w")));
        assert!(matches!(p.files.get("/w/f"), Some(Node::File { data, .. }) if data == b"hi"));
        // Not for arm64: refused.
        assert!(parse_config(br#"{"architecture":"amd64"}"#).is_err());
    }

    fn zstd(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }

    #[test]
    fn zstd_layers() {
        let tar = layer(&[("etc/", None), ("etc/a", Some(&"a".repeat(100_000))), ("etc/b", Some("b"))]);
        // One frame; then the same in two frames with a skippable frame
        // between them, as parallel compressors write it.
        let mut split = zstd(&tar[..5000]);
        split.extend_from_slice(&[0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3]);
        split.extend_from_slice(&zstd(&tar[5000..]));
        for packed in [zstd(&tar), split] {
            let mut files = BTreeMap::new();
            let compressed = apply_layer(&mut files, &mut &packed[..], &mut Totals::default()).unwrap();
            assert!(compressed);
            assert!(matches!(files.get("/etc/a"), Some(Node::File { data, .. }) if data.len() == 100_000));
            assert!(matches!(files.get("/etc/b"), Some(Node::File { data, .. }) if data == b"b"));
        }
        // Garbage after the magic is an error, not a panic.
        let mut bad = zstd(&tar);
        let n = bad.len();
        bad.truncate(n / 2);
        assert!(apply_layer(&mut BTreeMap::new(), &mut &bad[..], &mut Totals::default()).is_err());
    }

    /// A registry on this machine, over plain HTTP, that wants a login:
    /// `bearer` sends clients to its token service (which gives anonymous
    /// tokens that can't pull), otherwise it takes the login itself.
    struct FakeRegistry {
        port: u16,
    }

    impl FakeRegistry {
        fn start(bearer: bool, blobs: BTreeMap<String, Vec<u8>>, manifest: Vec<u8>) -> FakeRegistry {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let login = format!("Basic {}", {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode("user:pass")
            });
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    let Ok(mut conn) = conn else { continue };
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && head.len() < 65536 {
                        match conn.read(&mut byte) {
                            // Not HTTP (a TLS handshake): hang up.
                            Ok(1) if head.is_empty() && !byte[0].is_ascii_uppercase() => break,
                            Ok(1) => head.push(byte[0]),
                            _ => break,
                        }
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let Some(path) = head.lines().next().and_then(|l| l.split(' ').nth(1)) else { continue };
                    let auth = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Authorization: ").or(l.strip_prefix("authorization: ")))
                        .unwrap_or("")
                        .to_string();
                    let allowed = if bearer { auth == "Bearer good" } else { auth == login };
                    let (status, body, extra) = if path.starts_with("/token") {
                        let token = if auth == login { "good" } else { "anonymous" };
                        ("200 OK", format!("{{\"token\":\"{token}\"}}").into_bytes(), String::new())
                    } else if !allowed {
                        let challenge = if bearer {
                            format!("Bearer realm=\"http://127.0.0.1:{port}/token\",service=\"fake\"")
                        } else {
                            "Basic realm=\"fake\"".to_string()
                        };
                        ("401 Unauthorized", Vec::new(), format!("WWW-Authenticate: {challenge}\r\n"))
                    } else if path.contains("/manifests/") {
                        ("200 OK", manifest.clone(), format!("Content-Type: {OCI_MANIFEST}\r\n"))
                    } else if let Some(b) = path.rsplit_once("/blobs/").and_then(|(_, d)| blobs.get(d)) {
                        ("200 OK", b.clone(), String::new())
                    } else {
                        ("404 Not Found", Vec::new(), String::new())
                    };
                    let _ = write!(
                        conn,
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
                        body.len()
                    );
                    let _ = conn.write_all(&body);
                }
            });
            FakeRegistry { port }
        }
    }

    #[test]
    fn registries_that_want_a_login() {
        // A private image with a zstd layer.
        let config = br#"{"architecture":"arm64","os":"linux","config":{"Cmd":["/hello"]}}"#.to_vec();
        let layer_data = zstd(&layer(&[("hello", Some(&random_suffix()))]));
        let digest = |d: &[u8]| format!("sha256:{}", sha256(d));
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(&config), "size": config.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": digest(&layer_data), "size": layer_data.len()}],
        })
        .to_string()
        .into_bytes();
        let blobs: BTreeMap<String, Vec<u8>> =
            [(digest(&config), config.clone()), (digest(&layer_data), layer_data.clone())].into_iter().collect();
        let dir = tempdir("logins").unwrap();
        let creds = dir.path.join("config.json");
        let auth = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode("user:pass")
        };
        for bearer in [true, false] {
            let reg = FakeRegistry::start(bearer, blobs.clone(), manifest.clone());
            let source = format!("localhost:{}/team/private:1", reg.port);
            // Without a login: refused, saying how to log in.
            let err = load_with(&source, &dir.path, Store::none()).err().unwrap();
            assert!(format!("{err:#}").contains(&format!("grix login localhost:{}", reg.port)), "{err:#}");
            // With one (as Docker keeps it): pulled.
            std::fs::write(
                &creds,
                serde_json::json!({"auths": {format!("localhost:{}", reg.port): {"auth": auth}}}).to_string(),
            )
            .unwrap();
            let pulled = load_with(&source, &dir.path, Store::file(&creds)).unwrap();
            assert_eq!(pulled.config.cmd, ["/hello"]);
            assert!(pulled.files.contains_key("/hello"));
            // A wrong one is refused.
            std::fs::write(
                &creds,
                serde_json::json!({"auths": {format!("localhost:{}", reg.port): {"username": "user", "password": "nope"}}})
                    .to_string(),
            )
            .unwrap();
            let err = load_with(&format!("localhost:{}/team/other:1", reg.port), &dir.path, Store::file(&creds));
            assert!(err.is_err());
        }
    }

    #[test]
    fn where_registries_may_send_us() {
        let r = Reference::parse("ghcr.io/o/r:1").unwrap();
        let reg = Registry::new(&r, Store::none()).unwrap();
        assert!(reg.may_reach("https://elsewhere.example/token"));
        assert!(!reg.may_reach("http://127.0.0.1:8080/token"));
        let r = Reference::parse("localhost:5000/o/r:1").unwrap();
        let mut reg = Registry::new(&r, Store::none()).unwrap();
        assert!(!reg.may_reach("http://127.0.0.1:8080/token"));
        reg.scheme = "http";
        assert!(reg.may_reach("http://127.0.0.1:8080/token"));
        assert!(reg.may_reach("http://[::1]:8080/x") && !reg.may_reach("http://example.com/x"));
        assert!(loopback("localhost:5000") && loopback("[::1]:5000") && !loopback("localhost.example.com"));
    }

    #[test]
    fn references() {
        let r = Reference::parse("alpine").unwrap();
        assert_eq!(
            (r.host.as_str(), r.repo.as_str(), r.tag_or_digest.as_str()),
            ("registry-1.docker.io", "library/alpine", "latest")
        );
        let r = Reference::parse("python:3.12-alpine").unwrap();
        assert_eq!((r.repo.as_str(), r.tag_or_digest.as_str()), ("library/python", "3.12-alpine"));
        let r = Reference::parse("ghcr.io/owner/tool:v1").unwrap();
        assert_eq!((r.host.as_str(), r.repo.as_str()), ("ghcr.io", "owner/tool"));
        let r = Reference::parse("localhost:5000/x@sha256:abc").unwrap();
        assert_eq!((r.host.as_str(), r.tag_or_digest.as_str()), ("localhost:5000", "sha256:abc"));
        assert!(Reference::parse("UPPER").is_err());
    }
}
