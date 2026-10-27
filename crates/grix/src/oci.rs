//! Docker and OCI images as the files of a grix image. They can be pulled
//! from a registry (Docker Hub, GHCR, ...), read from an OCI image layout
//! directory, or read from a `docker save` archive.
//!
//! The image for linux/arm64 is picked and its layers are applied in order,
//! whiteouts included. Its config gives the command, environment and working
//! directory. Every blob is checked against its digest, and blobs from a
//! registry are cached by digest (`~/.cache/grix/blobs`).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::image::{self, Node};

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
pub(crate) fn load(source: &str, base: &Path) -> Result<Pulled> {
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
    let mut registry = Registry::new(&reference)?;
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
    let mut registry = Registry::new(&reference)?;
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
        let (mut files, mut totals) = (BTreeMap::new(), Totals::default());
        for layer in manifest["layers"].as_array().context("manifest without layers")? {
            let d = layer["digest"].as_str().context("layer without a digest")?;
            let media = layer["mediaType"].as_str().unwrap_or("");
            if media.contains("zstd") {
                bail!("layer {d} is zstd-compressed, which grix can't read yet");
            }
            fetch(d, layer["size"].as_u64())?;
            // Checked as it's read: what's applied is what was checked.
            let mut blob = Hashing::new(File::open(self.blob_path(d)?)?);
            apply_layer(&mut files, &mut blob, &mut totals).with_context(|| format!("applying layer {d}"))?;
            if blob.finish()? != check_digest(d)? {
                bail!("layer {d} doesn't match its digest");
            }
        }
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
        let gzipped = apply_layer(&mut files, &mut blob, &mut totals)?;
        let hash = blob.finish()?;
        if let Some(d) = diff_ids.get(i)
            && !gzipped
            && hash != check_digest(d)?
        {
            bail!("layer {} doesn't match its digest", i + 1);
        }
    }
    Ok(Pulled { files, config, digest: String::new() })
}

// ---------------------------------------------------------------- layers

/// Apply one layer (a tar, gzipped or not) to `files`: OCI whiteouts
/// (`.wh.NAME`, `.wh..wh..opq`) remove what lower layers had. Returns
/// whether it was gzipped.
pub(crate) fn apply_layer(
    files: &mut BTreeMap<String, Node>,
    data: &mut dyn Read,
    totals: &mut Totals,
) -> Result<bool> {
    let mut r = BufReader::new(data);
    let head = r.fill_buf()?;
    let gzipped = head.starts_with(&[0x1f, 0x8b]);
    let reader: Box<dyn Read> = if gzipped {
        Box::new(flate2::read::GzDecoder::new(r))
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        bail!("zstd-compressed layers aren't supported yet");
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
    Ok(gzipped)
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
    token: Option<String>,
}

impl Registry {
    fn new(r: &Reference) -> Result<Registry> {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(120))
            .build();
        Ok(Registry { agent, host: r.host.clone(), repo: r.repo.clone(), token: None })
    }

    /// GET `/v2/<repo>/<path>`, getting a token if the registry asks for
    /// one, and following redirects (without the token: they go to
    /// storage elsewhere).
    fn get(&mut self, path: &str, accept: &str) -> Result<ureq::Response> {
        let url = format!("https://{}/v2/{}/{path}", self.host, self.repo);
        for attempt in 0..2 {
            let mut req = self.agent.get(&url).set("Accept", accept);
            if let Some(t) = &self.token {
                req = req.set("Authorization", &format!("Bearer {t}"));
            }
            let resp = match req.call() {
                Ok(r) => r,
                Err(ureq::Error::Status(401, r)) if attempt == 0 => {
                    let challenge = r.header("www-authenticate").context("401 without a challenge")?.to_string();
                    self.token = Some(self.authenticate(&challenge)?);
                    continue;
                }
                Err(ureq::Error::Status(code, _)) => bail!("{url}: HTTP {code}"),
                Err(e) => return Err(anyhow::Error::new(e).context(url)),
            };
            let mut resp = resp;
            for _ in 0..5 {
                if !(300..400).contains(&resp.status()) {
                    return Ok(resp);
                }
                let to = resp.header("location").context("redirect without a location")?.to_string();
                let to = if to.starts_with("http") { to } else { format!("https://{}{to}", self.host) };
                resp = match self.agent.get(&to).call() {
                    Ok(r) => r,
                    Err(ureq::Error::Status(code, _)) => bail!("{to}: HTTP {code}"),
                    Err(e) => return Err(e.into()),
                };
            }
            bail!("{url}: too many redirects");
        }
        bail!("{url}: not authorized")
    }

    /// An anonymous pull token, as the registry's challenge says to get one.
    fn authenticate(&self, challenge: &str) -> Result<String> {
        let params = challenge.strip_prefix("Bearer ").context("unsupported registry authentication")?;
        let mut fields = BTreeMap::new();
        for part in params.split(',') {
            if let Some((k, v)) = part.trim().split_once('=') {
                fields.insert(k.to_string(), v.trim_matches('"').to_string());
            }
        }
        let realm = fields.get("realm").context("challenge without a realm")?;
        let mut req = self.agent.get(realm);
        if let Some(s) = fields.get("service") {
            req = req.query("service", s);
        }
        let scope = fields.get("scope").cloned().unwrap_or_else(|| format!("repository:{}:pull", self.repo));
        req = req.query("scope", &scope);
        let body: Value = serde_json::from_slice(&read_limited(req.call()?.into_reader(), MAX_JSON)?)?;
        Ok(body["token"].as_str().or(body["access_token"].as_str()).context("no token in the answer")?.to_string())
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
