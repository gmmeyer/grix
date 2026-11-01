//! `grix build`: a grix image from a Grixfile (TOML).
//!
//! ```toml
//! from = "python:3.12-alpine"     # a Docker/OCI image (see below), or none at all
//! command = ["python3", "/app/main.py"]
//! cwd = "/app"
//! capabilities = ["threads"]      # granted when the image runs
//! memory_mb = 512
//! run = ["pip install requests",  # build steps, in the image, with net:
//!        ["/app/setup", "--x"]]   # a shell command, or a program and its arguments
//!
//! [env]
//! PYTHONUNBUFFERED = "1"
//!
//! [[copy]]                        # host files, relative to the Grixfile
//! host = "app"
//! guest = "/app"
//!
//! [[file]]
//! guest = "/etc/motd"
//! content = "hello\n"
//! ```
//!
//! An image is for one architecture, arm64 or x86_64: the host's by
//! default (or `GRIX_ARCH`'s), or `BuildOptions::arch`. Its kernel is that
//! one's, and so is the Docker/OCI image it's built from (linux/arm64 or
//! linux/amd64), and a grix image it builds on.
//!
//! `from` takes a registry reference (`alpine:3.21`,
//! `ghcr.io/owner/repo:tag`), `oci:DIR` (an OCI image layout),
//! `docker-archive:FILE` (`docker save` output), `docker:NAME` (from the
//! local Docker daemon), `dir:DIR` (a root file system) or `image:FILE`
//! (another grix image: its files and settings, to build on). Without
//! `from`, the image has nothing but the grix kernel and what the Grixfile
//! puts in: a static program needs no other OS. Build steps run in grix
//! itself, with `fs_write`, `process`, `threads` and `net`, and the file
//! tree they leave is the image's. A step that's a string runs with
//! `/bin/sh -c`; one that's a list is a program and its arguments, which
//! needs no shell.
//!
//! What a step leaves is cached (`treecache`), by everything that went
//! into it: the files before it (contents and modes), the step, the
//! environment, the user, the working directory, the kernel, the
//! architecture and what the network allowed. A step whose inputs haven't changed isn't run again,
//! as with Docker's build cache; `grix build --no-cache` runs them all.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use grix_abi::policy::Capability;
use serde::Deserialize;

use crate::container::{Image, ImageConfig};
use crate::export::ExportContent;
use crate::image::{self, Node};
use crate::sandbox::{Arch, ExitStatus, Sandbox, Stream};

/// What a container runtime gives each container, not the image's.
const RUNTIME_FILES: &[&str] = &["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"];

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grixfile {
    pub from: Option<String>,
    pub command: Option<Vec<String>>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub memory_mb: Option<u64>,
    /// Who the program runs as (`uid[:gid]`, or names from the image's
    /// /etc/passwd); build steps run as the base image's user.
    pub user: Option<String>,
    #[serde(default, rename = "copy")]
    pub copies: Vec<Copy>,
    #[serde(default, rename = "file")]
    pub files: Vec<FileSpec>,
    #[serde(default)]
    pub run: Vec<Step>,
    /// `from`'s path may be outside the build context (given on the command
    /// line).
    #[serde(skip)]
    pub from_outside_context: bool,
}

/// `path` (from `base`), which must stay in the build context unless
/// `anywhere`: a Grixfile from somewhere mustn't read the host's files.
fn in_context(base: &Path, path: &Path, anywhere: bool) -> Result<PathBuf> {
    let full = if path.is_absolute() { path.to_path_buf() } else { base.join(path) };
    if anywhere {
        return image::real_dirs(&full);
    }
    let context = base.canonicalize().with_context(|| format!("the build context {}", base.display()))?;
    let real = full.canonicalize().with_context(|| format!("{} does not exist", full.display()))?;
    if !real.starts_with(&context) {
        bail!(
            "{} is outside the build context {} (a Grixfile only reads files under its own directory)",
            path.display(),
            context.display()
        );
    }
    Ok(real)
}

/// A build step: a shell command, or a program and its arguments.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Step {
    Shell(String),
    Exec(Vec<String>),
}

impl Step {
    fn argv(&self) -> Vec<String> {
        match self {
            Step::Shell(s) => vec!["/bin/sh".into(), "-c".into(), s.clone()],
            Step::Exec(argv) => argv.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Copy {
    pub host: PathBuf,
    pub guest: String,
    /// May be outside the build context (the Grixfile's directory): for
    /// paths given on the command line, never for a Grixfile's own.
    #[serde(skip)]
    pub outside_context: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSpec {
    pub guest: String,
    pub content: String,
    pub mode: Option<u32>,
}

/// How to build: where the kernel and QEMU are, and where build steps'
/// output goes.
pub struct BuildOptions<'a> {
    /// The architecture to build for: `kernel`'s if one is given, otherwise
    /// the host's or `GRIX_ARCH`'s by default.
    pub arch: Option<Arch>,
    /// The kernel to put in the image (by default the grix kernel
    /// installed for the architecture); it must be the architecture's.
    pub kernel: Option<PathBuf>,
    /// Each build step's output, as it comes.
    pub on_output: &'a mut dyn FnMut(Stream, &[u8]),
    /// Signals and stops reach build steps through this; a cancelled
    /// build ends before its next step ([`RunControl::cancel`]).
    pub control: Option<crate::RunControl>,
    /// What a build may do (the default: anything a user's own build may).
    pub policy: BuildPolicy,
}

/// What a build may reach, for builds someone else asks for (an agent).
#[derive(Clone, Debug)]
pub struct BuildPolicy {
    /// Build steps get `net`, under these `allow_host` rules (none: anywhere
    /// but the host and special addresses).
    pub net: bool,
    pub allow_hosts: Vec<String>,
    /// As [`SandboxBuilder::strict_network`](crate::SandboxBuilder::strict_network),
    /// for steps and pulls.
    pub strict_network: bool,
    /// `from` may name a registry image (the host fetches it).
    pub registries: bool,
    /// `from` may be `docker:NAME` (the host's Docker daemon).
    pub docker: bool,
    /// A registry that wants a login gets the user's (`auth`).
    pub credentials: bool,
    /// `from` may name a registry on this machine (which may speak plain
    /// HTTP): a way to reach the host's own services otherwise.
    pub local_registries: bool,
    /// Steps whose inputs are unchanged may be taken from the cache
    /// instead of running (what they leave is cached either way).
    pub cache: bool,
    /// Each step's time limit and the most memory it may have.
    pub step_timeout: Duration,
    pub step_memory_mb: u64,
}

impl Default for BuildPolicy {
    fn default() -> Self {
        BuildPolicy {
            net: true,
            allow_hosts: Vec::new(),
            strict_network: false,
            registries: true,
            docker: true,
            credentials: true,
            local_registries: true,
            cache: true,
            step_timeout: Duration::from_secs(1800),
            // Files a step writes live in its memory (half of it at
            // most), and memory it doesn't touch costs nothing. Enough
            // for `apk add chromium`; a step may ask for up to this.
            step_memory_mb: 4 << 10,
        }
    }
}

impl Grixfile {
    pub fn parse(text: &str) -> Result<Grixfile> {
        Ok(toml::from_str(text)?)
    }

    /// Build the image the Grixfile at `path` describes (relative paths in
    /// it are from its directory).
    pub fn build_file(path: &Path, opts: BuildOptions) -> Result<Image> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let g = Grixfile::parse(&text).with_context(|| format!("parsing {}", path.display()))?;
        g.build(path.parent().unwrap_or(Path::new(".")), opts)
    }

    /// Build the image, taking relative paths from `base`.
    pub fn build(&self, base: &Path, opts: BuildOptions) -> Result<Image> {
        let (arch, kernel_path) = target(opts.arch, opts.kernel.as_deref())?;
        let mut files = BTreeMap::new();
        let mut config = ImageConfig::default();
        match self.from.as_deref() {
            None => {}
            Some(dir) if dir.starts_with("dir:") => {
                let dir = in_context(base, Path::new(&dir[4..]), self.from_outside_context)?;
                image::import(&mut files, &dir, "/")?;
            }
            // Another grix image: its files and how it runs, built on.
            Some(path) if path.starts_with("image:") => {
                let path = in_context(base, Path::new(&path[6..]), self.from_outside_context)?;
                let base_image = Image::open(&path)?;
                let theirs = base_image.arch()?;
                if theirs != arch {
                    bail!(
                        "{} is an image for {theirs}, and this build is for {arch}: build for {theirs} \
                         (`--arch {theirs}`), or build the base for {arch}",
                        path.display()
                    );
                }
                files = base_image.files;
                config = base_image.config;
            }
            Some(source) => {
                let local = ["oci:", "docker-archive:", "docker:"].iter().any(|p| source.starts_with(p));
                if source.starts_with("docker:") && !opts.policy.docker {
                    bail!("this build may not read images from the Docker daemon");
                }
                if !local && !opts.policy.registries {
                    bail!("this build may not pull images from registries");
                }
                // Paths in it stay in the build context too.
                for prefix in ["oci:", "docker-archive:"] {
                    if let Some(p) = source.strip_prefix(prefix) {
                        in_context(base, Path::new(p), self.from_outside_context)?;
                    }
                }
                // Where the steps may connect, so may the pull.
                let allow = opts
                    .policy
                    .allow_hosts
                    .iter()
                    .map(|r| crate::net::HostRule::parse(r))
                    .collect::<Result<Vec<_>>>()?;
                let reach = crate::oci::Reach {
                    allow: (!allow.is_empty()).then_some(allow),
                    local: opts.policy.local_registries,
                    strict: opts.policy.strict_network,
                };
                let pulled = crate::oci::load(source, base, opts.policy.credentials, reach, arch)
                    .with_context(|| format!("from {source}"))?;
                files = pulled.files;
                // A container's runtime provides these (Docker mounts its
                // own over the image's), and so does grix's kernel: its
                // /etc/hosts names the sandbox, which the image's can't.
                for path in RUNTIME_FILES {
                    if files.get(*path).is_some_and(|n| !matches!(n, Node::Dir { .. })) {
                        files.remove(*path);
                    }
                }
                let c = pulled.config;
                config.command = c.entrypoint.into_iter().chain(c.cmd).collect();
                config.env = c.env;
                config.cwd = c.cwd;
                // Docker's default user is root.
                config.user = Some(if c.user.is_empty() { "0".into() } else { c.user });
                config.source = Some(if pulled.digest.is_empty() {
                    source.to_string()
                } else {
                    format!("{source}@{}", pulled.digest)
                });
            }
        }
        for (k, v) in &self.env {
            config.env.retain(|e| e.split_once('=').is_none_or(|(key, _)| key != k));
            config.env.push(format!("{k}={v}"));
        }
        if let Some(c) = &self.command {
            config.command = c.clone();
        }
        if let Some(c) = &self.cwd {
            config.cwd = Some(c.clone());
        }
        for name in &self.capabilities {
            Capability::from_name(name).with_context(|| format!("unknown capability {name:?}"))?;
        }
        // What a base image's program needs, this one may well need too.
        for name in &self.capabilities {
            if !config.capabilities.contains(name) {
                config.capabilities.push(name.clone());
            }
        }
        if let Some(mb) = self.memory_mb {
            let max = grix_abi::image::MAX_RAM >> 20;
            if mb == 0 || mb > max {
                bail!("memory_mb = {mb}: a sandbox has 1 to {max} MiB");
            }
            config.memory_mb = self.memory_mb;
        }
        for c in &self.copies {
            let host = in_context(base, &c.host, c.outside_context)?;
            image::import(&mut files, &host, &c.guest)?;
        }
        // Build steps run there, as Docker's WORKDIR makes it.
        if let Some(cwd) = &config.cwd {
            let cwd = image::guest_path(cwd)?;
            if cwd != "/" && !files.contains_key(&cwd) {
                files.insert(cwd, Node::Dir { mode: 0o755, mtime_ns: image::now_ns() });
            }
        }
        for f in &self.files {
            let path = image::guest_path(&f.guest)?;
            let node = Node::File {
                data: f.content.clone().into_bytes(),
                mode: f.mode.unwrap_or(0o644),
                mtime_ns: image::now_ns(),
            };
            files.insert(path, node);
        }
        let kernel =
            std::fs::read(&kernel_path).with_context(|| format!("reading the kernel {}", kernel_path.display()))?;
        match Arch::of_elf(&kernel) {
            Some(a) if a == arch => {}
            Some(a) => bail!("the kernel {} is for {a}, and this build is for {arch}", kernel_path.display()),
            None => bail!("the kernel {} isn't an arm64 or x86_64 ELF file", kernel_path.display()),
        }
        crate::container::check_kernel(&kernel).with_context(|| format!("the kernel {}", kernel_path.display()))?;
        // The kernel runs only its own architecture's programs: say so now,
        // not when a step or the image's program fails to start.
        crate::container::check_programs(&files, &config.command, arch)?;
        let mut image = Image::new(files, config, kernel);
        for step in &self.run {
            if opts.control.as_ref().is_some_and(|c| c.is_cancelled()) {
                bail!("the build was cancelled");
            }
            image = run_step(image, step, &opts.policy, opts.on_output, opts.control.as_ref())?;
        }
        // Steps run as the base image's user (root, for most): they're
        // what installs software and adds users. The program runs as this.
        if let Some(user) = &self.user {
            crate::container::resolve_user(user, &image.files)?;
            image.config.user = Some(user.clone());
        }
        Ok(image)
    }
}

/// The architecture a build is for, and the kernel it packs.
fn target(arch: Option<Arch>, kernel: Option<&Path>) -> Result<(Arch, PathBuf)> {
    let arch = match (arch, kernel) {
        (Some(a), _) => a,
        // A kernel given says what it's for.
        (None, Some(k)) => {
            let data = std::fs::read(k).with_context(|| format!("reading the kernel {}", k.display()))?;
            Arch::of_elf(&data)
                .with_context(|| format!("the kernel {} isn't an arm64 or x86_64 ELF file", k.display()))?
        }
        (None, None) => Arch::from_env(),
    };
    let kernel = match kernel {
        Some(k) => k.to_path_buf(),
        None => Sandbox::builder().arch(arch).installed_kernel(),
    };
    Ok((arch, kernel))
}

/// A build step's guest memory: room for the tree, what the step adds,
/// and the export of it all, or the image's `memory_mb` if that's more
/// (installing a toolchain adds more than a small base's own size, and
/// files take at most half of it), within the policy's limit.
fn step_memory_mb(image_bytes: u64, asked: Option<u64>, limit: u64) -> u64 {
    (image_bytes * 3 / (1 << 20) + 512).max(asked.unwrap_or(0)).min(limit)
}

/// What a step's result depends on: the files before it, the step, and
/// how it runs.
fn step_key(image: &Image, argv: &[String], policy: &BuildPolicy) -> String {
    use sha2::{Digest, Sha256};
    let tree = crate::treecache::tree_hash(&image.files);
    let kernel: String = Sha256::digest(image.kernel_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    let arch = image.arch().map_or("?", |a| a.name());
    let c = &image.config;
    let strict = if policy.strict_network { "\0strict" } else { "" };
    let net = if policy.net { policy.allow_hosts.join("\0") + strict } else { "\0no net".into() };
    let parts = [
        arch.as_bytes(),
        tree.as_bytes(),
        argv.join("\0").as_bytes(),
        c.env.join("\0").as_bytes(),
        c.user.as_deref().unwrap_or("").as_bytes(),
        c.cwd.as_deref().unwrap_or("").as_bytes(),
        kernel.as_bytes(),
        net.as_bytes(),
    ]
    .map(|p| p.to_vec());
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    crate::treecache::key("build-step-v3", &parts)
}

/// Run one build step in `image` and take the file tree it leaves (or
/// what it left before, from the cache).
fn run_step(
    image: Image,
    step: &Step,
    policy: &BuildPolicy,
    on_output: &mut dyn FnMut(Stream, &[u8]),
    control: Option<&crate::RunControl>,
) -> Result<Image> {
    let argv = step.argv();
    if argv.is_empty() {
        bail!("an empty build step");
    }
    let key = step_key(&image, &argv, policy);
    if policy.cache
        && let Some(files) = crate::treecache::get(&key)
    {
        on_output(Stream::Stderr, format!("grix: {step:?}: cached\n").as_bytes());
        let kernel = image.kernel_bytes().to_vec();
        return Ok(Image::new(files, image.config, kernel));
    }
    let (_, bytes) = image.size();
    let memory_mb = step_memory_mb(bytes, image.config.memory_mb, policy.step_memory_mb);
    // The image's own architecture, whatever GRIX_ARCH says.
    let mut b = Sandbox::builder()
        .arch(image.arch()?)
        .image_files_only(&image)?
        .memory_mb(memory_mb)
        .timeout(policy.step_timeout)
        .max_export((bytes as usize).saturating_mul(4).max(1 << 30))
        .allow(Capability::FsWrite)
        .allow(Capability::Process)
        .allow(Capability::Threads)
        .export("/")?;
    if policy.net {
        b = b.allow(Capability::Net);
        for rule in &policy.allow_hosts {
            b = b.allow_host(rule)?;
        }
        if policy.strict_network {
            b = b.strict_network();
        }
    }
    if let Some(c) = control {
        b = b.control(c);
    }
    for e in &image.config.env {
        if let Some((k, v)) = e.split_once('=') {
            b = b.env(k, v);
        }
    }
    let out = b.build()?.run_streaming(&argv, |s, d| on_output(s, d))?;
    if out.status != ExitStatus::Exited(0) {
        // What the guest says it ran out of (its say-so, only for a hint):
        // a full file system shows as ENOSPC, or as SIGBUS through a mapping.
        use grix_abi::stats::Limit;
        let full = out.guest_stats.as_ref().is_some_and(|s| s.hits(Limit::FileData) + s.hits(Limit::Memory) > 0);
        let hint = if full {
            format!(
                "\nThe step ran out of room: its files live in guest memory ({memory_mb} MiB, half of it for \
                 files). Ask for more with `memory_mb` in the Grixfile."
            )
        } else {
            String::new()
        };
        bail!("build step {step:?} failed: {:?}{hint}\n{}", out.status, out.stderr_str());
    }
    let ex = out.export("/").context("no export")?;
    if ex.state != crate::ExportState::Complete {
        bail!("build step {step:?}: the file tree didn't all come back ({:?})", ex.state);
    }
    let mut files = BTreeMap::new();
    for e in &ex.entries {
        let mtime_ns = image::ns(e.mtime);
        let node = match &e.content {
            ExportContent::Dir => Node::Dir { mode: e.mode, mtime_ns },
            ExportContent::File(data) => Node::File { data: data.clone(), mode: e.mode, mtime_ns },
            ExportContent::Symlink(t) => Node::Symlink { target: t.clone(), mtime_ns },
        };
        files.insert(format!("/{}", e.path), node);
    }
    // Only a chance to save time later.
    let _ = crate::treecache::put(&key, &files);
    let kernel = image.kernel_bytes().to_vec();
    Ok(Image::new(files, image.config, kernel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::tests::elf;

    #[test]
    fn steps_are_cached_per_architecture() {
        let files: BTreeMap<String, Node> =
            [("/a".to_string(), Node::File { data: b"x".to_vec(), mode: 0o644, mtime_ns: 0 })].into_iter().collect();
        let argv = ["/bin/sh".to_string(), "-c".into(), "true".into()];
        let policy = BuildPolicy::default();
        let key =
            |machine: u16| step_key(&Image::new(files.clone(), ImageConfig::default(), elf(machine)), &argv, &policy);
        assert_ne!(key(183), key(62));
        assert_eq!(key(62), key(62));
    }

    #[test]
    fn builds_are_for_one_architecture() {
        let dir = std::env::temp_dir().join(format!("grix-arch-{}", crate::container::random_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        // A kernel given says what the build is for, unless told otherwise.
        let kernel = dir.join("kernel");
        std::fs::write(&kernel, elf(62)).unwrap();
        assert_eq!(target(None, Some(&kernel)).unwrap(), (Arch::X86_64, kernel.clone()));
        assert_eq!(target(Some(Arch::Aarch64), None).unwrap().0, Arch::Aarch64);
        // ... and must be its kernel.
        let err = |g: &Grixfile, arch| {
            let opts = BuildOptions {
                arch: Some(arch),
                kernel: Some(kernel.clone()),
                on_output: &mut |_, _| {},
                control: None,
                policy: BuildPolicy::default(),
            };
            g.build(&dir, opts).err().unwrap().to_string()
        };
        let e = err(&Grixfile::default(), Arch::Aarch64);
        assert!(e.contains("is for x86_64, and this build is for aarch64"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn steps_get_the_memory_the_grixfile_asks_for() {
        // A 100 MiB base: 812 MiB, unless memory_mb says more, up to the limit.
        let base = 100 << 20;
        assert_eq!(step_memory_mb(base, None, 3000), 812);
        assert_eq!(step_memory_mb(base, Some(256), 3000), 812);
        assert_eq!(step_memory_mb(base, Some(2048), 3000), 2048);
        assert_eq!(step_memory_mb(base, Some(8192), 3000), 3000);
        // By default a step gets what `apk add chromium` takes, and an image
        // asking for more than that doesn't get it unless the caller says.
        let limit = BuildPolicy::default().step_memory_mb;
        assert_eq!(limit, 4096);
        assert_eq!(step_memory_mb(base, Some(64 << 10), limit), limit);
    }
}
