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
//! `from` takes a registry reference (`alpine:3.21`,
//! `ghcr.io/owner/repo:tag`), `oci:DIR` (an OCI image layout),
//! `docker-archive:FILE` (`docker save` output), `docker:NAME` (from the
//! local Docker daemon) or `dir:DIR` (a root file system). Without `from`,
//! the image has nothing but the grix kernel and what the Grixfile puts in:
//! a static program needs no other OS. Build steps run in grix itself, with
//! `fs_write`, `process`, `threads` and `net`, and the file tree they leave
//! is the image's. A step that's a string runs with `/bin/sh -c`; one that's
//! a list is a program and its arguments, which needs no shell.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use grix_abi::policy::Capability;
use serde::Deserialize;

use crate::container::{Image, ImageConfig};
use crate::export::ExportContent;
use crate::image::{self, Node};
use crate::sandbox::{ExitStatus, Sandbox, Stream};

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
        return Ok(full);
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
    /// The kernel to put in the image (by default the one `Sandbox` uses).
    pub kernel: Option<PathBuf>,
    /// Each build step's output, as it comes.
    pub on_output: &'a mut dyn FnMut(Stream, &[u8]),
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
    /// `from` may name a registry image (the host fetches it).
    pub registries: bool,
    /// `from` may be `docker:NAME` (the host's Docker daemon).
    pub docker: bool,
    /// Each step's time limit and the most memory it may have.
    pub step_timeout: Duration,
    pub step_memory_mb: u64,
}

impl Default for BuildPolicy {
    fn default() -> Self {
        BuildPolicy {
            net: true,
            allow_hosts: Vec::new(),
            registries: true,
            docker: true,
            step_timeout: Duration::from_secs(1800),
            step_memory_mb: 3000,
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
        let mut files = BTreeMap::new();
        let mut config = ImageConfig::default();
        match self.from.as_deref() {
            None => {}
            Some(dir) if dir.starts_with("dir:") => {
                let dir = in_context(base, Path::new(&dir[4..]), self.from_outside_context)?;
                image::import(&mut files, &dir, "/")?;
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
                let pulled = crate::oci::load(source, base).with_context(|| format!("from {source}"))?;
                files = pulled.files;
                let c = pulled.config;
                config.command = c.entrypoint.into_iter().chain(c.cmd).collect();
                config.env = c.env;
                config.cwd = c.cwd;
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
        config.capabilities = self.capabilities.clone();
        config.memory_mb = self.memory_mb;
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
        let kernel_path = opts.kernel.clone().unwrap_or_else(|| Sandbox::builder().kernel_path().to_path_buf());
        let kernel =
            std::fs::read(&kernel_path).with_context(|| format!("reading the kernel {}", kernel_path.display()))?;
        crate::container::check_kernel(&kernel).with_context(|| format!("the kernel {}", kernel_path.display()))?;
        let mut image = Image::new(files, config, kernel);
        for step in &self.run {
            image = run_step(image, step, &opts.policy, opts.on_output)?;
        }
        Ok(image)
    }
}

/// Run one build step in `image` and take the file tree it leaves.
fn run_step(
    image: Image,
    step: &Step,
    policy: &BuildPolicy,
    on_output: &mut dyn FnMut(Stream, &[u8]),
) -> Result<Image> {
    let argv = step.argv();
    if argv.is_empty() {
        bail!("an empty build step");
    }
    let (_, bytes) = image.size();
    // Room for the tree, what the step adds, and the export of it all.
    let memory_mb = (bytes * 3 / (1 << 20) + 512).min(policy.step_memory_mb);
    let mut b = Sandbox::builder()
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
    }
    for e in &image.config.env {
        if let Some((k, v)) = e.split_once('=') {
            b = b.env(k, v);
        }
    }
    let out = b.build()?.run_streaming(&argv, |s, d| on_output(s, d))?;
    if out.status != ExitStatus::Exited(0) {
        bail!("build step {step:?} failed: {:?}\n{}", out.status, out.stderr_str());
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
    let kernel = image.kernel_bytes().to_vec();
    Ok(Image::new(files, image.config, kernel))
}
