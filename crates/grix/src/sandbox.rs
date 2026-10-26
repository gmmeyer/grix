use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use grix_abi::image::{IMAGE_BASE, Image, MAX_RAM, RAM_BASE};
use grix_abi::policy::{Capability, DenyAction, Policy};
use grix_abi::wire::{Channel, Event, ExitKind};
use serde::Serialize;

use crate::event::GuestEvent;
use crate::image::{self, Node};
use crate::vmm::{self, VmConfig, VmEnd};

/// Room the kernel needs below the boot image (kernel, heap, page tables).
const RESERVED_LOW: u64 = IMAGE_BASE - RAM_BASE;
/// Minimum RAM left for the program above the boot image.
const MIN_FREE: u64 = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ExitStatus {
    /// The program exited with this status.
    Exited(i32),
    /// The program was killed by this signal.
    Signaled(i32),
    /// The program ran past the time limit and was stopped.
    Timeout,
    /// The guest kernel crashed (a bug in grix, see `kernel_log`).
    KernelPanic,
    /// The VM ended without reporting a status.
    VmFailed(String),
}

impl ExitStatus {
    pub fn success(&self) -> bool {
        *self == ExitStatus::Exited(0)
    }

    /// Shell-style exit code: status, 128+signal, 124 on timeout, 125 on sandbox failure.
    pub fn code(&self) -> i32 {
        match self {
            ExitStatus::Exited(c) => *c,
            ExitStatus::Signaled(s) => 128 + s,
            ExitStatus::Timeout => 124,
            ExitStatus::KernelPanic | ExitStatus::VmFailed(_) => 125,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RunOutput {
    pub status: ExitStatus,
    #[serde(serialize_with = "lossy")]
    pub stdout: Vec<u8>,
    #[serde(serialize_with = "lossy")]
    pub stderr: Vec<u8>,
    #[serde(serialize_with = "display_all")]
    pub events: Vec<GuestEvent>,
    pub kernel_log: String,
    #[serde(serialize_with = "millis")]
    pub duration: Duration,
}

fn lossy<S: serde::Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&String::from_utf8_lossy(b))
}

fn display_all<S: serde::Serializer>(evs: &[GuestEvent], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(evs.iter().map(|e| e.to_string()))
}

fn millis<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_millis() as u64)
}

impl RunOutput {
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Capabilities the program asked for but did not have.
    pub fn missing_capabilities(&self) -> Vec<String> {
        let mut caps: Vec<String> = self
            .events
            .iter()
            .filter_map(|e| match e {
                GuestEvent::Denied { capability, .. } if capability != "privileged" => Some(capability.clone()),
                _ => None,
            })
            .collect();
        caps.sort();
        caps.dedup();
        caps
    }
}

/// Hardware virtualization if this host can run an arm64 guest natively,
/// otherwise emulation.
fn default_accel() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        if cfg!(target_os = "macos") {
            return "hvf";
        }
        if cfg!(target_os = "linux") && std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok() {
            return "kvm";
        }
    }
    "tcg"
}

/// Configure a [`Sandbox`]: what the program can see and do.
#[derive(Clone)]
pub struct SandboxBuilder {
    files: BTreeMap<String, Node>,
    policy: Policy,
    env: Vec<(String, String)>,
    cwd: String,
    memory_mb: u64,
    timeout: Duration,
    uid: u32,
    gid: u32,
    kernel: PathBuf,
    qemu: PathBuf,
    accel: String,
}

impl Default for SandboxBuilder {
    fn default() -> Self {
        let env_path = |var: &str, default: &str| std::env::var_os(var).map_or_else(|| default.into(), PathBuf::from);
        SandboxBuilder {
            files: BTreeMap::new(),
            policy: Policy::default(),
            env: Vec::new(),
            cwd: "/".into(),
            memory_mb: 512,
            timeout: Duration::from_secs(60),
            uid: 1000,
            gid: 1000,
            kernel: env_path(
                "GRIX_KERNEL",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel"
                ),
            ),
            qemu: env_path("GRIX_QEMU", "qemu-system-aarch64"),
            accel: std::env::var("GRIX_ACCEL").unwrap_or_else(|_| default_accel().into()),
        }
    }
}

impl SandboxBuilder {
    /// Make a host file or directory (recursively) visible at `guest`.
    pub fn import(mut self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        image::import(&mut self.files, host.as_ref(), guest)?;
        Ok(self)
    }

    /// Create a file with the given contents at `guest`.
    pub fn file(mut self, guest: &str, data: impl Into<Vec<u8>>, mode: u32) -> Result<Self> {
        let path = image::guest_path(guest)?;
        self.files.insert(path, Node::File { data: data.into(), mode: mode & 0o7777 });
        Ok(self)
    }

    /// Create an empty directory at `guest`.
    pub fn dir(mut self, guest: &str) -> Result<Self> {
        let path = image::guest_path(guest)?;
        self.files.insert(path, Node::Dir { mode: 0o755 });
        Ok(self)
    }

    pub fn allow(mut self, cap: Capability) -> Self {
        self.policy.grant(cap);
        self
    }

    pub fn on_deny(mut self, action: DenyAction) -> Self {
        self.policy.on_deny = action;
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn cwd(mut self, dir: impl Into<String>) -> Self {
        self.cwd = dir.into();
        self
    }

    pub fn memory_mb(mut self, mb: u64) -> Self {
        self.memory_mb = mb;
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn kernel(mut self, path: impl Into<PathBuf>) -> Self {
        self.kernel = path.into();
        self
    }

    pub fn qemu(mut self, path: impl Into<PathBuf>) -> Self {
        self.qemu = path.into();
        self
    }

    /// QEMU accelerator: `hvf` (macOS), `kvm` (Linux) or `tcg` (emulation, works
    /// everywhere). Defaults to hardware virtualization when the host has it.
    pub fn accel(mut self, accel: impl Into<String>) -> Self {
        self.accel = accel.into();
        self
    }

    pub fn build(self) -> Result<Sandbox> {
        if !self.cwd.starts_with('/') {
            bail!("working directory {:?} must be absolute", self.cwd);
        }
        let ram = self.memory_mb << 20;
        let needed = RESERVED_LOW + image::imported_bytes(&self.files) + MIN_FREE;
        if ram < needed {
            bail!(
                "memory_mb = {} is too small for {} MiB of imports (need at least {} MiB)",
                self.memory_mb,
                image::imported_bytes(&self.files) >> 20,
                needed.div_ceil(1 << 20)
            );
        }
        if ram > MAX_RAM {
            bail!("memory_mb = {} exceeds the {} MiB limit", self.memory_mb, MAX_RAM >> 20);
        }
        Ok(Sandbox { cfg: self })
    }
}

/// A reusable sandbox configuration. Each [`run`](Sandbox::run) boots a fresh VM.
#[derive(Clone)]
pub struct Sandbox {
    cfg: SandboxBuilder,
}

impl Sandbox {
    pub fn builder() -> SandboxBuilder {
        SandboxBuilder::default()
    }

    /// Run `argv[0]` (a path inside the sandbox) and collect its output.
    pub fn run<S: AsRef<str>>(&self, argv: &[S]) -> Result<RunOutput> {
        self.run_streaming(argv, |_, _| {})
    }

    /// Like [`run`](Sandbox::run), also passing output to `on_output` as it arrives.
    pub fn run_streaming<S: AsRef<str>>(
        &self,
        argv: &[S],
        mut on_output: impl FnMut(Stream, &[u8]),
    ) -> Result<RunOutput> {
        let cfg = &self.cfg;
        let argv: Vec<&str> = argv.iter().map(|s| s.as_ref()).collect();
        let exe = *argv.first().context("empty command")?;
        let env: Vec<String> = cfg.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
            .context("reading /dev/urandom")?;
        let boot_time_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
        let bytes = Image {
            ram_size: cfg.memory_mb << 20,
            boot_time_ns,
            seed,
            policy: cfg.policy,
            uid: cfg.uid,
            gid: cfg.gid,
            cwd: &cfg.cwd,
            exe,
            argv: argv.clone(),
            envp: env.iter().map(String::as_str).collect(),
            entries: image::entries(&cfg.files),
        }
        .encode();

        let vm = VmConfig {
            qemu: cfg.qemu.clone(),
            kernel: cfg.kernel.clone(),
            memory_mb: cfg.memory_mb,
            accel: cfg.accel.clone(),
        };
        let mut out = RunOutput {
            status: ExitStatus::Timeout,
            stdout: Vec::new(),
            stderr: Vec::new(),
            events: Vec::new(),
            kernel_log: String::new(),
            duration: Duration::ZERO,
        };
        let started = Instant::now();
        let end = vmm::run(&vm, &bytes, cfg.timeout, |ch, payload| match ch {
            Channel::Stdout => {
                out.stdout.extend_from_slice(payload);
                on_output(Stream::Stdout, payload);
            }
            Channel::Stderr => {
                out.stderr.extend_from_slice(payload);
                on_output(Stream::Stderr, payload);
            }
            Channel::Log => out.kernel_log.push_str(&String::from_utf8_lossy(payload)),
            Channel::Event => match Event::decode(payload) {
                Ok(e) => out.events.push(e.into()),
                Err(_) => out.kernel_log.push_str("[grix] undecodable event from guest\n"),
            },
            Channel::Exit => {}
        })?;
        out.duration = started.elapsed();
        out.status = match end {
            VmEnd::Exited { kind: ExitKind::Exited, code } => ExitStatus::Exited(code),
            VmEnd::Exited { kind: ExitKind::Signaled, code } => ExitStatus::Signaled(code),
            VmEnd::Exited { kind: ExitKind::Panic, .. } => ExitStatus::KernelPanic,
            VmEnd::Timeout => ExitStatus::Timeout,
            VmEnd::Lost { qemu_status, qemu_stderr } => ExitStatus::VmFailed(format!(
                "qemu exited ({qemu_status:?}) without a guest status: {}",
                qemu_stderr.trim()
            )),
        };
        Ok(out)
    }
}
