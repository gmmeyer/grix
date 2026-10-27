use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use grix_abi::image::{IMAGE_BASE, Image, MAX_ENTRIES, MAX_RAM, RAM_BASE};
use grix_abi::policy::{Capability, DenyAction, Policy};
use grix_abi::wire::{Channel, Event, ExitKind};
use serde::Serialize;

use crate::event::GuestEvent;
use crate::export::{Collector, Export};
use crate::image::{self, Node};
use crate::mount::{Mount, MountChanges};
use crate::net::{ForwardFrom, HostRule, NetPolicy};
use crate::vmm::{self, VmConfig, VmEnd};

/// Room the kernel needs below the boot image (kernel, heap, page tables).
const RESERVED_LOW: u64 = IMAGE_BASE - RAM_BASE;
/// Minimum RAM left for the program above the boot image.
const MIN_FREE: u64 = 64 << 20;
/// Output kept per stream unless `max_output` says otherwise.
const DEFAULT_MAX_OUTPUT: usize = 64 << 20;
/// Exported bytes kept unless `max_export` says otherwise.
const DEFAULT_MAX_EXPORT: usize = 256 << 20;

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
    /// The program wrote more than `max_output` to stdout; the rest was dropped.
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    #[serde(serialize_with = "display_all")]
    pub events: Vec<GuestEvent>,
    /// The directories given to [`SandboxBuilder::export`], in that order,
    /// as the program left them.
    pub exports: Vec<Export>,
    /// What happened to each directory given to [`SandboxBuilder::mount`],
    /// in that order.
    pub mounts: Vec<MountChanges>,
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

    /// The export of guest directory `dir` (as given to
    /// [`SandboxBuilder::export`]).
    pub fn export(&self, dir: &str) -> Option<&Export> {
        let dir = image::guest_path(dir).ok()?;
        self.exports.iter().find(|e| e.dir == dir)
    }

    /// Capabilities the program asked for but did not have (not counting
    /// connections the network policy refused).
    pub fn missing_capabilities(&self) -> Vec<String> {
        let mut caps: Vec<String> = self
            .events
            .iter()
            .filter_map(|e| match e {
                GuestEvent::Denied { capability, .. }
                    if capability != "privileged" && capability != crate::event::NET_POLICY =>
                {
                    Some(capability.clone())
                }
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
    max_output: usize,
    exports: Vec<String>,
    max_export: usize,
    mounts: Vec<Mount>,
    net: NetPolicy,
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
            max_output: DEFAULT_MAX_OUTPUT,
            exports: Vec::new(),
            max_export: DEFAULT_MAX_EXPORT,
            mounts: Vec::new(),
            net: NetPolicy::default(),
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
        self.files.insert(path, Node::File { data: data.into(), mode: mode & 0o7777, mtime_ns: image::now_ns() });
        Ok(self)
    }

    /// Create a symbolic link at `guest` pointing to `target` (absolute,
    /// or relative to the link's directory), like `ln -s target guest`.
    pub fn symlink(mut self, guest: &str, target: &str) -> Result<Self> {
        let path = image::guest_path(guest)?;
        if target.is_empty() || target.contains('\0') {
            bail!("symlink target {target:?} for {guest} must be non-empty, without NUL");
        }
        self.files.insert(path, Node::Symlink { target: target.into(), mtime_ns: image::now_ns() });
        Ok(self)
    }

    /// Create an empty directory at `guest`.
    pub fn dir(mut self, guest: &str) -> Result<Self> {
        let path = image::guest_path(guest)?;
        self.files.insert(path, Node::Dir { mode: 0o755, mtime_ns: image::now_ns() });
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

    /// Keep at most this many bytes of each of stdout and stderr (64 MiB by
    /// default). The program keeps running; the rest is dropped and
    /// [`RunOutput::stdout_truncated`] / `stderr_truncated` say so.
    pub fn max_output(mut self, bytes: usize) -> Self {
        self.max_output = bytes;
        self
    }

    /// Send directory `guest` back when the program ends, however it ends
    /// (except a timeout or kernel panic), into [`RunOutput::exports`]: the
    /// program's results. Write one to the host with [`Export::write_to`].
    /// The program's status comes first; the export then has 30 seconds
    /// (or what's left of the timeout, if longer).
    /// If nothing is imported there, it starts out as an empty directory for
    /// the program to fill (writable with [`Capability::FsWrite`]), so a
    /// program that makes it itself needs `mkdir -p` or the like.
    pub fn export(mut self, guest: &str) -> Result<Self> {
        let path = image::guest_path(guest)?;
        if !self.exports.contains(&path) {
            self.exports.push(path);
        }
        Ok(self)
    }

    /// Mount host directory `host` read-write at `guest`. Each run sees it
    /// as it is when the run starts. When the program ends (except on a
    /// timeout or kernel panic), what it changed there is applied to
    /// `host`: new and changed files, links and directories, and removals.
    /// Only the changes are sent, and they count against
    /// [`max_export`](SandboxBuilder::max_export); if they don't all fit,
    /// nothing is applied. Anything that also changed on the host during
    /// the run is left as the host has it ([`MountChanges::conflicts`]).
    ///
    /// The program can't remove or rename the mount point itself (EBUSY).
    /// Changing files needs [`Capability::FsWrite`], which this grants (it
    /// lets the program write anywhere in its own filesystem, but nothing
    /// else reaches the host). The directory lives in guest memory during
    /// the run, so `memory_mb` bounds its size.
    pub fn mount(mut self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        let host = host.as_ref();
        let canonical = host.canonicalize().with_context(|| format!("mounting {}", host.display()))?;
        if !canonical.is_dir() {
            bail!("mounting {}: not a directory", host.display());
        }
        let guest = image::guest_path(guest)?;
        if guest == "/" {
            bail!("mount {} at a directory other than /", host.display());
        }
        let nested = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
        if let Some(m) = self.mounts.iter().find(|m| nested(&guest, &m.guest) || nested(&m.guest, &guest)) {
            bail!("mounts at {guest} and {} overlap", m.guest);
        }
        // One's changes could otherwise move the other's directory.
        if let Some(m) = self.mounts.iter().find(|m| canonical.starts_with(&m.host) || m.host.starts_with(&canonical)) {
            bail!("mounted directories {} and {} overlap", canonical.display(), m.host.display());
        }
        self.policy.grant(Capability::FsWrite);
        self.mounts.push(Mount { host: canonical, guest });
        Ok(self)
    }

    /// Send at most this many bytes of exports in all (256 MiB by default,
    /// counting paths and a little per entry). Entries that don't fit are
    /// left out, and [`ExportState::Truncated`](crate::ExportState::Truncated)
    /// says so.
    pub fn max_export(mut self, bytes: usize) -> Self {
        self.max_export = bytes;
        self
    }

    /// Let the program connect (with [`Capability::Net`]) only to hosts a
    /// rule allows: `example.com`, `*.example.com`, `1.2.3.4`,
    /// `10.0.0.0/8`, `[::1]`, each optionally with `:port`. Names cover the
    /// addresses DNS gives for them, and only allowed names resolve.
    ///
    /// Without any rule, `net` allows connections anywhere except the host
    /// itself (`host.grix.internal`, which reaches the host's localhost) and
    /// link-local addresses such as cloud metadata services: those need a
    /// rule naming them either way.
    pub fn allow_host(mut self, rule: &str) -> Result<Self> {
        let rule = HostRule::parse(rule)?;
        self.net.allow.get_or_insert_with(Vec::new).push(rule);
        Ok(self)
    }

    /// Forward connections to `host` (an address and port the host listens
    /// on, like `127.0.0.1:8080`) to `guest_port`, where a program in the
    /// sandbox listens (with [`Capability::Net`]).
    pub fn forward(mut self, host: &str, guest_port: u16) -> Result<Self> {
        let addr = std::net::ToSocketAddrs::to_socket_addrs(host)
            .with_context(|| format!("forward address {host:?}"))?
            .next()
            .with_context(|| format!("forward address {host:?} resolves to nothing"))?;
        if guest_port == 0 {
            bail!("forwarding {host} needs a guest port");
        }
        self.net.forwards.push((ForwardFrom::Addr(addr), guest_port));
        Ok(self)
    }

    /// Like [`forward`](SandboxBuilder::forward), from a listener the
    /// caller bound: to port 0, say, to get a free port and know which.
    /// Every run of the sandbox serves it.
    pub fn forward_listener(mut self, listener: std::net::TcpListener, guest_port: u16) -> Result<Self> {
        if guest_port == 0 {
            bail!("forwarding a listener needs a guest port");
        }
        self.net.forwards.push((ForwardFrom::Listener(std::sync::Arc::new(listener)), guest_port));
        Ok(self)
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

    pub fn build(mut self) -> Result<Sandbox> {
        for m in &self.mounts {
            let inside = format!("{}/", m.guest);
            if let Some(p) = self.files.keys().find(|p| **p == m.guest || p.starts_with(&inside)) {
                bail!("mount at {} overlaps imported {p}", m.guest);
            }
            // Where it goes must be a directory, or not there yet.
            if let Some((p, _)) =
                self.files.iter().find(|(p, n)| !matches!(n, Node::Dir { .. }) && m.guest.starts_with(&format!("{p}/")))
            {
                bail!("mount at {} is inside imported file {p}", m.guest);
            }
        }
        let mounted =
            |dir: &str| self.mounts.iter().any(|m| dir == m.guest || dir.starts_with(&format!("{}/", m.guest)));
        for dir in self.exports.iter().filter(|d| !mounted(d)) {
            let inside = format!("{dir}/");
            let exists = self.files.keys().any(|p| p == dir || p.starts_with(&inside));
            // Not under an imported file or link: that would replace it.
            let room = self
                .files
                .iter()
                .all(|(p, n)| matches!(n, Node::Dir { .. }) || !(p == "/" || dir.starts_with(&format!("{p}/"))));
            if !exists && room {
                self.files.insert(dir.clone(), Node::Dir { mode: 0o755, mtime_ns: image::now_ns() });
            }
        }
        if !self.cwd.starts_with('/') {
            bail!("working directory {:?} must be absolute", self.cwd);
        }
        if self.files.len() > MAX_ENTRIES {
            bail!("{} files, directories and links imported: at most {MAX_ENTRIES} fit", self.files.len());
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
    /// stdin is at end-of-file.
    pub fn run<S: AsRef<str>>(&self, argv: &[S]) -> Result<RunOutput> {
        self.run_inner(argv, None, |_, _| {})
    }

    /// Like [`run`](Sandbox::run), with `input` as the program's stdin.
    pub fn run_with_stdin<S: AsRef<str>>(&self, argv: &[S], input: impl Into<Vec<u8>>) -> Result<RunOutput> {
        self.run_inner(argv, Some(Box::new(std::io::Cursor::new(input.into()))), |_, _| {})
    }

    /// Like [`run`](Sandbox::run), also passing output to `on_output` as it arrives.
    pub fn run_streaming<S: AsRef<str>>(&self, argv: &[S], on_output: impl FnMut(Stream, &[u8])) -> Result<RunOutput> {
        self.run_inner(argv, None, on_output)
    }

    /// Like [`run_streaming`](Sandbox::run_streaming), reading the program's
    /// stdin from `stdin` as it asks for it. The reader is used on another
    /// thread, which may still be blocked in it after the run ends.
    pub fn run_streaming_with_stdin<S: AsRef<str>>(
        &self,
        argv: &[S],
        stdin: impl Read + Send + 'static,
        on_output: impl FnMut(Stream, &[u8]),
    ) -> Result<RunOutput> {
        self.run_inner(argv, Some(Box::new(stdin)), on_output)
    }

    fn run_inner<S: AsRef<str>>(
        &self,
        argv: &[S],
        stdin: Option<Box<dyn Read + Send>>,
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
        // Mounts are read now, as they are for this run.
        let mounted = cfg.mounts.iter().map(Mount::import).collect::<Result<Vec<_>>>()?;
        let mount_dirs: Vec<String> = cfg.mounts.iter().map(|m| m.guest.clone()).collect();
        let imported =
            image::imported_bytes(&cfg.files) + mounted.iter().map(|i| image::imported_bytes(&i.files)).sum::<u64>();
        let count = cfg.files.len() + mounted.iter().map(|i| i.files.len()).sum::<usize>();
        if count > MAX_ENTRIES {
            bail!(
                "{count} files, directories and links in the imports and mounts: at most {MAX_ENTRIES} fit \
                 (mount a smaller directory)"
            );
        }
        let needed = RESERVED_LOW + imported + MIN_FREE;
        if cfg.memory_mb << 20 < needed {
            bail!(
                "memory_mb = {} is too small for {} MiB of imports and mounts (need at least {} MiB)",
                cfg.memory_mb,
                imported >> 20,
                needed.div_ceil(1 << 20)
            );
        }
        let mut entries = image::entries(&cfg.files);
        for i in &mounted {
            entries.extend(image::entries(&i.files));
        }
        let boot_time_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
        let bytes = Image {
            ram_size: cfg.memory_mb << 20,
            boot_time_ns,
            seed,
            policy: cfg.policy,
            uid: cfg.uid,
            gid: cfg.gid,
            cwd: &cfg.cwd,
            stdin: stdin.is_some(),
            exe,
            argv: argv.clone(),
            envp: env.iter().map(String::as_str).collect(),
            entries,
            exports: cfg.exports.iter().map(String::as_str).collect(),
            export_budget: cfg.max_export as u64,
            mounts: mount_dirs.iter().map(String::as_str).collect(),
            forwards: cfg.net.forwards.iter().map(|&(_, port)| port).collect(),
        }
        .encode();
        let mut exports = Collector::new(&cfg.exports, &mount_dirs, cfg.max_export as u64);

        let vm = VmConfig {
            net: cfg.net.clone(),
            qemu: cfg.qemu.clone(),
            kernel: cfg.kernel.clone(),
            memory_mb: cfg.memory_mb,
            accel: cfg.accel.clone(),
        };
        let mut out = RunOutput {
            status: ExitStatus::Timeout,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            events: Vec::new(),
            exports: Vec::new(),
            mounts: Vec::new(),
            kernel_log: String::new(),
            duration: Duration::ZERO,
        };
        let started = Instant::now();
        let max = cfg.max_output;
        // Keep up to `max` bytes; mark the stream once anything is dropped.
        let keep = |buf: &mut Vec<u8>, truncated: &mut bool, payload: &[u8]| -> usize {
            let room = max.saturating_sub(buf.len()).min(payload.len());
            buf.extend_from_slice(&payload[..room]);
            *truncated |= room < payload.len();
            room
        };
        let run = vmm::run(&vm, &bytes, cfg.timeout, stdin, |ch, payload| match ch {
            Channel::Stdout => {
                let n = keep(&mut out.stdout, &mut out.stdout_truncated, payload);
                on_output(Stream::Stdout, &payload[..n]);
            }
            Channel::Stderr => {
                let n = keep(&mut out.stderr, &mut out.stderr_truncated, payload);
                on_output(Stream::Stderr, &payload[..n]);
            }
            Channel::Log => out.kernel_log.push_str(&String::from_utf8_lossy(payload)),
            Channel::Event => match Event::decode(payload) {
                Ok(e) => out.events.push(e.into()),
                Err(_) => out.kernel_log.push_str("[grix] undecodable event from guest\n"),
            },
            Channel::Export => exports.push(payload),
            Channel::Exit | Channel::Link => {}
        })?;
        out.events.extend(run.events);
        let end = run.end;
        let (exported, changes) = exports.finish();
        out.exports = exported;
        out.mounts = cfg.mounts.iter().zip(&mounted).zip(changes).map(|((m, i), c)| i.apply(m, c)).collect();
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
