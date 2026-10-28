use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use grix_abi::image::{IMAGE_BASE, Image, MAX_ENTRIES, MAX_RAM, RAM_BASE};
use grix_abi::machine;
use grix_abi::policy::{Capability, DenyAction, Policy};
use grix_abi::wire::{Channel, Event, ExitKind};
use serde::Serialize;

use crate::control::RunControl;
use crate::event::GuestEvent;
use crate::export::{Collector, Export};
use crate::hostfs::LiveMount;
use crate::image::{self, Node};
use crate::mount::{Mount, MountChanges};
use crate::net::{ForwardFrom, HostRule, NetPolicy};
use crate::vmm::{self, SnapshotFile, VmConfig, VmEnd};

/// Room the kernel needs below the boot image (kernel, heap, page tables).
const RESERVED_LOW: u64 = IMAGE_BASE - RAM_BASE;
/// Minimum RAM left for the program above the boot image.
const MIN_FREE: u64 = 64 << 20;
/// Output kept per stream unless `max_output` says otherwise.
const DEFAULT_MAX_OUTPUT: usize = 64 << 20;
/// Exported bytes kept unless `max_export` says otherwise.
const DEFAULT_MAX_EXPORT: usize = 256 << 20;
/// How long a program has to end after the SIGTERM a timeout sends.
const DEFAULT_GRACE: Duration = Duration::from_secs(5);

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
    /// The program ran past the time limit. It got SIGTERM and the grace
    /// period ([`SandboxBuilder::grace`]) to end, and was stopped if it
    /// didn't; if it did, its exports came back.
    Timeout,
    /// [`RunControl::stop`](crate::RunControl::stop) ended the run.
    Stopped,
    /// The guest kernel crashed (a bug in grix, see `kernel_log`).
    KernelPanic,
    /// The VM ended without reporting a status.
    VmFailed(String),
}

impl ExitStatus {
    pub fn success(&self) -> bool {
        *self == ExitStatus::Exited(0)
    }

    /// Shell-style exit code: status, 128+signal, 124 on timeout, 137 when
    /// stopped (as for SIGKILL), 125 on sandbox failure.
    pub fn code(&self) -> i32 {
        match self {
            ExitStatus::Exited(c) => *c,
            ExitStatus::Signaled(s) => 128 + s,
            ExitStatus::Timeout => 124,
            ExitStatus::Stopped => 137,
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
    /// What happened to each directory given to
    /// [`SandboxBuilder::mount_on_exit`], in that order.
    pub mount_changes: Vec<MountChanges>,
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

/// The macOS major version (`kern.osproductversion`).
#[cfg(not(target_os = "macos"))]
fn macos_major() -> Option<u32> {
    None
}

/// The macOS major version (`kern.osproductversion`).
#[cfg(target_os = "macos")]
fn macos_major() -> Option<u32> {
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    // SAFETY: a NUL-terminated name, and a buffer with its length.
    let r = unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..len]).ok()?.trim_end_matches('\0');
    s.split('.').next()?.parse().ok()
}

/// grix's own VMM where it runs (arm64 macOS 15+, arm64 Linux with KVM)
/// and is installed: `GRIX_VMM`, next to the running program, or this
/// source tree's build. `GRIX_VMM=qemu`, or choosing a QEMU accelerator,
/// means QEMU.
pub(crate) fn default_vmm() -> Option<PathBuf> {
    if std::env::var_os("GRIX_ACCEL").is_some_and(|v| !v.is_empty()) {
        return None;
    }
    // Hypervisor.framework has the GIC grix-vmm needs from macOS 15.
    let runs = match default_accel() {
        "hvf" => macos_major().is_none_or(|v| v >= 15),
        "kvm" => true,
        _ => false,
    };
    if !runs {
        return None;
    }
    match std::env::var_os("GRIX_VMM") {
        Some(v) if v == "qemu" => return None,
        Some(v) => return Some(v.into()),
        None => {}
    }
    let beside = std::env::current_exe().ok().and_then(|e| Some(e.parent()?.join("grix-vmm")));
    let built = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/release/grix-vmm"));
    beside.into_iter().chain([built]).find(|p| p.is_file())
}

/// How [`SandboxBuilder::mount_with`] mounts a host directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountMode {
    /// Live and writable ([`SandboxBuilder::mount`]).
    ReadWrite,
    /// Live and read-only ([`SandboxBuilder::mount_read_only`]).
    ReadOnly,
    /// Changes applied when the program ends ([`SandboxBuilder::mount_on_exit`]).
    OnExit,
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
    live: Vec<LiveMount>,
    net: NetPolicy,
    control: Option<RunControl>,
    grace: Duration,
    uid: u32,
    gid: u32,
    kernel: PathBuf,
    qemu: PathBuf,
    accel: String,
    /// grix's own VMM, instead of QEMU.
    vmm: Option<PathBuf>,
    cpus: u32,
    /// What runs when `run` gets no command (an image's).
    command: Vec<String>,
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
            live: Vec::new(),
            net: NetPolicy::default(),
            control: None,
            grace: DEFAULT_GRACE,
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
            accel: std::env::var("GRIX_ACCEL").ok().filter(|a| !a.is_empty()).unwrap_or_else(|| default_accel().into()),
            vmm: default_vmm(),
            cpus: std::env::var("GRIX_CPUS").ok().and_then(|n| n.parse().ok()).unwrap_or(1),
            command: Vec::new(),
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

    /// CPUs for the program's threads (1 by default, at most
    /// `grix_abi::machine::MAX_CPUS`). The threads of one process run in
    /// parallel; separate processes take turns.
    pub fn cpus(mut self, n: u32) -> Self {
        self.cpus = n;
        self
    }

    pub fn memory_mb(mut self, mb: u64) -> Self {
        self.memory_mb = mb;
        self
    }

    /// The memory the sandbox gets so far (an [`image`](Self::image) may
    /// have raised it).
    pub fn current_memory_mb(&self) -> u64 {
        self.memory_mb
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
        if let Some(m) = self.live.iter().find(|m| path == m.guest || path.starts_with(&format!("{}/", m.guest))) {
            bail!("{path} is in live mount {}: its files are on the host already", m.guest);
        }
        if !self.exports.contains(&path) {
            self.exports.push(path);
        }
        Ok(self)
    }

    /// Mount host directory `host` read-write at `guest`, live: the
    /// program sees the directory as it is, and what it changes there
    /// changes on the host at once. Nothing of it is copied into the
    /// sandbox up front: the kernel asks the host for directory listings
    /// and file contents as the program needs them, so the directory can be
    /// any size. Changes made on the host during the run show up within a
    /// second.
    ///
    /// The program can't reach anything outside `host` through it: the host
    /// never follows a link there, and never lets a name lead out. It can't
    /// remove or rename the mount point itself (EBUSY). Changing files
    /// needs [`Capability::FsWrite`], which this grants (it also lets the
    /// program write anywhere in its own in-memory filesystem, but nothing
    /// else reaches the host).
    pub fn mount(self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        self.mount_with(host, guest, MountMode::ReadWrite)
    }

    /// Like [`mount`](SandboxBuilder::mount), but read-only (EROFS): a way
    /// to give the program a large directory without copying it in.
    pub fn mount_read_only(self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        self.mount_with(host, guest, MountMode::ReadOnly)
    }

    /// Mount `host` read-write at `guest`, but apply the program's changes
    /// to it only when the program ends, all at once. Each run imports the
    /// directory as it is when the run starts. When the program ends
    /// (except on a timeout or kernel panic), only the changes are sent:
    /// new and changed files, links and directories, and removals. They
    /// count against [`max_export`](SandboxBuilder::max_export), and if
    /// they don't all fit, nothing is applied. Anything that also changed
    /// on the host during the run is left as the host has it
    /// ([`MountChanges::conflicts`]). See [`RunOutput::mount_changes`].
    ///
    /// The directory lives in guest memory during the run, so `memory_mb`
    /// bounds its size. Grants [`Capability::FsWrite`].
    pub fn mount_on_exit(self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        self.mount_with(host, guest, MountMode::OnExit)
    }

    /// Mount `host` at `guest` in `mode`.
    pub fn mount_with(mut self, host: impl AsRef<Path>, guest: &str, mode: MountMode) -> Result<Self> {
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
        for (g, h) in self.mount_points() {
            if nested(&guest, g) || nested(g, &guest) {
                bail!("mounts at {guest} and {g} overlap");
            }
            // One's changes could otherwise move the other's directory.
            if canonical.starts_with(h) || h.starts_with(&canonical) {
                bail!("mounted directories {} and {} overlap", canonical.display(), h.display());
            }
        }
        if mode != MountMode::OnExit
            && let Some(e) = self.exports.iter().find(|e| **e == guest || e.starts_with(&format!("{guest}/")))
        {
            bail!("export {e} would be in live mount {guest}: its files are on the host already");
        }
        match mode {
            MountMode::OnExit => self.mounts.push(Mount { host: canonical, guest }),
            _ => self.live.push(LiveMount { host: canonical, guest, writable: mode == MountMode::ReadWrite }),
        }
        if mode != MountMode::ReadOnly {
            self.policy.grant(Capability::FsWrite);
        }
        Ok(self)
    }

    /// (guest path, host directory) of every mount.
    fn mount_points(&self) -> impl Iterator<Item = (&str, &Path)> {
        let on_exit = self.mounts.iter().map(|m| (m.guest.as_str(), m.host.as_path()));
        on_exit.chain(self.live.iter().map(|m| (m.guest.as_str(), m.host.as_path())))
    }

    /// Send the program signals while it runs, or stop it, with `control`
    /// (see [`RunControl`]). It reaches whichever runs of this sandbox are
    /// in progress.
    pub fn control(mut self, control: &RunControl) -> Self {
        self.control = Some(control.clone());
        self
    }

    /// When the time limit is reached, the program gets SIGTERM, and this
    /// long to end (5 seconds by default; zero to stop it at once). If it
    /// ends in time, its exports and `mount_on_exit` changes come back as
    /// usual. The status is [`ExitStatus::Timeout`] either way.
    pub fn grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
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

    /// The kernel the sandbox boots.
    pub fn kernel_path(&self) -> &Path {
        &self.kernel
    }

    /// Run grix image `image` (see [`Image`](crate::Image)): its files, its
    /// environment, working directory and command, enough memory for it,
    /// and its kernel. Of the capabilities it asks for, those that stay in
    /// the sandbox (`threads`, `process`, `fs_write`) are granted; `net`,
    /// which reaches the host and beyond, only by an explicit
    /// [`allow`](SandboxBuilder::allow). Settings made after this override
    /// the image's (call it first).
    pub fn image(mut self, image: &crate::Image) -> Result<Self> {
        self = self.image_files_only(image)?;
        let c = &image.config;
        for e in &c.env {
            let (k, v) = e.split_once('=').unwrap_or((e, ""));
            self.env.retain(|(key, _)| key != k);
            self.env.push((k.to_string(), v.to_string()));
        }
        for name in &c.capabilities {
            let cap = Capability::from_name(name).with_context(|| format!("unknown capability {name:?}"))?;
            if cap != Capability::Net {
                self.policy.grant(cap);
            }
        }
        let (_, bytes) = image.size();
        let needed = (RESERVED_LOW + bytes + MIN_FREE).div_ceil(1 << 20) + 128;
        self.memory_mb = self.memory_mb.max(needed).max(c.memory_mb.unwrap_or(0));
        self.command = c.command.clone();
        Ok(self)
    }

    /// An image's files, kernel and working directory.
    pub(crate) fn image_files_only(mut self, image: &crate::Image) -> Result<Self> {
        for (path, node) in &image.files {
            self.files.insert(path.clone(), node.clone());
        }
        if let Some(cwd) = &image.config.cwd {
            self.cwd = cwd.clone();
        }
        self.kernel = image.kernel_path()?;
        Ok(self)
    }

    /// Run in QEMU, this one.
    pub fn qemu(mut self, path: impl Into<PathBuf>) -> Self {
        self.qemu = path.into();
        self.vmm = None;
        self
    }

    /// Run in QEMU with this accelerator: `hvf` (macOS), `kvm` (Linux) or
    /// `tcg` (emulation, works everywhere). By default grix uses its own VMM
    /// where there is one (macOS on Apple silicon), otherwise QEMU with
    /// hardware virtualization when the host has it.
    pub fn accel(mut self, accel: impl Into<String>) -> Self {
        self.accel = accel.into();
        self.vmm = None;
        self
    }

    /// Run in grix's own VMM (`grix-vmm`, built by `make vmm`; macOS on
    /// Apple silicon), this one.
    pub fn vmm(mut self, path: impl Into<PathBuf>) -> Self {
        self.vmm = Some(path.into());
        self
    }

    /// The VMM a run uses: `grix-vmm`'s path, or `None` for QEMU.
    pub fn vmm_path(&self) -> Option<&Path> {
        self.vmm.as_deref()
    }

    pub fn build(mut self) -> Result<Sandbox> {
        for (guest, _) in self.mount_points() {
            let inside = format!("{guest}/");
            if let Some(p) = self.files.keys().find(|p| *p == guest || p.starts_with(&inside)) {
                bail!("mount at {guest} overlaps imported {p}");
            }
            // Where it goes must be a directory, or not there yet.
            if let Some((p, _)) =
                self.files.iter().find(|(p, n)| !matches!(n, Node::Dir { .. }) && guest.starts_with(&format!("{p}/")))
            {
                bail!("mount at {guest} is inside imported file {p}");
            }
        }
        let points: Vec<String> = self.mount_points().map(|(g, _)| g.to_string()).collect();
        let mounted = |dir: &str| points.iter().any(|g| dir == g || dir.starts_with(&format!("{g}/")));
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
        if self.cpus == 0 || self.cpus > machine::MAX_CPUS {
            bail!("cpus = {}: a sandbox has 1 to {} CPUs", self.cpus, machine::MAX_CPUS);
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

    /// The command an image gave (see [`SandboxBuilder::image`]), for
    /// running it as it is: `sandbox.run(sandbox.command())`.
    pub fn command(&self) -> &[String] {
        &self.cfg.command
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
        on_output: impl FnMut(Stream, &[u8]),
    ) -> Result<RunOutput> {
        Ok(self.run_mode(argv, stdin, None, on_output)?.0)
    }

    /// A run; with `take`, one that ends in a snapshot written there (and
    /// whether it did).
    fn run_mode<S: AsRef<str>>(
        &self,
        argv: &[S],
        stdin: Option<Box<dyn Read + Send>>,
        take: Option<std::fs::File>,
        on_output: impl FnMut(Stream, &[u8]),
    ) -> Result<(RunOutput, bool)> {
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
        let gicr = if cfg.vmm.is_some() { machine::GICR_GRIX_VMM } else { machine::GICR_QEMU };
        let bytes = Image {
            ram_size: cfg.memory_mb << 20,
            gicr,
            boot_time_ns,
            seed,
            policy: cfg.policy,
            uid: cfg.uid,
            gid: cfg.gid,
            cwd: &cfg.cwd,
            stdin: stdin.is_some() || take.is_some(),
            exe,
            argv: argv.clone(),
            envp: env.iter().map(String::as_str).collect(),
            entries,
            exports: cfg.exports.iter().map(String::as_str).collect(),
            export_budget: cfg.max_export as u64,
            mounts: mount_dirs.iter().map(String::as_str).collect(),
            live_mounts: cfg
                .live
                .iter()
                .map(|m| grix_abi::image::LiveMount { path: &m.guest, writable: m.writable })
                .collect(),
            forwards: cfg.net.forwards.iter().map(|&(_, port)| port).collect(),
            snapshot: take.is_some(),
            cpus: cfg.cpus,
        }
        .encode();
        let exports = Collector::new(&cfg.exports, &mount_dirs, cfg.max_export as u64);
        let mut net = cfg.net.clone();
        net.enabled = cfg.policy.allows(Capability::Net);
        let vm = VmConfig {
            net,
            control: cfg.control.clone(),
            grace: cfg.grace,
            live: cfg.live.clone(),
            qemu: cfg.qemu.clone(),
            kernel: cfg.kernel.clone(),
            memory_mb: cfg.memory_mb,
            accel: cfg.accel.clone(),
            vmm: cfg.vmm.clone(),
            cpus: cfg.cpus,
            snapshot: take.map(SnapshotFile::Take),
        };
        // A snapshot is taken while the program waits for stdin, which
        // must neither come nor end.
        let stdin = if vm.snapshot.is_some() { None } else { stdin };
        let (mut out, changes, taken) = execute(&vm, &bytes, cfg.timeout, stdin, exports, cfg.max_output, on_output)?;
        out.mount_changes = cfg.mounts.iter().zip(&mounted).zip(changes).map(|((m, i), c)| i.apply(m, c)).collect();
        Ok((out, taken))
    }

    /// Run `argv` until it first waits for input, and save the whole machine
    /// to `path` there: each [`Snapshot::run`](crate::Snapshot::run) then
    /// starts from that moment (see [`crate::snapshot`]). Needs grix-vmm
    /// on macOS; the sandbox can't have mounts, or listeners from
    /// [`forward_listener`](SandboxBuilder::forward_listener).
    pub fn snapshot<S: AsRef<str>>(&self, argv: &[S], path: impl AsRef<Path>) -> Result<crate::Snapshot> {
        let cfg = &self.cfg;
        let path = path.as_ref();
        if cfg.vmm.is_none() || !cfg!(target_os = "macos") {
            bail!("snapshots need grix's own VMM on macOS 15+ (Hypervisor.framework), not QEMU or KVM");
        }
        if !cfg.mounts.is_empty() || !cfg.live.is_empty() {
            bail!("a sandbox with mounts can't be snapshotted: what the host holds for them isn't saved");
        }
        if cfg.cpus != 1 {
            bail!("a sandbox with more than one CPU can't be snapshotted yet");
        }
        let mut forwards = Vec::new();
        for (from, port) in &cfg.net.forwards {
            match from {
                ForwardFrom::Addr(a) => forwards.push((a.to_string(), *port)),
                ForwardFrom::Listener(_) => bail!("a forwarded listener can't be saved in a snapshot (use forward)"),
            }
        }
        let settings = crate::snapshot::Settings {
            abi: grix_abi::ABI_VERSION,
            net: cfg.policy.allows(Capability::Net),
            allow_hosts: cfg.net.allow.as_ref().map(|rules| rules.iter().map(|r| r.to_string()).collect()),
            forwards,
            exports: cfg.exports.clone(),
            max_export: cfg.max_export,
            max_output: cfg.max_output,
            timeout_ms: cfg.timeout.as_millis() as u64,
            grace_ms: cfg.grace.as_millis() as u64,
            memory_mb: cfg.memory_mb,
        };
        // Written to a new file of our own (it holds the program's memory:
        // only we may read it), then renamed into place: never through a
        // link, and never over a snapshot runs may still be mapping.
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let name = path.file_name().context("the snapshot needs a file name")?.to_string_lossy();
        let temp = dir.join(format!(".{name}.{}.tmp", crate::container::random_suffix()));
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&temp)
        }
        .with_context(|| format!("creating {}", temp.display()))?;
        let cleanup = TempFile(temp.clone());
        let mut keep = file.try_clone()?;
        let (out, taken) = self.run_mode(argv, None, Some(file), |_, _| {})?;
        // The VMM ends the run once it has written the machine out; the
        // program ending, the time running out (or anything else) means
        // there's no snapshot.
        if !taken {
            let events: Vec<String> = out.events.iter().map(|e| e.to_string()).collect();
            bail!(
                "no snapshot: the program didn't wait for input ({:?})\n{}{}",
                out.status,
                events.join("\n"),
                out.stderr_str()
            );
        }
        crate::snapshot::finish(&mut keep, &settings)?;
        std::fs::rename(&temp, path).with_context(|| format!("writing {}", path.display()))?;
        std::mem::forget(cleanup);
        crate::Snapshot::open(path)
    }
}

/// Removes a file unless forgotten.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Run `vm` with `image` (or its snapshot) and collect what the program
/// said and sent back; and whether the VMM ended the run having taken a
/// snapshot (in time).
fn execute(
    vm: &VmConfig,
    image: &[u8],
    timeout: Duration,
    stdin: Option<Box<dyn Read + Send>>,
    mut exports: Collector,
    max_output: usize,
    mut on_output: impl FnMut(Stream, &[u8]),
) -> Result<(RunOutput, Vec<crate::export::Changes>, bool)> {
    let mut out = RunOutput {
        status: ExitStatus::Timeout,
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        events: Vec::new(),
        exports: Vec::new(),
        mount_changes: Vec::new(),
        kernel_log: String::new(),
        duration: Duration::ZERO,
    };
    let started = Instant::now();
    let max = max_output;
    // Keep up to `max` bytes; mark the stream once anything is dropped.
    let keep = |buf: &mut Vec<u8>, truncated: &mut bool, payload: &[u8]| -> usize {
        let room = max.saturating_sub(buf.len()).min(payload.len());
        buf.extend_from_slice(&payload[..room]);
        *truncated |= room < payload.len();
        room
    };
    let run = vmm::run(vm, image, timeout, stdin, |ch, payload| match ch {
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
        Channel::Exit | Channel::Link | Channel::Fs => {}
    })?;
    out.events.extend(run.events);
    let run_timed_out = run.timed_out;
    let (exported, changes) = exports.finish();
    out.exports = exported;
    out.duration = started.elapsed();
    let taken = vm.snapshot.is_some() && !run_timed_out && matches!(run.end, VmEnd::Lost { vmm_status: Some(0), .. });
    out.status = match run.end {
        // Out of time, even if the program then ended on the SIGTERM;
        // a kernel panic or a lost VM still says so.
        VmEnd::Exited { kind: ExitKind::Exited | ExitKind::Signaled, .. } | VmEnd::Stopped if run_timed_out => {
            ExitStatus::Timeout
        }
        VmEnd::Exited { kind: ExitKind::Exited, code } => ExitStatus::Exited(code),
        VmEnd::Exited { kind: ExitKind::Signaled, code } => ExitStatus::Signaled(code),
        VmEnd::Exited { kind: ExitKind::Panic, .. } => ExitStatus::KernelPanic,
        VmEnd::Timeout => ExitStatus::Timeout,
        VmEnd::Stopped => ExitStatus::Stopped,
        VmEnd::Lost { vmm_status, vmm_stderr } => ExitStatus::VmFailed(format!(
            "{} exited ({vmm_status:?}) without a guest status: {}",
            if vm.vmm.is_some() { "grix-vmm" } else { "qemu" },
            vmm_stderr.trim()
        )),
    };
    Ok((out, changes, taken))
}

/// A run restored from `snap`, with `stdin`.
pub(crate) fn run_snapshot(
    snap: &crate::Snapshot,
    stdin: Box<dyn Read + Send>,
    on_output: impl FnMut(Stream, &[u8]),
) -> Result<RunOutput> {
    if !cfg!(target_os = "macos") {
        bail!("snapshots need grix's own VMM on macOS 15+ (Hypervisor.framework)");
    }
    let s = &snap.settings;
    let file = std::fs::File::open(snap.path()).with_context(|| format!("opening {}", snap.path().display()))?;
    let mut net = NetPolicy {
        enabled: s.net,
        allow: s
            .allow_hosts
            .as_ref()
            .map(|rules| rules.iter().map(|r| HostRule::parse(r)).collect::<Result<Vec<_>>>())
            .transpose()?,
        forwards: Vec::new(),
    };
    for (addr, port) in &s.forwards {
        let a = addr.parse().with_context(|| format!("forward address {addr:?} in the snapshot"))?;
        net.forwards.push((ForwardFrom::Addr(a), *port));
    }
    let vm = VmConfig {
        net,
        control: snap.control.clone(),
        grace: Duration::from_millis(s.grace_ms),
        live: Vec::new(),
        qemu: PathBuf::new(),
        kernel: PathBuf::new(),
        memory_mb: s.memory_mb,
        accel: String::new(),
        vmm: Some(snap.vmm.clone().context("snapshots need grix's own VMM (grix-vmm, on macOS 15+)")?),
        cpus: 1,
        snapshot: Some(SnapshotFile::Restore(file)),
    };
    let exports = Collector::new(&s.exports, &[], s.max_export as u64);
    Ok(execute(&vm, &[], snap.timeout, Some(stdin), exports, s.max_output, on_output)?.0)
}
