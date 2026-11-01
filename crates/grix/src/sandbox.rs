use std::collections::BTreeMap;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use grix_abi::image::{IMAGE_BASE, Image, LOW_RAM, MAX_ENTRIES, MAX_RAM, RAM_BASE};
use grix_abi::machine;
use grix_abi::policy::{Capability, DenyAction, Policy};
use grix_abi::stats::Stats as GuestStats;
use grix_abi::wire::{Channel, Event, ExitKind};
use serde::Serialize;

use crate::control::RunControl;
use crate::event::GuestEvent;
use crate::export::{Collector, Export};
use crate::hostfs::LiveMount;
use crate::image::{self, Node};
use crate::metrics::Metrics;
use crate::mount::{Mount, MountChanges};
use crate::net::{ForwardFrom, HostRule, NetPolicy, Publish, UdpFrom, forward_addr};
use crate::vmm::{self, SnapshotFile, VmConfig, VmEnd};

/// Room the kernel needs below the boot image (kernel, heap, page tables).
const RESERVED_LOW: u64 = IMAGE_BASE - RAM_BASE;
/// Minimum RAM left for the program above the boot image.
const MIN_FREE: u64 = 64 << 20;
/// Output kept per stream unless `max_output` says otherwise.
pub(crate) const DEFAULT_MAX_OUTPUT: usize = 64 << 20;
/// Exported bytes kept unless `max_export` says otherwise.
pub(crate) const DEFAULT_MAX_EXPORT: usize = 256 << 20;
/// How long a program has to end after the SIGTERM a timeout sends.
pub(crate) const DEFAULT_GRACE: Duration = Duration::from_secs(5);
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// What the guest kernel last said of its resources, normally as the
    /// program ended (not if the VM was stopped, or the kernel panicked).
    /// The guest's own say-so: [`host_usage`](RunOutput::host_usage) is
    /// what the host measured.
    #[serde(serialize_with = "guest_stats")]
    pub guest_stats: Option<GuestStats>,
    /// What the VM's process cost the host, if it could be measured.
    pub host_usage: Option<HostUsage>,
}

/// What a run's VM process (grix-vmm or QEMU) cost the host, as the host's
/// operating system counted it when the process ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HostUsage {
    #[serde(rename = "cpu_user_ms", serialize_with = "millis")]
    pub cpu_user: Duration,
    #[serde(rename = "cpu_system_ms", serialize_with = "millis")]
    pub cpu_system: Duration,
    /// Its peak resident memory: the guest RAM it touched, and its own.
    pub peak_memory_bytes: u64,
}

/// `{"cpu_ms", "syscalls", ..., "usage": {resource: {now, peak, limit}},
/// "limits_hit": {limit: count}}`, with only the limits that were hit.
fn guest_stats<S: serde::Serializer>(s: &Option<GuestStats>, ser: S) -> Result<S::Ok, S::Error> {
    use grix_abi::stats::{Limit, Resource};
    let Some(s) = s else { return ser.serialize_none() };
    let usage: BTreeMap<&str, serde_json::Value> = Resource::ALL
        .iter()
        .map(|&r| {
            let u = s.usage(r);
            (r.name(), serde_json::json!({"now": u.now, "peak": u.peak, "limit": u.limit}))
        })
        .collect();
    let hits: BTreeMap<&str, u64> =
        Limit::ALL.iter().filter(|&&l| s.hits(l) > 0).map(|&l| (l.name(), s.hits(l))).collect();
    serde_json::json!({
        "cpu_ms": s.cpu_ns / 1_000_000,
        "syscalls": s.syscalls,
        "page_faults": s.page_faults,
        "context_switches": s.context_switches,
        "processes_started": s.processes_started,
        "usage": usage,
        "limits_hit": hits,
    })
    .serialize(ser)
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

/// The guest's architecture: what its kernel and the programs it runs are
/// built for. The host's own by default (`GRIX_ARCH` says otherwise), as
/// only that one has hardware virtualization; another is emulated (QEMU's
/// TCG).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    /// The host's.
    pub fn host() -> Arch {
        if cfg!(target_arch = "x86_64") { Arch::X86_64 } else { Arch::Aarch64 }
    }

    /// `GRIX_ARCH` (`aarch64`/`arm64` or `x86_64`/`amd64`), or the host's.
    pub fn from_env() -> Arch {
        Arch::env().unwrap_or_else(Arch::host)
    }

    /// `GRIX_ARCH`'s, if it names one.
    fn env() -> Option<Arch> {
        std::env::var("GRIX_ARCH").ok().as_deref().and_then(Arch::parse)
    }

    /// `aarch64`/`arm64` or `x86_64`/`amd64`.
    pub fn parse(name: &str) -> Option<Arch> {
        match name {
            "x86_64" | "amd64" => Some(Arch::X86_64),
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            _ => None,
        }
    }

    /// What an ELF file (a kernel or a program) is built for: its
    /// `e_machine`. None if it isn't a 64-bit little-endian ELF file for
    /// either.
    pub fn of_elf(data: &[u8]) -> Option<Arch> {
        match elf_machine(data)? {
            EM_AARCH64 => Some(Arch::Aarch64),
            EM_X86_64 => Some(Arch::X86_64),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        }
    }

    /// Its name in Docker/OCI platforms (`linux/arm64`, `linux/amd64`).
    pub fn oci_name(self) -> &'static str {
        match self {
            Arch::Aarch64 => "arm64",
            Arch::X86_64 => "amd64",
        }
    }

    /// Where its machine loads the boot image.
    pub(crate) fn image_base(self) -> u64 {
        match self {
            Arch::Aarch64 => IMAGE_BASE,
            Arch::X86_64 => machine::x86_64::IMAGE_BASE,
        }
    }

    /// The kernel's name in an installation, and its build in this source tree.
    fn kernel_names(self) -> (&'static str, &'static str) {
        match self {
            Arch::Aarch64 => ("grix-kernel", "kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel"),
            Arch::X86_64 => ("grix-kernel-x86_64", "kernel/target/x86_64-unknown-none/release/grix-kernel"),
        }
    }

    fn default_qemu(self) -> PathBuf {
        let (var, name) = match self {
            Arch::Aarch64 => ("GRIX_QEMU", "qemu-system-aarch64"),
            Arch::X86_64 => ("GRIX_QEMU_X86_64", "qemu-system-x86_64"),
        };
        std::env::var_os(var).map_or_else(|| name.into(), PathBuf::from)
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// An ELF file's `e_machine`, if it's a 64-bit little-endian ELF file.
pub(crate) fn elf_machine(data: &[u8]) -> Option<u16> {
    if !data.starts_with(b"\x7fELF\x02\x01") {
        return None;
    }
    data.get(18..20).map(|m| u16::from_le_bytes([m[0], m[1]]))
}

/// Hardware virtualization if this host can run `arch`'s guests natively,
/// otherwise emulation.
fn default_accel_for(arch: Arch) -> &'static str {
    if arch == Arch::host() {
        if cfg!(target_os = "macos") {
            return "hvf";
        }
        if cfg!(target_os = "linux") && kvm_error(arch).is_none() {
            return "kvm";
        }
    }
    "tcg"
}

/// Why grix-vmm can't run `arch`'s guests on this host's KVM: opening
/// /dev/kvm failed. None if KVM isn't what's missing (not Linux, or
/// another architecture's guest, which only QEMU's emulator runs).
pub(crate) fn kvm_error(arch: Arch) -> Option<std::io::Error> {
    if !cfg!(target_os = "linux") || arch != Arch::host() {
        return None;
    }
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").err()
}

/// Is `program` there to run: a path to a file, or a name on PATH.
fn runnable(program: &Path) -> bool {
    if program.components().count() > 1 {
        return program.is_file();
    }
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(program).is_file()))
}

fn default_accel() -> &'static str {
    default_accel_for(Arch::from_env())
}

/// Where `SandboxBuilder::x86_64` puts the translator.
const X86_64_TRANSLATOR: &str = "/usr/libexec/grix/x86_64";

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
    default_vmm_for(Arch::from_env())
}

/// grix-vmm for `arch`'s guests, where it runs them.
fn default_vmm_for(arch: Arch) -> Option<PathBuf> {
    vmm_for(home_dir("target/release/grix-vmm").as_deref(), arch)
}

/// Where an installation's `file` is: beside the running program (a
/// release unpacks grix, grix-vmm and the kernel together). None for a
/// build of this source tree that has `built` (relative to it): that's
/// what `make` built, where cargo leaves an unsigned grix-vmm beside a
/// debug grix.
fn home_dir(built: &str) -> Option<PathBuf> {
    if SOURCE_TREE.is_some_and(|t| Path::new(t).join(built).is_file()) {
        return None;
    }
    std::env::current_exe().ok().and_then(|e| Some(e.parent()?.to_path_buf()))
}

/// This source tree, for a build of it (where `make` puts the kernel and
/// grix-vmm). Release builds (`GRIX_RELEASE_BUILD` set when compiling)
/// have none: a path from the machine that built them means nothing on
/// another, and anyone there could put files at it.
const SOURCE_TREE: Option<&str> = if option_env!("GRIX_RELEASE_BUILD").is_some() {
    None
} else {
    Some(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
};

/// grix-vmm in `dir` (an installation), or this source tree's build, unless
/// `GRIX_VMM` says otherwise. None where it doesn't run.
pub(crate) fn vmm_in(dir: Option<&Path>) -> Option<PathBuf> {
    vmm_for(dir, Arch::from_env())
}

fn vmm_for(dir: Option<&Path>, arch: Arch) -> Option<PathBuf> {
    if !vmm_runs_for(arch) {
        return None;
    }
    match std::env::var_os("GRIX_VMM") {
        Some(v) if v == "qemu" => return None,
        Some(v) => return Some(v.into()),
        None => {}
    }
    let built = SOURCE_TREE.map(|t| Path::new(t).join("target/release/grix-vmm"));
    dir.map(|d| d.join("grix-vmm")).into_iter().chain(built).find(|p| p.is_file())
}

/// `arch`'s kernel in `dir` (an installation), or this source tree's
/// build, unless `GRIX_KERNEL` says otherwise.
fn kernel_in(dir: Option<&Path>, arch: Arch) -> PathBuf {
    if let Some(k) = std::env::var_os("GRIX_KERNEL") {
        return k.into();
    }
    let (name, built) = arch.kernel_names();
    let built = SOURCE_TREE.map(|t| Path::new(t).join(built));
    let candidates: Vec<PathBuf> = dir.map(|d| d.join(name)).into_iter().chain(built).collect();
    // The first that's there; if none is, the one an error should name.
    candidates.iter().find(|p| p.is_file()).or(candidates.first()).cloned().unwrap_or_else(|| "grix-kernel".into())
}

/// The grix kernel: `GRIX_KERNEL`, beside the running program (as a
/// release unpacks), or this source tree's build.
fn default_kernel(arch: Arch) -> PathBuf {
    kernel_in(home_dir(arch.kernel_names().1).as_deref(), arch)
}

/// Does grix-vmm run here, unless told otherwise (`GRIX_ACCEL`)?
/// Does grix-vmm run `arch`'s guests here, unless told otherwise
/// (`GRIX_ACCEL`)? Only the host's own architecture's, with hardware
/// virtualization: Hypervisor.framework on arm64 macOS, KVM on Linux.
fn vmm_runs_for(arch: Arch) -> bool {
    if std::env::var_os("GRIX_ACCEL").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if arch != Arch::host() || arch == Arch::X86_64 && !cfg!(target_os = "linux") {
        return false;
    }
    // Hypervisor.framework has the GIC grix-vmm needs from macOS 15.
    match default_accel_for(arch) {
        "hvf" => macos_major().is_none_or(|v| v >= 15),
        "kvm" => true,
        _ => false,
    }
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
    /// A lazy import ([`SandboxBuilder::import_lazy`]).
    Lazy,
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
    network: Option<Network>,
    control: Option<RunControl>,
    metrics: Option<Metrics>,
    grace: Duration,
    uid: u32,
    gid: u32,
    arch: Arch,
    /// Who chose `arch`, if anyone did (`GRIX_ARCH`, or `arch`): an image
    /// for another is an error then, rather than a reason to switch.
    arch_chosen_by: Option<&'static str>,
    /// The architecture of the image whose kernel this runs, if any.
    image_arch: Option<Arch>,
    /// Where grix is installed, if not beside the running program.
    install: Option<PathBuf>,
    kernel: PathBuf,
    qemu: PathBuf,
    accel: String,
    /// grix's own VMM, instead of QEMU.
    vmm: Option<PathBuf>,
    cpus: u32,
    /// The guest path of the x86_64 translator, if any.
    x86_64: Option<String>,
    /// TTY mode's terminal size (rows, columns).
    tty: Option<(u16, u16)>,
    /// The sandbox's host name, if not `grix_abi::HOSTNAME`.
    hostname: Option<String>,
    /// Fill in a default environment (`default_env`) at `build`.
    default_env: bool,
    /// The host's time zone rather than UTC (`host_timezone`) at `build`.
    host_timezone: bool,
    /// What runs when `run` gets no command (an image's).
    command: Vec<String>,
}

impl Default for SandboxBuilder {
    fn default() -> Self {
        let arch = Arch::from_env();
        SandboxBuilder {
            files: BTreeMap::new(),
            policy: Policy::default(),
            env: Vec::new(),
            cwd: "/".into(),
            memory_mb: 512,
            timeout: DEFAULT_TIMEOUT,
            max_output: DEFAULT_MAX_OUTPUT,
            exports: Vec::new(),
            max_export: DEFAULT_MAX_EXPORT,
            mounts: Vec::new(),
            live: Vec::new(),
            net: NetPolicy::default(),
            network: None,
            control: None,
            metrics: None,
            grace: DEFAULT_GRACE,
            uid: 1000,
            gid: 1000,
            arch,
            arch_chosen_by: Arch::env().map(|_| "GRIX_ARCH"),
            image_arch: None,
            install: None,
            kernel: default_kernel(arch),
            qemu: arch.default_qemu(),
            accel: std::env::var("GRIX_ACCEL").ok().filter(|a| !a.is_empty()).unwrap_or_else(|| default_accel().into()),
            vmm: default_vmm(),
            cpus: std::env::var("GRIX_CPUS").ok().and_then(|n| n.parse().ok()).unwrap_or(1),
            x86_64: None,
            tty: None,
            hostname: None,
            default_env: false,
            host_timezone: false,
            command: Vec::new(),
        }
    }
}

impl SandboxBuilder {
    /// Make a host file or directory (recursively) visible at `guest`.
    pub fn import(self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        let host = image::real_dirs(host.as_ref())?;
        self.import_real(&host, guest)
    }

    /// [`import`](Self::import) of a path whose directories are real ones
    /// already, which nothing resolves again: a path checked to be in an
    /// allowed directory stays there, whatever is swapped in since.
    pub(crate) fn import_real(mut self, host: &Path, guest: &str) -> Result<Self> {
        image::import(&mut self.files, host, guest)?;
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

    /// The network stack: this grants [`Capability::Net`], but for
    /// [`Network::None`], which refuses to go with it. Unsaid, `net` means
    /// the [native](Network::Native) stack (`GRIX_NETWORK` can say otherwise).
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    pub fn on_deny(mut self, action: DenyAction) -> Self {
        self.policy.on_deny = action;
        self
    }

    /// Set `key` to `value` in the program's environment, in place of
    /// any value it had (the image's, or an earlier call's).
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        self.env.retain(|(k, _)| *k != key);
        self.env.push((key, value.into()));
        self
    }

    /// Run in the host's time zone (`TZ`, or else `/etc/localtime`), not
    /// UTC. It's a choice as it says something of where the host is. An
    /// image's own `/etc/localtime` gives way to it.
    pub fn host_timezone(mut self) -> Self {
        self.host_timezone = true;
        self
    }

    /// Start the program with what a shell's login would give it, for
    /// whatever the environment doesn't have by `build`: `HOME` (the
    /// user's, from /etc/passwd), `PATH` (Docker's default), `LANG`
    /// (`C.UTF-8`) and `TMPDIR` (`/tmp`). Without it the program gets only
    /// what it's given (and an image's own environment).
    pub fn default_env(mut self) -> Self {
        self.default_env = true;
        self
    }

    /// The sandbox's host name (`grix` unless given), as uname, /etc/hostname,
    /// /etc/hosts and /proc/sys/kernel/hostname show it: 1 to 64 letters,
    /// digits, `-` and `.`. An image's `HOSTNAME` (Docker's) follows it.
    pub fn hostname(mut self, name: &str) -> Result<Self> {
        if !grix_abi::valid_hostname(name) {
            bail!(
                "host name {name:?} must be 1 to {} letters, digits, '-' and '.', not starting with '-' or '.'",
                grix_abi::MAX_HOSTNAME
            );
        }
        let old = self.hostname.as_deref().unwrap_or(grix_abi::HOSTNAME);
        if self.env.iter().any(|(k, v)| k == "HOSTNAME" && v == old) {
            self = self.env("HOSTNAME", name);
        }
        self.hostname = Some(name.into());
        Ok(self)
    }

    pub fn cwd(mut self, dir: impl Into<String>) -> Self {
        self.cwd = dir.into();
        self
    }

    /// Run x86_64 Linux programs with `translator`, an arm64 Linux
    /// program that translates them (`qemu-x86_64` in user mode; box64
    /// should work too, untested), copied in at `/usr/libexec/grix/x86_64`:
    /// execve of an x86_64 ELF runs it with the program's path and
    /// arguments, as binfmt_misc would. It needs what it needs to run (a
    /// static `qemu-x86_64`: the `threads` capability), and dynamically
    /// linked x86_64 programs their own libraries (`QEMU_LD_PREFIX` for
    /// qemu).
    pub fn x86_64(self, translator: impl AsRef<Path>) -> Result<Self> {
        let path = translator.as_ref();
        // The file itself (through links), and one that can run here.
        let data = std::fs::read(path).with_context(|| format!("reading the x86_64 translator {}", path.display()))?;
        if elf_machine(&data) != Some(EM_AARCH64) {
            bail!(
                "the x86_64 translator {} isn't an arm64 Linux program (it runs inside the sandbox, which is arm64)",
                path.display()
            );
        }
        let mut b = self.file(X86_64_TRANSLATOR, data, 0o755)?;
        b.x86_64 = Some(X86_64_TRANSLATOR.into());
        Ok(b)
    }

    /// CPUs for the program's threads (1 by default, at most
    /// `grix_abi::machine::MAX_CPUS`). The threads of one process run in
    /// parallel; separate processes take turns.
    pub fn cpus(mut self, n: u32) -> Self {
        self.cpus = n;
        self
    }

    /// TTY mode: the program's stdin, stdout and stderr are a terminal
    /// (/dev/pts/0, its controlling terminal) of `rows` by `cols`, as with
    /// `docker run -t`. Its stdin is what's typed (Ctrl-C and Ctrl-Z
    /// included, as the bytes a terminal sends: the terminal turns them
    /// into signals), and its stdout what the terminal shows, with CR LF
    /// line ends and echo; there's no separate stderr.
    /// [`RunControl::resize`](crate::RunControl::resize) changes the size.
    pub fn tty(mut self, rows: u16, cols: u16) -> Self {
        self.tty = Some((rows.max(1), cols.max(1)));
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

    /// How long the program may run (60 seconds by default): then it gets
    /// SIGTERM and the [`grace`](Self::grace) period, and the status is
    /// [`ExitStatus::Timeout`].
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// No time limit: the program runs until it ends, or is stopped
    /// ([`RunControl::stop`]): a server's. Once it ends, its exports still
    /// have 30 seconds to arrive.
    pub fn no_timeout(self) -> Self {
        self.timeout(Duration::MAX)
    }

    /// Keep at most this many bytes of each of stdout and stderr in the
    /// [`RunOutput`] (64 MiB by default; 0 when it's only streamed). The
    /// program keeps running; the rest isn't kept, and
    /// [`RunOutput::stdout_truncated`] / `stderr_truncated` say so. What
    /// [`run_streaming`](Sandbox::run_streaming) passes on as it comes is
    /// all of it, whatever this says.
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

    /// Import directory `host` at `guest` without copying it in: the guest
    /// reads its files from the host as the program uses them, so its size
    /// isn't bounded by `memory_mb` (large runtimes and datasets). It
    /// behaves as an import otherwise: the host's directory never changes
    /// (with [`Capability::FsWrite`], whatever the program changes is
    /// copied into the sandbox first, and stays there), and what the
    /// program sees is the directory as it found it. A file changed on the
    /// host after the program first saw it reads as EIO rather than a
    /// mixture. Exports skip what is still the host's.
    pub fn import_lazy(self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        self.mount_with(host, guest, MountMode::Lazy)
    }

    /// Mount `host` at `guest` in `mode`.
    pub fn mount_with(self, host: impl AsRef<Path>, guest: &str, mode: MountMode) -> Result<Self> {
        let host = host.as_ref();
        let canonical = host.canonicalize().with_context(|| format!("mounting {}", host.display()))?;
        self.mount_real(canonical, guest, mode)
    }

    /// [`mount_with`](Self::mount_with) of a canonical path, which nothing
    /// resolves again: a directory checked to be an allowed one stays the
    /// one mounted, whatever is swapped in since (a link on the way fails
    /// the run instead).
    pub(crate) fn mount_real(mut self, canonical: PathBuf, guest: &str, mode: MountMode) -> Result<Self> {
        let host = canonical.as_path();
        crate::at::open_dir(host).with_context(|| format!("mounting {}: not a directory", host.display()))?;
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
            _ => self.live.push(LiveMount {
                host: canonical,
                guest,
                writable: mode == MountMode::ReadWrite,
                lazy: mode == MountMode::Lazy,
            }),
        }
        if matches!(mode, MountMode::ReadWrite | MountMode::OnExit) {
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

    /// Count this sandbox's runs in `metrics` (see [`Metrics`]): how they
    /// end, what they cost, and, while they run, what their kernels report.
    pub fn metrics(mut self, metrics: &Metrics) -> Self {
        self.metrics = Some(metrics.clone());
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
        let addr = forward_addr(host, guest_port)?;
        self.net.forwards.push((ForwardFrom::Addr(addr), guest_port));
        Ok(self)
    }

    /// Forward UDP datagrams to `host` (an address and port the host binds,
    /// like `127.0.0.1:5353`) to `guest_port`, where a program in the
    /// sandbox has a UDP socket bound (with [`Capability::Net`]). It sees
    /// each sender's address as the source (the host's own loopback as
    /// `10.0.2.2`, `host.grix.internal`), and its replies to a sender go
    /// back out from `host`. Only to senders, the most recent 256 of them:
    /// anywhere else, its sends are under [`allow_host`](Self::allow_host)
    /// as any socket's are. Datagrams over about 4 KiB are dropped.
    pub fn forward_udp(mut self, host: &str, guest_port: u16) -> Result<Self> {
        let addr = forward_addr(host, guest_port)?;
        self.net.udp_forwards.push((UdpFrom::Addr(addr), guest_port));
        Ok(self)
    }

    /// Like [`forward_udp`](SandboxBuilder::forward_udp), from a socket
    /// the caller bound (to port 0, say, to know which it got). Every run
    /// of the sandbox serves it.
    pub fn forward_udp_socket(mut self, socket: std::net::UdpSocket, guest_port: u16) -> Result<Self> {
        if guest_port == 0 {
            bail!("forwarding a UDP socket needs a guest port");
        }
        self.net.udp_forwards.push((UdpFrom::Socket(std::sync::Arc::new(socket)), guest_port));
        Ok(self)
    }

    /// [`forward`](Self::forward) or [`forward_udp`](Self::forward_udp) as
    /// `grix run -p` spells it: `[ADDR:]HOSTPORT:GUESTPORT`, with `/udp`
    /// after it for UDP (see [`Publish`]).
    pub fn publish(self, spec: &str) -> Result<Self> {
        let p = Publish::parse(spec)?;
        if p.udp { self.forward_udp(&p.host, p.guest) } else { self.forward(&p.host, p.guest) }
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

    /// Where grix is installed (as a release unpacks: `grix`, `grix-vmm`
    /// and `grix-kernel` together), for programs that aren't `grix`
    /// themselves (the Python module): the kernel and grix-vmm are looked
    /// for there instead of beside the running program, unless
    /// `GRIX_KERNEL` or `GRIX_VMM` say otherwise.
    pub fn install_dir(mut self, dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        self.kernel = kernel_in(Some(dir), self.arch);
        self.vmm = vmm_for(Some(dir), self.arch);
        self.install = Some(dir.to_path_buf());
        self
    }

    /// The grix kernel installed for the guest's architecture (the one
    /// `kernel` replaces, an image's for instance).
    pub fn installed_kernel(&self) -> PathBuf {
        match &self.install {
            Some(dir) => kernel_in(Some(dir), self.arch),
            None => default_kernel(self.arch),
        }
    }

    /// The guest's architecture: the host's, `GRIX_ARCH`'s, `arch`'s or
    /// an image's.
    pub fn guest_arch(&self) -> Arch {
        self.arch
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
        crate::container::check_programs(&image.files, &c.command, self.arch)?;
        for e in &c.env {
            let (k, v) = e.split_once('=').unwrap_or((e, ""));
            self.env.retain(|(key, _)| key != k);
            self.env.push((k.to_string(), v.to_string()));
        }
        for name in &c.capabilities {
            let cap = Capability::from_name(name).with_context(|| format!("unknown capability {name:?}"))?;
            // What reaches beyond the sandbox, an image may only ask for.
            if !matches!(cap, Capability::Net | Capability::NetRaw) {
                self.policy.grant(cap);
            }
        }
        let (_, bytes) = image.size();
        let needed = (RESERVED_LOW + bytes + MIN_FREE).div_ceil(1 << 20) + 128;
        self.memory_mb = self.memory_mb.max(needed).max(c.memory_mb.unwrap_or(0));
        self.command = c.command.clone();
        Ok(self)
    }

    /// An image's files, kernel and working directory, and its kernel's
    /// architecture: the machine is that one's, unless one was chosen
    /// (`GRIX_ARCH`, [`arch`](Self::arch)) and it isn't.
    pub(crate) fn image_files_only(mut self, image: &crate::Image) -> Result<Self> {
        let arch = image.arch()?;
        if arch != self.arch {
            if let Some(who) = self.arch_chosen_by {
                bail!(
                    "the image is for {arch} (its kernel is), and {who} asks for {}: an image runs on its own \
                     architecture, so leave {who} out (or build the image for {} with `grix build --arch {}`)",
                    self.arch,
                    self.arch,
                    self.arch
                );
            }
            self = self.switch_arch(arch);
        }
        self.image_arch = Some(arch);
        for (path, node) in &image.files {
            self.files.insert(path.clone(), node.clone());
        }
        if let Some(cwd) = &image.config.cwd {
            self.cwd = cwd.clone();
        }
        if let Some(user) = &image.config.user {
            (self.uid, self.gid) = crate::container::resolve_user(user, &image.files)?;
        }
        // What Docker puts in a container's environment unless the image
        // sets it (the image's own environment comes after this).
        let home = crate::container::home_dir(self.uid, &image.files);
        self = self.env("HOME", home);
        let hostname = self.hostname.clone().unwrap_or_else(|| grix_abi::HOSTNAME.into());
        self = self.env("HOSTNAME", hostname);
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

    /// The guest's architecture (the host's by default, or `GRIX_ARCH`'s):
    /// its kernel, QEMU and accelerator follow. Programs must be built for
    /// it. Another architecture than the host's is emulated (slowly).
    /// An image's architecture is its kernel's: choosing another for it
    /// fails the build.
    pub fn arch(mut self, arch: Arch) -> Self {
        self.arch_chosen_by = Some("--arch");
        if arch != self.arch {
            self = self.switch_arch(arch);
        }
        self
    }

    /// Run `arch`'s guests: its kernel, QEMU, accelerator and grix-vmm.
    fn switch_arch(mut self, arch: Arch) -> Self {
        self.arch = arch;
        self.kernel = self.installed_kernel();
        self.qemu = arch.default_qemu();
        // GRIX_ACCEL's, for the host's own: another's is emulated.
        self.accel = match std::env::var("GRIX_ACCEL") {
            Ok(a) if !a.is_empty() && arch == Arch::host() => a,
            _ => default_accel_for(arch).into(),
        };
        self.vmm = match &self.install {
            Some(dir) => vmm_for(Some(dir), arch),
            None => default_vmm_for(arch),
        };
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

    /// What a run boots, and in what: "an x86_64 machine in grix-vmm",
    /// "an aarch64 machine in qemu-system-aarch64 (tcg)".
    pub fn machine(&self) -> String {
        match &self.vmm {
            Some(_) => format!("an {} machine in grix-vmm", self.arch),
            None => format!("an {} machine in {} ({})", self.arch, self.qemu.display(), self.accel),
        }
    }

    /// Why a run will emulate a machine this host could run natively, if
    /// it will: grix fell back on QEMU's emulator (installed) because
    /// /dev/kvm can't be opened, and this is that error. None when there's
    /// KVM, when `GRIX_ACCEL` asked for QEMU, and for another
    /// architecture's guest.
    pub fn emulated_without_kvm(&self) -> Option<std::io::Error> {
        if self.vmm.is_some() || self.accel != "tcg" || std::env::var_os("GRIX_ACCEL").is_some_and(|v| !v.is_empty()) {
            return None;
        }
        kvm_error(self.arch).filter(|_| runnable(&self.qemu))
    }

    pub fn build(mut self) -> Result<Sandbox> {
        if self.default_env {
            // The home /etc/passwd gives the user: the imported one, or
            // the one the kernel writes (root's, or grix's).
            let home = match (self.files.contains_key("/etc/passwd"), self.uid) {
                (true, uid) => crate::container::home_dir(uid, &self.files),
                (false, 0) => "/root".into(),
                (false, _) => "/home/grix".into(),
            };
            let path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
            for (key, value) in [("HOME", home.as_str()), ("PATH", path), ("LANG", "C.UTF-8"), ("TMPDIR", "/tmp")] {
                if !self.env.iter().any(|(k, _)| k == key) {
                    self.env.push((key.into(), value.into()));
                }
            }
        }
        if self.host_timezone {
            self = match crate::timezone::host_zone()? {
                crate::timezone::Zone::Named { name, data } => {
                    let path = format!("/usr/share/zoneinfo/{name}");
                    self.file(&path, data, 0o644)?.symlink("/etc/localtime", &path)?
                }
                crate::timezone::Zone::File(data) => self.file("/etc/localtime", data, 0o644)?,
                // (A `TZ` of the program's own is its own.)
                crate::timezone::Zone::Rule(_) if self.env.iter().any(|(k, _)| k == "TZ") => self,
                crate::timezone::Zone::Rule(rule) => self.env("TZ", rule),
            };
        }
        match self.network {
            Some(Network::None) if self.policy.allows(Capability::Net) => {
                bail!("`net` is granted and the network is none: one or the other")
            }
            Some(Network::Native | Network::Vm) => self.policy.grant(Capability::Net),
            _ => {}
        }
        // `arch` after `image`: the image's programs and kernel are another's.
        if let Some(image) = self.image_arch.filter(|&a| a != self.arch) {
            bail!("the image is for {image}, and --arch asks for {}: an image runs on its own architecture", self.arch);
        }
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
        let ram = self.memory_mb.saturating_mul(1 << 20);
        let imported = image::imported_bytes(&self.files);
        check_imports_fit(imported, "imports")?;
        let needed = RESERVED_LOW + imported + MIN_FREE;
        if ram < needed {
            bail!(
                "memory_mb = {} is too small for {} MiB of imports (need at least {} MiB)",
                self.memory_mb,
                imported >> 20,
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

/// The boot image holds what's imported, and must fit below 4 GiB of guest
/// memory however much RAM there is (`image::LOW_RAM`).
fn check_imports_fit(imported: u64, what: &str) -> Result<()> {
    if RESERVED_LOW + imported > LOW_RAM {
        bail!(
            "{} MiB of {what}: they're in the boot image, which must fit below 4 GiB of guest memory, so at most \
             {} MiB can be (mount big directories live instead)",
            imported >> 20,
            (LOW_RAM - RESERVED_LOW) >> 20
        );
    }
    Ok(())
}

/// Which network stack a sandbox has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// None at all: no sockets, whatever an image asks for.
    None,
    /// The host's: a socket's connection is one the host's proxy makes. What
    /// [`Capability::Net`] gives unless told otherwise.
    Native,
    /// The sandbox's own TCP/IP, in its kernel, with IP packets on the
    /// console. A gateway on the host ends them and asks the same proxy for
    /// the same connections, so the same policy holds.
    Vm,
}

impl Network {
    pub fn parse(s: &str) -> Result<Network> {
        match s {
            "none" => Ok(Network::None),
            "native" => Ok(Network::Native),
            "vm" => Ok(Network::Vm),
            _ => bail!("network {s:?}: it's none, native or vm"),
        }
    }

    /// `GRIX_NETWORK`'s, if it names one.
    fn env() -> Option<Network> {
        std::env::var("GRIX_NETWORK").ok().and_then(|n| Network::parse(&n).ok())
    }
}

/// A reusable sandbox configuration. Each [`run`](Sandbox::run) boots a fresh VM.
#[derive(Clone)]
pub struct Sandbox {
    cfg: SandboxBuilder,
}

impl SandboxBuilder {
    fn vm_stack(&self) -> bool {
        self.policy.allows(Capability::Net) && self.network.or(Network::env()) == Some(Network::Vm)
    }
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
    ) -> Result<(RunOutput, Option<Vec<u8>>)> {
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
        check_imports_fit(imported, "imports and mounts")?;
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
        let vm_stack = cfg.vm_stack();
        // Where the GIC's redistributors are (arm64 only).
        let gicr = match cfg.arch {
            Arch::X86_64 => 0,
            _ if cfg.vmm.is_some() => machine::GICR_GRIX_VMM,
            _ => machine::GICR_QEMU,
        };
        let bytes = Image {
            ram_size: cfg.memory_mb << 20,
            gicr,
            boot_time_ns,
            seed,
            policy: cfg.policy,
            uid: cfg.uid,
            gid: cfg.gid,
            cwd: &cfg.cwd,
            stdin: stdin.is_some() || take.is_some() || cfg.tty.is_some(),
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
                .map(|m| grix_abi::image::LiveMount { path: &m.guest, writable: m.writable, lazy: m.lazy })
                .collect(),
            forwards: cfg.net.forwards.iter().map(|&(_, port)| port).collect(),
            udp_forwards: cfg.net.udp_forwards.iter().map(|&(_, port)| port).collect(),
            vm_stack,
            snapshot: take.is_some(),
            cpus: cfg.cpus,
            x86_64: cfg.x86_64.as_deref().unwrap_or(""),
            tty: cfg.tty,
            hostname: cfg.hostname.as_deref().unwrap_or(grix_abi::HOSTNAME),
        }
        .encode();
        let exports = Collector::new(&cfg.exports, &mount_dirs, cfg.max_export as u64);
        let mut net = cfg.net.clone();
        net.enabled = cfg.policy.allows(Capability::Net);
        net.icmp = net.enabled && cfg.policy.allows(Capability::NetRaw);
        let vm = VmConfig {
            net,
            vm_stack,
            control: cfg.control.clone(),
            metrics: cfg.metrics.clone(),
            grace: cfg.grace,
            live: cfg.live.clone(),
            arch: cfg.arch,
            qemu: cfg.qemu.clone(),
            kernel: cfg.kernel.clone(),
            memory_mb: cfg.memory_mb,
            accel: cfg.accel.clone(),
            vmm: cfg.vmm.clone(),
            cpus: cfg.cpus,
            snapshot: take.map(SnapshotFile::Take),
            fs_state: None,
        };
        // A snapshot is taken while the program waits for stdin, which
        // must neither come nor end. A terminal with nothing to type gets
        // end-of-file (^D, see the kernel's tty.rs).
        let stdin = if vm.snapshot.is_some() { None } else { stdin };
        let stdin = match stdin {
            None if cfg.tty.is_some() && vm.snapshot.is_none() => {
                Some(Box::new(std::io::empty()) as Box<dyn Read + Send>)
            }
            s => s,
        };
        let (mut out, changes, taken) = execute(&vm, &bytes, cfg.timeout, stdin, exports, cfg.max_output, on_output)?;
        out.mount_changes = cfg.mounts.iter().zip(&mounted).zip(changes).map(|((m, i), c)| i.apply(m, c)).collect();
        Ok((out, taken))
    }

    /// Run `argv` until it first waits for input, and save the whole machine
    /// to `path` there: each [`Snapshot::run`](crate::Snapshot::run) then
    /// starts from that moment (see [`crate::snapshot`]). Needs grix-vmm
    /// on macOS; the sandbox can't have mounts applied when it ends
    /// ([`mount_on_exit`](SandboxBuilder::mount_on_exit)), or listeners
    /// from [`forward_listener`](SandboxBuilder::forward_listener). Live
    /// mounts are kept: each run gives them their host directories again
    /// ([`Snapshot::mount`](crate::Snapshot::mount)).
    pub fn snapshot<S: AsRef<str>>(&self, argv: &[S], path: impl AsRef<Path>) -> Result<crate::Snapshot> {
        self.snapshot_real(argv, &image::real_dirs(path.as_ref())?)
    }

    /// [`snapshot`](Self::snapshot) to a path whose directories are real
    /// ones already, which nothing resolves again (see `import_real`).
    pub(crate) fn snapshot_real<S: AsRef<str>>(&self, argv: &[S], path: &Path) -> Result<crate::Snapshot> {
        let cfg = &self.cfg;
        if cfg.vmm.is_none() {
            bail!(
                "snapshots need grix's own VMM (grix-vmm: Hypervisor.framework on macOS 15+, KVM on Linux 6.4+), not QEMU"
            );
        }
        if !cfg.mounts.is_empty() {
            bail!("a sandbox with on-exit mounts can't be snapshotted: what the host holds for them isn't saved");
        }
        let mut forwards = Vec::new();
        for (from, port) in &cfg.net.forwards {
            match from {
                ForwardFrom::Addr(a) => forwards.push((a.to_string(), *port)),
                ForwardFrom::Listener(_) => bail!("a forwarded listener can't be saved in a snapshot (use forward)"),
            }
        }
        let mut udp_forwards = Vec::new();
        for (from, port) in &cfg.net.udp_forwards {
            match from {
                UdpFrom::Addr(a) => udp_forwards.push((a.to_string(), *port)),
                UdpFrom::Socket(_) => bail!("a forwarded UDP socket can't be saved in a snapshot (use forward_udp)"),
            }
        }
        let settings = crate::snapshot::Settings {
            abi: grix_abi::ABI_VERSION,
            net: cfg.policy.allows(Capability::Net),
            allow_hosts: cfg.net.allow.as_ref().map(|rules| rules.iter().map(|r| r.to_string()).collect()),
            forwards,
            udp_forwards,
            exports: cfg.exports.clone(),
            max_export: cfg.max_export,
            max_output: cfg.max_output,
            timeout_ms: cfg.timeout.as_millis().try_into().unwrap_or(u64::MAX),
            grace_ms: cfg.grace.as_millis().try_into().unwrap_or(u64::MAX),
            memory_mb: cfg.memory_mb,
            cpus: cfg.cpus,
            vm_stack: cfg.vm_stack(),
            tty: cfg.tty.is_some(),
            live: cfg
                .live
                .iter()
                .map(|m| crate::snapshot::SavedMount { guest: m.guest.clone(), writable: m.writable, lazy: m.lazy })
                .collect(),
            fs_state: String::new(),
        };
        // Written to a new file of our own (it holds the program's memory:
        // only we may read it), then renamed into place: never through a
        // link, and never over a snapshot runs may still be mapping. In the
        // directory it goes in, held open from the start, so whatever is
        // swapped in on the way there meanwhile can't move it elsewhere.
        path.file_name().context("the snapshot needs a file name")?;
        let (dir, name) =
            crate::at::open_parent(path).with_context(|| format!("the directory for {}", path.display()))?;
        let temp = crate::at::cname(
            format!(".{}.{}.tmp", name.to_string_lossy(), crate::container::random_suffix()).as_ref(),
        )?;
        let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
        let file = std::fs::File::from(
            crate::at::openat(dir.as_raw_fd(), &temp, flags, 0o600)
                .with_context(|| format!("creating a file beside {}", path.display()))?,
        );
        let cleanup = TempAt(dir, temp);
        let mut keep = file.try_clone()?;
        let (out, taken) = self.run_mode(argv, None, Some(file), |_, _| {})?;
        // The VMM ends the run once it has written the machine out; the
        // program ending, the time running out (or anything else) means
        // there's no snapshot.
        let Some(fs_state) = taken else {
            let events: Vec<String> = out.events.iter().map(|e| e.to_string()).collect();
            bail!(
                "no snapshot: the program didn't wait for input ({:?})\n{}{}",
                out.status,
                events.join("\n"),
                out.stderr_str()
            );
        };
        let mut settings = settings;
        settings.fs_state = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(fs_state)
        };
        crate::snapshot::finish(&mut keep, &settings)?;
        crate::at::rename(cleanup.0.as_raw_fd(), &cleanup.1, cleanup.0.as_raw_fd(), &name, false, false)
            .with_context(|| format!("writing {}", path.display()))?;
        std::mem::forget(cleanup);
        crate::Snapshot::open(path)
    }
}

/// Removes file `.1` in directory `.0` unless forgotten.
struct TempAt(std::os::fd::OwnedFd, std::ffi::CString);

impl Drop for TempAt {
    fn drop(&mut self) {
        let _ = crate::at::remove_at(self.0.as_raw_fd(), &self.1, false);
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
) -> Result<(RunOutput, Vec<crate::export::Changes>, Option<Vec<u8>>)> {
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
        guest_stats: None,
        host_usage: None,
    };
    let started = Instant::now();
    // Counted from here: a run that fails to start counts as an error.
    let mut recorder = vm.metrics.as_ref().map(Metrics::start);
    let max = max_output;
    // Keep up to `max` bytes; mark the stream once anything isn't kept.
    let keep = |buf: &mut Vec<u8>, truncated: &mut bool, payload: &[u8]| {
        let room = max.saturating_sub(buf.len()).min(payload.len());
        buf.extend_from_slice(&payload[..room]);
        *truncated |= room < payload.len();
    };
    let mut event_bytes = 0usize;
    let run = vmm::run(vm, image, timeout, stdin, |ch, payload| match ch {
        Channel::Stdout | Channel::Stderr => {
            let (stream, buf, truncated) = match ch {
                Channel::Stdout => (Stream::Stdout, &mut out.stdout, &mut out.stdout_truncated),
                _ => (Stream::Stderr, &mut out.stderr, &mut out.stderr_truncated),
            };
            keep(buf, truncated, payload);
            if let Some(r) = &recorder {
                r.output(stream, payload.len());
            }
            on_output(stream, payload);
        }
        Channel::Log => add_log(&mut out.kernel_log, &String::from_utf8_lossy(payload)),
        Channel::Stats => match GuestStats::decode(payload) {
            Ok(s) => {
                if let Some(r) = &mut recorder {
                    r.guest(&s);
                }
                out.guest_stats = Some(s);
            }
            Err(_) => add_log(&mut out.kernel_log, "[grix] undecodable stats from guest\n"),
        },
        Channel::Event => {
            event_bytes = event_bytes.saturating_add(payload.len());
            if event_bytes > MAX_EVENT_BYTES {
                if event_bytes - payload.len() <= MAX_EVENT_BYTES {
                    add_log(&mut out.kernel_log, "[grix] over 4 MiB of events from the guest: the rest are dropped\n");
                }
                // Still counted (a fixed set of series): a server's
                // metrics shouldn't stop after its first 4 MiB of events.
                if let (Some(m), Ok(e)) = (&vm.metrics, Event::decode(payload)) {
                    m.event(&e.into());
                }
                return;
            }
            match Event::decode(payload) {
                Ok(e) => {
                    let e: GuestEvent = e.into();
                    if let Some(m) = &vm.metrics {
                        m.event(&e);
                    }
                    if let Some(c) = &vm.control {
                        c.event(&e);
                    }
                    out.events.push(e);
                }
                Err(_) => add_log(&mut out.kernel_log, "[grix] undecodable event from guest\n"),
            }
        }
        Channel::Export => exports.push(payload),
        Channel::Exit | Channel::Link | Channel::Fs | Channel::Packet => {}
    })?;
    // The host's own events (network policy) were passed on as they came.
    out.events.extend(run.events);
    out.host_usage = run.usage;
    let run_timed_out = run.timed_out;
    let (exported, changes) = exports.finish();
    out.exports = exported;
    out.duration = started.elapsed();
    // Taken: with what the host must keep of its live mounts.
    let taken = (vm.snapshot.is_some() && !run_timed_out && matches!(run.end, VmEnd::Lost { vmm_status: Some(0), .. }))
        .then(|| run.fs_state.clone().unwrap_or_default());
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
    if let Some(r) = recorder {
        r.finish(&out);
    }
    Ok((out, changes, taken))
}

/// What's kept of the kernel's log, and of its events (each one a frame,
/// at most `wire::MAX_FRAME`): a guest that floods them mustn't take the
/// host's memory, as `max_output` bounds the program's own output.
const MAX_KERNEL_LOG: usize = 4 << 20;
const MAX_EVENT_BYTES: usize = 4 << 20;

/// Add `text` to the kernel's log, up to MAX_KERNEL_LOG, and say once if
/// the rest is dropped.
fn add_log(log: &mut String, text: &str) {
    let Some(room) = MAX_KERNEL_LOG.checked_sub(log.len()) else { return };
    if text.len() <= room {
        log.push_str(text);
        return;
    }
    let mut cut = room;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    log.push_str(&text[..cut]);
    log.push_str("\n[grix] over 4 MiB of kernel log: the rest is dropped\n");
}

/// A run restored from `snap`, with `stdin`.
pub(crate) fn run_snapshot(
    snap: &crate::Snapshot,
    stdin: Box<dyn Read + Send>,
    on_output: impl FnMut(Stream, &[u8]),
) -> Result<RunOutput> {
    let s = &snap.settings;
    let file = std::fs::File::open(snap.path()).with_context(|| format!("opening {}", snap.path().display()))?;
    let mut net = NetPolicy {
        icmp: false,
        enabled: s.net,
        allow: s
            .allow_hosts
            .as_ref()
            .map(|rules| rules.iter().map(|r| HostRule::parse(r)).collect::<Result<Vec<_>>>())
            .transpose()?,
        forwards: Vec::new(),
        udp_forwards: Vec::new(),
    };
    for (addr, port) in &s.forwards {
        let a = addr.parse().with_context(|| format!("forward address {addr:?} in the snapshot"))?;
        net.forwards.push((ForwardFrom::Addr(a), *port));
    }
    for (addr, port) in &s.udp_forwards {
        let a = addr.parse().with_context(|| format!("UDP forward address {addr:?} in the snapshot"))?;
        net.udp_forwards.push((UdpFrom::Addr(a), *port));
    }
    let (live, fs_state) = snap.live_mounts()?;
    let vm = VmConfig {
        net,
        vm_stack: s.vm_stack,
        control: snap.control.clone(),
        metrics: snap.metrics.clone(),
        grace: Duration::from_millis(s.grace_ms),
        live,
        arch: Arch::Aarch64,
        qemu: PathBuf::new(),
        kernel: PathBuf::new(),
        memory_mb: s.memory_mb,
        accel: String::new(),
        vmm: Some(snap.vmm.clone().context(
            "snapshots need grix's own VMM (grix-vmm: Hypervisor.framework on macOS 15+, KVM on Linux 6.4+), not QEMU",
        )?),
        cpus: s.cpus,
        snapshot: Some(SnapshotFile::Restore(file)),
        fs_state,
    };
    let exports = Collector::new(&s.exports, &[], s.max_export as u64);
    Ok(execute(&vm, &[], snap.timeout, Some(stdin), exports, s.max_output, on_output)?.0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn the_kernel_log_is_bounded() {
        let mut log = String::new();
        // Multi-byte characters: cut at a boundary.
        let line = "é".repeat(1000);
        while log.len() < MAX_KERNEL_LOG {
            add_log(&mut log, &line);
        }
        let len = log.len();
        assert!(len <= MAX_KERNEL_LOG + 100 && log.ends_with("the rest is dropped\n"), "{len}");
        add_log(&mut log, "more");
        assert_eq!(log.len(), len);
    }

    /// The start of a 64-bit little-endian ELF file for `machine`.
    pub(crate) fn elf(machine: u16) -> Vec<u8> {
        let mut e = b"\x7fELF\x02\x01\x01".to_vec();
        e.resize(64, 0);
        e[18..20].copy_from_slice(&machine.to_le_bytes());
        e
    }

    fn other() -> Arch {
        match Arch::host() {
            Arch::Aarch64 => Arch::X86_64,
            Arch::X86_64 => Arch::Aarch64,
        }
    }

    fn elf_for(arch: Arch) -> Vec<u8> {
        elf(match arch {
            Arch::Aarch64 => EM_AARCH64,
            Arch::X86_64 => EM_X86_64,
        })
    }

    #[test]
    fn architectures_of_elf_files() {
        assert_eq!(Arch::of_elf(&elf(183)), Some(Arch::Aarch64));
        assert_eq!(Arch::of_elf(&elf(62)), Some(Arch::X86_64));
        // Another machine, 32-bit, big-endian, cut off or not ELF at all.
        assert_eq!(Arch::of_elf(&elf(40)), None);
        let mut e32 = elf(62);
        e32[4] = 1;
        assert_eq!(Arch::of_elf(&e32), None);
        let mut big = elf(183);
        big[5] = 2;
        assert_eq!(Arch::of_elf(&big), None);
        assert_eq!(Arch::of_elf(&elf(62)[..19]), None);
        assert_eq!(Arch::of_elf(b"#!/bin/sh\n"), None);
        // The kernels this source tree builds, where they're built.
        for arch in [Arch::Aarch64, Arch::X86_64] {
            let path = Path::new(SOURCE_TREE.unwrap_or("/nowhere")).join(arch.kernel_names().1);
            if let Ok(kernel) = std::fs::read(&path) {
                assert_eq!(Arch::of_elf(&kernel), Some(arch), "{}", path.display());
            }
        }
        assert_eq!(Arch::parse("amd64"), Some(Arch::X86_64));
        assert_eq!(Arch::parse("arm64"), Some(Arch::Aarch64));
        assert_eq!(Arch::parse("riscv64"), None);
        assert_eq!((Arch::Aarch64.oci_name(), Arch::X86_64.oci_name()), ("arm64", "amd64"));
    }

    #[test]
    fn images_run_on_their_own_architecture() {
        let image = |arch: Arch| crate::Image::new(BTreeMap::new(), Default::default(), elf_for(arch));
        // Nobody chose: the image's architecture, emulated if it isn't the
        // host's, with the image's kernel.
        let b = SandboxBuilder { arch_chosen_by: None, ..Default::default() };
        let b = b.image(&image(other())).unwrap();
        assert_eq!(b.guest_arch(), other());
        assert_eq!((b.accel.as_str(), b.vmm.is_none()), ("tcg", true));
        assert_eq!(std::fs::read(b.kernel_path()).unwrap(), elf_for(other()));
        assert_eq!(b.qemu, other().default_qemu());
        // GRIX_ARCH or --arch for another: an error, saying what to do.
        for who in ["GRIX_ARCH", "--arch"] {
            let mut b = SandboxBuilder::default().arch(Arch::host());
            b.arch_chosen_by = Some(who);
            let err = b.image(&image(other())).err().unwrap().to_string();
            assert!(err.contains(&format!("the image is for {}", other())) && err.contains(who), "{err}");
        }
        // The same as the image's: fine.
        assert!(SandboxBuilder::default().arch(other()).image(&image(other())).is_ok());
        // --arch after the image: the build fails.
        let b = SandboxBuilder { arch_chosen_by: None, ..Default::default() };
        let err = b.image(&image(other())).unwrap().arch(Arch::host()).build().err().unwrap().to_string();
        assert!(err.contains("an image runs on its own architecture"), "{err}");
    }

    #[test]
    fn kernels_boot_only_in_their_own_machine() {
        assert!(crate::vmm::check_machine(&elf(183), Arch::Aarch64).is_ok());
        assert!(crate::vmm::check_machine(&elf(62), Arch::X86_64).is_ok());
        let err = crate::vmm::check_machine(&elf(183), Arch::X86_64).unwrap_err().to_string();
        assert!(err.contains("it's for aarch64, and the machine about to boot it is x86_64's"), "{err}");
        assert!(crate::vmm::check_machine(&elf(62), Arch::Aarch64).is_err());
        assert!(crate::vmm::check_machine(b"not a kernel", Arch::Aarch64).is_err());
    }

    #[test]
    fn programs_must_be_the_kernels() {
        use crate::container::check_programs;
        let file = |data: Vec<u8>| Node::File { data, mode: 0o755, mtime_ns: 0 };
        let link = |t: &str| Node::Symlink { target: t.into(), mtime_ns: 0 };
        let mut files: BTreeMap<String, Node> = [
            ("/bin/busybox".to_string(), file(elf(183))),
            ("/bin/sh".to_string(), link("busybox")),
            ("/usr/bin/env".to_string(), link("../../bin/busybox")),
            ("/app/run.sh".to_string(), file(b"#!/bin/sh\necho hi\n".to_vec())),
            ("/app/amd".to_string(), file(elf(62))),
        ]
        .into_iter()
        .collect();
        let none: &[String] = &[];
        assert!(check_programs(&files, none, Arch::Aarch64).is_ok());
        // An x86_64 kernel with arm64 programs (what grix before images had
        // architectures built on x86_64 hosts): refused, naming one.
        let err = check_programs(&files, none, Arch::X86_64).unwrap_err().to_string();
        assert!(err.starts_with("/bin/sh is an aarch64 program, and the image's kernel is x86_64's"), "{err}");
        assert!(err.contains("grix build --arch aarch64"), "{err}");
        // The command's program, found on PATH, through links.
        let err = check_programs(&files, &["env".into()], Arch::X86_64).unwrap_err().to_string();
        assert!(err.starts_with("/usr/bin/env is an aarch64 program"), "{err}");
        // An x86_64 program in an arm64 image may run with a translator.
        assert!(check_programs(&files, &["/app/amd".into()], Arch::Aarch64).is_ok());
        let err = check_programs(&files, &["/app/amd".into()], Arch::X86_64).unwrap_err().to_string();
        assert!(err.starts_with("/bin/sh is an aarch64"), "{err}");
        // Scripts, and programs that aren't there, are the kernel's to judge.
        files.remove("/bin/busybox");
        assert!(check_programs(&files, &["/app/run.sh".into()], Arch::X86_64).is_ok());
        assert!(check_programs(&files, &["/nowhere".into()], Arch::X86_64).is_ok());
        // Links that go round in circles end.
        files.insert("/bin/sh".into(), link("/bin/sh"));
        assert!(check_programs(&files, none, Arch::X86_64).is_ok());
    }
}
