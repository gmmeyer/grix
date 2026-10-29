//! Snapshots: a sandbox's whole machine, saved the moment its program first
//! sits waiting for input, and runs restored from it.
//!
//! A runtime that takes a second to start (Python importing its libraries,
//! Node loading a bundle) is started once, by [`Sandbox::snapshot`]; each
//! [`Snapshot::run`] then begins where it waited, with its own stdin, in
//! milliseconds. The machine is restored copy-on-write from the file, so
//! runs don't see each other's changes, and the kernel's random number
//! generator is reseeded for each.
//!
//! What the program set up for itself before the snapshot is shared by
//! every run: a random seed it drew then, say. And what the host holds for
//! a run isn't all saved, so the snapshot waits until the program has no
//! connections or DNS lookups open through the host, and sandboxes with
//! on-exit mounts can't take one. Live mounts are kept (what the host
//! knows of them: the names it gave ids, and what the guest first saw of
//! lazy imports); each run gives them their host directories again
//! ([`Snapshot::mount`]).
//!
//! Snapshots need grix's own VMM (Hypervisor.framework on macOS 15+, KVM
//! on Linux 6.4+), and a snapshot runs only on the kind of host that took
//! it.
//!
//! File: what `grix-vmm` writes (machine state, then RAM), then the host's
//! settings for a restored run as JSON, its length (u64 LE), and
//! [`FOOTER`].

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::sandbox::RunOutput;

pub(crate) const FOOTER: &[u8; 8] = b"GRIXSNPH";
/// The VMM's part starts with this once it's complete.
pub(crate) const VMM_MAGIC: &[u8; 8] = b"GRIXSNP1";
/// The settings, live mounts' state included (lazy imports remember what
/// the guest saw of them).
const MAX_SETTINGS: u64 = 256 << 20;

/// What the host side of a restored run needs to be the same as the run
/// that took the snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Settings {
    /// `grix_abi::ABI_VERSION` of the kernel in the snapshot.
    pub abi: u32,
    pub net: bool,
    /// `allow_host` rules (none: anywhere but the host's own addresses).
    pub allow_hosts: Option<Vec<String>>,
    /// Forwarded ports: host address, guest port.
    pub forwards: Vec<(String, u16)>,
    /// Forwarded UDP ports, the same way.
    #[serde(default)]
    pub udp_forwards: Vec<(String, u16)>,
    pub exports: Vec<String>,
    pub max_export: usize,
    pub max_output: usize,
    pub timeout_ms: u64,
    pub grace_ms: u64,
    pub memory_mb: u64,
    /// The machine's CPUs (each run has as many).
    #[serde(default = "one_cpu")]
    pub cpus: u32,
    /// Taken in TTY mode: the program's stdio is a terminal.
    #[serde(default)]
    pub tty: bool,
    /// Live mounts, in the order the guest numbers them, and the host
    /// side's state for them (`hostfs::Server::save`, base64).
    #[serde(default)]
    pub live: Vec<SavedMount>,
    #[serde(default)]
    pub fs_state: String,
}

fn one_cpu() -> u32 {
    1
}

/// A live mount a snapshot has, which each run gives a host directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SavedMount {
    pub guest: String,
    pub writable: bool,
    pub lazy: bool,
}

/// A saved machine to run from (see the module docs).
///
/// A file may be anyone's, so what it says of the host side is only what
/// it asks for: runs from it get no network unless the caller allows it
/// ([`allow_net`](Snapshot::allow_net)), never the file's host rules or
/// forwarded ports, and the limits of a sandbox's defaults (or the file's,
/// if lower) unless the caller sets others, never above the file's.
#[derive(Clone)]
pub struct Snapshot {
    path: PathBuf,
    /// What runs get (the file's, restricted as above).
    pub(crate) settings: Settings,
    /// What the file asks for.
    asked: Asked,
    pub(crate) timeout: Duration,
    pub(crate) vmm: Option<PathBuf>,
    pub(crate) control: Option<crate::RunControl>,
    /// Guest RAM, as the VMM's header says (what a restored run maps).
    ram_size: u64,
    /// Host directories for its live mounts: (host, guest, read-only).
    mounts: Vec<(PathBuf, String, bool)>,
}

#[derive(Clone, Debug)]
struct Asked {
    net: bool,
    max_output: usize,
    max_export: usize,
    grace_ms: u64,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("path", &self.path)
            .field("memory_mb", &self.memory_mb())
            .field("cpus", &self.cpus())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Snapshot {
    /// A snapshot file `Sandbox::snapshot` (or `grix snapshot`) wrote.
    pub fn open(path: impl Into<PathBuf>) -> Result<Snapshot> {
        let path = path.into();
        let mut f = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let mut header = [0u8; 24];
        f.read_exact(&mut header).with_context(|| format!("reading {}", path.display()))?;
        if &header[..8] != VMM_MAGIC {
            bail!("{} isn't a complete grix snapshot", path.display());
        }
        let ram_size = u64::from_le_bytes(header[16..24].try_into().unwrap());
        let len = f.seek(SeekFrom::End(0))?;
        if len < 16 {
            bail!("{} isn't a complete grix snapshot", path.display());
        }
        let mut tail = [0u8; 16];
        f.seek(SeekFrom::End(-16))?;
        f.read_exact(&mut tail)?;
        let json_len = u64::from_le_bytes(tail[..8].try_into().unwrap());
        if &tail[8..] != FOOTER || json_len > MAX_SETTINGS || json_len + 16 > len {
            bail!("{} has no grix settings at its end (was it written completely?)", path.display());
        }
        let mut json = vec![0u8; json_len as usize];
        f.seek(SeekFrom::End(-16 - json_len as i64))?;
        f.read_exact(&mut json)?;
        let settings: Settings =
            serde_json::from_slice(&json).with_context(|| format!("the settings in {}", path.display()))?;
        if settings.abi != grix_abi::ABI_VERSION {
            bail!(
                "{} holds a kernel that speaks ABI {}; this grix speaks {} (take the snapshot again)",
                path.display(),
                settings.abi,
                grix_abi::ABI_VERSION
            );
        }
        if settings.cpus == 0 || settings.cpus > grix_abi::machine::MAX_CPUS {
            bail!("{} says it has {} CPUs", path.display(), settings.cpus);
        }
        let asked = Asked {
            net: settings.net,
            max_output: settings.max_output,
            max_export: settings.max_export,
            grace_ms: settings.grace_ms,
        };
        let mut settings = settings;
        settings.net = false;
        settings.allow_hosts = None;
        settings.forwards.clear();
        settings.udp_forwards.clear();
        let timeout = Duration::from_millis(settings.timeout_ms).min(crate::sandbox::DEFAULT_TIMEOUT);
        let snap = Snapshot {
            path,
            settings,
            asked,
            timeout,
            vmm: crate::sandbox::default_vmm(),
            control: None,
            ram_size,
            mounts: Vec::new(),
        };
        Ok(snap.limits(
            crate::sandbox::DEFAULT_MAX_OUTPUT,
            crate::sandbox::DEFAULT_MAX_EXPORT,
            crate::sandbox::DEFAULT_GRACE,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The guest's memory, in MiB.
    pub fn memory_mb(&self) -> u64 {
        self.ram_size >> 20
    }

    /// The machine's CPUs.
    pub fn cpus(&self) -> u32 {
        self.settings.cpus
    }

    /// The time limit the snapshot's sandbox had. Runs get it, or a
    /// sandbox's default if that's shorter, unless
    /// [`timeout`](Snapshot::timeout) says.
    pub fn default_timeout(&self) -> Duration {
        Duration::from_millis(self.settings.timeout_ms)
    }

    /// Did the snapshot's sandbox have `net` (its program may expect it)?
    pub fn asks_for_net(&self) -> bool {
        self.asked.net
    }

    /// Let runs from here use the network, if the snapshot's sandbox could:
    /// only to `allow_hosts`, if there are any, or anywhere but the host's
    /// own and other special addresses, as for a sandbox. The file's own
    /// rules are never used (they could name the host).
    pub fn allow_net(mut self, allow_hosts: &[String]) -> Result<Self> {
        for rule in allow_hosts {
            crate::net::HostRule::parse(rule)?;
        }
        self.settings.net = self.asked.net;
        self.settings.allow_hosts = (!allow_hosts.is_empty()).then(|| allow_hosts.to_vec());
        Ok(self)
    }

    /// Forward connections to `host` to `guest_port` in runs from here (see
    /// [`SandboxBuilder::forward`](crate::SandboxBuilder::forward)); the
    /// file's forwarded ports aren't.
    pub fn forward(mut self, host: &str, guest_port: u16) -> Result<Self> {
        let addr = crate::net::forward_addr(host, guest_port)?;
        self.settings.forwards.push((addr.to_string(), guest_port));
        Ok(self)
    }

    /// Forward UDP datagrams to `host` to `guest_port` in runs from here
    /// (see [`SandboxBuilder::forward_udp`](crate::SandboxBuilder::forward_udp));
    /// the file's forwarded ports aren't.
    pub fn forward_udp(mut self, host: &str, guest_port: u16) -> Result<Self> {
        let addr = crate::net::forward_addr(host, guest_port)?;
        self.settings.udp_forwards.push((addr.to_string(), guest_port));
        Ok(self)
    }

    /// [`forward`](Self::forward) or [`forward_udp`](Self::forward_udp) as
    /// `grix run -p` spells it (see [`Publish`](crate::Publish)).
    pub fn publish(self, spec: &str) -> Result<Self> {
        let p = crate::net::Publish::parse(spec)?;
        if p.udp { self.forward_udp(&p.host, p.guest) } else { self.forward(&p.host, p.guest) }
    }

    /// At most this much of each of stdout and stderr is kept, and at most
    /// this much exported; and at most this long between the SIGTERM at the
    /// time limit and the stop. Never more than the snapshot's sandbox had.
    pub fn limits(self, max_output: usize, max_export: usize, grace: Duration) -> Self {
        self.max_output(max_output).max_export(max_export).grace(grace)
    }

    /// See [`limits`](Snapshot::limits).
    pub fn max_output(mut self, bytes: usize) -> Self {
        self.settings.max_output = self.asked.max_output.min(bytes);
        self
    }

    /// See [`limits`](Snapshot::limits).
    pub fn max_export(mut self, bytes: usize) -> Self {
        self.settings.max_export = self.asked.max_export.min(bytes);
        self
    }

    /// See [`limits`](Snapshot::limits).
    pub fn grace(mut self, grace: Duration) -> Self {
        self.settings.grace_ms = self.asked.grace_ms.min(grace.as_millis().try_into().unwrap_or(u64::MAX));
        self
    }

    /// The live mounts each run needs a host directory for (`mount`): guest
    /// path, and whether it's writable.
    pub fn live_mounts_needed(&self) -> Vec<(&str, bool)> {
        self.settings.live.iter().map(|m| (m.guest.as_str(), m.writable)).collect()
    }

    /// Give live mount `guest` its host directory `host` for runs from
    /// here (each needs one): writable if it was.
    pub fn mount(self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        self.mount_with(host, guest, false)
    }

    /// Like [`mount`](Snapshot::mount), but read-only whatever it was
    /// (the program's writes there fail with EROFS).
    pub fn mount_read_only(self, host: impl AsRef<Path>, guest: &str) -> Result<Self> {
        self.mount_with(host, guest, true)
    }

    fn mount_with(self, host: impl AsRef<Path>, guest: &str, read_only: bool) -> Result<Self> {
        let host = host.as_ref();
        let real = host.canonicalize().with_context(|| format!("mounting {}", host.display()))?;
        self.mount_real(real, guest, read_only)
    }

    /// Mount a canonical path, which nothing resolves again (see
    /// `SandboxBuilder::mount_real`).
    pub(crate) fn mount_real(mut self, real: PathBuf, guest: &str, read_only: bool) -> Result<Self> {
        if !self.settings.live.iter().any(|m| m.guest == guest) {
            let have: Vec<&str> = self.settings.live.iter().map(|m| m.guest.as_str()).collect();
            bail!("the snapshot has no live mount at {guest} (it has {have:?})");
        }
        crate::at::open_dir(&real).with_context(|| format!("{} isn't a directory", real.display()))?;
        self.mounts.retain(|m| m.1 != guest);
        self.mounts.push((real, guest.to_string(), read_only));
        Ok(self)
    }

    /// The live mounts for a run, in the guest's order, and the host side's
    /// state for them.
    pub(crate) fn live_mounts(&self) -> Result<(Vec<crate::hostfs::LiveMount>, Option<Vec<u8>>)> {
        if self.settings.live.is_empty() {
            return Ok((Vec::new(), None));
        }
        let mut live = Vec::new();
        for m in &self.settings.live {
            let Some((host, _, read_only)) = self.mounts.iter().find(|x| x.1 == m.guest) else {
                bail!(
                    "the snapshot has a live mount at {}: give it a host directory (Snapshot::mount, --mount HOST:{})",
                    m.guest,
                    m.guest
                );
            };
            live.push(crate::hostfs::LiveMount {
                host: host.clone(),
                guest: m.guest.clone(),
                writable: m.writable && !read_only,
                lazy: m.lazy,
            });
        }
        let state = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(&self.settings.fs_state)
                .context("the snapshot's mount state is bad")?
        };
        Ok((live, Some(state)))
    }

    /// Taken in TTY mode: the program's stdio is a terminal (its size comes
    /// from [`RunControl::resize`](crate::RunControl::resize)), and stdin
    /// is what's typed into it.
    pub fn tty(&self) -> bool {
        self.settings.tty
    }

    /// The directories a run from here sends back when the program ends
    /// (those the sandbox exported).
    pub fn exports(&self) -> &[String] {
        &self.settings.exports
    }

    /// How long each run may take (by default the sandbox's).
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Signal or stop runs from here (see [`RunControl`](crate::RunControl)).
    pub fn control(mut self, control: &crate::RunControl) -> Self {
        self.control = Some(control.clone());
        self
    }

    /// Run in this `grix-vmm`.
    /// Look for grix-vmm in `dir`, where grix is installed, instead of
    /// beside the running program (see
    /// [`SandboxBuilder::install_dir`](crate::SandboxBuilder::install_dir)).
    pub fn install_dir(mut self, dir: impl AsRef<std::path::Path>) -> Self {
        self.vmm = crate::sandbox::vmm_in(Some(dir.as_ref()));
        self
    }

    pub fn vmm(mut self, path: impl Into<PathBuf>) -> Self {
        self.vmm = Some(path.into());
        self
    }

    /// Restore the machine and give the program `input` as stdin, from
    /// where it was waiting.
    pub fn run(&self, input: impl Into<Vec<u8>>) -> Result<RunOutput> {
        crate::sandbox::run_snapshot(self, Box::new(std::io::Cursor::new(input.into())), |_, _| {})
    }

    /// Like [`run`](Snapshot::run), reading stdin from `stdin` as the
    /// program asks for it and passing output to `on_output` as it comes.
    pub fn run_streaming(
        &self,
        stdin: impl Read + Send + 'static,
        on_output: impl FnMut(crate::Stream, &[u8]),
    ) -> Result<RunOutput> {
        crate::sandbox::run_snapshot(self, Box::new(stdin), on_output)
    }
}

/// Finish the file the VMM wrote: check it's complete, add the settings.
pub(crate) fn finish(file: &mut File, settings: &Settings) -> Result<()> {
    let mut magic = [0u8; 8];
    file.seek(SeekFrom::Start(0))?;
    if file.read_exact(&mut magic).is_err() || &magic != VMM_MAGIC {
        bail!("the VMM didn't finish writing the snapshot");
    }
    let json = serde_json::to_vec(settings)?;
    file.seek(SeekFrom::End(0))?;
    file.write_all(&json)?;
    file.write_all(&(json.len() as u64).to_le_bytes())?;
    file.write_all(FOOTER)?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snapshot file whose settings ask for everything: the network
    /// with the host's own loopback, a forwarded port on every address, no
    /// limits.
    fn crafted() -> Snapshot {
        let settings = Settings {
            abi: grix_abi::ABI_VERSION,
            net: true,
            allow_hosts: Some(vec!["host.grix.internal".into(), "127.0.0.0/8".into()]),
            forwards: vec![("0.0.0.0:8080".into(), 80)],
            udp_forwards: vec![("0.0.0.0:5353".into(), 53)],
            exports: vec![],
            max_export: usize::MAX,
            max_output: usize::MAX,
            timeout_ms: u64::MAX,
            grace_ms: u64::MAX,
            memory_mb: 512,
            cpus: 1,
            tty: false,
            live: vec![],
            fs_state: String::new(),
        };
        let path = std::env::temp_dir().join(format!("grix-snapshot-test-{}", std::process::id()));
        let mut f = File::options().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        f.write_all(VMM_MAGIC).unwrap();
        f.write_all(&[0; 8]).unwrap();
        f.write_all(&(512u64 << 20).to_le_bytes()).unwrap();
        finish(&mut f, &settings).unwrap();
        let snap = Snapshot::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        snap
    }

    /// Whatever the file says, runs get the caller's network policy and
    /// limits: by default no network, and a sandbox's default limits.
    #[test]
    fn the_callers_policy_wins() {
        let s = crafted();
        assert!(s.asks_for_net());
        assert!(!s.settings.net && s.settings.allow_hosts.is_none() && s.settings.forwards.is_empty());
        assert!(s.settings.udp_forwards.is_empty());
        assert_eq!(s.settings.max_output, crate::sandbox::DEFAULT_MAX_OUTPUT);
        assert_eq!(s.settings.max_export, crate::sandbox::DEFAULT_MAX_EXPORT);
        assert_eq!(s.settings.grace_ms, crate::sandbox::DEFAULT_GRACE.as_millis() as u64);
        assert_eq!(s.timeout, crate::sandbox::DEFAULT_TIMEOUT);
        // Allowed, the network has the caller's rules only.
        let s = crafted().allow_net(&[]).unwrap();
        assert!(s.settings.net && s.settings.allow_hosts.is_none() && s.settings.forwards.is_empty());
        let s = crafted().allow_net(&["pypi.org".into()]).unwrap().forward("127.0.0.1:0", 80).unwrap();
        assert_eq!(s.settings.allow_hosts, Some(vec!["pypi.org".to_string()]));
        assert_eq!(s.settings.forwards, [("127.0.0.1:0".to_string(), 80)]);
        assert!(s.settings.udp_forwards.is_empty());
        let s = crafted().allow_net(&[]).unwrap().publish("127.0.0.1:0:53/udp").unwrap();
        assert_eq!(s.settings.udp_forwards, [("127.0.0.1:0".to_string(), 53)]);
        assert!(s.settings.forwards.is_empty());
        // Limits are the caller's, up to the file's.
        let s = crafted().limits(10, 20, Duration::from_secs(1));
        assert_eq!((s.settings.max_output, s.settings.max_export, s.settings.grace_ms), (10, 20, 1000));
        let s = crafted().max_output(1 << 30);
        assert_eq!(s.settings.max_output, 1 << 30);
    }
}
