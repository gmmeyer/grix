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
//! a run isn't saved, so the snapshot waits until the program has no
//! connections or DNS lookups open through the host, and sandboxes with
//! mounts can't take one.
//!
//! Snapshots need grix's own VMM on macOS (Hypervisor.framework).
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
const MAX_SETTINGS: u64 = 1 << 20;

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
    pub exports: Vec<String>,
    pub max_export: usize,
    pub max_output: usize,
    pub timeout_ms: u64,
    pub grace_ms: u64,
    pub memory_mb: u64,
}

/// A saved machine to run from (see the module docs).
#[derive(Clone)]
pub struct Snapshot {
    path: PathBuf,
    pub(crate) settings: Settings,
    pub(crate) timeout: Duration,
    pub(crate) vmm: Option<PathBuf>,
    pub(crate) control: Option<crate::RunControl>,
    /// Guest RAM, as the VMM's header says (what a restored run maps).
    ram_size: u64,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("path", &self.path)
            .field("memory_mb", &self.memory_mb())
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
        let timeout = Duration::from_millis(settings.timeout_ms);
        Ok(Snapshot { path, settings, timeout, vmm: crate::sandbox::default_vmm(), control: None, ram_size })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The guest's memory, in MiB.
    pub fn memory_mb(&self) -> u64 {
        self.ram_size >> 20
    }

    /// The time limit runs get unless [`timeout`](Snapshot::timeout) says.
    pub fn default_timeout(&self) -> Duration {
        Duration::from_millis(self.settings.timeout_ms)
    }

    /// Only what this allows of the network, whatever the file says (for
    /// snapshots someone else wrote): no `net` unless `allowed`, then only
    /// to `allow_hosts` if there are any, and no forwarded ports.
    pub fn restrict_net(mut self, allowed: bool, allow_hosts: &[String]) -> Result<Self> {
        for rule in allow_hosts {
            crate::net::HostRule::parse(rule)?;
        }
        self.settings.net &= allowed;
        // The caller's rules only: none means anywhere but the special
        // addresses, as for a sandbox (the file's could name the host).
        self.settings.allow_hosts = (!allow_hosts.is_empty()).then(|| allow_hosts.to_vec());
        self.settings.forwards.clear();
        Ok(self)
    }

    /// At most this much of each of stdout and stderr is kept, and at most
    /// this much exported (or less, if the snapshot says so); and at most
    /// this long between the SIGTERM at the time limit and the stop.
    pub fn limits(mut self, max_output: usize, max_export: usize, grace: Duration) -> Self {
        let s = &mut self.settings;
        s.max_output = s.max_output.min(max_output);
        s.max_export = s.max_export.min(max_export);
        s.grace_ms = s.grace_ms.min(grace.as_millis() as u64);
        self
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

    fn snap(allow_hosts: Option<Vec<String>>, forwards: Vec<(String, u16)>) -> Snapshot {
        let settings = Settings {
            abi: grix_abi::ABI_VERSION,
            net: true,
            allow_hosts,
            forwards,
            exports: vec![],
            max_export: usize::MAX,
            max_output: usize::MAX,
            timeout_ms: 1000,
            grace_ms: u64::MAX,
            memory_mb: 512,
        };
        Snapshot { path: "x".into(), settings, timeout: Duration::ZERO, vmm: None, control: None, ram_size: 0 }
    }

    /// Whatever the file says, a caller's network policy and limits win.
    #[test]
    fn the_callers_policy_wins() {
        let crafted = || snap(Some(vec!["host.grix.internal".into()]), vec![("127.0.0.1:22".into(), 22)]);
        let s = crafted().restrict_net(true, &[]).unwrap();
        assert_eq!(s.settings.allow_hosts, None, "the file's rules are dropped");
        assert!(s.settings.forwards.is_empty());
        let s = crafted().restrict_net(true, &["pypi.org".into()]).unwrap();
        assert_eq!(s.settings.allow_hosts, Some(vec!["pypi.org".to_string()]));
        assert!(!crafted().restrict_net(false, &[]).unwrap().settings.net);
        let s = crafted().limits(10, 20, Duration::from_secs(5));
        assert_eq!((s.settings.max_output, s.settings.max_export, s.settings.grace_ms), (10, 20, 5000));
    }
}
