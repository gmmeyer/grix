//! TOML manifests: a declarative description of a sandbox.
//!
//! ```toml
//! command = ["/bin/hello", "world"]
//! capabilities = []          # fs_write, threads, process, net, net_raw
//! network = "vm"             # none, native (what `net` gives) or vm
//! on_deny = "errno"          # or "kill"
//! memory_mb = 256
//! hostname = "worker-1"      # grix unless given
//! default_env = true         # HOME, PATH, LANG and TMPDIR unless set
//! host_timezone = true        # the host's time zone, not UTC
//! timeout_secs = 30        # 0: no time limit (a server)
//! grace_secs = 5             # after the time limit: SIGTERM, then this long to end
//! max_export_mb = 256
//!
//! [env]
//! GREETING = "hi"
//!
//! [[import]]
//! host = "build/hello"       # relative to this manifest
//! guest = "/bin/hello"
//!
//! allow_hosts = ["pypi.org", "*.pythonhosted.org"]   # with net: only these
//!
//! [[forward]]                # host 127.0.0.1:8080 -> port 8000 in the sandbox
//! host = "127.0.0.1:8080"
//! guest = 8000
//! protocol = "tcp"           # or "udp"
//!
//! [[export]]                 # copied out when the program ends (CLI)
//! guest = "/out"
//! host = "results"           # relative to this manifest; must not exist yet
//!
//! [[mount]]                  # live and read-write
//! host = "."                 # relative to this manifest
//! guest = "/work"
//! mode = "rw"                # or "ro", "on_exit" (changes applied when it ends),
//!                            # or "lazy" (imported without copying it in)
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use grix_abi::policy::{Capability, DenyAction};
use serde::Deserialize;

use crate::sandbox::{MountMode, SandboxBuilder};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// A grix image to run (`grix build`), relative to the manifest.
    pub image: Option<PathBuf>,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub on_deny: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub hostname: Option<String>,
    #[serde(default)]
    pub default_env: bool,
    #[serde(default)]
    pub host_timezone: bool,
    /// The network stack: none, native or vm.
    pub network: Option<String>,
    pub memory_mb: Option<u64>,
    /// 0: no time limit.
    pub timeout_secs: Option<u64>,
    /// After the time limit, seconds to end after SIGTERM.
    pub grace_secs: Option<u64>,
    pub max_export_mb: Option<usize>,
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default, rename = "forward")]
    pub forwards: Vec<Forward>,
    #[serde(default, rename = "import")]
    pub imports: Vec<Import>,
    #[serde(default, rename = "export")]
    pub exports: Vec<ExportTo>,
    #[serde(default, rename = "mount")]
    pub mounts: Vec<MountSpec>,
}

/// A host directory to mount, and how.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountSpec {
    pub host: PathBuf,
    pub guest: String,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub host: PathBuf,
    pub guest: String,
}

/// A host address whose connections (or UDP datagrams) go to a port in
/// the sandbox.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub host: String,
    pub guest: u16,
    /// "tcp" (the default) or "udp".
    pub protocol: Option<String>,
}

/// A guest directory to export, and where on the host to write it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportTo {
    pub guest: String,
    pub host: PathBuf,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self> {
        Ok(toml::from_str(text)?)
    }

    /// Load a manifest; relative `host` paths are resolved against its directory.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut m = Self::parse(&text).with_context(|| format!("parsing {}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new("."));
        if let Some(img) = &mut m.image
            && img.is_relative()
        {
            *img = dir.join(&*img);
        }
        for imp in &mut m.imports {
            if imp.host.is_relative() {
                imp.host = dir.join(&imp.host);
            }
        }
        for exp in &mut m.exports {
            if exp.host.is_relative() {
                exp.host = dir.join(&exp.host);
            }
        }
        for mount in &mut m.mounts {
            if mount.host.is_relative() {
                mount.host = dir.join(&mount.host);
            }
        }
        Ok(m)
    }

    pub fn apply(&self, mut b: SandboxBuilder) -> Result<SandboxBuilder> {
        for name in &self.capabilities {
            let cap = Capability::from_name(name).with_context(|| {
                let known: Vec<&str> = Capability::ALL.iter().map(|c| c.name()).collect();
                format!("unknown capability {name:?} (known: {})", known.join(", "))
            })?;
            b = b.allow(cap);
        }
        match self.on_deny.as_deref() {
            None | Some("errno") => {}
            Some("kill") => b = b.on_deny(DenyAction::Kill),
            Some(other) => bail!("on_deny must be \"errno\" or \"kill\", not {other:?}"),
        }
        for (k, v) in &self.env {
            b = b.env(k, v);
        }
        if let Some(cwd) = &self.cwd {
            b = b.cwd(cwd);
        }
        if let Some(name) = &self.hostname {
            b = b.hostname(name)?;
        }
        if self.default_env {
            b = b.default_env();
        }
        if self.host_timezone {
            b = b.host_timezone();
        }
        if let Some(mb) = self.memory_mb {
            b = b.memory_mb(mb);
        }
        if let Some(s) = self.grace_secs {
            b = b.grace(Duration::from_secs(s));
        }
        match self.timeout_secs {
            Some(0) => b = b.no_timeout(),
            Some(s) => b = b.timeout(Duration::from_secs(s)),
            None => {}
        }
        if let Some(mb) = self.max_export_mb {
            b = b.max_export(mb << 20);
        }
        if let Some(network) = &self.network {
            b = b.network(crate::Network::parse(network)?);
        }
        for rule in &self.allow_hosts {
            b = b.allow_host(rule)?;
        }
        for f in &self.forwards {
            b = match f.protocol.as_deref() {
                None | Some("tcp") => b.forward(&f.host, f.guest)?,
                Some("udp") => b.forward_udp(&f.host, f.guest)?,
                Some(other) => bail!("forward protocol {other:?} isn't tcp or udp"),
            };
        }
        for imp in &self.imports {
            b = b.import(&imp.host, &imp.guest)?;
        }
        for exp in &self.exports {
            b = b.export(&exp.guest)?;
        }
        for mount in &self.mounts {
            let mode = match mount.mode.as_deref() {
                None | Some("rw") => MountMode::ReadWrite,
                Some("ro") => MountMode::ReadOnly,
                Some("on_exit") => MountMode::OnExit,
                Some("lazy") => MountMode::Lazy,
                Some(other) => bail!("mount mode must be \"rw\", \"ro\" or \"on_exit\", not {other:?}"),
            };
            b = b.mount_with(&mount.host, &mount.guest, mode)?;
        }
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_manifest() {
        let m = Manifest::parse(
            r#"
            command = ["/bin/x", "a"]
            capabilities = ["net"]
            on_deny = "kill"
            memory_mb = 300
            [env]
            A = "1"
            [[import]]
            host = "x"
            guest = "/bin/x"
            [[export]]
            guest = "/out"
            host = "results"
            "#,
        )
        .unwrap();
        assert_eq!(m.command, ["/bin/x", "a"]);
        assert_eq!(m.imports[0].guest, "/bin/x");
        assert_eq!(m.exports[0].host, Path::new("results"));
        assert_eq!(m.env["A"], "1");
    }

    #[test]
    fn rejects_unknown_fields_and_capabilities() {
        assert!(Manifest::parse("comand = []").is_err());
        let m = Manifest::parse(r#"capabilities = ["root"]"#).unwrap();
        assert!(m.apply(SandboxBuilder::default()).is_err());
    }

    #[test]
    fn forwards_tcp_or_udp() {
        let m = Manifest::parse(
            r#"
            [[forward]]
            host = "127.0.0.1:0"
            guest = 80
            [[forward]]
            host = "127.0.0.1:0"
            guest = 53
            protocol = "udp"
            "#,
        )
        .unwrap();
        assert_eq!(m.forwards[1].protocol.as_deref(), Some("udp"));
        assert!(m.apply(SandboxBuilder::default()).is_ok());
        let m = Manifest::parse("[[forward]]\nhost = \"127.0.0.1:0\"\nguest = 1\nprotocol = \"sctp\"").unwrap();
        assert!(m.apply(SandboxBuilder::default()).is_err());
    }
}
