//! TOML manifests: a declarative description of a sandbox.
//!
//! ```toml
//! command = ["/bin/hello", "world"]
//! capabilities = []          # fs_write, threads, process, net
//! on_deny = "errno"          # or "kill"
//! memory_mb = 256
//! timeout_secs = 30
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
//!
//! [[export]]                 # copied out when the program ends (CLI)
//! guest = "/out"
//! host = "results"           # relative to this manifest; must not exist yet
//!
//! [[mount]]                  # read-write: changes go back when the program ends
//! host = "."                 # relative to this manifest
//! guest = "/work"
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use grix_abi::policy::{Capability, DenyAction};
use serde::Deserialize;

use crate::sandbox::SandboxBuilder;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub on_deny: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub memory_mb: Option<u64>,
    pub timeout_secs: Option<u64>,
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
    pub mounts: Vec<Import>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub host: PathBuf,
    pub guest: String,
}

/// A host address whose connections go to a port in the sandbox.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub host: String,
    pub guest: u16,
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
        if let Some(mb) = self.memory_mb {
            b = b.memory_mb(mb);
        }
        if let Some(s) = self.timeout_secs {
            b = b.timeout(Duration::from_secs(s));
        }
        if let Some(mb) = self.max_export_mb {
            b = b.max_export(mb << 20);
        }
        for rule in &self.allow_hosts {
            b = b.allow_host(rule)?;
        }
        for f in &self.forwards {
            b = b.forward(&f.host, f.guest)?;
        }
        for imp in &self.imports {
            b = b.import(&imp.host, &imp.guest)?;
        }
        for exp in &self.exports {
            b = b.export(&exp.guest)?;
        }
        for mount in &self.mounts {
            b = b.mount(&mount.host, &mount.guest)?;
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
}
