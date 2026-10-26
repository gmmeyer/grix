//! TOML manifests: a declarative description of a sandbox.
//!
//! ```toml
//! command = ["/bin/hello", "world"]
//! capabilities = []          # fs_write, threads, process, net
//! on_deny = "errno"          # or "kill"
//! memory_mb = 256
//! timeout_secs = 30
//!
//! [env]
//! GREETING = "hi"
//!
//! [[import]]
//! host = "build/hello"       # relative to this manifest
//! guest = "/bin/hello"
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
    #[serde(default, rename = "import")]
    pub imports: Vec<Import>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub host: PathBuf,
    pub guest: String,
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
        for imp in &self.imports {
            b = b.import(&imp.host, &imp.guest)?;
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
            "#,
        )
        .unwrap();
        assert_eq!(m.command, ["/bin/x", "a"]);
        assert_eq!(m.imports[0].guest, "/bin/x");
        assert_eq!(m.env["A"], "1");
    }

    #[test]
    fn rejects_unknown_fields_and_capabilities() {
        assert!(Manifest::parse("comand = []").is_err());
        let m = Manifest::parse(r#"capabilities = ["root"]"#).unwrap();
        assert!(m.apply(SandboxBuilder::default()).is_err());
    }
}
