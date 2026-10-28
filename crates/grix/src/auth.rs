//! Registry credentials, for pulling images that need a login. They come
//! from what `grix login` saved (`~/.config/grix/auth.json`), then
//! Docker's configuration (`$DOCKER_CONFIG/config.json` or
//! `~/.docker/config.json`: `credHelpers`, `auths`, `credsStore`), then
//! Podman's (`$REGISTRY_AUTH_FILE`, `$XDG_RUNTIME_DIR/containers/auth.json`,
//! `~/.config/containers/auth.json`). All are in Docker's format.
//!
//! They're looked up only when a registry asks (a 401), go only to that
//! registry and the token service it names, and only over TLS (or to a
//! registry on this machine).

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};

/// A login for a registry.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Credential {
    Basic {
        user: String,
        password: String,
    },
    /// An OAuth refresh token (Docker's `identitytoken`).
    IdentityToken(String),
}

impl std::fmt::Debug for Credential {
    // Never the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::Basic { user, .. } => write!(f, "Basic({user})"),
            Credential::IdentityToken(_) => write!(f, "IdentityToken"),
        }
    }
}

impl Credential {
    pub(crate) fn basic_header(&self) -> Option<String> {
        match self {
            Credential::Basic { user, password } => {
                Some(format!("Basic {}", BASE64.encode(format!("{user}:{password}"))))
            }
            Credential::IdentityToken(_) => None,
        }
    }
}

/// Where credentials come from.
pub(crate) struct Store {
    files: Vec<PathBuf>,
    /// Credential helpers may run (`docker-credential-NAME get`).
    helpers: bool,
}

impl Store {
    /// The user's: grix's own file, then Docker's, then Podman's.
    pub(crate) fn user() -> Store {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let mut files = Vec::new();
        if let Ok(f) = grix_file() {
            files.push(f);
        }
        match std::env::var_os("DOCKER_CONFIG") {
            Some(d) => files.push(PathBuf::from(d).join("config.json")),
            None => files.extend(home.as_ref().map(|h| h.join(".docker/config.json"))),
        }
        if let Some(f) = std::env::var_os("REGISTRY_AUTH_FILE") {
            files.push(PathBuf::from(f));
        }
        if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
            files.push(PathBuf::from(d).join("containers/auth.json"));
        }
        files.extend(home.map(|h| h.join(".config/containers/auth.json")));
        Store { files, helpers: true }
    }

    /// None at all: anonymous pulls only.
    pub(crate) fn none() -> Store {
        Store { files: Vec::new(), helpers: false }
    }

    #[cfg(test)]
    pub(crate) fn file(path: &Path) -> Store {
        Store { files: vec![path.to_path_buf()], helpers: false }
    }

    /// The credential for `host` (as in URLs: `registry-1.docker.io`,
    /// `ghcr.io`, `localhost:5000`), if any.
    pub(crate) fn lookup(&self, host: &str) -> Result<Option<Credential>> {
        let names = aliases(host);
        for file in &self.files {
            let Ok(text) = fs::read(file) else { continue };
            let config: Value =
                serde_json::from_slice(&text).with_context(|| format!("reading credentials in {}", file.display()))?;
            let find = |table: &Value| -> Option<Value> {
                let map = table.as_object()?;
                map.iter().find(|(k, _)| names.contains(&normalize(k))).map(|(_, v)| v.clone())
            };
            if self.helpers
                && let Some(helper) = find(&config["credHelpers"]).and_then(|h| h.as_str().map(String::from))
            {
                return run_helper(&helper, &names[0]);
            }
            if let Some(entry) = find(&config["auths"])
                && let Some(c) = from_entry(&entry).with_context(|| format!("credentials in {}", file.display()))?
            {
                return Ok(Some(c));
            }
            if self.helpers
                && let Some(store) = config["credsStore"].as_str()
                && let Some(c) = run_helper(store, &names[0])?
            {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }
}

/// grix's own credentials file.
fn grix_file() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME isn't set")?).join(".config"),
    };
    Ok(base.join("grix/auth.json"))
}

/// The names a registry goes by in credential files, the one helpers are
/// asked about first.
fn aliases(host: &str) -> Vec<String> {
    match host {
        "registry-1.docker.io" | "docker.io" | "index.docker.io" => {
            ["https://index.docker.io/v1/", "index.docker.io", "docker.io", "registry-1.docker.io"]
                .map(String::from)
                .to_vec()
        }
        h => vec![h.to_string()],
    }
}

/// A credential file's key as a registry host (`https://ghcr.io/v2/` is
/// `ghcr.io`), except Docker Hub's own.
fn normalize(key: &str) -> String {
    if key == "https://index.docker.io/v1/" {
        return key.to_string();
    }
    let k = key.strip_prefix("https://").or_else(|| key.strip_prefix("http://")).unwrap_or(key);
    k.split('/').next().unwrap_or(k).to_string()
}

/// An `auths` entry: `auth` (base64 of `user:password`), or
/// `identitytoken`, or `username` and `password`.
fn from_entry(entry: &Value) -> Result<Option<Credential>> {
    if let Some(t) = entry["identitytoken"].as_str().filter(|t| !t.is_empty()) {
        return Ok(Some(Credential::IdentityToken(t.to_string())));
    }
    if let Some(a) = entry["auth"].as_str().filter(|a| !a.is_empty()) {
        let raw = String::from_utf8(BASE64.decode(a.trim()).context("bad base64 in auth")?).context("bad auth")?;
        let (user, password) = raw.split_once(':').context("auth isn't user:password")?;
        return Ok(Some(Credential::Basic { user: user.to_string(), password: password.to_string() }));
    }
    match (entry["username"].as_str(), entry["password"].as_str()) {
        (Some(u), Some(p)) if !u.is_empty() => Ok(Some(Credential::Basic { user: u.into(), password: p.into() })),
        _ => Ok(None),
    }
}

/// How long a credential helper may take (one may ask the user).
const HELPER_TIMEOUT: Duration = Duration::from_secs(120);

/// Ask `docker-credential-NAME get` for `server`'s credential.
fn run_helper(name: &str, server: &str) -> Result<Option<Credential>> {
    // A program name on the PATH, not a path.
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        bail!("bad credential helper name {name:?}");
    }
    let program = format!("docker-credential-{name}");
    let mut child = match Command::new(&program)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!("credential helper {program} isn't installed"),
        Err(e) => return Err(e).context(program),
    };
    child.stdin.take().unwrap().write_all(server.as_bytes())?;
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = (&mut stdout).take(1 << 20).read_to_end(&mut out);
        out
    });
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if started.elapsed() > HELPER_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} didn't answer in {} s", HELPER_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = reader.join().unwrap_or_default();
    if !status.success() {
        // "credentials not found": no login for it.
        return Ok(None);
    }
    let v: Value = serde_json::from_slice(&out).with_context(|| format!("{program}'s answer"))?;
    let user = v["Username"].as_str().unwrap_or("");
    let secret = v["Secret"].as_str().unwrap_or("");
    Ok(match (user, secret) {
        (_, "") => None,
        ("<token>", s) => Some(Credential::IdentityToken(s.to_string())),
        (u, s) => Some(Credential::Basic { user: u.to_string(), password: s.to_string() }),
    })
}

/// Save a login for `registry` in grix's credentials file (mode 0600).
pub fn login(registry: &str, user: &str, password: &str) -> Result<PathBuf> {
    let path = grix_file()?;
    let key = registry_key(registry);
    let entry = json!({ "auth": BASE64.encode(format!("{user}:{password}")) });
    update(&path, |auths| {
        auths.insert(key, entry);
    })?;
    Ok(path)
}

/// Forget `registry`'s login in grix's credentials file. Returns whether
/// there was one.
pub fn logout(registry: &str) -> Result<bool> {
    let path = grix_file()?;
    let key = registry_key(registry);
    let mut had = false;
    if path.exists() {
        update(&path, |auths| had = auths.remove(&key).is_some())?;
    }
    Ok(had)
}

/// How `grix login` names a registry: its host as in URLs, Docker Hub's
/// as Docker does.
fn registry_key(registry: &str) -> String {
    let host = normalize(registry);
    if aliases(&host).len() > 1 { "https://index.docker.io/v1/".to_string() } else { host }
}

fn update(path: &Path, change: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = path.parent().context("no directory for credentials")?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let mut config: Value = match fs::read(path) {
        Ok(text) => serde_json::from_slice(&text).with_context(|| format!("reading {}", path.display()))?,
        Err(_) => json!({}),
    };
    if !config["auths"].is_object() {
        config["auths"] = json!({});
    }
    change(config["auths"].as_object_mut().unwrap());
    let tmp = dir.join(format!("auth.json.tmp-{}", crate::container::random_suffix()));
    let result = (|| -> Result<()> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(&config)?)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_from_docker_style_files() {
        let dir = std::env::temp_dir().join(format!("grix-auth-{}", crate::container::random_suffix()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.json");
        fs::write(
            &file,
            json!({
                "auths": {
                    "https://index.docker.io/v1/": {"auth": BASE64.encode("hub:secret")},
                    "ghcr.io": {"identitytoken": "tok"},
                    "https://localhost:5000/v2/": {"username": "u", "password": "p"},
                    "empty.example": {},
                }
            })
            .to_string(),
        )
        .unwrap();
        let store = Store::file(&file);
        let basic = |u: &str, p: &str| Some(Credential::Basic { user: u.into(), password: p.into() });
        assert_eq!(store.lookup("registry-1.docker.io").unwrap(), basic("hub", "secret"));
        assert_eq!(store.lookup("ghcr.io").unwrap(), Some(Credential::IdentityToken("tok".into())));
        assert_eq!(store.lookup("localhost:5000").unwrap(), basic("u", "p"));
        assert_eq!(store.lookup("empty.example").unwrap(), None);
        assert_eq!(store.lookup("quay.io").unwrap(), None);
        assert!(format!("{:?}", basic("hub", "secret").unwrap()).find("secret").is_none());
        assert_eq!(registry_key("docker.io"), "https://index.docker.io/v1/");
        assert_eq!(registry_key("https://ghcr.io/"), "ghcr.io");
        // grix login's file: written privately, and read back.
        let saved = dir.join("grix/auth.json");
        update(&saved, |a| {
            a.insert("ghcr.io".into(), json!({"auth": BASE64.encode("me:pw")}));
        })
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&saved).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(Store::file(&saved).lookup("ghcr.io").unwrap(), basic("me", "pw"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
