//! The host's time zone, for a sandbox that asks for it: a sandbox is in
//! UTC, as what zone a host is in says something of where it is.
//!
//! The guest gets what a system has: the zone's compiled file in
//! `/usr/share/zoneinfo`, with `/etc/localtime` a link to it. libc reads it
//! through the link, and ICU (Node's `Intl`, Java) goes by where the link
//! leads to name the zone. A zone with no name (a plain `/etc/localtime`)
//! is just that file, and a `TZ` that's a rule (`EST5EDT,M3.2.0,M11.1.0`)
//! needs no file at all, so it goes on being `TZ`.

use std::path::Path;

use anyhow::{Context, Result, bail};

/// Where systems keep their zones (macOS's are where `/etc/localtime` goes).
const ZONEINFO: &[&str] = &["/usr/share/zoneinfo", "/var/db/timezone/zoneinfo"];
/// More than any zone's compiled file: this goes in the boot image.
const MAX_ZONE_FILE: u64 = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Zone {
    Named { name: String, data: Vec<u8> },
    File(Vec<u8>),
    Rule(String),
}

/// The host's zone: `TZ` if it's set, as for any program there, or else
/// `/etc/localtime`.
pub(crate) fn host_zone() -> Result<Zone> {
    let tz = std::env::var("TZ").ok();
    find(tz.as_deref(), Path::new("/etc/localtime"), ZONEINFO)
}

fn find(tz: Option<&str>, localtime: &Path, roots: &[&str]) -> Result<Zone> {
    let Some(tz) = tz.filter(|t| !t.is_empty()) else { return from_file(localtime) };
    // POSIX's way of saying it's a file, and glibc's of leaving that out.
    let tz = tz.strip_prefix(':').unwrap_or(tz);
    if tz.starts_with('/') {
        return from_file(Path::new(tz));
    }
    if valid_name(tz) {
        for root in roots {
            let path = Path::new(root).join(tz);
            if path.is_file() {
                return Ok(Zone::Named { name: tz.into(), data: zone_file(&path)? });
            }
        }
    }
    // A rule says what its offset is, in digits. A name that's found
    // nowhere doesn't, and would be UTC for a program there too.
    if tz.len() <= 255 && tz.bytes().all(|b| b.is_ascii_graphic()) && tz.bytes().any(|b| b.is_ascii_digit()) {
        return Ok(Zone::Rule(tz.into()));
    }
    bail!("the host's TZ is {tz:?}: no such zone here, and it isn't a rule");
}

/// The zone in file `path`, named by where it really is, if that's a zone
/// directory.
fn from_file(path: &Path) -> Result<Zone> {
    let data = zone_file(path)?;
    let real = std::fs::canonicalize(path).with_context(|| format!("reading {}", path.display()))?;
    let real = real.to_string_lossy();
    let name = real.rfind("zoneinfo/").map(|at| &real[at + "zoneinfo/".len()..]);
    // Copies with leap seconds or without are the same zone.
    let name = name.map(|n| n.strip_prefix("posix/").or(n.strip_prefix("right/")).unwrap_or(n));
    Ok(match name.filter(|n| valid_name(n)) {
        Some(name) => Zone::Named { name: name.into(), data },
        None => Zone::File(data),
    })
}

fn zone_file(path: &Path) -> Result<Vec<u8>> {
    let shown = path.display();
    let len = std::fs::metadata(path).with_context(|| format!("the host's time zone: {shown}"))?.len();
    if len > MAX_ZONE_FILE {
        bail!("the host's time zone: {shown} is {len} bytes, too big for a zone file");
    }
    let data = std::fs::read(path).with_context(|| format!("the host's time zone: {shown}"))?;
    if !data.starts_with(b"TZif") {
        bail!("the host's time zone: {shown} isn't a zone file");
    }
    Ok(data)
}

/// A path under a zone directory, and so one in the guest: names as the tz
/// database has them, and nothing that climbs out.
fn valid_name(name: &str) -> bool {
    let plain = |c: char| c.is_ascii_alphanumeric() || "_+-".contains(c);
    !name.is_empty() && name.split('/').all(|part| !part.is_empty() && part.chars().all(plain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("grix-tz-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("zoneinfo/Asia")).unwrap();
        std::fs::write(d.join("zoneinfo/Asia/Tokyo"), b"TZif tokyo").unwrap();
        d
    }

    #[test]
    fn a_link_names_its_zone() {
        let d = scratch("link");
        std::os::unix::fs::symlink(d.join("zoneinfo/Asia/Tokyo"), d.join("localtime")).unwrap();
        let got = find(None, &d.join("localtime"), &[]).unwrap();
        assert_eq!(got, Zone::Named { name: "Asia/Tokyo".into(), data: b"TZif tokyo".to_vec() });
        // An empty TZ is as good as none, here.
        assert_eq!(find(Some(""), &d.join("localtime"), &[]).unwrap(), got);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_copy_has_no_name() {
        let d = scratch("copy");
        std::fs::write(d.join("localtime"), b"TZif copy").unwrap();
        assert_eq!(find(None, &d.join("localtime"), &[]).unwrap(), Zone::File(b"TZif copy".to_vec()));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn tz_comes_first() {
        let d = scratch("tz");
        let root = d.join("zoneinfo");
        let roots = [root.to_str().unwrap()];
        let nothing = d.join("not-there");
        let tokyo = Zone::Named { name: "Asia/Tokyo".into(), data: b"TZif tokyo".to_vec() };
        assert_eq!(find(Some("Asia/Tokyo"), &nothing, &roots).unwrap(), tokyo);
        assert_eq!(find(Some(":Asia/Tokyo"), &nothing, &roots).unwrap(), tokyo);
        let path = d.join("zoneinfo/Asia/Tokyo");
        assert_eq!(find(Some(path.to_str().unwrap()), &nothing, &roots).unwrap(), tokyo);
        let rule = "EST5EDT,M3.2.0,M11.1.0";
        assert_eq!(find(Some(rule), &nothing, &roots).unwrap(), Zone::Rule(rule.into()));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn what_cant_be_trusted_is_refused() {
        let d = scratch("bad");
        let root = d.join("zoneinfo");
        let roots = [root.to_str().unwrap()];
        std::fs::write(d.join("secret"), b"not a zone").unwrap();
        // A file that isn't a zone doesn't go into the guest.
        assert!(find(None, &d.join("secret"), &roots).is_err());
        assert!(find(Some(d.join("secret").to_str().unwrap()), &d.join("x"), &roots).is_err());
        // Out of the zone directory by way of TZ: not a name, so not read,
        // and not a rule either.
        assert!(find(Some("../secret"), &d.join("x"), &roots).is_err());
        assert!(find(Some("Nowhere/Land"), &d.join("x"), &roots).is_err());
        // Too big to be one.
        let big = d.join("big");
        std::fs::write(&big, vec![b'T'; MAX_ZONE_FILE as usize + 1]).unwrap();
        assert!(find(None, &big, &roots).is_err());
        assert!(!valid_name("a/../b") && !valid_name("/etc/passwd") && !valid_name("a//b") && !valid_name(""));
        assert!(valid_name("America/Argentina/Buenos_Aires") && valid_name("Etc/GMT+5"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
