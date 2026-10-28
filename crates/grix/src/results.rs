//! What a run's results do on the host, the same for every front end
//! (`grix run`, the Python module): exports written to their host
//! directories, and what each mount's changes did. Each says what happened
//! in `notes` (for the user to see) and whether it all worked.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::{Export, ExportState, MountState, RunOutput};

/// Exports' destinations, checked before the run so its results have
/// somewhere to go: each can take an export, none takes two, and none is
/// inside a mounted directory (`mounted`: their host paths), since mounts
/// are applied first and a program's changes mustn't decide where an
/// export goes. The checks on `Destinations::write` see that the
/// destinations' directories are still what they were.
pub fn check_destinations(exports: &[(String, PathBuf)], mounted: &[PathBuf]) -> Result<Destinations> {
    let mounted: Vec<PathBuf> = mounted.iter().filter_map(|m| m.canonicalize().ok()).collect();
    let mut parents = Vec::new();
    for (i, (_, dest)) in exports.iter().enumerate() {
        Export::check_destination(dest).map_err(|e| e.context("export destination"))?;
        if exports[..i].iter().any(|(_, h)| h == dest) {
            bail!("{} is the destination of two exports", dest.display());
        }
        let parent = parent_of(dest).canonicalize()?;
        if let Some(m) = mounted.iter().find(|m| parent.starts_with(m)) {
            bail!("export destination {} is inside mounted {}", dest.display(), m.display());
        }
        parents.push(parent);
    }
    Ok(Destinations { exports: exports.to_vec(), parents })
}

fn parent_of(dest: &Path) -> &Path {
    dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

/// Exports' destinations, checked (`check_destinations`).
pub struct Destinations {
    exports: Vec<(String, PathBuf)>,
    /// Each destination's directory, resolved when it was checked.
    parents: Vec<PathBuf>,
}

impl Destinations {
    /// Write each exported directory to its host path. Partial exports are
    /// written too, with a note; a missing one isn't. A destination whose
    /// directory now resolves elsewhere (a link a mount's changes put in
    /// its way) isn't written. False if any couldn't be.
    pub fn write(&self, out: &RunOutput, quiet: bool, notes: &mut Vec<String>) -> bool {
        let mut ok = true;
        for ((guest, host), parent) in self.exports.iter().zip(&self.parents) {
            let Some(export) = out.export(guest) else { continue };
            let note = match export.state {
                ExportState::Complete => "",
                ExportState::Missing => {
                    notes.push(format!("{guest} didn't exist when the program ended; nothing exported"));
                    continue;
                }
                ExportState::Truncated => " (cut off at the export limit)",
                ExportState::Incomplete => " (incomplete: the run ended before all of it arrived)",
            };
            if export.entries.is_empty() && !note.is_empty() {
                notes.push(format!("nothing of {guest} was exported{note}"));
                continue;
            }
            if parent_of(host).canonicalize().ok().as_ref() != Some(parent) {
                notes.push(format!(
                    "exporting {guest} to {}: its directory changed during the run; nothing written",
                    host.display()
                ));
                ok = false;
                continue;
            }
            match export.write_to(host) {
                Ok(()) if quiet && note.is_empty() => {}
                Ok(()) => {
                    let n = export.entries.len();
                    let s = if n == 1 { "entry" } else { "entries" };
                    notes.push(format!("exported {guest} to {} ({n} {s}){note}", host.display()));
                }
                Err(e) => {
                    notes.push(format!("exporting {guest} to {}: {e:#}", host.display()));
                    ok = false;
                }
            }
        }
        ok
    }
}

/// What happened to each mount's changes. False if a program that ended
/// normally didn't get them applied.
pub fn report_mounts(out: &RunOutput, quiet: bool, notes: &mut Vec<String>) -> bool {
    let ended = matches!(out.status, crate::ExitStatus::Exited(_) | crate::ExitStatus::Signaled(_));
    let mut ok = true;
    for m in &out.mount_changes {
        let host = m.host.display();
        let (w, r) = (m.written.len(), m.removed.len());
        match &m.state {
            MountState::Applied if quiet || w + r == 0 => {}
            MountState::Applied => notes.push(format!("applied the changes to {host}: {w} written, {r} removed")),
            MountState::NotApplied if ended => {
                notes.push(format!(
                    "the changes to {host} weren't applied: they didn't all arrive \
                     (over the export limit, or paths nested deeper than 4096 bytes)"
                ));
                ok = false;
            }
            MountState::NotApplied => notes.push(format!("the changes to {host} weren't applied")),
            MountState::Failed(why) => {
                notes.push(format!("applying the changes to {host} failed after {w} written, {r} removed: {why}"));
                ok = false;
            }
        }
        if !m.conflicts.is_empty() {
            let n = m.conflicts.len();
            let shown: Vec<&str> = m.conflicts.iter().take(10).map(String::as_str).collect();
            let more = if n > 10 { format!(" and {} more", n - 10) } else { String::new() };
            notes.push(format!(
                "{n} path(s) in {host} changed on the host during the run too and were left as they are: {}{more}",
                shown.join(", ")
            ));
        }
    }
    ok
}
