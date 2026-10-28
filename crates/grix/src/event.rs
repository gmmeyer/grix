use std::fmt;

use grix_abi::wire::Event;

/// Something the guest kernel reported about the program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestEvent {
    /// A syscall needed a capability that was not granted.
    Denied { syscall: String, capability: String, detail: String },
    /// The program needed kernel functionality that is not implemented yet.
    Unimplemented { nr: u32, syscall: String, detail: String },
    /// The program looked for a path that was not imported.
    MissingPath { path: String },
    /// The program was killed by a fault or signal.
    Fault { signal: u32, addr: u64, pc: u64, detail: String },
    /// The program could not be started.
    ExecFailed { path: String, reason: String },
    /// The program stopped (job control: a stop signal's default action),
    /// until SIGCONT.
    Stopped { signal: u32 },
    /// The program continued after stopping.
    Continued,
}

impl From<Event<'_>> for GuestEvent {
    fn from(e: Event<'_>) -> Self {
        match e {
            Event::Denied { syscall, capability, detail, .. } => {
                GuestEvent::Denied { syscall: syscall.into(), capability: capability.into(), detail: detail.into() }
            }
            Event::Unimplemented { nr, syscall, detail } => {
                GuestEvent::Unimplemented { nr, syscall: syscall.into(), detail: detail.into() }
            }
            Event::MissingPath { path } => GuestEvent::MissingPath { path: path.into() },
            Event::Fault { signal, addr, pc, detail } => GuestEvent::Fault { signal, addr, pc, detail: detail.into() },
            Event::ExecFailed { path, reason } => GuestEvent::ExecFailed { path: path.into(), reason: reason.into() },
            Event::Stopped { signal } => GuestEvent::Stopped { signal },
            Event::Continued => GuestEvent::Continued,
        }
    }
}

/// The "capability" of a Denied event for something the network policy
/// (`SandboxBuilder::allow_host`) refused, rather than a missing capability.
pub(crate) const NET_POLICY: &str = "allow_host";

impl fmt::Display for GuestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestEvent::Denied { syscall, capability, detail } => {
                write!(f, "denied {syscall}")?;
                if !detail.is_empty() {
                    write!(f, " ({detail})")?;
                }
                if capability == "privileged" {
                    write!(f, ": never available in the sandbox")
                } else if capability == NET_POLICY {
                    write!(f, ": not allowed by the network policy (allow_host)")
                } else {
                    write!(f, ": needs capability `{capability}`")
                }
            }
            GuestEvent::Unimplemented { nr, syscall, detail } => {
                if syscall == "unknown" {
                    write!(f, "unsupported syscall {nr}")?;
                } else {
                    write!(f, "unsupported {syscall}")?;
                }
                if !detail.is_empty() {
                    write!(f, " ({detail})")?;
                }
                write!(f, ": not implemented by the grix kernel yet")
            }
            GuestEvent::MissingPath { path } => write!(f, "missing {path}: not imported"),
            GuestEvent::Fault { signal, addr, pc, detail } => {
                write!(f, "killed by signal {signal}: {detail}")?;
                if *pc != 0 {
                    write!(f, " (addr {addr:#x}, pc {pc:#x})")?;
                }
                Ok(())
            }
            GuestEvent::ExecFailed { path, reason } => write!(f, "could not start {path}: {reason}"),
            GuestEvent::Stopped { signal } => write!(f, "stopped by signal {signal} (until SIGCONT)"),
            GuestEvent::Continued => write!(f, "continued"),
        }
    }
}
