use std::fmt;

use agentbox_abi::wire::Event;

/// Something the guest kernel reported about the program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestEvent {
    /// A syscall needed a capability that was not granted.
    Denied { syscall: String, capability: String, detail: String },
    /// The program needed kernel functionality that is not implemented yet.
    Unimplemented { syscall: String, detail: String },
    /// The program looked for a path that was not imported.
    MissingPath { path: String },
    /// The program was killed by a fault or signal.
    Fault { signal: u32, addr: u64, pc: u64, detail: String },
    /// The program could not be started.
    ExecFailed { path: String, reason: String },
}

impl From<Event<'_>> for GuestEvent {
    fn from(e: Event<'_>) -> Self {
        match e {
            Event::Denied { syscall, capability, detail, .. } => {
                GuestEvent::Denied { syscall: syscall.into(), capability: capability.into(), detail: detail.into() }
            }
            Event::Unimplemented { syscall, detail, .. } => {
                GuestEvent::Unimplemented { syscall: syscall.into(), detail: detail.into() }
            }
            Event::MissingPath { path } => GuestEvent::MissingPath { path: path.into() },
            Event::Fault { signal, addr, pc, detail } => GuestEvent::Fault { signal, addr, pc, detail: detail.into() },
            Event::ExecFailed { path, reason } => GuestEvent::ExecFailed { path: path.into(), reason: reason.into() },
        }
    }
}

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
                } else {
                    write!(f, ": needs capability `{capability}`")
                }
            }
            GuestEvent::Unimplemented { syscall, detail } => {
                write!(f, "unsupported {syscall}")?;
                if !detail.is_empty() {
                    write!(f, " ({detail})")?;
                }
                write!(f, ": not implemented by the agentbox kernel yet")
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
        }
    }
}
