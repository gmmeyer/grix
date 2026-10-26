//! Capability model.
//!
//! A sandboxed program always gets "core" functionality: memory management,
//! time, randomness, stdout/stderr, and read access to whatever files the host
//! *imported* into the image (nothing else exists in its filesystem).
//! Everything else must be granted explicitly. Syscalls that need a capability
//! that was not granted are denied and reported back to the host, so an agent
//! can see exactly what a program tried to do and what it would need.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Capability {
    /// Create, modify or delete files.
    FsWrite = 0,
    /// Spawn threads (clone with CLONE_THREAD).
    Threads = 1,
    /// Spawn processes (fork/vfork/execve/wait).
    Process = 2,
    /// Sockets and networking.
    Net = 3,
}

impl Capability {
    pub const ALL: [Capability; 4] = [Capability::FsWrite, Capability::Threads, Capability::Process, Capability::Net];

    pub const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Capability::FsWrite => "fs_write",
            Capability::Threads => "threads",
            Capability::Process => "process",
            Capability::Net => "net",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Capability::FsWrite => "create, modify or delete files",
            Capability::Threads => "spawn threads",
            Capability::Process => "spawn processes (fork/exec/wait)",
            Capability::Net => "open sockets",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s)
    }
}

/// What the guest kernel does when a program calls a syscall it was not granted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum DenyAction {
    /// Fail the syscall with EPERM (like a non-root user hitting a permission check).
    #[default]
    Errno = 0,
    /// Terminate the program with SIGSYS (like a seccomp kill filter).
    Kill = 1,
}

impl DenyAction {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Errno),
            1 => Some(Self::Kill),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub caps: u64,
    pub on_deny: DenyAction,
}

impl Policy {
    pub fn allows(&self, cap: Capability) -> bool {
        self.caps & cap.bit() != 0
    }

    pub fn grant(&mut self, cap: Capability) {
        self.caps |= cap.bit();
    }
}
