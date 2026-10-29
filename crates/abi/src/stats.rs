//! What the guest kernel says of its own resources, for the host's metrics
//! (`wire::Channel::Stats`): when the host asks (`wire::Input::Stats`), and
//! once more as the program ends, just before its status.
//!
//! It's the guest's say-so, which a program that took over its kernel can
//! make anything: the host reports it, for seeing what a program used and
//! which limits it ran into, but measures what a run costs it (CPU time,
//! memory) itself.

use alloc::vec::Vec;

use crate::codec::{DecodeError, Reader, Writer};

/// What the kernel has a fixed amount of: what's in use, at most, out of how
/// much.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Resource {
    /// Guest RAM (bytes): everything the kernel hands out in pages, the
    /// program's memory, its files' data and page tables.
    Memory,
    /// Kernel heap that programs can make the kernel hold (bytes): pipe and
    /// socket buffers, queued messages, generated /proc files.
    KernelMemory,
    /// Data written to the in-memory filesystem (bytes).
    FileData,
    /// Names and nodes in the filesystem (bytes, as the kernel counts them).
    FileMetadata,
    /// Processes, zombies included.
    Processes,
    /// Threads, in every process.
    Threads,
}

impl Resource {
    pub const ALL: [Resource; 6] = [
        Resource::Memory,
        Resource::KernelMemory,
        Resource::FileData,
        Resource::FileMetadata,
        Resource::Processes,
        Resource::Threads,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Resource::Memory => "memory",
            Resource::KernelMemory => "kernel_memory",
            Resource::FileData => "file_data",
            Resource::FileMetadata => "file_metadata",
            Resource::Processes => "processes",
            Resource::Threads => "threads",
        }
    }

    /// Counted in bytes (the others are counts).
    pub fn in_bytes(self) -> bool {
        !matches!(self, Resource::Processes | Resource::Threads)
    }
}

/// A limit a program can run into: the kernel refused something (ENOMEM,
/// ENOSPC, EAGAIN, ...) because one of its budgets or caps was used up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Limit {
    /// Guest RAM ran out.
    Memory,
    /// The kernel memory budget (`Resource::KernelMemory`).
    KernelMemory,
    /// The filesystem's data limit (half of RAM).
    FileData,
    /// The filesystem's names and nodes.
    FileMetadata,
    Processes,
    Threads,
    /// Open files in every process.
    OpenFiles,
    /// Memory mappings, in a process or in all of them.
    Mappings,
    /// Network connections, or connections waiting to be accepted.
    Connections,
    /// Pseudo-terminals.
    Ptys,
    /// flock, POSIX and OFD locks.
    FileLocks,
    /// Descriptors in flight over AF_UNIX sockets.
    PassedDescriptors,
    InotifyWatches,
    /// Queued real-time signals.
    QueuedSignals,
    /// A process's POSIX timers.
    Timers,
}

impl Limit {
    pub const ALL: [Limit; 15] = [
        Limit::Memory,
        Limit::KernelMemory,
        Limit::FileData,
        Limit::FileMetadata,
        Limit::Processes,
        Limit::Threads,
        Limit::OpenFiles,
        Limit::Mappings,
        Limit::Connections,
        Limit::Ptys,
        Limit::FileLocks,
        Limit::PassedDescriptors,
        Limit::InotifyWatches,
        Limit::QueuedSignals,
        Limit::Timers,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Limit::Memory => "memory",
            Limit::KernelMemory => "kernel_memory",
            Limit::FileData => "file_data",
            Limit::FileMetadata => "file_metadata",
            Limit::Processes => "processes",
            Limit::Threads => "threads",
            Limit::OpenFiles => "open_files",
            Limit::Mappings => "mappings",
            Limit::Connections => "connections",
            Limit::Ptys => "ptys",
            Limit::FileLocks => "file_locks",
            Limit::PassedDescriptors => "passed_descriptors",
            Limit::InotifyWatches => "inotify_watches",
            Limit::QueuedSignals => "queued_signals",
            Limit::Timers => "timers",
        }
    }
}

/// How much of a [`Resource`] is in use now, the most that was at once
/// since boot, and how much there is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub now: u64,
    pub peak: u64,
    pub limit: u64,
}

/// The kernel's report. Counters count from boot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// CPU time the program's threads ran, in every process (to within a
    /// time slice of each CPU's).
    pub cpu_ns: u64,
    /// System calls made (a blocked call counts again each time it re-runs).
    pub syscalls: u64,
    /// Page faults the kernel handled for programs (demand paging,
    /// copy-on-write), and those that became signals.
    pub page_faults: u64,
    /// Times a CPU switched to another thread.
    pub context_switches: u64,
    /// Processes forked.
    pub processes_started: u64,
    /// By `Resource as usize`.
    pub usage: [Usage; Resource::ALL.len()],
    /// How often each limit refused something, by `Limit as usize`.
    pub limits_hit: [u64; Limit::ALL.len()],
}

impl Stats {
    /// Its encoding's length: a u64 for every number. One frame's worth at
    /// most, as the kernel sends it.
    pub const LEN: usize = 8 * (5 + 3 * Resource::ALL.len() + Limit::ALL.len());
    const FITS_A_FRAME: () = assert!(Self::LEN <= crate::wire::MAX_FRAME);

    pub fn usage(&self, r: Resource) -> Usage {
        self.usage[r as usize]
    }

    pub fn hits(&self, l: Limit) -> u64 {
        self.limits_hit[l as usize]
    }

    pub fn encode(&self) -> Vec<u8> {
        let () = Self::FITS_A_FRAME;
        let mut w = Writer::new();
        for v in [self.cpu_ns, self.syscalls, self.page_faults, self.context_switches, self.processes_started] {
            w.u64(v);
        }
        for u in &self.usage {
            w.u64(u.now);
            w.u64(u.peak);
            w.u64(u.limit);
        }
        for &n in &self.limits_hit {
            w.u64(n);
        }
        w.buf
    }

    pub fn decode(buf: &[u8]) -> Result<Stats, DecodeError> {
        if buf.len() != Self::LEN {
            return Err(DecodeError);
        }
        let mut r = Reader::new(buf);
        let mut s = Stats {
            cpu_ns: r.u64()?,
            syscalls: r.u64()?,
            page_faults: r.u64()?,
            context_switches: r.u64()?,
            processes_started: r.u64()?,
            ..Stats::default()
        };
        for u in &mut s.usage {
            *u = Usage { now: r.u64()?, peak: r.u64()?, limit: r.u64()? };
        }
        for n in &mut s.limits_hit {
            *n = r.u64()?;
        }
        r.done()?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_exact_length() {
        let mut s = Stats {
            cpu_ns: 1,
            syscalls: 2,
            page_faults: 3,
            context_switches: 4,
            processes_started: 5,
            ..Stats::default()
        };
        s.usage[Resource::Threads as usize] = Usage { now: 6, peak: 7, limit: 8 };
        s.limits_hit[Limit::Timers as usize] = 9;
        let bytes = s.encode();
        assert_eq!(bytes.len(), Stats::LEN);
        let back = Stats::decode(&bytes).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.usage(Resource::Threads).peak, 7);
        assert_eq!(back.hits(Limit::Timers), 9);
        assert!(Stats::decode(&bytes[1..]).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(Stats::decode(&long).is_err());
        assert!(Stats::decode(&[]).is_err());
    }

    #[test]
    fn names_are_distinct_and_in_order() {
        for (i, r) in Resource::ALL.iter().enumerate() {
            assert_eq!(*r as usize, i);
        }
        for (i, l) in Limit::ALL.iter().enumerate() {
            assert_eq!(*l as usize, i);
        }
        let mut names: Vec<&str> = Limit::ALL.iter().map(|l| l.name()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), Limit::ALL.len());
    }
}
