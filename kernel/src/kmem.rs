//! A budget for kernel heap memory that programs can make the kernel hold:
//! pipe and socket buffers, netlink replies, generated /proc contents,
//! descriptor tables, threads, timers, mappings. The heap is 32 MiB and a
//! share of RAM (`mm::init`), and running out of it is a kernel panic, so
//! these fail with an errno (ENOMEM, ENOBUFS, EAGAIN) once the budget is
//! used up: `BASE`, and all of the share of RAM. Filesystem names and nodes
//! have their own budget (fs.rs). What stays out of both (processes, locks,
//! queued signals) has a low limit for all processes, and fits in what's
//! left of the heap.

use core::sync::atomic::{AtomicU64, Ordering};
use grix_abi::stats::{Limit, Resource};

use crate::errno::*;

/// What the fixed part of the heap gives the budget.
pub const BASE: u64 = 10 << 20;
static LIMIT: AtomicU64 = AtomicU64::new(BASE);
static USED: AtomicU64 = AtomicU64::new(0);

/// The heap's share of RAM gives the budget `extra` bytes more.
pub fn init(extra: u64) {
    LIMIT.store(BASE + extra, Ordering::Relaxed);
}

/// The whole budget.
pub fn limit() -> u64 {
    LIMIT.load(Ordering::Relaxed)
}

/// Bytes charged now.
pub fn used() -> u64 {
    USED.load(Ordering::Relaxed)
}

/// Bytes left in the budget.
pub fn available() -> u64 {
    limit().saturating_sub(USED.load(Ordering::Relaxed))
}

/// Bytes charged against the budget, given back when dropped.
#[derive(Debug, Default)]
pub struct Charge(u64);

impl Charge {
    pub fn bytes(&self) -> u64 {
        self.0
    }

    pub fn new(bytes: u64) -> Result<Charge, Errno> {
        let mut c = Charge(0);
        c.resize(bytes)?;
        Ok(c)
    }

    /// A charge for what's made either way, and nothing with no room: what
    /// the caller's own limit keeps in what's left of the heap.
    pub fn if_room(bytes: u64) -> Charge {
        if available() >= bytes { Charge::new(bytes).unwrap_or_default() } else { Charge::default() }
    }

    /// Change the amount held. Growing past the budget fails with ENOMEM
    /// and leaves the charge as it was.
    pub fn resize(&mut self, bytes: u64) -> Result<(), Errno> {
        if bytes > self.0 {
            let more = bytes - self.0;
            // One CPU, no preemption in the kernel: check-then-add doesn't race.
            if USED.load(Ordering::Relaxed) + more > limit() {
                crate::stats::hit(Limit::KernelMemory);
                return Err(ENOMEM);
            }
            let now = USED.fetch_add(more, Ordering::Relaxed) + more;
            crate::stats::peak(Resource::KernelMemory, now);
        } else {
            USED.fetch_sub(self.0 - bytes, Ordering::Relaxed);
        }
        self.0 = bytes;
        Ok(())
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        USED.fetch_sub(self.0, Ordering::Relaxed);
    }
}
