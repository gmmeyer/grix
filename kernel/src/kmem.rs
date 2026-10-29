//! A budget for kernel heap memory that programs can make the kernel hold:
//! pipe and socket buffers, netlink replies, generated /proc contents,
//! queued real-time signals. The heap is 32 MiB and running out of it is a
//! kernel panic, so these fail with an errno (ENOMEM, ENOBUFS, EAGAIN) once
//! the budget is used up. Filesystem names and nodes have their own budget
//! (fs.rs), and fixed-size tables (threads, descriptors, timers) their own
//! limits.

use core::sync::atomic::{AtomicU64, Ordering};
use grix_abi::stats::{Limit, Resource};

use crate::errno::*;

pub const LIMIT: u64 = 10 << 20;
static USED: AtomicU64 = AtomicU64::new(0);

/// Bytes charged now.
pub fn used() -> u64 {
    USED.load(Ordering::Relaxed)
}

/// Bytes left in the budget.
pub fn available() -> u64 {
    LIMIT.saturating_sub(USED.load(Ordering::Relaxed))
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

    /// Change the amount held. Growing past the budget fails with ENOMEM
    /// and leaves the charge as it was.
    pub fn resize(&mut self, bytes: u64) -> Result<(), Errno> {
        if bytes > self.0 {
            let more = bytes - self.0;
            // One CPU, no preemption in the kernel: check-then-add doesn't race.
            if USED.load(Ordering::Relaxed) + more > LIMIT {
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
