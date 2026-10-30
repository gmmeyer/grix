//! A process's address space, and which CPU may use it now.
//!
//! The big kernel lock doesn't cover address spaces: a CPU may handle a
//! page fault without it (`fast::fault`). So each address space has a
//! gate, held by one CPU at a time: by the CPU that has its process
//! checked out (from `smp::lock`, or `sched::schedule` switching to it,
//! until `smp::unlock` or the next switch puts it back), by a fast entry
//! on its own, and briefly by code that looks at another process's
//! (`Mm::access`). Lock order: a gate (only ever one more than the
//! running process's, taken through `access`), then the filesystem, then
//! a `FileData`. Nothing that holds a gate waits for another CPU but in
//! `arch::flush_tlb`, which doesn't wait for a CPU in the kernel.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

use super::aspace::AddressSpace;

const FREE: usize = usize::MAX;

/// Gates each CPU holds (debug builds: `none_held`).
#[cfg(debug_assertions)]
static HELD: [AtomicUsize; grix_abi::machine::MAX_CPUS as usize] =
    [const { AtomicUsize::new(0) }; grix_abi::machine::MAX_CPUS as usize];

/// Does this CPU hold no gate? (As it must when it goes back to user mode
/// or starts a fast entry. Always true in release builds.)
pub fn none_held() -> bool {
    #[cfg(debug_assertions)]
    return HELD[crate::smp::me()].load(Ordering::Relaxed) == 0;
    #[cfg(not(debug_assertions))]
    true
}

/// The address space's gate and contents, and its page table's root (which
/// never changes), kept here too so the CPUs that switch to it don't read
/// another cache line for it.
pub struct Mm(Arc<Inner>, u64);

pub struct Inner {
    /// The CPU holding the gate, or `FREE`.
    holder: AtomicUsize,
    aspace: UnsafeCell<AddressSpace>,
}

// SAFETY: the address space is reached only by the gate's holder.
unsafe impl Sync for Inner {}
unsafe impl Send for Inner {}

impl Mm {
    /// An address space nobody holds yet.
    pub fn new(aspace: AddressSpace) -> Mm {
        let root = aspace.pt.root;
        Mm(Arc::new(Inner { holder: AtomicUsize::new(FREE), aspace: UnsafeCell::new(aspace) }), root)
    }

    /// One held by this CPU (a process it has checked out).
    pub fn new_held(aspace: AddressSpace) -> Mm {
        let mm = Mm::new(aspace);
        mm.lock();
        mm
    }

    /// Take the gate, waiting for whoever has it: another CPU's fast
    /// entry, or exclusive code looking at it (each brief).
    pub fn lock(&self) {
        self.0.lock();
    }

    pub fn unlock(&self) {
        self.0.unlock();
    }

    /// The root of its page table (what TTBR0 or CR3 holds for it).
    pub fn root(&self) -> u64 {
        self.1
    }

    /// Does this CPU hold it?
    pub fn held(&self) -> bool {
        self.0.held()
    }

    /// A reference for this CPU's fast entries (`fast::update`).
    pub fn share(&self) -> Arc<Inner> {
        self.0.clone()
    }

    /// Is `inner` this address space?
    pub fn is(&self, inner: &Arc<Inner>) -> bool {
        Arc::ptr_eq(&self.0, inner)
    }

    /// The address space, for code that may not hold its gate (another
    /// process's): taken until the guard goes, unless this CPU holds it.
    pub fn access(&self) -> Guard<'_> {
        let take = !self.held();
        if take {
            self.lock();
        }
        Guard { inner: &self.0, release: take }
    }
}

impl Inner {
    pub fn lock(&self) {
        let me = crate::smp::me();
        debug_assert!(self.holder.load(Ordering::Relaxed) != me, "address space gate taken twice on CPU {me}");
        while self.holder.compare_exchange_weak(FREE, me, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        #[cfg(debug_assertions)]
        HELD[me].fetch_add(1, Ordering::Relaxed);
    }

    pub fn unlock(&self) {
        debug_assert!(self.held(), "address space gate released by a CPU without it");
        #[cfg(debug_assertions)]
        HELD[crate::smp::me()].fetch_sub(1, Ordering::Relaxed);
        self.holder.store(FREE, Ordering::Release);
    }

    pub fn held(&self) -> bool {
        self.holder.load(Ordering::Relaxed) == crate::smp::me()
    }

    /// The address space; only with the gate held (the caller's to see to).
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get(&self) -> &mut AddressSpace {
        debug_assert!(self.held(), "address space used without its gate");
        // SAFETY: the caller holds the gate, so nothing else reaches it.
        unsafe { &mut *self.aspace.get() }
    }
}

impl Drop for Mm {
    /// A process going lets its gate go (the address space itself goes
    /// with the last reference).
    fn drop(&mut self) {
        if self.held() {
            self.unlock();
        }
    }
}

impl Deref for Mm {
    type Target = AddressSpace;
    fn deref(&self) -> &AddressSpace {
        debug_assert!(self.held(), "address space used without its gate (not this CPU's process: Mm::access)");
        // SAFETY: held by this CPU (the running process's, checked out here).
        unsafe { &*self.0.aspace.get() }
    }
}

impl DerefMut for Mm {
    fn deref_mut(&mut self) -> &mut AddressSpace {
        // SAFETY: as for `deref`, and `&mut self` is the only way in here.
        unsafe { self.0.get() }
    }
}

pub struct Guard<'a> {
    inner: &'a Inner,
    release: bool,
}

impl Deref for Guard<'_> {
    type Target = AddressSpace;
    fn deref(&self) -> &AddressSpace {
        // SAFETY: held (by this guard, or this CPU's checked-out process).
        unsafe { self.inner.get() }
    }
}

impl DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut AddressSpace {
        // SAFETY: as for `deref`.
        unsafe { self.inner.get() }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if self.release {
            self.inner.unlock();
        }
    }
}
