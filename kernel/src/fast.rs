//! Kernel entries that don't take the big kernel lock.
//!
//! Most exceptions take the kernel lock (`smp::enter`). A few, which touch
//! nothing of the kernel's but this CPU's own state and the running
//! process's address space, are handled before that, here, and go
//! straight back to user mode, so CPUs running threads of one process, or
//! of several, take them at the same time:
//!
//! - page faults that fill an empty entry with a new frame
//!   (`AddressSpace::fast_fault`), under the address space's gate.
//!
//! What a CPU may use here is `Snapshot`, its own copy of what the kernel
//! lock's holder last left it (`smp::unlock`), and the address space it
//! names, with its gate. Never the process (it's in `procs::PROCS`, where
//! the lock's holder may be changing it), another CPU's state, the
//! filesystem, the scheduler's or anything else the lock covers. Nothing
//! here waits but for the gate, whose holders never wait for this CPU,
//! and anything that can't be done this way is left to the usual path,
//! untouched (it starts again from the exception).
//!
//! A CPU leaves user mode for nothing else: pending signals, preemption
//! and the like reach it as interrupts (kicks, its timer), which it takes
//! on its way back, as from user code.

use alloc::sync::Arc;
use core::cell::UnsafeCell;

use grix_abi::machine::MAX_CPUS;

use crate::arch;
use crate::mm::aspace::Access;
use crate::mm::gate;
use crate::smp::{self, Stat};

/// What this CPU's fast entries may use: kept in step with the thread it
/// runs by `smp::unlock`, the only writer, on this CPU.
pub struct Snapshot {
    /// The running process's address space (none: no thread).
    mm: Option<Arc<gate::Inner>>,
}

#[repr(align(128))]
struct Slot(UnsafeCell<Snapshot>);

// SAFETY: each CPU touches only its own slot, with interrupts masked (in
// the kernel), so never two at once.
unsafe impl Sync for Slot {}

static SLOTS: [Slot; MAX_CPUS as usize] = [const { Slot(UnsafeCell::new(Snapshot { mm: None })) }; MAX_CPUS as usize];

/// This CPU's snapshot.
#[allow(clippy::mut_from_ref)]
fn here() -> &'static mut Snapshot {
    // SAFETY: see `Slot`; the reference doesn't outlive the kernel entry.
    unsafe { &mut *SLOTS[smp::me()].0.get() }
}

/// Set this CPU's snapshot for the process it now runs a thread of
/// (`None`: no thread), with the kernel lock and that process's gate.
/// A previous address space may go here (its last reference): this CPU's
/// TTBR0 is no longer it.
pub fn update(p: Option<&crate::process::Process>) {
    let s = here();
    match p {
        Some(p) if s.mm.as_ref().is_some_and(|mm| p.aspace.is(mm)) => {}
        Some(p) => s.mm = Some(p.aspace.share()),
        None => s.mm = None,
    }
}

/// A page fault at `va` from user mode: handled (true), or left for the
/// usual path. On arm64 a translation fault; on x86_64 one on a page not
/// present.
pub fn fault(va: u64, access: Access) -> bool {
    let Some(mm) = here().mm.as_ref() else { return false };
    smp::fast_enter();
    mm.lock();
    // Flushes of this address space happen with its gate held: any this
    // CPU missed (in the kernel, it couldn't take their IPI) are done now.
    arch::tlb_sync();
    // SAFETY: the gate is held.
    let done = unsafe { mm.get() }.fast_fault(va, access);
    smp::fast_leave();
    mm.unlock();
    if done {
        crate::stats::page_fault();
        smp::note(Stat::Fault, 1);
        smp::note(Stat::Fast, 1);
    }
    done
}
