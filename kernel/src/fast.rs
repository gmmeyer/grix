//! Kernel entries that don't take the big kernel lock.
//!
//! Most exceptions take the kernel lock (`smp::enter`). A few, which touch
//! nothing of the kernel's but this CPU's own state and the running
//! process's address space, are handled before that, here, and go
//! straight back to user mode, so CPUs running threads of one process, or
//! of several, take them at the same time:
//!
//! - page faults that fill an empty entry with a new frame
//!   (`AddressSpace::fast_fault`), under the address space's gate;
//! - system calls that only report what `Snapshot` holds (getpid and the
//!   like), and sched_yield with no thread waiting to run anywhere: no
//!   lock at all (`syscall`).
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
//! A snapshot stays right while its thread runs: what only the thread
//! changes comes back through the lock, which takes a new one, and what
//! another CPU may change meanwhile (a parent's end reparenting, a
//! sibling thread's setuid, seccomp's TSYNC) calls `changed`, after which
//! every CPU's snapshot is stale until its next `update`.
//!
//! A CPU leaves user mode for nothing else: pending signals, preemption
//! and the like reach it as interrupts (kicks, its timer), which it takes
//! on its way back, as from user code.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use grix_abi::machine::MAX_CPUS;

use crate::arch::{self, TrapFrame};
use crate::mm::aspace::Access;
use crate::mm::gate;
use crate::process::{Process, Thread};
use crate::smp::{self, Stat};
use crate::syscall::table::nr;

/// What this CPU's fast entries may use: kept in step with the thread it
/// runs by `smp::unlock`, the only writer, on this CPU.
pub struct Snapshot {
    /// The running process's address space (none: no thread).
    mm: Option<Arc<gate::Inner>>,
    /// `GENERATION` when it was taken: stale once that moves on.
    generation: u64,
    /// Its thread may make fast system calls (`calls_allowed`).
    calls: bool,
    pid: u32,
    tid: u32,
    ppid: u32,
    ruid: u32,
    euid: u32,
    rgid: u32,
    egid: u32,
}

const EMPTY: Snapshot =
    Snapshot { mm: None, generation: 0, calls: false, pid: 0, tid: 0, ppid: 0, ruid: 0, euid: 0, rgid: 0, egid: 0 };

/// Bumped whenever something a snapshot holds may have changed for a
/// thread running on another CPU (`changed`).
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Something a thread's snapshot holds changed, and it may be running on
/// another CPU: a process's parent or credentials, a thread's seccomp
/// state, a process's AIO polls. With the kernel lock, after the change.
pub fn changed() {
    GENERATION.fetch_add(1, Ordering::Release);
}

/// May thread `t` of `p` take its system calls here? Not with seccomp (its
/// filters see every call), nor in the middle of one (a call waited in,
/// restarted, or with a mask or a FIFO open to finish: `syscall::handle`
/// sees to those), nor with AIO polls to complete at its next call.
fn calls_allowed(p: &Process, t: &Thread) -> bool {
    t.seccomp.mode == crate::seccomp::MODE_DISABLED
        && !t.restarting
        && !t.recheck
        && t.restart_deadline.is_none()
        && t.io_done == 0
        && t.saved_sigmask.is_none()
        && t.fifo_wait.is_none()
        && t.lock_wait.is_none()
        && !p.aio.polling()
}

#[repr(align(128))]
struct Slot(UnsafeCell<Snapshot>);

// SAFETY: each CPU touches only its own slot, with interrupts masked (in
// the kernel), so never two at once.
unsafe impl Sync for Slot {}

static SLOTS: [Slot; MAX_CPUS as usize] = [const { Slot(UnsafeCell::new(EMPTY)) }; MAX_CPUS as usize];

/// This CPU's snapshot.
#[allow(clippy::mut_from_ref)]
fn here() -> &'static mut Snapshot {
    // SAFETY: see `Slot`; the reference doesn't outlive the kernel entry.
    unsafe { &mut *SLOTS[smp::me()].0.get() }
}

/// Set this CPU's snapshot for the thread it now runs, `tid` of `p`
/// (`None`: none), with the kernel lock and that process's gate. A
/// previous address space may go here (its last reference): this CPU's
/// TTBR0 is no longer it.
pub fn update(running: Option<(&Process, u32)>) {
    let s = here();
    let Some((p, tid)) = running else {
        s.mm = None;
        s.calls = false;
        return;
    };
    if !s.mm.as_ref().is_some_and(|mm| p.aspace.is(mm)) {
        s.mm = Some(p.aspace.share());
    }
    s.generation = GENERATION.load(Ordering::Acquire);
    s.calls = p.threads.get(&tid).is_some_and(|t| calls_allowed(p, t));
    (s.pid, s.tid, s.ppid) = (p.pid, tid, p.ppid);
    (s.ruid, s.euid, s.rgid, s.egid) = (p.ids.ruid, p.uid, p.ids.rgid, p.gid);
}

/// A system call: done (true, its result in `tf`), or left for the usual
/// path. Nothing is locked, and nothing but `tf` and counters written.
pub fn syscall(tf: &mut TrapFrame) -> bool {
    let s = here();
    if !s.calls || s.generation != GENERATION.load(Ordering::Acquire) {
        return false;
    }
    #[allow(non_upper_case_globals)]
    let r = match u32::try_from(tf.syscall_nr()) {
        Ok(nr::getpid) => s.pid,
        Ok(nr::gettid) => s.tid,
        Ok(nr::getppid) => s.ppid,
        Ok(nr::getuid) => s.ruid,
        Ok(nr::geteuid) => s.euid,
        Ok(nr::getgid) => s.rgid,
        Ok(nr::getegid) => s.egid,
        // Yielding to nobody: no thread waits to run, anywhere (one
        // queued meanwhile came after the yield).
        Ok(nr::sched_yield) if crate::process::queued() == 0 => 0,
        _ => return false,
    };
    tf.set_return(r as u64);
    crate::stats::syscall();
    smp::note(Stat::Syscall, 1);
    smp::note(Stat::Fast, 1);
    true
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
