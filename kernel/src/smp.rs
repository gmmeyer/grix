//! More than one CPU (`Image::cpus`).
//!
//! The kernel stays the single-CPU kernel it was, made safe by one lock:
//! every exception takes the big kernel lock (`lock`) and releases it on
//! the way back to EL0 (`unlock`). Kernel work never blocks (it returns
//! EBLOCKED and restarts), so the lock is held only briefly, and no CPU
//! ever waits holding it: a CPU with nothing to run waits in `finish`
//! with no locks at all.
//!
//! What runs in parallel is user code: each CPU runs a thread of any
//! process, several processes at once. Between kernel entries every
//! process lives in `procs::PROCS`; the CPU that takes the lock moves the
//! process it runs into `PROCESS` (`lock`) and puts it back (`unlock`),
//! so the rest of the kernel still sees "the running process" and "the
//! others". Each CPU keeps its own scheduling state (`Cpu`: process,
//! thread, time slice), swapped into the `Process` fields the kernel uses
//! (`current`, `slice_start`, `resched`, `timer_dirty`, `running`) while it
//! holds the lock. Finishing off a process that ended, and execve, wait
//! until the CPU doing it is the only one running the process (`alone`):
//! the others leave it at their next scheduling point, which a kick (an
//! SGI) brings forward.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use grix_abi::machine::MAX_CPUS;

use crate::arch::{self, TrapFrame, irq};
use crate::process::{PROCESS, Process};
use crate::procs::PROCS;

const N: usize = MAX_CPUS as usize;
/// `Process::current` on a CPU with no thread.
pub const NO_THREAD: u32 = u32::MAX;

/// One CPU's scheduling state, kept here while another CPU has the kernel.
#[derive(Clone, Copy)]
struct Cpu {
    /// The process this CPU runs a thread of, and the thread, if any.
    pid: Option<u32>,
    tid: Option<u32>,
    slice_start: u64,
    resched: bool,
    timer_dirty: bool,
    /// The user page table in TTBR0 (0: the empty one).
    ttbr: u64,
}

const IDLE: Cpu = Cpu { pid: None, tid: None, slice_start: 0, resched: false, timer_dirty: true, ttbr: 0 };

/// Indexed by CPU; only touched with the kernel lock held.
static CPUS: spin::Mutex<[Cpu; N]> = spin::Mutex::new([IDLE; N]);
/// Online CPUs.
static ONLINE: AtomicU32 = AtomicU32::new(1);
/// The machine's CPUs.
static COUNT: AtomicU32 = AtomicU32::new(1);
/// The big kernel lock: a ticket lock, so no CPU starves.
static NEXT: AtomicU64 = AtomicU64::new(0);
static SERVING: AtomicU64 = AtomicU64::new(0);
/// Something may be runnable for this CPU (set before its kick).
static WORK: [AtomicBool; N] = [const { AtomicBool::new(false) }; N];

/// This CPU (MPIDR affinity 0; the VMMs number CPUs 0..n).
pub fn me() -> usize {
    arch::cpu_number() % N
}

/// How many CPUs the machine has.
pub fn count() -> u32 {
    COUNT.load(Ordering::Relaxed)
}

/// Kernel entries per CPU, and whether it's in the kernel now (counted
/// before it waits for the lock): for `barrier_others`.
static ENTRIES: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static IN_KERNEL: [AtomicBool; N] = [const { AtomicBool::new(false) }; N];

/// Take the kernel, and make the process this CPU runs `PROCESS`, with
/// this CPU's scheduling state in it. A CPU with no thread gets some
/// process to schedule from.
pub fn lock() {
    let cpu = me();
    IN_KERNEL[cpu].store(true, Ordering::SeqCst);
    ENTRIES[cpu].fetch_add(1, Ordering::SeqCst);
    let ticket = NEXT.fetch_add(1, Ordering::Relaxed);
    while SERVING.load(Ordering::Acquire) != ticket {
        core::hint::spin_loop();
    }
    let me = me();
    let cpu = CPUS.lock()[me];
    let mut guard = PROCESS.lock();
    let mut procs = PROCS.lock();
    if guard.is_none() {
        let pid = cpu.pid.filter(|pid| procs.others.contains_key(pid)).or_else(|| procs.others.keys().next().copied());
        *guard = pid.and_then(|pid| procs.others.remove(&pid));
    }
    if let Some(p) = guard.as_mut() {
        // A thread that ended while this CPU ran it (exit_group, execve on
        // another CPU) is gone: nothing runs here until it schedules.
        let tid = cpu.tid.filter(|t| cpu.pid == Some(p.pid) && p.threads.contains_key(t));
        p.current = tid.unwrap_or(NO_THREAD);
        p.running = tid.is_some();
        p.slice_start = cpu.slice_start;
        p.resched = cpu.resched || tid.is_none() && cpu.tid.is_some();
        p.timer_dirty = cpu.timer_dirty;
        crate::process::set_current_pid(p.pid);
    }
}

/// Keep this CPU's scheduling state, put its process back with the others
/// (or, if it has ended, let it go), kick idle CPUs for threads waiting
/// to run anywhere, and give the kernel back.
pub fn unlock() {
    let me = me();
    {
        let mut cpus = CPUS.lock();
        let taken = PROCESS.lock().take();
        let mut procs = PROCS.lock();
        if let Some(mut p) = taken {
            let c = &mut cpus[me];
            c.tid = (p.running && p.current != NO_THREAD).then_some(p.current);
            c.pid = c.tid.map(|_| p.pid);
            c.slice_start = p.slice_start;
            c.resched = p.resched;
            c.timer_dirty = p.timer_dirty;
            // What's per CPU stays with the CPU.
            p.running = false;
            p.current = NO_THREAD;
            if p.dead {
                // Finished off (no other CPU runs it): its address space
                // goes, once it isn't this CPU's.
                if c.ttbr == p.aspace.pt.root {
                    arch::set_user_page_table(arch::empty_page_table());
                    c.ttbr = 0;
                }
            } else {
                procs.others.insert(p.pid, p);
            }
        }
        // Idle CPUs for the threads waiting to run.
        let idle = (0..online()).filter(|&i| i != me && cpus[i].tid.is_none()).count();
        if idle > 0 {
            let mut want: usize = procs
                .others
                .values()
                .filter(|q| crate::sched::runnable(q) && (runs_here(q) || !running_on(&cpus, q.pid)))
                .map(|q| q.runq.len())
                .sum();
            for (i, other) in cpus.iter().enumerate() {
                if want == 0 {
                    break;
                }
                if i != me && i < online() && other.tid.is_none() {
                    kick(i);
                    want -= 1;
                }
            }
        }
    }
    IN_KERNEL[me].store(false, Ordering::SeqCst);
    SERVING.fetch_add(1, Ordering::Release);
}

/// Is a thread of `pid` on any CPU (`cpus`: the CPUs, already locked)?
fn running_on(cpus: &[Cpu; N], pid: u32) -> bool {
    cpus.iter().any(|c| c.pid == Some(pid))
}

/// Every other CPU running a thread (of process `pid`, or of any process)
/// executes a full barrier and a context synchronization (an exception)
/// before this returns: membarrier. One already in the kernel has.
pub fn barrier_others(pid: Option<u32>) {
    if count() == 1 {
        return;
    }
    let me = me();
    let running: [bool; N] = {
        let cpus = CPUS.lock();
        core::array::from_fn(|i| i != me && cpus[i].tid.is_some() && pid.is_none_or(|pid| cpus[i].pid == Some(pid)))
    };
    for (i, &runs) in running.iter().enumerate() {
        if !runs || IN_KERNEL[i].load(Ordering::SeqCst) {
            continue;
        }
        let seen = ENTRIES[i].load(Ordering::SeqCst);
        kick(i);
        // It counts its entry before it waits for the lock we hold.
        while ENTRIES[i].load(Ordering::SeqCst) == seen && !IN_KERNEL[i].load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }
    }
}

/// When the CPU running thread `tid` (another one) started its slice.
pub fn running_since(tid: u32) -> Option<u64> {
    let me = me();
    CPUS.lock().iter().enumerate().find(|(i, c)| *i != me && c.tid == Some(tid)).map(|(_, c)| c.slice_start)
}

fn online() -> usize {
    ONLINE.load(Ordering::Relaxed) as usize
}

/// Is no other CPU running threads of process `pid`?
pub fn alone(pid: u32) -> bool {
    if count() == 1 {
        return true;
    }
    let me = me();
    CPUS.lock().iter().enumerate().all(|(i, c)| i == me || c.pid != Some(pid))
}

/// Does another CPU run a thread of `pid`? (This one, in the kernel, runs
/// none: its entry may name the process it was running when it came in.)
pub fn running_anywhere(pid: u32) -> bool {
    let me = me();
    CPUS.lock().iter().enumerate().any(|(i, c)| i != me && c.pid == Some(pid))
}

/// Does another CPU run a thread of any process (which may wake anyone)?
pub fn others_running() -> bool {
    let me = me();
    CPUS.lock().iter().enumerate().any(|(i, c)| i != me && c.tid.is_some())
}

/// Can more CPUs take threads of `p` now? Not while it waits to be alone
/// (execve, its end), or is stopped.
pub fn runs_here(p: &Process) -> bool {
    !p.exclusive_wanted && p.exit_status.is_none() && !p.stopped
}

/// Make the other CPUs running threads of `pid` come into the kernel and
/// schedule (they then leave it if it wants to be alone, has ended or has
/// stopped).
pub fn kick_others(pid: u32) {
    let me = me();
    let mut cpus = CPUS.lock();
    for (i, c) in cpus.iter_mut().enumerate() {
        if i != me && c.pid == Some(pid) {
            c.resched = true;
            kick(i);
        }
    }
}

/// If thread `tid` runs on another CPU, make that CPU enter the kernel
/// (where a pending signal is delivered).
pub fn kick_thread(tid: u32) {
    if count() == 1 {
        return;
    }
    let me = me();
    let cpus = CPUS.lock();
    if let Some(i) = cpus.iter().enumerate().position(|(i, c)| i != me && c.tid == Some(tid)) {
        kick(i);
    }
}

/// Wake CPU `cpu`: from its wait in `finish`, or out of user code.
fn kick(cpu: usize) {
    WORK[cpu].store(true, Ordering::Release);
    irq::send_sgi(cpu as u32);
    arch::vmm_kick(cpu);
}

/// Called last on every exception, with the kernel lock: if this CPU has
/// no thread (it parked, or idles), wait for something to run without
/// holding anything, and load it into `tf`. Then give the kernel back.
pub fn finish(tf: &mut TrapFrame) {
    // Schedule before waiting: a CPU whose thread just ended may have
    // others to run.
    let mut look = true;
    loop {
        let picked = {
            let mut guard = PROCESS.lock();
            let Some(p) = guard.as_mut() else { break };
            if p.running {
                activate(p);
                break;
            }
            if look {
                crate::sched::schedule(p, tf);
            }
            // Its address space, before anything reads or writes its
            // memory (a signal frame, below).
            if p.running {
                activate(p);
            }
            p.running
        };
        if picked {
            // Picked here: its pending signals haven't been looked at (a
            // thread that never enters the kernel, alone on its CPU, would
            // never take them: Go waits for each preemption signal to land
            // before sending another).
            crate::signal::return_to_user(tf);
            continue;
        }
        // Checking on the host may itself have freed room for a writer.
        let quiet = crate::ipc::generation() == crate::sched::polled();
        unlock_idle();
        if quiet {
            wait();
        }
        lock();
        if let Some(id) = irq::ack() {
            crate::sched::handle_interrupt(id);
        }
        look = true;
    }
    unlock();
}

/// Give the kernel back from a CPU with no thread, its user page table
/// away (so nothing it caches outlives the tables), its timer as idle
/// left it.
fn unlock_idle() {
    let me = me();
    {
        let mut cpus = CPUS.lock();
        if cpus[me].ttbr != 0 {
            arch::set_user_page_table(arch::empty_page_table());
            cpus[me].ttbr = 0;
        }
    }
    unlock();
}

/// Until there's something to do: a kick, or an interrupt for this CPU.
fn wait() {
    let me = me();
    while !WORK[me].swap(false, Ordering::Acquire) && !irq::pending() {
        arch::wait_for_interrupt();
    }
}

/// Point this CPU's TTBR0 at `p`'s address space, if it isn't already.
fn activate(p: &Process) {
    let root = p.aspace.pt.root;
    let mut cpus = CPUS.lock();
    let c = &mut cpus[me()];
    if c.ttbr != root {
        p.aspace.activate();
        c.ttbr = root;
    }
}

/// The process's address space was just put in TTBR0 here (a switch).
pub fn activated(root: u64) {
    CPUS.lock()[me()].ttbr = root;
}

/// Start the other CPUs (on CPU 0, before the program runs).
pub fn start(cpus: u32) {
    COUNT.store(cpus.clamp(1, MAX_CPUS), Ordering::Relaxed);
    CPUS.lock()[0].ttbr = PROCESS.lock().as_ref().map_or(0, |p| p.aspace.pt.root);
    for cpu in 1..count() {
        let entry = arch::secondary_entry_phys();
        let stack = arch::stack_top(cpu as usize);
        let r = arch::start_cpu(cpu as usize, entry, stack);
        if r != 0 {
            crate::console::klog!("cpu {cpu} didn't start ({r})\n");
            COUNT.store(cpu, Ordering::Relaxed);
            break;
        }
    }
}

/// A secondary CPU, MMU on, on its own stack: set up its part of the GIC
/// and its timer, then run threads as they come.
/// `frame` is the top of its stack, above the Rust code's.
#[unsafe(no_mangle)]
extern "C" fn secondary_main(frame: *mut TrapFrame) -> ! {
    let me = me();
    irq::init_cpu(me);
    arch::allow_user_counter();
    arch::set_user_page_table(arch::empty_page_table());
    ONLINE.fetch_add(1, Ordering::Relaxed);
    debug_assert_eq!(frame as u64 + core::mem::size_of::<TrapFrame>() as u64, arch::stack_top(me));
    // SAFETY: the top of this CPU's own stack, which nothing else uses.
    let tf = unsafe {
        frame.write(TrapFrame::default());
        &mut *frame
    };
    lock();
    // Nothing yet: wait for a thread, like any CPU that has none.
    if let Some(p) = PROCESS.lock().as_mut() {
        p.running = false;
        p.current = NO_THREAD;
    }
    finish(tf);
    // SAFETY: `frame` holds the thread's user state, at the top of the
    // stack, as a trap would have left it.
    unsafe { arch::return_to_frame(frame) }
}
