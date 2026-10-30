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
//! process it runs into its slot of `PROCESS` (`lock`) and puts it back
//! (`unlock`),
//! so the rest of the kernel still sees "the running process" and "the
//! others". Each CPU keeps its own scheduling state (`Cpu`: process,
//! thread, time slice), swapped into the `Process` fields the kernel uses
//! (`current`, `slice_start`, `resched`, `running`) while it holds the
//! lock. Finishing off a process that ended, and execve, wait
//! until the CPU doing it is the only one running the process (`alone`):
//! the others leave it at their next scheduling point, which a kick (an
//! SGI) brings forward.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use grix_abi::machine::MAX_CPUS;

use crate::arch::{self, TrapFrame, irq};
use crate::process::{self, Process};
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
    /// The user page table in TTBR0 (0: the empty one).
    ttbr: u64,
}

const IDLE: Cpu = Cpu { pid: None, tid: None, slice_start: 0, resched: false, ttbr: 0 };

/// Indexed by CPU; only touched with the kernel lock held.
static CPUS: spin::Mutex<[Cpu; N]> = spin::Mutex::new([IDLE; N]);
/// Online CPUs.
static ONLINE: AtomicU32 = AtomicU32::new(1);
/// The machine's CPUs.
static COUNT: AtomicU32 = AtomicU32::new(1);
/// The big kernel lock: a ticket lock whose turn can be skipped
/// (`acquire`). Tickets come from `NEXT`; `LOCK` is the ticket served (low
/// 32 bits) and whether its CPU has taken the lock (`HELD`), in one word
/// so taking a turn and skipping it are one compare-and-swap.
static NEXT: AtomicU32 = AtomicU32::new(0);
static LOCK: AtomicU64 = AtomicU64::new(0);
const HELD: u64 = 1 << 32;
/// How long the lock may lie free with its turn untaken before a waiter
/// moves the turn on, in µs.
const SKIP_US: u64 = 20;
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

/// What each CPU counts, for /proc/grix/smp: how often it enters the
/// kernel and why, and what the kernel lock and TLB flushes cost it.
#[derive(Clone, Copy)]
pub enum Stat {
    /// Entries: system calls, other exceptions (page faults mostly), and
    /// interrupts from user mode.
    Syscall,
    Fault,
    Irq,
    /// Interrupts taken, from user mode or while idle: the timer's, and
    /// of those the ones after which nothing woke or was preempted; kicks;
    /// devices'.
    Timer,
    TimerIdle,
    Kick,
    Device,
    /// Kicks this CPU sent.
    KickSent,
    /// Counter ticks spent waiting for the kernel lock, and holding it.
    LockWait,
    LockHeld,
    /// The longest single wait for it (counter ticks).
    LockWaitMax,
    /// Turns this CPU skipped, their CPU not taking the lock (`acquire`).
    LockSkip,
    /// TLB flushes this CPU asked for, the IPIs they sent (x86_64), and
    /// counter ticks spent waiting for those to be acknowledged.
    Flush,
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    FlushIpi,
    FlushWait,
    /// Entries handled without the kernel lock (`fast`), counted among
    /// the syscalls and faults too.
    Fast,
}

const STATS: usize = Stat::Fast as usize + 1;
/// The names /proc/grix/smp shows, in `Stat`'s order (times in µs).
const STAT_NAMES: [&str; STATS] = [
    "syscall",
    "fault",
    "irq",
    "timer",
    "timer_idle",
    "kick",
    "device",
    "kick_sent",
    "lock_wait_us",
    "lock_held_us",
    "lock_wait_max_us",
    "lock_skip",
    "flush",
    "flush_ipi",
    "flush_wait_us",
    "fast",
];
/// A CPU's counts, on cache lines of their own.
#[repr(align(128))]
struct Counts([AtomicU64; STATS]);
static COUNTS: [Counts; N] = [const { Counts([const { AtomicU64::new(0) }; STATS]) }; N];
/// When this CPU took the kernel lock (`Stat::LockHeld`).
static TAKEN: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

/// Count `n` of `stat` on CPU `cpu`.
pub fn note_on(cpu: usize, stat: Stat, n: u64) {
    COUNTS[cpu % N].0[stat as usize].fetch_add(n, Ordering::Relaxed);
}

/// Count `n` of `stat` on this CPU.
pub fn note(stat: Stat, n: u64) {
    note_on(me(), stat, n);
}

/// What a kernel stack holds until it's first used: its high-water mark
/// is the lowest word that isn't this (`stack_used`).
const STACK_PAINT: u64 = 0x6b73_7461_636b_2121;

/// Paint CPU `cpu`'s kernel stack below `limit` (its top for a CPU that
/// hasn't started).
fn paint_stack(cpu: usize, limit: u64) {
    let mut at = arch::stack_bottom(cpu);
    while at < limit {
        // SAFETY: that CPU's stack, below anything in use there. Volatile:
        // no call to memset, whose own frame could be below `limit`.
        unsafe { (at as *mut u64).write_volatile(STACK_PAINT) };
        at += 8;
    }
}

/// Paint the rest of this CPU's stack (CPU 0's, which it boots on).
#[inline(never)]
pub fn paint_own_stack() {
    let here = 0u64;
    // Below this frame, and room for the loop's own.
    paint_stack(me(), ((&raw const here) as u64 & !7) - 512);
}

/// The most of CPU `cpu`'s kernel stack used so far (bytes).
pub fn stack_used(cpu: usize) -> u64 {
    let (mut at, top) = (arch::stack_bottom(cpu), arch::stack_top(cpu));
    // SAFETY: inside the stack, which is mapped; another CPU may be
    // writing it, and only how deep it has ever gone matters.
    while at < top && unsafe { (at as *const u64).read_volatile() } == STACK_PAINT {
        at += 8;
    }
    top - at
}

/// Panic if this CPU's kernel stack has run into its canary: its lowest
/// `arch::CANARY_SIZE` bytes, painted at boot, which nothing may use
/// (there's no guard page, `arch::stack`). On every way back to user mode
/// and before the idle wait, so an overflow is reported before anything
/// else runs on the CPU; it has written only into this CPU's emergency
/// stack, below.
pub fn check_stack() {
    let cpu = me();
    let bottom = arch::stack_bottom(cpu);
    // A word of each cache line: four loads, on every return to user mode.
    let mut changed = 0;
    for at in (bottom..bottom + arch::CANARY_SIZE).step_by(64) {
        // SAFETY: inside this CPU's stack, which is mapped.
        changed |= unsafe { (at as *const u64).read_volatile() } ^ STACK_PAINT;
    }
    if changed != 0 {
        panic!("kernel stack overflow on CPU {cpu} (its canary at {bottom:#x} was written)");
    }
}

/// /proc/grix/smp: a header, a line per CPU, and their sum.
pub fn stats(s: &mut alloc::string::String) {
    use core::fmt::Write;
    let freq = arch::counter_freq().max(1);
    let shown = |i: usize, v: u64| match i {
        i if [Stat::LockWait, Stat::LockHeld, Stat::LockWaitMax, Stat::FlushWait].iter().any(|&t| t as usize == i) => {
            (v as u128 * 1_000_000 / freq as u128) as u64
        }
        _ => v,
    };
    // And the deepest each CPU's kernel stack has been (bytes).
    let _ = writeln!(s, "cpu {} stack_max", STAT_NAMES.join(" "));
    let (mut all, mut stack) = ([0u64; STATS], 0);
    for (cpu, counts) in COUNTS.iter().enumerate().take(count() as usize) {
        let _ = write!(s, "{cpu}");
        for (i, c) in counts.0.iter().enumerate() {
            let v = c.load(Ordering::Relaxed);
            all[i] = if i == Stat::LockWaitMax as usize { all[i].max(v) } else { all[i] + v };
            let _ = write!(s, " {}", shown(i, v));
        }
        let used = stack_used(cpu);
        stack = stack.max(used);
        let _ = writeln!(s, " {used}");
    }
    let _ = write!(s, "all");
    for (i, &v) in all.iter().enumerate() {
        let _ = write!(s, " {}", shown(i, v));
    }
    let _ = writeln!(s, " {stack}");
}

/// A fast entry (`fast`) starts, without the kernel lock: as one in the
/// kernel for `barrier_others` and x86_64's TLB flushes, which then leave
/// it to catch up (`arch::tlb_sync`) once it has the address space's gate.
pub fn fast_enter() {
    let cpu = me();
    IN_KERNEL[cpu].store(true, Ordering::SeqCst);
    ENTRIES[cpu].fetch_add(1, Ordering::SeqCst);
}

/// It's done (still holding the gate: a flush that comes after sees it
/// out of the kernel, and its IPI is taken on the way back to user mode).
/// A full barrier, for `barrier_others`, which took being in the kernel
/// for one: nothing else on the way back to user mode is.
pub fn fast_leave() {
    check_stack();
    IN_KERNEL[me()].store(false, Ordering::SeqCst);
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// Take the kernel for an exception of kind `why` (`Stat::Syscall`,
/// `Fault` or `Irq`).
pub fn enter(why: Stat) {
    note(why, 1);
    lock();
}

/// Take the kernel, and make the process this CPU runs its `PROCESS`, with
/// this CPU's scheduling state in it. A CPU with no thread takes none: it
/// schedules from no process (`sched::schedule`), so it never holds one
/// another CPU may want.
pub fn lock() {
    debug_assert!(!crate::fast::active(), "a fast entry took the kernel lock");
    let cpu = me();
    IN_KERNEL[cpu].store(true, Ordering::SeqCst);
    ENTRIES[cpu].fetch_add(1, Ordering::SeqCst);
    let start = arch::counter();
    acquire();
    let taken = arch::counter();
    let waited = taken.wrapping_sub(start);
    note_on(cpu, Stat::LockWait, waited);
    COUNTS[cpu].0[Stat::LockWaitMax as usize].fetch_max(waited, Ordering::Relaxed);
    TAKEN[cpu].store(taken, Ordering::Relaxed);
    arch::tlb_sync();
    let me = me();
    let cpu = CPUS.lock()[me];
    let mut guard = process::running().lock();
    let mut procs = PROCS.lock();
    let checked_out = guard.is_none();
    if checked_out {
        // Gone if it ended (finished off on another CPU).
        *guard = cpu.pid.and_then(|pid| procs.others.remove(&pid));
    }
    if let Some(p) = guard.as_mut() {
        // A thread that ended while this CPU ran it (exit_group, execve on
        // another CPU) is gone: nothing runs here until it schedules.
        let tid = cpu.tid.filter(|t| cpu.pid == Some(p.pid) && p.threads.contains_key(t));
        p.current = tid.unwrap_or(NO_THREAD);
        p.running = tid.is_some();
        p.slice_start = cpu.slice_start;
        p.resched = cpu.resched || tid.is_none() && cpu.tid.is_some();
        process::set_current_pid(p.pid);
        // Its address space, from a fast entry on another CPU if one has it.
        if checked_out {
            p.aspace.lock();
        }
    }
    drop(procs);
    drop(guard);
    debug_assert!(checked_out_elsewhere(me) == 0, "a process checked out on another CPU");
}

/// Is this CPU the only one with a process checked out? (Always, under
/// the kernel lock.)
pub fn exclusive() -> bool {
    checked_out_elsewhere(me()) == 0
}

/// How many CPUs other than `me` have a process in their slot of
/// `PROCESS`. Under the kernel lock, none: only the holder has one.
fn checked_out_elsewhere(me: usize) -> usize {
    (0..N).filter(|&i| i != me && process::PROCESS[i].lock().is_some()).count()
}

/// Keep this CPU's scheduling state, put its process back with the others
/// (or, if it has ended, let it go), kick idle CPUs for threads waiting
/// to run anywhere, and give the kernel back.
pub fn unlock() {
    let me = me();
    {
        let mut cpus = CPUS.lock();
        let taken = process::running().lock().take();
        debug_assert!(checked_out_elsewhere(me) == 0, "a process checked out on another CPU");
        let mut procs = PROCS.lock();
        if taken.is_none() {
            (cpus[me].tid, cpus[me].pid) = (None, None);
            crate::fast::update(None);
        }
        if let Some(mut p) = taken {
            let c = &mut cpus[me];
            c.tid = (p.running && p.current != NO_THREAD).then_some(p.current);
            c.pid = c.tid.map(|_| p.pid);
            c.slice_start = p.slice_start;
            c.resched = p.resched;
            crate::fast::update(c.tid.map(|tid| (&*p, tid)));
            // What's per CPU stays with the CPU.
            p.running = false;
            p.current = NO_THREAD;
            if p.dead {
                // Finished off (no other CPU runs it): its address space
                // goes, once it isn't this CPU's.
                if c.ttbr == p.aspace.root() {
                    arch::set_user_page_table(arch::empty_page_table());
                    c.ttbr = 0;
                }
            } else {
                p.aspace.unlock();
                procs.others.insert(p.pid, p);
            }
        }
        // Idle CPUs for the threads waiting to run (looked for only if
        // there are any).
        let idle = (0..online()).filter(|&i| i != me && cpus[i].tid.is_none()).count();
        if idle > 0 && process::queued() > 0 {
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
    note_on(me, Stat::LockHeld, arch::counter().wrapping_sub(TAKEN[me].load(Ordering::Relaxed)));
    // Back to user mode (or idle) holding no address space's gate.
    debug_assert!(crate::mm::gate::none_held(), "CPU {me} left the kernel holding an address space's gate");
    IN_KERNEL[me].store(false, Ordering::SeqCst);
    // Only the holder changes it while it's held: the next turn, free.
    let served = LOCK.load(Ordering::Relaxed) as u32;
    LOCK.store(served.wrapping_add(1) as u64, Ordering::Release);
}

/// Take the kernel lock, in turn. A plain ticket lock is fair, and
/// hands the lock straight to the next waiter (which a futex ping-pong
/// between CPUs wants: test-and-set let the CPU that just gave the lock
/// back win it again, and ran that at a third of the speed). But in a VM
/// the CPU whose turn is next may be a vCPU the host has descheduled, and
/// then every CPU waits for it, the lock free all the while, for as long
/// as the host keeps it off (Linux's virt_spin_lock gives up queueing in
/// guests for this). So when the lock has lain free with its turn untaken
/// for `SKIP_US`, a waiter moves the turn on, and the CPU whose turn it
/// was takes a new ticket when it runs again.
fn acquire() {
    let skip = arch::counter_freq() * SKIP_US / 1_000_000;
    let mut ticket = NEXT.fetch_add(1, Ordering::Relaxed);
    // The free, untaken turn last seen, and since when.
    let mut stalled = (u64::MAX, 0);
    loop {
        let v = LOCK.load(Ordering::Acquire);
        let serving = v as u32;
        if v & HELD == 0 && serving == ticket {
            if LOCK.compare_exchange_weak(v, v | HELD, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                return;
            }
            continue;
        }
        if (serving.wrapping_sub(ticket) as i32) > 0 {
            // Skipped while this CPU wasn't running: to the back.
            ticket = NEXT.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if v & HELD == 0 {
            let now = arch::counter();
            if stalled.0 != v {
                stalled = (v, now);
            } else if now.wrapping_sub(stalled.1) > skip {
                let next = serving.wrapping_add(1) as u64;
                if LOCK.compare_exchange(v, next, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    note(Stat::LockSkip, 1);
                }
            }
        }
        // The lock's holder may be waiting for this (`flush_tables`).
        arch::tlb_sync();
        core::hint::spin_loop();
    }
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

/// How many CPUs are up.
pub fn online() -> usize {
    ONLINE.load(Ordering::Relaxed) as usize
}

/// Is CPU `cpu` in the kernel, or waiting for it (with interrupts off)?
/// For x86_64's TLB flushes (arm64's are broadcast).
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub fn in_kernel(cpu: usize) -> bool {
    IN_KERNEL[cpu % N].load(Ordering::SeqCst)
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

/// Does CPU `cpu` (another) run a thread?
pub fn has_thread(cpu: usize) -> bool {
    CPUS.lock()[cpu % N].tid.is_some()
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
    note(Stat::KickSent, 1);
    WORK[cpu].store(true, Ordering::Release);
    irq::send_sgi(cpu as u32);
    arch::vmm_kick(cpu);
}

/// Called last on every exception, with the kernel lock: if this CPU has
/// no thread (it parked, or idles), wait for something to run without
/// holding anything, and load it into `tf`. Then give the kernel back.
pub fn finish(tf: &mut TrapFrame) {
    check_stack();
    // Schedule before waiting: a CPU whose thread just ended may have
    // others to run.
    loop {
        let picked = {
            let mut guard = process::running().lock();
            if let Some(p) = guard.as_mut().filter(|p| p.running) {
                activate(p);
                break;
            }
            crate::sched::schedule(&mut guard, tf);
            // Its address space, before anything reads or writes its
            // memory (a signal frame, below).
            let p = guard.as_ref().filter(|p| p.running);
            if let Some(p) = p {
                activate(p);
            }
            p.is_some()
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
        let quiet = crate::sched::quiet();
        check_stack();
        unlock_idle();
        if quiet {
            wait();
        }
        lock();
        crate::sched::interrupts();
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
    let root = p.aspace.root();
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
    CPUS.lock()[0].ttbr = process::running().lock().as_ref().map_or(0, |p| p.aspace.root());
    for cpu in 1..count() {
        let entry = arch::secondary_entry_phys();
        let stack = arch::stack_top(cpu as usize);
        paint_stack(cpu as usize, stack);
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
pub extern "C" fn secondary_main(frame: *mut TrapFrame) -> ! {
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
    // Nothing yet (no process either): wait for a thread, like any CPU
    // that has none.
    lock();
    finish(tf);
    // SAFETY: `frame` holds the thread's user state, at the top of the
    // stack, as a trap would have left it.
    unsafe { arch::return_to_frame(frame) }
}
