//! Scheduling on one CPU: round-robin across processes, and across each
//! process's threads, with a time slice driven by the virtual timer. There
//! is a single kernel stack: switching threads means saving the trapped user
//! state into the old thread and loading the new thread's saved state into
//! the trap frame before returning to EL0. Switching processes also swaps
//! the running process's body in `PROCESS` with one from `procs::PROCS`, and
//! the address space in TTBR0.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{self, TrapFrame, irq};
use crate::console;
use crate::process::{PROCESS, Process, WaitOn};
use crate::procs::{self, PROCS, Procs};
use crate::signal::SIGKILL;
use crate::time;
use grix_abi::wire::Event;

pub const SLICE_NS: u64 = 10_000_000;

/// Pick the next runnable thread, in this process or another, and make `tf`
/// its state. If the current thread is still runnable it goes to the back
/// of its run queue; if it blocked or exited it is simply not chosen. An
/// ended process is finished off here, and never runs again.
pub fn schedule(p: &mut Process, tf: &mut TrapFrame) {
    p.resched = false;
    let mut procs = PROCS.lock();
    let prev = p.current;
    // CPU time: prev ran from slice_start until now (not while we idle below).
    let now = time::monotonic_ns();
    if let Some(t) = p.threads.get_mut(&prev) {
        t.cpu_ns += now.saturating_sub(p.slice_start);
        t.regs = *tf;
        // The kernel never touches FP/SIMD or TPIDR_EL0, so the CPU still
        // holds prev's values.
        t.tpidr = arch::tpidr();
        arch::save_fp(&mut t.fp);
        if t.wait.is_none() {
            p.runq.push_back(prev);
        }
    }
    p.running = false;
    if p.exit_status.is_some() && !p.dead {
        procs::finalize(p, None, &mut procs);
    }
    let next = loop {
        procs::reap_others(p, &mut procs);
        poll(p, &mut procs);
        if let Some(pid) = pick(p, &procs) {
            break pid;
        }
        idle(p, &mut procs);
    };
    if next != p.pid {
        let mut body = procs.others.remove(&next).unwrap();
        core::mem::swap(p, &mut body);
        p.aspace.activate();
        // `body` is the process that was running: back with the others,
        // unless it has ended (its address space is no longer in TTBR0).
        if !body.dead {
            procs.others.insert(body.pid, body);
        }
    }
    drop(procs);
    let tid = p.runq.pop_front().unwrap();
    let t = &p.threads[&tid];
    arch::set_tpidr(t.tpidr);
    arch::restore_fp(&t.fp);
    *tf = t.regs;
    p.current = tid;
    p.running = true;
    p.slice_start = time::monotonic_ns();
    p.timer_dirty = true;
    update_timer(p);
}

/// The process to run next: the first after this one (by pid, wrapping)
/// with a runnable thread, so processes take turns; this one if it's the
/// only one.
fn pick(p: &Process, procs: &Procs) -> Option<u32> {
    let runnable = |(&pid, q): (&u32, &Process)| (!q.runq.is_empty()).then_some(pid);
    let others = procs.others.range(p.pid + 1..).chain(procs.others.range(..p.pid));
    others.filter_map(runnable).next().or_else(|| (!p.runq.is_empty()).then_some(p.pid))
}

/// Everything due, in every process: timers, I/O waiters, expired
/// deadlines. Returns whether anything woke.
fn poll(p: &mut Process, procs: &mut Procs) -> bool {
    let mut woke = false;
    for sig in console::take_host_signals() {
        woke |= from_host(p, procs, sig);
    }
    // Until I/O state stops changing (a timer can fire a timerfd), so every
    // waiter has seen the generation `idle` compares against.
    loop {
        let generation = crate::ipc::generation();
        for q in procs.all(p) {
            woke |= crate::timer::fire(q);
            woke |= q.wake_io_waiters();
            woke |= wake_expired(q);
        }
        if crate::ipc::generation() == generation {
            POLLED.store(generation, Ordering::Relaxed);
            return woke;
        }
    }
}

/// The I/O generation the last `poll` left everyone at.
static POLLED: AtomicU64 = AtomicU64::new(0);

/// A signal from the host: to the program's process group, as a terminal
/// sends Ctrl-C to its foreground group. Unlike other senders, nothing
/// shields init (the program) from it.
fn from_host(p: &mut Process, procs: &mut Procs, sig: u32) -> bool {
    let Some(group) = procs.all(p).find(|q| q.pid == crate::process::INIT).map(|q| q.pgid) else { return false };
    let mut sent = false;
    for q in procs.all(p) {
        if q.pgid == group {
            let info = crate::signal::SigInfo::sent(sig, crate::signal::SI_USER, 0, 0, "a signal from the host");
            sent |= crate::signal::send(q, crate::signal::Target::Process, info).is_ok();
        }
    }
    p.timer_dirty = true;
    sent
}

/// After a syscall: if I/O state changed, wake waiters in every process,
/// not just this one (a pipe's reader may be another process).
pub fn wake_io_everywhere(p: &mut Process) {
    p.wake_io_waiters();
    let mut procs = PROCS.lock();
    procs::reap_others(p, &mut procs);
    let mut woke = false;
    for q in procs.others.values_mut() {
        woke |= q.wake_io_waiters();
    }
    if woke {
        p.timer_dirty = true;
    }
}

/// Wake threads whose deadline has passed. Returns whether any woke.
fn wake_expired(p: &mut Process) -> bool {
    let now = time::monotonic_ns();
    let expired: Vec<u32> = p
        .threads
        .values()
        .filter(|t| t.wait.is_some_and(|w| w.deadline.is_some_and(|d| d <= now)))
        .map(|t| t.tid)
        .collect();
    for &tid in &expired {
        p.wake(tid, None);
    }
    !expired.is_empty()
}

/// Nothing is runnable anywhere: sleep until the next deadline, or give up
/// if no thread can ever wake.
fn idle(p: &mut Process, procs: &mut Procs) {
    match earliest_deadline(p, procs) {
        Some(deadline) => irq::timer_at(deadline),
        // The host can still wake whoever waits for I/O, and a thread
        // waiting for a signal may get one: a RunControl's, or the SIGTERM
        // the time limit sends.
        None if waiting_for_input(p, procs) || waiting_for_signal(p, procs) => irq::timer_off(),
        None => deadlock(p, procs),
    }
    p.timer_dirty = true;
    // The moment a snapshot wants: everything started, waiting for input.
    if waiting_for_input(p, procs) {
        crate::snapshot::take_if_wanted();
    }
    // Checking on the host may itself have freed room for a writer. (Not
    // `p.io_seen`: `p` may have just ended, and nothing updates that.)
    if crate::ipc::generation() != POLLED.load(Ordering::Relaxed) {
        return;
    }
    if let Some(id) = irq::wait_for_interrupt() {
        handle_interrupt(id);
    }
}

/// A thread is blocked on I/O while the host may still send stdin or take
/// output.
fn waiting_for_input(p: &mut Process, procs: &mut Procs) -> bool {
    let io = procs.all(p).any(|q| q.threads.values().any(|t| t.wait.is_some_and(|w| w.on == WaitOn::Io)));
    io && console::host_pending()
}

/// A thread waits for a signal (pause, sigsuspend, sigwait).
fn waiting_for_signal(p: &mut Process, procs: &mut Procs) -> bool {
    procs.all(p).any(|q| {
        q.threads.values().any(|t| t.wait.is_some_and(|w| matches!(w.on, WaitOn::Signal | WaitOn::SigWait(_))))
    })
}

/// Handle an acknowledged interrupt and signal its end.
fn handle_interrupt(id: u32) {
    match id {
        irq::TIMER_INTID => irq::timer_off(),
        _ => {
            console::interrupt(id);
        }
    }
    irq::eoi(id);
}

/// The next time something needs the CPU, anywhere: a sleeping thread's
/// deadline or a timer.
fn earliest_deadline(p: &mut Process, procs: &mut Procs) -> Option<u64> {
    procs
        .all(p)
        .filter_map(|q| {
            let sleepers = q.threads.values().filter_map(|t| t.wait?.deadline);
            sleepers.chain(q.timers.next_deadline()).min()
        })
        .min()
}

fn deadlock(p: &mut Process, procs: &mut Procs) -> ! {
    let (mut n, mut futex, mut io, mut sig, mut processes) = (0, 0, 0, 0, 0);
    for q in procs.all(p) {
        processes += 1;
        for t in q.threads.values() {
            n += 1;
            match t.wait.map(|w| w.on) {
                Some(WaitOn::Futex(_)) => futex += 1,
                Some(WaitOn::Io) => io += 1,
                Some(WaitOn::Signal | WaitOn::SigWait(_)) => sig += 1,
                _ => {}
            }
        }
    }
    let detail = alloc::format!(
        "deadlock: all {n} thread(s) are blocked and nothing can wake them \
         ({futex} on futexes, {io} on I/O, {sig} waiting for signals; {processes} process(es))"
    );
    console::event(&Event::Fault { signal: SIGKILL, addr: 0, pc: 0, detail: &detail });
    crate::process::finish(grix_abi::wire::ExitKind::Signaled, SIGKILL as i32)
}

/// Program the timer for the next thing that needs the CPU's attention: the
/// end of the time slice (if anything else is runnable) or the next deadline.
pub fn update_timer(p: &mut Process) {
    if !p.timer_dirty {
        return;
    }
    p.timer_dirty = false;
    let mut procs = PROCS.lock();
    let others_runnable = procs.others.values().any(|q| !q.runq.is_empty());
    let slice_end = (!p.runq.is_empty() || others_runnable).then(|| p.slice_start + SLICE_NS);
    match [slice_end, earliest_deadline(p, &mut procs)].into_iter().flatten().min() {
        Some(t) => irq::timer_at(t),
        None => irq::timer_off(),
    }
}

/// An interrupt while user code was running.
pub fn irq(tf: &mut TrapFrame) {
    let Some(id) = irq::ack() else { return };
    handle_interrupt(id);
    let mut guard = PROCESS.lock();
    let p = guard.as_mut().expect("interrupt without a process");
    p.timer_dirty = true;
    let (woke, others_runnable) = {
        let mut procs = PROCS.lock();
        procs::reap_others(p, &mut procs);
        let woke = poll(p, &mut procs);
        (woke, procs.others.values().any(|q| !q.runq.is_empty()))
    };
    let slice_over = time::monotonic_ns() >= p.slice_start + SLICE_NS;
    if (!p.runq.is_empty() || others_runnable) && (slice_over || woke) {
        schedule(p, tf);
    } else {
        update_timer(p);
    }
}
