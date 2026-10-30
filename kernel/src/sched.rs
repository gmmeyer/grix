//! Scheduling: round-robin across processes, and across each process's
//! threads, with a time slice driven by the virtual timer. Each CPU has one
//! kernel stack: switching threads means saving the trapped user state into
//! the old thread and loading the new thread's saved state into the trap
//! frame before returning to EL0. Switching processes also swaps the
//! running process's body in this CPU's slot of `PROCESS` with one from
//! `procs::PROCS`, and the address space in TTBR0. With more CPUs each runs
//! threads of any process (see `smp`).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::arch::{self, TrapFrame, irq};
use crate::console;
use crate::process::{self, Process, WaitOn};
use crate::procs::{self, PROCS, Procs};
use crate::signal::SIGKILL;
use crate::smp;
use crate::time;
use grix_abi::machine::MAX_CPUS;
use grix_abi::wire::Event;

pub const SLICE_NS: u64 = 10_000_000;

/// Pick the next runnable thread, in this CPU's process (`slot`) or
/// another, and make `tf` its state. If the current thread is still
/// runnable it goes to the back of its run queue; if it blocked or exited
/// it is simply not chosen. An ended process is finished off here, and
/// never runs again. A CPU with no thread may have no process either. With
/// nothing to run, the CPU is left with no thread (`running` false) and its
/// timer set for what comes next: `smp::finish` waits for it, then calls
/// this again.
pub fn schedule(slot: &mut Option<Process>, tf: &mut TrapFrame) {
    let mut procs = PROCS.lock();
    let mut was = None;
    let mut alone = true;
    if let Some(p) = slot.as_mut() {
        p.resched = false;
        let prev = p.current;
        was = p.running.then_some((p.pid, prev));
        // CPU time: prev ran from slice_start until now (not while we idle).
        let now = time::monotonic_ns();
        if p.running
            && let Some(t) = p.threads.get_mut(&prev)
        {
            let ran = now.saturating_sub(p.slice_start);
            t.cpu_ns += ran;
            crate::stats::cpu(ran);
            t.regs = *tf;
            // The kernel never touches FP/SIMD or the TLS register, so the CPU
            // still holds prev's values.
            t.tls = arch::tls();
            arch::save_fp(&mut t.fp);
            if t.wait.is_none() {
                p.runq.push_back(prev);
            }
        }
        p.running = false;
        p.current = smp::NO_THREAD;
        alone = smp::alone(p.pid);
        if p.exit_status.is_some() && !p.dead {
            if alone {
                procs::finalize(p, None, &mut procs);
            } else {
                // Its threads on other CPUs stop; the last CPU finishes it off.
                smp::kick_others(p.pid);
            }
        }
        // The other CPUs have left: whoever waited for that (execve) goes on.
        if p.exclusive_wanted && alone {
            crate::ipc::changed();
        }
    }
    procs::reap_others(slot.as_mut(), &mut procs);
    // A timer interrupt that brought an idle CPU here (`irq` takes its own).
    let timer = TIMER_FIRED[smp::me()].swap(false, Ordering::Relaxed);
    if !poll(slot.as_mut(), &mut procs) && timer {
        smp::note(smp::Stat::TimerIdle, 1);
    }
    // Others may have ended just now too (a timer's signal, the host's).
    procs::reap_others(slot.as_mut(), &mut procs);
    if let Some(p) = slot.as_mut() {
        // The process may have ended just now (a timer's signal, the host's).
        if p.exit_status.is_some() && !p.dead && alone {
            procs::finalize(p, None, &mut procs);
        }
        // Other CPUs running a process that wants to be alone (execve, its
        // end) or has stopped leave it.
        if !alone && !smp::runs_here(p) {
            smp::kick_others(p.pid);
        }
    }
    crate::stats::tasks(procs.count(), procs::threads());
    let Some(next) = pick(slot.as_ref(), &procs, alone) else {
        idle(slot.as_mut(), &mut procs);
        return;
    };
    if slot.as_ref().is_none_or(|p| p.pid != next) {
        let body = procs.others.remove(&next).unwrap();
        let old = slot.replace(body);
        let p = slot.as_mut().unwrap();
        process::set_current_pid(p.pid);
        p.aspace.activate();
        smp::activated(p.aspace.pt.root);
        // The process that was running: back with the others, unless it
        // has ended (its address space is no longer in TTBR0).
        if let Some(old) = old
            && !old.dead
        {
            procs.others.insert(old.pid, old);
        }
    }
    drop(procs);
    let p = slot.as_mut().unwrap();
    let tid = p.runq.pop_front().unwrap();
    let t = &p.threads[&tid];
    arch::set_tls(t.tls);
    arch::restore_fp(&t.fp);
    *tf = t.regs;
    p.current = tid;
    p.running = true;
    if was != Some((p.pid, tid)) {
        crate::stats::switched();
    }
    p.slice_start = time::monotonic_ns();
    p.timer_dirty = true;
    update_timer(p);
}

/// The process to run next: the first after this CPU's (by pid, wrapping)
/// with a thread waiting to run, so processes take turns; this one if it's
/// the only one. A process that wants to be alone (execve, its end) only
/// if no other CPU runs it: then it is. A CPU with no process starts from
/// the first, and looks at it last.
fn pick(p: Option<&Process>, procs: &Procs, alone: bool) -> Option<u32> {
    let takes = |q: &Process, alone: bool| runnable(q) && (smp::runs_here(q) || alone);
    let start = p.map(|p| p.pid).or_else(|| procs.others.keys().next().copied()).unwrap_or(0);
    let others = procs.others.range(start + 1..).chain(procs.others.range(..=start));
    others
        .filter(|(pid, q)| takes(q, !smp::running_anywhere(**pid)))
        .map(|(&pid, _)| pid)
        .next()
        .or_else(|| p.filter(|p| takes(p, alone)).map(|p| p.pid))
}

/// `q` has threads waiting to run, and isn't stopped.
pub fn runnable(q: &Process) -> bool {
    !q.runq.is_empty() && !q.stopped
}

/// Another process has threads waiting to run.
pub fn others_wait(procs: &Procs) -> bool {
    procs.others.values().any(runnable)
}

/// Everything due, in every process: timers, I/O waiters, expired
/// deadlines. Returns whether anything woke.
fn poll(mut p: Option<&mut Process>, procs: &mut Procs) -> bool {
    let mut woke = false;
    for sig in console::take_host_signals() {
        woke |= from_host(p.as_deref_mut(), procs, sig);
    }
    // Until I/O state stops changing (a timer can fire a timerfd), so every
    // waiter has seen the generation `idle` compares against.
    loop {
        let generation = crate::ipc::generation();
        for q in procs.each(p.as_deref_mut()) {
            woke |= crate::timer::fire(q);
            woke |= q.wake_io_waiters();
            woke |= wake_expired(q);
        }
        crate::fasync::deliver(p.as_deref_mut(), procs);
        if crate::ipc::generation() == generation {
            POLLED.store(generation, Ordering::Relaxed);
            return woke;
        }
    }
}

/// The I/O generation the last `poll` left everyone at.
static POLLED: AtomicU64 = AtomicU64::new(0);

pub fn polled() -> u64 {
    POLLED.load(Ordering::Relaxed)
}

/// A signal from the host: to the program's process group, as a terminal
/// sends Ctrl-C to its foreground group. Unlike other senders, nothing
/// shields init (the program) from it.
fn from_host(mut p: Option<&mut Process>, procs: &mut Procs, sig: u32) -> bool {
    let init = procs.each(p.as_deref_mut()).find(|q| q.pid == crate::process::INIT).map(|q| q.pgid);
    let Some(group) = init else { return false };
    let mut sent = false;
    for q in procs.each(p.as_deref_mut()) {
        if q.pgid == group {
            let info = crate::signal::SigInfo::sent(sig, crate::signal::SI_USER, 0, 0, "a signal from the host");
            sent |= crate::signal::send(q, crate::signal::Target::Process, info).is_ok();
        }
    }
    if let Some(p) = p {
        p.timer_dirty = true;
    }
    sent
}

/// After a syscall: if I/O state changed, wake waiters in every process,
/// not just this one (a pipe's reader may be another process).
pub fn wake_io_everywhere(p: &mut Process) {
    p.wake_io_waiters();
    let mut procs = PROCS.lock();
    procs::reap_others(Some(&mut *p), &mut procs);
    crate::fasync::deliver(Some(&mut *p), &mut procs);
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

/// Nothing is runnable here: set the timer for the next deadline (the CPU
/// then waits in `smp::finish`), or give up if no thread anywhere can ever
/// wake.
fn idle(mut p: Option<&mut Process>, procs: &mut Procs) {
    let others_running = smp::others_running();
    match earliest_deadline(p.as_deref_mut(), procs) {
        Some(deadline) => arm(None, Some(deadline)),
        // The host can still wake whoever waits for I/O, and a thread
        // waiting for a signal may get one: a RunControl's, or the SIGTERM
        // the time limit sends. Threads on other CPUs may wake anyone.
        None if others_running
            || waiting_for_input(p.as_deref_mut(), procs)
            || waiting_for_signal(p.as_deref_mut(), procs) =>
        {
            arm(None, None)
        }
        None => deadlock(p, procs),
    }
    if let Some(p) = p.as_deref_mut() {
        p.timer_dirty = true;
    }
    // The moment a snapshot wants: everything started, waiting for input.
    if !others_running && waiting_for_input(p, procs) {
        crate::snapshot::take_if_wanted();
    }
}

/// A thread is blocked on I/O while the host may still send stdin or take
/// output.
fn waiting_for_input(p: Option<&mut Process>, procs: &mut Procs) -> bool {
    let io = procs.each(p).any(|q| q.threads.values().any(|t| t.wait.is_some_and(|w| w.on == WaitOn::Io)));
    io && console::host_pending()
}

/// A thread waits for a signal (pause, sigsuspend, sigwait), or a
/// process for SIGCONT.
fn waiting_for_signal(p: Option<&mut Process>, procs: &mut Procs) -> bool {
    procs.each(p).any(|q| {
        q.stopped
            || q.threads.values().any(|t| t.wait.is_some_and(|w| matches!(w.on, WaitOn::Signal | WaitOn::SigWait(_))))
    })
}

/// A timer interrupt came, and hasn't been looked at by `poll` yet (for
/// `Stat::TimerIdle`).
static TIMER_FIRED: [AtomicBool; MAX_CPUS as usize] = [const { AtomicBool::new(false) }; MAX_CPUS as usize];

/// Handle an acknowledged interrupt and signal its end.
pub fn handle_interrupt(id: u32) {
    match id {
        irq::TIMER_INTID => {
            smp::note(smp::Stat::Timer, 1);
            TIMER_FIRED[smp::me()].store(true, Ordering::Relaxed);
            irq::timer_off()
        }
        // A kick: the CPU schedules on its way out.
        irq::KICK_INTID => smp::note(smp::Stat::Kick, 1),
        _ => {
            smp::note(smp::Stat::Device, 1);
            console::interrupt(id);
        }
    }
    irq::eoi(id);
}

/// The next time something needs the CPU, anywhere: a sleeping thread's
/// deadline or a timer.
fn earliest_deadline(p: Option<&mut Process>, procs: &mut Procs) -> Option<u64> {
    procs
        .each(p)
        .filter_map(|q| {
            let sleepers = q.threads.values().filter_map(|t| t.wait?.deadline);
            sleepers.chain(q.timers.next_deadline()).chain(crate::timer::cpu_deadline(q)).min()
        })
        .min()
}

fn deadlock(p: Option<&mut Process>, procs: &mut Procs) -> ! {
    let (mut n, mut futex, mut io, mut sig, mut processes) = (0, 0, 0, 0, 0);
    for q in procs.each(p) {
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
/// end of the time slice (if anything else is runnable), the process's
/// CPU-time timers, or the next deadline (`arm`).
pub fn update_timer(p: &mut Process) {
    if !p.timer_dirty {
        return;
    }
    p.timer_dirty = false;
    // A CPU running a thread keeps the time, if one does (see `KEEPER`).
    let me = smp::me();
    let keeper = KEEPER.load(Ordering::Relaxed);
    if keeper != me && p.running && !smp::has_thread(keeper) {
        KEEPER.store(me, Ordering::Relaxed);
    }
    let mut procs = PROCS.lock();
    let slice_end = (runnable(p) || others_wait(&procs)).then(|| p.slice_start + SLICE_NS);
    let own = slice_end.into_iter().chain(crate::timer::cpu_deadline(p)).min();
    arm(own, earliest_deadline(Some(p), &mut procs));
}

/// The CPU whose timer keeps everyone's deadlines (sleepers', timers'),
/// and when its timer fires next (`u64::MAX`: not at all). Only with the
/// kernel lock. A CPU running a thread takes the job from an idle one:
/// its timer is the hardware's, while an idle vCPU waits in its VMM,
/// which wakes it when the host's timers do (on macOS a 1 ms wait takes
/// 1.5 ms; an idle timekeeper made sleepers beside busy threads that
/// late, as they already are alone). On KVM an idle one would do as well
/// and spare a thread the interrupt.
static KEEPER: AtomicUsize = AtomicUsize::new(0);
static KEEPER_AT: AtomicU64 = AtomicU64::new(u64::MAX);

/// Program this CPU's timer for `own` (what only it can see to: its time
/// slice, its process's CPU-time timers), and for `all` (the earliest
/// deadline anywhere) if it's the timekeeper or that comes before the
/// timekeeper's timer. Every CPU used to arm `all`, so each deadline
/// interrupted every CPU running a thread, one after another taking the
/// lock to find it done. A deadline is never missed: whenever a timer
/// fires, its CPU looks at everything again (`irq`, `idle`), the
/// timekeeper's included, and all of this happens under the kernel lock.
fn arm(own: Option<u64>, all: Option<u64>) {
    let keeper = KEEPER.load(Ordering::Relaxed) == smp::me();
    let all = all.filter(|&d| keeper || d < KEEPER_AT.load(Ordering::Relaxed));
    let at = own.into_iter().chain(all).min();
    match at {
        Some(t) => irq::timer_at(t),
        None => irq::timer_off(),
    }
    if keeper {
        KEEPER_AT.store(at.unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

/// An interrupt while user code was running.
pub fn irq(tf: &mut TrapFrame) {
    let Some(id) = irq::ack() else { return };
    handle_interrupt(id);
    let mut guard = process::running().lock();
    // Its thread (or its process) ended while it ran (on another CPU's
    // say): `smp::finish` schedules.
    let Some(p) = guard.as_mut().filter(|p| p.running) else { return };
    p.timer_dirty = true;
    let timer = TIMER_FIRED[smp::me()].swap(false, Ordering::Relaxed);
    let (woke, others_runnable) = {
        let mut procs = PROCS.lock();
        procs::reap_others(Some(&mut *p), &mut procs);
        let woke = poll(Some(&mut *p), &mut procs);
        procs::reap_others(Some(&mut *p), &mut procs);
        (woke, others_wait(&procs))
    };
    let slice_over = time::monotonic_ns() >= p.slice_start + SLICE_NS;
    let preempt = p.resched || (runnable(p) || others_runnable) && (slice_over || woke);
    if timer && !woke && !preempt {
        smp::note(smp::Stat::TimerIdle, 1);
    }
    if preempt {
        schedule(&mut guard, tf);
    } else {
        update_timer(p);
    }
}
