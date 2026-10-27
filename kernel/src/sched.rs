//! Thread scheduling on one CPU: round-robin with a time slice, driven by the
//! virtual timer. There is a single kernel stack: switching threads means
//! saving the trapped user state into the old thread and loading the new
//! thread's saved state into the trap frame before returning to EL0.

use alloc::vec::Vec;

use crate::arch::{self, TrapFrame, irq};
use crate::console;
use crate::process::{PROCESS, Process, WaitOn};
use crate::signal::SIGKILL;
use crate::time;
use grix_abi::wire::Event;

pub const SLICE_NS: u64 = 10_000_000;

/// Pick the next runnable thread and make `tf` its state. If the current
/// thread is still runnable it goes to the back of the run queue; if it
/// blocked or exited it is simply not chosen.
pub fn schedule(p: &mut Process, tf: &mut TrapFrame) {
    p.resched = false;
    let prev = p.current;
    // CPU time: prev ran from slice_start until now (not while we idle below).
    let now = time::monotonic_ns();
    if let Some(t) = p.threads.get_mut(&prev) {
        t.cpu_ns += now.saturating_sub(p.slice_start);
    }
    let prev_alive = match p.threads.get_mut(&prev) {
        Some(t) => {
            t.regs = *tf;
            if t.wait.is_none() {
                p.runq.push_back(prev);
            }
            true
        }
        None => false,
    };
    let next = loop {
        crate::timer::fire(p);
        p.wake_io_waiters();
        wake_expired(p);
        if let Some(next) = p.runq.pop_front() {
            break next;
        }
        idle(p);
    };
    if next != prev {
        // The kernel never touches FP/SIMD or TPIDR_EL0, so the CPU still
        // holds prev's values even if we idled in between.
        if prev_alive {
            let t = p.threads.get_mut(&prev).unwrap();
            t.tpidr = arch::tpidr();
            arch::save_fp(&mut t.fp);
        }
        let t = &p.threads[&next];
        arch::set_tpidr(t.tpidr);
        arch::restore_fp(&t.fp);
    }
    *tf = p.threads[&next].regs;
    p.current = next;
    p.slice_start = time::monotonic_ns();
    p.timer_dirty = true;
    update_timer(p);
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

/// Nothing is runnable: sleep until the next deadline, or give up if no
/// thread can ever wake.
fn idle(p: &mut Process) {
    let Some(deadline) = earliest_deadline(p) else { deadlock(p) };
    irq::timer_at(deadline);
    irq::wait_for_interrupt();
    p.timer_dirty = true;
}

/// The next time something needs the CPU: a sleeping thread's deadline or a timer.
fn earliest_deadline(p: &Process) -> Option<u64> {
    let sleepers = p.threads.values().filter_map(|t| t.wait?.deadline);
    sleepers.chain(p.timers.next_deadline()).min()
}

fn deadlock(p: &Process) -> ! {
    let count = |on: fn(WaitOn) -> bool| p.threads.values().filter(|t| t.wait.is_some_and(|w| on(w.on))).count();
    let futex = count(|on| matches!(on, WaitOn::Futex(_)));
    let io = count(|on| on == WaitOn::Io);
    let sig = count(|on| matches!(on, WaitOn::Signal | WaitOn::SigWait(_)));
    let n = p.threads.len();
    let detail = alloc::format!(
        "deadlock: all {n} thread(s) are blocked and nothing can wake them \
         ({futex} on futexes, {io} on I/O, {sig} waiting for signals)"
    );
    console::event(&Event::Fault { signal: SIGKILL, addr: 0, pc: 0, detail: &detail });
    console::exit(grix_abi::wire::ExitKind::Signaled, SIGKILL as i32)
}

/// Program the timer for the next thing that needs the CPU's attention: the
/// end of the time slice (if anyone else is runnable) or the next deadline.
pub fn update_timer(p: &mut Process) {
    if !p.timer_dirty {
        return;
    }
    p.timer_dirty = false;
    let slice_end = (!p.runq.is_empty()).then(|| p.slice_start + SLICE_NS);
    match [slice_end, earliest_deadline(p)].into_iter().flatten().min() {
        Some(t) => irq::timer_at(t),
        None => irq::timer_off(),
    }
}

/// Timer interrupt while user code was running.
pub fn irq(tf: &mut TrapFrame) {
    let Some(id) = irq::ack() else { return };
    if id == irq::TIMER_INTID {
        irq::timer_off();
    }
    irq::eoi(id);
    let mut guard = PROCESS.lock();
    let p = guard.as_mut().expect("interrupt without a process");
    p.timer_dirty = true;
    let fired = crate::timer::fire(p);
    p.wake_io_waiters();
    let woke = wake_expired(p) || fired;
    let slice_over = time::monotonic_ns() >= p.slice_start + SLICE_NS;
    if !p.runq.is_empty() && (slice_over || woke) {
        schedule(p, tf);
    } else {
        update_timer(p);
    }
}
