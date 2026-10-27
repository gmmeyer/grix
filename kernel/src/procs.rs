//! Every process but the running one, and zombies: what fork, wait4, kill
//! and the scheduler share. The running process is in `process::PROCESS`;
//! the scheduler swaps bodies between the two (`sched::schedule`).
//!
//! Lock order: `PROCESS`, then `PROCS`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::fd::FdTable;
use crate::process::{INIT, Process};
use crate::signal::{self, SA_NOCLDWAIT, SIG_IGN, SIGCHLD, SigInfo, Target};

/// Processes, zombies included, that may exist at once. Each holds page
/// tables and kernel memory, so a fork bomb gets EAGAIN instead.
pub const MAX_PROCESSES: usize = 128;

/// An ended process its parent hasn't waited for.
pub struct Zombie {
    pub ppid: u32,
    pub pgid: u32,
    /// As wait4 reports it.
    pub status: i32,
    /// CPU time of the process and of the children it reaped.
    pub cpu_ns: u64,
}

pub struct Procs {
    /// Every live process except the running one.
    pub others: BTreeMap<u32, Process>,
    pub zombies: BTreeMap<u32, Zombie>,
}

pub static PROCS: Mutex<Procs> = Mutex::new(Procs { others: BTreeMap::new(), zombies: BTreeMap::new() });

/// A process has ended and may need finishing off (`reap_others`).
pub static DYING: AtomicBool = AtomicBool::new(false);

impl Procs {
    /// Processes in existence, the running one and zombies included.
    pub fn count(&self) -> usize {
        1 + self.others.len() + self.zombies.len()
    }

    /// Threads in every process (bounded by `process::MAX_THREADS`).
    pub fn threads(&self, cur: &Process) -> usize {
        cur.threads.len() + self.others.values().map(|q| q.threads.len()).sum::<usize>()
    }

    /// Live process `pid`: the running one (`cur`) or another.
    pub fn get<'a>(&'a mut self, cur: &'a mut Process, pid: u32) -> Option<&'a mut Process> {
        if cur.pid == pid {
            return (!cur.dead).then_some(cur);
        }
        self.others.get_mut(&pid)
    }

    /// Every live process: the running one first.
    pub fn all<'a>(&'a mut self, cur: &'a mut Process) -> impl Iterator<Item = &'a mut Process> {
        core::iter::once(cur).filter(|p| !p.dead).chain(self.others.values_mut())
    }
}

/// Finish off a process that has ended (its `exit_status` is set): close
/// its files (so pipe readers see EOF), drop its threads and timers, give
/// its children to init, and tell its parent: wake a vfork parent, leave a
/// zombie for wait4 (unless the parent ignores SIGCHLD), and send the exit
/// signal. `cur` is the running process, or `None` if `dead` is it. The
/// address space stays: the running one may still be in TTBR0.
pub fn finalize(dead: &mut Process, mut cur: Option<&mut Process>, procs: &mut Procs) {
    let status = dead.exit_status.expect("finalizing a live process");
    let cpu_ns = dead.process_cpu_ns() + dead.children_cpu_ns;
    dead.fds = FdTable::empty();
    dead.threads.clear();
    dead.runq.clear();
    dead.futexes.clear();
    dead.timers = Default::default();
    dead.shared_pending = Default::default();
    dead.cwd_pin = None;
    dead.dead = true;
    let (pid, ppid) = (dead.pid, dead.ppid);
    for q in procs.others.values_mut().chain(cur.as_deref_mut()) {
        if q.ppid == pid {
            q.ppid = INIT;
        }
    }
    for z in procs.zombies.values_mut() {
        if z.ppid == pid {
            z.ppid = INIT;
        }
    }
    let parent = match cur {
        Some(c) if c.pid == ppid => Some(c),
        _ => procs.others.get_mut(&ppid),
    };
    // Orphans belong to init, which outlives everything.
    let Some(parent) = parent else { return };
    if let Some((_, tid)) = dead.vfork_parent.take() {
        parent.wake(tid, Some(pid as u64));
    }
    let act = parent.sigactions[SIGCHLD as usize];
    // Linux reaps at once for a parent that ignores SIGCHLD (or asked with
    // SA_NOCLDWAIT): its wait4 then just waits for the last child.
    if act.handler != SIG_IGN && act.flags & SA_NOCLDWAIT == 0 {
        procs.zombies.insert(pid, Zombie { ppid, pgid: dead.pgid, status, cpu_ns });
    }
    if dead.exit_signal != 0 && dead.exit_signal <= signal::NSIG {
        let _ = signal::send(parent, Target::Process, SigInfo::child(dead.exit_signal, pid, dead.uid, status));
    }
    parent.timer_dirty = true;
    // wait4 waits for I/O state to change.
    crate::ipc::changed();
}

/// Finish off processes other than the running one that were killed (by a
/// signal from it, or a timer). Their address spaces go too.
pub fn reap_others(cur: &mut Process, procs: &mut Procs) {
    while DYING.swap(false, Ordering::Relaxed) {
        let dying: Vec<u32> =
            procs.others.iter().filter(|(_, q)| q.exit_status.is_some()).map(|(&pid, _)| pid).collect();
        for pid in dying {
            let mut q = procs.others.remove(&pid).unwrap();
            finalize(&mut q, Some(cur), procs);
        }
    }
}
