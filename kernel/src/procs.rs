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
use crate::process::{INIT, Ids, Process};
use crate::signal::{self, SA_NOCLDSTOP, SA_NOCLDWAIT, SIG_IGN, SIGCHLD, SigInfo, Target};

/// Processes, zombies included, that may exist at once. Each holds page
/// tables and kernel memory, so a fork bomb gets EAGAIN instead.
pub const MAX_PROCESSES: usize = 128;

/// An ended process its parent hasn't waited for.
pub struct Zombie {
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    /// As wait4 reports it.
    pub status: i32,
    /// CPU time of the process and of the children it reaped.
    pub cpu_ns: u64,
    /// What its /proc/<pid> still shows.
    pub remains: crate::procfs::Remains,
}

pub struct Procs {
    /// Every live process except the running one.
    pub others: BTreeMap<u32, Process>,
    pub zombies: BTreeMap<u32, Zombie>,
}

pub static PROCS: Mutex<Procs> = Mutex::new(Procs { others: BTreeMap::new(), zombies: BTreeMap::new() });

/// Bumped whenever a process ends (pidfds' readiness).
static EXITS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn exits() -> u64 {
    EXITS.load(Ordering::Relaxed)
}

/// Has process `pid` ended (a zombie, or reaped)? `p` is the running one.
pub fn ended(p: &Process, pid: u32) -> bool {
    pid != p.pid && !PROCS.lock().others.contains_key(&pid)
}

/// May `p` look at `q`'s descriptors (Linux's ptrace access check, which
/// /proc/<pid>/fd and pidfd_getfd use): root may, and so may a process
/// whose user and group (`real`: real ids, otherwise effective ones) are
/// all of `q`'s.
pub fn may_inspect(p: &Process, q: &Process, real: bool) -> bool {
    may_inspect_creds(p, q.uid, q.gid, &q.ids, real)
}

/// `may_inspect` for a process with these credentials (a zombie's).
pub fn may_inspect_creds(p: &Process, quid: u32, qgid: u32, qids: &Ids, real: bool) -> bool {
    let (uid, gid) = if real { (p.ids.ruid, p.ids.rgid) } else { (p.uid, p.gid) };
    p.uid == 0 || ([quid, qids.ruid, qids.suid] == [uid; 3] && [qgid, qids.rgid, qids.sgid] == [gid; 3])
}

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
    let remains = crate::procfs::Remains::of(dead);
    if dead.posix_locks {
        crate::locks::release_all(crate::locks::Owner::Process(dead.pid));
    }
    dead.fds = FdTable::empty();
    dead.threads.clear();
    dead.runq.clear();
    dead.futexes.clear();
    dead.timers = Default::default();
    dead.shared_pending = Default::default();
    dead.cwd_pin = None;
    dead.dead = true;
    let (pid, ppid) = (dead.pid, dead.ppid);
    // Its pidfds are readable.
    EXITS.fetch_add(1, Ordering::Relaxed);
    crate::ipc::changed();
    // A session leader's end hangs up its terminal's foreground group.
    if let Some(tty) = dead.ctty.take()
        && dead.sid == pid
    {
        crate::tty::disassociate(cur.as_deref_mut(), procs, &tty, pid, true);
    }
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
    let Some(parent) = parent else {
        crate::fs::proc_gone(pid);
        return;
    };
    if let Some((_, tid)) = dead.vfork_parent.take() {
        parent.wake(tid, Some(pid as u64));
    }
    let act = parent.sigactions[SIGCHLD as usize];
    // Linux reaps at once for a parent that ignores SIGCHLD (or asked with
    // SA_NOCLDWAIT): its wait4 then just waits for the last child.
    // Its /proc/<pid> stays while it's a zombie.
    if act.handler != SIG_IGN && act.flags & SA_NOCLDWAIT == 0 {
        procs.zombies.insert(pid, Zombie { ppid, pgid: dead.pgid, sid: dead.sid, status, cpu_ns, remains });
        crate::fs::proc_zombie(pid);
    } else {
        crate::fs::proc_gone(pid);
    }
    if dead.exit_signal != 0 && dead.exit_signal <= signal::NSIG {
        let _ = signal::send(parent, Target::Process, SigInfo::child(dead.exit_signal, pid, dead.uid, status));
    }
    parent.timer_dirty = true;
    // wait4 waits for I/O state to change.
    crate::ipc::changed();
}

/// Shared mappings' read-only copies of file pages that now have frames
/// go from every process (see `fs::take_stale`).
pub fn zap_stale(cur: &mut Process, procs: &mut Procs) {
    let stale = crate::fs::take_stale();
    if stale.is_empty() {
        return;
    }
    for q in procs.all(cur) {
        q.aspace.zap_stale(&stale);
    }
}

/// Finish off processes other than the running one that were killed (by a
/// signal from it, or a timer). Their address spaces go too. And tell the
/// parents of processes that stopped or continued.
pub fn reap_others(cur: &mut Process, procs: &mut Procs) {
    crate::tty::service(cur, procs);
    zap_stale(cur, procs);
    if signal::JOBS.swap(false, Ordering::Relaxed) {
        let notices: Vec<(u32, SigInfo)> =
            procs.all(cur).filter_map(|q| Some((q.ppid, q.job_notice.take()?))).collect();
        for (ppid, info) in notices {
            let parent = if cur.pid == ppid { Some(&mut *cur) } else { procs.others.get_mut(&ppid) };
            if let Some(parent) = parent
                && parent.sigactions[SIGCHLD as usize].flags & SA_NOCLDSTOP == 0
            {
                let _ = signal::send(parent, Target::Process, info);
            }
        }
    }
    let mut later = false;
    while DYING.swap(false, Ordering::Relaxed) {
        let dying: Vec<u32> =
            procs.others.iter().filter(|(_, q)| q.exit_status.is_some()).map(|(&pid, _)| pid).collect();
        for pid in dying {
            // One running on another CPU is finished off there, once its
            // threads have all left (its address space is in use).
            if crate::smp::running_anywhere(pid) {
                crate::smp::kick_others(pid);
                later = true;
                continue;
            }
            let mut q = procs.others.remove(&pid).unwrap();
            finalize(&mut q, Some(cur), procs);
        }
    }
    if later {
        DYING.store(true, Ordering::Relaxed);
    }
}
