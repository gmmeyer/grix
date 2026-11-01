//! Every process but the running one, and zombies: what fork, wait4, kill
//! and the scheduler share. The process a CPU in the kernel runs is in
//! that CPU's slot of `process::PROCESS`; the scheduler swaps bodies
//! between the two (`sched::schedule`).
//!
//! Lock order: a `PROCESS` slot, then `PROCS`.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use crate::fd::FdTable;
use crate::process::{FsInfo, INIT, Ids, Process, Shared};
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
    /// What its last thread paid, for the task entry it keeps.
    pub _charge: crate::kmem::Charge,
}

pub struct Procs {
    /// Every live process except the running one. Boxed: a process moves
    /// in and out on every kernel entry (`smp::lock`), and a B-tree keeps
    /// its values inline, shifting them about.
    pub others: BTreeMap<u32, Box<Process>>,
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
    may_inspect_creds(p, q.uid, q.gid, &q.ids, real) && crate::landlock::may_inspect(p, q)
}

/// `may_inspect` for a process with these credentials (a zombie's).
pub fn may_inspect_creds(p: &Process, quid: u32, qgid: u32, qids: &Ids, real: bool) -> bool {
    let (uid, gid) = if real { (p.ids.ruid, p.ids.rgid) } else { (p.uid, p.gid) };
    p.uid == 0 || ([quid, qids.ruid, qids.suid] == [uid; 3] && [qgid, qids.rgid, qids.sgid] == [gid; 3])
}

/// A process has ended and may need finishing off (`reap_others`).
pub static DYING: AtomicBool = AtomicBool::new(false);

/// Has `reap_others` anything to do? (Without the process table.)
pub fn housekeeping_due() -> bool {
    DYING.load(Ordering::Relaxed)
        || signal::JOBS.load(Ordering::Relaxed)
        || crate::fs::stale_pending()
        || crate::tty::service_due()
}

/// Live processes (not finished off yet) and their threads, counted as
/// they come and go, wherever they are: in `PROCS` or a CPU's slot.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static THREADS: AtomicUsize = AtomicUsize::new(0);

/// A process with one thread came into being (fork, the first one).
pub fn born() {
    LIVE.fetch_add(1, Ordering::Relaxed);
    THREADS.fetch_add(1, Ordering::Relaxed);
}

/// A thread was added to a live process (clone).
pub fn thread_added() {
    THREADS.fetch_add(1, Ordering::Relaxed);
}

/// `n` threads of a live process went (exit, execve).
pub fn threads_gone(n: usize) {
    THREADS.fetch_sub(n, Ordering::Relaxed);
}

/// Threads in every process (bounded by `process::MAX_THREADS`).
pub fn threads() -> usize {
    THREADS.load(Ordering::Relaxed)
}

impl Procs {
    /// Processes in existence, zombies included.
    pub fn count(&self) -> usize {
        LIVE.load(Ordering::Relaxed) + self.zombies.len()
    }

    /// Live process `pid`: the running one (`cur`) or another.
    pub fn get<'a>(&'a mut self, cur: &'a mut Process, pid: u32) -> Option<&'a mut Process> {
        if cur.pid == pid {
            return (!cur.dead).then_some(cur);
        }
        self.other_mut(pid)
    }

    /// Live process `pid`, if it isn't the running one.
    pub fn other_mut(&mut self, pid: u32) -> Option<&mut Process> {
        self.others.get_mut(&pid).map(|q| &mut **q)
    }

    /// Every live process but the running one.
    pub fn others_mut(&mut self) -> impl Iterator<Item = &mut Process> {
        self.others.values_mut().map(|q| &mut **q)
    }

    /// Every live process: the running one first. Only with the kernel to
    /// this CPU (any other CPU's process is in `others` then).
    pub fn all<'a>(&'a mut self, cur: &'a mut Process) -> impl Iterator<Item = &'a mut Process> {
        self.each(Some(cur))
    }

    /// `all`, from a CPU that may have no process (`cur`: its own, if any).
    pub fn each<'a>(&'a mut self, cur: Option<&'a mut Process>) -> impl Iterator<Item = &'a mut Process> {
        debug_assert!(crate::smp::exclusive(), "another CPU has a process checked out");
        debug_assert!(!crate::fast::active(), "a fast entry looked at every process");
        cur.into_iter().filter(|p| !p.dead).chain(self.others_mut())
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
    if dead.sem_undo {
        crate::sysv::process_ended(dead.pid);
    }
    let cpu_ns = dead.process_cpu_ns() + dead.children_cpu_ns;
    LIVE.fetch_sub(1, Ordering::Relaxed);
    threads_gone(dead.threads.len());
    // What /proc/<pid> keeps of it, before anything goes.
    let remains = crate::procfs::Remains::of(dead);
    let charge = dead.threads.values_mut().next().map(|t| core::mem::take(&mut t.charge)).unwrap_or_default();
    // Its POSIX locks go with its descriptor table, unless another process
    // (CLONE_FILES) still uses that.
    dead.fds = FdTable::empty();
    dead.aio = Default::default();
    dead.threads.clear();
    dead.runq.clear();
    dead.futexes.clear();
    crate::futex::forget(dead.pid);
    dead.timers = Default::default();
    dead.shared_pending = Default::default();
    // What it shared with others (CLONE_FS, CLONE_SIGHAND) is theirs alone.
    let umask = dead.umask();
    dead.fs = Shared::new(FsInfo { cwd: crate::fs::ROOT, cwd_pin: None, umask });
    dead.sigactions.unshare();
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
    for q in procs.others_mut().chain(cur.as_deref_mut()) {
        if q.ppid == pid {
            q.ppid = INIT;
        }
    }
    for z in procs.zombies.values_mut() {
        if z.ppid == pid {
            z.ppid = INIT;
        }
    }
    // Its children's getppid, which may be a fast call on another CPU.
    crate::fast::changed();
    // The vfork caller isn't the parent with CLONE_PARENT.
    if let Some((vpid, tid)) = dead.vfork_parent.take() {
        let caller = match cur.as_deref_mut() {
            Some(c) if c.pid == vpid => Some(c),
            _ => procs.other_mut(vpid),
        };
        if let Some(caller) = caller {
            caller.wake(tid, Some(pid as u64));
        }
    }
    let parent = match cur {
        Some(c) if c.pid == ppid => Some(c),
        // Not `other_mut`: `zombies` is borrowed below.
        _ => procs.others.get_mut(&ppid).map(|q| &mut **q),
    };
    // Orphans belong to init, which outlives everything.
    let Some(parent) = parent else {
        crate::fs::proc_gone(pid);
        return;
    };
    let act = parent.action(SIGCHLD);
    // Linux reaps at once for a parent that ignores SIGCHLD (or asked with
    // SA_NOCLDWAIT): its wait4 then just waits for the last child.
    // Its /proc/<pid> stays while it's a zombie, its threads' entries
    // but the leader's going with what paid for them.
    if act.handler != SIG_IGN && act.flags & SA_NOCLDWAIT == 0 {
        procs
            .zombies
            .insert(pid, Zombie { ppid, pgid: dead.pgid, sid: dead.sid, status, cpu_ns, remains, _charge: charge });
        crate::fs::proc_zombie(pid);
    } else {
        crate::fs::proc_gone(pid);
    }
    if dead.exit_signal != 0 && dead.exit_signal <= signal::NSIG {
        let _ = signal::send(parent, Target::Process, SigInfo::child(dead.exit_signal, pid, dead.uid, status));
    }
    // wait4 waits for I/O state to change.
    crate::ipc::changed();
}

/// Shared mappings' read-only copies of file pages that now have frames
/// go from every process (see `fs::take_stale`).
pub fn zap_stale(cur: Option<&mut Process>, procs: &mut Procs) {
    let Some(stale) = crate::fs::take_stale() else { return };
    for q in procs.each(cur) {
        q.aspace.access().zap_stale(&stale);
    }
}

/// Finish off processes other than the running one that were killed (by a
/// signal from it, or a timer). Their address spaces go too. And tell the
/// parents of processes that stopped or continued.
pub fn reap_others(mut cur: Option<&mut Process>, procs: &mut Procs) {
    crate::tty::service(cur.as_deref_mut(), procs);
    zap_stale(cur.as_deref_mut(), procs);
    if signal::JOBS.swap(false, Ordering::Relaxed) {
        let notices: Vec<(u32, SigInfo)> =
            procs.each(cur.as_deref_mut()).filter_map(|q| Some((q.ppid, q.job_notice.take()?))).collect();
        for (ppid, info) in notices {
            let parent = match cur.as_deref_mut() {
                Some(c) if c.pid == ppid => Some(c),
                _ => procs.other_mut(ppid),
            };
            if let Some(parent) = parent
                && parent.action(SIGCHLD).flags & SA_NOCLDSTOP == 0
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
            finalize(&mut q, cur.as_deref_mut(), procs);
        }
    }
    if later {
        DYING.store(true, Ordering::Relaxed);
    }
}
