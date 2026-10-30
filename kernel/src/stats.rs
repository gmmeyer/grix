//! Counters for the host's metrics (`grix_abi::stats`): what programs did
//! (CPU time, system calls, faults, switches), the most of each resource
//! in use at once, and how often a limit refused something. Atomics only,
//! so a report can be made wherever the console can be written to, whatever
//! locks the caller holds.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use grix_abi::stats::{Limit, Resource, Stats, Usage};

static CPU_NS: AtomicU64 = AtomicU64::new(0);
static SYSCALLS: AtomicU64 = AtomicU64::new(0);
static PAGE_FAULTS: AtomicU64 = AtomicU64::new(0);
static SWITCHES: AtomicU64 = AtomicU64::new(0);
static FORKS: AtomicU64 = AtomicU64::new(0);
static PEAKS: [AtomicU64; Resource::ALL.len()] = [const { AtomicU64::new(0) }; Resource::ALL.len()];
static HITS: [AtomicU64; Limit::ALL.len()] = [const { AtomicU64::new(0) }; Limit::ALL.len()];
/// Processes and threads as the scheduler last counted them (`tasks`).
static PROCESSES: AtomicU64 = AtomicU64::new(0);
static THREADS: AtomicU64 = AtomicU64::new(0);

/// A program's threads ran this long.
pub fn cpu(ns: u64) {
    CPU_NS.fetch_add(ns, Relaxed);
}

pub fn syscall() {
    SYSCALLS.fetch_add(1, Relaxed);
}

pub fn page_fault() {
    PAGE_FAULTS.fetch_add(1, Relaxed);
}

pub fn switched() {
    SWITCHES.fetch_add(1, Relaxed);
}

pub fn forked() {
    FORKS.fetch_add(1, Relaxed);
}

/// `r` has `now` in use: the most so far, if it's more.
pub fn peak(r: Resource, now: u64) {
    PEAKS[r as usize].fetch_max(now, Relaxed);
}

/// Limit `l` refused something.
pub fn hit(l: Limit) {
    HITS[l as usize].fetch_add(1, Relaxed);
}

/// How many processes (zombies included) and threads there are now.
pub fn tasks(processes: usize, threads: usize) {
    PROCESSES.store(processes as u64, Relaxed);
    THREADS.store(threads as u64, Relaxed);
    peak(Resource::Processes, processes as u64);
    peak(Resource::Threads, threads as u64);
}

/// A run restored from a snapshot: its report is its own, from here.
pub fn restored() {
    for c in [&CPU_NS, &SYSCALLS, &PAGE_FAULTS, &SWITCHES, &FORKS].into_iter().chain(&PEAKS).chain(&HITS) {
        c.store(0, Relaxed);
    }
}

/// The report, as things stand.
pub fn current() -> Stats {
    let (total, used) = crate::mm::frame::usage();
    let (data, data_limit) = crate::fs::usage();
    let (meta, meta_limit) = crate::fs::meta_usage();
    let now_limit = [
        (used * 4096, total * 4096),
        (crate::kmem::used(), crate::kmem::limit()),
        (data * 4096, data_limit * 4096),
        (meta, meta_limit),
        (PROCESSES.load(Relaxed), crate::procs::MAX_PROCESSES as u64),
        (THREADS.load(Relaxed), crate::process::threads_max() as u64),
    ];
    let mut s = Stats {
        cpu_ns: CPU_NS.load(Relaxed),
        syscalls: SYSCALLS.load(Relaxed),
        page_faults: PAGE_FAULTS.load(Relaxed),
        context_switches: SWITCHES.load(Relaxed),
        processes_started: FORKS.load(Relaxed),
        ..Stats::default()
    };
    for r in Resource::ALL {
        let (now, limit) = now_limit[r as usize];
        let peak = PEAKS[r as usize].load(Relaxed).max(now);
        s.usage[r as usize] = Usage { now, peak, limit };
    }
    for l in Limit::ALL {
        s.limits_hit[l as usize] = HITS[l as usize].load(Relaxed);
    }
    s
}
