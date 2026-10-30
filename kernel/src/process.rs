//! A process: its threads, exec, faults, termination, and reporting of
//! denied/unimplemented operations. The one a CPU in the kernel runs is in
//! its slot of `PROCESS` (`running`); the others, and zombies, are in
//! `procs::PROCS`.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use grix_abi::image::Image;
use grix_abi::policy::{DenyAction, Policy};
use grix_abi::wire::{Event, ExitKind};
use spin::Mutex;

use crate::arch::{self, TrapFrame};
use crate::console::{self, klog};
use crate::elf;
use crate::errno::*;
use crate::fd::FdTable;
use crate::fs::{self, Ino, Kind, ROOT};
use crate::mm::PAGE_SIZE;
pub use crate::mm::aspace::Access;
use crate::mm::aspace::{
    AddressSpace, Backing, FaultError, MAX_STACK, SIGPAGE, STACK_SIZE, STACK_TOP, VDSO, VVAR, Vma,
};
use crate::mm::gate::Mm;
use crate::mm::paging::Prot;
use crate::rng;
use crate::signal::{self, AltStack, SigQueue};
use crate::uaccess::copy_out;

/// The program the sandbox runs. When it ends, the sandbox does.
pub const INIT: u32 = 1;
/// What a thread holds of the kernel heap, charged to `kmem` while it
/// lives: its `Thread` twice over (threads made one after another leave
/// the process's B-tree nodes half full), x86_64's boxed XSAVE area, its
/// /proc/<pid>/task/<tid> nodes, and a signal of each standard kind
/// pending (real-time ones have `MAX_QUEUED_RT`).
pub const THREAD_COST: u64 = (2 * core::mem::size_of::<Thread>()
    + arch::FP_HEAP_BYTES
    + 64
    + 32 * core::mem::size_of::<crate::signal::SigInfo>()) as u64
    + crate::fs::TASK_NODES_COST
    + crate::futex::COST;
/// threads-max at least: what grix always allowed.
const MIN_THREADS_MAX: usize = 1024;

/// Threads in all processes together (/proc/sys/kernel/threads-max): as
/// many as the heap's share of RAM holds (`mm::init`), as Linux sizes
/// threads-max from RAM. Each also takes its `THREAD_COST` from `kmem`,
/// which fails first if buffers have taken the rest.
pub fn threads_max() -> usize {
    (((crate::kmem::limit() - crate::kmem::BASE) / THREAD_COST) as usize).max(MIN_THREADS_MAX)
}

/// Thread and process ids, from one sequence (a process's id is its first
/// thread's). Never reused.
static NEXT_TID: AtomicU32 = AtomicU32::new(INIT + 1);

pub fn new_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}

/// wait4 statuses.
pub fn exited(code: i32) -> i32 {
    (code & 0xff) << 8
}

pub fn signaled(sig: u32) -> i32 {
    (sig & 0x7f) as i32
}

#[derive(Clone, Copy, Default)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

/// What a blocked thread is waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOn {
    /// A futex word (user virtual address).
    Futex(u64),
    /// A futex word in memory processes share (`futex.rs`).
    SharedFutex(crate::futex::Key),
    /// Any of the futex words in `Thread::futexv` (futex_waitv).
    FutexV,
    /// Only the deadline (nanosleep, poll timeouts).
    Sleep,
    /// I/O readiness (pipes, eventfds, epoll). The syscall is restarted from
    /// scratch whenever I/O state changes anywhere.
    Io,
    /// Any signal that runs a handler (rt_sigsuspend).
    Signal,
    /// A vfork child to exec or exit (signals wait until then).
    Vfork,
    /// One of these signals becoming pending (rt_sigtimedwait). The syscall
    /// is restarted to dequeue it.
    SigWait(u64),
}

#[derive(Clone, Copy, Debug)]
pub struct Wait {
    pub on: WaitOn,
    /// Monotonic ns.
    pub deadline: Option<u64>,
    /// x0 to return if the deadline passes.
    pub timeout_ret: u64,
    /// When the deadline passes, run the syscall again instead (it then
    /// finds its deadline gone: select and poll write out what's ready).
    pub rerun: bool,
}

/// A blocking FIFO open waiting for the other side: its own end (which
/// counts for the other side meanwhile), the FIFO, the other side's open
/// count when it began, and the call it's in. It lasts until the thread
/// enters a different call, or a signal handler interrupts it (as Linux's
/// fifo_open drops its count then, and a restart begins afresh): not
/// `restarting`, which an interrupt before the call runs again clears.
pub struct FifoWait {
    pub ino: crate::fs::Ino,
    pub end: crate::ipc::PipeEnd,
    pub since: u64,
    pub call: (u64, u64),
}

pub struct Thread {
    pub tid: u32,
    /// User registers, valid while the thread is not running.
    pub regs: TrapFrame,
    pub tls: u64,
    /// Boxed on x86_64 (`arch::ThreadFp`): its XSAVE area is 2.7 KiB, and
    /// a `Thread` is moved by value (fork, clone, the B-tree's nodes),
    /// each move a copy on the kernel stack.
    pub fp: arch::ThreadFp,
    /// `Some` while blocked.
    pub wait: Option<Wait>,
    /// set_tid_address / CLONE_CHILD_CLEARTID: zeroed and futex-woken on exit.
    pub clear_child_tid: u64,
    pub sigmask: u64,
    /// The mask to restore once a signal handler returns, set by syscalls
    /// that change the mask while they wait (rt_sigsuspend, ppoll, ...).
    pub saved_sigmask: Option<u64>,
    /// Signals sent to this thread (tgkill, faults).
    pub pending: SigQueue,
    pub altstack: AltStack,
    pub robust_list: u64,
    /// Absolute deadline of a blocking call, kept when the call is rewound to
    /// re-run (I/O changes, signals) so it doesn't start its relative timeout over.
    pub restart_deadline: Option<u64>,
    /// The thread was rewound to the `svc` of an unfinished syscall. If a
    /// signal handler runs before the call re-executes, the call may fail
    /// with EINTR instead (see `signal::return_to_user`).
    pub restarting: bool,
    /// Rewound by a wakeup (a signal, an I/O change): the syscall re-runs
    /// once before any signal is delivered, so a call that can now complete
    /// does (and the handler runs after it), as Linux checks the wait's
    /// condition before the signal. If it would block again,
    /// `signal::interrupt_self` rewinds it for good and the handler decides.
    pub recheck: bool,
    /// Bytes an unfinished write to stdout/stderr already sent before it
    /// blocked. Its re-run continues after them; a signal handler makes it
    /// return them instead of EINTR, as Linux returns a partial count.
    pub io_done: u64,
    /// CPU time used (ns), up to its last switch out.
    pub cpu_ns: u64,
    /// The record lock it waits for in fcntl(F_SETLKW): (file, start, end,
    /// write), for finding deadlocks. Only meaningful while it's blocked
    /// there.
    pub lock_wait: Option<(usize, u64, u64, bool)>,
    /// The end a blocking open of a FIFO holds while it waits for the other
    /// side (`open_fifo`).
    pub fifo_wait: Option<FifoWait>,
    /// The syscall it's in: (pc, number) as it entered.
    pub call: (u64, u64),
    /// Its seccomp mode, filters and no_new_privs (inherited by threads and
    /// processes it makes, kept across execve).
    pub seccomp: crate::seccomp::State,
    /// Its Landlock domain (landlock.rs): inherited like `seccomp`, and
    /// only ever replaced by one with a layer more.
    pub landlock: Option<alloc::sync::Arc<crate::landlock::Domain>>,
    /// Its NUMA memory policy (set_mempolicy's mode and mode flags), kept
    /// to be read back: with one node, every policy places memory alike.
    pub mempolicy: u32,
    /// Its name (PR_SET_NAME, /proc/<pid>/task/<tid>/comm); all zeros:
    /// the process's (`Process::name`, which is the main thread's).
    pub name: [u8; 16],
    /// Its `THREAD_COST` (none for a placeholder that's replaced).
    pub charge: crate::kmem::Charge,
    /// The futex words a futex_waitv waits on, in its order (a wake
    /// returns the index of the word that woke it), while it waits.
    pub futexv: Option<FutexV>,
}

/// futex_waitv's words, charged to kmem (up to 128 per thread).
pub struct FutexV {
    pub addrs: Vec<u64>,
    pub _charge: crate::kmem::Charge,
}

impl Thread {
    pub fn new(tid: u32) -> Self {
        Thread {
            tid,
            regs: TrapFrame::default(),
            tls: 0,
            fp: Default::default(),
            wait: None,
            clear_child_tid: 0,
            sigmask: 0,
            saved_sigmask: None,
            pending: SigQueue::default(),
            altstack: AltStack::default(),
            robust_list: 0,
            restart_deadline: None,
            restarting: false,
            recheck: false,
            io_done: 0,
            cpu_ns: 0,
            lock_wait: None,
            fifo_wait: None,
            call: (0, 0),
            seccomp: Default::default(),
            landlock: None,
            mempolicy: 0,
            name: [0; 16],
            charge: Default::default(),
            futexv: None,
        }
    }
}

/// What processes made with a clone flag share (CLONE_FS: `FsInfo`,
/// CLONE_SIGHAND: `SigActions`; descriptors are `FdTable`'s own handle):
/// a handle to one value. Every access is under the big kernel lock, so
/// the mutex is only held for a moment.
pub struct Shared<T>(alloc::sync::Arc<Mutex<T>>);

impl<T: Clone> Shared<T> {
    pub fn new(v: T) -> Self {
        Shared(alloc::sync::Arc::new(Mutex::new(v)))
    }

    /// The same value (the clone flag given).
    pub fn share(&self) -> Self {
        Shared(self.0.clone())
    }

    /// A value of its own, as it is now (fork without the flag).
    pub fn copy(&self) -> Self {
        Self::new(self.get())
    }

    pub fn get(&self) -> T {
        self.0.lock().clone()
    }

    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.0.lock())
    }

    /// Other processes use it too.
    pub fn shared(&self) -> bool {
        alloc::sync::Arc::strong_count(&self.0) > 1
    }

    /// Is `other` the same one?
    pub fn same(&self, other: &Self) -> bool {
        alloc::sync::Arc::ptr_eq(&self.0, &other.0)
    }

    /// Make it this process's own, if it's shared (exec, unshare).
    pub fn unshare(&mut self) {
        if self.shared() {
            *self = self.copy();
        }
    }
}

/// Linux's fs_struct: the working directory and umask (the root is always
/// the sandbox's).
#[derive(Clone)]
pub struct FsInfo {
    pub cwd: Ino,
    /// Keeps the working directory's slot from being reused if it's removed.
    pub cwd_pin: Option<alloc::sync::Arc<()>>,
    pub umask: u32,
}

/// Linux's sighand_struct: each signal's action.
pub type SigActions = [SigAction; 65];

/// The ids besides the effective ones (`Process::uid`/`gid`, which
/// permission checks and new files use), as Linux keeps them: real, saved
/// and supplementary groups. They mean nothing outside the sandbox; uid 0
/// may set them as on Linux, others only shuffle what they have.
#[derive(Clone, Debug, Default)]
pub struct Ids {
    pub ruid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub sgid: u32,
    pub groups: Vec<u32>,
}

/// At most this many supplementary groups (Linux allows 65536; each process
/// keeps its own, and fork copies them).
pub const MAX_GROUPS: usize = 64;

pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    /// Sent to the parent when this process ends (clone's low byte, usually SIGCHLD).
    pub exit_signal: u32,
    /// Set once the process has ended (a wait4 status); the scheduler then
    /// finishes it off (`procs::finalize`) before anything else of it runs.
    pub exit_status: Option<i32>,
    /// Finished off: no threads or files left, just the address space still
    /// in TTBR0 until another process is switched in.
    pub dead: bool,
    /// A thread of it is on the CPU whose slot of `PROCESS` it's in.
    pub running: bool,
    /// A vfork child: the parent thread waiting for it to exec or exit.
    pub vfork_parent: Option<(u32, u32)>,
    /// CPU time of reaped children (RUSAGE_CHILDREN, times).
    pub children_cpu_ns: u64,
    /// Held by this CPU while the process is checked out here (`mm::gate`).
    pub aspace: Mm,
    pub fds: FdTable,
    /// The working directory and umask (`cwd`, `umask`).
    pub fs: Shared<FsInfo>,
    pub policy: Policy,
    pub uid: u32,
    pub gid: u32,
    pub ids: Ids,
    /// Signal actions (`action`, `set_action`).
    pub sigactions: Shared<SigActions>,
    /// Signals sent to the whole process (kill), taken by any thread that doesn't block them.
    pub shared_pending: SigQueue,
    pub rlimits: [(u64, u64); 16],
    pub name: [u8; 16],
    /// The running program (after `#!` resolution), its argv and environment.
    pub exe: String,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
    /// The auxiliary vector the program started with, as (type, value)
    /// words ending in AT_NULL: /proc/<pid>/auxv.
    pub auxv: Vec<u64>,
    /// The kernel memory `argv` and `envp` take (every fork copies them).
    pub args_charge: crate::kmem::Charge,

    // Threads and scheduling (see sched.rs).
    pub threads: BTreeMap<u32, Thread>,
    /// The running thread. Its live state is in the CPU, not in `threads`.
    pub current: u32,
    /// Runnable threads other than `current`, in round-robin order.
    pub runq: RunQ,
    /// Futex wait queues: address -> (tid, bitset) in FIFO order.
    pub futexes: BTreeMap<u64, VecDeque<(u32, u32)>>,
    /// When the current thread's time slice started (monotonic ns).
    pub slice_start: u64,
    /// Switch threads before returning to user space.
    pub resched: bool,
    /// A thread waits to be the only one running (execve): other CPUs
    /// leave this process at their next scheduling point (see `smp`).
    pub exclusive_wanted: bool,
    /// `ipc::generation()` when I/O waiters were last woken.
    pub io_seen: u64,
    /// setitimer, POSIX timers and timerfds (see timer.rs).
    pub timers: crate::timer::Timers,
    /// CPU time of threads that have exited.
    pub exited_cpu_ns: u64,
    /// prctl(PR_SET_CHILD_SUBREAPER).
    pub subreaper: bool,
    /// membarrier commands registered for (MEMBARRIER_CMD_REGISTER_*).
    pub membarrier_registered: u64,
    /// A signalfd was created: queued signals must wake I/O waiters.
    pub uses_signalfd: bool,
    /// Stopped by a stop signal (job control): none of its threads run
    /// until SIGCONT (`sched::runnable`).
    pub stopped: bool,
    /// The last stop or continue, until a wait4/waitid with WUNTRACED or
    /// WCONTINUED reports it.
    pub job_report: Option<JobReport>,
    /// The SIGCHLD that tells the parent about it, sent from
    /// `procs::reap_others` (which can reach the parent).
    pub job_notice: Option<crate::signal::SigInfo>,
    /// The controlling terminal (the session's, inherited across fork).
    pub ctty: Option<crate::tty::TtyRef>,
    /// AIO contexts (io_setup), shared by its threads, not inherited.
    pub aio: crate::syscall::aio::Contexts,
    /// A thread of it may have a Landlock domain: without, checks are this
    /// one test (`landlock::domain`).
    pub landlocked: bool,
}

/// What a child made by clone shares with its parent instead of copying.
#[derive(Clone, Copy, Default)]
pub struct Share {
    /// CLONE_FILES: the descriptor table.
    pub files: bool,
    /// CLONE_FS: the working directory and umask.
    pub fs: bool,
    /// CLONE_SIGHAND: the signal actions.
    pub sighand: bool,
}

/// A change a parent's wait can report besides an exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobReport {
    Stopped(u32),
    Continued,
}

/// Threads waiting to run, in every process's `RunQ` (stopped ones' too):
/// when there are none, nothing need look at every process to find one.
static QUEUED: AtomicUsize = AtomicUsize::new(0);

pub fn queued() -> usize {
    QUEUED.load(Ordering::Relaxed)
}

/// A process's run queue, counted in `QUEUED`.
#[derive(Default)]
pub struct RunQ(VecDeque<u32>);

impl RunQ {
    pub fn push_back(&mut self, tid: u32) {
        self.0.push_back(tid);
        QUEUED.fetch_add(1, Ordering::Relaxed);
        // Whichever process it's in, this CPU may have no slice to end.
        crate::sched::timer_changed();
    }

    pub fn pop_front(&mut self) -> Option<u32> {
        let tid = self.0.pop_front()?;
        QUEUED.fetch_sub(1, Ordering::Relaxed);
        Some(tid)
    }

    pub fn clear(&mut self) {
        QUEUED.fetch_sub(self.0.len(), Ordering::Relaxed);
        self.0.clear();
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for RunQ {
    fn drop(&mut self) {
        self.clear();
    }
}

const N: usize = grix_abi::machine::MAX_CPUS as usize;

/// The process each CPU in the kernel runs, by CPU: `smp::lock` takes it
/// out of `procs::PROCS` and `smp::unlock` puts it back, so between
/// kernel entries every slot is empty.
pub static PROCESS: [Mutex<Option<Box<Process>>>; N] = [const { Mutex::new(None) }; N];

/// This CPU's slot of `PROCESS`.
pub fn running() -> &'static Mutex<Option<Box<Process>>> {
    &PROCESS[crate::smp::me()]
}

/// The pid of the process in each CPU's slot (what /proc/self is).
static CURRENT_PID: [AtomicU32; N] = [const { AtomicU32::new(INIT) }; N];

pub fn current_pid() -> u32 {
    CURRENT_PID[crate::smp::me()].load(Ordering::Relaxed)
}

pub fn set_current_pid(pid: u32) {
    CURRENT_PID[crate::smp::me()].store(pid, Ordering::Relaxed);
}

/// What has been reported to the host already, for every process: each
/// denial, gap and missing path once.
static REPORTED: Mutex<BTreeSet<(u8, u32, String)>> = Mutex::new(BTreeSet::new());

const MAX_REPORTS: usize = 512;
const MAX_REPORT_BYTES: usize = 512;
const RLIM_INFINITY: u64 = u64::MAX;

impl Process {
    fn new(pid: u32, policy: Policy, uid: u32, gid: u32, aspace: AddressSpace) -> Self {
        let mut rlimits = [(RLIM_INFINITY, RLIM_INFINITY); 16];
        rlimits[3] = (STACK_SIZE, RLIM_INFINITY); // RLIMIT_STACK
        rlimits[4] = (0, 0); // RLIMIT_CORE
        rlimits[7] = (crate::fd::NOFILE_DEFAULT as u64, crate::fd::MAX_FDS as u64); // RLIMIT_NOFILE
        Process {
            pid,
            ppid: 0,
            pgid: pid,
            sid: pid,
            exit_signal: 0,
            exit_status: None,
            dead: false,
            running: false,
            vfork_parent: None,
            children_cpu_ns: 0,
            aspace: Mm::new(aspace),
            fds: FdTable::with_stdio(),
            fs: Shared::new(FsInfo { cwd: ROOT, cwd_pin: None, umask: 0o022 }),
            policy,
            uid,
            gid,
            ids: Ids { ruid: uid, suid: uid, rgid: gid, sgid: gid, groups: alloc::vec![gid] },
            sigactions: Shared::new([SigAction::default(); 65]),
            shared_pending: SigQueue::default(),
            rlimits,
            name: [0; 16],
            exe: String::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            auxv: Vec::new(),
            args_charge: Default::default(),
            threads: BTreeMap::from([(pid, Thread::new(pid))]),
            current: pid,
            runq: RunQ::default(),
            futexes: BTreeMap::new(),
            slice_start: 0,
            resched: false,
            exclusive_wanted: false,
            io_seen: 0,
            timers: crate::timer::Timers::default(),
            exited_cpu_ns: 0,
            subreaper: false,
            membarrier_registered: 0,
            uses_signalfd: false,
            stopped: false,
            job_report: None,
            job_notice: None,
            ctty: None,
            aio: Default::default(),
            landlocked: false,
        }
    }

    /// A child, as fork makes it: the same memory (`aspace`, already
    /// copied), files, handlers, limits and working directory, and one
    /// thread, which the caller sets up. Descriptors, working directory
    /// and handlers are copies, or the same ones for what `share` says.
    /// Timers aren't inherited (timerfds are, being files).
    pub fn fork(&self, pid: u32, aspace: AddressSpace, share: Share) -> Result<Process, Errno> {
        let args_charge = crate::kmem::Charge::new(self.args_charge.bytes())?;
        let mut c = Process::new(pid, self.policy, self.uid, self.gid, aspace);
        c.args_charge = args_charge;
        c.ppid = self.pid;
        c.pgid = self.pgid;
        c.sid = self.sid;
        c.ctty = self.ctty.clone();
        c.fds = if share.files { self.fds.share() } else { self.fds.copy()? };
        c.fs = if share.fs { self.fs.share() } else { self.fs.copy() };
        c.ids = self.ids.clone();
        c.sigactions = if share.sighand { self.sigactions.share() } else { self.sigactions.copy() };
        c.rlimits = self.rlimits;
        c.name = self.name;
        c.exe = self.exe.clone();
        c.argv = self.argv.clone();
        c.envp = self.envp.clone();
        c.auxv = self.auxv.clone();
        c.io_seen = self.io_seen;
        c.uses_signalfd = self.uses_signalfd;
        Ok(c)
    }

    pub fn cwd(&self) -> Ino {
        self.fs.get().cwd
    }

    pub fn umask(&self) -> u32 {
        self.fs.get().umask
    }

    pub fn action(&self, sig: u32) -> SigAction {
        self.sigactions.update(|a| a[sig as usize])
    }

    pub fn set_action(&self, sig: u32, act: SigAction) {
        self.sigactions.update(|a| a[sig as usize] = act);
    }

    /// Name thread `tid` (PR_SET_NAME, a write to its comm file): the main
    /// thread's is the process's.
    pub fn set_thread_name(&mut self, tid: u32, name: [u8; 16]) {
        if tid == self.pid {
            self.name = name;
            if let Some(t) = self.threads.get_mut(&tid) {
                t.name = [0; 16];
            }
        } else if let Some(t) = self.threads.get_mut(&tid) {
            t.name = name;
        }
    }

    /// Thread `tid`'s name as comm holds it (16 bytes, NUL-padded).
    pub fn thread_name(&self, tid: u32) -> [u8; 16] {
        match self.threads.get(&tid) {
            Some(t) if t.name[0] != 0 => t.name,
            _ => self.name,
        }
    }

    /// The command name (comm), for reports.
    pub fn comm(&self) -> &str {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }

    /// CPU time used by thread `tid` so far (ns). The running thread has
    /// been on the CPU since `slice_start`.
    pub fn thread_cpu_ns(&self, tid: u32) -> Option<u64> {
        let t = self.threads.get(&tid)?;
        let now = crate::time::monotonic_ns();
        let running = if self.running && tid == self.current {
            now.saturating_sub(self.slice_start)
        } else {
            // On another CPU since then.
            crate::smp::running_since(tid).map_or(0, |since| now.saturating_sub(since))
        };
        Some(t.cpu_ns + running)
    }

    pub fn process_cpu_ns(&self) -> u64 {
        self.exited_cpu_ns + self.threads.keys().filter_map(|&tid| self.thread_cpu_ns(tid)).sum::<u64>()
    }

    pub fn cur(&mut self) -> &mut Thread {
        self.threads.get_mut(&self.current).expect("current thread missing")
    }

    /// Block the calling thread. The syscall handler returns the result of
    /// this (EBLOCKED) and the scheduler runs something else; whoever wakes the
    /// thread decides its syscall's return value.
    pub fn block(&mut self, on: WaitOn, deadline: Option<u64>, on_timeout: SysResult) -> SysResult {
        let timeout_ret = match on_timeout {
            Ok(v) => v,
            Err(e) => (-(e.0 as i64)) as u64,
        };
        let t = self.cur();
        t.wait = Some(Wait { on, deadline, timeout_ret, rerun: false });
        t.restart_deadline = deadline;
        crate::sched::timer_changed();
        if let Some(deadline) = deadline {
            crate::sched::deadline_at(deadline);
        }
        Err(EBLOCKED)
    }

    /// Deadline for a blocking call with a relative timeout (`None` = forever),
    /// reusing the original deadline if this is a re-run of a rewound call.
    pub fn timeout_deadline(&mut self, timeout_ns: Option<u64>) -> Option<u64> {
        let restarted = self.cur().restart_deadline.take();
        restarted.or_else(|| timeout_ns.map(|ns| crate::time::monotonic_ns().saturating_add(ns)))
    }

    /// Block until I/O state changes (then the syscall reruns) or the deadline passes.
    pub fn block_io(&mut self, deadline: Option<u64>, on_timeout: SysResult) -> SysResult {
        self.block(WaitOn::Io, deadline, on_timeout)
    }

    /// The same, but the syscall runs again when the deadline passes too
    /// (`restart_deadline` then says it has).
    pub fn block_io_rerun(&mut self, deadline: Option<u64>) -> SysResult {
        let r = self.block(WaitOn::Io, deadline, Ok(0));
        if let Some(w) = self.cur().wait.as_mut() {
            w.rerun = true;
        }
        r
    }

    /// If any I/O state changed, restart every thread blocked on I/O.
    /// Returns whether any was.
    pub fn wake_io_waiters(&mut self) -> bool {
        let version = crate::ipc::generation();
        if version == self.io_seen {
            return false;
        }
        self.io_seen = version;
        let waiting: Vec<u32> =
            self.threads.values().filter(|t| t.wait.is_some_and(|w| w.on == WaitOn::Io)).map(|t| t.tid).collect();
        let any = !waiting.is_empty();
        for tid in waiting {
            let t = self.threads.get_mut(&tid).unwrap();
            t.wait = None;
            // Re-execute the system call: its arguments are still there.
            t.regs.rewind_syscall();
            t.restarting = true;
            t.recheck = true;
            self.runq.push_back(tid);
        }
        any
    }

    /// Make a blocked thread runnable; its syscall returns `ret` (or its
    /// timeout value if `None`).
    pub fn wake(&mut self, tid: u32, ret: Option<u64>) {
        let Some(w) = self.cancel_wait(tid) else { return };
        let t = self.threads.get_mut(&tid).unwrap();
        if ret.is_none() && w.rerun {
            // Out of time: it runs again, keeping its (past) deadline.
            t.regs.rewind_syscall();
            t.restarting = true;
            t.recheck = true;
        } else {
            t.regs.set_return(ret.unwrap_or(w.timeout_ret));
            t.restart_deadline = None;
        }
        self.runq.push_back(tid);
    }

    /// Stop a thread's wait (leaving its futex queue) without making it runnable.
    pub fn cancel_wait(&mut self, tid: u32) -> Option<Wait> {
        let t = self.threads.get_mut(&tid)?;
        let w = t.wait.take()?;
        let addrs = match w.on {
            WaitOn::Futex(addr) => alloc::vec![addr],
            WaitOn::SharedFutex(key) => {
                crate::futex::leave(key, tid);
                Vec::new()
            }
            WaitOn::FutexV => t.futexv.take().map(|v| v.addrs).unwrap_or_default(),
            _ => Vec::new(),
        };
        for addr in addrs {
            if let Some(q) = self.futexes.get_mut(&addr) {
                q.retain(|&(t, _)| t != tid);
                if q.is_empty() {
                    self.futexes.remove(&addr);
                }
            }
        }
        crate::sched::timer_changed();
        Some(w)
    }

    fn first_report(&mut self, kind: u8, nr: u32, detail: &str) -> bool {
        // Enough to tell reports apart: a path has no limit but the tree's.
        let kept = detail.floor_char_boundary(MAX_REPORT_BYTES);
        let mut reported = REPORTED.lock();
        reported.len() < MAX_REPORTS && reported.insert((kind, nr, detail[..kept].into()))
    }

    /// End the process with wait status `status`. The main program ending
    /// ends the sandbox. Any other process is finished off by the scheduler
    /// before anything of it runs again (`procs::finalize`): the syscall or
    /// trap that got here unwinds normally first.
    pub fn terminate(&mut self, status: i32) {
        if self.pid == INIT {
            // The running thread's time since `slice_start`: the scheduler
            // won't count it, as the sandbox ends here.
            if self.running {
                let now = crate::time::monotonic_ns();
                crate::stats::cpu(now.saturating_sub(self.slice_start));
                self.slice_start = now;
            }
            match status & 0x7f {
                0 => finish(ExitKind::Exited, (status >> 8) & 0xff),
                sig => finish(ExitKind::Signaled, sig),
            }
        }
        if self.exit_status.is_none() {
            self.exit_status = Some(status);
            crate::procs::DYING.store(true, Ordering::Relaxed);
            // Its threads running on other CPUs stop now (it may not be
            // the running process: a signal from the host, a timer).
            crate::smp::kick_others(self.pid);
        }
    }

    /// End the process with signal `sig`. `report` sends a Fault event
    /// (faults, policy kills); the main program always reports, since its
    /// end is the sandbox's.
    pub fn kill(&mut self, sig: u32, addr: u64, pc: u64, detail: &str, report: bool) {
        if self.pid == INIT {
            console::event(&Event::Fault { signal: sig, addr, pc, detail });
        } else if report {
            let detail = alloc::format!("process {} ({}): {detail}", self.pid, self.comm());
            console::event(&Event::Fault { signal: sig, addr, pc, detail: &detail });
        }
        self.terminate(signaled(sig))
    }

    /// A syscall needed a capability the policy does not grant.
    pub fn deny(&mut self, nr: u32, syscall: &str, capability: &str, detail: &str) -> SysResult {
        if self.first_report(0, nr, detail) {
            console::event(&Event::Denied { nr, syscall, capability, detail });
        }
        match self.policy.on_deny {
            DenyAction::Errno => Err(EPERM),
            DenyAction::Kill => {
                let msg = alloc::format!("{syscall} denied (needs capability `{capability}`)");
                self.kill(signal::SIGSYS, 0, 0, &msg, true);
                // Unwinds to the syscall handler, which finishes the process off.
                Err(EBLOCKED)
            }
        }
    }

    /// The program needs something this kernel does not implement yet.
    pub fn unimplemented(&mut self, nr: u32, syscall: &str, detail: &str, err: Errno) -> SysResult {
        if self.first_report(1, nr, detail) {
            console::event(&Event::Unimplemented { nr, syscall, detail });
        }
        Err(err)
    }

    /// The program looked for a path that was not imported.
    pub fn missing_path(&mut self, base: Ino, path: &str) {
        if !fs::lock().missing_is_import_gap(base, path) {
            return;
        }
        let abs = if path.starts_with('/') {
            String::from(path)
        } else {
            let mut s = fs::lock().path_of(base);
            if !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(path);
            s
        };
        if self.first_report(2, 0, &abs) {
            console::event(&Event::MissingPath { path: &abs });
        }
    }
}

/// The program has ended: report its status, then send the exported
/// directories. Status first, so a slow export can't cost the host it.
pub fn finish(kind: ExitKind, code: i32) -> ! {
    // What the terminal still has to show goes before the status, and so
    // do the final counts.
    crate::tty::flush_console();
    console::report_stats();
    // What the kernel lock and TLB flushes cost (`grix run -v` shows it).
    if crate::smp::count() > 1 {
        let mut s = alloc::string::String::new();
        crate::smp::stats(&mut s);
        console::klog!("{s}");
    }
    console::report_exit(kind, code);
    crate::export::send();
    console::power_off()
}

/// Demand paging for a user translation fault.
pub fn user_fault(tf: &TrapFrame, far: u64, access: Access, esr: u64) {
    crate::stats::page_fault();
    let mut guard = running().lock();
    let p = guard.as_mut().expect("fault without a process");
    match p.aspace.fault(far, access) {
        // A write that gave a page its frame: other mappings' copies of it
        // go before this thread goes on.
        Ok(()) => crate::procs::zap_stale(Some(p), &mut crate::procs::PROCS.lock()),
        Err(FaultError::Segv) => {
            let code = if p.aspace.find(far).is_some() { signal::SEGV_ACCERR } else { signal::SEGV_MAPERR };
            let fault = signal::Fault { addr: far, pc: tf.pc(), syndrome: Some(esr) };
            signal::fault(p, signal::SIGSEGV, code, fault, access.describe_violation())
        }
        Err(FaultError::OutOfMemory) => p.kill(signal::SIGKILL, far, tf.pc(), "out of memory", true),
        Err(FaultError::PastEnd) => {
            const BUS_ADRERR: i32 = 2;
            let fault = signal::Fault { addr: far, pc: tf.pc(), syndrome: Some(esr) };
            signal::fault(p, signal::SIGBUS, BUS_ADRERR, fault, "past the end of a mapped file")
        }
        // As Linux does when a mapped file can't be read.
        Err(FaultError::Io) => {
            const BUS_ADRERR: i32 = 2;
            let fault = signal::Fault { addr: far, pc: tf.pc(), syndrome: Some(esr) };
            signal::fault(p, signal::SIGBUS, BUS_ADRERR, fault, "a mapped file couldn't be read")
        }
    }
}

/// The program to start: a name without a slash is looked up in the
/// environment's PATH (as a shell or a container runtime does), the first
/// regular file there being it. Otherwise, or if none is found, the name as
/// it is.
fn search_path(cwd: Ino, exe: &str, envp: &[String]) -> String {
    if exe.contains('/') {
        return exe.into();
    }
    let path = envp
        .iter()
        .find_map(|e| e.strip_prefix("PATH="))
        .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    let mut fs = fs::lock();
    for dir in path.split(':').filter(|d| !d.is_empty()) {
        let candidate = alloc::format!("{}/{exe}", dir.trim_end_matches('/'));
        if let Ok(ino) = fs.lookup(cwd, &candidate, true)
            && matches!(fs.node(ino).kind, Kind::File(_))
        {
            return candidate;
        }
    }
    exe.into()
}

/// Load the image's program and jump to it.
pub fn start(img: Image<'static>) -> ! {
    // Kept for good (this never returns), for comparing mounts at the end.
    let entries: &'static [grix_abi::image::Entry<'static>] = img.entries.leak();
    crate::export::init(&img.exports, &img.mounts, entries, img.export_budget);
    crate::inet::init(img.forwards.clone(), img.udp_forwards.clone());
    crate::procfs::set_hostname(img.hostname);
    let fail = |code: i32, reason: &str| -> ! {
        console::event(&Event::ExecFailed { path: img.exe, reason });
        klog!("exec {}: {}\n", img.exe, reason);
        finish(ExitKind::Exited, code)
    };
    let cpus = img.cpus.clamp(1, grix_abi::machine::MAX_CPUS);
    // With `net`, the guest has an interface to describe (/sys/class/net).
    crate::netlink::init(img.policy.allows(grix_abi::policy::Capability::Net));
    let mut fs = fs::Fs::build(entries, &img.mounts, &img.live_mounts, (img.uid, img.gid), cpus);
    for m in &img.mounts {
        fs.mark_mount(m);
    }
    let cwd = match fs.lookup(ROOT, img.cwd, true) {
        Ok(ino) if fs.is_dir(ino) => ino,
        _ => fail(127, &alloc::format!("working directory {} does not exist", img.cwd)),
    };
    fs::install(fs);
    // Like tmpfs's default size: half of RAM for written file data.
    fs::set_limit(crate::mm::frame::stats().0 / 2);

    let (stdin, gicr) = (img.stdin, img.gicr);
    X86_64.call_once(|| String::from(img.x86_64));
    let aspace = AddressSpace::new().expect("out of memory at boot");
    let mut p = Process::new(INIT, img.policy, img.uid, img.gid, aspace);
    p.cur().charge = crate::kmem::Charge::new(THREAD_COST).expect("no kernel memory for the first thread");
    // This CPU's process from the start (`mm::gate`).
    p.aspace.lock();
    if let Some((rows, cols)) = img.tty {
        // The program leads its session, with the terminal as its
        // controlling one, in the foreground.
        let (tty, file) = crate::tty::console_terminal(rows, cols, img.uid, img.gid);
        p.fds = FdTable::with_terminal(file);
        (tty.lock().session, tty.lock().fg) = (INIT, INIT);
        p.ctty = Some(tty);
    }
    let cwd_pin = Some(fs::lock().pin(cwd));
    p.fs.update(|f| (f.cwd, f.cwd_pin) = (cwd, cwd_pin));
    p.running = true;
    // One process and its thread, until the scheduler counts.
    crate::procs::born();
    crate::stats::tasks(1, 1);
    let argv = img.argv.iter().map(|s| String::from(*s)).collect();
    let envp: Vec<String> = img.envp.iter().map(|s| String::from(*s)).collect();
    let exe = search_path(cwd, img.exe, &envp);
    let program = match load_program(&p, Start::Path(cwd), &exe, argv, envp) {
        Ok(program) => program,
        Err(e) => fail(if e.errno == ENOENT { 127 } else { 126 }, &e.reason),
    };
    {
        let mut fs = fs::lock();
        let cwd_path = fs.path_of(cwd);
        fs.proc_add(INIT, (img.uid, img.gid), &program.exe, &cwd_path);
    }
    let (entry, sp) = program.install(&mut p);
    p.slice_start = crate::time::monotonic_ns();
    // The kernel is ours while the other CPUs start (they wait for it).
    crate::smp::lock();
    *running().lock() = Some(Box::new(p));
    arch::irq::init(gicr);
    crate::smp::start(cpus);
    console::start(stdin);
    crate::smp::unlock();
    arch::enter_user(entry, sp)
}

/// The heap an argument takes beyond its bytes: its `String` (Vecs leave
/// room to grow) and the smallest allocation.
pub const ARG_OVERHEAD: u64 = 2 * core::mem::size_of::<String>() as u64 + 16;

/// Why a program couldn't be loaded: the errno execve returns, and the
/// explanation reported for the first program.
pub struct ExecError {
    pub errno: Errno,
    pub reason: String,
}

fn exec_error(errno: Errno, reason: String) -> ExecError {
    ExecError { errno, reason }
}

/// A program loaded into a new address space, ready to replace a
/// process's image (`install`).
pub struct Program {
    aspace: AddressSpace,
    args_charge: crate::kmem::Charge,
    entry: u64,
    sp: u64,
    /// The file actually run (the interpreter, for `#!` scripts), its argv
    /// and environment.
    exe: String,
    argv: Vec<String>,
    envp: Vec<String>,
    auxv: Vec<u64>,
}

/// What execve starts from.
pub enum Start {
    /// A path, from this directory.
    Path(Ino),
    /// A file open at a descriptor (fexecve): `path` is only its name.
    File { ino: Ino, content: fs::Content, cwd: Ino, reachable: bool },
}

/// Find what `start` and `path` name, follow `#!` lines, and load the ELF
/// and its interpreter into a new address space with the initial stack
/// built. `p` is untouched, so a failure leaves it running.
pub fn load_program(
    p: &Process,
    start: Start,
    path: &str,
    argv: Vec<String>,
    envp: Vec<String>,
) -> Result<Program, ExecError> {
    let landlock = crate::landlock::domain(p);
    let (exe, ino, src, argv) = {
        let mut fs = fs::lock();
        resolve_interpreters(&mut fs, landlock.as_deref(), (p.uid, p.gid), start, path, argv)?
    };
    let bytes: u64 = argv.iter().chain(&envp).map(|s| s.len() as u64 + 1).sum();
    // What they hold on the heap (`Process::argv`, the name): an empty
    // string costs more than its byte, and execve takes 100,000 of them.
    let held = bytes + (argv.len() + envp.len()) as u64 * ARG_OVERHEAD + exe.len() as u64;
    let args_charge = crate::kmem::Charge::new(held)
        .map_err(|e| exec_error(e, "no kernel memory left for argv and environment".into()))?;
    let mut aspace = AddressSpace::new().ok_or_else(|| exec_error(ENOMEM, "out of memory".into()))?;
    // The stack is as big as RLIMIT_STACK lets it grow on Linux, with room
    // for the arguments (and their pointers) at least.
    let strings = (argv.len() + envp.len()) as u64;
    let need = bytes + strings * 8 + (128 << 10);
    aspace.set_stack(crate::mm::page_up(p.rlimits[3].0.min(MAX_STACK).max(need)).unwrap_or(MAX_STACK));
    let loaded = elf::load(&mut aspace, &src, ino, Some(elf::DYN_BASE))
        .map_err(|e| exec_error(ENOEXEC, alloc::format!("{exe}: {e}")))?;
    let (entry, interp_base) = match &loaded.interp {
        Some(ipath) => {
            let cwd = p.cwd();
            let (isrc, iino) = {
                let mut fs = fs::lock();
                let ino = fs.lookup(cwd, ipath, true).map_err(|_| {
                    exec_error(ENOENT, alloc::format!("ELF interpreter {ipath} not found (was it imported?)"))
                })?;
                match &fs.node(ino).kind {
                    Kind::File(c) => {
                        let src = elf::Source::of(c);
                        may_execute(&mut fs, landlock.as_deref(), ino, cwd, ipath)?;
                        (src, ino)
                    }
                    _ => {
                        return Err(exec_error(
                            EACCES,
                            alloc::format!("ELF interpreter {ipath} is not a regular file"),
                        ));
                    }
                }
            };
            let interp = elf::load(&mut aspace, &isrc, iino, None)
                .map_err(|e| exec_error(ELIBBAD, alloc::format!("{ipath}: {e}")))?;
            if interp.interp.is_some() {
                return Err(exec_error(ELIBBAD, "ELF interpreter requests its own interpreter".into()));
            }
            (interp.entry, interp.base)
        }
        None => (loaded.entry, 0),
    };

    aspace.brk_start = loaded.end;
    aspace.brk = loaded.end;
    aspace.map(Vma::anon(aspace.stack_bottom(), STACK_TOP, Prot::RW));
    aspace.map(Vma { start: SIGPAGE, end: SIGPAGE + PAGE_SIZE, prot: Prot::RX, backing: Backing::Sigpage });
    let (vvar, vdso) = crate::vdso::frames();
    aspace.map(Vma {
        start: VVAR,
        end: VVAR + PAGE_SIZE,
        prot: Prot { read: true, write: false, exec: false },
        backing: Backing::KernelPage(vvar),
    });
    aspace.map(Vma { start: VDSO, end: VDSO + PAGE_SIZE, prot: Prot::RX, backing: Backing::KernelPage(vdso) });

    let auxv = [
        (33, VDSO),                       // AT_SYSINFO_EHDR
        (3, loaded.phdr),                 // AT_PHDR
        (4, 56),                          // AT_PHENT
        (5, loaded.phnum),                // AT_PHNUM
        (6, 4096),                        // AT_PAGESZ
        (7, interp_base),                 // AT_BASE
        (8, 0),                           // AT_FLAGS
        (9, loaded.entry),                // AT_ENTRY
        (11, p.ids.ruid as u64),          // AT_UID
        (12, p.uid as u64),               // AT_EUID
        (13, p.ids.rgid as u64),          // AT_GID
        (14, p.gid as u64),               // AT_EGID
        (16, arch::hwcap()),              // AT_HWCAP
        (17, 100),                        // AT_CLKTCK
        (23, 0),                          // AT_SECURE
        (26, arch::hwcap2()),             // AT_HWCAP2
        (51, arch::sigframe::max_size()), // AT_MINSIGSTKSZ
    ];
    // The stack is written through the new address space's own mapping.
    aspace.activate();
    let sp = {
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let env: Vec<&str> = envp.iter().map(String::as_str).collect();
        build_stack(&mut aspace, &args, &env, path, &auxv)
    };
    p.aspace.activate();
    let (sp, auxv) =
        sp.map_err(|e| exec_error(e, alloc::format!("could not build the initial stack (errno {})", e.0)))?;
    Ok(Program { aspace, args_charge, entry, sp, exe, argv, envp, auxv })
}

impl Program {
    /// Replace `p`'s image with this program (the point of no return).
    /// Returns where it starts: (entry, sp).
    pub fn install(self, p: &mut Process) -> (u64, u64) {
        // Held here, as the process is (`mm::gate`); the old one's gate
        // goes with it.
        let old = core::mem::replace(&mut p.aspace, Mm::new_held(self.aspace));
        p.aspace.activate();
        drop(old);
        let base = self.exe.rsplit('/').next().unwrap_or(&self.exe).as_bytes();
        p.name = [0; 16];
        p.name[..base.len().min(15)].copy_from_slice(&base[..base.len().min(15)]);
        p.exe = self.exe;
        p.argv = self.argv;
        p.envp = self.envp;
        p.auxv = self.auxv;
        p.args_charge = self.args_charge;
        (self.entry, self.sp)
    }
}

/// The translator for x86_64 programs (`Image::x86_64`).
pub static X86_64: spin::Once<String> = spin::Once::new();

/// A 64-bit little-endian ELF for x86_64 (EM_X86_64), on a kernel that
/// isn't x86_64's: one for a translator.
fn is_x86_64_elf(head: &[u8]) -> bool {
    crate::arch::ELF_MACHINE != 62
        && head.len() >= 20
        && head.starts_with(b"\x7fELF\x02\x01")
        && u16::from_le_bytes([head[18], head[19]]) == 62
}

/// Follow `#!` lines like Linux's binfmt_script: `#!interp [arg]` runs
/// `interp [arg] script args...`, and x86_64 programs through their
/// translator. Returns the ELF to load (its path, node and bytes) and the
/// final argv.
/// Landlock's check of a file execve opens (the program, a script's
/// interpreter, the ELF interpreter) by `path` from `base`: as Linux's
/// open_exec, it's read too.
fn may_execute(
    fs: &mut fs::Fs,
    landlock: Option<&crate::landlock::Domain>,
    ino: Ino,
    base: Ino,
    path: &str,
) -> Result<(), ExecError> {
    use crate::landlock::{EXECUTE, READ_FILE};
    let Some(d) = landlock else { return Ok(()) };
    let dir = fs.found_in(ino, base, path, &fs::Scope::NONE);
    d.check_in(fs, ino, dir, EXECUTE | READ_FILE)
        .map_err(|e| exec_error(e, alloc::format!("{path}: refused by the program's Landlock rules")))
}

fn resolve_interpreters(
    fs: &mut fs::Fs,
    landlock: Option<&crate::landlock::Domain>,
    (uid, gid): (u32, u32),
    start: Start,
    path: &str,
    mut argv: Vec<String>,
) -> Result<(String, Ino, elf::Source, Vec<String>), ExecError> {
    let mut path = String::from(path);
    let (cwd, mut opened, mut reachable) = match start {
        Start::Path(base) => (base, None, true),
        Start::File { ino, content, cwd, reachable } => (cwd, Some((ino, content)), reachable),
    };
    for _ in 0..5 {
        let what = if argv.first().is_some_and(|a| *a == path) || argv.is_empty() { "program" } else { "interpreter" };
        let (ino, content) = match opened.take() {
            Some((ino, content)) => (ino, Some(content)),
            None => {
                let ino = fs
                    .lookup(cwd, &path, true)
                    .map_err(|e| exec_error(e, alloc::format!("{what} {path} not found (was it imported?)")))?;
                (ino, fs.content(ino).filter(|_| matches!(fs.node(ino).kind, Kind::File(_))))
            }
        };
        let Some(content) = content else {
            return Err(exec_error(EACCES, alloc::format!("{what} {path} is not a regular file")));
        };
        if !fs.permits(ino, uid, gid, fs::MAY_EXEC) {
            return Err(exec_error(EACCES, alloc::format!("{what} {path} is not executable")));
        }
        let src = elf::Source::of(&content);
        may_execute(fs, landlock, ino, cwd, &path)?;
        // Linux reads at most this much of the #! line.
        let mut buf = [0u8; 256];
        let n = src.read(0, &mut buf);
        let head = &buf[..n];
        // An x86_64 program: its translator runs it (binfmt_misc's way:
        // the translator, the program's path, then its arguments).
        if is_x86_64_elf(head) {
            let Some(translator) = X86_64.get().filter(|t| !t.is_empty()) else {
                return Err(exec_error(
                    ENOEXEC,
                    alloc::format!(
                        "{path} is an x86_64 program, and grix runs arm64 ones: give the sandbox an x86_64 \
                         translator (qemu-x86_64 or box64; `--x86-64`)"
                    ),
                ));
            };
            let mut next = alloc::vec![translator.clone(), path.clone()];
            next.extend(argv.into_iter().skip(1));
            argv = next;
            path = translator.clone();
            continue;
        }
        let Some(rest) = head.strip_prefix(b"#!") else { return Ok((fs.path_of(ino), ino, src, argv)) };
        if !reachable {
            return Err(exec_error(
                ENOENT,
                alloc::format!("{path}: a close-on-exec script can't be read by its #! line"),
            ));
        }
        reachable = true;
        let line = rest.split(|&b| b == b'\n').next().unwrap_or(rest);
        let line = core::str::from_utf8(&line[..line.len().min(254)])
            .map_err(|_| exec_error(ENOEXEC, alloc::format!("{path}: invalid #! line")))?
            .trim();
        let (interp, arg) = match line.split_once([' ', '\t']) {
            Some((i, a)) => (i, Some(a.trim()).filter(|a| !a.is_empty())),
            None => (line, None),
        };
        if interp.is_empty() {
            return Err(exec_error(ENOEXEC, alloc::format!("{path}: empty #! line")));
        }
        let mut next = alloc::vec![String::from(interp)];
        next.extend(arg.map(String::from));
        next.push(path.clone());
        next.extend(argv.into_iter().skip(1));
        argv = next;
        path = String::from(interp);
    }
    Err(exec_error(ELOOP, alloc::format!("{path}: too many levels of #! interpreters")))
}

/// The most argv + envp may hold, their pointers counted: a quarter of the
/// default stack, as Linux and so `sysconf(_SC_ARG_MAX)`, which is what
/// `find -exec {} +` fills.
pub const MAX_ARGS: usize = (crate::mm::aspace::STACK_SIZE / 4) as usize;

/// Lay out argc/argv/envp/auxv at the top of the stack as Linux does.
/// Returns the stack pointer and the auxiliary vector as written.
fn build_stack(
    a: &mut AddressSpace,
    argv: &[&str],
    envp: &[&str],
    execfn: &str,
    aux: &[(u64, u64)],
) -> Result<(u64, Vec<u64>), Errno> {
    let total: usize = argv.iter().chain(envp).map(|s| s.len() + 1).sum::<usize>() + execfn.len() + 1;
    if total > MAX_ARGS {
        return Err(E2BIG);
    }
    // As Linux's exec, the strings start a pointer below the top: the
    // stack ends with a zero word after the program's name (code that
    // rewrites the argv and environment area, like Node's process.title,
    // may reach it).
    let mut sp = STACK_TOP - 8;
    let mut push = |a: &mut AddressSpace, bytes: &[u8]| -> Result<u64, Errno> {
        sp -= bytes.len() as u64;
        copy_out(a, sp, bytes)?;
        Ok(sp)
    };
    let mut cstr = |a: &mut AddressSpace, s: &str| -> Result<u64, Errno> {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        push(a, &v)
    };
    // In Linux's order, from the top down: the program's name, then the
    // environment's strings and the arguments', each array ascending and
    // all of it contiguous. setproctitle code (libuv's, nginx's,
    // PostgreSQL's) measures the area it may rewrite by that.
    let execfn_ptr = cstr(a, execfn)?;
    let mut env_ptrs = envp.iter().rev().map(|s| cstr(a, s)).collect::<Result<Vec<_>, _>>()?;
    env_ptrs.reverse();
    let mut arg_ptrs = argv.iter().rev().map(|s| cstr(a, s)).collect::<Result<Vec<_>, _>>()?;
    arg_ptrs.reverse();
    let platform_ptr = cstr(a, crate::arch::PLATFORM)?;
    let mut random = [0u8; 16];
    rng::fill(&mut random);
    let random_ptr = push(a, &random)?;

    let mut auxv: Vec<u64> = Vec::new();
    for &(k, v) in aux.iter().chain(&[(15, platform_ptr), (25, random_ptr), (31, execfn_ptr), (0, 0)]) {
        auxv.push(k);
        auxv.push(v);
    }
    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(&arg_ptrs);
    words.push(0);
    words.extend(&env_ptrs);
    words.push(0);
    words.extend(&auxv);
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let sp = (random_ptr - bytes.len() as u64) & !15;
    copy_out(a, sp, &bytes)?;
    Ok((sp, auxv))
}
