//! A process: its threads, exec, faults, termination, and reporting of
//! denied/unimplemented operations. The one running is in `PROCESS`; the
//! others, and zombies, are in `procs::PROCS`.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use grix_abi::image::Image;
use grix_abi::policy::{DenyAction, Policy};
use grix_abi::wire::{Event, ExitKind};
use spin::Mutex;

use crate::arch::{self, FpState, TrapFrame};
use crate::console::{self, klog};
use crate::elf;
use crate::errno::*;
use crate::fd::FdTable;
use crate::fs::{self, Ino, Kind, ROOT};
use crate::mm::PAGE_SIZE;
pub use crate::mm::aspace::Access;
use crate::mm::aspace::{AddressSpace, Backing, FaultError, SIGPAGE, STACK_SIZE, STACK_TOP, Vma};
use crate::mm::paging::Prot;
use crate::rng;
use crate::signal::{self, AltStack, SigQueue};
use crate::uaccess::copy_out;

/// The program the sandbox runs. When it ends, the sandbox does.
pub const INIT: u32 = 1;
/// Threads in all processes together. Linux allows far more; this bounds
/// kernel memory per sandbox.
pub const MAX_THREADS: usize = 1024;

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
}

pub struct Thread {
    pub tid: u32,
    /// User registers, valid while the thread is not running.
    pub regs: TrapFrame,
    pub tpidr: u64,
    pub fp: FpState,
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
}

impl Thread {
    pub fn new(tid: u32) -> Self {
        Thread {
            tid,
            regs: TrapFrame::default(),
            tpidr: 0,
            fp: FpState::default(),
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
        }
    }
}

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
    /// This is the process in `PROCESS`, on the CPU.
    pub running: bool,
    /// A vfork child: the parent thread waiting for it to exec or exit.
    pub vfork_parent: Option<(u32, u32)>,
    /// CPU time of reaped children (RUSAGE_CHILDREN, times).
    pub children_cpu_ns: u64,
    pub aspace: AddressSpace,
    pub fds: FdTable,
    pub cwd: Ino,
    /// Keeps the working directory's slot from being reused if it's removed.
    pub cwd_pin: Option<alloc::sync::Arc<()>>,
    pub policy: Policy,
    pub uid: u32,
    pub gid: u32,
    pub umask: u32,
    pub sigactions: [SigAction; 65],
    /// Signals sent to the whole process (kill), taken by any thread that doesn't block them.
    pub shared_pending: SigQueue,
    pub rlimits: [(u64, u64); 16],
    pub name: [u8; 16],
    /// The running program (after `#!` resolution), its argv and environment.
    pub exe: String,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
    /// The kernel memory `argv` and `envp` take (every fork copies them).
    pub args_charge: crate::kmem::Charge,

    // Threads and scheduling (see sched.rs).
    pub threads: BTreeMap<u32, Thread>,
    /// The running thread. Its live state is in the CPU, not in `threads`.
    pub current: u32,
    /// Runnable threads other than `current`, in round-robin order.
    pub runq: VecDeque<u32>,
    /// Futex wait queues: address -> (tid, bitset) in FIFO order.
    pub futexes: BTreeMap<u64, VecDeque<(u32, u32)>>,
    /// When the current thread's time slice started (monotonic ns).
    pub slice_start: u64,
    /// Switch threads before returning to user space.
    pub resched: bool,
    /// The timer needs reprogramming (runnable set or deadlines changed).
    pub timer_dirty: bool,
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
}

pub static PROCESS: Mutex<Option<Process>> = Mutex::new(None);

/// What has been reported to the host already, for every process: each
/// denial, gap and missing path once.
static REPORTED: Mutex<BTreeSet<(u8, u32, String)>> = Mutex::new(BTreeSet::new());

const MAX_REPORTS: usize = 512;
const RLIM_INFINITY: u64 = u64::MAX;

impl Process {
    fn new(pid: u32, policy: Policy, uid: u32, gid: u32, aspace: AddressSpace) -> Self {
        let mut rlimits = [(RLIM_INFINITY, RLIM_INFINITY); 16];
        rlimits[3] = (STACK_SIZE, RLIM_INFINITY); // RLIMIT_STACK
        rlimits[4] = (0, 0); // RLIMIT_CORE
        rlimits[7] = (crate::fd::MAX_FDS as u64, crate::fd::MAX_FDS as u64); // RLIMIT_NOFILE
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
            aspace,
            fds: FdTable::with_stdio(),
            cwd: ROOT,
            cwd_pin: None,
            policy,
            uid,
            gid,
            umask: 0o022,
            sigactions: [SigAction::default(); 65],
            shared_pending: SigQueue::default(),
            rlimits,
            name: [0; 16],
            exe: String::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            args_charge: Default::default(),
            threads: BTreeMap::from([(pid, Thread::new(pid))]),
            current: pid,
            runq: VecDeque::new(),
            futexes: BTreeMap::new(),
            slice_start: 0,
            resched: false,
            timer_dirty: true,
            io_seen: 0,
            timers: crate::timer::Timers::default(),
            exited_cpu_ns: 0,
            subreaper: false,
            membarrier_registered: 0,
            uses_signalfd: false,
        }
    }

    /// A child, as fork makes it: the same memory (`aspace`, already
    /// copied), files, handlers, limits and working directory, and one
    /// thread, which the caller sets up. Timers aren't inherited (timerfds
    /// are, being files).
    pub fn fork(&self, pid: u32, aspace: AddressSpace) -> Result<Process, Errno> {
        let args_charge = crate::kmem::Charge::new(self.args_charge.bytes())?;
        let mut c = Process::new(pid, self.policy, self.uid, self.gid, aspace);
        c.args_charge = args_charge;
        c.ppid = self.pid;
        c.pgid = self.pgid;
        c.sid = self.sid;
        c.fds = self.fds.clone();
        c.cwd = self.cwd;
        c.cwd_pin = self.cwd_pin.clone();
        c.umask = self.umask;
        c.sigactions = self.sigactions;
        c.rlimits = self.rlimits;
        c.name = self.name;
        c.exe = self.exe.clone();
        c.argv = self.argv.clone();
        c.envp = self.envp.clone();
        c.io_seen = self.io_seen;
        c.timers.fds = self.timers.fds.clone();
        c.uses_signalfd = self.uses_signalfd;
        Ok(c)
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
        let running = if self.running && tid == self.current {
            crate::time::monotonic_ns().saturating_sub(self.slice_start)
        } else {
            0
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
        t.wait = Some(Wait { on, deadline, timeout_ret });
        t.restart_deadline = deadline;
        self.timer_dirty = true;
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
            // Re-execute the svc: x0..x7 still hold the original arguments.
            t.regs.elr -= 4;
            t.restarting = true;
            t.recheck = true;
            self.runq.push_back(tid);
            self.timer_dirty = true;
        }
        any
    }

    /// Make a blocked thread runnable; its syscall returns `ret` (or its
    /// timeout value if `None`).
    pub fn wake(&mut self, tid: u32, ret: Option<u64>) {
        let Some(w) = self.cancel_wait(tid) else { return };
        let t = self.threads.get_mut(&tid).unwrap();
        t.regs.x[0] = ret.unwrap_or(w.timeout_ret);
        t.restart_deadline = None;
        self.runq.push_back(tid);
        self.timer_dirty = true;
    }

    /// Stop a thread's wait (leaving its futex queue) without making it runnable.
    pub fn cancel_wait(&mut self, tid: u32) -> Option<Wait> {
        let w = self.threads.get_mut(&tid)?.wait.take()?;
        if let WaitOn::Futex(addr) = w.on
            && let Some(q) = self.futexes.get_mut(&addr)
        {
            q.retain(|&(t, _)| t != tid);
            if q.is_empty() {
                self.futexes.remove(&addr);
            }
        }
        self.timer_dirty = true;
        Some(w)
    }

    fn first_report(&mut self, kind: u8, nr: u32, detail: &str) -> bool {
        let mut reported = REPORTED.lock();
        reported.len() < MAX_REPORTS && reported.insert((kind, nr, detail.into()))
    }

    /// End the process with wait status `status`. The main program ending
    /// ends the sandbox. Any other process is finished off by the scheduler
    /// before anything of it runs again (`procs::finalize`): the syscall or
    /// trap that got here unwinds normally first.
    pub fn terminate(&mut self, status: i32) {
        if self.pid == INIT {
            match status & 0x7f {
                0 => finish(ExitKind::Exited, (status >> 8) & 0xff),
                sig => finish(ExitKind::Signaled, sig),
            }
        }
        if self.exit_status.is_none() {
            self.exit_status = Some(status);
            crate::procs::DYING.store(true, Ordering::Relaxed);
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
    console::report_exit(kind, code);
    crate::export::send();
    console::power_off()
}

/// Demand paging for a user translation fault.
pub fn user_fault(tf: &TrapFrame, far: u64, access: Access, esr: u64) {
    let mut guard = PROCESS.lock();
    let p = guard.as_mut().expect("fault without a process");
    match p.aspace.fault(far, access) {
        Ok(()) => {}
        Err(FaultError::Segv) => {
            let code = if p.aspace.find(far).is_some() { signal::SEGV_ACCERR } else { signal::SEGV_MAPERR };
            let fault = signal::Fault { addr: far, pc: tf.elr, esr: Some(esr) };
            signal::fault(p, signal::SIGSEGV, code, fault, access.describe_violation())
        }
        Err(FaultError::OutOfMemory) => p.kill(signal::SIGKILL, far, tf.elr, "out of memory", true),
        // As Linux does when a mapped file can't be read.
        Err(FaultError::Io) => {
            const BUS_ADRERR: i32 = 2;
            let fault = signal::Fault { addr: far, pc: tf.elr, esr: Some(esr) };
            signal::fault(p, signal::SIGBUS, BUS_ADRERR, fault, "a mapped file couldn't be read")
        }
    }
}

/// Load the image's program and jump to it.
pub fn start(img: Image<'static>) -> ! {
    // Kept for good (this never returns), for comparing mounts at the end.
    let entries: &'static [grix_abi::image::Entry<'static>] = img.entries.leak();
    crate::export::init(&img.exports, &img.mounts, entries, img.export_budget);
    crate::inet::init(img.forwards.clone());
    let fail = |code: i32, reason: &str| -> ! {
        console::event(&Event::ExecFailed { path: img.exe, reason });
        klog!("exec {}: {}\n", img.exe, reason);
        finish(ExitKind::Exited, code)
    };
    let mut fs = fs::Fs::build(entries, &img.mounts, &img.live_mounts, img.uid, img.gid);
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

    let stdin = img.stdin;
    let aspace = AddressSpace::new().expect("out of memory at boot");
    let mut p = Process::new(INIT, img.policy, img.uid, img.gid, aspace);
    p.cwd = cwd;
    p.cwd_pin = Some(fs::lock().pin(cwd));
    p.running = true;
    let argv = img.argv.iter().map(|s| String::from(*s)).collect();
    let envp = img.envp.iter().map(|s| String::from(*s)).collect();
    let program = match load_program(&p, cwd, img.exe, argv, envp) {
        Ok(program) => program,
        Err(e) => fail(if e.errno == ENOENT { 127 } else { 126 }, &e.reason),
    };
    fs::lock().set_exe(&program.exe);
    let (entry, sp) = program.install(&mut p);
    p.slice_start = crate::time::monotonic_ns();
    *PROCESS.lock() = Some(p);
    arch::irq::init();
    console::start(stdin);
    arch::enter_user(entry, sp)
}

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
}

/// Find `path` (relative to directory `base`), follow `#!` lines, and load
/// the ELF and its interpreter into a new address space with the initial
/// stack built. `p` is untouched, so a failure leaves it running.
pub fn load_program(
    p: &Process,
    base: Ino,
    path: &str,
    argv: Vec<String>,
    envp: Vec<String>,
) -> Result<Program, ExecError> {
    let (exe, ino, src, argv) = {
        let mut fs = fs::lock();
        resolve_interpreters(&mut fs, base, path, argv)?
    };
    let bytes = argv.iter().chain(&envp).map(|s| s.len() as u64 + 1).sum();
    let args_charge = crate::kmem::Charge::new(bytes)
        .map_err(|e| exec_error(e, "no kernel memory left for argv and environment".into()))?;
    let mut aspace = AddressSpace::new().ok_or_else(|| exec_error(ENOMEM, "out of memory".into()))?;
    let loaded = elf::load(&mut aspace, &src, ino, Some(elf::DYN_BASE))
        .map_err(|e| exec_error(ENOEXEC, alloc::format!("{exe}: {e}")))?;
    let (entry, interp_base) = match &loaded.interp {
        Some(ipath) => {
            let (isrc, iino) = {
                let mut fs = fs::lock();
                let ino = fs.lookup(p.cwd, ipath, true).map_err(|_| {
                    exec_error(ENOENT, alloc::format!("ELF interpreter {ipath} not found (was it imported?)"))
                })?;
                match &fs.node(ino).kind {
                    Kind::File(c) => (elf::Source::of(c), ino),
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
    aspace.map(Vma::anon(STACK_TOP - STACK_SIZE, STACK_TOP, Prot::RW));
    aspace.map(Vma { start: SIGPAGE, end: SIGPAGE + PAGE_SIZE, prot: Prot::RX, backing: Backing::Sigpage });

    let auxv = [
        (3, loaded.phdr),  // AT_PHDR
        (4, 56),           // AT_PHENT
        (5, loaded.phnum), // AT_PHNUM
        (6, 4096),         // AT_PAGESZ
        (7, interp_base),  // AT_BASE
        (8, 0),            // AT_FLAGS
        (9, loaded.entry), // AT_ENTRY
        (11, p.uid as u64),
        (12, p.uid as u64),
        (13, p.gid as u64),
        (14, p.gid as u64),
        (16, arch::hwcap()), // AT_HWCAP
        (17, 100),           // AT_CLKTCK
        (23, 0),             // AT_SECURE
        (26, 0),             // AT_HWCAP2
    ];
    // The stack is written through the new address space's own mapping.
    aspace.activate();
    let sp = {
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let env: Vec<&str> = envp.iter().map(String::as_str).collect();
        build_stack(&mut aspace, &args, &env, path, &auxv)
    };
    p.aspace.activate();
    let sp = sp.map_err(|e| exec_error(e, alloc::format!("could not build the initial stack (errno {})", e.0)))?;
    Ok(Program { aspace, args_charge, entry, sp, exe, argv, envp })
}

impl Program {
    /// Replace `p`'s image with this program (the point of no return).
    /// Returns where it starts: (entry, sp).
    pub fn install(self, p: &mut Process) -> (u64, u64) {
        let old = core::mem::replace(&mut p.aspace, self.aspace);
        p.aspace.activate();
        drop(old);
        let base = self.exe.rsplit('/').next().unwrap_or(&self.exe).as_bytes();
        p.name = [0; 16];
        p.name[..base.len().min(15)].copy_from_slice(&base[..base.len().min(15)]);
        p.exe = self.exe;
        p.argv = self.argv;
        p.envp = self.envp;
        p.args_charge = self.args_charge;
        (self.entry, self.sp)
    }
}

/// Follow `#!` lines like Linux's binfmt_script: `#!interp [arg]` runs
/// `interp [arg] script args...`. Returns the ELF to load (its path, node
/// and bytes) and the final argv.
fn resolve_interpreters(
    fs: &mut fs::Fs,
    cwd: Ino,
    path: &str,
    mut argv: Vec<String>,
) -> Result<(String, Ino, elf::Source, Vec<String>), ExecError> {
    let mut path = String::from(path);
    for _ in 0..5 {
        let what = if argv.first().is_some_and(|a| *a == path) || argv.is_empty() { "program" } else { "interpreter" };
        let ino = fs
            .lookup(cwd, &path, true)
            .map_err(|e| exec_error(e, alloc::format!("{what} {path} not found (was it imported?)")))?;
        let node = fs.node(ino);
        let src = match &node.kind {
            Kind::File(c) if node.perm & 0o111 != 0 => elf::Source::of(c),
            Kind::File(_) => return Err(exec_error(EACCES, alloc::format!("{what} {path} is not executable"))),
            _ => return Err(exec_error(EACCES, alloc::format!("{what} {path} is not a regular file"))),
        };
        // Linux reads at most this much of the #! line.
        let mut buf = [0u8; 256];
        let n = src.read(0, &mut buf);
        let head = &buf[..n];
        let Some(rest) = head.strip_prefix(b"#!") else { return Ok((fs.path_of(ino), ino, src, argv)) };
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

/// Lay out argc/argv/envp/auxv at the top of the stack as Linux does.
fn build_stack(
    a: &mut AddressSpace,
    argv: &[&str],
    envp: &[&str],
    execfn: &str,
    aux: &[(u64, u64)],
) -> Result<u64, Errno> {
    let total: usize = argv.iter().chain(envp).map(|s| s.len() + 1).sum::<usize>() + execfn.len() + 1;
    if total > 1 << 20 {
        return Err(E2BIG);
    }
    let mut sp = STACK_TOP;
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
    let execfn_ptr = cstr(a, execfn)?;
    let env_ptrs = envp.iter().map(|s| cstr(a, s)).collect::<Result<Vec<_>, _>>()?;
    let arg_ptrs = argv.iter().map(|s| cstr(a, s)).collect::<Result<Vec<_>, _>>()?;
    let platform_ptr = cstr(a, "aarch64")?;
    let mut random = [0u8; 16];
    rng::fill(&mut random);
    let random_ptr = push(a, &random)?;

    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(&arg_ptrs);
    words.push(0);
    words.extend(&env_ptrs);
    words.push(0);
    for &(k, v) in aux.iter().chain(&[(15, platform_ptr), (25, random_ptr), (31, execfn_ptr), (0, 0)]) {
        words.push(k);
        words.push(v);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let sp = (random_ptr - bytes.len() as u64) & !15;
    copy_out(a, sp, &bytes)?;
    Ok(sp)
}
