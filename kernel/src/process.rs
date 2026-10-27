//! The single process this kernel runs: its threads, exec, faults,
//! termination, and reporting of denied/unimplemented operations.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
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

pub const PID: u64 = 1;
/// Linux defaults to a much higher limit; this bounds kernel memory per sandbox.
pub const MAX_THREADS: usize = 1024;

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
            cpu_ns: 0,
        }
    }
}

pub struct Process {
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
    reported: BTreeSet<(u8, u32, String)>,
    /// The running program (after `#!` resolution), its argv and environment.
    pub exe: String,
    pub argv: Vec<String>,
    pub envp: Vec<String>,

    // Threads and scheduling (see sched.rs).
    pub threads: BTreeMap<u32, Thread>,
    /// The running thread. Its live state is in the CPU, not in `threads`.
    pub current: u32,
    /// Runnable threads other than `current`, in round-robin order.
    pub runq: VecDeque<u32>,
    /// Futex wait queues: address -> (tid, bitset) in FIFO order.
    pub futexes: BTreeMap<u64, VecDeque<(u32, u32)>>,
    pub next_tid: u32,
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

const MAX_REPORTS: usize = 512;
const RLIM_INFINITY: u64 = u64::MAX;

impl Process {
    fn new(policy: Policy, uid: u32, gid: u32) -> Self {
        let mut rlimits = [(RLIM_INFINITY, RLIM_INFINITY); 16];
        rlimits[3] = (STACK_SIZE, RLIM_INFINITY); // RLIMIT_STACK
        rlimits[4] = (0, 0); // RLIMIT_CORE
        rlimits[7] = (crate::fd::MAX_FDS as u64, crate::fd::MAX_FDS as u64); // RLIMIT_NOFILE
        Process {
            aspace: AddressSpace::new().expect("out of memory"),
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
            reported: BTreeSet::new(),
            exe: String::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            threads: BTreeMap::from([(PID as u32, Thread::new(PID as u32))]),
            current: PID as u32,
            runq: VecDeque::new(),
            futexes: BTreeMap::new(),
            next_tid: PID as u32 + 1,
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

    /// CPU time used by thread `tid` so far (ns). The running thread has
    /// been on the CPU since `slice_start`.
    pub fn thread_cpu_ns(&self, tid: u32) -> Option<u64> {
        let t = self.threads.get(&tid)?;
        let running =
            if tid == self.current { crate::time::monotonic_ns().saturating_sub(self.slice_start) } else { 0 };
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
    pub fn wake_io_waiters(&mut self) {
        let version = crate::ipc::generation();
        if version == self.io_seen {
            return;
        }
        self.io_seen = version;
        let waiting: Vec<u32> =
            self.threads.values().filter(|t| t.wait.is_some_and(|w| w.on == WaitOn::Io)).map(|t| t.tid).collect();
        for tid in waiting {
            let t = self.threads.get_mut(&tid).unwrap();
            t.wait = None;
            // Re-execute the svc: x0..x7 still hold the original arguments.
            t.regs.elr -= 4;
            t.restarting = true;
            self.runq.push_back(tid);
            self.timer_dirty = true;
        }
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
        self.reported.len() < MAX_REPORTS && self.reported.insert((kind, nr, detail.into()))
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
                exit_signaled(signal::SIGSYS, 0, 0, &msg)
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

/// Exit the program normally.
pub fn exit(code: i32) -> ! {
    console::exit(ExitKind::Exited, code)
}

/// Terminate the program with a signal and report why.
pub fn exit_signaled(signal: u32, addr: u64, pc: u64, detail: &str) -> ! {
    console::event(&Event::Fault { signal, addr, pc, detail });
    console::exit(ExitKind::Signaled, signal as i32)
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
        Err(FaultError::OutOfMemory) => exit_signaled(signal::SIGKILL, far, tf.elr, "out of memory"),
    }
}

/// Load the image's program and jump to it.
pub fn start(img: Image<'static>) -> ! {
    let fail = |code: i32, reason: &str| -> ! {
        console::event(&Event::ExecFailed { path: img.exe, reason });
        klog!("exec {}: {}\n", img.exe, reason);
        exit(code)
    };
    let mut fs = fs::Fs::build(&img.entries, img.uid, img.gid);
    let cwd = match fs.lookup(ROOT, img.cwd, true) {
        Ok(ino) if fs.is_dir(ino) => ino,
        _ => fail(127, &alloc::format!("working directory {} does not exist", img.cwd)),
    };
    let argv = img.argv.iter().map(|s| String::from(*s)).collect();
    let (exe, argv) = match resolve_interpreters(&fs, cwd, img.exe, argv) {
        Ok(r) => r,
        Err((code, reason)) => fail(code, &reason),
    };
    fs.set_exe(&exe);
    fs::install(fs);
    // Like tmpfs's default size: half of RAM for written file data.
    fs::set_limit(crate::mm::frame::stats().0 / 2);

    let mut p = Process::new(img.policy, img.uid, img.gid);
    p.cwd = cwd;
    p.cwd_pin = Some(fs::lock().pin(cwd));
    p.argv = argv;
    p.envp = img.envp.iter().map(|s| String::from(*s)).collect();
    p.exe = exe;
    p.aspace.activate();
    match exec(&mut p, img.exe) {
        Ok((entry, sp)) => {
            p.slice_start = crate::time::monotonic_ns();
            *PROCESS.lock() = Some(p);
            arch::irq::init();
            arch::enter_user(entry, sp)
        }
        Err((code, reason)) => fail(code, &reason),
    }
}

/// Follow `#!` lines like Linux's binfmt_script: `#!interp [arg]` runs
/// `interp [arg] script args...`. Returns the ELF to load and the final argv.
fn resolve_interpreters(
    fs: &fs::Fs,
    cwd: Ino,
    path: &str,
    mut argv: Vec<String>,
) -> Result<(String, Vec<String>), (i32, String)> {
    let mut path = String::from(path);
    for _ in 0..5 {
        let what = if argv.first().is_some_and(|a| *a == path) || argv.is_empty() { "program" } else { "interpreter" };
        let ino = fs
            .lookup(cwd, &path, true)
            .map_err(|_| (127, alloc::format!("{what} {path} not found (was it imported?)")))?;
        let node = fs.node(ino);
        let data = match &node.kind {
            Kind::File(c) if node.perm & 0o111 != 0 => image_of(c, path.as_str())?,
            Kind::File(_) => return Err((126, alloc::format!("{what} {path} is not executable"))),
            _ => return Err((126, alloc::format!("{what} {path} is not a regular file"))),
        };
        let Some(rest) = data.strip_prefix(b"#!") else { return Ok((fs.path_of(ino), argv)) };
        // Linux reads at most this much of the #! line.
        let line = rest.split(|&b| b == b'\n').next().unwrap_or(rest);
        let line = core::str::from_utf8(&line[..line.len().min(254)])
            .map_err(|_| (126, alloc::format!("{path}: invalid #! line")))?
            .trim();
        let (interp, arg) = match line.split_once([' ', '\t']) {
            Some((i, a)) => (i, Some(a.trim()).filter(|a| !a.is_empty())),
            None => (line, None),
        };
        if interp.is_empty() {
            return Err((126, alloc::format!("{path}: empty #! line")));
        }
        let mut next = alloc::vec![String::from(interp)];
        next.extend(arg.map(String::from));
        next.push(path.clone());
        next.extend(argv.into_iter().skip(1));
        argv = next;
        path = String::from(interp);
    }
    Err((126, alloc::format!("{path}: too many levels of #! interpreters")))
}

/// The bytes of a file to execute. Programs run straight from the boot
/// image; a file the program wrote can't be executed yet (that comes with execve).
fn image_of(c: &fs::Content, path: &str) -> Result<&'static [u8], (i32, String)> {
    c.lock().image().ok_or_else(|| (126, alloc::format!("{path} was modified in the sandbox and can't be executed")))
}

/// Load `p.exe` (already resolved by `resolve_interpreters`) and build the
/// initial stack. `execfn` is the path originally asked for (AT_EXECFN).
fn exec(p: &mut Process, execfn: &str) -> Result<(u64, u64), (i32, String)> {
    let fs = fs::lock();
    let file = |path: &str, what: &str| -> Result<(&'static [u8], Ino), (i32, String)> {
        let ino = fs
            .lookup(p.cwd, path, true)
            .map_err(|_| (127, alloc::format!("{what} {path} not found (was it imported?)")))?;
        match &fs.node(ino).kind {
            Kind::File(c) => Ok((image_of(c, path)?, ino)),
            _ => Err((126, alloc::format!("{what} {path} is not a regular file"))),
        }
    };

    let (data, ino) = file(&p.exe, "program")?;
    let exe = elf::load(&mut p.aspace, data, ino, Some(elf::DYN_BASE))
        .map_err(|e| (126, alloc::format!("{}: {e}", p.exe)))?;
    let (entry, interp_base) = match exe.interp {
        Some(path) => {
            let (idata, iino) = file(path, "ELF interpreter")?;
            let interp =
                elf::load(&mut p.aspace, idata, iino, None).map_err(|e| (126, alloc::format!("{path}: {e}")))?;
            if interp.interp.is_some() {
                return Err((126, "ELF interpreter requests its own interpreter".into()));
            }
            (interp.entry, interp.base)
        }
        None => (exe.entry, 0),
    };

    p.aspace.brk_start = exe.end;
    p.aspace.brk = exe.end;
    p.aspace.map(Vma::anon(STACK_TOP - STACK_SIZE, STACK_TOP, Prot::RW));
    p.aspace.map(Vma { start: SIGPAGE, end: SIGPAGE + PAGE_SIZE, prot: Prot::RX, backing: Backing::Sigpage });

    let auxv = [
        (3, exe.phdr),    // AT_PHDR
        (4, 56),          // AT_PHENT
        (5, exe.phnum),   // AT_PHNUM
        (6, 4096),        // AT_PAGESZ
        (7, interp_base), // AT_BASE
        (8, 0),           // AT_FLAGS
        (9, exe.entry),   // AT_ENTRY
        (11, p.uid as u64),
        (12, p.uid as u64),
        (13, p.gid as u64),
        (14, p.gid as u64),
        (16, arch::hwcap()), // AT_HWCAP
        (17, 100),           // AT_CLKTCK
        (23, 0),             // AT_SECURE
        (26, 0),             // AT_HWCAP2
    ];
    let argv: Vec<&str> = p.argv.iter().map(String::as_str).collect();
    let envp: Vec<&str> = p.envp.iter().map(String::as_str).collect();
    let sp = build_stack(&mut p.aspace, &argv, &envp, execfn, &auxv)
        .map_err(|e| (126, alloc::format!("could not build initial stack (errno {})", e.0)))?;
    Ok((entry, sp))
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
