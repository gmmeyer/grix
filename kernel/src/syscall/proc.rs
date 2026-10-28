//! Processes: fork/vfork (clone without CLONE_THREAD), execve, wait4/waitid,
//! process groups and sessions. All gated by the `process` capability.

use alloc::string::String;
use alloc::vec::Vec;
use grix_abi::policy::Capability;

use super::thread::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_VFORK, CLONE_VM, CloneArgs,
};
use super::{require, table};
use crate::arch::{self, FpState, TrapFrame};
use crate::errno::*;
use crate::process::{self, JobReport, Process, SigAction, Thread, WaitOn};
use crate::procs::{MAX_PROCESSES, PROCS};
use crate::signal::{self, SIG_IGN, SIGCHLD, SigInfo};
use crate::uaccess::*;

const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_PARENT: u64 = 0x8000;

/// clone without CLONE_THREAD: a new process with a copy-on-write copy of
/// this one's memory, its files, handlers and working directory, and one
/// thread resuming from the same svc with x0 = 0. vfork (CLONE_VFORK, with
/// or without CLONE_VM) is the same copy, with the parent waiting until the
/// child execs or exits: what vfork users rely on works on a copy too, as
/// long as the child only execs or _exits, as POSIX requires.
pub fn fork(p: &mut Process, tf: &TrapFrame, n: u32, args: CloneArgs) -> SysResult {
    let (name, _) = table::info(n);
    let flags = args.flags;
    require(p, n, Capability::Process, "")?;
    let vfork = flags & CLONE_VFORK != 0;
    if flags & CLONE_VM != 0 && !vfork {
        return p.unimplemented(n, name, "CLONE_VM without CLONE_THREAD or CLONE_VFORK", EINVAL);
    }
    for (bit, what) in [
        (CLONE_FILES, "CLONE_FILES without CLONE_THREAD"),
        (CLONE_FS, "CLONE_FS without CLONE_THREAD"),
        (CLONE_SIGHAND, "CLONE_SIGHAND without CLONE_THREAD"),
        (CLONE_PARENT, "CLONE_PARENT"),
        (CLONE_PIDFD, "CLONE_PIDFD"),
    ] {
        if flags & bit != 0 {
            return p.unimplemented(n, name, what, EINVAL);
        }
    }
    let exit_signal = (flags & 0xff) as u32;
    if exit_signal > signal::NSIG {
        return Err(EINVAL);
    }
    let mut procs = PROCS.lock();
    if procs.count() >= MAX_PROCESSES || procs.threads(p) >= process::MAX_THREADS {
        return Err(EAGAIN);
    }
    let pid = process::new_tid();
    if flags & CLONE_PARENT_SETTID != 0 {
        write_u32(&mut p.aspace, args.parent_tid, pid)?;
    }
    let aspace = p.aspace.fork()?;
    let mut c = p.fork(pid, aspace)?;
    c.exit_signal = exit_signal;
    let mut t = Thread::new(pid);
    t.regs = *tf;
    t.regs.x[0] = 0;
    if args.stack != 0 {
        t.regs.sp_el0 = args.stack;
    }
    arch::save_fp(&mut t.fp);
    t.tpidr = if flags & CLONE_SETTLS != 0 { args.tls } else { arch::tpidr() };
    let parent_thread = p.cur();
    t.sigmask = parent_thread.sigmask;
    t.altstack = parent_thread.altstack;
    t.clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 { args.child_tid } else { 0 };
    if flags & CLONE_CHILD_SETTID != 0 {
        // In the child's memory: through its own mapping, unsharing the page.
        c.aspace.activate();
        let r = write_u32(&mut c.aspace, args.child_tid, pid);
        p.aspace.activate();
        r?;
    }
    c.threads.insert(pid, t);
    c.runq.push_back(pid);
    if vfork {
        c.vfork_parent = Some((p.pid, p.current));
    }
    let owner = (c.uid, c.gid);
    procs.others.insert(pid, c);
    p.timer_dirty = true;
    drop(procs);
    {
        let mut fs = crate::fs::lock();
        let cwd = fs.path_of(p.cwd);
        fs.proc_add(pid, owner, &p.exe, &cwd);
    }
    if vfork { p.block(WaitOn::Vfork, None, Ok(pid as u64)) } else { Ok(pid as u64) }
}

/// The most argv + envp may hold (Linux allows a quarter of the stack).
const MAX_ARGS: usize = 1 << 20;

/// Read a NULL-terminated array of strings (argv, envp).
fn read_strings(p: &mut Process, mut ptr: u64, total: &mut usize) -> Result<Vec<String>, Errno> {
    let mut out = Vec::new();
    if ptr == 0 {
        return Ok(out);
    }
    loop {
        let s = read_u64(&mut p.aspace, ptr)?;
        if s == 0 {
            return Ok(out);
        }
        let arg = read_cstr(&mut p.aspace, s, MAX_ARGS).map_err(|e| if e == ENAMETOOLONG { E2BIG } else { e })?;
        *total += arg.len() + 1 + 8;
        if *total > MAX_ARGS {
            return Err(E2BIG);
        }
        out.push(arg);
        ptr += 8;
    }
}

/// execve / execveat: replace the program, keeping the pid, files (but
/// close-on-exec ones), ignored signals, the mask and pending signals.
pub fn execve(
    p: &mut Process,
    tf: &mut TrapFrame,
    dirfd: u64,
    pathp: u64,
    argv: u64,
    envp: u64,
    flags: u64,
) -> SysResult {
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
        return Err(EINVAL);
    }
    let path = read_cstr(&mut p.aspace, pathp, PATH_MAX)?;
    let mut total = 0;
    let argv = read_strings(p, argv, &mut total)?;
    let envp = read_strings(p, envp, &mut total)?;
    let (base, path) = if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        // fexecve: the file open at dirfd.
        let ino = super::file::fd_node(p, dirfd)?;
        (crate::fs::ROOT, crate::fs::lock().path_of(ino))
    } else {
        (super::file::base_of(p, dirfd, &path)?, path)
    };
    let program = match process::load_program(p, base, &path, argv, envp) {
        Ok(program) => program,
        Err(e) => {
            if e.errno == ENOENT {
                p.missing_path(base, &path);
            }
            return Err(e.errno);
        }
    };
    // Other CPUs running threads of this process, in the address space
    // about to go, leave it first (see `smp`); the call then runs again.
    // (A signal meanwhile leaves the process on one CPU until the next
    // execve: slower, not wrong.)
    if !crate::smp::alone() {
        p.exclusive_wanted = true;
        crate::smp::kick_others();
        return p.block_io(None, Err(EINTR));
    }
    p.exclusive_wanted = false;
    // The point of no return.
    let (entry, sp) = program.install(p);
    // As on Linux, the saved ids become the effective ones.
    (p.ids.suid, p.ids.sgid) = (p.uid, p.gid);
    crate::fs::lock().proc_set(p.pid, "exe", &p.exe);
    // The other threads end (Linux's de_thread); this one takes the pid.
    let mut t = p.threads.remove(&p.current).unwrap();
    for (_, other) in core::mem::take(&mut p.threads) {
        p.exited_cpu_ns += other.cpu_ns;
    }
    p.runq.clear();
    p.futexes.clear();
    t.tid = p.pid;
    t.clear_child_tid = 0;
    t.robust_list = 0;
    t.altstack = Default::default();
    t.saved_sigmask = None;
    p.current = p.pid;
    p.threads.insert(p.pid, t);
    for file in p.fds.cloexec_files() {
        super::file::closing(p, &file);
    }
    p.fds.close_on_exec();
    // Handlers point into the old program; ignoring a signal survives exec.
    for act in p.sigactions.iter_mut() {
        if act.handler != SIG_IGN {
            *act = SigAction::default();
        }
    }
    // POSIX timers go; setitimer's survives.
    p.timers.posix.clear();
    crate::timer::resync(p);
    p.timer_dirty = true;
    if let Some((ppid, tid)) = p.vfork_parent.take()
        && let Some(parent) = PROCS.lock().others.get_mut(&ppid)
    {
        parent.wake(tid, Some(p.pid as u64));
    }
    *tf = TrapFrame { elr: entry, sp_el0: sp, ..TrapFrame::default() };
    arch::set_tpidr(0);
    arch::restore_fp(&FpState::default());
    Ok(0)
}

const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
const WEXITED: u64 = 4;
const WCONTINUED: u64 = 8;
const WNOWAIT: u64 = 0x0100_0000;
/// __WNOTHREAD, __WALL, __WCLONE: about threads and clone children, which
/// are all the same here.
const WTHREADS: u64 = 0x2000_0000 | 0x4000_0000 | 0x8000_0000;

/// Which children a wait looks at.
#[derive(Clone, Copy)]
enum Which {
    Any,
    Pid(u32),
    Group(u32),
}

impl Which {
    fn matches(self, pid: u32, pgid: u32) -> bool {
        match self {
            Which::Any => true,
            Which::Pid(p) => pid == p,
            Which::Group(g) => pgid == g,
        }
    }
}

/// A child that `which` matches with something to report: (pid, wait
/// status, cpu ns). Ended children (with WEXITED), then stopped ones
/// (WUNTRACED) and continued ones (WCONTINUED). `reap` removes the zombie,
/// or the report. ECHILD if there is no matching child at all; `None` if
/// none has anything to report.
fn waitable(p: &mut Process, which: Which, options: u64, reap: bool) -> Result<Option<(u32, i32, u64)>, Errno> {
    let mut procs = PROCS.lock();
    let me = p.pid;
    let zombie =
        procs.zombies.iter().find(|(pid, z)| z.ppid == me && which.matches(**pid, z.pgid)).map(|(pid, _)| *pid);
    if let Some(pid) = zombie.filter(|_| options & WEXITED != 0) {
        let z = &procs.zombies[&pid];
        let r = (pid, z.status, z.cpu_ns);
        if reap {
            procs.zombies.remove(&pid);
            p.children_cpu_ns += r.2;
        }
        return Ok(Some(r));
    }
    let mut children = zombie.is_some();
    for q in procs.others.values_mut().filter(|q| q.ppid == me && which.matches(q.pid, q.pgid)) {
        children = true;
        let status = match q.job_report {
            Some(JobReport::Stopped(sig)) if options & WUNTRACED != 0 => 0x7f | (sig as i32) << 8,
            Some(JobReport::Continued) if options & WCONTINUED != 0 => 0xffff,
            _ => continue,
        };
        if reap {
            q.job_report = None;
        }
        return Ok(Some((q.pid, status, 0)));
    }
    if children { Ok(None) } else { Err(ECHILD) }
}

fn block_for_child(p: &mut Process) -> SysResult {
    // A child ending changes I/O state (procs::finalize), so this re-runs.
    let deadline = p.timeout_deadline(None);
    p.block_io(deadline, Ok(0))
}

fn rusage(p: &mut Process, ptr: u64, cpu_ns: u64) -> Result<(), Errno> {
    if ptr == 0 {
        return Ok(());
    }
    let mut b = [0u8; 144];
    b[..8].copy_from_slice(&(cpu_ns / 1_000_000_000).to_le_bytes());
    b[8..16].copy_from_slice(&((cpu_ns % 1_000_000_000) / 1000).to_le_bytes());
    copy_out(&mut p.aspace, ptr, &b)
}

pub fn wait4(p: &mut Process, pid: u64, wstatus: u64, options: u64, ru: u64) -> SysResult {
    if options & !(WNOHANG | WUNTRACED | WCONTINUED | WTHREADS) != 0 {
        return Err(EINVAL);
    }
    let which = match pid as i32 {
        -1 => Which::Any,
        0 => Which::Group(p.pgid),
        pid if pid > 0 => Which::Pid(pid as u32),
        pgid => Which::Group(pgid.unsigned_abs()),
    };
    let options = options | WEXITED;
    // Look first, so a bad pointer leaves the child to wait for again.
    let Some((child, status, cpu)) = waitable(p, which, options, false)? else {
        return if options & WNOHANG != 0 { Ok(0) } else { block_for_child(p) };
    };
    if wstatus != 0 {
        write_u32(&mut p.aspace, wstatus, status as u32)?;
    }
    rusage(p, ru, cpu)?;
    waitable(p, Which::Pid(child), options, true)?;
    Ok(child as u64)
}

pub fn waitid(p: &mut Process, idtype: u64, id: u64, infop: u64, options: u64, ru: u64) -> SysResult {
    const P_ALL: u64 = 0;
    const P_PID: u64 = 1;
    const P_PGID: u64 = 2;
    const P_PIDFD: u64 = 3;
    if options & !(WNOHANG | WUNTRACED | WEXITED | WCONTINUED | WNOWAIT | WTHREADS) != 0
        || options & (WEXITED | WUNTRACED | WCONTINUED) == 0
    {
        return Err(EINVAL);
    }
    let which = match idtype {
        P_ALL => Which::Any,
        P_PID if id as i32 > 0 => Which::Pid(id as u32),
        P_PGID if id == 0 => Which::Group(p.pgid),
        P_PGID if id as i32 > 0 => Which::Group(id as u32),
        P_PIDFD => return p.unimplemented(table::nr::waitid, "waitid", "P_PIDFD", EINVAL),
        _ => return Err(EINVAL),
    };
    let found = waitable(p, which, options, false)?;
    let Some((child, status, cpu)) = found else {
        if options & WNOHANG == 0 {
            return block_for_child(p);
        }
        if infop != 0 {
            zero_out(&mut p.aspace, infop, 128)?;
        }
        return Ok(0);
    };
    if infop != 0 {
        copy_out(&mut p.aspace, infop, &SigInfo::child(SIGCHLD, child, p.uid, status).bytes())?;
    }
    rusage(p, ru, cpu)?;
    if options & WNOWAIT == 0 {
        waitable(p, Which::Pid(child), options, true)?;
    }
    Ok(0)
}

/// getpgid / getsid for `pid` (0 = the caller).
pub fn group_of(p: &mut Process, pid: u64, session: bool) -> SysResult {
    let pid = pid as u32;
    if pid == 0 || pid == p.pid {
        return Ok((if session { p.sid } else { p.pgid }) as u64);
    }
    let procs = PROCS.lock();
    if let Some(q) = procs.others.get(&pid) {
        return Ok((if session { q.sid } else { q.pgid }) as u64);
    }
    match procs.zombies.get(&pid) {
        Some(z) if !session => Ok(z.pgid as u64),
        _ => Err(ESRCH),
    }
}

/// setpgid(pid, pgid): move the caller or one of its children into a
/// process group of its session (a new one named after it, for pgid 0).
pub fn setpgid(p: &mut Process, pid: u64, pgid: u64) -> SysResult {
    let pid = if pid == 0 { p.pid } else { pid as u32 };
    if (pgid as i32) < 0 {
        return Err(EINVAL);
    }
    let pgid = if pgid == 0 { pid } else { pgid as u32 };
    let (my_pid, my_sid) = (p.pid, p.sid);
    let mut procs = PROCS.lock();
    let group_exists = pgid == pid || procs.all(p).any(|q| q.pgid == pgid && q.sid == my_sid);
    let Some(target) = procs.get(p, pid) else { return Err(ESRCH) };
    if target.pid != my_pid && target.ppid != my_pid {
        return Err(ESRCH);
    }
    if target.sid != my_sid || target.sid == target.pid || !group_exists {
        return Err(EPERM);
    }
    target.pgid = pgid;
    Ok(0)
}

/// setsid: a new session and process group, led by the caller (unless it
/// already leads a group).
pub fn setsid(p: &mut Process) -> SysResult {
    let pid = p.pid;
    let mut procs = PROCS.lock();
    if procs.all(p).any(|q| q.pgid == pid) {
        return Err(EPERM);
    }
    p.sid = pid;
    p.pgid = pid;
    p.ctty = None;
    Ok(pid as u64)
}

/// Is `sig`'s disposition in `q` the default? Init ignores signals from
/// other processes it has no handler for, as in a Linux pid namespace.
pub fn shields_init(q: &Process, sender: u32, sig: u32) -> bool {
    q.pid == process::INIT && sender != process::INIT && q.sigactions[sig as usize].handler == signal::SIG_DFL
}
