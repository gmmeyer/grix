//! Processes: fork/vfork (clone without CLONE_THREAD), execve, wait4/waitid,
//! process groups and sessions. All gated by the `process` capability.

use alloc::string::String;
use alloc::vec::Vec;
use grix_abi::policy::Capability;
use grix_abi::stats::{Limit, Resource};

use super::thread::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_CLEAR_SIGHAND, CLONE_NAMESPACES, CLONE_NEWTIME, CLONE_PARENT,
    CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VFORK, CLONE_VM, CloneArgs,
};
use super::{require, table};
use crate::arch::{self, FpState, TrapFrame};
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, O_NONBLOCK, O_RDWR, new_file};
use crate::process::{self, JobReport, Process, Share, SigAction, Thread, WaitOn};
use crate::procs::{MAX_PROCESSES, PROCS};
use crate::signal::{self, SIG_IGN, SIGCHLD, SigInfo};
use crate::uaccess::*;

const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_SYSVSEM: u64 = 0x4_0000;

/// clone without CLONE_THREAD: a new process with a copy-on-write copy of
/// this one's memory, its files, handlers and working directory, and one
/// thread resuming from the same svc with x0 = 0. vfork (CLONE_VFORK, with
/// or without CLONE_VM) is the same copy, with the parent waiting until the
/// child execs or exits: what vfork users rely on works on a copy too, as
/// long as the child only execs or _exits, as POSIX requires.
///
/// The descriptor table (CLONE_FILES), working directory and umask
/// (CLONE_FS) and signal actions (CLONE_SIGHAND, which Linux allows only
/// with CLONE_VM, so here only for vfork) are shared instead of copied
/// when asked. With CLONE_PARENT the child is the caller's parent's, and
/// tells it of its end as the caller would (Linux's copy_process).
pub fn fork(p: &mut Process, tf: &TrapFrame, n: u32, args: CloneArgs) -> SysResult {
    let (name, _) = table::info(n);
    let flags = args.flags;
    require(p, n, Capability::Process, "")?;
    let vfork = flags & CLONE_VFORK != 0;
    // Shared handlers imply shared memory (copy_process).
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(EINVAL);
    }
    if flags & CLONE_VM != 0 && !vfork {
        return p.unimplemented(n, name, "CLONE_VM without CLONE_THREAD or CLONE_VFORK", EINVAL);
    }
    let exit_signal = (flags & 0xff) as u32;
    if exit_signal > signal::NSIG {
        return Err(EINVAL);
    }
    let mut procs = PROCS.lock();
    let (count, threads) = (procs.count(), crate::procs::threads());
    if count >= MAX_PROCESSES || threads >= process::threads_max() {
        crate::stats::hit(if count >= MAX_PROCESSES { Limit::Processes } else { Limit::Threads });
        return Err(EAGAIN);
    }
    let charge = crate::kmem::Charge::new(process::THREAD_COST).map_err(|_| EAGAIN)?;
    let pid = process::new_tid();
    if flags & CLONE_PARENT_SETTID != 0 {
        write_u32(&mut p.aspace, args.parent_tid, pid)?;
    }
    let aspace = p.aspace.fork()?;
    let share =
        Share { files: flags & CLONE_FILES != 0, fs: flags & CLONE_FS != 0, sighand: flags & CLONE_SIGHAND != 0 };
    let mut c = p.fork(pid, aspace, share)?;
    // Named as the thread that forked it.
    c.name = p.thread_name(p.current);
    if flags & CLONE_CLEAR_SIGHAND != 0 {
        // clone3: handled signals start out default in the child (ignored
        // ones stay ignored), as after an exec.
        c.sigactions.update(reset_handlers);
    }
    if flags & CLONE_PARENT != 0 {
        c.ppid = p.ppid;
        c.exit_signal = p.exit_signal;
    } else {
        c.exit_signal = exit_signal;
    }
    // The parent's pidfd for the child, made after the child's copy of the
    // descriptors (it has none, unless it shares the table).
    let pidfd = if flags & CLONE_PIDFD != 0 {
        let fd = new_pidfd(p, pid, false)?;
        if let Err(e) = write_u32(&mut p.aspace, args.pidfd, fd as u32) {
            let _ = p.fds.close(fd);
            return Err(e);
        }
        Some(fd)
    } else {
        None
    };
    let mut t = Thread::new(pid);
    t.charge = charge;
    t.regs = *tf;
    t.regs.set_return(0);
    if args.stack != 0 {
        t.regs.set_sp(args.stack);
    }
    arch::save_fp(&mut t.fp);
    t.tls = if flags & CLONE_SETTLS != 0 { args.tls } else { arch::tls() };
    let parent_thread = p.cur();
    t.sigmask = parent_thread.sigmask;
    t.altstack = parent_thread.altstack;
    t.seccomp = parent_thread.seccomp.clone();
    t.landlock = parent_thread.landlock.clone();
    t.mempolicy = parent_thread.mempolicy;
    c.landlocked = t.landlock.is_some();
    t.clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 { args.child_tid } else { 0 };
    if flags & CLONE_CHILD_SETTID != 0 {
        // In the child's memory: through its own mapping, unsharing the page.
        c.aspace.activate();
        let r = write_u32(&mut c.aspace, args.child_tid, pid);
        p.aspace.activate();
        if let Err(e) = r {
            if let Some(fd) = pidfd {
                let _ = p.fds.close(fd);
            }
            return Err(e);
        }
    }
    c.threads.insert(pid, t);
    c.runq.push_back(pid);
    if vfork {
        c.vfork_parent = Some((p.pid, p.current));
    }
    let owner = (c.uid, c.gid);
    procs.others.insert(pid, alloc::boxed::Box::new(c));
    crate::procs::born();
    crate::stats::forked();
    crate::stats::peak(Resource::Processes, count as u64 + 1);
    crate::stats::peak(Resource::Threads, threads as u64 + 1);
    p.timer_dirty = true;
    drop(procs);
    {
        let mut fs = crate::fs::lock();
        let cwd = fs.path_of(p.cwd());
        fs.proc_add(pid, owner, &p.exe, &cwd);
    }
    if vfork { p.block(WaitOn::Vfork, None, Ok(pid as u64)) } else { Ok(pid as u64) }
}

/// Every action but ignoring goes back to the default (Linux's
/// flush_signal_handlers).
fn reset_handlers(acts: &mut process::SigActions) {
    for act in acts.iter_mut() {
        if act.handler != SIG_IGN {
            *act = SigAction::default();
        }
    }
}

/// unshare(flags): stop sharing what clone shared. A descriptor table
/// (CLONE_FILES) and working directory (CLONE_FS) become copies of the
/// process's own. The rest Linux allows only when there's nothing to
/// unshare (one thread, signal actions not shared), and does nothing
/// then; there are no System V semaphores, so no undo list to drop
/// (CLONE_SYSVSEM). New namespaces are refused, and a thread can't have a
/// table or directory apart from the other threads (reported).
pub fn unshare(p: &mut Process, flags: u64) -> SysResult {
    let namespaces = CLONE_NAMESPACES | CLONE_NEWTIME;
    let known = CLONE_THREAD | CLONE_FS | CLONE_SIGHAND | CLONE_VM | CLONE_FILES | CLONE_SYSVSEM | namespaces;
    if flags & !known != 0 {
        return Err(EINVAL);
    }
    // What each implies (ksys_unshare); CLONE_NEWUSER and CLONE_NEWNS
    // imply more, but are refused anyway.
    let mut flags = flags;
    if flags & CLONE_VM != 0 {
        flags |= CLONE_SIGHAND;
    }
    if flags & CLONE_SIGHAND != 0 {
        flags |= CLONE_THREAD;
    }
    // check_unshare_flags.
    if flags & CLONE_THREAD != 0 && p.threads.len() > 1 {
        return Err(EINVAL);
    }
    if flags & CLONE_SIGHAND != 0 && p.sigactions.shared() {
        return Err(EINVAL);
    }
    let (name, _) = table::info(table::nr::unshare);
    if flags & namespaces != 0 {
        let detail = super::thread::namespaces_denied(flags & namespaces);
        return p.deny(table::nr::unshare, name, "privileged", &detail);
    }
    // On Linux that gives the calling thread a table or directory of its
    // own; here threads share their process's.
    if flags & (CLONE_FS | CLONE_FILES) != 0 && p.threads.len() > 1 {
        let what = "CLONE_FILES or CLONE_FS with more threads (one thread's own)";
        return p.unimplemented(table::nr::unshare, name, what, EINVAL);
    }
    // The table's copy may fail (ENOMEM): first, so a failure changes nothing.
    if flags & CLONE_FILES != 0 {
        p.fds.unshare()?;
    }
    if flags & CLONE_FS != 0 {
        p.fs.unshare();
    }
    Ok(0)
}

/// The most argv + envp may hold (Linux allows a quarter of the stack).
const MAX_ARGS: usize = 1 << 20;

/// Read a NULL-terminated array of strings (argv, envp).
fn read_strings(
    p: &mut Process,
    mut ptr: u64,
    total: &mut usize,
    held: &mut crate::kmem::Charge,
) -> Result<Vec<String>, Errno> {
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
        // Megabytes of small strings, before `load_program` charges them.
        held.resize(held.bytes() + arg.len() as u64 + process::ARG_OVERHEAD)?;
        out.try_reserve(1).map_err(|_| ENOMEM)?;
        out.push(arg);
        ptr += 8;
    }
}

/// The file open at `fd`, O_PATH or not, for execveat: EACCES for what
/// isn't a regular file, as do_open_execat.
fn open_program(p: &Process, fd: u64) -> Result<process::Start, Errno> {
    if fd as i32 == crate::syscall::AT_FDCWD {
        return Err(EACCES);
    }
    let file = p.fds.get_raw(fd)?;
    let f = file.lock();
    match (&f.kind, &f.content) {
        (FileKind::Node(ino), Some(content)) => {
            // A script's interpreter couldn't get at the file (Linux's
            // BINPRM_FLAGS_PATH_INACCESSIBLE).
            let reachable = !p.fds.cloexec(fd)?;
            Ok(process::Start::File { ino: *ino, content: content.clone(), cwd: p.cwd(), reachable })
        }
        _ => Err(EACCES),
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
    let mut held = crate::kmem::Charge::default();
    let argv = read_strings(p, argv, &mut total, &mut held)?;
    let envp = read_strings(p, envp, &mut total, &mut held)?;
    let program = if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        // fexecve: the file open at dirfd, whatever its name leads to now.
        // Scripts get to their own text by /dev/fd/N (Linux's name for it).
        let start = open_program(p, dirfd)?;
        process::load_program(p, start, &alloc::format!("/dev/fd/{}", dirfd as i32), argv, envp).map_err(|e| e.errno)?
    } else {
        let base = super::file::base_of(p, dirfd, &path)?;
        // O_NOFOLLOW's ELOOP, as do_open_execat.
        let link =
            |fs: &mut crate::fs::Fs| fs.lookup(base, &path, false).is_ok_and(|ino| fs.link_target(ino) != Err(EINVAL));
        if flags & AT_SYMLINK_NOFOLLOW != 0 && link(&mut crate::fs::lock()) {
            return Err(ELOOP);
        }
        process::load_program(p, process::Start::Path(base), &path, argv, envp).map_err(|e| {
            if e.errno == ENOENT {
                p.missing_path(base, &path);
            }
            e.errno
        })?
    };
    // Other CPUs running threads of this process, in the address space
    // about to go, leave it first (see `smp`); the call then runs again.
    // (A signal meanwhile leaves the process on one CPU until the next
    // execve: slower, not wrong.)
    if !crate::smp::alone(p.pid) {
        p.exclusive_wanted = true;
        crate::smp::kick_others(p.pid);
        return p.block_io(None, Err(EINTR));
    }
    p.exclusive_wanted = false;
    // A descriptor table shared with another process (CLONE_FILES) becomes
    // this one's own below: copied now, while failing (ENOMEM) still
    // leaves the caller running.
    let own_fds = if p.fds.shared() { Some(p.fds.copy()?) } else { None };
    // The point of no return.
    let (entry, sp) = program.install(p);
    // As on Linux, the saved ids become the effective ones.
    (p.ids.suid, p.ids.sgid) = (p.uid, p.gid);
    crate::fs::lock().proc_set(p.pid, "exe", &p.exe);
    // The other threads end (Linux's de_thread); this one takes the pid.
    let mut t = p.threads.remove(&p.current).unwrap();
    crate::procs::threads_gone(p.threads.len());
    for (_, other) in core::mem::take(&mut p.threads) {
        p.exited_cpu_ns += other.cpu_ns;
    }
    p.runq.clear();
    p.futexes.clear();
    // AIO contexts belong to the old address space (Linux's exit_aio).
    p.aio = Default::default();
    t.tid = p.pid;
    crate::fs::tasks_reset(p.pid, p.pid);
    // The process's name is the program's now (`install`).
    t.name = [0; 16];
    t.clear_child_tid = 0;
    t.robust_list = 0;
    t.altstack = Default::default();
    t.saved_sigmask = None;
    p.current = p.pid;
    p.threads.insert(p.pid, t);
    // A descriptor table or signal actions shared with another process
    // (CLONE_FILES, CLONE_SIGHAND) become this one's own first, as Linux's
    // exec unshares them (unshare_files, de_thread). A working directory
    // shared by CLONE_FS stays shared.
    if let Some(fds) = own_fds {
        p.fds = fds;
    }
    p.sigactions.unshare();
    for file in p.fds.cloexec_files() {
        super::file::closing(p, &file);
    }
    p.fds.close_on_exec();
    // Handlers point into the old program; ignoring a signal survives exec.
    p.sigactions.update(reset_handlers);
    // POSIX timers go; setitimer's survives.
    p.timers.posix.clear();
    crate::timer::resync(p);
    p.timer_dirty = true;
    if let Some((ppid, tid)) = p.vfork_parent.take()
        && let Some(parent) = PROCS.lock().other_mut(ppid)
    {
        parent.wake(tid, Some(p.pid as u64));
    }
    *tf = TrapFrame::new_user(entry, sp);
    arch::set_tls(0);
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
            crate::fs::proc_gone(pid);
            p.children_cpu_ns += r.2;
        }
        return Ok(Some(r));
    }
    let mut children = zombie.is_some();
    for q in procs.others_mut().filter(|q| q.ppid == me && which.matches(q.pid, q.pgid)) {
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
        P_PIDFD => Which::Pid(pidfd_pid(p, id)?),
        _ => return Err(EINVAL),
    };
    let found = waitable(p, which, options, false)?;
    let Some((child, status, cpu)) = found else {
        // A non-blocking pidfd doesn't wait (Linux 5.10).
        let nonblocking = idtype == P_PIDFD && p.fds.get(id)?.lock().nonblocking();
        if options & WNOHANG == 0 && nonblocking {
            return Err(EAGAIN);
        }
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

/// A new pidfd for process `pid`, close-on-exec as on Linux.
fn new_pidfd(p: &mut Process, pid: u32, nonblock: bool) -> SysResult {
    let file = new_file(FileKind::PidFd(pid), O_RDWR | if nonblock { O_NONBLOCK } else { 0 });
    p.fds.alloc(FdEntry { file, cloexec: true }, 0)
}

/// The process a pidfd refers to.
pub(super) fn pidfd_pid(p: &Process, fd: u64) -> Result<u32, Errno> {
    match p.fds.get(fd)?.lock().kind {
        FileKind::PidFd(pid) => Ok(pid),
        _ => Err(EINVAL),
    }
}

/// pidfd_open(pid, flags): a pidfd for a process (or zombie).
pub fn pidfd_open(p: &mut Process, pid: u64, flags: u64) -> SysResult {
    if flags & !(O_NONBLOCK as u64) != 0 || pid as i32 <= 0 {
        return Err(EINVAL);
    }
    let pid = pid as u32;
    let exists = pid == p.pid || {
        let procs = PROCS.lock();
        procs.others.contains_key(&pid) || procs.zombies.contains_key(&pid)
    };
    if !exists {
        return Err(ESRCH);
    }
    new_pidfd(p, pid, flags & O_NONBLOCK as u64 != 0)
}

/// pidfd_getfd(pidfd, fd, flags): a copy of another process's descriptor
/// (as SCM_RIGHTS would give it), for a caller ptrace would let attach.
pub fn pidfd_getfd(p: &mut Process, pidfd: u64, fd: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(EINVAL);
    }
    let pid = pidfd_pid(p, pidfd)?;
    let file = if pid == p.pid {
        p.fds.get_raw(fd)?
    } else {
        let procs = PROCS.lock();
        let q = procs.others.get(&pid).ok_or(ESRCH)?;
        if !crate::procs::may_inspect(p, q, true) {
            return Err(EPERM);
        }
        q.fds.get_raw(fd)?
    };
    p.fds.alloc(FdEntry { file, cloexec: true }, 0)
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
    let z = procs.zombies.get(&pid).ok_or(ESRCH)?;
    Ok((if session { z.sid } else { z.pgid }) as u64)
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
    q.pid == process::INIT && sender != process::INIT && q.action(sig).handler == signal::SIG_DFL
}
