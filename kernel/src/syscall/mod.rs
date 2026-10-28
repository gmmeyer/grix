//! Linux syscall ABI. Each syscall is checked against the policy before it runs.

mod file;
mod mem;
mod misc;
mod net;
mod proc;
mod signal;
pub mod table;
mod thread;
mod timer;

use grix_abi::policy::Capability;

use crate::arch::TrapFrame;
use crate::errno::*;
use crate::process::{PROCESS, Process};
use crate::sched;
use table::{Gate, nr};

/// execve's dirfd for "relative to the working directory".
const AT_FDCWD: i32 = -100;

pub fn handle(tf: &mut TrapFrame) {
    let n = tf.x[8];
    let a = [tf.x[0], tf.x[1], tf.x[2], tf.x[3], tf.x[4], tf.x[5]];
    let mut guard = PROCESS.lock();
    let p = guard.as_mut().expect("syscall without a process");
    // A rewound call is running again: no longer something a signal must
    // decide for (see `signal::return_to_user`).
    p.cur().restarting = false;
    let result = match u32::try_from(n) {
        Ok(n) => dispatch(p, tf, n, a),
        Err(_) => p.unimplemented(u32::MAX, "unknown", "", ENOSYS),
    };
    // The process ended (exit_group, a fatal signal to itself, a policy
    // kill): it's finished off and something else runs.
    if p.exit_status.is_some() {
        sched::schedule(p, tf);
        return;
    }
    if result == Err(EBLOCKED) && !crate::signal::interrupt_self(p, tf) {
        // The thread blocked or exited: its return value is set when it wakes.
        // (schedule() saves its registers before waking any I/O waiters.)
        sched::schedule(p, tf);
        return;
    }
    // (If it was about to block for a deliverable signal, interrupt_self
    // already set x0 or rewound to the svc.)
    if result != Err(EBLOCKED) {
        p.cur().restart_deadline = None;
        p.cur().io_done = 0;
        tf.x[0] = match result {
            Ok(v) => v,
            Err(e) => (-(e.0 as i64)) as u64,
        };
        crate::signal::syscall_done(p, result == Err(EINTR));
    }
    sched::wake_io_everywhere(p);
    if p.resched {
        sched::schedule(p, tf);
    } else {
        sched::update_timer(p);
    }
}

/// Check a capability needed for a specific use of a syscall (e.g. clone flags).
pub(crate) fn require(p: &mut Process, n: u32, cap: Capability, detail: &str) -> Result<(), Errno> {
    if p.policy.allows(cap) {
        return Ok(());
    }
    let (name, _) = table::info(n);
    p.deny(n, name, cap.name(), detail).map(|_| ())
}

fn dispatch(p: &mut Process, tf: &mut TrapFrame, n: u32, a: [u64; 6]) -> SysResult {
    let (name, gate) = table::info(n);
    match gate {
        Gate::Core => {}
        Gate::Cap(cap) => {
            if !p.policy.allows(cap) {
                return p.deny(n, name, cap.name(), "");
            }
        }
        Gate::Privileged => return p.deny(n, name, "privileged", ""),
    }

    #[allow(non_upper_case_globals)]
    match n {
        // files
        nr::openat => file::openat(p, a[0], a[1], a[2], a[3]),
        nr::close => file::close(p, a[0]),
        nr::read => file::read(p, a[0], a[1], a[2]),
        nr::write => file::write(p, a[0], a[1], a[2]),
        nr::readv => file::readv(p, a[0], a[1], a[2]),
        nr::writev => file::writev(p, a[0], a[1], a[2]),
        nr::pread64 => file::pread(p, a[0], a[1], a[2], a[3]),
        nr::pwrite64 => file::pwrite(p, a[0], a[1], a[2], a[3]),
        nr::preadv => file::preadv(p, a[0], a[1], a[2], a[3], false),
        nr::pwritev => file::preadv(p, a[0], a[1], a[2], a[3], true),
        nr::lseek => file::lseek(p, a[0], a[1], a[2]),
        nr::fstat => file::fstat(p, a[0], a[1]),
        nr::newfstatat => file::newfstatat(p, a[0], a[1], a[2], a[3]),
        nr::statx => file::statx(p, a[0], a[1], a[2], a[4]),
        nr::getdents64 => file::getdents64(p, a[0], a[1], a[2]),
        nr::readlinkat => file::readlinkat(p, a[0], a[1], a[2], a[3]),
        nr::faccessat => file::faccessat(p, a[0], a[1], a[2], 0),
        nr::faccessat2 => file::faccessat(p, a[0], a[1], a[2], a[3]),
        nr::getcwd => file::getcwd(p, a[0], a[1]),
        nr::chdir => file::chdir(p, a[0]),
        nr::fchdir => file::fchdir(p, a[0]),
        nr::dup => file::dup(p, a[0]),
        nr::dup3 => file::dup3(p, a[0], a[1], a[2]),
        nr::fcntl => file::fcntl(p, a[0], a[1], a[2]),
        nr::ioctl => file::ioctl(p, a[0], a[1], a[2]),
        nr::ppoll => {
            signal::wait_mask(p, a[3], a[4])?;
            file::ppoll(p, a[0], a[1], a[2])
        }
        nr::pselect6 => {
            signal::pselect_mask(p, a[5])?;
            file::pselect6(p, a[0], a[1], a[2], a[3], a[4])
        }
        nr::pipe2 => file::pipe2(p, a[0], a[1]),
        nr::eventfd2 => file::eventfd2(p, a[0], a[1]),
        nr::epoll_create1 => file::epoll_create1(p, a[0]),
        nr::epoll_ctl => file::epoll_ctl(p, a[0], a[1], a[2], a[3]),
        nr::epoll_pwait => {
            signal::wait_mask(p, a[4], a[5])?;
            file::epoll_wait(p, a[0], a[1], a[2], file::ms_timeout(a[3]))
        }
        nr::epoll_pwait2 => {
            signal::wait_mask(p, a[4], a[5])?;
            file::epoll_pwait2(p, a[0], a[1], a[2], a[3])
        }
        nr::close_range => file::close_range(p, a[0], a[1], a[2]),
        nr::statfs => file::statfs(p, a[0], a[1]),
        nr::fstatfs => file::fstatfs(p, a[0], a[1]),
        nr::getxattr | nr::lgetxattr | nr::fgetxattr => file::xattr_query(p, n, a[0], false),
        nr::listxattr | nr::llistxattr | nr::flistxattr => file::xattr_query(p, n, a[0], true),
        nr::inotify_init1 => file::inotify_init1(p, a[0]),
        nr::inotify_add_watch => file::inotify_add_watch(p, a[0], a[1], a[2]),
        nr::inotify_rm_watch => file::inotify_rm_watch(p, a[0], a[1]),
        nr::fsync | nr::fdatasync => file::fsync(p, a[0]),
        // changing the tree (gated by fs_write in the table)
        nr::mkdirat => file::mkdirat(p, a[0], a[1], a[2]),
        nr::unlinkat => file::unlinkat(p, a[0], a[1], a[2]),
        nr::renameat => file::renameat2(p, a[0], a[1], a[2], a[3], 0),
        nr::renameat2 => file::renameat2(p, a[0], a[1], a[2], a[3], a[4]),
        nr::linkat => file::linkat(p, a[0], a[1], a[2], a[3], a[4]),
        nr::symlinkat => file::symlinkat(p, a[0], a[1], a[2]),
        nr::truncate => file::truncate(p, a[0], a[1]),
        nr::ftruncate => file::ftruncate(p, a[0], a[1]),
        nr::fallocate => file::fallocate(p, a[0], a[1], a[2], a[3]),
        nr::fchmod => file::fchmod(p, a[0], a[1]),
        nr::fchmodat => file::fchmodat(p, a[0], a[1], a[2]),
        nr::fchown => file::fchown(p, a[0], a[1], a[2]),
        nr::fchownat => file::fchownat(p, a[0], a[1], a[2], a[3], a[4]),
        nr::utimensat => file::utimensat(p, a[0], a[1], a[2], a[3]),
        nr::setxattr | nr::lsetxattr | nr::fsetxattr | nr::removexattr | nr::lremovexattr | nr::fremovexattr => {
            p.unimplemented(n, name, "extended attributes", EOPNOTSUPP)
        }
        nr::sendfile => file::sendfile(p, a[0], a[1], a[2], a[3]),
        nr::memfd_create => file::memfd_create(p, a[0], a[1]),
        nr::signalfd4 => file::signalfd4(p, a[0], a[1], a[2], a[3]),
        nr::copy_file_range => file::copy_file_range(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::sync => Ok(0),
        nr::fadvise64 => p.fds.get(a[0]).map(|_| 0),
        nr::flock => p.fds.get(a[0]).map(|_| 0),

        // sockets
        nr::socketpair => net::socketpair(p, a[0], a[1], a[2], a[3]),
        nr::sendto => net::sendto(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::recvfrom => net::recvfrom(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::sendmsg => net::sendmsg(p, a[0], a[1], a[2]),
        nr::recvmsg => net::recvmsg(p, a[0], a[1], a[2]),
        nr::getsockopt => net::getsockopt(p, a[0], a[1], a[2], a[3], a[4]),
        nr::setsockopt => net::setsockopt(p, a[0], a[1], a[2], a[3], a[4]),
        nr::shutdown => net::shutdown(p, a[0], a[1]),
        nr::getsockname => net::getname(p, a[0], a[1], a[2], false),
        nr::getpeername => net::getname(p, a[0], a[1], a[2], true),
        nr::socket => net::socket(p, a[0], a[1], a[2]),
        nr::bind => net::bind(p, a[0], a[1], a[2]),
        nr::connect => net::connect(p, a[0], a[1], a[2]),
        nr::listen => net::listen(p, a[0], a[1]),
        nr::accept => net::accept4(p, a[0], a[1], a[2], 0),
        nr::accept4 => net::accept4(p, a[0], a[1], a[2], a[3]),

        // memory
        nr::brk => mem::brk(p, a[0]),
        nr::mmap => mem::mmap(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::munmap => mem::munmap(p, a[0], a[1]),
        nr::mprotect => mem::mprotect(p, a[0], a[1], a[2]),
        nr::mremap => mem::mremap(p, a[0], a[1], a[2], a[3], a[4]),
        nr::madvise => mem::madvise(p, a[0], a[1], a[2]),
        nr::msync | nr::mlock | nr::munlock | nr::mlock2 | nr::mlockall | nr::munlockall => Ok(0),

        // threads (processes are gated in clone, not implemented yet)
        nr::clone => thread::clone(p, tf, a),
        nr::clone3 => thread::clone3(p, tf, a[0], a[1]),
        nr::exit => thread::exit_thread(p, (a[0] & 0xff) as i32),
        nr::exit_group => {
            p.terminate(crate::process::exited((a[0] & 0xff) as i32));
            Err(EBLOCKED)
        }
        nr::futex => thread::futex(p, a),
        nr::set_tid_address => thread::set_tid_address(p, a[0]),
        nr::set_robust_list => {
            p.cur().robust_list = a[0];
            Ok(0)
        }
        nr::gettid => Ok(p.current as u64),
        nr::sched_yield => thread::sched_yield(p),
        nr::nanosleep => thread::nanosleep(p, a[0]),
        nr::clock_nanosleep => thread::clock_nanosleep(p, a[0], a[1], a[2]),

        // timers
        nr::getitimer => timer::getitimer(p, a[0], a[1]),
        nr::setitimer => timer::setitimer(p, a[0], a[1], a[2]),
        nr::timer_create => timer::timer_create(p, a[0], a[1], a[2]),
        nr::timer_settime => timer::timer_settime(p, a[0], a[1], a[2], a[3]),
        nr::timer_gettime => timer::timer_gettime(p, a[0], a[1]),
        nr::timer_getoverrun => timer::timer_getoverrun(p, a[0]),
        nr::timer_delete => timer::timer_delete(p, a[0]),
        nr::timerfd_create => timer::timerfd_create(p, a[0], a[1]),
        nr::timerfd_settime => timer::timerfd_settime(p, a[0], a[1], a[2], a[3]),
        nr::timerfd_gettime => timer::timerfd_gettime(p, a[0], a[1]),

        // signals
        nr::rt_sigaction => signal::rt_sigaction(p, a[0], a[1], a[2], a[3]),
        nr::rt_sigprocmask => signal::rt_sigprocmask(p, a[0], a[1], a[2], a[3]),
        nr::rt_sigpending => signal::rt_sigpending(p, a[0], a[1]),
        nr::rt_sigsuspend => signal::rt_sigsuspend(p, a[0], a[1]),
        nr::rt_sigtimedwait => signal::rt_sigtimedwait(p, a[0], a[1], a[2], a[3]),
        nr::rt_sigqueueinfo => signal::rt_sigqueueinfo(p, a[0], None, a[1], a[2]),
        nr::rt_tgsigqueueinfo => signal::rt_sigqueueinfo(p, a[0], Some(a[1]), a[2], a[3]),
        nr::rt_sigreturn => crate::signal::sigreturn(p, tf),
        nr::sigaltstack => signal::sigaltstack(p, tf.sp_el0, a[0], a[1]),
        nr::kill => signal::kill(p, a[0], a[1]),

        // processes
        nr::execve => proc::execve(p, tf, AT_FDCWD as u64, a[0], a[1], a[2], 0),
        nr::execveat => proc::execve(p, tf, a[0], a[1], a[2], a[3], a[4]),
        nr::wait4 => proc::wait4(p, a[0], a[1], a[2], a[3]),
        nr::waitid => proc::waitid(p, a[0], a[1], a[2], a[3], a[4]),
        nr::getpid => Ok(p.pid as u64),
        nr::getppid => Ok(p.ppid as u64),
        nr::getpgid => proc::group_of(p, a[0], false),
        nr::getsid => proc::group_of(p, a[0], true),
        nr::setpgid => proc::setpgid(p, a[0], a[1]),
        nr::setsid => proc::setsid(p),
        nr::tkill => signal::tgkill(p, None, a[0], a[1]),
        nr::tgkill => signal::tgkill(p, Some(a[0]), a[1], a[2]),

        // everything else
        _ => misc::dispatch(p, n, name, a),
    }
}
