//! Linux syscall ABI. Each syscall is checked against the policy before it runs.

mod file;
mod mem;
mod misc;
mod net;
pub mod table;
mod thread;

use grix_abi::policy::Capability;

use crate::arch::TrapFrame;
use crate::errno::*;
use crate::process::{PROCESS, Process};
use crate::sched;
use table::{Gate, nr};

pub fn handle(tf: &mut TrapFrame) {
    let n = tf.x[8];
    let a = [tf.x[0], tf.x[1], tf.x[2], tf.x[3], tf.x[4], tf.x[5]];
    let mut guard = PROCESS.lock();
    let p = guard.as_mut().expect("syscall without a process");
    let result = match u32::try_from(n) {
        Ok(n) => dispatch(p, tf, n, a),
        Err(_) => p.unimplemented(u32::MAX, "unknown", "", ENOSYS),
    };
    match result {
        // The thread blocked or exited: its return value is set when it wakes.
        // (schedule() saves its registers before waking any I/O waiters.)
        Err(EBLOCKED) => sched::schedule(p, tf),
        r => {
            p.cur().restart_deadline = None;
            tf.x[0] = match r {
                Ok(v) => v,
                Err(e) => (-(e.0 as i64)) as u64,
            };
            p.wake_io_waiters();
            if p.resched {
                sched::schedule(p, tf);
            } else {
                sched::update_timer(p);
            }
        }
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

fn dispatch(p: &mut Process, tf: &TrapFrame, n: u32, a: [u64; 6]) -> SysResult {
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
        nr::openat => file::openat(p, a[0], a[1], a[2]),
        nr::close => file::close(p, a[0]),
        nr::read => file::read(p, a[0], a[1], a[2]),
        nr::write => file::write(p, a[0], a[1], a[2]),
        nr::readv => file::readv(p, a[0], a[1], a[2]),
        nr::writev => file::writev(p, a[0], a[1], a[2]),
        nr::pread64 => file::pread(p, a[0], a[1], a[2], a[3]),
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
        nr::ppoll => file::ppoll(p, a[0], a[1], a[2]),
        nr::pselect6 => file::pselect6(p, a[0], a[1], a[2], a[3], a[4]),
        nr::pipe2 => file::pipe2(p, a[0], a[1]),
        nr::eventfd2 => file::eventfd2(p, a[0], a[1]),
        nr::epoll_create1 => file::epoll_create1(p, a[0]),
        nr::epoll_ctl => file::epoll_ctl(p, a[0], a[1], a[2], a[3]),
        nr::epoll_pwait => file::epoll_wait(p, a[0], a[1], a[2], file::ms_timeout(a[3])),
        nr::epoll_pwait2 => file::epoll_pwait2(p, a[0], a[1], a[2], a[3]),
        nr::close_range => file::close_range(p, a[0], a[1], a[2]),
        nr::statfs => file::statfs(p, a[0], a[1]),
        nr::fstatfs => file::fstatfs(p, a[0], a[1]),
        nr::getxattr | nr::lgetxattr | nr::fgetxattr => file::xattr_query(p, n, a[0], false),
        nr::listxattr | nr::llistxattr | nr::flistxattr => file::xattr_query(p, n, a[0], true),
        nr::inotify_init1 => file::inotify_init1(p, a[0]),
        nr::inotify_add_watch => file::inotify_add_watch(p, a[0], a[1], a[2]),
        nr::inotify_rm_watch => file::inotify_rm_watch(p, a[0], a[1]),
        nr::fsync | nr::fdatasync => p.fds.get(a[0]).map(|_| 0),
        nr::sync => Ok(0),
        nr::fadvise64 => p.fds.get(a[0]).map(|_| 0),
        nr::flock => p.fds.get(a[0]).map(|_| 0),

        // sockets
        nr::socketpair => net::socketpair(p, a[0], a[1], a[2], a[3]),
        nr::sendto => net::sendto(p, a[0], a[1], a[2], a[3], a[4]),
        nr::recvfrom => net::recvfrom(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::sendmsg => net::sendmsg(p, a[0], a[1], a[2]),
        nr::recvmsg => net::recvmsg(p, a[0], a[1], a[2]),
        nr::getsockopt => net::getsockopt(p, a[0], a[1], a[2], a[3], a[4]),
        nr::setsockopt => net::setsockopt(p, a[0], a[1], a[2]),
        nr::shutdown => net::shutdown(p, a[0], a[1]),
        nr::getsockname | nr::getpeername => net::getname(p, a[0], a[1], a[2]),

        // memory
        nr::brk => mem::brk(p, a[0]),
        nr::mmap => mem::mmap(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::munmap => mem::munmap(p, a[0], a[1]),
        nr::mprotect => mem::mprotect(p, a[0], a[1], a[2]),
        nr::mremap => mem::mremap(p, a[0], a[1], a[2], a[3]),
        nr::madvise => mem::madvise(p, a[0], a[1], a[2]),
        nr::msync | nr::mlock | nr::munlock | nr::mlock2 | nr::mlockall | nr::munlockall => Ok(0),

        // threads (processes are gated in clone, not implemented yet)
        nr::clone => thread::clone(p, tf, a),
        nr::clone3 => thread::clone3(p, tf, a[0], a[1]),
        nr::exit => thread::exit_thread(p, (a[0] & 0xff) as i32),
        nr::exit_group => crate::process::exit((a[0] & 0xff) as i32),
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

        // everything else
        _ => misc::dispatch(p, n, name, a),
    }
}
