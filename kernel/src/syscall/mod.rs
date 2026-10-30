//! Linux syscall ABI. Each syscall is checked against the policy before it runs.

pub mod aio;
mod file;
mod mem;
mod misc;
mod net;
mod proc;
pub use proc::shields_init;
mod shm;
mod signal;
mod splice;
pub mod table;
mod thread;
mod timer;
mod tty;
mod unix;
#[cfg(target_arch = "x86_64")]
mod x86;

use grix_abi::policy::Capability;

use crate::arch::TrapFrame;
use crate::errno::*;
use crate::process::{self, Process};
use crate::sched;
use crate::seccomp::Verdict;
use table::{Gate, nr};

/// execve's dirfd for "relative to the working directory".
pub(crate) const AT_FDCWD: i32 = -100;

/// Debug builds only: a call no Linux has, which runs this CPU's kernel
/// stack 1 KiB past its bottom, then returns (its first argument 0) or
/// faults there (1), for the test that either is reported
/// (`kernel_stack_overflow_is_reported`, with fixtures/src/kstack.c). And
/// x86_64's next idle wait starts with the console's vector in service
/// (3, `irq::take_device_beneath`), for
/// `a_device_interrupt_beneath_a_timer_is_not_left_behind`.
#[cfg(debug_assertions)]
const STACK_OVERFLOW_TEST: u64 = 0x6772_6978;

#[cfg(debug_assertions)]
fn overflow_stack(to: u64, fault: bool) -> u64 {
    let frame = core::hint::black_box([to; 64]);
    if (&raw const frame) as u64 > to {
        return overflow_stack(to, fault) ^ frame[63];
    }
    if fault {
        // SAFETY: none; it faults (nothing is mapped at 8), on purpose.
        return unsafe { (8 as *const u64).read_volatile() };
    }
    frame[0]
}

pub fn handle(tf: &mut TrapFrame) {
    crate::stats::syscall();
    let n = tf.syscall_nr();
    let a = tf.syscall_args();
    #[cfg(debug_assertions)]
    if n == STACK_OVERFLOW_TEST {
        if a[0] == 3 {
            #[cfg(target_arch = "x86_64")]
            crate::arch::irq::device_beneath_next_wake(crate::console::irq());
            return;
        }
        let bottom = crate::arch::stack_bottom(crate::smp::me());
        overflow_stack(bottom - 1024, a[0] == 1);
        return;
    }
    let mut guard = process::running().lock();
    let p = guard.as_mut().expect("syscall without a process");
    // A rewound call is running again: no longer something a signal must
    // decide for (see `signal::return_to_user`).
    p.cur().restarting = false;
    // Any other call than the one it waited in: a FIFO open's wait (and
    // its end) is over.
    let call = (tf.pc(), n);
    let t = p.cur();
    t.call = call;
    if t.fifo_wait.as_ref().is_some_and(|w| w.call != call) {
        t.fifo_wait = None;
    }
    // AIO polls whose files are ready complete (into the ring, which only
    // this process's own calls can reach).
    if p.aio.polling() {
        aio::complete_polls(p);
    }
    // A seccomp filter's SECCOMP_RET_TRAP leaves the registers as they
    // were (Linux's syscall_rollback): no result to set.
    let mut trapped = false;
    let result = match u32::try_from(n) {
        Ok(n) => match gate(p, n, a) {
            Err(e) => Err(e),
            Ok(()) => match crate::seccomp::verdict(p, n, a, tf.pc()) {
                Verdict::Allow => dispatch(p, tf, n, a),
                Verdict::Return(r) => r,
                Verdict::Trap => {
                    trapped = true;
                    Ok(0)
                }
                Verdict::KillThread(_) if p.threads.len() > 1 => thread::exit_thread(p, 0),
                Verdict::KillThread(sig) => {
                    let why = if sig == crate::signal::SIGKILL {
                        "killed by seccomp's strict mode"
                    } else {
                        "killed by its seccomp filter (SECCOMP_RET_KILL_THREAD)"
                    };
                    p.kill(sig, 0, tf.pc(), &alloc::format!("{why} at syscall {n}"), true);
                    Err(EBLOCKED)
                }
                Verdict::KillProcess => {
                    let why = alloc::format!("killed by its seccomp filter (SECCOMP_RET_KILL_PROCESS) at syscall {n}");
                    p.kill(crate::signal::SIGSYS, 0, tf.pc(), &why, true);
                    Err(EBLOCKED)
                }
            },
        },
        Err(_) => p.unimplemented(u32::MAX, "unknown", "", ENOSYS),
    };
    // The process ended (exit_group, a fatal signal to itself, a policy
    // kill): it's finished off and something else runs.
    if p.exit_status.is_some() {
        sched::schedule(&mut guard, tf);
        return;
    }
    if result == Err(EBLOCKED) && !crate::signal::interrupt_self(p, tf) {
        // The thread blocked or exited: its return value is set when it wakes.
        // (schedule() saves its registers before waking any I/O waiters.)
        sched::schedule(&mut guard, tf);
        return;
    }
    // (If it was about to block for a deliverable signal, interrupt_self
    // already set x0 or rewound to the svc.)
    if result != Err(EBLOCKED) {
        p.cur().restart_deadline = None;
        p.cur().io_done = 0;
        if !trapped {
            tf.set_return(match result {
                Ok(v) => v,
                Err(e) => (-(e.0 as i64)) as u64,
            });
        }
        crate::signal::syscall_done(p, result == Err(EINTR));
    }
    sched::wake_io_everywhere(p);
    if p.resched {
        sched::schedule(&mut guard, tf);
    } else {
        sched::update_timer(p);
    }
}

/// clone's arguments in arm64's order (flags, stack, parent_tid, tls,
/// child_tid): x86_64 has the last two the other way round.
fn clone_args(a: [u64; 6]) -> [u64; 6] {
    if cfg!(target_arch = "x86_64") { [a[0], a[1], a[2], a[4], a[3], a[5]] } else { a }
}

/// Check a capability needed for a specific use of a syscall (e.g. clone flags).
pub(crate) fn require(p: &mut Process, n: u32, cap: Capability, detail: &str) -> Result<(), Errno> {
    if p.policy.allows(cap) {
        return Ok(());
    }
    let (name, _) = table::info(n);
    p.deny(n, name, cap.name(), detail).map(|_| ())
}

/// The policy's gate for call `n`. It comes before any seccomp filter:
/// what the policy refuses is denied (and reported) whatever the
/// program's filters say.
fn gate(p: &mut Process, n: u32, a: [u64; 6]) -> Result<(), Errno> {
    let (name, gate) = table::info(n);
    match gate {
        Gate::Core => Ok(()),
        Gate::Cap(cap) if p.policy.allows(cap) => Ok(()),
        // A read-only live mount is read-only whatever the policy says.
        Gate::Cap(Capability::FsWrite) if file::read_only_target(p, n, a) => Err(EROFS),
        Gate::Cap(cap) => p.deny(n, name, cap.name(), "").map(|_| ()),
        Gate::Privileged => p.deny(n, name, "privileged", "").map(|_| ()),
    }
}

fn dispatch(p: &mut Process, tf: &mut TrapFrame, n: u32, a: [u64; 6]) -> SysResult {
    let (name, _) = table::info(n);
    #[cfg(target_arch = "x86_64")]
    if let Some(r) = x86::legacy(p, tf, n, a) {
        return r;
    }

    #[allow(non_upper_case_globals)]
    match n {
        // files
        nr::openat => file::openat(p, a[0], a[1], a[2], a[3]),
        nr::openat2 => file::openat2(p, a[0], a[1], a[2], a[3]),
        nr::close => file::close(p, a[0]),
        nr::read => file::read(p, a[0], a[1], a[2]),
        nr::write => file::write(p, a[0], a[1], a[2]),
        nr::readv => file::readv(p, a[0], a[1], a[2]),
        nr::writev => file::writev(p, a[0], a[1], a[2]),
        nr::pread64 => file::pread(p, a[0], a[1], a[2], a[3]),
        nr::pwrite64 => file::pwrite(p, a[0], a[1], a[2], a[3]),
        nr::preadv => file::preadv(p, a[0], a[1], a[2], a[3], false),
        nr::pwritev => file::preadv(p, a[0], a[1], a[2], a[3], true),
        nr::preadv2 => file::preadv2(p, a[0], a[1], a[2], a[3], a[5], false),
        nr::pwritev2 => file::preadv2(p, a[0], a[1], a[2], a[3], a[5], true),
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
        nr::name_to_handle_at => file::name_to_handle_at(p, a[0], a[1], a[4]),
        nr::fstatfs => file::fstatfs(p, a[0], a[1]),
        nr::getxattr | nr::lgetxattr | nr::fgetxattr => file::getxattr(p, n, a[0], a[1], a[2], a[3]),
        nr::listxattr | nr::llistxattr | nr::flistxattr => file::listxattr(p, n, a[0], a[1], a[2]),
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
        nr::mknodat => file::mknodat(p, a[0], a[1], a[2]),
        nr::fchmodat2 => file::fchmodat2(p, a[0], a[1], a[2], a[3]),
        nr::fchown => file::fchown(p, a[0], a[1], a[2]),
        nr::fchownat => file::fchownat(p, a[0], a[1], a[2], a[3], a[4]),
        nr::utimensat => file::utimensat(p, a[0], a[1], a[2], a[3]),
        nr::setxattr | nr::lsetxattr | nr::fsetxattr => file::setxattr(p, n, a[0], a[1], a[2], a[3], a[4]),
        nr::removexattr | nr::lremovexattr | nr::fremovexattr => file::removexattr(p, n, a[0], a[1]),
        nr::sendfile => file::sendfile(p, a[0], a[1], a[2], a[3]),
        nr::splice => splice::splice(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::tee => splice::tee(p, a[0], a[1], a[2], a[3]),
        nr::vmsplice => splice::vmsplice(p, a[0], a[1], a[2], a[3]),
        nr::memfd_create => file::memfd_create(p, a[0], a[1]),
        nr::signalfd4 => file::signalfd4(p, a[0], a[1], a[2], a[3]),
        nr::copy_file_range => file::copy_file_range(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::sync => Ok(0),
        nr::fadvise64 => p.fds.get(a[0]).map(|_| 0),
        nr::flock => file::flock(p, a[0], a[1]),
        nr::io_setup => aio::io_setup(p, a[0], a[1]),
        nr::io_destroy => aio::io_destroy(p, a[0]),
        nr::io_submit => aio::io_submit(p, a[0], a[1], a[2]),
        nr::io_cancel => aio::io_cancel(p, a[0], a[1], a[2]),
        nr::io_getevents => aio::io_getevents(p, a[0], a[1], a[2], a[3], a[4]),
        nr::io_pgetevents => {
            signal::pselect_mask(p, a[5])?;
            aio::io_getevents(p, a[0], a[1], a[2], a[3], a[4])
        }

        // sockets
        nr::socketpair => net::socketpair(p, a[0], a[1], a[2], a[3]),
        nr::sendto => net::sendto(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::recvfrom => net::recvfrom(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::sendmsg => net::sendmsg(p, a[0], a[1], a[2]),
        nr::recvmsg => net::recvmsg(p, a[0], a[1], a[2]),
        nr::sendmmsg => net::sendmmsg(p, a[0], a[1], a[2], a[3]),
        nr::recvmmsg => net::recvmmsg(p, a[0], a[1], a[2], a[3]),
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
        nr::shmget => shm::shmget(p, a[0], a[1], a[2]),
        nr::shmat => shm::shmat(p, a[0], a[1], a[2]),
        nr::shmdt => shm::shmdt(p, a[0]),
        nr::shmctl => shm::shmctl(p, a[0], a[1], a[2]),
        nr::mprotect => mem::mprotect(p, a[0], a[1], a[2]),
        nr::mremap => mem::mremap(p, a[0], a[1], a[2], a[3], a[4]),
        nr::madvise => mem::madvise(p, a[0], a[1], a[2]),
        nr::mbind => mem::mbind(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::set_mempolicy => mem::set_mempolicy(p, a[0], a[1], a[2]),
        nr::get_mempolicy => mem::get_mempolicy(p, a[0], a[1], a[2], a[3], a[4]),
        nr::msync | nr::mlock | nr::munlock | nr::mlock2 | nr::mlockall | nr::munlockall => Ok(0),

        // threads (processes are gated in clone, not implemented yet)
        nr::clone => thread::clone(p, tf, clone_args(a)),
        nr::clone3 => thread::clone3(p, tf, a[0], a[1]),
        nr::unshare => proc::unshare(p, a[0]),
        nr::exit => thread::exit_thread(p, (a[0] & 0xff) as i32),
        nr::exit_group => {
            p.terminate(crate::process::exited((a[0] & 0xff) as i32));
            Err(EBLOCKED)
        }
        nr::futex => thread::futex(p, a),
        nr::futex_waitv => thread::futex_waitv(p, a[0], a[1], a[2], a[3], a[4]),
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
        nr::sigaltstack => signal::sigaltstack(p, tf.sp(), a[0], a[1]),
        nr::kill => signal::kill(p, a[0], a[1]),
        nr::seccomp => crate::seccomp::seccomp(p, a[0], a[1], a[2]),
        nr::landlock_create_ruleset => crate::landlock::create_ruleset(p, a[0], a[1], a[2]),
        nr::landlock_add_rule => crate::landlock::add_rule(p, a[0], a[1], a[2], a[3]),
        nr::landlock_restrict_self => crate::landlock::restrict_self(p, a[0], a[1]),

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
        nr::pidfd_open => proc::pidfd_open(p, a[0], a[1]),
        nr::pidfd_send_signal => signal::pidfd_send_signal(p, a[0], a[1], a[2], a[3]),
        nr::pidfd_getfd => proc::pidfd_getfd(p, a[0], a[1], a[2]),

        // everything else
        _ => misc::dispatch(p, n, name, a),
    }
}
