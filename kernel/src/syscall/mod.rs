//! Linux syscall ABI. Each syscall is checked against the policy before it runs.

mod file;
mod mem;
mod misc;
pub mod table;

use agentbox_abi::policy::Capability;

use crate::arch::TrapFrame;
use crate::errno::*;
use crate::process::{PROCESS, Process};
use table::{Gate, nr};

pub fn handle(tf: &mut TrapFrame) {
    let n = tf.x[8];
    let a = [tf.x[0], tf.x[1], tf.x[2], tf.x[3], tf.x[4], tf.x[5]];
    let mut guard = PROCESS.lock();
    let p = guard.as_mut().expect("syscall without a process");
    let result = match u32::try_from(n) {
        Ok(n) => dispatch(p, n, a),
        Err(_) => p.unimplemented(u32::MAX, "unknown", "", ENOSYS),
    };
    tf.x[0] = match result {
        Ok(v) => v,
        Err(e) => (-(e.0 as i64)) as u64,
    };
}

/// Check a capability needed for a specific use of a syscall (e.g. clone flags).
pub(crate) fn require(p: &mut Process, n: u32, cap: Capability, detail: &str) -> Result<(), Errno> {
    if p.policy.allows(cap) {
        return Ok(());
    }
    let (name, _) = table::info(n);
    p.deny(n, name, cap.name(), detail).map(|_| ())
}

fn dispatch(p: &mut Process, n: u32, a: [u64; 6]) -> SysResult {
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
        nr::close_range => file::close_range(p, a[0], a[1], a[2]),
        nr::fsync | nr::fdatasync => p.fds.get(a[0]).map(|_| 0),
        nr::sync => Ok(0),
        nr::fadvise64 => p.fds.get(a[0]).map(|_| 0),
        nr::flock => p.fds.get(a[0]).map(|_| 0),

        // memory
        nr::brk => mem::brk(p, a[0]),
        nr::mmap => mem::mmap(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        nr::munmap => mem::munmap(p, a[0], a[1]),
        nr::mprotect => mem::mprotect(p, a[0], a[1], a[2]),
        nr::mremap => mem::mremap(p, a[0], a[1], a[2], a[3]),
        nr::madvise => mem::madvise(p, a[0], a[1], a[2]),
        nr::msync | nr::mlock | nr::munlock | nr::mlock2 | nr::mlockall | nr::munlockall => Ok(0),

        // processes and threads (not implemented yet, but gated)
        nr::clone => misc::clone(p, n, a[0]),
        nr::clone3 => {
            let flags = crate::uaccess::read_u64(&mut p.aspace, a[0])?;
            misc::clone(p, n, flags)
        }

        // everything else
        nr::exit | nr::exit_group => crate::process::exit((a[0] & 0xff) as i32),
        _ => misc::dispatch(p, n, name, a),
    }
}
