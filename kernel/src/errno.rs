//! Linux errno values.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(pub u32);

pub type SysResult = Result<u64, Errno>;

pub const EPERM: Errno = Errno(1);
pub const ENOENT: Errno = Errno(2);
pub const ESRCH: Errno = Errno(3);
pub const EINTR: Errno = Errno(4);
pub const EBADF: Errno = Errno(9);
pub const EAGAIN: Errno = Errno(11);
pub const ENOMEM: Errno = Errno(12);
pub const EACCES: Errno = Errno(13);
pub const EFAULT: Errno = Errno(14);
pub const EBUSY: Errno = Errno(16);
pub const EEXIST: Errno = Errno(17);
pub const EIO: Errno = Errno(5);
pub const ENXIO: Errno = Errno(6);
pub const ENODEV: Errno = Errno(19);
pub const ENOTDIR: Errno = Errno(20);
pub const EISDIR: Errno = Errno(21);
pub const EINVAL: Errno = Errno(22);
pub const EMFILE: Errno = Errno(24);
pub const ENOTTY: Errno = Errno(25);
pub const EFBIG: Errno = Errno(27);
pub const ENOSPC: Errno = Errno(28);
pub const ESPIPE: Errno = Errno(29);
pub const EROFS: Errno = Errno(30);
pub const EPIPE: Errno = Errno(32);
pub const ERANGE: Errno = Errno(34);
pub const ENAMETOOLONG: Errno = Errno(36);
pub const ENOSYS: Errno = Errno(38);
pub const ENOTEMPTY: Errno = Errno(39);
pub const ELOOP: Errno = Errno(40);
pub const ENODATA: Errno = Errno(61);
pub const EOPNOTSUPP: Errno = Errno(95);
pub const ENOBUFS: Errno = Errno(105);
pub const ENOTCONN: Errno = Errno(107);
pub const E2BIG: Errno = Errno(7);
pub const ETIMEDOUT: Errno = Errno(110);

/// Internal: the syscall blocked the calling thread (or it exited); the
/// scheduler decides what runs next. Never returned to user space.
pub const EBLOCKED: Errno = Errno(u32::MAX);
