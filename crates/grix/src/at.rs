//! File system calls relative to directories held open, never following a
//! link: for host directories something else can change while grix works
//! in them (a live mount's guest, another run's, anything on the host). A
//! path that was checked and is then used again by name can be a link by
//! the time it's used; a directory held open stays the one that was checked.

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path};

/// For directories only passed through on the way down: no read permission
/// needed, as for a path lookup.
#[cfg(target_os = "linux")]
const SEARCH: libc::c_int = libc::O_PATH;
#[cfg(target_os = "macos")]
const SEARCH: libc::c_int = libc::O_SEARCH;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const SEARCH: libc::c_int = libc::O_RDONLY;

pub(crate) fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
}

/// One name, for the system calls.
pub(crate) fn cname(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_encoded_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in a name"))
}

pub(crate) fn openat(dir: RawFd, name: &CStr, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated; the result is a new descriptor we own.
    let fd = check(unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Directory `name` in `dir`, itself and not a link to one.
pub(crate) fn open_dir_at(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    openat(dir, name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0)
}

/// The directory holding `path`, and its name there (`.` for `/`), walked
/// down to from `/` without following a link: `path` must be canonical,
/// and a link swapped in anywhere on the way since fails the walk.
pub(crate) fn open_parent(path: &Path) -> io::Result<(OwnedFd, CString)> {
    let not_real = || io::Error::new(io::ErrorKind::InvalidInput, format!("{} isn't a canonical path", path.display()));
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(not_real());
    }
    let mut names = Vec::new();
    for c in parts {
        let Component::Normal(name) = c else { return Err(not_real()) };
        names.push(cname(name)?);
    }
    let mut dir = openat(libc::AT_FDCWD, c"/", libc::O_DIRECTORY | SEARCH, 0)?;
    let Some(last) = names.pop() else { return Ok((dir, c".".into())) };
    for name in names {
        dir = openat(dir.as_raw_fd(), &name, libc::O_DIRECTORY | libc::O_NOFOLLOW | SEARCH, 0)?;
    }
    Ok((dir, last))
}

/// Directory `path` (canonical), reached as [`open_parent`] walks.
pub(crate) fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let (dir, name) = open_parent(path)?;
    open_dir_at(dir.as_raw_fd(), &name)
}

/// Is this "not a directory (any more)": gone, a file, or a link?
pub(crate) fn not_a_dir(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP))
}

pub(crate) fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: fstat fills `st`, a plain C struct.
    let mut st = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

pub(crate) fn stat_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    // SAFETY: as for stat_fd; AT_SYMLINK_NOFOLLOW never follows a link.
    let mut st = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(st)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    Symlink,
    /// A socket, FIFO or device.
    Other,
}

/// (The casts are for the field types that differ by platform.)
#[allow(clippy::unnecessary_cast)]
pub(crate) fn kind(st: &libc::stat) -> Kind {
    match st.st_mode as u32 & libc::S_IFMT as u32 {
        f if f == libc::S_IFREG as u32 => Kind::File,
        f if f == libc::S_IFDIR as u32 => Kind::Dir,
        f if f == libc::S_IFLNK as u32 => Kind::Symlink,
        _ => Kind::Other,
    }
}

#[allow(clippy::unnecessary_cast)]
pub(crate) fn mode(st: &libc::stat) -> u32 {
    st.st_mode as u32 & 0o7777
}

/// The modification time in ns since the Unix epoch (0 before it).
#[allow(clippy::unnecessary_cast)]
pub(crate) fn mtime_ns(st: &libc::stat) -> u64 {
    let (sec, nsec) = (st.st_mtime as i64, st.st_mtime_nsec as i64);
    if sec < 0 { 0 } else { (sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64) }
}

#[allow(clippy::unnecessary_cast)]
pub(crate) fn ctime_ns(st: &libc::stat) -> i128 {
    st.st_ctime as i128 * 1_000_000_000 + st.st_ctime_nsec as i128
}

/// Which file this is: (device, inode).
#[allow(clippy::unnecessary_cast)]
pub(crate) fn identity(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

pub(crate) fn readlink_at(dir: RawFd, name: &CStr) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: readlinkat writes at most buf.len() bytes.
    let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// The names in directory `dir` (not `.` or `..`).
pub(crate) fn read_dir(dir: RawFd) -> io::Result<Vec<CString>> {
    // fdopendir takes the descriptor over, so give it a copy.
    // SAFETY: dup of a descriptor we hold; fdopendir owns the copy, and
    // closedir closes it.
    let copy = check(unsafe { libc::dup(dir) })?;
    let d = unsafe { libc::fdopendir(copy) };
    if d.is_null() {
        let e = io::Error::last_os_error();
        unsafe { libc::close(copy) };
        return Err(e);
    }
    // From the start, whatever the shared offset was.
    unsafe { libc::rewinddir(d) };
    let mut names = Vec::new();
    loop {
        // SAFETY: readdir's entry is valid until the next call on `d`.
        let e = unsafe { libc::readdir(d) };
        if e.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    unsafe { libc::closedir(d) };
    Ok(names)
}

pub(crate) fn mkdir_at(dir: RawFd, name: &CStr, mode: u32) -> io::Result<()> {
    // SAFETY: a checked name in a directory we hold.
    check(unsafe { libc::mkdirat(dir, name.as_ptr(), mode as libc::mode_t) }).map(|_| ())
}

pub(crate) fn symlink_at(target: &CStr, dir: RawFd, name: &CStr) -> io::Result<()> {
    // SAFETY: as for mkdir_at; the target is stored, not followed.
    check(unsafe { libc::symlinkat(target.as_ptr(), dir, name.as_ptr()) }).map(|_| ())
}

/// Remove `name` from `dir` (with `dir`, an empty directory): whatever it
/// is now, and never what a link points at.
pub(crate) fn remove_at(dir: RawFd, name: &CStr, is_dir: bool) -> io::Result<()> {
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: as for mkdir_at.
    check(unsafe { libc::unlinkat(dir, name.as_ptr(), flags) }).map(|_| ())
}

/// rename, or with `noreplace` fail if `to` exists, or with `exchange`
/// swap the two (Linux's RENAME_EXCHANGE, macOS's RENAME_SWAP).
pub(crate) fn rename(
    from_dir: RawFd,
    from: &CStr,
    to_dir: RawFd,
    to: &CStr,
    noreplace: bool,
    exchange: bool,
) -> io::Result<()> {
    if noreplace && exchange {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: renameat and its variants on descriptors we hold and checked
    // names; none follows a link in the last component.
    let r = if !noreplace && !exchange {
        unsafe { libc::renameat(from_dir, from.as_ptr(), to_dir, to.as_ptr()) }
    } else {
        // The system call itself: musl has no wrapper for it.
        #[cfg(target_os = "linux")]
        let r = unsafe {
            let flags = if exchange { libc::RENAME_EXCHANGE } else { libc::RENAME_NOREPLACE };
            libc::syscall(libc::SYS_renameat2, from_dir, from.as_ptr(), to_dir, to.as_ptr(), flags) as libc::c_int
        };
        #[cfg(target_os = "macos")]
        let r = unsafe {
            let flags = if exchange { libc::RENAME_SWAP } else { libc::RENAME_EXCL };
            libc::renameatx_np(from_dir, from.as_ptr(), to_dir, to.as_ptr(), flags)
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let r = {
            let _ = (from_dir, from, to_dir, to);
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        };
        r
    };
    check(r).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let d =
            std::env::temp_dir().join(format!("grix-at-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn walks_real_directories_only() {
        let root = tempdir();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/b/f"), "x").unwrap();
        std::os::unix::fs::symlink(root.join("a"), root.join("link")).unwrap();
        assert!(open_dir(&root.join("a/b")).is_ok());
        let (d, name) = open_parent(&root.join("a/b/f")).unwrap();
        assert_eq!(kind(&stat_at(d.as_raw_fd(), &name).unwrap()), Kind::File);
        // A link anywhere on the way, or as the directory itself, fails.
        assert!(not_a_dir(&open_dir(&root.join("link/b")).unwrap_err()));
        assert!(not_a_dir(&open_dir(&root.join("link")).unwrap_err()));
        assert!(not_a_dir(&open_dir(&root.join("a/b/f")).unwrap_err()));
        // The last name may be a link: it's what's looked at, not followed.
        let (d, name) = open_parent(&root.join("link")).unwrap();
        assert_eq!(kind(&stat_at(d.as_raw_fd(), &name).unwrap()), Kind::Symlink);
        // Only canonical paths.
        assert!(open_dir(Path::new("relative")).is_err());
        assert!(open_dir(&root.join("a/../a")).is_err());
        assert!(open_dir(Path::new("/")).is_ok());
        fs::remove_dir_all(&root).unwrap();
    }
}
