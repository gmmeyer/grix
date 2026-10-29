//! Memory syscalls: brk, mmap, munmap, mprotect, mremap, madvise.

use crate::errno::*;
use crate::fd::{FileKind, O_ACCMODE, O_RDWR, O_WRONLY};
use crate::mm::aspace::{Backing, USER_TOP, Vma};
use crate::mm::paging::Prot;
use crate::mm::{PAGE_SIZE, page_up};
use crate::process::Process;
use crate::syscall::table::nr;

const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
pub(super) const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
/// Nothing is mapped below this (`/proc/sys/vm/mmap_min_addr`): a NULL
/// pointer, in the kernel too, always faults.
pub const MMAP_MIN_ADDR: u64 = 0x1_0000;

fn aligned(a: u64) -> bool {
    a.is_multiple_of(PAGE_SIZE)
}

pub fn brk(p: &mut Process, addr: u64) -> SysResult {
    let a = &mut p.aspace;
    if addr < a.brk_start || addr >= USER_TOP {
        return Ok(a.brk);
    }
    let (Some(old_end), Some(new_end)) = (page_up(a.brk), page_up(addr)) else { return Ok(a.brk) };
    if new_end > old_end {
        if !a.is_free(old_end, new_end) {
            return Ok(a.brk);
        }
        // One mapping for the whole heap, however many times it grows.
        if !a.extend_anon(old_end, new_end, Prot::RW) {
            if a.has_room(1).is_err() {
                return Ok(a.brk);
            }
            a.map(Vma::anon(old_end, new_end, Prot::RW));
        }
    } else if new_end < old_end {
        a.unmap(new_end, old_end);
    }
    a.brk = addr;
    Ok(addr)
}

pub fn mmap(p: &mut Process, addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> SysResult {
    let len = page_up(len).filter(|&l| l > 0 && l < USER_TOP).ok_or(if len == 0 { EINVAL } else { ENOMEM })?;
    if !aligned(off) {
        return Err(EINVAL);
    }
    let shared = match flags & 0x3 {
        MAP_SHARED => true,
        MAP_PRIVATE => false,
        0x3 => true, // MAP_SHARED_VALIDATE
        _ => return Err(EINVAL),
    };
    let prot = Prot::from_linux(prot);
    let shared_anon = || Backing::Shared { pages: Default::default(), index: 0, may_write: true, sysv: None };
    let backing = if flags & MAP_ANONYMOUS != 0 {
        if shared { shared_anon() } else { Backing::Anon }
    } else {
        let file = p.fds.get(fd)?;
        let f = file.lock();
        if f.path_only {
            return Err(EBADF);
        }
        if f.flags & O_ACCMODE == O_WRONLY {
            return Err(EACCES);
        }
        match (&f.kind, &f.content) {
            (FileKind::Node(ino), Some(c)) => {
                // As Linux's file_mmap_ok: no file offset in the mapping
                // past MAX_LFS_FILESIZE (so none wraps, either).
                if off.checked_add(len).is_none_or(|end| end > i64::MAX as u64) {
                    return Err(EOVERFLOW);
                }
                let ino = *ino;
                let rdwr = f.flags & O_ACCMODE == O_RDWR;
                if shared && prot.write && !rdwr {
                    return Err(EACCES);
                }
                let mut data = c.lock();
                // A sealed memfd can't be written through a mapping either.
                let sealed = data.seals.unwrap_or(0) & (crate::fs::F_SEAL_WRITE | crate::fs::F_SEAL_FUTURE_WRITE) != 0;
                if shared && prot.write && sealed {
                    return Err(EPERM);
                }
                let may_write = rdwr && !sealed;
                // A file in the sandbox: the mapping is the file's pages.
                if shared && data.remote_id().is_none() {
                    let token = data.map_live(may_write);
                    let backing = Backing::SharedFile { data: c.clone(), offset: off, ino, may_write, token };
                    drop(data);
                    drop(f);
                    return map_at(p, addr, len, flags, prot, backing);
                }
                if shared && prot.write {
                    // A live mount's: writes through it would have to reach the host.
                    return p.unimplemented(nr::mmap, "mmap", "shared writable mappings of a mounted file", ENODEV);
                }
                // Unmodified imports map straight from the boot image; written
                // files are copied page by page as they fault in. Either way
                // the mapping holds a copy, so a live mount's shared one is
                // registered with the file: changing the file later is reported.
                let shared = shared.then(|| data.map_shared());
                match data.image() {
                    Some(bytes) => Backing::File {
                        data: bytes,
                        offset: off,
                        filesz: (bytes.len() as u64).saturating_sub(off),
                        ino,
                        shared,
                    },
                    None => Backing::Data { data: c.clone(), offset: off, end: u64::MAX, ino, shared },
                }
            }
            // /dev/zero, which Linux maps as shared anonymous memory when shared.
            (FileKind::Dev(..), _) if shared => shared_anon(),
            (FileKind::Dev(..), _) => Backing::Anon,
            _ => return Err(ENODEV),
        }
    };
    map_at(p, addr, len, flags, prot, backing)
}

/// Place a new mapping: at `addr` with MAP_FIXED, there if it's free and
/// asked for (and not below MMAP_MIN_ADDR, as for MAP_FIXED), or wherever
/// there's room.
pub(super) fn map_at(p: &mut Process, addr: u64, len: u64, flags: u64, prot: Prot, backing: Backing) -> SysResult {
    let a = &mut p.aspace;
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    let start = if fixed {
        let end = addr.checked_add(len).ok_or(ENOMEM)?;
        if !aligned(addr) || end > USER_TOP {
            return Err(EINVAL);
        }
        if addr < MMAP_MIN_ADDR {
            return Err(EPERM);
        }
        if flags & MAP_FIXED_NOREPLACE != 0 && !a.is_free(addr, end) {
            return Err(EEXIST);
        }
        addr
    } else if addr >= MMAP_MIN_ADDR
        && aligned(addr)
        && addr.checked_add(len).is_some_and(|e| a.is_free(addr, e) && a.clear_of_stack(e))
    {
        addr
    } else {
        a.find_free(len).ok_or(ENOMEM)?
    };
    a.room_for(start, start + len, false, 1)?;
    a.map(Vma { start, end: start + len, prot, backing });
    Ok(start)
}

pub fn munmap(p: &mut Process, addr: u64, len: u64) -> SysResult {
    let len = page_up(len).filter(|&l| l > 0).ok_or(EINVAL)?;
    let end = addr.checked_add(len).filter(|&e| e <= USER_TOP).ok_or(EINVAL)?;
    if !aligned(addr) {
        return Err(EINVAL);
    }
    p.aspace.room_for(addr, end, false, 0)?;
    p.aspace.unmap(addr, end);
    Ok(0)
}

pub fn mprotect(p: &mut Process, addr: u64, len: u64, prot: u64) -> SysResult {
    if !aligned(addr) {
        return Err(EINVAL);
    }
    let len = page_up(len).ok_or(ENOMEM)?;
    if len == 0 {
        return Ok(0);
    }
    let end = addr.checked_add(len).filter(|&e| e <= USER_TOP).ok_or(ENOMEM)?;
    let prot = Prot::from_linux(prot);
    p.aspace.room_for(addr, end, true, 0)?;
    if prot.write && p.aspace.has_read_only_shared_file(addr, end) {
        return Err(EACCES);
    }
    if prot.write && p.aspace.has_shared_file(addr, end) {
        // Writes through it would have to reach the host.
        return p.unimplemented(nr::mprotect, "mprotect", "shared writable mappings of a mounted file", EACCES);
    }
    p.aspace.protect(addr, end, prot).map(|_| 0)
}

pub fn mremap(p: &mut Process, old: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64) -> SysResult {
    const MREMAP_MAYMOVE: u64 = 1;
    const MREMAP_FIXED: u64 = 2;
    if !aligned(old) || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED) != 0 {
        return Err(EINVAL);
    }
    let old_len = page_up(old_len).ok_or(EINVAL)?;
    let new_len = page_up(new_len).filter(|&l| l > 0).ok_or(EINVAL)?;
    if old_len == 0 {
        return Err(EINVAL); // duplicating shared mappings is not supported
    }
    // MREMAP_FIXED: to exactly `new_addr` (it needs MREMAP_MAYMOVE), whatever
    // is there unmapped first; the two ranges mustn't overlap.
    let fixed = if flags & MREMAP_FIXED != 0 {
        let end = new_addr.checked_add(new_len).filter(|&e| e <= USER_TOP).ok_or(EINVAL)?;
        let old_end = old.checked_add(old_len).ok_or(EINVAL)?;
        if flags & MREMAP_MAYMOVE == 0 || !aligned(new_addr) || (new_addr < old_end && old < end) {
            return Err(EINVAL);
        }
        if new_addr < MMAP_MIN_ADDR {
            return Err(EPERM);
        }
        Some(new_addr)
    } else {
        None
    };
    p.aspace.has_room(3)?;
    p.aspace.remap(old, old_len, new_len, flags & MREMAP_MAYMOVE != 0, fixed)
}

pub fn madvise(p: &mut Process, addr: u64, len: u64, advice: u64) -> SysResult {
    const MADV_DONTNEED: u64 = 4;
    const MADV_FREE: u64 = 8;
    if !aligned(addr) {
        return Err(EINVAL);
    }
    let len = page_up(len).ok_or(EINVAL)?;
    let end = addr.checked_add(len).filter(|&e| e <= USER_TOP).ok_or(EINVAL)?;
    if matches!(advice, MADV_DONTNEED | MADV_FREE) {
        p.aspace.discard(addr, end);
    }
    Ok(0)
}
