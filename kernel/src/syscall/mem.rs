//! Memory syscalls: brk, mmap, munmap, mprotect, mremap, madvise.

use crate::errno::*;
use crate::fd::{FileKind, O_ACCMODE, O_WRONLY};
use crate::fs::{self, Kind};
use crate::mm::aspace::{Backing, USER_TOP, Vma};
use crate::mm::paging::Prot;
use crate::mm::{PAGE_SIZE, page_up};
use crate::process::Process;

const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

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
        a.map(Vma::anon(old_end, new_end, Prot::RW));
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
    let backing = if flags & MAP_ANONYMOUS != 0 {
        Backing::Anon
    } else {
        let file = p.fds.get(fd)?;
        let f = file.lock();
        if f.path_only {
            return Err(EBADF);
        }
        if f.flags & O_ACCMODE == O_WRONLY {
            return Err(EACCES);
        }
        match f.kind {
            FileKind::Node(ino) => match fs::get().node(ino).kind {
                Kind::File(data) => {
                    // Files are read-only, so a shared writable mapping is impossible.
                    if shared && prot.write {
                        return Err(EACCES);
                    }
                    Backing::File { data, offset: off, filesz: (data.len() as u64).saturating_sub(off), ino }
                }
                _ => return Err(ENODEV),
            },
            FileKind::Dev(..) => Backing::Anon, // /dev/zero
            _ => return Err(ENODEV),
        }
    };

    let a = &mut p.aspace;
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    let start = if fixed {
        let end = addr.checked_add(len).ok_or(ENOMEM)?;
        if !aligned(addr) || end > USER_TOP || addr == 0 {
            return Err(EINVAL);
        }
        if flags & MAP_FIXED_NOREPLACE != 0 && !a.is_free(addr, end) {
            return Err(EEXIST);
        }
        addr
    } else if addr != 0 && aligned(addr) && addr.checked_add(len).is_some_and(|e| a.is_free(addr, e)) {
        addr
    } else {
        a.find_free(len).ok_or(ENOMEM)?
    };
    a.map(Vma { start, end: start + len, prot, backing });
    Ok(start)
}

pub fn munmap(p: &mut Process, addr: u64, len: u64) -> SysResult {
    let len = page_up(len).filter(|&l| l > 0).ok_or(EINVAL)?;
    let end = addr.checked_add(len).filter(|&e| e <= USER_TOP).ok_or(EINVAL)?;
    if !aligned(addr) {
        return Err(EINVAL);
    }
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
    p.aspace.protect(addr, end, Prot::from_linux(prot)).map(|_| 0)
}

pub fn mremap(p: &mut Process, old: u64, old_len: u64, new_len: u64, flags: u64) -> SysResult {
    const MREMAP_MAYMOVE: u64 = 1;
    const MREMAP_FIXED: u64 = 2;
    if !aligned(old) || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED) != 0 {
        return Err(EINVAL);
    }
    if flags & MREMAP_FIXED != 0 {
        return p.unimplemented(super::table::nr::mremap, "mremap", "MREMAP_FIXED", EINVAL);
    }
    let old_len = page_up(old_len).ok_or(EINVAL)?;
    let new_len = page_up(new_len).filter(|&l| l > 0).ok_or(EINVAL)?;
    if old_len == 0 {
        return Err(EINVAL); // duplicating shared mappings is not supported
    }
    p.aspace.remap(old, old_len, new_len, flags & MREMAP_MAYMOVE != 0)
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
