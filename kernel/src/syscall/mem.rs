//! Memory syscalls: brk, mmap, munmap, mprotect, mremap, madvise, and the
//! NUMA policies (mbind, set_mempolicy, get_mempolicy).

use crate::errno::*;
use crate::fd::FileKind;
use crate::mm::aspace::{Backing, MMAP_MIN_ADDR, USER_TOP, Vma};
use crate::mm::paging::Prot;
use crate::mm::{PAGE_SIZE, page_up};
use crate::process::Process;
use crate::syscall::table::nr;

const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
pub(super) const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_GROWSDOWN: u64 = 0x100;
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
    if flags & MAP_GROWSDOWN != 0 {
        if shared && flags & MAP_ANONYMOUS != 0 {
            return Err(EINVAL);
        }
        // Growing would need the offset to move below where it started.
        if flags & MAP_ANONYMOUS == 0 {
            return p.unimplemented(nr::mmap, "mmap", "MAP_GROWSDOWN of a file", EINVAL);
        }
    }
    let prot = Prot::from_linux(prot);
    let shared_anon = || Backing::Shared { pages: Default::default(), index: 0, may_write: true, sysv: None };
    let backing = if flags & MAP_ANONYMOUS != 0 {
        if shared { shared_anon() } else { Backing::Anon }
    } else {
        let file = p.fds.get(fd)?;
        let f = file.lock();
        if !f.readable() {
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
                let rdwr = f.writable();
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
                    None => {
                        // Its pages come as they're used, after a close too.
                        let pinned = data.pin(false);
                        Backing::Data { data: c.clone(), offset: off, end: u64::MAX, ino, shared, pinned }
                    }
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
        && addr.checked_add(len).is_some_and(|e| a.is_free(addr, e) && a.clear_of_stack(e) && a.clear_of_growing(e))
    {
        addr
    } else {
        a.find_free(len).ok_or(ENOMEM)?
    };
    a.room_for(start, start + len, false, 1)?;
    let mut vma = Vma::new(start, start + len, prot, backing);
    vma.grows_down = flags & MAP_GROWSDOWN != 0;
    a.map(vma);
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
    const PROT_SEM: u64 = 8;
    const PROT_GROWSDOWN: u64 = 0x0100_0000;
    const PROT_GROWSUP: u64 = 0x0200_0000;
    let grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
    let prot = prot & !grows;
    if grows == PROT_GROWSDOWN | PROT_GROWSUP || !aligned(addr) {
        return Err(EINVAL);
    }
    let len = page_up(len).ok_or(ENOMEM)?;
    if len == 0 {
        return Ok(0);
    }
    let end = addr.checked_add(len).filter(|&e| e <= USER_TOP).ok_or(ENOMEM)?;
    if prot & !(7 | PROT_SEM) != 0 {
        return Err(EINVAL);
    }
    // Down to where the mapping starts, wherever that's got to by now.
    let addr = if grows == PROT_GROWSDOWN {
        let v = p.aspace.first_in(addr, end).ok_or(ENOMEM)?;
        if !v.grows_down {
            return Err(EINVAL);
        }
        v.start
    } else if grows != 0 {
        // Nothing here grows up.
        return Err(EINVAL);
    } else {
        addr
    };
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

/// What a shared mapping shows: a file (from its offset), or shared memory
/// (from a page). MADV_REMOVE makes a hole there.
enum Held {
    File(crate::fs::Content, crate::fs::Ino, u64),
    Memory(alloc::sync::Arc<crate::mm::aspace::SharedPages>, u64),
}

/// madvise, as Linux 6.1's, which is what uname says: mm/madvise.c. What
/// only advises is taken and does nothing, as it may on Linux too; what a
/// program can see the effect of, happens. A range with holes in it is
/// ENOMEM, after the rest has been done, and an error stops at the mapping
/// it's about, after those before it.
pub fn madvise(p: &mut Process, addr: u64, len: u64, advice: u64) -> SysResult {
    const MADV_DONTNEED: u32 = 4;
    const MADV_FREE: u32 = 8;
    const MADV_REMOVE: u32 = 9;
    const MADV_DONTFORK: u32 = 10;
    const MADV_DOFORK: u32 = 11;
    const MADV_WIPEONFORK: u32 = 18;
    const MADV_KEEPONFORK: u32 = 19;
    const MADV_POPULATE_READ: u32 = 22;
    const MADV_POPULATE_WRITE: u32 = 23;
    const MADV_DONTNEED_LOCKED: u32 = 24;
    const MADV_COLLAPSE: u32 = 25;
    // An `int` there. Nothing's 5 to 7; 100 and 101 take CONFIG_MEMORY_FAILURE,
    // which this isn't, and MADV_GUARD_* came with 6.13.
    let advice = advice as u32;
    if !matches!(advice, 0..=4 | 8..=25) || !aligned(addr) {
        return Err(EINVAL);
    }
    let end = page_up(len).and_then(|len| addr.checked_add(len)).ok_or(EINVAL)?;
    let (mut at, mut hole) = (addr, false);
    while at < end {
        let Some(v) = p.aspace.first_in(at, end) else {
            hole = true;
            break;
        };
        hole |= v.start > at;
        let (start, stop) = (v.start.max(at), v.end.min(end));
        let anon = matches!(v.backing, Backing::Anon);
        let (read, write) = (v.prot.read, v.prot.write);
        // VM_MAYWRITE: what the descriptor could do, not what the mapping
        // does now.
        let shared_file = match v.backing {
            Backing::Shared { may_write, .. } | Backing::SharedFile { may_write, .. } => Some(may_write),
            _ => None,
        };
        let file = shared_file.is_some() || matches!(v.backing, Backing::Data { .. } | Backing::File { .. });
        let v_start = v.start;
        let held = match &v.backing {
            Backing::SharedFile { data, offset, ino, .. } => Some(Held::File(data.clone(), *ino, *offset)),
            Backing::Shared { pages, index, .. } => Some(Held::Memory(pages.clone(), *index)),
            _ => None,
        };
        match advice {
            MADV_DONTNEED | MADV_DONTNEED_LOCKED => p.aspace.discard(start, stop),
            // Only what nothing else holds: a file's pages aren't the
            // mapping's to lose, and its private copies aren't to go.
            MADV_FREE if !anon => return Err(EINVAL),
            MADV_FREE => p.aspace.discard(start, stop),
            MADV_REMOVE if !file => return Err(EINVAL),
            MADV_REMOVE if shared_file != Some(true) => return Err(EACCES),
            MADV_REMOVE => {
                let (pages, off) = (start - v_start, stop - start);
                match held.expect("shared") {
                    Held::File(data, ino, offset) => {
                        super::file::punch_hole(p, nr::madvise, &data, ino, offset + pages, offset + pages + off)?;
                    }
                    Held::Memory(shared, index) => {
                        let first = index + pages / PAGE_SIZE;
                        let last = first + off / PAGE_SIZE;
                        p.aspace.zap_pages(&shared, first, last);
                        for q in crate::procs::PROCS.lock().others.values_mut() {
                            q.aspace.access().zap_pages(&shared, first, last);
                        }
                        shared.punch(first, last);
                    }
                }
            }
            MADV_WIPEONFORK if !anon => return Err(EINVAL),
            MADV_DONTFORK | MADV_DOFORK | MADV_WIPEONFORK | MADV_KEEPONFORK => {
                // A mapping that can't be cut: EAGAIN, as Linux says for
                // what's only short for now.
                p.aspace.room_for(start, stop, true, 0).map_err(|_| EAGAIN)?;
                p.aspace.set_flags(start, stop, |v| match advice {
                    MADV_DONTFORK | MADV_DOFORK => v.dontfork = advice == MADV_DONTFORK,
                    _ => v.wipeonfork = advice == MADV_WIPEONFORK,
                });
            }
            // EINVAL rather than EFAULT for permissions: faultin_vma_page_range.
            MADV_POPULATE_READ if !read => return Err(EINVAL),
            MADV_POPULATE_WRITE if !write => return Err(EINVAL),
            MADV_POPULATE_READ | MADV_POPULATE_WRITE => {
                p.aspace.ensure(start, stop - start, advice == MADV_POPULATE_WRITE)?;
            }
            // Nothing here is a huge page, or could be.
            MADV_COLLAPSE => return Err(EINVAL),
            _ => {}
        }
        at = stop;
    }
    if hole { Err(ENOMEM) } else { Ok(0) }
}

// NUMA memory policies (mm/mempolicy.c). The machine has one node, 0, so
// every valid policy puts memory in the same place: they're checked as
// Linux checks them, and the thread's is kept to be read back. A range's
// own policy (mbind) isn't kept: get_mempolicy's MPOL_F_ADDR reports the
// thread's.
const MPOL_DEFAULT: u32 = 0;
const MPOL_PREFERRED: u32 = 1;
const MPOL_BIND: u32 = 2;
const MPOL_INTERLEAVE: u32 = 3;
const MPOL_LOCAL: u32 = 4;
const MPOL_PREFERRED_MANY: u32 = 5;
const MPOL_WEIGHTED_INTERLEAVE: u32 = 6;
const MPOL_F_STATIC_NODES: u32 = 1 << 15;
const MPOL_F_RELATIVE_NODES: u32 = 1 << 14;
const MPOL_F_NUMA_BALANCING: u32 = 1 << 13;
const MPOL_MODE_FLAGS: u32 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;

/// The nodes a user nodemask of `maxnode` bits names (get_nodes): (any
/// bit set, node 0's bit set). Other nodes don't exist, so they're
/// dropped, as Linux drops nodes the task may not use.
fn read_nodes(p: &mut Process, mask: u64, maxnode: u64) -> Result<(bool, bool), Errno> {
    let bits = maxnode.saturating_sub(1);
    if mask == 0 || bits == 0 {
        return Ok((false, false));
    }
    if bits > PAGE_SIZE * 8 {
        return Err(EINVAL);
    }
    // At most a page: on the heap, off the kernel stack.
    let len = bits.div_ceil(64) as usize * 8;
    let mut buf = alloc::vec![0u8; len];
    crate::uaccess::copy_in(&mut p.aspace, mask, &mut buf)?;
    // Bits past `bits` in the last word don't count.
    let last = len - 8;
    let used = bits - last as u64 * 8;
    if used < 64 {
        let w = u64::from_le_bytes(buf[last..].try_into().unwrap()) & ((1u64 << used) - 1);
        buf[last..].copy_from_slice(&w.to_le_bytes());
    }
    Ok((buf.iter().any(|&b| b != 0), buf[0] & 1 != 0))
}

/// Check a policy as mpol_new does: `Ok(mode | flags)`, or EINVAL.
fn check_policy(p: &mut Process, mode: u64, mask: u64, maxnode: u64) -> Result<u32, Errno> {
    // An int.
    let mode = mode as u32;
    let (flags, base) = (mode & MPOL_MODE_FLAGS, mode & !MPOL_MODE_FLAGS);
    if base > MPOL_WEIGHTED_INTERLEAVE || flags & MPOL_F_STATIC_NODES != 0 && flags & MPOL_F_RELATIVE_NODES != 0 {
        return Err(EINVAL);
    }
    if flags & MPOL_F_NUMA_BALANCING != 0 && !matches!(base, MPOL_BIND | MPOL_PREFERRED_MANY) {
        return Err(EINVAL);
    }
    let (any, node0) = read_nodes(p, mask, maxnode)?;
    let ok = match base {
        MPOL_DEFAULT | MPOL_LOCAL => !any,
        // No nodes: local allocation.
        MPOL_PREFERRED => !any || node0,
        _ => node0,
    };
    if !ok {
        return Err(EINVAL);
    }
    Ok(if base == MPOL_DEFAULT { 0 } else { mode })
}

pub fn set_mempolicy(p: &mut Process, mode: u64, mask: u64, maxnode: u64) -> SysResult {
    let policy = check_policy(p, mode, mask, maxnode)?;
    p.cur().mempolicy = policy;
    Ok(0)
}

pub fn mbind(p: &mut Process, addr: u64, len: u64, mode: u64, mask: u64, maxnode: u64, flags: u64) -> SysResult {
    const MPOL_MF_STRICT: u64 = 1;
    const MPOL_MF_MOVE: u64 = 2;
    const MPOL_MF_MOVE_ALL: u64 = 4;
    if flags & !(MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0 || !aligned(addr) {
        return Err(EINVAL);
    }
    // Moving other processes' pages needs CAP_SYS_NICE, which nothing has.
    if flags & MPOL_MF_MOVE_ALL != 0 {
        return Err(EPERM);
    }
    let end = page_up(len).and_then(|l| addr.checked_add(l)).ok_or(EINVAL)?;
    check_policy(p, mode, mask, maxnode)?;
    // A hole in the range is EFAULT.
    let mut at = addr;
    while at < end {
        at = p.aspace.find(at).ok_or(EFAULT)?.end;
    }
    Ok(0)
}

pub fn get_mempolicy(p: &mut Process, policy: u64, mask: u64, maxnode: u64, addr: u64, flags: u64) -> SysResult {
    const MPOL_F_NODE: u64 = 1;
    const MPOL_F_ADDR: u64 = 2;
    const MPOL_F_MEMS_ALLOWED: u64 = 4;
    if flags & !(MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED) != 0 || mask != 0 && maxnode < 1 {
        return Err(EINVAL);
    }
    let mine = p.cur().mempolicy;
    let (value, nodes) = if flags & MPOL_F_MEMS_ALLOWED != 0 {
        if flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0 {
            return Err(EINVAL);
        }
        (0, 1u64)
    } else {
        if flags & MPOL_F_ADDR != 0 && p.aspace.find(addr).is_none() {
            return Err(EFAULT);
        }
        let nodes = (mine & !MPOL_MODE_FLAGS != MPOL_DEFAULT && mine & !MPOL_MODE_FLAGS != MPOL_LOCAL) as u64;
        match flags & (MPOL_F_NODE | MPOL_F_ADDR) {
            // The node the page is on, or the next interleaving one: 0.
            f if f == MPOL_F_NODE | MPOL_F_ADDR => (0, nodes),
            MPOL_F_NODE if mine & !MPOL_MODE_FLAGS == MPOL_INTERLEAVE => (0, nodes),
            MPOL_F_NODE => return Err(EINVAL),
            _ => (mine, nodes),
        }
    };
    if policy != 0 {
        crate::uaccess::write_u32(&mut p.aspace, policy, value)?;
    }
    if mask != 0 {
        // copy_nodes_to_user: whole longs for maxnode - 1 bits, past the
        // first zeroed, at most a page.
        let len = (maxnode - 1).next_multiple_of(64) / 8;
        if len > PAGE_SIZE {
            return Err(EINVAL);
        }
        let mut buf = alloc::vec![0u8; len as usize];
        let n = buf.len().min(8);
        buf[..n].copy_from_slice(&nodes.to_le_bytes()[..n]);
        crate::uaccess::copy_out(&mut p.aspace, mask, &buf)?;
    }
    Ok(0)
}
