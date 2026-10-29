//! System V shared memory: shmget, shmat, shmdt, shmctl. PostgreSQL's
//! postmaster keeps a small segment as an interlock (its shm_nattch says
//! whether an old server still runs).
//!
//! A segment's pages are a MAP_SHARED anonymous mapping's (`SharedPages`,
//! made as they're first touched, in guest RAM). Each mapping of it holds
//! a reference to them, so how many there are besides the segment's own
//! is shm_nattch, counted per mapping through fork, splits and munmap, as
//! Linux counts it. A removed segment keeps only a weak reference, so its
//! pages go with its last mapping.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use spin::Mutex;

use super::mem::{MAP_FIXED, map_at};
use crate::errno::*;
use crate::mm::aspace::{Backing, SharedPages, Sysv};
use crate::mm::paging::Prot;
use crate::mm::{PAGE_SIZE, frame, page_up};
use crate::process::Process;
use crate::uaccess::*;

/// Segments at once, in the whole sandbox (Linux's SHMMNI is 4096).
const MAX_SEGMENTS: usize = 256;
/// An id is `seq * SEQ_MULTIPLIER + index`, as Linux makes them: the
/// index is the lowest free one, and the sequence number moves on with
/// every segment, so an old id doesn't name a new segment soon. Ids stay
/// below i32::MAX (programs keep them in ints).
const SEQ_MULTIPLIER: u32 = 32768;
const MAX_SEQ: u32 = i32::MAX as u32 / SEQ_MULTIPLIER;

const IPC_PRIVATE: u64 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const IPC_64: u64 = 0x100;
const SHM_LOCK: u64 = 11;
const SHM_UNLOCK: u64 = 12;
const SHM_STAT: u64 = 13;
const SHM_INFO: u64 = 14;
const SHM_STAT_ANY: u64 = 15;
const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_EXEC: u64 = 0o100000;
/// In shm_perm.mode: removed, waiting for its last detach.
const SHM_DEST: u32 = 0o1000;

struct Segment {
    key: i32,
    size: u64,
    /// The segment's own reference to its pages, until it's removed.
    pages: Option<Arc<SharedPages>>,
    weak: Weak<SharedPages>,
    mode: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    cpid: u32,
    lpid: u32,
    atime: u64,
    dtime: u64,
    ctime: u64,
}

impl Segment {
    fn attached(&self) -> u64 {
        (self.weak.strong_count() - self.pages.is_some() as usize) as u64
    }

    fn removed(&self) -> bool {
        self.mode & SHM_DEST != 0
    }

    fn is(&self, pages: &Arc<SharedPages>) -> bool {
        self.weak.as_ptr() == Arc::as_ptr(pages)
    }

    /// Does `p` have the `want` bits (0o4 read, 0o2 write, 0o1 execute) of
    /// its mode? As Linux's ipcperms: the owner's or creator's bits, then
    /// the group's (either group, also as a supplementary one), then the
    /// others'.
    fn permits(&self, p: &Process, want: u32) -> bool {
        if p.uid == 0 {
            return true;
        }
        let in_group = |g: u32| p.gid == g || p.ids.groups.contains(&g);
        let shift = if p.uid == self.uid || p.uid == self.cuid {
            6
        } else if in_group(self.gid) || in_group(self.cgid) {
            3
        } else {
            0
        };
        (self.mode >> shift) & want == want
    }

    /// Its owner or creator, or root, may change or remove it.
    fn owned_by(&self, p: &Process) -> bool {
        p.uid == 0 || p.uid == self.uid || p.uid == self.cuid
    }
}

struct Segments {
    by_id: BTreeMap<u32, Segment>,
    seq: u32,
}

static SEGMENTS: Mutex<Segments> = Mutex::new(Segments { by_id: BTreeMap::new(), seq: 0 });

fn now() -> u64 {
    crate::time::realtime_ns() / 1_000_000_000
}

/// The most a segment may be: all of the guest's memory.
fn shmmax() -> u64 {
    frame::stats().0 * PAGE_SIZE
}

/// Forget removed segments nothing maps any more.
fn purge(s: &mut Segments) {
    s.by_id.retain(|_, seg| !(seg.removed() && seg.attached() == 0));
}

/// The highest index in use (IPC_INFO and SHM_INFO return it).
fn max_index(s: &Segments) -> u64 {
    s.by_id.keys().map(|id| id % SEQ_MULTIPLIER).max().unwrap_or(0) as u64
}

pub fn shmget(p: &mut Process, key: u64, size: u64, flags: u64) -> SysResult {
    let key = key as i32;
    let mut s = SEGMENTS.lock();
    purge(&mut s);
    let req = (flags & 0o777) as u32;
    let want = (req >> 6 | req >> 3 | req) & 0o7;
    if key as u64 != IPC_PRIVATE
        && let Some((&id, seg)) = s.by_id.iter().find(|(_, seg)| seg.key == key && !seg.removed())
    {
        if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
            return Err(EEXIST);
        }
        if size > seg.size {
            return Err(EINVAL);
        }
        if !seg.permits(p, want) {
            return Err(EACCES);
        }
        return Ok(id as u64);
    }
    if key as u64 != IPC_PRIVATE && flags & IPC_CREAT == 0 {
        return Err(ENOENT);
    }
    if size == 0 || size > shmmax() {
        return Err(EINVAL);
    }
    let index = (0..MAX_SEGMENTS as u32).find(|i| !s.by_id.keys().any(|id| id % SEQ_MULTIPLIER == *i));
    let index = index.ok_or(ENOSPC)?;
    s.seq = (s.seq + 1) % MAX_SEQ;
    let id = s.seq * SEQ_MULTIPLIER + index;
    let pages = Arc::new(SharedPages::default());
    let t = now();
    s.by_id.insert(
        id,
        Segment {
            key,
            size,
            weak: Arc::downgrade(&pages),
            pages: Some(pages),
            mode: req,
            uid: p.uid,
            gid: p.gid,
            cuid: p.uid,
            cgid: p.gid,
            cpid: p.pid,
            lpid: 0,
            atime: 0,
            dtime: 0,
            ctime: t,
        },
    );
    Ok(id as u64)
}

pub fn shmat(p: &mut Process, id: u64, addr: u64, flags: u64) -> SysResult {
    let (pages, len, sysv) = {
        let s = SEGMENTS.lock();
        let seg = s.by_id.get(&(id as u32)).ok_or(EINVAL)?;
        if seg.removed() {
            return Err(EIDRM);
        }
        // As Linux: read, write unless SHM_RDONLY, execute for SHM_EXEC.
        let want = 0o4 | if flags & SHM_RDONLY == 0 { 0o2 } else { 0 } | if flags & SHM_EXEC != 0 { 0o1 } else { 0 };
        if !seg.permits(p, want) {
            return Err(EACCES);
        }
        let pages = seg.pages.clone().ok_or(EIDRM)?;
        let len = page_up(seg.size).ok_or(EINVAL)?;
        (pages, len, Sysv { key: seg.key, id: id as u32, pages: len / PAGE_SIZE })
    };
    let write = flags & SHM_RDONLY == 0;
    let prot = Prot { read: true, write, exec: flags & SHM_EXEC != 0 };
    // A read-only attach can't be made writable (mprotect: EACCES).
    let backing = Backing::Shared { pages, index: 0, may_write: write, sysv: Some(sysv) };
    let start = if addr == 0 {
        map_at(p, 0, len, 0, prot, backing)?
    } else {
        let addr = if flags & SHM_RND != 0 { addr & !(PAGE_SIZE - 1) } else { addr };
        if addr % PAGE_SIZE != 0 {
            return Err(EINVAL);
        }
        // Over what's there only with SHM_REMAP.
        let end = addr.checked_add(len).ok_or(EINVAL)?;
        if flags & SHM_REMAP == 0 && !p.aspace.is_free(addr, end) {
            return Err(EINVAL);
        }
        map_at(p, addr, len, MAP_FIXED, prot, backing)?
    };
    if let Some(seg) = SEGMENTS.lock().by_id.get_mut(&(id as u32)) {
        (seg.atime, seg.lpid) = (now(), p.pid);
    }
    Ok(start)
}

pub fn shmdt(p: &mut Process, addr: u64) -> SysResult {
    let mut s = SEGMENTS.lock();
    let Some(Backing::Shared { pages, index: 0, sysv: Some(_), .. }) =
        p.aspace.find(addr).filter(|v| v.start == addr).map(|v| &v.backing)
    else {
        return Err(EINVAL);
    };
    let pages = pages.clone();
    let Some(seg) = s.by_id.values_mut().find(|seg| seg.is(&pages)) else { return Err(EINVAL) };
    // Every piece of this attachment (mprotect may have split it), and
    // nothing else that's mapped there since.
    let end = addr.saturating_add(page_up(seg.size).unwrap_or(u64::MAX));
    let pieces: Vec<(u64, u64)> = p
        .aspace
        .vmas()
        .filter(|v| v.start >= addr && v.start < end)
        .filter(|v| matches!(&v.backing, Backing::Shared { pages: q, .. } if Arc::ptr_eq(q, &pages)))
        .map(|v| (v.start, v.end))
        .collect();
    (seg.dtime, seg.lpid) = (now(), p.pid);
    drop(pages);
    for (start, end) in pieces {
        p.aspace.unmap(start, end);
    }
    purge(&mut s);
    Ok(0)
}

pub fn shmctl(p: &mut Process, id: u64, cmd: u64, buf: u64) -> SysResult {
    let cmd = cmd & !IPC_64;
    let mut s = SEGMENTS.lock();
    purge(&mut s);
    match cmd {
        IPC_INFO => {
            let all = shmmax() / PAGE_SIZE;
            // struct shminfo64: shmmax, shmmin, shmmni, shmseg, shmall.
            let info = [shmmax(), 1, MAX_SEGMENTS as u64, MAX_SEGMENTS as u64, all, 0, 0, 0, 0];
            let bytes: Vec<u8> = info.iter().flat_map(|v| v.to_le_bytes()).collect();
            copy_out(&mut p.aspace, buf, &bytes)?;
            return Ok(max_index(&s));
        }
        SHM_INFO => {
            // struct shm_info: used_ids, then shm_tot (pages), shm_rss,
            // shm_swp, swap_attempts, swap_successes.
            let tot: u64 = s.by_id.values().map(|seg| page_up(seg.size).unwrap_or(0) / PAGE_SIZE).sum();
            let mut b = [0u8; 48];
            b[..4].copy_from_slice(&(s.by_id.len() as u32).to_le_bytes());
            b[8..16].copy_from_slice(&tot.to_le_bytes());
            copy_out(&mut p.aspace, buf, &b)?;
            return Ok(max_index(&s));
        }
        _ => {}
    }
    // SHM_STAT and SHM_STAT_ANY take an index, and return the id.
    let id = match cmd {
        SHM_STAT | SHM_STAT_ANY => *s.by_id.keys().find(|k| (*k % SEQ_MULTIPLIER) as u64 == id).ok_or(EINVAL)?,
        _ => id as u32,
    };
    let seg = s.by_id.get_mut(&id).ok_or(EINVAL)?;
    match cmd {
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            if cmd != SHM_STAT_ANY && !seg.permits(p, 0o4) {
                return Err(EACCES);
            }
            // struct shmid64_ds: ipc64_perm (key, uid, gid, cuid, cgid,
            // mode, seq), shm_segsz, atime, dtime, ctime, cpid, lpid,
            // shm_nattch.
            let mut b = [0u8; 112];
            let words = [seg.key as u32, seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode];
            for (i, w) in words.iter().enumerate() {
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            b[24..26].copy_from_slice(&((id / SEQ_MULTIPLIER) as u16).to_le_bytes());
            b[48..56].copy_from_slice(&seg.size.to_le_bytes());
            b[56..64].copy_from_slice(&seg.atime.to_le_bytes());
            b[64..72].copy_from_slice(&seg.dtime.to_le_bytes());
            b[72..80].copy_from_slice(&seg.ctime.to_le_bytes());
            b[80..84].copy_from_slice(&seg.cpid.to_le_bytes());
            b[84..88].copy_from_slice(&seg.lpid.to_le_bytes());
            b[88..96].copy_from_slice(&seg.attached().to_le_bytes());
            copy_out(&mut p.aspace, buf, &b)?;
            Ok(if cmd == IPC_STAT { 0 } else { id as u64 })
        }
        IPC_SET => {
            if !seg.owned_by(p) {
                return Err(EPERM);
            }
            let mut b = [0u8; 24];
            copy_in(&mut p.aspace, buf, &mut b)?;
            let word = |i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
            (seg.uid, seg.gid) = (word(1), word(2));
            seg.mode = (seg.mode & !0o777) | (word(5) & 0o777);
            seg.ctime = now();
            Ok(0)
        }
        IPC_RMID => {
            if !seg.owned_by(p) {
                return Err(EPERM);
            }
            // Its key is free at once; its pages go with its last mapping.
            seg.mode |= SHM_DEST;
            seg.key = IPC_PRIVATE as i32;
            seg.ctime = now();
            seg.pages = None;
            purge(&mut s);
            Ok(0)
        }
        // Nothing is ever swapped out.
        SHM_LOCK | SHM_UNLOCK => Ok(0),
        _ => Err(EINVAL),
    }
}
