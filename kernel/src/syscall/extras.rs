//! Calls programs meet less often, each as Linux has it (`linuxcalls` passes
//! there). Most are small because there's less here to say: one NUMA node,
//! no protection keys, and a scheduler that keeps a process's nice value and
//! I/O priority for it to read back rather than going by them.

use super::table::nr;
use crate::errno::*;
use crate::fd::FileKind;
use crate::fs;
use crate::mm::aspace::{Backing, Vma};
use crate::mm::{PAGE_SIZE, page_up};
use crate::process::Process;
use crate::syscall::SysResult;
use crate::uaccess::*;

const MAX_PID: u64 = i32::MAX as u64;

/// Who a call about priorities is about. The three calls that take this
/// number it differently (`PRIO_*` from 0, `IOPRIO_WHO_*` from 1).
#[derive(Clone, Copy)]
enum Whom {
    Process(u32),
    Group(u32),
    User(u32),
}

impl Whom {
    fn decode(which: u64, who: u64, first: u64) -> Result<Whom, Errno> {
        let who = who as u32;
        match which.wrapping_sub(first) {
            0 => Ok(Whom::Process(who)),
            1 => Ok(Whom::Group(who)),
            2 => Ok(Whom::User(who)),
            _ => Err(EINVAL),
        }
    }

    fn takes(self, me: u32, group: u32, user: u32, q: &Process) -> bool {
        match self {
            Whom::Process(pid) => q.pid == if pid == 0 { me } else { pid },
            Whom::Group(pgid) => q.pgid == if pgid == 0 { group } else { pgid },
            Whom::User(uid) => q.uid == if uid == 0 { user } else { uid },
        }
    }
}

/// `f` on every process `whom` means, the caller too: ESRCH if that's none.
fn each_of(p: &mut Process, whom: Whom, mut f: impl FnMut(&mut Process) -> Result<(), Errno>) -> Result<(), Errno> {
    let (me, group, user) = (p.pid, p.pgid, p.uid);
    let mut found = false;
    if whom.takes(me, group, user, p) {
        found = true;
        f(p)?;
    }
    let mut procs = crate::procs::PROCS.lock();
    for q in procs.others.values_mut().filter(|q| !q.dead && whom.takes(me, group, user, q)) {
        found = true;
        f(q)?;
    }
    if found { Ok(()) } else { Err(ESRCH) }
}

/// Is `pid` (0: the caller) a process that's there?
fn check_pid(p: &Process, pid: u64) -> Result<(), Errno> {
    if pid as i64 == 0 || pid == p.pid as u64 {
        return Ok(());
    }
    let there = pid <= MAX_PID && crate::procs::PROCS.lock().others.get(&(pid as u32)).is_some_and(|q| !q.dead);
    if there { Ok(()) } else { Err(ESRCH) }
}

pub fn getpriority(p: &mut Process, which: u64, who: u64) -> SysResult {
    let mut best = i8::MAX;
    each_of(p, Whom::decode(which, who, 0)?, |q| {
        best = best.min(q.nice);
        Ok(())
    })?;
    Ok((20 - best as i64) as u64)
}

pub fn setpriority(p: &mut Process, which: u64, who: u64, nice: u64) -> SysResult {
    let (uid, nice) = (p.uid, (nice as i32).clamp(-20, 19) as i8);
    each_of(p, Whom::decode(which, who, 0)?, |q| set_nice(uid, q, nice))?;
    Ok(0)
}

/// A process's nice value: its user's to change, and lower only for root, as
/// RLIMIT_NICE is 0 here.
fn set_nice(uid: u32, q: &mut Process, nice: i8) -> Result<(), Errno> {
    if uid != 0 && uid != q.uid {
        return Err(EPERM);
    }
    if uid != 0 && nice < q.nice {
        return Err(EACCES);
    }
    q.nice = nice;
    Ok(())
}

pub fn sched_rr_get_interval(p: &mut Process, pid: u64, out: u64) -> SysResult {
    if pid as i32 > 0 || pid == 0 {
        check_pid(p, pid)?;
    } else {
        return Err(EINVAL);
    }
    write_timespec(&mut p.aspace, out, crate::sched::SLICE_NS)?;
    Ok(0)
}

/// `struct sched_attr`'s two sizes.
const ATTR_V0: usize = 48;
const ATTR_V1: usize = 56;

pub fn sched_getattr(p: &mut Process, pid: u64, out: u64, size: u64, flags: u64) -> SysResult {
    if pid as i32 >= 0 && out != 0 && flags == 0 && (ATTR_V0 as u64..=PAGE_SIZE).contains(&size) {
        check_pid(p, pid)?;
    } else {
        return Err(EINVAL);
    }
    let mut nice = 0;
    each_of(p, Whom::Process(pid as u32), |q| {
        nice = q.nice;
        Ok(())
    })?;
    // Everyone's SCHED_OTHER, so all that says anything is the size and nice.
    let mut b = [0u8; ATTR_V1];
    b[16..20].copy_from_slice(&(nice as i32).to_le_bytes());
    let n = (size as usize).min(ATTR_V1);
    b[..4].copy_from_slice(&(n as u32).to_le_bytes());
    copy_out(&mut p.aspace, out, &b[..n])?;
    Ok(0)
}

pub fn sched_setattr(p: &mut Process, pid: u64, attr: u64, flags: u64) -> SysResult {
    const RESET_ON_FORK: u64 = 1;
    if pid as i32 >= 0 && attr != 0 && flags == 0 {
        check_pid(p, pid)?;
    } else {
        return Err(EINVAL);
    }
    let mut b = [0u8; ATTR_V0];
    let size = read_u32(&mut p.aspace, attr)? as usize;
    if size != 0 && size < ATTR_V0 {
        write_u32(&mut p.aspace, attr, ATTR_V1 as u32)?;
        return Err(E2BIG);
    }
    copy_in(&mut p.aspace, attr, &mut b)?;
    let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let (policy, nice, priority) = (word(4), word(16) as i32, word(20));
    let attr_flags = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    if attr_flags & !RESET_ON_FORK != 0 {
        return Err(EINVAL);
    }
    match policy {
        0 | 3 | 5 if priority == 0 => {}
        1 | 2 | 6 => return Err(EPERM),
        _ => return Err(EINVAL),
    }
    let (uid, nice) = (p.uid, nice.clamp(-20, 19) as i8);
    each_of(p, Whom::Process(pid as u32), |q| set_nice(uid, q, nice))?;
    Ok(0)
}

pub fn ioprio_get(p: &mut Process, which: u64, who: u64) -> SysResult {
    let mut best = u16::MAX;
    each_of(p, Whom::decode(which, who, 1)?, |q| {
        best = best.min(q.ioprio);
        Ok(())
    })?;
    Ok(best as u64)
}

pub fn ioprio_set(p: &mut Process, which: u64, who: u64, prio: u64) -> SysResult {
    const CLASS_SHIFT: u64 = 13;
    const RT: u64 = 1;
    const BE: u64 = 2;
    const IDLE: u64 = 3;
    const LEVELS: u64 = 8;
    let (class, data) = ((prio >> CLASS_SHIFT) & 7, prio & ((1 << CLASS_SHIFT) - 1));
    let whom = Whom::decode(which, who, 1)?;
    match class {
        RT if p.uid != 0 => return Err(EPERM),
        RT | BE if data >= LEVELS => return Err(EINVAL),
        0 | RT | BE | IDLE => {}
        _ => return Err(EINVAL),
    }
    each_of(p, whom, |q| {
        q.ioprio = prio as u16;
        Ok(())
    })?;
    Ok(0)
}

/// What a clock adjustment reads. Nothing here disciplines the clock: an
/// unsynchronized one, as a machine without NTP has.
fn read_timex(p: &mut Process, n: u32, name: &str, tx: u64) -> SysResult {
    const TIME_ERROR: u64 = 5;
    const STA_UNSYNC: u32 = 0x40;
    const ADJ_OFFSET_SS_READ: u32 = 0xa001;
    let modes = read_u32(&mut p.aspace, tx)?;
    if modes != 0 && modes != ADJ_OFFSET_SS_READ {
        return p.deny(n, name, "privileged", "setting the clock");
    }
    let now = crate::time::realtime_ns();
    let mut b = [0u8; 208];
    let long = |b: &mut [u8; 208], at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    long(&mut b, 24, 16_000_000); // maxerror, as an unsynchronized clock's
    long(&mut b, 32, 16_000_000); // esterror
    b[40..44].copy_from_slice(&STA_UNSYNC.to_le_bytes());
    long(&mut b, 48, 7); // constant
    long(&mut b, 56, 1); // precision
    long(&mut b, 64, 32_768_000); // tolerance
    long(&mut b, 72, now / 1_000_000_000);
    long(&mut b, 80, now / 1_000 % 1_000_000);
    long(&mut b, 88, 10_000); // tick
    copy_out(&mut p.aspace, tx, &b)?;
    Ok(TIME_ERROR)
}

pub fn adjtimex(p: &mut Process, tx: u64) -> SysResult {
    read_timex(p, nr::adjtimex, "adjtimex", tx)
}

pub fn clock_adjtime(p: &mut Process, clock: u64, tx: u64) -> SysResult {
    const CLOCK_REALTIME: u64 = 0;
    match clock {
        CLOCK_REALTIME => read_timex(p, nr::clock_adjtime, "clock_adjtime", tx),
        1..=11 => Err(EOPNOTSUPP),
        _ => Err(EINVAL),
    }
}

/// The process behind a descriptor: EBADF for any that isn't a pidfd.
fn pidfd(p: &Process, fd: u64) -> Result<u32, Errno> {
    match p.fds.get(fd)?.lock().kind {
        FileKind::PidFd(pid) => Ok(pid),
        _ => Err(EBADF),
    }
}

pub fn process_mrelease(p: &mut Process, fd: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(EINVAL);
    }
    let pid = pidfd(p, fd)?;
    // Only a process that's dying has memory for this to hurry along, and
    // here that's gone by the time anyone can ask.
    if crate::procs::ended(p, pid) { Err(ESRCH) } else { Err(EINVAL) }
}

pub fn process_madvise(p: &mut Process, fd: u64, iov: u64, count: u64, advice: u64, flags: u64) -> SysResult {
    const MADV_WILLNEED: u64 = 3;
    const MADV_COLD: u64 = 20;
    const MADV_PAGEOUT: u64 = 21;
    const MADV_COLLAPSE: u64 = 25;
    const UIO_MAXIOV: u64 = 1024;
    if flags != 0 {
        return Err(EINVAL);
    }
    let pid = pidfd(p, fd)?;
    if !matches!(advice, MADV_WILLNEED | MADV_COLD | MADV_PAGEOUT | MADV_COLLAPSE) || count > UIO_MAXIOV {
        return Err(EINVAL);
    }
    if pid != p.pid {
        return Err(EPERM);
    }
    // Advice to the memory manager, and there's nowhere for pages to go to.
    let mut total = 0u64;
    for i in 0..count {
        total = total.saturating_add(read_u64(&mut p.aspace, iov + i * 16 + 8)?);
    }
    Ok(total)
}

pub fn pkey_alloc(_p: &mut Process, flags: u64, access: u64) -> SysResult {
    const ACCESS_MASK: u64 = 3;
    if flags != 0 || access & !ACCESS_MASK != 0 {
        return Err(EINVAL);
    }
    Err(crate::arch::abi::NO_PROTECTION_KEYS)
}

pub fn pkey_mprotect(p: &mut Process, addr: u64, len: u64, prot: u64, key: u64) -> SysResult {
    if key as i32 != -1 {
        return Err(EINVAL);
    }
    super::mem::mprotect(p, addr, len, prot)
}

pub fn move_pages(p: &mut Process, pid: u64, count: u64, pages: u64, nodes: u64, status: u64, flags: u64) -> SysResult {
    const MOVE: u64 = 2;
    const MOVE_ALL: u64 = 4;
    const MAX_PAGES: u64 = 1 << 24;
    if flags & !(MOVE | MOVE_ALL) != 0 || count > MAX_PAGES {
        return Err(EINVAL);
    }
    check_pid(p, pid)?;
    if flags & MOVE_ALL != 0 && p.uid != 0 {
        return Err(EPERM);
    }
    // Only the running process's memory can be looked at.
    if pid != 0 && pid != p.pid as u64 {
        return Err(EPERM);
    }
    for i in 0..count {
        if nodes != 0 && read_u32(&mut p.aspace, nodes + i * 4)? != 0 {
            return Err(ENODEV);
        }
    }
    for i in 0..count {
        let page = read_u64(&mut p.aspace, pages + i * 8)? & !(PAGE_SIZE - 1);
        let there = p.aspace.find(page).is_some() && p.aspace.pt.lookup(page).is_some();
        write_u32(&mut p.aspace, status + i * 4, if there { 0 } else { -14i32 as u32 })?;
    }
    Ok(0)
}

pub fn migrate_pages(p: &mut Process, pid: u64) -> SysResult {
    check_pid(p, pid)?;
    Ok(0)
}

pub fn set_mempolicy_home_node(start: u64, home: u64, flags: u64) -> SysResult {
    if flags != 0 || home != 0 || !start.is_multiple_of(PAGE_SIZE) {
        return Err(EINVAL);
    }
    Ok(0)
}

pub fn remap_file_pages(p: &mut Process, start: u64, size: u64, prot: u64, offset: u64) -> SysResult {
    let end = page_up(size).filter(|&s| s > 0).and_then(|s| start.checked_add(s)).ok_or(EINVAL)?;
    if prot != 0 || !start.is_multiple_of(PAGE_SIZE) {
        return Err(EINVAL);
    }
    let v = p.aspace.find(start).filter(|v| end <= v.end).ok_or(EINVAL)?;
    let Backing::SharedFile { data, ino, may_write, token, .. } = &v.backing else { return Err(EINVAL) };
    let backing = Backing::SharedFile {
        data: data.clone(),
        offset: offset.checked_mul(PAGE_SIZE).ok_or(EINVAL)?,
        ino: *ino,
        may_write: *may_write,
        token: token.clone(),
    };
    let vma = Vma::new(start, end, v.prot, backing);
    p.aspace.room_for(start, end, false, 1)?;
    p.aspace.map(vma);
    Ok(0)
}

pub fn cachestat(p: &mut Process, fd: u64, range: u64, out: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(EINVAL);
    }
    let file = p.fds.get(fd)?;
    let (off, len) = (read_u64(&mut p.aspace, range)?, read_u64(&mut p.aspace, range + 8)?);
    let f = file.lock();
    if !matches!(f.kind, FileKind::Node(_)) {
        return Err(ESPIPE);
    }
    let last = if len == 0 { u64::MAX } else { off.saturating_add(len) };
    let cached = f.content.as_ref().map_or(0, |c| c.lock().pages_in(off / PAGE_SIZE, last.div_ceil(PAGE_SIZE)));
    drop(f);
    // Nothing's dirty, written back or evicted: there's nowhere for it to go.
    let mut b = [0u8; 40];
    b[..8].copy_from_slice(&cached.to_le_bytes());
    copy_out(&mut p.aspace, out, &b)?;
    Ok(0)
}

pub fn mseal(p: &mut Process, addr: u64, len: u64, flags: u64) -> SysResult {
    if flags != 0 || !addr.is_multiple_of(PAGE_SIZE) {
        return Err(EINVAL);
    }
    let len = page_up(len).ok_or(EINVAL)?;
    if len == 0 {
        return Ok(0);
    }
    let end = addr.checked_add(len).ok_or(EINVAL)?;
    // All of it mapped, and nothing's changed if it isn't.
    if !p.aspace.all_mapped(addr, end) {
        return Err(ENOMEM);
    }
    p.aspace.room_for(addr, end, true, 0)?;
    p.aspace.set_flags(addr, end, |v| v.sealed = true);
    Ok(0)
}

/// FUTEX2_SIZE_U32 and FUTEX2_PRIVATE: 32-bit words are all Linux has.
const SIZE_MASK: u64 = 3;
const SIZE_U32: u64 = 2;
const PRIVATE: u64 = 128;
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_CLOCK_REALTIME: u64 = 256;

fn futex2_op(flags: u64) -> Result<u64, Errno> {
    if flags & SIZE_MASK != SIZE_U32 || flags & !(SIZE_MASK | PRIVATE) != 0 {
        return Err(EINVAL);
    }
    Ok(flags & PRIVATE)
}

pub fn futex_wake(p: &mut Process, uaddr: u64, mask: u64, count: u64, flags: u64) -> SysResult {
    let op = futex2_op(flags)?;
    if mask == 0 {
        return Err(EINVAL);
    }
    super::thread::futex(p, [uaddr, FUTEX_WAKE_BITSET | op, count, 0, 0, mask])
}

pub fn futex_wait(p: &mut Process, uaddr: u64, val: u64, mask: u64, flags: u64, timeout: u64, clock: u64) -> SysResult {
    const CLOCK_REALTIME: u64 = 0;
    const CLOCK_MONOTONIC: u64 = 1;
    let op = futex2_op(flags)?;
    let clock = match clock {
        _ if timeout == 0 => 0,
        CLOCK_REALTIME => FUTEX_CLOCK_REALTIME,
        CLOCK_MONOTONIC => 0,
        _ => return Err(EINVAL),
    };
    if mask == 0 {
        return Err(EINVAL);
    }
    super::thread::futex(p, [uaddr, FUTEX_WAIT_BITSET | op | clock, val, timeout, 0, mask])
}

pub fn futex_requeue(p: &mut Process, waiters: u64, flags: u64, wake: u64, requeue: u64) -> SysResult {
    if flags != 0 {
        return Err(EINVAL);
    }
    // struct futex_waitv { u64 val, u64 uaddr, u32 flags, u32 reserved }, two.
    let (val, from) = (read_u64(&mut p.aspace, waiters)?, read_u64(&mut p.aspace, waiters + 8)?);
    let to = read_u64(&mut p.aspace, waiters + 32)?;
    let op = futex2_op(read_u32(&mut p.aspace, waiters + 16)? as u64)?;
    futex2_op(read_u32(&mut p.aspace, waiters + 40)? as u64)?;
    super::thread::futex(p, [from, FUTEX_CMP_REQUEUE | op, wake, requeue, to, val])
}

pub fn lsm_list_modules(p: &mut Process, ids: u64, size: u64, flags: u64) -> SysResult {
    const CAPABILITY: u64 = 100;
    if flags != 0 {
        return Err(EINVAL);
    }
    let room = read_u32(&mut p.aspace, size)?;
    write_u32(&mut p.aspace, size, 8)?;
    if room < 8 {
        return Err(E2BIG);
    }
    write_u64(&mut p.aspace, ids, CAPABILITY)?;
    Ok(1)
}

pub fn syncfs(p: &mut Process, fd: u64) -> SysResult {
    p.fds.get(fd).map(|_| 0)
}

pub fn sync_file_range(p: &mut Process, fd: u64, off: u64, len: u64, flags: u64) -> SysResult {
    const VALID: u64 = 1 | 2 | 4;
    let file = p.fds.get(fd)?;
    if flags & !VALID != 0 || off as i64 > i64::MAX - len as i64 || (off as i64) < 0 || (len as i64) < 0 {
        return Err(EINVAL);
    }
    let f = file.lock();
    if !matches!(f.kind, FileKind::Node(_)) {
        return Err(ESPIPE);
    }
    Ok(0)
}

pub fn readahead(p: &mut Process, fd: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let f = file.lock();
    if !f.readable() {
        return Err(EBADF);
    }
    match f.kind {
        FileKind::Node(ino) if fs::lock().is_regular(ino) => Ok(0),
        _ => Err(EINVAL),
    }
}
