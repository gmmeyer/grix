//! Linux AIO (fs/aio.c): io_setup, io_destroy, io_submit, io_cancel,
//! io_getevents and io_pgetevents.
//!
//! A context is a ring in the program's memory (a shared mapping, as
//! Linux's is), laid out as Linux's `struct aio_ring` (libaio and
//! user-space reapers read it directly), whose address is the context's
//! id. io_destroy unmaps it only if it's still there: not whatever the
//! program put in its place. Reads, writes and syncs are done
//! when they're submitted: the files they reach are in memory (or a live
//! mount's, whose requests wait for the host in place), so their events
//! go into the ring at once. A request that would have to wait for a
//! pipe, socket or terminal completes with EAGAIN instead (`file::aio_rw`).
//! IOCB_CMD_POLL is the one that waits: it completes when the process
//! next makes a system call with the file ready (`complete_polls`, from
//! `syscall::handle`), which a wait in io_getevents (or epoll on its
//! eventfd) is: an I/O change re-runs it. Nothing waits in the kernel:
//! io_getevents blocks with `block_io_rerun` and re-runs (invariant 9).
//!
//! Events are only ever written into the running process's own ring (no
//! other process's memory is reachable, invariant 13), and the kernel
//! keeps only its own position in it, so a program scribbling on its ring
//! only confuses itself. Contexts are budgeted together, as Linux's
//! aio-max-nr: the events every context asked for (EAGAIN past
//! `AIO_MAX_NR`), and each context's and pending poll's kernel memory
//! (`kmem`).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::file;
use crate::errno::*;
use crate::fd::{FileKind, FileRef, O_ACCMODE, O_APPEND, O_RDONLY, O_WRONLY};
use crate::ipc;
use crate::kmem::Charge;
use crate::mm::PAGE_SIZE;
use crate::mm::aspace::{Backing, SharedPages};
use crate::mm::paging::Prot;
use crate::process::Process;
use crate::uaccess::*;

/// Linux's /proc/sys/fs/aio-max-nr default: the events all contexts
/// together may ask for.
pub const AIO_MAX_NR: u64 = 65536;
static AIO_NR: AtomicU64 = AtomicU64::new(0);

/// Events asked for now (/proc/sys/fs/aio-nr).
pub fn aio_nr() -> u64 {
    AIO_NR.load(Ordering::Relaxed)
}

// struct aio_ring's header.
const RING_HEADER: u64 = 32;
const RING_HEAD: u64 = 8;
const RING_TAIL: u64 = 12;
const AIO_RING_MAGIC: u32 = 0xa10a_10a1;
const AIO_RING_COMPAT_FEATURES: u32 = 1;
/// sizeof(struct io_event): data, obj, res, res2.
const EVENT: u64 = 32;
/// sizeof(struct iocb).
const IOCB: usize = 64;

const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;
const IOCB_CMD_FSYNC: u16 = 2;
const IOCB_CMD_FDSYNC: u16 = 3;
const IOCB_CMD_POLL: u16 = 5;
const IOCB_CMD_PREADV: u16 = 7;
const IOCB_CMD_PWRITEV: u16 = 8;
const IOCB_FLAG_RESFD: u32 = 1;
/// What io_submit writes into aio_key (Linux's KIOCB_KEY).
const KIOCB_KEY: u32 = 0;
const EINPROGRESS: Errno = Errno(115);

// The RWF_* flags a read or write may carry (preadv2's).
const RWF_HIPRI: u32 = 1;
const RWF_DSYNC: u32 = 2;
const RWF_SYNC: u32 = 4;
const RWF_NOWAIT: u32 = 8;
const RWF_APPEND: u32 = 0x10;

const POLLERR: u32 = 0x8;
const POLLHUP: u32 = 0x10;

/// A process's contexts (Linux's mm->ioctx_table): its threads share
/// them; a forked child, or a new program, has none.
#[derive(Default)]
pub struct Contexts(Vec<Ctx>);

impl Contexts {
    /// Any polls waiting for their files?
    pub fn polling(&self) -> bool {
        self.0.iter().any(|c| !c.polls.is_empty())
    }
}

struct Ctx {
    /// The ring's address, which is the context's id, and its length.
    id: u64,
    len: u64,
    /// Event slots in the ring; at most `nr - 1` events are outstanding.
    nr: u64,
    /// Where the next event goes (the ring's tail is the program's copy).
    tail: u64,
    /// What io_setup asked for, counted in `AIO_NR`.
    max_reqs: u64,
    /// The ring's pages, to know its mapping from anything the program
    /// put in its place.
    pages: alloc::sync::Weak<SharedPages>,
    polls: Vec<Poll>,
    _charge: Charge,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        AIO_NR.fetch_sub(self.max_reqs, Ordering::Relaxed);
    }
}

/// An IOCB_CMD_POLL waiting for its file.
struct Poll {
    iocb: u64,
    data: u64,
    file: FileRef,
    events: u32,
    resfd: Option<FileRef>,
    _charge: Charge,
}

fn find(p: &Process, id: u64) -> Result<usize, Errno> {
    p.aio.0.iter().position(|c| c.id == id).ok_or(EINVAL)
}

/// io_setup(nr_events, ctxp): a context for `nr_events` requests, its id
/// stored at `ctxp` (which must hold 0).
pub fn io_setup(p: &mut Process, nr_events: u64, ctxp: u64) -> SysResult {
    let requested = nr_events as u32 as u64;
    if read_u64(&mut p.aspace, ctxp)? != 0 || requested == 0 {
        return Err(EINVAL);
    }
    // As Linux's ioctx_alloc: room for twice as many (and at least 4 per
    // CPU), two more, and whatever fills the last page.
    let doubled = requested.max(4 * crate::smp::count() as u64) * 2;
    if doubled > 0x1000_0000 / EVENT {
        return Err(EINVAL);
    }
    if requested > AIO_MAX_NR || aio_nr() + requested > AIO_MAX_NR {
        return Err(EAGAIN);
    }
    let len = (RING_HEADER + (doubled + 2) * EVENT).div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let nr = (len - RING_HEADER) / EVENT;
    let charge = Charge::new((core::mem::size_of::<Ctx>() + 64) as u64)?;
    // A shared mapping, as Linux's ring is (a fork's copy is the same pages).
    let pages = alloc::sync::Arc::<SharedPages>::default();
    let weak = alloc::sync::Arc::downgrade(&pages);
    let backing = Backing::Shared { pages, index: 0, may_write: true, sysv: None };
    let id = super::mem::map_at(p, 0, len, 0, Prot::RW, backing)?;
    let index = p.aio.0.len() as u32;
    let mut header = [0u8; RING_HEADER as usize];
    for (i, v) in
        [index, nr as u32, 0, 0, AIO_RING_MAGIC, AIO_RING_COMPAT_FEATURES, 0, RING_HEADER as u32].iter().enumerate()
    {
        header[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    let ctx = Ctx { id, len, nr, tail: 0, max_reqs: requested, pages: weak, polls: Vec::new(), _charge: charge };
    AIO_NR.fetch_add(requested, Ordering::Relaxed);
    if let Err(e) = copy_out(&mut p.aspace, id, &header).and_then(|_| write_u64(&mut p.aspace, ctxp, id)) {
        drop(ctx);
        p.aspace.unmap(id, id + len);
        return Err(e);
    }
    p.aio.0.push(ctx);
    Ok(0)
}

/// io_destroy: pending polls are cancelled (their events go with the
/// ring), and the ring is unmapped, as Linux's kill_ioctx does.
pub fn io_destroy(p: &mut Process, id: u64) -> SysResult {
    let ctx = p.aio.0.remove(find(p, id)?);
    // Only if the ring is still there as io_setup mapped it: the program
    // may have unmapped it, or mapped something else over it, which isn't
    // the context's to take away (nor to split, making mappings past the
    // budget's check).
    let end = ctx.id + ctx.len;
    let ring = |v: &crate::mm::aspace::Vma| {
        v.start == ctx.id
            && v.end == end
            && matches!(&v.backing, Backing::Shared { pages, .. } if core::ptr::eq(alloc::sync::Arc::as_ptr(pages), ctx.pages.as_ptr()))
    };
    if p.aspace.find(ctx.id).is_some_and(ring) {
        p.aspace.unmap(ctx.id, end);
    }
    // A wait in io_getevents on it ends (EINVAL).
    ipc::changed();
    Ok(0)
}

/// The ring's head (where the program reads next), as a slot.
fn head(p: &mut Process, i: usize) -> Result<u64, Errno> {
    let id = p.aio.0[i].id;
    Ok(read_u32(&mut p.aspace, id + RING_HEAD)? as u64 % p.aio.0[i].nr)
}

/// Events in the ring not yet read.
fn available(p: &mut Process, i: usize) -> Result<u64, Errno> {
    let head = head(p, i)?;
    let c = &p.aio.0[i];
    Ok((c.tail + c.nr - head) % c.nr)
}

/// Put an event in context `i`'s ring and tell whoever waits: io_getevents,
/// and the request's eventfd. A ring the program unmapped or made
/// read-only loses it, as the program asked.
fn post(p: &mut Process, i: usize, iocb: u64, data: u64, res: SysResult, resfd: Option<FileRef>) {
    let res = match res {
        Ok(v) => v,
        Err(e) => (-(e.0 as i64)) as u64,
    };
    let c = &mut p.aio.0[i];
    let (id, slot) = (c.id, c.tail);
    let next = (slot + 1) % c.nr;
    let mut ev = [0u8; EVENT as usize];
    for (k, v) in [data, iocb, res, 0].iter().enumerate() {
        ev[k * 8..k * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    if copy_out(&mut p.aspace, id + RING_HEADER + slot * EVENT, &ev).is_ok() {
        // The event before the tail that shows it, for a reader on another CPU.
        core::sync::atomic::fence(Ordering::Release);
        if write_u32(&mut p.aspace, id + RING_TAIL, next as u32).is_ok() {
            p.aio.0[i].tail = next;
        }
    }
    if let Some(resfd) = resfd
        && let FileKind::EventFd(e) = &resfd.lock().kind
    {
        // Linux's eventfd_signal: add one, saturating.
        let mut ev = e.lock();
        ev.count = ev.count.saturating_add(1);
        ev.touch();
    }
    ipc::changed();
}

/// Complete every poll whose file is ready (from `syscall::handle`, and
/// the calls on a context).
pub fn complete_polls(p: &mut Process) {
    for i in 0..p.aio.0.len() {
        let mut k = 0;
        while k < p.aio.0[i].polls.len() {
            let q = &p.aio.0[i].polls[k];
            let mask = file::poll_kind(p, &q.file.lock().kind).0 & q.events;
            if mask == 0 {
                k += 1;
                continue;
            }
            let q = p.aio.0[i].polls.remove(k);
            post(p, i, q.iocb, q.data, Ok(mask as u64), q.resfd);
        }
    }
}

/// io_submit(ctx, nr, iocbpp): the number of requests submitted, or the
/// first one's error if none was.
pub fn io_submit(p: &mut Process, id: u64, nr: u64, iocbpp: u64) -> SysResult {
    if (nr as i64) < 0 {
        return Err(EINVAL);
    }
    let i = find(p, id)?;
    complete_polls(p);
    let nr = nr.min(p.aio.0[i].nr);
    for k in 0..nr {
        let r = iocbpp
            .checked_add(8 * k)
            .ok_or(EFAULT)
            .and_then(|at| read_u64(&mut p.aspace, at))
            .and_then(|iocb| submit_one(p, i, iocb));
        if let Err(e) = r {
            return if k == 0 { Err(e) } else { Ok(k) };
        }
    }
    Ok(nr)
}

fn submit_one(p: &mut Process, i: usize, iocb: u64) -> Result<(), Errno> {
    let mut b = [0u8; IOCB];
    copy_in(&mut p.aspace, iocb, &mut b)?;
    let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let (data, rw_flags, opcode, fd) = (u64_at(0), u32_at(12), u16_at(16), u32_at(20));
    let (buf, nbytes, offset, reserved2, flags, resfd) =
        (u64_at(24), u64_at(32), u64_at(40), u64_at(48), u32_at(56), u32_at(60));
    if reserved2 != 0 || (nbytes as i64) < 0 {
        return Err(EINVAL);
    }
    // Room for its event: what's in the ring and the polls still waiting.
    let c = &p.aio.0[i];
    let waiting = c.polls.len() as u64;
    if available(p, i)? + waiting >= p.aio.0[i].nr - 1 {
        return Err(EAGAIN);
    }
    let resfd = if flags & IOCB_FLAG_RESFD != 0 {
        let f = p.fds.get(resfd as u64)?;
        if !matches!(f.lock().kind, FileKind::EventFd(_)) {
            return Err(EINVAL);
        }
        Some(f)
    } else {
        None
    };
    write_u32(&mut p.aspace, iocb + 8, KIOCB_KEY)?;
    let file = p.fds.get(fd as u64)?;
    let res = match opcode {
        IOCB_CMD_PREAD | IOCB_CMD_PWRITE | IOCB_CMD_PREADV | IOCB_CMD_PWRITEV => {
            let write = matches!(opcode, IOCB_CMD_PWRITE | IOCB_CMD_PWRITEV);
            if rw_flags & !(RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND) != 0 {
                return Err(EOPNOTSUPP);
            }
            let at = {
                let f = file.lock();
                let mode = f.flags & O_ACCMODE;
                if f.path_only || mode == if write { O_RDONLY } else { O_WRONLY } {
                    return Err(EBADF);
                }
                file::seekable(&f).then_some(offset)
            };
            if at.is_some_and(|o| (o as i64) < 0) {
                return Err(EINVAL);
            }
            let bufs = if matches!(opcode, IOCB_CMD_PREAD | IOCB_CMD_PWRITE) {
                alloc::vec![(buf, nbytes)]
            } else {
                file::iovecs(p, buf, nbytes)?
            };
            let extra = if write && rw_flags & RWF_APPEND != 0 { O_APPEND } else { 0 };
            file::aio_rw(p, &file, bufs, at, write, extra)
        }
        IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => {
            if buf != 0 || offset != 0 || nbytes != 0 || rw_flags != 0 {
                return Err(EINVAL);
            }
            // Only files have a sync (Linux's f_op->fsync): not pipes or sockets.
            if !matches!(file.lock().kind, FileKind::Node(_)) {
                return Err(EINVAL);
            }
            super::file::fsync(p, fd as u64)
        }
        IOCB_CMD_POLL => {
            if buf as u16 as u64 != buf || offset != 0 || nbytes != 0 || rw_flags != 0 {
                return Err(EINVAL);
            }
            let events = buf as u32 | POLLERR | POLLHUP;
            let mask = file::poll_kind(p, &file.lock().kind).0 & events;
            if mask == 0 {
                let charge = Charge::new(core::mem::size_of::<Poll>() as u64).map_err(|_| EAGAIN)?;
                let q = Poll { iocb, data, file, events, resfd, _charge: charge };
                p.aio.0[i].polls.push(q);
                return Ok(());
            }
            Ok(mask as u64)
        }
        _ => return Err(EINVAL),
    };
    post(p, i, iocb, data, res, resfd);
    Ok(())
}

/// io_cancel: only a poll still waiting can be; its event (res 0) goes
/// into the ring and the call says EINPROGRESS, as since Linux 5.0
/// (`result` is unused). Anything already done is EINVAL.
pub fn io_cancel(p: &mut Process, id: u64, iocb: u64, _result: u64) -> SysResult {
    let i = find(p, id)?;
    if read_u32(&mut p.aspace, iocb.checked_add(8).ok_or(EFAULT)?)? != KIOCB_KEY {
        return Err(EINVAL);
    }
    let k = p.aio.0[i].polls.iter().position(|q| q.iocb == iocb).ok_or(EINVAL)?;
    let q = p.aio.0[i].polls.remove(k);
    post(p, i, q.iocb, q.data, Ok(0), q.resfd);
    Err(EINPROGRESS)
}

/// io_getevents(ctx, min_nr, nr, events, timeout) and io_pgetevents (its
/// signal mask already in place): at least `min_nr` events, at most
/// `nr`, or what there is when the timeout passes.
pub fn io_getevents(p: &mut Process, id: u64, min_nr: u64, nr: u64, events: u64, timeout: u64) -> SysResult {
    let (min_nr, nr) = (min_nr as i64, nr as i64);
    if min_nr < 0 || nr < 0 || min_nr > nr {
        return Err(EINVAL);
    }
    let timeout = if timeout == 0 { None } else { Some(read_timespec_ns(&mut p.aspace, timeout)?) };
    let i = find(p, id)?;
    complete_polls(p);
    let avail = available(p, i)?;
    let deadline = p.timeout_deadline(timeout);
    let expired = deadline.is_some_and(|d| d <= crate::time::monotonic_ns());
    if avail < min_nr as u64 && timeout != Some(0) && !expired {
        return p.block_io_rerun(deadline);
    }
    let n = avail.min(nr as u64);
    let c = &p.aio.0[i];
    let (ring, slots) = (c.id + RING_HEADER, c.nr);
    let mut head = head(p, i)?;
    let mut ev = [0u8; EVENT as usize];
    for k in 0..n {
        copy_in(&mut p.aspace, ring + head * EVENT, &mut ev)?;
        copy_out(&mut p.aspace, events + k * EVENT, &ev)?;
        head = (head + 1) % slots;
    }
    write_u32(&mut p.aspace, ring - RING_HEADER + RING_HEAD, head as u32)?;
    Ok(n)
}
