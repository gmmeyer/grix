//! System V message queues and semaphores: `msgget` and the rest, `semget`
//! and the rest (shared memory is `syscall/shm.rs`). Ids and permissions are
//! those of shared memory, and Linux's. They hold memory a program asks for,
//! so everything is charged, and counted against limits of their own: they
//! outlive whoever made them.
//!
//! A call that has to wait does as I/O does (`Process::block_io_rerun`): it
//! runs again each time anything changes, so `semop` is all or nothing by
//! never starting until all of it can go. Whoever removes something wakes
//! its waiters, and they find its id among those just gone: EIDRM, where a
//! call that comes later gets EINVAL.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

use crate::errno::*;
use crate::fs::Who;
use crate::ipc;
use crate::kmem::Charge;
use crate::process::Process;
use crate::uaccess::*;

/// Sets and queues at once, each kind, in the whole sandbox.
const MAX_OBJECTS: usize = 256;
/// As Linux's SEQ_MULTIPLIER (`shm.rs` has the why).
const SEQ_MULTIPLIER: u32 = 32768;
const MAX_SEQ: u32 = i32::MAX as u32 / SEQ_MULTIPLIER;
/// Ids told apart from ones that never were, for whoever was waiting.
const REMEMBERED: usize = 64;

const IPC_PRIVATE: u64 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: u64 = 0o4000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const IPC_64: u64 = 0x100;
/// `struct ipc64_perm`, at the start of each kind's `*id64_ds`.
const PERM_BYTES: usize = 48;

/// Who a queue or set is, and whose.
#[derive(Clone)]
struct Perm {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
}

impl Perm {
    fn new(key: i32, mode: u32, p: &Process) -> Perm {
        Perm { key, uid: p.uid, gid: p.gid, cuid: p.uid, cgid: p.gid, mode: mode & 0o777 }
    }

    /// As Linux's ipcperms.
    fn permits(&self, who: Who, want: u32) -> bool {
        if who.uid == 0 {
            return true;
        }
        let shift = if who.uid == self.uid || who.uid == self.cuid {
            6
        } else if who.in_group(self.gid) || who.in_group(self.cgid) {
            3
        } else {
            0
        };
        (self.mode >> shift) & want == want
    }

    fn owned_by(&self, uid: u32) -> bool {
        uid == 0 || uid == self.uid || uid == self.cuid
    }

    fn encode(&self, id: u32, b: &mut [u8]) {
        let words = [self.key as u32, self.uid, self.gid, self.cuid, self.cgid, self.mode];
        for (i, w) in words.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        b[24..26].copy_from_slice(&((id / SEQ_MULTIPLIER) as u16).to_le_bytes());
    }

    /// IPC_SET: the owner, group and low mode bits at the start of `b`.
    fn set_from(&mut self, b: &[u8]) {
        let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        (self.uid, self.gid) = (word(4), word(8));
        self.mode = word(20) & 0o777;
    }
}

/// Objects of one kind by id, as `shm.rs` has them.
struct Table<T> {
    by_id: BTreeMap<u32, T>,
    seq: u32,
    /// The last ones removed.
    gone: VecDeque<u32>,
}

impl<T> Table<T> {
    const fn new() -> Self {
        Table { by_id: BTreeMap::new(), seq: 0, gone: VecDeque::new() }
    }

    fn next_id(&mut self) -> Option<u32> {
        if self.by_id.len() >= MAX_OBJECTS {
            return None;
        }
        let index = (0..MAX_OBJECTS as u32).find(|i| !self.by_id.keys().any(|k| k % SEQ_MULTIPLIER == *i))?;
        self.seq = (self.seq + 1) % MAX_SEQ;
        Some(self.seq * SEQ_MULTIPLIER + index)
    }

    fn remove(&mut self, id: u32) {
        self.by_id.remove(&id);
        if self.gone.len() >= REMEMBERED {
            self.gone.pop_front();
        }
        self.gone.push_back(id);
        ipc::changed();
    }

    /// Why `id` isn't there, for a call that may have been waiting on it.
    fn missing(&self, id: u32, rerun: bool) -> Errno {
        if rerun && self.gone.contains(&id) { EIDRM } else { EINVAL }
    }
}

fn now() -> u64 {
    crate::time::realtime_ns() / 1_000_000_000
}

/// Was this thread's last call here waiting? If what it waited on is gone,
/// it's going that woke it.
fn rerun(p: &mut Process) -> bool {
    core::mem::take(&mut p.cur().waited_on_ipc)
}

/// Wait for anything to change, and run the call again.
fn wait(p: &mut Process, deadline: Option<u64>) -> SysResult {
    p.cur().waited_on_ipc = true;
    p.block_io_rerun(deadline)
}

// ---------------------------------------------------------------- queues

/// Linux's MSGMAX and MSGMNB.
const MSG_MAX: u64 = 8192;
const MSG_MNB: u64 = 16384;
/// A message's own cost, with its `Vec`.
const MESSAGE_COST: u64 = 64;
/// `struct msqid64_ds`, the same on both architectures.
const MSQID_BYTES: usize = 120;

const MSG_NOERROR: u64 = 0o10000;
const MSG_EXCEPT: u64 = 0o20000;
const MSG_INFO: u64 = 12;
const MSG_STAT: u64 = 11;
const MSG_STAT_ANY: u64 = 13;

struct Queue {
    perm: Perm,
    messages: VecDeque<(i64, Vec<u8>)>,
    bytes: u64,
    limit: u64,
    charge: Charge,
    last_send: u32,
    last_receive: u32,
    sent_at: u64,
    received_at: u64,
    changed_at: u64,
}

static QUEUES: Mutex<Table<Queue>> = Mutex::new(Table::new());

pub fn msgget(p: &mut Process, key: u64, flags: u64) -> SysResult {
    let (key, mode) = (key as i32, flags as u32);
    let mut t = QUEUES.lock();
    if key as u64 != IPC_PRIVATE {
        let found = t.by_id.iter().find(|(_, q)| q.perm.key == key).map(|(id, q)| (*id, q.perm.clone()));
        if let Some((id, perm)) = found {
            if flags & (IPC_CREAT | IPC_EXCL) == IPC_CREAT | IPC_EXCL {
                return Err(EEXIST);
            }
            if !perm.permits(p.who(), (mode >> 6) & 0o7) {
                return Err(EACCES);
            }
            return Ok(id as u64);
        }
        if flags & IPC_CREAT == 0 {
            return Err(ENOENT);
        }
    }
    let id = t.next_id().ok_or(ENOSPC)?;
    let queue = Queue {
        perm: Perm::new(key, mode, p),
        messages: VecDeque::new(),
        bytes: 0,
        limit: MSG_MNB,
        charge: Charge::default(),
        last_send: 0,
        last_receive: 0,
        sent_at: 0,
        received_at: 0,
        changed_at: now(),
    };
    t.by_id.insert(id, queue);
    Ok(id as u64)
}

pub fn msgsnd(p: &mut Process, id: u64, msgp: u64, size: u64, flags: u64) -> SysResult {
    if size > MSG_MAX || (id as i32) < 0 {
        return Err(EINVAL);
    }
    let kind = read_u64(&mut p.aspace, msgp)? as i64;
    if kind < 1 {
        return Err(EINVAL);
    }
    let mut body = Vec::new();
    body.try_reserve_exact(size as usize).map_err(|_| ENOMEM)?;
    body.resize(size as usize, 0);
    copy_in(&mut p.aspace, msgp + 8, &mut body)?;
    let again = rerun(p);
    let mut t = QUEUES.lock();
    let missing = t.missing(id as u32, again);
    let q = t.by_id.get_mut(&(id as u32)).ok_or(missing)?;
    if !q.perm.permits(p.who(), 0o2) {
        return Err(EACCES);
    }
    if q.bytes + size > q.limit || q.messages.len() as u64 >= q.limit {
        if flags & IPC_NOWAIT != 0 {
            return Err(EAGAIN);
        }
        drop(t);
        return wait(p, None);
    }
    // What the queue keeps is its slots, as many as it's ever needed until
    // it's next empty, not the messages in them, so that's what it pays
    // for, and first: a thousand of them is a big allocation.
    let slots = match q.messages.capacity() {
        full if full == q.messages.len() => (full * 2).max(8),
        room => room,
    };
    q.charge.resize(q.bytes + size + slots as u64 * MESSAGE_COST).map_err(|_| ENOMEM)?;
    q.messages.try_reserve_exact(slots - q.messages.len()).map_err(|_| ENOMEM)?;
    q.bytes += size;
    q.messages.push_back((kind, body));
    (q.last_send, q.sent_at) = (p.pid, now());
    drop(t);
    ipc::changed();
    Ok(0)
}

/// Where the message `kind` and `flags` ask for is.
fn pick(q: &Queue, kind: i64, flags: u64) -> Option<usize> {
    let mut m = q.messages.iter().enumerate();
    if kind == 0 {
        m.next().map(|(i, _)| i)
    } else if kind < 0 {
        // The lowest type up to -kind, the first of those.
        m.filter(|(_, (t, _))| *t <= -kind).min_by_key(|(i, (t, _))| (*t, *i)).map(|(i, _)| i)
    } else if flags & MSG_EXCEPT != 0 {
        m.find(|(_, (t, _))| *t != kind).map(|(i, _)| i)
    } else {
        m.find(|(_, (t, _))| *t == kind).map(|(i, _)| i)
    }
}

pub fn msgrcv(p: &mut Process, id: u64, msgp: u64, size: u64, kind: u64, flags: u64) -> SysResult {
    if (size as i64) < 0 || (id as i32) < 0 {
        return Err(EINVAL);
    }
    let again = rerun(p);
    let mut t = QUEUES.lock();
    let missing = t.missing(id as u32, again);
    let q = t.by_id.get_mut(&(id as u32)).ok_or(missing)?;
    if !q.perm.permits(p.who(), 0o4) {
        return Err(EACCES);
    }
    let Some(i) = pick(q, kind as i64, flags) else {
        if flags & IPC_NOWAIT != 0 {
            return Err(ENOMSG);
        }
        drop(t);
        return wait(p, None);
    };
    let (mtype, ref body) = q.messages[i];
    if body.len() as u64 > size && flags & MSG_NOERROR == 0 {
        return Err(E2BIG);
    }
    let n = (body.len() as u64).min(size) as usize;
    let mut out = Vec::new();
    out.try_reserve_exact(n + 8).map_err(|_| ENOMEM)?;
    out.extend_from_slice(&mtype.to_le_bytes());
    out.extend_from_slice(&body[..n]);
    drop(t);
    // Written before it's taken: a bad pointer loses nothing, as on Linux.
    copy_out(&mut p.aspace, msgp, &out)?;
    let mut t = QUEUES.lock();
    if let Some(q) = t.by_id.get_mut(&(id as u32))
        && let Some(i) = pick(q, kind as i64, flags)
    {
        let body = q.messages.remove(i).map(|(_, b)| b).unwrap_or_default();
        q.bytes -= body.len() as u64;
        (q.last_receive, q.received_at) = (p.pid, now());
        if q.messages.is_empty() {
            q.messages = VecDeque::new();
        }
        let _ = q.charge.resize(q.bytes + q.messages.capacity() as u64 * MESSAGE_COST);
    }
    drop(t);
    ipc::changed();
    Ok(n as u64)
}

pub fn msgctl(p: &mut Process, id: u64, cmd: u64, buf: u64) -> SysResult {
    let cmd = cmd & !IPC_64;
    let mut t = QUEUES.lock();
    match cmd {
        IPC_INFO | MSG_INFO => {
            // struct msginfo: msgpool, msgmap, msgmax, msgmnb, msgmni,
            // msgssz, msgtql, msgseg.
            let (held, count): (u64, u64) =
                t.by_id.values().fold((0, 0), |(h, c), q| (h + q.bytes, c + q.messages.len() as u64));
            let words: [u32; 8] = if cmd == IPC_INFO {
                [32000, 32000, MSG_MAX as u32, MSG_MNB as u32, MAX_OBJECTS as u32, 16, 32000, 0xffff]
            } else {
                [
                    t.by_id.len() as u32,
                    count as u32,
                    MSG_MAX as u32,
                    MSG_MNB as u32,
                    MAX_OBJECTS as u32,
                    16,
                    held as u32,
                    0xffff,
                ]
            };
            let mut b = [0u8; 32];
            for (i, w) in words.iter().enumerate() {
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            let highest = t.by_id.keys().map(|k| k % SEQ_MULTIPLIER).max().unwrap_or(0);
            drop(t);
            copy_out(&mut p.aspace, buf, &b)?;
            return Ok(highest as u64);
        }
        IPC_STAT | IPC_SET | IPC_RMID | MSG_STAT | MSG_STAT_ANY => {}
        _ => return Err(EINVAL),
    }
    let id = match cmd {
        MSG_STAT | MSG_STAT_ANY => *t.by_id.keys().find(|k| (*k % SEQ_MULTIPLIER) as u64 == id).ok_or(EINVAL)?,
        _ => id as u32,
    };
    let q = t.by_id.get_mut(&id).ok_or(EINVAL)?;
    match cmd {
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            if cmd != MSG_STAT_ANY && !q.perm.permits(p.who(), 0o4) {
                return Err(EACCES);
            }
            let mut b = [0u8; MSQID_BYTES];
            q.perm.encode(id, &mut b);
            let longs = [q.sent_at, q.received_at, q.changed_at, q.bytes, q.messages.len() as u64, q.limit];
            for (i, v) in longs.iter().enumerate() {
                let at = PERM_BYTES + i * 8;
                b[at..at + 8].copy_from_slice(&v.to_le_bytes());
            }
            b[96..100].copy_from_slice(&q.last_send.to_le_bytes());
            b[100..104].copy_from_slice(&q.last_receive.to_le_bytes());
            drop(t);
            copy_out(&mut p.aspace, buf, &b)?;
            Ok(if cmd == IPC_STAT { 0 } else { id as u64 })
        }
        IPC_SET => {
            if !q.perm.owned_by(p.uid) {
                return Err(EPERM);
            }
            let mut b = [0u8; MSQID_BYTES];
            drop(t);
            copy_in(&mut p.aspace, buf, &mut b)?;
            let mut t = QUEUES.lock();
            let q = t.by_id.get_mut(&id).ok_or(EINVAL)?;
            let limit = u64::from_le_bytes(b[88..96].try_into().unwrap());
            if limit > MSG_MNB && p.uid != 0 {
                return Err(EPERM);
            }
            q.perm.set_from(&b);
            q.limit = limit;
            q.changed_at = now();
            drop(t);
            ipc::changed();
            Ok(0)
        }
        _ => {
            if !q.perm.owned_by(p.uid) {
                return Err(EPERM);
            }
            t.remove(id);
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------- semaphores

/// Linux's SEMMSL, SEMOPM and SEMVMX.
const SEM_MSL: u64 = 32000;
const SEM_OPM: u64 = 500;
const SEM_VMX: i32 = 32767;
/// What a semaphore costs, with its share of the rest.
const SEMAPHORE_COST: u64 = 16;

const SEM_UNDO: u16 = 0x1000;
const GETPID: u64 = 11;
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const GETNCNT: u64 = 14;
const GETZCNT: u64 = 15;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;
const SEM_STAT: u64 = 18;
const SEM_INFO: u64 = 19;
const SEM_STAT_ANY: u64 = 20;

#[derive(Clone, Copy)]
struct Semaphore {
    value: u16,
    last: u32,
}

/// Who's waiting on what: thread, semaphore, and for zero or for more.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Waiter {
    pid: u32,
    tid: u32,
    num: u16,
    zero: bool,
}

struct Set {
    perm: Perm,
    values: Vec<Semaphore>,
    waiters: Vec<Waiter>,
    _charge: Charge,
    op_at: u64,
    changed_at: u64,
}

static SETS: Mutex<Table<Set>> = Mutex::new(Table::new());

/// Each process's SEM_UNDO adjustments, by (set, semaphore): what a process
/// did that ends with it. Kept here, as they're only about sets: the
/// process's own record is just that it has any (`Process::sem_undo`).
static UNDO: Mutex<BTreeMap<(u32, u32, u16), i32>> = Mutex::new(BTreeMap::new());
/// As many as there are semaphores, in the worst case of one process.
const MAX_UNDO: usize = 4096;

pub fn semget(p: &mut Process, key: u64, count: u64, flags: u64) -> SysResult {
    let (key, mode) = (key as i32, flags as u32);
    let count = count as i32;
    let mut t = SETS.lock();
    if key as u64 != IPC_PRIVATE {
        let found = t.by_id.iter().find(|(_, s)| s.perm.key == key);
        let found = found.map(|(id, s)| (*id, s.perm.clone(), s.values.len()));
        if let Some((id, perm, have)) = found {
            if flags & (IPC_CREAT | IPC_EXCL) == IPC_CREAT | IPC_EXCL {
                return Err(EEXIST);
            }
            if !perm.permits(p.who(), (mode >> 6) & 0o7) {
                return Err(EACCES);
            }
            if count < 0 || count as usize > have {
                return Err(EINVAL);
            }
            return Ok(id as u64);
        }
        if flags & IPC_CREAT == 0 {
            return Err(ENOENT);
        }
    }
    if count <= 0 || count as u64 > SEM_MSL {
        return Err(EINVAL);
    }
    let charge = Charge::new(count as u64 * SEMAPHORE_COST).map_err(|_| ENOSPC)?;
    let id = t.next_id().ok_or(ENOSPC)?;
    let mut values = Vec::new();
    values.try_reserve_exact(count as usize).map_err(|_| ENOSPC)?;
    values.resize(count as usize, Semaphore { value: 0, last: 0 });
    let set = Set {
        perm: Perm::new(key, mode, p),
        values,
        waiters: Vec::new(),
        _charge: charge,
        op_at: 0,
        changed_at: now(),
    };
    t.by_id.insert(id, set);
    Ok(id as u64)
}

pub fn semtimedop(p: &mut Process, id: u64, ops: u64, count: u64, timeout: u64, timed: bool) -> SysResult {
    const OP_BYTES: u64 = 6;
    if count == 0 || (id as i32) < 0 {
        return Err(EINVAL);
    }
    if count > SEM_OPM {
        return Err(E2BIG);
    }
    let mut raw = alloc::vec![0u8; (count * OP_BYTES) as usize];
    copy_in(&mut p.aspace, ops, &mut raw)?;
    let op: Vec<(u16, i16, u16)> = raw
        .chunks(OP_BYTES as usize)
        .map(|b| {
            let word = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
            (word(0), word(2) as i16, word(4))
        })
        .collect();
    // A deadline of its first run, kept through the runs after it.
    let ns = if timed && timeout != 0 { Some(read_timespec_ns(&mut p.aspace, timeout)?) } else { None };
    let deadline = p.timeout_deadline(ns);
    let again = rerun(p);
    let mut t = SETS.lock();
    let missing = t.missing(id as u32, again);
    let set = t.by_id.get_mut(&(id as u32)).ok_or(missing)?;
    if op.iter().any(|(n, ..)| *n as usize >= set.values.len()) {
        return Err(EFBIG);
    }
    let want = if op.iter().any(|(_, o, _)| *o != 0) { 0o2 } else { 0o4 };
    if !set.perm.permits(p.who(), want) {
        return Err(EACCES);
    }
    let (pid, tid) = (p.pid, p.cur().tid);
    set.waiters.retain(|w| (w.pid, w.tid) != (pid, tid));
    // All of it against a copy, so nothing's changed if any of it can't go.
    let mut values: Vec<(u16, i32)> = op.iter().map(|(n, ..)| (*n, -1)).collect();
    for (i, (n, _, _)) in op.iter().enumerate() {
        values[i].1 = set.values[*n as usize].value as i32;
    }
    let value_of = |values: &[(u16, i32)], n: u16| values.iter().find(|(m, _)| *m == n).map_or(0, |(_, v)| *v);
    for &(n, change, flags) in &op {
        let v = value_of(&values, n);
        let next = v + change as i32;
        if next > SEM_VMX {
            return Err(ERANGE);
        }
        if next < 0 || (change == 0 && v != 0) {
            if flags as u64 & IPC_NOWAIT != 0 {
                return Err(EAGAIN);
            }
            set.waiters.push(Waiter { pid, tid, num: n, zero: change == 0 });
            drop(t);
            if deadline.is_some_and(|d| crate::time::monotonic_ns() >= d) {
                return Err(EAGAIN);
            }
            return wait(p, deadline);
        }
        for (m, value) in values.iter_mut() {
            if *m == n {
                *value = next;
            }
        }
    }
    {
        let mut undo = UNDO.lock();
        for &(n, change, flags) in &op {
            if flags & SEM_UNDO != 0 && change != 0 {
                if undo.len() >= MAX_UNDO {
                    return Err(ENOMEM);
                }
                let e = undo.entry((pid, id as u32, n)).or_insert(0);
                *e -= change as i32;
                p.sem_undo = true;
            }
        }
    }
    for (n, v) in values {
        let s = &mut set.values[n as usize];
        s.value = v as u16;
        s.last = pid;
    }
    set.op_at = now();
    drop(t);
    ipc::changed();
    Ok(0)
}

/// How many of `set`'s waiters are still waiting on `num` (for zero, or for
/// more): one that a signal took away isn't, and doesn't say so.
fn waiting(p: &Process, set: &mut Set, num: u16, zero: bool) -> u64 {
    let procs = crate::procs::PROCS.lock();
    set.waiters.retain(|w| {
        let q: Option<&Process> = if w.pid == p.pid { Some(p) } else { procs.others.get(&w.pid).map(|q| &**q) };
        q.and_then(|q| q.threads.get(&w.tid)).is_some_and(|t| t.wait.is_some())
    });
    set.waiters.iter().filter(|w| w.num == num && w.zero == zero).count() as u64
}

pub fn semctl(p: &mut Process, id: u64, num: u64, cmd: u64, arg: u64) -> SysResult {
    let cmd = cmd & !IPC_64;
    let num = num as u32 as usize;
    let mut t = SETS.lock();
    if matches!(cmd, IPC_INFO | SEM_INFO) {
        // struct seminfo: semmap, semmni, semmns, semmnu, semmsl, semopm,
        // semume, semusz, semvmx, semaem.
        let total: u64 = t.by_id.values().map(|s| s.values.len() as u64).sum();
        let (used, more) = if cmd == SEM_INFO { (t.by_id.len() as u32, total as u32) } else { (32000, 1024000000) };
        let words =
            [used, MAX_OBJECTS as u32, more, 32000, SEM_MSL as u32, SEM_OPM as u32, 500, 20, SEM_VMX as u32, 32767];
        let mut b = [0u8; 40];
        for (i, w) in words.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let highest = t.by_id.keys().map(|k| k % SEQ_MULTIPLIER).max().unwrap_or(0);
        drop(t);
        copy_out(&mut p.aspace, arg, &b)?;
        return Ok(highest as u64);
    }
    let id = match cmd {
        SEM_STAT | SEM_STAT_ANY => *t.by_id.keys().find(|k| (*k % SEQ_MULTIPLIER) as u64 == id).ok_or(EINVAL)?,
        _ if (id as i32) < 0 => return Err(EINVAL),
        _ => id as u32,
    };
    let set = t.by_id.get_mut(&id).ok_or(EINVAL)?;
    let count = set.values.len();
    let one = |set: &Set| set.values.get(num).copied().ok_or(EINVAL);
    match cmd {
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            if cmd != SEM_STAT_ANY && !set.perm.permits(p.who(), 0o4) {
                return Err(EACCES);
            }
            use crate::arch::abi::{SEMID_BYTES, SEMID_CTIME, SEMID_NSEMS, SEMID_OTIME};
            let mut b = [0u8; SEMID_BYTES];
            set.perm.encode(id, &mut b);
            b[SEMID_OTIME..SEMID_OTIME + 8].copy_from_slice(&set.op_at.to_le_bytes());
            b[SEMID_CTIME..SEMID_CTIME + 8].copy_from_slice(&set.changed_at.to_le_bytes());
            b[SEMID_NSEMS..SEMID_NSEMS + 8].copy_from_slice(&(count as u64).to_le_bytes());
            drop(t);
            copy_out(&mut p.aspace, arg, &b)?;
            Ok(if cmd == IPC_STAT { 0 } else { id as u64 })
        }
        GETVAL | GETPID | GETNCNT | GETZCNT => {
            if !set.perm.permits(p.who(), 0o4) {
                return Err(EACCES);
            }
            let s = one(set)?;
            match cmd {
                GETVAL => Ok(s.value as u64),
                GETPID => Ok(s.last as u64),
                _ => Ok(waiting(p, set, num as u16, cmd == GETZCNT)),
            }
        }
        GETALL => {
            if !set.perm.permits(p.who(), 0o4) {
                return Err(EACCES);
            }
            let out: Vec<u8> = set.values.iter().flat_map(|s| s.value.to_le_bytes()).collect();
            drop(t);
            copy_out(&mut p.aspace, arg, &out)?;
            Ok(0)
        }
        SETVAL => {
            if !set.perm.permits(p.who(), 0o2) {
                return Err(EACCES);
            }
            one(set)?;
            let value = arg as i32;
            if !(0..=SEM_VMX).contains(&value) {
                return Err(ERANGE);
            }
            let s = &mut set.values[num];
            (s.value, s.last) = (value as u16, p.pid);
            set.changed_at = now();
            drop(t);
            UNDO.lock().retain(|(_, set_id, n), _| (*set_id, *n as usize) != (id, num));
            ipc::changed();
            Ok(0)
        }
        SETALL => {
            if !set.perm.permits(p.who(), 0o2) {
                return Err(EACCES);
            }
            drop(t);
            let mut raw = alloc::vec![0u8; count * 2];
            copy_in(&mut p.aspace, arg, &mut raw)?;
            let values: Vec<u16> = raw.chunks(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
            if values.iter().any(|&v| v as i32 > SEM_VMX) {
                return Err(ERANGE);
            }
            let mut t = SETS.lock();
            let set = t.by_id.get_mut(&id).ok_or(EINVAL)?;
            for (s, v) in set.values.iter_mut().zip(values) {
                (s.value, s.last) = (v, p.pid);
            }
            set.changed_at = now();
            drop(t);
            UNDO.lock().retain(|(_, set_id, _), _| *set_id != id);
            ipc::changed();
            Ok(0)
        }
        IPC_SET => {
            if !set.perm.owned_by(p.uid) {
                return Err(EPERM);
            }
            let mut b = [0u8; PERM_BYTES];
            drop(t);
            copy_in(&mut p.aspace, arg, &mut b)?;
            let mut t = SETS.lock();
            let set = t.by_id.get_mut(&id).ok_or(EINVAL)?;
            set.perm.set_from(&b);
            set.changed_at = now();
            Ok(0)
        }
        IPC_RMID => {
            if !set.perm.owned_by(p.uid) {
                return Err(EPERM);
            }
            t.remove(id);
            drop(t);
            UNDO.lock().retain(|(_, set_id, _), _| *set_id != id);
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Process `pid` ended: what it did with SEM_UNDO goes back, as far as that
/// can without a value going below zero.
pub fn process_ended(pid: u32) {
    let mut undo = UNDO.lock();
    let mine: Vec<_> = undo.iter().filter(|((who, ..), _)| *who == pid).map(|(k, v)| (*k, *v)).collect();
    if mine.is_empty() {
        return;
    }
    undo.retain(|(who, ..), _| *who != pid);
    drop(undo);
    let mut t = SETS.lock();
    for ((_, id, num), adjust) in mine {
        if let Some(s) = t.by_id.get_mut(&id).and_then(|set| set.values.get_mut(num as usize)) {
            s.value = (s.value as i32 + adjust).clamp(0, SEM_VMX) as u16;
            s.last = pid;
        }
    }
    drop(t);
    ipc::changed();
}
