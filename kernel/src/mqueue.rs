//! POSIX message queues: `mq_open` and the rest. A queue has a name of its
//! own, in a table here as there's no /dev/mqueue, and a descriptor of one
//! is a file that polls, as Linux's are. They outlive who made them, so
//! they're counted, and what they hold is charged.
//!
//! A call that has to wait does as I/O does (`Process::block_io_rerun`).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::errno::*;
use crate::fd::{FdEntry, FileKind, new_file};
use crate::ipc::{self, EPOLLIN, EPOLLOUT};
use crate::kmem::Charge;
use crate::process::Process;
use crate::signal::{self, SigInfo, Target};
use crate::uaccess::*;

/// Linux's /proc/sys/fs/mqueue: queues_max, msg_default (and msg_max),
/// msgsize_default (and msgsize_max); what root may ask for past them.
const MAX_QUEUES: usize = 256;
const DEFAULT_MESSAGES: u64 = 10;
const DEFAULT_SIZE: u64 = 8192;
const HARD_MESSAGES: u64 = 65536;
const HARD_SIZE: u64 = 16 << 20;
const PRIO_MAX: u64 = 32768;
const NAME_MAX: usize = 255;
/// A message's own cost, with its `Vec` and place in the list.
const MESSAGE_COST: u64 = 96;
/// What a queue costs before anything's in it.
const QUEUE_COST: u64 = 256;

const O_ACCMODE: u32 = 3;
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: u32 = 0o4000;

const SIGEV_SIGNAL: u32 = 0;
const SIGEV_NONE: u32 = 1;
const SIGEV_THREAD: u32 = 2;
const SI_MESGQ: i32 = -3;
const ETIMEDOUT: Errno = Errno(110);
const EMSGSIZE: Errno = Errno(90);

/// Who's told when an empty queue gets a message, once.
pub struct Notify {
    pid: u32,
    signal: u32,
    value: u64,
    /// SIGEV_THREAD: libc's netlink socket and its cookie (its own
    /// thread does the rest), told of this or of its being taken back.
    thread: Option<(crate::fd::FileRef, [u8; COOKIE])>,
}

const COOKIE: usize = 32;
const NOTIFY_WOKENUP: u8 = 1;
const NOTIFY_REMOVED: u8 = 2;

impl Notify {
    /// The cookie, its last byte saying why. Lost if there's no memory for
    /// it, as Linux's netlink_sendskb is, or the socket has no room.
    fn tell_thread(self, why: u8) {
        let Some((sock, mut cookie)) = self.thread else { return };
        cookie[COOKIE - 1] = why;
        let mut f = sock.lock();
        if let FileKind::Netlink(nl) = &mut f.kind {
            nl.deliver(&cookie);
        }
        drop(f);
        ipc::changed();
    }
}

pub struct Queue {
    uid: u32,
    gid: u32,
    mode: u32,
    max_messages: u64,
    max_size: u64,
    /// By priority, highest first, and then oldest first.
    messages: BTreeMap<(u32, u64), Vec<u8>>,
    next: u64,
    bytes: u64,
    _queue: Charge,
    charge: Charge,
    notify: Option<Notify>,
    /// Threads waiting to receive: a message for them is no one's news.
    receivers: Vec<(u32, u32)>,
    version: u64,
}

pub type QueueRef = Arc<Mutex<Queue>>;

impl Queue {
    fn touch(&mut self) {
        self.version += 1;
        ipc::changed();
    }

    fn permits(&self, p: &Process, want: u32) -> bool {
        if p.uid == 0 {
            return true;
        }
        let shift = if p.uid == self.uid {
            6
        } else if p.who().in_group(self.gid) {
            3
        } else {
            0
        };
        (self.mode >> shift) & want == want
    }

    pub fn poll(&self) -> (u32, u64) {
        let readable = if self.messages.is_empty() { 0 } else { EPOLLIN };
        let writable = if (self.messages.len() as u64) < self.max_messages { EPOLLOUT } else { 0 };
        (readable | writable, self.version)
    }

    /// What reading a descriptor of it says, as Linux's mqueue file does.
    pub fn status(&self) -> String {
        let (signal, pid) = self.notify.as_ref().map_or((0, 0), |n| (n.signal, n.pid));
        alloc::format!("QSIZE:{:<10} NOTIFY:{:<5} SIGNO:{:<5} NOTIFY_PID:{:<6}\n", self.bytes, 0, signal, pid)
    }

    pub fn mode(&self) -> u32 {
        self.mode
    }

    pub fn owner(&self) -> (u32, u32) {
        (self.uid, self.gid)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// A descriptor of it was closed by `pid`: its notification goes.
    /// (Which the caller tells, with no queue held.)
    pub fn closed_by(&mut self, pid: u32) -> Option<Notify> {
        self.notify.take_if(|n| n.pid == pid)
    }
}

static NAMES: Mutex<BTreeMap<String, QueueRef>> = Mutex::new(BTreeMap::new());

fn read_name(p: &mut Process, name: u64) -> Result<String, Errno> {
    let name = read_cstr(&mut p.aspace, name, NAME_MAX + 2)?;
    match name.as_str() {
        "" => Err(ENOENT),
        "." | ".." => Err(EINVAL),
        n if n.len() > NAME_MAX => Err(ENAMETOOLONG),
        n if n.contains('/') => Err(EACCES),
        _ => Ok(name),
    }
}

/// What to make a queue with: `struct mq_attr`'s mq_maxmsg and mq_msgsize,
/// the system's defaults without one.
fn read_attr(p: &mut Process, attr: u64) -> Result<(u64, u64), Errno> {
    if attr == 0 {
        return Ok((DEFAULT_MESSAGES, DEFAULT_SIZE));
    }
    let (messages, size) = (read_u64(&mut p.aspace, attr + 8)?, read_u64(&mut p.aspace, attr + 16)?);
    if messages as i64 <= 0 || size as i64 <= 0 {
        return Err(EINVAL);
    }
    let limits = if p.uid == 0 { (HARD_MESSAGES, HARD_SIZE) } else { (DEFAULT_MESSAGES, DEFAULT_SIZE) };
    if messages > limits.0 || size > limits.1 { Err(EINVAL) } else { Ok((messages, size)) }
}

pub fn mq_open(p: &mut Process, name: u64, flags: u64, mode: u64, attr: u64) -> SysResult {
    let name = read_name(p, name)?;
    let access = flags as u32 & O_ACCMODE;
    if access == 3 {
        return Err(EINVAL);
    }
    let mut names = NAMES.lock();
    let queue = match names.get(&name) {
        Some(q) => {
            if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                return Err(EEXIST);
            }
            q.clone()
        }
        None if flags & O_CREAT == 0 => return Err(ENOENT),
        None => {
            drop(names);
            let (max_messages, max_size) = read_attr(p, attr)?;
            names = NAMES.lock();
            if names.len() >= MAX_QUEUES {
                return Err(ENOSPC);
            }
            let umask = p.fs.get().umask;
            let queue = Queue {
                uid: p.uid,
                gid: p.gid,
                mode: mode as u32 & !umask & 0o777,
                max_messages,
                max_size,
                messages: BTreeMap::new(),
                next: 0,
                bytes: 0,
                _queue: Charge::new(QUEUE_COST).map_err(|_| ENOMEM)?,
                charge: Charge::default(),
                notify: None,
                receivers: Vec::new(),
                version: 0,
            };
            let queue = Arc::new(Mutex::new(queue));
            names.insert(name, queue.clone());
            drop(names);
            let file = new_file(FileKind::Mqueue(queue), access | (flags as u32 & O_NONBLOCK));
            return p.fds.alloc(FdEntry { file, cloexec: true }, 0);
        }
    };
    drop(names);
    let want = match access {
        O_RDONLY => 0o4,
        O_WRONLY => 0o2,
        O_RDWR => 0o6,
        _ => return Err(EINVAL),
    };
    if !queue.lock().permits(p, want) {
        return Err(EACCES);
    }
    let file = new_file(FileKind::Mqueue(queue), access | (flags as u32 & O_NONBLOCK));
    p.fds.alloc(FdEntry { file, cloexec: true }, 0)
}

pub fn mq_unlink(p: &mut Process, name: u64) -> SysResult {
    let name = read_name(p, name)?;
    let mut names = NAMES.lock();
    let q = names.get(&name).ok_or(ENOENT)?;
    if p.uid != 0 && q.lock().uid != p.uid {
        return Err(EACCES);
    }
    names.remove(&name);
    Ok(0)
}

/// The queue behind `fd`, and whether it's not to wait: EBADF for anything
/// else, or a descriptor not open the way it's needed.
fn queue_of(p: &Process, fd: u64, read: bool) -> Result<(QueueRef, bool), Errno> {
    let file = p.fds.get(fd)?;
    let f = file.lock();
    let FileKind::Mqueue(q) = &f.kind else { return Err(EBADF) };
    if !(if read { f.readable() } else { f.writable() }) {
        return Err(EBADF);
    }
    Ok((q.clone(), f.flags & O_NONBLOCK != 0))
}

/// An absolute CLOCK_REALTIME timeout, as these calls have it: its time in
/// ns, or None for none.
fn read_timeout(p: &mut Process, at: u64) -> Result<Option<u64>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    read_timespec_ns(&mut p.aspace, at).map(Some)
}

/// It can't go yet: give up, or wait.
fn wait(p: &mut Process, nonblock: bool, abs: Option<u64>) -> SysResult {
    if nonblock {
        return Err(EAGAIN);
    }
    let now = crate::time::realtime_ns();
    let left = match abs {
        Some(at) if at <= now => return Err(ETIMEDOUT),
        Some(at) => Some(at - now),
        None => None,
    };
    let deadline = p.timeout_deadline(left);
    p.block_io_rerun(deadline)
}

pub fn mq_timedsend(p: &mut Process, fd: u64, msg: u64, len: u64, prio: u64, timeout: u64) -> SysResult {
    if prio >= PRIO_MAX {
        return Err(EINVAL);
    }
    let abs = read_timeout(p, timeout)?;
    let (q, nonblock) = queue_of(p, fd, false)?;
    let g = q.lock();
    if len > g.max_size {
        return Err(EMSGSIZE);
    }
    if g.messages.len() as u64 >= g.max_messages {
        drop(g);
        return wait(p, nonblock, abs);
    }
    drop(g);
    let mut data = Vec::new();
    data.try_reserve_exact(len as usize).map_err(|_| ENOMEM)?;
    data.resize(len as usize, 0);
    copy_in(&mut p.aspace, msg, &mut data)?;
    let mut g = q.lock();
    let held = g.bytes + len + (g.messages.len() as u64 + 1) * MESSAGE_COST;
    g.charge.resize(held).map_err(|_| ENOMEM)?;
    let was_empty = g.messages.is_empty();
    let seq = g.next;
    g.next += 1;
    g.bytes += len;
    g.messages.insert((u32::MAX - prio as u32, seq), data);
    let notify = if was_empty && !someone_receiving(&mut g, p) { g.notify.take() } else { None };
    g.touch();
    drop(g);
    if let Some(n) = notify {
        tell(p, n);
    }
    Ok(0)
}

/// Is a thread waiting to receive? A signal may have taken one away, which
/// nothing says.
fn someone_receiving(q: &mut Queue, p: &Process) -> bool {
    let procs = crate::procs::PROCS.lock();
    q.receivers.retain(|&(pid, tid)| {
        let who: Option<&Process> = if pid == p.pid { Some(p) } else { procs.others.get(&pid).map(|q| &**q) };
        who.and_then(|q| q.threads.get(&tid)).is_some_and(|t| t.wait.is_some())
    });
    !q.receivers.is_empty()
}

/// A notification taken back, by closing or by mq_notify.
pub fn removed(n: Option<Notify>) {
    if let Some(n) = n {
        n.tell_thread(NOTIFY_REMOVED);
    }
}

/// A message came for whoever asked to hear of it.
fn tell(p: &mut Process, n: Notify) {
    if n.thread.is_some() {
        return n.tell_thread(NOTIFY_WOKENUP);
    }
    if n.signal == 0 {
        return;
    }
    let mut info = SigInfo::sent(n.signal, SI_MESGQ, p.pid, p.uid, "a message for a queue");
    info.fields[1] = n.value;
    if n.pid == p.pid {
        let _ = signal::send(p, Target::Process, info);
    } else if let Some(q) = crate::procs::PROCS.lock().others.get_mut(&n.pid) {
        let _ = signal::send(q, Target::Process, info);
    }
}

pub fn mq_timedreceive(p: &mut Process, fd: u64, msg: u64, len: u64, prio: u64, timeout: u64) -> SysResult {
    let abs = read_timeout(p, timeout)?;
    let (q, nonblock) = queue_of(p, fd, true)?;
    let (pid, tid) = (p.pid, p.cur().tid);
    let mut g = q.lock();
    if len < g.max_size {
        return Err(EMSGSIZE);
    }
    g.receivers.retain(|&w| w != (pid, tid));
    let Some(key) = g.messages.keys().next().copied() else {
        if !nonblock {
            g.receivers.push((pid, tid));
        }
        drop(g);
        return wait(p, nonblock, abs);
    };
    let data = g.messages.get(&key).cloned().unwrap_or_default();
    drop(g);
    // Copied before it's taken: a bad pointer loses nothing.
    copy_out(&mut p.aspace, msg, &data)?;
    if prio != 0 {
        write_u32(&mut p.aspace, prio, u32::MAX - key.0)?;
    }
    let mut g = q.lock();
    if g.messages.remove(&key).is_some() {
        g.bytes -= data.len() as u64;
        let held = g.bytes + g.messages.len() as u64 * MESSAGE_COST;
        let _ = g.charge.resize(held);
    }
    g.touch();
    Ok(data.len() as u64)
}

pub fn mq_notify(p: &mut Process, fd: u64, event: u64) -> SysResult {
    let file = p.fds.get(fd)?;
    let q = match &file.lock().kind {
        FileKind::Mqueue(q) => q.clone(),
        _ => return Err(EBADF),
    };
    let pid = p.pid;
    if event == 0 {
        let was = q.lock().closed_by(pid);
        removed(was);
        return Ok(0);
    }
    // struct sigevent: sigev_value, sigev_signo, sigev_notify.
    let value = read_u64(&mut p.aspace, event)?;
    let signal = read_u32(&mut p.aspace, event + 8)?;
    let how = read_u32(&mut p.aspace, event + 12)?;
    let mut thread = None;
    let signal = match how {
        SIGEV_NONE => 0,
        SIGEV_SIGNAL if (1..=64).contains(&signal) => signal,
        SIGEV_THREAD => {
            let mut cookie = [0; COOKIE];
            copy_in(&mut p.aspace, value, &mut cookie)?;
            let sock = p.fds.get(signal as u64)?;
            let f = sock.lock();
            match f.kind {
                FileKind::Netlink(_) => {}
                _ if f.is_socket() => return Err(EINVAL),
                _ => return Err(Errno(88)), // ENOTSOCK
            }
            drop(f);
            thread = Some((sock, cookie));
            0
        }
        _ => return Err(EINVAL),
    };
    let mut g = q.lock();
    if g.notify.is_some() {
        return Err(EBUSY);
    }
    g.notify = Some(Notify { pid, signal, value, thread });
    g.touch();
    Ok(0)
}

pub fn mq_getsetattr(p: &mut Process, fd: u64, new: u64, old: u64) -> SysResult {
    let set = if new != 0 {
        let flags = read_u64(&mut p.aspace, new)?;
        if flags & !(O_NONBLOCK as u64) != 0 {
            return Err(EINVAL);
        }
        Some(flags as u32)
    } else {
        None
    };
    let file = p.fds.get(fd)?;
    let mut f = file.lock();
    let FileKind::Mqueue(q) = &f.kind else { return Err(EBADF) };
    let g = q.lock();
    let (messages, size, count) = (g.max_messages, g.max_size, g.messages.len() as u64);
    drop(g);
    let was = (f.flags & O_NONBLOCK) as u64;
    if let Some(flags) = set {
        f.flags = f.flags & !O_NONBLOCK | flags;
    }
    drop(f);
    if old != 0 {
        let mut b = [0u8; 64];
        for (i, v) in [was, messages, size, count].iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        copy_out(&mut p.aspace, old, &b)?;
    }
    Ok(0)
}
