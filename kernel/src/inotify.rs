//! inotify: an instance's watches and the events queued for it.
//!
//! Events come from the host, for live mounts' nodes (`grix_abi::hostfs`'s
//! `Watch` and `Notice`): the first watch on a node asks the host to watch
//! it, and the last one going tells it to stop. The guest's own changes
//! to its other files make no events (yet), though changes it makes in a
//! live mount do, since the host sees them. A lazy import never changes
//! for the guest, so watching it asks nothing of the host.
//!
//! Every event is charged to the kernel heap, and an instance queues at
//! most `MAX_QUEUED` (Linux's max_queued_events): past that, one
//! IN_Q_OVERFLOW, as on Linux.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use grix_abi::hostfs::{Notice, mask::*};
use spin::Mutex;

use crate::errno::*;
use crate::fs::Ino;
use crate::kmem;

/// Watches across all inotify instances (Linux's max_user_watches): they
/// take kernel memory.
pub const MAX_WATCHES: u64 = 8192;
static WATCHES: AtomicU64 = AtomicU64::new(0);

/// Events an instance queues at most.
pub const MAX_QUEUED: usize = 16384;

/// What a watch can ask for.
pub const IN_ALL_EVENTS: u32 = 0xfff;
const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;
const WATCH_FLAGS: u32 =
    IN_ALL_EVENTS | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_CREATE | IN_MASK_ADD | IN_ONESHOT;

/// struct inotify_event, before its name.
const HEADER: usize = 16;

struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}

impl Event {
    /// The name's room in the record: NUL-terminated and padded to the
    /// header's size, as Linux does (0 without a name).
    fn name_len(&self) -> usize {
        if self.name.is_empty() { 0 } else { (self.name.len() + 1).next_multiple_of(HEADER) }
    }

    fn size(&self) -> usize {
        HEADER + self.name_len()
    }

    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.wd.to_le_bytes());
        out.extend_from_slice(&self.mask.to_le_bytes());
        out.extend_from_slice(&self.cookie.to_le_bytes());
        out.extend_from_slice(&(self.name_len() as u32).to_le_bytes());
        let start = out.len();
        out.extend_from_slice(self.name.as_bytes());
        out.resize(start + self.name_len(), 0);
    }

    /// What it costs the kernel heap.
    fn cost(&self) -> u64 {
        (core::mem::size_of::<Event>() + self.name.len() + 32) as u64
    }
}

struct Watch {
    ino: Ino,
    mask: u32,
    /// The host's id for it, when the host watches it for us.
    remote: Option<u64>,
    /// Keeps the node's slot from being reused while it's watched.
    _pin: Arc<()>,
}

pub struct State {
    watches: BTreeMap<i32, Watch>,
    next_wd: i32,
    queue: VecDeque<Event>,
    /// What reading the whole queue would return, in bytes.
    bytes: usize,
    charge: kmem::Charge,
    /// Bumped with every new event (for edge-triggered epoll).
    version: u64,
}

/// An inotify instance (`FileKind::Inotify`).
pub struct Inotify(pub Arc<Mutex<State>>);

/// Instances watching each node the host watches for us, once per watch.
static REMOTE: Mutex<BTreeMap<u64, Vec<Weak<Mutex<State>>>>> = Mutex::new(BTreeMap::new());

impl Inotify {
    pub fn new() -> Inotify {
        Inotify(Arc::new(Mutex::new(State {
            watches: BTreeMap::new(),
            next_wd: 0,
            queue: VecDeque::new(),
            bytes: 0,
            charge: kmem::Charge::default(),
            version: 0,
        })))
    }

    /// inotify_add_watch on node `ino`: `remote` is the host's id for it
    /// if the host can watch it (a live mount's file or directory, not a
    /// lazy import's). Returns the watch descriptor.
    pub fn add_watch(
        &self,
        ino: Ino,
        is_dir: bool,
        remote: Option<u64>,
        pin: Arc<()>,
        mask: u32,
    ) -> Result<i32, Errno> {
        // Linux ignores bits it doesn't know, but wants one it does.
        if mask & WATCH_FLAGS == 0 || (mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0) {
            return Err(EINVAL);
        }
        if mask & IN_ONLYDIR != 0 && !is_dir {
            return Err(ENOTDIR);
        }
        let mut st = self.0.lock();
        let keep = IN_ALL_EVENTS | IN_EXCL_UNLINK | IN_ONESHOT;
        if let Some((&wd, w)) = st.watches.iter_mut().find(|(_, w)| w.ino == ino) {
            if mask & IN_MASK_CREATE != 0 {
                return Err(EEXIST);
            }
            w.mask = if mask & IN_MASK_ADD != 0 { w.mask | (mask & keep) } else { mask & keep };
            return Ok(wd);
        }
        let wd = st.next_wd.checked_add(1).ok_or(ENOSPC)?;
        if WATCHES.load(Ordering::Relaxed) >= MAX_WATCHES {
            crate::stats::hit(grix_abi::stats::Limit::InotifyWatches);
            return Err(ENOSPC);
        }
        if let Some(id) = remote {
            let first = !REMOTE.lock().contains_key(&id);
            // The host's answer comes before anything else changes here.
            if first {
                crate::hostfs::watch(id).inspect_err(|&e| {
                    // The host's own cap on watches.
                    if e == ENOSPC {
                        crate::stats::hit(grix_abi::stats::Limit::InotifyWatches);
                    }
                })?;
            }
            REMOTE.lock().entry(id).or_default().push(Arc::downgrade(&self.0));
        }
        WATCHES.fetch_add(1, Ordering::Relaxed);
        st.next_wd = wd;
        st.watches.insert(wd, Watch { ino, mask: mask & keep, remote, _pin: pin });
        Ok(wd)
    }

    pub fn rm_watch(&self, wd: i32) -> Result<(), Errno> {
        let mut st = self.0.lock();
        let w = st.watches.remove(&wd).ok_or(EINVAL)?;
        st.push(Event { wd, mask: IN_IGNORED, cookie: 0, name: String::new() });
        drop(st);
        gone(&self.0, w);
        Ok(())
    }

    /// (EPOLL* bits, version)
    pub fn poll(&self) -> (u32, u64) {
        let st = self.0.lock();
        (if st.queue.is_empty() { 0 } else { crate::ipc::EPOLLIN }, st.version)
    }

    /// Bytes a read could return now (FIONREAD).
    pub fn available(&self) -> usize {
        self.0.lock().bytes
    }

    /// As many whole queued events as fit in `count` bytes, handed to
    /// `out` (which copies them to the program), and taken once it says
    /// they arrived. None if there are none; EINVAL if the first doesn't
    /// fit, as on Linux.
    pub fn read(&self, count: usize, out: impl FnOnce(&[u8]) -> Result<(), Errno>) -> Option<Result<usize, Errno>> {
        let mut st = self.0.lock();
        if st.queue.is_empty() {
            return None;
        }
        let mut buf = Vec::new();
        let mut n = 0;
        for ev in &st.queue {
            if buf.len() + ev.size() > count {
                break;
            }
            ev.put(&mut buf);
            n += 1;
        }
        if n == 0 {
            return Some(Err(EINVAL));
        }
        if let Err(e) = out(&buf) {
            return Some(Err(e));
        }
        for _ in 0..n {
            st.pop();
        }
        Some(Ok(buf.len()))
    }
}

impl State {
    /// Queue `ev`: merged with the last if it's the same (as Linux does),
    /// or, with the queue full or no memory for it, an overflow.
    fn push(&mut self, ev: Event) {
        let same = |l: &Event| (l.wd, l.mask, l.cookie, &l.name) == (ev.wd, ev.mask, ev.cookie, &ev.name);
        if self.queue.back().is_some_and(same) {
            return;
        }
        // The last place is the overflow's.
        let ev = if self.queue.len() < MAX_QUEUED - 1 && self.charge.resize(self.charge.bytes() + ev.cost()).is_ok() {
            ev
        } else {
            let o = Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: String::new() };
            if self.queue.back().is_some_and(|l| l.mask == IN_Q_OVERFLOW)
                || self.charge.resize(self.charge.bytes() + o.cost()).is_err()
            {
                return;
            }
            o
        };
        self.bytes += ev.size();
        self.queue.push_back(ev);
        self.version += 1;
        crate::ipc::changed();
    }

    fn pop(&mut self) {
        if let Some(ev) = self.queue.pop_front() {
            self.bytes -= ev.size();
            let _ = self.charge.resize(self.charge.bytes() - ev.cost());
        }
        if self.queue.is_empty() {
            self.queue = VecDeque::new(); // give the memory back
        }
    }

    /// A change the host saw in node `id`, for this instance's watches of
    /// it. Returns the watches that ended (for `gone`).
    fn deliver(&mut self, id: u64, n: &Notice) -> Vec<Watch> {
        let wds: Vec<i32> = self.watches.iter().filter(|(_, w)| w.remote == Some(id)).map(|(&wd, _)| wd).collect();
        let mut ended = Vec::new();
        for wd in wds {
            let w = &self.watches[&wd];
            // The host's own end of the watch: so it ends here too.
            if n.mask & IN_IGNORED != 0 {
                self.push(Event { wd, mask: IN_IGNORED, cookie: 0, name: String::new() });
                ended.extend(self.watches.remove(&wd));
                continue;
            }
            let wanted = n.mask & w.mask & IN_ALL_EVENTS != 0 || n.mask & IN_UNMOUNT != 0;
            if !wanted {
                continue;
            }
            let oneshot = w.mask & IN_ONESHOT != 0;
            self.push(Event { wd, mask: n.mask, cookie: n.cookie, name: n.name.to_string() });
            if oneshot {
                self.push(Event { wd, mask: IN_IGNORED, cookie: 0, name: String::new() });
                ended.extend(self.watches.remove(&wd));
            }
        }
        ended
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for (_, w) in core::mem::take(&mut self.watches) {
            WATCHES.fetch_sub(1, Ordering::Relaxed);
            if let Some(id) = w.remote {
                // This instance's own entries are dead already.
                unregister(id, |e| e.strong_count() == 0);
            }
        }
    }
}

/// One of `id`'s entries matching `is` goes; the host stops watching it
/// after the last one.
fn unregister(id: u64, is: impl Fn(&Weak<Mutex<State>>) -> bool) {
    let mut remote = REMOTE.lock();
    let Some(list) = remote.get_mut(&id) else { return };
    if let Some(i) = list.iter().position(is) {
        list.remove(i);
    }
    if list.is_empty() {
        remote.remove(&id);
        drop(remote);
        crate::hostfs::unwatch(id);
    }
}

/// Watch `w` of instance `st` ended.
fn gone(st: &Arc<Mutex<State>>, w: Watch) {
    WATCHES.fetch_sub(1, Ordering::Relaxed);
    if let Some(id) = w.remote {
        let me = Arc::downgrade(st);
        unregister(id, |e| e.ptr_eq(&me));
    }
}

/// Every instance watching anything through the host, once each.
fn all_instances() -> Vec<Arc<Mutex<State>>> {
    let mut out: Vec<Arc<Mutex<State>>> = Vec::new();
    for list in REMOTE.lock().values() {
        for s in list.iter().filter_map(Weak::upgrade) {
            if !out.iter().any(|o| Arc::ptr_eq(o, &s)) {
                out.push(s);
            }
        }
    }
    out
}

/// Notices from the host (`Input::FsEvent`), and whether some were lost
/// on the way (`lost`). What they say changed is fetched again before
/// it's next used.
pub fn from_host(msgs: &[Vec<u8>], lost: bool) {
    let overflow = |all: &[Arc<Mutex<State>>]| {
        for s in all {
            s.lock().push(Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: String::new() });
        }
        crate::fs::host_changed(None);
    };
    for msg in msgs {
        // Garbled ones are dropped (the host is checked, not trusted).
        let Ok(n) = Notice::decode(msg) else { continue };
        if n.id == 0 {
            if n.mask & IN_Q_OVERFLOW != 0 {
                overflow(&all_instances());
            }
            continue;
        }
        let instances: Vec<Arc<Mutex<State>>> =
            REMOTE.lock().get(&n.id).map_or_else(Vec::new, |l| l.iter().filter_map(Weak::upgrade).collect());
        let mut seen: Vec<&Arc<Mutex<State>>> = Vec::new();
        for s in &instances {
            if seen.iter().any(|o| Arc::ptr_eq(o, s)) {
                continue;
            }
            seen.push(s);
            let mut st = s.lock();
            let inos: Vec<Ino> = st.watches.values().filter(|w| w.remote == Some(n.id)).map(|w| w.ino).collect();
            let ended = st.deliver(n.id, &n);
            drop(st);
            for ino in inos {
                crate::fs::host_changed(Some((ino, n.name)));
            }
            for w in ended {
                gone(s, w);
            }
        }
    }
    if lost {
        overflow(&all_instances());
    }
}

/// Restored from a snapshot: the host watches nothing yet, so ask again
/// for every node watched; what changed meanwhile is lost (an overflow).
/// A node the host can't watch now ends its watches (IN_IGNORED).
pub fn rewatch() {
    let ids: Vec<u64> = REMOTE.lock().keys().copied().collect();
    for id in ids {
        if crate::hostfs::watch(id).is_ok() {
            continue;
        }
        let instances: Vec<Arc<Mutex<State>>> =
            REMOTE.lock().get(&id).map_or_else(Vec::new, |l| l.iter().filter_map(Weak::upgrade).collect());
        let ignored = Notice { id, mask: IN_IGNORED, cookie: 0, name: "" };
        for s in &instances {
            let ended = s.lock().deliver(id, &ignored);
            for w in ended {
                gone(s, w);
            }
        }
    }
    let all = all_instances();
    for s in &all {
        s.lock().push(Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: String::new() });
    }
}
