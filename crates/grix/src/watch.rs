//! Watching live mounts for changes (`hostfs::Request::Watch`): what the
//! guest's inotify watches in a live mount, the host watches with its own
//! facility, and every change goes to the guest as a `hostfs::Notice`.
//!
//! Nodes are watched through descriptors the file server opened by walking
//! down from the mount's root, never by a path that could lead elsewhere.
//! Linux: inotify, handed the descriptor as `/proc/self/fd/N` (the
//! descriptor's own file, whatever its name is now). macOS: kqueue's
//! `EVFILT_VNODE` on the descriptor, which says that a directory changed
//! but not how: each watched directory's entries are kept, and compared
//! again when it changes (inode numbers pair a rename's halves), and its
//! files are watched too, up to a budget (beyond it they're polled).
//!
//! What the host keeps is bounded: `hostfs::MAX_WATCHES` nodes, and on
//! macOS `MAX_ENTRIES` directory entries and descriptors: `MAX_CHILD_FDS`
//! of a watcher's, and a share of RLIMIT_NOFILE (`at::fd_budget`) of what
//! the process holds for guests, since it needs descriptors for much else.
//! Past that budget files are polled, and a node isn't watched at all:
//! the guest is told it may have lost changes (`IN_Q_OVERFLOW`).
//! The notices of one round of changes are bounded too (`MAX_BATCH`):
//! past that the guest is told it lost some (`IN_Q_OVERFLOW`), as Linux
//! does when its queue is full. They're sent as the guest takes them, so
//! a guest that doesn't read holds the thread back, and changes wait in
//! the host kernel's own bounded queue.

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use grix_abi::hostfs::{MAX_WATCHES, Notice, mask::*};

/// Notices from one round of changes at most.
const MAX_BATCH: usize = 1024;
/// How long the thread waits for changes before it checks whether to stop.
const TICK: Duration = Duration::from_millis(200);

/// Where notices go (a `Notice`'s encoding); false once the guest is gone.
pub(crate) type Sink = Box<dyn FnMut(Vec<u8>) -> bool + Send>;

/// A change, before it's encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Change {
    pub id: u64,
    pub mask: u32,
    pub cookie: u32,
    pub name: String,
}

impl Change {
    fn new(id: u64, mask: u32, name: &str) -> Change {
        Change { id, mask, cookie: 0, name: name.to_string() }
    }
}

/// A round of changes, bounded: past `MAX_BATCH`, an overflow instead.
fn bounded(mut changes: Vec<Change>) -> Vec<Change> {
    if changes.len() > MAX_BATCH {
        changes.truncate(MAX_BATCH - 1);
        changes.push(Change::new(0, IN_Q_OVERFLOW, ""));
    }
    changes
}

/// `change` for each of `ids` (one file can be many nodes), while a round
/// has room: one event mustn't turn into thousands of changes to be
/// thrown away by `bounded`.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn for_each_id(out: &mut Vec<Change>, ids: &[u64], mask: u32, cookie: u32, name: &str) {
    let room = (MAX_BATCH + 1).saturating_sub(out.len());
    out.extend(ids.iter().take(room).map(|&id| Change { id, mask, cookie, name: name.to_string() }));
}

/// A name the guest can see: UTF-8, and at most NAME_MAX bytes.
fn guest_name(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok().filter(|s| !s.is_empty() && s.len() <= grix_abi::hostfs::NAME_MAX)
}

pub(crate) struct Watcher {
    state: Arc<Mutex<os::State>>,
    stop: Arc<AtomicBool>,
}

impl Watcher {
    /// Start watching (nothing yet); changes go to `sink`.
    pub fn new(mut sink: Sink) -> std::io::Result<Watcher> {
        let state = Arc::new(Mutex::new(os::State::new()?));
        let stop = Arc::new(AtomicBool::new(false));
        let (st, halt) = (state.clone(), stop.clone());
        std::thread::Builder::new().name("grix-watch".into()).spawn(move || {
            while !halt.load(Ordering::Relaxed) {
                let changes = bounded(os::wait(&st, TICK));
                for c in changes {
                    let n = Notice { id: c.id, mask: c.mask, cookie: c.cookie, name: &c.name };
                    if !sink(n.encode()) {
                        return;
                    }
                }
            }
        })?;
        Ok(Watcher { state, stop })
    }

    /// Watch node `id`, a directory or regular file open as `fd`. An errno
    /// for the guest if it can't be.
    pub fn add(&self, id: u64, fd: OwnedFd) -> Result<(), u16> {
        let mut st = self.state.lock().unwrap();
        if st.watching(id) {
            return Ok(());
        }
        if st.count() >= MAX_WATCHES {
            return Err(ENOSPC);
        }
        st.add(id, fd)
    }

    pub fn remove(&self, id: u64) {
        self.state.lock().unwrap().remove(id);
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // The thread notices within a tick, and its descriptors go with it.
        self.stop.store(true, Ordering::Relaxed);
    }
}

const ENOSPC: u16 = 28;

#[cfg(target_os = "linux")]
mod os {
    //! inotify. Two ids can be the same file (one inotify watch): each
    //! change goes to both.

    use std::collections::HashMap;
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Mutex;
    use std::time::Duration;

    use super::{Change, ENOSPC, guest_name};
    use grix_abi::hostfs::mask::*;

    pub struct State {
        fd: OwnedFd,
        wds: HashMap<i32, Vec<u64>>,
        ids: HashMap<u64, i32>,
    }

    impl State {
        pub fn new() -> io::Result<State> {
            // SAFETY: a new descriptor we own.
            let fd = crate::at::check(unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) })?;
            Ok(State { fd: unsafe { OwnedFd::from_raw_fd(fd) }, wds: HashMap::new(), ids: HashMap::new() })
        }

        pub fn watching(&self, id: u64) -> bool {
            self.ids.contains_key(&id)
        }

        pub fn count(&self) -> usize {
            self.ids.len()
        }

        pub fn add(&mut self, id: u64, node: OwnedFd) -> Result<(), u16> {
            // The descriptor's own file: /proc resolves it to what was
            // opened, not by any name.
            let path = CString::new(format!("/proc/self/fd/{}", node.as_raw_fd())).unwrap();
            // SAFETY: a NUL-terminated path; the watch outlives `node`.
            let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), path.as_ptr(), HOST_EVENTS) };
            if wd < 0 {
                let e = io::Error::last_os_error();
                return Err(if e.raw_os_error() == Some(libc::ENOSPC) {
                    ENOSPC
                } else {
                    crate::hostfs::linux_errno(&e)
                });
            }
            self.wds.entry(wd).or_default().push(id);
            self.ids.insert(id, wd);
            Ok(())
        }

        pub fn remove(&mut self, id: u64) {
            let Some(wd) = self.ids.remove(&id) else { return };
            let ids = self.wds.entry(wd).or_default();
            ids.retain(|&i| i != id);
            if ids.is_empty() {
                self.wds.remove(&wd);
                // SAFETY: plain call on our descriptor.
                unsafe { libc::inotify_rm_watch(self.fd.as_raw_fd(), wd) };
            }
        }

        /// What the kernel reported, for the guest's ids.
        fn take(&mut self, out: &mut Vec<Change>) {
            // inotify_event is 4-byte aligned.
            let mut buf = vec![0u32; 16 * 1024];
            loop {
                // SAFETY: read writes at most the buffer's bytes.
                let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len() * 4) };
                if n <= 0 {
                    return;
                }
                // SAFETY: the bytes of `buf` that read filled.
                let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n as usize) };
                self.parse(bytes, out);
                if out.len() > super::MAX_BATCH {
                    return;
                }
            }
        }

        fn parse(&mut self, mut bytes: &[u8], out: &mut Vec<Change>) {
            // struct inotify_event { int wd; u32 mask, cookie, len; char name[len]; }
            while bytes.len() >= 16 {
                let word = |i: usize| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap());
                let (wd, mask, cookie, len) = (word(0) as i32, word(4), word(8), word(12) as usize);
                let Some(name) = bytes.get(16..16 + len) else { return };
                bytes = &bytes[16 + len..];
                let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                if mask & IN_Q_OVERFLOW != 0 {
                    super::for_each_id(out, &[0], IN_Q_OVERFLOW, 0, "");
                    continue;
                }
                let Some(ids) = self.wds.get(&wd) else { continue };
                let name = if name.is_empty() {
                    ""
                } else {
                    // A name the guest couldn't hold: it can't see that entry.
                    let Some(n) = guest_name(name) else { continue };
                    n
                };
                if mask & NOTICE != 0 {
                    super::for_each_id(out, ids, mask & NOTICE, cookie, name);
                }
                // The file is gone (or its file system): so is the watch.
                if mask & IN_IGNORED != 0 {
                    for id in self.wds.remove(&wd).unwrap_or_default() {
                        self.ids.remove(&id);
                    }
                }
            }
        }
    }

    pub fn wait(state: &Mutex<State>, tick: Duration) -> Vec<Change> {
        let fd = state.lock().unwrap().fd.as_raw_fd();
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd. The descriptor lives as long as `state`.
        if unsafe { libc::poll(&mut pfd, 1, tick.as_millis() as libc::c_int) } <= 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        state.lock().unwrap().take(&mut out);
        out
    }

    #[cfg(test)]
    pub(super) fn parse_for_test(st: &mut State, bytes: &[u8]) -> Vec<Change> {
        let mut out = Vec::new();
        st.parse(bytes, &mut out);
        out
    }
}

#[cfg(target_os = "macos")]
mod os {
    //! kqueue. A directory's vnode events don't say which entry changed,
    //! so its entries are kept and compared; its files get their own
    //! events (while the budget lasts) for writes and attribute changes.

    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::{Change, ENOSPC, MAX_BATCH, guest_name};
    use crate::at::{
        Kind, check, ctime_ns, each_name, give_fd, identity, kind, mode, mtime_ns, openat, stat_at, stat_fd, take_fd,
    };
    use grix_abi::hostfs::mask::*;
    use std::collections::HashSet;

    /// Directory entries kept, across every watched directory.
    pub const MAX_ENTRIES: usize = 256 * 1024;
    /// Descriptors held for watched directories' files.
    pub const MAX_CHILD_FDS: usize = 1024;
    /// How often directories with files not watched on their own are
    /// compared again.
    const POLL: Duration = Duration::from_secs(1);

    const NODE_EVENTS: u32 = libc::NOTE_DELETE
        | libc::NOTE_WRITE
        | libc::NOTE_EXTEND
        | libc::NOTE_ATTRIB
        | libc::NOTE_LINK
        | libc::NOTE_RENAME
        | libc::NOTE_REVOKE;

    /// What's compared of an entry.
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Seen {
        file: (u64, u64),
        dir: bool,
        size: u64,
        mtime: u64,
        ctime: i128,
        mode: u32,
    }

    fn seen(st: &libc::stat) -> Option<Seen> {
        let k = kind(st);
        // What the guest can't see (sockets, FIFOs, devices) isn't there.
        (k != Kind::Other).then(|| Seen {
            file: identity(st),
            dir: k == Kind::Dir,
            size: st.st_size as u64,
            mtime: mtime_ns(st),
            ctime: ctime_ns(st),
            mode: mode(st),
        })
    }

    struct Entry {
        seen: Seen,
        /// The file's own descriptor and its token, if it has one.
        fd: Option<(OwnedFd, u64)>,
    }

    struct Watch {
        fd: OwnedFd,
        token: u64,
        dir: bool,
        entries: BTreeMap<String, Entry>,
        /// Some of its files have no descriptor: compare them every `POLL`.
        polled: bool,
    }

    /// What a token stands for: a watched node, or a watched directory's
    /// file.
    enum Target {
        Node(u64),
        Child(u64, String),
    }

    pub struct State {
        kq: OwnedFd,
        watches: HashMap<u64, Watch>,
        tokens: HashMap<u64, Target>,
        next_token: u64,
        entries: usize,
        child_fds: usize,
        next_cookie: u32,
        last_poll: Instant,
        /// Nodes the budget had no descriptor for: nothing reports them,
        /// which the guest has been told (`lost`).
        blind: HashSet<u64>,
        lost: bool,
    }

    /// A directory's entries the guest can see, by name; None past `room`,
    /// with no more of them held than that.
    fn scan(dir: RawFd, room: usize) -> io::Result<Option<BTreeMap<String, Seen>>> {
        let mut out = BTreeMap::new();
        let all = each_name(dir, |name| {
            let Some(s) = guest_name(name.to_bytes()) else { return true };
            let Some(seen) = stat_at(dir, name).ok().as_ref().and_then(seen) else { return true };
            if out.len() >= room {
                return false;
            }
            out.insert(s.to_string(), seen);
            true
        })?;
        Ok(all.then_some(out))
    }

    impl State {
        pub fn new() -> io::Result<State> {
            // SAFETY: a new descriptor we own.
            let kq = check(unsafe { libc::kqueue() })?;
            Ok(State {
                kq: unsafe { OwnedFd::from_raw_fd(kq) },
                watches: HashMap::new(),
                tokens: HashMap::new(),
                next_token: 1,
                entries: 0,
                child_fds: 0,
                next_cookie: 1,
                last_poll: Instant::now(),
                blind: HashSet::new(),
                lost: false,
            })
        }

        pub fn watching(&self, id: u64) -> bool {
            self.watches.contains_key(&id) || self.blind.contains(&id)
        }

        pub fn count(&self) -> usize {
            self.watches.len() + self.blind.len()
        }

        /// Tell kqueue about `fd`, as `token`.
        fn register(&mut self, fd: RawFd, target: Target) -> io::Result<u64> {
            let token = self.next_token;
            // SAFETY: a zeroed kevent is valid; we fill in what we use.
            let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
            ev.ident = fd as usize;
            ev.filter = libc::EVFILT_VNODE;
            ev.flags = libc::EV_ADD | libc::EV_CLEAR;
            ev.fflags = NODE_EVENTS;
            ev.udata = token as *mut libc::c_void;
            // SAFETY: one change, no events back.
            check(unsafe { libc::kevent(self.kq.as_raw_fd(), &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) })?;
            self.next_token += 1;
            self.tokens.insert(token, target);
            Ok(token)
        }

        /// A descriptor for a watched directory's file `name`, if the
        /// budget allows (closing it takes it out of the kqueue).
        fn child_fd(&mut self, id: u64, dir: RawFd, name: &str, seen: &Seen) -> Option<(OwnedFd, u64)> {
            if seen.dir || self.child_fds >= MAX_CHILD_FDS || !take_fd() {
                return None;
            }
            let opened = (|| {
                let c = std::ffi::CString::new(name).ok()?;
                let fd = openat(dir, &c, libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0).ok()?;
                // Only the file that was seen (not a link or FIFO put there since).
                if stat_fd(fd.as_raw_fd()).ok().map(|st| identity(&st)) != Some(seen.file) {
                    return None;
                }
                let token = self.register(fd.as_raw_fd(), Target::Child(id, name.to_string())).ok()?;
                Some((fd, token))
            })();
            match opened {
                Some(_) => self.child_fds += 1,
                None => give_fd(),
            }
            opened
        }

        fn drop_entry(&mut self, e: Entry) {
            if let Some((_, token)) = e.fd {
                self.tokens.remove(&token);
                self.child_fds -= 1;
                give_fd();
            }
            self.entries -= 1;
        }

        pub fn add(&mut self, id: u64, fd: OwnedFd) -> Result<(), u16> {
            // Nothing to spare for it: the host isn't to run out for one
            // program's watches, and the guest can look for itself.
            if !take_fd() {
                self.blind.insert(id);
                self.lost = true;
                return Ok(());
            }
            let added = self.add_held(id, fd);
            if added.is_err() {
                give_fd();
            }
            added
        }

        fn add_held(&mut self, id: u64, fd: OwnedFd) -> Result<(), u16> {
            let st = stat_fd(fd.as_raw_fd()).map_err(|e| crate::hostfs::linux_errno(&e))?;
            let dir = kind(&st) == Kind::Dir;
            let found = if dir {
                let found =
                    scan(fd.as_raw_fd(), MAX_ENTRIES - self.entries).map_err(|e| crate::hostfs::linux_errno(&e))?;
                // More entries than the host can keep track of.
                found.ok_or(ENOSPC)?
            } else {
                BTreeMap::new()
            };
            let token = self.register(fd.as_raw_fd(), Target::Node(id)).map_err(|e| crate::hostfs::linux_errno(&e))?;
            let mut w = Watch { fd, token, dir, entries: BTreeMap::new(), polled: false };
            for (name, seen) in found {
                let fd = self.child_fd(id, w.fd.as_raw_fd(), &name, &seen);
                w.polled |= fd.is_none() && !seen.dir;
                w.entries.insert(name, Entry { seen, fd });
                self.entries += 1;
            }
            self.watches.insert(id, w);
            Ok(())
        }

        pub fn remove(&mut self, id: u64) {
            self.blind.remove(&id);
            let Some(w) = self.watches.remove(&id) else { return };
            self.tokens.remove(&w.token);
            give_fd();
            for (_, e) in w.entries {
                self.drop_entry(e);
            }
        }

        /// Directory `id` changed: how, compared with what was kept.
        /// Entries gone and new go to `gone`/`new` (id, name, file, is a
        /// directory) to be paired up; changed ones to `out`.
        fn compare(
            &mut self,
            id: u64,
            gone: &mut Vec<(u64, String, Seen)>,
            new: &mut Vec<(u64, String, Seen)>,
            out: &mut Vec<Change>,
        ) {
            let Some(w) = self.watches.get_mut(&id) else { return };
            let kept = w.entries.len();
            let Ok(found) = scan(w.fd.as_raw_fd(), MAX_ENTRIES - (self.entries - kept)) else {
                // Gone: its own NOTE_DELETE says so.
                return;
            };
            let Some(mut found) = found else {
                // Grown past what can be kept: the guest has to look again.
                out.push(Change::new(0, IN_Q_OVERFLOW, ""));
                out.push(Change::new(id, IN_IGNORED, ""));
                self.remove(id);
                return;
            };
            let old = std::mem::take(&mut w.entries);
            let dirfd = w.fd.as_raw_fd();
            let mut entries = BTreeMap::new();
            let mut polled = false;
            for (name, e) in old {
                match found.remove(&name) {
                    Some(now) if now.file == e.seen.file => {
                        // A file with its own descriptor reports itself.
                        if e.fd.is_none() && !now.dir {
                            if (now.size, now.mtime) != (e.seen.size, e.seen.mtime) {
                                out.push(Change::new(id, IN_MODIFY, &name));
                            } else if (now.mode, now.ctime) != (e.seen.mode, e.seen.ctime) {
                                out.push(Change::new(id, IN_ATTRIB, &name));
                            }
                        } else if now.dir && now.mode != e.seen.mode {
                            // Not its times: they change with its entries,
                            // which Linux doesn't report here.
                            out.push(Change::new(id, IN_ATTRIB | IN_ISDIR, &name));
                        }
                        polled |= e.fd.is_none() && !now.dir;
                        entries.insert(name, Entry { seen: now, fd: e.fd });
                    }
                    other => {
                        gone.push((id, name.clone(), e.seen));
                        self.drop_entry(e);
                        // Replaced by another file: that one's new.
                        if let Some(now) = other {
                            found.insert(name, now);
                        }
                    }
                }
            }
            for (name, seen) in found {
                let fd = self.child_fd(id, dirfd, &name, &seen);
                polled |= fd.is_none() && !seen.dir;
                new.push((id, name.clone(), seen));
                entries.insert(name, Entry { seen, fd });
                self.entries += 1;
            }
            let w = self.watches.get_mut(&id).unwrap();
            (w.entries, w.polled) = (entries, polled);
        }

        /// Entries gone and new, as renames where the same file is both
        /// (Linux's MOVED_FROM and MOVED_TO with one cookie), or else
        /// deletions and creations.
        fn pair(&mut self, gone: Vec<(u64, String, Seen)>, mut new: Vec<(u64, String, Seen)>, out: &mut Vec<Change>) {
            // More than a round carries (`bounded` would throw them away)
            // is an overflow, and not a search of one list for each of the
            // other, up to `MAX_ENTRIES` of each, with `Watcher::add` waiting.
            if gone.len() > MAX_BATCH || new.len() > MAX_BATCH {
                out.push(Change::new(0, IN_Q_OVERFLOW, ""));
                return;
            }
            let isdir = |s: &Seen| if s.dir { IN_ISDIR } else { 0 };
            let mut moved_to = BTreeSet::new();
            let mut deleted = Vec::new();
            for (id, name, seen) in gone {
                match new.iter().position(|n| n.2.file == seen.file) {
                    Some(i) => {
                        let (to_id, to, to_seen) = new.remove(i);
                        let cookie = self.next_cookie;
                        self.next_cookie = self.next_cookie.wrapping_add(1).max(1);
                        out.push(Change { id, mask: IN_MOVED_FROM | isdir(&seen), cookie, name });
                        moved_to.insert((to_id, to.clone()));
                        out.push(Change { id: to_id, mask: IN_MOVED_TO | isdir(&to_seen), cookie, name: to });
                    }
                    None => deleted.push((id, name, seen)),
                }
            }
            // Renamed over: Linux says only that the other one moved there.
            for (id, name, seen) in deleted {
                if !moved_to.contains(&(id, name.clone())) {
                    out.push(Change::new(id, IN_DELETE | isdir(&seen), &name));
                }
            }
            for (id, name, seen) in new {
                out.push(Change::new(id, IN_CREATE | isdir(&seen), &name));
            }
        }

        /// What kqueue said, as changes.
        fn take(&mut self, events: &[libc::kevent], out: &mut Vec<Change>) {
            if std::mem::take(&mut self.lost) {
                out.push(Change::new(0, IN_Q_OVERFLOW, ""));
            }
            let mut changed = BTreeSet::new();
            for ev in events {
                let token = ev.udata as u64;
                let f = ev.fflags;
                match self.tokens.get(&token) {
                    Some(Target::Child(id, name)) => {
                        let (id, name) = (*id, name.clone());
                        if f & (libc::NOTE_DELETE | libc::NOTE_RENAME) != 0 {
                            changed.insert(id);
                        }
                        let Some(e) = self.watches.get_mut(&id).and_then(|w| w.entries.get_mut(&name)) else {
                            continue;
                        };
                        if let Some(now) =
                            e.fd.as_ref().and_then(|(fd, _)| stat_fd(fd.as_raw_fd()).ok()).as_ref().and_then(seen)
                        {
                            e.seen = now;
                        }
                        if f & (libc::NOTE_WRITE | libc::NOTE_EXTEND) != 0 {
                            out.push(Change::new(id, IN_MODIFY, &name));
                        } else if f & libc::NOTE_ATTRIB != 0 {
                            out.push(Change::new(id, IN_ATTRIB, &name));
                        }
                    }
                    Some(Target::Node(id)) => {
                        let id = *id;
                        let Some(w) = self.watches.get(&id) else { continue };
                        let isdir = if w.dir { IN_ISDIR } else { 0 };
                        if w.dir && f & (libc::NOTE_WRITE | libc::NOTE_LINK | libc::NOTE_EXTEND) != 0 {
                            changed.insert(id);
                        }
                        if !w.dir && f & (libc::NOTE_WRITE | libc::NOTE_EXTEND) != 0 {
                            out.push(Change::new(id, IN_MODIFY, ""));
                        }
                        if f & libc::NOTE_ATTRIB != 0 {
                            out.push(Change::new(id, IN_ATTRIB | isdir, ""));
                        }
                        if f & libc::NOTE_RENAME != 0 {
                            out.push(Change::new(id, IN_MOVE_SELF | isdir, ""));
                        }
                        if f & (libc::NOTE_DELETE | libc::NOTE_REVOKE) != 0 {
                            let why = if f & libc::NOTE_DELETE != 0 { IN_DELETE_SELF | isdir } else { IN_UNMOUNT };
                            out.push(Change::new(id, why, ""));
                            out.push(Change::new(id, IN_IGNORED, ""));
                            changed.remove(&id);
                            self.remove(id);
                        }
                    }
                    None => {}
                }
            }
            if self.last_poll.elapsed() >= POLL {
                self.last_poll = Instant::now();
                changed.extend(self.watches.iter().filter(|(_, w)| w.polled).map(|(&id, _)| id));
            }
            let (mut gone, mut new) = (Vec::new(), Vec::new());
            for id in changed {
                self.compare(id, &mut gone, &mut new, out);
            }
            self.pair(gone, new, out);
        }
    }

    #[cfg(test)]
    impl State {
        /// `n` files, each renamed.
        pub(super) fn pair_for_test(&mut self, n: usize, out: &mut Vec<Change>) {
            let file = |i: usize, name: String| {
                let seen = Seen { file: (1, i as u64), dir: false, size: 0, mtime: 0, ctime: 0, mode: 0o644 };
                (1, name, seen)
            };
            let gone = (0..n).map(|i| file(i, format!("a{i}"))).collect();
            let new = (0..n).map(|i| file(i, format!("b{i}"))).collect();
            self.pair(gone, new, out);
        }
    }

    pub fn wait(state: &Mutex<State>, tick: Duration) -> Vec<Change> {
        let kq = state.lock().unwrap().kq.as_raw_fd();
        // SAFETY: zeroed kevents are valid for the kernel to fill.
        let mut events: Vec<libc::kevent> = vec![unsafe { std::mem::zeroed() }; 64];
        let timeout = libc::timespec { tv_sec: 0, tv_nsec: tick.as_nanos().min(999_999_999) as libc::c_long };
        // SAFETY: room for `events.len()` events. The queue lives as long
        // as `state`.
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, events.as_mut_ptr(), events.len() as i32, &timeout) };
        let mut out = Vec::new();
        state.lock().unwrap().take(&events[..n.max(0) as usize], &mut out);
        out
    }

    impl Drop for State {
        fn drop(&mut self) {
            for _ in 0..self.watches.len() + self.child_fds {
                give_fd();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    fn open(path: &std::path::Path) -> OwnedFd {
        crate::at::open_dir(path).unwrap()
    }

    /// The changes made on the host, as the guest is told of them, until
    /// `done` says that's all.
    fn collect(rx: &mpsc::Receiver<Vec<u8>>, wait: u64, done: impl Fn(&[Change]) -> bool) -> Vec<Change> {
        let mut got = Vec::new();
        let end = Instant::now() + Duration::from_millis(wait);
        while !done(&got) && Instant::now() < end {
            if let Ok(b) = rx.recv_timeout(Duration::from_millis(100)) {
                let n = Notice::decode(&b).expect("a notice the guest accepts");
                got.push(Change { id: n.id, mask: n.mask, cookie: n.cookie, name: n.name.to_string() });
            }
        }
        got
    }

    #[test]
    fn a_round_of_changes_stays_small_as_it_is_made() {
        // 4096 events on a file with 8192 names: a read's worth would be
        // 33 million changes before `bounded` could look at them.
        let ids: Vec<u64> = (0..8192).collect();
        let mut out = Vec::new();
        for _ in 0..4096 {
            for_each_id(&mut out, &ids, IN_MODIFY, 0, "x");
            assert!(out.len() <= MAX_BATCH + 1);
        }
        let round = bounded(out);
        assert_eq!(round.len(), MAX_BATCH);
        assert_eq!(round.last().unwrap().mask, IN_Q_OVERFLOW);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_round_too_big_to_carry_is_an_overflow() {
        let mut st = os::State::new().unwrap();
        let mut out = Vec::new();
        st.pair_for_test(MAX_BATCH + 1, &mut out);
        assert_eq!(out, [Change::new(0, IN_Q_OVERFLOW, "")]);
        // Renames are found among as many as a round carries.
        out.clear();
        st.pair_for_test(MAX_BATCH, &mut out);
        assert_eq!(out.len(), MAX_BATCH * 2);
        assert!(out.iter().all(|c| c.mask & (IN_MOVED_FROM | IN_MOVED_TO) != 0), "{out:?}");
    }

    #[test]
    fn reports_changes_with_names() {
        let root = std::env::temp_dir().join(format!("grix-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a"), "1").unwrap();
        let root = root.canonicalize().unwrap();
        let (tx, rx) = mpsc::channel();
        let w = Watcher::new(Box::new(move |b| tx.send(b).is_ok())).unwrap();
        w.add(1, open(&root)).unwrap();
        // Watching it again is the same watch.
        w.add(1, open(&root)).unwrap();

        std::fs::write(root.join("new"), "x").unwrap();
        let has =
            |got: &[Change], m: u32, name: &str| got.iter().any(|c| c.id == 1 && c.mask & m != 0 && c.name == name);
        let got = collect(&rx, 10_000, |g| has(g, IN_CREATE, "new"));
        assert!(has(&got, IN_CREATE, "new"), "{got:?}");

        std::fs::write(root.join("a"), "changed").unwrap();
        let got = collect(&rx, 10_000, |g| has(g, IN_MODIFY, "a"));
        assert!(has(&got, IN_MODIFY, "a"), "{got:?}");

        std::fs::rename(root.join("a"), root.join("b")).unwrap();
        let got = collect(&rx, 10_000, |g| has(g, IN_MOVED_TO, "b"));
        let from = got.iter().find(|c| c.mask & IN_MOVED_FROM != 0 && c.name == "a").expect("moved from");
        let to = got.iter().find(|c| c.mask & IN_MOVED_TO != 0 && c.name == "b").expect("moved to");
        assert!(from.cookie != 0 && from.cookie == to.cookie, "{got:?}");

        std::fs::remove_file(root.join("b")).unwrap();
        std::fs::create_dir(root.join("d")).unwrap();
        let got = collect(&rx, 10_000, |g| has(g, IN_DELETE, "b") && has(g, IN_CREATE, "d"));
        assert!(has(&got, IN_DELETE, "b"), "{got:?}");
        assert!(got.iter().any(|c| c.name == "d" && c.mask == IN_CREATE | IN_ISDIR), "{got:?}");

        // A watched directory removed: the watch goes too.
        w.add(2, open(&root.join("sub"))).unwrap();
        std::fs::remove_dir(root.join("sub")).unwrap();
        let got = collect(&rx, 10_000, |g| {
            g.iter().any(|c| c.id == 2 && c.mask & IN_IGNORED != 0) && has(g, IN_DELETE, "sub")
        });
        assert!(got.iter().any(|c| c.id == 2 && c.mask & IN_DELETE_SELF != 0), "{got:?}");
        assert!(got.iter().any(|c| c.name == "sub" && c.mask == IN_DELETE | IN_ISDIR), "{got:?}");
        assert!(got.iter().any(|c| c.id == 2 && c.mask & IN_IGNORED != 0), "{got:?}");

        // Unwatched: nothing more.
        w.remove(1);
        std::fs::write(root.join("later"), "x").unwrap();
        let got = collect(&rx, 1500, |_| false);
        assert!(got.iter().all(|c| c.id != 1), "{got:?}");
        drop(w);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rounds_of_changes_are_bounded() {
        let many: Vec<Change> = (0..MAX_BATCH * 2).map(|i| Change::new(1, IN_CREATE, &i.to_string())).collect();
        let out = bounded(many);
        assert_eq!(out.len(), MAX_BATCH);
        assert_eq!(out.last().unwrap(), &Change::new(0, IN_Q_OVERFLOW, ""));
        let few = vec![Change::new(1, IN_CREATE, "a")];
        assert_eq!(bounded(few.clone()), few);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inotify_events_become_notices() {
        let mut st = os::State::new().unwrap();
        let root = std::env::temp_dir().join(format!("grix-watch-parse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        st.add(5, open(&root)).unwrap();
        st.add(6, open(&root)).unwrap();
        let ev = |wd: i32, mask: u32, cookie: u32, name: &[u8]| {
            let len = name.len().div_ceil(4) * 4;
            let mut b = Vec::new();
            for v in [wd as u32, mask, cookie, len as u32] {
                b.extend_from_slice(&v.to_ne_bytes());
            }
            b.extend_from_slice(name);
            b.resize(16 + len, 0);
            b
        };
        let wd = 1;
        let mut bytes = ev(wd, IN_CREATE, 0, b"x");
        bytes.extend(ev(wd, IN_OPEN, 0, b"y"));
        bytes.extend(ev(wd, IN_CREATE, 0, &[0xff, 0xfe]));
        bytes.extend(ev(-1, IN_Q_OVERFLOW, 0, b""));
        bytes.extend(ev(wd, IN_DELETE_SELF, 0, b""));
        bytes.extend(ev(wd, IN_IGNORED, 0, b""));
        bytes.extend(ev(wd, IN_CREATE, 0, b"after"));
        let got = os::parse_for_test(&mut st, &bytes);
        let want = [
            Change::new(5, IN_CREATE, "x"),
            Change::new(6, IN_CREATE, "x"),
            Change::new(0, IN_Q_OVERFLOW, ""),
            Change::new(5, IN_DELETE_SELF, ""),
            Change::new(6, IN_DELETE_SELF, ""),
            Change::new(5, IN_IGNORED, ""),
            Change::new(6, IN_IGNORED, ""),
        ];
        assert_eq!(got, want);
        assert!(!st.watching(5) && !st.watching(6));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
