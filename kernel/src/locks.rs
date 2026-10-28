//! Advisory file locks, as Linux keeps them:
//!
//! - flock(2): a shared or exclusive lock on the whole file, held by an
//!   open file description (so dup and fork share it), gone when that
//!   closes.
//! - POSIX record locks (fcntl F_SETLK): byte ranges held by a process,
//!   gone when it closes any descriptor for the file, or ends.
//! - Open file description locks (F_OFD_SETLK): byte ranges held by an
//!   open file description.
//!
//! flock locks and record locks don't see each other; POSIX and OFD locks
//! do. A process's POSIX locks never conflict with each other: setting one
//! replaces what it had over that range.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use crate::errno::*;

/// The locked file: its node, or (for files without one) the open file.
pub type Key = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// POSIX record locks: the process.
    Process(u32),
    /// flock and OFD locks: the open file description (`OpenFile` address).
    File(usize),
}

#[derive(Clone, Copy, Debug)]
pub struct Lock {
    pub owner: Owner,
    pub write: bool,
    /// [start, end); `end` u64::MAX: to wherever the file ends, ever.
    pub start: u64,
    pub end: u64,
    /// Who took it, for F_GETLK.
    pub pid: u32,
}

impl Lock {
    fn conflicts(&self, owner: Owner, write: bool, start: u64, end: u64) -> bool {
        self.owner != owner && (self.write || write) && self.start < end && start < self.end
    }
}

/// Locks at once, of every kind (a program could otherwise fill the
/// kernel heap splitting ranges): then ENOLCK.
pub const MAX_LOCKS: usize = 4096;

#[derive(Default)]
struct Table {
    flocks: BTreeMap<Key, Vec<Lock>>,
    ranges: BTreeMap<Key, Vec<Lock>>,
    count: usize,
}

static LOCKS: Mutex<Table> = Mutex::new(Table { flocks: BTreeMap::new(), ranges: BTreeMap::new(), count: 0 });

/// What asking for a lock came to.
pub enum Outcome {
    Done,
    /// Held against us by this lock.
    Conflict(Lock),
}

impl Table {
    fn forget_empty(&mut self, key: Key) {
        if self.flocks.get(&key).is_some_and(Vec::is_empty) {
            self.flocks.remove(&key);
        }
        if self.ranges.get(&key).is_some_and(Vec::is_empty) {
            self.ranges.remove(&key);
        }
    }
}

/// flock: `write` for LOCK_EX, `None` for LOCK_UN. Converting a lock
/// drops the old one first, as Linux does (so a conversion that has to
/// wait doesn't hold it meanwhile).
pub fn flock(key: Key, owner: Owner, pid: u32, write: Option<bool>) -> Result<Outcome, Errno> {
    let mut t = LOCKS.lock();
    let locks = t.flocks.entry(key).or_default();
    let before = locks.len();
    locks.retain(|l| l.owner != owner);
    let removed = before - locks.len();
    let outcome = match write {
        None => Outcome::Done,
        Some(write) => match locks.iter().find(|l| l.conflicts(owner, write, 0, u64::MAX)) {
            Some(l) => Outcome::Conflict(*l),
            None => {
                locks.push(Lock { owner, write, start: 0, end: u64::MAX, pid });
                Outcome::Done
            }
        },
    };
    let added = matches!(outcome, Outcome::Done) && write.is_some();
    if added && t.count - removed + 1 > MAX_LOCKS {
        t.flocks.get_mut(&key).unwrap().pop();
        t.count -= removed;
        t.forget_empty(key);
        return Err(ENOLCK);
    }
    t.count = t.count - removed + added as usize;
    t.forget_empty(key);
    if removed > 0 {
        crate::ipc::changed();
    }
    Ok(outcome)
}

/// The first lock that would stop `owner` from taking [start, end).
pub fn conflict(key: Key, owner: Owner, write: bool, start: u64, end: u64) -> Option<Lock> {
    let t = LOCKS.lock();
    t.ranges.get(&key)?.iter().find(|l| l.conflicts(owner, write, start, end)).copied()
}

/// F_SETLK and friends: lock [start, end) (`write`), or unlock it
/// (`None`). Whatever `owner` had over the range is replaced, splitting
/// its locks at the edges.
pub fn set_range(key: Key, owner: Owner, pid: u32, write: Option<bool>, start: u64, end: u64) -> Result<Outcome, Errno> {
    let mut t = LOCKS.lock();
    let old: &[Lock] = t.ranges.get(&key).map_or(&[], Vec::as_slice);
    if let Some(write) = write
        && let Some(l) = old.iter().find(|l| l.conflicts(owner, write, start, end))
    {
        return Ok(Outcome::Conflict(*l));
    }
    let mut new = Vec::with_capacity(old.len() + 2);
    let mut changed = false;
    for &l in old {
        if l.owner != owner || l.end <= start || end <= l.start {
            new.push(l);
            continue;
        }
        changed = true;
        if l.start < start {
            new.push(Lock { end: start, ..l });
        }
        if end < l.end {
            new.push(Lock { start: end, ..l });
        }
    }
    if let Some(write) = write {
        // Neighbours of the same kind become one lock, as on Linux.
        let (mut start, mut end) = (start, end);
        new.retain(|l| {
            let joins = l.owner == owner && l.write == write && (l.end == start || l.start == end);
            if joins {
                (start, end) = (start.min(l.start), end.max(l.end));
            }
            !joins
        });
        new.push(Lock { owner, write, start, end, pid });
    }
    let old_len = old.len();
    if t.count + new.len() > MAX_LOCKS + old_len {
        return Err(ENOLCK);
    }
    t.count = t.count + new.len() - old_len;
    if new.is_empty() {
        t.ranges.remove(&key);
    } else {
        t.ranges.insert(key, new);
    }
    if changed {
        crate::ipc::changed();
    }
    Ok(Outcome::Done)
}

/// Drop the locks `owner` holds on `key` (a process closed a descriptor
/// for the file: its POSIX locks on it go).
pub fn release(key: Key, owner: Owner) {
    let mut t = LOCKS.lock();
    let Some(v) = t.ranges.get_mut(&key) else { return };
    let before = v.len();
    v.retain(|l| l.owner != owner);
    let removed = before - v.len();
    if removed > 0 {
        t.count -= removed;
        t.forget_empty(key);
        crate::ipc::changed();
    }
}

/// Drop every lock `owner` holds, of every kind (a process ended, or an
/// open file description closed).
pub fn release_all(owner: Owner) {
    let mut t = LOCKS.lock();
    let t = &mut *t;
    let mut removed = 0;
    for v in t.flocks.values_mut().chain(t.ranges.values_mut()) {
        let before = v.len();
        v.retain(|l| l.owner != owner);
        removed += before - v.len();
    }
    if removed > 0 {
        t.count -= removed;
        t.flocks.retain(|_, v| !v.is_empty());
        t.ranges.retain(|_, v| !v.is_empty());
        crate::ipc::changed();
    }
}
