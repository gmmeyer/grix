//! Futex words in memory that processes share. Without FUTEX_PRIVATE_FLAG,
//! on a MAP_SHARED mapping or a System V segment, a word is the same word
//! at any address in any process, so its waiters are found by what it's a
//! part of, as Linux's get_futex_key does, and not by address in the
//! process (`Process::futexes`, for every other word): process-shared
//! semaphores and mutexes (PostgreSQL's LWLocks, Python's multiprocessing)
//! never woke anyone else's waiter before this, which one CPU hardly
//! showed. futex_waitv's words stay the process's.
//!
//! Every queue is under the kernel lock, and a waiter is a blocked thread,
//! paid for by it (`COST`, in `process::THREAD_COST`).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::mm::PAGE_SIZE;
use crate::mm::aspace::{AddressSpace, Backing};
use crate::process::{Process, WaitOn};
use crate::procs::PROCS;

/// A shared word: the object it's in, and the byte in that. A waiter's
/// mapping keeps the object; if another thread unmaps it, the worst a
/// later object at that address gets is a spurious wake-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    object: usize,
    at: u64,
}

#[derive(Clone, Copy)]
struct Waiter {
    pid: u32,
    tid: u32,
    bitset: u32,
}

/// A waiter's share of the heap: half-full B-tree nodes, and a queue of its
/// own while it's the only one there.
pub const COST: u64 = 2 * (core::mem::size_of::<Key>() + core::mem::size_of::<VecDeque<Waiter>>()) as u64
    + 4 * core::mem::size_of::<Waiter>() as u64;

static QUEUES: Mutex<BTreeMap<Key, VecDeque<Waiter>>> = Mutex::new(BTreeMap::new());

/// The word at `addr`, if it's in memory processes can share.
pub fn key(a: &AddressSpace, addr: u64) -> Option<Key> {
    let v = a.find(addr)?;
    let into = addr - v.start;
    match &v.backing {
        Backing::Shared { pages, index, .. } => {
            Some(Key { object: Arc::as_ptr(pages) as *const () as usize, at: index * PAGE_SIZE + into })
        }
        Backing::SharedFile { data, offset, .. } => {
            Some(Key { object: Arc::as_ptr(data) as *const () as usize, at: offset + into })
        }
        _ => None,
    }
}

/// `p`'s current thread waits on `key`.
pub fn enqueue(key: Key, pid: u32, tid: u32, bitset: u32) {
    QUEUES.lock().entry(key).or_default().push_back(Waiter { pid, tid, bitset });
}

/// Its wait is over (`Process::cancel_wait`).
pub fn leave(key: Key, tid: u32) {
    let mut queues = QUEUES.lock();
    if let Some(q) = queues.get_mut(&key) {
        q.retain(|w| w.tid != tid);
        if q.is_empty() {
            queues.remove(&key);
        }
    }
}

/// A process's waiters went without their waits ending: it ended, or
/// execve took its other threads.
pub fn forget(pid: u32) {
    QUEUES.lock().retain(|_, q| {
        q.retain(|w| w.pid != pid);
        !q.is_empty()
    });
}

/// `f` on the thread's process, wherever it is.
fn on_process(p: &mut Process, pid: u32, f: impl FnOnce(&mut Process)) {
    if pid == p.pid {
        f(p);
    } else if let Some(q) = PROCS.lock().others.get_mut(&pid) {
        f(q);
    }
}

/// Take up to `n` waiters on `key` for whom `bitset` is meant.
fn take(key: Key, n: u32, bitset: u32) -> Vec<Waiter> {
    let mut queues = QUEUES.lock();
    let Some(q) = queues.get_mut(&key) else { return Vec::new() };
    let mut taken = Vec::new();
    q.retain(|w| {
        let wanted = (taken.len() as u32) < n && w.bitset & bitset != 0;
        if wanted {
            taken.push(*w);
        }
        !wanted
    });
    if q.is_empty() {
        queues.remove(&key);
    }
    taken
}

/// Wake up to `n` waiters on `key`, in any process.
pub fn wake(p: &mut Process, key: Key, n: u32, bitset: u32) -> u32 {
    let taken = take(key, n, bitset);
    for w in &taken {
        on_process(p, w.pid, |q| q.wake(w.tid, Some(0)));
    }
    taken.len() as u32
}

/// Move up to `n` waiters from `from` to `to`.
pub fn requeue(p: &mut Process, from: Key, to: Key, n: u32) -> u32 {
    let moved = take(from, n, u32::MAX);
    if moved.is_empty() {
        return 0;
    }
    for w in &moved {
        on_process(p, w.pid, |q| {
            if let Some(wait) = q.threads.get_mut(&w.tid).and_then(|t| t.wait.as_mut()) {
                wait.on = WaitOn::SharedFutex(to);
            }
        });
    }
    QUEUES.lock().entry(to).or_default().extend(moved.iter().copied());
    moved.len() as u32
}
