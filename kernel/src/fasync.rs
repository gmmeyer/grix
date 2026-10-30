//! O_ASYNC: a signal to a file's owner when I/O on it becomes possible,
//! as Linux's fasync (FIOASYNC or F_SETFL, F_SETOWN, F_SETSIG). nginx's
//! master sets it on its channels to the workers.
//!
//! Files with it set are watched here (at most one entry per open file,
//! so the open-file limit bounds them). Whenever the I/O generation moves,
//! each one's readiness is looked at again: input that changed (new data,
//! a hangup) or output that became possible sends the owner its signal.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::fd::{FileKind, FileRef, O_ASYNC, OpenFile};
use crate::ipc::{EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT};
use crate::process::Process;
use crate::procs::Procs;
use crate::signal::{self, SigInfo, Target};

const SIGIO: u32 = 29;
const SI_KERNEL: i32 = 0x80;
const POLL_IN: i32 = 1;
const POLL_OUT: i32 = 2;
const POLL_ERR: i32 = 4;
const POLL_HUP: i32 = 6;

/// Who F_SETOWN (or F_SETOWN_EX) named.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Owner {
    #[default]
    None,
    Process(u32),
    Group(u32),
    Thread(u32),
}

/// A file's owner and the signal it gets (F_SETSIG; 0 is SIGIO without
/// details), and who named the owner: the signals are that process's, as
/// if it sent them with kill, so they can't reach init unless it asked.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fown {
    pub owner: Owner,
    pub sig: u32,
    /// The process that called F_SETOWN, and its effective uid then.
    pub sender: u32,
    pub sender_uid: u32,
}

struct Entry {
    file: Weak<Mutex<OpenFile>>,
    /// The descriptor it was set through (si_fd).
    fd: u64,
    mask: u32,
    version: u64,
}

static FILES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
/// The I/O generation `deliver` last looked at.
static SEEN: AtomicU64 = AtomicU64::new(0);

/// Does Linux signal for this kind of file (has it ->fasync)? Others keep
/// O_ASYNC but never signal, as there.
fn signals(kind: &FileKind) -> bool {
    matches!(
        kind,
        FileKind::Pipe(_)
            | FileKind::Fifo(_)
            | FileKind::Socket(_)
            | FileKind::Inet(_)
            | FileKind::Unix(_)
            | FileKind::Netlink(_)
            | FileKind::Pty(_)
            | FileKind::Stdin
            | FileKind::Inotify(_)
    )
}

/// O_ASYNC was just set on `file` (not locked), through `fd`: watch it,
/// from what it's ready for now.
pub fn watch(file: &FileRef, fd: u64) {
    let (mask, version) = file.lock().kind.poll();
    let mut files = FILES.lock();
    files.retain(|e| e.file.strong_count() > 0);
    match files.iter_mut().find(|e| e.file.as_ptr() == Arc::as_ptr(file)) {
        Some(e) => (e.fd, e.mask, e.version) = (fd, mask, version),
        None => files.push(Entry { file: Arc::downgrade(file), fd, mask, version }),
    }
}

/// Signal the owners of files that became ready since the I/O state last
/// changed.
pub fn deliver(p: &mut Process, procs: &mut Procs) {
    let generation = crate::ipc::generation();
    if SEEN.swap(generation, Ordering::Relaxed) == generation {
        return;
    }
    let mut due = Vec::new();
    {
        let mut files = FILES.lock();
        files.retain(|e| e.file.strong_count() > 0);
        for e in files.iter_mut() {
            let Some(file) = e.file.upgrade() else { continue };
            let f = file.lock();
            let (mask, version) = f.kind.poll();
            let (was, changed) = (e.mask, version != e.version);
            (e.mask, e.version) = (mask, version);
            if f.flags & O_ASYNC == 0 || f.fown.owner == Owner::None || !signals(&f.kind) {
                continue;
            }
            let input = mask & (EPOLLIN | EPOLLHUP | EPOLLERR);
            if changed && input != 0 {
                due.push((f.fown, e.fd, input));
            } else if mask & !was & EPOLLOUT != 0 {
                due.push((f.fown, e.fd, EPOLLOUT));
            }
        }
    }
    for (fown, fd, ready) in due {
        send(p, procs, fown, fd, ready);
    }
}

/// Linux's send_sigio: SIGIO plain, or F_SETSIG's signal with the reason
/// (si_code), the poll bits (si_band) and the descriptor (si_fd).
fn send(p: &mut Process, procs: &mut Procs, fown: Fown, fd: u64, ready: u32) {
    // POLLIN|POLLRDNORM, POLLOUT|POLLWRNORM|POLLWRBAND, POLLERR, POLLHUP|POLLERR.
    let (code, band) = if ready & EPOLLHUP != 0 {
        (POLL_HUP, 0x18)
    } else if ready & EPOLLERR != 0 {
        (POLL_ERR, 0x8)
    } else if ready & EPOLLIN != 0 {
        (POLL_IN, 0x41)
    } else {
        (POLL_OUT, 0x304)
    };
    let (signo, code) = if fown.sig == 0 { (SIGIO, SI_KERNEL) } else { (fown.sig, code) };
    let info = SigInfo {
        signo,
        errno: 0,
        code,
        fields: [band, fd, 0, 0],
        fault: None,
        timer: None,
        why: "I/O possible (O_ASYNC)",
    };
    for q in procs.all(p) {
        let target = match fown.owner {
            Owner::Process(pid) if q.pid == pid => Target::Process,
            Owner::Group(pgid) if q.pgid == pgid => Target::Process,
            Owner::Thread(tid) if q.threads.contains_key(&tid) => Target::Thread(tid),
            _ => continue,
        };
        // As kill's: init only takes what it handles, unless it asked.
        if crate::syscall::shields_init(q, fown.sender, signo) {
            continue;
        }
        let _ = signal::send(q, target, info);
        q.timer_dirty = true;
    }
}
