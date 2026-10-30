//! Terminal syscalls: reading and writing either end of a pseudo-terminal,
//! the termios and job-control ioctls, and opening /dev/ptmx, /dev/pts/N
//! and /dev/tty.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::file::would_block;
use super::table::nr;
use crate::errno::*;
use crate::fd::{FdEntry, FileKind, O_ACCMODE, O_CLOEXEC, new_file};
use crate::fs::{self, Dev, Ino};
use crate::process::Process;
use crate::signal::{self, SIG_IGN, SIGTTIN, SIGTTOU};
use crate::tty::{self, PtyEnd, TERMIOS_SIZE, TERMIOS2_SIZE, Termios, TtyRef};
use crate::uaccess::*;

const O_NOCTTY: u32 = 0o400;
/// How much one read or write moves (Linux's tty layer does 2 KiB at a time).
const CHUNK: usize = 4096;

/// A background process group touching its controlling terminal (Linux's
/// job_control and tty_check_change): the group gets `sig` (SIGTTIN for
/// reads, SIGTTOU for writes with TOSTOP and for changing settings) and
/// the call re-runs once it's continued. A SIGTTIN it ignores or blocks
/// makes the read fail with EIO; a SIGTTOU, the change just happens.
fn job_control(p: &mut Process, tty: &TtyRef, sig: u32) -> Result<(), Errno> {
    if !tty::is_ctty(p, tty) {
        return Ok(());
    }
    let fg = tty.lock().fg;
    if fg == 0 || fg == p.pgid {
        return Ok(());
    }
    let refused = p.action(sig).handler == SIG_IGN || p.cur().sigmask & signal::bit(sig) != 0;
    if refused {
        return if sig == SIGTTIN { Err(EIO) } else { Ok(()) };
    }
    tty::signal_group_now(p, p.pgid, sig);
    // Stopped now: this runs again when it continues (resuming changes I/O
    // state). With a handler, EINTR or SA_RESTART's re-run.
    let deadline = p.timeout_deadline(None);
    p.block_io(deadline, Ok(0)).map(|_| ())
}

pub fn read(p: &mut Process, end: &PtyEnd, buf: u64, count: u64, nonblock: bool) -> SysResult {
    if count == 0 {
        return Ok(0);
    }
    let max = (count as usize).min(CHUNK);
    let data = if end.master {
        let mut t = end.tty.lock();
        if t.output_len() == 0 {
            // The slave side is gone (and everything it wrote was read).
            if t.slave_closed() {
                return Err(EIO);
            }
            drop(t);
            return would_block(p, nonblock);
        }
        t.take_output(max)
    } else {
        job_control(p, &end.tty, SIGTTIN)?;
        let mut t = end.tty.lock();
        if t.hung_up() {
            return Ok(0);
        }
        if t.termios.lflag & tty::ICANON != 0 {
            match t.take_line(max) {
                Some(line) => line,
                None => {
                    drop(t);
                    tty::waiting_on(&end.tty);
                    return would_block(p, nonblock);
                }
            }
        } else {
            // VMIN bytes (or all that were asked for), waiting with no
            // limit; with VMIN 0, what's there after VTIME tenths of a
            // second at most. VMIN and VTIME together: any byte will do.
            let (min, time) = (t.termios.cc[tty::VMIN] as usize, t.termios.cc[tty::VTIME] as u64);
            let have = t.available();
            let enough = if min == 0 || time > 0 { have > 0 } else { have >= min.min(max) };
            if !enough && !(nonblock && have > 0) {
                drop(t);
                tty::waiting_on(&end.tty);
                if min == 0 && time == 0 {
                    return Ok(0);
                }
                if nonblock {
                    return Err(EAGAIN);
                }
                let timeout = (min == 0).then_some(time * 100_000_000);
                let deadline = p.timeout_deadline(timeout);
                return p.block_io(deadline, Ok(0));
            }
            t.take_input(max)
        }
    };
    copy_out(&mut p.aspace, buf, &data)?;
    Ok(data.len() as u64)
}

pub fn write(p: &mut Process, end: &PtyEnd, buf: u64, count: u64, nonblock: bool) -> SysResult {
    if count == 0 {
        return Ok(0);
    }
    let mut data = alloc::vec![0u8; (count as usize).min(CHUNK)];
    copy_in(&mut p.aspace, buf, &mut data)?;
    if end.master {
        let (used, sigs) = {
            let mut t = end.tty.lock();
            if t.slave_closed() {
                return Err(EIO);
            }
            let (used, sigs) = t.receive(&data);
            if used == 0 {
                drop(t);
                return would_block(p, nonblock);
            }
            (used, sigs)
        };
        for (pgrp, sig) in sigs {
            tty::signal_group_now(p, pgrp, sig);
        }
        return Ok(used as u64);
    }
    let tostop = end.tty.lock().termios.lflag & tty::TOSTOP != 0;
    if tostop {
        job_control(p, &end.tty, SIGTTOU)?;
    }
    let mut t = end.tty.lock();
    if t.hung_up() {
        return Err(EIO);
    }
    let used = if t.output_stopped() { 0 } else { t.write_slave(&data) };
    if used == 0 {
        drop(t);
        return would_block(p, nonblock);
    }
    Ok(used as u64)
}

pub fn ioctl(p: &mut Process, fd: u64, tty: TtyRef, master: bool, req: u64, arg: u64) -> SysResult {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TCGETS2: u64 = 0x802c_542a;
    const TCSETS2: u64 = 0x402c_542b;
    const TCSETSW2: u64 = 0x402c_542c;
    const TCSETSF2: u64 = 0x402c_542d;
    const TCSBRK: u64 = 0x5409;
    const TCXONC: u64 = 0x540a;
    const TCFLSH: u64 = 0x540b;
    const TIOCEXCL: u64 = 0x540c;
    const TIOCNXCL: u64 = 0x540d;
    const TIOCSCTTY: u64 = 0x540e;
    const TIOCGPGRP: u64 = 0x540f;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCOUTQ: u64 = 0x5411;
    const TIOCSTI: u64 = 0x5412;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONREAD: u64 = 0x541b;
    const TIOCNOTTY: u64 = 0x5422;
    const TIOCSETD: u64 = 0x5423;
    const TIOCGETD: u64 = 0x5424;
    const TCSBRKP: u64 = 0x5425;
    const TIOCSBRK: u64 = 0x5427;
    const TIOCCBRK: u64 = 0x5428;
    const TIOCGSID: u64 = 0x5429;
    const TIOCGPTN: u64 = 0x8004_5430;
    const TIOCSPTLCK: u64 = 0x4004_5431;
    const TIOCGPTLCK: u64 = 0x8004_5439;
    const TIOCGEXCL: u64 = 0x8004_5440;
    const TIOCGPTPEER: u64 = 0x5441;
    match req {
        TCGETS | TCGETS2 => {
            let b = tty.lock().termios.bytes();
            let n = if req == TCGETS { TERMIOS_SIZE } else { TERMIOS2_SIZE };
            copy_out(&mut p.aspace, arg, &b[..n]).map(|_| 0)
        }
        TCSETS | TCSETSW | TCSETSF | TCSETS2 | TCSETSW2 | TCSETSF2 => {
            let n = if req < 0x8000 { TERMIOS_SIZE } else { TERMIOS2_SIZE };
            let mut b = [0u8; TERMIOS2_SIZE];
            copy_in(&mut p.aspace, arg, &mut b[..n])?;
            job_control(p, &tty, SIGTTOU)?;
            // TCSETSW and TCSETSF don't wait for output to drain: a pty
            // has nothing to drain it to (Linux's has no chars_in_buffer).
            let mut t = tty.lock();
            if matches!(req, TCSETSF | TCSETSF2) {
                t.flush(true, false);
            }
            let new = Termios::from_bytes(&b[..n], &t.termios);
            t.set_termios(new);
            Ok(0)
        }
        // tcdrain (nothing to wait for, as above), tcsendbreak (no line
        // to send a break on).
        TCSBRK | TCSBRKP | TIOCSBRK | TIOCCBRK => Ok(0),
        TCXONC => {
            job_control(p, &tty, SIGTTOU)?;
            let mut t = tty.lock();
            match arg {
                0 => t.set_stopped(true),
                1 => t.set_stopped(false),
                2 => t.send_char(false),
                3 => t.send_char(true),
                _ => return Err(EINVAL),
            }
            Ok(0)
        }
        TCFLSH => {
            job_control(p, &tty, SIGTTOU)?;
            // The master's input is what the slave writes, and its output
            // what the slave reads.
            let (input, output) = match arg {
                0 => (true, false),
                1 => (false, true),
                2 => (true, true),
                _ => return Err(EINVAL),
            };
            let (input, output) = if master { (output, input) } else { (input, output) };
            tty.lock().flush(input, output);
            Ok(0)
        }
        TIOCEXCL | TIOCNXCL => {
            tty.lock().exclusive = req == TIOCEXCL;
            Ok(0)
        }
        TIOCGEXCL => {
            let v = tty.lock().exclusive as u32;
            write_u32(&mut p.aspace, arg, v).map(|_| 0)
        }
        TIOCGWINSZ => {
            let ws = tty.lock().winsize;
            let b: Vec<u8> = ws.iter().flat_map(|v| v.to_le_bytes()).collect();
            copy_out(&mut p.aspace, arg, &b).map(|_| 0)
        }
        TIOCSWINSZ => {
            let mut b = [0u8; 8];
            copy_in(&mut p.aspace, arg, &mut b)?;
            let ws = core::array::from_fn(|i| u16::from_le_bytes([b[i * 2], b[i * 2 + 1]]));
            let fg = tty.lock().set_winsize(ws);
            if let Some(fg) = fg {
                tty::signal_group_now(p, fg, tty::SIGWINCH);
            }
            Ok(0)
        }
        FIONREAD | TIOCOUTQ => {
            let t = tty.lock();
            // Each end's own queues: what it can read, and what it wrote
            // that the other end hasn't read.
            let n = match (req == FIONREAD, master) {
                (true, false) => t.available(),
                (true, true) => t.output_len(),
                (false, false) => t.output_len(),
                (false, true) => t.input_len(),
            };
            drop(t);
            write_u32(&mut p.aspace, arg, n as u32).map(|_| 0)
        }
        TIOCGETD => write_u32(&mut p.aspace, arg, 0).map(|_| 0), // N_TTY
        TIOCSETD => match read_u32(&mut p.aspace, arg)? {
            0 => Ok(0),
            _ => Err(EINVAL),
        },
        TIOCSCTTY => {
            if p.pid != p.sid {
                return Err(EPERM);
            }
            if let Some(c) = &p.ctty {
                return if Arc::ptr_eq(c, &tty) { Ok(0) } else { Err(EPERM) };
            }
            let readable = p.fds.get(fd)?.lock().readable();
            if !readable && p.uid != 0 {
                return Err(EPERM);
            }
            let old = tty.lock().session;
            if old != 0 {
                // Root may take it from another session (arg 1).
                if arg != 1 || p.uid != 0 {
                    return Err(EPERM);
                }
                let mut procs = crate::procs::PROCS.lock();
                for q in procs.all(p) {
                    if q.sid == old {
                        q.ctty = None;
                    }
                }
            }
            let mut t = tty.lock();
            if t.hung_up() {
                return Err(EIO);
            }
            (t.session, t.fg) = (p.sid, p.pgid);
            drop(t);
            p.ctty = Some(tty);
            Ok(0)
        }
        TIOCNOTTY => {
            if !tty::is_ctty(p, &tty) {
                return Err(ENOTTY);
            }
            if p.pid == p.sid {
                let sid = p.sid;
                let mut procs = crate::procs::PROCS.lock();
                tty::disassociate(Some(&mut *p), &mut procs, &tty, sid, false);
                crate::sched::timer_changed();
            }
            p.ctty = None;
            Ok(0)
        }
        TIOCGPGRP | TIOCGSID => {
            // The master may ask about its slave; anyone else only about
            // their controlling terminal.
            if !master && !tty::is_ctty(p, &tty) {
                return Err(ENOTTY);
            }
            let t = tty.lock();
            let v = if req == TIOCGPGRP { t.fg } else { t.session };
            drop(t);
            if req == TIOCGSID && v == 0 {
                return Err(ENOTTY);
            }
            write_u32(&mut p.aspace, arg, v).map(|_| 0)
        }
        TIOCSPGRP => {
            if !tty::is_ctty(p, &tty) || tty.lock().session != p.sid {
                return Err(ENOTTY);
            }
            let pgrp = read_u32(&mut p.aspace, arg)? as i32;
            if pgrp < 0 {
                return Err(EINVAL);
            }
            job_control(p, &tty, SIGTTOU)?;
            let pgrp = pgrp as u32;
            let (sid, mut found, mut same) = (p.sid, false, false);
            for q in crate::procs::PROCS.lock().all(p) {
                if q.pgid == pgrp {
                    found = true;
                    same |= q.sid == sid;
                }
            }
            if !found {
                return Err(ESRCH);
            }
            if !same {
                return Err(EPERM);
            }
            tty.lock().fg = pgrp;
            Ok(0)
        }
        // Linux leaves this off by default (legacy_tiocsti): it types into
        // someone else's terminal.
        TIOCSTI => p.unimplemented(nr::ioctl, "ioctl", "TIOCSTI", EIO),
        TIOCGPTN | TIOCSPTLCK | TIOCGPTLCK | TIOCGPTPEER if !master => Err(ENOTTY),
        TIOCGPTN => {
            let index = tty.lock().index;
            write_u32(&mut p.aspace, arg, index).map(|_| 0)
        }
        TIOCSPTLCK => {
            let lock = read_u32(&mut p.aspace, arg)? != 0;
            tty.lock().locked = lock;
            Ok(0)
        }
        TIOCGPTLCK => {
            let v = tty.lock().locked as u32;
            write_u32(&mut p.aspace, arg, v).map(|_| 0)
        }
        // The slave, opened from the master (glibc's openpty).
        TIOCGPTPEER => {
            let flags = arg as u32;
            let index = tty.lock().index;
            let ino = fs::lock().pts_node(index).ok_or(EIO)?;
            // An open like any other to Landlock (security_file_open).
            let denied = match crate::landlock::domain(p) {
                Some(d) => {
                    let fs = fs::lock();
                    crate::landlock::open_access(&d, &fs, ino, fs.node(ino).parent, flags & O_ACCMODE)?
                }
                None => 0,
            };
            let file = open_slave(p, &tty, ino, flags)?;
            file.lock().landlock_denied = denied;
            p.fds.alloc(FdEntry { file, cloexec: flags & O_CLOEXEC != 0 }, 0)
        }
        // Not terminals Linux's ptys answer for either: consoles, virtual
        // terminals, serial lines and modem lines.
        0x4b00..=0x4bff | 0x5600..=0x56ff | 0x5415..=0x5418 | 0x541c | 0x541e | 0x541f | 0x542e | 0x5459 | 0x545d => {
            Err(ENOTTY)
        }
        _ => p.unimplemented(nr::ioctl, "ioctl", &alloc::format!("terminal ioctl {req:#x}"), ENOTTY),
    }
}

/// An open slave, which a session leader may take as its controlling
/// terminal.
fn open_slave(p: &mut Process, tty: &TtyRef, ino: Ino, flags: u32) -> Result<crate::fd::FileRef, Errno> {
    {
        let t = tty.lock();
        if t.hung_up() || t.locked {
            return Err(EIO);
        }
        if t.exclusive && p.uid != 0 {
            return Err(EBUSY);
        }
    }
    let end = PtyEnd::new(tty.clone(), false, ino);
    tty::maybe_acquire(p, tty, flags & O_NOCTTY != 0);
    Ok(new_file(FileKind::Pty(end), flags & !(O_CLOEXEC | O_NOCTTY | crate::fd::O_CREAT_EXCL_TRUNC)))
}

/// Opening a terminal device node: /dev/ptmx makes a pair, /dev/pts/N is a
/// slave, /dev/tty the caller's controlling terminal. `fs` is held.
pub fn open_dev(p: &mut Process, fs: &mut fs::Fs, dev: Dev, ino: Ino, flags: u32) -> Result<crate::fd::FileRef, Errno> {
    let clean = flags & !(O_CLOEXEC | O_NOCTTY | crate::fd::O_CREAT_EXCL_TRUNC);
    match dev {
        Dev::Ptmx => {
            let tty = tty::new_pair(false)?;
            let index = tty.lock().index;
            fs.pts_show(index, (p.uid, p.gid));
            Ok(new_file(FileKind::Pty(PtyEnd::new(tty, true, ino)), clean))
        }
        Dev::Pts(index) => {
            let tty = tty::get(index).ok_or(EIO)?;
            open_slave(p, &tty, ino, flags)
        }
        Dev::Tty => {
            let tty = p.ctty.clone().ok_or(ENXIO)?;
            open_slave(p, &tty, ino, flags | O_NOCTTY)
        }
        _ => unreachable!("not a terminal"),
    }
}
