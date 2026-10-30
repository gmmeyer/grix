//! splice, tee and vmsplice, as copies through a kernel buffer: grix's
//! pipes hold bytes, not pages. Each call moves at most one chunk, as a
//! read and a write would: the source is looked at first and only what
//! the destination took is consumed, so nothing is lost when it takes
//! less (or nothing, and the call waits or fails with EAGAIN).
//! Linux's rules hold: one side of a splice must be a pipe, a pipe's
//! offset must be NULL (ESPIPE), the same pipe can't be both (EINVAL), and
//! SPLICE_F_NONBLOCK makes the pipes' sides not wait.

use alloc::vec::Vec;

use super::file::{Src, pipe_read, pipe_write, would_block, write_content_at};
use crate::errno::*;
use crate::fd::{FifoFile, FileKind, FileRef, O_APPEND, OpenFile, lock_pair};
use crate::inet::State;
use crate::ipc::PipeEnd;
use crate::process::Process;
use crate::uaccess::*;

const SPLICE_F_NONBLOCK: u64 = 2;
/// SPLICE_F_MOVE, NONBLOCK, MORE and GIFT: hints, or (NONBLOCK) honoured.
const SPLICE_FLAGS: u64 = 0xf;
/// The most one call moves (Linux's default pipe holds as much).
const CHUNK: usize = 64 * 1024;

/// The pipe end a file reads (`write`: writes) through, if it's a pipe or
/// FIFO.
fn pipe_end(f: &OpenFile, write: bool) -> Option<&PipeEnd> {
    match &f.kind {
        FileKind::Pipe(end) if end.write == write => Some(end),
        FileKind::Fifo(FifoFile { read: Some(end), .. }) if !write => Some(end),
        FileKind::Fifo(FifoFile { write: Some(end), .. }) if write => Some(end),
        _ => None,
    }
}

fn is_pipe(f: &OpenFile) -> bool {
    matches!(f.kind, FileKind::Pipe(_) | FileKind::Fifo(_))
}

/// What a source has now.
enum Peeked {
    Data(Vec<u8>),
    /// End of file, or a pipe or stream with no writers left.
    End,
    /// Nothing yet.
    Empty,
}

/// Up to `n` bytes from the front of a pipe, left there.
fn peek_pipe(end: &PipeEnd, n: usize) -> Peeked {
    let pipe = end.pipe.lock();
    if pipe.buf.is_empty() {
        return if pipe.writers == 0 { Peeked::End } else { Peeked::Empty };
    }
    Peeked::Data(pipe.buf.iter().take(n).copied().collect())
}

/// Take `n` bytes off the front of a pipe (what was peeked and written),
/// with any descriptors that came with them, which close.
fn consume_pipe(end: &PipeEnd, n: usize) {
    let mut pipe = end.pipe.lock();
    let n = n.min(pipe.buf.len());
    pipe.buf.drain(..n);
    pipe.read += n as u64;
    let read = pipe.read;
    let mut dropped = Vec::new();
    while pipe.rights.front().is_some_and(|&(pos, _)| pos < read) {
        dropped.push(pipe.rights.pop_front());
    }
    pipe.drained();
    pipe.touch();
    drop(pipe);
    drop(dropped);
}

/// Where a splice reads from.
enum Source {
    Pipe,
    /// A regular file, from this offset.
    File(u64),
    /// A connected stream socket.
    Stream,
}

/// Look at up to `n` bytes `f` has (at `off` for a file).
fn peek(f: &OpenFile, src: &Source, n: usize) -> Result<Peeked, Errno> {
    match (src, &f.kind) {
        (Source::Pipe, _) => Ok(peek_pipe(pipe_end(f, false).ok_or(EBADF)?, n)),
        (&Source::File(off), _) => {
            let c = f.content.clone().ok_or(EINVAL)?;
            let mut data = alloc::vec![0u8; n];
            let got = c.lock().read_at(off, &mut data)?;
            data.truncate(got);
            Ok(if got == 0 { Peeked::End } else { Peeked::Data(data) })
        }
        (Source::Stream, FileKind::Socket(s)) => Ok(s.rx.as_ref().map_or(Peeked::End, |rx| peek_pipe(rx, n))),
        (Source::Stream, FileKind::Inet(s)) => match &s.state {
            State::Local { end, .. } => Ok(end.rx.as_ref().map_or(Peeked::End, |rx| peek_pipe(rx, n))),
            State::Remote(c) => {
                let mut data = alloc::vec![0u8; n];
                match c.lock().read(&mut data, true) {
                    Some(Ok(0)) => Ok(Peeked::End),
                    Some(Ok(k)) => {
                        data.truncate(k);
                        Ok(Peeked::Data(data))
                    }
                    Some(Err(e)) => Err(e),
                    None => Ok(Peeked::Empty),
                }
            }
            State::Idle | State::Listening(_) | State::Udp(_) => Err(EINVAL),
        },
        _ => Err(EINVAL),
    }
}

/// Take the `n` bytes peeked (a file's offset moves in `splice`).
fn consume(f: &OpenFile, src: &Source, n: usize) {
    match (src, &f.kind) {
        (Source::Pipe, _) => {
            if let Some(end) = pipe_end(f, false) {
                consume_pipe(end, n);
            }
        }
        (Source::Stream, FileKind::Socket(s)) => {
            if let Some(rx) = &s.rx {
                consume_pipe(rx, n);
            }
        }
        (Source::Stream, FileKind::Inet(s)) => match &s.state {
            State::Local { end, .. } => {
                if let Some(rx) = &end.rx {
                    consume_pipe(rx, n);
                }
            }
            State::Remote(c) => {
                let mut scratch = alloc::vec![0u8; n];
                let _ = c.lock().read(&mut scratch, false);
            }
            _ => {}
        },
        _ => {}
    }
}

/// Write `data` to `f` (at `off` for a file, or where its offset is):
/// how much it took. Blocks (or EAGAIN with `nonblock`) as a write would.
fn write_out(p: &mut Process, f: &mut OpenFile, off: Option<u64>, data: &[u8], nonblock: bool) -> SysResult {
    let src = Src::Kernel(data);
    let n = data.len() as u64;
    let sock_nonblock = nonblock || f.nonblocking();
    if is_pipe(f) {
        let end = pipe_end(f, true).ok_or(EBADF)?;
        return pipe_write(p, end, src, n, nonblock, true);
    }
    match &mut f.kind {
        &mut FileKind::Node(ino) => {
            let c = f.content.clone().ok_or(EINVAL)?;
            let append = f.flags & O_APPEND != 0;
            let at = match off {
                Some(o) => o,
                None if append => c.lock().len(),
                None => f.offset,
            };
            let (k, at) = write_content_at(p, &c, ino, at, append, src, n)?;
            if off.is_none() {
                f.offset = at + k;
            }
            Ok(k)
        }
        FileKind::Socket(s) => match &s.tx {
            Some(tx) => pipe_write(p, tx, src, n, sock_nonblock, true),
            None => {
                crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: wrote to a socket that was shut down");
                Err(EPIPE)
            }
        },
        FileKind::Inet(s) if !s.dgram => super::net::inet_write(p, s, src, n, sock_nonblock, true, None),
        FileKind::Stdout | FileKind::Stderr => {
            let ch = if matches!(f.kind, FileKind::Stdout) {
                grix_abi::wire::Channel::Stdout
            } else {
                grix_abi::wire::Channel::Stderr
            };
            let k = data.len().min(crate::console::WRITE_CHUNK);
            if crate::console::try_write(ch, &data[..k]) { Ok(k as u64) } else { would_block(p, sock_nonblock) }
        }
        _ => Err(EINVAL),
    }
}

/// The two files, checked for reading and writing.
fn files(p: &Process, fd_in: u64, fd_out: u64) -> Result<(FileRef, FileRef), Errno> {
    let (fin, fout) = (p.fds.get(fd_in)?, p.fds.get(fd_out)?);
    // (One statement each: they may be one file.)
    let r = fin.lock().readable();
    let w = fout.lock().writable();
    if !r || !w {
        return Err(EBADF);
    }
    Ok((fin, fout))
}

pub fn splice(p: &mut Process, fd_in: u64, off_in: u64, fd_out: u64, off_out: u64, len: u64, flags: u64) -> SysResult {
    if flags & !SPLICE_FLAGS != 0 {
        return Err(EINVAL);
    }
    let (fin, fout) = files(p, fd_in, fd_out)?;
    if alloc::sync::Arc::ptr_eq(&fin, &fout) {
        return Err(EINVAL);
    }
    let in_pipe = is_pipe(&fin.lock());
    let out_pipe = is_pipe(&fout.lock());
    if !in_pipe && !out_pipe {
        return Err(EINVAL);
    }
    if (in_pipe && off_in != 0) || (out_pipe && off_out != 0) {
        return Err(ESPIPE);
    }
    if in_pipe && out_pipe {
        let same = {
            let (a, b) = lock_pair(&fin, &fout);
            match (pipe_end(&a, false), pipe_end(&b, true)) {
                (Some(x), Some(y)) => alloc::sync::Arc::ptr_eq(&x.pipe, &y.pipe),
                _ => return Err(EBADF),
            }
        };
        if same {
            return Err(EINVAL);
        }
    }
    let read_off = |p: &mut Process, ptr: u64| -> Result<Option<u64>, Errno> {
        if ptr == 0 {
            return Ok(None);
        }
        let o = read_u64(&mut p.aspace, ptr)?;
        if (o as i64) < 0 { Err(EINVAL) } else { Ok(Some(o)) }
    };
    let (oin, oout) = (read_off(p, off_in)?, read_off(p, off_out)?);
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    let (mut i, mut o) = lock_pair(&fin, &fout);
    // A file given an offset can't be one that appends (do_splice).
    if oout.is_some() && o.flags & O_APPEND != 0 {
        return Err(EINVAL);
    }
    let src = match &i.kind {
        FileKind::Pipe(_) | FileKind::Fifo(_) => Source::Pipe,
        FileKind::Node(_) if i.content.is_some() => Source::File(oin.unwrap_or(i.offset)),
        FileKind::Socket(_) => Source::Stream,
        FileKind::Inet(s) if !s.dgram => Source::Stream,
        _ => return Err(EINVAL),
    };
    if len == 0 {
        return Ok(0);
    }
    let mut want = (len as usize).min(CHUNK);
    // Into a pipe: no more than it has room for, so nothing taken from a
    // socket is lost.
    if out_pipe {
        let end = pipe_end(&o, true).ok_or(EBADF)?;
        let pipe = end.pipe.lock();
        if pipe.readers == 0 {
            drop(pipe);
            crate::signal::raise(p, crate::signal::SIGPIPE, "SIGPIPE: spliced to a pipe with no readers");
            return Err(EPIPE);
        }
        want = want.min(pipe.space());
        if want == 0 {
            drop(pipe);
            return would_block(p, nonblock);
        }
    }
    let mut data = match peek(&i, &src, want)? {
        Peeked::Data(d) => d,
        Peeked::End => return Ok(0),
        // The pipe's side waits unless SPLICE_F_NONBLOCK; a socket's as
        // its own O_NONBLOCK says too.
        Peeked::Empty => return would_block(p, nonblock || (!in_pipe && i.nonblocking())),
    };
    // Only now, for what there is: Go's io.Copy waits here, a pipe for each
    // idle connection, and room held for nothing is 64 KiB of `kmem` each.
    if out_pipe {
        let room = pipe_end(&o, true).ok_or(EBADF)?.pipe.lock().reserve(data.len());
        data.truncate(room);
        if room == 0 {
            return would_block(p, nonblock);
        }
    }
    let n = write_out(p, &mut o, oout, &data, nonblock)?;
    consume(&i, &src, n as usize);
    if let Source::File(at) = src {
        match oin {
            Some(_) => write_u64(&mut p.aspace, off_in, at + n)?,
            None => i.offset = at + n,
        }
    }
    if let Some(at) = oout {
        drop(o);
        write_u64(&mut p.aspace, off_out, at + n)?;
    }
    Ok(n)
}

/// tee: copy from one pipe to another, leaving the bytes in the first.
pub fn tee(p: &mut Process, fd_in: u64, fd_out: u64, len: u64, flags: u64) -> SysResult {
    if flags & !SPLICE_FLAGS != 0 {
        return Err(EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    let (fin, fout) = files(p, fd_in, fd_out)?;
    // One file can't be both ends, pipe or not (and it's one lock).
    if alloc::sync::Arc::ptr_eq(&fin, &fout) {
        return Err(EINVAL);
    }
    let (i, mut o) = lock_pair(&fin, &fout);
    let (Some(rx), Some(tx)) = (pipe_end(&i, false), pipe_end(&o, true)) else { return Err(EINVAL) };
    if alloc::sync::Arc::ptr_eq(&rx.pipe, &tx.pipe) {
        return Err(EINVAL);
    }
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    let data = match peek_pipe(rx, (len as usize).min(CHUNK)) {
        Peeked::Data(d) => d,
        Peeked::End => return Ok(0),
        Peeked::Empty => return would_block(p, nonblock),
    };
    write_out(p, &mut o, None, &data, nonblock)
}

/// vmsplice: the program's buffers into a pipe it writes, or (as Linux
/// copies them) out of one it reads.
pub fn vmsplice(p: &mut Process, fd: u64, iov: u64, nr_segs: u64, flags: u64) -> SysResult {
    if flags & !SPLICE_FLAGS != 0 {
        return Err(EINVAL);
    }
    let file = p.fds.get(fd)?;
    let f = file.lock();
    let write = f.writable();
    let Some(end) = pipe_end(&f, write).filter(|_| write || f.readable()) else { return Err(EBADF) };
    if nr_segs > 1024 {
        return Err(EINVAL);
    }
    let bufs = super::file::iovecs(p, iov, nr_segs)?;
    let nonblock = flags & SPLICE_F_NONBLOCK != 0 || f.nonblocking();
    let mut total = 0;
    for (k, &(base, len)) in bufs.iter().enumerate() {
        // Only the first may wait: then a partial count is returned.
        let nb = nonblock || k > 0;
        let r = if write {
            pipe_write(p, end, Src::User(base), len, nb, true)
        } else {
            pipe_read(p, end, base, len, nb, false)
        };
        match r {
            Ok(n) => {
                total += n;
                if n < len {
                    break;
                }
            }
            Err(e) if total == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(total)
}
