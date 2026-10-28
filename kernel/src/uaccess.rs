//! Copying data between the kernel and user memory.
//!
//! Every access is validated against the VMAs first and the pages are faulted
//! in up front, so the kernel never takes a fault on a user address.

use alloc::string::String;
use alloc::vec::Vec;

use crate::errno::*;
use crate::mm::aspace::AddressSpace;
use crate::mm::{PAGE_SIZE, page_down};

pub const PATH_MAX: usize = 4096;

pub fn copy_in(a: &mut AddressSpace, addr: u64, out: &mut [u8]) -> Result<(), Errno> {
    a.ensure(addr, out.len() as u64, false)?;
    unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), out.len()) };
    Ok(())
}

pub fn copy_out(a: &mut AddressSpace, addr: u64, data: &[u8]) -> Result<(), Errno> {
    a.ensure(addr, data.len() as u64, true)?;
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len()) };
    Ok(())
}

pub fn zero_out(a: &mut AddressSpace, addr: u64, len: u64) -> Result<(), Errno> {
    a.ensure(addr, len, true)?;
    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len as usize) };
    Ok(())
}

pub fn read_u64(a: &mut AddressSpace, addr: u64) -> Result<u64, Errno> {
    let mut b = [0u8; 8];
    copy_in(a, addr, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

pub fn read_u32(a: &mut AddressSpace, addr: u64) -> Result<u32, Errno> {
    let mut b = [0u8; 4];
    copy_in(a, addr, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

pub fn write_u64(a: &mut AddressSpace, addr: u64, v: u64) -> Result<(), Errno> {
    copy_out(a, addr, &v.to_le_bytes())
}

pub fn write_u32(a: &mut AddressSpace, addr: u64, v: u32) -> Result<(), Errno> {
    copy_out(a, addr, &v.to_le_bytes())
}

/// Replace the aligned u32 at `addr` with `f(old)` atomically (threads on
/// other CPUs may be changing it too); returns the old value.
pub fn update_u32(a: &mut AddressSpace, addr: u64, f: impl Fn(u32) -> u32) -> Result<u32, Errno> {
    if !addr.is_multiple_of(4) {
        return Err(EINVAL);
    }
    a.ensure(addr, 4, true)?;
    // SAFETY: validated, present and writable (ensure), and aligned.
    let word = unsafe { core::sync::atomic::AtomicU32::from_ptr(addr as *mut u32) };
    Ok(word
        .try_update(core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst, |v| Some(f(v)))
        .unwrap_or_else(|v| v))
}

/// Read a NUL-terminated string. Non-UTF-8 strings cannot name anything in
/// our filesystem, so they are reported as ENOENT.
pub fn read_cstr(a: &mut AddressSpace, addr: u64, max: usize) -> Result<String, Errno> {
    let mut out = Vec::new();
    let mut p = addr;
    loop {
        a.ensure(p, 1, false)?;
        let page_end = page_down(p) + PAGE_SIZE;
        while p < page_end {
            let b = unsafe { *(p as *const u8) };
            if b == 0 {
                return String::from_utf8(out).map_err(|_| ENOENT);
            }
            out.push(b);
            p += 1;
            if out.len() >= max {
                return Err(ENAMETOOLONG);
            }
        }
    }
}

/// Read a (sec, nsec) timespec as nanoseconds.
pub fn read_timespec_ns(a: &mut AddressSpace, addr: u64) -> Result<u64, Errno> {
    let sec = read_u64(a, addr)? as i64;
    let nsec = read_u64(a, addr + 8)? as i64;
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(EINVAL);
    }
    Ok((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64))
}

pub fn write_timespec(a: &mut AddressSpace, addr: u64, ns: u64) -> Result<(), Errno> {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
    b[8..].copy_from_slice(&(ns % 1_000_000_000).to_le_bytes());
    copy_out(a, addr, &b)
}
