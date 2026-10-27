//! Guest RAM: one anonymous mapping, shared with the vCPU.
//!
//! Device threads read and write it while the guest runs. Every address the
//! guest gives a device is checked against it first: a bad one is the
//! guest's error, never a fault here.

use std::ptr;

pub struct GuestMemory {
    host: *mut u8,
    base: u64,
    size: usize,
}

// SAFETY: the mapping lives as long as the process (it's never unmapped),
// and access is by copies through raw pointers, as with any memory the
// guest shares.
unsafe impl Send for GuestMemory {}
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    /// `size` bytes of zeroed memory for guest physical `base..`.
    pub fn new(base: u64, size: usize) -> std::io::Result<GuestMemory> {
        // SAFETY: a fresh anonymous mapping.
        let host = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(GuestMemory { host: host.cast(), base, size })
    }

    /// `size` bytes of `fd` from `offset`, copy-on-write: a snapshot's RAM,
    /// paged in as the guest touches it.
    pub fn map_file(fd: i32, offset: u64, base: u64, size: usize) -> std::io::Result<GuestMemory> {
        // SAFETY: a fresh private mapping of a file we hold.
        let host = unsafe {
            libc::mmap(ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE, fd, offset as libc::off_t)
        };
        if host == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(GuestMemory { host: host.cast(), base, size })
    }

    pub fn host(&self) -> *mut u8 {
        self.host
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// The host address of guest `addr..addr + len`, if that's all RAM.
    fn at(&self, addr: u64, len: usize) -> Option<*mut u8> {
        let off = addr.checked_sub(self.base)? as usize;
        (off <= self.size && len <= self.size - off).then(|| self.host.wrapping_add(off))
    }

    /// Is guest `addr..addr + len` all RAM?
    pub fn contains(&self, addr: u64, len: usize) -> bool {
        self.at(addr, len).is_some()
    }

    pub fn read(&self, addr: u64, out: &mut [u8]) -> bool {
        let Some(p) = self.at(addr, out.len()) else { return false };
        // SAFETY: in the mapping (checked above).
        unsafe { ptr::copy_nonoverlapping(p, out.as_mut_ptr(), out.len()) };
        true
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        let Some(p) = self.at(addr, data.len()) else { return false };
        // SAFETY: in the mapping (checked above).
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) };
        true
    }

    /// A little-endian u16 the guest may be writing concurrently (ring
    /// indices and flags).
    pub fn read_u16(&self, addr: u64) -> Option<u16> {
        let p = self.at(addr, 2)?;
        if !(p as usize).is_multiple_of(2) {
            return None;
        }
        // SAFETY: in the mapping and aligned.
        Some(u16::from_le(unsafe { ptr::read_volatile(p as *const u16) }))
    }

    pub fn write_u16(&self, addr: u64, v: u16) -> bool {
        let Some(p) = self.at(addr, 2) else { return false };
        if !(p as usize).is_multiple_of(2) {
            return false;
        }
        // SAFETY: in the mapping and aligned.
        unsafe { ptr::write_volatile(p as *mut u16, v.to_le()) };
        true
    }

    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let mut b = [0; 4];
        self.read(addr, &mut b).then(|| u32::from_le_bytes(b))
    }

    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0; 8];
        self.read(addr, &mut b).then(|| u64::from_le_bytes(b))
    }
}
