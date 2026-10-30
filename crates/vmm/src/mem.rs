//! Guest RAM: one anonymous mapping, shared with the vCPUs, for the
//! regions of guest physical memory `grix_abi::machine` puts it in.
//!
//! Device threads read and write it while the guest runs. Every address the
//! guest gives a device is checked against it first: a bad one is the
//! guest's error, never a fault here.

use std::ptr;

use grix_abi::machine::RamRegions;

pub struct GuestMemory {
    host: *mut u8,
    size: usize,
    /// Guest physical `(base, size)` of each region (`machine::RamRegions`,
    /// empty ones left out), one after another in the mapping.
    regions: Vec<(u64, usize)>,
}

// SAFETY: the mapping lives as long as the process (it's never unmapped),
// and access is by copies through raw pointers, as with any memory the
// guest shares.
unsafe impl Send for GuestMemory {}
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    /// Zeroed memory for guest RAM in `regions`.
    pub fn new(regions: RamRegions) -> std::io::Result<GuestMemory> {
        let regions = Self::layout(regions)?;
        let size = regions.iter().map(|r| r.1).sum();
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
        Ok(GuestMemory { host: host.cast(), size, regions })
    }

    /// `fd` from `offset`, copy-on-write, as guest RAM in `regions` (one
    /// after another in the file): a snapshot's RAM, paged in as the guest
    /// touches it.
    pub fn map_file(fd: i32, offset: u64, regions: RamRegions) -> std::io::Result<GuestMemory> {
        let regions = Self::layout(regions)?;
        let size = regions.iter().map(|r| r.1).sum();
        // SAFETY: a fresh private mapping of a file we hold.
        let host = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                fd,
                offset as libc::off_t,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(GuestMemory { host: host.cast(), size, regions })
    }

    fn layout(regions: RamRegions) -> std::io::Result<Vec<(u64, usize)>> {
        let regions: Vec<(u64, usize)> =
            regions.iter().filter(|r| r.1 > 0).map(|&(base, size)| (base, size as usize)).collect();
        if regions.is_empty() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        Ok(regions)
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Each region: its guest physical base, where it is in the mapping,
    /// and its size.
    pub fn regions(&self) -> impl Iterator<Item = (u64, *mut u8, usize)> + '_ {
        let mut off = 0;
        self.regions.iter().map(move |&(base, size)| {
            let host = self.host.wrapping_add(off);
            off += size;
            (base, host, size)
        })
    }

    /// The host address of guest `addr..addr + len`, if that's all RAM
    /// (in one region: they're never adjacent).
    fn at(&self, addr: u64, len: usize) -> Option<*mut u8> {
        self.regions().find_map(|(base, host, size)| {
            let off = addr.checked_sub(base)?;
            let off = usize::try_from(off).ok().filter(|&o| o < size || (o == size && len == 0))?;
            (len <= size - off).then(|| host.wrapping_add(off))
        })
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
