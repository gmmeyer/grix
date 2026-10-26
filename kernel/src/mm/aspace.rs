//! User address space: a set of VMAs (virtual memory areas) backed lazily by
//! page faults, plus the page table that realises them.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::paging::{ADDR_MASK, PageTable, Prot};
use super::{PAGE_SIZE, frame, p2v, page_down};
use crate::arch;
use crate::errno::*;

/// User addresses are below 2^48.
pub const USER_TOP: u64 = 1 << 48;
pub const STACK_TOP: u64 = 0x0000_ffff_fffe_0000;
pub const STACK_SIZE: u64 = 8 << 20;
/// mmap allocates top-down from here, leaving a gap below the stack.
pub const MMAP_TOP: u64 = STACK_TOP - STACK_SIZE - (128 << 20);
pub const MMAP_BOTTOM: u64 = 1 << 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Exec,
}

impl Access {
    pub fn describe_violation(self) -> &'static str {
        match self {
            Access::Read => "invalid read",
            Access::Write => "invalid write",
            Access::Exec => "invalid instruction fetch",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Backing {
    /// Zero-filled on first touch.
    Anon,
    /// Private file mapping. Byte `o` of the VMA is `data[offset + o]` while
    /// `o < filesz`, and zero after that (ELF .bss).
    File { data: &'static [u8], offset: u64, filesz: u64 },
}

#[derive(Clone, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
    pub backing: Backing,
}

impl Vma {
    pub fn anon(start: u64, end: u64, prot: Prot) -> Self {
        Vma { start, end, prot, backing: Backing::Anon }
    }

    /// The sub-range `[s, e)` of this VMA, with file offsets adjusted.
    pub fn slice(&self, s: u64, e: u64) -> Vma {
        debug_assert!(self.start <= s && s < e && e <= self.end);
        let skip = s - self.start;
        let backing = match self.backing {
            Backing::Anon => Backing::Anon,
            Backing::File { data, offset, filesz } => {
                Backing::File { data, offset: offset + skip, filesz: filesz.saturating_sub(skip) }
            }
        };
        Vma { start: s, end: e, prot: self.prot, backing }
    }

    pub fn allows(&self, access: Access) -> bool {
        match access {
            Access::Read => !self.prot.is_none(),
            Access::Write => self.prot.write,
            Access::Exec => self.prot.exec,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultError {
    /// No mapping, or the mapping forbids this access.
    Segv,
    OutOfMemory,
}

pub struct AddressSpace {
    pub pt: PageTable,
    vmas: BTreeMap<u64, Vma>,
    pub brk_start: u64,
    pub brk: u64,
}

impl AddressSpace {
    pub fn new() -> Option<Self> {
        Some(Self { pt: PageTable::new()?, vmas: BTreeMap::new(), brk_start: 0, brk: 0 })
    }

    pub fn activate(&self) {
        arch::set_user_page_table(self.pt.root);
    }

    pub fn find(&self, va: u64) -> Option<&Vma> {
        self.vmas.range(..=va).next_back().map(|(_, v)| v).filter(|v| va < v.end)
    }

    pub fn is_free(&self, start: u64, end: u64) -> bool {
        start < end && end <= USER_TOP && self.vmas.range(..end).next_back().is_none_or(|(_, v)| v.end <= start)
    }

    /// Highest free `len`-byte range below MMAP_TOP.
    pub fn find_free(&self, len: u64) -> Option<u64> {
        let mut end = MMAP_TOP;
        for (_, v) in self.vmas.range(..MMAP_TOP).rev() {
            if v.end <= end && end - v.end >= len {
                return Some(end - len);
            }
            end = end.min(v.start);
        }
        (end >= MMAP_BOTTOM + len).then(|| end - len)
    }

    /// Insert a mapping, replacing anything already in its range (MAP_FIXED semantics).
    pub fn map(&mut self, vma: Vma) {
        self.unmap(vma.start, vma.end);
        self.vmas.insert(vma.start, vma);
    }

    /// Remove `[start, end)` from the VMA set without touching pages.
    /// Returns the removed pieces in ascending order.
    fn carve(&mut self, start: u64, end: u64) -> Vec<Vma> {
        let keys: Vec<u64> = self.vmas.range(..end).rev().take_while(|(_, v)| v.end > start).map(|(k, _)| *k).collect();
        let mut removed = Vec::with_capacity(keys.len());
        for k in keys.into_iter().rev() {
            let v = self.vmas.remove(&k).unwrap();
            if v.start < start {
                self.vmas.insert(v.start, v.slice(v.start, start));
            }
            if v.end > end {
                self.vmas.insert(end, v.slice(end, v.end));
            }
            removed.push(v.slice(v.start.max(start), v.end.min(end)));
        }
        removed
    }

    /// munmap: drop mappings and free their pages.
    pub fn unmap(&mut self, start: u64, end: u64) {
        self.carve(start, end);
        self.discard(start, end);
    }

    /// Free the pages in `[start, end)` but keep the VMAs; the next access
    /// faults in fresh zero (or file) contents. MADV_DONTNEED semantics.
    pub fn discard(&mut self, start: u64, end: u64) {
        let mut any = false;
        self.pt.for_each_mapped(start, end, |_, pte| unsafe {
            frame::free(*pte & ADDR_MASK);
            *pte = 0;
            any = true;
        });
        if any {
            arch::flush_tlb();
        }
    }

    /// mprotect. Fails with ENOMEM if any part of the range is unmapped.
    pub fn protect(&mut self, start: u64, end: u64, prot: Prot) -> Result<(), Errno> {
        let mut expected = start;
        for (_, v) in self.vmas.range(..end).filter(|(_, v)| v.end > start) {
            if v.start > expected {
                return Err(ENOMEM);
            }
            expected = v.end;
        }
        if expected < end {
            return Err(ENOMEM);
        }
        for mut piece in self.carve(start, end) {
            piece.prot = prot;
            self.vmas.insert(piece.start, piece);
        }
        let flags = prot.pte_flags();
        self.pt.for_each_mapped(start, end, |_, pte| unsafe {
            let pa = *pte & ADDR_MASK;
            *pte = pa | flags;
            if prot.exec {
                arch::sync_icache(p2v(pa), PAGE_SIZE);
            }
        });
        arch::flush_tlb();
        Ok(())
    }

    /// mremap. `old`/`new_len`/`old_len` are page aligned.
    pub fn remap(&mut self, old: u64, old_len: u64, new_len: u64, may_move: bool) -> Result<u64, Errno> {
        let old_end = old.checked_add(old_len).ok_or(EINVAL)?;
        let vma = self.find(old).filter(|v| old_end <= v.end).ok_or(EFAULT)?.clone();
        if new_len <= old_len {
            self.unmap(old + new_len, old_end);
            return Ok(old);
        }
        let grow_end = old.checked_add(new_len).ok_or(ENOMEM)?;
        if old_end == vma.end && self.is_free(old_end, grow_end) {
            let mut ext = vma.slice(vma.start, vma.end);
            ext.start = vma.start;
            ext.end = grow_end;
            self.vmas.insert(vma.start, ext);
            return Ok(old);
        }
        if !may_move {
            return Err(ENOMEM);
        }
        let new = self.find_free(new_len).ok_or(ENOMEM)?;
        // Move existing pages rather than copying them.
        let mut pages = Vec::new();
        self.pt.for_each_mapped(old, old_end, |va, pte| unsafe {
            pages.push((va - old, *pte));
            *pte = 0;
        });
        self.carve(old, old_end);
        let mut moved = vma.slice(old, old_end);
        moved.start = new;
        moved.end = new + new_len;
        self.vmas.insert(new, moved);
        for (off, pte) in pages {
            self.pt.map(new + off, pte & ADDR_MASK, pte & !ADDR_MASK).ok_or(ENOMEM)?;
        }
        arch::flush_tlb();
        Ok(new)
    }

    /// Resolve a fault on an unmapped page.
    pub fn fault(&mut self, va: u64, access: Access) -> Result<(), FaultError> {
        let page = page_down(va);
        let vma = self.find(va).ok_or(FaultError::Segv)?.clone();
        if !vma.allows(access) || self.pt.lookup(page).is_some() {
            return Err(FaultError::Segv);
        }
        let pa = frame::alloc().ok_or(FaultError::OutOfMemory)?;
        if let Backing::File { data, offset, filesz } = vma.backing {
            let o = page - vma.start;
            if o < filesz {
                let n = (filesz - o).min(PAGE_SIZE);
                let src = offset + o;
                let avail = (data.len() as u64).saturating_sub(src).min(n);
                if avail > 0 {
                    let src = &data[src as usize..(src + avail) as usize];
                    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), p2v(pa) as *mut u8, src.len()) };
                }
            }
        }
        if vma.prot.exec {
            arch::sync_icache(p2v(pa), PAGE_SIZE);
        }
        if self.pt.map(page, pa, vma.prot.pte_flags()).is_none() {
            frame::free(pa);
            return Err(FaultError::OutOfMemory);
        }
        Ok(())
    }

    /// Make sure the kernel can access `[addr, addr+len)` on behalf of the
    /// user: every page must be in a VMA that permits the access, and gets
    /// faulted in now so the kernel itself never takes a page fault.
    pub fn ensure(&mut self, addr: u64, len: u64, write: bool) -> Result<(), Errno> {
        if len == 0 {
            return Ok(());
        }
        let end = addr.checked_add(len).ok_or(EFAULT)?;
        if end > USER_TOP {
            return Err(EFAULT);
        }
        let access = if write { Access::Write } else { Access::Read };
        let mut page = page_down(addr);
        while page < end {
            if !self.find(page).ok_or(EFAULT)?.allows(access) {
                return Err(EFAULT);
            }
            if self.pt.lookup(page).is_none() {
                self.fault(page, access).map_err(|e| match e {
                    FaultError::OutOfMemory => ENOMEM,
                    FaultError::Segv => EFAULT,
                })?;
            }
            page += PAGE_SIZE;
        }
        Ok(())
    }
}
