//! 4-level, 4 KiB-granule page tables for user address spaces (TTBR0).

use super::{PAGE_SIZE, frame, p2v};
use crate::arch;

pub const PTE_VALID: u64 = 1 << 0;
const PTE_TABLE_OR_PAGE: u64 = 1 << 1;
const PTE_ATTR_NORMAL: u64 = 1 << 2; // MAIR index 1
const PTE_AP_EL0: u64 = 1 << 6;
const PTE_AP_RO: u64 = 1 << 7;
const PTE_SH_INNER: u64 = 3 << 8;
const PTE_AF: u64 = 1 << 10;
const PTE_NG: u64 = 1 << 11;
const PTE_PXN: u64 = 1 << 53;
const PTE_UXN: u64 = 1 << 54;
pub const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prot {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Prot {
    pub const RW: Prot = Prot { read: true, write: true, exec: false };
    pub const RX: Prot = Prot { read: true, write: false, exec: true };

    /// From Linux PROT_* bits.
    pub fn from_linux(p: u64) -> Prot {
        Prot { read: p & 1 != 0, write: p & 2 != 0, exec: p & 4 != 0 }
    }

    /// From ELF PF_* bits.
    pub fn from_elf(f: u32) -> Prot {
        Prot { read: f & 4 != 0, write: f & 2 != 0, exec: f & 1 != 0 }
    }

    pub fn is_none(self) -> bool {
        !(self.read || self.write || self.exec)
    }

    /// Page-table flags for a user page. Writable implies readable and exec
    /// implies readable (as on Linux/arm64). PROT_NONE pages stay mapped but
    /// are inaccessible from EL0, so their contents survive mprotect round-trips.
    pub fn pte_flags(self) -> u64 {
        let mut f = PTE_VALID | PTE_TABLE_OR_PAGE | PTE_ATTR_NORMAL | PTE_SH_INNER | PTE_AF | PTE_NG | PTE_PXN;
        if self.is_none() {
            return f | PTE_UXN;
        }
        f |= PTE_AP_EL0;
        if !self.write {
            f |= PTE_AP_RO;
        }
        if !self.exec {
            f |= PTE_UXN;
        }
        f
    }
}

/// A leaf entry with writes forbidden, for pages shared copy-on-write.
pub fn read_only(pte: u64) -> u64 {
    pte | PTE_AP_RO
}

/// Does a leaf entry let EL0 (and the kernel) write the page?
pub fn writable(pte: u64) -> bool {
    pte & PTE_AP_RO == 0
}

pub struct PageTable {
    pub root: u64,
}

fn entry(table_pa: u64, idx: u64) -> *mut u64 {
    (p2v(table_pa) + idx * 8) as *mut u64
}

impl PageTable {
    pub fn new() -> Option<Self> {
        Some(Self { root: frame::alloc()? })
    }

    /// Pointer to the level-3 entry for `va`, creating intermediate tables if asked.
    fn walk(&mut self, va: u64, create: bool) -> Option<*mut u64> {
        let mut table = self.root;
        for level in 0..3 {
            let idx = (va >> (39 - 9 * level)) & 511;
            let e = entry(table, idx);
            let v = unsafe { *e };
            if v & PTE_VALID == 0 {
                if !create {
                    return None;
                }
                let next = frame::alloc()?;
                unsafe { *e = next | PTE_VALID | PTE_TABLE_OR_PAGE };
                table = next;
            } else {
                table = v & ADDR_MASK;
            }
        }
        Some(entry(table, (va >> 12) & 511))
    }

    /// The valid leaf entry for `va`, if any.
    pub fn lookup(&mut self, va: u64) -> Option<u64> {
        let e = unsafe { *self.walk(va, false)? };
        (e & PTE_VALID != 0).then_some(e)
    }

    pub fn map(&mut self, va: u64, pa: u64, flags: u64) -> Option<()> {
        let e = self.walk(va, true)?;
        unsafe { *e = (pa & ADDR_MASK) | flags };
        arch::pte_barrier();
        Some(())
    }

    /// Call `f(va, pte)` for every valid leaf entry in `[start, end)`,
    /// skipping unpopulated subtrees.
    pub fn for_each_mapped(&mut self, start: u64, end: u64, mut f: impl FnMut(u64, *mut u64)) {
        if start < end {
            visit(self.root, 0, 0, start, end, &mut f);
        }
    }
}

impl Drop for PageTable {
    /// Free the table pages (not the pages they map: the address space does that).
    fn drop(&mut self) {
        fn free_level(table: u64, level: u32) {
            if level < 3 {
                for idx in 0..512 {
                    let v = unsafe { *entry(table, idx) };
                    if v & PTE_VALID != 0 {
                        free_level(v & ADDR_MASK, level + 1);
                    }
                }
            }
            frame::free(table);
        }
        free_level(self.root, 0);
    }
}

fn visit(table: u64, level: u32, base: u64, start: u64, end: u64, f: &mut dyn FnMut(u64, *mut u64)) {
    let shift = 39 - 9 * level;
    let span = 1u64 << shift;
    let lo = (start.max(base) - base) >> shift;
    let hi = ((end - 1).min(base + 512 * span - 1) - base) >> shift;
    for idx in lo..=hi {
        let e = entry(table, idx);
        let v = unsafe { *e };
        if v & PTE_VALID == 0 {
            continue;
        }
        let va = base + idx * span;
        if level == 3 {
            f(va, e);
        } else {
            visit(v & ADDR_MASK, level + 1, va, start, end, f);
        }
    }
}

const _: () = assert!(PAGE_SIZE == 1 << 12);
