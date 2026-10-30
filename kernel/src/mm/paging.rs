//! 4-level, 4 KiB-granule page tables for user address spaces (the entries'
//! format is `arch::pte`'s).

use alloc::vec::Vec;

use super::{PAGE_SIZE, frame, p2v};
use crate::arch;

pub use crate::arch::pte::ADDR_MASK;
use crate::arch::pte::{self, VALID};

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

    /// Page-table flags for a user page (`arch::pte::leaf`).
    pub fn pte_flags(self) -> u64 {
        pte::leaf(self)
    }
}

/// A leaf entry with writes forbidden, for pages shared copy-on-write.
pub fn read_only(e: u64) -> u64 {
    pte::read_only(e)
}

/// Does a leaf entry let user code (and the kernel) write the page?
pub fn writable(e: u64) -> bool {
    pte::writable(e)
}

pub struct PageTable {
    pub root: u64,
}

fn entry(table_pa: u64, idx: u64) -> *mut u64 {
    (p2v(table_pa) + idx * 8) as *mut u64
}

impl PageTable {
    pub fn new() -> Option<Self> {
        let root = frame::alloc()?;
        pte::new_root(root);
        Some(Self { root })
    }

    /// Pointer to the level-3 entry for `va`, creating intermediate tables if asked.
    fn walk(&mut self, va: u64, create: bool) -> Option<*mut u64> {
        let mut table = self.root;
        for level in 0..3 {
            let idx = (va >> (39 - 9 * level)) & 511;
            let e = entry(table, idx);
            let v = unsafe { *e };
            if v & VALID == 0 {
                if !create {
                    return None;
                }
                let next = frame::alloc()?;
                // The zeroed table before the entry that points at it.
                arch::publish_barrier();
                unsafe { *e = pte::table(next) };
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
        (e & VALID != 0).then_some(e)
    }

    pub fn map(&mut self, va: u64, pa: u64, flags: u64) -> Option<()> {
        let e = self.walk(va, true)?;
        // The page's contents before the entry that maps it.
        arch::publish_barrier();
        unsafe { *e = (pa & ADDR_MASK) | flags };
        arch::pte_barrier();
        Some(())
    }

    /// Call `f(pte)` for every valid leaf entry in `[start, end)`, only
    /// reading them.
    pub fn each_entry(&self, start: u64, end: u64, mut f: impl FnMut(u64)) {
        if start < end {
            visit(self.root, 0, 0, start, end, &mut |_, e| f(unsafe { *e }));
        }
    }

    /// Take out the tables under the root that cover part of `[start,
    /// end)` and map nothing now, and return them ((table, an address it
    /// covered)): the caller frees them once no TLB or walk cache can
    /// lead to them (`arch::flush_tables`).
    pub fn prune(&mut self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut gone = Vec::new();
        if start < end {
            prune(self.root, 0, 0, start, end, &mut gone);
        }
        gone
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
                // The root's upper entries may be the kernel's: not ours to free.
                let entries = if level == 0 { pte::USER_ROOT_ENTRIES } else { 512 };
                for idx in 0..entries {
                    let v = unsafe { *entry(table, idx) };
                    if v & VALID != 0 {
                        free_level(v & ADDR_MASK, level + 1);
                    }
                }
            }
            frame::free(table);
        }
        free_level(self.root, 0);
    }
}

/// `PageTable::prune` below `table` (at `level`, covering from `base`).
fn prune(table: u64, level: u32, base: u64, start: u64, end: u64, gone: &mut Vec<(u64, u64)>) {
    let shift = 39 - 9 * level;
    let span = 1u64 << shift;
    let lo = (start.max(base) - base) >> shift;
    let hi = ((end - 1).min(base + 512 * span - 1) - base) >> shift;
    for idx in lo..=hi {
        let e = entry(table, idx);
        let v = unsafe { *e };
        if v & VALID == 0 || level == 3 {
            continue;
        }
        let (next, va) = (v & ADDR_MASK, base + idx * span);
        prune(next, level + 1, va, start, end, gone);
        if (0..512).all(|i| unsafe { *entry(next, i) } & VALID == 0) {
            unsafe { *e = 0 };
            gone.push((next, va));
        }
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
        if v & VALID == 0 {
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
