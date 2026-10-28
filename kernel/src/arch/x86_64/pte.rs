//! x86_64 page-table entries (4 levels, 4 KiB pages): what `mm::paging`
//! writes. Every root has the kernel's upper half (`new_root`); a process's
//! own entries are the lower half's.

use crate::mm::p2v;
use crate::mm::paging::Prot;

pub const VALID: u64 = 1 << 0; // present
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const NX: u64 = 1 << 63;
pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// A root's entries that are the process's (the rest are the kernel's).
pub const USER_ROOT_ENTRIES: u64 = 256;

/// An entry pointing at the next level's table (the leaf decides).
pub fn table(next_pa: u64) -> u64 {
    next_pa | VALID | WRITABLE | USER
}

/// A user page's flags. Writable implies readable, as everywhere on x86.
/// PROT_NONE pages stay mapped but the kernel's alone (as on arm64), so
/// their contents survive mprotect round-trips. Accessed and dirty are set
/// already: nothing reads them.
pub fn leaf(prot: Prot) -> u64 {
    let f = VALID | ACCESSED | DIRTY;
    if prot.is_none() {
        return f | WRITABLE | NX;
    }
    let mut f = f | USER;
    if prot.write {
        f |= WRITABLE;
    }
    if !prot.exec {
        f |= NX;
    }
    f
}

/// A leaf entry with writes forbidden, for pages shared copy-on-write.
pub fn read_only(pte: u64) -> u64 {
    pte & !WRITABLE
}

/// Does a leaf entry let user code (and the kernel: CR0.WP) write the page?
pub fn writable(pte: u64) -> bool {
    pte & WRITABLE != 0
}

/// A new root at `root_pa` (zeroed): the kernel's half in it.
pub fn new_root(root_pa: u64) {
    let kernel = p2v(super::kernel_root()) as *const u64;
    let root = p2v(root_pa) as *mut u64;
    for i in USER_ROOT_ENTRIES as usize..512 {
        // SAFETY: both are page tables, mapped linearly.
        unsafe { root.add(i).write(kernel.add(i).read()) };
    }
}
