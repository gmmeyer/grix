//! Stage-1 page-table entries (4 KiB granule): what `mm::paging` writes.

use crate::mm::paging::Prot;

pub const VALID: u64 = 1 << 0;
const TABLE_OR_PAGE: u64 = 1 << 1;
const ATTR_NORMAL: u64 = 1 << 2; // MAIR index 1
const AP_EL0: u64 = 1 << 6;
const AP_RO: u64 = 1 << 7;
const SH_INNER: u64 = 3 << 8;
const AF: u64 = 1 << 10;
const NG: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
pub const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// A root's entries that are the process's: all of TTBR0's (the kernel has
/// TTBR1).
pub const USER_ROOT_ENTRIES: u64 = 512;

/// A new root (zeroed): nothing of the kernel's goes in it.
pub fn new_root(_root_pa: u64) {}

/// An entry pointing at the next level's table.
pub fn table(next_pa: u64) -> u64 {
    next_pa | VALID | TABLE_OR_PAGE
}

/// A user page's flags. Writable implies readable and exec implies readable
/// (as on Linux/arm64). PROT_NONE pages stay mapped but are inaccessible
/// from EL0, so their contents survive mprotect round-trips.
pub fn leaf(prot: Prot) -> u64 {
    let mut f = VALID | TABLE_OR_PAGE | ATTR_NORMAL | SH_INNER | AF | NG | PXN;
    if prot.is_none() {
        return f | UXN;
    }
    f |= AP_EL0;
    if !prot.write {
        f |= AP_RO;
    }
    if !prot.exec {
        f |= UXN;
    }
    f
}

/// A leaf entry with writes forbidden, for pages shared copy-on-write.
pub fn read_only(pte: u64) -> u64 {
    pte | AP_RO
}

/// Does a leaf entry let user code (and the kernel) write the page?
pub fn writable(pte: u64) -> bool {
    pte & AP_RO == 0
}
