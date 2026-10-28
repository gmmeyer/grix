//! Physical memory, page tables and user address spaces.

pub mod aspace;
pub mod frame;
pub mod paging;

use crate::arch::machine::RAM_BASE;
use grix_abi::image::MAX_RAM;

pub const PAGE_SIZE: u64 = 4096;
/// Physical memory is mapped linearly at this offset (the arch's high half,
/// where the kernel runs: its linker script says the same).
pub const KERNEL_OFFSET: u64 = crate::arch::KERNEL_OFFSET;
const HEAP_SIZE: u64 = 32 << 20;

#[inline]
pub const fn p2v(pa: u64) -> u64 {
    pa + KERNEL_OFFSET
}

#[inline]
pub const fn v2p(va: u64) -> u64 {
    va - KERNEL_OFFSET
}

#[inline]
pub const fn page_down(a: u64) -> u64 {
    a & !(PAGE_SIZE - 1)
}

#[inline]
pub fn page_up(a: u64) -> Option<u64> {
    a.checked_add(PAGE_SIZE - 1).map(page_down)
}

unsafe extern "C" {
    static __kernel_end: u8;
}

/// Set up the kernel heap and the frame allocator, keeping the kernel image
/// and the boot image (at `image_base..image_base+image_len`) reserved.
pub fn init(ram_size: u64, image_base: u64, image_len: u64) {
    let ram_end = RAM_BASE + ram_size;
    let kernel_end = page_up(v2p((&raw const __kernel_end) as u64)).unwrap();
    let image_end = page_up(image_base + image_len).unwrap();
    assert!(ram_size <= MAX_RAM, "RAM size {ram_size:#x} exceeds the {MAX_RAM:#x} limit");
    assert!(kernel_end <= image_base, "kernel overlaps the boot image");
    assert!(image_end <= ram_end, "boot image does not fit in RAM");

    let heap_size = HEAP_SIZE.min((image_base - kernel_end) / 2);
    frame::init_heap(kernel_end, heap_size);
    frame::init(&[(kernel_end + heap_size, image_base), (image_end, ram_end)]);
}
