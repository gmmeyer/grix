//! Physical memory, page tables and user address spaces.

pub mod aspace;
pub mod frame;
pub mod gate;
pub mod pageindex;
pub mod paging;

use crate::arch::machine::ram_regions;
use grix_abi::image::MAX_RAM;

pub const PAGE_SIZE: u64 = 4096;
/// Physical memory is mapped linearly at this offset (the arch's high half,
/// where the kernel runs: its linker script says the same).
pub const KERNEL_OFFSET: u64 = crate::arch::KERNEL_OFFSET;
const HEAP_SIZE: u64 = 32 << 20;
/// The share of what the boot image leaves of RAM that the heap grows by,
/// beyond `HEAP_SIZE`, and at most how much: room for threads' kernel state
/// (`process::THREAD_COST`), as Linux sizes threads-max from RAM. The image
/// is left out: its bytes are RAM no thread can run in, and of 2 GiB with
/// an image of 1.7 (Maven's) a share of it all takes 40% of what's free.
const HEAP_RAM_SHARE: u64 = 16;
const HEAP_EXTRA_MAX: u64 = 128 << 20;

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

/// What boot.S maps of physical memory (the rest of RAM is mapped by
/// `arch::map_ram` at boot).
const BOOT_MAPPED: u64 = 4 << 30;

/// Set up the kernel heap and the frame allocator for `ram_size` bytes of
/// RAM, keeping the kernel image and the boot image (at
/// `image_base..image_base+image_len`) reserved.
///
/// Below the boot image: the kernel, its heap, a reference count for each
/// frame of RAM (2 bytes a page: 32 MiB for `MAX_RAM`, which the heap
/// couldn't hold) and the page tables mapping RAM above 4 GiB; what's
/// left there is frames too.
pub fn init(ram_size: u64, image_base: u64, image_len: u64) {
    assert!(ram_size <= MAX_RAM, "RAM size {ram_size:#x} exceeds the {MAX_RAM:#x} limit");
    let regions = ram_regions(ram_size);
    let (low_base, low_size) = regions[0];
    let low_end = low_base + low_size;
    let top = regions.iter().filter(|r| r.1 > 0).map(|r| r.0 + r.1).max().unwrap_or(low_end);
    let kernel_end = page_up(v2p((&raw const __kernel_end) as u64)).unwrap();
    let image_end = page_up(image_base + image_len).unwrap();
    assert!(kernel_end <= image_base, "kernel overlaps the boot image");
    assert!(image_end <= low_end, "boot image does not fit in RAM");

    let heap_size = HEAP_SIZE.min((image_base - kernel_end) / 2);
    frame::init_heap(kernel_end, heap_size);
    let refs = kernel_end + heap_size;
    let mut early = page_up(refs + frame::refs_bytes(low_base, top)).unwrap();
    for &(base, size) in &regions {
        let (start, end) = (base.max(BOOT_MAPPED), base + size);
        if start < end {
            crate::arch::map_ram(start, end, &mut || {
                let table = early;
                early += PAGE_SIZE;
                assert!(early <= image_base, "no room below the boot image for page tables");
                // SAFETY: below the boot image, mapped, and nobody's yet.
                unsafe { core::ptr::write_bytes(p2v(table) as *mut u8, 0, PAGE_SIZE as usize) };
                table
            });
        }
    }
    assert!(early <= image_base, "no room below the boot image for frame counts");

    // More from the top of RAM (the highest region's end, mapped by now),
    // in proportion to what the boot image leaves of it (32 MiB of 512
    // MiB), half of it for the `kmem` budget (threads above all) and a
    // quarter for files' names and nodes: the rest is for what the budgets
    // can't see, the holes that many small allocations leave once they go
    // (thousands of threads' leave 15 MiB free in 30,000 pieces too small
    // for a pipe's buffer).
    let highest = regions.iter().rposition(|r| r.1 > 0).unwrap_or(0);
    let (hbase, hsize) = regions[highest];
    let room = (hbase + hsize).saturating_sub(hbase.max(image_end));
    let usable = ram_size.saturating_sub(image_len);
    let extra = page_down((usable / HEAP_RAM_SHARE).min(HEAP_EXTRA_MAX)).min(page_down(room / 2));
    if extra > 0 {
        frame::init_heap(hbase + hsize - extra, extra);
    }
    crate::kmem::init(extra / 2);
    crate::fs::grow_meta(extra / 4);

    // Highest first (`frame::Frames`): RAM above 4 GiB, then the rest.
    let mut free = alloc::vec::Vec::new();
    for (i, &(base, size)) in regions.iter().enumerate().rev() {
        let end = base + size - if i == highest { extra } else { 0 };
        let start = base.max(image_end);
        if start < end && end > BOOT_MAPPED {
            free.push((start.max(BOOT_MAPPED), end));
        }
        if start < end.min(BOOT_MAPPED) {
            free.push((start, end.min(BOOT_MAPPED)));
        }
    }
    free.push((early, image_base));
    frame::init(&free, refs, low_base, top);
}
