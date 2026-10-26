//! Physical frame allocator and kernel heap.

use alloc::vec::Vec;
use linked_list_allocator::LockedHeap;
use spin::Mutex;

use super::{PAGE_SIZE, p2v};

#[global_allocator]
static HEAP: LockedHeap = LockedHeap::empty();

pub fn init_heap(pa: u64, size: u64) {
    unsafe { HEAP.lock().init(p2v(pa) as *mut u8, size as usize) };
}

struct Frames {
    regions: Vec<(u64, u64)>,
    region: usize,
    next: u64,
    free: Vec<u64>,
    total: u64,
    in_use: u64,
}

static FRAMES: Mutex<Option<Frames>> = Mutex::new(None);

pub fn init(regions: &[(u64, u64)]) {
    let regions: Vec<(u64, u64)> = regions.iter().copied().filter(|(s, e)| s < e).collect();
    let total = regions.iter().map(|(s, e)| (e - s) / PAGE_SIZE).sum();
    let next = regions.first().map_or(0, |r| r.0);
    *FRAMES.lock() = Some(Frames { regions, region: 0, next, free: Vec::new(), total, in_use: 0 });
}

/// Allocate a zeroed 4 KiB frame. Returns its physical address.
pub fn alloc() -> Option<u64> {
    let pa = {
        let mut guard = FRAMES.lock();
        let f = guard.as_mut()?;
        let pa = match f.free.pop() {
            Some(pa) => pa,
            None => loop {
                let &(start, end) = f.regions.get(f.region)?;
                f.next = f.next.max(start);
                if f.next + PAGE_SIZE <= end {
                    let pa = f.next;
                    f.next += PAGE_SIZE;
                    break pa;
                }
                f.region += 1;
            },
        };
        f.in_use += 1;
        pa
    };
    unsafe { core::ptr::write_bytes(p2v(pa) as *mut u8, 0, PAGE_SIZE as usize) };
    Some(pa)
}

pub fn free(pa: u64) {
    let mut guard = FRAMES.lock();
    let f = guard.as_mut().expect("frame allocator not initialised");
    f.free.push(pa);
    f.in_use -= 1;
}

/// (total frames, frames in use)
pub fn stats() -> (u64, u64) {
    let guard = FRAMES.lock();
    guard.as_ref().map_or((0, 0), |f| (f.total, f.in_use))
}
