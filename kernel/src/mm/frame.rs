//! Physical frame allocator and kernel heap.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use grix_abi::stats::{Limit, Resource};
use spin::Mutex;
use talc::{ErrOnOom, Span, Talc, Talck};

use super::{PAGE_SIZE, p2v};

/// talc rather than a first-fit list: the heap holds tens of thousands of
/// small objects (a live mount's nodes and names), and a list allocator
/// slows down with every fragment.
#[global_allocator]
static HEAP: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

pub fn init_heap(pa: u64, size: u64) {
    // SAFETY: the range is RAM set aside for the heap, mapped and unused.
    unsafe {
        HEAP.lock().claim(Span::from_base_size(p2v(pa) as *mut u8, size as usize)).expect("heap");
    }
}

/// Frames from `regions`, highest first (a guest with RAM above 4 GiB
/// uses it from the start, so it's never the untried part), then freed
/// ones again. Nothing here is on the heap, which RAM would outgrow: the
/// free list is linked through the free frames themselves, and the counts
/// are an array of RAM set aside below the boot image (`mm::init`).
struct Frames {
    regions: Vec<(u64, u64)>,
    region: usize,
    next: u64,
    /// The last frame freed (`NONE`: none), whose first word is the one
    /// freed before it.
    free: u64,
    total: u64,
    in_use: u64,
    /// How many mappings hold each frame (indexed from `base`): forked
    /// processes share pages copy-on-write until one of them writes.
    refs: &'static mut [u16],
    base: u64,
}

const NONE: u64 = u64::MAX;

impl Frames {
    fn refs(&mut self, pa: u64) -> &mut u16 {
        &mut self.refs[((pa - self.base) / PAGE_SIZE) as usize]
    }
}

static FRAMES: Mutex<Option<Frames>> = Mutex::new(None);
/// `Frames::total` and `in_use`, for reading without the lock (`usage`).
static TOTAL: AtomicU64 = AtomicU64::new(0);
static IN_USE: AtomicU64 = AtomicU64::new(0);

/// Bytes of counts `init` needs for frames from `base` to `top`.
pub fn refs_bytes(base: u64, top: u64) -> u64 {
    (top - base) / PAGE_SIZE * core::mem::size_of::<u16>() as u64
}

/// Hand out the frames of `regions` (in that order), counting references
/// in `refs_pa` (`refs_bytes(base, top)` of RAM, mapped and unused), for
/// frames from `base` to `top`.
pub fn init(regions: &[(u64, u64)], refs_pa: u64, base: u64, top: u64) {
    let regions: Vec<(u64, u64)> = regions.iter().copied().filter(|(s, e)| s < e).collect();
    assert!(regions.iter().all(|&(s, e)| base <= s && e <= top), "frames outside RAM");
    let total = regions.iter().map(|(s, e)| (e - s) / PAGE_SIZE).sum();
    let next = regions.first().map_or(0, |r| r.0);
    let len = ((top - base) / PAGE_SIZE) as usize;
    // SAFETY: the caller set the range aside for this, and it's mapped
    // linearly; it's zeroed here, as a snapshot's restore keeps it.
    let refs = unsafe {
        let p = p2v(refs_pa) as *mut u16;
        core::ptr::write_bytes(p, 0, len);
        core::slice::from_raw_parts_mut(p, len)
    };
    *FRAMES.lock() = Some(Frames { regions, region: 0, next, free: NONE, total, in_use: 0, refs, base });
    TOTAL.store(total, Ordering::Relaxed);
}

/// Allocate a zeroed 4 KiB frame. Returns its physical address.
pub fn alloc() -> Option<u64> {
    let pa = {
        let mut guard = FRAMES.lock();
        let f = guard.as_mut()?;
        let pa = match f.free {
            NONE => loop {
                let Some(&(_, end)) = f.regions.get(f.region) else {
                    crate::stats::hit(Limit::Memory);
                    return None;
                };
                if f.next + PAGE_SIZE <= end {
                    let pa = f.next;
                    f.next += PAGE_SIZE;
                    break pa;
                }
                f.region += 1;
                if let Some(&(start, _)) = f.regions.get(f.region) {
                    f.next = start;
                }
            },
            pa => {
                // SAFETY: a free frame, mapped linearly: its first word
                // links the list.
                f.free = unsafe { (p2v(pa) as *const u64).read() };
                pa
            }
        };
        f.in_use += 1;
        IN_USE.store(f.in_use, Ordering::Relaxed);
        crate::stats::peak(Resource::Memory, f.in_use * PAGE_SIZE);
        *f.refs(pa) = 1;
        pa
    };
    unsafe { core::ptr::write_bytes(p2v(pa) as *mut u8, 0, PAGE_SIZE as usize) };
    Some(pa)
}

/// Drop one reference to a frame; the last one frees it.
pub fn free(pa: u64) {
    let mut guard = FRAMES.lock();
    let f = guard.as_mut().expect("frame allocator not initialised");
    let refs = f.refs(pa);
    assert!(*refs > 0, "freeing free frame {pa:#x}");
    *refs -= 1;
    if *refs == 0 {
        // SAFETY: the frame is free now, and mapped linearly.
        unsafe { (p2v(pa) as *mut u64).write(f.free) };
        f.free = pa;
        f.in_use -= 1;
        IN_USE.store(f.in_use, Ordering::Relaxed);
    }
}

/// Another mapping of a frame (fork shares pages copy-on-write). False,
/// and no reference taken, if the frame has as many as its count holds:
/// the caller fails with ENOMEM. A program can come close (one page mapped
/// in every mapping of every process, `MAX_VMAS_TOTAL` of them, is 2^16),
/// and a count that wrapped would free a frame still mapped.
#[must_use]
pub fn share(pa: u64) -> bool {
    let mut guard = FRAMES.lock();
    let f = guard.as_mut().expect("frame allocator not initialised");
    let refs = f.refs(pa);
    match refs.checked_add(1) {
        Some(n) => {
            *refs = n;
            true
        }
        None => false,
    }
}

/// Is a frame mapped more than once (so writing it needs a copy)?
pub fn is_shared(pa: u64) -> bool {
    let mut guard = FRAMES.lock();
    let f = guard.as_mut().expect("frame allocator not initialised");
    *f.refs(pa) > 1
}

/// (total frames, frames in use), without the allocator's lock: for
/// reports made whatever locks are held.
pub fn usage() -> (u64, u64) {
    (TOTAL.load(Ordering::Relaxed), IN_USE.load(Ordering::Relaxed))
}

/// How many mappings hold a frame: 0 for memory the allocator doesn't
/// own (an imported file's bytes, mapped where they are).
pub fn mappings(pa: u64) -> u16 {
    let guard = FRAMES.lock();
    let Some(f) = guard.as_ref() else { return 0 };
    let i = pa.checked_sub(f.base).map(|o| (o / PAGE_SIZE) as usize);
    i.and_then(|i| f.refs.get(i)).copied().unwrap_or(0)
}

/// (total frames, frames in use)
pub fn stats() -> (u64, u64) {
    let guard = FRAMES.lock();
    guard.as_ref().map_or((0, 0), |f| (f.total, f.in_use))
}
