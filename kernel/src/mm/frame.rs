//! Physical frame allocator and kernel heap.

use alloc::vec::Vec;
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

struct Frames {
    regions: Vec<(u64, u64)>,
    region: usize,
    next: u64,
    free: Vec<u64>,
    total: u64,
    in_use: u64,
    /// How many mappings hold each frame (indexed from `base`): forked
    /// processes share pages copy-on-write until one of them writes.
    refs: Vec<u16>,
    base: u64,
}

impl Frames {
    fn refs(&mut self, pa: u64) -> &mut u16 {
        &mut self.refs[((pa - self.base) / PAGE_SIZE) as usize]
    }
}

static FRAMES: Mutex<Option<Frames>> = Mutex::new(None);

pub fn init(regions: &[(u64, u64)]) {
    let regions: Vec<(u64, u64)> = regions.iter().copied().filter(|(s, e)| s < e).collect();
    let total = regions.iter().map(|(s, e)| (e - s) / PAGE_SIZE).sum();
    let next = regions.first().map_or(0, |r| r.0);
    let base = regions.iter().map(|r| r.0).min().unwrap_or(0);
    let top = regions.iter().map(|r| r.1).max().unwrap_or(0);
    let refs = alloc::vec![0; ((top - base) / PAGE_SIZE) as usize];
    *FRAMES.lock() = Some(Frames { regions, region: 0, next, free: Vec::new(), total, in_use: 0, refs, base });
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
        f.free.push(pa);
        f.in_use -= 1;
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

/// (total frames, frames in use)
pub fn stats() -> (u64, u64) {
    let guard = FRAMES.lock();
    guard.as_ref().map_or((0, 0), |f| (f.total, f.in_use))
}
