//! The vDSO: clock_gettime and gettimeofday without a system call, as
//! Linux's arm64 one has them (`__kernel_clock_gettime` and friends, at
//! version LINUX_2.6.39, found through AT_SYSINFO_EHDR). It's a small ELF
//! shared object assembled in `arch` (`vdso.S`), in a page every process maps at `VDSO`
//! (`Backing::KernelPage`). Its functions read the counter (EL0 may, see
//! `arch::allow_user_counter`) and the clock's parameters from the page
//! before it, `VVAR`, which only the kernel writes: a sequence count, the
//! counter at boot, the multiplier that turns ticks into nanoseconds
//! (`(ticks * mult) >> 32`, as `time::monotonic_ns` does, so the two never
//! disagree), and the time of day at boot. Anything else (CPU-time clocks,
//! a timezone) is the system call.

use core::sync::atomic::{AtomicU64, Ordering, fence};

use spin::Once;

use crate::arch;
use crate::mm::{PAGE_SIZE, frame, p2v};

unsafe extern "C" {
    static grix_vdso_start: u8;
    static grix_vdso_end: u8;
}

/// The frames of the clock's parameters and of the vDSO, which the kernel
/// keeps (mappings take their own references).
static FRAMES: Once<(u64, u64)> = Once::new();

/// The clock's parameters in `VVAR`, as u64s.
const SEQ: usize = 0;
const COUNTER0: usize = 1;
const MULT: usize = 2;
const BOOT_REALTIME: usize = 3;

/// Make the two pages, once the clock is running.
pub fn init() {
    FRAMES.call_once(|| {
        let start = &raw const grix_vdso_start as usize;
        let len = &raw const grix_vdso_end as usize - start;
        assert!(len <= PAGE_SIZE as usize, "the vDSO is bigger than a page");
        let vvar = frame::alloc().expect("no memory for the vDSO");
        let text = frame::alloc().expect("no memory for the vDSO");
        // SAFETY: both frames were just allocated and are mapped linearly;
        // the vDSO's bytes are in the kernel's read-only data.
        unsafe {
            core::ptr::write_bytes(p2v(vvar) as *mut u8, 0, PAGE_SIZE as usize);
            core::ptr::write_bytes(p2v(text) as *mut u8, 0, PAGE_SIZE as usize);
            core::ptr::copy_nonoverlapping(start as *const u8, p2v(text) as *mut u8, len);
        }
        arch::sync_icache(p2v(text), PAGE_SIZE);
        (vvar, text)
    });
    publish();
}

/// The frame of the clock's parameters and of the vDSO's code.
pub fn frames() -> (u64, u64) {
    *FRAMES.get().expect("vDSO not made yet")
}

/// Write the clock's parameters (at boot, and when a restored snapshot
/// moves the time of day on), seqlock-style for readers on other CPUs.
pub fn publish() {
    let Some(&(vvar, _)) = FRAMES.get() else { return };
    // SAFETY: the frame is the kernel's, mapped linearly, and user code only
    // reads it (aligned u64s).
    let words = unsafe { &*(p2v(vvar) as *const [AtomicU64; 4]) };
    let (counter0, mult, boot_realtime) = crate::time::vdso_params();
    let seq = words[SEQ].load(Ordering::Relaxed);
    words[SEQ].store(seq + 1, Ordering::Relaxed);
    fence(Ordering::Release);
    words[COUNTER0].store(counter0, Ordering::Relaxed);
    words[MULT].store(mult, Ordering::Relaxed);
    words[BOOT_REALTIME].store(boot_realtime, Ordering::Relaxed);
    words[SEQ].store(seq + 2, Ordering::Release);
}
