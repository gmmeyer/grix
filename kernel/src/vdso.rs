//! The vDSO: clock_gettime and gettimeofday without a system call, as
//! Linux's arm64 one has them (`__kernel_clock_gettime` and friends, at
//! version LINUX_2.6.39, found through AT_SYSINFO_EHDR). It's a small ELF
//! shared object assembled below, in a page every process maps at `VDSO`
//! (`Backing::KernelPage`). Its functions read the counter (EL0 may, see
//! `arch::allow_el0_counter`) and the clock's parameters from the page
//! before it, `VVAR`, which only the kernel writes: a sequence count, the
//! counter at boot, the multiplier that turns ticks into nanoseconds
//! (`(ticks * mult) >> 32`, as `time::monotonic_ns` does, so the two never
//! disagree), and the time of day at boot. Anything else (CPU-time clocks,
//! a timezone) is the system call.

use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering, fence};

use spin::Once;

use crate::arch;
use crate::mm::{PAGE_SIZE, frame, p2v};

// The ELF header, one PT_LOAD for everything and a PT_DYNAMIC; the dynamic
// section, symbols, a SysV hash table with one bucket, version definitions
// (the base one, then LINUX_2.6.39 for every symbol), and the code. No
// section headers: loaders don't need them. Offsets are from the start,
// which the PT_LOAD puts at virtual address 0.
global_asm!(
    r#"
    .pushsection .rodata.grix_vdso, "a"
    .balign 4096
    .globl grix_vdso_start
    .globl grix_vdso_end
grix_vdso_start:
.Lv_base:
    .byte 0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0
    .quad 0
    .short 3, 183
    .long 1
    .quad 0, 64, 0
    .long 0
    .short 64, 56, 2, 64, 0, 0

    .long 1, 5
    .quad 0, 0, 0, .Lv_end - .Lv_base, .Lv_end - .Lv_base, 4096
    .long 2, 4
    .quad .Lv_dyn - .Lv_base, .Lv_dyn - .Lv_base, .Lv_dyn - .Lv_base
    .quad .Lv_dyn_end - .Lv_dyn, .Lv_dyn_end - .Lv_dyn, 8

.Lv_dyn:
    .quad 4, .Lv_hash - .Lv_base
    .quad 5, .Lv_str - .Lv_base
    .quad 6, .Lv_sym - .Lv_base
    .quad 10, .Lv_str_end - .Lv_str
    .quad 11, 24
    .quad 14, .Lv_soname - .Lv_str
    .quad 0x6ffffff0, .Lv_versym - .Lv_base
    .quad 0x6ffffffc, .Lv_verdef - .Lv_base
    .quad 0x6ffffffd, 2
    .quad 0, 0
.Lv_dyn_end:

.Lv_sym:
    .long 0
    .byte 0, 0
    .short 0
    .quad 0, 0
    .long .Lv_n_gettime - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_gettime - .Lv_base, .Lv_gettime_end - .Lv_gettime
    .long .Lv_n_gtod - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_gtod - .Lv_base, .Lv_gtod_end - .Lv_gtod
    .long .Lv_n_getres - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_getres - .Lv_base, .Lv_getres_end - .Lv_getres
    .long .Lv_n_sigreturn - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_sigreturn - .Lv_base, .Lv_sigreturn_end - .Lv_sigreturn

.Lv_hash:
    .long 1, 5
    .long 1
    .long 0, 2, 3, 4, 0

.Lv_verdef:
    .short 1, 1, 1, 1
    .long 0x0deebfa1, 20, 28
    .long .Lv_soname - .Lv_str, 0
    .short 1, 0, 2, 1
    .long 0x075fcb89, 20, 0
    .long .Lv_n_version - .Lv_str, 0

.Lv_versym:
    .short 0, 2, 2, 2, 2

.Lv_str:
    .byte 0
.Lv_soname:
    .asciz "linux-vdso.so.1"
.Lv_n_version:
    .asciz "LINUX_2.6.39"
.Lv_n_gettime:
    .asciz "__kernel_clock_gettime"
.Lv_n_gtod:
    .asciz "__kernel_gettimeofday"
.Lv_n_getres:
    .asciz "__kernel_clock_getres"
.Lv_n_sigreturn:
    .asciz "__kernel_rt_sigreturn"
.Lv_str_end:

    .balign 16
// The time in ns in x10: monotonic for x12 = 0, of day otherwise.
// Clobbers x9, x11, x13-x17.
.Lv_now:
    adr x9, .Lv_base
    sub x9, x9, #4096
1:  ldar x13, [x9]
    tbnz x13, #0, 1b
    ldp x14, x15, [x9, #8]
    ldr x16, [x9, #24]
    isb
    mrs x17, cntvct_el0
    dmb ishld
    ldr x11, [x9]
    cmp x11, x13
    b.ne 1b
    sub x17, x17, x14
    mul x10, x17, x15
    umulh x11, x17, x15
    extr x10, x11, x10, #32
    cbz x12, 2f
    add x10, x10, x16
2:  ret

// clock_gettime(clock, ts): REALTIME, REALTIME_COARSE and TAI are the time
// of day; MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE and BOOTTIME
// monotonic, as the system call has them.
.Lv_gettime:
    cmp w0, #11
    b.hi 9f
    mov w10, #0x821
    lsr w10, w10, w0
    and x12, x10, #1
    mov w11, #0xd2
    lsr w11, w11, w0
    orr w11, w11, w10
    tbz w11, #0, 9f
    mov x6, x30
    bl .Lv_now
    mov x30, x6
    mov x11, #0xca00
    movk x11, #0x3b9a, lsl #16
    udiv x12, x10, x11
    msub x13, x12, x11, x10
    stp x12, x13, [x1]
    mov x0, #0
    ret
9:  mov x8, #113
    svc #0
    ret
.Lv_gettime_end:

// gettimeofday(tv, tz): a timezone is the system call's.
.Lv_gtod:
    cbnz x1, 9f
    cbz x0, 8f
    mov x12, #1
    mov x6, x30
    bl .Lv_now
    mov x30, x6
    mov x11, #1000
    udiv x10, x10, x11
    mov x11, #0x4240
    movk x11, #0xf, lsl #16
    udiv x12, x10, x11
    msub x13, x12, x11, x10
    stp x12, x13, [x0]
8:  mov x0, #0
    ret
9:  mov x8, #169
    svc #0
    ret
.Lv_gtod_end:

.Lv_getres:
    mov x8, #114
    svc #0
    ret
.Lv_getres_end:

// What unwinders recognize as a signal frame's return (as signal::TRAMPOLINE).
.Lv_sigreturn:
    mov x8, #139
    svc #0
.Lv_sigreturn_end:
.Lv_end:
grix_vdso_end:
    .popsection
"#
);

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
