//! x86_64 specifics: boot (PVH, then long mode), the GDT, TSS and IDT,
//! exception and system call entry, MSRs and control registers.
//!
//! The kernel runs at CPL 0 with interrupts off (IF clear) and user code at
//! CPL 3 with them on. Every trap from user mode (an exception, an
//! interrupt, `syscall`) lands in `trap_entry` with a `TrapFrame` at the top
//! of this CPU's kernel stack, and leaves by `iretq` from that frame. The
//! only interrupts taken in kernel mode are in the idle loop's `sti; hlt`
//! (`wait_for_interrupt`): they're noted for `irq::ack` and nothing else,
//! as a masked interrupt waits in the GIC on arm64.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

use crate::signal::{self, *};
use crate::{process, sched, syscall};

pub mod abi;
pub mod irq;
pub mod pte;
pub mod sigframe;
pub mod uart;

/// Where this machine's RAM, boot image and devices are (QEMU `microvm`'s).
pub mod machine {
    pub use grix_abi::machine::x86_64::{IMAGE_BASE, RAM_BASE, VIRTIO, VIRTIO_SLOTS, VIRTIO_STRIDE};
    /// Transport `i` interrupts on GSI `VIRTIO_IRQ + i` (`irq::ack`'s id).
    pub const VIRTIO_IRQ: u32 = grix_abi::machine::x86_64::VIRTIO_GSI;
}

global_asm!(include_str!("boot.S"), options(att_syntax));
global_asm!(include_str!("entry.S"), options(att_syntax));
global_asm!(include_str!("vdso.S"), options(att_syntax));

/// Registers saved on every trap from user mode, ending at the top of the
/// CPU's kernel stack. Layout must match entry.S: the general registers
/// pushed there, then what the CPU pushed (or `syscall_entry` pushed as it
/// would have).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
    /// Keeps the frame (and the stack below it) 16-byte aligned.
    pad: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    /// The system call's number, which `rax`'s result overwrites (for a
    /// restart), or !0.
    pub orig_rax: u64,
    /// What trapped: an IDT vector, or `SYSCALL`.
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 192);

/// `TrapFrame::vector` for a `syscall`.
const SYSCALL: u64 = 0x100;

/// Selectors (GDT order: null, kernel code, kernel data, user 32-bit code
/// (for `sysret`'s layout), user data, user code, then each CPU's TSS).
const KERNEL_CS: u64 = 0x08;
const USER_SS: u64 = 0x20 | 3;
const USER_CS: u64 = 0x28 | 3;
const TSS_SEL: u16 = 0x30;

/// RFLAGS for user code: interrupts on (and the reserved bit 1).
const USER_RFLAGS: u64 = 0x202;

/// What the rest of the kernel knows of a trapped thread's registers: Linux's
/// x86_64 conventions (rax the system call's number and its result, rdi,
/// rsi, rdx, r10, r8, r9 its arguments; `syscall` is 2 bytes).
impl TrapFrame {
    /// A thread entering user mode at `pc` with stack `sp`, every other
    /// register zero.
    pub fn new_user(pc: u64, sp: u64) -> TrapFrame {
        TrapFrame {
            rip: pc,
            rsp: sp,
            cs: USER_CS,
            ss: USER_SS,
            rflags: USER_RFLAGS,
            orig_rax: !0,
            vector: SYSCALL,
            ..TrapFrame::default()
        }
    }

    pub fn syscall_nr(&self) -> u64 {
        self.orig_rax
    }

    /// Argument `n` (0..6) of the system call.
    pub fn arg(&self, n: usize) -> u64 {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9][n]
    }

    pub fn syscall_args(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }

    /// The system call's result, as it returns.
    pub fn set_return(&mut self, v: u64) {
        self.rax = v;
    }

    pub fn return_value(&self) -> u64 {
        self.rax
    }

    pub fn pc(&self) -> u64 {
        self.rip
    }

    pub fn sp(&self) -> u64 {
        self.rsp
    }

    pub fn set_sp(&mut self, sp: u64) {
        self.rsp = sp;
    }

    /// Back to the `syscall` it trapped from, to run it again: with its
    /// number in rax again, as Linux's restart does.
    pub fn rewind_syscall(&mut self) {
        self.rip -= 2;
        self.rax = self.orig_rax;
    }

    /// Past it again: a rewound call that returns after all.
    pub fn skip_syscall(&mut self) {
        self.rip += 2;
    }
}

/// Room for the largest XSAVE area this kernel keeps (standard format):
/// the legacy x87/SSE region, the header, AVX's upper halves, and
/// AVX-512's opmasks and upper registers.
pub const FP_AREA: usize = 2688;

/// User x87/SSE state as `fxsave` writes it, or, once `init_xsave` has
/// turned XSAVE on, every component in `XCR0` as `xsave` writes them.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct FpState {
    pub area: [u8; FP_AREA],
}

impl Default for FpState {
    /// The state a new program starts with (as `fninit` and Linux leave
    /// it): FCW 0x37f, MXCSR 0x1f80 (every exception masked), and an
    /// XSAVE header that has every other component in its initial state.
    fn default() -> Self {
        let mut area = [0u8; FP_AREA];
        area[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        area[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        FpState { area }
    }
}

/// The XSAVE components user code has (XCR0), or 0 for fxsave alone.
static XCR0: AtomicU64 = AtomicU64::new(0);
/// The size of their XSAVE area (standard format).
static XSAVE_SIZE: AtomicU32 = AtomicU32::new(0);

/// The XSAVE components user state has, or 0 without XSAVE.
pub fn xsave_features() -> u64 {
    XCR0.load(Ordering::Relaxed)
}

/// The size of user state's XSAVE area, or 0 without XSAVE (fxsave's 512).
pub fn xsave_size() -> usize {
    XSAVE_SIZE.load(Ordering::Relaxed) as usize
}

/// Turn XSAVE on for x87, SSE and AVX, and AVX-512 when the CPU has all of
/// its three components, as Linux does (glibc, musl and compilers look
/// for OSXSAVE and XCR0 before they use AVX). Not MPX, PKRU or AMX: their
/// state isn't user code's to use here. Without XSAVE, fxsave alone.
fn init_xsave() {
    if cpuid(1, 0)[2] & (1 << 26) == 0 {
        return;
    }
    // SAFETY: CR4.OSXSAVE, on a CPU that has XSAVE.
    unsafe {
        asm!("mov {t}, cr4", "or {t}, {set}", "mov cr4, {t}", t = out(reg) _, set = in(reg) 1u64 << 18,
             options(nostack));
    }
    let d = cpuid(0xd, 0);
    let have = (d[3] as u64) << 32 | d[0] as u64;
    let avx = if have & 0b111 == 0b111 { 0b111 } else { 0b11 };
    let avx512 = if avx == 0b111 && have & 0xe0 == 0xe0 { avx | 0xe0 } else { avx };
    for mask in [avx512, avx, 0b11] {
        // SAFETY: components the CPU supports, x87 and SSE among them.
        unsafe { asm!("xsetbv", in("ecx") 0, in("eax") mask as u32, in("edx") (mask >> 32) as u32, options(nostack)) };
        // CPUID 0xd's EBX: the area's size for what XCR0 has now.
        let size = cpuid(0xd, 0)[1];
        if size as usize <= FP_AREA {
            XCR0.store(mask, Ordering::Relaxed);
            XSAVE_SIZE.store(size, Ordering::Relaxed);
            return;
        }
    }
}

unsafe extern "C" {
    fn return_to_frame_asm(frame: *const TrapFrame) -> !;
    fn load_cpu_tables(gdtr: *const u8, idtr: *const u8, tss: u16);
    static isr_table: [u64; 256];
    fn syscall_entry();
    static __stacks: u8;
    static __df_stack_top: u8;
    fn boot_pml4_phys() -> u64;
    fn empty_pml4_phys() -> u64;
}

const STACK_SIZE: u64 = 0x10000;

/// Top of CPU `cpu`'s kernel stack (they're laid out in the linker script).
pub fn stack_top(cpu: usize) -> u64 {
    (&raw const __stacks) as u64 + (cpu as u64 + 1) * STACK_SIZE
}

/// Where a secondary CPU starts (physical). They don't, yet: `start_cpu`
/// says so.
pub fn secondary_entry_phys() -> u64 {
    0
}

/// A user page table that maps nothing: only the kernel's half (physical).
pub fn empty_page_table() -> u64 {
    unsafe { empty_pml4_phys() }
}

/// Return to user mode from `frame`, which must be at the top of this CPU's
/// stack.
///
/// # Safety
/// `frame` holds a valid user state (CPL 3 selectors), as a trap leaves it.
pub unsafe fn return_to_frame(frame: *const TrapFrame) -> ! {
    unsafe { return_to_frame_asm(frame) }
}

pub fn save_fp(state: &mut FpState) {
    let mask = xsave_features();
    // SAFETY: a 64-byte aligned area, larger than XSAVE_SIZE. xsave writes
    // only the header's first 8 bytes (XSTATE_BV): the rest stay zero.
    unsafe {
        if mask == 0 {
            asm!("fxsave64 [{}]", in(reg) state.area.as_mut_ptr(), options(nostack));
        } else {
            asm!("xsave64 [{}]", in(reg) state.area.as_mut_ptr(), in("eax") mask as u32,
                 in("edx") (mask >> 32) as u32, options(nostack));
        }
    }
}

pub fn restore_fp(state: &FpState) {
    let mask = xsave_features();
    // SAFETY: as above. A frame from user memory may hold any MXCSR or
    // XSAVE header: `sigframe` keeps only what these accept (anything else
    // would fault here).
    unsafe {
        if mask == 0 {
            asm!("fxrstor64 [{}]", in(reg) state.area.as_ptr(), options(nostack));
        } else {
            asm!("xrstor64 [{}]", in(reg) state.area.as_ptr(), in("eax") mask as u32,
                 in("edx") (mask >> 32) as u32, options(nostack));
        }
    }
}

const MSR_EFER: u32 = 0xc000_0080;
const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_SFMASK: u32 = 0xc000_0084;
const MSR_FS_BASE: u32 = 0xc000_0100;
const MSR_GS_BASE: u32 = 0xc000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

pub(crate) fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: reading an MSR this kernel knows the CPU has.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (hi as u64) << 32 | lo as u64
}

pub(crate) fn wrmsr(msr: u32, v: u64) {
    // SAFETY: as above.
    unsafe { asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nostack)) };
}

pub(crate) fn cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    let (a, b, c, d): (u32, u32, u32, u32);
    // SAFETY: cpuid has no side effects; rbx is LLVM's, so it's moved.
    unsafe {
        asm!("mov {t:r}, rbx", "cpuid", "xchg {t:r}, rbx", t = out(reg) b, inout("eax") leaf => a,
             inout("ecx") sub => c, out("edx") d, options(nomem, nostack));
    }
    [a, b, c, d]
}

/// The user thread pointer (TLS base: FS's base, which `arch_prctl` sets).
pub fn tls() -> u64 {
    rdmsr(MSR_FS_BASE)
}

/// Can `v` be a thread pointer? FS's base must be canonical (wrmsr faults
/// otherwise), and a user address.
pub fn valid_tls(v: u64) -> bool {
    v < USER_TOP
}

pub fn set_tls(v: u64) {
    // Every way in checks (`valid_tls`); a fault here would be the kernel's.
    if valid_tls(v) {
        wrmsr(MSR_FS_BASE, v);
    }
}

/// Physical memory is mapped linearly here, in the upper half's first slot
/// (as linker.ld).
pub const KERNEL_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// The end of user addresses: the lower canonical half (4-level paging).
pub const USER_TOP: u64 = 1 << 47;

/// Where position-independent executables go (ELF_ET_DYN_BASE: two thirds
/// of the way up).
pub const ELF_DYN_BASE: u64 = 0x0000_5555_5555_0000;

/// ELF's e_machine for the programs this kernel runs.
pub const ELF_MACHINE: u16 = 62; // EM_X86_64
/// Why an ELF for another machine doesn't load.
pub const ELF_OTHER_MACHINE: &str = "not an x86_64 binary";
/// AT_PLATFORM and uname's machine.
pub const PLATFORM: &str = "x86_64";
/// Linux's MINSIGSTKSZ.
pub const MINSIGSTKSZ: u64 = 2048;

/// This CPU's number: its local APIC's ID (the VMMs number CPUs 0..n).
pub fn cpu_number() -> usize {
    irq::lapic_id() as usize
}

/// Wait for an interrupt. `sti` takes effect after the next instruction, so
/// none can come between it and `hlt`; one that comes is noted
/// (`irq::taken`) for `irq::ack`.
pub fn wait_for_interrupt() {
    // SAFETY: interrupts on for the halt only.
    unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}

/// Order memory writes (a virtqueue's) before a device register write.
pub fn device_barrier() {
    fence(Ordering::SeqCst);
}

/// Start CPU `cpu`: not on x86_64 yet (`smp::start` goes on with one).
pub fn start_cpu(_cpu: usize, _entry: u64, _stack: u64) -> i64 {
    -1
}

/// Tell the VMM CPU `cpu` was kicked: the IPI is enough on x86.
pub fn vmm_kick(_cpu: usize) {}

/// `SNAPSHOT_CALL`: not on x86_64 yet (the kernel refuses).
pub fn snapshot_call() -> [u64; 6] {
    [!0; 6]
}

/// Drop to user mode at `entry` with stack pointer `sp`. Never returns:
/// from here on the kernel only runs in trap handlers.
pub fn enter_user(entry: u64, sp: u64) -> ! {
    let frame = (stack_top(0) - core::mem::size_of::<TrapFrame>() as u64) as *mut TrapFrame;
    // SAFETY: the top of CPU 0's stack, which nothing else uses now.
    unsafe {
        let mut tf = TrapFrame::new_user(entry, sp);
        sanitize(&mut tf);
        frame.write(tf);
        return_to_frame(frame)
    }
}

/// Every trap from user mode, and interrupts in the idle loop (entry.S).
#[unsafe(no_mangle)]
extern "C" fn trap_entry(tf: &mut TrapFrame) {
    if tf.cs & 3 == 0 {
        if (32..256).contains(&tf.vector) {
            irq::taken(tf.vector as u8);
            return;
        }
        // The callers, by frame pointer, while they're on a kernel stack.
        let mut trace = [0u64; 8];
        let (mut fp, stacks) = (tf.rbp, (&raw const __stacks) as u64);
        for slot in trace.iter_mut() {
            if fp < stacks || fp >= stack_top(MAX_CPUS - 1) || fp & 7 != 0 {
                break;
            }
            // SAFETY: inside the kernel stacks, which are mapped.
            unsafe {
                *slot = ((fp + 8) as *const u64).read();
                fp = (fp as *const u64).read();
            }
        }
        panic!(
            "kernel exception {} (error {:#x}) at {:#x}, cr2 {:#x}, rsp {:#x}, rdi {:#x}, rsi {:#x}, rcx {:#x}, \
             called from {trace:x?}",
            tf.vector,
            tf.error,
            tf.rip,
            cr2(),
            tf.rsp,
            tf.rdi,
            tf.rsi,
            tf.rcx,
        );
    }
    crate::smp::lock();
    // The thread this CPU ran may have ended meanwhile (exit_group or
    // execve on another CPU): then there's nothing to handle for it.
    let has_thread = process::PROCESS.lock().as_ref().is_some_and(|p| p.running);
    match tf.vector {
        SYSCALL if has_thread => {
            syscall::handle(tf);
            signal::return_to_user(tf);
        }
        SYSCALL => {}
        v if v < 32 => {
            if has_thread {
                user_exception(tf);
                signal::return_to_user(tf);
            }
        }
        v => {
            irq::taken(v as u8);
            sched::irq(tf);
            signal::return_to_user(tf);
        }
    }
    // Something to run (waiting for it if need be), and the kernel back.
    crate::smp::finish(tf);
    sanitize(tf);
}

/// iretq to a non-canonical rip or rsp faults in the kernel: user code
/// that asked for one (a bad entry point, handler or return address, or a
/// stack pointer it set to a kernel-half or non-canonical value) faults
/// at 0 instead, in user mode.
fn sanitize(tf: &mut TrapFrame) {
    if tf.rip >= sigframe::USER_END {
        tf.rip = 0;
    }
    if tf.rsp >= sigframe::USER_END {
        tf.rsp = 0;
    }
}

const FPE_INTDIV: i32 = 1;
const ILL_ILLOPN: i32 = 2;
const SI_KERNEL: i32 = 0x80;

fn user_exception(tf: &mut TrapFrame) {
    // sigcontext's trapno and err.
    let syndrome = Some(tf.vector << 32 | (tf.error & 0xffff_ffff));
    let (sig, code, addr, why) = match tf.vector {
        14 => {
            let addr = cr2();
            let access = if tf.error & 0x10 != 0 {
                process::Access::Exec
            } else if tf.error & 2 != 0 {
                process::Access::Write
            } else {
                process::Access::Read
            };
            // Not present: demand paging. A write to a present page may be
            // to one shared copy-on-write; `user_fault` tells.
            if tf.error & 1 == 0 || access == process::Access::Write {
                return process::user_fault(tf, addr, access, tf.vector << 32 | tf.error);
            }
            (SIGSEGV, SEGV_ACCERR, addr, access.describe_violation())
        }
        0 => (SIGFPE, FPE_INTDIV, tf.rip, "division by zero"),
        1 | 3 => (SIGTRAP, TRAP_BRKPT, tf.rip, "breakpoint (int3)"),
        6 => (SIGILL, ILL_ILLOPN, tf.rip, "illegal instruction"),
        16 | 19 => (SIGFPE, FPE_FLTUNK, tf.rip, "floating point exception"),
        17 => (SIGBUS, BUS_ADRALN, tf.rip, "alignment check"),
        12 => (SIGBUS, SI_KERNEL, 0, "stack segment fault"),
        _ => (SIGSEGV, SI_KERNEL, 0, "general protection fault"),
    };
    let mut guard = process::PROCESS.lock();
    let p = guard.as_mut().expect("fault without a process");
    signal::fault(p, sig, code, signal::Fault { addr, pc: tf.rip, syndrome }, why);
}

fn cr2() -> u64 {
    let v;
    // SAFETY: reading a control register.
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack)) };
    v
}

/// The TSC's rate, measured at boot (`init`).
static TSC_HZ: AtomicU64 = AtomicU64::new(1_000_000_000);

pub fn counter() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc, ordered after what came before.
    unsafe { asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (hi as u64) << 32 | lo as u64
}

pub fn counter_freq() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

/// User code may read the TSC already (CR4.TSD is clear).
pub fn allow_user_counter() {}

/// A hardware random number (RDRAND), if the CPU has it.
pub fn hw_random() -> Option<u64> {
    if cpuid(1, 0)[2] & (1 << 30) == 0 {
        return None;
    }
    for _ in 0..10 {
        let (v, ok): (u64, u8);
        // SAFETY: rdrand; CF says whether it gave a number.
        unsafe { asm!("rdrand {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack)) };
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

/// Linux AT_HWCAP: CPUID 1's EDX.
pub fn hwcap() -> u64 {
    cpuid(1, 0)[3] as u64
}

pub fn set_user_page_table(root_pa: u64) {
    // SAFETY: a root with the kernel's half in it (`pte::new_root`).
    unsafe { asm!("mov cr3, {}", in(reg) root_pa, options(nostack)) };
}

/// Order what was written to a page before the entry that publishes it:
/// x86 keeps stores in order, so only the compiler must.
pub fn publish_barrier() {
    fence(Ordering::Release);
}

/// Page-table writes are seen by the walker in program order.
pub fn pte_barrier() {
    fence(Ordering::SeqCst);
}

/// Forget cached translations (one CPU: reloading CR3 does it).
pub fn flush_tlb() {
    let v: u64;
    // SAFETY: CR3 back as it was.
    unsafe { asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) v, options(nostack)) };
    let _ = v;
}

/// Instruction fetch sees what was written (x86 keeps them coherent).
pub fn sync_icache(_kva: u64, _len: u64) {}

/// End the machine: the frame went out already. A triple fault, which QEMU
/// (`-no-reboot`) and grix-vmm take as the end.
pub fn power_off() -> ! {
    let null: [u64; 2] = [0, 0];
    // SAFETY: an empty IDT, then a trap no handler can take.
    unsafe { asm!("lidt [{}]", "int3", in(reg) null.as_ptr(), options(noreturn)) }
}

/// /proc/cpuinfo, as Linux x86 writes it (the parts programs read), for
/// `cpus` CPUs.
pub fn cpuinfo(s: &mut alloc::string::String, cpus: u32) {
    use core::fmt::Write;
    let v = cpuid(0, 0);
    let mut vendor = [0u8; 12];
    vendor[..4].copy_from_slice(&v[1].to_le_bytes());
    vendor[4..8].copy_from_slice(&v[3].to_le_bytes());
    vendor[8..].copy_from_slice(&v[2].to_le_bytes());
    let vendor = core::str::from_utf8(&vendor).unwrap_or("unknown");
    let f = cpuid(1, 0);
    let (family, model, stepping) = ((f[0] >> 8) & 0xf, (f[0] >> 4) & 0xf | ((f[0] >> 12) & 0xf0), f[0] & 0xf);
    const EDX: [&str; 32] = [
        "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "", "sep", "mtrr", "pge", "mca", "cmov",
        "pat", "pse36", "pn", "clflush", "", "dts", "acpi", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm", "ia64",
        "pbe",
    ];
    const ECX: [&str; 32] = [
        "pni",
        "pclmulqdq",
        "dtes64",
        "monitor",
        "ds_cpl",
        "vmx",
        "smx",
        "est",
        "tm2",
        "ssse3",
        "cid",
        "sdbg",
        "fma",
        "cx16",
        "xtpr",
        "pdcm",
        "",
        "pcid",
        "dca",
        "sse4_1",
        "sse4_2",
        "x2apic",
        "movbe",
        "popcnt",
        "tsc_deadline_timer",
        "aes",
        "xsave",
        "",
        "avx",
        "f16c",
        "rdrand",
        "hypervisor",
    ];
    let mut flags = alloc::vec::Vec::new();
    for (i, n) in EDX.iter().enumerate() {
        if f[3] & (1 << i) != 0 && !n.is_empty() {
            flags.push(*n);
        }
    }
    for (i, n) in ECX.iter().enumerate() {
        // AVX only when this kernel keeps its state (XSAVE with AVX on).
        let off = match *n {
            "xsave" => xsave_features() == 0,
            "avx" | "f16c" | "fma" => xsave_features() & 0b100 == 0,
            _ => false,
        };
        if f[2] & (1 << i) != 0 && !n.is_empty() && !off {
            flags.push(*n);
        }
    }
    let mhz = counter_freq() / 1_000_000;
    for cpu in 0..cpus {
        let _ = write!(
            s,
            "processor\t: {cpu}\nvendor_id\t: {vendor}\ncpu family\t: {family}\nmodel\t\t: {model}\n\
             model name\t: grix virtual CPU\nstepping\t: {stepping}\ncpu MHz\t\t: {mhz}.000\n\
             physical id\t: 0\ncore id\t\t: {cpu}\ncpu cores\t: {cpus}\nfpu\t\t: yes\nflags\t\t: {}\n\
             bogomips\t: {}.00\nclflush size\t: 64\naddress sizes\t: 48 bits physical, 48 bits virtual\n\n",
            flags.join(" "),
            mhz * 2,
        );
    }
}

// ---------------------------------------------------------------- setup

/// The GDT: null, kernel code and data, user 32-bit code (unused, for
/// `sysret`'s layout), user data and code, then a 16-byte TSS descriptor
/// per CPU. The CPU writes it (the TSS's busy bit), hence atomics.
#[repr(C, align(16))]
struct Gdt([AtomicU64; 6 + 2 * MAX_CPUS]);

const MAX_CPUS: usize = grix_abi::machine::MAX_CPUS as usize;

static GDT: Gdt = Gdt([const { AtomicU64::new(0) }; 6 + 2 * MAX_CPUS]);

/// Each CPU's TSS (104 bytes, as u32s: rsp0 isn't 8-byte aligned in it).
#[repr(C, align(16))]
struct Tss([AtomicU32; 26]);

static TSS: [Tss; MAX_CPUS] = [const { Tss([const { AtomicU32::new(0) }; 26]) }; MAX_CPUS];

#[repr(C, align(16))]
struct Idt([AtomicU64; 512]);

static IDT: Idt = Idt([const { AtomicU64::new(0) }; 512]);

/// What `syscall_entry` finds through GS: this CPU's kernel stack, and room
/// for the user's rsp.
#[repr(C)]
pub(crate) struct PerCpu {
    kernel_rsp: AtomicU64,
    user_rsp: AtomicU64,
}

static PER_CPU: [PerCpu; MAX_CPUS] =
    [const { PerCpu { kernel_rsp: AtomicU64::new(0), user_rsp: AtomicU64::new(0) } }; MAX_CPUS];

/// Set the CPU up, before anything else: segments, traps, `syscall`, the
/// FPU and the clock (boot.S calls it on CPU 0).
#[unsafe(no_mangle)]
extern "C" fn arch_init() {
    let g = &GDT.0;
    g[1].store(0x00af_9a00_0000_ffff, Ordering::Relaxed); // kernel code: 64-bit, DPL 0
    g[2].store(0x00cf_9200_0000_ffff, Ordering::Relaxed); // kernel data
    g[3].store(0x00cf_fa00_0000_ffff, Ordering::Relaxed); // user code, 32-bit (never used)
    g[4].store(0x00cf_f200_0000_ffff, Ordering::Relaxed); // user data: DPL 3
    g[5].store(0x00af_fa00_0000_ffff, Ordering::Relaxed); // user code: 64-bit, DPL 3
    for (n, &handler) in unsafe { isr_table.iter() }.enumerate() {
        // Interrupt gates (IF off on entry), DPL 0 but for int3, which user
        // code may use; a double fault on its own stack (IST 1).
        let dpl = if n == 3 { 3u64 } else { 0 };
        let ist = if n == 8 { 1u64 } else { 0 };
        let lo =
            (handler & 0xffff) | KERNEL_CS << 16 | ist << 32 | (0x8e | dpl << 5) << 40 | (handler >> 16 & 0xffff) << 48;
        IDT.0[2 * n].store(lo, Ordering::Relaxed);
        IDT.0[2 * n + 1].store(handler >> 32, Ordering::Relaxed);
    }
    init_cpu(0);
    // x87 and SSE for user code, SSE exceptions as #XM; then XSAVE.
    // SAFETY: control register setup on this CPU.
    unsafe {
        asm!("mov {t}, cr0", "and {t}, {clear}", "or {t}, {set}", "mov cr0, {t}",
             t = out(reg) _, clear = in(reg) !((1u64 << 2) | (1 << 3)), set = in(reg) (1u64 << 1) | (1 << 5),
             options(nostack));
        asm!("mov {t}, cr4", "or {t}, {set}", "mov cr4, {t}", t = out(reg) _,
             set = in(reg) (1u64 << 9) | (1 << 10), options(nostack));
        asm!("fninit", options(nomem, nostack));
    }
    init_xsave();
    TSC_HZ.store(irq::measure_tsc(), Ordering::Relaxed);
}

/// This CPU's GDT, TSS, IDT and `syscall` MSRs.
fn init_cpu(cpu: usize) {
    let tss = &TSS[cpu].0;
    let top = stack_top(cpu);
    tss[1].store(top as u32, Ordering::Relaxed); // rsp0
    tss[2].store((top >> 32) as u32, Ordering::Relaxed);
    let df = (&raw const __df_stack_top) as u64 - cpu as u64 * 0x1000;
    tss[9].store(df as u32, Ordering::Relaxed); // ist1
    tss[10].store((df >> 32) as u32, Ordering::Relaxed);
    tss[25].store(104 << 16, Ordering::Relaxed); // no I/O bitmap
    let base = tss.as_ptr() as u64;
    let desc = 103 | (base & 0xff_ffff) << 16 | 0x89 << 40 | (base >> 24 & 0xff) << 56;
    let slot = TSS_SEL as usize / 8 + 2 * cpu;
    GDT.0[slot].store(desc, Ordering::Relaxed);
    GDT.0[slot + 1].store(base >> 32, Ordering::Relaxed);
    // lgdt/lidt operands: a 16-bit limit, then the base (packed).
    let mut gdtr = [0u8; 10];
    gdtr[..2].copy_from_slice(&(core::mem::size_of::<Gdt>() as u16 - 1).to_le_bytes());
    gdtr[2..].copy_from_slice(&((&raw const GDT) as u64).to_le_bytes());
    let mut idtr = [0u8; 10];
    idtr[..2].copy_from_slice(&(core::mem::size_of::<Idt>() as u16 - 1).to_le_bytes());
    idtr[2..].copy_from_slice(&((&raw const IDT) as u64).to_le_bytes());
    // SAFETY: the tables are static, the selectors theirs.
    unsafe { load_cpu_tables(gdtr.as_ptr(), idtr.as_ptr(), TSS_SEL + 16 * cpu as u16) };
    let pc = &PER_CPU[cpu];
    pc.kernel_rsp.store(top, Ordering::Relaxed);
    // `syscall`: kernel CS/SS from STAR[47:32], user from [63:48] (+16 code,
    // +8 data), entry, and the flags cleared on entry.
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | 1 | (1 << 11)); // SCE, NXE
    wrmsr(MSR_STAR, KERNEL_CS << 32 | (0x18 | 3) << 48);
    wrmsr(MSR_LSTAR, syscall_entry as *const () as u64);
    // As Linux masks them: TF, IF, DF, IOPL, NT, RF, AC and ID. NT
    // especially, which user code may set (popf) and which would make the
    // kernel's own iretq fault.
    wrmsr(MSR_SFMASK, (1 << 8) | (1 << 9) | (1 << 10) | (3 << 12) | (1 << 14) | (1 << 16) | (1 << 18) | (1 << 21));
    // GS is this CPU's in the kernel; the user's (0) waits in
    // KERNEL_GS_BASE until the return to user mode swaps them.
    wrmsr(MSR_GS_BASE, pc as *const PerCpu as u64);
    wrmsr(MSR_KERNEL_GS_BASE, 0);
}

/// The boot page tables' root (physical): the kernel's half of every root.
pub(crate) fn kernel_root() -> u64 {
    unsafe { boot_pml4_phys() }
}
