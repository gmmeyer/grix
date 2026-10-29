//! KVM on x86_64: the VM, its memory, KVM's own interrupt controllers (the
//! IOAPIC and each vCPU's local APIC, which also start the others), and the
//! vCPUs. What comes back to us is port I/O (the UART), MMIO (the virtio
//! console) and the guest's end (a triple fault: `Exit::Shutdown`).

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const KVMIO: u64 = 0xae;

const fn io(nr: u64) -> u64 {
    (KVMIO << 8) | nr
}
const fn iow(nr: u64, size: u64) -> u64 {
    (1 << 30) | (size << 16) | (KVMIO << 8) | nr
}
const fn ior(nr: u64, size: u64) -> u64 {
    (2 << 30) | (size << 16) | (KVMIO << 8) | nr
}
const fn iowr(nr: u64, size: u64) -> u64 {
    (3 << 30) | (size << 16) | (KVMIO << 8) | nr
}

const KVM_GET_API_VERSION: u64 = io(0x00);
const KVM_CREATE_VM: u64 = io(0x01);
const KVM_GET_VCPU_MMAP_SIZE: u64 = io(0x04);
const KVM_GET_SUPPORTED_CPUID: u64 = iowr(0x05, 8);
const KVM_CREATE_VCPU: u64 = io(0x41);
const KVM_SET_USER_MEMORY_REGION: u64 = iow(0x46, 32);
const KVM_SET_TSS_ADDR: u64 = io(0x47);
const KVM_SET_IDENTITY_MAP_ADDR: u64 = iow(0x48, 8);
const KVM_CREATE_IRQCHIP: u64 = io(0x60);
const KVM_IRQ_LINE: u64 = iow(0x61, 8);
const KVM_RUN: u64 = io(0x80);
const KVM_GET_REGS: u64 = ior(0x81, 144);
const KVM_SET_REGS: u64 = iow(0x82, 144);
const KVM_GET_SREGS: u64 = ior(0x83, 312);
const KVM_SET_SREGS: u64 = iow(0x84, 312);
const KVM_SET_CPUID2: u64 = iow(0x90, 8);
const KVM_GET_TSC_KHZ: u64 = io(0xa3);

const EXIT_IO: u32 = 2;
const EXIT_MMIO: u32 = 6;
const EXIT_SHUTDOWN: u32 = 8;
const EXIT_INTR: u32 = 10;

/// Room KVM needs for its own use on Intel (three pages for a TSS, one for
/// an identity map), just below the top of the 4 GiB, clear of RAM and the
/// devices.
const TSS_ADDR: u64 = 0xfffb_d000;
const IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn ioctl(fd: RawFd, req: u64, arg: u64) -> Result<i32, Error> {
    // SAFETY: each call site passes an argument of the size and kind the
    // request number encodes.
    let r = unsafe { libc::ioctl(fd, req as _, arg) };
    if r < 0 {
        return Err(Error(format!("ioctl {req:#x}: {}", std::io::Error::last_os_error())));
    }
    Ok(r)
}

/// kvm_cpuid_entry2's flags: the leaf has subleaves (`index`).
const KVM_CPUID_FLAG_SIGNIFCANT_INDEX: u32 = 1;

/// struct kvm_cpuid_entry2.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct CpuidEntry {
    function: u32,
    index: u32,
    flags: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    padding: [u32; 3],
}

/// struct kvm_cpuid2, with room for the entries.
#[repr(C)]
struct Cpuid {
    nent: u32,
    padding: u32,
    entries: [CpuidEntry; 256],
}

/// struct kvm_segment.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Segment {
    base: u64,
    limit: u32,
    selector: u16,
    ty: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
}

/// struct kvm_sregs.
#[repr(C)]
#[derive(Clone, Copy)]
struct Sregs {
    segs: [Segment; 8], // cs, ds, es, fs, gs, ss, tr, ldt
    gdt: [u64; 2],
    idt: [u64; 2],
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<Sregs>() == 312);

pub struct Vm {
    vm: OwnedFd,
}

/// A vCPU and its shared `kvm_run` page, for the thread that runs it.
pub struct Cpu {
    fd: OwnedFd,
    run: *mut u8,
    run_size: usize,
    /// Where the last port I/O exit's data is in the run page, and its
    /// length (every unit of a string instruction's).
    io: (usize, usize),
}

// SAFETY: the kvm_run page belongs to the vCPU's fd, which moves with it;
// only one thread at a time runs a vCPU.
unsafe impl Send for Cpu {}

impl Vm {
    /// Create the VM with `size` bytes of memory at host `host` (guest
    /// physical 0), KVM's interrupt controllers, and `cpus` vCPUs: the first
    /// entering at `entry` as PVH says (32-bit protected mode, paging off),
    /// the others waiting for the APIC's INIT and start-up IPIs.
    ///
    /// # Safety
    /// `host` must stay mapped for as long as the VM runs.
    pub unsafe fn create(host: *mut u8, size: usize, entry: u64, cpus: u32) -> Result<(Vm, Vec<Cpu>), Error> {
        let kvm = File::options()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map_err(|e| Error(format!("opening /dev/kvm: {e}")))?;
        if ioctl(kvm.as_raw_fd(), KVM_GET_API_VERSION, 0)? != 12 {
            return Err(Error("unexpected KVM API version".into()));
        }
        let own = |fd: i32| {
            // SAFETY: a descriptor KVM just made for us.
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        let vm = own(ioctl(kvm.as_raw_fd(), KVM_CREATE_VM, 0)?);
        ioctl(vm.as_raw_fd(), KVM_SET_TSS_ADDR, TSS_ADDR)?;
        ioctl(vm.as_raw_fd(), KVM_SET_IDENTITY_MAP_ADDR, &IDENTITY_MAP_ADDR as *const u64 as u64)?;
        ioctl(vm.as_raw_fd(), KVM_CREATE_IRQCHIP, 0)?;
        let region: [u64; 4] = [0, 0, size as u64, host as u64]; // slot 0, flags 0, at 0
        ioctl(vm.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, region.as_ptr() as u64)?;

        let mut supported = Box::new(Cpuid { nent: 256, padding: 0, entries: [CpuidEntry::default(); 256] });
        ioctl(kvm.as_raw_fd(), KVM_GET_SUPPORTED_CPUID, &mut *supported as *mut Cpuid as u64)?;
        let run_size = ioctl(kvm.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0)? as usize;
        let mut vcpus = Vec::new();
        for n in 0..cpus.max(1) {
            let fd = own(ioctl(vm.as_raw_fd(), KVM_CREATE_VCPU, n as u64)?);
            // SAFETY: the vCPU's kvm_run page, shared with KVM.
            let run = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    run_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd.as_raw_fd(),
                    0,
                )
            };
            if run == libc::MAP_FAILED {
                return Err(Error(format!("mapping kvm_run: {}", std::io::Error::last_os_error())));
            }
            let cpu = Cpu { fd, run: run.cast(), run_size, io: (0, 0) };
            cpu.set_cpuid(&supported, n, cpus.max(1))?;
            vcpus.push(cpu);
        }
        vcpus[0].enter_pvh(entry)?;
        Ok((Vm { vm }, vcpus))
    }

    /// The handle device threads use to drive interrupt lines.
    pub fn irq_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
    }
}

/// Drive IOAPIC pin (GSI) `gsi` on VM `vm` (any thread).
pub fn set_irq(vm: RawFd, gsi: u32, level: bool) {
    let irq: [u32; 2] = [gsi, level as u32];
    if let Err(e) = ioctl(vm, KVM_IRQ_LINE, irq.as_ptr() as u64) {
        eprintln!("grix-vmm: KVM_IRQ_LINE {gsi}: {e}");
    }
}

/// What a run stopped for.
pub enum Exit {
    /// Port I/O of `len`-byte units: one, or every one of a string
    /// instruction's (`rep outsb` and the like), written out or to be
    /// filled in, in `Cpu::io_data`.
    Io {
        port: u16,
        len: u32,
        write: bool,
    },
    /// A load (`write` false: fill `data`) or store at `addr`.
    Mmio {
        addr: u64,
        len: u32,
        write: bool,
        data: u64,
    },
    /// The guest ended (a triple fault, as the kernel ends).
    Shutdown,
    /// A signal interrupted the run.
    Interrupted,
    Other(u32),
}

/// What the guest's CPUID says its caches are, whatever the host's: L1
/// data and instruction caches of 32 KiB, 8 ways, a 1 MiB L2 of 16 and a
/// 16 MiB L3 of 16, 64-byte lines. As (type, level, ways, sets): leaf 4's
/// (and AMD's 0x8000001d's) encoding.
const CACHES: [(u32, u32, u32, u32); 4] = [(1, 1, 8, 64), (2, 1, 8, 64), (3, 2, 16, 1024), (3, 3, 16, 16384)];

/// The guest's brand string (CPUID 0x80000002..4), as /proc/cpuinfo's.
const BRAND: &[u8; 48] = b"grix virtual CPU\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// The CPUID vCPU `n` of `cpus` sees: what KVM can give (`supported`),
/// less what describes the host rather than the CPU's features, so a
/// program can't tell one host from another of the same model, or that
/// it's KVM. Vendor, family, model and stepping and the feature flags
/// stay, as MIDR does on arm64: software needs them to run right. The
/// brand string, cache and topology leaves are made up; the physical
/// address width is 36 bits (every x86_64 CPU's least; RAM and the
/// devices are below 4 GiB); and the only hypervisor leaves are the
/// timing leaf (VMware's, which KVM-based VMMs fill in too: the TSC's
/// rate, `tsc_khz`, which the kernel would otherwise measure) and the
/// one that says it's there, with no vendor.
fn guest_cpuid(supported: &[CpuidEntry], n: u32, cpus: u32, tsc_khz: u32) -> Vec<CpuidEntry> {
    let cpus = cpus.max(1);
    let leaf = |function, index| CpuidEntry { function, index, ..CpuidEntry::default() };
    let max_ext = supported.iter().find(|e| e.function == 0x8000_0000).map_or(0, |e| e.eax);
    // "AuthenticAMD", in EBX, EDX and ECX.
    let amd =
        supported.iter().any(|e| e.function == 0 && [e.ebx, e.edx, e.ecx] == [0x6874_7541, 0x6974_6e65, 0x444d_4163]);
    // Leaf 4's and 0x8000001d's: a cache per subleaf, then an empty one.
    // The L3 is every CPU's; the rest each one's own.
    let caches = |function: u32| {
        let mut v: Vec<CpuidEntry> = CACHES
            .iter()
            .enumerate()
            .map(|(i, &(ty, level, ways, sets))| {
                let sharing = if level == 3 { cpus - 1 } else { 0 };
                let cores = if function == 4 { (cpus - 1) << 26 } else { 0 };
                CpuidEntry {
                    eax: ty | level << 5 | 1 << 8 | sharing << 14 | cores,
                    ebx: (ways - 1) << 22 | 63,
                    ecx: sets - 1,
                    flags: KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
                    ..leaf(function, i as u32)
                }
            })
            .collect();
        v.push(CpuidEntry { flags: KVM_CPUID_FLAG_SIGNIFCANT_INDEX, ..leaf(function, CACHES.len() as u32) });
        v
    };
    let mut out = Vec::new();
    for e in supported {
        let mut e = *e;
        match e.function {
            // The APIC ID, and how many logical processors there are; no
            // brand index.
            1 => e.ebx = (e.ebx & 0x0000_ff00) | n << 24 | (cpus & 0xff) << 16,
            // Leaf 2's descriptors (Intel's): none, see leaf 4.
            2 if !amd => (e.eax, e.ebx, e.ecx, e.edx) = (0xff01, 0, 0, 0),
            // The serial number.
            3 => (e.eax, e.ebx, e.ecx, e.edx) = (0, 0, 0, 0),
            4 | 0x8000_001d if e.index == 0 => {
                // An AMD CPU has no leaf 4, nor an Intel one 0x8000001d.
                if e.eax & 0x1f != 0 {
                    out.extend(caches(e.function));
                }
                continue;
            }
            4 | 0x8000_001d => continue,
            // No topology (EBX 0): software goes by leaf 1 and the APIC ID.
            0xb | 0x1f => (e.eax, e.ebx, e.ecx, e.edx) = (0, 0, e.index & 0xff, n),
            // KVM's own leaves.
            0x4000_0000..=0x4fff_ffff => continue,
            0x8000_0002..=0x8000_0004 => continue,
            // The caches leaf 4 has, as each vendor encodes them here (AMD's
            // L1, its L2 and L3; Intel's L2 only, with no lines per tag);
            // no TLBs.
            0x8000_0005 if amd => (e.eax, e.ebx, e.ecx, e.edx) = (0, 0, 0x2008_0140, 0x2008_0140),
            0x8000_0006 if amd => (e.eax, e.ebx, e.ecx, e.edx) = (0, 0, 0x0400_8140, 0x0080_8140),
            0x8000_0005 => (e.eax, e.ebx, e.ecx, e.edx) = (0, 0, 0, 0),
            0x8000_0006 => (e.eax, e.ebx, e.ecx, e.edx) = (0, 0, 0x0400_8040, 0),
            // 36 bits physical, 48 virtual; AMD's core count, without the
            // host's APIC ID size.
            0x8000_0008 => {
                e.eax = 36 | 48 << 8;
                if amd {
                    e.ecx = (e.ecx & !0xf0ff) | ((cpus - 1) & 0xff);
                }
            }
            // AMD's topology: the extended APIC ID, and a core of its own.
            0x8000_001e => (e.eax, e.ebx, e.ecx, e.edx) = (n, n & 0xff, 0, 0),
            _ => {}
        }
        out.push(e);
    }
    if max_ext >= 0x8000_0004 {
        for (i, w) in BRAND.as_chunks::<16>().0.iter().enumerate() {
            let [eax, ebx, ecx, edx] =
                core::array::from_fn(|k| u32::from_le_bytes(w[4 * k..4 * k + 4].try_into().unwrap()));
            out.push(CpuidEntry { eax, ebx, ecx, edx, ..leaf(0x8000_0002 + i as u32, 0) });
        }
    }
    out.push(CpuidEntry { eax: 0x4000_0010, ..leaf(0x4000_0000, 0) });
    out.push(CpuidEntry { eax: tsc_khz, ebx: 1_000_000, ..leaf(0x4000_0010, 0) });
    out
}

impl Cpu {
    /// The CPUID the guest sees (`guest_cpuid`).
    fn set_cpuid(&self, supported: &Cpuid, n: u32, cpus: u32) -> Result<(), Error> {
        let tsc_khz = ioctl(self.fd.as_raw_fd(), KVM_GET_TSC_KHZ, 0)? as u32;
        let entries = guest_cpuid(&supported.entries[..(supported.nent as usize).min(256)], n, cpus, tsc_khz);
        let mut c = Box::new(Cpuid { nent: 0, padding: 0, entries: [CpuidEntry::default(); 256] });
        if entries.len() > c.entries.len() {
            return Err(Error(format!("{} CPUID entries is more than {}", entries.len(), c.entries.len())));
        }
        c.entries[..entries.len()].copy_from_slice(&entries);
        c.nent = entries.len() as u32;
        ioctl(self.fd.as_raw_fd(), KVM_SET_CPUID2, &*c as *const Cpuid as u64).map(|_| ())
    }

    /// PVH's entry state: flat 32-bit code and data segments, protected
    /// mode without paging, at `entry`.
    fn enter_pvh(&self, entry: u64) -> Result<(), Error> {
        // SAFETY: zeroed plain data, filled by KVM.
        let mut s: Sregs = unsafe { std::mem::zeroed() };
        ioctl(self.fd.as_raw_fd(), KVM_GET_SREGS, &mut s as *mut Sregs as u64)?;
        let flat = |selector: u16, ty: u8| Segment {
            base: 0,
            limit: 0xffff_ffff,
            selector,
            ty,
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            ..Segment::default()
        };
        s.segs[0] = flat(0x08, 0xb); // cs: code, execute/read, accessed
        for i in 1..6 {
            s.segs[i] = flat(0x10, 0x3); // ds, es, fs, gs, ss: data, read/write, accessed
        }
        s.segs[6] = Segment { limit: 0x67, ty: 0xb, present: 1, ..Segment::default() }; // tr: busy 32-bit TSS
        s.cr0 = 0x11; // PE, ET
        s.cr3 = 0;
        s.cr4 = 0;
        s.efer = 0;
        ioctl(self.fd.as_raw_fd(), KVM_SET_SREGS, &s as *const Sregs as u64)?;
        let mut regs = [0u64; 18]; // rax..r15, rip, rflags
        ioctl(self.fd.as_raw_fd(), KVM_GET_REGS, regs.as_mut_ptr() as u64)?;
        regs = [0; 18];
        regs[16] = entry;
        regs[17] = 0x2;
        ioctl(self.fd.as_raw_fd(), KVM_SET_REGS, regs.as_ptr() as u64).map(|_| ())
    }

    pub fn run(&mut self) -> Result<Exit, Error> {
        // SAFETY: KVM_RUN takes no argument; the run page is ours.
        let r = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_RUN as _, 0) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                return Ok(Exit::Interrupted);
            }
            return Err(Error(format!("KVM_RUN: {e}")));
        }
        // SAFETY: struct kvm_run: exit_reason at 8, the exit's union at 32.
        unsafe {
            let reason = (self.run.add(8) as *const u32).read_volatile();
            Ok(match reason {
                EXIT_IO => {
                    // struct { u8 direction; u8 size; u16 port; u32 count; u64 data_offset; }
                    let write = self.run.add(32).read_volatile() == 1;
                    let len = (self.run.add(33).read_volatile() as u32).clamp(1, 4);
                    let port = (self.run.add(34) as *const u16).read_volatile();
                    let count = (self.run.add(36) as *const u32).read_volatile();
                    let at = (self.run.add(40) as *const u64).read_volatile() as usize;
                    // Every unit KVM put in the page (a string instruction's
                    // take up to a page), and never past its end.
                    let room = self.run_size.saturating_sub(at) / len as usize;
                    self.io = (at, (count as usize).min(room) * len as usize);
                    Exit::Io { port, len, write }
                }
                EXIT_MMIO => {
                    let addr = (self.run.add(32) as *const u64).read_volatile();
                    let mut data = [0u8; 8];
                    std::ptr::copy_nonoverlapping(self.run.add(40), data.as_mut_ptr(), 8);
                    let len = (self.run.add(48) as *const u32).read_volatile().min(8);
                    let write = self.run.add(52).read_volatile() != 0;
                    Exit::Mmio { addr, len, write, data: u64::from_le_bytes(data) }
                }
                EXIT_SHUTDOWN => Exit::Shutdown,
                EXIT_INTR => Exit::Interrupted,
                r => Exit::Other(r),
            })
        }
    }

    /// The last port I/O exit's data: what an `out` wrote, or the room for
    /// what an `in` reads, which the guest gets when the run resumes.
    pub fn io_data(&mut self) -> &mut [u8] {
        let (at, len) = self.io;
        // SAFETY: inside the run page (`run` bounds it), which is ours
        // between runs.
        unsafe { std::slice::from_raw_parts_mut(self.run.add(at), len) }
    }

    /// The value a load that exited gets, when the run resumes.
    pub fn complete_load(&mut self, value: u64, len: u32) {
        let bytes = value.to_le_bytes();
        // SAFETY: kvm_run's mmio.data, 8 bytes at 40.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.run.add(40), len.min(8) as usize) };
    }
}

/// Give up everything but running the VM, in every thread: a seccomp
/// filter allows only the system calls the vCPU loop and the device
/// threads make on what's already open, and of ioctls only running a vCPU
/// and driving an interrupt line; anything else fails with EPERM. The x32
/// ABI's calls (another table of numbers on the same entry) kill the
/// process.
pub fn confine() -> Result<(), String> {
    // x86_64 system call numbers.
    const IOCTL: u32 = 16;
    const ALLOWED: &[u32] = &[
        0,   // read
        1,   // write
        3,   // close
        9,   // mmap
        10,  // mprotect
        11,  // munmap
        12,  // brk
        13,  // rt_sigaction
        14,  // rt_sigprocmask
        15,  // rt_sigreturn
        20,  // writev
        24,  // sched_yield
        25,  // mremap
        28,  // madvise
        35,  // nanosleep
        39,  // getpid
        60,  // exit
        131, // sigaltstack
        186, // gettid
        202, // futex
        228, // clock_gettime
        230, // clock_nanosleep
        231, // exit_group
        273, // set_robust_list
        318, // getrandom
        // A new thread's own: glibc registers it as the thread starts (which
        // may be after the filter is on, for threads made just before), and
        // gives up if refused.
        334, // rseq
    ];
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const JGE_K: u16 = 0x35;
    const RET_K: u16 = 0x06;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const RET_ERRNO: u32 = 0x0005_0000;
    let stmt = |code, k| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
    let ioctls = [KVM_RUN as u32, KVM_IRQ_LINE as u32];
    let mut prog = vec![
        stmt(LD_W_ABS, 4), // seccomp_data.arch
        jump(JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(RET_K, RET_KILL_PROCESS),
        stmt(LD_W_ABS, 0), // seccomp_data.nr
        jump(JGE_K, X32_SYSCALL_BIT, 0, 1),
        stmt(RET_K, RET_KILL_PROCESS),
        // ioctl: only these requests (the low word of args[1]).
        jump(JEQ_K, IOCTL, 0, ioctls.len() as u8 + 3),
        stmt(LD_W_ABS, 24),
    ];
    for (i, &req) in ioctls.iter().enumerate() {
        prog.push(jump(JEQ_K, req, (ioctls.len() - i) as u8, 0));
    }
    prog.push(stmt(RET_K, RET_ERRNO | libc::EPERM as u32));
    prog.push(stmt(RET_K, RET_ALLOW));
    // Everything else, by number (the accumulator still holds it).
    for (i, &nr) in ALLOWED.iter().enumerate() {
        let rest = (ALLOWED.len() - i - 1) as u8;
        prog.push(jump(JEQ_K, nr, rest + 1, 0));
    }
    prog.push(stmt(RET_K, RET_ERRNO | libc::EPERM as u32));
    prog.push(stmt(RET_K, RET_ALLOW));
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
    // SAFETY: prctl and seccomp with a filter that outlives the calls (the
    // kernel copies it). TSYNC applies it to the threads already running.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!("no_new_privs: {}", std::io::Error::last_os_error()));
        }
        const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
        const SECCOMP_FILTER_FLAG_TSYNC: libc::c_long = 1;
        let r = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &fprog as *const libc::sock_fprog,
        );
        if r != 0 {
            return Err(format!("installing the seccomp filter: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(function: u32, index: u32, [eax, ebx, ecx, edx]: [u32; 4]) -> CpuidEntry {
        CpuidEntry { function, index, eax, ebx, ecx, edx, ..CpuidEntry::default() }
    }

    fn get(v: &[CpuidEntry], function: u32, index: u32) -> Option<[u32; 4]> {
        v.iter().find(|x| x.function == function && x.index == index).map(|x| [x.eax, x.ebx, x.ecx, x.edx])
    }

    fn words(s: &[u8]) -> [u32; 4] {
        let mut b = [0u8; 16];
        b[..s.len().min(16)].copy_from_slice(&s[..s.len().min(16)]);
        core::array::from_fn(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
    }

    /// An Intel host as KVM describes it: `brand`, its caches (L3 of
    /// `l3_sets`), `cores`, `phys` address bits.
    fn intel(brand: &[u8], l3_sets: u32, cores: u32, phys: u32) -> Vec<CpuidEntry> {
        let mut v = vec![
            e(0, 0, [0x1f, 0x756e_6547, 0x6c65_746e, 0x4965_6e69]), // GenuineIntel
            e(1, 0, [0x0006_06a6, 0x0040_0800 | (cores * 2) << 16 | 0x17 << 24 | 0x01, 0xfeda_3223, 0x1f8b_fbff]),
            e(2, 0, [0x00fe_ff01, 0xf0, 0, 0]),
        ];
        let l = (cores - 1) << 26;
        v.extend([
            e(4, 0, [0x121 | l, 0x02c0_003f, 63, 0]),
            e(4, 1, [0x122 | l, 0x01c0_003f, 63, 0]),
            e(4, 2, [0x143 | 1 << 14 | l, 0x04c0_003f, 1023, 0]),
            e(4, 3, [0x163 | (cores * 2 - 1) << 14 | l, 0x02c0_003f, l3_sets - 1, 4]),
            e(4, 4, [0, 0, 0, 0]),
            e(0xb, 0, [1, 2, 0x100, 0x17]),
            e(0xb, 1, [6, cores * 2, 0x201, 0x17]),
            e(0x4000_0000, 0, [0x4000_0001, 0x4b4d_564b, 0x564b_4d56, 0x4d]), // KVMKVMKVM
            e(0x4000_0001, 0, [0x0100_7afb, 0, 0, 0]),
            e(0x8000_0000, 0, [0x8000_0008, 0, 0, 0]),
            e(0x8000_0001, 0, [0, 0, 0x121, 0x2c10_0800]),
            e(0x8000_0002, 0, words(brand)),
            e(0x8000_0003, 0, words(brand.get(16..).unwrap_or(&[]))),
            e(0x8000_0004, 0, words(brand.get(32..).unwrap_or(&[]))),
            e(0x8000_0006, 0, [0, 0, 0x0500_7040, 0]),
            e(0x8000_0008, 0, [0x3000 | phys, 0x0100_d000, 0, 0]),
        ]);
        v
    }

    #[test]
    fn the_guest_cant_tell_hosts_of_a_model_apart() {
        let a = guest_cpuid(&intel(b"Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz", 49152, 32, 46), 0, 2, 2_900_000);
        let b = guest_cpuid(&intel(b"Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz", 32768, 16, 52), 0, 2, 2_900_000);
        assert_eq!(a, b);
        let brand: Vec<u8> =
            (0x8000_0002..=0x8000_0004).flat_map(|f| get(&a, f, 0).unwrap()).flat_map(u32::to_le_bytes).collect();
        assert_eq!(&brand[..], &BRAND[..]);
        // No KVM signature, only the timing leaf.
        assert_eq!(get(&a, 0x4000_0000, 0), Some([0x4000_0010, 0, 0, 0]));
        assert_eq!(get(&a, 0x4000_0001, 0), None);
        assert_eq!(get(&a, 0x4000_0010, 0), Some([2_900_000, 1_000_000, 0, 0]));
        assert_eq!(get(&a, 0x8000_0008, 0).unwrap()[0], 36 | 48 << 8);
        // The features, family and model are the CPU's.
        let host = intel(b"x", 49152, 32, 46);
        let [eax, ebx, ecx, edx] = get(&a, 1, 0).unwrap();
        let h = get(&host, 1, 0).unwrap();
        assert_eq!((eax, ecx, edx), (h[0], h[2], h[3]));
        assert_eq!(ebx, 0x0002_0800);
        assert_eq!(get(&a, 0x8000_0001, 0), get(&host, 0x8000_0001, 0));
        // No topology, and leaf 2 says to look at leaf 4.
        assert_eq!(get(&a, 0xb, 1), Some([0, 0, 1, 0]));
        assert_eq!(get(&a, 2, 0), Some([0xff01, 0, 0, 0]));
    }

    #[test]
    fn caches_are_made_up() {
        let v = guest_cpuid(&intel(b"x", 49152, 32, 46), 3, 4, 1);
        let size = |[eax, ebx, ecx, _]: [u32; 4]| {
            (
                eax & 0x1f,
                (eax >> 5) & 7,
                ((ebx >> 22) + 1) * ((ebx >> 12 & 0x3ff) + 1) * ((ebx & 0xfff) + 1) * (ecx + 1),
            )
        };
        let caches: Vec<_> = (0..4).map(|i| size(get(&v, 4, i).unwrap())).collect();
        assert_eq!(caches, [(1, 1, 32 << 10), (2, 1, 32 << 10), (3, 2, 1 << 20), (3, 3, 16 << 20)]);
        assert_eq!(get(&v, 4, 4), Some([0, 0, 0, 0]));
        assert_eq!(get(&v, 4, 5), None);
        // Four cores, the L3 shared by all of them.
        assert_eq!(get(&v, 4, 0).unwrap()[0] >> 26, 3);
        assert_eq!(get(&v, 4, 3).unwrap()[0] >> 14 & 0xfff, 3);
        // This vCPU's APIC ID.
        assert_eq!(get(&v, 1, 0).unwrap()[1] >> 24, 3);
        assert_eq!(get(&v, 0xb, 0).unwrap()[3], 3);
    }

    #[test]
    fn amd_caches_and_topology() {
        let mut host = vec![
            e(0, 0, [0x10, 0x6874_7541, 0x444d_4163, 0x6974_6e65]), // AuthenticAMD
            e(1, 0, [0x00a0_0f11, 0x0420_0800, 0x7ef8_3203, 0x178b_fbff]),
            e(0x8000_0000, 0, [0x8000_0021, 0, 0, 0]),
            e(0x8000_0005, 0, [0xff40_ff40, 0xff40_ff40, 0x2008_0140, 0x2008_0140]),
            e(0x8000_0006, 0, [0x5c00_2200, 0x6c00_4200, 0x0200_6140, 0x0100_9140]),
            e(0x8000_0008, 0, [0x3030, 0x0100_d000, 0x0000_703f, 0]),
            e(0x8000_001e, 0, [5, 0x0102, 0x0300, 0]),
        ];
        host.extend((0..4).map(|i| e(0x8000_001d, i, [0x121 + i, 0x01c0_003f, 63, 0])));
        host.push(e(0x8000_001d, 4, [0, 0, 0, 0]));
        let v = guest_cpuid(&host, 1, 2, 1);
        assert_eq!(get(&v, 0x8000_0006, 0), Some([0, 0, 0x0400_8140, 0x0080_8140]));
        assert_eq!(get(&v, 0x8000_0008, 0).unwrap()[2], 1);
        assert_eq!(get(&v, 0x8000_001e, 0), Some([1, 1, 0, 0]));
        assert_eq!(get(&v, 0x8000_001d, 3).unwrap()[0], 0x163 | 1 << 14);
        assert_eq!(get(&v, 4, 0), None);
    }
}
