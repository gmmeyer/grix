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

/// struct kvm_cpuid_entry2.
#[repr(C)]
#[derive(Clone, Copy, Default)]
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
            let cpu = Cpu { fd, run: run.cast() };
            cpu.set_cpuid(&supported, n)?;
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
    /// Port I/O: an `out` of `data` (`len` bytes), or an `in` to fill.
    Io {
        port: u16,
        len: u32,
        write: bool,
        data: u32,
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

impl Cpu {
    /// The CPUID KVM can give, with this vCPU's APIC ID, and the hypervisor
    /// timing leaf (VMware's, which KVM-based VMMs fill in too): the TSC's
    /// rate, which the kernel would otherwise measure.
    fn set_cpuid(&self, supported: &Cpuid, n: u32) -> Result<(), Error> {
        let tsc_khz = ioctl(self.fd.as_raw_fd(), KVM_GET_TSC_KHZ, 0)? as u32;
        let mut c = Box::new(Cpuid { nent: 0, padding: 0, entries: [CpuidEntry::default(); 256] });
        let mut have_timing = false;
        for e in &supported.entries[..(supported.nent as usize).min(255)] {
            let mut e = *e;
            match e.function {
                1 => e.ebx = (e.ebx & 0x00ff_ffff) | n << 24,
                0xb | 0x1f => e.edx = n,
                0x4000_0000 => e.eax = e.eax.max(0x4000_0010),
                0x4000_0010 => {
                    (e.eax, e.ebx) = (tsc_khz, 1_000_000);
                    have_timing = true;
                }
                _ => {}
            }
            c.entries[c.nent as usize] = e;
            c.nent += 1;
        }
        if !have_timing {
            c.entries[c.nent as usize] =
                CpuidEntry { function: 0x4000_0010, eax: tsc_khz, ebx: 1_000_000, ..CpuidEntry::default() };
            c.nent += 1;
        }
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
                    let len = (self.run.add(33).read_volatile() as u32).min(4);
                    let port = (self.run.add(34) as *const u16).read_volatile();
                    let count = (self.run.add(36) as *const u32).read_volatile();
                    let at = (self.run.add(40) as *const u64).read_volatile() as usize;
                    // String I/O (rep outsb, ...): only its first unit.
                    let _ = count;
                    let mut data = [0u8; 4];
                    if write {
                        std::ptr::copy_nonoverlapping(self.run.add(at), data.as_mut_ptr(), len as usize);
                    }
                    Exit::Io { port, len, write, data: u32::from_le_bytes(data) }
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

    /// The value an `in` that exited gets, when the run resumes.
    pub fn complete_in(&mut self, value: u32, len: u32) {
        // SAFETY: kvm_run's io.data_offset says where, within the run page.
        unsafe {
            let at = (self.run.add(40) as *const u64).read_volatile() as usize;
            let bytes = value.to_le_bytes();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.run.add(at), len.min(4) as usize);
        }
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
        318, // getrandom
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
