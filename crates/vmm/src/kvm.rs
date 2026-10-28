//! KVM (Linux on arm64): the VM, its memory, the in-kernel GICv3 and one
//! vCPU. KVM handles WFI, the timer and PSCI itself; what comes back to us
//! is MMIO to our devices and the guest powering off.

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
const KVM_CREATE_VCPU: u64 = io(0x41);
const KVM_SET_USER_MEMORY_REGION: u64 = iow(0x46, 32);
const KVM_IRQ_LINE: u64 = iow(0x61, 8);
const KVM_RUN: u64 = io(0x80);
const KVM_SET_ONE_REG: u64 = iow(0xac, 16);
const KVM_ARM_VCPU_INIT: u64 = iow(0xae, 32);
const KVM_ARM_PREFERRED_TARGET: u64 = ior(0xaf, 32);
const KVM_CREATE_DEVICE: u64 = iowr(0xe0, 12);
const KVM_SET_DEVICE_ATTR: u64 = iow(0xe1, 24);

const KVM_DEV_TYPE_ARM_VGIC_V3: u32 = 7;
const KVM_DEV_ARM_VGIC_GRP_ADDR: u32 = 0;
const KVM_DEV_ARM_VGIC_GRP_NR_IRQS: u32 = 3;
const KVM_DEV_ARM_VGIC_GRP_CTRL: u32 = 4;
const KVM_VGIC_V3_ADDR_TYPE_DIST: u64 = 2;
const KVM_VGIC_V3_ADDR_TYPE_REDIST: u64 = 3;
const KVM_DEV_ARM_VGIC_CTRL_INIT: u64 = 0;
const KVM_ARM_VCPU_POWER_OFF: u32 = 0;
const KVM_ARM_VCPU_PSCI_0_2: u32 = 2;
const KVM_ARM_IRQ_TYPE_SPI: u32 = 1;

pub const EXIT_MMIO: u32 = 6;
pub const EXIT_INTR: u32 = 10;
pub const EXIT_SYSTEM_EVENT: u32 = 24;

/// Core register ids: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE,
/// plus the offset in `struct kvm_regs` in 32-bit words.
const fn core_reg(offset_bytes: u64) -> u64 {
    0x6030_0000_0010_0000 | (offset_bytes / 4)
}
pub const REG_PC: u64 = core_reg(32 * 8);
pub const REG_PSTATE: u64 = core_reg(33 * 8);

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

#[repr(C)]
#[derive(Default)]
struct VcpuInit {
    target: u32,
    features: [u32; 7],
}

#[repr(C)]
struct DeviceAttr {
    flags: u32,
    group: u32,
    attr: u64,
    addr: u64,
}

pub struct Vm {
    vm: OwnedFd,
    _gic: OwnedFd,
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
    /// Create the VM with `size` bytes of memory at host `host`, guest
    /// `ipa`, a GICv3 at the given bases, and `cpus` vCPUs: the first
    /// starting at `pc`, the others off until PSCI CPU_ON (which KVM
    /// handles).
    ///
    /// # Safety
    /// `host` must stay mapped for as long as the VM runs.
    pub unsafe fn create(
        host: *mut u8,
        ipa: u64,
        size: usize,
        gicd: u64,
        gicr: u64,
        pc: u64,
        cpus: u32,
    ) -> Result<(Vm, Vec<Cpu>), Error> {
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
        let region: [u64; 4] = [0, ipa, size as u64, host as u64]; // slot 0, flags 0
        ioctl(vm.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, region.as_ptr() as u64)?;

        let mut dev: [u32; 3] = [KVM_DEV_TYPE_ARM_VGIC_V3, 0, 0];
        ioctl(vm.as_raw_fd(), KVM_CREATE_DEVICE, dev.as_mut_ptr() as u64)?;
        let gic = own(dev[1] as i32);
        let set = |group: u32, attr: u64, value: *const u8| {
            let a = DeviceAttr { flags: 0, group, attr, addr: value as u64 };
            ioctl(gic.as_raw_fd(), KVM_SET_DEVICE_ATTR, &a as *const DeviceAttr as u64)
        };
        set(KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_DIST, &gicd as *const u64 as *const u8)?;
        set(KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_REDIST, &gicr as *const u64 as *const u8)?;
        let nr_irqs: u32 = 128;
        set(KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr_irqs as *const u32 as *const u8)?;

        let run_size = ioctl(kvm.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0)? as usize;
        let mut vcpus = Vec::new();
        for n in 0..cpus.max(1) {
            let fd = own(ioctl(vm.as_raw_fd(), KVM_CREATE_VCPU, n as u64)?);
            let mut init = VcpuInit::default();
            ioctl(vm.as_raw_fd(), KVM_ARM_PREFERRED_TARGET, &mut init as *mut VcpuInit as u64)?;
            // PSCI 0.2 in the kernel: SYSTEM_OFF comes back as a system
            // event, and CPU_ON starts the others.
            init.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
            if n > 0 {
                init.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
            }
            ioctl(fd.as_raw_fd(), KVM_ARM_VCPU_INIT, &init as *const VcpuInit as u64)?;
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
            vcpus.push(Cpu { fd, run: run.cast() });
        }
        // The GIC is ready once its vCPUs exist.
        set(KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_CTRL_INIT, std::ptr::null())?;
        vcpus[0].set_reg(REG_PC, pc)?;
        vcpus[0].set_reg(REG_PSTATE, 0x3c5)?; // EL1h, interrupts masked
        Ok((Vm { vm, _gic: gic }, vcpus))
    }

    /// The handle device threads use to drive interrupt lines.
    pub fn irq_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
    }
}

/// Drive shared peripheral interrupt `intid` on VM `vm` (any thread).
pub fn set_spi(vm: RawFd, intid: u32, level: bool) {
    let irq: [u32; 2] = [(KVM_ARM_IRQ_TYPE_SPI << 24) | intid, level as u32];
    if let Err(e) = ioctl(vm, KVM_IRQ_LINE, irq.as_ptr() as u64) {
        eprintln!("grix-vmm: KVM_IRQ_LINE {intid}: {e}");
    }
}

/// What a run stopped for.
pub enum Exit {
    /// A load (`write` false: fill `data`) or store at `addr`.
    Mmio {
        addr: u64,
        len: u32,
        write: bool,
        data: u64,
    },
    /// The guest powered off (or reset).
    Shutdown,
    /// A signal interrupted the run.
    Interrupted,
    Other(u32),
}

impl Cpu {
    pub fn set_reg(&mut self, id: u64, value: u64) -> Result<(), Error> {
        let reg: [u64; 2] = [id, &value as *const u64 as u64];
        ioctl(self.fd.as_raw_fd(), KVM_SET_ONE_REG, reg.as_ptr() as u64).map(|_| ())
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
                EXIT_MMIO => {
                    let addr = (self.run.add(32) as *const u64).read_volatile();
                    let mut data = [0u8; 8];
                    std::ptr::copy_nonoverlapping(self.run.add(40), data.as_mut_ptr(), 8);
                    let len = (self.run.add(48) as *const u32).read_volatile().min(8);
                    let write = self.run.add(52).read_volatile() != 0;
                    Exit::Mmio { addr, len, write, data: u64::from_le_bytes(data) }
                }
                EXIT_SYSTEM_EVENT => Exit::Shutdown,
                EXIT_INTR => Exit::Interrupted,
                r => Exit::Other(r),
            })
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
/// threads make on what's already open (no open, socket, exec, signals to
/// anyone, ...), and of ioctls only running the vCPU and driving an
/// interrupt line. Anything else fails with EPERM. If guest input ever
/// found a bug in this process, that's all it would have.
pub fn confine() -> Result<(), String> {
    // aarch64 system call numbers.
    const IOCTL: u32 = 29;
    const ALLOWED: &[u32] = &[
        57,  // close
        63,  // read
        64,  // write
        66,  // writev
        93,  // exit
        94,  // exit_group
        98,  // futex
        101, // nanosleep
        113, // clock_gettime
        115, // clock_nanosleep
        124, // sched_yield
        132, // sigaltstack
        134, // rt_sigaction
        135, // rt_sigprocmask
        139, // rt_sigreturn
        172, // getpid
        178, // gettid
        214, // brk
        215, // munmap
        216, // mremap
        222, // mmap
        226, // mprotect
        233, // madvise
        278, // getrandom
    ];
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const RET_ERRNO: u32 = 0x0005_0000;
    let stmt = |code, k| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jeq = |k, jt, jf| libc::sock_filter { code: JEQ_K, jt, jf, k };
    let mut prog = vec![
        stmt(LD_W_ABS, 4), // seccomp_data.arch
        jeq(AUDIT_ARCH_AARCH64, 1, 0),
        stmt(RET_K, RET_KILL_PROCESS),
        stmt(LD_W_ABS, 0), // seccomp_data.nr
        // ioctl: only these requests (the low word of args[1]: musl passes
        // an int).
        jeq(IOCTL, 0, 5),
        stmt(LD_W_ABS, 24),
        jeq(KVM_RUN as u32, 2, 0),
        jeq(KVM_IRQ_LINE as u32, 1, 0),
        stmt(RET_K, RET_ERRNO | libc::EPERM as u32),
        stmt(RET_K, RET_ALLOW),
        // Everything else, by number (the accumulator still holds it).
    ];
    for (i, &nr) in ALLOWED.iter().enumerate() {
        // Matched: jump past the rest of the list and the deny to the allow.
        let rest = (ALLOWED.len() - i - 1) as u8;
        prog.push(jeq(nr, rest + 1, 0));
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
