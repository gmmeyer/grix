//! KVM (Linux on arm64): the VM, its memory, the in-kernel GICv3 and its
//! vCPUs. KVM handles WFI, the timer and PSCI itself; what comes back to
//! us is MMIO to our devices, the guest powering off, and (for a snapshot)
//! the one SMCCC call we ask KVM to forward.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

pub use crate::kick::{Kick, handle_kicks};

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
const KVM_GET_ONE_REG: u64 = iow(0xab, 16);
const KVM_SET_ONE_REG: u64 = iow(0xac, 16);
const KVM_GET_REG_LIST: u64 = iowr(0xb0, 8);
const KVM_GET_MP_STATE: u64 = ior(0x98, 4);
const KVM_SET_MP_STATE: u64 = iow(0x99, 4);
const KVM_GET_DEVICE_ATTR: u64 = iow(0xe2, 24);
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
const KVM_ARM_VM_SMCCC_CTRL: u32 = 0;
const KVM_ARM_VM_SMCCC_FILTER: u64 = 0;
const KVM_SMCCC_FILTER_FWD_TO_USER: u8 = 2;

pub const EXIT_HYPERCALL: u32 = 3;
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

/// General-purpose register `n` (x0..x30).
pub const fn reg_x(n: u64) -> u64 {
    core_reg(n * 8)
}

/// The guest's virtual counter (CNTVCT_EL0, whose id KVM swapped with
/// CNTV_CVAL's): writing it sets the VM's counter offset.
pub const REG_TIMER_CNT: u64 = 0x6030_0000_0013_df1a;
/// The physical counter (CNTPCT_EL0, `KVM_REG_ARM_PTIMER_CNT`).
pub const REG_PTIMER_CNT: u64 = 0x6030_0000_0013_df01;

/// A register's size in bytes, from its id.
pub fn reg_size(id: u64) -> usize {
    1 << ((id >> 52) & 0xf)
}

/// A vCPU's PSCI power state (`KVM_GET_MP_STATE`): running or off.
pub const MP_STATE_RUNNABLE: u32 = 0;
pub const MP_STATE_STOPPED: u32 = 5;

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
    gic: OwnedFd,
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
        Ok((Vm { vm, gic }, vcpus))
    }

    /// Have SMCCC function `function` come back to us as an
    /// `Exit::Hypercall` (before any vCPU runs).
    pub fn forward(&self, function: u32) -> Result<(), Error> {
        // struct kvm_smccc_filter: base, nr_functions, action, pad.
        let mut filter = [0u8; 24];
        filter[..4].copy_from_slice(&function.to_le_bytes());
        filter[4..8].copy_from_slice(&1u32.to_le_bytes());
        filter[8] = KVM_SMCCC_FILTER_FWD_TO_USER;
        let a = DeviceAttr {
            flags: 0,
            group: KVM_ARM_VM_SMCCC_CTRL,
            attr: KVM_ARM_VM_SMCCC_FILTER,
            addr: filter.as_ptr() as u64,
        };
        ioctl(self.vm.as_raw_fd(), KVM_SET_DEVICE_ATTR, &a as *const DeviceAttr as u64)
            .map(|_| ())
            .map_err(|e| Error(format!("snapshots on KVM need Linux 6.4 or later (its SMCCC filter): {e}")))
    }

    /// The in-kernel GIC, whose state is its device attributes.
    pub fn gic_fd(&self) -> RawFd {
        self.gic.as_raw_fd()
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
    /// A signal interrupted the run (or a kick).
    Interrupted,
    /// An SMCCC call we asked for (`Vm::create`'s `forward`), with its
    /// function id; the PC is past the HVC.
    Hypercall {
        function: u64,
    },
    Other(u32),
}

impl Cpu {
    pub fn set_reg(&mut self, id: u64, value: u64) -> Result<(), Error> {
        self.set_raw(id, &value.to_le_bytes()[..reg_size(id).min(8)])
    }

    /// A register of any size (`reg_size`), as bytes.
    pub fn get_raw(&self, id: u64, value: &mut [u8]) -> Result<(), Error> {
        if value.len() != reg_size(id) {
            return Err(Error(format!("register {id:#x} isn't {} bytes", value.len())));
        }
        let reg: [u64; 2] = [id, value.as_mut_ptr() as u64];
        ioctl(self.fd.as_raw_fd(), KVM_GET_ONE_REG, reg.as_ptr() as u64).map(|_| ())
    }

    pub fn set_raw(&mut self, id: u64, value: &[u8]) -> Result<(), Error> {
        if value.len() != reg_size(id) {
            return Err(Error(format!("register {id:#x} isn't {} bytes", value.len())));
        }
        let reg: [u64; 2] = [id, value.as_ptr() as u64];
        ioctl(self.fd.as_raw_fd(), KVM_SET_ONE_REG, reg.as_ptr() as u64).map(|_| ())
    }

    /// Every register KVM has for this vCPU.
    pub fn reg_list(&self) -> Result<Vec<u64>, Error> {
        // struct kvm_reg_list: n, then n ids. KVM says how many with E2BIG.
        let mut list = vec![0u64; 1];
        let _ = ioctl(self.fd.as_raw_fd(), KVM_GET_REG_LIST, list.as_mut_ptr() as u64);
        let n = list[0] as usize;
        if n == 0 || n > 1 << 16 {
            return Err(Error(format!("KVM_GET_REG_LIST says {n} registers")));
        }
        list = vec![0u64; 1 + n];
        list[0] = n as u64;
        ioctl(self.fd.as_raw_fd(), KVM_GET_REG_LIST, list.as_mut_ptr() as u64)?;
        let n = (list[0] as usize).min(n);
        Ok(list[1..1 + n].to_vec())
    }

    pub fn mp_state(&self) -> Result<u32, Error> {
        let mut state = 0u32;
        ioctl(self.fd.as_raw_fd(), KVM_GET_MP_STATE, &mut state as *mut u32 as u64)?;
        Ok(state)
    }

    pub fn set_mp_state(&mut self, state: u32) -> Result<(), Error> {
        ioctl(self.fd.as_raw_fd(), KVM_SET_MP_STATE, &state as *const u32 as u64).map(|_| ())
    }

    /// Finish what the last exit left (an MMIO load's value, ...): the
    /// state isn't consistent until KVM_RUN has seen it. With
    /// `immediate_exit` set, KVM does that and runs nothing.
    pub fn complete(&mut self) -> Result<(), Error> {
        self.immediate_exit().store(1, Ordering::SeqCst);
        match self.run()? {
            Exit::Interrupted => Ok(()),
            _ => Err(Error("KVM_RUN with immediate_exit ran the guest".into())),
        }
    }

    fn immediate_exit(&self) -> &AtomicU8 {
        // SAFETY: kvm_run's immediate_exit, a byte at 1, in a page mapped
        // for as long as the process lives.
        unsafe { &*(self.run.add(1) as *const AtomicU8) }
    }

    /// What makes this vCPU's thread leave KVM_RUN, for other threads.
    pub fn kick(&self) -> Kick {
        // SAFETY: the run page is never unmapped.
        unsafe { Kick::new(self.immediate_exit()) }
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
                EXIT_HYPERCALL => Exit::Hypercall { function: (self.run.add(32) as *const u64).read_volatile() },
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

/// Read attribute `attr` of `group` from device `fd` (the GIC): 32 or 64
/// bits, as the attribute is.
pub fn device_attr(fd: RawFd, group: u32, attr: u64) -> Result<u64, Error> {
    let mut value = 0u64;
    let a = DeviceAttr { flags: 0, group, attr, addr: &mut value as *mut u64 as u64 };
    ioctl(fd, KVM_GET_DEVICE_ATTR, &a as *const DeviceAttr as u64)?;
    Ok(value)
}

/// Set attribute `attr` of `group` on device `fd` (its low 32 bits, for a
/// 32-bit one: little-endian).
pub fn set_device_attr(fd: RawFd, group: u32, attr: u64, value: u64) -> Result<(), Error> {
    let a = DeviceAttr { flags: 0, group, attr, addr: &value as *const u64 as u64 };
    ioctl(fd, KVM_SET_DEVICE_ATTR, &a as *const DeviceAttr as u64).map(|_| ())
}

/// Give up everything but running the VM, in every thread: a seccomp
/// filter allows only the system calls the vCPU loop and the device
/// threads make on what's already open (no open, socket, exec, signals to
/// anyone, ...), and of ioctls only running the vCPU and driving an
/// interrupt line. Anything else fails with EPERM. If guest input ever
/// found a bug in this process, that's all it would have. A run that may
/// take a `snapshot` also reads its own vCPUs' and GIC's state, kicks its
/// own threads, and writes the snapshot file it holds. One `restoring` a
/// snapshot may also put its vCPUs' and GIC's state back, and add a
/// filter: confined again without `restoring` once that's done, it has
/// those no more.
pub fn confine(snapshot: bool, restoring: bool) -> Result<(), String> {
    // aarch64 system call numbers.
    const IOCTL: u32 = 29;
    const TGKILL: u32 = 131;
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
        // A new thread's own: glibc registers them as the thread starts
        // (which may be after the filter is on, for threads made just
        // before), and gives up if rseq is refused.
        99,  // set_robust_list
        293, // rseq
    ];
    const SNAPSHOT_ALLOWED: &[u32] = &[
        46, // ftruncate
        68, // pwrite64
    ];
    const SECCOMP: u32 = 277;
    let mut ioctls = vec![KVM_RUN, KVM_IRQ_LINE];
    let mut allowed = ALLOWED.to_vec();
    if snapshot {
        ioctls.extend([KVM_GET_ONE_REG, KVM_SET_ONE_REG, KVM_GET_REG_LIST, KVM_GET_MP_STATE, KVM_GET_DEVICE_ATTR]);
        allowed.extend(SNAPSHOT_ALLOWED);
    }
    if restoring {
        ioctls.extend([KVM_GET_REG_LIST, KVM_SET_ONE_REG, KVM_SET_MP_STATE, KVM_SET_DEVICE_ATTR]);
        allowed.push(SECCOMP);
    }
    ioctls.sort_unstable();
    ioctls.dedup();
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
        jeq(IOCTL, 0, ioctls.len() as u8 + 3),
        stmt(LD_W_ABS, 24),
    ];
    for (i, &req) in ioctls.iter().enumerate() {
        // Matched: past the rest and the deny, to the allow.
        prog.push(jeq(req as u32, (ioctls.len() - i) as u8, 0));
    }
    prog.push(stmt(RET_K, RET_ERRNO | libc::EPERM as u32));
    prog.push(stmt(RET_K, RET_ALLOW));
    // Not ioctl (the accumulator still holds the number). tgkill, for a
    // snapshot's kicks: only to our own threads (args[0], the process).
    if snapshot {
        // SAFETY: getpid has no arguments.
        let pid = unsafe { libc::getpid() } as u32;
        prog.extend([
            jeq(TGKILL, 0, 4),
            stmt(LD_W_ABS, 16),
            jeq(pid, 1, 0),
            stmt(RET_K, RET_ERRNO | libc::EPERM as u32),
            stmt(RET_K, RET_ALLOW),
        ]);
    }
    // Everything else, by number.
    for (i, &nr) in allowed.iter().enumerate() {
        // Matched: jump past the rest of the list and the deny to the allow.
        let rest = (allowed.len() - i - 1) as u8;
        prog.push(jeq(nr, rest + 1, 0));
    }
    prog.push(stmt(RET_K, RET_ERRNO | libc::EPERM as u32));
    prog.push(stmt(RET_K, RET_ALLOW));
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
    // A second filter (after a restore): no_new_privs is on already, and
    // prctl isn't allowed.
    static CONFINED: AtomicBool = AtomicBool::new(false);
    // SAFETY: prctl and seccomp with a filter that outlives the calls (the
    // kernel copies it). TSYNC applies it to the threads already running.
    unsafe {
        if !CONFINED.swap(true, Ordering::SeqCst) && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
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
