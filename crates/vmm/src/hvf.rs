//! Hypervisor.framework (macOS on Apple silicon): the VM, its memory, the
//! in-kernel GICv3 (macOS 15+) and one vCPU.

use std::ffi::c_void;
use std::fmt;

type HvReturn = i32;
pub type Vcpu = u64;

#[repr(C)]
pub struct Exit {
    pub reason: u32,
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

pub const EXIT_CANCELED: u32 = 0;
pub const EXIT_EXCEPTION: u32 = 1;
pub const EXIT_VTIMER: u32 = 2;

const MEMORY_READ: u64 = 1;
const MEMORY_WRITE: u64 = 2;
const MEMORY_EXEC: u64 = 4;

pub const REG_PC: u32 = 31;
pub const REG_CPSR: u32 = 34;

pub const SYS_MPIDR_EL1: u16 = 0xc005;
pub const SYS_CNTV_CTL_EL0: u16 = 0xdf19;
pub const SYS_CNTV_CVAL_EL0: u16 = 0xdf1a;

// Linked weakly (build.rs): on macOS before 15 the GIC functions are null,
// and `check_version` stops us before any is called.
unsafe extern "C" {
    fn hv_vm_create(config: *mut c_void) -> HvReturn;
    fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> HvReturn;
    fn hv_vcpu_create(vcpu: *mut Vcpu, exit: *mut *const Exit, config: *mut c_void) -> HvReturn;
    fn hv_vcpu_run(vcpu: Vcpu) -> HvReturn;
    fn hv_vcpu_get_reg(vcpu: Vcpu, reg: u32, value: *mut u64) -> HvReturn;
    fn hv_vcpu_set_reg(vcpu: Vcpu, reg: u32, value: u64) -> HvReturn;
    fn hv_vcpu_get_sys_reg(vcpu: Vcpu, reg: u16, value: *mut u64) -> HvReturn;
    fn hv_vcpu_set_sys_reg(vcpu: Vcpu, reg: u16, value: u64) -> HvReturn;
    fn hv_vcpu_get_vtimer_offset(vcpu: Vcpu, offset: *mut u64) -> HvReturn;
    fn hv_vcpu_set_vtimer_offset(vcpu: Vcpu, offset: u64) -> HvReturn;
    fn hv_vcpu_get_simd_fp_reg(vcpu: Vcpu, reg: u32, value: *mut [u8; 16]) -> HvReturn;
    // (vcpu, reg, value) with the value, an hv_simd_fp_uchar16_t, by value
    // in q0: stable Rust can't pass vectors through FFI, so `set_simd_reg`
    // calls it from assembly.
    fn hv_vcpu_set_simd_fp_reg();
    fn hv_gic_get_icc_reg(vcpu: Vcpu, reg: u16, value: *mut u64) -> HvReturn;
    fn hv_gic_set_icc_reg(vcpu: Vcpu, reg: u16, value: u64) -> HvReturn;
    fn hv_gic_state_create() -> *mut c_void;
    fn hv_gic_state_get_size(state: *mut c_void, size: *mut usize) -> HvReturn;
    fn hv_gic_state_get_data(state: *mut c_void, data: *mut c_void) -> HvReturn;
    fn hv_gic_set_state(data: *const c_void, size: usize) -> HvReturn;
    fn hv_vcpu_set_vtimer_mask(vcpu: Vcpu, masked: bool) -> HvReturn;
    fn hv_vcpus_exit(vcpus: *const Vcpu, count: u32) -> HvReturn;
    fn hv_gic_config_create() -> *mut c_void;
    fn hv_gic_config_set_distributor_base(config: *mut c_void, base: u64) -> HvReturn;
    fn hv_gic_config_set_redistributor_base(config: *mut c_void, base: u64) -> HvReturn;
    fn hv_gic_create(config: *mut c_void) -> HvReturn;
    fn hv_gic_set_spi(intid: u32, level: bool) -> HvReturn;
    fn hv_gic_get_redistributor_region_size(size: *mut usize) -> HvReturn;
    fn os_release(object: *mut c_void);
    fn hv_vm_config_create() -> *mut c_void;
    fn hv_vm_config_get_default_ipa_size(bits: *mut u32) -> HvReturn;
    fn hv_vm_config_get_max_ipa_size(bits: *mut u32) -> HvReturn;
    fn hv_vm_config_set_ipa_size(config: *mut c_void, bits: u32) -> HvReturn;
}

#[repr(C)]
struct TimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn mach_absolute_time() -> u64;
    fn mach_timebase_info(info: *mut TimebaseInfo) -> i32;
    fn sandbox_init(profile: *const libc::c_char, flags: u64, errorbuf: *mut *mut libc::c_char) -> i32;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Give up everything the process could still do but run the VM: no
/// files, no network, no new processes, no services. What's already open
/// (stdin, stdout, the serial socket) keeps working, and so does the
/// hypervisor. If guest input ever found a bug in this process, that's
/// all it would have.
pub fn confine() -> Result<(), String> {
    let mut err = std::ptr::null_mut();
    // SAFETY: a NUL-terminated profile and an out-pointer to a local.
    let r = unsafe { sandbox_init(c"(version 1) (deny default)".as_ptr(), 0, &mut err) };
    if r == 0 {
        return Ok(());
    }
    let msg = if err.is_null() {
        String::new()
    } else {
        // SAFETY: the library's NUL-terminated message, freed after.
        let m = unsafe { std::ffi::CStr::from_ptr(err) }.to_string_lossy().into_owned();
        unsafe { sandbox_free_error(err) };
        m
    };
    Err(format!("entering the sandbox: {msg}"))
}

#[derive(Debug)]
pub struct Error {
    what: &'static str,
    code: HvReturn,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let why = match self.code as u32 {
            0xfae9_4001 => "error",
            0xfae9_4002 => "busy",
            0xfae9_4003 => "bad argument",
            0xfae9_4005 => "no resources",
            0xfae9_4006 => "no device",
            0xfae9_4007 => {
                "denied (is grix-vmm signed with the com.apple.security.hypervisor entitlement? `make vmm` does that)"
            }
            0xfae9_400f => "unsupported",
            _ => "failed",
        };
        write!(f, "{}: {why} ({:#x})", self.what, self.code as u32)
    }
}

impl std::error::Error for Error {}

fn check(what: &'static str, code: HvReturn) -> Result<(), Error> {
    if code == 0 { Ok(()) } else { Err(Error { what, code }) }
}

/// Hypervisor.framework has a GIC from macOS 15.
pub fn check_version() -> Result<(), String> {
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    // SAFETY: a NUL-terminated name, and a buffer with its length.
    let r = unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    let version = String::from_utf8_lossy(&buf[..len.min(buf.len())]).trim_end_matches('\0').to_string();
    let major: u32 = version.split('.').next().and_then(|v| v.parse().ok()).unwrap_or(0);
    if r != 0 || major < 15 {
        return Err(format!("needs macOS 15 or later (this is {version}); use QEMU with GRIX_VMM=qemu"));
    }
    Ok(())
}

/// How much guest-physical room the GIC's redistributors take: enough for
/// as many vCPUs as the machine could have.
pub fn redistributor_region_size() -> Result<usize, Error> {
    let mut size = 0;
    // SAFETY: an out-pointer to a local.
    check("hv_gic_get_redistributor_region_size", unsafe { hv_gic_get_redistributor_region_size(&mut size) })?;
    Ok(size)
}

/// The guest-physical address size (IPA bits) a VM reaching `top` needs,
/// if that's more than the framework's default (36 bits, 64 GiB, where
/// arm64's RAM, from 1 GiB, stops short of `MAX_RAM`); an error that says
/// so if it's more than this Mac's hypervisor can map.
pub fn ipa_bits(top: u64) -> Result<Option<u32>, String> {
    let need = 64 - top.saturating_sub(1).leading_zeros();
    let (mut default, mut max) = (0, 0);
    // SAFETY: out-pointers to locals.
    unsafe {
        check("hv_vm_config_get_default_ipa_size", hv_vm_config_get_default_ipa_size(&mut default))
            .map_err(|e| e.to_string())?;
        check("hv_vm_config_get_max_ipa_size", hv_vm_config_get_max_ipa_size(&mut max)).map_err(|e| e.to_string())?;
    }
    if need <= default {
        return Ok(None);
    }
    if need > max {
        let ram_gib = ((1u64 << max) - grix_abi::image::RAM_BASE) >> 30;
        return Err(format!(
            "this Mac's hypervisor maps at most {} GiB of guest physical memory ({max}-bit addresses), and the \
             machine needs {} GiB: give it at most {ram_gib} GiB of RAM (memory_mb = {})",
            1u64 << (max - 30),
            top.div_ceil(1 << 30),
            ram_gib << 10
        ));
    }
    Ok(Some(need))
}

/// Create the VM (one per process), with `ipa_bits` of guest physical
/// addresses (`ipa_bits`; None: the default), and its GICv3 at the given
/// bases.
pub fn create_vm(gicd: u64, gicr: u64, ipa_bits: Option<u32>) -> Result<(), Error> {
    // SAFETY: plain calls; the config objects are released after use.
    unsafe {
        match ipa_bits {
            None => check("hv_vm_create", hv_vm_create(std::ptr::null_mut()))?,
            Some(bits) => {
                let config = hv_vm_config_create();
                if config.is_null() {
                    return Err(Error { what: "hv_vm_config_create", code: -1 });
                }
                let r = check("hv_vm_config_set_ipa_size", hv_vm_config_set_ipa_size(config, bits))
                    .and_then(|_| check("hv_vm_create", hv_vm_create(config)));
                os_release(config);
                r?
            }
        }
        let config = hv_gic_config_create();
        if config.is_null() {
            return Err(Error { what: "hv_gic_config_create", code: -1 });
        }
        let r = check("hv_gic_config_set_distributor_base", hv_gic_config_set_distributor_base(config, gicd))
            .and_then(|_| {
                check("hv_gic_config_set_redistributor_base", hv_gic_config_set_redistributor_base(config, gicr))
            })
            .and_then(|_| check("hv_gic_create", hv_gic_create(config)));
        os_release(config);
        r
    }
}

/// Map `size` bytes at host address `host` as guest memory at `ipa`.
///
/// # Safety
/// `host` must stay mapped (and not be moved) for as long as the VM runs.
pub unsafe fn map(host: *mut u8, ipa: u64, size: usize) -> Result<(), Error> {
    // SAFETY: the caller keeps the memory alive.
    check("hv_vm_map", unsafe { hv_vm_map(host.cast(), ipa, size, MEMORY_READ | MEMORY_WRITE | MEMORY_EXEC) })
}

/// Drive a shared peripheral interrupt line (level-triggered).
pub fn set_spi(intid: u32, level: bool) {
    // SAFETY: a plain call; the GIC exists before any device runs.
    let r = unsafe { hv_gic_set_spi(intid, level) };
    if r != 0 {
        eprintln!("grix-vmm: hv_gic_set_spi({intid}, {level}) failed: {r:#x}");
    }
}

/// The GIC's state (but its CPU interface's), with the vCPU stopped.
pub fn gic_state() -> Result<Vec<u8>, Error> {
    // SAFETY: the state object is released after use; the buffer is the
    // size it asks for.
    unsafe {
        let state = hv_gic_state_create();
        if state.is_null() {
            return Err(Error { what: "hv_gic_state_create", code: -1 });
        }
        let mut size = 0;
        let r = check("hv_gic_state_get_size", hv_gic_state_get_size(state, &mut size)).and_then(|_| {
            let mut data = vec![0u8; size];
            check("hv_gic_state_get_data", hv_gic_state_get_data(state, data.as_mut_ptr().cast())).map(|_| data)
        });
        os_release(state);
        r
    }
}

/// Put back what `gic_state` saved (after the vCPU exists, before it runs).
pub fn set_gic_state(data: &[u8]) -> Result<(), Error> {
    // SAFETY: a buffer and its length.
    check("hv_gic_set_state", unsafe { hv_gic_set_state(data.as_ptr().cast(), data.len()) })
}

/// Make `vcpu` leave (or not enter) the guest. Any thread may call it.
pub fn kick(vcpu: Vcpu) {
    // SAFETY: a plain call.
    unsafe { hv_vcpus_exit(&vcpu, 1) };
}

/// The vCPU, owned by the thread that made it.
pub struct Cpu {
    pub id: Vcpu,
    exit: *const Exit,
}

impl Cpu {
    pub fn create() -> Result<Cpu, Error> {
        let mut id = 0;
        let mut exit = std::ptr::null();
        // SAFETY: out-pointers to locals.
        check("hv_vcpu_create", unsafe { hv_vcpu_create(&mut id, &mut exit, std::ptr::null_mut()) })?;
        Ok(Cpu { id, exit })
    }

    pub fn run(&mut self) -> Result<&Exit, Error> {
        // SAFETY: our vCPU, on its thread; the exit structure is the
        // framework's, valid for the vCPU's life.
        unsafe {
            check("hv_vcpu_run", hv_vcpu_run(self.id))?;
            Ok(&*self.exit)
        }
    }

    pub fn reg(&self, reg: u32) -> u64 {
        let mut v = 0;
        // SAFETY: an out-pointer to a local.
        unsafe { hv_vcpu_get_reg(self.id, reg, &mut v) };
        v
    }

    pub fn set_reg(&mut self, reg: u32, v: u64) {
        // SAFETY: a plain call.
        unsafe { hv_vcpu_set_reg(self.id, reg, v) };
    }

    pub fn sys_reg(&self, reg: u16) -> u64 {
        let mut v = 0;
        // SAFETY: an out-pointer to a local.
        unsafe { hv_vcpu_get_sys_reg(self.id, reg, &mut v) };
        v
    }

    pub fn set_sys_reg(&mut self, reg: u16, v: u64) -> Result<(), Error> {
        // SAFETY: a plain call.
        check("hv_vcpu_set_sys_reg", unsafe { hv_vcpu_set_sys_reg(self.id, reg, v) })
    }

    /// Host counter value minus the guest's (CNTVCT = mach_absolute_time - offset).
    pub fn vtimer_offset(&self) -> u64 {
        let mut v = 0;
        // SAFETY: an out-pointer to a local.
        unsafe { hv_vcpu_get_vtimer_offset(self.id, &mut v) };
        v
    }

    pub fn set_vtimer_offset(&mut self, offset: u64) -> Result<(), Error> {
        // SAFETY: a plain call.
        check("hv_vcpu_set_vtimer_offset", unsafe { hv_vcpu_set_vtimer_offset(self.id, offset) })
    }

    pub fn simd_reg(&self, q: u32) -> Result<[u8; 16], Error> {
        let mut v = [0u8; 16];
        // SAFETY: an out-pointer to a local of the register's size.
        check("hv_vcpu_get_simd_fp_reg", unsafe { hv_vcpu_get_simd_fp_reg(self.id, q, &mut v) })?;
        Ok(v)
    }

    pub fn set_simd_reg(&mut self, q: u32, v: [u8; 16]) -> Result<(), Error> {
        let r: u64;
        // SAFETY: a call by the C ABI: vcpu in x0, reg in w1, the vector in
        // q0, the result in w0; clobber_abi covers what the callee may
        // change.
        unsafe {
            std::arch::asm!(
                "ldr q0, [{v}]",
                "blr {f}",
                v = in(reg) v.as_ptr(),
                f = in(reg) hv_vcpu_set_simd_fp_reg as *const (),
                inlateout("x0") self.id => r,
                in("x1") q as u64,
                clobber_abi("C"),
            );
        }
        check("hv_vcpu_set_simd_fp_reg", r as u32 as i32)
    }

    pub fn icc_reg(&self, reg: u16) -> Result<u64, Error> {
        let mut v = 0;
        // SAFETY: an out-pointer to a local.
        check("hv_gic_get_icc_reg", unsafe { hv_gic_get_icc_reg(self.id, reg, &mut v) })?;
        Ok(v)
    }

    pub fn set_icc_reg(&mut self, reg: u16, v: u64) -> Result<(), Error> {
        // SAFETY: a plain call.
        check("hv_gic_set_icc_reg", unsafe { hv_gic_set_icc_reg(self.id, reg, v) })
    }

    pub fn set_vtimer_mask(&mut self, masked: bool) {
        // SAFETY: a plain call.
        unsafe { hv_vcpu_set_vtimer_mask(self.id, masked) };
    }
}

/// The host's counter, which the guest's virtual counter runs on.
pub fn now() -> u64 {
    // SAFETY: a plain call.
    unsafe { mach_absolute_time() }
}

fn timebase() -> (u32, u32) {
    static TIMEBASE: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
    *TIMEBASE.get_or_init(|| {
        let mut info = TimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: an out-pointer to a local.
        unsafe { mach_timebase_info(&mut info) };
        (info.numer.max(1), info.denom.max(1))
    })
}

/// Counter ticks to nanoseconds.
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let (numer, denom) = timebase();
    (ticks as u128 * numer as u128 / denom as u128) as u64
}
