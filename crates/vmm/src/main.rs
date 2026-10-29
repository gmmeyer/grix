//! grix-vmm: the virtual machine monitor grix runs its kernel in, in place
//! of QEMU. It makes the machine the kernel expects (QEMU `virt`'s layout,
//! cut down) and nothing else:
//!
//! - RAM at `RAM_BASE`, with the kernel (an ELF, loaded at its physical
//!   addresses) and the boot image at `IMAGE_BASE`.
//! - One vCPU and a GICv3 (the hypervisor's own).
//! - A PL011 serial port, written to a Unix socket (early boot and panics).
//! - A virtio console in virtio-mmio slot 0: its port 1 is stdin and stdout.
//! - PSCI SYSTEM_OFF, which ends the process.
//!
//! The layout is `grix_abi::machine`'s. No disks, no network, no other
//! devices: what the guest can reach of the host is two pipes and a socket.
//! Once the machine is made, the process itself drops into a sandbox that
//! allows nothing else (`hvf::confine`, `kvm::confine`).
//!
//! On macOS it runs on Hypervisor.framework (15+, for its GIC), on Linux on
//! KVM.
//!
//! `grix-vmm --kernel FILE --image FILE --mem MIB [--cpus N] [--uart SOCKET] [--snapshot]`
//! boots the kernel; with `--snapshot`, fd 3 is where to save the machine
//! when the kernel asks (`snapshot.rs`). `grix-vmm --restore [--cpus N]
//! [--uart SOCKET]` runs the snapshot on fd 3 instead (of N vCPUs, as it
//! says).

#[cfg(supported)]
mod console;
#[cfg(all(supported, target_os = "macos"))]
mod hvf;
#[cfg(all(supported, target_os = "linux"))]
mod kick;
#[cfg(all(supported, target_os = "linux", target_arch = "aarch64"))]
mod kvm;
#[cfg(all(supported, target_arch = "x86_64"))]
mod kvm_x86;
#[cfg(supported)]
mod mem;
#[cfg(supported)]
mod pause;
#[cfg(supported)]
mod snapshot;
#[cfg(all(supported, target_os = "macos"))]
mod snapshot_hvf;
#[cfg(all(supported, target_os = "linux", target_arch = "aarch64"))]
mod snapshot_kvm;
#[cfg(all(supported, target_arch = "x86_64"))]
mod snapshot_kvm_x86;
#[cfg(all(supported, target_arch = "aarch64"))]
mod vm;
#[cfg(all(supported, target_arch = "x86_64"))]
mod vm_x86;

use std::path::PathBuf;
use std::process::ExitCode;

pub struct Args {
    pub kernel: PathBuf,
    pub image: PathBuf,
    pub mem_mb: u64,
    pub uart: Option<PathBuf>,
    /// Save the machine to fd 3 when the kernel asks.
    pub snapshot: bool,
    /// Run the snapshot on fd 3 (`kernel`, `image` and `mem_mb` unused).
    pub restore: bool,
    /// vCPUs (the kernel starts all but the first with PSCI CPU_ON).
    pub cpus: u32,
}

fn parse() -> Result<Args, String> {
    let mut kernel = None;
    let mut image = None;
    let mut mem_mb = None;
    let mut uart = None;
    let (mut snapshot, mut restore) = (false, false);
    let mut cpus = 1;
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{} needs a value", a.to_string_lossy()));
        match a.to_str() {
            Some("--kernel") => kernel = Some(PathBuf::from(value()?)),
            Some("--image") => image = Some(PathBuf::from(value()?)),
            Some("--mem") => {
                let v = value()?;
                mem_mb = Some(v.to_str().and_then(|s| s.parse().ok()).ok_or("--mem takes a number of MiB")?);
            }
            Some("--uart") => uart = Some(PathBuf::from(value()?)),
            Some("--cpus") => {
                let v = value()?;
                cpus = v
                    .to_str()
                    .and_then(|s| s.parse().ok())
                    .filter(|n| (1..=grix_abi::machine::MAX_CPUS).contains(n))
                    .ok_or(format!("--cpus takes 1 to {}", grix_abi::machine::MAX_CPUS))?;
            }
            Some("--snapshot") => snapshot = true,
            Some("--restore") => restore = true,
            _ => return Err(format!("unknown argument {}", a.to_string_lossy())),
        }
    }
    if restore {
        return Ok(Args {
            kernel: PathBuf::new(),
            image: PathBuf::new(),
            mem_mb: 0,
            uart,
            snapshot: false,
            restore,
            cpus,
        });
    }
    Ok(Args {
        kernel: kernel.ok_or("--kernel is required")?,
        image: image.ok_or("--image is required")?,
        mem_mb: mem_mb.ok_or("--mem is required")?,
        uart,
        snapshot,
        restore,
        cpus,
    })
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "grix-vmm: {e}\nusage: grix-vmm --kernel FILE --image FILE --mem MIB [--cpus N] [--uart SOCKET] [--snapshot]\n       \
                 grix-vmm --restore [--cpus N] [--uart SOCKET]   (the snapshot on fd 3)"
            );
            return ExitCode::from(2);
        }
    };
    #[cfg(all(supported, target_arch = "aarch64"))]
    let result = vm::run(&args);
    #[cfg(all(supported, target_arch = "x86_64"))]
    let result = vm_x86::run(&args);
    #[cfg(not(supported))]
    let result: Result<(), String> = {
        let _ = args;
        Err("grix-vmm runs on arm64 macOS (Hypervisor.framework) and arm64 and x86_64 Linux (KVM)".into())
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("grix-vmm: {e}");
            ExitCode::FAILURE
        }
    }
}
