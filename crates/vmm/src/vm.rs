//! The machine: its memory, its devices, and the vCPU loop for each
//! hypervisor (Hypervisor.framework on macOS, KVM on Linux).

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use grix_abi::image::{self, HEADER_LEN, IMAGE_BASE, MAX_RAM, RAM_BASE};
use grix_abi::machine::{GICD, GICR_GRIX_VMM, UART, UART_SIZE, VIRTIO, VIRTIO_IRQ, VIRTIO_STRIDE};

use crate::Args;
use crate::console::{Console, Line};
use crate::mem::GuestMemory;

/// The console sits in virtio-mmio slot 0.
const CONSOLE_IRQ: u32 = VIRTIO_IRQ;

/// The PL011: transmit only, to the socket. Each byte costs an exit, so the
/// kernel uses it only before the console is up and for panics.
struct Uart {
    out: Option<UnixStream>,
}

impl Uart {
    fn read(&self, off: u64) -> u32 {
        match off {
            0x018 => 0x90, // FR: transmit FIFO empty, receive FIFO empty
            // PrimeCell identification.
            0xfe0 => 0x11,
            0xfe4 => 0x10,
            0xfe8 => 0x14,
            0xff0 => 0x0d,
            0xff4 => 0xf0,
            0xff8 => 0x05,
            0xffc => 0xb1,
            _ => 0,
        }
    }

    fn write(&mut self, off: u64, v: u32) {
        if off == 0
            && let Some(s) = &mut self.out
            && let Err(e) = s.write_all(&[v as u8])
        {
            eprintln!("grix-vmm: the serial port's socket: {e}");
            self.out = None;
        }
    }
}

/// RAM with the kernel and boot image in it, and the devices (which every
/// vCPU's thread uses).
struct Machine {
    mem: Arc<GuestMemory>,
    entry: u64,
    uart: Mutex<Uart>,
}

fn connect_uart(args: &Args) -> Result<Mutex<Uart>, String> {
    let out = match &args.uart {
        Some(p) => Some(UnixStream::connect(p).map_err(|e| format!("connecting to {}: {e}", p.display()))?),
        None => None,
    };
    Ok(Mutex::new(Uart { out }))
}

impl Machine {
    /// A machine with RAM we already have (a snapshot's).
    fn with_memory(args: &Args, mem: GuestMemory) -> Result<Machine, String> {
        Ok(Machine { mem: Arc::new(mem), entry: 0, uart: connect_uart(args)? })
    }

    fn new(args: &Args) -> Result<Machine, String> {
        let ram = args.mem_mb << 20;
        if ram == 0 || ram > MAX_RAM {
            return Err(format!("--mem {} is outside 1..={} MiB", args.mem_mb, MAX_RAM >> 20));
        }
        let mem = Arc::new(GuestMemory::new(RAM_BASE, ram as usize).map_err(|e| format!("allocating RAM: {e}"))?);
        let kernel = std::fs::read(&args.kernel).map_err(|e| format!("reading {}: {e}", args.kernel.display()))?;
        let entry = load_kernel(&mem, &kernel)?;
        let img = std::fs::read(&args.image).map_err(|e| format!("reading {}: {e}", args.image.display()))?;
        // The host made it for this machine: the GIC is where we put it.
        let header = image::parse_header(img.get(..HEADER_LEN).unwrap_or(&[]))
            .map_err(|_| "the boot image has no valid header".to_string())?;
        if header.gicr != GICR_GRIX_VMM {
            return Err(format!("the boot image is for another machine (GIC redistributors at {:#x})", header.gicr));
        }
        if !mem.write(IMAGE_BASE, &img) {
            return Err(format!("the boot image ({} MiB) doesn't fit in RAM", img.len() >> 20));
        }
        Ok(Machine { mem, entry, uart: connect_uart(args)? })
    }

    /// The time of day the kernel starts from is now, not when the host
    /// made the image (which may be seconds earlier on a busy host): just
    /// before the first vCPU runs, for a fresh boot.
    fn stamp_boot_time(&self) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
        self.mem.write(IMAGE_BASE + image::BOOT_TIME_OFFSET as u64, &now.to_le_bytes());
    }

    fn mmio_read(&self, console: &Console, addr: u64, size: u32) -> u64 {
        let v = match addr {
            a if (UART..UART + UART_SIZE).contains(&a) => {
                self.uart.lock().unwrap_or_else(|e| e.into_inner()).read(a - UART)
            }
            a if (VIRTIO..VIRTIO + VIRTIO_STRIDE).contains(&a) => {
                // Registers are 32-bit; config space may be read in parts.
                let off = a - VIRTIO;
                console.read(off & !3) >> (8 * (off & 3))
            }
            // Empty virtio slots, and anything else: zero.
            _ => 0,
        };
        let v = v as u64;
        if size >= 4 { v } else { v & ((1u64 << (8 * size)) - 1) }
    }

    fn mmio_write(&self, console: &Console, addr: u64, v: u64) {
        match addr {
            a if (UART..UART + UART_SIZE).contains(&a) => {
                self.uart.lock().unwrap_or_else(|e| e.into_inner()).write(a - UART, v as u32)
            }
            a if (VIRTIO..VIRTIO + VIRTIO_STRIDE).contains(&a) => console.write(a - VIRTIO, v as u32),
            // Empty virtio slots, and anything else: ignored.
            _ => {}
        }
    }
}

/// Load the kernel ELF's segments at their physical addresses. Returns the
/// entry point.
fn load_kernel(mem: &GuestMemory, elf: &[u8]) -> Result<u64, String> {
    let u16_at = |o: usize| elf.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| elf.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u64_at = |o: usize| elf.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    // 64-bit, little-endian, AArch64.
    if elf.get(..6) != Some(b"\x7fELF\x02\x01") || u16_at(0x12) != Some(183) {
        return Err("the kernel isn't an arm64 ELF".into());
    }
    let bad = || "the kernel's ELF headers are malformed".to_string();
    let entry = u64_at(0x18).ok_or_else(bad)?;
    let phoff = u64_at(0x20).ok_or_else(bad)? as usize;
    let phentsize = u16_at(0x36).ok_or_else(bad)? as usize;
    let phnum = u16_at(0x38).ok_or_else(bad)? as usize;
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize).ok_or_else(bad)?).ok_or_else(bad)?;
        if u32_at(ph) != Some(1) {
            continue; // not PT_LOAD
        }
        let offset = u64_at(ph + 0x08).ok_or_else(bad)? as usize;
        let paddr = u64_at(ph + 0x18).ok_or_else(bad)?;
        let filesz = u64_at(ph + 0x20).ok_or_else(bad)? as usize;
        let memsz = u64_at(ph + 0x28).ok_or_else(bad)?;
        let data = elf.get(offset..offset.checked_add(filesz).ok_or_else(bad)?).ok_or_else(bad)?;
        // The rest of memsz is zero already (fresh memory).
        let end = paddr.checked_add(memsz).ok_or_else(bad)?;
        if paddr < mem.base() || end > mem.base() + mem.size() as u64 || !mem.write(paddr, data) {
            return Err(format!("the kernel segment at {paddr:#x} doesn't fit in RAM"));
        }
    }
    Ok(entry)
}

#[cfg(target_os = "macos")]
pub use hvf_loop::run;

#[cfg(target_os = "macos")]
mod hvf_loop {
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use grix_abi::machine::GICR_GRIX_VMM_END;

    use super::*;
    use crate::hvf::{self, Cpu};
    use crate::pause::{Pauses, Power};
    use crate::{snapshot, snapshot_hvf};

    const PSCI_VERSION: u64 = 0x8400_0000;
    const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
    const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
    const PSCI_NOT_SUPPORTED: u64 = -1i64 as u64;

    /// ESR exception classes.
    const EC_WFX: u64 = 0x01;
    const EC_HVC: u64 = 0x16;
    const EC_SMC: u64 = 0x17;
    const EC_SYSREG: u64 = 0x18;
    const EC_DATA_ABORT: u64 = 0x24;

    /// Wakes the vCPU from a WFI when a device has something for it.
    struct Wake {
        generation: Mutex<u64>,
        changed: Condvar,
        vcpu: Mutex<Option<hvf::Vcpu>>,
    }

    impl Wake {
        fn new() -> Wake {
            Wake { generation: Mutex::new(0), changed: Condvar::new(), vcpu: Mutex::new(None) }
        }

        fn generation(&self) -> u64 {
            *self.generation.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// A device raised an interrupt: wake a waiting vCPU, and make a
        /// running one look (the next run returns at once if it isn't in
        /// the guest).
        fn notify(&self) {
            *self.generation.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            self.changed.notify_all();
            if let Some(v) = *self.vcpu.lock().unwrap_or_else(|e| e.into_inner()) {
                hvf::kick(v);
            }
        }

        /// Wait until something changes after `seen`, or host counter time
        /// `deadline`.
        fn wait(&self, seen: u64, deadline: Option<u64>) {
            let mut g = self.generation.lock().unwrap_or_else(|e| e.into_inner());
            while *g == seen {
                let wait = match deadline {
                    Some(d) => {
                        let now = hvf::now();
                        if now >= d {
                            return;
                        }
                        Duration::from_nanos(hvf::ticks_to_ns(d - now))
                    }
                    None => Duration::from_secs(1),
                };
                g = self.changed.wait_timeout(g, wait).unwrap_or_else(|e| e.into_inner()).0;
            }
        }
    }

    const PSCI_CPU_ON: [u64; 2] = [0x8400_0003, 0xc400_0003];
    const PSCI_INVALID_PARAMETERS: u64 = -2i64 as u64;
    const PSCI_ALREADY_ON: u64 = -4i64 as u64;

    /// What every vCPU's thread shares.
    struct Shared {
        m: Machine,
        console: Arc<Console>,
        wakes: Vec<Arc<Wake>>,
        pauses: Pauses,
        snapshot: bool,
        /// A restored run's state, which each vCPU's thread puts back.
        restored: Option<snapshot::State>,
    }

    pub fn run(args: &Args) -> Result<(), String> {
        hvf::check_version()?;
        let saved = if args.restore { Some(snapshot::open()?) } else { None };
        let (m, restored) = match saved {
            Some(s) => {
                let (mem, rest) = s.split();
                (Machine::with_memory(args, mem)?, Some(rest))
            }
            None => (Machine::new(args)?, None),
        };
        if let Some(s) = &restored
            && s.cpus() != args.cpus as usize
        {
            return Err(format!("the snapshot is of {} vCPUs, not {}", s.cpus(), args.cpus));
        }
        // The framework reserves redistributor room for every vCPU the
        // machine could have; it must stay clear of the devices and RAM.
        let room = hvf::redistributor_region_size().map_err(|e| e.to_string())?;
        if GICR_GRIX_VMM + room as u64 > GICR_GRIX_VMM_END {
            return Err(format!(
                "the hypervisor's GIC needs {room:#x} bytes of redistributors, more than this layout has"
            ));
        }
        hvf::create_vm(GICD, GICR_GRIX_VMM).map_err(|e| e.to_string())?;
        // SAFETY: `m.mem` is never unmapped, and lives until the process ends.
        unsafe { hvf::map(m.mem.host(), RAM_BASE, m.mem.size()) }.map_err(|e| e.to_string())?;
        let cpus = args.cpus as usize;
        let wakes: Vec<Arc<Wake>> = (0..cpus).map(|_| Arc::new(Wake::new())).collect();
        let mut cpu = Cpu::create().map_err(|e| e.to_string())?;
        // Affinity 0.0.0.n for vCPU n: the kernel routes interrupts to 0.
        cpu.set_sys_reg(hvf::SYS_MPIDR_EL1, 1 << 31).map_err(|e| e.to_string())?;
        cpu.set_reg(hvf::REG_PC, m.entry);
        cpu.set_reg(hvf::REG_CPSR, 0x3c5); // EL1h, interrupts masked
        if let Some(s) = &restored {
            cpu.set_vtimer_offset(snapshot_hvf::vtimer_offset(s)).map_err(|e| e.to_string())?;
        }
        *wakes[0].vcpu.lock().unwrap() = Some(cpu.id);
        // Every vCPU exists before any runs (the GIC's topology is fixed
        // then), each made on the thread that runs it, all with one
        // counter.
        let offset = cpu.vtimer_offset();
        let mut machine = Vec::new();
        // One after another, so the framework numbers them in order.
        for n in 1..cpus {
            let (made_tx, made_rx) = std::sync::mpsc::channel();
            let (shared_tx, shared_rx) = std::sync::mpsc::channel::<Arc<Shared>>();
            std::thread::spawn(move || {
                let made = make_secondary(n, offset);
                let _ = made_tx.send(made.as_ref().map(|_| ()).map_err(Clone::clone));
                // Then the machine, once it's all made (if it is).
                let Ok(cpu) = made else { return };
                let Ok(shared) = shared_rx.recv() else { return };
                let result = secondary(n, cpu, &shared);
                // A vCPU's end is the machine's.
                if let Err(e) = &result {
                    eprintln!("grix-vmm: vCPU {n}: {e}");
                }
                std::process::exit(if result.is_ok() { 0 } else { 1 });
            });
            made_rx.recv().map_err(|_| format!("vCPU {n} didn't start"))??;
            machine.push(shared_tx);
        }
        // A restored machine: the GIC once every vCPU exists, and before
        // the console can raise its interrupt (input may be there at once);
        // then each vCPU that was on, on its own thread.
        if let Some(s) = &restored {
            snapshot_hvf::restore_gic(s)?;
            snapshot_hvf::restore_cpu(s, 0, &mut cpu)?;
        }
        let w = wakes[0].clone();
        let line: Line = Box::new(move |level| {
            hvf::set_spi(CONSOLE_IRQ, level);
            if level {
                w.notify();
            }
        });
        let console = match &restored {
            Some(s) => Console::restore(m.mem.clone(), line, s.console())?,
            None => Console::start(m.mem.clone(), line),
        };
        let power = (0..cpus)
            .map(|n| match &restored {
                _ if n == 0 => Power::On,
                Some(s) if s.started(n) => Power::Restore,
                _ => Power::Off,
            })
            .collect();
        let shared =
            Arc::new(Shared { m, console, wakes, pauses: Pauses::new(power), snapshot: args.snapshot, restored });
        // Confined before any guest code runs: a restored machine's other
        // vCPUs run as soon as they have it.
        hvf::confine()?;
        shared.console.go();
        for tx in machine {
            let _ = tx.send(shared.clone());
        }
        if shared.restored.is_none() {
            shared.m.stamp_boot_time();
        }
        vcpu_loop(0, cpu, &shared)
    }

    /// vCPU `n`, made on the thread that runs it.
    fn make_secondary(n: usize, offset: u64) -> Result<Cpu, String> {
        let mut cpu = Cpu::create().map_err(|e| e.to_string())?;
        cpu.set_sys_reg(hvf::SYS_MPIDR_EL1, 1 << 31 | n as u64).map_err(|e| e.to_string())?;
        cpu.set_vtimer_offset(offset).map_err(|e| e.to_string())?;
        Ok(cpu)
    }

    /// Run vCPU `n` once CPU_ON says where (or it's restored).
    fn secondary(n: usize, mut cpu: Cpu, shared: &Shared) -> Result<(), String> {
        match shared.pauses.wait_on(n) {
            Power::Start(entry, context) => {
                cpu.set_reg(hvf::REG_PC, entry);
                cpu.set_reg(0, context);
                cpu.set_reg(hvf::REG_CPSR, 0x3c5);
            }
            _ => snapshot_hvf::restore_cpu(shared.restored.as_ref().ok_or("no snapshot to restore")?, n, &mut cpu)?,
        }
        *shared.wakes[n].vcpu.lock().unwrap_or_else(|e| e.into_inner()) = Some(cpu.id);
        vcpu_loop(n, cpu, shared)
    }

    /// PSCI CPU_ON: start vCPU `target` at `entry` with x0 = `context`.
    fn cpu_on(shared: &Shared, target: u64, entry: u64, context: u64) -> u64 {
        match shared.pauses.turn_on(target as usize, entry, context) {
            None => PSCI_INVALID_PARAMETERS,
            Some(true) => 0,
            Some(false) => PSCI_ALREADY_ON,
        }
    }

    /// `SNAPSHOT_CALL` from vCPU `n`: stop every other vCPU that's on, then
    /// save the machine. True once it's saved (this run ends there); false
    /// to put it off (input is on its way), every vCPU going on.
    fn take_snapshot(n: usize, cpu: &Cpu, shared: &Shared) -> Result<bool, String> {
        let kick = |m: usize| shared.wakes[m].notify();
        shared.pauses.take(n, snapshot_hvf::cpu_state(cpu)?, kick, |saved| {
            let counter = hvf::now().wrapping_sub(cpu.vtimer_offset());
            shared.console.save_with(|console| {
                let gic = snapshot_hvf::gic_state()?;
                snapshot::save(n, saved, &gic, counter, &shared.m.mem, console)
            })
        })
    }

    /// Run vCPU `n` until the machine powers off.
    fn vcpu_loop(n: usize, mut cpu: Cpu, shared: &Shared) -> Result<(), String> {
        let (m, console, wake) = (&shared.m, &*shared.console, &shared.wakes[n]);
        let mut warned_sysreg = false;
        loop {
            shared.pauses.point(n, || snapshot_hvf::cpu_state(&cpu))?;
            let seen = wake.generation();
            let exit = cpu.run().map_err(|e| e.to_string())?;
            let (reason, syndrome, ipa) = (exit.reason, exit.syndrome, exit.physical_address);
            match reason {
                hvf::EXIT_CANCELED => continue,
                hvf::EXIT_VTIMER => {
                    // The in-kernel GIC delivers the timer itself; this only
                    // tells us it fired. Let it fire again.
                    cpu.set_vtimer_mask(false);
                    continue;
                }
                hvf::EXIT_EXCEPTION => {}
                r => return Err(format!("unexpected exit reason {r}")),
            }
            let ec = (syndrome >> 26) & 0x3f;
            let pc = cpu.reg(hvf::REG_PC);
            match ec {
                EC_DATA_ABORT => {
                    let iss = syndrome & 0x1ff_ffff;
                    if iss & (1 << 24) == 0 {
                        return Err(format!("unemulatable access to {ipa:#x} at pc {pc:#x} (esr {syndrome:#x})"));
                    }
                    let size = 1u32 << ((iss >> 22) & 3);
                    let reg = ((iss >> 16) & 0x1f) as u32;
                    if iss & (1 << 6) != 0 {
                        let v = if reg == 31 { 0 } else { cpu.reg(reg) };
                        m.mmio_write(console, ipa, v);
                    } else {
                        let v = m.mmio_read(console, ipa, size);
                        if reg != 31 {
                            cpu.set_reg(reg, v);
                        }
                    }
                    cpu.set_reg(hvf::REG_PC, pc + 4);
                }
                EC_WFX => {
                    // WFI: sleep until a device interrupts, another vCPU
                    // kicks this one, or the timer fires. (WFE: an event
                    // from another vCPU's SEV; it's only a hint.)
                    if syndrome & 1 == 0 {
                        let ctl = cpu.sys_reg(hvf::SYS_CNTV_CTL_EL0);
                        let deadline = (ctl & 3 == 1)
                            .then(|| cpu.sys_reg(hvf::SYS_CNTV_CVAL_EL0).wrapping_add(cpu.vtimer_offset()));
                        wake.wait(seen, deadline);
                    }
                    cpu.set_reg(hvf::REG_PC, pc + 4);
                }
                EC_HVC | EC_SMC => {
                    match cpu.reg(0) {
                        PSCI_SYSTEM_OFF | PSCI_SYSTEM_RESET => return Ok(()),
                        f if PSCI_CPU_ON.contains(&f) => {
                            let r = cpu_on(shared, cpu.reg(1) & 0xff, cpu.reg(2), cpu.reg(3));
                            cpu.set_reg(0, r);
                        }
                        grix_abi::machine::KICK_CALL => {
                            if let Some(w) = shared.wakes.get(cpu.reg(1) as usize) {
                                w.notify();
                            }
                            cpu.set_reg(0, 0);
                        }
                        // Saved, this run ends there; restored runs go on.
                        grix_abi::image::SNAPSHOT_CALL if shared.snapshot && ec == EC_HVC => {
                            if take_snapshot(n, &cpu, shared)? {
                                return Ok(());
                            }
                            cpu.set_reg(0, grix_abi::image::SNAPSHOT_RETRY);
                        }
                        PSCI_VERSION => cpu.set_reg(0, 0x1_0000),
                        _ => cpu.set_reg(0, PSCI_NOT_SUPPORTED),
                    }
                    // HVC returns past itself; a trapped SMC doesn't.
                    if ec == EC_SMC {
                        cpu.set_reg(hvf::REG_PC, pc + 4);
                    }
                }
                EC_SYSREG => {
                    // Registers the hypervisor doesn't give the guest: reads
                    // as zero, writes ignored.
                    let iss = syndrome & 0x1ff_ffff;
                    if !warned_sysreg {
                        warned_sysreg = true;
                        eprintln!("grix-vmm: trapped system register access (iss {iss:#x}) at pc {pc:#x}");
                    }
                    let reg = ((iss >> 5) & 0x1f) as u32;
                    if iss & 1 == 1 && reg != 31 {
                        cpu.set_reg(reg, 0);
                    }
                    cpu.set_reg(hvf::REG_PC, pc + 4);
                }
                _ => return Err(format!("unhandled exception class {ec:#x} at pc {pc:#x} (esr {syndrome:#x})")),
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod kvm_loop {
    use std::sync::Arc;

    use super::*;
    use crate::kvm::{self, Exit};
    use crate::pause::{Pauses, Power};
    use crate::{snapshot, snapshot_kvm};

    const PSCI_NOT_SUPPORTED: u64 = -1i64 as u64;

    /// What every vCPU's thread shares.
    struct Shared {
        m: Machine,
        console: Arc<Console>,
        kicks: Vec<kvm::Kick>,
        pauses: Pauses,
        snapshot: bool,
        gic: std::os::fd::RawFd,
    }

    pub fn run(args: &Args) -> Result<(), String> {
        let saved = if args.restore { Some(snapshot::open()?) } else { None };
        let (m, restored) = match saved {
            Some(s) => {
                let (mem, rest) = s.split();
                (Machine::with_memory(args, mem)?, Some(rest))
            }
            None => (Machine::new(args)?, None),
        };
        if let Some(s) = &restored
            && s.cpus() != args.cpus as usize
        {
            return Err(format!("the snapshot is of {} vCPUs, not {}", s.cpus(), args.cpus));
        }
        // SAFETY: `m.mem` is never unmapped, and lives until the process ends.
        let (vm, mut cpus) =
            unsafe { kvm::Vm::create(m.mem.host(), RAM_BASE, m.mem.size(), GICD, GICR_GRIX_VMM, m.entry, args.cpus) }
                .map_err(|e| e.to_string())?;
        // The kernel's snapshot call comes back to us (KVM answers SMCCC
        // calls itself).
        if args.snapshot {
            vm.forward(grix_abi::image::SNAPSHOT_CALL as u32).map_err(|e| e.to_string())?;
        }
        // A restored machine: every vCPU (from this thread: none runs yet),
        // then the GIC, then the counter; all before the console can raise
        // its interrupt.
        if let Some(s) = &restored {
            for (n, cpu) in cpus.iter_mut().enumerate() {
                snapshot_kvm::restore_cpu(s, n, cpu)?;
            }
            snapshot_kvm::restore_gic(vm.gic_fd(), s)?;
            snapshot_kvm::set_counter(s, &mut cpus[0])?;
        }
        let irq_fd = vm.irq_fd();
        let line: Line = Box::new(move |level| kvm::set_spi(irq_fd, CONSOLE_IRQ, level));
        let console = match &restored {
            Some(s) => Console::restore(m.mem.clone(), line, s.console())?,
            None => Console::start(m.mem.clone(), line),
        };
        kvm::handle_kicks()?;
        let shared = Arc::new(Shared {
            m,
            console,
            kicks: cpus.iter().map(|c| c.kick()).collect(),
            // KVM does PSCI: every vCPU's thread runs, an off one waiting
            // in KVM_RUN.
            pauses: Pauses::new(vec![Power::On; cpus.len()]),
            snapshot: args.snapshot,
            gic: vm.gic_fd(),
        });
        let mut cpus = cpus.into_iter();
        let first = cpus.next().ok_or("no vCPU")?;
        // The threads first (the seccomp filter allows none to be made),
        // then confined, then any guest code (a restored machine's other
        // vCPUs run at once).
        let confined = Arc::new(std::sync::Barrier::new(shared.kicks.len()));
        for (n, cpu) in cpus.enumerate() {
            let (shared, confined) = (shared.clone(), confined.clone());
            std::thread::spawn(move || {
                confined.wait();
                let result = vcpu_loop(n + 1, cpu, &shared);
                if let Err(e) = &result {
                    eprintln!("grix-vmm: vCPU {}: {e}", n + 1);
                }
                // A vCPU's end is the machine's.
                std::process::exit(if result.is_ok() { 0 } else { 1 });
            });
        }
        kvm::confine(args.snapshot)?;
        shared.console.go();
        if !args.restore {
            shared.m.stamp_boot_time();
        }
        confined.wait();
        vcpu_loop(0, first, &shared)
    }

    /// Run vCPU `n` until the machine powers off.
    fn vcpu_loop(n: usize, mut cpu: kvm::Cpu, shared: &Shared) -> Result<(), String> {
        let (m, console, kick) = (&shared.m, &*shared.console, &shared.kicks[n]);
        kick.bind();
        loop {
            kick.clear();
            shared.pauses.point(n, || snapshot_kvm::cpu_state(&mut cpu))?;
            match cpu.run().map_err(|e| e.to_string())? {
                Exit::Mmio { addr, write: true, data, .. } => m.mmio_write(console, addr, data),
                Exit::Mmio { addr, len, write: false, .. } => {
                    let v = m.mmio_read(console, addr, len);
                    cpu.complete_load(v, len);
                }
                Exit::Shutdown => return Ok(()),
                Exit::Interrupted => {}
                // Saved, this run ends there; restored runs go on.
                Exit::Hypercall { function } => {
                    let r = if function == grix_abi::image::SNAPSHOT_CALL && shared.snapshot {
                        if take_snapshot(n, &mut cpu, shared)? {
                            return Ok(());
                        }
                        grix_abi::image::SNAPSHOT_RETRY
                    } else {
                        PSCI_NOT_SUPPORTED
                    };
                    cpu.set_reg(kvm::reg_x(0), r).map_err(|e| e.to_string())?;
                }
                Exit::Other(r) => return Err(format!("unexpected KVM exit {r}")),
            }
        }
    }

    /// `SNAPSHOT_CALL` from vCPU `n`: stop every other vCPU, then save the
    /// machine. True once it's saved (this run ends there); false to put it
    /// off (input is on its way), every vCPU going on.
    fn take_snapshot(n: usize, cpu: &mut kvm::Cpu, shared: &Shared) -> Result<bool, String> {
        let own = snapshot_kvm::cpu_state(cpu)?;
        let kick = |m: usize| shared.kicks[m].kick();
        shared.pauses.take(n, own, kick, |saved| {
            let counter = match snapshot_kvm::counter(cpu) {
                Ok(c) => c,
                Err(e) => return Some(Err(e)),
            };
            shared.console.save_with(|console| {
                let gic = snapshot_kvm::gic_state(shared.gic, saved.len())?;
                snapshot::save(n, saved, &gic, counter, &shared.m.mem, console)
            })
        })
    }
}

#[cfg(target_os = "linux")]
pub use kvm_loop::run;
