//! The x86_64 machine on KVM: QEMU `microvm`'s layout
//! (`grix_abi::machine::x86_64`), which the x86_64 kernel expects. RAM at
//! 0, the boot image at `IMAGE_BASE`, COM1 on ports 0x3f8.., the virtio
//! console in the first virtio-mmio slot on GSI `VIRTIO_GSI`, and KVM's own
//! IOAPIC and local APICs. The kernel is entered as PVH says.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use grix_abi::image::{self, HEADER_LEN, MAX_RAM};
use grix_abi::machine::x86_64::{IMAGE_BASE, RAM_BASE, UART_PORT, VIRTIO, VIRTIO_GSI, VIRTIO_STRIDE, VMM_PORT};

use crate::Args;
use crate::console::{Console, Line};
use crate::kvm_x86::{self, Exit, Part};
use crate::mem::GuestMemory;
use crate::pause::{Pauses, Power};
use crate::{snapshot, snapshot_kvm_x86};

/// COM1, transmit only, to the socket. Each byte costs an exit, so the
/// kernel uses it only before the console is up and for panics.
struct Uart {
    /// The connected socket, as a plain file: written with write(2), which
    /// the seccomp filter allows (a socket's own writes are sendto).
    out: Option<std::fs::File>,
    /// The line control register (its DLAB bit makes the data port the
    /// divisor's).
    lcr: u8,
}

impl Uart {
    fn read(&self, off: u16) -> u8 {
        match off {
            3 => self.lcr,
            5 => 0x60, // LSR: transmitter empty, holding register empty
            _ => 0,
        }
    }

    fn write(&mut self, off: u16, v: u8) {
        match off {
            0 if self.lcr & 0x80 == 0 => {
                if let Some(s) = &mut self.out
                    && let Err(e) = s.write_all(&[v])
                {
                    eprintln!("grix-vmm: the serial port's socket: {e}");
                    self.out = None;
                }
            }
            3 => self.lcr = v,
            _ => {}
        }
    }
}

struct Machine {
    mem: Arc<GuestMemory>,
    entry: u64,
    uart: Mutex<Uart>,
}

impl Machine {
    fn new(args: &Args) -> Result<Machine, String> {
        let ram = args.mem_mb << 20;
        if ram == 0 || ram > MAX_RAM {
            return Err(format!("--mem {} is outside 1..={} MiB", args.mem_mb, MAX_RAM >> 20));
        }
        let mem = GuestMemory::new(RAM_BASE, ram as usize).map_err(|e| format!("allocating RAM: {e}"))?;
        let kernel = std::fs::read(&args.kernel).map_err(|e| format!("reading {}: {e}", args.kernel.display()))?;
        let entry = load_kernel(&mem, &kernel)?;
        let img = std::fs::read(&args.image).map_err(|e| format!("reading {}: {e}", args.image.display()))?;
        image::parse_header(img.get(..HEADER_LEN).unwrap_or(&[]))
            .map_err(|_| "the boot image has no valid header".to_string())?;
        if !mem.write(IMAGE_BASE, &img) {
            return Err(format!("the boot image ({} MiB) doesn't fit in RAM", img.len() >> 20));
        }
        Ok(Machine { entry, ..Machine::with_memory(args, mem)? })
    }

    /// The machine around memory that's ready: a snapshot's (whose vCPUs
    /// are put back, not entered).
    fn with_memory(args: &Args, mem: GuestMemory) -> Result<Machine, String> {
        let out = match &args.uart {
            Some(p) => {
                let s = UnixStream::connect(p).map_err(|e| format!("connecting to {}: {e}", p.display()))?;
                Some(std::fs::File::from(OwnedFd::from(s)))
            }
            None => None,
        };
        Ok(Machine { mem: Arc::new(mem), entry: 0, uart: Mutex::new(Uart { out, lcr: 0 }) })
    }

    /// The time of day the kernel starts from is now (as on arm64).
    fn stamp_boot_time(&self) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
        self.mem.write(IMAGE_BASE + image::BOOT_TIME_OFFSET as u64, &now.to_le_bytes());
    }

    fn port_in(&self, port: u16) -> u32 {
        match port {
            p if (UART_PORT..UART_PORT + 8).contains(&p) => {
                self.uart.lock().unwrap_or_else(|e| e.into_inner()).read(p - UART_PORT) as u32
            }
            // Nothing else is there.
            _ => u32::MAX,
        }
    }

    fn port_out(&self, port: u16, v: u32) {
        if (UART_PORT..UART_PORT + 8).contains(&port) {
            self.uart.lock().unwrap_or_else(|e| e.into_inner()).write(port - UART_PORT, v as u8);
        }
    }

    fn mmio_read(&self, console: &Console, addr: u64, size: u32) -> u64 {
        let v = match addr {
            a if (VIRTIO..VIRTIO + VIRTIO_STRIDE).contains(&a) => {
                // Registers are 32-bit; config space may be read in parts.
                let off = a - VIRTIO;
                console.read(off & !3) >> (8 * (off & 3))
            }
            // Empty virtio slots, and anything else: zero.
            _ => 0,
        } as u64;
        if size >= 4 { v } else { v & ((1u64 << (8 * size)) - 1) }
    }

    fn mmio_write(&self, console: &Console, addr: u64, v: u64) {
        if (VIRTIO..VIRTIO + VIRTIO_STRIDE).contains(&addr) {
            console.write(addr - VIRTIO, v as u32);
        }
    }
}

/// Load the kernel ELF's segments at their physical addresses. Returns its
/// PVH entry point (the XEN_ELFNOTE_PHYS32_ENTRY note).
fn load_kernel(mem: &GuestMemory, elf: &[u8]) -> Result<u64, String> {
    let u16_at = |o: usize| elf.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| elf.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u64_at = |o: usize| elf.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    if elf.get(..6) != Some(b"\x7fELF\x02\x01") || u16_at(0x12) != Some(62) {
        return Err("the kernel isn't an x86_64 ELF".into());
    }
    let bad = || "the kernel's ELF headers are malformed".to_string();
    let phoff = u64_at(0x20).ok_or_else(bad)? as usize;
    let phentsize = u16_at(0x36).ok_or_else(bad)? as usize;
    let phnum = u16_at(0x38).ok_or_else(bad)? as usize;
    let mut entry = None;
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize).ok_or_else(bad)?).ok_or_else(bad)?;
        let ty = u32_at(ph).ok_or_else(bad)?;
        let offset = u64_at(ph + 0x08).ok_or_else(bad)? as usize;
        let filesz = u64_at(ph + 0x20).ok_or_else(bad)? as usize;
        let data = elf.get(offset..offset.checked_add(filesz).ok_or_else(bad)?).ok_or_else(bad)?;
        match ty {
            1 => {
                let paddr = u64_at(ph + 0x18).ok_or_else(bad)?;
                let memsz = u64_at(ph + 0x28).ok_or_else(bad)?;
                // The rest of memsz is zero already (fresh memory).
                let end = paddr.checked_add(memsz).ok_or_else(bad)?;
                if paddr < mem.base() || end > mem.base() + mem.size() as u64 || !mem.write(paddr, data) {
                    return Err(format!("the kernel segment at {paddr:#x} doesn't fit in RAM"));
                }
            }
            // PT_NOTE: namesz, descsz, type, the name and the descriptor,
            // each 4-byte aligned.
            4 => {
                let mut at = 0;
                while at + 12 <= data.len() {
                    let word = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
                    let (namesz, descsz, ty) = (word(at), word(at + 4), word(at + 8));
                    let name = at + 12;
                    let desc = name + namesz.next_multiple_of(4);
                    let next = desc + descsz.next_multiple_of(4);
                    if next > data.len() {
                        break;
                    }
                    if ty == 18 && &data[name..name + namesz] == b"Xen\0" && descsz >= 4 {
                        entry = Some(word(desc) as u64);
                    }
                    at = next;
                }
            }
            _ => {}
        }
    }
    entry.ok_or_else(|| "the kernel has no PVH entry (XEN_ELFNOTE_PHYS32_ENTRY)".to_string())
}

/// What every vCPU's thread shares.
struct Shared {
    m: Machine,
    console: Arc<Console>,
    vm: kvm_x86::Vm,
    kicks: Vec<kvm_x86::Kick>,
    pauses: Pauses,
    snapshot: bool,
    /// A vCPU's XSAVE area's size (`Vm::xsave_size`).
    xsave: usize,
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
        unsafe { kvm_x86::Vm::create(m.mem.host(), m.mem.size(), m.entry, args.cpus) }.map_err(|e| e.to_string())?;
    let irq_fd = vm.irq_fd();
    let line: Line = Box::new(move |level| kvm_x86::set_irq(irq_fd, VIRTIO_GSI, level));
    let console = match &restored {
        Some(s) => Console::restore(m.mem.clone(), line, s.console())?,
        None => Console::start(m.mem.clone(), line),
    };
    kvm_x86::handle_kicks()?;
    let xsave = vm.xsave_size();
    let shared = Arc::new(Shared {
        m,
        console,
        vm,
        kicks: cpus.iter().map(|c| c.kick()).collect(),
        // KVM does INIT and SIPI: every vCPU's thread runs, one that waits
        // for its start waiting in KVM_RUN.
        pauses: Pauses::new(vec![Power::On; cpus.len()]),
        snapshot: args.snapshot,
        xsave,
    });
    // The threads first (the seccomp filter allows none to be made), each
    // given its vCPU once the VMM is confined and a restored machine is
    // back (its other vCPUs run at once).
    let mut given = Vec::new();
    for n in 1..cpus.len() {
        let (tx, rx) = std::sync::mpsc::channel::<kvm_x86::Cpu>();
        let shared = shared.clone();
        std::thread::spawn(move || {
            let Ok(cpu) = rx.recv() else { return };
            let result = vcpu_loop(n, cpu, &shared);
            if let Err(e) = &result {
                eprintln!("grix-vmm: vCPU {n}: {e}");
            }
            // A vCPU's end is the machine's.
            std::process::exit(if result.is_ok() { 0 } else { 1 });
        });
        given.push(tx);
    }
    kvm_x86::confine(args.snapshot, restored.is_some())?;
    // A restored machine, confined first (the file may be anyone's): every
    // vCPU (from this thread: none runs yet), then the interrupt
    // controllers, then the counter; all before the console can raise its
    // interrupt. Then what putting them back took is given up too.
    if let Some(s) = &restored {
        for (n, cpu) in cpus.iter_mut().enumerate() {
            snapshot_kvm_x86::restore_cpu(s, n, cpu, xsave)?;
        }
        snapshot_kvm_x86::restore_irqchip(&shared.vm, s)?;
        snapshot_kvm_x86::set_counter(s, &cpus)?;
        kvm_x86::confine(args.snapshot, false)?;
    }
    shared.console.go();
    if !args.restore {
        shared.m.stamp_boot_time();
    }
    let mut cpus = cpus.into_iter();
    let first = cpus.next().ok_or("no vCPU")?;
    for (tx, cpu) in given.into_iter().zip(cpus) {
        tx.send(cpu).map_err(|_| "a vCPU's thread is gone")?;
    }
    vcpu_loop(0, first, &shared)
}

/// Run vCPU `n` until the machine ends.
fn vcpu_loop(n: usize, mut cpu: kvm_x86::Cpu, shared: &Shared) -> Result<(), String> {
    let (m, console, kick) = (&shared.m, &*shared.console, &shared.kicks[n]);
    kick.bind();
    loop {
        kick.clear();
        shared.pauses.point(n, || snapshot_kvm_x86::cpu_state(&mut cpu, shared.xsave))?;
        match cpu.run().map_err(|e| e.to_string())? {
            // The kernel's call (`SNAPSHOT_CALL`): saved, this run ends
            // there; restored runs go on. Without --snapshot, ignored, as
            // QEMU does: the kernel finds rax as it was.
            Exit::Io { port: VMM_PORT, write: true, .. } if shared.snapshot => {
                if take_snapshot(n, &mut cpu, shared)? {
                    return Ok(());
                }
                // Not now (input is on its way): the call returns that.
                let mut regs = cpu.get(Part::Regs).map_err(|e| e.to_string())?;
                regs[..8].copy_from_slice(&grix_abi::image::SNAPSHOT_RETRY.to_le_bytes());
                cpu.set(Part::Regs, &regs).map_err(|e| e.to_string())?;
            }
            // One unit at a time, as the instruction would have done them.
            Exit::Io { port, len, write } => {
                for unit in cpu.io_data().chunks_exact_mut(len as usize) {
                    if write {
                        let mut v = [0u8; 4];
                        v[..unit.len()].copy_from_slice(unit);
                        m.port_out(port, u32::from_le_bytes(v));
                    } else {
                        unit.copy_from_slice(&m.port_in(port).to_le_bytes()[..unit.len()]);
                    }
                }
            }
            Exit::Mmio { addr, write: true, data, .. } => m.mmio_write(console, addr, data),
            Exit::Mmio { addr, len, write: false, .. } => {
                let v = m.mmio_read(console, addr, len);
                cpu.complete_load(v, len);
            }
            Exit::Shutdown => return Ok(()),
            Exit::Interrupted => {}
            Exit::Other(r) => return Err(format!("unexpected KVM exit {r}")),
        }
    }
}

/// `SNAPSHOT_CALL` from vCPU `n`: stop every other vCPU, then save the
/// machine. True once it's saved (this run ends there); false to put it
/// off (input is on its way), every vCPU going on.
fn take_snapshot(n: usize, cpu: &mut kvm_x86::Cpu, shared: &Shared) -> Result<bool, String> {
    let own = snapshot_kvm_x86::cpu_state(cpu, shared.xsave)?;
    let kick = |m: usize| shared.kicks[m].kick();
    shared.pauses.take(n, own, kick, |saved| {
        let counter = match snapshot_kvm_x86::counter(cpu) {
            Ok(c) => c,
            Err(e) => return Some(Err(e)),
        };
        shared.console.save_with(|console| {
            let chips = snapshot_kvm_x86::irqchip_state(&shared.vm)?;
            snapshot::save(n, saved, &chips, counter, &shared.m.mem, console)
        })
    })
}
