//! Snapshots of the whole machine (Hypervisor.framework).
//!
//! The kernel asks for one with `SNAPSHOT_CALL` when the program first
//! sits idle waiting for input. Every vCPU stops (each saves its own
//! registers, system registers, FP/SIMD and GIC CPU interface: the
//! framework only lets a vCPU's thread touch it), and we save them, the
//! GIC, the console device and RAM to the file the host gave us as fd 3,
//! and end the process. A restored run maps that RAM copy-on-write straight from the
//! file, so it starts in milliseconds however big the runtime is, puts the
//! rest back, and returns from the call with `SNAPSHOT_RESTORED` and fresh
//! entropy.
//!
//! Layout (little-endian):
//!
//! ```text
//!   0   magic "GRIXSNP1" (written last: a file without it is incomplete)
//!   8   version u32, 0 u32
//!   16  ram_size u64, ram_offset u64, state_len u64
//!   40  state (state_len bytes, `grix_abi::codec`)
//!   ram_offset (16 KiB aligned): guest RAM, written only where it isn't zero
//!   ram_offset + ram_size: whatever the host appends (it reads `ram_end`)
//! ```

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::time::{SystemTime, UNIX_EPOCH};

use grix_abi::codec::{Reader, Writer};

use crate::hvf::{self, Cpu};
use crate::mem::GuestMemory;

pub const MAGIC: [u8; 8] = *b"GRIXSNP1";
const VERSION: u32 = 2;
const HEADER: u64 = 40;
const PAGE: usize = 16 * 1024;

/// The file the host passes us.
pub const FD: i32 = 3;

/// The system registers a restored vCPU needs, by Hypervisor.framework id.
const SYS_REGS: &[u16] = &[
    0xc005, // MPIDR_EL1
    0xc080, // SCTLR_EL1
    0xc082, // CPACR_EL1
    0xc100, // TTBR0_EL1
    0xc101, // TTBR1_EL1
    0xc102, // TCR_EL1
    0xc108, 0xc109, 0xc10a, 0xc10b, // APIAKEY, APIBKEY
    0xc110, 0xc111, 0xc112, 0xc113, // APDAKEY, APDBKEY
    0xc118, 0xc119, // APGAKEY
    0xc200, // SPSR_EL1
    0xc201, // ELR_EL1
    0xc208, // SP_EL0
    0xc288, 0xc289, // AFSR0/1_EL1
    0xc290, // ESR_EL1
    0xc300, // FAR_EL1
    0xc3a0, // PAR_EL1
    0xc510, // MAIR_EL1
    0xc518, // AMAIR_EL1
    0xc600, // VBAR_EL1
    0xc681, // CONTEXTIDR_EL1
    0xc684, // TPIDR_EL1
    0xc708, // CNTKCTL_EL1
    0xd000, // CSSELR_EL1
    0xde82, // TPIDR_EL0
    0xde83, // TPIDRRO_EL0
    0xdf19, // CNTV_CTL_EL0
    0xdf1a, // CNTV_CVAL_EL0
    0xe208, // SP_EL1
    0x8012, // MDSCR_EL1
];

/// The GIC CPU interface (not in the framework's GIC state).
const ICC_REGS: &[u16] = &[
    0xc230, // PMR
    0xc643, // BPR0
    0xc644, // AP0R0
    0xc648, // AP1R0
    0xc663, // BPR1
    0xc664, // CTLR
    0xc665, // SRE
    0xc666, // IGRPEN0
    0xc667, // IGRPEN1
];

/// X0..X30, PC, FPCR, FPSR, CPSR.
const GP_REGS: u32 = 35;

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

fn snapshot_file() -> File {
    // SAFETY: fd 3 is the snapshot file the host opened for us (checked by
    // the first read or write; never closed here).
    unsafe { File::from_raw_fd(FD) }
}

/// One vCPU's registers, read on its own thread: general purpose,
/// system, FP/SIMD, and its GIC CPU interface.
pub fn cpu_state(cpu: &Cpu) -> Result<Vec<u8>, String> {
    let mut w = Writer::new();
    for r in 0..GP_REGS {
        w.u64(cpu.reg(r));
    }
    for &r in SYS_REGS {
        w.u64(cpu.sys_reg(r));
    }
    for q in 0..32 {
        w.raw(&cpu.simd_reg(q).map_err(|e| e.to_string())?);
    }
    for &r in ICC_REGS {
        w.u64(cpu.icc_reg(r).map_err(|e| e.to_string())?);
    }
    Ok(w.buf)
}

/// Save the machine to fd 3. vCPU `caller` asked, stopped at its call
/// with its PC past the HVC; `cpus` holds each vCPU's `cpu_state` (none
/// for one that was never started), all stopped; `counter` is the guest's
/// counter now; `console` the device's saved state.
pub fn save(
    caller: usize,
    cpus: &[Option<Vec<u8>>],
    counter: u64,
    mem: &GuestMemory,
    console: Vec<u8>,
) -> Result<(), String> {
    let file = std::mem::ManuallyDrop::new(snapshot_file());
    let mut w = Writer::new();
    w.u32(caller as u32);
    w.u32(cpus.len() as u32);
    for c in cpus {
        match c {
            Some(state) => {
                w.u8(1);
                w.bytes(state);
            }
            None => w.u8(0),
        }
    }
    w.bytes(&hvf::gic_state().map_err(|e| e.to_string())?);
    // The guest's counter, and when: a restored one runs on from there by
    // however long it's been.
    w.u64(counter);
    w.u64(now_ns());
    w.bytes(&console);
    let state = w.buf;

    let ram_offset = (HEADER + state.len() as u64).next_multiple_of(PAGE as u64);
    let mut header = Vec::with_capacity(HEADER as usize);
    header.extend_from_slice(&[0u8; 8]); // the magic, last
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&(mem.size() as u64).to_le_bytes());
    header.extend_from_slice(&ram_offset.to_le_bytes());
    header.extend_from_slice(&(state.len() as u64).to_le_bytes());
    let io = |e: std::io::Error| format!("writing the snapshot: {e}");
    file.set_len(0).map_err(io)?;
    file.write_all_at(&header, 0).map_err(io)?;
    file.write_all_at(&state, HEADER).map_err(io)?;
    // RAM: only what isn't zero; the rest stays a hole in the file.
    file.set_len(ram_offset + mem.size() as u64).map_err(io)?;
    let mut page = vec![0u8; PAGE];
    for off in (0..mem.size()).step_by(PAGE) {
        let n = PAGE.min(mem.size() - off);
        mem.read(mem.base() + off as u64, &mut page[..n]);
        if page[..n].iter().any(|&b| b != 0) {
            file.write_all_at(&page[..n], ram_offset + off as u64).map_err(io)?;
        }
    }
    file.write_all_at(&MAGIC, 0).map_err(io)?;
    Ok(())
}

/// A snapshot read back: RAM mapped from the file, and what to restore.
pub struct Saved {
    mem: GuestMemory,
    state: State,
}

/// The rest of a snapshot, once its memory is the machine's.
pub struct State {
    caller: usize,
    cpus: Vec<Option<Vec<u8>>>,
    gic: Vec<u8>,
    counter: u64,
    then: u64,
    console: Vec<u8>,
    /// Fresh entropy for the restored kernel (drawn now: the vCPU that
    /// asked may be put back after `confine`).
    entropy: [u8; 32],
}

/// Map fd 3's snapshot.
pub fn open() -> Result<Saved, String> {
    let file = std::mem::ManuallyDrop::new(snapshot_file());
    let bad = || "not a complete grix snapshot (or one from another grix: take it again)".to_string();
    let mut header = [0u8; HEADER as usize];
    file.read_exact_at(&mut header, 0).map_err(|e| format!("reading the snapshot: {e}"))?;
    let u64_at = |o: usize| u64::from_le_bytes(header[o..o + 8].try_into().unwrap());
    if header[..8] != MAGIC || u32::from_le_bytes(header[8..12].try_into().unwrap()) != VERSION {
        return Err(bad());
    }
    let (ram_size, ram_offset, state_len) = (u64_at(16), u64_at(24), u64_at(32));
    let file_len = file.metadata().map_err(|e| e.to_string())?.len();
    if ram_size == 0
        || ram_size > grix_abi::image::MAX_RAM
        || state_len > 16 << 20
        || ram_offset % PAGE as u64 != 0
        || ram_offset < HEADER + state_len
        || ram_offset.checked_add(ram_size).is_none_or(|end| end > file_len)
    {
        return Err(bad());
    }
    let mut raw = vec![0u8; state_len as usize];
    file.read_exact_at(&mut raw, HEADER).map_err(|e| format!("reading the snapshot: {e}"))?;
    let malformed = |_| "the snapshot's state is malformed".to_string();
    let mut r = Reader::new(&raw);
    let caller = r.u32().map_err(malformed)? as usize;
    let n = r.u32().map_err(malformed)? as usize;
    if n == 0 || n > grix_abi::machine::MAX_CPUS as usize || caller >= n {
        return Err("the snapshot's state is malformed".into());
    }
    let mut cpus = Vec::with_capacity(n);
    for _ in 0..n {
        cpus.push(match r.u8().map_err(malformed)? {
            0 => None,
            _ => Some(r.bytes().map_err(malformed)?.to_vec()),
        });
    }
    if cpus[caller].is_none() {
        return Err("the snapshot's state is malformed".into());
    }
    let gic = r.bytes().map_err(malformed)?.to_vec();
    let (counter, then) = (r.u64().map_err(malformed)?, r.u64().map_err(malformed)?);
    let console = r.bytes().map_err(malformed)?.to_vec();
    let mem = GuestMemory::map_file(file.as_raw_fd(), ram_offset, grix_abi::image::RAM_BASE, ram_size as usize)
        .map_err(|e| format!("mapping the snapshot's memory: {e}"))?;
    let mut entropy = [0u8; 32];
    // SAFETY: a buffer of the size given.
    if unsafe { libc::getentropy(entropy.as_mut_ptr().cast(), entropy.len()) } != 0 {
        return Err("getentropy failed".into());
    }
    Ok(Saved { mem, state: State { caller, cpus, gic, counter, then, console, entropy } })
}

impl Saved {
    pub fn split(self) -> (GuestMemory, State) {
        (self.mem, self.state)
    }
}

impl State {
    /// How many vCPUs the machine had.
    pub fn cpus(&self) -> usize {
        self.cpus.len()
    }

    /// Had vCPU `n` been started (PSCI CPU_ON)?
    pub fn started(&self, n: usize) -> bool {
        self.cpus.get(n).is_some_and(Option::is_some)
    }

    /// The vCPU timer offset that makes the guest's counter go on from
    /// where it was, as after a suspend (the kernel moves its time of day
    /// on by the time since).
    pub fn vtimer_offset(&self) -> u64 {
        hvf::now().wrapping_sub(self.counter)
    }

    /// The device's saved state.
    pub fn console(&self) -> &[u8] {
        &self.console
    }

    /// Put the GIC back, once every vCPU exists and before any runs.
    pub fn restore_gic(&self) -> Result<(), String> {
        hvf::set_gic_state(&self.gic).map_err(|e| e.to_string())
    }

    /// Put vCPU `n` back (on its own thread, after the GIC). The one that
    /// asked returns from its call: restored, with fresh entropy and the
    /// time since.
    pub fn restore_cpu(&self, n: usize, cpu: &mut Cpu) -> Result<(), String> {
        let bad = |_| "the snapshot's state is malformed".to_string();
        let Some(Some(state)) = self.cpus.get(n) else { return Err("restoring a vCPU that wasn't saved".into()) };
        let mut r = Reader::new(state);
        for reg in 0..GP_REGS {
            cpu.set_reg(reg, r.u64().map_err(bad)?);
        }
        for &reg in SYS_REGS {
            cpu.set_sys_reg(reg, r.u64().map_err(bad)?).map_err(|e| e.to_string())?;
        }
        for q in 0..32 {
            let v: [u8; 16] = r.take(16).map_err(bad)?.try_into().unwrap();
            cpu.set_simd_reg(q, v).map_err(|e| e.to_string())?;
        }
        for &reg in ICC_REGS {
            cpu.set_icc_reg(reg, r.u64().map_err(bad)?).map_err(|e| e.to_string())?;
        }
        if n == self.caller {
            cpu.set_reg(5, now_ns().saturating_sub(self.then));
            cpu.set_reg(0, grix_abi::image::SNAPSHOT_RESTORED);
            for (i, word) in self.entropy.as_chunks::<8>().0.iter().enumerate() {
                cpu.set_reg(1 + i as u32, u64::from_le_bytes(*word));
            }
        }
        Ok(())
    }
}
