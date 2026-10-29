//! Snapshots of the whole machine.
//!
//! The kernel asks for one with `SNAPSHOT_CALL` when the program first
//! sits idle waiting for input. Every vCPU stops (`pause.rs`) and saves its
//! own registers, and we save them, the interrupt controller (arm64's GIC,
//! x86's IOAPIC and 8259s), the console device and RAM to
//! the file the host gave us as fd 3, and end the process. A restored run
//! maps that RAM copy-on-write straight from the file, so it starts in
//! milliseconds however big the runtime is, puts the rest back, and returns
//! from the call with `SNAPSHOT_RESTORED` and fresh entropy.
//!
//! What a vCPU's and the interrupt controller's state are is the
//! hypervisor's (`snapshot_hvf.rs`, `snapshot_kvm.rs`, `snapshot_kvm_x86.rs`):
//! a snapshot runs only where it was taken.
//!
//! Layout (little-endian):
//!
//! ```text
//!   0   magic "GRIXSNP1" (written last: a file without it is incomplete)
//!   8   version u32, hypervisor u32 (1: Hypervisor.framework, 2: arm64
//!       KVM, 3: x86_64 KVM)
//!   16  ram_size u64, ram_offset u64, state_len u64
//!   40  state (state_len bytes, `grix_abi::codec`)
//!   ram_offset (64 KiB aligned): guest RAM, written only where it isn't zero
//!   ram_offset + ram_size: whatever the host appends (it reads `ram_end`)
//! ```

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::time::{SystemTime, UNIX_EPOCH};

use grix_abi::codec::{Reader, Writer};

use crate::mem::GuestMemory;

pub const MAGIC: [u8; 8] = *b"GRIXSNP1";
const VERSION: u32 = 3;
const HEADER: u64 = 40;
/// RAM is written a page at a time, skipping zeros.
const PAGE: usize = 16 * 1024;
/// Where RAM starts in the file: mappable whatever the host's page size.
const RAM_ALIGN: u64 = 64 * 1024;

#[cfg(target_os = "macos")]
const HYPERVISOR: u32 = 1;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const HYPERVISOR: u32 = 2;
#[cfg(target_arch = "x86_64")]
const HYPERVISOR: u32 = 3;

/// Where guest RAM starts.
#[cfg(target_arch = "aarch64")]
const RAM_BASE: u64 = grix_abi::image::RAM_BASE;
#[cfg(target_arch = "x86_64")]
const RAM_BASE: u64 = grix_abi::machine::x86_64::RAM_BASE;

/// The file the host passes us.
pub const FD: i32 = 3;

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

fn snapshot_file() -> File {
    // SAFETY: fd 3 is the snapshot file the host opened for us (checked by
    // the first read or write; never closed here).
    unsafe { File::from_raw_fd(FD) }
}

/// Save the machine to fd 3. vCPU `caller` asked, stopped at its call
/// with its PC past the HVC (or `out`); `cpus` holds each vCPU's state
/// (none for one that was never started), all stopped; `gic` the interrupt
/// controller's; `counter` is the guest's counter now; `console` the
/// device's saved state.
pub fn save(
    caller: usize,
    cpus: &[Option<Vec<u8>>],
    gic: &[u8],
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
    w.bytes(gic);
    // The guest's counter, and when: a restored one runs on from there by
    // however long it's been.
    w.u64(counter);
    w.u64(now_ns());
    w.bytes(&console);
    let state = w.buf;

    let ram_offset = (HEADER + state.len() as u64).next_multiple_of(RAM_ALIGN);
    let mut header = Vec::with_capacity(HEADER as usize);
    header.extend_from_slice(&[0u8; 8]); // the magic, last
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.extend_from_slice(&HYPERVISOR.to_le_bytes());
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
    /// asked may be put back after the VMM confines itself).
    entropy: [u8; 32],
}

/// Map fd 3's snapshot.
pub fn open() -> Result<Saved, String> {
    let file = std::mem::ManuallyDrop::new(snapshot_file());
    let bad = || "not a complete grix snapshot (or one from another grix: take it again)".to_string();
    let mut header = [0u8; HEADER as usize];
    file.read_exact_at(&mut header, 0).map_err(|e| format!("reading the snapshot: {e}"))?;
    let u32_at = |o: usize| u32::from_le_bytes(header[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(header[o..o + 8].try_into().unwrap());
    if header[..8] != MAGIC || u32_at(8) != VERSION {
        return Err(bad());
    }
    if u32_at(12) != HYPERVISOR {
        return Err("the snapshot was taken on another hypervisor (macOS's or Linux's): take it again here".into());
    }
    let (ram_size, ram_offset, state_len) = (u64_at(16), u64_at(24), u64_at(32));
    let file_len = file.metadata().map_err(|e| e.to_string())?.len();
    if ram_size == 0
        || ram_size > grix_abi::image::MAX_RAM
        || state_len > 16 << 20
        || ram_offset % RAM_ALIGN != 0
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
    let mem = GuestMemory::map_file(file.as_raw_fd(), ram_offset, RAM_BASE, ram_size as usize)
        .map_err(|e| format!("mapping the snapshot's memory: {e}"))?;
    let mut entropy = [0u8; 32];
    // SAFETY: a buffer of the size given.
    #[cfg(target_os = "macos")]
    let drawn = unsafe { libc::getentropy(entropy.as_mut_ptr().cast(), entropy.len()) } == 0;
    // SAFETY: as above.
    #[cfg(target_os = "linux")]
    let drawn = unsafe { libc::getrandom(entropy.as_mut_ptr().cast(), entropy.len(), 0) } == entropy.len() as isize;
    if !drawn {
        return Err(format!("drawing entropy: {}", std::io::Error::last_os_error()));
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
    #[cfg(target_os = "macos")]
    pub fn started(&self, n: usize) -> bool {
        self.cpus.get(n).is_some_and(Option::is_some)
    }

    /// vCPU `n`'s saved state.
    pub fn cpu(&self, n: usize) -> Result<&[u8], String> {
        self.cpus.get(n).and_then(Option::as_deref).ok_or_else(|| format!("vCPU {n} wasn't saved"))
    }

    /// The interrupt controller's saved state.
    pub fn gic(&self) -> &[u8] {
        &self.gic
    }

    /// The guest's counter when it was saved: it goes on from there, as
    /// after a suspend (the kernel moves its time of day on by the time
    /// since).
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The device's saved state.
    pub fn console(&self) -> &[u8] {
        &self.console
    }

    /// If vCPU `n` asked for the snapshot, what it returns from the call
    /// with in x0..x5 (rax, rdi, rsi, rdx, rcx, r8 on x86_64): restored,
    /// fresh entropy, and the time since.
    pub fn returns(&self, n: usize) -> Option<[u64; 6]> {
        if n != self.caller {
            return None;
        }
        let mut x = [0u64; 6];
        x[0] = grix_abi::image::SNAPSHOT_RESTORED;
        for (i, word) in self.entropy.as_chunks::<8>().0.iter().enumerate() {
            x[1 + i] = u64::from_le_bytes(*word);
        }
        x[5] = now_ns().saturating_sub(self.then);
        Some(x)
    }
}
