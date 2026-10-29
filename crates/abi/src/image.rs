//! Boot image: everything the guest needs to run one program.
//!
//! The host places the encoded image at [`IMAGE_BASE`] in guest physical memory.
//! Layout: a fixed [`HEADER_LEN`]-byte header (magic, total length, RAM size,
//! where the GIC redistributors are) followed by a body encoded with
//! [`crate::codec`].

use alloc::vec::Vec;

use crate::codec::{DecodeError, Reader, Writer};
use crate::policy::{DenyAction, Policy};

pub const MAGIC: [u8; 8] = *b"GRIXIMG1";
pub const HEADER_LEN: usize = 32;
/// Where `Image::boot_time_ns` is in an encoded image: a VMM that starts
/// the machine well after the image was made (grix-vmm) writes the time
/// again there, just before the first vCPU runs.
pub const BOOT_TIME_OFFSET: usize = HEADER_LEN;

/// Guest physical memory layout (QEMU `virt` machine).
pub const RAM_BASE: u64 = 0x4000_0000;
/// Guest physical address the host loads the image at.
pub const IMAGE_BASE: u64 = 0x4800_0000;
/// The kernel linearly maps physical memory up to 4 GiB.
pub const MAX_RAM: u64 = 3 << 30;
/// The most entries (files, directories, links) an image may have, imports
/// and mounts together. Each costs a few hundred bytes of the kernel's small
/// heap, and the files a program creates need room there too.
pub const MAX_ENTRIES: usize = 30_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    File = 0,
    Dir = 1,
    /// `data` holds the link target.
    Symlink = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Absolute, normalized guest path.
    pub path: &'a str,
    pub kind: EntryKind,
    /// Permission bits (e.g. 0o755).
    pub mode: u32,
    /// Modification time on the host, in ns since the Unix epoch (0: boot time).
    pub mtime_ns: u64,
    pub data: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image<'a> {
    pub ram_size: u64,
    /// The GIC redistributors' base (`machine::GICR_QEMU` or
    /// `machine::GICR_GRIX_VMM`): the one thing that differs between VMMs.
    pub gicr: u64,
    /// Host wall-clock time when the image was built, in ns since the Unix
    /// epoch (or when the machine started: `BOOT_TIME_OFFSET`). The kernel
    /// pairs it with its counter at boot.
    pub boot_time_ns: u64,
    /// Entropy for the guest CSPRNG.
    pub seed: [u8; 32],
    pub policy: Policy,
    pub uid: u32,
    pub gid: u32,
    pub cwd: &'a str,
    /// The host sends stdin over the console (see `wire::Input`). Without
    /// it, stdin reads return end-of-file at once.
    pub stdin: bool,
    /// Path of the program to execute.
    pub exe: &'a str,
    pub argv: Vec<&'a str>,
    pub envp: Vec<&'a str>,
    pub entries: Vec<Entry<'a>>,
    /// Directories to send back to the host when the program ends (see
    /// `wire::ExportMsg`), and the most they may cost in all
    /// (`wire::export_cost`).
    pub exports: Vec<&'a str>,
    pub export_budget: u64,
    /// Directories mounted read-write from the host: when the program ends,
    /// what changed in each is sent back (`ExportKind::Removed` for what's
    /// gone), after the exports and within the same budget. Their entries
    /// are among `entries`, as the host found them.
    pub mounts: Vec<&'a str>,
    /// Directories mounted live from the host (`hostfs`): nothing of them is
    /// in `entries`; the guest asks the host as it goes. The root of
    /// `live_mounts[i]` has id `i + 1`.
    pub live_mounts: Vec<LiveMount<'a>>,
    /// Guest ports the host forwards connections to (`link::ToGuest::Incoming`).
    pub forwards: Vec<u16>,
    /// Guest ports the host forwards UDP datagrams to
    /// (`link::ToGuest::UdpIncoming`).
    pub udp_forwards: Vec<u16>,
    /// Snapshot the machine when the program first waits for stdin (see
    /// [`SNAPSHOT_CALL`]).
    pub snapshot: bool,
    /// CPUs the machine has (1..=`machine::MAX_CPUS`); the kernel starts
    /// the others with PSCI CPU_ON.
    pub cpus: u32,
    /// A program (a path in the guest) that runs x86_64 Linux programs on
    /// arm64, like `qemu-x86_64` or box64: execve of an x86_64 ELF runs it
    /// with the program's path and arguments, as binfmt_misc would. Empty:
    /// none.
    pub x86_64: &'a str,
    /// TTY mode: the program's stdin, stdout and stderr are a terminal
    /// (/dev/pts/0) of this many rows and columns, whose other side is the
    /// host: stdin carries what's typed, stdout what the terminal shows
    /// (and `wire::Input::Resize` its new size). Needs `stdin`.
    pub tty: Option<(u16, u16)>,
}

/// The hypervisor call (HVC, in SMCCC's OEM service range: Hypervisor.framework
/// answers the vendor-specific hypervisor range itself) the kernel makes to
/// have the VMM snapshot the whole machine. It returns
/// [`SNAPSHOT_TAKEN`] in x0 in the run that took it (whose VMM then stops
/// it there), [`SNAPSHOT_RESTORED`] in each run restored from it, with 32
/// bytes of fresh entropy in x1..x4 and the nanoseconds since the snapshot
/// in x5, [`SNAPSHOT_RETRY`] if input arrived meanwhile (call again when
/// next idle), or PSCI's NOT_SUPPORTED (-1) when the VMM can't. On x86_64
/// it's an `out` to [`crate::machine::x86_64::VMM_PORT`], and the
/// registers are rax, rdi, rsi, rdx, rcx and r8; a VMM that can't leaves
/// rax as it was.
pub const SNAPSHOT_CALL: u64 = 0xc300_0001;
pub const SNAPSHOT_TAKEN: u64 = 0;
pub const SNAPSHOT_RESTORED: u64 = 1;
pub const SNAPSHOT_RETRY: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveMount<'a> {
    pub path: &'a str,
    pub writable: bool,
    /// A lazy import: the host's files as the run found them, read as
    /// they're used and never written there. With `fs_write`, what the
    /// program changes is copied into the sandbox first, as for imports.
    pub lazy: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub total_len: u64,
    pub ram_size: u64,
    pub gicr: u64,
}

pub fn parse_header(buf: &[u8]) -> Result<Header, DecodeError> {
    let mut r = Reader::new(buf);
    if r.take(8)? != MAGIC {
        return Err(DecodeError);
    }
    let total_len = r.u64()?;
    let ram_size = r.u64()?;
    let gicr = r.u64()?;
    if total_len < HEADER_LEN as u64 {
        return Err(DecodeError);
    }
    Ok(Header { total_len, ram_size, gicr })
}

impl<'a> Image<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&MAGIC);
        w.u64(0); // total length, patched below
        w.u64(self.ram_size);
        w.u64(self.gicr);
        w.u64(self.boot_time_ns);
        w.raw(&self.seed);
        w.u64(self.policy.caps);
        w.u8(self.policy.on_deny as u8);
        w.u32(self.uid);
        w.u32(self.gid);
        w.str(self.cwd);
        w.u8(self.stdin as u8);
        w.str(self.exe);
        w.strs(&self.argv);
        w.strs(&self.envp);
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            w.str(e.path);
            w.u8(e.kind as u8);
            w.u32(e.mode);
            w.u64(e.mtime_ns);
            w.bytes(e.data);
        }
        w.strs(&self.exports);
        w.u64(self.export_budget);
        w.strs(&self.mounts);
        w.u32(self.live_mounts.len() as u32);
        for m in &self.live_mounts {
            w.str(m.path);
            w.u8(m.writable as u8 | (m.lazy as u8) << 1);
        }
        w.u32(self.forwards.len() as u32);
        for port in &self.forwards {
            w.u32(*port as u32);
        }
        w.u32(self.udp_forwards.len() as u32);
        for port in &self.udp_forwards {
            w.u32(*port as u32);
        }
        w.u8(self.snapshot as u8);
        w.u32(self.cpus);
        w.str(self.x86_64);
        w.u8(self.tty.is_some() as u8);
        let (rows, cols) = self.tty.unwrap_or_default();
        w.u32(rows as u32 | (cols as u32) << 16);
        let len = w.len() as u64;
        w.buf[8..16].copy_from_slice(&len.to_le_bytes());
        w.buf
    }

    pub fn decode(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let header = parse_header(buf)?;
        let total = usize::try_from(header.total_len).map_err(|_| DecodeError)?;
        let buf = buf.get(..total).ok_or(DecodeError)?;
        let mut r = Reader::new(buf);
        r.take(HEADER_LEN)?;
        let boot_time_ns = r.u64()?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(r.take(32)?);
        let caps = r.u64()?;
        let on_deny = DenyAction::from_u8(r.u8()?).ok_or(DecodeError)?;
        let uid = r.u32()?;
        let gid = r.u32()?;
        let cwd = r.str()?;
        let stdin = r.u8()? != 0;
        let exe = r.str()?;
        let argv = r.strs()?;
        let envp = r.strs()?;
        let n = r.u32()? as usize;
        if n > r.remaining() / 16 {
            return Err(DecodeError);
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let path = r.str()?;
            let kind = match r.u8()? {
                0 => EntryKind::File,
                1 => EntryKind::Dir,
                2 => EntryKind::Symlink,
                _ => return Err(DecodeError),
            };
            let mode = r.u32()?;
            let mtime_ns = r.u64()?;
            let data = r.bytes()?;
            entries.push(Entry { path, kind, mode, mtime_ns, data });
        }
        let exports = r.strs()?;
        let export_budget = r.u64()?;
        let mounts = r.strs()?;
        let n = r.u32()? as usize;
        if n > r.remaining() / 9 {
            return Err(DecodeError);
        }
        let live_mounts = (0..n).map(|_| live_mount(&mut r)).collect::<Result<_, _>>()?;
        let n = r.u32()? as usize;
        if n > r.remaining() / 4 {
            return Err(DecodeError);
        }
        let forwards = (0..n).map(|_| r.u32().map(|p| p as u16)).collect::<Result<_, _>>()?;
        let n = r.u32()? as usize;
        if n > r.remaining() / 4 {
            return Err(DecodeError);
        }
        let udp_forwards = (0..n).map(|_| r.u32().map(|p| p as u16)).collect::<Result<_, _>>()?;
        let snapshot = r.u8()? != 0;
        let cpus = r.u32()?;
        if cpus == 0 || cpus > crate::machine::MAX_CPUS {
            return Err(DecodeError);
        }
        let x86_64 = r.str()?;
        let has_tty = r.u8()? != 0;
        let size = r.u32()?;
        let tty = has_tty.then_some((size as u16, (size >> 16) as u16));
        Ok(Image {
            ram_size: header.ram_size,
            gicr: header.gicr,
            boot_time_ns,
            seed,
            policy: Policy { caps, on_deny },
            uid,
            gid,
            cwd,
            stdin,
            exe,
            argv,
            envp,
            entries,
            exports,
            export_budget,
            mounts,
            live_mounts,
            forwards,
            udp_forwards,
            snapshot,
            cpus,
            x86_64,
            tty,
        })
    }
}

fn live_mount<'a>(r: &mut Reader<'a>) -> Result<LiveMount<'a>, DecodeError> {
    let path = r.str()?;
    let flags = r.u8()?;
    Ok(LiveMount { path, writable: flags & 1 != 0, lazy: flags & 2 != 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip() {
        let img = Image {
            ram_size: 256 << 20,
            gicr: crate::machine::GICR_QEMU,
            boot_time_ns: 1_700_000_000_000_000_000,
            seed: [7; 32],
            policy: Policy { caps: 0b101, on_deny: DenyAction::Kill },
            uid: 1000,
            gid: 1000,
            cwd: "/",
            stdin: true,
            exe: "/bin/hello",
            argv: vec!["hello", "world"],
            envp: vec!["A=1"],
            entries: vec![
                Entry { path: "/bin", kind: EntryKind::Dir, mode: 0o755, mtime_ns: 0, data: b"" },
                Entry { path: "/bin/hello", kind: EntryKind::File, mode: 0o755, mtime_ns: 5, data: b"\x7fELF" },
                Entry { path: "/bin/hi", kind: EntryKind::Symlink, mode: 0o777, mtime_ns: 9, data: b"hello" },
            ],
            exports: vec!["/out", "/tmp/results"],
            export_budget: 1 << 20,
            mounts: vec!["/work"],
            live_mounts: vec![
                LiveMount { path: "/src", writable: false, lazy: false },
                LiveMount { path: "/big", writable: false, lazy: true },
            ],
            forwards: vec![8000, 80],
            udp_forwards: vec![53],
            snapshot: true,
            cpus: 4,
            x86_64: "/usr/bin/qemu-x86_64",
            tty: Some((24, 80)),
        };
        let bytes = img.encode();
        let h = parse_header(&bytes).unwrap();
        assert_eq!(h.total_len as usize, bytes.len());
        assert_eq!(h.ram_size, 256 << 20);
        assert_eq!(Image::decode(&bytes).unwrap(), img);
    }

    #[test]
    fn rejects_truncated() {
        let img = Image {
            ram_size: 1,
            gicr: 0,
            boot_time_ns: 0,
            seed: [0; 32],
            policy: Policy::default(),
            uid: 0,
            gid: 0,
            cwd: "/",
            stdin: false,
            exe: "/x",
            argv: vec![],
            envp: vec![],
            entries: vec![],
            exports: vec![],
            export_budget: 0,
            mounts: vec![],
            live_mounts: vec![],
            forwards: vec![],
            udp_forwards: vec![],
            snapshot: false,
            cpus: 1,
            x86_64: "",
            tty: None,
        };
        let bytes = img.encode();
        assert!(Image::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(parse_header(b"NOTMAGIC").is_err());
    }
}
