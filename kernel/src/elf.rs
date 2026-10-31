//! ELF64 (AArch64) loader. Segments become file-backed VMAs that are paged in
//! on demand: straight from the boot image, or from a file the program wrote.

use alloc::string::String;
use alloc::vec::Vec;

use crate::fs::{Content, Ino};
use crate::mm::aspace::{AddressSpace, Backing, USER_TOP, Vma};
use crate::mm::paging::Prot;
use crate::mm::{PAGE_SIZE, page_down, page_up};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PHDR_SIZE: usize = 56;

/// Where position-independent main executables go (Linux's
/// ELF_ET_DYN_BASE for the architecture).
pub const DYN_BASE: u64 = crate::arch::ELF_DYN_BASE;

/// An executable's bytes: imported and unchanged (in the boot image), or
/// written in the sandbox.
#[derive(Clone)]
pub enum Source {
    Image(&'static [u8]),
    Written(Content),
}

impl Source {
    pub fn of(c: &Content) -> Source {
        match c.lock().image() {
            Some(bytes) => Source::Image(bytes),
            None => Source::Written(c.clone()),
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Source::Image(d) => d.len() as u64,
            Source::Written(c) => c.lock().len(),
        }
    }

    /// Bytes at `off`; returns how many there were.
    pub fn read(&self, off: u64, out: &mut [u8]) -> usize {
        match self {
            Source::Image(d) => {
                let from = (off as usize).min(d.len());
                let n = out.len().min(d.len() - from);
                out[..n].copy_from_slice(&d[from..from + n]);
                n
            }
            Source::Written(c) => c.lock().read(off, out),
        }
    }

    /// A VMA backing for `filesz` file bytes at `offset` (zero after them).
    fn backing(&self, offset: u64, filesz: u64, ino: Ino) -> Backing {
        match self {
            Source::Image(data) => Backing::File { data, offset, filesz, ino, shared: None },
            Source::Written(c) => {
                let pinned = c.lock().pin(false);
                Backing::Data { data: c.clone(), offset, end: offset + filesz, ino, shared: None, pinned }
            }
        }
    }
}

pub struct Loaded {
    pub entry: u64,
    /// Load bias (0 for ET_EXEC).
    pub base: u64,
    pub phdr: u64,
    pub phnum: u64,
    /// End of the highest segment, page aligned.
    pub end: u64,
    pub interp: Option<String>,
}

struct Phdr {
    ty: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

fn u16_at(d: &[u8], o: usize) -> Result<u16, &'static str> {
    Ok(u16::from_le_bytes(d.get(o..o + 2).ok_or("truncated ELF")?.try_into().unwrap()))
}

fn u32_at(d: &[u8], o: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(d.get(o..o + 4).ok_or("truncated ELF")?.try_into().unwrap()))
}

fn u64_at(d: &[u8], o: usize) -> Result<u64, &'static str> {
    Ok(u64::from_le_bytes(d.get(o..o + 8).ok_or("truncated ELF")?.try_into().unwrap()))
}

/// Load `src` into `aspace`. For ET_DYN, `base` picks the load address
/// (None = let the address space choose).
pub fn load(aspace: &mut AddressSpace, src: &Source, ino: Ino, base: Option<u64>) -> Result<Loaded, &'static str> {
    let mut header = [0u8; 64];
    let n = src.read(0, &mut header);
    let data = &header[..n];
    if data.get(..4) != Some(b"\x7fELF") {
        return Err("not an ELF file");
    }
    if data.len() < 64 {
        return Err("truncated ELF");
    }
    if data[4] != 2 || data[5] != 1 {
        return Err("not a 64-bit little-endian ELF");
    }
    let ty = u16_at(data, 16)?;
    if u16_at(data, 18)? != crate::arch::ELF_MACHINE {
        return Err(crate::arch::ELF_OTHER_MACHINE);
    }
    if ty != ET_EXEC && ty != ET_DYN {
        return Err("not an executable");
    }
    let entry = u64_at(data, 24)?;
    let phoff = u64_at(data, 32)? as usize;
    if u16_at(data, 54)? as usize != PHDR_SIZE {
        return Err("unexpected program header size");
    }
    let phnum = u16_at(data, 56)? as usize;
    if phnum == 0 || phnum > 512 {
        return Err("bad program header count");
    }

    let mut table = alloc::vec![0u8; phnum * PHDR_SIZE];
    if src.read(phoff as u64, &mut table) != table.len() {
        return Err("truncated ELF");
    }
    let data = &table;
    let mut phdrs = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let o = i * PHDR_SIZE;
        phdrs.push(Phdr {
            ty: u32_at(data, o)?,
            flags: u32_at(data, o + 4)?,
            offset: u64_at(data, o + 8)?,
            vaddr: u64_at(data, o + 16)?,
            filesz: u64_at(data, o + 32)?,
            memsz: u64_at(data, o + 40)?,
        });
    }

    let loads = || phdrs.iter().filter(|p| p.ty == PT_LOAD);
    let lo = page_down(loads().map(|p| p.vaddr).min().ok_or("no loadable segments")?);
    let hi = loads().map(|p| p.vaddr.saturating_add(p.memsz)).max().unwrap();
    let span = page_up(hi).ok_or("bad segment")? - lo;

    let bias = if ty == ET_DYN {
        let at = match base {
            Some(b) => b,
            // Over-allocate so the base can be 64 KiB aligned (common p_align on arm64).
            None => aspace.find_free(span + 0x10000).ok_or("no room for interpreter")?,
        };
        ((at + 0xffff) & !0xffff).wrapping_sub(lo)
    } else {
        0
    };

    let mut end = 0;
    for p in loads() {
        if p.filesz > p.memsz || p.offset.checked_add(p.filesz).is_none_or(|e| e > src.len()) {
            return Err("segment outside file");
        }
        if p.offset % PAGE_SIZE != p.vaddr % PAGE_SIZE {
            return Err("misaligned segment");
        }
        let vstart = bias.checked_add(p.vaddr).ok_or("bad segment address")?;
        let vend = vstart.checked_add(p.memsz).and_then(page_up).ok_or("bad segment address")?;
        if vend > USER_TOP || vstart < PAGE_SIZE {
            return Err("segment outside user address space");
        }
        let start = page_down(vstart);
        let skew = vstart - start;
        aspace.map(Vma::new(start, vend, Prot::from_elf(p.flags), src.backing(p.offset - skew, p.filesz + skew, ino)));
        end = end.max(vend);
    }

    let phdr = match phdrs.iter().find(|p| p.ty == PT_PHDR) {
        Some(p) => bias + p.vaddr,
        None => {
            let seg = loads()
                .find(|p| p.offset <= phoff as u64 && (phoff + phnum * PHDR_SIZE) as u64 <= p.offset + p.filesz)
                .ok_or("program headers not loaded")?;
            bias + seg.vaddr + (phoff as u64 - seg.offset)
        }
    };

    let interp = match phdrs.iter().find(|p| p.ty == PT_INTERP) {
        Some(p) if p.filesz <= 4096 => {
            let mut raw = alloc::vec![0u8; p.filesz as usize];
            if src.read(p.offset, &mut raw) != raw.len() {
                return Err("bad PT_INTERP");
            }
            let raw = raw.split(|&b| b == 0).next().unwrap_or(&raw);
            Some(String::from(core::str::from_utf8(raw).map_err(|_| "bad PT_INTERP")?))
        }
        Some(_) => return Err("bad PT_INTERP"),
        None => None,
    };

    Ok(Loaded { entry: bias + entry, base: bias, phdr, phnum: phnum as u64, end, interp })
}
