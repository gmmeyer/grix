//! ELF64 (AArch64) loader. Segments become file-backed VMAs that are paged in
//! on demand straight from the boot image.

use crate::fs::Ino;
use crate::mm::aspace::{AddressSpace, Backing, USER_TOP, Vma};
use crate::mm::paging::Prot;
use crate::mm::{PAGE_SIZE, page_down, page_up};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PHDR_SIZE: usize = 56;

/// Where position-independent main executables go (like Linux's ELF_ET_DYN_BASE).
pub const DYN_BASE: u64 = 0x0000_aaaa_aaa0_0000;

pub struct Loaded {
    pub entry: u64,
    /// Load bias (0 for ET_EXEC).
    pub base: u64,
    pub phdr: u64,
    pub phnum: u64,
    /// End of the highest segment, page aligned.
    pub end: u64,
    pub interp: Option<&'static str>,
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

/// Load `data` into `aspace`. For ET_DYN, `base` picks the load address
/// (None = let the address space choose).
pub fn load(
    aspace: &mut AddressSpace,
    data: &'static [u8],
    ino: Ino,
    base: Option<u64>,
) -> Result<Loaded, &'static str> {
    if data.get(..4) != Some(b"\x7fELF") {
        return Err("not an ELF file");
    }
    if data[4] != 2 || data[5] != 1 {
        return Err("not a 64-bit little-endian ELF");
    }
    let ty = u16_at(data, 16)?;
    if u16_at(data, 18)? != EM_AARCH64 {
        return Err("not an AArch64 binary");
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

    let mut phdrs = alloc::vec::Vec::with_capacity(phnum);
    for i in 0..phnum {
        let o = phoff.checked_add(i * PHDR_SIZE).ok_or("bad phoff")?;
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
        if p.filesz > p.memsz || p.offset.checked_add(p.filesz).is_none_or(|e| e > data.len() as u64) {
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
        aspace.map(Vma {
            start,
            end: vend,
            prot: Prot::from_elf(p.flags),
            backing: Backing::File { data, offset: p.offset - skew, filesz: p.filesz + skew, ino, shared: None },
        });
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
        Some(p) => {
            let raw = data.get(p.offset as usize..(p.offset + p.filesz) as usize).ok_or("bad PT_INTERP")?;
            let raw = raw.split(|&b| b == 0).next().unwrap_or(raw);
            Some(core::str::from_utf8(raw).map_err(|_| "bad PT_INTERP")?)
        }
        None => None,
    };

    Ok(Loaded { entry: bias + entry, base: bias, phdr, phnum: phnum as u64, end, interp })
}
