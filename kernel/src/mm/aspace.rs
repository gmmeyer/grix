//! User address space: a set of VMAs (virtual memory areas) backed lazily by
//! page faults, plus the page table that realises them.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use grix_abi::stats::Limit;
use spin::Mutex;

use super::paging::{self, ADDR_MASK, PageTable, Prot};
use super::{PAGE_SIZE, frame, p2v, page_down};
use crate::arch;
use crate::errno::*;
use crate::fs::{Content, Ino};

/// User addresses are below 2^48.
pub const USER_TOP: u64 = crate::arch::USER_TOP;
pub const STACK_TOP: u64 = USER_TOP - 0x2_0000;
/// RLIMIT_STACK's default, as on Linux.
pub const STACK_SIZE: u64 = 8 << 20;
/// The biggest stack exec makes (for an unlimited RLIMIT_STACK too). It's
/// only address space until touched.
pub const MAX_STACK: u64 = 4 << 30;
/// No mmap without a hint comes closer to the stack than this, nor one
/// with a hint closer than Linux's stack_guard_gap.
const STACK_GAP: u64 = 128 << 20;
const STACK_GUARD: u64 = 1 << 20;
/// The signal-return trampoline page, above the stack.
pub const SIGPAGE: u64 = STACK_TOP + 0x1_0000;
/// The vDSO's clock parameters, and the vDSO just after (vdso.rs).
pub const VVAR: u64 = SIGPAGE + 0x2000;
pub const VDSO: u64 = VVAR + PAGE_SIZE;
/// At most this many mappings (Linux's vm.max_map_count is 65530): each
/// takes kernel heap, so a program mapping page after page gets ENOMEM.
pub const MAX_VMAS: usize = 32768;
/// Mappings in all address spaces together: fork copies them, so the
/// per-process limit alone doesn't bound kernel memory.
pub const MAX_VMAS_TOTAL: usize = 65536;
static VMAS_TOTAL: AtomicUsize = AtomicUsize::new(0);
pub const MMAP_BOTTOM: u64 = 1 << 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Exec,
}

impl Access {
    pub fn describe_violation(self) -> &'static str {
        match self {
            Access::Read => "invalid read",
            Access::Write => "invalid write",
            Access::Exec => "invalid instruction fetch",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Backing {
    /// Zero-filled on first touch.
    Anon,
    /// Private file mapping. Byte `o` of the VMA is `data[offset + o]` while
    /// `o < filesz`, and zero after that (ELF .bss). `ino` names the file.
    File { data: &'static [u8], offset: u64, filesz: u64, ino: Ino, shared: Option<Arc<()>> },
    /// Private copy of a file written in the sandbox: each page is copied
    /// from byte `offset + o` of the file when it faults in. File bytes at
    /// or past `end` read as zero (an ELF segment's .bss).
    Data { data: Content, offset: u64, end: u64, ino: Ino, shared: Option<Arc<()>> },
    /// Each page starts with the signal-return trampoline (`arch::sigframe::TRAMPOLINE`).
    Sigpage,
    /// MAP_SHARED anonymous memory: page `index + o / PAGE_SIZE` of
    /// `pages`, which every mapping of it sees, in every process that
    /// shares it since a fork. Never copy-on-write.
    /// `may_write`: mprotect may add PROT_WRITE (not for a System V
    /// segment attached SHM_RDONLY); `sysv`: the segment it is.
    Shared { pages: Arc<SharedPages>, index: u64, may_write: bool, sysv: Option<Sysv> },
    /// MAP_SHARED of a file in the sandbox: the file's own pages (byte
    /// `offset + o`), so writes through the mapping are the file's and the
    /// file's writes show in it. Never copy-on-write. `may_write`: the fd
    /// was open for writing (mprotect may add PROT_WRITE). `token` counts
    /// it among the file's shared mappings (`FileData::mapped_shared`).
    SharedFile { data: Content, offset: u64, ino: Ino, may_write: bool, token: Arc<()> },
    /// A page of the kernel's that every process shares, read-only (the
    /// vDSO's): the frame at `pa`, which the kernel holds a reference to.
    KernelPage(u64),
}

/// Bytes of a mapping in memory, by kind (`AddressSpace::usage`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Usage {
    pub rss: u64,
    pub pss: u64,
    pub shared_clean: u64,
    pub shared_dirty: u64,
    pub private_clean: u64,
    pub private_dirty: u64,
    pub anonymous: u64,
}

impl Usage {
    pub fn add(&mut self, o: &Usage) {
        self.rss += o.rss;
        self.pss += o.pss;
        self.shared_clean += o.shared_clean;
        self.shared_dirty += o.shared_dirty;
        self.private_clean += o.private_clean;
        self.private_dirty += o.private_dirty;
        self.anonymous += o.anonymous;
    }
}

/// A System V shared memory segment, as its mappings know it: its key and
/// id (for /proc/<pid>/maps) and its size in pages.
#[derive(Clone, Copy, Debug)]
pub struct Sysv {
    pub key: i32,
    pub id: u32,
    pub pages: u64,
}

/// The pages of a MAP_SHARED anonymous mapping (or a System V segment),
/// made as they're first touched. Holds a reference to each (every
/// mapping holds its own). Their addresses are kept in chunks of
/// `SHARED_CHUNK` (2 MiB of the mapping each), charged to the kernel
/// memory budget: a program can touch a lot of shared memory.
#[derive(Debug, Default)]
pub struct SharedPages(Mutex<SharedChunks>);

const SHARED_CHUNK: usize = 512;
/// A chunk's page that has no frame yet.
const NO_FRAME: u64 = u64::MAX;

#[derive(Debug, Default)]
struct SharedChunks {
    chunks: BTreeMap<u64, alloc::boxed::Box<[u64; SHARED_CHUNK]>>,
    charge: crate::kmem::Charge,
}

impl SharedPages {
    /// Page `idx`'s frame, made if it has none.
    fn frame(&self, idx: u64) -> Result<u64, FaultError> {
        let mut s = self.0.lock();
        let (chunk, i) = (idx / SHARED_CHUNK as u64, (idx % SHARED_CHUNK as u64) as usize);
        if !s.chunks.contains_key(&chunk) {
            let bytes = s.charge.bytes() + (SHARED_CHUNK * 8) as u64;
            s.charge.resize(bytes).map_err(|_| FaultError::OutOfMemory)?;
            s.chunks.insert(chunk, alloc::boxed::Box::new([NO_FRAME; SHARED_CHUNK]));
        }
        let slot = &mut s.chunks.get_mut(&chunk).unwrap()[i];
        if *slot == NO_FRAME {
            *slot = frame::alloc().ok_or(FaultError::OutOfMemory)?;
        }
        Ok(*slot)
    }
}

impl Drop for SharedPages {
    fn drop(&mut self) {
        for chunk in self.0.get_mut().chunks.values() {
            for &pa in chunk.iter().filter(|&&pa| pa != NO_FRAME) {
                frame::free(pa);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
    pub backing: Backing,
}

impl Vma {
    pub fn anon(start: u64, end: u64, prot: Prot) -> Self {
        Vma { start, end, prot, backing: Backing::Anon }
    }

    /// The sub-range `[s, e)` of this VMA, with file offsets adjusted.
    pub fn slice(&self, s: u64, e: u64) -> Vma {
        debug_assert!(self.start <= s && s < e && e <= self.end);
        let skip = s - self.start;
        let backing = match self.backing {
            Backing::Anon => Backing::Anon,
            Backing::Data { ref data, offset, end, ino, ref shared } => Backing::Data {
                data: data.clone(),
                offset: offset.saturating_add(skip),
                end,
                ino,
                shared: shared.clone(),
            },
            Backing::Sigpage => Backing::Sigpage,
            Backing::KernelPage(pa) => Backing::KernelPage(pa),
            Backing::Shared { ref pages, index, may_write, sysv } => {
                Backing::Shared { pages: pages.clone(), index: index + skip / PAGE_SIZE, may_write, sysv }
            }
            Backing::SharedFile { ref data, offset, ino, may_write, ref token } => Backing::SharedFile {
                data: data.clone(),
                offset: offset.saturating_add(skip),
                ino,
                may_write,
                token: token.clone(),
            },
            Backing::File { data, offset, filesz, ino, ref shared } => Backing::File {
                data,
                offset: offset.saturating_add(skip),
                filesz: filesz.saturating_sub(skip),
                ino,
                shared: shared.clone(),
            },
        };
        Vma { start: s, end: e, prot: self.prot, backing }
    }

    /// A MAP_SHARED file mapping that only holds a copy of the file (a
    /// live mount's).
    pub fn is_shared_file(&self) -> bool {
        matches!(self.backing, Backing::File { shared: Some(_), .. } | Backing::Data { shared: Some(_), .. })
    }

    /// Never copy-on-write: its pages are the same for everyone.
    fn shared_pages(&self) -> bool {
        matches!(self.backing, Backing::Shared { .. } | Backing::SharedFile { .. } | Backing::KernelPage(_))
    }

    pub fn allows(&self, access: Access) -> bool {
        match access {
            Access::Read => !self.prot.is_none(),
            Access::Write => self.prot.write,
            Access::Exec => self.prot.exec,
        }
    }
}

/// The pages whose entries changed, for a flush of just those
/// (`AddressSpace::flush`).
struct Span {
    lo: u64,
    hi: u64,
}

impl Span {
    fn new() -> Self {
        Span { lo: u64::MAX, hi: 0 }
    }

    fn add(&mut self, va: u64) {
        self.lo = self.lo.min(va);
        self.hi = self.hi.max(va + PAGE_SIZE);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultError {
    /// No mapping, or the mapping forbids this access.
    Segv,
    OutOfMemory,
    /// The file behind the mapping couldn't be read (a live mount's).
    Io,
    /// A shared file mapping's page past the end of the file (SIGBUS).
    PastEnd,
}

pub struct AddressSpace {
    pub pt: PageTable,
    vmas: BTreeMap<u64, Vma>,
    /// How many of `vmas` are counted in VMAS_TOTAL.
    counted: usize,
    pub brk_start: u64,
    pub brk: u64,
    /// The stack is [STACK_TOP - stack_size, STACK_TOP); mmap allocates
    /// top-down from `mmap_top`, a gap below it.
    stack_size: u64,
    mmap_top: u64,
}

impl Drop for AddressSpace {
    /// Release every page (shared ones lose a reference). Must not be the
    /// active address space.
    fn drop(&mut self) {
        self.pt.for_each_mapped(0, USER_TOP, |_, pte| unsafe {
            frame::free(*pte & ADDR_MASK);
            *pte = 0;
        });
        VMAS_TOTAL.fetch_sub(self.counted, Ordering::Relaxed);
    }
}

impl AddressSpace {
    pub fn new() -> Option<Self> {
        let mut a = Self {
            pt: PageTable::new()?,
            vmas: BTreeMap::new(),
            counted: 0,
            brk_start: 0,
            brk: 0,
            stack_size: 0,
            mmap_top: 0,
        };
        a.set_stack(STACK_SIZE);
        Some(a)
    }

    /// Where the stack goes (exec maps it), and so where mmap starts.
    pub fn set_stack(&mut self, size: u64) {
        self.stack_size = size;
        self.mmap_top = STACK_TOP - size - STACK_GAP;
    }

    /// The stack's lowest address.
    pub fn stack_bottom(&self) -> u64 {
        STACK_TOP - self.stack_size
    }

    /// May a mapping end at `end` without a MAP_FIXED? Not within the
    /// stack's guard gap, or above it.
    pub fn clear_of_stack(&self, end: u64) -> bool {
        end <= self.stack_bottom() - STACK_GUARD
    }

    /// Bring VMAS_TOTAL up to date after the mappings changed.
    fn recount(&mut self) {
        let n = self.vmas.len();
        VMAS_TOTAL.fetch_add(n, Ordering::Relaxed);
        VMAS_TOTAL.fetch_sub(self.counted, Ordering::Relaxed);
        self.counted = n;
    }

    /// A copy for a forked child: the same mappings, sharing every page.
    /// Writable pages become read-only in both, and the first write to one
    /// copies it (`fault`'s copy-on-write).
    pub fn fork(&mut self) -> Result<AddressSpace, Errno> {
        if VMAS_TOTAL.load(Ordering::Relaxed) + self.vmas.len() > MAX_VMAS_TOTAL {
            crate::stats::hit(Limit::Mappings);
            return Err(ENOMEM);
        }
        let mut child = AddressSpace::new().ok_or(ENOMEM)?;
        child.vmas = self.vmas.clone();
        child.recount();
        child.brk_start = self.brk_start;
        child.brk = self.brk;
        child.set_stack(self.stack_size);
        let mut out_of_memory = false;
        // Entries made read-only: until the flush, other CPUs running the
        // parent's threads may still write through their old ones.
        let mut downgraded = Span::new();
        for v in self.vmas.values() {
            let cow = v.prot.write && !v.shared_pages();
            self.pt.for_each_mapped(v.start, v.end, |va, pte| unsafe {
                if out_of_memory {
                    return;
                }
                let shared = if cow { paging::read_only(*pte) } else { *pte };
                if shared != *pte {
                    downgraded.add(va);
                }
                let pa = shared & ADDR_MASK;
                if !frame::share(pa) {
                    out_of_memory = true;
                    return;
                }
                if child.pt.map(va, pa, shared & !ADDR_MASK).is_none() {
                    frame::free(pa);
                    out_of_memory = true;
                }
                *pte = shared;
            });
        }
        self.flush(downgraded);
        // The child is dropped, which releases what it got; the parent's
        // pages are just read-only now, and fault back in writable.
        if out_of_memory { Err(ENOMEM) } else { Ok(child) }
    }

    /// The page at `page` is mapped read-only in a writable mapping: it's
    /// shared with a forked process. Copy it, unless nobody else has it
    /// any more, then make it writable.
    fn unshare(&mut self, page: u64, pte: u64, prot: Prot) -> Result<(), FaultError> {
        let old = pte & ADDR_MASK;
        let pa = if frame::is_shared(old) {
            let new = frame::alloc().ok_or(FaultError::OutOfMemory)?;
            // SAFETY: both frames are mapped linearly; `new` is ours alone.
            unsafe { core::ptr::copy_nonoverlapping(p2v(old) as *const u8, p2v(new) as *mut u8, PAGE_SIZE as usize) };
            frame::free(old);
            new
        } else {
            old
        };
        if prot.exec {
            arch::sync_icache(p2v(pa), PAGE_SIZE);
        }
        // Break before make: the old entry is gone from every CPU's TLB
        // before the new one, to another page, appears (in an invalid
        // slot, which no TLB holds: nothing more to flush). The same page
        // made writable is flushed too: a CPU still holding it read-only
        // would fault on the kernel's own writes there (`ensure` sees the
        // new entry, the TLB has the old).
        if pa != old {
            self.pt.for_each_mapped(page, page + PAGE_SIZE, |_, pte| unsafe { *pte = 0 });
            self.flush_page(page);
        }
        self.pt.map(page, pa, prot.pte_flags()).ok_or(FaultError::OutOfMemory)?;
        if pa == old {
            self.flush_page(page);
        }
        Ok(())
    }

    /// Forget the entries of `span` (if any) on every CPU that may hold
    /// them: before a page they mapped is freed or mapped elsewhere.
    fn flush(&self, span: Span) {
        if span.lo < span.hi {
            arch::flush_tlb(self.pt.root, span.lo, span.hi);
        }
    }

    fn flush_page(&self, page: u64) {
        arch::flush_tlb(self.pt.root, page, page + PAGE_SIZE);
    }

    pub fn activate(&self) {
        arch::set_user_page_table(self.pt.root);
    }

    /// What a mapping's resident pages are (`/proc/<pid>/smaps`), from
    /// its page table and each frame's reference count: a frame others map
    /// too is shared, one of the kernel's or an imported file's is clean.
    pub fn usage(&self, v: &Vma) -> Usage {
        let mut u = Usage::default();
        let kernel = matches!(v.backing, Backing::KernelPage(_) | Backing::Sigpage);
        let shmem = matches!(v.backing, Backing::Shared { .. } | Backing::SharedFile { .. });
        self.pt.each_entry(v.start, v.end, |pte| {
            let refs = frame::mappings(pte & ADDR_MASK) as u64;
            let dirty = refs != 0 && !kernel;
            let shared = refs != 1;
            u.rss += PAGE_SIZE;
            u.pss += PAGE_SIZE / refs.max(1);
            *match (shared, dirty) {
                (true, false) => &mut u.shared_clean,
                (true, true) => &mut u.shared_dirty,
                (false, false) => &mut u.private_clean,
                (false, true) => &mut u.private_dirty,
            } += PAGE_SIZE;
            if dirty && !shmem {
                u.anonymous += PAGE_SIZE;
            }
        });
        u
    }

    pub fn vmas(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.values()
    }

    /// The mappings overlapping `[start, end)`, last first. They're sorted and
    /// disjoint, so walking back from `end` stops at the first one that ends
    /// before `start`: O(log n + k), not a scan of everything below `end`.
    fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = &Vma> {
        self.vmas.range(..end).rev().map(|(_, v)| v).take_while(move |v| v.end > start)
    }

    /// Room for `more` mappings (an operation that may split some)?
    pub fn has_room(&self, more: usize) -> Result<(), Errno> {
        if self.vmas.len() + more > MAX_VMAS || VMAS_TOTAL.load(Ordering::Relaxed) + more > MAX_VMAS_TOTAL {
            crate::stats::hit(Limit::Mappings);
            Err(ENOMEM)
        } else {
            Ok(())
        }
    }

    /// Would changing `[start, end)` stay within MAX_VMAS? The mappings it
    /// overlaps are cut at its edges; with `keep` (mprotect) their middle
    /// parts stay as mappings, otherwise (munmap, MAP_FIXED) they go, and
    /// `added` new ones are mapped.
    pub fn room_for(&self, start: u64, end: u64, keep: bool, added: usize) -> Result<(), Errno> {
        let overlapping: Vec<&Vma> = self.overlapping(start, end).collect();
        let edges =
            overlapping.iter().filter(|v| v.start < start).count() + overlapping.iter().filter(|v| v.end > end).count();
        let after = self.vmas.len() - overlapping.len() + edges + if keep { overlapping.len() } else { 0 } + added;
        let growth = after.saturating_sub(self.vmas.len());
        if growth > 0 && (after > MAX_VMAS || VMAS_TOTAL.load(Ordering::Relaxed) + growth > MAX_VMAS_TOTAL) {
            crate::stats::hit(Limit::Mappings);
            Err(ENOMEM)
        } else {
            Ok(())
        }
    }

    /// Grow the anonymous mapping that ends at `end` up to `new_end`, if
    /// there is one with this protection (brk). Returns whether it did.
    pub fn extend_anon(&mut self, end: u64, new_end: u64, prot: Prot) -> bool {
        let Some((_, v)) = self.vmas.range_mut(..end).next_back() else { return false };
        if v.end != end || v.prot != prot || !matches!(v.backing, Backing::Anon) {
            return false;
        }
        v.end = new_end;
        true
    }

    pub fn find(&self, va: u64) -> Option<&Vma> {
        self.vmas.range(..=va).next_back().map(|(_, v)| v).filter(|v| va < v.end)
    }

    pub fn is_free(&self, start: u64, end: u64) -> bool {
        start < end && end <= USER_TOP && self.vmas.range(..end).next_back().is_none_or(|(_, v)| v.end <= start)
    }

    /// Highest free `len`-byte range below `mmap_top`.
    pub fn find_free(&self, len: u64) -> Option<u64> {
        let mut end = self.mmap_top;
        for (_, v) in self.vmas.range(..self.mmap_top).rev() {
            if v.end <= end && end - v.end >= len {
                return Some(end - len);
            }
            end = end.min(v.start);
        }
        (end >= MMAP_BOTTOM + len).then(|| end - len)
    }

    /// Insert a mapping, replacing anything already in its range (MAP_FIXED semantics).
    pub fn map(&mut self, vma: Vma) {
        self.unmap(vma.start, vma.end);
        self.vmas.insert(vma.start, vma);
        self.recount();
    }

    /// Remove `[start, end)` from the VMA set without touching pages.
    /// Returns the removed pieces in ascending order.
    fn carve(&mut self, start: u64, end: u64) -> Vec<Vma> {
        let keys: Vec<u64> = self.vmas.range(..end).rev().take_while(|(_, v)| v.end > start).map(|(k, _)| *k).collect();
        let mut removed = Vec::with_capacity(keys.len());
        for k in keys.into_iter().rev() {
            let v = self.vmas.remove(&k).unwrap();
            if v.start < start {
                self.vmas.insert(v.start, v.slice(v.start, start));
            }
            if v.end > end {
                self.vmas.insert(end, v.slice(end, v.end));
            }
            removed.push(v.slice(v.start.max(start), v.end.min(end)));
        }
        removed
    }

    /// munmap: drop mappings and free their pages.
    pub fn unmap(&mut self, start: u64, end: u64) {
        self.carve(start, end);
        self.discard(start, end);
        self.recount();
    }

    /// Free the pages in `[start, end)` but keep the VMAs; the next access
    /// faults in fresh zero (or file) contents. MADV_DONTNEED semantics.
    pub fn discard(&mut self, start: u64, end: u64) {
        let mut freed = Vec::new();
        let mut span = Span::new();
        self.pt.for_each_mapped(start, end, |va, pte| unsafe {
            freed.push(*pte & ADDR_MASK);
            span.add(va);
            *pte = 0;
        });
        // Other CPUs may still have the pages in their TLBs until this.
        self.flush(span);
        for pa in freed {
            frame::free(pa);
        }
    }

    /// Does `[start, end)` overlap a MAP_SHARED file mapping that only
    /// holds a copy (a live mount's)?
    pub fn has_shared_file(&self, start: u64, end: u64) -> bool {
        self.overlapping(start, end).any(Vma::is_shared_file)
    }

    /// Does `[start, end)` overlap a shared mapping of a file whose fd
    /// wasn't open for writing, or a page of the kernel's (mprotect can't
    /// make those writable)?
    pub fn has_read_only_shared_file(&self, start: u64, end: u64) -> bool {
        self.overlapping(start, end).any(|v| {
            matches!(
                v.backing,
                Backing::SharedFile { may_write: false, .. }
                    | Backing::Shared { may_write: false, .. }
                    | Backing::KernelPage(_)
            )
        })
    }

    /// Pages that got a frame since this address space's shared mappings
    /// took read-only copies of them ((file id, page index), from
    /// `fs::take_stale`): the copies go, and the next access maps the frame.
    pub fn zap_stale(&mut self, stale: &[(usize, u64)]) {
        let mut pages = Vec::new();
        for v in self.vmas.values() {
            let Backing::SharedFile { data, offset, .. } = &v.backing else { continue };
            let id = data.lock().id();
            for &(file, idx) in stale {
                let at = idx * PAGE_SIZE;
                if file == id && at >= *offset && at - offset < v.end - v.start {
                    pages.push(v.start + (at - offset));
                }
            }
        }
        for va in pages {
            self.discard(va, va + PAGE_SIZE);
        }
    }

    /// `data` shrank to `len`: its pages past the end go from this address
    /// space's shared mappings of it (they fault with SIGBUS from now on).
    pub fn zap_file(&mut self, data: &Content, len: u64) {
        let keep = len.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let ranges: Vec<(u64, u64)> = self
            .vmas
            .values()
            .filter_map(|v| match &v.backing {
                Backing::SharedFile { data: d, offset, .. } if Arc::ptr_eq(d, data) => {
                    let from = v.start + keep.saturating_sub(*offset);
                    (from < v.end).then_some((from, v.end))
                }
                _ => None,
            })
            .collect();
        for (s, e) in ranges {
            self.discard(s, e);
        }
    }

    /// mprotect. Fails with ENOMEM if any part of the range is unmapped.
    pub fn protect(&mut self, start: u64, end: u64, prot: Prot) -> Result<(), Errno> {
        let mut pieces: Vec<(u64, u64)> = self.overlapping(start, end).map(|v| (v.start, v.end)).collect();
        pieces.reverse();
        let mut expected = start;
        for (s, e) in pieces {
            if s > expected {
                return Err(ENOMEM);
            }
            expected = e;
        }
        if expected < end {
            return Err(ENOMEM);
        }
        let flags = prot.pte_flags();
        // Only entries that were there and changed can be in a TLB as they
        // were (thread stacks, mapped PROT_NONE and then opened up, have
        // none yet).
        let mut changed = Span::new();
        for mut piece in self.carve(start, end) {
            piece.prot = prot;
            // A page shared with a forked process stays read-only until
            // it's written (and copied); shared memory is meant to be shared.
            let cow = prot.write && !piece.shared_pages();
            self.pt.for_each_mapped(piece.start, piece.end, |va, pte| unsafe {
                let pa = *pte & ADDR_MASK;
                let new = if cow && frame::is_shared(pa) { paging::read_only(pa | flags) } else { pa | flags };
                if new != *pte {
                    changed.add(va);
                }
                *pte = new;
                if prot.exec {
                    arch::sync_icache(p2v(pa), PAGE_SIZE);
                }
            });
            self.vmas.insert(piece.start, piece);
        }
        self.recount();
        self.flush(changed);
        Ok(())
    }

    /// mremap. `old`/`new_len`/`old_len` are page aligned.
    /// `fixed`: move it to exactly there (MREMAP_FIXED), checked by the caller.
    pub fn remap(
        &mut self,
        old: u64,
        old_len: u64,
        new_len: u64,
        may_move: bool,
        fixed: Option<u64>,
    ) -> Result<u64, Errno> {
        let old_end = old.checked_add(old_len).ok_or(EINVAL)?;
        let vma = self.find(old).filter(|v| old_end <= v.end).ok_or(EFAULT)?.clone();
        if let Some(to) = fixed {
            self.unmap(to, to + new_len);
            if new_len < old_len {
                self.unmap(old + new_len, old_end);
            }
            return self.move_to(&vma, old, old_len.min(new_len), new_len, to);
        }
        if new_len <= old_len {
            self.unmap(old + new_len, old_end);
            return Ok(old);
        }
        let grow_end = old.checked_add(new_len).ok_or(ENOMEM)?;
        if old_end == vma.end && self.is_free(old_end, grow_end) {
            let mut ext = vma.slice(vma.start, vma.end);
            ext.start = vma.start;
            ext.end = grow_end;
            self.vmas.insert(vma.start, ext);
            return Ok(old);
        }
        if !may_move {
            return Err(ENOMEM);
        }
        let new = self.find_free(new_len).ok_or(ENOMEM)?;
        self.move_to(&vma, old, old_len, new_len, new)
    }

    /// Move `[old, old + old_len)` of `vma`, pages and all, to `new`, as a
    /// mapping `new_len` long.
    fn move_to(&mut self, vma: &Vma, old: u64, old_len: u64, new_len: u64, new: u64) -> Result<u64, Errno> {
        let old_end = old + old_len;
        // Move existing pages rather than copying them.
        let mut pages = Vec::new();
        self.pt.for_each_mapped(old, old_end, |va, pte| unsafe {
            pages.push((va - old, *pte));
            *pte = 0;
        });
        self.carve(old, old_end);
        let mut moved = vma.slice(old, old_end);
        moved.start = new;
        moved.end = new + new_len;
        self.vmas.insert(new, moved);
        self.recount();
        // The new slots were unmapped (no TLB holds them); the old entries
        // must go from every TLB, whatever happens to the new ones.
        let moved = !pages.is_empty();
        let mut result = Ok(new);
        for (off, pte) in pages {
            if self.pt.map(new + off, pte & ADDR_MASK, pte & !ADDR_MASK).is_none() {
                result = Err(ENOMEM);
                break;
            }
        }
        if moved {
            arch::flush_tlb(self.pt.root, old, old_end);
        }
        result
    }

    /// Resolve a fault: an unmapped page, or a write to one shared
    /// copy-on-write.
    pub fn fault(&mut self, va: u64, access: Access) -> Result<(), FaultError> {
        let page = page_down(va);
        let vma = self.find(va).ok_or(FaultError::Segv)?.clone();
        if !vma.allows(access) {
            return Err(FaultError::Segv);
        }
        if let Some(pte) = self.pt.lookup(page) {
            return match vma.backing {
                // Mapped, and allowed: another CPU's fault got there first
                // (or a TLB had an old entry). The access is tried again.
                _ if access != Access::Write || paging::writable(pte) => Ok(()),
                // Writing a page it has a read-only copy of: the file's frame
                // replaces it.
                Backing::SharedFile { ref data, offset, .. } => {
                    let idx = offset.saturating_add(page - vma.start) / PAGE_SIZE;
                    let pa = data.lock().shared_frame(idx, true)?.expect("a frame for a write");
                    let old = pte & ADDR_MASK;
                    if old != pa && !frame::share(pa) {
                        return Err(FaultError::OutOfMemory);
                    }
                    // Break before make, as in `unshare`.
                    if old != pa {
                        self.pt.for_each_mapped(page, page + PAGE_SIZE, |_, pte| unsafe { *pte = 0 });
                        self.flush_page(page);
                        frame::free(old);
                    }
                    let mapped = self.pt.map(page, pa, vma.prot.pte_flags());
                    if mapped.is_none() && old != pa {
                        frame::free(pa);
                    }
                    mapped.ok_or(FaultError::OutOfMemory)?;
                    if old == pa {
                        self.flush_page(page);
                    }
                    Ok(())
                }
                Backing::Shared { .. } => {
                    self.pt.map(page, pte & ADDR_MASK, vma.prot.pte_flags()).ok_or(FaultError::OutOfMemory)?;
                    self.flush_page(page);
                    Ok(())
                }
                _ => self.unshare(page, pte, vma.prot),
            };
        }
        if let Backing::KernelPage(pa) = vma.backing {
            if !frame::share(pa) {
                return Err(FaultError::OutOfMemory);
            }
            if self.pt.map(page, pa, vma.prot.pte_flags()).is_none() {
                frame::free(pa);
                return Err(FaultError::OutOfMemory);
            }
            return Ok(());
        }
        if let Backing::Shared { ref pages, index, sysv, .. } = vma.backing {
            let idx = index + (page - vma.start) / PAGE_SIZE;
            // Past a System V segment's end (mremap made the mapping
            // longer): SIGBUS, as on Linux.
            if sysv.is_some_and(|s| idx >= s.pages) {
                return Err(FaultError::PastEnd);
            }
            let pa = pages.frame(idx)?;
            if vma.prot.exec {
                arch::sync_icache(p2v(pa), PAGE_SIZE);
            }
            if !frame::share(pa) {
                return Err(FaultError::OutOfMemory);
            }
            if self.pt.map(page, pa, vma.prot.pte_flags()).is_none() {
                frame::free(pa);
                return Err(FaultError::OutOfMemory);
            }
            return Ok(());
        }
        if let Backing::SharedFile { ref data, offset, .. } = vma.backing {
            let idx = offset.saturating_add(page - vma.start) / PAGE_SIZE;
            let mut d = data.lock();
            let (pa, flags) = match d.shared_frame(idx, access == Access::Write)? {
                // The mapping's own reference; the file keeps its.
                Some(pa) => {
                    if !frame::share(pa) {
                        return Err(FaultError::OutOfMemory);
                    }
                    (pa, vma.prot.pte_flags())
                }
                // A read-only copy, until someone writes the page.
                None => {
                    let pa = frame::alloc().ok_or(FaultError::OutOfMemory)?;
                    // SAFETY: `pa` is the frame just allocated, mapped linearly.
                    let dst = unsafe { core::slice::from_raw_parts_mut(p2v(pa) as *mut u8, PAGE_SIZE as usize) };
                    dst.fill(0);
                    let _ = d.read_at(idx * PAGE_SIZE, dst);
                    d.copied_page(idx);
                    (pa, Prot { write: false, ..vma.prot }.pte_flags())
                }
            };
            drop(d);
            if vma.prot.exec {
                arch::sync_icache(p2v(pa), PAGE_SIZE);
            }
            if self.pt.map(page, pa, flags).is_none() {
                frame::free(pa);
                return Err(FaultError::OutOfMemory);
            }
            return Ok(());
        }
        let pa = frame::alloc().ok_or(FaultError::OutOfMemory)?;
        let src: &[u8] = match vma.backing {
            Backing::Anon => &[],
            Backing::Data { ref data, offset, end, .. } => {
                // SAFETY: `pa` is the frame just allocated, mapped linearly.
                let dst = unsafe { core::slice::from_raw_parts_mut(p2v(pa) as *mut u8, PAGE_SIZE as usize) };
                let at = offset.saturating_add(page - vma.start);
                let n = end.saturating_sub(at).min(PAGE_SIZE) as usize;
                if data.lock().read_at(at, &mut dst[..n]).is_err() {
                    frame::free(pa);
                    return Err(FaultError::Io);
                }
                &[]
            }
            Backing::Sigpage => &crate::arch::sigframe::TRAMPOLINE,
            Backing::Shared { .. } | Backing::SharedFile { .. } | Backing::KernelPage(_) => {
                unreachable!("handled above")
            }
            Backing::File { data, offset, filesz, .. } => {
                let o = page - vma.start;
                let n = filesz.saturating_sub(o).min(PAGE_SIZE);
                let src = offset.saturating_add(o).min(data.len() as u64);
                let avail = (data.len() as u64 - src).min(n);
                &data[src as usize..(src + avail) as usize]
            }
        };
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), p2v(pa) as *mut u8, src.len()) };
        if vma.prot.exec {
            arch::sync_icache(p2v(pa), PAGE_SIZE);
        }
        if self.pt.map(page, pa, vma.prot.pte_flags()).is_none() {
            frame::free(pa);
            return Err(FaultError::OutOfMemory);
        }
        Ok(())
    }

    /// Make sure the kernel can access `[addr, addr+len)` on behalf of the
    /// user: every page must be in a VMA that permits the access, and gets
    /// faulted in now so the kernel itself never takes a page fault.
    pub fn ensure(&mut self, addr: u64, len: u64, write: bool) -> Result<(), Errno> {
        if len == 0 {
            return Ok(());
        }
        let end = addr.checked_add(len).ok_or(EFAULT)?;
        if end > USER_TOP {
            return Err(EFAULT);
        }
        let access = if write { Access::Write } else { Access::Read };
        let mut page = page_down(addr);
        while page < end {
            if !self.find(page).ok_or(EFAULT)?.allows(access) {
                return Err(EFAULT);
            }
            let pte = self.pt.lookup(page);
            // Not there yet, or shared copy-on-write and about to be written:
            // the kernel's own access must not fault.
            if pte.is_none_or(|pte| write && !paging::writable(pte)) {
                self.fault(page, access).map_err(|e| match e {
                    FaultError::OutOfMemory => ENOMEM,
                    FaultError::Segv => EFAULT,
                    FaultError::Io => EIO,
                    FaultError::PastEnd => EFAULT,
                })?;
            }
            page += PAGE_SIZE;
        }
        Ok(())
    }
}
