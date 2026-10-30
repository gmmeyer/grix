//! A sparse map from a page's index (in a file, or a shared mapping) to
//! the frame holding it, as a radix tree whose nodes are frames of 512
//! entries, like a page table's. A file's pages are as many as RAM's, and
//! the heap is 32 MiB: a tree on the heap would outgrow it long before
//! RAM ran out, where this costs a frame per 2 MiB (plus a few for a
//! sparse file), taken from RAM like the pages themselves.

use super::{PAGE_SIZE, frame, p2v};

const BITS: u32 = 9;
const FANOUT: u64 = 1 << BITS;
/// Levels enough for any page of a file (`i64::MAX` bytes).
const MAX_LEVELS: u32 = 6;

#[derive(Debug, Default)]
pub struct PageIndex {
    /// The root node's frame (0: none), covering `FANOUT^levels` pages.
    root: u64,
    levels: u32,
    /// Frames mapped, and node frames.
    len: u64,
    nodes: u64,
}

fn node(pa: u64) -> *mut u64 {
    p2v(pa) as *mut u64
}

/// Entry `i` of node `pa` (0: empty).
fn get(pa: u64, i: u64) -> u64 {
    debug_assert!(i < FANOUT);
    // SAFETY: a node is a frame of FANOUT entries, mapped linearly.
    unsafe { node(pa).add(i as usize).read() }
}

fn set(pa: u64, i: u64, v: u64) {
    debug_assert!(i < FANOUT);
    // SAFETY: as in `get`.
    unsafe { node(pa).add(i as usize).write(v) }
}

impl PageIndex {
    pub const fn new() -> PageIndex {
        PageIndex { root: 0, levels: 0, len: 0, nodes: 0 }
    }

    /// Pages mapped.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Frames the tree itself takes.
    pub fn nodes(&self) -> u64 {
        self.nodes
    }

    /// The pages the tree covers.
    fn span(&self) -> u64 {
        if self.levels >= MAX_LEVELS { u64::MAX } else { 1 << (BITS * self.levels) }
    }

    /// Page `idx`'s frame.
    pub fn get(&self, idx: u64) -> Option<u64> {
        if self.root == 0 || idx >= self.span() {
            return None;
        }
        let mut pa = self.root;
        for level in (0..self.levels).rev() {
            pa = get(pa, (idx >> (BITS * level)) % FANOUT);
            if pa == 0 {
                return None;
            }
        }
        Some(pa)
    }

    /// How many levels a tree holding page `idx` needs.
    fn levels_for(idx: u64) -> u32 {
        let mut levels = 1;
        while levels < MAX_LEVELS && idx >> (BITS * levels) != 0 {
            levels += 1;
        }
        levels
    }

    /// How many nodes inserting page `idx` would add.
    pub fn nodes_needed(&self, idx: u64) -> u64 {
        let levels = Self::levels_for(idx).max(self.levels);
        if self.root == 0 {
            return levels as u64;
        }
        if levels > self.levels {
            // New roots over the old one, and a path from the top one
            // down (idx is past the old root's pages).
            return (levels - self.levels + levels - 1) as u64;
        }
        let mut at = self.root;
        for level in (1..self.levels).rev() {
            at = get(at, (idx >> (BITS * level)) % FANOUT);
            if at == 0 {
                return level as u64;
            }
        }
        0
    }

    fn new_node(&mut self) -> Option<u64> {
        let pa = frame::alloc()?;
        self.nodes += 1;
        Some(pa)
    }

    fn free_node(&mut self, pa: u64) {
        frame::free(pa);
        self.nodes -= 1;
    }

    /// Map page `idx` to frame `pa` (not 0), which it had no frame for.
    /// None if there's no frame for the tree's nodes (it's as it was then,
    /// but for nodes it keeps for later).
    pub fn insert(&mut self, idx: u64, pa: u64) -> Option<()> {
        assert!(pa != 0, "frame 0 in a page index");
        if self.root == 0 {
            self.root = self.new_node()?;
            self.levels = Self::levels_for(idx);
        }
        while idx >= self.span() {
            let root = self.new_node()?;
            set(root, 0, self.root);
            self.root = root;
            self.levels += 1;
        }
        let mut at = self.root;
        for level in (1..self.levels).rev() {
            let i = (idx >> (BITS * level)) % FANOUT;
            let mut next = get(at, i);
            if next == 0 {
                next = self.new_node()?;
                set(at, i, next);
            }
            at = next;
        }
        let i = idx % FANOUT;
        debug_assert_eq!(get(at, i), 0, "page {idx} mapped twice");
        set(at, i, pa);
        self.len += 1;
        Some(())
    }

    /// Take page `idx` out, if it's there. Its nodes stay, for later.
    pub fn remove(&mut self, idx: u64) -> bool {
        if self.root == 0 || idx >= self.span() {
            return false;
        }
        let mut at = self.root;
        for level in (1..self.levels).rev() {
            at = get(at, (idx >> (BITS * level)) % FANOUT);
            if at == 0 {
                return false;
            }
        }
        let i = idx % FANOUT;
        let there = get(at, i) != 0;
        if there {
            set(at, i, 0);
            self.len -= 1;
        }
        there
    }

    /// Take out every page from `keep` on, passing each frame to `each`.
    pub fn remove_from(&mut self, keep: u64, each: &mut dyn FnMut(u64)) {
        if self.root == 0 {
            return;
        }
        if self.remove_in(self.root, self.levels - 1, 0, keep, each) {
            self.free_node(self.root);
            (self.root, self.levels) = (0, 0);
        }
    }

    /// Take out the pages from `keep` on under `pa` (a node at `level`,
    /// covering pages from `first`). True if it's empty now.
    fn remove_in(&mut self, pa: u64, level: u32, first: u64, keep: u64, each: &mut dyn FnMut(u64)) -> bool {
        let per = 1u64 << (BITS * level);
        let mut empty = true;
        for i in 0..FANOUT {
            let child = get(pa, i);
            if child == 0 {
                continue;
            }
            let start = first + i * per;
            if level == 0 {
                if start >= keep {
                    each(child);
                    set(pa, i, 0);
                    self.len -= 1;
                } else {
                    empty = false;
                }
            } else if start.saturating_add(per) <= keep {
                empty = false;
            } else if self.remove_in(child, level - 1, start, keep, each) {
                self.free_node(child);
                set(pa, i, 0);
            } else {
                empty = false;
            }
        }
        empty
    }
}

impl Drop for PageIndex {
    /// The tree's own frames: whoever holds the pages frees them first
    /// (`remove_from(0, ..)`).
    fn drop(&mut self) {
        debug_assert!(self.is_empty(), "a page index dropped with its pages");
        self.remove_from(0, &mut |_| {});
    }
}

const _: () = assert!(FANOUT * 8 == PAGE_SIZE);
