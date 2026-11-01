//! What Linux's x86_64 ABI lays out its own way: `struct stat`
//! (arch/x86/include/uapi/asm/stat.h), `struct epoll_event` (packed), and
//! the open flags that differ by architecture.

use crate::fs::StatInfo;

pub const O_DIRECTORY: u32 = 0o200000;
pub const O_NOFOLLOW: u32 = 0o400000;
pub const O_DIRECT: u32 = 0o40000;

/// x86_64's struct stat: 64-bit st_nlink before st_mode, a 64-bit
/// st_blksize, and three unused longs at the end.
pub fn stat(st: &StatInfo) -> [u8; 144] {
    let mut b = [0u8; 144];
    let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(0, &1u64.to_le_bytes()); // st_dev
    put(8, &st.ino.to_le_bytes());
    put(16, &(st.nlink as u64).to_le_bytes());
    put(24, &st.mode.to_le_bytes());
    put(28, &st.uid.to_le_bytes());
    put(32, &st.gid.to_le_bytes());
    put(40, &st.rdev.to_le_bytes());
    put(48, &st.size.to_le_bytes());
    put(56, &4096u64.to_le_bytes()); // st_blksize
    put(64, &st.blocks.to_le_bytes());
    for (off, t) in [(72, st.atime), (88, st.mtime), (104, st.ctime)] {
        put(off, &(t / 1_000_000_000).to_le_bytes());
        put(off + 8, &(t % 1_000_000_000).to_le_bytes());
    }
    b
}

/// struct epoll_event: u32 events, u64 data, packed (12 bytes).
pub const EPOLL_EVENT: usize = 12;

pub fn epoll_event(events: u32, data: u64) -> [u8; EPOLL_EVENT] {
    let mut b = [0u8; EPOLL_EVENT];
    b[..4].copy_from_slice(&events.to_le_bytes());
    b[4..].copy_from_slice(&data.to_le_bytes());
    b
}

pub fn epoll_event_get(b: &[u8; EPOLL_EVENT]) -> (u32, u64) {
    (u32::from_le_bytes(b[..4].try_into().unwrap()), u64::from_le_bytes(b[4..].try_into().unwrap()))
}

/// What pkey_alloc says without the hardware: x86's finds out setting up a key it had.
pub const NO_PROTECTION_KEYS: crate::errno::Errno = crate::errno::EINVAL;
