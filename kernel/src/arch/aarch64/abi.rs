//! What Linux's arm64 (asm-generic) ABI lays out its own way: `struct
//! stat`, `struct epoll_event`, and the open flags that differ by
//! architecture.

use crate::fs::StatInfo;

pub const O_DIRECTORY: u32 = 0o40000;
pub const O_NOFOLLOW: u32 = 0o100000;
pub const O_DIRECT: u32 = 0o200000;

/// asm-generic's struct stat.
pub fn stat(st: &StatInfo) -> [u8; 128] {
    let mut b = [0u8; 128];
    let mut put = |off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    put(0, &1u64.to_le_bytes()); // st_dev
    put(8, &st.ino.to_le_bytes());
    put(16, &st.mode.to_le_bytes());
    put(20, &st.nlink.to_le_bytes());
    put(24, &st.uid.to_le_bytes());
    put(28, &st.gid.to_le_bytes());
    put(32, &st.rdev.to_le_bytes());
    put(48, &st.size.to_le_bytes());
    put(56, &4096u32.to_le_bytes()); // st_blksize
    put(64, &st.blocks.to_le_bytes());
    for (off, t) in [(72, st.atime), (88, st.mtime), (104, st.ctime)] {
        put(off, &(t / 1_000_000_000).to_le_bytes());
        put(off + 8, &(t % 1_000_000_000).to_le_bytes());
    }
    b
}

/// struct epoll_event: u32 events, padding, u64 data (not packed here).
pub const EPOLL_EVENT: usize = 16;

pub fn epoll_event(events: u32, data: u64) -> [u8; EPOLL_EVENT] {
    let mut b = [0u8; EPOLL_EVENT];
    b[..4].copy_from_slice(&events.to_le_bytes());
    b[8..].copy_from_slice(&data.to_le_bytes());
    b
}

pub fn epoll_event_get(b: &[u8; EPOLL_EVENT]) -> (u32, u64) {
    (u32::from_le_bytes(b[..4].try_into().unwrap()), u64::from_le_bytes(b[8..].try_into().unwrap()))
}

/// What pkey_alloc says without the hardware: arm64's has none to give.
pub const NO_PROTECTION_KEYS: crate::errno::Errno = crate::errno::ENOSPC;

/// `struct semid64_ds`: its size, and where its fields are.
pub const SEMID_BYTES: usize = 104;
pub const SEMID_OTIME: usize = 48;
pub const SEMID_CTIME: usize = 56;
pub const SEMID_NSEMS: usize = 64;
