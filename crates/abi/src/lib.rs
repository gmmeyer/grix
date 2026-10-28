//! Definitions shared by the grix host library and the guest kernel.
//!
//! Everything that crosses the host/guest boundary lives here so the two sides
//! cannot drift apart:
//! - [`image`]: the boot image the host builds (program, args, env, imported files, policy)
//! - [`policy`]: the capability model enforced by the guest kernel
//! - [`wire`]: the framed protocol the guest uses to talk back to the host
//! - [`link`]: networking and flow control between the guest kernel and the host

#![cfg_attr(not(test), no_std)]

extern crate alloc;

/// The version of everything here that crosses the boundary: the boot
/// image, the wire format, `link` and `hostfs`. A grix image carries the
/// kernel it was built with, and runs only with a host of the same
/// version. Bump it with any change the other side couldn't read.
pub const ABI_VERSION: u32 = 4;

/// The kernel says which ABI it speaks with these bytes in its binary
/// (`MARK` then `ABI_VERSION`, little-endian), so a host can tell before
/// booting it: an image's kernel may come from anywhere.
pub const ABI_MARK: &[u8; 9] = b"GRIX-ABI:";

/// The marker the kernel embeds.
pub const fn abi_marker() -> [u8; 13] {
    let mut m = [0u8; 13];
    let mut i = 0;
    while i < 9 {
        m[i] = ABI_MARK[i];
        i += 1;
    }
    let v = ABI_VERSION.to_le_bytes();
    m[9] = v[0];
    m[10] = v[1];
    m[11] = v[2];
    m[12] = v[3];
    m
}

/// The ABI a kernel binary speaks, from its marker.
pub fn kernel_abi(kernel: &[u8]) -> Option<u32> {
    let at = kernel.windows(ABI_MARK.len()).position(|w| w == ABI_MARK)? + ABI_MARK.len();
    Some(u32::from_le_bytes(kernel.get(at..at + 4)?.try_into().ok()?))
}

pub mod codec;
pub mod hostfs;
pub mod image;
pub mod link;
pub mod machine;
pub mod policy;
pub mod wire;
