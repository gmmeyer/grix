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

pub mod codec;
pub mod image;
pub mod link;
pub mod policy;
pub mod wire;
