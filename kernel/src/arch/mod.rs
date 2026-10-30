//! The CPU: boot, exceptions and the return to user mode, page-table
//! entries, the interrupt controller and timer, and what Linux's ABI says
//! about registers on it. Everything outside `arch` is the same on every
//! architecture.

mod stack;
pub use stack::{CANARY_SIZE, stack_bottom, stack_top};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
