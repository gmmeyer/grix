//! Each CPU's kernel stack and what's below it: the linker script's
//! `.stack`, sized from here. CPU n's slot holds its emergency stack, then
//! its stack: an overflow runs into memory only a report of it uses, not
//! the stack of the CPU below. There's no guard page (mapping the stacks
//! with 4 KiB pages, the kernel's code and data around them too, cost
//! contended system calls a fifth of their speed): the lowest
//! `CANARY_SIZE` bytes of each stack are painted, and the way back to
//! user mode and the idle wait check them (`smp::check_stack`). An
//! exception taken that low is reported too (on arm64 from the emergency
//! stack, as its frame wouldn't fit).

use grix_abi::machine::MAX_CPUS;

/// Each CPU's kernel stack. A release build's deepest is about 16 KiB on
/// either architecture (`stack_max` in /proc/grix/smp), a debug build's
/// about 57 KiB.
pub const STACK_SIZE: u64 = 0x20000;
/// Enough for the panic that reports an overflow.
pub const EMERGENCY_STACK_SIZE: u64 = 0x4000;
/// What one CPU's stacks take.
pub const STACK_SLOT: u64 = EMERGENCY_STACK_SIZE + STACK_SIZE;
/// All of `.stack`.
pub const STACKS_SIZE: u64 = STACK_SLOT * MAX_CPUS as u64;
/// The bottom of each stack that nothing may reach.
pub const CANARY_SIZE: u64 = 256;

// For the linker script and the assembly.
core::arch::global_asm!(
    ".globl __stack_size",
    ".set __stack_size, {size}",
    ".globl __stack_slot",
    ".set __stack_slot, {slot}",
    ".globl __stacks_size",
    ".set __stacks_size, {all}",
    size = const STACK_SIZE,
    slot = const STACK_SLOT,
    all = const STACKS_SIZE,
);

unsafe extern "C" {
    static __stacks: u8;
}

/// The start of `.stack`.
pub fn stacks_start() -> u64 {
    (&raw const __stacks) as u64
}

/// Top of CPU `cpu`'s kernel stack.
pub fn stack_top(cpu: usize) -> u64 {
    stacks_start() + (cpu as u64 + 1) * STACK_SLOT
}

/// The lowest address of CPU `cpu`'s kernel stack.
pub fn stack_bottom(cpu: usize) -> u64 {
    stack_top(cpu) - STACK_SIZE
}

/// Top of CPU `cpu`'s emergency stack, just below its stack.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub fn emergency_stack_top(cpu: usize) -> u64 {
    stack_bottom(cpu)
}

/// `sp` is CPU `cpu`'s, and into its canary or below it: an exception
/// taken there is an overflow.
pub fn overflowed(cpu: usize, sp: u64) -> bool {
    (stack_bottom(cpu) - EMERGENCY_STACK_SIZE..stack_bottom(cpu) + CANARY_SIZE).contains(&sp)
}

/// `addr` is in a kernel stack or an emergency stack.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub fn on_a_stack(addr: u64) -> bool {
    (stacks_start()..stacks_start() + STACKS_SIZE).contains(&addr)
}
