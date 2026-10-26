//! Clocks backed by the ARM generic timer.

use spin::Once;

use crate::arch;

struct Clock {
    counter0: u64,
    freq: u64,
    boot_time_ns: u64,
}

static CLOCK: Once<Clock> = Once::new();

pub fn init(boot_time_ns: u64) {
    CLOCK.call_once(|| Clock { counter0: arch::counter(), freq: arch::counter_freq().max(1), boot_time_ns });
}

fn clock() -> &'static Clock {
    CLOCK.get().expect("clock not initialised")
}

/// Nanoseconds since boot.
pub fn monotonic_ns() -> u64 {
    let c = clock();
    let ticks = arch::counter().wrapping_sub(c.counter0) as u128;
    (ticks * 1_000_000_000 / c.freq as u128) as u64
}

/// Nanoseconds since the Unix epoch.
pub fn realtime_ns() -> u64 {
    clock().boot_time_ns + monotonic_ns()
}

/// Busy-wait. (No timer interrupts yet.)
pub fn sleep_until_monotonic(deadline_ns: u64) {
    while monotonic_ns() < deadline_ns {
        core::hint::spin_loop();
    }
}

pub fn sleep_ns(ns: u64) {
    sleep_until_monotonic(monotonic_ns().saturating_add(ns));
}
