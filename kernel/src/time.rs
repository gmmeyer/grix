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

/// Boot time in seconds since the Unix epoch.
pub fn realtime_to_boot_secs() -> u64 {
    clock().boot_time_ns / 1_000_000_000
}

static BOOT_ID: Once<[u8; 16]> = Once::new();

/// Random per boot, like /proc/sys/kernel/random/boot_id.
pub fn boot_id() -> [u8; 16] {
    *BOOT_ID.call_once(|| {
        let mut b = [0u8; 16];
        crate::rng::fill(&mut b);
        b
    })
}

/// The counter value at monotonic time `ns` (for programming the timer).
pub fn counter_at(ns: u64) -> u64 {
    let c = clock();
    let ticks = (ns as u128 * c.freq as u128 / 1_000_000_000).min(u64::MAX as u128) as u64;
    c.counter0.saturating_add(ticks)
}

/// Convert an absolute CLOCK_REALTIME time to monotonic time.
pub fn realtime_to_monotonic(ns: u64) -> u64 {
    ns.saturating_sub(clock().boot_time_ns)
}
