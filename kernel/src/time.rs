//! Clocks backed by the ARM generic timer.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Once;

use crate::arch;

struct Clock {
    counter0: u64,
    freq: u64,
    boot_time_ns: u64,
}

static CLOCK: Once<Clock> = Once::new();
/// How far the time of day has moved without the monotonic clock: the time
/// a snapshot sat before this run was restored from it (like a suspend:
/// CLOCK_MONOTONIC doesn't count it, CLOCK_REALTIME does).
static SUSPENDED_NS: AtomicU64 = AtomicU64::new(0);

/// The machine was saved and is now restored, `ns` later.
pub fn resumed_after(ns: u64) {
    SUSPENDED_NS.fetch_add(ns, Ordering::Relaxed);
}

/// The time of day at boot, as the monotonic clock sees it.
fn boot_time_ns() -> u64 {
    clock().boot_time_ns + SUSPENDED_NS.load(Ordering::Relaxed)
}

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
    boot_time_ns() + monotonic_ns()
}

/// Boot time in nanoseconds since the Unix epoch.
pub fn boot_realtime_ns() -> u64 {
    boot_time_ns()
}

/// Boot time in seconds since the Unix epoch.
pub fn realtime_to_boot_secs() -> u64 {
    boot_time_ns() / 1_000_000_000
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
    ns.saturating_sub(boot_time_ns())
}
