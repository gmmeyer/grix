//! Snapshots (`Image::snapshot`): when the program first sits idle waiting
//! for input, the VMM saves the whole machine (`SNAPSHOT_CALL`). Every run
//! restored from it continues from that moment, with fresh entropy, so a
//! runtime that took seconds to start answers its first input at once.
//!
//! What the host held for this run doesn't come along, so the snapshot
//! waits while any of it is in use (connections and DNS lookups through the
//! host), and is put off if input arrived while it was being taken. (Live
//! mounts' host side is saved by the host, and what this kernel knew of
//! them is fetched again; stdin hasn't been touched: nothing has been sent
//! yet.) It's taken with every other CPU idle, and the VMM stops them all.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use grix_abi::image::{SNAPSHOT_CALL, SNAPSHOT_RESTORED, SNAPSHOT_RETRY, SNAPSHOT_TAKEN};
use grix_abi::wire::{Event, ExitKind};

use crate::console::{self, klog};

static WANTED: AtomicBool = AtomicBool::new(false);

pub fn init(wanted: bool) {
    WANTED.store(wanted, Ordering::Relaxed);
}

/// Every thread is blocked and some wait for I/O: take the snapshot, if
/// this run should, hasn't yet, and the program has found stdin empty.
pub fn take_if_wanted() {
    if !WANTED.load(Ordering::Relaxed) || !console::stdin_waited() {
        return;
    }
    // A lookup or connection through the host may be what it waits for;
    // it'll come back to stdin.
    if crate::inet::host_state() > 0 {
        return;
    }
    // Everything said so far reaches the host first: it's this run's. And
    // everything the host sent is taken: if anything had come, it isn't
    // the moment.
    console::flush();
    if !console::take_all_input() {
        return;
    }
    let (x0, x1, x2, x3, x4, x5): (u64, u64, u64, u64, u64, u64);
    // SAFETY: a hypervisor call. The VMM saves every register; a restored
    // run returns here with x0..x5 set and the rest as they were.
    unsafe {
        asm!("hvc #0", inout("x0") SNAPSHOT_CALL => x0, out("x1") x1, out("x2") x2, out("x3") x3, out("x4") x4,
             out("x5") x5);
    }
    match x0 {
        SNAPSHOT_RESTORED => {
            WANTED.store(false, Ordering::Relaxed);
            let mut entropy = [0u8; 32];
            for (i, v) in [x1, x2, x3, x4].iter().enumerate() {
                entropy[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            crate::rng::reseed(&entropy);
            crate::time::resumed_after(x5);
            crate::fs::lock().forget_live();
            klog!("restored from a snapshot taken {} ms ago\n", x5 / 1_000_000);
        }
        // Input arrived as it was being taken: next time.
        SNAPSHOT_RETRY => {}
        SNAPSHOT_TAKEN => WANTED.store(false, Ordering::Relaxed),
        _ => refuse("this VMM can't take snapshots (grix-vmm can)"),
    }
}

fn refuse(why: &str) -> ! {
    console::event(&Event::Unimplemented { nr: 0, syscall: "snapshot", detail: why });
    crate::process::finish(ExitKind::Exited, 125)
}
