//! Snapshots (`Image::snapshot`): when the program first sits idle waiting
//! for input, the VMM saves the whole machine (`SNAPSHOT_CALL`). Every run
//! restored from it continues from that moment, with fresh entropy, so a
//! runtime that took seconds to start answers its first input at once.
//!
//! What the host held for this run doesn't come along, so the snapshot is
//! refused while any of it is in use: connections and DNS lookups through
//! the host. (The host refuses live mounts, and stdin hasn't been touched:
//! nothing has been sent yet.)

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use grix_abi::image::{SNAPSHOT_CALL, SNAPSHOT_RESTORED, SNAPSHOT_TAKEN};
use grix_abi::wire::{Event, ExitKind};

use crate::console::{self, klog};

static WANTED: AtomicBool = AtomicBool::new(false);

pub fn init(wanted: bool) {
    WANTED.store(wanted, Ordering::Relaxed);
}

/// Every thread is blocked and some wait for input: take the snapshot, if
/// this run should and hasn't yet.
pub fn take_if_wanted() {
    if !WANTED.swap(false, Ordering::Relaxed) {
        return;
    }
    if crate::inet::host_state() > 0 {
        refuse("the program has connections or DNS lookups open through the host");
    }
    // Everything said so far reaches the host first: it's this run's.
    console::flush();
    let (x0, x1, x2, x3, x4): (u64, u64, u64, u64, u64);
    // SAFETY: a hypervisor call. The VMM saves every register; a restored
    // run returns here with x0..x4 set and the rest as they were.
    unsafe {
        asm!("hvc #0", inout("x0") SNAPSHOT_CALL => x0, out("x1") x1, out("x2") x2, out("x3") x3, out("x4") x4);
    }
    match x0 {
        SNAPSHOT_RESTORED => {
            let mut entropy = [0u8; 32];
            for (i, v) in [x1, x2, x3, x4].iter().enumerate() {
                entropy[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            crate::rng::reseed(&entropy);
            klog!("restored from a snapshot\n");
        }
        SNAPSHOT_TAKEN => {}
        _ => refuse("this VMM can't take snapshots (grix-vmm can)"),
    }
}

fn refuse(why: &str) -> ! {
    console::event(&Event::Unimplemented { nr: 0, syscall: "snapshot", detail: why });
    crate::process::finish(ExitKind::Exited, 125)
}
