//! grix guest kernel.
//!
//! Boots, reads the boot image the host placed in memory, and runs the one
//! Linux program it describes. The program sees only the files the host
//! imported, and every syscall is checked against the image's capability
//! policy. Output, denials and the exit status go back to the host as framed
//! messages on the virtio console.

#![no_std]
#![no_main]

extern crate alloc;

/// Which ABI this kernel speaks, for hosts to read from the binary.
#[used]
static ABI_MARKER: [u8; 13] = grix_abi::abi_marker();

mod arch;
mod console;
mod elf;
mod errno;
mod export;
mod fd;
mod fs;
mod hostfs;
mod inet;
mod ipc;
mod kmem;
mod locks;
mod mm;
mod netlink;
mod process;
mod procfs;
mod procs;
mod rng;
mod sched;
mod signal;
mod smp;
mod snapshot;
mod syscall;
mod time;
mod timer;
mod tty;
mod unix;
mod uaccess;
mod virtio;

use grix_abi::image::{self, HEADER_LEN, IMAGE_BASE, Image};

use console::klog;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    console::init();
    let header_bytes = unsafe { core::slice::from_raw_parts(mm::p2v(IMAGE_BASE) as *const u8, HEADER_LEN) };
    let header = image::parse_header(header_bytes).unwrap_or_else(|_| panic!("no boot image at {IMAGE_BASE:#x}"));
    mm::init(header.ram_size, IMAGE_BASE, header.total_len);

    let bytes: &'static [u8] =
        unsafe { core::slice::from_raw_parts(mm::p2v(IMAGE_BASE) as *const u8, header.total_len as usize) };
    let img = Image::decode(bytes).unwrap_or_else(|_| panic!("corrupt boot image"));

    time::init(img.boot_time_ns);
    console::init_virtio();
    rng::init(&img.seed);
    snapshot::init(img.snapshot);
    arch::allow_el0_counter();
    klog!("grix kernel: {} MiB RAM, {} imported paths, exec {}\n", img.ram_size >> 20, img.entries.len(), img.exe);
    process::start(img)
}
