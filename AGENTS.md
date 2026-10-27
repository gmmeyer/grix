# AGENTS.md

Guidance for AI coding agents (and humans) working on this repository. For
what the project is and how to use it, see [README.md](README.md).

## Build and test

```sh
make kernel      # guest kernel  -> kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel
make host        # host CLI      -> target/release/grix
make fixtures    # C (zig) and Go test programs + Alpine busybox, python3, nodejs (network, cached)
make test        # everything; end-to-end tests boot the kernel in QEMU
make check       # clippy for host and kernel
```

- The kernel is a **separate cargo workspace** (`kernel/`) with its own target in
  `kernel/.cargo/config.toml`. Build it from inside `kernel/` or with `make kernel`.
  `cargo test` at the root does **not** rebuild it, so after changing kernel code
  run `make kernel` (or `make test`) before the end-to-end tests.
- End-to-end tests live in `crates/grix/tests/guest.rs` (C fixtures, busybox)
  and `crates/grix/tests/runtimes.rs` (Python, Node). They need QEMU, the
  built kernel, and `fixtures/build/`. Missing pieces fail loudly; they are
  never skipped.
- Tests use hardware virtualization when available (HVF/KVM). Also run them
  with `GRIX_ACCEL=tcg` when touching boot, MMU, cache, page-table, timer or
  scheduler code. Emulation and real hardware catch different mistakes, and
  timing-dependent bugs show up differently on each. Concurrency changes
  deserve a stress loop (run the `threads`/`events`/`signals`/`gosignals`
  fixtures 30× each).
- Debugging a guest: `grix run -v ...` prints the kernel log, and `--json`
  shows status, output and events together. A kernel panic message ends up in
  `RunOutput::kernel_log`.

## Architecture in one paragraph

The host (`crates/grix`) turns imports, argv/env and a capability `Policy`
into a boot image (`crates/abi/src/image.rs`). QEMU loads the image at
physical `0x4800_0000` and the kernel at `0x4020_0000`. The kernel
(`kernel/src`) enables the MMU in `arch/boot.S`, runs in the high half
(`0xFFFF_0000_0000_0000 + phys`), builds a read-only in-memory filesystem from
the image (`fs.rs`, writable in guest memory with `fs_write`), loads the ELF
(`elf.rs`, `process.rs`), and drops to EL0.
After that, every bit of kernel work happens in an exception handler
(`arch/mod.rs` → `syscall/`, demand paging in `mm/aspace.rs`, or the timer
interrupt in `sched.rs`). Everything the guest says goes out as frames
(`console.rs`, format in `crates/abi/src/wire.rs`) on a virtio console
(`virtio.rs`: virtio-mmio, port 1 of a `virtio-serial-device`, on QEMU's
stdio), and stdin comes back on it as `wire::Input` frames. When the host
reads slowly, program writes to stdout/stderr block like pipe writes (woken
by the device's interrupt; `Thread::io_done` lets a re-run continue after
what it already sent) or fail with EAGAIN; the kernel's own messages spin
until there's room. Before the virtio console is up, and for panics, frames
go to the PL011 UART, on a Unix socket the host reads (bounded).

Threads (`sched.rs`): one CPU and one kernel stack. Each thread keeps its user
registers, TLS and FP/SIMD state in `process::Thread`. A syscall that must
wait calls `Process::block` (futex/sleep) or `Process::block_io` (I/O) and
returns `EBLOCKED`. `schedule()` then saves the trapped state and loads
another thread's state into the trap frame. I/O waits are *restarted*: when
`ipc::changed()` bumps the I/O generation, blocked I/O syscalls re-execute
from the `svc` (ELR − 4) with their original deadline (`restart_deadline`).
Timers (`timer.rs`: setitimer, POSIX timers, timerfds) are deadlines too:
the scheduler programs the CPU timer for the earliest one and calls
`timer::fire` from the timer interrupt and the idle loop.

Signals (`signal.rs`): actions are per process; masks, pending queues and
sigaltstacks are per thread. `kill` picks a receiver like Linux (the main
thread first, then any thread that doesn't block the signal) and queues it
there. If every thread blocks it, it waits on the process. Delivery happens
on every return to EL0 (`signal::return_to_user`, called from
`trap_handler`): the kernel pushes a Linux-layout `rt_sigframe` (with the
FP/SIMD record) and points the thread at the handler. Handlers return
through the `[sigpage]` trampoline unless they set `SA_RESTORER`, as Go and
glibc on arm64 don't. `signal::send` rewinds a blocked receiver to its `svc`
and sets `Thread::restarting`. I/O wakeups do the same. When a handler is
then delivered, the call fails with EINTR unless the handler has
`SA_RESTART` and the call is restartable. With no handler it simply re-runs,
keeping its deadline (`restart_deadline`).

## Invariants: don't break these

1. **Host and guest agree through `crates/abi` only.** Never duplicate an
   encoding, address or constant on both sides; put it in `abi`. The `abi`
   crate must stay `no_std` (plus `alloc`).
2. **The kernel never faults on user memory.** Every access to a user pointer
   goes through `uaccess.rs` (`copy_in`, `copy_out`, `read_cstr`, …).
   `AddressSpace::ensure` validates against VMAs and pre-faults the pages. An
   EL1 fault is a kernel bug and panics.
3. **The kernel is softfloat** and never touches FP/SIMD registers, which is
   why user FP state doesn't need saving on traps. Don't change the target, and
   don't add code that needs FP in the kernel.
4. **Every syscall has a gate.** New syscall numbers go in
   `kernel/src/syscall/table.rs` with `Core`, `Cap(...)` or `Privileged`. If a
   use is only dangerous with certain arguments (e.g. `openat` with write
   flags, `clone` flags), gate it in the handler with `syscall::require`.
5. **Denied ≠ unimplemented.** Use `Process::deny` when the policy forbids
   something (it reports `Denied` and returns EPERM, or kills with SIGSYS). Use
   `Process::unimplemented` when it's allowed but missing (it reports
   `Unimplemented`). Never silently return success for something that didn't
   happen.
6. **Guest output is untrusted.** Host-side decoding (`FrameDecoder`,
   `Event::decode`) must bound lengths and survive garbage. Don't add host
   code that trusts guest-provided sizes, paths or strings.
7. **Least privilege at the VM level too.** Don't add QEMU devices (NICs,
   disks, virtio-fs), semihosting, or the monitor unless a capability gates
   them. Semihosting in particular gives the guest host file access. The
   only devices are the PL011 and the virtio console, and both carry
   nothing but the framed channel to the host; keep it that way (no more
   ports, no `virtconsole`, which drops output under backpressure).
8. **No paths outside imports.** The guest filesystem is exactly the import
   list plus the synthetic nodes in `fs.rs`. `/dev` and `/proc` are reserved
   (`crates/grix/src/image.rs`).
9. **The kernel never blocks inside a syscall.** There is one kernel stack,
   so waiting means returning `EBLOCKED` after recording a wait. Anything
   that can make a blocked I/O call succeed (data, space, closing an end,
   epoll_ctl) must call `ipc::changed()`, or waiters will sleep forever. IRQs
   stay masked in the kernel; don't unmask them.
10. **The kernel heap is small (32 MiB) and running out of it panics.**
    Anything a program can make the kernel allocate needs a budget that
    fails with an errno first:
    - File data counts pages (`fs::set_limit`), and nodes and names count
      against `META_LIMIT` (ENOSPC).
    - Buffers held for a program (pipes, netlink replies, generated /proc
      files) take a `kmem::Charge`.
    - Counts are capped: mappings (`MAX_VMAS`), queued real-time signals,
      inotify watches, POSIX timers, threads, descriptors.

    Limits must be global, not per object: a program can open many objects.
11. **`fs::lock()` is not re-entrant**; it panics if the lock is already
    held. Drop the guard before calling anything that takes it
    (`Process::missing_path`, `procfs::generate`, …). Lock order:
    `OpenFile` → filesystem → `FileData`. Never hold a `FileData` lock
    across `copy_in`/`copy_out`, because a fault may read the same file
    through a mapping (file.rs uses bounce buffers).
12. **User register state never reaches EL1.** `rt_sigreturn` loads every
    register from user memory. It must reject a frame whose pstate names
    another exception level, AArch32 or masked interrupts, and keep only
    NZCV (`signal::read_frame`). Anything else that loads a user-supplied
    context needs the same check.

## Adding a syscall

1. Check the number and argument layout against the Linux **arm64 /
   asm-generic** ABI, not x86_64: numbers, `struct stat` layout and `O_*`
   flags (e.g. `O_DIRECTORY = 0o40000` on arm64) all differ.
2. Add or adjust its entry in `table.rs` (with the right gate) and implement it
   in `syscall/file.rs`, `mem.rs` or `misc.rs`. Return `Err(errno)` like Linux.
3. Add a C fixture in `fixtures/src/` or a Go one in `fixtures/go/<name>/`
   (built automatically by `fixtures/build.sh`) or use busybox, plus an end-to-end test in
   `crates/grix/tests/guest.rs` that checks the program's output, its
   exit status, **and** `events`.
4. Run `make test`, plus `GRIX_ACCEL=hvf cargo test -p grix --test guest` on Apple Silicon.

To find what a real program is missing, run it with `--json` and read the
`unsupported` / `denied` events.

## Style

- Rust 2024 edition, `cargo fmt`, clippy-clean (`make check`).
- Kernel: no `static mut`; globals are `spin::Mutex`/`spin::Once`. Keep
  `unsafe` blocks small and next to the hardware or pointer access they cover.
- Comment the *why* (ABI quirks, hardware requirements), not the what. Cite
  the Linux behaviour being emulated when it's non-obvious.
- Prefer clear errors to panics on the host. In the kernel, panic only on
  kernel bugs, never on bad user input.
