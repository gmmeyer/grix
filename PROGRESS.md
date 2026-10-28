# Progress log

## Session 1 (2026-10-26)

**grix** (greg + unix) is an *agentbox*: a Rust unikernel that runs
unmodified arm64 Linux programs for AI agents, with least privilege by
default. At the end of the session `main` was at `e9aa0d9` and everything
was pushed to github.com/gmmeyer/grix. All 39 tests passed, both with
hardware virtualization (HVF) and under emulation (TCG).

### How it works

- Every run boots a fresh VM in QEMU. The VM has no network card, no disk,
  and no access to host files. All guest output (program stdout/stderr,
  kernel log, events, exit status) comes back as frames on a virtio
  console (early boot and panics: the serial port), and the host treats it
  as untrusted input.
- The guest's filesystem is exactly what the host imported, read-only, plus
  generated `/dev`, `/proc` and `/sys`, and an `/etc/passwd` / `/etc/group`
  describing the sandbox user.
- Capabilities `fs_write`, `threads`, `process` and `net` must be granted.
  Privileged calls (mount, ptrace, bpf, module loading, changing uid) are
  always denied. Every denial comes back as an event naming the syscall
  and the capability it needs.
- Interfaces: the Rust library (`Sandbox::builder()...run()`), the `grix`
  CLI (`--json` for machine-readable results), and TOML manifests.
- grix uses hardware virtualization automatically when the host has it (HVF
  on Apple Silicon, KVM on arm64 Linux). `GRIX_ACCEL` overrides.

### What was built, in order

1. **Kernel basics** (initial commit `5509ac8`):
   - aarch64 boot into the high half with the MMU on
   - page tables, demand paging, mmap/mprotect/mremap/brk
   - ELF loader for static, static-PIE and dynamic (musl `ld.so`) programs
   - Linux syscall table with a capability gate on every syscall
   - read-only in-memory filesystem built from the imports
   - faults turned into signals
   - ChaCha20 RNG seeded by the host
2. **Rename to grix** (`feb635a`).
3. **Threads and blocking I/O** (`e0ed3ae`):
   - `clone`/`clone3`, per-thread TLS, FP/SIMD state and signal masks
   - round-robin scheduler with 10 ms time slices, driven by the GICv3 timer
   - futexes (wait, wake, requeue, wake-op, timeouts)
   - blocking sleeps
   - deadlock detection: when every thread is blocked and nothing can wake them, the program is killed with an explanation
   - pipes, eventfd, epoll (level, edge, oneshot), poll/select
   - blocked I/O syscalls restart when I/O state changes
4. **Real runtimes** (`69a32ab`):
   - AF_UNIX `socketpair`, which Python's asyncio needs
   - `tools/alpine.py`, which resolves Alpine packages and their dependencies into an importable root filesystem, checking each against the index
   - end-to-end tests for Python and Node
5. **Docs** (`c71d290`): README (what can be imported, capability model, compatibility, roadmap) and AGENTS.md (invariants, how to add a syscall).
6. **TODO.md** (`77ca959`): what ordinary programs still need. Built by
   running Python, Node, Go, git, coreutils and busybox and recording what
   failed.
7. **Linux surface** (`e9aa0d9`):
   - `#!` scripts, so `pip3` runs
   - `/proc`: `self/{maps,status,stat,cmdline,environ,fd/,...}`, cpuinfo, meminfo, stat, uptime, `sys/*`
   - `/sys`: cpu online, cgroup v2 limits, transparent hugepages
   - `/dev/fd` and `/dev/std*`
   - `/etc/passwd` and `/etc/group` for the sandbox user
   - `statfs`, the xattr calls, `inotify` (watches that never fire)
   - unknown syscalls are reported with their number

### What runs today (unmodified Alpine builds)

- Python 3.12: threads, asyncio, hashlib, sqlite, ssl, `pip --version`.
- Node 22: timers, crypto, fs, worker_threads, `fs.watch`.
- busybox, git, coreutils (`ls -l`, `df`, `id`), ruby, perl, lua, jq,
  sqlite3.

### Biggest gaps (see TODO.md for all of them)

1. **Signal delivery to handlers.** Go programs die on SIGURG (signal 23);
   Python `signal.signal` and Node `process.on('SIG…')` handlers kill the
   program instead of running.
2. **No writable filesystem.** This breaks tempfile, `pip install`,
   `git init` and anything else that writes files.
3. **No timers:** alarm/setitimer, timerfd, POSIX timers.
4. **No stdin from the host.** stdin is always EOF.
5. **No network interface listing.** Planned as netlink reporting only
   `lo`. Node's `os.networkInterfaces()` throws.
6. **No networking.** Planned as sockets proxied through the host, with
   allow-lists and port forwarding. This is what web servers need.
7. **No processes:** fork/exec/wait. This blocks subprocess, child_process
   and shell pipelines.

## Session 2 (2026-10-26): signal delivery

Signals now reach handlers, the way Linux arm64 delivers them
(`kernel/src/signal.rs`, syscalls in `kernel/src/syscall/signal.rs`):

- **Frames**: the same `rt_sigframe` layout as Linux (siginfo, ucontext,
  sigcontext, FP/SIMD record, ESR record for faults).
- **`rt_sigreturn`** validates the frame. It rejects any pstate that isn't
  EL0 and keeps only NZCV (AGENTS.md invariant 12).
- **`[sigpage]`**: a trampoline page that handlers return to unless they set
  `SA_RESTORER`. Go and glibc on arm64 rely on it, since they normally use
  the vDSO's trampoline.
- **Per-thread state**: masks, pending queues and sigaltstacks. Real-time
  signals queue every instance; `kill` goes to the main thread first, as on
  Linux.
- **Flags**: `SA_SIGINFO`/`ONSTACK`/`RESTART`/`NODEFER`/`RESETHAND`, and
  `SS_AUTODISARM` for sigaltstack.
- **Blocked syscalls** fail with EINTR, or restart after an `SA_RESTART`
  handler if the call is restartable. The decision is made when the handler
  is delivered. An interrupted `nanosleep` reports the time left.
- **Waiting for signals**: `rt_sigsuspend`, `rt_sigtimedwait`,
  `rt_(tg)sigqueueinfo`, and the sigmask arguments of
  `ppoll`/`pselect6`/`epoll_pwait(2)`.
- **Faults** (SIGSEGV/SIGBUS/SIGILL/SIGTRAP/SIGFPE) go to handlers, with
  `si_code` and `si_addr` set.

Tests:
- New fixtures:
  - `fixtures/src/signals.c`, which covers every feature above.
  - `fixtures/go/signals`, built with the host Go toolchain: goroutine
    preemption, nil dereference panics, `os/signal`.
  - `fault sigreturn`, a forged frame asking for EL1.
- New runtime tests:
  - Python: handlers, PEP 475 sleep, `signal.pause`, KeyboardInterrupt,
    `sigwait`.
  - Node: `process.on('SIGUSR2')`.
- 43 tests pass under both HVF and TCG. The stress loop
  (`threads`/`events`/`signals`/`gosignals`, 30× each on both
  accelerators) had no failures.
- An independent review found two scheduling bugs, fixed with regression
  tests:
  - A signal racing an I/O wakeup didn't interrupt the syscall.
  - `kill` went to the sender instead of the main thread.

### Writable filesystem (`fs_write`)

With `fs_write` the whole tree is writable in guest memory
(`kernel/src/fs.rs`):

- **Storage**: file contents are the imported bytes plus copy-on-write page
  frames. Written data is limited to half of RAM (ENOSPC, like tmpfs).
  Nodes and names count against a 12 MiB metadata budget, so a program
  can't exhaust the 32 MiB kernel heap (AGENTS.md invariant 10).
- **Ownership**: Unix owners, modes, the sticky bit and real timestamps.
  The sandbox user owns `/` and the imports. `/dev`, `/proc` and `/sys` are
  fixed. `/tmp` and `/dev/shm` are 1777.
- **Syscalls**:
  - open flags O_CREAT/EXCL/TRUNC/APPEND/TMPFILE, pwrite/preadv/pwritev
  - mkdir/unlink/rmdir/rename(2) with NOREPLACE and EXCHANGE, link/symlink
  - truncate/fallocate, chmod/chown/utimensat
  - sendfile and copy_file_range, SEEK_DATA/SEEK_HOLE
- **Unlinked files**: unlinked-but-open files stay usable, and slots are
  reused once nothing refers to them.
- **getdents** uses a name cursor, so `rm -rf` works while it deletes.
- **mmap** of written files works. MAP_SHARED mappings hold a copy, so
  changing the file, or making the mapping writable, is reported as
  unimplemented. (Since round 2, item 11, only a live mount's do.)
- **Missing-path events** are no longer reported for directories the
  program changed, or for /tmp.

Tests:
- `fixtures/src/files.c` covers all of the above, plus hostile inputs: a
  doubling symlink chain (ELOOP after 40 links), reads far past /proc
  files, a symlink flood (ENOSPC instead of a kernel panic), and 100k
  mkdir/rmdir rounds.
- Python: tempfile, shutil, an on-disk sqlite database, rmtree. Node: fs
  writes and renames, fs.promises, rmSync.
- 49 tests pass under HVF and TCG, and the stress loop was clean.
- A review found the heap, symlink and /proc problems above before they
  shipped.

### Timers, interface listing, small gaps, kernel memory budget

- **Timers** (`kernel/src/timer.rs`):
  - ITIMER_REAL / `alarm`.
  - POSIX timers: signal values, overruns, SIGEV_THREAD_ID, SIGEV_NONE,
    absolute times.
  - timerfd: blocking, non-blocking, epoll.

  As on Linux, a timer re-arms only once its last expiry is consumed, so a
  1 ns interval can't starve the program. The scheduler fires timers from
  the timer interrupt and the idle loop.
- **Interface listing** without `net` (`kernel/src/netlink.rs`). NETLINK_ROUTE
  dumps, interface ioctls and `/proc/net/dev` report just `lo`; changing
  interfaces gets EPERM.
  - Node `os.networkInterfaces()`, Python `if_nameindex` and busybox
    `ip addr` work.
  - Socket creation is now gated by address family, and
    connect/listen/accept "act on existing sockets".
- **Small gaps**:
  - `memfd_create`, with seals.
  - `signalfd4`.
  - Real per-thread and per-process CPU time (clocks, getrusage, times,
    /proc stat).
  - `membarrier`, `mincore`, more `prctl` options (unknown ones are now
    reported).
  - A generated UTC `/etc/localtime`.
- **Kernel memory budget** (`kernel/src/kmem.rs`, AGENTS.md invariant 10).
  Pipe buffers, netlink replies, generated /proc files, queued RT signals,
  mappings and inotify watches all fail with an errno before the 32 MiB
  heap runs out. A review found the netlink path; the others were older.
  `brk` growth now merges into one mapping, and mapping lookups are
  O(log n + k).

Tests:
- New fixtures: `timers.c`, `netif.c`, `linux.c` and `limits.c`.
- New runtime tests: Python timers and CPU time, Node interfaces.
- 55 tests pass under HVF and TCG. The stress loops were clean, including
  a parallel-load run (8 VMs at once).
- That parallel run is what exposed a race in a test, and some
  timing-dependent tests that are now load-independent.

Next, in TODO.md order:
1. stdin from the host, and output limits.
2. Give written files back to the host (the agent's results).
3. fork/exec/wait.
4. Networking through the host.

### stdin, a fast transport, and exports

- **stdin from the host** and **output limits** (`550b1bb`): `run_with_stdin`,
  the CLI passes a non-terminal stdin through, and `max_output` caps what's
  kept of stdout/stderr.
- **virtio-console** (`52aa085`): the framed channel moved off the PL011 to
  port 1 of a virtio-serial device (`kernel/src/virtio.rs`). About 50 MB/s
  out and 30 MB/s in with HVF, up from 100 KB/s and 25 KB/s. When the host
  reads slowly, only the writing thread waits (or gets EAGAIN); a blocking
  write still returns its full count. A review found a single-threaded
  writer killed as "deadlocked" before it shipped.
- **Exports**: `SandboxBuilder::export("/out")` (CLI `-x /out:./results`,
  manifest `[[export]]`). When the program ends, however it ends short of a
  timeout or kernel panic, the kernel sends the directory's entries (mode,
  mtime, contents, symlink targets) before the exit status. The host
  checks every path and size (`max_export`, 256 MiB), and `write_to`
  recreates the tree without following links.

- **Processes**: fork, vfork and posix_spawn (copy-on-write, with
  per-frame refcounts), execve of imported and written programs and `#!`
  scripts, wait4/waitid, SIGCHLD, zombies, orphans, process groups and
  sessions, up to 128 processes. Shell pipelines, Python `subprocess` and
  `os.fork`, Node `child_process` (including `fork` with IPC) and Go
  `os/exec` work. The kernel now keeps the running process in `PROCESS` and
  the rest in `procs::PROCS`, and the scheduler round-robins across them.
  A woken syscall re-runs before signals are delivered, so `waitpid` with a
  SIGCHLD handler returns the child instead of EINTR. Under a fully loaded
  TCG suite that exposed a duplicated-output bug (an interrupt between
  `eret` and the re-run `svc`), fixed by keeping `restarting` until the svc
  runs again.

- **Networking through the host**: the guest has no TCP/IP stack and the
  VM no network card. TCP sockets become `link` messages on the console;
  the host's proxy checks `allow_host` rules, connects, forwards ports and
  answers DNS from its own resolver. Flow control is by credit both ways
  (stdin moved to the same scheme). Connections to the guest's own
  addresses are kernel socket pairs. busybox `wget`/`nslookup`, Python
  `urllib` and asyncio, and a Node server behind a forward work. A review
  found and we fixed: an unbounded accept queue that panicked the kernel,
  connect threads and queued frames the guest could pile up on the host,
  broad rules (`0.0.0.0/0`, `10.0.0.0/8`) opening the host or the metadata
  address, v4-mapped addresses dodging checks, data sent right after
  `Connected` being dropped, and a lost wakeup on close.

- **Read-write host mounts**: `mount(host, guest)` / `--mount` /
  `[[mount]]`. Each run imports the directory fresh, now with the host's
  mtimes (all imports have them now). When the program ends the kernel
  sends only what changed, comparing each node with what was imported (a
  pointer comparison for untouched files), plus the topmost removed paths.
  The host applies the change set only if it all arrived, never through a
  link, replacing files by rename, and leaves anything that changed on the
  host during the run as a reported conflict. The mount point can't be
  removed or renamed (EBUSY).

- **Live mounts**: `mount` / `mount_read_only` (the earlier kind is now
  `mount_on_exit`). Nothing goes into the boot image. The kernel asks the
  host for directory listings, file bytes and changes over the console
  (`hostfs`, one request at a time, waiting with interrupts masked). The
  host serves them confined to the mount with `openat`/`O_NOFOLLOW`. Nodes
  are a cache with a one-second freshness. Eviction forgets idle
  directories under memory pressure, and directories too big to hold are
  looked up name by name and read page by page. Python runs entirely from
  read-only mounts of its `/lib` and `/usr`. 150,000 files walk in about 4
  s, and a single 50,000-entry directory in about 4 s. That needed a new
  kernel heap allocator (talc), because `linked_list_allocator` went
  quadratic with tens of thousands of small objects.

- **Signals from the host**: `RunControl` (`signal`, `stop`) and the
  CLI's Ctrl-C/SIGTERM/SIGHUP/SIGQUIT reach the program's process group as
  `Input::Signal` frames. A timeout now sends SIGTERM and waits `grace` (5
  s), so a program that cleans up still sends its exports. Threads waiting
  only for a signal are no longer a deadlock. That includes musl's
  `pause()`, which on arm64 is a `ppoll` with nothing to watch. This
  exposed an old scheduler bug: when the process that ran last had just
  ended, `idle` compared the I/O generation with that dead process's, never
  settled, and spun with interrupts masked. It now compares with what
  `poll` last settled on.

- **Images**: `grix build` makes a `.grix` file (a file tree, settings,
  and the kernel) from a Grixfile or flags. The base is a Docker/OCI image
  (pulled from a registry with anonymous token auth and digest checks, or
  read from an OCI layout or `docker save` archive) or nothing at all.
  Build steps run in grix itself. `python:3.12-alpine` with `pip install
  requests` builds and runs; a from-scratch image of one static program is
  2.6 MB. The host's network proxy now enforces `net` itself, since an
  image's kernel isn't trusted to.

- **MCP and Python**: `grix mcp` serves agents a `run` tool (files, image,
  mounts, stdin, capabilities, exports back in the answer) and
  `build_image`, confined to roots and an allowed capability set (no `net`
  unless enabled). Agents only read the host unless the server is
  `--writable`; builds follow the server's policy (`build::BuildPolicy`:
  no registry or Docker sources without `net`); images run on the server's
  kernel; registry token services and redirects must be https. `python/`
  is a small package over `grix run --json`.

- **Own VMM** (`crates/vmm`, `grix-vmm`): Hypervisor.framework, one vCPU,
  the framework's GICv3 (`hv_gic`, macOS 15+) at QEMU `virt`'s addresses,
  so the kernel didn't change. It emulates a PL011 (transmit only, to the
  serial socket) and a virtio-mmio console in slot 0 (SPI 16), which
  holds output back until stdout takes it and waits for the guest's
  receive buffers. WFI sleeps until a device interrupts or the vtimer's
  deadline; the framework delivers the timer itself. PSCI SYSTEM_OFF ends
  the process. After setup it enters a `(deny default)` macOS sandbox.
  The host runs it as a child process exactly like QEMU (same stdio and
  serial socket); it's the default on macOS when built (`make vmm`
  codesigns it), and `GRIX_ACCEL=...` or `GRIX_VMM=qemu` mean QEMU. A
  hand-assembled stand-in kernel tests the serial/panic path on both.
  On Linux the same machine runs on KVM (`kvm.rs`: in-kernel vGICv3,
  PSCI and WFI; we see MMIO and the power-off), confined by a seccomp
  allowlist applied to every thread (TSYNC). The layout moved to
  `grix_abi::machine`, with the GIC redistributors' base in the boot
  image header (ABI 2): Hypervisor.framework reserves 32 MiB of
  redistributors, which from QEMU's base would cover the UART and virtio,
  so grix-vmm puts them at 0x1000_0000. `make test-kvm` boots Alpine's
  kernel in QEMU with nested virtualization (HVF, M3+) and runs static
  musl builds of grix and grix-vmm there.

- **Snapshots** (`grix snapshot`, `grix run --snapshot`,
  `Sandbox::snapshot`, `Snapshot::run`, MCP, Python): the kernel makes
  `SNAPSHOT_CALL` the first time it idles with a thread waiting for
  input; grix-vmm saves registers (general, system, FP/SIMD, GIC CPU
  interface), the framework's GIC state, the console device and sparse
  RAM to fd 3, and restored runs map RAM copy-on-write. Python with a few
  imports: 2.0 s cold, 0.13 s from a snapshot. The call had to move out
  of SMCCC's vendor-hypervisor range (0xC6...), which
  Hypervisor.framework answers itself with NOT_SUPPORTED; set_simd_fp_reg
  takes a vector by value, so it's called from inline assembly.

- **More CPUs** (`smp.rs`, `--cpus N`, `GRIX_CPUS` for test runs): a
  big kernel lock taken at trap entry, gang scheduling of the running
  process's threads, per-CPU scheduling state swapped into `Process`,
  idle CPUs waiting outside every lock, process switches / finalize /
  execve only when no other CPU runs the process, broadcast TLB flushes,
  break-before-make in COW, and PSCI CPU_ON for secondaries (grix-vmm
  creates every vCPU up front, with one vtimer offset; KVM starts them
  itself). Two bugs worth remembering: a secondary's Rust frame sat in
  the trap frame at the top of its stack; and a thread picked up by an
  idle CPU went back to user code without its pending signals, so Go's
  preemption signal (sent once until it lands) was lost and the spinning
  thread never entered the kernel again. 3.9× on 4 CPUs for CPU-bound
  threads.

- **x86_64 programs**: binfmt_misc-style. `Image::x86_64` names an arm64
  translator in the guest (`SandboxBuilder::x86_64(host_path)` imports it
  at `/usr/libexec/grix/x86_64`); `resolve_interpreters` runs it for an
  x86_64 ELF with the program's path and arguments. Alpine's static-pie
  qemu-x86_64 needed only MREMAP_FIXED (now implemented) and
  /proc/sys/vm/mmap_min_addr; dynamically linked x86_64 Alpine busybox
  and CPython (threads, hashlib) run with `QEMU_LD_PREFIX=/`.
  `tools/alpine.py --arch x86_64` fetches x86_64 packages.

- **glibc programs** (round 2, item 9): Debian bookworm's bash, coreutils,
  tar, perl, git and curl, `apt-get install` in a build step, and the
  official python and node images. glibc's resolver sends its A and AAAA
  queries in one sendmmsg (now with recvmmsg too); dpkg wants root, so an
  OCI image's `User` (root by default, as in Docker) now sets the uid and
  gid, resolved against the image's /etc/passwd and /etc/group
  (`container::resolve_user`, Grixfile `user`); apt drops to `_apt` with
  setgroups/setresgid/setresuid, so the kernel keeps real, effective and
  saved ids and supplementary groups (`process::Ids`) by Linux's rules,
  with execve resetting the saved ones. GNU mv's `O_PATH|O_DIRECTORY`
  probe of a file must fail with ENOTDIR. The test pulls
  `debian:bookworm-slim` once into `fixtures/build/oci/debian`.

- **Interactive use** (round 2, item 10): job control (stop signals stop
  the whole process, SIGCONT continues it, `WUNTRACED`/`WCONTINUED`,
  `CLD_STOPPED`, from the host too), pseudo-terminals with Linux's line
  discipline, controlling terminals and foreground groups, and TTY mode
  (`grix run -t`, `SandboxBuilder::tty`): an interactive busybox shell
  with ^Z, `jobs`, `fg` and ^C, through Python's `pty` and through the
  host's terminal. Two older bugs came out on the way: musl passes
  ioctl numbers sign-extended (the kernel takes an unsigned int), and
  select and ppoll left the caller's sets as they were on a timeout
  (Linux clears them; CPython reads the sets, so a timed-out select
  looked ready): they now run once more when the deadline passes
  (`Process::block_io_rerun`).

- **Shared file mappings and locks** (round 2, item 11): a MAP_SHARED
  mapping of a file in the sandbox maps the file's own frames
  (`Backing::SharedFile`, `FileData::shared_frame`), never copy-on-write,
  so writes go both ways and across fork; past the end of the file is
  SIGBUS, and a truncate takes the pages out of every process's mappings
  (`AddressSpace::zap_file`). Reading a page the file has no frame for
  (an import's) takes a read-only copy instead, so reading doesn't use up
  file space; once the page gets a frame, the copies go everywhere
  (`fs::take_stale`, `procs::zap_stale`). Sealed memfds can't be written
  through mappings (EPERM, and EBUSY for F_SEAL_WRITE while one may
  write). Locks were faked (always granted), which
  stopped being harmless once there were several processes: `locks.rs`
  now keeps flock locks (per open file description), POSIX record locks
  (per process, gone on any close of the file, on exec's close-on-exec
  and on exit, with `EDEADLK` for a cycle of F_SETLKW waiters) and OFD
  locks, at most `MAX_LOCKS` (ENOLCK). Four processes writing SQLite in
  WAL mode agree.

- **Lazy imports** (round 2, item 12): a read-only live mount the guest
  never refreshes and the host checks against what the guest first saw
  (size and mtime; EIO otherwise; listings and lookups as first answered),
  with copy-up: before anything in it changes, the node (and every
  directory above it, up to the mount) is made the sandbox's own, a
  directory listed in full, keeping its inode number; a file's bytes are
  read in at its first write (a truncate reads only what stays, so
  emptying a 1 GiB file reads nothing). A 400 MB file hashes in a 256 MB
  guest (14 s); Python runs from lazy imports of its /lib and /usr and
  writes its own site-packages without touching the host. ABI 6 (the
  live mount's flags).

- **Networking** (round 2, item 13): AF_UNIX sockets bound to paths (a
  socket node) and abstract names, listening and connecting, datagram and
  seqpacket sockets, SO_PEERCRED and SCM_RIGHTS (`unix.rs`); and UDP
  beyond DNS: datagrams between the guest's own sockets stay in it, others
  go through a socket on the host per guest socket, to destinations the
  host's policy allowed (the first send to one waits for the answer:
  EPERM if refused, with the usual `Denied` event), and only those
  destinations' replies come back. ABI 7.

### Notes for the next session

- In this shell, `cp`, `rm` and `make` are aliased or broken. Use
  `/bin/cp -f`, `/bin/rm`, `/usr/bin/make`. `rm` prompts and hangs a
  non-interactive command. `cargo` lives in `~/.cargo/bin`, which isn't on
  the PATH that `make` sees: `export PATH="$HOME/.cargo/bin:$PATH"`.
- `make fixtures` now also needs Go (cross-compiles `fixtures/go/*`).
- Tests that time things can fail under the full suite's load, mostly on
  TCG: `timers` (an itimer's remaining time), `stdout_backpressure`,
  `serving_through_a_forwarded_port` and `signals_from_the_host` (TCG
  under load), and once `snapshots_resume_where_the_program_waited` (its
  third restore didn't answer `read -t 2` in time). Rerun them alone before suspecting
  a change.
- `make test` builds the kernel and fixtures (it downloads the Alpine
  runtimes, cached in `~/.cache/grix/alpine`) and runs everything.
- When touching boot, MMU, timer or scheduler code, run the suite under
  both `GRIX_ACCEL=tcg` and the default (HVF).
