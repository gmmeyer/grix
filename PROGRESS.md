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
  unimplemented.
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

Next, in TODO.md order: networking through the host.

### Notes for the next session

- In this shell, `cp`, `rm` and `make` are aliased or broken. Use
  `/bin/cp -f`, `/bin/rm`, `/usr/bin/make`. `rm` prompts and hangs a
  non-interactive command. `cargo` lives in `~/.cargo/bin`, which isn't on
  the PATH that `make` sees: `export PATH="$HOME/.cargo/bin:$PATH"`.
- `make fixtures` now also needs Go (cross-compiles `fixtures/go/*`).
- `make test` builds the kernel and fixtures (it downloads the Alpine
  runtimes, cached in `~/.cache/grix/alpine`) and runs everything.
- When touching boot, MMU, timer or scheduler code, run the suite under
  both `GRIX_ACCEL=tcg` and the default (HVF).
