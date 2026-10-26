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
  kernel log, events, exit status) comes back as frames on the serial port,
  and the host treats it as untrusted input.
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

### Notes for the next session

- In this shell, `cp`, `rm` and `make` are aliased or broken. Use
  `/bin/cp -f`, `/bin/rm`, `/usr/bin/make`.
- `make test` builds the kernel and fixtures (it downloads the Alpine
  runtimes, cached in `~/.cache/grix/alpine`) and runs everything.
- When touching boot, MMU, timer or scheduler code, run the suite under
  both `GRIX_ACCEL=tcg` and the default (HVF).
