# TODO: what normal Linux programs still need

The gaps were found by running real programs: Python 3.12, Node 22, Go,
git, coreutils and busybox from Alpine. A note after each item says what
breaks today. To find more, run a program with `grix run --json ...` and
read the `unsupported` / `denied` / `missing` events.

Legend: `[ ]` todo, `[~]` partial, `[x]` done (kept for a while so the list
shows progress).

## Next up

Order: small kernel-only items first, then the ones that need host
support too, then the big ones. Re-probed 2026-10-26: Python (tempfile,
pip, sqlite), Node (fs), `git init` and Go now pass.

1. ~~**Timers**~~: done (see below).
2. ~~**Network interface listing**~~: done (see Networking).
3. ~~**Small Linux gaps**~~: done. `memfd_create`, CPU-time clocks,
   `membarrier`, `mincore`, `prctl`, `signalfd4` and `/etc/localtime` all work.
4. ~~**stdin from the host**, and output size limits~~: done.
5. ~~**A fast host transport**~~: done. stdio, events and stdin travel on a
   virtio console: about 50 MB/s out and 30 MB/s in with HVF, up from
   100 KB/s and 25 KB/s on the UART.
6. ~~**Getting written files back to the host**~~: done. `export` /
   `--export` / `[[export]]` send directories back when the program ends.
7. ~~**fork/exec/wait**~~: done. Shell pipelines, Python `subprocess`,
   Node `child_process`, Go `os/exec` and posix_spawn work.
8. ~~**Networking through the host** (`net`)~~: done. TCP clients and
   servers, DNS, loopback, port forwards and an allow-list.

### Round 2 (2026-10-28), in this order

9. [x] **glibc programs** (Debian/Ubuntu arm64 images): bash, coreutils,
   perl, `apt-get install` in a build step, curl over HTTPS, git, and the
   official python/node images. Needed sendmmsg/recvmmsg (glibc's
   resolver), the image's user (Docker's `User`, root by default), Linux's
   real/effective/saved ids and setgroups, `O_PATH|O_DIRECTORY` on a file
   (ENOTDIR), and ENOENT/ECONNREFUSED for AF_UNIX connects to nothing.
   Left: `capset` (setpriv), supplementary groups in permission checks,
   `posix_openpt` (apt's log; item 10), a `--user` flag for `grix build`
   and `grix run`.
10. [x] **Interactive use**: TTY mode (`grix run -t`, `tty`), pseudo-terminals
    and termios, job control (SIGSTOP/SIGTSTP/SIGCONT, `WUNTRACED`, from the
    host too). Left: packet mode (`TIOCPKT`), `VMIN`+`VTIME`'s interbyte
    timer (any byte returns), orphaned process groups (SIGTSTP from a
    terminal isn't dropped, no SIGHUP when one with stopped members is
    orphaned), snapshots in TTY mode, TTY mode over MCP and Python.
11. [x] **Shared file mappings and locks**: `MAP_SHARED` file mappings are
    the file's pages (writes go both ways, across fork; SIGBUS past the
    end, also after a truncate); `flock`, POSIX record locks (`F_GETLK`,
    waiting, `EDEADLK`, released on any close and on exit) and OFD locks.
    SQLite in WAL mode from several processes works. Left: a live mount's
    files still map as copies (a writable shared mapping of one is
    unimplemented); locks are the sandbox's own (the host doesn't see
    them).
12. [x] **Big imports without copying them into RAM**: lazy imports
    (`import_lazy`, `--mount HOST:GUEST:lazy`), read from the host as
    they're used, frozen as the program first saw them, with changes
    copied into the sandbox. Python runs from lazy imports of its own
    /lib and /usr and installs into them. Left: an image's root served
    lazily (needs its layers unpacked on the host: item 15's cache);
    reading is about 30 MB/s (one 64 KiB request at a time); copying up a
    directory too large to hold fails with ENOSPC.
13. [x] **Networking**: UDP beyond DNS (through the host, policed per
    destination; between the guest's own sockets in it), AF_UNIX sockets
    bound to paths, abstract names, datagrams, seqpackets and SCM_RIGHTS.
    Left: UDP port forwarding, datagrams over one frame (~4 KiB),
    SO_PASSCRED.
14. [x] **Smaller syscalls**: `/proc/<pid>` for every process (`ps`),
    pidfds (`pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`,
    `CLONE_PIDFD`, `waitid(P_PIDFD)`, polling), CPU-time timers
    (`ITIMER_VIRTUAL`/`ITIMER_PROF`, POSIX timers on CPU clocks), a stack
    sized by `RLIMIT_STACK` at exec with mmap kept clear of it, and a vDSO
    (`clock_gettime` and `gettimeofday` without a system call). Left:
    `MAP_GROWSDOWN`; another process's CPU clock as a timer's clock;
    `/proc/<pid>` of zombies; `PIDFD_THREAD`.
15. **Images**: zstd layers, registries that need a login, a cache of
    applied base layers.
16. **Agents**: MCP progress/streaming and cancellation; native Python
    bindings (PyO3).
17. **SMP**: several processes in parallel; finer locking than one kernel
    lock.
18. **Snapshots**: on KVM, with more CPUs, with live mounts.
19. **A native x86_64 kernel** and grix-vmm on x86 KVM, for x86 hosts.
20. **An outside security review** (after the above).

## Agent integrations

- [x] MCP server (`grix mcp`): `run` and `build_image` tools, confined to
      roots, an allowed capability set and time/memory caps; host writes
      only with `--writable`.
- [x] Python bindings (`python/`), over `grix run --json`.
- [x] Snapshots: the `snapshot` tool and `run`'s `snapshot` (with the
      server's network policy, whoever wrote the file).
- [ ] Streaming output and signals over MCP (progress notifications,
      cancellation into `RunControl`).
- [ ] Native Python bindings (PyO3) instead of driving the CLI.

## Images

- [x] `grix build` from a Grixfile or flags: a Docker/OCI image (registry,
      OCI layout, `docker save`, the Docker daemon) or nothing, copies, files,
      build steps (shell or argv), settings, and the kernel, in a `.grix` file.
      `grix run --image`, `SandboxBuilder::image`, `grix inspect`, `grix pull`.
- [ ] zstd-compressed layers.
- [ ] Registries that need credentials (only anonymous pulls today).
- [ ] Multi-image layering without re-reading the base (a cache of applied
      bases); building is a full re-import every time.
- [x] A Docker image of grix itself (`Dockerfile`): static `grix` and
      `grix-vmm`, FROM scratch, run with `--device /dev/kvm`.

## Processes and exec

- [x] `#!` scripts for the initial exec and `execve`, including nested
      interpreters and scripts written in the sandbox.
- [x] `fork`/`vfork`/`clone` without `CLONE_THREAD`: separate address spaces
      with copy-on-write. vfork (and `CLONE_VM|CLONE_VFORK`, posix_spawn)
      is a copy too, with the parent waiting for exec or exit. At most 128
      processes (zombies included).
- [x] `execve`/`execveat` (and fexecve): replace the process image, close
      `O_CLOEXEC` fds, keep the pid, reset handlers. Programs written in the
      sandbox run too (`cc` then `./a.out`).
- [x] `wait4`/`waitid` (`WNOHANG`, `WNOWAIT`), exit statuses, zombies,
      `SIGCHLD` (`SIG_IGN`/`SA_NOCLDWAIT` reap at once), orphans go to init.
- [x] Process groups and sessions (`setpgid`, `setsid`, `kill(-pgid)`, `kill(-1)`).
      Init (the program) ignores signals from other processes it has no handler for, as in a pid namespace.
- [x] `pidfd_open`/`pidfd_send_signal`/`pidfd_getfd`/`CLONE_PIDFD`/`waitid(P_PIDFD)`
      (newer Python, Go's `os/exec`, systemd), pollable for the process's end.
- [ ] `CLONE_FILES`/`CLONE_FS`/`CLONE_SIGHAND` without `CLONE_THREAD`, `CLONE_PARENT` (reported).
- [x] `/proc/<pid>/…` for every process (`ps`), with `exe`, `cwd`, `root` and `fd/`;
      `/proc/self` is the caller's. Another process's descriptors need its user (or root).
- [ ] Job control: stopping and continuing (SIGSTOP/SIGTSTP/SIGCONT, `WUNTRACED`).

## Signals

- [x] Deliver signals to handlers: build an `rt_sigframe` (siginfo +
      ucontext with FP/SIMD state) on the user stack, then `rt_sigreturn`.
      Go programs die with signal 23 (the runtime preempts goroutines with
      SIGURG). Python `signal.signal` and Node `process.on('SIGUSR1')` die
      with the signal.
- [x] `SA_SIGINFO`, `SA_ONSTACK` + `sigaltstack`, `SA_NODEFER`, `SA_RESETHAND`.
- [x] Interrupt blocking syscalls: `EINTR`, or restart with `SA_RESTART`.
- [x] Per-thread pending signals, `tgkill` aimed at a specific thread,
      process signals delivered to any thread that doesn't block them.
- [x] Faults (SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGTRAP) delivered to handlers.
      Needed by the JVM, Go (nil checks become panics), and crash reporters.
- [x] `rt_sigsuspend`, `rt_sigtimedwait`, `signalfd4`.
      `rt_sigqueueinfo` and the ppoll/pselect/epoll_pwait masks work too.
- [x] Signals from the host: SIGTERM before the timeout kill, SIGINT from the agent.
      `RunControl::signal` / `stop`, the CLI's Ctrl-C (and SIGTERM, SIGHUP, SIGQUIT), to the program's process group. A timeout sends SIGTERM and waits `grace` (5 s). Threads waiting for a signal (including musl's ppoll-based `pause()`) aren't a deadlock.
- [ ] Job control from the host (SIGTSTP/SIGCONT stopping and continuing the program).
- [ ] Stop and continue (SIGSTOP/SIGTSTP/SIGCONT). They are ignored today:
      there is no job control or host to report the stop to.
- [ ] Restarted `nanosleep`-style calls without a handler (Linux's
      `restart_syscall`). This only matters once stop signals exist.

## Timers and clocks

- [x] `alarm`/`setitimer`/`getitimer` (SIGALRM). Python `signal.alarm`
      reports "unsupported setitimer" today.
      ITIMER_VIRTUAL and ITIMER_PROF count the process's CPU time (all of it user time).
- [x] POSIX timers: `timer_create`/`timer_settime`/`timer_gettime`/`timer_delete`.
      Signals with values, overruns, SIGEV_THREAD_ID, SIGEV_NONE and absolute times all work, on CPU-time clocks too
      (the process's or a thread's; another process's is reported as unimplemented).
- [x] `timerfd_create`/`timerfd_settime`/`timerfd_gettime` (event loops,
      systemd-style services).
- [x] Real CPU-time clocks (`CLOCK_PROCESS_CPUTIME_ID`, `CLOCK_THREAD_CPUTIME_ID`,
      `getrusage`, `times`). These report wall time today.
      Per-thread CPU time is accounted by the scheduler. It all counts as user time: system time isn't separated.
- [x] CPU-time timers (`ITIMER_VIRTUAL`/`ITIMER_PROF`, timers on CPU clocks).
- [x] vDSO (`AT_SYSINFO_EHDR`) for fast `clock_gettime`/`gettimeofday`; musl, glibc and Go use it.

## Filesystem

- [x] Writable tmpfs at `/tmp` (and anywhere `fs_write` allows), with a size
      limit. Python `tempfile`, `pip install`, `git init`, compilers,
      `__pycache__`, Node `fs.writeFileSync`.
      With `fs_write` the whole tree is writable in guest memory. File data is limited to half of RAM, and nodes and names to a metadata budget.
- [x] mkdir/unlink/rmdir/rename(2)/link/symlink/truncate/fallocate/chmod/chown/utimensat.
- [x] `O_CREAT`/`O_TRUNC`/`O_APPEND`/`O_EXCL`/`O_TMPFILE`, `pwrite64`/`pwritev`.
- [x] Copy-on-write overlay over imported files, for programs that modify
      their own tree.
- [x] Hand writable directories back to the host after a run (the agent's results).
      `SandboxBuilder::export` / `--export GUEST:HOST` / `[[export]]`. Sent when the program ends (exit, crash, deadlock), into `RunOutput::exports`, under a `max_export` budget. `Export::write_to` recreates it on the host without following links.
- [x] Export only what changed in an imported tree (an overlay's upper layer, with deletions), instead of all of it.
      Mounts do this: the kernel compares each node with what was imported and sends new and changed entries and the topmost removed paths.
- [x] Exports after a timeout: the host would have to ask the guest to stop (see signals from the host).
      A timeout sends SIGTERM first; a program that ends within the grace period sends its exports.
- [ ] An option for `write_to` to refuse symlinks that point outside the export (like Python tarfile's `data` filter).
- [x] Read-write host directory mounts, gated by policy.
      Live: `mount` / `mount_read_only` / `--mount HOST:GUEST[:rw|ro]` (`hostfs`: the host serves listings, bytes and changes, confined with `openat`/`O_NOFOLLOW`; any size; host changes show within a second). Or applied when the program ends: `mount_on_exit` / `:on-exit`.
- [ ] Live mounts: a file the host replaces while the program has it open can show the new contents once the host's descriptor for it ages out (it reopens by name). Pin descriptors for files the guest has open (Open/Close requests).
- [ ] Live mounts: changes on a read-only mount without `fs_write` report "needs fs_write" (the syscall gate runs first) instead of EROFS.
- [ ] Live mounts: inotify for host-side changes; hard links within a mount (EPERM today); RENAME_EXCHANGE (EINVAL); O_TMPFILE (EOPNOTSUPP).
- [ ] Faster live-mount round trips (each lookup in a directory too big to hold, and each read past the read-ahead, waits for the host).
- [x] `statfs`/`fstatfs`. `df` fails today; Python `shutil.disk_usage` too.
- [x] `/proc/self/mountinfo`, `/proc/mounts`, `/etc/mtab` (df, findmnt).
- [x] xattrs (`getxattr`/`listxattr`/…): answer ENODATA/ENOTSUP.
      Coreutils `ls -la` currently hits an "unknown" syscall.
- [~] `inotify`. Node `fs.watch`, webpack, watchdog.
      Watches can be added and removed but never fire, even now that files change.
- [x] `flock` and `fcntl` record locks with real semantics (sqlite): see
      round 2, item 11.
- [x] Real file timestamps from the host (make, build caches). Everything
      shows boot time today.
      Imports carry the host's mtime (atime and ctime start there too), and files the program changes get real times.
- [~] `sendfile`/`copy_file_range`/`splice`/`tee`. Python `shutil.copyfile`,
      web servers serving static files.
      `sendfile` works between files and to stdout/stderr, and `copy_file_range` between files. `splice` and `tee` are missing.
- [ ] `openat2`, `name_to_handle_at` (newer tools).
- [x] `memfd_create`, `/dev/shm` (`shm_open`, POSIX semaphores, multiprocessing).
      `memfd_create` works with seals and needs no `fs_write`. `/dev/shm` is a writable 1777 directory.
- [x] `MAP_SHARED` mappings of writable files, `msync`.
      They map the file's own pages. A live mount's files still map as copies: a writable shared mapping of one, or changing one mapped shared, is reported as unimplemented.
- [x] Executing files the program wrote.
- [ ] Large imports without copying everything into RAM: read-only
      virtio-blk/virtio-fs, loaded lazily (big runtimes, datasets).

## /proc, /sys, /dev

- [x] `/proc/self/maps` (glibc `pthread_getattr_np`, so Rust std stack guards
      on glibc, the JVM, sanitizers).
- [x] `/proc/self/fd/N`, `/dev/fd`, `/dev/stdin|stdout|stderr`.
- [x] `/proc/self/{status,stat,statm,cmdline,environ,cgroup,limits,auxv}`.
      Go reads `/proc/self/cgroup`.
- [x] `/proc/{cpuinfo,stat,meminfo,uptime,loadavg,version}`. Node
      `os.cpus()` returns `[]`; busybox `free` fails.
- [x] `/proc/sys/kernel/{hostname,osrelease,ostype,pid_max,random/uuid}`,
      `/proc/sys/vm/overcommit_memory`.
- [x] `/sys/devices/system/cpu/{online,possible}` (glibc `get_nprocs`),
      `/sys/kernel/mm/transparent_hugepage/*` (Go probes it),
      `/sys/fs/cgroup/*` (cgroup v2 limits for Go/Java/Node).
- [ ] `/dev/tty`, `/dev/pts`, pseudo-terminals (`openpty`, termios,
      `TIOCGWINSZ`). Interactive REPLs, shells, `less`, progress bars.

## Users, environment, host config

- [x] Synthesize `/etc/passwd` and `/etc/group` with the sandbox user (unless
      imported). Python `getpass.getuser()` raises; Node `os.userInfo()` and
      `os.homedir()` throw; `ls -l` and `id` show numbers.
- [ ] Opt-in default environment (`HOME`, `PATH`, `LANG`, `TMPDIR`).
- [~] `/etc/localtime`/`TZ` from the host. Everything is UTC today.
      A UTC `/etc/localtime` is generated unless one is imported (`-i /etc/localtime`). There's no option yet to pass in the host's zone.
- [~] With `net`: `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, a CA
      bundle in `/etc/ssl/certs`.
      `/etc/hosts` and `/etc/resolv.conf` are generated unless imported. Alpine's
      runtimes bring their own CA bundle (`ca-certificates`); there's no option yet
      to pass in the host's.
- [ ] Configurable hostname.

## Networking (`net`)

- [x] TCP sockets (AF_INET/AF_INET6) proxied through the host: connect,
      send/recv, nonblocking + epoll, `SO_ERROR` for async connect.
      Credit-based flow control (32 KiB per connection each way), half-close,
      `SO_RCVTIMEO`/`SO_SNDTIMEO`. Other socket options are accepted and ignored.
- [~] UDP beyond DNS, raw sockets, ICMP. UDP works (round 2, item 13);
      raw sockets and ICMP are reported as unsupported.
- [x] Listening sockets with port forwarding to the host (bind/listen/accept4).
      `forward` / `-p` / `[[forward]]`. Node and Python servers work.
- [~] Host-side policy: allow-list for outbound connections
      (hosts/ports/CIDRs), DNS policy, bandwidth limits.
      `allow_host` rules (names, wildcards, IPs, CIDRs, ports); DNS only for names
      they cover; the host and special addresses need their own rule. No bandwidth
      limits yet.
- [x] DNS through a host resolver (A and AAAA; other types get empty answers).
- [x] Loopback (127.0.0.1, `::1`, 10.0.2.15) inside the sandbox, so a server
      and its client in the same sandbox work without the host.
- [ ] Forwarded connections reach a listener whatever address it bound
      (Docker-like), not only 0.0.0.0. Decide whether that should be stricter.
- [x] `AF_NETLINK` route sockets (`getifaddrs`): report `lo` only. Node
      `os.networkInterfaces()` throws today.
      No capability needed: it only reports `lo`. Interface ioctls (`if_nametoindex`) and `/proc/net/dev` work too, and changing interfaces gets EPERM.
- [x] AF_UNIX sockets bound to filesystem paths (bind/listen/accept/connect),
      abstract names, datagrams and seqpackets, `SO_PEERCRED`, `SCM_RIGHTS`.
      Left: `SO_PASSCRED`/`SCM_CREDENTIALS` on receive; a descriptor passed
      through its own socket stays open (Linux collects those cycles).
- [x] A fast host transport. virtio-console (port 1 of a
      `virtio-serial-device`) carries the framed channel. Networking adds
      `link` messages there.

## stdio and host interaction

- [x] stdin from the host (pipes, interactive sessions). stdin is always EOF today.
      Piped, from the library or the CLI, with backpressure. Interactive sessions come with TTY mode.
- [x] Faster output path.
      virtio-console moves frames through shared 4 KiB buffers: about 50 MB/s out and 30 MB/s in with HVF. A slow host reader blocks the writing thread only (EAGAIN with `O_NONBLOCK`, epoll readiness), never the whole VM.
- [x] Output size limits with truncation reported.
      `max_output` (64 MiB per stream by default): the program keeps running, and the rest is dropped and reported.
- [ ] Interactive TTY mode (`grix run -t`).

## Memory

- [x] Copy-on-write and shared-page refcounting (needed by fork).
- [x] `MAP_SHARED` anonymous memory (and `/dev/zero`) shared across fork.
- [~] Linux-like stack growth and guard pages (`MAP_GROWSDOWN`, `RLIMIT_STACK`).
      exec sizes the stack from `RLIMIT_STACK` (up to 4 GiB), and mmap stays 128 MiB below it
      (a hint, 1 MiB). `MAP_GROWSDOWN` mappings don't grow.
- [x] `membarrier` commands (`PRIVATE_EXPEDITED` for .NET and JITs): trivial on one CPU.
- [~] `mincore`; accept the remaining `madvise` advice values.
      `mincore` works.
- [ ] Free empty page-table pages on munmap.
- [x] Bound kernel memory a program can tie up. Pipe buffers, netlink
      replies, /proc contents, queued RT signals, mappings and inotify
      watches all hit an errno before the heap runs out (kmem.rs).
- [ ] `find_free` (mmap without a hint) is O(n) in the number of mappings.

## Binary compatibility

- [x] Report the syscall number for unknown syscalls. Today the event says
      only "unsupported unknown".
- [x] glibc dynamic executables (Debian/Ubuntu arm64): see round 2, item 9.
- [ ] `AT_HWCAP2`, `AT_MINSIGSTKSZ`; `HWCAP_CPUID` with emulated ID-register reads.
- [ ] `seccomp`/Landlock self-sandboxing (Chrome, systemd services): accept
      and ignore, or implement.
- [x] More `prctl` options (`PR_SET_CHILD_SUBREAPER`, `PR_GET_TID_ADDRESS`, …).
      Unknown options are reported as unimplemented.
- [ ] Newer syscalls as programs need them (`futex_waitv`, …).
- [x] x86_64 programs, through a user-mode translator in the arm64 guest
      (`--x86-64`: qemu-x86_64; box64 untested; binfmt_misc-style). x86_64
      Alpine busybox and CPython run.
- [ ] A native x86_64 kernel (and grix-vmm on x86 KVM), for x86 hosts and
      full speed there.

## Performance and scale

- [x] SMP: more than one vCPU (`--cpus N`, `SandboxBuilder::cpus`): the
      threads of a process run in parallel (3.9× on 4 CPUs), with a big
      kernel lock; on grix-vmm (HVF, KVM) and QEMU.
- [ ] SMP for several processes at once (today they take turns: gang
      scheduling), and finer locking than one kernel lock.
- [ ] Snapshots of machines with more than one CPU.
- [x] Our own VMM instead of QEMU: `grix-vmm` on Hypervisor.framework
      (macOS 15+) and KVM (arm64 Linux), confined after setup, about 0.1 s
      per run. `make test-kvm` tests KVM from a Mac.
- [x] Snapshots for instant start (`grix snapshot`, `Sandbox::snapshot`,
      MCP, Python): grix-vmm on macOS.
- [ ] Snapshots on KVM (vCPU and vGIC state through KVM's device
      attributes, and an SMCCC filter to forward the call).
- [ ] Snapshots with live mounts (the host's open files would need
      saving too).
- [x] `getdents64` is O(n²) on large directories.
