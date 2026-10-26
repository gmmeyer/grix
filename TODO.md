# TODO: what normal Linux programs still need

The gaps were found by running real programs: Python 3.12, Node 22, Go,
git, coreutils and busybox from Alpine. A note after each item says what
breaks today. To find more, run a program with `grix run --json ...` and
read the `unsupported` / `denied` / `missing` events.

Legend: `[ ]` todo, `[~]` partial, `[x]` done (kept for a while so the list
shows progress).

## Processes and exec

- [~] `#!` scripts for the initial exec and `execve`. `pip3` fails today
      with "not an ELF file".
      Done for the initial program, including nested interpreters; `execve` comes with processes.
- [ ] `fork`/`vfork`/`clone` without `CLONE_THREAD`: separate address spaces
      with copy-on-write. Python `subprocess`, Node `child_process`,
      busybox `sh -c 'a | b'` ("can't fork"), make, compilers.
- [ ] `execve`/`execveat`: replace the process image, close `O_CLOEXEC`
      fds, keep pid.
- [ ] `wait4`/`waitid`, exit statuses, zombies, `SIGCHLD`.
- [ ] Process groups and sessions (`setpgid`, `setsid`, `kill(-pgid)`).
- [ ] `pidfd_open`/`pidfd_send_signal`/`CLONE_PIDFD` (newer Python, Go, systemd).
- [ ] `/proc/<pid>/…` for every process; `ps` lists nothing today.

## Signals

- [ ] Deliver signals to handlers: build an `rt_sigframe` (siginfo +
      ucontext with FP/SIMD state) on the user stack, then `rt_sigreturn`.
      Go programs die with signal 23 (the runtime preempts goroutines with
      SIGURG). Python `signal.signal` and Node `process.on('SIGUSR1')` die
      with the signal.
- [ ] `SA_SIGINFO`, `SA_ONSTACK` + `sigaltstack`, `SA_NODEFER`, `SA_RESETHAND`.
- [ ] Interrupt blocking syscalls: `EINTR`, or restart with `SA_RESTART`.
- [ ] Per-thread pending signals, `tgkill` aimed at a specific thread,
      process signals delivered to any thread that doesn't block them.
- [ ] Faults (SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGTRAP) delivered to handlers.
      Needed by the JVM, Go (nil checks become panics), and crash reporters.
- [ ] `rt_sigsuspend`, `rt_sigtimedwait`, `signalfd4`.
- [ ] Signals from the host: SIGTERM before the timeout kill, SIGINT from the agent.

## Timers and clocks

- [ ] `alarm`/`setitimer`/`getitimer` (SIGALRM). Python `signal.alarm`
      reports "unsupported setitimer" today.
- [ ] POSIX timers: `timer_create`/`timer_settime`/`timer_gettime`/`timer_delete`.
- [ ] `timerfd_create`/`timerfd_settime`/`timerfd_gettime` (event loops,
      systemd-style services).
- [ ] Real CPU-time clocks (`CLOCK_PROCESS_CPUTIME_ID`, `CLOCK_THREAD_CPUTIME_ID`,
      `getrusage`, `times`). These report wall time today.
- [ ] vDSO (`AT_SYSINFO_EHDR`) for fast `clock_gettime`; glibc and Go use it
      when present. Performance only.

## Filesystem

- [ ] Writable tmpfs at `/tmp` (and anywhere `fs_write` allows), with a size
      limit. Python `tempfile`, `pip install`, `git init`, compilers,
      `__pycache__`, Node `fs.writeFileSync`.
- [ ] mkdir/unlink/rmdir/rename(2)/link/symlink/truncate/fallocate/chmod/chown/utimensat.
- [ ] `O_CREAT`/`O_TRUNC`/`O_APPEND`/`O_EXCL`/`O_TMPFILE`, `pwrite64`/`pwritev`.
- [ ] Copy-on-write overlay over imported files, for programs that modify
      their own tree.
- [ ] Hand writable directories back to the host after a run (the agent's results).
- [ ] Read-write host directory mounts, gated by policy.
- [x] `statfs`/`fstatfs`. `df` fails today; Python `shutil.disk_usage` too.
- [x] `/proc/self/mountinfo`, `/proc/mounts`, `/etc/mtab` (df, findmnt).
- [x] xattrs (`getxattr`/`listxattr`/…): answer ENODATA/ENOTSUP.
      Coreutils `ls -la` currently hits an "unknown" syscall.
- [~] `inotify`. Node `fs.watch`, webpack, watchdog. Imports never change,
      so a watch that never fires is correct until writes exist.
      Watches can be added and removed, and never fire. Real events come with the writable filesystem.
- [ ] `flock` and `fcntl` record locks with real semantics (sqlite) once there
      are writers.
- [ ] Real file timestamps from the host (make, build caches). Everything
      shows boot time today.
- [ ] `sendfile`/`copy_file_range`/`splice`/`tee`. Python `shutil.copyfile`,
      web servers serving static files.
- [ ] `openat2`, `name_to_handle_at` (newer tools).
- [ ] `memfd_create`, `/dev/shm` (`shm_open`, POSIX semaphores, multiprocessing).
- [ ] `MAP_SHARED` mappings of writable files, `msync`.
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
- [ ] `/etc/localtime`/`TZ` from the host. Everything is UTC today.
- [ ] With `net`: `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, a CA
      bundle in `/etc/ssl/certs`.
- [ ] Configurable hostname.

## Networking (`net`)

- [ ] TCP/UDP sockets (AF_INET/AF_INET6) proxied through the host: connect,
      send/recv, nonblocking + epoll, `SO_ERROR` for async connect. Python
      `getaddrinfo` and Node `dns` get ENOSYS today.
- [ ] Listening sockets with port forwarding to the host (bind/listen/accept4).
      Node `http.createServer().listen()` fails today. This is the web-server goal.
- [ ] Host-side policy: allow-list for outbound connections
      (hosts/ports/CIDRs), DNS policy, bandwidth limits.
- [ ] DNS through a host resolver.
- [ ] Loopback (127.0.0.1) inside the sandbox, so a server and its client in
      the same sandbox work without the host.
- [ ] `AF_NETLINK` route sockets (`getifaddrs`): report `lo` only. Node
      `os.networkInterfaces()` throws today.
- [ ] AF_UNIX sockets bound to filesystem paths (bind/listen/accept/connect),
      datagram and seqpacket pairs, `SCM_RIGHTS` fd passing.
- [ ] A fast host transport (virtio-vsock or virtio-console). The UART takes
      one VM exit per byte.

## stdio and host interaction

- [ ] stdin from the host (pipes, interactive sessions). stdin is always EOF today.
- [ ] Faster output path (same UART problem as networking).
- [ ] Output size limits with truncation reported.
- [ ] Interactive TTY mode (`grix run -t`).

## Memory

- [ ] Copy-on-write and shared-page refcounting (needed by fork);
      `MAP_SHARED` anonymous memory across fork.
- [ ] Linux-like stack growth and guard pages (`MAP_GROWSDOWN`, `RLIMIT_STACK`).
- [ ] `membarrier` commands (`PRIVATE_EXPEDITED` for .NET and JITs): trivial on one CPU.
- [ ] `mincore`; accept the remaining `madvise` advice values.
- [ ] Free empty page-table pages on munmap.

## Binary compatibility

- [x] Report the syscall number for unknown syscalls. Today the event says
      only "unsupported unknown".
- [ ] glibc dynamic executables (Debian/Ubuntu arm64). Most prebuilt Linux
      tools are glibc-linked; untested so far.
- [ ] `AT_HWCAP2`, `AT_MINSIGSTKSZ`; `HWCAP_CPUID` with emulated ID-register reads.
- [ ] `seccomp`/Landlock self-sandboxing (Chrome, systemd services): accept
      and ignore, or implement.
- [ ] More `prctl` options (`PR_SET_CHILD_SUBREAPER`, `PR_GET_TID_ADDRESS`, …).
- [ ] Newer syscalls as programs need them (`futex_waitv`, …).
- [ ] x86_64 guests. Most prebuilt binaries are x86_64.

## Performance and scale

- [ ] SMP: more than one vCPU.
- [ ] Our own VMM instead of QEMU (boot time, attack surface).
- [ ] Snapshots of booted runtimes for instant start.
- [ ] `getdents64` is O(n²) on large directories.
