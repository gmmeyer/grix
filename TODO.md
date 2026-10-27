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
4. **stdin from the host**, and output size limits.
5. **Getting written files back to the host** (the agent's results).
6. **fork/exec/wait**: Python `subprocess`, Node `child_process`, shell
   pipelines and `git commit` (run through `sh`) all stop here.
7. **Networking through the host** (`net`).

## Processes and exec

- [~] `#!` scripts for the initial exec and `execve`.
      Done for the initial program, including nested interpreters (`pip3` runs). `execve` comes with processes.
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
- [ ] Signals from the host: SIGTERM before the timeout kill, SIGINT from the agent.
- [ ] Stop and continue (SIGSTOP/SIGTSTP/SIGCONT). They are ignored today:
      there is no job control or host to report the stop to.
- [ ] Restarted `nanosleep`-style calls without a handler (Linux's
      `restart_syscall`). This only matters once stop signals exist.

## Timers and clocks

- [x] `alarm`/`setitimer`/`getitimer` (SIGALRM). Python `signal.alarm`
      reports "unsupported setitimer" today.
      ITIMER_REAL works. ITIMER_VIRTUAL/PROF count CPU time and are reported as unimplemented.
- [x] POSIX timers: `timer_create`/`timer_settime`/`timer_gettime`/`timer_delete`.
      Signals with values, overruns, SIGEV_THREAD_ID, SIGEV_NONE and absolute times all work. CPU-time clocks are reported as unimplemented.
- [x] `timerfd_create`/`timerfd_settime`/`timerfd_gettime` (event loops,
      systemd-style services).
- [x] Real CPU-time clocks (`CLOCK_PROCESS_CPUTIME_ID`, `CLOCK_THREAD_CPUTIME_ID`,
      `getrusage`, `times`). These report wall time today.
      Per-thread CPU time is accounted by the scheduler. It all counts as user time: system time isn't separated.
- [ ] CPU-time timers (`ITIMER_VIRTUAL`/`ITIMER_PROF`, timers on CPU clocks). Reported as unimplemented.
- [ ] vDSO (`AT_SYSINFO_EHDR`) for fast `clock_gettime`; glibc and Go use it
      when present. Performance only.

## Filesystem

- [x] Writable tmpfs at `/tmp` (and anywhere `fs_write` allows), with a size
      limit. Python `tempfile`, `pip install`, `git init`, compilers,
      `__pycache__`, Node `fs.writeFileSync`.
      With `fs_write` the whole tree is writable in guest memory. File data is limited to half of RAM, and nodes and names to a metadata budget.
- [x] mkdir/unlink/rmdir/rename(2)/link/symlink/truncate/fallocate/chmod/chown/utimensat.
- [x] `O_CREAT`/`O_TRUNC`/`O_APPEND`/`O_EXCL`/`O_TMPFILE`, `pwrite64`/`pwritev`.
- [x] Copy-on-write overlay over imported files, for programs that modify
      their own tree.
- [ ] Hand writable directories back to the host after a run (the agent's results).
- [ ] Read-write host directory mounts, gated by policy.
- [x] `statfs`/`fstatfs`. `df` fails today; Python `shutil.disk_usage` too.
- [x] `/proc/self/mountinfo`, `/proc/mounts`, `/etc/mtab` (df, findmnt).
- [x] xattrs (`getxattr`/`listxattr`/…): answer ENODATA/ENOTSUP.
      Coreutils `ls -la` currently hits an "unknown" syscall.
- [~] `inotify`. Node `fs.watch`, webpack, watchdog.
      Watches can be added and removed but never fire, even now that files change.
- [ ] `flock` and `fcntl` record locks with real semantics (sqlite) once there
      are writers.
- [~] Real file timestamps from the host (make, build caches). Everything
      shows boot time today.
      Files the program changes get real atime/mtime/ctime. Imports still show boot time.
- [~] `sendfile`/`copy_file_range`/`splice`/`tee`. Python `shutil.copyfile`,
      web servers serving static files.
      `sendfile` works between files and to stdout/stderr, and `copy_file_range` between files. `splice` and `tee` are missing.
- [ ] `openat2`, `name_to_handle_at` (newer tools).
- [x] `memfd_create`, `/dev/shm` (`shm_open`, POSIX semaphores, multiprocessing).
      `memfd_create` works with seals and needs no `fs_write`. `/dev/shm` is a writable 1777 directory.
- [ ] `MAP_SHARED` mappings of writable files, `msync`.
      Shared mappings hold a copy taken at fault time. Changing the file, or making the mapping writable, is reported as unimplemented.
- [ ] Executing files the program wrote (needs execve).
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
- [x] `AF_NETLINK` route sockets (`getifaddrs`): report `lo` only. Node
      `os.networkInterfaces()` throws today.
      No capability needed: it only reports `lo`. Interface ioctls (`if_nametoindex`) and `/proc/net/dev` work too, and changing interfaces gets EPERM.
- [ ] AF_UNIX sockets bound to filesystem paths (bind/listen/accept/connect),
      datagram and seqpacket pairs, `SCM_RIGHTS` fd passing.
      `socket(AF_UNIX)` works for ioctls. bind, connect and listen on it are reported as unimplemented.
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
- [x] `membarrier` commands (`PRIVATE_EXPEDITED` for .NET and JITs): trivial on one CPU.
- [~] `mincore`; accept the remaining `madvise` advice values.
      `mincore` works.
- [ ] Free empty page-table pages on munmap.

## Binary compatibility

- [x] Report the syscall number for unknown syscalls. Today the event says
      only "unsupported unknown".
- [ ] glibc dynamic executables (Debian/Ubuntu arm64). Most prebuilt Linux
      tools are glibc-linked; untested so far.
- [ ] `AT_HWCAP2`, `AT_MINSIGSTKSZ`; `HWCAP_CPUID` with emulated ID-register reads.
- [ ] `seccomp`/Landlock self-sandboxing (Chrome, systemd services): accept
      and ignore, or implement.
- [x] More `prctl` options (`PR_SET_CHILD_SUBREAPER`, `PR_GET_TID_ADDRESS`, …).
      Unknown options are reported as unimplemented.
- [ ] Newer syscalls as programs need them (`futex_waitv`, …).
- [ ] x86_64 guests. Most prebuilt binaries are x86_64.

## Performance and scale

- [ ] SMP: more than one vCPU.
- [ ] Our own VMM instead of QEMU (boot time, attack surface).
- [ ] Snapshots of booted runtimes for instant start.
- [x] `getdents64` is O(n²) on large directories.
