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
    orphaned), TTY mode over MCP and Python.
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
    UDP port forwarding (`forward_udp`, `-p 5353:53/udp`): replies leave
    from the forwarded port, only to its recent senders. Left: datagrams
    over one frame (~4 KiB).
14. [x] **Smaller syscalls**: `/proc/<pid>` for every process (`ps`),
    zombies included until they're reaped, pidfds (`pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`,
    `CLONE_PIDFD`, `waitid(P_PIDFD)`, polling), CPU-time timers
    (`ITIMER_VIRTUAL`/`ITIMER_PROF`, POSIX timers on CPU clocks), a stack
    sized by `RLIMIT_STACK` at exec with mmap kept clear of it, and a vDSO
    (`clock_gettime` and `gettimeofday` without a system call). Left:
    `MAP_GROWSDOWN`; another process's CPU clock as a timer's clock;
    `PIDFD_THREAD`.
15. [x] **Images**: zstd layers, registries that need a login (`grix
    login`, Docker's and Podman's logins and credential helpers), a cache
    of applied base layers and of build steps, and images built on grix
    images (`from = "image:FILE"`). Left: pushing images; an image's root
    served lazily.
16. [x] **Agents**: MCP progress/streaming, cancellation and parallel
    tool calls; native Python bindings (PyO3: `grix._native`, the GIL
    released, output callbacks, `grix.Control`, Ctrl-C). Left: wheels on
    PyPI; `build` through the native module.
17. [~] **SMP**: several processes in parallel (each CPU runs a thread
    of any process; three busy processes on four CPUs use 2.5 CPUs'
    worth, one at a time before). Left: finer locking than one kernel
    lock. It shows most where the host has few cores for the vCPUs: on a
    4-core runner shared with other machines, 4 threads on x86_64's 4
    CPUs ran at 0.5 to 1.2 times one (2.0 alone), as vCPUs wait for the
    lock or a TLB flush on one the host descheduled (KVM's PV TLB flush
    and spinlock hints would help). The `smpbench` fixture measures
    each kind of load, with the kernel's counters (/proc/grix/smp).
    Done since: flushes only of the pages that changed and only to the
    CPUs running that address space; a waiter skips the lock's turn of a
    CPU that doesn't take it (twice the kernel-bound throughput with
    80 other vCPUs on a 32-core host); one CPU keeps the deadlines,
    rather than every CPU being interrupted for each; each CPU has its
    own running-process slot, an idle CPU takes none, and the filesystem
    lock knows its holder; a kernel entry moves a pointer to its process,
    not the process; and the scheduler keeps what it looked through every
    process for (threads waiting to run, the next deadline, whether I/O
    waiters need waking) as it changes, so an entry with nothing new costs
    the same beside 32 idle processes as alone (getppid 1.85M a second to
    6.1M on one thread, a futex ping-pong 1.2M to 2.9M on four CPUs).
    Next (phase 2): a reader/writer lock with per-process check-out.
    x86_64's 64 KiB kernel stacks are nearly full: a secondary CPU's
    reaches 57 KiB in smpbench (arm64's 20), and a build with debug
    assertions overflows them. On macOS an idle
    vCPU wakes ~0.5 ms late for a 1 ms timer (the host's timer
    coalescing, in grix-vmm and QEMU alike): a kqueue timer with
    NOTE_CRITICAL in grix-vmm might fix it.
18. [x] **Snapshots**: in TTY mode, with live mounts (each run gives
    their host directories again), with more CPUs, and on KVM.
19. [x] **A native x86_64 kernel** and grix-vmm on x86 KVM, for x86 hosts.
    Done: the kernel's arm64 code under `arch/aarch64`, and `arch/x86_64`
    (PVH boot, traps and `syscall`, paging, LAPIC/IOAPIC, the 16550, the
    signal frame, the vDSO), the x86_64 syscall table, its older calls
    and structure layouts; QEMU microvm (`--arch x86_64`); grix-vmm on
    x86 KVM; every end-to-end test passes on it, in CI on an x86 runner
    with KVM (`x86.yml`); x86_64 Linux releases; AVX and AVX-512 state
    (XSAVE, in Linux's signal frame); more CPUs (INIT/SIPI, TLB flushes
    by IPI); snapshots of x86_64 machines (grix-vmm on KVM); images per
    architecture (`grix build --arch`, linux/amd64 pulled for x86_64), so
    images built on x86_64 Linux run there natively.
20. **An outside security review** (after the above).

### Round 3 (2026-10-29): popular software (COMPAT.md)

Forty-odd programs from their official images. Done: `smaps`,
descriptors reached through symlinks, `IPV6_V6ONLY`, cache maintenance
faults on arm64, UDP `connect(AF_UNSPEC)`, the sandbox's hostname in
every image, `O_ASYNC`/SIGIO, `sendfile` to pipes and sockets,
`preadv2`/`pwritev2`, System V shared memory, `mkdir` EEXIST without
`fs_write`, the stack's strings in Linux's order, build steps' memory,
and shared memory charged to kmem (`/proc/<pid>/auxv`, TCP to 0.0.0.0,
named pipes and images per architecture came with 0.0.31 and 0.0.32).
Left, in order of impact:

21. [x] **Named pipes**: done in the Datadog series (`mkfifo`, `mknod`,
    Linux's open semantics); Elasticsearch's ML controller runs.
22. [x] **x86_64 images from registries**: done with images per
    architecture (`grix build --arch x86_64` pulls linux/amd64); nginx
    and Redis from Docker Hub run on the x86_64 kernel.
23. [x] **`openat2`**: `struct open_how` checked as `build_open_flags`
    does, and every `RESOLVE_*` flag in `Fs::walk` (`fs::Scope`): the
    mounts NO_XDEV won't cross are /proc, /dev and the host's
    directories; magic links are /proc/<pid>/{exe,cwd,root,fd/N};
    RESOLVE_CACHED is EAGAIN on a live mount (the host would be asked).
24. [x] **More than 1024 descriptors**: `RLIMIT_NOFILE` is 1024/65536
    (as Docker gives), the table grows with use up to `fd::MAX_FDS`,
    each slot charged to kmem (fork copies only up to the last open
    one, and fails with ENOMEM past the budget), and the global
    open-file cap is still the bound (ENFILE).
25. [x] **xattrs**: `user.*`, and `trusted.*`/`security.*` for root, on
    the sandbox's nodes, charged to `META_LIMIT`. Left: on live mounts
    (EOPNOTSUPP; the host's would need hostfs messages), in exports,
    POSIX ACLs (`system.posix_acl_*`, EOPNOTSUPP).
26. [x] **Linux AIO**: `io_setup`, `io_destroy`, `io_submit` (pread,
    pwrite, preadv, pwritev, fsync, fdsync, poll), `io_cancel`,
    `io_getevents`, `io_pgetevents`. Reads, writes and syncs complete as
    they're submitted, into Linux's ring in the program's memory (libaio
    and user-space reapers read it); a pipe or socket that isn't ready
    completes with EAGAIN rather than waiting in io_submit as Linux
    would. Polls wait, and complete at the process's next system call
    with the file ready (io_getevents, or epoll on their eventfd).
    Budgeted as Linux's aio-max-nr (65536 events, EAGAIN), each context
    and poll charged to kmem.
    **io_uring stays unimplemented** (ENOSYS, not reported), deliberately:
    it is a large second surface (its own submission paths for every
    operation, each needing its own gate, and shared rings the kernel
    would read while the program runs), and Docker's default seccomp
    profile blocks it, so the programs that use it (MariaDB, nginx,
    libuv) already fall back to AIO or plain calls. It isn't reported:
    they probe it (libuv as every Node program starts), so a report would
    say nothing about a missing feature.
27. [x] **seccomp filters**: `seccomp(2)` and `prctl(PR_SET_SECCOMP)`,
    strict mode and classic BPF checked and run as Linux does (every
    action, stacking, TSYNC, inherited across fork, threads and
    execve, `no_new_privs` unless root), run after the policy's gate so
    it can only take away. Filters are budgeted globally (count and
    instructions, and kmem). Left: user notification
    (`SECCOMP_RET_USER_NOTIF`, `NEW_LISTENER`: reported, refused as a
    kernel before 5.0 refuses them).
28. [x] **ID registers from EL0**: an `mrs` of `ID_AA64*`, `MIDR_EL1`,
    `MPIDR_EL1` or `REVIDR_EL1` (EC 0x18 with FEAT_IDST, an undefined
    instruction without it) is emulated as Linux's `emulate_mrs` does,
    with only the fields HWCAP advertises (HWCAP is made from the same
    values, and has `HWCAP_CPUID`); MIDR as /proc/cpuinfo shows it,
    MPIDR as Linux's safe value. More HWCAPs and HWCAP2 since (see
    Binary compatibility). Left: DPB (DC CVAP), pointer authentication,
    SVE and SME, which need the kernel.
29. [x] `/proc/sys/vm/overcommit_memory` says 1, Linux's "always
    overcommit", which is what grix does (memory is only taken as it's
    touched); Redis and Valkey no longer warn. `max_map_count` is the
    real cap (`MAX_VMAS`), and inotify's limits are there (Chromium).
30. [x] **A guest interface with `net`** (DATADOG.md: the Agent's "not
    connected to the network"): `eth0`, 10.0.2.15/24, up, and the
    default route via 10.0.2.2, in netlink (links, addresses, the main
    table's routes), the interface ioctls, `/proc/net/dev`,
    `/proc/net/route` and `/sys/class/net/eth0`. No device: the host's
    proxy still carries and checks every connection. IPv6 too since
    round 4 (below). Left: counters.

### Round 4 (2026-10-30): popular software again (COMPAT.md, round 2)

COMPAT.md's programs again, and 23 more (MySQL, ClickHouse, Valkey,
DuckDB, Envoy, Jetty, Maven, Gradle, the .NET SDK, Bun, Deno, Kafka,
NATS, Consul, Vault, InfluxDB, OpenSearch, Grafana, headless Chromium,
web stacks on Node, Ruby and Python). Done: Docker's HOME and HOSTNAME
in images (and `run -e KEY`), item 29's sysctls,
`sched_get_priority_max/min` (.NET), NUMA policies for one node,
`prctl`'s refusals, `/proc/<pid>/task`, `SO_PASSCRED` on message
sockets and `capset` that drops everything (Chromium), and a build
step that runs out of room saying so. Left, in order of impact:

31. [x] **Guests bigger than 3 GiB**: up to 64 GiB (`grix_abi::image::MAX_RAM`).
    RAM is in two regions on x86_64 (below 3 GiB and from 4 GiB, as
    `microvm` puts it) and runs on past 4 GiB on arm64
    (`grix_abi::machine::ram_regions`); the kernel maps what's past 4 GiB
    at boot (`arch::map_ram`) and hands those frames out first. What
    grew with RAM on the kernel heap is in RAM: frame reference counts,
    the free list, and the page indexes of files and shared memory
    (`mm::pageindex`). grix-vmm asks Hypervisor.framework for a bigger
    IPA when it needs one. The boot image (imports) must still fit below
    4 GiB.
30. [x] **IPv6 on `eth0`** (what round 3's item 30 left): with `net`,
    `fd00::15/64`, a unique local address (`link::GUEST_V6`, the layout
    slirp4netns and Podman use), in netlink (addresses; the prefix route,
    `::1`'s and the default one via `fd00::2`), `/proc/net/if_inet6`,
    `/proc/net/ipv6_route` and `/etc/hosts`. Programs that ask
    getaddrinfo with `AI_ADDRCONFIG` before listening on `[::]`
    (ClickHouse) now do; ClickHouse then finds `0.0.0.0` taken by `[::]`,
    as under Docker with IPv6, which its `listen_try` makes a warning.
    The proxy carries IPv6 connections where the host can make them, and
    the route to a global address leaves from the ULA (getsockname), so
    RFC 6724's sorting (glibc, musl, Go: fc00::/7's label differs from
    2000::/3's, while an IPv4 destination's matches its source) still
    tries IPv4 first: the address doesn't make anything prefer a route
    the host may not have. `fd00::2` is the host's own loopback when
    named (`allow_host("fd00::2")`, as `10.0.2.2`); the rest of
    `fd00::/64` is refused. No link-local address (nothing could use it).
32. [x] **More than 1024 threads**: each thread takes its kernel state
    from `kmem` (`process::THREAD_COST`: its `Thread` twice over, as
    B-tree nodes filled in order stay half full, x86_64's XSAVE box, its
    `/proc/<pid>/task/<tid>` nodes, which no longer count against file
    metadata). The heap grows by 1/16 of RAM (at most 128 MiB) from the
    top of RAM: half for that budget, half for the holes thousands of
    small allocations leave (measured: 15 MiB free in 30,000 pieces once
    6,000 threads had gone, none big enough for a pipe's buffer).
    threads-max (and `pids.max`) is what the budget's share holds: 4405
    at 512 MiB and 17623 from 2 GiB on (the share stops at 128 MiB) on
    arm64, fewer on x86_64. clone and
    fork fail with EAGAIN at either limit (the `threadmax` fixture).
    Left: ClickHouse still warns below 30,000; a thread's task directory
    is still real nodes (Linux makes them on lookup), whose slots stay
    allocated for reuse.
33. [x] **`SO_PASSCRED` on streams**: a stream's pipe keeps a run per
    writer (`Pipe::creds`, at most `MAX_CRED_RUNS`, charged); reads with
    SO_PASSCRED stop where the writer changes and carry SCM_CREDENTIALS,
    sendmsg's SCM_CREDENTIALS names the writer, and the option set before
    connect, or on a listener, stays.
34. [~] **Landlock**: EOPNOTSUPP from all three calls, unreported, as
    Linux with Landlock disabled at boot (Chromium goes on). The real
    thing, as seccomp is done: a per-thread domain (an `Arc` chain of
    layers like `seccomp::State`, kept across fork, clone and execve,
    only ever added to); `landlock_create_ruleset` an fd holding the
    handled access (ABI 4: filesystem rights through TRUNCATE,
    `BIND_TCP` and `CONNECT_TCP`; unknown bits EINVAL; the version
    query); `landlock_add_rule` with PATH_BENEATH (the parent fd's node,
    pinned so its slot isn't reused) and NET_PORT; `restrict_self`
    needing no_new_privs (nobody has CAP_SYS_ADMIN). Checks: every layer
    that handles an access must have a rule granting it on the node or
    an ancestor, in every path operation (open's read, write, truncate
    and directory listing, execve, create by type, unlink and rmdir,
    rename and link with REFER, truncate, bind on a path), and TCP bind
    and connect by port; EACCES, never reported as denied (the policy
    didn't refuse: the program did). About a thousand lines with tests;
    worth it when a program needs it to start, not as an option.
35. [x] `/proc/<pid>/task/<tid>`: each thread's own name (`Thread::name`:
    PR_SET_NAME, `pthread_setname_np`, writes to its `comm` by the
    process's own threads, EINVAL from others), state (stopped, waiting,
    or running), signals and CPU time. A fork is named as the thread that
    made it, a thread as its creator.
36. [x] `SIOCETHTOOL`: eth0 answers as a container's veth (driver info,
    link up, 10 Gb/s full duplex, the permanent address), lo only its
    link; changes EPERM, the rest EOPNOTSUPP. A `NETLINK_KOBJECT_UEVENT`
    socket binds and hears nothing; what's sent to it gets EPERM back.
37. [x] `splice`, `tee`, `vmsplice` (copies, a chunk per call: nothing
    taken from a socket is lost to a full pipe), F_SETPIPE_SZ, and
    `/proc/<pid>/mem` for the process itself (EIO where unmapped or
    read-only: no FOLL_FORCE; another's EACCES, and a descriptor
    inherited across fork EIO).

Also found in the re-runs: Chromium writes `/proc/<pid>/oom_score_adj`
for its renderers (EACCES, logged): a per-process value that may only go
up without CAP_SYS_RESOURCE would do.

## Agent integrations

- [x] MCP server (`grix mcp`): `run` and `build_image` tools, confined to
      roots, an allowed capability set and time/memory caps; host writes
      only with `--writable`.
- [x] Python bindings (`python/`), over `grix run --json`.
- [x] Snapshots: the `snapshot` tool and `run`'s `snapshot` (with the
      server's network policy, whoever wrote the file).
- [x] Streaming output and signals over MCP: progress notifications with
      the output as it comes, cancellation into `RunControl::cancel`, tool
      calls in parallel (`--max-parallel`).
- [x] Native Python bindings (PyO3) instead of driving the CLI
      (`make python`; the CLI is the fallback).
- [x] Monitoring: the kernel's report of its resources and limits hit
      (`guest_stats`, live while a run goes on), the VM's cost to the host
      (`host_usage`), Prometheus metrics (`Metrics`, `--metrics ADDR` for
      `grix run` and `grix mcp`). For a server in a container: no time
      limit (`--timeout 0`), output streamed without a cap or a copy,
      events printed as they happen.
- [ ] /proc/grix/smp's per-CPU counters (kernel entries by kind, the
      kernel lock's waits and holds, TLB flushes and their IPIs, timer
      interrupts) in `guest_stats` too, and `stats::syscall` and
      `page_fault` as sums of per-CPU counts rather than one shared atomic
      on every entry (a `grix_abi::stats` change: bump `ABI_VERSION`).

## Images

- [x] `grix build` from a Grixfile or flags: a Docker/OCI image (registry,
      OCI layout, `docker save`, the Docker daemon) or nothing, copies, files,
      build steps (shell or argv), settings, and the kernel, in a `.grix` file.
      `grix run --image`, `SandboxBuilder::image`, `grix inspect`, `grix pull`.
- [x] Images per architecture: `grix build` and `grix pull` for the host's
      (or `--arch`), linux/arm64 or linux/amd64 and that kernel; an image
      runs on its own architecture anywhere (emulated in QEMU if it isn't
      the host's), and mismatches (kernel, machine, programs, a base
      image, `--arch`) are errors. The build cache is per architecture.
- [ ] Multi-architecture images (one `.grix` with both kernels and trees),
      if a use turns up: today it's one file per architecture.
- [x] zstd-compressed layers (and multi-member gzip).
- [x] Registries that need credentials: `grix login`, Docker's and Podman's
      logins and credential helpers, Bearer (with a login or an identity
      token) and Basic. Agents' builds pull anonymously unless the MCP
      server allows otherwise (`--registry-credentials`).
- [x] Multi-image layering without re-reading the base: images built on
      grix images (`from = "image:FILE"`), and a cache of applied bases and
      of build steps (`--no-cache`).
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
- [x] `CLONE_FILES`/`CLONE_FS`/`CLONE_SIGHAND` without `CLONE_THREAD`, `CLONE_PARENT`
      (by `clone` and `clone3`, with `CLONE_CLEAR_SIGHAND`): a shared descriptor
      table (owning its POSIX locks, as Linux's files_struct does), working
      directory and umask, signal actions (with `CLONE_VM`, so only for vfork).
      `execve` unshares the table and actions; `unshare(2)` the table and
      working directory (and allows what it allows with nothing to unshare).
- [ ] `CLONE_VM` without `CLONE_THREAD` or `CLONE_VFORK` (and so `CLONE_SIGHAND`
      without vfork): a process sharing the caller's memory (reported).
      `CLONE_INTO_CGROUP` (reported). Threads with their own descriptor table or
      working directory: `CLONE_THREAD` without `CLONE_FILES`/`CLONE_FS` (they
      share them anyway), `unshare(CLONE_FILES|CLONE_FS)` with more threads (reported).
- [x] `/proc/<pid>/…` for every process (`ps`), with `exe`, `cwd`, `root` and `fd/`;
      `/proc/self` is the caller's. Another process's descriptors need its user (or root).
- [x] Job control: stopping and continuing (SIGSTOP/SIGTSTP/SIGCONT, `WUNTRACED`).
      `signal.rs`'s `stop`/`resume`, `job_report`; the `jobs` fixture
      (`job_control` test). Round 2, item 10.

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
- [x] Job control from the host (SIGTSTP/SIGCONT stopping and continuing the program).
      `RunControl::stop`, `ExitStatus::Stopped`, `Event::Stopped`
      (`stopped_and_continued_from_the_host`).
- [x] Stop and continue (SIGSTOP/SIGTSTP/SIGCONT): the whole process
      stops (`Process::stopped`) and the scheduler passes it over.
- [x] Restarted `nanosleep`-style calls without a handler (Linux's
      `restart_syscall`): a woken sleep re-runs with its first deadline
      (`Thread::restart_deadline`), so a stop and continue doesn't
      lengthen it; with a handler, EINTR and the time left in `rem`
      (`signals` fixture).

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
- [x] An option for `write_to` to refuse symlinks that point outside the export (like Python tarfile's `data` filter).
      `Export::write_to_with(dest, Links::Inside)`, `Destinations::links`,
      `grix run --no-outside-links`: a link that is absolute or leads out,
      followed through the export's own links, fails it before anything
      is written (`exports_with_links_inside_only`). Not yet in Grixfiles,
      MCP or Python.
- [x] Read-write host directory mounts, gated by policy.
      Live: `mount` / `mount_read_only` / `--mount HOST:GUEST[:rw|ro]` (`hostfs`: the host serves listings, bytes and changes, confined with `openat`/`O_NOFOLLOW`; any size; host changes show within a second). Or applied when the program ends: `mount_on_exit` / `:on-exit`.
- [ ] Live mounts: a file the host replaces while the program has it open can show the new contents once the host's descriptor for it ages out (it reopens by name). Pin descriptors for files the guest has open (Open/Close requests).
- [x] Live mounts: changes on a read-only mount without `fs_write` report "needs fs_write" (the syscall gate runs first) instead of EROFS.
      The gate looks at what an `fs_write` call would change first
      (`file::read_only_target`), as `open` and `mkdir` do
      (`need_write_in`): EROFS, no denial (`read_only_mounts_without_fs_write`).
- [x] Live mounts: inotify for host-side changes (the host watches what the guest watches: inotify on Linux, kqueue on macOS).
- [ ] Live mounts: hard links within a mount (EPERM today); RENAME_EXCHANGE (EINVAL); O_TMPFILE (EOPNOTSUPP).
- [ ] Faster live-mount round trips (each lookup in a directory too big to hold, and each read past the read-ahead, waits for the host).
- [x] `statfs`/`fstatfs`. `df` fails today; Python `shutil.disk_usage` too.
- [x] `/proc/self/mountinfo`, `/proc/mounts`, `/etc/mtab` (df, findmnt).
- [x] xattrs (`getxattr`/`listxattr`/…): kept on the sandbox's nodes
      (round 3, 25).
- [~] `inotify`. Node `fs.watch`, webpack, watchdog.
      Events for live mounts' changes, the host's and the program's (which
      arrive just after the call that made them, not before it returns).
      The sandbox's own files (imports, written files) make none yet.
- [x] `flock` and `fcntl` record locks with real semantics (sqlite): see
      round 2, item 11.
- [x] Real file timestamps from the host (make, build caches). Everything
      shows boot time today.
      Imports carry the host's mtime (atime and ctime start there too), and files the program changes get real times.
- [x] `sendfile`/`copy_file_range`/`splice`/`tee`. Python `shutil.copyfile`,
      web servers serving static files.
      `sendfile` works between files and to stdout/stderr, and `copy_file_range` between files. `splice`, `tee` and `vmsplice`: round 4, item 37.
- [x] `openat2`, `name_to_handle_at` (newer tools).
      `openat2`: round 3, item 23. `name_to_handle_at` resolves the path
      and answers EOPNOTSUPP, as a filesystem without file handles does;
      `open_by_handle_at` is privileged (`file_handles`).
- [x] `memfd_create`, `/dev/shm` (`shm_open`, POSIX semaphores, multiprocessing).
      `memfd_create` works with seals and needs no `fs_write`. `/dev/shm` is a writable 1777 directory.
- [x] `MAP_SHARED` mappings of writable files, `msync`.
      They map the file's own pages. A live mount's files still map as copies: a writable shared mapping of one, or changing one mapped shared, is reported as unimplemented.
- [x] Executing files the program wrote.
- [x] Large imports without copying everything into RAM (big runtimes,
      datasets): lazy imports (`import_lazy`, `--mount HOST:GUEST:lazy`,
      round 2, item 12), served by the host over hostfs. Not virtio-blk or
      virtio-fs: more devices would break invariant 7.

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
- [x] `/dev/tty`, `/dev/pts`, pseudo-terminals (`openpty`, termios,
      `TIOCGWINSZ`). Interactive REPLs, shells, `less`, progress bars.
      `tty.rs`, `syscall/tty.rs`; the `pty` fixture (`pseudo_terminals`)
      and `an_interactive_shell_on_a_pty` in runtimes.rs.

## Users, environment, host config

- [x] Synthesize `/etc/passwd` and `/etc/group` with the sandbox user (unless
      imported). Python `getpass.getuser()` raises; Node `os.userInfo()` and
      `os.homedir()` throw; `ls -l` and `id` show numbers.
- [x] Opt-in default environment (`HOME`, `PATH`, `LANG`, `TMPDIR`).
      `SandboxBuilder::default_env`, `--default-env`, `default_env` in
      manifests, MCP's `run` and Python: each unless it's set, `HOME` from
      /etc/passwd (`a_default_environment_on_request`). Images get
      Docker's `HOME` and `HOSTNAME` anyway (round 4).
- [~] `/etc/localtime`/`TZ` from the host. Everything is UTC today.
      A UTC `/etc/localtime` is generated unless one is imported (`-i /etc/localtime`). There's no option yet to pass in the host's zone.
- [~] With `net`: `/etc/hosts`, `/etc/resolv.conf`, `/etc/nsswitch.conf`, a CA
      bundle in `/etc/ssl/certs`.
      `/etc/hosts` and `/etc/resolv.conf` are generated unless imported. Alpine's
      runtimes bring their own CA bundle (`ca-certificates`); there's no option yet
      to pass in the host's.
- [x] Configurable hostname: `SandboxBuilder::hostname`, `--hostname`,
      `hostname` in manifests, MCP's `run` and Python (`Image::hostname`;
      uname, /etc/hostname, /etc/hosts, /proc/sys/kernel/hostname, and an
      image's `HOSTNAME`), `grix` by default (`a_host_name_of_its_own`).
      Images don't carry one, as Docker's don't. `sethostname` stays
      privileged.

## Networking (`net`)

- [x] TCP sockets (AF_INET/AF_INET6) proxied through the host: connect,
      send/recv, nonblocking + epoll, `SO_ERROR` for async connect.
      Credit-based flow control (32 KiB per connection each way), half-close,
      `SO_RCVTIMEO`/`SO_SNDTIMEO`. Other socket options are accepted and ignored.
- [~] UDP beyond DNS, raw sockets, ICMP. UDP works (round 2, item 13);
      raw sockets and ICMP are reported as unsupported.
- [x] Listening sockets with port forwarding to the host (bind/listen/accept4).
      `forward` / `-p` / `[[forward]]`. Node and Python servers work.
      UDP too: `forward_udp` / `-p HOST:GUEST/udp` / `protocol = "udp"`.
- [~] Host-side policy: allow-list for outbound connections
      (hosts/ports/CIDRs), DNS policy, bandwidth limits.
      `allow_host` rules (names, wildcards, IPs, CIDRs, ports); DNS only for names
      they cover; the host and special addresses need their own rule. No bandwidth
      limits yet.
- [x] DNS through a host resolver (A and AAAA; other types get empty answers).
- [x] Loopback (127.0.0.1, `::1`, 10.0.2.15) inside the sandbox, so a server
      and its client in the same sandbox work without the host.
- [x] Forwarded connections reach a listener whatever address it bound
      (Docker-like), not only 0.0.0.0. Decided: one on the guest's
      address (10.0.2.15) or all of them, never one bound to loopback only,
      as Linux and Docker's published ports do (`inet.rs`, `Incoming`).
- [x] `AF_NETLINK` route sockets (`getifaddrs`): report `lo` only. Node
      `os.networkInterfaces()` throws today.
      No capability needed: it only reports `lo`. Interface ioctls (`if_nametoindex`) and `/proc/net/dev` work too, and changing interfaces gets EPERM.
- [x] AF_UNIX sockets bound to filesystem paths (bind/listen/accept/connect),
      abstract names, datagrams and seqpackets, `SO_PEERCRED`, `SCM_RIGHTS`.
      `SO_PASSCRED`/`SCM_CREDENTIALS` on messages and streams. Left: a
      descriptor passed through its own socket stays open (Linux collects
      those cycles).
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
- [x] Interactive TTY mode (`grix run -t`, `SandboxBuilder::tty`): the
      program's stdio is /dev/pts/0, the console its master (`tty::pump`,
      `wire::Input::Resize`); `tty_mode`. Not yet over MCP or Python.

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
- [x] `AT_HWCAP2`, `AT_MINSIGSTKSZ`; `HWCAP_CPUID` with emulated ID-register reads.
      `HWCAP_CPUID`: round 3, item 28. `AT_MINSIGSTKSZ` is the signal
      frame's size (`sigframe::max_size`); on arm64 ID_AA64ISAR1's plain
      instructions (JSCVT, FCMA, LRCPC, FRINTTS, SB, BF16, DGH, I8MM) and
      ISAR0's SM3, SM4, FHM, TS and RNDR show now, in HWCAP, HWCAP2 and
      /proc/cpuinfo alike (`id_registers_from_user_mode`,
      `auxv_hwcap2_and_minsigstksz`). x86_64's HWCAP2 is 0 (no
      FSGSBASE).
- [~] `seccomp`/Landlock self-sandboxing (Chrome, systemd services): accept
      and ignore, or implement. seccomp filters work; Landlock is
      EOPNOTSUPP (round 4, item 34, with the design).
- [x] More `prctl` options (`PR_SET_CHILD_SUBREAPER`, `PR_GET_TID_ADDRESS`, …).
      Unknown options are reported as unimplemented.
- [ ] Newer syscalls as programs need them (`futex_waitv`, …).
      `futex_waitv` is done (`WaitOn::FutexV`, the `futexv` fixture).
- [x] x86_64 programs, through a user-mode translator in the arm64 guest
      (`--x86-64`: qemu-x86_64; box64 untested; binfmt_misc-style). x86_64
      Alpine busybox and CPython run.
- [x] A native x86_64 kernel (and grix-vmm on x86 KVM), for x86 hosts and
      full speed there: `kernel/src/arch/x86_64`, `vm_x86.rs`, `x86.yml`
      (round 2, item 19).

## Performance and scale

- [x] SMP: more than one vCPU (`--cpus N`, `SandboxBuilder::cpus`): the
      threads of a process run in parallel (3.9× on 4 CPUs), with a big
      kernel lock; on grix-vmm (HVF, KVM) and QEMU.
- [x] SMP for several processes at once (each CPU runs a thread of any
      process).
- [~] Finer locking than one kernel lock. Round 2, item 17 made the big
      lock cheap (skipping descheduled waiters, per-CPU process slots, a
      filesystem lock that knows its holder, flushes only where needed).
      Left: phase 2, a reader/writer lock with per-process check-out.
- [x] Snapshots of machines with more than one CPU.
- [x] Our own VMM instead of QEMU: `grix-vmm` on Hypervisor.framework
      (macOS 15+) and KVM (arm64 Linux), confined after setup, about 0.1 s
      per run. `make test-kvm` tests KVM from a Mac.
- [x] Snapshots for instant start (`grix snapshot`, `Sandbox::snapshot`,
      MCP, Python): grix-vmm on macOS.
- [x] Snapshots on KVM (vCPU and vGIC state through KVM's device
      attributes, and an SMCCC filter to forward the call).
- [x] Snapshots with live mounts (each run gives them host directories
      again; the host's ids and lazy imports' first views are saved).
- [x] `getdents64` is O(n²) on large directories.
