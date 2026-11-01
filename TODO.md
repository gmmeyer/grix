# TODO: what normal Linux programs still need

The gaps were found by running real programs: Python 3.12, Node 22, Go,
git, coreutils and busybox from Alpine. A note after each item says what
breaks today. To find more, run a program with `grix run --json ...` and
read the `unsupported` / `denied` / `missing` events.

Legend: `[ ]` todo, `[~]` partial, `[x]` done (kept for a while so the list
shows progress).

## What's left (after 0.0.70)

Each is written up in its section below; this is the order. No known way
out of the sandbox, and no hang anyone can reproduce.

To decide (each is a choice already made and documented, to keep or
change):

- `fc00::/7` is refused by default, while RFC 1918 stays reachable.
- Alibaba's and Azure's metadata addresses are refused.
- `--no-outside-links` is stricter than it was.
- `O_PATH|O_NOFOLLOW` with `RESOLVE_*` is ELOOP, stricter than Linux.

Robustness, first:

1. `rv048 extremes`: one hang at 0.0.48, none in 32,000 runs since.
   Only worth more with a new idea, or if it comes back.
2. `hostfds` fails without the budget for files held open, on Linux too;
   what it guards of kqueue's descriptors takes an unfixed build on macOS.

Linux behaviour:

3. An image's files keep their owners, then directories' search
   permission, in that order; then an image's user's supplementary
   groups. Nothing surveyed needs them yet: wait for a program that does.
4. A node left unwatched on macOS, newer syscalls as programs ask for
   them.
5. Raw sockets other than ICMP echo (reported as unsupported).
6. `/proc/<pid>/fd/N/name`: left, as few tools go there and it means
   another process's table under the filesystem's lock.

Bigger:

7. `CLONE_VM` without `CLONE_THREAD` or `CLONE_VFORK`: address spaces
   shared between processes.
8. Finer locking: phase 2, a reader/writer lock with per-process
   check-out.
9. Faster live-mount round trips, multi-architecture images, and the
   rest of `/proc/grix/smp`'s counters.
10. An outside security review (round 2, item 20).

By design, not left: eBPF and Linux capabilities (DATADOG.md: the agent
runs and its intake accepts data, system-probe's eBPF features don't),
and io_uring.

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
34. [x] **Landlock**: ABI 5, as Linux's security/landlock
    (`landlock.rs`; AGENTS.md): rulesets as descriptors, path and port
    rules, layers on each thread (at most 16, kept by fork, clone and
    execve), EACCES and EXDEV, never reported. Filesystem rights through
    REFER, TRUNCATE and IOCTL_DEV, TCP bind and connect by port, and no
    looking into processes outside the domain. Left: ABI 6's scoping of
    abstract sockets and signals (domains already compare, `scope_le`:
    signals need a check where `kill` picks a receiver, sockets the
    domain of who bound the name). A descriptor of a generated /proc
    file is EBADFD as a rule's parent (`O_PATH` works); a memfd is taken
    (Linux: EBADFD). A rule on a live mount's file holds for that name
    alone: each name there is a node of its own, and the host says
    nothing of inodes (its other names just stay refused). Moves within
    a mount walk up through the mount point, as Linux's check ends up
    doing, so the tree counts as one mount.
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

### A second security review (of 0.0.48)

Done (`fixtures/src/hardening2.c`, a test each in `guest.rs`, and
`tests/hostfds.rs`): POSIX timers, mappings, argv and UDP verdict tables
charged (timers and argv each panicked the heap); access mode 3 and O_PATH as Linux's FMODE_* and fdget;
socket addresses and paths read once; `/proc/self/fd/N/name`; fexecve of
the file; TIOCGPTPEER and a full ruleset under Landlock; device nodes'
permissions; `sigio_perm`; the tab eraser; timerfds that outlive their
makers; the alternate stack's end; kqueue's descriptors; `Server::restore`.

Left, none of it a way out of the sandbox:

- [ ] An image's files don't keep their owners (a layer's or a build
      step's `chown`): everything imported is the sandbox user's. Docker's
      own entrypoints (PostgreSQL, MariaDB, MySQL) work anyway, as they
      `chown` at run time; it takes the image format, `Entry`, the export
      messages and the tree cache. Do this before the next item, which
      would otherwise refuse services their own directories.
- [ ] A path's directories aren't searched by anyone's permission: only
      the last component is checked (`MAY_EXEC` on the way down isn't).
- [ ] An image's user gets no supplementary groups from its `/etc/group`,
      as Docker's does; `initgroups` in the program works.
- [ ] `/proc/<pid>/fd/N/name` only for the caller's own descriptors:
      another process's are ENOENT past their own name. Few tools go
      there, and it means another process's table under the filesystem's
      lock (`FdTable::walking`).
- [ ] A node with no descriptor left for it (macOS, `at::take_fd`)
      stays unwatched until the guest watches it again.

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
      `grix-vmm`, FROM scratch, run with `--device /dev/kvm`. Its
      `kvm-optional` target adds QEMU, and emulates without KVM.
- [x] Kubernetes without KubeVirt (`examples/kubernetes`): pods get
      `/dev/kvm` from a device plugin (generic-device-plugin, unprivileged):
      `devic.es/kvm` only on nodes with KVM, or `devic.es/kvm-optional` on
      every node, with `/dev/kvm` where there is one (for `kvm-optional`).

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
      Few programs need it (glibc's and musl's posix_spawn use
      `CLONE_VM|CLONE_VFORK`, which works; LinuxThreads-era code and some
      runtimes' helper processes don't), and it's large, so it waits.
      What it would take: `Process::aspace` a handle to one
      `AddressSpace` (as `Process::fs` is a `Shared<FsInfo>`), through its
      ~300 uses; freed with its last sharer, never while active (invariant
      13 then holds as it does for threads); futex queues keyed by the
      address space, not the process, so a wake reaches every sharer's
      waiters; flushes are by root already (x86's `ROOTS`), but
      `smp::alone` and execve's unsharing must take sharers into account
      (execve gives the caller a fresh space, as vfork's child gets);
      `/proc/<pid>/maps` and the mapping budgets (`MAX_VMAS_TOTAL`) count
      a shared space once.
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
- [x] Live mounts: a file the host replaces while the program has it open stays what it opened, as on Linux, and a new open gets what's there now.
      `hostfs::Request::Pin` and `Unpin` (`fs::Pinned`, one a file, held by
      whatever has it open or mapped, the running program's own file too):
      the host holds the file open, and when it sees its name is another
      file gives the name a new id (`check_pinned`), which is a new node
      to the guest. Past the share of descriptors the host keeps for
      guests (`at::take_fd`) an id goes on meaning its name, as it did.
      `files_the_host_replaces_while_they_are_open`.
- [x] Live mounts: changes on a read-only mount without `fs_write` report "needs fs_write" (the syscall gate runs first) instead of EROFS.
      The gate looks at what an `fs_write` call would change first
      (`file::read_only_target`), as `open` and `mkdir` do
      (`need_write_in`): EROFS, no denial (`read_only_mounts_without_fs_write`).
- [x] Live mounts: inotify for host-side changes (the host watches what the guest watches: inotify on Linux, kqueue on macOS).
- [x] Live mounts: hard links within a mount, RENAME_EXCHANGE, O_TMPFILE.
      `hostfs::Request::Link` (`linkat` without AT_SYMLINK_FOLLOW, both ends
      walked to as always) and `Rename`'s `exchange` (RENAME_EXCHANGE,
      macOS's RENAME_SWAP), `links_and_exchanges_in_a_live_mount`. A link's
      new name is a node of its own (the host keeps an id per name), so
      the guest shows the two names different inode numbers and an nlink
      of 1. O_TMPFILE: the file is the sandbox's until linkat names it
      (`Fs::publish`), as a host's O_TMPFILE is Linux's alone: the host
      makes it and takes its bytes, and what has it open follows, with
      `unnamed_files_in_a_live_mount`. Left: its inode number changes
      then, and what has it open isn't pinned; naming one that's mapped
      shared is reported, as a mapping of its pages can't follow it.
- [ ] Faster live-mount round trips (each lookup in a directory too big to hold, and each read past the read-ahead, waits for the host).
- [x] `statfs`/`fstatfs`. `df` fails today; Python `shutil.disk_usage` too.
- [x] `/proc/self/mountinfo`, `/proc/mounts`, `/etc/mtab` (df, findmnt).
- [x] xattrs (`getxattr`/`listxattr`/…): kept on the sandbox's nodes
      (round 3, 25).
- [x] `inotify`. Node `fs.watch`, webpack, watchdog.
      Events for live mounts' changes, the host's and the program's (which
      arrive just after the call that made them, not before it returns),
      and for the sandbox's own files, as Linux's fsnotify makes them:
      `fsevents.c` prints each step's events, and `fsevents.expected` is
      what it printed on Linux. Left: a file with several names is reported
      by its first, whichever it was opened by; an unnamed O_TMPFILE file
      makes none (Linux's name for it is its inode number); a working
      directory removed from under a process isn't IN_DELETE_SELF until
      something else lets go of it.
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
- [x] `/etc/localtime`/`TZ` from the host, on request: everything's UTC
      otherwise, as a zone says something of where the host is.
      `SandboxBuilder::host_timezone`, `--host-timezone`, `host_timezone`
      in manifests and Python, and over MCP if the server allows it
      (`grix mcp --host-timezone`). The zone's file goes in
      `/usr/share/zoneinfo`, and `/etc/localtime` is a link to it, as ICU
      goes by where that leads (a copy of the file is `undefined` to
      Node's Intl, for a zone it can't guess from an abbreviation). A
      `TZ` that's a rule stays `TZ`. `timezone.rs`.
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
- [~] UDP beyond DNS, raw sockets, ICMP. UDP works (round 2, item 13).
      ICMP echo works with the `net_raw` capability, on top of `net` (`ping`,
      ping sockets and `SOCK_RAW`, IPv4 and IPv6): it goes through the
      proxy as UDP does, with `link::ICMP_PORT`, so the host checks the
      capability and the policy (a rule without a port) and sends only
      echo requests, by a ping socket or, where the host has none, a raw
      one, which takes root. The guest answers for its own addresses.
      An image can only ask for it, and a restored snapshot hasn't got it.
      Left: raw sockets of any other kind (reported, as a program making
      its own packets could forge them), `IP_TTL` and so traceroute, a
      reply's real TTL (64 is what's read).
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
- [x] Linux-like stack growth and guard pages (`MAP_GROWSDOWN`, `RLIMIT_STACK`).
      The stack starts at what the arguments need and 128 KiB, and it and
      `MAP_GROWSDOWN` mappings grow on a fault, a kernel access's too
      (`AddressSpace::grow_down`, Linux's expand_downwards), as far as
      `RLIMIT_STACK` says at the time and a 1 MiB gap from what's below
      allows, so a program can raise its own limit (gcc's cc1 does). exec
      leaves room for what the limit says then, up to 4 GiB, and mmap stays
      128 MiB below that (a hint, 1 MiB). `PROT_GROWSDOWN`, and `gd` in
      smaps. The `stackgrow` fixture passes on Linux as it is. Left:
      `MAP_GROWSDOWN` of a file (reported).
- [x] `membarrier` commands (`PRIVATE_EXPEDITED` for .NET and JITs): trivial on one CPU.
- [x] `mincore`, and `madvise` as Linux 6.1's, every advice (the `madvise`
      fixture passes on Linux too, built with `-DON_LINUX`): invalid advice
      refused where it all used to succeed, holes in a range ENOMEM,
      `MADV_FREE` only for what's nobody else's (it took a file mapping's
      private copies), `MADV_DONTFORK` and `MADV_WIPEONFORK` per mapping,
      `MADV_POPULATE_*`, `MADV_REMOVE`, and `dc` and `wf` in smaps.
- [x] Holes: `FALLOC_FL_PUNCH_HOLE` and `MADV_REMOVE` (`file::punch_hole`,
      `FileData::punch`, `SharedPages::punch`), as tmpfs does them, the
      `holes` fixture passing on Linux as it is. They cost what's there,
      not the size of the hole (`PageIndex::remove_range`), and what's
      punched is given back, but for imported bytes, which would show
      through, so those stay as zeroed pages. `st_blocks` is what a file
      holds now, not its length, so `du` and sparse copies see holes.
      A live mount's file has EOPNOTSUPP, as the host's may have no holes.
- [x] Free empty page-table pages on munmap. `PageTable::prune`, after
      `arch::flush_tables` (TLBI VAE1IS on arm64, every level; INVLPG or a
      CR3 load on x86_64). A page touched in each of 2000 2 MiB regions
      left 8 MB of tables behind; now MemFree comes all the way back
      (`many_mappings`). MAP_FIXED over a mapping keeps them.
- [x] Bound kernel memory a program can tie up. Pipe buffers, netlink
      replies, /proc contents, queued RT signals, mappings and inotify
      watches all hit an errno before the heap runs out (kmem.rs).
- [x] `find_free` (mmap without a hint) is O(n) in the number of mappings.
      It starts at `AddressSpace::free_hint` unless a stretch above it
      might fit (`free_hole`: Linux 2.6's free_area_cache and
      cached_hole_size); removing a mapping above the hint raises it.
      With 20000 mappings the last thousand mmaps took 41 ms (the first
      thousand 0.9 ms); now 0.27 ms both (`manymaps` fixture).

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
- [x] `seccomp`/Landlock self-sandboxing (Chrome, systemd services): both
      work (round 4, item 34; AGENTS.md).
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

## Hardening

- [x] Review of 0.0.38..0.0.46 (`hardening.c`, and the tests from
      `page_table_entries_cost_no_heap` on in `guest.rs`): page table
      entries cost no heap, zombies keep only their leader's task entry,
      tee and splice on one file, reading holes costs no heap, epoll
      registrations are charged, IPv6's ways to what IPv4 refuses,
      `--no-outside-links` on hosts that fold names, magic links with
      O_NOFOLLOW, `Pipe::creds` for bytes that are there, `/proc/self/mem`
      across execve, exchanges counted in `id_bytes`, and Landlock's rules
      paying for the nodes they keep.
- [x] Review of 0.0.52 (`wakeups.c`, `read_only_copies` in `filelocks.c`,
      `kstack picked`): what a process's end changes reaches every waiter
      before anyone decides what can run (`sched::settle`), so a timer
      ending a child isn't a deadlock and a sleeper isn't left behind a
      spinning thread; a CPU's timer is the CPU's (`sched::timer_changed`),
      so whoever wakes a thread in another process gives it a slice to
      wait for; `mprotect` leaves a shared file's read-only copies
      read-only; x86_64 handles every vector it took around `hlt`; and a
      stack overflow is seen after a signal frame is pushed, not after.
- [ ] `rv048 extremes` (`review/0.0.48-proofs`) hung once, on arm64 at 2
      CPUs, and hasn't since (9,600 runs of 0.0.52 and 0.0.54, 22,551 of
      0.0.57): not explained by the
      lost wake-ups above, which need another thread to keep running. It
      has a 1 ns periodic timerfd armed, 64 fatal timers and a child
      spinning; look there, and in grix-vmm's wait for the virtual timer.
      (0.0.57's timerfd livelock needs O_ASYNC, which that run hadn't. A
      kick landing just before `wfi` doesn't lose it, with 200 µs added
      there; and 22,551 runs of 0.0.57 at 2 CPUs didn't hang.)
- [x] `crates/grix/tests/runtimes.rs`'s forwarded-port test counts only
      its own request, and probes the port itself: a request for
      something else, and a connection that says nothing, which used to
      keep the server up until the run timed out. Each of the host's
      connections there has its own thread, for the same reason.
- [x] The permission tests, run on kernels without their checks:
      `ptsperm` and `sigioperm` fail there. `execperm` didn't: the program
      it runs if it's let exits 0, so the child looked like a success, and
      Landlock's refused exec had the same hole (`after-exec`). Both now
      run something that ends as no success, and both fail there too.
- [ ] RFC 1918 addresses stay reachable with `net` and no allow-list,
      unlike `fc00::/7`: a default-deny there would break programs that
      reach a LAN, so it's documented rather than changed.
- [x] `timer.rs`, `hostfs.rs` on both sides (0.0.57) and `watch.rs` (0.0.62)
      have had a security read. A listing is held a window at a time
      (`MAX_LISTED`, read on from where the guest is, so a directory of
      any size still works; a lazy import's as far as there's room to
      keep it), `Create` and `Link` ask for an id before they change
      anything, and kqueue's side no longer reads every name into memory
      before it looks at its limit (`each_name`) or searches a list for
      each of another (`pair`, up to 256 KiB of entries each, with
      `Watcher::add` waiting: past a round, an overflow). Nothing else
      in `os::wait` or kqueue's side: its limits hold, and it panics
      on nothing a guest can do. `os::take` on Linux reads on while
      what it reads gives no changes, which takes names no guest can
      make.

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
