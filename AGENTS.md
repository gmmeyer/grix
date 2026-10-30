# AGENTS.md

Guidance for AI coding agents (and humans) working on this repository. For
what the project is and how to use it, see [README.md](README.md).

## Build and test

```sh
make kernel      # guest kernels -> kernel/target/aarch64-unknown-none-softfloat/release/grix-kernel
                 #                  and kernel/target/x86_64-unknown-none/release/grix-kernel
make host        # host CLI      -> target/release/grix
make vmm         # our own VMM   -> target/release/grix-vmm (arm64 macOS 15+ / arm64 and x86_64 Linux KVM; codesigned on macOS)
make python      # grix's native Python module -> python/grix/_native.abi3.so (PyO3)
make fixtures    # C (zig) and Go test programs + Alpine busybox, python3, nodejs (network, cached)
make test        # everything; end-to-end tests boot the kernel in grix-vmm (or QEMU)
make test-kvm    # grix-vmm on KVM: Linux in QEMU with nested virtualization (M3+ Mac)
make check       # clippy for host and kernel
```

- The kernel is a **separate cargo workspace** (`kernel/`) with its own target in
  `kernel/.cargo/config.toml`. Build it from inside `kernel/` or with `make kernel`.
  `cargo test` at the root does **not** rebuild it, so after changing kernel code
  run `make kernel` (or `make test`) before the end-to-end tests.
- End-to-end tests live in `crates/grix/tests/guest.rs` (C fixtures, busybox)
  and `crates/grix/tests/runtimes.rs` (Python, Node). They need
  `grix-vmm` (`make vmm`) where it runs, QEMU (some tests run both), the
  built kernel, and `fixtures/build/`. Missing pieces fail loudly; they
  are never skipped.
- Which VMM: grix's own (`crates/vmm`) for the host's own architecture's
  guests, on arm64 macOS 15+ and on arm64 and x86_64 Linux with KVM, when
  it's built; QEMU otherwise. `GRIX_ACCEL=hvf|kvm|tcg` (or
  `.accel(...)`) means QEMU with that accelerator; `GRIX_VMM=PATH|qemu`
  picks too. The machine layout is `grix_abi::machine`'s; the one thing
  that differs, where the GIC redistributors are, is in the boot image's
  header.
  Rebuilding `grix-vmm` with plain cargo drops its signature: use `make
  vmm`, or every run fails with a "denied" error from Hypervisor.framework.
- Tests use hardware virtualization when available (HVF/KVM). Also run them
  with `GRIX_ACCEL=tcg` when touching boot, MMU, cache, page-table, timer or
  scheduler code, and with `GRIX_ACCEL=hvf` (QEMU) when touching the VMM
  or anything the kernel expects of the machine. Emulation, QEMU and our
  VMM catch different mistakes, and timing-dependent bugs show up
  differently on each. Concurrency changes deserve a stress loop (run the
  `threads`/`events`/`signals`/`gosignals` fixtures 30× each). Changes to
  `crates/vmm` also get `make test-kvm`.
- Debugging a guest: `grix run -v ...` prints the kernel log, and `--json`
  shows status, output and events together. A kernel panic message ends up in
  `RunOutput::kernel_log`.

## Releases

Every commit to `main` is a release, numbered 0.0.1, 0.0.2, ...: bump the
version in the commit itself (`tools/bump-version.sh`: the workspace,
the kernel and the Python package, and the lock files) and push each
commit on its own. `.github/workflows/release.yml` builds the kernel and
grix and grix-vmm for arm64 macOS and Linux, runs the unit tests and a
smoke test, and publishes `v<version>` with the archives; a version
already released isn't released again.

## Architecture in one paragraph

The host (`crates/grix`) turns imports, argv/env and a capability `Policy`
into a boot image (`crates/abi/src/image.rs`). The VMM, a child process
(`crates/vmm`'s `grix-vmm` on Hypervisor.framework, or QEMU), loads the image at
physical `0x4800_0000` and the kernel at `0x4020_0000`. The kernel
(`kernel/src`) enables the MMU in `arch/aarch64/boot.S`, runs in the high half
(`0xFFFF_0000_0000_0000 + phys`), builds a read-only in-memory filesystem from
the image (`fs.rs`, writable in guest memory with `fs_write`), loads the ELF
(`elf.rs`, `process.rs`), and drops to EL0.
RAM is in the regions `grix_abi::machine::ram_regions` gives for its size
(up to `image::MAX_RAM`, 64 GiB): on arm64 one, from 1 GiB on past 4 GiB;
on x86_64 up to 3 GiB below the devices and the rest from 4 GiB, as
QEMU's `microvm` puts it. boot.S maps the first 4 GiB and `arch::map_ram`
the rest; the boot image must fit below 4 GiB (`image::LOW_RAM`), and
grix-vmm's `GuestMemory` is one mapping for every region, as is a
snapshot's RAM. Frames above 4 GiB are handed out first.
After that, every bit of kernel work happens in an exception handler
(`arch/aarch64/mod.rs` → `syscall/`, demand paging in `mm/aspace.rs`, or the timer
interrupt in `sched.rs`). Everything the guest says goes out as frames
(`console.rs`, format in `crates/abi/src/wire.rs`) on a virtio console
(`virtio.rs`: virtio-mmio, port 1 of a `virtio-serial-device`, on the VMM's
stdio), and stdin comes back on it as `wire::Input` frames. When the host
reads slowly, program writes to stdout/stderr block like pipe writes (woken
by the device's interrupt; `Thread::io_done` lets a re-run continue after
what it already sent) or fail with EAGAIN; the kernel's own messages spin
until there's room. Before the virtio console is up, and for panics, frames
go to the PL011 UART, on a Unix socket the host reads (bounded). When the
program ends (`process::finish`), `export.rs` sends the directories listed
in `Image::exports` before the exit status (`wire::ExportMsg`), then, for
each of `Image::mounts`, only what differs from what was imported (a file
is unchanged if it still points at its image bytes, or has the same ones)
and `ExportKind::Removed` for the topmost paths that are gone. The host
(`crates/grix/src/mount.rs`) applies those to the mounted directory
without following links and skips anything that changed on the host during
the run. Mount points are `Node::mount_point` (EBUSY to remove or rename).

Architectures: everything a CPU decides is in `kernel/src/arch/<arch>/`
(`aarch64`, `x86_64`): boot and the linker script, exception entry and the
return to user mode, `TrapFrame` and its accessors (the system call's
number, arguments and result, pc, sp, rewinding to the call), the FP and
TLS registers, page-table entries (`pte`, and `USER_ROOT_ENTRIES`: an x86
root's upper half is the kernel's), the interrupt controller and timer
(`irq`), the early UART (`uart`), the signal frame (`sigframe`), the
structures Linux lays out per architecture (`abi`: `stat`,
`epoll_event`, the `O_*` flags that differ), arm64's ID registers as
user mode reads them (`user_id_register`, emulating an EL0 `mrs` as
Linux's HWCAP_CPUID does; `hwcap` is made from the same values, so
the two agree), the vDSO's code, the
machine's layout (`machine`), USER_TOP and ELF_DYN_BASE, the VMM calls,
and `/proc/cpuinfo`. Code outside `arch` uses only that interface. The
syscall table (`syscall/table.rs`) has each architecture's numbers for
the same names; x86_64's older calls (`open`, `stat`, `fork`, ...) are
turned into the calls that replaced them (`syscall/x86.rs`), gated as
those are. Test with both: `GRIX_ARCH=x86_64 cargo test -p grix --test
guest --test runtimes --test mcp` (and `python3 -m unittest discover -s
python/tests`) runs the end-to-end tests on the x86_64 kernel (fixtures
in `fixtures/build/amd64`, and `<name>-x86_64` roots).

x86_64 (`kernel/src/arch/x86_64`): PVH entry (32-bit, the ELF note) to
long mode in `boot.S`; the high half at `0xffff8000_00000000` (static,
large code model). User mode is CPL 3 with IF set; every trap from it
lands at the top of the CPU's stack (TSS.rsp0, or `syscall_entry` by
hand, with `swapgs`) and leaves by `iretq` (`sanitize` makes a
non-canonical rip or rsp fault at 0 in user mode instead of in the
kernel). Every way in clears the program's flags (AC especially): SMEP
and SMAP are on when the CPU has them (`init_protection`), so the kernel
touches user memory only inside `arch::user_access`. The GDT has no 32-bit
user code segment, so user code can't enter compatibility mode (AMD's
`syscall` from there would go to CSTAR). The idle loop's `sti; hlt` is the only place the kernel takes an interrupt:
it's noted for `irq::ack` (which lets one still in the APIC in for an
instruction), as a masked one waits in the GIC on arm64. The TSC is the
counter, its rate from the hypervisor's CPUID leaf, CPUID 0x15, or the
PIT; the APIC timer is one-shot. FP state is XSAVE's (`init_xsave`:
x87, SSE, AVX, and AVX-512 when the CPU has it; fxsave without XSAVE),
in Linux's signal frame layout, and `sigframe::read_fp` keeps a frame's
XSAVE header to what xrstor accepts (invariant 12). More CPUs start
with INIT and a startup IPI at a real-mode trampoline (`boot.S`
`ap_trampoline`, copied below 1 MiB), which comes into long mode as CPU
0 did and finds its stack by its APIC ID (`ap_main`). grix-vmm runs it on x86 KVM (`vm_x86.rs`,
`kvm_x86.rs`): microvm's layout again, KVM's own IOAPIC and local APICs,
COM1 by port I/O, PVH's entry state, a CPUID with nothing of the host's
but the CPU's model and features (`guest_cpuid`: made-up brand, caches
and topology, no KVM signature) and the hypervisor timing leaf filled in
(`KVM_GET_TSC_KHZ`), and a seccomp filter of x86_64's numbers that kills
the x32 ABI's. `.github/workflows/x86.yml` runs the end-to-end
tests on a GitHub x86 runner with KVM, in grix-vmm and in QEMU (push to a
`ci/**` branch to try something without a release).

Images (`crates/grix/src/container.rs`, `build.rs`, `oci.rs`): a `.grix`
file is a gzipped tar of `grix-image.json` (settings and `ABI_VERSION`),
`kernel` and `rootfs/`. `grix build` assembles one from a Grixfile: a
Docker/OCI image (`oci.rs` pulls from registries and reads OCI layouts and
`docker save` archives, applying layers with whiteouts and checking
digests; zstd too), copies, files, and build steps, or another grix
image (`image:FILE`). An image is one architecture's: its kernel's ELF
machine is what it is (`Image::arch`, nothing in `grix-image.json`).
A build targets one (`BuildOptions::arch`: the host's, `GRIX_ARCH`'s or
`--arch`), pulls that platform (`linux/arm64`, `linux/amd64`) and packs
that kernel; `SandboxBuilder::image` switches the machine (VMM or QEMU,
accelerator, image base) to the image's unless an architecture was
chosen, which is then an error, as is a kernel for another machine
(`vmm::check_machine`) or programs for another kernel
(`container::check_programs`). Registry logins come from `auth.rs` (only when a
registry asks, to its own site's token service; agents' builds only
with `--registry-credentials`). Every connection a pull makes goes
through `oci::Resolver`, which checks the addresses names resolve to
against the build's network policy (`net::reachable`), as the proxy
checks a program's.
`treecache.rs` keeps applied layers and build steps' results, keyed by
what went into them (the architecture too): anything new that changes a
step's result belongs in `build::step_key`. Steps run in grix itself and
export `/`; nodes the kernel made at boot (`Node::generated`) stay out
unless the step changed them. They run as the image's user
(`ImageConfig::user`, an OCI image's `User`, root by default as in
Docker, resolved by `container::resolve_user`). An image's kernel is the one that boots it,
so bump `grix_abi::ABI_VERSION` with any change to the boot image, wire,
`link` or `hostfs` formats.

AF_UNIX (`unix.rs`, `syscall/unix.rs`): a connected stream is a socket
pair (`ipc::SocketEnd`, with `unix::StreamInfo` for its names and peer)
however it was made; a named, listening or message (datagram, seqpacket)
socket is a `unix::Sock`, found by name in `unix::NAMES` (a path is an
`fs::Kind::Socket` node whose id is the key, so a reused inode can't be
reached). Descriptors passed with SCM_RIGHTS are `unix::Rights` (at most
`MAX_INFLIGHT`), attached to a message or to a stream's byte position
(`Pipe::rights`); reads stop at them. A stream's pipe also keeps who
wrote what (`Pipe::creds`, a run per writer, at most `MAX_CRED_RUNS`):
with SO_PASSCRED (`StreamInfo::passcred`, inherited from a listener)
reads stop where the writer changes and carry SCM_CREDENTIALS.
splice, tee and vmsplice (`syscall/splice.rs`) copy a chunk at a time,
looking at the source first and consuming only what the destination
took.

Networking (`inet.rs`, the AF_INET part of `syscall/net.rs`, host side in
`crates/grix/src/net.rs` and `dns.rs`, messages in `crates/abi/src/link.rs`):
the guest has no TCP/IP stack. A TCP connect becomes `link::ToHost::Connect`
on `Channel::Link`, the host checks its `NetPolicy` and connects, and data
flows as `Data` messages with credit-based flow control (`link::WINDOW` per
connection each way; stdin uses the same scheme). Connections to the
guest's own addresses (loopback, 10.0.2.15) never leave the guest: they're
socket pairs queued on the listener. Ports forwarded from the host arrive
as `Incoming`, for a listener on the guest's address or all of them,
never one bound to loopback only (as on Linux, and Docker's published
ports). UDP (`inet::Udp`): a query to port 53 goes to the host's
resolver; a datagram to the guest's own address to the socket bound there
(`deliver_local`); any other through the host (`ToHost::UdpSend`), to
destinations the host allowed (`UdpAllow`, asked once per destination:
the send waits for the `UdpVerdict`, EPERM if refused), and the host
passes back only those destinations' replies. Forwarded UDP ports
(`NetPolicy::udp_forwards`, `Image::udp_forwards` for deadlock
detection): the host binds them and sends each datagram as
`UdpIncoming` (lossy, under the outbox's half; over one frame dropped),
with the host's loopback as 10.0.2.2 (`guest_view`), to the socket
bound at that port. Both sides remember the last
`link::MAX_FORWARD_PEERS` senders (`inet::forward_peer`, `UdpForward`):
a send to one is a `UdpReply` out of the forwarded port, which the host
checks again; anything else goes through `UdpAllow` like any socket's.
Restoring a snapshot forgets them. The guest is 10.0.2.15, the host's own loopback is 10.0.2.2
(`host.grix.internal`, only with an explicit rule), and the nameserver is
10.0.2.3 (synthetic `/etc/resolv.conf` and `/etc/hosts` in `fs.rs`). Host
denials come back as `Denied` events with capability `allow_host`.
Interface listings (`netlink.rs`: netlink, the `SIOCGIF*` ioctls,
`SIOCETHTOOL`, `/proc/net/dev`, `route`, `if_inet6` and `ipv6_route`;
`procfs::ETH0_FILES` for `/sys/class/net/eth0`) show `lo`, and with
`net` also `eth0` (10.0.2.15/24 and `link::GUEST_V6`, fd00::15/64, a
made-up MAC, the default routes via 10.0.2.2 and fd00::2), set at boot
(`netlink::init`). It's no device: a description of what the proxy
does, which still decides what sockets reach. The IPv6 address is a
ULA on purpose: a connection to a global address leaves from it
(`inet::source_for`), and RFC 6724 then sorts IPv4 first; fd00::2 is
the host's loopback as 10.0.2.2 is, and the rest of fd00::/64 nobody.
A NETLINK_KOBJECT_UEVENT socket (`Netlink::uevent`) hears nothing.

Live mounts (`hostfs.rs` in the kernel and in `crates/grix/src`, messages
in `crates/abi/src/hostfs.rs`): directories the host serves while the
program runs. A read-only one is EROFS for every change, before the
policy's `fs_write` gate (`file::read_only_target`). A hard link's new
name is a node of its own (the host has an id per name). Their nodes carry `Node::remote` (the host's id), and their
files' `FileData` reads and writes go to the host. A directory's entries
are fetched on first use and kept for `hostfs::FRESH_NS` (`Fs::ensure`).
Under memory pressure `Fs::evict` forgets idle directories' entries. A
directory too big to hold is `Remote::large`: names are looked up one at a
time and getdents pages through the host. Each request waits for the
host's answer in `console::host_request`. The host walks every path down
from the mount's root fd with `openat`/`O_NOFOLLOW`, so nothing the guest
says can lead outside the mount. Lazy imports (`LiveMount::lazy`) are
read-only live mounts that the guest never refreshes (`Fs::is_lazy`: once
listed or fetched, a node stays as it was) and the host checks against
what the guest first saw: listings, attributes and lookups come from the
first answer (`Server::entries`, `saw`), and a file whose bytes changed
reads as EIO (`unchanged`). Any change first makes the node the
sandbox's (`Fs::copy_up`: a directory fully listed, and every directory
above it up to the mount), after which it's an ordinary node keeping its
inode number (`Node::host_ino`); a file's bytes stay the host's until
the first write or truncate reads them in (`FileData::adopt`,
`make_local`).
inotify (`inotify.rs`) gets its events from the host: the first watch
on a live mount's node (`Fs::watchable_remote`: not a lazy import's)
sends `Request::Watch`, the last one going `Unwatch` (`inotify::REMOTE`
counts them). The host watches through descriptors walked down to like
every other (`crates/grix/src/watch.rs`: inotify on Linux, via
`/proc/self/fd/N`; kqueue on macOS, comparing a directory's entries to
name what changed and pairing renames by inode), and sends each change
as a `hostfs::Notice` on `Input::FsEvent`, unasked, one per frame, so
it never mixes with an answer. The console hands them to
`inotify::from_host` (at most `MAX_NOTICES` held; more lost become an
IN_Q_OVERFLOW), which queues them on the matching watches (each event
charged, `MAX_QUEUED` per instance) and marks what changed for fetching
again (`fs::host_changed`, applied when the filesystem is next free).
The host bounds what it keeps (`hostfs::MAX_WATCHES`; on macOS entries
and descriptors) and a round of changes (`watch::MAX_BATCH`, then an
overflow), and sends as the guest takes them, within a quarter of the
outbox (`Outbox::send_notice`: stats requests and datagrams still fit),
so its own kernel's queue holds the rest. A restored snapshot's host watches nothing:
`inotify::rewatch` asks again for every node and queues an overflow,
as what changed meanwhile was missed. The guest's changes elsewhere make
no events yet.

Processes (`process.rs`, `procs.rs`, `syscall/proc.rs`): the running
process is in this CPU's slot of `PROCESS` (`process::running()`); every
other one, and zombies, are in `procs::PROCS` (lock order: a `PROCESS`
slot, then `PROCS`). `sched::schedule`
picks threads round-robin across processes, swapping bodies between the two
and the address space in TTBR0. fork copies the address space
copy-on-write (per-frame refcounts in `mm/frame.rs`; `AddressSpace::fork`
and `unshare`; the kernel's own writes unshare in `ensure`). vfork is a
copy too, with the parent waiting (`WaitOn::Vfork`) for exec or exit.
Every way a process ends goes through `Process::terminate`: for init (pid
1, the program) that ends the sandbox; any other process is marked, and
`procs::finalize` (run from `schedule`, which `return_to_user` calls for an
ended process) closes its files, leaves a zombie, gives its children to
init and sends the exit signal. Each process has a `/proc/<pid>`
(`Fs::proc_add` at fork, `fs::proc_gone` once it's reaped; `/proc/self`
is `process::current_pid`). A zombie's is generated from what
`procfs::Remains` kept of it (`Zombie::remains`, `fs::proc_zombie`
makes its `exe`, `cwd` and `root` fail with ENOENT); a pidfd (`FileKind::PidFd`) is just the pid,
which is never reused. `execve` loads the new program into a fresh
address space first (`process::load_program`), so a failure leaves the
caller running. What clone can share between processes is a handle to
one value: the descriptor table (`fd::FdTable`, CLONE_FILES), the
working directory and umask (`Process::fs`, a `process::Shared<FsInfo>`,
CLONE_FS) and the signal actions (`Process::sigactions`, CLONE_SIGHAND,
which needs CLONE_VM: vfork only). Fork copies each (`share`/`copy`);
`execve` unshares the table and the actions (Linux's `unshare_files`,
`de_thread`), `unshare(2)` the table and fs. POSIX record locks belong
to the table (`locks::Owner::Files`, as Linux's to the files_struct) and
go when it does. A zombie keeps none of them (`Remains::of` takes its
signal dispositions before `finalize` lets them go). CLONE_PARENT makes
the caller's parent the child's, with the caller's exit signal: that
parent reaps the zombie, and a vfork caller isn't always the parent
(`vfork_parent`). New namespaces are denied, by clone and by unshare. Credentials: `Process::uid`/`gid` are the effective ids
(permission checks, new files); `Process::ids` keeps the real and saved
ones and supplementary groups, changed by Linux's rules (uid 0 may set
anything). They only matter inside the guest filesystem: root bypasses
mode bits but not `Node::system`, and nothing honours setuid bits, so
keep it that way rather than giving uid 0 anything else.

Threads (`sched.rs`): each takes `process::THREAD_COST` from `kmem`
for as long as it lives (its `Thread`, x86_64's FP box, its
`/proc/<pid>/task/<tid>` nodes, which are `prepaid` and stay out of the
metadata budget); `process::threads_max` is what the heap's share of
RAM gives (`mm::init`: the heap is 32 MiB plus 1/16 of RAM, at most 128
MiB more, from the top of the highest RAM region, half of that for
`kmem`, half for fragmentation), and clone
and fork fail with EAGAIN at either. A thread has its own name
(`Thread::name`, zeros meaning the process's, `Process::name` being the
main thread's), state and CPU time in its task directory, whose
entries come and go one at a time (`fs::task_changed`). One kernel
stack per CPU (`arch::stack`'s
`STACK_SIZE`, which the linker scripts and assembly take from there),
with that CPU's emergency stack below it. There's no guard page (4 KiB
mappings there cost contended system calls a fifth of their speed):
the lowest `CANARY_SIZE` bytes of each stack are painted and checked on
every way back to user mode and before the idle wait
(`smp::check_stack`), and an exception taken that low is reported too
(arm64's vectors check sp against `tpidr_el1` before pushing a frame
and move to the emergency stack), all as "kernel stack overflow on CPU
n". `stack_max` in /proc/grix/smp is each CPU's high-water mark (about
16 KiB in release builds): keep big things off the stack, and remember
that a `Thread` is moved by value (x86_64's FP state is boxed for that,
`arch::ThreadFp`). Each thread keeps its user registers, TLS and FP/SIMD
state in `process::Thread`. A syscall that must
wait calls `Process::block` (futex/sleep) or `Process::block_io` (I/O) and
returns `EBLOCKED`. `schedule()` then saves the trapped state and loads
another thread's state into the trap frame. I/O waits are *restarted*: when
`ipc::changed()` bumps the I/O generation, blocked I/O syscalls re-execute
from the `svc` (ELR − 4) with their original deadline (`restart_deadline`).
Timers (`timer.rs`: setitimer, POSIX timers, timerfds) are deadlines too:
the scheduler programs the CPU timer for the earliest one and calls
`timer::fire` from the timer interrupt and the idle loop. With more
CPUs one keeps everyone's deadlines (`sched::KEEPER`, a CPU running a
thread if one does); the others program their own time slice and
process's CPU-time timers, and a deadline only if it comes before the
timekeeper's timer (`sched::arm`). Whichever CPU's timer fires looks at
everything again, so a deadline is never missed. A CPU-time
timer's deadline is in CPU time, a wake-up only while its threads run
(`timer::cpu_deadline`). Nothing looks through every process for a
deadline unless one may be due: `sched::EARLIEST` is no later than any
sleeper's or timer's (a thread that sleeps lowers it, in `Process::block`;
a timer set, its signal taken or its timerfd read resets it,
`sched::deadlines_changed`, and the next look counts them again), and
while a CPU-time timer is armed (`CPU_TIMED`) every look looks. Anything
new that sets a deadline must do one or the other, or its sleeper wakes
only when something else comes due. So too I/O waiters are looked for
only once the I/O generation has moved past the one they all saw
(`sched::POLLED`), and the threads waiting to run are counted
(`process::queued`, kept by `RunQ`). The vDSO (`vdso.rs`, a page every process
shares) reads the clocks without a system call from a page only the
kernel writes (`vdso::publish`); the kernel's clock uses the same
`(ticks * mult) >> 32`, so keep the two in step.

More CPUs (`smp.rs`, `Image::cpus`, `SandboxBuilder::cpus`): the kernel
is still the single-CPU kernel, made safe by a big kernel lock that every
exception takes (`smp::lock` in `trap_handler`) and gives back on the way
to EL0 (`smp::finish`). It's a ticket lock whose turn a waiter skips
when the lock has lain free and untaken for `SKIP_US` (that CPU's vCPU
is likely descheduled; it takes a new ticket when it runs): FIFO hands
off as a futex ping-pong wants, and a descheduled waiter doesn't stall
everyone. What runs in parallel is user code: each CPU runs
a thread of any process. Between kernel entries every process is in
`procs::PROCS`; `smp::lock` moves the one this CPU runs (boxed: a
pointer) into this CPU's slot of `PROCESS` (and `CURRENT_PID`,
/proc/self, is per CPU too) and
`smp::unlock` puts it back (a finished-off one goes then, out of TTBR0
first), so kernel code still sees "the running process" and "the
others", and a process in `PROCS` may be running on another CPU. Under
the lock only the holder's slot is filled (a debug assertion checks). Each
CPU's scheduling state (`smp::CPUS`: its process and thread, time slice,
resched, timer_dirty) is swapped into the `Process` fields while it holds
the lock, so `p.current` is this CPU's thread, and a thread running on
another CPU is in neither `runq` nor `current`, its registers live in that
CPU: don't touch them. A CPU with nothing to run waits in `smp::finish`
holding nothing, no process either (a kick: SGI 0, plus `KICK_CALL` for
grix-vmm), and schedules from none (`sched::schedule` takes the CPU's
slot, empty or not); `unlock` kicks idle CPUs for threads waiting
anywhere. Finishing off a process
that ended and execve need the other CPUs out of it (`smp::alone(pid)`);
they leave at their next schedule (`exclusive_wanted`, `kick_others`), and
a process killed while it runs elsewhere is finished off there
(`smp::running_anywhere`, `procs::reap_others`). Signals for a thread on
another CPU kick it (`kick_thread`). Little else relies on the lock
making one CPU the kernel's, and what does says so: `Procs::all` and
`each` (every process, so no other CPU may have one out: debug-asserted,
`smp::exclusive`) and the program's end (`export::send`). The
filesystem's lock knows its holder (`fs::lock` waits for another CPU's
and panics on this one's), and code that can't wait for it leaves the
work to its next holder (`fs::later`); the process and thread counts are
kept as they change (`procs::born`, `threads_gone`); a pipe is held
across the copy to a reader as to a writer; a socket polls its peer
without its own lock.
TLB flushes are of the pages that changed (`flush_tlb(root, start,
end)`, through `AddressSpace::flush`) and instruction-cache invalidation
is broadcast. Arm64's TLBIs are broadcast too, per page (`vale1is`;
every process is ASID 0, so it reaches all of them) or everything past
`FLUSH_PAGES`. x86_64 has no broadcast invalidation: `flush_tlb` IPIs
the CPUs with that root in CR3 (`ROOTS`; any other has none of its
entries, as loading CR3 dropped them) and waits for each, except one in
the kernel: IF is clear there and it may be waiting for the lock, so it
catches up when it gets it (the flushes asked of it, `WANTED`, against
those it did: `tlb_sync`), before it touches user memory. Flush only when an entry
that was there changed (no TLB holds an empty slot), but do flush one
made writable: a CPU still holding it read-only would fault on the
kernel's own write there; free pages
only after the flush, break before make when a mapping changes page, and
order a new page's contents before the entry that publishes it
(`publish_barrier`). munmap also frees page tables that map nothing now
(`PageTable::prune`); a table goes only through `arch::flush_tables`,
which arm64 needs because `flush_tlb` drops last-level entries only, and
which on x86_64 also waits for CPUs in the kernel, which catch up as they
spin for the lock (`tlb_sync`): a speculative walk from one that hadn't
could reach a freed table. User memory other threads use at the same time is
updated atomically (`uaccess::update_u32`, FUTEX_WAKE_OP). membarrier
makes every other CPU running the process (or any, for GLOBAL) enter the
kernel (`smp::barrier_others`). Processes running at once write at once:
a fixture that checks whole lines writes each with one `write`. Secondaries start with PSCI CPU_ON (`boot.S`
`secondary_entry`) on arm64, INIT and SIPI on x86_64. What it all
costs is counted per CPU (`smp::Stat`: entries by kind, time waiting
for and holding the lock, TLB flushes and their IPIs, timer interrupts
that found nothing due), shown in `/proc/grix/smp` and, after a run
with more CPUs, in the kernel log (`grix run -v`); the `smpbench`
fixture runs each kind of load on one CPU and on n and prints the
counters' deltas: measure with it before and after a locking change.

x86_64 programs (`Image::x86_64`, `SandboxBuilder::x86_64`, `--x86-64`):
the guest stays arm64; an x86_64 ELF that execve meets is run by the
configured translator (an arm64 program: qemu-x86_64 in user mode;
box64 should work, untested) with its path and arguments, as binfmt_misc would
(`resolve_interpreters`). Whatever the translator needs is the program's
to import (x86_64 libraries for dynamic programs, `QEMU_LD_PREFIX`).

In a web page (`web/`, `crates/web`): the kernel boots in QEMU compiled
to wasm, and `grix-web` (wasm32) is the host side: the boot image and
the console's frames with `grix_abi` itself, stdin within the guest's
credit. QEMU's arguments come from `grix_web::qemu_args`; keep them in
step with `vmm.rs`'s `qemu_command`. See `web/README.md` for what the
browser changes (the console's pty, `virtio-mmio.ioeventfd=off`).

Snapshots (`kernel/src/snapshot.rs`, `crates/vmm/src/snapshot.rs`,
`crates/grix/src/snapshot.rs`): with `Image::snapshot`, the first time the
scheduler idles with a thread waiting for I/O and no other CPU running
one (`smp::others_running`), after the program found
stdin empty (`console::stdin_waited`) and with nothing open through the
host (`inet::host_state`), the kernel flushes the console, takes whatever
the host sent (`console::take_all_input`: anything there means not now)
and makes `SNAPSHOT_CALL` (an HVC in SMCCC's OEM range: Hypervisor.framework
answers the vendor-hypervisor range itself; KVM forwards it only because
grix-vmm installs an SMCCC filter, `kvm::Vm::forward`, Linux 6.4+; on
x86_64, where KVM answers `vmcall` itself, an `out` to
`machine::x86_64::VMM_PORT`).
grix-vmm stops every other vCPU between exits (`pause.rs`: each saves its
own registers, as only its thread may on Hypervisor.framework; on KVM a
kick is `immediate_exit` plus a signal, and a vCPU first finishes its last
exit with a `KVM_RUN` that runs nothing, `kvm::Cpu::complete`), then,
holding the console's lock so its threads can't touch guest memory, writes
the vCPUs, GIC, console device and RAM (its regions one after another,
zero pages left as holes) to its fd 3 and exits, or answers
`SNAPSHOT_RETRY` if input is on its way and lets them all go on. What a
vCPU's and the GIC's state are is the hypervisor's (`snapshot_hvf.rs`; on
KVM, `snapshot_kvm.rs`: every register `KVM_GET_REG_LIST` names and the
power state, and the vGIC's attributes in one fixed order, so a file only
supplies values; on x86 KVM, `snapshot_kvm_x86.rs`: what QEMU saves of a
vCPU, registers to XSAVE area, MSRs, local APIC and pending events, put
back in QEMU's order, and the IOAPIC and 8259s), and a snapshot runs only
where it was taken. A restore
makes every vCPU, confines grix-vmm before it puts any of the file's state
back (on KVM, with the ioctls that takes until a second filter goes on),
puts the GIC back before the console raises its interrupt (`Console::go`,
which also lets the console's threads touch the device: its queues are
the file's), and only then runs a vCPU. On KVM the counter is set last,
once for the VM. A `--restore` run maps that RAM
copy-on-write, puts the rest back with the guest's counter continuous (as
after a suspend), and returns `SNAPSHOT_RESTORED`, fresh entropy
(`rng::reseed`) and the time since, which moves the kernel's time of day
on (`time::resumed_after`). The host writes the file privately and renames
it into place, and appends its settings for restored runs (network
policy, exports, limits) as JSON: a file may come from anyone, so
`Snapshot::open` drops its network policy and forwards (runs get only
what the caller allows: `allow_net`, `forward`) and caps its limits. Of what the host held,
only live mounts' state is saved (`hostfs::Server::save`, validated by
`restore`: names, ids, limits); each run gives them host directories
again (`Snapshot::mount`), and the kernel fetches what it knew of them
again (`Fs::forget_live`). On-exit mounts are refused. In TTY mode the
moment is the program waiting at its terminal (`tty::waiting_on`).
Anything new that lives on the host side of a run needs the same
treatment.

Extended attributes (`Node::xattrs`, `syscall/file.rs`'s `setxattr`
and the rest): kept on the sandbox's nodes, names and values charged to
`META_LIMIT` (ENOSPC). A lazy import's node shows none of the host's
and is copied up to take one; a live mount's, and /dev, /proc and /sys,
keep none (EOPNOTSUPP). Exports don't carry them to the host; snapshots
keep them, as the rest of the tree. The namespaces' rules are
`xattr_permission`'s (Linux's, with uid 0 for every capability), and
nothing honours them: `security.capability` is a value, as setuid bits
are only bits.

Shared file mappings and locks: a MAP_SHARED mapping of a file in the
sandbox maps the file's own frames (`Backing::SharedFile`; the file and
each mapping hold a reference; a read of a page without a frame maps a
read-only copy, taken out everywhere once the page gets one,
`procs::zap_stale`), so it's never copy-on-write, and a file
that shrinks takes its pages out of every process's mappings
(`file::zap_shared`): page tables are kernel memory, so another
process's can be changed without its address space active. A live
mount's files still map as copies. `locks.rs` has flock, POSIX and OFD
locks; anything that closes a descriptor must call `file::closing`
first (POSIX locks go with any close of the file), and `OpenFile::drop`
releases flock and OFD locks.

Job control (`signal.rs` `stop`/`resume`): a stop signal's default action
stops the whole process when it's sent (or delivered, if it was blocked):
`Process::stopped`, and the scheduler passes it over (`sched::runnable`,
`smp::runs_here`) with its threads where they were; SIGCONT, whatever its
action, continues it. `job_report` is for wait's WUNTRACED/WCONTINUED;
`job_notice` is the parent's SIGCHLD, sent from `procs::reap_others`
(which can reach the parent). Init stopping is an `Event::Stopped`.

Terminals (`tty.rs`, `syscall/tty.rs`): a `Tty` is a pseudo-terminal
pair, its line discipline Linux's N_TTY (`receive` for what the master
writes, `out` for OPOST). It doesn't touch processes: it returns the
signals to send, and the caller sends them (`signal_group`). /dev/ptmx
makes one (at most `MAX_PTYS`, each charged its buffers), /dev/pts/N is
shown while the master is open (`Fs::pts_show`, the node kept for reuse),
/dev/tty is `Process::ctty`. A closed master hangs up from
`tty::service` (in `reap_others`). Background reads and writes stop the
group (`job_control`) and re-run once it continues. In TTY mode
(`Image::tty`) the program's stdio is /dev/pts/0, whose master side is the
console: `tty::pump` moves host stdin in and output out, and
`wire::Input::Resize` changes its size.

seccomp (`seccomp.rs`): a program's filters on itself. State is per
thread (`Thread::seccomp`: the mode, the newest filter, which holds
the ones before it in an `Arc` chain shared by every thread and process
that inherited it, and no_new_privs), copied by fork and clone, kept by
execve. `syscall::handle` runs the policy's gate first (`gate`: what
the policy refuses is denied and reported whatever a filter says),
then the filters (`seccomp::verdict`, Linux's precedence: the
strictest action, the newest of equals), then the call; a check
inside a handler (`syscall::require`) comes after the filters, as the
call has to run to make it. A filter can only take away: what it
refuses isn't a denial and isn't reported, but a kill is (a `Fault`).
TRAP leaves the registers as they were and forces SIGSYS
(`signal::force`: fatal if blocked or ignored) with `si_syscall`,
`si_arch` and the data in `si_errno`. Landlock, the other way a
program restricts itself, answers EOPNOTSUPP to every call (Linux with
it disabled at boot), unreported; TODO.md item 34 has the design.
Programs are checked as Linux's `bpf_check_classic` and
`seccomp_check_filter` check them (only forward jumps, so a run ends within its length). TSYNC writes the
other threads' state directly: one running on another CPU is in user
mode and sees it at its next call. User notification is unimplemented
(reported).

Landlock (`landlock.rs`): a program's rules on itself, to ABI 5
(filesystem rights through TRUNCATE and IOCTL_DEV, TCP ports; not ABI
6's scoping). As with seccomp, the policy comes first: every check
stands after the handler's `require`, so what the policy refuses is
denied and reported, and what Landlock refuses is EACCES (EXDEV for a
move only REFER stops), never reported. A ruleset is a descriptor
(`FileKind::Landlock`); `restrict_self` merges it into a new immutable
`Domain` (`Thread::landlock`, an `Arc` shared by fork, clone and
execve), each layer's rights and every rule by object, each saying what
each layer grants. `landlock::domain` is the fast path: one test of
`Process::landlocked` without one. A layer with any filesystem right
handles REFER too, so moving between directories is EXDEV unless a rule
grants it. Checks are Linux's: layer masks unmasked from the node up (`Domain::walk`, under the caller's
`fs::lock()`: `check` takes it, `check_in` and the rest are given it,
so never call `check` holding it), and `check_refer` is
current_check_refer_path with the tree as one mount. A rule holds its
node by `Ino`, pinned: a pinned node is never idle to `Fs::evict`, so a
live mount's directories with rules (and those above) stay, and
`copy_up` keeps the slot. A file's path decides what's above it
(`Fs::found_in`), as a dentry's parent does: `Node::parent` is only the
first name's. (On a live mount each name is a node of its own, so a rule
on a file there holds for that name alone.) Links and renames go through
`check_refer`, an exchange both ways, after what Linux checks first: a
move across mounts is EXDEV (`Fs::crosses_mount`), and a change on a
read-only mount EROFS (`landlock::domain_changing`). What matters after the open is decided at open
(`OpenFile::landlock_denied`, TRUNCATE and IOCTL_DEV, inverted so a file
made any other way has them). A new way to make, remove, open, execute
or move a node, or to bind or connect a TCP socket, needs its check.
`/proc/self/fd/N` isn't re-checked: it's the same open file here
(`procfs::fd_path`), not a new open. `landlock::may_inspect` keeps a
domain out of processes outside it, as Linux's ptrace hook.

Linux AIO (`syscall/aio.rs`): a context is a ring in the program's
memory, Linux's `struct aio_ring` at the context's id (libaio reads it;
a shared mapping that io_destroy unmaps only if it's still the ring),
in `Process::aio` (threads share it; fork and execve leave it behind).
Reads, writes and syncs are done in io_submit (`file::aio_rw`, never
waiting: a stream that isn't ready gets EAGAIN) and their events
written to the ring then; polls wait in the context and complete at the
process's next system call with the file ready (`aio::complete_polls`
from `syscall::handle`), since only the running process's ring is
reachable. io_getevents waits with `block_io_rerun`, so anything that
completes one calls `ipc::changed()`. io_uring is unimplemented on
purpose (TODO.md).

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
keeping its deadline (`restart_deadline`). A woken call always re-runs once
before signals are delivered (`Thread::recheck`), so one that can now
complete does, as on Linux; it stays `restarting` until the svc actually
runs again. Signals from the host (`wire::Input::Signal`, from `RunControl`
or a timeout's SIGTERM) are queued by the console and sent to init's
process group from `sched::poll`; a thread waiting for a signal is never
treated as deadlocked.

Metrics (`kernel/src/stats.rs`, `crates/abi/src/stats.rs`,
`crates/grix/src/metrics.rs`): the kernel counts in atomics only (CPU
time where the scheduler and a thread's end count it, system calls,
faults, switches, forks, each `Resource`'s peak, and each `Limit` that
refused something), so a report can be made whatever locks are held. It
reports on `Channel::Stats`: once before the exit status
(`console::report_stats`), and when the host sends `wire::Input::Stats`,
answered from `drain` with `try_send` (no room: no answer, and the host
asks again). A restored snapshot's counts start again
(`stats::restored`). With `Metrics`, the host asks every
`metrics::REPORT_EVERY` (`Outbox::offer_lossy`: a kernel that doesn't
read can't make requests pile up), never in a run taking a snapshot (and
a request makes `take_all_input` not quiet). The report is the guest's say-so: the
host's own measure is `HostUsage` (`wait4`'s rusage of the VMM, which is
then reaped by hand: `ChildGuard`). Every label is from a fixed set
(`capability_label`): never put a guest's string in one. A new limit
gets a `Limit` (and `stats::hit` where it refuses); a new budget, a
`Resource`. Events the host itself reports (the proxy's denials) reach
`RunControl::on_event` and the metrics as they happen, as the guest's do.

## Invariants: don't break these

1. **Host and guest agree through `crates/abi` only.** Never duplicate an
   encoding, address or constant on both sides; put it in `abi`. The `abi`
   crate must stay `no_std` (plus `alloc`).
2. **The kernel never faults on user memory.** Every access to a user pointer
   goes through `uaccess.rs` (`copy_in`, `copy_out`, `read_cstr`, …), each
   inside `arch::user_access` (SMAP on x86_64 faults anything else).
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
7. **Least privilege at the VM level too.** Don't add devices (NICs,
   disks, virtio-fs), semihosting, or QEMU's monitor unless a capability
   gates them. Semihosting in particular gives the guest host file access.
   The only devices are the PL011 and the virtio console, and both carry
   nothing but the framed channel to the host; keep it that way (no more
   ports, no `virtconsole`, which drops output under backpressure).
   `grix-vmm` is the same machine, and everything the guest tells its
   devices (ring addresses, descriptor lengths, MMIO) is checked against
   guest RAM and bounded before use. Once the VM exists it confines itself
   (`hvf::confine`: a deny-everything macOS sandbox; `kvm::confine`: a
   seccomp allowlist on every thread): keep new work in it to what's
   already open (stdin, stdout, the serial socket), and add a system call
   to the allowlist only when it can't reach anything new.
   Networking is no exception: there's no NIC and no guest TCP/IP stack.
   Sockets are `link` messages on the console, and the host's proxy
   (`crates/grix/src/net.rs`) makes every connection after checking the
   policy, so a compromised guest can't reach anything the policy doesn't
   allow. The host never trusts the guest's flow control either: credit,
   threads, lookups and queued frames all have host-side caps. Nor its
   capability checks: the proxy itself refuses everything without `net`,
   since an image brings its own kernel.
8. **No paths outside imports.** The guest filesystem is exactly the import
   list plus the synthetic nodes in `fs.rs`. `/dev` and `/proc` are reserved
   (`crates/grix/src/image.rs`).
9. **The kernel never blocks inside a syscall.** There is one kernel stack
   per CPU and one kernel lock, so waiting means returning `EBLOCKED` after
   recording a wait, and no CPU ever waits holding the lock. The one
   exception is a live mount's request (`console::host_request`), which
   spins for the host's answer so file system code stays synchronous;
   networking messages that arrive meanwhile wait for the console
   interrupt. Anything
   that can make a blocked I/O call succeed (data, space, closing an end,
   epoll_ctl) must call `ipc::changed()`, or waiters will sleep forever. IRQs
   stay masked in the kernel; don't unmask them.
10. **The kernel heap is small (32 MiB, and 1/16 of RAM: `mm::init`) and
    running out of it panics.**
    Anything a program can make the kernel allocate needs a budget that
    fails with an errno first. Nothing that grows with RAM goes on the
    heap: frame reference counts are RAM set aside below the boot image
    (`mm::init`), the free list is linked through the free frames, and
    pages of files and shared memory are indexed in frames
    (`mm::pageindex`; a file's index nodes count as its data).
    - File data counts pages (`fs::set_limit`), and nodes, names and
      extended attributes count against `META_LIMIT` (ENOSPC).
    - Buffers held for a program (pipes, netlink replies, generated /proc
      files, network receive windows, DNS answers, inotify events) take a
      `kmem::Charge`.
    - A live mount's nodes count against `META_LIMIT` like the program's
      own; when it's full, `Fs::evict` forgets idle ones (the host still
      has them) before anything fails.
    - Counts are capped: mappings (`MAX_VMAS`, and `MAX_VMAS_TOTAL` for
      all processes), queued real-time signals, inotify watches, POSIX
      timers, threads (all processes, `process::threads_max`, and each
      charged `THREAD_COST` to `kmem`), descriptors (RLIMIT_NOFILE, at
      most `fd::MAX_FDS`; a table's slots take a `kmem::Charge`, so
      fork's copies are budgeted too), open files
      (`MAX_OPEN_FILES`, all processes), processes (`MAX_PROCESSES`,
      zombies included), network connections (`inet::MAX_CONNS`),
      connections waiting to be accepted (`inet::MAX_PENDING`),
      pseudo-terminals (`tty::MAX_PTYS`, each charged its buffers),
      file locks (`locks::MAX_LOCKS`), descriptors in flight over
      AF_UNIX sockets (`unix::MAX_INFLIGHT`; message queues take a
      `kmem::Charge`) and seccomp filters (`seccomp::MAX_FILTERS` and
      `MAX_INSNS_TOTAL` in all processes, each filter charged to
      `kmem`; ENOMEM), Landlock rules (`landlock::MAX_RULES` in all
      rulesets and domains, each charged to `kmem`; ENOMEM) and layers
      (`landlock::MAX_LAYERS` per thread; E2BIG). AIO contexts count
      the events they ask for against `aio::AIO_MAX_NR` (EAGAIN, Linux's
      aio-max-nr), and each
      context and waiting poll is charged to `kmem`. argv and environment copies take a
      `kmem::Charge`.

    Limits must be global, not per object: a program can open many objects,
    and fork copies whatever is per process.
11. **`fs::lock()` is not re-entrant**; it panics if this CPU already
    holds it (another CPU's hold is waited for), and `fs::try_lock` fails
    if anyone does. Drop the guard before calling anything that takes it
    (`Process::missing_path`, `procfs::generate`, …). Lock order:
    `OpenFile` → filesystem → `FileData`. Never hold a `FileData` lock
    across `copy_in`/`copy_out`, because a fault may read the same file
    through a mapping (file.rs uses bounce buffers).
12. **User register state never reaches EL1.** `rt_sigreturn` loads every
    register from user memory. It must reject a frame whose pstate names
    another exception level, AArch32 or masked interrupts, and keep only
    NZCV (`signal::read_frame`). Anything else that loads a user-supplied
    context needs the same check.
13. **Only the running process's memory is reachable.** The kernel reads
    and writes user memory through TTBR0, which holds the running process's
    address space. Code acting on another process (signals, timers, kill,
    wait, `finalize`) must not touch its user memory, unless it activates
    that address space first and switches back (fork's `CLONE_CHILD_SETTID`).
    A process that ended keeps its address space until another process is
    switched in: never free the active one. `/proc/<pid>/mem`
    (`FileKind::ProcMem`) is the caller's own memory only: another's
    can't be opened, and one inherited across fork reads EIO.

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
