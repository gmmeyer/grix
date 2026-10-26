# grix

**grix** (greg + unix) is an *agentbox*: a Rust unikernel for running Linux
programs on behalf of AI agents, with **least privilege by default**. Each
run boots a fresh microVM whose kernel runs exactly one unmodified Linux
binary. The program sees only the files you
import, and every syscall is checked against the capabilities you grant.
Anything it tries beyond that is denied and reported back, so the agent can
see exactly what the program needed.

```console
$ grix run -i ./build/net:/bin/net -- /bin/net
socket: Operation not permitted
grix: denied socket: needs capability `net`

$ grix run -i busybox.static:/bin/busybox -- /bin/busybox cat /etc/passwd
cat: can't open '/etc/passwd': No such file or directory
grix: missing /etc/passwd: not imported
```

> **Status: early prototype.** It runs unmodified **Python 3.12** and
> **Node 22** (Alpine's builds), busybox, and static, static-PIE or
> dynamically linked musl programs, with threads, pipes, eventfd and epoll.
> Processes (fork/exec), signal handlers, writable files and networking are
> gated by capabilities but **not implemented yet**. See
> [Compatibility](#compatibility) and [Roadmap](#roadmap).

## Quick start

Requirements: macOS or Linux on any host, Rust (stable), QEMU
(`qemu-system-aarch64`), and [zig](https://ziglang.org) to build the C test programs.

```sh
make            # kernel + host CLI + test fixtures (downloads Alpine busybox, python3, nodejs)
make test       # unit tests + end-to-end tests that boot the kernel in QEMU

./target/release/grix run -i fixtures/build/hello:/bin/hello -e GREETING=hi -- /bin/hello world
./target/release/grix run -m examples/busybox.toml
./target/release/grix run --json -m examples/busybox.toml     # machine-readable result
./target/release/grix caps                                    # list capabilities

# Language runtimes: import a whole root filesystem and allow threads.
./target/release/grix run -a threads -i fixtures/build/python:/ -- /usr/bin/python3 -c 'print(6*7)'
./target/release/grix run -a threads -i fixtures/build/node:/ -- /usr/bin/node -e 'console.log(6*7)'
```

grix uses hardware virtualization when the host has it (Hypervisor.framework
on Apple Silicon, KVM on arm64 Linux) and QEMU's emulator otherwise. Set
`GRIX_ACCEL=tcg|hvf|kvm` to choose. A Node script that boots, starts a worker
thread and exits takes about 0.9s with HVF, 9s emulated.

## Using it from an agent (Rust)

```rust
use grix::{Capability, Sandbox};

let sandbox = Sandbox::builder()
    .import("./tools/busybox.static", "/bin/busybox")?   // a host file or directory
    .file("/data/input.csv", csv_bytes, 0o644)?          // or inline contents
    .env("LANG", "C")
    .memory_mb(256)
    .timeout(std::time::Duration::from_secs(10))
    // .allow(Capability::Net)                            // grant only what's needed
    .build()?;

let out = sandbox.run(&["/bin/busybox", "wc", "-l", "/data/input.csv"])?;
println!("{}", out.stdout_str());           // also: stderr, status, kernel_log, duration
for event in &out.events {
    eprintln!("{event}");                   // denied / missing / unsupported / faults
}
let needed = out.missing_capabilities();    // e.g. ["net"] -> ask the user, then re-run
```

Every `run` boots a new VM from the same configuration, so runs don't share
state. `run_streaming` delivers stdout/stderr as they arrive.

## Manifests

The same sandbox written as TOML (`grix run -m file.toml [-- cmd...]`):

```toml
command = ["/bin/busybox", "sha256sum", "/data/hello.c"]
capabilities = []        # fs_write, threads, process, net
on_deny = "errno"        # "errno" (EPERM) or "kill" (SIGSYS, like seccomp)
memory_mb = 256
timeout_secs = 30

[env]
LANG = "C"

[[import]]
host = "../fixtures/build/alpine/bin/busybox.static"   # relative to the manifest
guest = "/bin/busybox"
```

## What you can import

Anything that is a file. `import` copies host files and directories
(recursively, keeping modes and symlinks) into the sandbox's filesystem:

- **Programs**: any AArch64 Linux executable, static or dynamic. For a
  dynamic one, also import its loader and libraries.
- **Whole runtimes**: `tools/alpine.py --out DIR pkg...` resolves Alpine
  packages and their dependencies into a directory you import at `/`. This
  is how the Python and Node fixtures are built. The same works for `ruby`,
  `perl`, `lua`, `git`, `sqlite`, `jq`, ...
- **Libraries and code**: a `site-packages` or `node_modules` tree, a
  project checkout, scripts written by the agent (`file()` takes inline
  contents).
- **Data and config**: inputs, CA certificates (`/etc/ssl`), timezone data,
  `/etc/passwd` stubs. `missing ...` events tell you what a program looked
  for and didn't find.

Everything imported is read-only and lives in guest memory, so total size is
bounded by `memory_mb` (Python's root is 40 MB, Node's 73 MB).

## Capability model

| What | Default | How to get more |
|---|---|---|
| Files | Only imported paths exist (read-only), plus `/dev/{null,zero,random,urandom}`, `/proc/self/exe`, empty `/tmp` | `import` / `file` |
| Environment | Empty | `env` |
| Memory, time, randomness, stdout/stderr | Always available | `memory_mb`, `timeout` limit them |
| Local IPC: pipes, eventfd, epoll, AF_UNIX socket pairs | Always available | — |
| `fs_write` | Denied | `allow(Capability::FsWrite)` |
| `threads` | Denied | `allow(Capability::Threads)` |
| `process` (fork/exec/wait) | Denied | `allow(Capability::Process)` |
| `net` | Denied, and the VM has no network device | `allow(Capability::Net)` |
| Privileged (mount, ptrace, bpf, module loading, changing uid, …) | Always denied | — |

A program can't get around the policy by making the call itself (with
`syscall()` or inline assembly). The policy is enforced by the kernel the
program runs on.

Events tell you what happened:

- `denied <syscall>: needs capability <cap>`: blocked by policy.
- `missing <path>: not imported`: the program looked for a file you didn't provide.
- `unsupported <syscall>`: granted (or harmless), but grix doesn't implement it yet.
- `killed by signal N`: crash or abort, with the faulting address.
- `could not start`: missing or invalid program.

## How it works

```
 host process (your agent)                          microVM (QEMU virt, 1 vCPU)
┌──────────────────────────────┐                   ┌─────────────────────────────────┐
│ grix crate                   │  boot image       │ grix kernel (no_std Rust)       │
│  - collects imports          │ ───────────────►  │  - boots at EL1, high-half MMU  │
│  - encodes policy+argv+env   │  @0x4800_0000     │  - reads image, builds RO fs    │
│  - starts QEMU               │                   │  - loads ELF (+ interpreter)    │
│  - decodes framed console    │ ◄───────────────  │  - runs program at EL0          │
│    stdout/stderr/events/exit │   serial frames   │  - Linux syscall ABI + policy   │
└──────────────────────────────┘                   └─────────────────────────────────┘
```

- **One program, one address space.** The kernel implements the Linux AArch64
  syscall ABI directly (`kernel/src/syscall/`). Memory is demand-paged. ELF
  segments are paged in straight from the boot image, and anonymous memory is
  zero-filled on first touch.
- **The filesystem is the import list.** It's built in memory from the boot
  image. File contents aren't copied: they're referenced in place.
- **Talking to the host.** Everything the guest says (program output, kernel
  log, events, exit status) travels in length-prefixed frames on the serial
  port. The host treats this stream as untrusted input.
- **The VM's devices.** The VM gets RAM, a serial port, and nothing else: no
  network card, no disks, no QEMU monitor, and no semihosting (which would
  expose host files).

### Security model

The isolation boundary is the **hypervisor**. A program that fully compromised
the grix kernel would still be inside a VM with no network device, no
disk, and only the imported files in its memory. The guest kernel's policy
checks are what make the sandbox *least privilege* and *observable*, but they
aren't the only wall.

Caveat: the current VMM is QEMU, which is large. A minimal Rust VMM
(Hypervisor.framework / KVM, serial console only) is on the roadmap and would
shrink that attack surface substantially. Until then, don't treat this as
hardened against a determined attacker.

## Compatibility

Linux compatibility means *binary* compatibility: unmodified AArch64 Linux
ELF executables, the same files you'd run on an arm64 Linux machine.

| Works today | Not yet |
|---|---|
| Static, static-PIE and dynamic (musl `ld.so`) executables | glibc dynamic binaries (untested) |
| argv/envp/auxv, HWCAP, AT_RANDOM, TLS | Network sockets (`net`), stdin from the host |
| Threads: `clone`/`clone3`, futexes (incl. requeue, wake-op, timeouts), preemption, deadlock detection | `fork`/`vfork`/`execve`/`wait` (needed by shells running commands) |
| Pipes, eventfd, epoll (level/edge/oneshot), `poll`/`select`, AF_UNIX `socketpair` | Signal handlers (`sigaction` is recorded; delivery isn't). Go needs this |
| `read`/`write`/`readv`/`writev`/`pread`/`lseek`, `openat`, `stat*`, `getdents64`, `readlink`, `fcntl`, `dup*`, `ioctl` | Writable filesystem (`fs_write`) |
| `mmap`/`munmap`/`mprotect`/`mremap`/`madvise`/`brk` (lazy paging) | Multiple vCPUs (threads share one) |
| Clocks, blocking sleeps, `getrandom` (ChaCha20, host-seeded + RNDR) | x86_64 guests |
| Faults become signals (SIGSEGV/SIGILL/SIGTRAP/SIGBUS/SIGPIPE/...) | Linux/KVM hosts are untested |

Verified programs: the C fixtures in `fixtures/src`; Alpine's busybox (static
and dynamic: `sha256sum`, `sort`, `grep`, `awk`, `ls`, `sh` builtins, …);
Alpine's **python3** (threads, asyncio, hashlib, json) and **nodejs**
(timers, crypto, fs, worker_threads).

## Roadmap

1. **Networking** (`net`), so web servers can run: socket syscalls in the
   guest, proxied to the host, which enforces allow-lists for outbound
   connections and forwards listening ports. The guest needs no TCP/IP stack.
2. **Signal delivery** and `rt_sigreturn` (Go's preemption, Python's
   SIGINT, Node's process.on('SIGTERM')).
3. **Writable filesystem**: tmpfs with a size limit (`fs_write`), optionally
   exported back to the host, and stdin from the host.
4. **Processes**: fork/vfork/execve/wait with separate address spaces (`process`).
5. **Own VMM**: a small Rust VMM on Hypervisor.framework / KVM to replace
   QEMU. That means faster boots, a smaller attack surface, and a `grix`
   crate with no external dependencies. Also faster I/O than the serial port.
6. **Agent integrations**: an MCP server and Python bindings; prebuilt
   runtime bundles; snapshots for instant start.
7. **SMP and x86_64 guests**.

## Repository layout

```
crates/abi/        shared host<->guest definitions: boot image, policy, wire protocol (no_std)
crates/grix/       host library + `grix` CLI (builds images, runs QEMU, decodes output)
kernel/            the guest kernel (no_std, aarch64-unknown-none-softfloat)
  src/arch/        boot.S (MMU bring-up), vectors.S (traps), system registers
  src/mm/          frame allocator, page tables, address spaces / VMAs
  src/sched.rs     threads: round-robin scheduler, blocking, timer interrupts
  src/ipc.rs       pipes, eventfds, socket pairs
  src/syscall/     Linux syscall table (+ capability gates) and implementations
fixtures/          C test programs (built with zig); build/ also gets Alpine runtimes
tools/alpine.py    Alpine package resolver for building importable root filesystems
examples/          example manifests
```

See [AGENTS.md](AGENTS.md) for contributor and agent guidelines.
