# agentbox

A Rust unikernel for running Linux programs on behalf of AI agents, with
**least privilege by default**. Each run boots a fresh microVM whose kernel
runs exactly one unmodified Linux binary. The program sees only the files you
import, and every syscall is checked against the capabilities you grant.
Anything it tries beyond that is denied and reported back, so the agent can
see exactly what the program needed.

```console
$ agentbox run -i ./build/net:/bin/net -- /bin/net
socket: Operation not permitted
agentbox: denied socket: needs capability `net`

$ agentbox run -i busybox.static:/bin/busybox -- /bin/busybox cat /etc/passwd
cat: can't open '/etc/passwd': No such file or directory
agentbox: missing /etc/passwd: not imported
```

> **Status: early prototype (milestone 1).** It runs single-threaded,
> single-process Linux programs: static, static-PIE, and dynamically linked
> musl binaries. That includes Alpine's prebuilt busybox, and the test suite
> covers all three. Threads, fork/exec, signal handlers, writable files and
> networking are gated by capabilities but **not implemented yet**. See
> [Compatibility](#compatibility) and [Roadmap](#roadmap).

## Quick start

Requirements: macOS or Linux on any host, Rust (stable), QEMU
(`qemu-system-aarch64`), and [zig](https://ziglang.org) to build the C test programs.

```sh
make            # kernel + host CLI + test fixtures (fetches pinned Alpine busybox)
make test       # unit tests + end-to-end tests that boot the kernel in QEMU

./target/release/agentbox run -i fixtures/build/hello:/bin/hello -e GREETING=hi -- /bin/hello world
./target/release/agentbox run -m examples/busybox.toml
./target/release/agentbox run --json -m examples/busybox.toml     # machine-readable result
./target/release/agentbox caps                                    # list capabilities
```

On Apple Silicon, `AGENTBOX_ACCEL=hvf` uses hardware virtualization: runs
take about 0.2s instead of 0.8s under emulation.

## Using it from an agent (Rust)

```rust
use agentbox::{Capability, Sandbox};

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

The same sandbox written as TOML (`agentbox run -m file.toml [-- cmd...]`):

```toml
command = ["/bin/busybox", "sha256sum", "/data/hello.c"]
capabilities = []        # fs_write, threads, process, net
on_deny = "errno"        # "errno" (EPERM) or "kill" (SIGSYS, like seccomp)
memory_mb = 256
timeout_secs = 30

[env]
LANG = "C"

[[import]]
host = "../fixtures/build/alpine/busybox.static"   # relative to the manifest
guest = "/bin/busybox"
```

## Capability model

| What | Default | How to get more |
|---|---|---|
| Files | Only imported paths exist (read-only), plus `/dev/{null,zero,random,urandom}`, `/proc/self/exe`, empty `/tmp` | `import` / `file` |
| Environment | Empty | `env` |
| Memory, time, randomness, stdout/stderr | Always available | `memory_mb`, `timeout` limit them |
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
- `unsupported <syscall>`: granted (or harmless), but agentbox doesn't implement it yet.
- `killed by signal N`: crash or abort, with the faulting address.
- `could not start`: missing or invalid program.

## How it works

```
 host process (your agent)                          microVM (QEMU virt, 1 vCPU)
┌──────────────────────────────┐                   ┌─────────────────────────────────┐
│ agentbox crate               │  boot image       │ agentbox kernel (no_std Rust)   │
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
the agentbox kernel would still be inside a VM with no network device, no
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
| argv/envp/auxv, HWCAP, AT_RANDOM, TLS | Threads (`clone(CLONE_THREAD)`), futex blocking |
| `read`/`write`/`readv`/`writev`/`pread`/`lseek`, `openat`, `stat*`, `getdents64`, `readlink`, `fcntl`, `dup*`, `ppoll` | `fork`/`vfork`/`execve`/`wait` (needed by shells running commands) |
| `mmap`/`munmap`/`mprotect`/`mremap`/`madvise`/`brk` (lazy paging) | Signal handlers (`sigaction` is recorded; delivery isn't) |
| Clocks, `nanosleep`, `getrandom` (ChaCha20, host-seeded + RNDR) | Writable filesystem (`fs_write`), pipes, `eventfd`, `epoll` |
| Faults become signals (SIGSEGV/SIGILL/SIGTRAP/SIGBUS/...) | Sockets (`net`), stdin from the host |
| Apple Silicon: HVF hardware virtualization and TCG | x86_64 guests; Linux/KVM hosts are untested |

Verified programs: the C fixtures in `fixtures/src`, plus Alpine's static and
dynamic busybox (`sha256sum`, `sort`, `grep`, `awk`, `ls`, `sh` builtins, …).

## Roadmap

1. **Threads and blocking**: scheduler, timer interrupts (GIC), real futex
   waits, signal delivery and `rt_sigreturn`. This unlocks Go, Python, Node, Java and Rust std threads.
2. **Writable filesystem**: tmpfs with a size limit (`fs_write`), pipes,
   eventfd/epoll, and stdin from the host.
3. **Processes**: fork/vfork/execve/wait with separate address spaces (`process`).
4. **Networking**: virtio-net, with egress allow-lists enforced on the *host* side (`net`).
5. **Own VMM**: a small Rust VMM on Hypervisor.framework / KVM to replace
   QEMU. That means faster boots, a smaller attack surface, and an
   `agentbox` crate with no external dependencies.
6. **Agent integrations**: an MCP server and Python bindings; runtime images
   (python, node) as importable bundles.
7. **x86_64 guest**.

## Repository layout

```
crates/abi/        shared host<->guest definitions: boot image, policy, wire protocol (no_std)
crates/agentbox/   host library + `agentbox` CLI (builds images, runs QEMU, decodes output)
kernel/            the guest kernel (no_std, aarch64-unknown-none-softfloat)
  src/arch/        boot.S (MMU bring-up), vectors.S (traps), system registers
  src/mm/          frame allocator, page tables, address spaces / VMAs
  src/syscall/     Linux syscall table (+ capability gates) and implementations
fixtures/          C test programs (built with zig) + pinned Alpine binaries
examples/          example manifests
```

See [AGENTS.md](AGENTS.md) for contributor and agent guidelines.
