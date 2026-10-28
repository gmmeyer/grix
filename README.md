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

> **Status: early prototype.** It runs unmodified **Python 3.12**,
> **Node 22** (Alpine's builds), **Go** programs, busybox, and static,
> static-PIE or dynamically linked musl programs, with threads, signal
> handlers, pipes, eventfd, epoll and (with `fs_write`) a writable in-memory
> filesystem. With the matching capabilities it also runs processes
> (fork/exec) and **networks through the host**: clients, servers on
> forwarded ports, and DNS, under an allow-list. Host directories can be
> **mounted live**, read-write or read-only, without copying them in. See
> [Compatibility](#compatibility) and [Roadmap](#roadmap).

## Quick start

Requirements: macOS 15+ on Apple silicon or arm64 Linux with KVM (grix's own
VMM), or QEMU (`qemu-system-aarch64`) on anything else; Rust (stable);
[zig](https://ziglang.org) to build the C test programs, and Go to build the
Go ones. `make test` needs QEMU too, since some tests run on both VMMs.

```sh
make            # kernel + host CLI + grix-vmm + test fixtures (downloads Alpine busybox, python3, nodejs)
make test       # unit tests + end-to-end tests that boot the kernel

./target/release/grix run -i fixtures/build/hello:/bin/hello -e GREETING=hi -- /bin/hello world
./target/release/grix run -m examples/busybox.toml
./target/release/grix run --json -m examples/busybox.toml     # machine-readable result
./target/release/grix caps                                    # list capabilities

# stdin is passed through when it isn't a terminal (--no-stdin turns that off).
echo 'a b c' | ./target/release/grix run -i fixtures/build/alpine/bin/busybox.static:/bin/busybox -- /bin/busybox wc -w

# Results: the program fills /out, and it's copied to ./results when it ends.
./target/release/grix run -a fs_write -x /out:./results \
    -i fixtures/build/alpine/bin/busybox.static:/bin/busybox -- /bin/busybox cp /etc/passwd /out/

# Language runtimes: import a whole root filesystem and allow threads.
./target/release/grix run -a threads -i fixtures/build/python:/ -- /usr/bin/python3 -c 'print(6*7)'
./target/release/grix run -a threads -i fixtures/build/node:/ -- /usr/bin/node -e 'console.log(6*7)'

# More CPUs: a process's threads run in parallel (separate processes take turns).
./target/release/grix run --cpus 4 -a threads -i fixtures/build/smp:/bin/smp -- /bin/smp

# x86_64 programs, through an x86_64 translator (here Alpine's arm64 qemu-x86_64).
./target/release/grix run --x86-64 fixtures/build/qemu-x86_64/usr/bin/qemu-x86_64 -a threads \
    -e QEMU_LD_PREFIX=/ -i fixtures/build/x86_64:/ -- /usr/bin/python3 -c 'import platform; print(platform.machine())'

# Networking: only to example.com, port 443.
./target/release/grix run -a net -a threads --allow-host example.com:443 -i fixtures/build/python:/ -- \
    /usr/bin/python3 -c 'import urllib.request as u; print(u.urlopen("https://example.com").status)'

# A server: host port 8080 goes to port 8000 in the sandbox.
./target/release/grix run -a net -a threads -p 8080:8000 -i fixtures/build/python:/ -- \
    /usr/bin/python3 -m http.server 8000
```

On arm64 macOS 15+ and arm64 Linux with KVM, grix runs its kernel in its
own VMM, `grix-vmm` (Hypervisor.framework or KVM, about 1,300 lines of
Rust, no QEMU needed). A run that boots, runs a program and exits takes
about 0.1 s. Elsewhere it uses QEMU, with its emulator if the host can't
virtualize arm64. `GRIX_ACCEL=tcg|hvf|kvm` chooses QEMU with that
accelerator, and `GRIX_VMM=PATH|qemu` picks the VMM. A Node script that
boots, starts a worker thread and exits takes about 0.9s with HVF, 9s
emulated.

`grix-vmm` lives next to `grix` or in this tree's `target/release/`. On
macOS it must be signed with the hypervisor entitlement (`make vmm` does
it, ad hoc). `make test-kvm` checks the KVM side from an M3 (or later)
Mac: it boots Linux in QEMU with nested virtualization and runs grix there.

## Using it from an agent (Rust)

```rust
use grix::{Capability, Sandbox};

let sandbox = Sandbox::builder()
    .import("./tools/busybox.static", "/bin/busybox")?   // a host file or directory
    .file("/data/input.csv", csv_bytes, 0o644)?          // or inline contents
    .env("LANG", "C")
    .memory_mb(256)
    .timeout(std::time::Duration::from_secs(10))
    .allow(Capability::FsWrite)                          // grant only what's needed
    .export("/out")?                                     // sent back when the program ends
    .build()?;

let out = sandbox.run(&["/bin/busybox", "sort", "-o", "/out/sorted.csv", "/data/input.csv"])?;
println!("{}", out.stdout_str());           // also: stderr, status, kernel_log, duration
for event in &out.events {
    eprintln!("{event}");                   // denied / missing / unsupported / faults
}
let needed = out.missing_capabilities();    // e.g. ["net"] -> ask the user, then re-run
let results = out.export("/out").unwrap();  // entries in memory (state says if it's all there)
results.write_to("./results")?;             // or recreate it on the host
```

### Signals and timeouts

A `RunControl` sends the program signals while it runs, as a terminal
would: to its whole process group, so a shell's children get Ctrl-C too.

```rust
use grix::RunControl;

let control = RunControl::new();
let sandbox = Sandbox::builder().import("./server", "/bin/server")?.control(&control).build()?;
let c = control.clone();
std::thread::spawn(move || {
    // ... later, from anywhere:
    c.signal(2);   // SIGINT: what Ctrl-C would send
    c.signal(15);  // SIGTERM: shut down
    c.stop();      // or just end the run (ExitStatus::Stopped)
});
let out = sandbox.run(&["/bin/server"])?;
```

- When the time limit runs out, the program gets SIGTERM and a grace
  period (`grace`, 5 seconds by default) to end. If it does, its exports
  and `mount_on_exit` changes come back. The status is `Timeout` either way.
- A program whose threads are all blocked is ended at once and reported as
  a deadlock, unless one waits for a signal (`pause`, `sigsuspend`,
  `sigwait`): one may yet come, from a control or the time limit.
- The CLI passes on Ctrl-C, SIGTERM, SIGHUP and SIGQUIT (QEMU runs in its
  own process group, so a terminal's Ctrl-C is the program's alone). The
  third Ctrl-C stops the sandbox. `--grace SECS` and the manifest's
  `grace_secs` set the grace period.

### Working on a host directory

`mount` makes a host directory live in the sandbox, like a bind mount:
the program sees it as it is, and what it changes there changes on the
host at once. Nothing is copied in up front. The kernel asks the host for
directory listings and file contents as the program needs them, so the
directory can be any size.

```rust
let sandbox = Sandbox::builder()
    .import("./tools/busybox.static", "/bin/busybox")?
    .mount("./my-project", "/work")?            // read-write; grants fs_write
    .mount_read_only("./datasets", "/data")?    // EROFS on any change
    .cwd("/work")
    .build()?;
let out = sandbox.run(&["/bin/busybox", "sed", "-i", "s/foo/bar/g", "/work/src/main.c"])?;
```

- **Confined.** The host serves each request by walking down from the
  mounted directory one checked name at a time, never following a link.
  A link the program makes (or finds) can't lead it out.
- **Fresh within a second.** The kernel keeps what the host told it for a
  second, so changes made on the host during the run show up within one.
  Its own changes are visible at once, to it and to the host.
- **Linux semantics**:
  - files removed while open stay usable;
  - `O_APPEND` writes go to the host file's end;
  - `fsync` reaches the host's disk;
  - the mount point itself can't be removed or renamed (EBUSY);
  - renames and hard links into or out of the mount fail with EXDEV, and
    hard links within it with EPERM.
- **Files' times and modes are the host's.** Ownership shows as the sandbox
  user's, and `chown` can't change it.
- **Any size.** Runtimes work from a live mount too: Python runs entirely
  from read-only mounts of its `/lib` and `/usr`, mapping its shared
  libraries page by page from the host. A tree or a single directory can be
  larger than the kernel can hold at once: it forgets entries it's done
  with and asks again.
- **Limits:**
  - A file the host replaces while the program has it open may show the new
    contents (the host reopens it by name once its descriptor ages out).
  - On a read-only mount, changes that need `fs_write` are reported as
    denied (`needs capability fs_write`) when it isn't granted, instead of
    EROFS.

`mount_on_exit` is the other kind of read-write mount: each run imports the
directory, and what the program changed is applied to the host only when it
ends, all at once. Only what changed is sent back, and nothing at all is
applied if the changes don't all arrive (over `max_export`, or the run was
cut off). Applying never follows a link and replaces files by renaming new
ones into place. Anything that also changed on the host during the run is
left as the host has it and listed in `RunOutput::mount_changes[i].conflicts`.
The directory lives in guest memory, so `memory_mb` bounds it.

The CLI has `--mount HOST:GUEST[:rw|ro|on-exit]`, and manifests `[[mount]]`
tables with `host`, `guest` and `mode` (`"rw"`, `"ro"` or `"on_exit"`).

An exported directory comes back whenever the program ends (exit, crash,
deadlock, or a timeout it ends within the grace period of; see below). If
nothing is imported there, it starts out empty. The program's status is reported first, and the export then has
30 seconds. The guest leaves out entries over the budget (`max_export`, 256
MiB by default) or nested deeper than 4096 bytes of path, and `state` says
when anything is missing. `write_to` builds the tree beside its target and
renames it into place. It never writes through a symlink, drops
setuid/setgid and group/other write, and leaves nothing behind if it fails.
The CLI checks `-x` destinations before the run.

Every `run` boots a new VM from the same configuration, so runs don't share
state. `run_streaming` delivers stdout/stderr as they arrive.

### Networking

With `Capability::Net`, sockets work, but the VM still has no network card.
Each connection the program makes is made by the host on its behalf, after
a policy check:

```rust
let sandbox = Sandbox::builder()
    .import("./fixtures/build/python", "/")?
    .allow(Capability::Net)
    .allow(Capability::Threads)
    .allow_host("pypi.org")?               // names, *.wildcards, IPs, CIDRs, each with an optional :port
    .allow_host("*.pythonhosted.org:443")?
    .allow_host("host.grix.internal:5432")? // the host's own 127.0.0.1:5432
    .forward("127.0.0.1:8080", 8000)?      // host 8080 -> sandbox port 8000
    .build()?;
```

- Without `allow_host` rules, the program may connect anywhere except the
  host itself and special addresses (loopback, link-local such as cloud
  metadata at 169.254.169.254, multicast). With rules, only what they match,
  and DNS answers only names they cover, so lookups can't carry data out
  either. Special addresses need a rule for them specifically: `0.0.0.0/0`
  doesn't open them.
- The host's own services are `host.grix.internal` (10.0.2.2) and need a
  rule naming them.
- Connections inside the sandbox (127.0.0.1, `::1`, its own 10.0.2.15) stay
  in the sandbox, so a server and its client in one sandbox work with no
  rules.
- DNS goes to the host's resolver: the sandbox gets an `/etc/resolv.conf`
  and `/etc/hosts` unless you import your own.
- Denials come back as events: `denied connect (93.184.216.34:80 isn't in
  the allow-list): not allowed by the network policy (allow_host)`.
- HTTPS needs CA certificates in the sandbox. Node has its own; for Python
  or curl, add Alpine's `ca-certificates-bundle` to the runtime (the test
  fixture has it).
- `forward_listener` takes a `TcpListener` you bound (port 0 to let the OS
  pick), for tests.

The CLI has `--allow-host RULE` and `-p/--publish [ADDR:]HOSTPORT:GUESTPORT`;
manifests have `allow_hosts = [...]` and `[[forward]]` tables with `host` and
`guest`. Only TCP and DNS are supported: other UDP, raw sockets and ICMP are
reported as unsupported.

## MCP server and Python

`grix mcp` serves AI agents over the Model Context Protocol (stdio). Its
`run` tool runs a program in a fresh sandbox: imports, inline files, a
grix image, mounts, env, stdin, capabilities and exports. It answers with
the exit status, output, events, missing capabilities and the exported
files, and what writable mounts changed on the host. Its `build_image`
tool builds an image from a Grixfile. Agents get only what the server
allows:

```sh
grix mcp --root ~/projects/demo          # host paths only under the roots (default: the current directory)
grix mcp -a fs_write -a process          # capabilities agents may grant (default: fs_write, threads, process)
grix mcp -a net --allow-host pypi.org    # net only if allowed, and only where the rules say
grix mcp --writable                      # rw/on_exit mounts and build_image (default: agents only read the host)
grix mcp --max-timeout 120 --max-mem 1024
```

Images an agent runs get the server's kernel, and may ask only for
capabilities the server allows. Builds follow the same policy: their steps
get `net` (under the same host rules) and `from` may pull from a registry
only if the server allows `net`; `docker:` sources are refused.

For example, in a Claude Code or other MCP client config:

```json
{"mcpServers": {"grix": {"command": "grix", "args": ["mcp", "--root", "/path/to/project"]}}}
```

Python (`pip install ./python`) drives the same CLI:

```python
import grix

sb = grix.Sandbox(imports={"./busybox": "/bin/busybox"}, files={"/data/in.txt": "b\na\n"},
                  capabilities=["process"], timeout=30)
r = sb.run(["/bin/busybox", "sort", "/data/in.txt"])
print(r.exit_code, r.stdout, r.events, r.missing_capabilities)

grix.build("app.grix", grixfile="Grixfile")        # images too
print(grix.Sandbox(image="app.grix").run().stdout)
```

## Snapshots

A runtime that takes seconds to start can be started once and snapshotted
the moment it first waits for input. Each run from the snapshot then goes on
from there, with its own stdin, in a tenth of a second:

```sh
# Python with its libraries imported, waiting for code on stdin: 2.6 s, once.
grix snapshot -o py.snap -a threads -i fixtures/build/python:/ -- \
    /usr/bin/python3 -c 'import json, decimal, asyncio, sys; exec(sys.stdin.read())'

echo 'print(json.dumps({"sum": sum(range(10))}))' | grix run --snapshot py.snap   # 0.13 s
```

```rust
let snap = sandbox.snapshot(&["/usr/bin/python3", "-c", "...; exec(sys.stdin.read())"], "py.snap")?;
let out = snap.run("print(6 * 7)")?;                       // or grix::Snapshot::open("py.snap")?
```

Also from MCP (the `snapshot` tool, and `run`'s `snapshot`) and Python
(`Sandbox.snapshot()`, `Snapshot.run()`).

- The VMM saves the vCPU, the GIC, the console device and RAM. A run maps
  that RAM copy-on-write from the file, so runs never see each other's
  changes, and only what a run touches is read. The file is sparse: 80 MB
  on disk for that Python.
- Each run gets fresh entropy for the kernel's random number generator.
  As after a suspend, the time of day moves on by however long the
  snapshot sat there, and the monotonic clock doesn't (so a `read -t 5`
  that was waiting still has its 5 seconds). What the program drew for
  itself before the snapshot (a random seed, say) is the same in every
  run.
- The snapshot is taken once the program has found stdin empty and waits.
  What the host holds for a run isn't saved, so it waits until the
  program has no connections or DNS lookups open through the host, and
  sandboxes with mounts can't take one.
- The file holds the program's memory, so it's created readable only by
  you, and written fully before it replaces the old one.
- Snapshots need grix-vmm on macOS (Hypervisor.framework). Runs from a
  snapshot get the sandbox's network policy as it was. Over MCP they get
  the server's, whoever wrote the file.

## Images

A grix image is a file tree, the settings to run it with, and the grix
kernel, in one file (`.grix`, a gzipped tar) you can copy anywhere grix
runs. Build one from a Docker/OCI image and your own files, or from
nothing but the grix kernel and a static program: no other OS needed.

```sh
# From Docker Hub's python image, with a dependency installed at build time:
cat > Grixfile <<'TOML'
from = "python:3.12-alpine"
command = ["python3", "/app/main.py"]
capabilities = ["threads"]
run = ["pip install --no-cache-dir requests"]
[[copy]]
host = "app"
guest = "/app"
TOML
grix build -o app.grix
grix run --image app.grix                 # its command, settings and kernel
grix run --image app.grix -- python3 -V   # or another command

# Nothing but grix and one static program, without a Grixfile:
grix build -o hello.grix --copy ./hello:/bin/hello -- /bin/hello
```

- `from` takes a registry reference (`alpine:3.21`,
  `ghcr.io/owner/repo:tag`; the linux/arm64 image), `oci:DIR` (an OCI image
  layout), `docker-archive:FILE` (`docker save` output), `docker:NAME` or
  `dir:DIR`. Layers are applied with their whiteouts, every blob is checked
  against its digest, and the image's entrypoint, command, environment and
  working directory become the grix image's, and so does its user (root
  unless it names one, as in Docker). A command that's a bare name is
  looked up on the image's `PATH`. `grix pull REF --oci DIR` saves an
  image for offline builds.
- Build steps (`run`) run in grix itself, with `fs_write`, `process`,
  `threads` and `net`. A string runs with `/bin/sh -c`; a list such as
  `["/bin/setup", "--fast"]` runs as it is, without a shell. The file tree
  a step leaves is the image's, minus what the kernel makes at boot
  (`/etc/passwd`, `/tmp`, ...). `apt-get install` works in a Debian or
  Ubuntu image. `user = "uid[:gid]"` (or names from the image's
  `/etc/passwd`) says who the program runs as; build steps run as the base
  image's user. Without one or the other, it's 1000:1000. Ids mean something only inside the sandbox:
  root may switch to any user (`setuid` and friends follow Linux's rules),
  and nothing honours setuid bits.
- `grix build` flags (`--from`, `--copy`, `--env`, `--cwd`, `--allow`,
  `--run`, `--exec`, `--mem`, `-- COMMAND`) add to `./Grixfile`, or make the
  whole image without one. Like Docker's build context, a Grixfile reads
  host files only under its own directory; paths given as flags may be
  anywhere.
- `grix inspect app.grix` shows the settings. From Rust:
  `Sandbox::builder().image(&grix::Image::open("app.grix")?)?`, then
  `sandbox.run(sandbox.command())`. A manifest can say `image = "app.grix"`.
- An image runs only with a grix of the same ABI version as its kernel
  (the kernel carries a marker that grix checks). Running it grants the
  capabilities it lists that stay in the sandbox (`threads`, `process`,
  `fs_write`). `net` it can only ask for: grant it with `-a net` /
  `allow(Capability::Net)`. Its kernel runs inside the VM like any other:
  `net`, the network policy, mounts and exports are checked by the host,
  whatever the guest kernel does.

## Manifests

The same sandbox written as TOML (`grix run -m file.toml [-- cmd...]`):

```toml
command = ["/bin/busybox", "sha256sum", "/data/hello.c"]
capabilities = []        # fs_write, threads, process, net
on_deny = "errno"        # "errno" (EPERM) or "kill" (SIGSYS, like seccomp)
# allow_hosts = ["pypi.org", "*.pythonhosted.org"]   # with net: only these
memory_mb = 256
timeout_secs = 30

[env]
LANG = "C"

[[import]]
host = "../fixtures/build/alpine/bin/busybox.static"   # relative to the manifest
guest = "/bin/busybox"

[[export]]               # copied out when the program ends (needs fs_write to fill it)
guest = "/out"
host = "results"         # relative to the manifest; must not exist yet, or be empty

# [[mount]]              # live; mode = "rw" (default), "ro" or "on_exit"
# host = "../my-project"
# guest = "/work"

# [[forward]]            # with net: host 127.0.0.1:8080 -> port 8000 in the sandbox
# host = "127.0.0.1:8080"
# guest = 8000
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
| Files | Only imported paths exist (read-only), plus `/dev/{null,zero,random,urandom}`, `/proc/self/exe`, empty `/tmp` | `import` / `file`; `mount` / `mount_read_only` for a live host directory |
| Environment | Empty | `env` |
| Memory, time, randomness, stdout/stderr | Always available | `memory_mb`, `timeout` limit them |
| Local IPC: pipes, eventfd, epoll, AF_UNIX socket pairs | Always available | — |
| `fs_write` | Denied: the filesystem is read-only | `allow(Capability::FsWrite)`: the whole tree becomes writable in guest memory (copy-on-write over the imports, up to half of RAM). The host's files never change. |
| `threads` | Denied | `allow(Capability::Threads)` |
| `process` (fork/exec/wait) | Denied | `allow(Capability::Process)` |
| `net` | Denied, and the VM has no network device | `allow(Capability::Net)`: TCP and DNS through the host, which checks `allow_host` rules; `forward` for servers |
| Privileged (mount, ptrace, bpf, module loading, capabilities, …) | Always denied | — |

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
 host process (your agent)                          microVM (grix-vmm or QEMU, 1 vCPU)
┌──────────────────────────────┐                   ┌─────────────────────────────────┐
│ grix crate                   │  boot image       │ grix kernel (no_std Rust)       │
│  - collects imports          │ ───────────────►  │  - boots at EL1, high-half MMU  │
│  - encodes policy+argv+env   │  @0x4800_0000     │  - reads image, builds RO fs    │
│  - starts the VMM            │                   │  - loads ELF (+ interpreter)    │
│  - decodes framed console    │ ◄───────────────  │  - runs program at EL0          │
│    stdout/stderr/events/exit │  virtio frames    │  - Linux syscall ABI + policy   │
└──────────────────────────────┘                   └─────────────────────────────────┘
```

- **One program, one address space.** The kernel implements the Linux AArch64
  syscall ABI directly (`kernel/src/syscall/`). Memory is demand-paged. ELF
  segments are paged in straight from the boot image, and anonymous memory is
  zero-filled on first touch.
- **The filesystem is the import list.** It's built in memory from the boot
  image. File contents aren't copied: they're referenced in place.
- **Talking to the host.** Everything the guest says (program output, kernel
  log, events, exit status) travels in length-prefixed frames on a virtio
  console, and stdin comes back the same way: tens of MB/s, with
  backpressure in both directions. Early boot messages and panics use the
  serial port. The host treats both streams as untrusted input.
- **The VM's devices.** The VM gets RAM, the virtio console, a serial port,
  and nothing else: no network card, no disks, no QEMU monitor, and no
  semihosting (which would expose host files).
- **Its own VMM.** `grix-vmm` (`crates/vmm`) makes that machine on
  Hypervisor.framework or KVM: one vCPU, the hypervisor's own GICv3, a
  PL011 and the virtio console, emulated in a few hundred lines. It runs as
  a child process like QEMU would, and once the VM is set up it confines
  itself (a deny-everything macOS sandbox; a seccomp allowlist on Linux):
  no files, no network, no new processes, only its stdin, stdout and the
  serial socket.
- **Host directories without a disk.** A live mount is served by the host
  over the console too: the kernel asks for listings and bytes as the
  program needs them, and sends its changes as it makes them.
- **Networking without a network card.** The guest kernel turns sockets
  into messages on the console. The host makes the connections (after the
  policy check), forwards ports, and answers DNS. Flow control is by credit
  in both directions, so a slow connection never stalls the console.

### Security model

The isolation boundary is the **hypervisor**. A program that fully compromised
the grix kernel would still be inside a VM with no network device, no
disk, and only the imported files in its memory. The guest kernel's policy
checks are what make the sandbox *least privilege* and *observable*, but they
aren't the only wall.

Where it runs (arm64 macOS and Linux), the VMM is grix's own: small, and
confined itself, so a guest that escaped the hypervisor into it would
still have no files or network. Elsewhere it's QEMU, which is large.
Either way, don't treat grix as hardened against a determined attacker yet:
it hasn't had an outside security review.

## Compatibility

Linux compatibility means *binary* compatibility: unmodified AArch64 Linux
ELF executables, the same files you'd run on an arm64 Linux machine.

| Works today | Not yet |
|---|---|
| Static, static-PIE and dynamic executables, musl and glibc (Debian's bash, coreutils, perl, apt, git, curl; the official `python` and `node` images) | Terminals: `posix_openpt`, a TTY for the program |
| argv/envp/auxv, HWCAP, AT_RANDOM, TLS, stdin from the host (`run_with_stdin`, or piped into the CLI), output limits (`max_output`), fast stdio with backpressure (a slow reader blocks the writer, or EAGAIN) | UDP other than DNS, raw sockets, ICMP (`ping`) |
| With `net`: TCP clients and servers (AF_INET/AF_INET6, blocking and non-blocking, epoll, `SO_ERROR`, `SO_RCVTIMEO`/`SO_SNDTIMEO`, half-close), DNS through the host, loopback inside the sandbox, ports forwarded from the host, an allow-list | Socket options beyond timeouts (`SO_RCVBUF` and TCP options are accepted and ignored); bandwidth limits |
| Interface listing without `net`: netlink route sockets, `getifaddrs`, `if_nameindex`, interface ioctls and `/proc/net/dev` all report just `lo` | AF_UNIX sockets bound to paths |
| Threads: `clone`/`clone3`, futexes (incl. requeue, wake-op, timeouts), preemption, deadlock detection | `pidfd_*`; `/proc/<pid>` for other processes |
| With `process`: `fork`/`vfork`/posix_spawn (copy-on-write), `execve` of imported and written programs and `#!` scripts, `wait4`/`waitid`, `SIGCHLD`, zombies and orphans, process groups and sessions, `MAP_SHARED` anonymous memory shared across fork. Shell pipelines, Python `subprocess`, Node `child_process`, Go `os/exec` | Job control (stopping and continuing) |
| Pipes, eventfd, epoll (level/edge/oneshot), `poll`/`select`, AF_UNIX `socketpair`, `signalfd`, `memfd_create` (with seals) | CPU-time timers (`ITIMER_VIRTUAL`/`PROF`, CPU-clock POSIX timers) |
| Timers: `alarm`/`setitimer` (SIGALRM), POSIX timers (signal values, overruns, `SIGEV_THREAD_ID`, absolute times), `timerfd` (blocking, non-blocking, epoll) | |
| Signal handlers: Linux arm64 frames with FP/SIMD state, `SA_SIGINFO`/`SA_RESTART`/`SA_ONSTACK`/`SA_NODEFER`/`SA_RESETHAND`, `sigaltstack`, per-thread masks, queued real-time signals, `sigsuspend`/`sigtimedwait`, faults delivered to handlers, EINTR and restart of blocked calls | Job control signals from the host (SIGTSTP/SIGCONT) |
| Signals from the host: `RunControl::signal` and the CLI's Ctrl-C reach the program's process group; a timeout sends SIGTERM and a grace period first, so exports still come back | |
| `read`/`write`/`readv`/`writev`/`pread`/`lseek`, `openat`, `stat*`, `getdents64`, `readlink`, `fcntl`, `dup*`, `ioctl`; the host's file times | |
| Live host directory mounts (`mount`, `mount_read_only`, `--mount`), of any size; or changes applied when the program ends (`mount_on_exit`) | inotify events for host changes |
| With `fs_write`: creating, writing, truncating, renaming and deleting files and directories, hard and symbolic links, `O_TMPFILE`, unlinked-but-open files, chmod/chown/utimensat with Unix permissions, `sendfile`/`copy_file_range`, mmap of written files. Exporting directories back to the host when the program ends (`export`, `--export`) | Writable `MAP_SHARED` file mappings (reported); `inotify` events; xattrs |
| `mmap`/`munmap`/`mprotect`/`mremap`/`madvise`/`brk` (lazy paging) | Multiple vCPUs (threads share one) |
| Clocks (including per-thread and per-process CPU time), blocking sleeps, `getrandom` (ChaCha20, host-seeded + RNDR), `membarrier`, `mincore` | x86_64 guests |
| Unhandled faults and signals end the program with the signal (SIGSEGV/SIGILL/SIGTRAP/SIGBUS/SIGPIPE/...) | Linux/KVM hosts are untested |

Verified programs: the C fixtures in `fixtures/src`; Alpine's busybox (static
and dynamic: `sha256sum`, `sort`, `grep`, `awk`, `ls`, `sh` builtins, …);
Alpine's **python3** (threads, asyncio, hashlib, json, signal handlers,
KeyboardInterrupt, tempfile, shutil, an on-disk sqlite database) and
**nodejs** (timers, crypto, fs reads and writes, worker_threads,
`process.on('SIG…')`, `os.networkInterfaces()`, `child_process`, `http`
servers and `fetch`); Python `urllib` and `asyncio` servers; busybox `wget` and
`nslookup`; static Go binaries
(goroutine preemption, nil dereference panics, `os/signal`, `os/exec`); busybox
`cp -r`, `mv`, `rm -rf`, `tar`, `dd`, `find`, and `sh` scripts with pipelines and
subshells.

## Roadmap

1. ~~**Networking**~~: done. Sockets are proxied through the host, which
   enforces the allow-list and forwards ports. The guest has no TCP/IP stack.
2. ~~**Host directories**~~: done. Live mounts (read-write or read-only,
   any size) and mounts whose changes are applied when the program ends.
3. ~~**Signals from the host**~~: done (`RunControl`, Ctrl-C in the CLI,
   SIGTERM and a grace period on timeout).
4. ~~**Own VMM**~~: `grix-vmm` on Hypervisor.framework and KVM is done
   (the default where it runs: about twice as fast to start as QEMU, and
   confined), with snapshots on macOS.
5. ~~**Agent integrations**~~: images (`grix build`), the MCP server,
   Python bindings and snapshots for instant start are done.
6. ~~**SMP and x86_64 guests**~~: more CPUs (`--cpus N`, threads of a
   process run in parallel) and x86_64 programs, through a user-mode
   translator in the arm64 sandbox (`--x86-64 qemu-x86_64`: x86_64 Alpine
   and CPython run). Next: a native x86_64 kernel and grix-vmm on x86 KVM,
   for x86 hosts.

## Repository layout

```
crates/abi/        shared host<->guest definitions: boot image, policy, wire protocol (no_std)
crates/grix/       host library + `grix` CLI (builds images, runs the VMM, decodes output)
crates/vmm/        grix-vmm: the VMM (Hypervisor.framework, KVM), PL011 + virtio console
kernel/            the guest kernel (no_std, aarch64-unknown-none-softfloat)
  src/arch/        boot.S (MMU bring-up), vectors.S (traps), system registers
  src/mm/          frame allocator, page tables, address spaces / VMAs
  src/sched.rs     threads: round-robin scheduler, blocking, timer interrupts
  src/signal.rs    signal queues, rt_sigframe delivery, rt_sigreturn, EINTR/restart
  src/timer.rs     setitimer, POSIX timers and timerfds, fired by the scheduler
  src/netlink.rs   NETLINK_ROUTE answers and interface ioctls: the only interface is lo
  src/kmem.rs      the budget for kernel memory programs can make the kernel hold
  src/fs.rs        the filesystem: imports plus copy-on-write pages, permissions, size limits
  src/ipc.rs       pipes, eventfds, socket pairs
  src/syscall/     Linux syscall table (+ capability gates) and implementations
fixtures/          C (src/, built with zig) and Go (go/) test programs; build/ also gets Alpine runtimes
tools/alpine.py    Alpine package resolver for building importable root filesystems
examples/          example manifests
```

See [AGENTS.md](AGENTS.md) for contributor and agent guidelines.
