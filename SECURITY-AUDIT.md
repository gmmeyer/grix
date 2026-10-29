# Security audit catalogue

A point-in-time catalogue of security issues found in this repository — 2026-10-28,
every finding verified against the source at commit `cddbc06` ("Snapshots with
more CPUs (0.0.7)"). Every confirmed finding, and I4, is fixed in 0.0.12
(`02e6228`); the index's Status column names the commit. I1–I3 are unchanged
by design (see each). Line numbers are `cddbc06`'s. Categories:
severity × component. "Confirmed" = verified by direct read of the code;
"hardening" = defense-in-depth or invariant erosion, not directly exploitable
today. A list of areas checked and found sound is at the end, so later work
doesn't have to re-derive what was already ruled out.

## Index

| # | Severity | Component | Issue | Where | Status |
|---|----------|-----------|-------|-------|--------|
| C1 | Critical | kernel | `u16` frame-refcount overflow → premature frame free → kernel escape / panic | `kernel/src/mm/frame.rs:31,93-97`; `aspace.rs:241,252-259` | fixed, `4aa24c5` |
| H1 | High | host | Snapshot files set their own net policy, forwards and limits on CLI/library/Python; only MCP sanitizes | `main.rs:326-369`; `sandbox.rs:1139-1178`; `python/lib.rs:273-296` | fixed, `f8f5db1` |
| M1 | Medium | host | Boot image (env/argv, secrets) world-readable at a predictable /tmp path | `crates/grix/src/vmm.rs:88-104,222,233-236` | fixed, `f840b06` |
| M2 | Medium | kernel | mmap hint below `MMAP_MIN_ADDR` is honored | `kernel/src/syscall/mem.rs:140-144` | fixed, `4aa24c5` |
| M3 | Medium | host | Unbounded host accumulation of Log/Event frames | `crates/grix/src/sandbox.rs:1096-1105` | fixed, `e5788da` |
| M4 | Medium | host | On-exit mount apply is check-then-use on path strings (TOCTOU) | `crates/grix/src/mount.rs:248-265,334,369,302-307,240` | fixed, `bb602bc` |
| M5 | Medium | host | Registry can send the user's credentials to any HTTPS realm it names | `crates/grix/src/oci.rs:783-812` | fixed, `8402ca9` |
| L1 | Low | host | Compressed layers in docker-archive/docker inputs skip digest verification | `crates/grix/src/oci.rs:414-421` | fixed, `04edcf0` |
| L2 | Low | host | Unbounded extraction of docker-save archives to /tmp | `crates/grix/src/oci.rs:386` | fixed, `04edcf0` |
| L3 | Low | kernel | `/proc/<pid>/fd` listing skips `may_inspect` | `kernel/src/syscall/file.rs:1142-1149` | fixed, `4aa24c5` |
| L4 | Low | host | Export-collector length arithmetic can overflow | `crates/grix/src/export.rs:313-314,339-341` | fixed, `e5788da` |
| L5 | Low | kernel | `d_reclen` truncated to `u16` in `getdents64` | `kernel/src/syscall/file.rs:1169-1182` | fixed, `4aa24c5` |
| L6 | Low | kernel | Pipe mutex held across `copy_out` (invariant-11-shaped deviation) | `kernel/src/syscall/file.rs:780-813` | fixed, `4aa24c5` |
| L7 | Low | kernel | File-offset wraparound in file-backed VMA math | `kernel/src/mm/aspace.rs:587,638,670-691` | fixed, `4aa24c5` |
| L8 | Low | host | Layer entry names don't count against `MAX_BYTES` | `crates/grix/src/oci.rs:489-496` | fixed, `04edcf0` |
| L9 | Low | host | hostfs id/listing caps allow ~600 MB host memory amplification | `crates/grix/src/hostfs.rs:44,48` | fixed, `e5788da` |
| L10 | Low | host | Live-mount root opened without `O_NOFOLLOW` / identity re-check | `crates/grix/src/hostfs.rs:262-263` | fixed, `bb602bc` |
| L11 | Low | VMM | Hostile GIC snapshot state parsed before `hvf::confine()` | `crates/vmm/src/vm.rs:349-352` vs `:383` | fixed, `f810523` |
| L12 | Low | abi | `Event::decode` accepts trailing bytes | `crates/abi/src/wire.rs:399-412` | fixed, `e5788da` |
| I1-I4 | Info | various | Trust-model notes: forgeable kernel marker, treecache poisoning, mknodat gap, setuid modes kept | see below | I4 fixed, `04edcf0`; I1–I3 by design |

---

## Critical

### C1. `u16` frame-refcount overflow → premature physical-frame free → kernel memory corruption / guaranteed panic

**Status:** fixed in 0.0.12 by `4aa24c5` (Kernel: bounded frame counts, mmap's lower bound and offsets).

- **Component:** guest kernel, memory management
- **Where:** `kernel/src/mm/frame.rs:31` (`refs: Vec<u16>`), `frame.rs:93-97` (`share()` —
  unchecked `+= 1`), `frame.rs:80-90` (`free()` — `assert!` + free-list push),
  `kernel/src/mm/aspace.rs:241` (fork's VMA bound, `>` not `>=`), `aspace.rs:252-259`
  (fork shares every non-CoW PTE), `aspace.rs:637-655` (SharedFile fault →
  `frame::share`).
- **Confirmed.** `MAX_VMAS = 32768` per process, `MAX_VMAS_TOTAL = 65536`; both checks
  are `>`, so exactly 2×32768 VMAs across a fork is allowed. The kernel release
  profile sets only `panic = "abort"` (`kernel/Cargo.toml:24-26`), so a `u16`
  overflow wraps silently in release builds.
- **Attack (deterministic, guest-only syscalls):** `memfd_create` + write 1 byte
  (refs = 1, the FileData's own) → `munmap` stack/sigpage/vdso/vvar (`munmap` accepts
  any range; the shellcode then lives in the memfd mapping) → map the same memfd page
  (`MAP_SHARED`, off = 0) at 32768 distinct addresses, fault each
  (refs = 1 + 32768 = 32769) → `fork()` (the bound check `65536 > 65536` is false, so
  it proceeds; +32768 shares → 65537 → wraps to 1).
- **Impact:**
  (a) one more `free()` → `assert!(*refs > 0)` → kernel panic → whole-VM death
  (violates "panic only on kernel bugs, never on bad user input");
  (b) `munmap` exactly one mapping → refs 1→0 → the frame lands on the free list
  while ~65534 PTEs and the FileData still reference it → the next `frame::alloc()`
  hands it out zeroed → silent cross-process corruption and read/write of whatever
  the kernel puts there; if it becomes a page-table page, the guest writes its own
  PTEs through the remaining mappings → full EL1 escape.
- **Fix direction:** widen the refcount (u32 or u32-checked `share`, failing with
  an errno at saturation), or make the VMA bounds strictly below 2^16 − 1, or
  `checked_add` in `share()` with ENOMEM/EAGAIN at the call sites.

## High

### H1. Snapshot files' network policy, forwards and limits are honored on CLI / Rust library / Python; only MCP sanitizes

**Status:** fixed in 0.0.12 by `f8f5db1` (Snapshot files no longer set their runs' network policy or limits).

- **Component:** host, snapshot restore path
- **Where:** `crates/grix/src/main.rs:326-369` (CLI: only `--timeout`, `--mount`,
  `--export` are applied; `-a net`, `--allow-host`, `--max-output`, `--max-export`,
  `--grace` are silently unused on that branch), `crates/grix/src/sandbox.rs:1139-1178`
  (`run_snapshot` builds the `NetPolicy` verbatim from `s.net` / `s.allow_hosts` /
  `s.forwards` and uses `s.max_output`, `s.max_export`, `s.grace_ms`),
  `crates/python/src/lib.rs:273-296` (`snapshot_run` — no restriction calls), versus
  `crates/grix/src/mcp.rs:540-542` — the only caller of `restrict_net`/`limits` in
  the codebase.
- **Confirmed.** The documented threat model (AGENTS.md: "a file may come from
  anyone, so MCP replaces the network policy and caps the limits") is enforced on
  exactly one of four front ends. A crafted snapshot gets:
  - `allow_hosts: ["host.grix.internal"]` or `["127.0.0.0/8"]` → the restored guest
    connects to services on the host's loopback (`net.rs:249-257` maps 10.0.2.2 →
    127.0.0.1) — SSRF into host-local services;
  - `forwards: ["0.0.0.0:8080", ...]` → the host binds listeners on all interfaces
    for the run's duration (`net.rs:555-566` binds the file's `SocketAddr`
    verbatim; privileged ports too if grix runs as root);
  - `max_output` / `max_export` = `usize::MAX` → unbounded host RAM buffering of
    guest output and export data;
  - `grace_ms` = `u64::MAX` → the run hangs instead of stopping; `timeout_ms`
    unclamped.
- **Note:** running someone else's snapshot is running their (guest) code
  regardless — but the sandbox's premise is that the *operator's* policy gates what
  guest code can reach on the host, and here the attacker's file sets that policy.
- **Fix direction:** the tools already exist — `Snapshot::restrict_net` and
  `Snapshot::limits` (`snapshot.rs:183-204`, with tests) — apply them in
  `run_snapshot` itself (net off unless the caller opts in), or wire the CLI flags
  and Python binding into the snapshot path.

## Medium

### M1. Boot image (full env/argv, including any secrets) written world-readable to a predictable /tmp path

**Status:** fixed in 0.0.12 by `f840b06` (A run's boot image and serial socket in a directory of its own).

- **Component:** host, VMM launcher
- **Where:** `crates/grix/src/vmm.rs:88-104` — `write_temp` uses `create_new(true)`
  but **no `.mode(0o600)`**; the path is `/tmp/grix-{pid}-{n}.img`, used for the boot
  image at `vmm.rs:222`. The image contains the program's complete environment and
  argv (`sandbox.rs:870`, `:914`).
- **Confirmed.** Every comparable artifact in this codebase is created 0600 — OCI
  blobs (`oci.rs:869`), treecache entries (`treecache.rs:157`), the credentials
  file (`auth.rs:275`), the snapshot file (`sandbox.rs:1015`) — this one was
  missed. Any local user can read `--env KEY=...` secrets for the run's duration.
  Same root cause, lower impact: the UART socket path is equally predictable
  (`vmm.rs:233-236`), so another local user can win the `accept` race (receiving
  the guest's early-boot/panic log) or pre-create the name (`create_new` → error →
  trivial local DoS of a run).
- **Fix direction:** `.mode(0o600)` on the image file; a private (mkdtemp-style)
  directory for the UART socket.

### M2. mmap *hint* below `MMAP_MIN_ADDR` is honored

**Status:** fixed in 0.0.12 by `4aa24c5` (Kernel: bounded frame counts, mmap's lower bound and offsets).

- **Component:** guest kernel, syscall gate
- **Where:** `kernel/src/syscall/mem.rs:125-147` — the MAP_FIXED branch checks
  `addr < MMAP_MIN_ADDR → EPERM` (`:133-135`), but the hint branch (`:140-144`)
  has no lower bound.
- **Confirmed.** Contradicts the kernel's own invariant (`mem.rs:16-18`: "Nothing
  is mapped below this … a NULL pointer, in the kernel too, always faults") and
  `/proc/sys/vm/mmap_min_addr`, which reports 65536 (`procfs.rs:89`). Not directly
  exploitable today (all user accesses go through `ensure()`), but it deletes the
  standard safety net for any future kernel bug that dereferences a user pointer
  at a small offset.
- **Fix direction:** one line — apply the `MMAP_MIN_ADDR` check to the hint branch
  too.

### M3. Unbounded host accumulation of `Channel::Log` and `Channel::Event` frames

**Status:** fixed in 0.0.12 by `e5788da` (Bounds on what the host keeps of a guest's output).

- **Component:** host, frame dispatch
- **Where:** `crates/grix/src/sandbox.rs:1096-1105` — `out.kernel_log.push_str(...)`
  and `out.events.push(e)` have no cap. stdout/stderr are capped by `max_output`
  (the `keep` closure, `:1081-1094`) and exports by `max_export`, but the
  kernel-log `String` and the events `Vec` (each event holding up to 4 heap
  `String`s) grow for the whole run.
- **Confirmed.** A compromised or buggy guest kernel emitting Log/Event frames at
  virtio speed grows the host process by GBs before the timeout fires (the
  16-slot bounded channel in `vmm.rs:371-384` bounds *in-flight* bytes, not
  accumulation). The events also flow uncapped into MCP `describe` answers. This
  is the one place invariant 6's "bound lengths" was missed.
- **Fix direction:** cap both, as `MAX_UART` (1 MiB) already caps the serial log
  elsewhere.

### M4. On-exit mount application: path-string TOCTOU against a racing local writer

**Status:** fixed in 0.0.12 by `bb602bc` (Host file system walks that never follow a swapped-in link).

- **Component:** host, mount change applier
- **Where:** `crates/grix/src/mount.rs:248-265` — `resolve()` walks each component
  with `fs::symlink_metadata` requiring a real directory, but the actual operations
  re-resolve the whole path string later and follow symlinks in intermediate
  components: `fs::rename` `:369`, `fs::create_dir` `:334`, `fs::remove_file`
  `:307`, `fs::remove_dir` `:302`, `fs::set_permissions` `:240`.
- **Confirmed (hardening-class fix).** The live-mount server does this correctly
  (`hostfs.rs:686-695`: `openat` + `O_DIRECTORY|O_NOFOLLOW` from a held root fd);
  the on-exit applier checks and then uses. An actor with write access to the
  mounted directory — e.g. another grix run holding a live writable mount on the
  same host directory, whose guest can `rmdir` a name and recreate it as a symlink
  through hostfs — races a directory component into a symlink between `resolve()`
  and the operation, landing a write or removal outside the mount.
- **Fix direction:** dirfd-relative `openat`/`renameat`/`unlinkat`/`mkdirat` from
  held fds, as hostfs.rs already does.

### M5. Registry can direct the user's credentials to any HTTPS realm it names

**Status:** fixed in 0.0.12 by `8402ca9` (Registry pulls keep to the build's network policy and logins to their site).

- **Component:** host, OCI registry auth
- **Where:** `crates/grix/src/oci.rs:783-812` — the `WWW-Authenticate` challenge's
  `realm` is only checked by `may_reach` (any `https` URL without userinfo; any
  loopback `http` URL when the registry itself is loopback), then the user's Basic
  credential for *this* registry — or a long-lived OAuth refresh token, as form
  data — is sent there.
- **Confirmed.** A malicious or compromised registry names
  `realm=https://evil.example/` and harvests the user's password / refresh token
  (password reuse across registries makes this worse than the content trust the
  registry already has). Mitigations already present: credentials only looked up
  on a 401, keyed to the reference's host, never printed, 0600 store; redirects do
  *not* forward Authorization (`oci.rs:752` — the classic registry-credential
  forwarding bug is correctly avoided there).
- **Fix direction:** pin the realm to the registry's own host (or parent domain),
  as newer clients do.

## Low (confirmed bugs)

### L1. Compressed layers in `docker-archive:`/`docker:` inputs skip digest verification entirely

**Status:** fixed in 0.0.12 by `04edcf0` (Layers count everything they keep; docker save layers checked).

`crates/grix/src/oci.rs:414-421`: the diff-id check is `&& !compressed`, so
gzipped/zstd layers from a `docker save` archive are applied with no hash check
(diff_ids hash *uncompressed* content; the code skips rather than
decompress-and-hash). Contradicts the module doc "Every blob is checked against
its digest" (`oci.rs:7-8`). The registry and OCI-layout paths verify correctly.
Fix: hash the decompressed stream against `diff_ids`.

### L2. Unbounded extraction of docker-save archives to /tmp

**Status:** fixed in 0.0.12 by `04edcf0` (Layers count everything they keep; docker save layers checked).

`crates/grix/src/oci.rs:386`: `std::io::copy(&mut entry, &mut File::create(&dest)?)`
with no per-entry or total size cap (unlike `apply_layer`'s `MAX_BYTES`
accounting). Path filtering is correct (normal components only, regular files
only, 0700 tempdir) — disk-fill DoS with a lying tar header.

### L3. `getdents64` on another process's `/proc/<pid>/fd` skips the permission check

**Status:** fixed in 0.0.12 by `4aa24c5` (Kernel: bounded frame counts, mmap's lower bound and offsets).

`kernel/src/syscall/file.rs:1142-1149`: enumerates any process's fd numbers from
`PROCS` without `procs::may_inspect`, which every other cross-process access uses
(`with_other`, `file.rs:104-111`; `pidfd_getfd`). Target names are not revealed
(lookup of `/proc/pid/fd/N` correctly fails), so it's an in-sandbox info leak —
but inconsistent with the design and with Linux (`PTRACE_MODE_READ`).

### L4. Export-collector length arithmetic can overflow

**Status:** fixed in 0.0.12 by `e5788da` (Bounds on what the host keeps of a guest's output).

`crates/grix/src/export.rs:313-314,339-341`: `path_len + data_len - received` with
guest-declared `data_len` up to `usize::MAX` — panics in debug builds (a guest
kills a dev/test host process), wraps in release where the outcome is benign (the
entry was already dropped by the failed `try_reserve_exact`). Fix: `checked_add`
and reject absurd `data_len` up front.

### L5. `d_reclen` truncated to `u16` in `getdents64`

**Status:** fixed in 0.0.12 by `4aa24c5` (Kernel: bounded frame counts, mmap's lower bound and offsets).

`kernel/src/syscall/file.rs:1169-1182`: `reclen` is computed as `usize` but
written `reclen as u16`; a live-mount name longer than ~65528 bytes (host-fed;
sandbox names are NAME_MAX-bounded) reports a wrapped record length to userspace
while the kernel's own buffer math uses the true value. Parser confusion only.

### L6. Pipe mutex held across `copy_out` (invariant-11-shaped deviation)

**Status:** fixed in 0.0.12 by `4aa24c5` (Kernel: bounded frame counts, mmap's lower bound and offsets).

`kernel/src/syscall/file.rs:780-813` (`pipe_read_rights`): `end.pipe.lock()` at
`:780` is held across `copy_out` of both slices (`:804-805`); data is drained only
after both copies succeed (that part is correct). The file paths all use bounce
buffers and drop locks first (`read_content`, `write_content_at`). Under the
single kernel lock this can't deadlock today, but a user buffer backed by a
live-mount page spins in `console::host_request` under the pipe lock
(pipe→FileData order; nothing inverts it yet). Fix: a bounce buffer for symmetry,
before the invariant erodes.

### L7. File-offset wraparound in file-backed VMA math

**Status:** fixed in 0.0.12 by `4aa24c5` (Kernel: bounded frame counts, mmap's lower bound and offsets).

`kernel/src/mm/aspace.rs:685-691` (`Backing::File`), `:670-674` (`Backing::Data`),
`:587`, `:638` (SharedFile idx): `offset + (page - vma.start)` can wrap u64
(`mmap` only requires `off` page-aligned — `mem.rs:50` — not `< file len`),
mapping the *first* page of the same file instead of past-EOF zeros. Same-file
confusion only (content readable via `pread` anyway) — but it feeds
`shared_frame` with attacker-wrapped indices. Fix: reject `off` beyond file
length / `checked_add` in `mmap`.

### L8. OCI layer entry *names* don't count against `MAX_BYTES`

**Status:** fixed in 0.0.12 by `04edcf0` (Layers count everything they keep; docker save layers checked).

`crates/grix/src/oci.rs:489-496`: only file data accumulates in `totals.bytes`;
GNU long names are unbounded individually (bounded overall by the
decompressed-stream `take(MAX_BYTES + 64 MiB)` at `:447`, so ~2× amplification of
intended memory, not unbounded). Fix: count name bytes or cap name length (cf.
`MAX_EXPORT_PATH`).

### L9. hostfs `Server` id/listing caps allow large host-side memory amplification

**Status:** fixed in 0.0.12 by `e5788da` (Bounds on what the host keeps of a guest's output).

`crates/grix/src/hostfs.rs:44,48`: `MAX_IDS = 1_000_000` (each id ≈ 2× a ≤255-byte
`String`) ≈ up to ~600 MB guest-driven host allocation before ENOMEM;
`MAX_FROZEN = 4_000_000` for lazy listings. Documented, errno-failing budgets
(invariant 10) — but ~10× looser than the kernel-side equivalents. Fix: lower the
caps or charge ids against a byte budget.

### L10. Live-mount root opened without `O_NOFOLLOW` / identity re-check

**Status:** fixed in 0.0.12 by `bb602bc` (Host file system walks that never follow a swapped-in link).

`crates/grix/src/hostfs.rs:262-263`: the mount root is opened
`openat(AT_FDCWD, path, O_RDONLY|O_DIRECTORY)` with no `O_NOFOLLOW` and no
post-open identity check — a symlink swapped into a parent between
`canonicalize()` (`sandbox.rs:546`) and run redirects the mount to another
directory. Everything *below* the root is walked with `O_NOFOLLOW` (verified).
Small window, needs local write access to a parent. Fix: the same component walk
for the root, or compare `st_dev`/`st_ino` after open.

### L11. VMM parses hostile snapshot state before confining itself

**Status:** fixed in 0.0.12 by `f810523` (grix-vmm: confined before a snapshot's GIC state is restored).

`crates/vmm/src/vm.rs:349-352` (GIC/CPU restore from the file, feeding
`hv_gic_set_state`) runs before `hvf::confine()` at `:383`. The comment
("Confined before any guest code runs") is true for code, but Apple's GIC state
parser runs on attacker-controlled bytes in the unconfined process. All
Rust-side parsing of the same file is bounds-checked (verified). Residual risk =
an Apple parser bug reached outside the sandbox. Fix if the framework allows:
confine first, restore state after.

### L12. `Event::decode` accepts trailing bytes

**Status:** fixed in 0.0.12 by `e5788da` (Bounds on what the host keeps of a guest's output).

`crates/abi/src/wire.rs:399-412`: no `r.remaining()` check, unlike
`ExportMsg::decode` (`:331-333`), hostfs `Request`/`Reply`, and
`link::ToHost::decode`. No memory-safety impact (all strings are length-prefixed
and `take`-bounded) — inconsistent with the "reject garbage" convention. Fix: add
`r.done()`.

## Info / trust model (not bugs; keep the compensating controls)

- **I1.** *(Unchanged, by design.)* The image kernel is "authenticated" only by a forgeable marker
  (`container.rs:109-115`, `grix_abi::kernel_abi`): an attacker-crafted `.grix`
  boots *their* kernel. Deliberate design ("an image brings its own kernel").
  Compensating controls verified sound: `net` is never auto-granted from an image
  (`sandbox.rs:694-699`, `main.rs:509-513`), the proxy re-checks policy against a
  lying kernel (`net.rs:497-508`, `:734-738`), and all host-side decoding is
  bounds-checked. Keep the no-setuid invariant and the never-auto-grant-`net`
  rule.
- **I2.** *(Unchanged: a per-machine secret doesn't stop the same user, who can read it too.)* treecache entries are forgeable by a same-uid attacker (unkeyed
  self-hash, `treecache.rs:91-116`, `:166-170`): anyone who can write
  `~/.cache/grix/trees/<key>.tar` substitutes contents for a known key (e.g.
  `applied-layers-v1`, keyed by a public manifest digest). Same-user attackers
  have easier attacks; consider keying the stored hash with a per-machine secret.
- **I3.** *(Unchanged: correct per invariant 5.)* `mknodat` is gated in `kernel/src/syscall/table.rs:60` but has no
  handler → correct ENOSYS + `Unimplemented` event per invariant 5. Functional
  gap, not a security hole.
- **I4.** *(Fixed in 0.0.12 by `04edcf0`: setuid and setgid bits are dropped.)* Layer entry modes preserve setuid/setgid/sticky (`oci.rs:484`) — inert
  today because the kernel never honours setuid bits and every host-side exit
  strips them (`export.rs:165`, `hostfs.rs:504`, `:562`). Consider masking 0o7000
  at build time so this doesn't depend on those invariants holding forever.

---

## Verified clean (checked line-by-line, no findings)

Recorded so later work doesn't have to re-derive what was already ruled out, at
the commit above:

- `wire.rs` `FrameDecoder` (resynchronizes on garbage, `len ≤ MAX_FRAME` enforced
  inside the channel filter, no OOB slices); `codec.rs` `Reader` (all reads
  `take()`-bounded); the guest-side `InputDecoder` (fixed buffer).
- `abi/hostfs.rs` message caps (`MAX_MESSAGE` 256 KiB enforced by the `Assembler`;
  the server re-enforces `IO_MAX`/`LIST_MAX`); `crates/grix/src/hostfs.rs` request
  handling (`cname` rejects `""`/`.`/`..`/`/`/NUL/>255; every open
  `O_NOFOLLOW|O_NONBLOCK`; `AT_SYMLINK_NOFOLLOW` stats; cross-mount rename →
  EXDEV; `mode & 0o1777`; `Server::restore` validates names/ids/parents/caps and
  requires `r.done()`).
- `net.rs` proxy: policy checked against the literal connected IP (no
  resolve-then-connect gap); special addresses (loopback, link-local/169.254
  metadata, multicast, broadcast) require an explicit IP rule with minimum prefix
  — DNS rebinding to 127.0.0.1/169.254.169.254 blocked; `::ffff:` canonicalized;
  `host.grix.internal` needs an explicit rule; UDP verdicts asked once per
  destination; replies only from allowed peers; every counter bounded;
  per-connection credit flow control with drop on window violation; the host
  never trusts guest flow control.
- `dns.rs`: queries 12..4096 bytes, one question, labels ≤ 63, name ≤ 253,
  charset-checked, compression pointers rejected, answers built from scratch.
- `export.rs`/`mount.rs` static validation: `valid_path` rejects `""`/`.`/`..`/
  empty components/NUL; parent-before-child, duplicate and
  writes-inside-removals checks before anything is written; files via `create_new`
  0600 + chmod `&0o755`; symlinks created last; tmp-tree + atomic rename; host-side
  conflicts skipped.
- `oci.rs` registry path: TLS on (rustls + webpki-roots), plain HTTP only for
  loopback registries (refused without `local`); redirects: max 5, **fresh request
  without Authorization** (no credential forwarding on redirects); manifests
  fetched by digest and hash-checked twice; blobs verified on download *and* on
  cache hits (`verify_file`); layer application is in-memory (a `BTreeMap`) — no
  extraction root to escape: `..` bails, absolute/`/dev`/`/proc`/`/sys` rejected
  by `guest_path`, symlinks stored never followed, hardlinks are map lookups,
  devices/FIFOs skipped; decompressed stream capped, per-allocation caps, zstd
  window capped.
- Grixfile builds: `in_context` canonicalizes and rejects real paths outside the
  context (symlink escape blocked); build steps run *inside a sandbox* as the
  image's user — no host shell, no interpolation into host commands; `step_key`
  hashes tree + argv + env + user + cwd + kernel digest + net policy (no
  stale-result collision short of a SHA-256 break).
- `.grix` parsing: decompressed cap, `grix-image.json` ≤ 1 MiB + ABI check,
  kernel ≤ 256 MiB + ABI check, `guest_path` on every entry; `ImageConfig`
  contains no host paths — a crafted image cannot make the host mount or export
  host directories or grant itself `net`.
- `crates/vmm`: `mem.rs` `at()` (`checked_sub` + `len ≤ size − off` — no addr+len
  overflow, every device access gated); `console.rs` (queue size power-of-two ≤ 64,
  descriptor chains bounded with loop detection, TX `contains(addr,len)`-checked
  and copied in ≤ 64 KiB pieces regardless of claimed lengths, RX only into
  `DESC_F_WRITE` descriptors); KVM MMIO len clamped ≤ 8 both ways; PSCI/KICK
  targets bounds-checked; the seccomp filter hand-verified (strict allowlist, no
  open/socket/exec/clone, ioctls whitelisted to `KVM_RUN`/`KVM_IRQ_LINE`); HVF
  `confine()` is a deny-everything seatbelt profile with zero allowances.
- VMM snapshot reader (`vmm/src/snapshot.rs`): magic/version, `ram_size ≤
  MAX_RAM`, `state_len ≤ 16 MiB`, alignment, `ram_offset + ram_size ≤ file_len`,
  vCPU count/caller checks, fresh entropy per run.
- The MCP snapshot path (`mcp.rs:536-570`): network policy fully *replaced* (not
  merged), forwards cleared, limits clamped to min(file, server), mounts validated
  against roots, the VMM resolved locally (never from the file), on-exit mounts
  refused.
- Kernel syscall gates: every table entry gated `Core`/`Cap`/`Privileged`;
  `openat` gates existing-file writes, `O_TRUNC`, `O_CREAT`/`O_TMPFILE`; clone
  rejects namespaces/`CLONE_VM` misuse; mmap blocks shared-writable on live mounts
  and `mprotect` write-upgrades on read-only-shared; `ioctl` whitelisted (no
  `TIOCSTI`); `fcntl F_SETFL` masked; `rt_sigaction` masks sanitized;
  `membarrier` private-unregistered → EPERM.
- `signal::read_frame` (invariant 12): rejects pstate naming another EL / AArch32
  / masked IRQs, bounds every record, keeps only NZCV — stronger than Linux.
- `uaccess`/`ensure`: `checked_add`, `USER_TOP` cap, per-page VMA check +
  pre-fault (including write-faulting CoW/shared pages); `read_cstr` re-ensures
  per page with `ENAMETOOLONG`; fork's one cross-aspace write activates the
  child's table and restores the parent's.
- Lock discipline (invariant 11): no `FileData` guard is held across
  `copy_in`/`copy_out` anywhere (the `Pipe` lock in L6 is the one deviation);
  `fs::lock()` re-entrancy callers all drop the guard before re-entering.
- Budgets (invariant 10): every guest-driven allocation traced has a failing
  errno cap (pipes, AF_UNIX queues, SCM_RIGHTS, netlink, TCP/UDP, RT signals,
  POSIX timers, inotify, ptys, /proc files, argv/env, file locks, fds, VMAs,
  processes/threads, ELF phnum/interp/`#!`-depth, getrandom, META_LIMIT).
- ELF loader: `vend ≤ USER_TOP`, `vstart ≥ PAGE_SIZE`, `filesz ≤ memsz`,
  `offset + filesz ≤ len`, congruence check, ET_DYN bias 64 KiB-aligned; no
  high-half aliasing.
- SMP/snapshot: `SNAPSHOT_CALL` only issued from `sched::idle` under the kernel
  lock with `!smp::others_running()`; an EL0 `hvc` is UNDEFINED → SIGILL, so the
  guest cannot spoof SMCCC calls or force a snapshot of inconsistent state.

## Suggested fix order (as found; all done in 0.0.12)

1. **C1** — checked/saturating refcount (kernel memory integrity).
2. **H1** — call `restrict_net`/`limits` in `run_snapshot` (the code already
   exists; three front ends need wiring).
3. **M1** — `.mode(0o600)` + private socket dir (one-liner plus).
4. **M2** — `MMAP_MIN_ADDR` check in the hint branch (one line).
5. Then the mediums and lows in the order listed.
