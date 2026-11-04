# Security review — 2026-11-04

Point-in-time review of `grix` at commit `b531be5` ("A choice of network
stacks: none, native or vm (0.0.71)").

This pass complements the two catalogues already in
[SECURITY-AUDIT.md](SECURITY-AUDIT.md). It deliberately targets surface that
landed **after** those audits (the last one covers 0.0.15), and re-checks the
invariants their fixes rely on. Findings C1, H1, M1–M5, L1–L12 and R1–R9 are
not repeated; they are assumed fixed.

## Method and limitations

- Static, line-by-line review of the current tree, plus callers, with the
  prior audits' "verified clean" list used to skip re-derivation.
- Threat model as documented in `AGENTS.md`: the guest *kernel and program*
  are hostile (an image brings its own kernel); the host's operator policy is
  the boundary. For the VMM and host decoders, all guest bytes are hostile.
  For snapshots/images, the file may come from anyone.
- No live proof-of-concept was run for this pass. Items marked "static" are
  confirmed by reading the code path; they are cheap to turn into fixtures.
- Severity here means: **Critical/High** = host or EL1 compromise; **Medium** =
  sandbox-level containment gap or a whole-run DoS (panic/hang/OOM) reachable
  with normal syscalls; **Low/hardening** = in-sandbox DoS or defense-in-depth.

## Bottom line

No direct guest→host memory escape was found on the normal run path. The VMM
(`mem.at`, console/descriptor handling, confinement ordering), `uaccess` /
`ensure`, the ABI decoders, and the host filesystem walks still look sound.

What remains is a set of **guest-triggerable kernel panics/hangs**, a few
**policy/containment gaps**, and **host-side DoS/TOCTOU** issues around
snapshots, builds and MCP. The kernel availability bugs are small and worth
fixing first.

## Index

| # | Severity | Area | Issue | Where |
|---|----------|------|-------|-------|
| 1 | Medium | kernel/ELF+mm | Zero-length `PT_LOAD` VMA makes `madvise` loop forever under the kernel lock | `kernel/src/elf.rs:176`, `kernel/src/syscall/mem.rs:285` |
| 2 | Medium | kernel/procfs | `/proc/self/maps` allocates unbounded heap before any charge | `kernel/src/procfs.rs:523`, `kernel/src/syscall/file.rs:590` |
| 3 | Medium | kernel/x86_64 | TLB-flush IPI return path skips `sanitize` → `#SS` at CPL0 | `kernel/src/arch/x86_64/mod.rs:468` |
| 4 | Medium | kernel/procfs | `/proc/<pid>/maps` and `exe` bypass `may_inspect` | `kernel/src/procfs.rs:157`, `kernel/src/syscall/file.rs:579` |
| 5 | Medium | host/MCP | `build_image` output path is check-then-use | `crates/grix/src/mcp.rs:633`, `crates/grix/src/container.rs:262` |
| 6 | Medium | host/snapshot | Snapshot settings have a byte cap but no element cap | `crates/grix/src/snapshot.rs:43` |
| 7 | Medium | host/net | Wildcard rules open `host.grix.internal` | `crates/grix/src/net.rs:320`, `:554` |
| 8 | Medium | kernel/net (vm) | Forwarded UDP ignores the socket's bind address | `kernel/src/inet.rs:939` |
| 9 | Low | kernel/live mounts | Read-only pin upgraded for writing writes the replacement file | `kernel/src/fs.rs:277`, `crates/grix/src/hostfs.rs:809` |
| 10 | Low | host/gateway | First datagram per destination bypasses `HELD_BYTES` | `crates/grix/src/gateway.rs:356` |
| 11 | Low | kernel/x86_64 | Secondary CPU's first return to user is unsanitized; `clone` stack unbounded | `kernel/src/smp.rs:673`, `kernel/src/syscall/thread.rs:152` |
| 12 | Low | host/snapshot | A snapshot file chooses `tty` (and `vm_stack`) for the run | `crates/grix/src/snapshot.rs:182`, `crates/grix/src/main.rs:447` |
| 13 | Low | host/net | TCP forwards are not gated by `net` | `crates/grix/src/net.rs:947`, `:1493` |
| 14 | Low | host/net | A `0.0.0.0/8` allow-rule reaches loopback | `crates/grix/src/net.rs:531` |
| 15 | Low | kernel/AF_UNIX | Zero-length I/O loses/drops in-flight SCM_RIGHTS | `kernel/src/syscall/file.rs:1221`, `kernel/src/syscall/unix.rs:603` |
| 16 | Low | kernel/AF_UNIX | `accept` leaks the new fd if the sockaddr copy faults | `kernel/src/syscall/unix.rs:273` |
| 17 | Low | kernel/file | `getdents64` `d_off` arithmetic overflows at `i64::MAX` | `kernel/src/syscall/file.rs:1777` |
| 18 | Low | kernel/mm | `mremap` of a partial page length hits `Vma::slice`'s debug assert | `kernel/src/mm/aspace.rs:910`, `:199` |
| 19 | Low | kernel/ELF+brk | `MMAP_MIN_ADDR` is not enforced for ELF segments or `brk` | `kernel/src/elf.rs:181`, `kernel/src/syscall/mem.rs:23` |
| 20 | Low | kernel/mm | `AddressSpace::map` skips the mapping budget; `recount` ignores charge failure | `kernel/src/mm/aspace.rs:702`, `:447` |
| 21 | Low | host/build | Build inputs can exhaust host memory/inodes/time before limits | `crates/grix/src/oci.rs:415`, `:649`, `crates/grix/src/mcp.rs:671` |
| 22 | Low | kernel/NUMA | `get_mempolicy` `next_multiple_of` overflow on `maxnode = u64::MAX` | `kernel/src/syscall/mem.rs:482` |

## Medium

### 1. Zero-length `PT_LOAD` VMA makes `madvise` loop forever

**Where:** `kernel/src/elf.rs:176-184`, `kernel/src/mm/aspace.rs:702`,
`kernel/src/syscall/mem.rs:285-352`.

The loader accepts a `PT_LOAD` with `filesz == memsz == 0` (`0 > 0` is false)
and maps `Vma::new(start, vend, …)` with `vend == start`. `AddressSpace::map`
does not reject an empty range. `madvise`'s walk then does:

```rust
let Some(v) = p.aspace.first_in(at, end) else { … };
let (start, stop) = (v.start.max(at), v.end.min(end)); // both == at
…
at = stop;                                            // no progress
```

`first_in` returns the zero-length VMA through `vmas.range(start..end)`, even
though `find` skips it, so the loop never advances while holding the kernel
lock with IRQs masked.

**Attack (guest-only, static):** exec a crafted ELF that has a real executable
segment plus a page-aligned `PT_LOAD { filesz: 0, memsz: 0, vaddr: 0x10000 }`,
then call `madvise(0x10000, 4096, MADV_DONTNEED)` (any advice). Every CPU
blocks behind the kernel lock; the host can only kill the run.

**Impact:** whole-sandbox hang (debug builds also panic in `Vma::slice` via
`munmap`). Violates "panic/hang only on kernel bugs, never on bad user input".

**Fix:** require `vend > start` in the ELF loader / `AddressSpace::map`, or
make `madvise` require `stop > at`.

### 2. `/proc/self/maps` allocates unbounded heap before charging

**Where:** `kernel/src/procfs.rs:523-530`, `kernel/src/syscall/file.rs:590`.

`maps()` writes into a plain `String` with infallible growth; the
`Charge::new(data.capacity())` happens only after `generate()` has returned
the whole buffer. `smaps()` already does this correctly with `try_reserve`
and a `Charge`.

**Attack (guest-only, static):** create a directory tree with a long path,
map that file at many distinct addresses (`MAX_VMAS` allows 32768), then read
`/proc/self/maps`. Each VMA line repeats the full path; tens of MB are
allocated before any limit is checked, and `talc`'s `ErrOnOom` panics the
kernel.

**Impact:** kernel heap exhaustion → panic → whole-sandbox death. Contradicts
invariant 10 and the "generated /proc files take a `kmem::Charge`" rule.

**Fix:** make `maps()` use `try_reserve`/a `Charge`, as `smaps()` does, and/or
cap the generated size.

### 3. x86_64 TLB-flush IPI return path skips `sanitize`

**Where:** `kernel/src/arch/x86_64/mod.rs:468-471`, `:561-568`.

```rust
if tf.vector == irq::FLUSH_INTID as u64 {
    flush_ipi();
    return;                 // no sanitize(tf)
}
```

`flush()` targets CPUs with that root that are **not** in the kernel — i.e.
CPUs running user code. `trap_entry` captures the user `rsp`; returning
through `iretq` with a non-canonical one raises `#SS` at CPL0 and panics.
This is exactly the R1 class, on a path the R1 fix did not cover. `arm64` is
structurally safe here because `eret` does not reload `sp` from the frame.

**Attack (guest-only, static):** with `cpus >= 2`, thread A sets
`rsp = 0x8000_0000_0000_0000` and spins without touching the stack; thread B
in the same address space does `munmap`/`mprotect`/`mmap` so a flush IPI lands
on A.

**Fix:** `sanitize(tf)` before returning when `tf.cs & 3 == 3`.

### 4. `/proc/<pid>/maps` and `exe` bypass `may_inspect`

**Where:** `kernel/src/procfs.rs:150-159`, `kernel/src/syscall/file.rs:579`,
`kernel/src/fs.rs:1506-1524`.

`inspected()` covers only `Environ`, `Auxv`, `Smaps` and `SmapsRollup`.
`Maps` is `0444` in a `0555` directory, so any uid can read another process's
address-space layout and mapped file paths. `exe` is a `0777` symlink and
`readlinkat` never consults `may_inspect`, so its path leaks too (Linux gates
`/proc/pid/exe` with `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`).

**Attack (static):** fork, `setuid(1000)`, then `open("/proc/1/maps")` and
`readlink("/proc/1/exe")`. No `may_inspect` check runs.

**Impact:** cross-user information disclosure: ASLR layout, mapped paths,
executable path. (Does not read memory contents; `mem` is correctly gated.)

**Fix:** add `Maps` to `inspected()`, and gate `exe` in `readlinkat`.

### 5. MCP `build_image` output path is check-then-use

**Where:** `crates/grix/src/mcp.rs:633-639`, `:859-880`;
`crates/grix/src/container.rs:262-269`.

`output_path` canonicalizes the parent and checks it against the MCP roots
once. `build_image` then runs a long build and calls `Image::write_to`, which
re-resolves the path by name (`File::create(tmp)`, `fs::rename(tmp, path)`).
A concurrent run with a writable mount can rename the output directory away
and replace it with a symlink during the build, landing the image outside the
roots.

**Impact:** host file creation/clobber outside the MCP roots. `snapshot_real`
already does this correctly with `at::open_parent` + dirfd + `renameat`; the
image writer should use the same pattern. The same check-then-use affects
read paths (`Image::open`, `Snapshot::open`, `Grixfile::build_file`), though
reads are less severe.

### 6. Snapshot settings have a byte cap but no element cap

**Where:** `crates/grix/src/snapshot.rs:43-80`, `:156-202`;
`crates/grix/src/export.rs:358-366`.

`MAX_SETTINGS` caps the JSON at 256 MiB, but `allow_hosts`, `forwards`,
`udp_forwards`, `exports` and `live` are unbounded `Vec`s deserialized before
any sanitization. `exports` survives `Snapshot::open` and is passed to
`Collector::new`, which allocates one `Export` (plus a `Vec`) per entry.

**Attack (static):** put millions of empty strings in `"exports"` within the
256 MiB cap. A crafted file can drive multi-GB host allocation; in MCP a guest
with a writable live mount can write such a file, then have `run` point at it.

**Impact:** host OOM, killing the MCP/CLI/Python process and other tasks.
Contradicts invariant 6 ("a file may come from anyone") and the host-side
budget analogue of invariant 10.

**Fix:** small `MAX_SETTINGS`, plus explicit count/length caps for every
vector field before/at deserialization.

### 7. Wildcard host rules open `host.grix.internal`

**Where:** `crates/grix/src/net.rs:320-329`, `:554-570`.

`matches_name` implements a wildcard as `name.ends_with(".<base>")`, so
`*.internal` (or `*.grix.internal`) matches `host.grix.internal`. `check`
treats that as an explicit rule and connects to the host's loopback, bypassing
the "host's own services: only a rule naming exactly that" intent.

**Attack (static):** an operator allows `*.internal` for private services; the
guest connects to `host.grix.internal:<allowed port>` and reaches host
loopback (TCP, and via `udp_allow` UDP/ICMP).

**Fix:** when checking `HOST_NAME`, accept only an exact name or a `/32` or
`/128` address rule, never a wildcard.

### 8. Forwarded UDP on the `vm` stack ignores the socket's bind address

**Where:** `kernel/src/inet.rs:939-946`, `:1069-1073`, `:876-881`;
`kernel/src/netstack.rs:220`.

`datagram_in` looks up the destination by port only and pushes without
checking the socket's local address, family, or the target address. The
`native` paths require `local` to be unspecified or the guest address (and
`deliver_local` also checks loopback). So with `--network vm`, a forwarded UDP
port delivers to a socket bound only to `127.0.0.1` or `fd00::15`, and v4
datagrams can reach v6-bound sockets and vice versa.

**Impact:** loopback-only UDP services become reachable from the network when
an operator forwards that port, contrary to the documented forwarding rule and
to `native`'s behavior.

**Fix:** apply the same binding/address check in `datagram_in`.

## Low / hardening

### 9. Read-only pin upgraded for writing writes the replacement file

`FileData::pin` (`kernel/src/fs.rs:277-288`) sets the guest-side write bit
unconditionally, but the host `Pin` is one-way. If the name now holds another
file, the host keeps the old read-only fd (`crates/grix/src/hostfs.rs:809-817`);
a later write then skips the non-writable pin and re-opens **by name**
(`crates/grix/src/hostfs.rs:944-959`). A write/truncate lands in a file the
descriptor never opened, defeating the 0.0.64 "a live mount's file stays what
the program opened" guarantee and acting as a stale-attribute mode-check
bypass. Fix: report which file was actually pinned, and never fall through to
a by-name open when a pin exists but is not writable.

### 10. Gateway `HELD_BYTES` bypass for the first datagram per destination

`crates/grix/src/gateway.rs:356-369` checks `HELD_BYTES` only when appending
to an already-asked destination; the first datagram for each new destination
is always stored. With `SOCKETS = 1024`, `DESTINATIONS = 256`, this is up to
hundreds of MB if verdicts are dropped because the guest stops reading.
Fix: check the cap in the `None` arm too.

### 11. Secondary CPU's first return to user is unsanitized

`secondary_main` (`kernel/src/smp.rs:673-680`) calls `arch::return_to_frame`
after `finish` loads a picked thread's registers, without `sanitize`.
`do_clone` sets `regs.set_sp(args.stack)` with no bound
(`kernel/src/syscall/thread.rs:152-155`). A thread created with a
non-canonical stack can be picked first by an idle AP on x86_64 → `#SS` at
CPL0. Fix: sanitize on this path too, and bound `clone`'s stack.

### 12. A snapshot file chooses `tty` (and `vm_stack`) for the run

`Snapshot::open` resets net/allow_hosts/forwards (`snapshot.rs:182-185`) but
not `tty` or `vm_stack`. `main.rs:447-451` uses `snap.tty()` to decide whether
to read the operator's terminal, so an untrusted snapshot marked
`"tty": true` makes `grix run --snapshot FILE` feed the terminal to
attacker-controlled guest code even without `-t`. Reset both like net.

### 13. TCP forwards are not gated by `net`

`Proxy::start` binds `policy.forwards` regardless of `policy.enabled`
(`net.rs:947-958`), and `accept_loop` (`net.rs:1493`) does not check
`policy.enabled`; the UDP loops do. With `net` withheld but a forward
configured (e.g. `Snapshot::forward` without `allow_net`), a hostile image
kernel can use the forwarded connection. Fix: require `enabled` for both TCP
and UDP forwarding, or refuse to start with forwards when `net` is off.

### 14. `0.0.0.0/8` allow-rule reaches loopback

`special()` treats `0.0.0.0/8` as "this network" with minimum prefix 8
(`net.rs:531`), and `check` does not special-case `0.0.0.0`. On Linux
`connect(0.0.0.0)` goes to `127.0.0.1` (verified locally), so an operator rule
`0.0.0.0/8` reaches host loopback. Reject/normalize `0.0.0.0` in `check`.

### 15. Zero-length I/O loses in-flight SCM_RIGHTS

`pipe_read_full` (`kernel/src/syscall/file.rs:1221-1259`) sets
`take_rights = true` even when `n == 0`, then pops the rights batch; the
temporary `Vec` used by plain `read` is dropped, closing those descriptors.
`send_stream` (`kernel/src/syscall/unix.rs:603-609`) only attaches rights when
`n > 0`, silently dropping them for a zero-length send. Linux returns 0
immediately for `count == 0` without consuming SCM_RIGHTS. Fix: skip rights
handling when `n == 0`.

### 16. `accept` leaks the new fd on sockaddr EFAULT

`kernel/src/syscall/unix.rs:273-275` allocates the fd before `write_name` can
return EFAULT; the syscall then returns an error without revealing the fd.
Linux closes it on the copy-out failure. Fix: allocate/install after the copy,
or close on error.

### 17. `getdents64` `d_off` overflow

`kernel/src/syscall/file.rs:1777` computes `pos as i64 + 1`; directory
`lseek` accepts any non-negative `i64` (`:1563-1575`), so
`lseek(dirfd, i64::MAX, SEEK_SET)` then `getdents64` overflows (debug panic,
release wraps to a negative `d_off`). Use checked arithmetic.

### 18. `mremap` partial-page length hits a debug assert

`AddressSpace::remap` (`kernel/src/mm/aspace.rs:910-912`) calls
`unmap(old + new_len, old_end)` even when `new_len == old_len`; if the VMA is
larger than `old_len`, `carve` pushes `v.slice(end, end)`, tripping
`Vma::slice`'s `debug_assert` (`:199`). Debug builds panic; release silently
splits the VMA. Skip the unmap when nothing is removed.

### 19. `MMAP_MIN_ADDR` is not enforced for ELF segments or `brk`

The ELF loader checks only `vstart < PAGE_SIZE` (`kernel/src/elf.rs:181`), and
`brk` (`kernel/src/syscall/mem.rs:23-45`) has no lower bound, so a crafted
ELF with a segment at `0x1000` plus `brk(0x10000)` creates a writable region
below `MMAP_MIN_ADDR` — the same gap M2 fixed for `mmap`. Apply the check in
both places.

### 20. `AddressSpace::map` skips the mapping budget

`map` (`kernel/src/mm/aspace.rs:702-708`) never calls `total_room`/`has_room`;
the ELF loader and `process.rs` use it directly. `recount` (`:447-453`)
silently ignores a failed `Charge::resize`. A crafted many-segment ELF can
therefore create uncharged VMAs, and repeated execs can overshoot
`MAX_VMAS_TOTAL`. Make `map` check the budget and make `recount`'s failure an
error.

### 21. Build inputs can exhaust host memory/inodes/time before limits

- `docker save` extraction (`crates/grix/src/oci.rs:415-435`) charges only
  regular-file bytes, so millions of zero-length entries exhaust `/tmp`
  inodes (residual of L2).
- A local `oci:` layout's blob is drained uncapped by `Hashing::finish`
  (`oci.rs:649-652`) after `apply_layer`'s decompressed cap; a sparse huge
  blob is read in full.
- MCP import/export arrays are processed before `MAX_ENTRIES`/byte limits
  (`mcp.rs:671-679`), and export dedupe is O(n²) (`sandbox.rs:766`).
- `.grix` parsing can hold a 3 GiB `Vec` (`container.rs:115-119`).

Fix: cap entry counts, blob sizes, and MCP array lengths before doing work.

### 22. `get_mempolicy` `next_multiple_of` overflow

`kernel/src/syscall/mem.rs:482` computes `(maxnode - 1).next_multiple_of(64)`
with user-controlled `maxnode`; `u64::MAX` makes it panic in debug and wrap to
0 in release. Use `checked_next_multiple_of` and reject absurd values.

## Ruled out (so it isn't re-derived)

- `FdTable::index`'s `fd as i32` truncation matches Linux's `unsigned int` fd
  ABI (`0x1_0000_0003` is fd 3 on Linux too). Not a new issue.
- `read_nodes` correctly guards `used == 64`; no shift overflow.
- `smaps` uses `try_reserve`/`Charge`; `wire`/`stats` decoders bound every
  length and reject trailing bytes; `codec::Reader` is `take()`-bounded.
- VMM `mem.at` (`checked_sub`, `len <= size - off`), console queue/descriptor
  bounds, KVM/HVF seccomp and confinement ordering, CPUID masking.
- `uaccess`/`ensure` discipline and "checked is what's used" in the reviewed
  syscall paths; signal-frame validation on both architectures.
- seccomp/Landlock ordering, AF_UNIX walks, O_TMPFILE `publish`, hard-link and
  `RENAME_EXCHANGE` mount checks.
- Export/mount application is dirfd-relative and no longer follows swapped-in
  links; registry auth keeps credentials to their site and does not forward
  them on redirects.
- Snapshot net-policy reset (H1) still holds; MCP additionally clears mounts
  and clamps limits.
- `net` cannot be granted by an image or snapshot; the proxy re-checks policy
  against the literal IP for Connect/UdpAllow/UdpReply/lookup.

## Suggested fix order

1. **#1, #2, #3** — small kernel changes that remove whole-VM panics/hangs.
2. **#4, #7, #8** — cheap containment fixes (procfs inspection, host special
   names, UDP binding).
3. **#5, #6, #12** — snapshot/MCP validation and dirfd-relative writes.
4. **#9, #10, #11** — live-mount pin correctness, gateway cap, x86 return
   paths.
5. The remaining Low items as cleanup, with regression fixtures where cheap.

## Suggested regression tests

- A fixture that execs an ELF with a zero-length `PT_LOAD` and calls
  `madvise` (watchdog should not fire; run must stay responsive).
- A fixture that maps a long path many times then reads `/proc/self/maps`
  (must return ENOMEM, not panic).
- x86_64 escape-battery additions: bad `rsp` plus a TLB flush IPI; clone with
  a non-canonical stack on a multi-CPU run.
- Net policy unit tests: `*.internal` must not match `host.grix.internal`;
  `0.0.0.0/8` must not reach loopback.
- `--network vm` test that a forwarded UDP port skips a loopback-only socket,
  mirroring `forwarded_ports_skip_loopback_only_listeners`.
- Snapshot test: a file with huge `exports`/`live` arrays is rejected before
  allocation; `"tty": true` does not turn on stdin without `-t`.
