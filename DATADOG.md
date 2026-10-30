# The Datadog Agent in grix

Does Datadog's official Agent image run in grix, and does Datadog get its
data? As of 2026-10-29, with the fixes on this branch: **yes**. The
image's own entrypoint (s6-overlay) starts the core Agent, its embedded
Python checks, DogStatsD, the trace-agent (APM) and live process
collection. They report to Datadog with a real API key, through an
allow-list that reaches only Datadog's intake. The pieces that need
eBPF or Linux capabilities (system-probe's network, USM and security
modules, and the security-agent) disable themselves, because grix denies
`bpf` and `capset` by design.

Tested with `datadog/agent:7` (7.85.0, linux/arm64, Ubuntu 24.04 base,
Go 1.26) on grix-vmm (Hypervisor.framework, arm64 macOS). The kernel
fixes are also tested on the x86_64 kernel.

## Running it

```sh
mkdir dd && cd dd
cat > Grixfile <<'TOML'
from = "datadog/agent:7"
capabilities = ["threads", "process", "fs_write"]
memory_mb = 2048
TOML
grix build -o agent.grix

set -a; . ./.env; set +a          # DATADOG_API_KEY=...; never echo it
grix run --image agent.grix --mem 2048 --cpus 4 --timeout 3600 -a net \
  --allow-host '*.datadoghq.com' --allow-host '*.datadog.pool.ntp.org:123' \
  -e DD_API_KEY="$DATADOG_API_KEY" -e DD_SITE=datadoghq.com -e DD_HOSTNAME=grix-test \
  -e DD_APM_ENABLED=true -e DD_PROCESS_CONFIG_PROCESS_COLLECTION_ENABLED=true \
  -i ./conf.d:/conf.d               # optional: check configs, as with Docker's /conf.d
```

- `*.datadoghq.com` covers the metrics intake (`7-85-0-app.agent.…`),
  `process.…`, `trace.agent.…` and remote config (`config.…:8042`). The
  NTP check needs UDP 123 to `*.datadog.pool.ntp.org`.
- `DD_HOSTNAME` is needed: the sandbox is named `grix`, and there's no
  cloud metadata to name it otherwise.
- The default command is `/bin/entrypoint.sh` (s6-overlay). `-- agent run`
  runs just the core Agent. Without s6's init scripts there's no
  `/etc/datadog-agent/datadog.yaml`, so the Agent puts its `auth_token`
  in `/`, and the trace-agent and system-probe can't find it. Create an
  empty `datadog.yaml` first.

## What Datadog receives

The Agent's own status (`agent status`, `agent health`, `agent check`)
after a minute or two:

- `API Key valid` for the key on datadoghq.com, and
  `Successfully posted payload to "https://7-85-0-app.agent.datadoghq.com./intake/" (202 Accepted)`.
- Forwarder: 28 successful transactions in 80 s (`intake` 4, which
  carries host metadata, `metadata_v1` 6, `series_v3` 5,
  `check_run_v1` 5, `process` 8), none failed. The host reports as
  `grix-test`, `ubuntu 24.04`, kernel `6.1.0-grix`, aarch64.
- `agent health`: PASS, 18 healthy components.
- DogStatsD: UDP on `localhost:8125` (5 of 5 test packets) and the UDS
  socket both receive.
- APM: the trace-loader takes the first connection on 8126 and starts the
  trace-agent. 5 test traces were accepted (HTTP 200). The writer sent
  `3 payloads, 5 traces` and `3 stats payloads`.
- Process collection: process payloads were posted (`process` endpoint).

I only had an API key, not an application key, so I couldn't query
Datadog's API for the host. The evidence is the intake's 202s and the
forwarder's success counts.

### Checks

| Check | Before | After | Notes |
|---|---|---|---|
| cpu, load, uptime, disk, network, ntp, telemetry | OK | OK | |
| memory | OK, with errors | OK | swap stats needed `/proc/vmstat` |
| io | ERROR | OK | `/proc/diskstats` (empty: no block devices) |
| file_handle | ERROR | OK | `/proc/sys/fs/file-nr` |
| linux_proc_extras (Python) | ERROR | OK | `inode-nr`, `entropy_avail`, `/proc/interrupts` |
| system_core, system_swap, process, directory (Python) | OK | OK | psutil warned about meminfo's Active/Inactive; fixed |
| http_check, tcp_check (Python) | OK | OK | through the allow-list |
| cloud_hostinfo, discovery, container_image, container_lifecycle | OK | OK | nothing to report outside a cloud or container runtime |

## What broke, and what was fixed

In the order the Agent hit them:

1. **SIGILL at startup** (`70b3a4b`, `/proc/<pid>/auxv`). Go's
   `golang.org/x/sys/cpu` can initialise before its hook into the
   runtime's auxv is set. It then reads `/proc/self/auxv`, and if that's
   missing on a kernel that claims 4.11+, it reads `ID_AA64ISAR0_EL1`
   with `mrs`. Linux emulates that read and grix didn't, so `agent` died
   before `main`.
2. **`lookup localhost: no such host`** (`610a21b`). Docker images ship
   empty `/etc/hosts` and `/etc/resolv.conf`, which Docker replaces at
   run time, and grix only filled in missing ones. As a result, `agent
   status`, `agent health`, the trace-agent, IPC and DogStatsD's UDP
   listener all failed. An empty file now counts as missing. `/etc/hosts`
   also names the sandbox (`grix` at 10.0.2.15), so looking up its own
   name no longer goes to the host's resolver.
3. **Checks failing on missing `/proc` files** (`3239c40`, `0928864`):
   `file-nr`, `inode-nr`, `vmstat`, `diskstats`, `partitions`,
   `cap_last_cap`, meminfo's `Active`/`Inactive`, `/sys/class/net/lo/*`,
   per-CPU `topology/`, `entropy_avail`, `fips_enabled`,
   `/proc/interrupts`. `file-max` now reports the real limit
   (`MAX_OPEN_FILES`) instead of 1024.
4. **`fchmodat2` unimplemented** (`fca6ed2`). glibc 2.39 tries it
   first.
5. **s6-overlay: `unable to mkfifo …: Function not implemented`**
   (`4bd9a5e`, named pipes). `mknodat` was gated but not implemented.
   FIFOs now follow Linux's `fifo_open` semantics: blocking opens wait
   for the other side, `O_NONBLOCK` and `O_RDWR` opens don't wait, and
   the data goes when the last end closes. Device nodes are denied.
6. **trace-agent couldn't reach the core Agent** (`1c6ed92`). Go dials
   `":5001"` as `[::]:5001`, and Linux connects the unspecified address
   to loopback. grix refused the connection.

## What's left

### By design: eBPF and capabilities

The following need `bpf()`, and grix denies it (`Privileged`):
system-probe's network performance monitoring, universal service
monitoring, OOM-kill and TCP-queue-length checks, and the security-agent
(CWS, runtime security). The same goes for capability changes
(`capset`: system-probe-lite logs that it can't drop capabilities and
carries on). These components detect this and disable themselves. Making
them work would mean an in-kernel eBPF verifier and the kprobes they
attach to. That is out of scope for a sandbox whose point is a small
kernel surface. In the s6 run, `system-probe` exits 0 with nothing
enabled, `system-probe-lite` (service discovery) keeps running, and
`security-agent` exits because it has nothing to do.

system-probe also logs `could not determine kernel version: opening mem:
open /proc/self/mem`. cilium/ebpf reads the vDSO's `LINUX_VERSION_CODE`
note through `/proc/self/mem`. Without eBPF this doesn't matter, but
see below.

### Worth doing next

- **Network interfaces** (done since). Without `net` the guest has only
  `lo`, and gohai's network metadata reported `not connected to the
  network`, the process check found no network ID, and the network check
  had only `lo`. With `net` the guest now shows `eth0`, 10.0.2.15/24 and
  the default route via 10.0.2.2 (netlink, the interface ioctls,
  `/proc/net/dev`, `/proc/net/route`, `/sys/class/net/eth0`), with no
  device behind it: traffic still goes through the host's proxy.
- **`splice` (76).** Go uses it for pipe and socket copies and falls back
  on ENOSYS, so the only cost is an `unsupported` event and a slower
  copy. A pipe-to-anything `splice` through a bounce buffer is moderate
  work. `sendfile` covers only files today.
- **`mrs` from EL0.** Linux emulates reads of the `ID_AA64*` registers
  (`HWCAP_CPUID`). grix doesn't advertise `HWCAP_CPUID`, so well-behaved
  programs don't try. But code that keys off the kernel version, as
  x/sys/cpu did, gets SIGILL. Emulating the trap (EC 0x18, or an
  undefined instruction at EL0 that decodes as `mrs`) with Linux's
  sanitised values would close this for good.
- **`/proc/self/mem`** for the process's own memory (`pread` and
  `pwrite` at virtual addresses through `uaccess`). Debuggers, cilium's
  version probe and some JITs use it.
- **`*.localhost` names.** gRPC looks up the `_grpc_config.localhost`
  TXT record. That goes to the host's resolver, and the allow-list
  denies it, which shows up as a `denied` event. RFC 6761 lets the
  guest answer `*.localhost` itself.
- **Smaller misses** (each costs a few metrics, not a check):
  `/proc/net/netstat` and `/proc/net/snmp` (TCP retransmit metrics),
  `cpufreq`, `/sys/devices/system/node`, DMI `product_uuid` (gohai's
  host ID), and no cgroup mount in `/proc/self/mounts` (so no
  container metrics for the Agent itself).
- **FIFOs on live mounts.** Creating one there is EPERM (the host
  protocol has no FIFO type), and exports skip FIFOs.

### Noise worth knowing about

Even with an allow-list, the Agent probes cloud metadata endpoints
(`169.254.169.254`, `100.100.100.200`). They're denied and reported as
`denied` events, which is correct. `DD_CLOUD_PROVIDER_METADATA=[]`
quiets them.
