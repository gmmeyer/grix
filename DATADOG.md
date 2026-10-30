# The Datadog Agent in grix

Does Datadog's official Agent image run in grix, and does Datadog get its
data? As of 2026-10-29, with the fixes on this branch: **yes**. The
image's own entrypoint (s6-overlay) starts the core Agent, its embedded
Python checks, DogStatsD, the trace-agent (APM) and live process
collection. They report to Datadog with a real API key, through an
allow-list that reaches only Datadog's intake. The pieces that need
eBPF or Linux capabilities (system-probe's network, USM and security
modules, and the security-agent) disable themselves, because grix denies
`bpf`, and no process has a capability to use.

Tested with `datadog/agent:7` (7.85.0, linux/arm64, Ubuntu 24.04 base,
Go 1.26) on grix-vmm (Hypervisor.framework, arm64 macOS). The kernel
fixes are also tested on the x86_64 kernel. Run again on 2026-10-30
(grix 0.0.41 and the second compatibility round): still yes, and the
guest's `eth0` is what the Agent sees (see "Again, with eth0").

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
export DD_API_KEY="$DATADOG_API_KEY"
grix run --image agent.grix --mem 2048 --cpus 4 --timeout 3600 -a net \
  --allow-host '*.datadoghq.com' --allow-host '*.datadog.pool.ntp.org:123' \
  -e DD_API_KEY -e DD_SITE=datadoghq.com -e DD_HOSTNAME=grix-test \
  -e DD_APM_ENABLED=true -e DD_PROCESS_CONFIG_PROCESS_COLLECTION_ENABLED=true \
  -i ./conf.d:/conf.d               # optional: check configs, as with Docker's /conf.d
```

- `-e DD_API_KEY` without a value passes the host's, as Docker's `-e`
  does, so the key is never on a command line (or in `ps`).
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

## Again, with eth0 (2026-10-30)

The same run (s6 entrypoint, the key passed by name, `conf.d` with the
Python checks plus `network.d`: the image enables no network check in a
container), for two minutes, with five DogStatsD packets over UDP, one
over the Unix socket, and five traces:

- `agent health`: PASS, 18 healthy components. The forwarder's
  successful transactions: `series_v3` 8, `check_run_v1` 8, `intake` 4,
  `metadata_v1` 6, `process` 13; none failed. The API key never appeared
  in anything the run wrote.
- Every check `[OK]`: cpu, disk, file_handle, io, load, memory,
  **network**, ntp, uptime, telemetry, cloud_hostinfo, container_image,
  container_lifecycle, discovery, and the Python ones (directory,
  http_check, tcp_check, linux_proc_extras, process, system_core,
  system_swap).
- DogStatsD counted the UDP and Unix socket packets; the trace-loader
  started the trace-agent on the first connection and all five traces
  got 200.
- **"not connected to the network" is gone.** gohai's network metadata,
  run as outside a container (`DOCKER_DD_AGENT` unset), is `eth0`,
  10.0.2.15 in 10.0.2.0/24, MAC 52:54:00:12:34:56. In the container
  image it's `null`, as under Docker: gohai collects network metadata in
  a container only when it sees a `docker0` (host networking).
- The process check still logs `no network ID detected`: that ID comes
  from a cloud provider's metadata (EC2's IMDS here, which the allow-list
  denies), not from the interfaces, so it's expected outside a cloud.

What it still reported in that run: `splice` (unimplemented, Go falls
back), `bpf` denied, `/proc/self/mem` missing (system-probe's kernel
version probe; both are there since 0.0.45, not re-run with the Agent
yet), and the cloud metadata and `_grpc_config.localhost` lookups the
allow-list denies. system-probe-lite now warns that `CAP_DAC_READ_SEARCH`
and `CAP_SYS_PTRACE` aren't in its permitted set, as in an unprivileged
container: dropping capabilities works (there are none), and only
asking for one is denied.

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
(CWS, runtime security). The same goes for capabilities: no process
has any (capget says so), so dropping them all succeeds and asking for
one is denied (system-probe-lite warns and carries on). These components detect this and disable themselves. Making
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

- **Network interfaces** (done since, and checked on 2026-10-30).
  Without `net` the guest has only `lo`, and gohai's network metadata
  reported `not connected to the network`. With `net` the guest shows
  `eth0`, 10.0.2.15/24 and the default route via 10.0.2.2 (netlink, the
  interface ioctls, `/proc/net/dev`, `/proc/net/route`,
  `/sys/class/net/eth0`), with no device behind it: traffic still goes
  through the host's proxy. gohai and the network check see it.
- **`splice` (76)** (done since, 0.0.45): Go used it for pipe and socket
  copies and fell back on ENOSYS, at the cost of an `unsupported` event
  and a slower copy. It's a copy through a kernel buffer now, as are
  `tee` and `vmsplice`.
- **`mrs` from EL0** (done since): reads of the `ID_AA64*` registers
  are emulated as Linux's `HWCAP_CPUID` does, with values that agree
  with HWCAP.
- **`/proc/self/mem`** (done since, 0.0.45) for the process's own memory
  (`pread` and `pwrite` at virtual addresses through `uaccess`; another
  process's is refused). Debuggers, cilium's version probe and some JITs
  use it.
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
