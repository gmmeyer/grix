# Popular software in grix

A survey of widely used Linux software, run from the official images
(`grix build` from a Grixfile with `from = "..."`, then `grix run
--image ... --json`). arm64 guests ran in grix-vmm (Hypervisor.framework,
Apple silicon); x86_64 guests in QEMU microvm (emulated), from
linux/amd64 images and Alpine x86_64 packages. Each program got only the
capabilities in its row. Servers were driven from the host through a
forwarded port (`-p`) or from inside the guest.

Two rounds so far. The first (2026-10-29) took grix 0.0.22 to 0.0.33
and is the "Results" table. The second (2026-10-30, on 0.0.41) re-ran
every program in it and surveyed 23 more: databases, proxies, build
tools, runtimes, services and headless Chromium ("Round 2" below).
Every failure fixed in either has a check in `fixtures/src/popular.c`
and an end-to-end test in `crates/grix/tests/guest.rs`.

## Summary

| | Programs |
|---|---|
| Works | nginx, Apache httpd, Caddy, HAProxy, Traefik, Envoy, PostgreSQL, MySQL, MariaDB, Redis, Valkey, Memcached, MongoDB (mongod and mongosh), ClickHouse, SQLite, DuckDB, InfluxDB, Elasticsearch (with its ML module), OpenSearch, RabbitMQ, Kafka (KRaft), NATS (JetStream), etcd, Consul, Vault, Prometheus, Grafana, Python (FastAPI with uvicorn workers, pandas), Node (Express, TypeScript, esbuild), Bun, Deno, Ruby (Sinatra, Puma in cluster mode), PHP (CLI and FPM), Java (javac, Jetty), Maven, Gradle, .NET SDK (`dotnet new` and `dotnet run`), Go (`go build`), Rust (`cargo build`), Perl, headless Chromium, git, curl, wget, jq, ripgrep, gcc/make, OpenSSL, ssh-keygen, tar/gzip/xz/bzip2, rsync, vim, bash, zsh, busybox, coreutils/findutils, file, ps, less, supervisord, cron |
| Partly | none |
| Breaks | none of the programs tried (MinIO's images are no longer public: not tried) |

Of these, ten failed before the first round: nginx (no workers, empty
responses), PostgreSQL, Redis, Caddy, Traefik, etcd (v3 API), RabbitMQ,
MongoDB's shell, Elasticsearch, and curl in Ubuntu 20.04-based images.
Four more failed in the second: `go build` in the golang image (no
HOME), the .NET SDK (MSBuild's thread priorities), headless Chromium
(its zygote: `/proc/self/task`, `capset`, `SO_PASSCRED`) and Grafana's
plugin downloads (out of room: see "What's left").

## Results

Caps: n = `net`, t = `threads`, p = `process`, w = `fs_write`.

| Program | Version | Image | What ran | Caps | Result | Failure (before) and root cause | Fix |
|---|---|---|---|---|---|---|---|
| nginx | 1.31.8 | `nginx:alpine` | `nginx -g 'daemon off;'`, curl from the host through `-p`, `nginx -s quit` | n p w | works | 1. Couldn't open its logs: `error.log -> /dev/stderr` opened with `O_APPEND` gave EACCES (`/proc/self/fd/N` was only known by its literal name). 2. No workers: `ioctl(FIOASYNC)` was ENOTTY, `F_SETOWN` EINVAL. 3. Empty bodies: `sendfile()` to a socket was EINVAL. Also `pwritev2` was missing. | Fixed: symlinked descriptors, `O_ASYNC`, `sendfile`, `preadv2` |
| Apache httpd | 2.4.69 | `httpd:alpine` | `httpd-foreground` / `httpd -k start`, curl from the host | n t p w | works | Worked; warned `apr_sockaddr_info_get() failed for grix` (the hostname didn't resolve). | Fixed: the sandbox's name |
| Caddy | 2.11.7 | `caddy:alpine` | `caddy run` with a Caddyfile, curl from the host | n t w | works | SIGILL at startup: Go's `x/sys/cpu` reads `/proc/self/auxv` for HWCAP, and without it reads ID registers with `mrs` (trapped, not emulated). | Fixed: auxv |
| HAProxy | 3.4.7 | `haproxy:alpine` | frontend → backend on loopback, curl from the host | n t | works | | |
| Traefik | 3.7.16 | `traefik:v3` | file provider routing to its own API, curl from the host | n t | works | SIGILL, as Caddy. | Fixed: auxv |
| PostgreSQL | 17.11 | `postgres:17-alpine` | `docker-entrypoint.sh postgres` (initdb, temporary server, real one), psql: table, 10,000 rows, index | n t p w | works | initdb: `shmget` not implemented (the postmaster's System V interlock segment). | Fixed: System V shm |
| MariaDB | 11.8.9 | `mariadb:11` | `docker-entrypoint.sh mariadbd`, client: database, table, rows | n t p w | works | Works; it listens on 0.0.0.0 and `::` (needed `IPV6_V6ONLY`). io_uring and `io_setup` were ENOSYS (reported), and it fell back to synchronous I/O; it has Linux AIO now (io_uring stays ENOSYS, as under Docker's default seccomp profile). | |
| Redis | 7.4.12 | `redis:7-alpine` | `redis-server`, PING/SET/GET/BGSAVE from the host, SIGINT shutdown | n t p w | works | 1. Exited: its arm64 copy-on-write bug check forks and reads `Shared_Dirty` in `/proc/self/smaps`, which didn't exist. 2. `bind: Address in use`: `[::]:6379` with `IPV6_V6ONLY` beside `0.0.0.0:6379`. It warned that `maxclients` dropped to 992 (`RLIMIT_NOFILE` was 1024/1024), and that `vm.overcommit_memory` wasn't 1. Round 2: no warnings. | Fixed: smaps, `IPV6_V6ONLY`, `RLIMIT_NOFILE`, `overcommit_memory` |
| Memcached | 1.6.45 | `memcached:alpine` | `memcached -u root`, set/get/stats from the host | n t | works | | |
| MongoDB | 7.0.45, mongosh 2.14.0 | `mongo:7` | `mongod`, mongosh: insert, index, query | n t p w | works | mongosh died of SIGSEGV: the strings at the top of the stack were in reverse order within argv and environ, so libuv's process title came out with a negative length and wrote past the stack. Round 2: mongod warns that the soft `RLIMIT_NOFILE` (1024) is below 64000, as under Docker's default. | Fixed: the stack's strings |
| SQLite | 3.40.1 | `debian:bookworm` | `sqlite3` create/insert/select; Python's sqlite3 | w | works | | |
| Elasticsearch | 8.15.3 | `elasticsearch:8.15.3` | single node, index and search a document, cluster health | n t p w | works | 1. `UnknownHostException: grix` (the hostname didn't resolve). 2. curl aborted: glibc 2.31's getaddrinfo asserts on a UDP socket reconnected after `connect(AF_UNSPEC)`. 3. The ML controller needs named pipes, which 0.0.32 has: its `controller` runs and `_ml/info` answers. seccomp was unimplemented (it warned and went on); it installs its filter now. | Fixed: the sandbox's name, UDP `AF_UNSPEC`, named pipes (0.0.32) |
| RabbitMQ | 3.13.7 (Erlang/OTP 26.2.5) | `rabbitmq:3-alpine` | `rabbitmq-server`, `rabbitmqctl add_vhost`, AMQP handshake | n t p w | works | Every BEAM died of SIGSEGV: Erlang's JIT cleans the cache (`dc cvau`) on the executable view of its code before touching it, and grix took that fault for a write. | Fixed: cache maintenance faults |
| etcd | 3.5.17 | `quay.io/coreos/etcd:v3.5.17` | v3 put/range and health over HTTP from the host | n t w | works | v3 HTTP API: "connection refused": its gRPC gateway dials `0.0.0.0:2379`, which Linux treats as this host. | Fixed: connect to 0.0.0.0 |
| Prometheus | 3.15.1 | `prom/prometheus` | server, `/api/v1/query`, `/-/healthy` from the host | n t w | works | | |
| Python | 3.12.16 | `python:3.12-slim` | json, sqlite3, ssl, hashlib, threads | t | works | (Denied `__pycache__` writes without `fs_write`, as intended.) | |
| Node | 22.23.4 | `node:22-alpine` | crypto, timers | t | works | | |
| Ruby | 3.3.13 | `ruby:3.3-alpine` | json, digest, a thread | t | works | | |
| PHP | 8.3.36 | `php:8.3-cli-alpine`, `php:8.3-fpm-alpine` | CLI; php-fpm with workers (setuid `www-data`) answering a FastCGI request | n t p w | works | | |
| Java | Temurin 21.0.13 | `eclipse-temurin:21-jdk-alpine` | `java -version`; `javac` and a program (thread pool, SHA-256) | t p (w for javac) | works | `java` re-executes itself, so it needs `process`. Round 2: with its output on a pipe it calls `prctl(PR_SET_MM)`, reported as unimplemented; now EPERM, as under Docker. | Fixed: prctl |
| Go | 1.23.12 | `golang:1.23-alpine` | `go build` of a program with goroutines and an httptest server, then run it | n t p w | works | Round 2: "GOCACHE is not defined and neither $XDG_CACHE_HOME nor $HOME are defined": images got no HOME, which Docker sets. | Fixed: HOME |
| Rust | cargo 1.99.1 | `rust:alpine` | `cargo build --release` of a threaded program, then run it | t p w | works | Called `pwritev2` (fell back). | Fixed: `preadv2` |
| Perl | 5.44.0 | `perl:5-slim` | Digest::SHA, JSON::PP | — | works | | |
| git | 2.39.5 | `debian:bookworm` + apt | init, commit, branch, merge, log | p w | works | | |
| curl, wget | 7.88.1, 1.21.3 | `debian:bookworm` + apt | HTTPS to an allowed host; a host not allowed is refused | n t p w | works | | |
| jq, ripgrep, file, less, ps | 1.6, 13.0.0, 5.44, 590, procps 4.0 | `debian:bookworm` + apt | real tasks | p w | works | | |
| gcc, make | 12.2, 4.3 | `debian:bookworm` + apt | build and run a pthreads program | t p w | works | One `apt-get install` of all of this failed with ENOSPC: build steps got 3× the base's size + 512 MiB, whatever the Grixfile asked. | Fixed: build steps' memory |
| OpenSSL, ssh-keygen | 3.0.22, OpenSSH 9.2p1 | `debian:bookworm` + apt | RSA key, digest; ed25519 key | p w | works | | |
| tar, gzip, xz, bzip2 | Debian's | `debian:bookworm` + apt | compress and list | p w | works | | |
| rsync | 3.2.7 | `debian:bookworm` + apt | `rsync -a` of a tree | p w | works | `openat2` was unimplemented (reported); rsync fell back to `openat`. | Fixed: `openat2` |
| vim | 9.0 | `debian:bookworm` + apt | `vim -Es`: edit and write a file | w | works | | |
| bash, zsh | 5.2.15, 5.9 | `debian:bookworm` + apt | arrays, loops | — | works | | |
| busybox, coreutils, findutils | Alpine's, Debian's | several | `mkdir -p`, `cp -a`, `find`, `xargs` | p w | works | `mkdir -p /tmp/w` without `fs_write` stopped at `mkdir("/")`: EPERM where Linux says EEXIST. `cp -a` couldn't copy xattrs (unimplemented, reported). | Fixed: `mkdir` EEXIST, xattrs |
| supervisord | 4.2.5 | `debian:bookworm` + apt | two programs, autorestart, `supervisorctl` over its Unix socket, shutdown | t p w | works | | |
| cron | 3.0pl1 (Debian) | `debian:bookworm` + apt | a `/etc/cron.d` job every minute | t p w | works | `prctl(27)` and an audit netlink socket are unimplemented (reported); cron goes on. | |

### x86_64 guests

Images per architecture (0.0.31) build x86_64 images from Docker Hub's
linux/amd64 variants (`grix build --arch x86_64`), and they run on the
x86_64 kernel wherever they are (here in QEMU, emulated):

| Program | Image | Result |
|---|---|---|
| nginx (a request from inside, and `nginx -s quit`) | `nginx:alpine` | works |
| Redis (SET/GET, BGSAVE) | `redis:7-alpine` | works (round 2: no overcommit warning) |

Earlier, from an Alpine x86_64 root (`tools/alpine.py --arch x86_64`):
nginx (v4 and v6 listeners, a static file through `sendfile`),
PostgreSQL 17 (initdb, pg_ctl, psql), git, jq, sqlite3, Perl 5.40 and
Ruby 3.4 all work.

## Round 2 (2026-10-30)

On 0.0.41 and this series. Every program above was run again, with the
same tasks; all work, and the notes in their rows say what changed. These
are new:

| Program | Version | Image | What ran | Caps | Result | Events and warnings | Fix |
|---|---|---|---|---|---|---|---|
| MySQL | 8.4.13 | `mysql:8.4` | `docker-entrypoint.sh mysqld` (initialize, temporary server, real one), client: database, table, rows | n t p w | works | MySQL's own warnings (an empty root password during init, a self-signed CA, `/var/run/mysqld` world-accessible), as under Docker. | |
| ClickHouse | 25.8.33.6 | `clickhouse/clickhouse-server:25.8` | `clickhouse server`; MergeTree table, a million rows, `sum` | n t p w, 3 GiB, 4 CPUs | works | `get_mempolicy` unimplemented (reported). Warns that `threads-max` (1024: grix's limit for all processes) is low, and that `[::]` listeners fail with "Address family not supported": the guest has no IPv6 address but `::1`, so `getaddrinfo` with `AI_ADDRCONFIG` gives no IPv6 address, as in a Docker container without IPv6. | NUMA policies |
| Valkey | 8.1.11 | `valkey/valkey:8-alpine` | SET/GET, BGSAVE, INFO | n t p w | works | Warned about `vm.overcommit_memory`, as Redis did. | overcommit |
| DuckDB | 2.0.0 | `python:3.12-slim` + pip | a million-row aggregate, a table | t w | works | | |
| Envoy | 1.34.14 | `envoyproxy/envoy:v1.34-latest` | a listener with a direct response, curl from the host through `-p` | n t p w | works | Its own warning about no connection limit. | |
| Jetty | 12.1.14 (Temurin 21.0.13) | `jetty:12-jdk21` | `start.jar` with the http module, a request | n t p w | works | | |
| Maven | 3.10.0 | `maven:3-eclipse-temurin-21` | `mvn package` of a project with a dependency from Maven Central, then run it | n t p w | works | | |
| Gradle | 8.14.6 | `gradle:8-jdk21` | `gradle run` of an application (Kotlin DSL, Maven Central), no daemon | n t p w | works | | |
| .NET SDK | 8.0.427 (runtime 8.0.33) | `mcr.microsoft.com/dotnet/sdk:8.0` | `dotnet new console`, `dotnet run` | n t p w, 3 GiB, 4 CPUs | works | MSBuild failed: `Thread.set_Priority` threw, as `sched_get_priority_min/max` were ENOSYS; also `get_mempolicy`. | sched priorities, NUMA policies |
| Bun | 1.4.4 | `oven/bun:1` | `Bun.serve` and `fetch`, `bun add` from npm | n t p w | works | | |
| Deno | 2.9.8 | `denoland/deno` | `Deno.serve` and `fetch` | n t p w | works | | |
| Node web stack | 22.23.4 | `node:22-alpine` + npm | Express, `tsc`, esbuild, `npm view` | n t p w | works | | |
| Ruby web stack | 3.3.13 | `ruby:3.3-alpine` + gems | Sinatra, Puma with two workers | n t p w | works | | |
| Python web stack | 3.12.16 | `python:3.12-slim` + pip | FastAPI under uvicorn with two workers; pandas and NumPy | n t p w | works | `mbind` unimplemented (reported). | NUMA policies |
| InfluxDB | 2.9.1 | `influxdb:2-alpine` | `influxd`, `influx setup`, write and query | n t p w | works | | |
| OpenSearch | 2.19.7 | `opensearchproject/opensearch:2` | single node, security plugin off, index a document, cluster health | n t p w, 3 GiB, 4 CPUs | works | A made-up `prctl` option (its seccomp self-test) was reported as unimplemented. | prctl |
| Kafka (KRaft) | 3.9.1 | `apache/kafka:3.9.1` | the image's broker, create a topic, produce and consume a message | n t p w | works | `prctl(PR_SET_MM)` from its Alpine JDK (reported). | prctl |
| NATS | 2.15.2 | `nats:alpine` | `nats-server -js`, SUB/PUB/PING over a socket | n t p w | works | | |
| Consul | 2.1.0 | `hashicorp/consul` | `consul agent -dev`, KV put/get, members | n t p w | works | | |
| Vault | 2.2.1 | `hashicorp/vault` | `vault server -dev`, KV put/get | n t p w | works | | |
| Grafana | 13.3.0 | `grafana/grafana` | `/run.sh`, health and search APIs from the host | n t p w, 2 GiB | works | Its background plugin installs ran out of room ("no space left on device"): files live in guest memory. | |
| Chromium (headless) | 136.0.7103.113 | `alpine:3.21` + apk | `--headless --dump-dom` of a page that runs JavaScript; `--screenshot` | n t p w, 3 GiB, 4 CPUs | works | Its zygote aborted: no `/proc/self/task` (it counts its threads by the link count), then `capset` to drop capabilities was denied, then the children's pids never came (`SO_PASSCRED` did nothing). Left: `landlock_create_ruleset`, `SIOCETHTOOL` and a `NETLINK_KOBJECT_UEVENT` socket (reported; it goes on), and GPU initialisation fails as in any container without a GPU. | `/proc/<pid>/task`, capset, SO_PASSCRED, prctl |
| MinIO | | `minio/minio`, `quay.io/minio/minio` | | | not tried | MinIO no longer publishes public images (Docker Hub: 404; quay.io: unauthorized). | |

Caps as above; "3 GiB" is `--mem 3072`, the most a guest has (see
"What's left").

The Datadog Agent was run again too (DATADOG.md).

## What was fixed

In round 2 (each with its check in `popular.c`, or a test of its own):

| Fix | Programs |
|---|---|
| Docker's HOME (the image user's home in its `/etc/passwd`) and HOSTNAME, for runs and build steps; a variable set for a run replaces the image's instead of following it (getenv took the image's) | `go build` (GOCACHE), pip, npm, cargo and git's caches and configs |
| `/proc/sys/vm/overcommit_memory` is 1 (grix takes memory only as it's touched), `max_map_count` the real cap, inotify's limits | Redis and Valkey (no more warning), Chromium |
| `sched_get_priority_max/min`; real-time policies EPERM, as without CAP_SYS_NICE | the .NET SDK (MSBuild) |
| `mbind`, `set_mempolicy`, `get_mempolicy` for one NUMA node | ClickHouse, .NET, NumPy, Chromium |
| `prctl`: `PR_SET_MM` EPERM, SVE's EINVAL, unknown options EINVAL, quietly | Alpine's JDK (Kafka, Temurin), Chromium, OpenSearch |
| `/proc/<pid>/task/<tid>` | headless Chromium, `ps -L`, psutil |
| `SO_PASSCRED` and `SCM_CREDENTIALS` on message sockets | headless Chromium |
| `capset` that drops every capability (there are none) succeeds; raising one is still denied | headless Chromium |
| `grix run -e KEY` passes the host's value of KEY, as Docker's does | secrets such as the Datadog API key stay off the command line |
| A build step that runs out of room says so, and how to ask for more (`memory_mb`) | `apk add chromium` (a bare "Signaled(7)" before) |

In round 1 (each with its check in `popular.c`):

| Fix | Commit | Programs |
|---|---|---|
| symlinked descriptors | Descriptors reached through symlinks (`/var/log/nginx/error.log -> /dev/stderr`, relative paths) | nginx, httpd, every image that links its logs to stdio |
| `IPV6_V6ONLY` | A v4 and a v6 listener on one port | Redis, MariaDB, nginx with `listen [::]:80` |
| smaps | `/proc/<pid>/smaps` and `smaps_rollup` (another process's only for those who may inspect it) | Redis |
| cache maintenance faults | arm64: a cache maintenance fault (`dc cvau`) is a read | RabbitMQ, every Erlang/Elixir program |
| UDP `AF_UNSPEC` | UDP `connect(AF_UNSPEC)` disconnects, and each connect picks the source address | glibc ≤ 2.31 getaddrinfo (Ubuntu 20.04 images: curl, Elasticsearch's tools) |
| the sandbox's name | `/etc/hostname`, and images' own `/etc/hosts`, `hostname`, `resolv.conf` left out (as Docker does) | Elasticsearch, Java's `getLocalHost`, Apache, in Alpine-based images |
| `O_ASYNC` | FIOASYNC, `F_SETOWN(_EX)`, `F_SETSIG`, SIGIO (never to init unless it asked) | nginx's master and workers |
| `sendfile` | `sendfile` to pipes, named pipes and sockets | nginx (static files) |
| `preadv2` | `preadv2`, `pwritev2` | nginx, cargo |
| System V shm | `shmget`, `shmat`, `shmdt`, `shmctl` | PostgreSQL |
| `mkdir` EEXIST | `mkdir` of an existing name is EEXIST without `fs_write` | busybox `mkdir -p`, Python `makedirs` |
| build steps' memory | Build steps get the Grixfile's `memory_mb` | big `apt-get install` steps |
| the stack's strings | The stack's strings in Linux's order, with a zero word on top | mongosh (Node's process title), nginx's and PostgreSQL's setproctitle |
| shared memory budget | Shared memory's page list is charged to the kernel memory budget (it could fill the kernel heap) | anything with big `MAP_SHARED` or System V memory |
| `openat2` | openat2 and its RESOLVE_* flags | rsync |
| `RLIMIT_NOFILE` | Up to 65536 descriptors | Redis (`maxclients` 10000), busy servers |
| xattrs | Extended attributes | `cp -a`, `tar --xattrs`, `setcap` |

Already in 0.0.31 and the Datadog series (0.0.32), found here too:
`/proc/<pid>/auxv` (Caddy, Traefik), connecting to 0.0.0.0 and `::` as
to loopback (etcd), the sandbox's name in images' empty `/etc/hosts`,
named pipes (Elasticsearch's ML), and images per architecture (x86_64
images from registries, run on their own machine).

## What's left

In order of impact (details in TODO.md):

1. **Guest memory is at most 3 GiB** (`grix_abi::image::MAX_RAM`: the
   kernel maps physical memory linearly below 4 GiB). The sandbox's
   files live in that memory too, so Grafana's plugin downloads ran out
   of room at 2 GiB, an `apk add chromium` build step needed
   `memory_mb = 4096` (it dies of SIGBUS on a full file system without
   it, and the build's error now says it ran out of room), and
   Elasticsearch and OpenSearch need small heaps. Bigger guests need
   the kernel to map memory above 4 GiB.
2. **1024 threads in all** (`process::MAX_THREADS`, and
   `/proc/sys/kernel/threads-max` says so): ClickHouse warns, and a busy
   JVM or ClickHouse server could reach it.
3. **`splice`** is still unimplemented (Go and others fall back; it's
   reported), and so is **`/proc/self/mem`** (cilium/ebpf's version
   probe in Datadog's system-probe).
4. **No IPv6 address on `eth0`**: programs that listen on `[::]` with
   `AI_ADDRCONFIG` (ClickHouse) skip it, as in a container without IPv6.
5. **`SO_PASSCRED` on streams**: credentials come only with datagram and
   seqpacket messages (reported for streams).
6. **Landlock, ethtool, udev's netlink**: reported by Chromium, which
   goes on without them.

Done in earlier rounds: Linux AIO (io_uring stays ENOSYS on purpose:
a second way into every operation, each needing its own gate, and
blocked by Docker's default seccomp profile too, so programs fall back),
seccomp filters, and reading ID registers from EL0.

Denied by design (nothing in either round needed them): `mount`, raw
sockets, ptrace, module loading, eBPF.
