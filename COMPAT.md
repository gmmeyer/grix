# Popular software in grix

A survey of widely used Linux software, run from the official images
(`grix build` from a Grixfile with `from = "..."`, then `grix run
--image ... --json`). arm64 guests ran in grix-vmm (Hypervisor.framework,
Apple silicon); x86_64 guests in QEMU microvm (emulated), from
linux/amd64 images and Alpine x86_64 packages. Each program got only the
capabilities in its row. Servers were driven from the host through a
forwarded port (`-p`) or from inside the guest.

Three rounds so far. The first (2026-10-29) took grix 0.0.22 to 0.0.33
and is the "Results" table. The second (2026-10-30, on 0.0.41) re-ran
every program in it and surveyed 23 more: databases, proxies, build
tools, runtimes, services and headless Chromium ("Round 2" below). The
third (2026-10-30, on 0.0.51 and 0.0.53) re-ran them all after the
security hardening and pushed them hard ("Round 3" below).
Every failure fixed in any of them has a check in `fixtures/src/popular.c`
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
plugin downloads (out of room: see "What's left"). The third found no
regression from the hardening in what these programs do with default
settings, but what it loaded them with found more: see "Round 3".

## Results

Caps: n = `net`, t = `threads`, p = `process`, w = `fs_write`.

| Program | Version | Image | What ran | Caps | Result | Failure (before) and root cause | Fix |
|---|---|---|---|---|---|---|---|
| nginx | 1.31.8 | `nginx:alpine` | `nginx -g 'daemon off;'`, curl from the host through `-p`, `nginx -s quit` | n p w | works | 1. Couldn't open its logs: `error.log -> /dev/stderr` opened with `O_APPEND` gave EACCES (`/proc/self/fd/N` was only known by its literal name). 2. No workers: `ioctl(FIOASYNC)` was ENOTTY, `F_SETOWN` EINVAL. 3. Empty bodies: `sendfile()` to a socket was EINVAL. Also `pwritev2` was missing. | Fixed: symlinked descriptors, `O_ASYNC`, `sendfile`, `preadv2` |
| Apache httpd | 2.4.69 | `httpd:alpine` | `httpd-foreground` / `httpd -k start`, curl from the host | n t p w | works | Worked; warned `apr_sockaddr_info_get() failed for grix` (the hostname didn't resolve). | Fixed: the sandbox's name |
| Caddy | 2.11.7 | `caddy:alpine` | `caddy run` with a Caddyfile, curl from the host | n t w | works | SIGILL at startup: Go's `x/sys/cpu` reads `/proc/self/auxv` for HWCAP, and without it reads ID registers with `mrs` (trapped, not emulated). | Fixed: auxv |
| HAProxy | 3.4.7 | `haproxy:alpine` | frontend → backend on loopback, curl from the host | n t | works | | |
| Traefik | 3.7.16 | `traefik:v3` | file provider routing to its own API, curl from the host | n t | works | SIGILL, as Caddy. | Fixed: auxv |
| PostgreSQL | 17.11 | `postgres:17-alpine` | `docker-entrypoint.sh postgres` (initdb, temporary server, real one), psql: table, 10,000 rows, index; round 3: `pgbench -c 20 -j 4` at 4 CPUs | n t p w | works | initdb: `shmget` not implemented (the postmaster's System V interlock segment). Round 3: pgbench hung at 4 CPUs, in LWLocks, on every version: a futex wake never reached another process. 906 tps at 1 CPU, 3,907 at 4. | Fixed: System V shm, futexes between processes |
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
| ClickHouse | 25.8.33.6 | `clickhouse/clickhouse-server:25.8` | `clickhouse server`; MergeTree table, a million rows, `sum` | n t p w, 3 GiB, 4 CPUs | works | `get_mempolicy` unimplemented (reported). Warned that `threads-max` (1024: grix's limit for all processes) is low, and that `[::]` listeners fail with "Address family not supported": the guest had no IPv6 address but `::1`, so `getaddrinfo` with `AI_ADDRCONFIG` gave no IPv6 address, as in a Docker container without IPv6. Since (0.0.45): it listens on `[::]` (and finds `0.0.0.0` taken by it, as under Docker with IPv6: a warning, by `listen_try`); `threads-max` is 17623 at 3 GiB, still under the 30,000 it wants; "Cannot get pipe capacity" (F_GETPIPE_SZ) is gone. | NUMA policies |
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
| Chromium (headless) | 136.0.7103.113 | `alpine:3.21` + apk | `--headless --dump-dom` of a page that runs JavaScript; `--screenshot` | n t p w, 3 GiB, 4 CPUs | works | Its zygote aborted: no `/proc/self/task` (it counts its threads by the link count), then `capset` to drop capabilities was denied, then the children's pids never came (`SO_PASSCRED` did nothing). Left after round 2: `landlock_create_ruleset`, `SIOCETHTOOL` and a `NETLINK_KOBJECT_UEVENT` socket (reported; it went on). Since (0.0.45): none reported; it still logs that it can't raise its renderers' `oom_score_adj`, and GPU initialisation fails as in any container without a GPU. Since (0.0.48): it runs with a Landlock domain around it, `/` read-only and what it writes writable. | `/proc/<pid>/task`, capset, SO_PASSCRED, prctl |
| MinIO | | `minio/minio`, `quay.io/minio/minio` | | | not tried | MinIO no longer publishes public images (Docker Hub: 404; quay.io: unauthorized). | |

Caps as above; "3 GiB" is `--mem 3072`, which was the most a guest
had when these ran (64 GiB now).

The Datadog Agent was run again too (DATADOG.md).

## Round 3 (2026-10-30)

0.0.49 to 0.0.51 tightened a lot for security: device permissions at
open, execute permission by uid, EBADF on O_PATH for all but a list of
calls, access mode 3, signal frames that must fit the alternate stack,
more special addresses, and budgets on epoll, timers and mappings. Every
program above ran again on 0.0.51 with its round 2 task, on grix-vmm,
and was compared with round 2's status, time, events and warnings; the
tasks that had gone from the host (`-p`) ran that way. Then real programs
were loaded with what those budgets touch, and a dozen programs ran at
4 CPUs on 0.0.51 and on 0.0.53 (which has the locking of 0.0.52), turn
and turn about.

**The hardening broke one thing a program can see:** listing
`/proc/self/fd/N` of an O_PATH directory. All the rest of what changed
is what Linux does. Nothing hit the signal frame check: Go, Java,
Python's faulthandler, Ruby, Rust, .NET and Erlang all took stack
overflows or signals on their alternate stacks as before, so arm64 keeps
x86's check rather than writing past the stack as arm64 Linux does. What
the survey did find was older:

| Program | Version | What changed since round 2 | Why | Now |
|---|---|---|---|---|
| Maven | 3.10.0 | `mvn package` at 2 GiB: JVM killed, exit 137 (since 0.0.45) | the 1.7 GiB image left 314 MiB, and the heap took 128 of it, a share of all RAM | Works, 256 MiB for the program: the heap's share is of what the image leaves |
| Grafana | 13.3.0 | At 2 GiB its plugin downloads can still exhaust memory, and that kills it, or a plugin | they go to guest memory; the heap took 85 MiB more of it than now, and it was tight in round 2 too | Works at 2 GiB in some runs; use 3 GiB (no event, every time) |
| PostgreSQL | 17.11 | pgbench hangs at more than one CPU (all versions) | a process-shared semaphore's wake never reached another process | 3,907 tps at 4 CPUs |
| Go servers | 1.27 | 2,000 connections in the guest failed; 190 echoes/s | 4096 open files in the guest whatever the RAM, then 1024 waiting to be accepted | 10,000 connections, 50,000 echoes/s |
| Go proxies (`io.Copy`) | 1.27 | 1,000 idle connections filled `kmem`, then `mmap` failed: "out of memory" | splice reserved 64 KiB in its pipe before looking for data | 5,000 connections, 35,000 echoes/s |
| Anything behind `-p` | | At most 256 connections | `inet::MAX_CONNS`; 512 on the host | 2,000 at 2 GiB (30,000 echoes/s) |
| Node | 22.23.4 | At most about 2,000 connections, as Go | as Go | 10,000 keep-alive connections, 10,600 requests/s |
| `find -exec +`, `xargs -s` | | E2BIG past 1 MiB | half of Linux's limit | 2 MiB, as `getconf ARG_MAX` says |
| `npm install`, big trees | | ENOSPC at 37,000 files in `/tmp`, whatever the RAM | names and nodes had 12 MiB | 100,000 files and more at 2 GiB |
| Everything else | as above | Same result, same time (within 5%), no new events or warnings | | |

Warnings that are new are the programs': none comes from the kernel.
`mongod` still warns of the soft `RLIMIT_NOFILE`, ClickHouse of
`threads-max`, Elasticsearch and OpenSearch of `vm.max_map_count` (32768
against 262144). `splice` is gone from the Datadog Agent's events.

### Budgets under load

| Budget | Tried with | Reached? |
|---|---|---|
| Epoll registrations (`kmem`) | Go, Node, Java NIO: 60,000 timerfds in one epoll | No: 41 MiB of the budget at 2 GiB |
| POSIX timers (1024 a process, 8192 in all) | Go's CPU profile at 2,000 threads, a timer per thread | Yes, and harmless: Go falls back to setitimer. Nothing else makes many |
| `java.util.Timer`, scheduled tasks | 2,000 Timers (threads), 100,000 scheduled tasks, 100,000 Go tickers | No: they use futexes and the runtime's own timers |
| Mappings (32768 a process) | 40,000 anonymous mappings, 8,000 threads in Java | Only by asking for it (ENOMEM at 32,731); a JVM with 8,000 threads doesn't |
| Threads | 8,000 in Go and in Java at 4 GiB | No. `threads-max` is 2,269 at 512 MiB, 4,544 at 1 GiB and 9,093 from 2 GiB on, half what it was: 0.0.51 charges each its pending signals |
| argv | `xargs -P 8`, 16 execs of 2 MiB at once at 512 MiB | No |
| `getdents64` (1 MiB a call) | 120,000 entries on a live mount, 100,000 in `/tmp`, in `ls`, `find`, Python, Perl | No: it comes in pieces |
| `epoll_wait` (65536 events) | not run past it: from the code | No: it returns fewer, which is always allowed |
| Open files (raised) | 10,000 connections in Go and Node | 47,933 at 512 MiB, 136,545 from 2 GiB on |
| Connections through the host (raised) | 2,000 from the host through `-p` | 2,048, and fewer below 2 GiB (about 580 at 512 MiB): 32 KiB of `kmem` each. Past that, a clean EOF |
| Processes (128) | not raised: PostgreSQL's 100 connections fit | A prefork server past 128 gets EAGAIN |

`--no-outside-links`, the special addresses (100.100.100.200 and
168.63.129.16 are refused, all of `fc00::/7` with a rule of its own, and
Tailscale's 100.64.0.0/10 isn't touched), `/proc/self/mem` after execve
and device nodes for uid 1000 all do what they should.

### x86_64

Images from linux/amd64 in QEMU, emulated: nginx, Redis, Python, Node,
PostgreSQL, Go (signals, timers, 500 connections, `go build` in 219 s)
and Java (`javac`, a stack overflow) all work at 1 CPU. At 4 CPUs under
multi-threaded TCG Go, Node and PostgreSQL do too; the JVM doesn't,
always, though it does on real x86: see "What's left".

### At 4 CPUs, 0.0.51 and 0.0.53

Three passes each, alternating, of Java (2,000 Timers, 100,000 scheduled
tasks, 8,000 threads, NIO, `AlwaysPreTouch`), Go (connections, spliced
copies, threads, tickers, page faults, `go build`), Node, ClickHouse,
headless Chromium, .NET, Gradle and MySQL: every status the same, and
no new events. (PostgreSQL under pgbench hung on 0.0.51, and doesn't
now.) Run head to head, time on 0.0.53 is 0.82 to 1.04 of
0.0.51's, within what the machine's other work does to either. Fast page
faults show on a program that only faults: 30% less time in one pass, on
both architectures, though it doesn't hold up in every pass on a busy
machine. Chromium takes 23% less.

## What was fixed

In round 3 (each with its check in `popular.c`):

| Fix | Programs |
|---|---|
| Futexes between processes (`futex.rs`): a word in shared memory is found by what it's in, as Linux's get_futex_key | PostgreSQL at more than one CPU, Python's `multiprocessing`, anything with process-shared semaphores, mutexes or condition variables |
| The heap's share of RAM is of what the boot image leaves | Maven at 2 GiB, Grafana, any big image |
| Open files charged to `kmem`; `file-max` is what it pays for | Go and Node servers |
| Connections through the host: 2048 in the guest, 4096 on the host | servers behind `-p` |
| Accept queues charged to `kmem`, 16384 in all; listen's backlog refuses nothing | bursts of connects |
| splice reserves what it found, not 64 KiB first | Go's `io.Copy`, reverse proxies |
| Names and nodes get a quarter of what RAM adds to the heap | `npm install`, big source trees |
| argv up to 2 MiB, as Linux | `find -exec +`, `xargs -s` |
| `open(/proc/self/fd/N)` opens the file again if the descriptor can't do what's asked; `readlinkat(fd, "")` | Python's `listdir` of the link, `O_TMPFILE` read back, the idiom of runc, systemd and libpathrs (none of those run here) |
| No page for a signal frame is out of memory (SIGKILL), not a bad stack | what Grafana's plugin reported as "no room for a signal frame" |
| timerfds are swept as their list fills: 60,000 take 0.2 s, not 29 | anything with many |

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
| Since (0.0.45): IPv6 on `eth0`, threads by a kernel memory budget, `SO_PASSCRED` on streams, per-thread `/proc`, `SIOCETHTOOL`, udev's netlink socket, `splice`/`tee`/`vmsplice`, `F_SETPIPE_SZ`, `/proc/self/mem` | ClickHouse, headless Chromium, Go's socket copies, the Datadog Agent and system-probe, `top -H` |
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

1. **The JVM on x86_64, emulated at 4 CPUs on an arm64 Mac**: 2 of 16
   runs crashed on 0.0.51, 7 of 22 on 0.0.52 and after, with SIGSEGV or
   SIGILL in compiled code and a corrupted register. None of 32 on real
   x86 at 4 CPUs (an AMD EPYC, grix-vmm on KVM), none of 16 with TCG on
   one host thread, none at 1 CPU, none on arm64. It looks like QEMU's
   multi-threaded TCG, not the kernel. Don't trust x86_64 JIT runs at
   more than one CPU in it on this host.
2. **threads-max scales with RAM** (each thread's kernel state comes
   out of a budget that is a share of RAM, at most 64 MiB of it): 2,269
   at 512 MiB, 9,093 from 2 GiB on. ClickHouse still warns below 30,000.
3. **Connections through the host stop near 2,000**: each holds a 32 KiB
   window of `kmem` and two threads of the host's proxy, whose accept
   loop polls every 5 ms (bursts of about 18,000 connects a second were
   reset, it seems by macOS's listen queue).
4. **Mappings stop at 32768** where Linux's default is 65530: Elasticsearch
   and OpenSearch warn, and their bootstrap checks would stop a node
   outside `single-node` mode (not tried).
5. **`oom_score_adj` is read-only** (Chromium logs it for each renderer).
6. **Landlock stops at ABI 5**: no scoping of abstract sockets and
   signals (ABI 6); libraries ask for the version and use what's there.

Done since (0.0.48, TODO.md's item 34): Landlock, ABI 5: a program's
own restrictions on files and TCP ports (go-landlock's rules, on every
thread; Chromium under a domain).

Done since (0.0.45, TODO.md's items 30 and 32 to 37): an IPv6
address on `eth0` (a ULA, so IPv4 is still tried first for anything
global), threads beyond 1024, `SO_PASSCRED` on streams, per-thread
`/proc/<pid>/task/<tid>` (names, state, CPU time), `SIOCETHTOOL` and
udev's netlink socket, `splice`, `tee`, `vmsplice`, `F_SETPIPE_SZ` and
`/proc/self/mem`. And in 0.0.43: guests up to 64 GiB
(`grix_abi::image::MAX_RAM`), so files and heaps past 3 GiB fit.

Done in earlier rounds: Linux AIO (io_uring stays ENOSYS on purpose:
a second way into every operation, each needing its own gate, and
blocked by Docker's default seccomp profile too, so programs fall back),
seccomp filters, and reading ID registers from EL0.

Denied by design (nothing in either round needed them): `mount`, raw
sockets, ptrace, module loading, eBPF.
