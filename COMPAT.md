# Popular software in grix

A survey of widely used Linux software, run from the official Docker Hub
images (`grix build` from a Grixfile with `from = "..."`, then `grix run
--image ... --json`), on 2026-10-29. arm64 guests ran in grix-vmm
(Hypervisor.framework, Apple silicon); x86_64 guests in QEMU microvm
(emulated), from linux/amd64 images and Alpine x86_64 packages. Each
program got only the
capabilities in its row. Servers were driven from the host through a
forwarded port (`-p`) or from inside the guest.

"Before" is grix 0.0.22; "now" is this series on top of 0.0.32 (which
brought images per architecture, named pipes, `/proc/<pid>/auxv`, a
named sandbox in images' empty `/etc/hosts`, and connects to the
unspecified address, some of them found here too). Every failure fixed
here has a check in `fixtures/src/popular.c` and an end-to-end test in
`crates/grix/tests/guest.rs`.

## Summary

| | Programs |
|---|---|
| Works | nginx, Apache httpd, Caddy, HAProxy, Traefik, PostgreSQL, MariaDB, Redis, Memcached, MongoDB (mongod and mongosh), SQLite, RabbitMQ, etcd, Prometheus, Elasticsearch (with its ML module), Python, Node, Ruby, PHP (CLI and FPM), Java (javac and a program), Go (`go build`), Rust (`cargo build`), Perl, git, curl, wget, jq, ripgrep, gcc/make, OpenSSL, ssh-keygen, tar/gzip/xz/bzip2, rsync, vim, bash, zsh, busybox, coreutils/findutils, file, ps, less, supervisord, cron |
| Partly | none |
| Breaks | none of the programs tried |

Of these, ten failed before this round: nginx (no workers, empty
responses), PostgreSQL, Redis, Caddy, Traefik, etcd (v3 API), RabbitMQ,
MongoDB's shell, Elasticsearch, and curl in Ubuntu 20.04-based images.

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
| Redis | 7.4.12 | `redis:7-alpine` | `redis-server`, PING/SET/GET/BGSAVE from the host, SIGINT shutdown | n t p w | works | 1. Exited: its arm64 copy-on-write bug check forks and reads `Shared_Dirty` in `/proc/self/smaps`, which didn't exist. 2. `bind: Address in use`: `[::]:6379` with `IPV6_V6ONLY` beside `0.0.0.0:6379`. It warned that `maxclients` dropped to 992 (`RLIMIT_NOFILE` was 1024/1024); it still warns about `vm.overcommit_memory`. | Fixed: smaps, `IPV6_V6ONLY`, `RLIMIT_NOFILE` |
| Memcached | 1.6.45 | `memcached:alpine` | `memcached -u root`, set/get/stats from the host | n t | works | | |
| MongoDB | 7.0.45, mongosh 2.14.0 | `mongo:7` | `mongod`, mongosh: insert, index, query | n t p w | works | mongosh died of SIGSEGV: the strings at the top of the stack were in reverse order within argv and environ, so libuv's process title came out with a negative length and wrote past the stack. | Fixed: the stack's strings |
| SQLite | 3.40.1 | `debian:bookworm` | `sqlite3` create/insert/select; Python's sqlite3 | w | works | | |
| Elasticsearch | 8.15.3 | `elasticsearch:8.15.3` | single node, index and search a document, cluster health | n t p w | works | 1. `UnknownHostException: grix` (the hostname didn't resolve). 2. curl aborted: glibc 2.31's getaddrinfo asserts on a UDP socket reconnected after `connect(AF_UNSPEC)`. 3. The ML controller needs named pipes, which 0.0.32 has: its `controller` runs and `_ml/info` answers. seccomp was unimplemented (it warned and went on); it installs its filter now. | Fixed: the sandbox's name, UDP `AF_UNSPEC`, named pipes (0.0.32) |
| RabbitMQ | 3.13.7 (Erlang/OTP 26.2.5) | `rabbitmq:3-alpine` | `rabbitmq-server`, `rabbitmqctl add_vhost`, AMQP handshake | n t p w | works | Every BEAM died of SIGSEGV: Erlang's JIT cleans the cache (`dc cvau`) on the executable view of its code before touching it, and grix took that fault for a write. | Fixed: cache maintenance faults |
| etcd | 3.5.17 | `quay.io/coreos/etcd:v3.5.17` | v3 put/range and health over HTTP from the host | n t w | works | v3 HTTP API: "connection refused": its gRPC gateway dials `0.0.0.0:2379`, which Linux treats as this host. | Fixed: connect to 0.0.0.0 |
| Prometheus | 3.15.1 | `prom/prometheus` | server, `/api/v1/query`, `/-/healthy` from the host | n t w | works | | |
| Python | 3.12.16 | `python:3.12-slim` | json, sqlite3, ssl, hashlib, threads | t | works | (Denied `__pycache__` writes without `fs_write`, as intended.) | |
| Node | 22.23.4 | `node:22-alpine` | crypto, timers | t | works | | |
| Ruby | 3.3.13 | `ruby:3.3-alpine` | json, digest, a thread | t | works | | |
| PHP | 8.3.36 | `php:8.3-cli-alpine`, `php:8.3-fpm-alpine` | CLI; php-fpm with workers (setuid `www-data`) answering a FastCGI request | n t p w | works | | |
| Java | Temurin 21.0.13 | `eclipse-temurin:21-jdk-alpine` | `java -version`; `javac` and a program (thread pool, SHA-256) | t p (w for javac) | works | `java` re-executes itself, so it needs `process`. | |
| Go | 1.23.12 | `golang:1.23-alpine` | `go build` of a program with goroutines and an httptest server, then run it | n t p w | works | | |
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
| busybox, coreutils, findutils | Alpine's, Debian's | several | `mkdir -p`, `cp -a`, `find`, `xargs` | p w | works | `mkdir -p /tmp/w` without `fs_write` stopped at `mkdir("/")`: EPERM where Linux says EEXIST. `cp -a` can't copy xattrs (unimplemented, reported). | Fixed: `mkdir` EEXIST. Left: xattrs |
| supervisord | 4.2.5 | `debian:bookworm` + apt | two programs, autorestart, `supervisorctl` over its Unix socket, shutdown | t p w | works | | |
| cron | 3.0pl1 (Debian) | `debian:bookworm` + apt | a `/etc/cron.d` job every minute | t p w | works | `prctl(27)` and an audit netlink socket are unimplemented (reported); cron goes on. | |

### x86_64 guests

Images per architecture (0.0.31) build x86_64 images from Docker Hub's
linux/amd64 variants (`grix build --arch x86_64`), and they run on the
x86_64 kernel wherever they are (here in QEMU, emulated):

| Program | Image | Result |
|---|---|---|
| nginx (a request from inside, and `nginx -s quit`) | `nginx:alpine` | works |
| Redis (SET/GET, BGSAVE) | `redis:7-alpine` | works |

Earlier, from an Alpine x86_64 root (`tools/alpine.py --arch x86_64`):
nginx (v4 and v6 listeners, a static file through `sendfile`),
PostgreSQL 17 (initdb, pg_ctl, psql), git, jq, sqlite3, Perl 5.40 and
Ruby 3.4 all work.

## What was fixed

In this series (each with its check in `popular.c`):

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

Already in 0.0.31 and the Datadog series (0.0.32), found here too:
`/proc/<pid>/auxv` (Caddy, Traefik), connecting to 0.0.0.0 and `::` as
to loopback (etcd), the sandbox's name in images' empty `/etc/hosts`,
named pipes (Elasticsearch's ML), and images per architecture (x86_64
images from registries, run on their own machine).

## What's left

In order of impact (details in TODO.md, "Round 3"):

1. **xattrs** (`cp -a`, `tar --xattrs`, `setcap` metadata).
2. ~~**Linux AIO**~~: done after the survey (`io_setup`, `io_submit`,
   `io_getevents`, ...: requests complete as they're submitted).
   **io_uring** stays ENOSYS, on purpose and unreported (programs probe it): it is a
   second way into every operation (each would need its own gate), and
   Docker's default seccomp profile blocks it too, so programs (MariaDB,
   nginx, libuv) are used to falling back to AIO or plain calls.
3. ~~**seccomp filters**~~: done after the survey (`seccomp(2)`, strict
   mode and classic-BPF filters, TSYNC); Elasticsearch installs its own.
4. ~~**Reading ID registers from EL0**~~: done after the survey (`mrs`
   of `ID_AA64*`, `MIDR_EL1`, `MPIDR_EL1`, `REVIDR_EL1` emulated as
   Linux's `HWCAP_CPUID`, sanitized to what HWCAP advertises).

Denied by design (nothing in this survey needed them): `mount`, raw
sockets, ptrace, module loading.
