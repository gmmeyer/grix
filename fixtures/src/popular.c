// What popular software expects of Linux, found running it in grix (see
// COMPAT.md): one check per argument.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <setjmp.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

static char buf[1 << 16];

/// The whole of a file, in `buf`; its length, or -1.
static ssize_t slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = 0, r;
    while (n < (ssize_t)sizeof buf - 1 && (r = read(fd, buf + n, sizeof buf - 1 - n)) > 0) n += r;
    close(fd);
    buf[n] = 0;
    return n;
}

// Go's golang.org/x/sys/cpu (Caddy, Traefik, etcd, ...) reads HWCAP from
// /proc/self/auxv. Without it, it reads the CPU's ID registers itself,
// which ends in SIGILL.
static int auxv(void) {
    ssize_t n = slurp("/proc/self/auxv");
    CHECK(n > 0 && n % 16 == 0);
    unsigned long *v = (unsigned long *)buf;
    int hwcap = 0, pagesz = 0, random = 0, end = 0;
    for (ssize_t i = 0; i < n / 8; i += 2) {
        hwcap |= v[i] == AT_HWCAP && v[i + 1] == getauxval(AT_HWCAP);
        pagesz |= v[i] == AT_PAGESZ && v[i + 1] == 4096;
        random |= v[i] == AT_RANDOM && v[i + 1] == getauxval(AT_RANDOM);
        if (v[i] == AT_NULL) {
            end = i + 2 == n / 8;
            break;
        }
    }
    CHECK(hwcap && pagesz && random && end);
    return 0;
}

// The official nginx and httpd images link their logs to /dev/stdout and
// /dev/stderr, which nginx opens with O_APPEND (and O_CREAT): a
// descriptor reached through a symlink, not by its own name.
static int fdlink(void) {
    CHECK(symlink("/dev/stderr", "/tmp/error.log") == 0);
    int fd = open("/tmp/error.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, "through a link\n", 15) == 15);
    close(fd);
    struct stat st;
    CHECK(stat("/tmp/error.log", &st) == 0 && S_ISFIFO(st.st_mode));
    CHECK(open("/tmp/error.log", O_WRONLY | O_CREAT | O_EXCL, 0644) == -1 && errno == EEXIST);
    // A relative path in /proc/self/fd.
    CHECK(chdir("/proc/self") == 0);
    fd = open("fd/2", O_WRONLY);
    CHECK(fd >= 0);
    CHECK(write(fd, "relative\n", 9) == 9);
    close(fd);
    CHECK(fstatat(AT_FDCWD, "fd/2", &st, 0) == 0 && S_ISFIFO(st.st_mode));
    CHECK(chdir("/") == 0);
    // A descriptor that isn't open.
    CHECK(symlink("/proc/self/fd/77", "/tmp/gone") == 0);
    CHECK(open("/tmp/gone", O_RDONLY) == -1 && errno == ENOENT);
    return 0;
}

// Redis listens on 0.0.0.0 and on [::] with IPV6_V6ONLY, both on the
// same port: one listener per family.
static int v6only(void) {
    int one = 1, v = 0;
    socklen_t len = sizeof v;
    struct sockaddr_in a4 = {.sin_family = AF_INET, .sin_port = htons(7000)};
    struct sockaddr_in6 a6 = {.sin6_family = AF_INET6, .sin6_port = htons(7000)};
    int s4 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(bind(s4, (struct sockaddr *)&a4, sizeof a4) == 0 && listen(s4, 8) == 0);
    // Without IPV6_V6ONLY, [::] takes v4 too: that's in use.
    int dual = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(bind(dual, (struct sockaddr *)&a6, sizeof a6) == -1 && errno == EADDRINUSE);
    int s6 = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(getsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &v, &len) == 0 && v == 0);
    CHECK(setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) == 0);
    CHECK(getsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &v, &len) == 0 && v == 1);
    CHECK(bind(s6, (struct sockaddr *)&a6, sizeof a6) == 0 && listen(s6, 8) == 0);
    CHECK(setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) == -1 && errno == EINVAL);
    CHECK(setsockopt(s4, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) == -1 && errno == ENOPROTOOPT);
    // Each family's connections reach its own listener.
    a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a6.sin6_addr = in6addr_loopback;
    int c4 = socket(AF_INET, SOCK_STREAM, 0), c6 = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(connect(c4, (struct sockaddr *)&a4, sizeof a4) == 0);
    CHECK(connect(c6, (struct sockaddr *)&a6, sizeof a6) == 0);
    struct sockaddr_storage peer;
    socklen_t plen = sizeof peer;
    int x4 = accept(s4, (struct sockaddr *)&peer, &plen);
    CHECK(x4 >= 0 && peer.ss_family == AF_INET);
    plen = sizeof peer;
    int x6 = accept(s6, (struct sockaddr *)&peer, &plen);
    CHECK(x6 >= 0 && peer.ss_family == AF_INET6);
    CHECK(accept(s4, 0, 0) == -1 && errno == EAGAIN);
    CHECK(accept(s6, 0, 0) == -1 && errno == EAGAIN);
    // Once they're closed, a dual-stack [::] may have the port.
    close(s4);
    close(s6);
    CHECK(bind(dual, (struct sockaddr *)&a6, sizeof a6) == 0 && listen(dual, 8) == 0);
    return 0;
}

// etcd's gRPC gateway dials 0.0.0.0:2379, where etcd listens: on Linux,
// the unspecified address is this host.
static int anyaddr(void) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(7001)};
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 8) == 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    struct sockaddr_in peer;
    socklen_t len = sizeof peer;
    CHECK(getpeername(c, (struct sockaddr *)&peer, &len) == 0 && peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    int x = accept(l, 0, 0);
    CHECK(x >= 0 && write(c, "hi", 2) == 2 && read(x, buf, 2) == 2 && memcmp(buf, "hi", 2) == 0);
    struct sockaddr_in6 a6 = {.sin6_family = AF_INET6, .sin6_port = htons(7001)};
    // [::] is ::1, where nothing listens: the listener is v4's.
    int c6 = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(connect(c6, (struct sockaddr *)&a6, sizeof a6) == -1 && errno == ECONNREFUSED);
    // Port 0 is nowhere.
    a.sin_port = 0;
    int z = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(z, (struct sockaddr *)&a, sizeof a) == -1 && errno == ECONNREFUSED);
    return 0;
}

/// getsockname's address, as text.
static const char *sockname(int s) {
    static char out[64];
    struct sockaddr_storage a;
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) return "?";
    if (a.ss_family == AF_INET) return inet_ntop(AF_INET, &((struct sockaddr_in *)&a)->sin_addr, out, sizeof out);
    return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&a)->sin6_addr, out, sizeof out);
}

// glibc's getaddrinfo (2.31, Ubuntu 20.04's: curl in the Elasticsearch
// image) sorts its answers by connecting one UDP socket to each in turn,
// disconnecting it in between with AF_UNSPEC, and asserts that a v6
// socket connected to a v4 address has a v4-mapped one.
static int udproute(void) {
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 a6 = {.sin6_family = AF_INET6, .sin6_port = htons(9200), .sin6_addr = in6addr_loopback};
    CHECK(connect(s, (struct sockaddr *)&a6, sizeof a6) == 0 && strcmp(sockname(s), "::1") == 0);
    struct sockaddr unspec = {.sa_family = AF_UNSPEC};
    CHECK(connect(s, &unspec, sizeof unspec) == 0 && strcmp(sockname(s), "::") == 0);
    struct sockaddr_in a4 = {.sin_family = AF_INET, .sin_port = htons(9200), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(connect(s, (struct sockaddr *)&a4, sizeof a4) == 0 && strcmp(sockname(s), "::ffff:127.0.0.1") == 0);
    CHECK(connect(s, &unspec, sizeof unspec) == 0);
    inet_pton(AF_INET6, "::ffff:1.2.3.4", &a6.sin6_addr);
    CHECK(connect(s, (struct sockaddr *)&a6, sizeof a6) == 0 && strcmp(sockname(s), "::ffff:10.0.2.15") == 0);
    // Connecting again chooses again, without a disconnect too.
    CHECK(connect(s, (struct sockaddr *)&a4, sizeof a4) == 0 && strcmp(sockname(s), "::ffff:127.0.0.1") == 0);
    // An address bind named stays.
    int b = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in here = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(b, (struct sockaddr *)&here, sizeof here) == 0);
    a4.sin_addr.s_addr = inet_addr("1.2.3.4");
    CHECK(connect(b, (struct sockaddr *)&a4, sizeof a4) == 0 && strcmp(sockname(b), "127.0.0.1") == 0);
    CHECK(connect(b, &unspec, sizeof unspec) == 0 && strcmp(sockname(b), "127.0.0.1") == 0);
    return 0;
}

// Elasticsearch (Java's InetAddress.getLocalHost) and Apache look up the
// machine's own name; Docker's /etc/hosts has it.
static int hostname(void) {
    char name[64];
    CHECK(gethostname(name, sizeof name) == 0 && strcmp(name, "grix") == 0);
    struct addrinfo hints = {.ai_family = AF_INET}, *res;
    CHECK(getaddrinfo(name, NULL, &hints, &res) == 0);
    struct sockaddr_in *a = (struct sockaddr_in *)res->ai_addr;
    CHECK(a->sin_addr.s_addr == inet_addr("10.0.2.15"));
    freeaddrinfo(res);
    CHECK(slurp("/etc/hostname") > 0 && strcmp(buf, "grix\n") == 0);
    return 0;
}

// Erlang's JIT writes code through one mapping of a memfd and runs it
// through another, read-only one, cleaning the data cache there to the
// point of unification (`dc cvau`, in __clear_cache) before the pages
// are ever touched: a fault that's not a write.
static int cacheflush(void) {
    int fd = memfd_create("jit", 0);
    CHECK(fd >= 0 && ftruncate(fd, 8192) == 0);
    char *rx = mmap(NULL, 8192, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    char *rw = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(rx != MAP_FAILED && rw != MAP_FAILED);
    rw[4096] = 7;
    for (char *a = rx; a < rx + 8192; a += 64) {
#ifdef __aarch64__
        asm volatile("dc cvau, %0" ::"r"(a) : "memory");
        asm volatile("ic ivau, %0" ::"r"(a) : "memory");
#else
        asm volatile("clflush (%0)" ::"r"(a) : "memory");
#endif
    }
    CHECK(rx[4096] == 7 && rx[0] == 0);
    return 0;
}

static volatile sig_atomic_t io_count, io_fd, io_code, io_band;

static void on_io(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)uc;
    io_count++;
    io_fd = si->si_fd;
    io_code = si->si_code;
    io_band = si->si_band;
}

// nginx's master sets O_ASYNC on its channel to each worker (FIOASYNC,
// then F_SETOWN), and gives up on the worker if it can't.
static int sigio(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    struct sigaction sa = {.sa_sigaction = on_io, .sa_flags = SA_SIGINFO};
    CHECK(sigaction(SIGIO, &sa, NULL) == 0 && sigaction(SIGRTMIN, &sa, NULL) == 0);
    int on = 1;
    CHECK(ioctl(sv[0], FIOASYNC, &on) == 0 && fcntl(sv[0], F_SETOWN, getpid()) == 0);
    CHECK((fcntl(sv[0], F_GETFL) & O_ASYNC) && fcntl(sv[0], F_GETOWN) == getpid());
    CHECK(io_count == 0);
    CHECK(write(sv[1], "x", 1) == 1);
    CHECK(io_count == 1 && io_code == SI_KERNEL);
    char c;
    CHECK(read(sv[0], &c, 1) == 1 && io_count == 1);
    // F_SETSIG: its signal, with the reason, the poll bits and the descriptor.
    CHECK(fcntl(sv[0], F_SETSIG, SIGRTMIN) == 0 && fcntl(sv[0], F_GETSIG) == SIGRTMIN);
    CHECK(write(sv[1], "y", 1) == 1 && read(sv[0], &c, 1) == 1);
    CHECK(io_count == 2 && io_fd == sv[0] && io_code == POLL_IN && (io_band & POLLIN));
    // Off again: nothing.
    on = 0;
    CHECK(ioctl(sv[0], FIOASYNC, &on) == 0 && !(fcntl(sv[0], F_GETFL) & O_ASYNC));
    CHECK(write(sv[1], "z", 1) == 1 && read(sv[0], &c, 1) == 1 && io_count == 2);
    // Another process's write: the worker's, to the master.
    CHECK(fcntl(sv[0], F_SETSIG, 0) == 0 && fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_ASYNC) == 0);
    sigset_t io, old;
    sigemptyset(&io);
    sigaddset(&io, SIGIO);
    CHECK(sigprocmask(SIG_BLOCK, &io, &old) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(write(sv[1], "w", 1) == 1 ? 0 : 1);
    while (io_count == 2) sigsuspend(&old);
    int status;
    CHECK(io_count == 3 && waitpid(pid, &status, 0) == pid && status == 0);
    CHECK(sigprocmask(SIG_SETMASK, &old, NULL) == 0);
    // F_SETOWN_EX names a thread, a process or a group.
    struct f_owner_ex ex = {.type = F_OWNER_PGRP, .pid = getpgrp()}, got;
    CHECK(fcntl(sv[0], F_SETOWN_EX, &ex) == 0 && fcntl(sv[0], F_GETOWN_EX, &got) == 0);
    CHECK(got.type == F_OWNER_PGRP && got.pid == getpgrp());
    return 0;
}

// O_ASYNC's signals are the F_SETOWN caller's, as kill's would be: a
// child can't end or stop init (pid 1, which handles none of them) by
// making it the owner, as a process, its group or its thread.
static int sigioinit(void) {
    CHECK(getpid() == 1);
    int sigs[] = {0, SIGKILL, SIGSTOP};
    for (int how = 0; how < 3; how++) {
        for (int i = 0; i < 3; i++) {
            pid_t pid = fork();
            CHECK(pid >= 0);
            if (pid == 0) {
                int sv[2], r;
                if (setpgid(0, 0) || socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) _exit(2);
                if (how == 0) {
                    r = fcntl(sv[0], F_SETOWN, 1);
                } else if (how == 1) {
                    r = fcntl(sv[0], F_SETOWN, -getpgid(1));
                } else {
                    struct f_owner_ex ex = {.type = F_OWNER_TID, .pid = 1};
                    r = fcntl(sv[0], F_SETOWN_EX, &ex);
                }
                if (r || fcntl(sv[0], F_SETSIG, sigs[i]) || fcntl(sv[0], F_SETFL, O_ASYNC)) _exit(3);
                _exit(write(sv[1], "x", 1) == 1 ? 0 : 4);
            }
            int status;
            CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
    }
    return 0;
}

/// Read exactly `n` bytes.
static int read_all(int fd, char *out, size_t n) {
    for (size_t got = 0; got < n;) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

// nginx serves static files with sendfile to the client's socket.
static int sendfile_out(void) {
    static char want[8192], got[8192];
    int in = open("/proc/self/exe", O_RDONLY);
    struct stat st;
    CHECK(in >= 0 && fstat(in, &st) == 0 && st.st_size > 8192 && pread(in, want, 8192, 0) == 8192);
    // To a socket pair.
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    off_t off = 0;
    CHECK(sendfile(sv[0], in, &off, 4096) == 4096 && off == 4096);
    CHECK(read_all(sv[1], got, 4096) == 0 && memcmp(got, want, 4096) == 0);
    // To a pipe, from the file's offset, which moves.
    int pf[2];
    CHECK(pipe(pf) == 0 && lseek(in, 100, SEEK_SET) == 100);
    CHECK(sendfile(pf[1], in, NULL, 50) == 50 && lseek(in, 0, SEEK_CUR) == 150);
    CHECK(read_all(pf[0], got, 50) == 0 && memcmp(got, want + 100, 50) == 0);
    // To a TCP connection.
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(7002), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int l = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 1) == 0);
    CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    int x = accept(l, NULL, NULL);
    off = 0;
    CHECK(x >= 0 && sendfile(x, in, &off, 8192) == 8192);
    CHECK(read_all(c, got, 8192) == 0 && memcmp(got, want, 8192) == 0);
    // At the end of the file: nothing.
    off = st.st_size;
    CHECK(sendfile(x, in, &off, 100) == 0);
    // To a named pipe.
    CHECK(mkfifo("/tmp/fifo", 0600) == 0);
    int fr = open("/tmp/fifo", O_RDONLY | O_NONBLOCK), fw = open("/tmp/fifo", O_WRONLY);
    off = 0;
    CHECK(fr >= 0 && fw >= 0 && sendfile(fw, in, &off, 1000) == 1000);
    CHECK(read_all(fr, got, 1000) == 0 && memcmp(got, want, 1000) == 0);
    // Nobody to read it.
    signal(SIGPIPE, SIG_IGN);
    close(pf[0]);
    CHECK(sendfile(pf[1], in, NULL, 10) == -1 && errno == EPIPE);
    return 0;
}

// nginx and cargo write with pwritev2; offset -1 is the file's own.
static int rwv2(void) {
    int fd = open("/tmp/v2", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    struct iovec w[2] = {{"hello ", 6}, {"world", 5}};
    CHECK(pwritev2(fd, w, 2, -1, 0) == 11 && lseek(fd, 0, SEEK_CUR) == 11);
    CHECK(pwritev2(fd, w, 1, 0, RWF_DSYNC) == 6 && lseek(fd, 0, SEEK_CUR) == 11);
    // RWF_APPEND: at the end, whatever the offset, which stays.
    CHECK(pwritev2(fd, &w[1], 1, 0, RWF_APPEND) == 5 && lseek(fd, 0, SEEK_CUR) == 11);
    char a[8] = {0}, b[16] = {0};
    struct iovec r[2] = {{a, 6}, {b, 10}};
    CHECK(preadv2(fd, r, 2, 0, 0) == 16 && strcmp(a, "hello ") == 0 && strcmp(b, "worldworld") == 0);
    CHECK(lseek(fd, 6, SEEK_SET) == 6 && preadv2(fd, &r[1], 1, -1, RWF_HIPRI) == 10 && lseek(fd, 0, SEEK_CUR) == 16);
    CHECK(preadv2(fd, r, 1, 0, 0x10000) == -1 && errno == EOPNOTSUPP);
    // RWF_NOWAIT on an empty pipe: EAGAIN, not a wait.
    int pf[2];
    CHECK(pipe(pf) == 0);
    CHECK(preadv2(pf[0], r, 1, -1, RWF_NOWAIT) == -1 && errno == EAGAIN);
    CHECK(preadv2(pf[0], r, 1, 0, 0) == -1 && errno == ESPIPE);
    CHECK(!(fcntl(pf[0], F_GETFL) & O_NONBLOCK));
    return 0;
}

static sigjmp_buf fault_jump;

static void on_fault(int sig) {
    siglongjmp(fault_jump, sig);
}

/// Which signal reading `p` raises (SIGSEGV or SIGBUS), or 0.
static int touch_faults(volatile char *p) {
    struct sigaction sa = {.sa_handler = on_fault}, old_segv, old_bus;
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);
    int sig = sigsetjmp(fault_jump, 1);
    if (sig == 0) {
        (void)*p;
    }
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    return sig;
}

#ifndef SHM_DEST
#define SHM_DEST 01000
#endif

// PostgreSQL's postmaster keeps a small System V segment as an interlock:
// shm_nattch says whether an old server (or its backends) still runs.
static int sysvshm(void) {
    key_t key = 5432001;
    int id = shmget(key, 56, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(id >= 0);
    CHECK(shmget(key, 56, IPC_CREAT | IPC_EXCL | 0600) == -1 && errno == EEXIST);
    CHECK(shmget(key, 0, 0) == id);
    CHECK(shmget(key, 100, 0) == -1 && errno == EINVAL);
    CHECK(shmget(key + 1, 56, 0) == -1 && errno == ENOENT);
    char *a = shmat(id, NULL, 0);
    CHECK(a != (void *)-1);
    struct shmid_ds ds;
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1 && ds.shm_segsz == 56);
    CHECK(ds.shm_perm.__ipc_perm_key == key && (ds.shm_perm.mode & 0777) == 0600 && ds.shm_cpid == getpid());
    strcpy(a, "hello");
    // Another attachment is the same memory.
    char *b = shmat(id, NULL, SHM_RDONLY);
    CHECK(b != (void *)-1 && b != a && strcmp(b, "hello") == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 2);
    CHECK(shmdt(b) == 0 && shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1);
    CHECK(shmdt(b) == -1 && errno == EINVAL);
    // A forked child's attachment counts, and its writes show.
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct shmid_ds d;
        int ok = shmctl(id, IPC_STAT, &d) == 0 && d.shm_nattch == 2;
        strcpy(a, "child");
        _exit(ok ? 0 : 1);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && status == 0 && strcmp(a, "child") == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1);
    // Removed: its key is free at once, its memory stays while attached.
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(shmget(key, 56, 0) == -1 && errno == ENOENT);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && (ds.shm_perm.mode & SHM_DEST));
    CHECK(strcmp(a, "child") == 0 && shmdt(a) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);
    // IPC_PRIVATE is always a new one.
    int p1 = shmget(IPC_PRIVATE, 4096, 0600), p2 = shmget(IPC_PRIVATE, 4096, 0600);
    CHECK(p1 >= 0 && p2 >= 0 && p1 != p2);
    CHECK(shmctl(p1, IPC_RMID, NULL) == 0 && shmctl(p2, IPC_RMID, NULL) == 0);
    // A read-only attach stays read-only, as Linux attaches it without
    // VM_MAYWRITE; and the mode's bits count (this isn't root).
    CHECK(getuid() != 0);
    int ro = shmget(IPC_PRIVATE, 4096, 0400);
    CHECK(ro >= 0);
    CHECK(shmat(ro, NULL, 0) == (void *)-1 && errno == EACCES);
    CHECK(shmat(ro, NULL, SHM_RDONLY | SHM_EXEC) == (void *)-1 && errno == EACCES);
    char *r = shmat(ro, NULL, SHM_RDONLY);
    CHECK(r != (void *)-1);
    CHECK(mprotect(r, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    // /proc/<pid>/maps names it as Linux does.
    char name[32];
    snprintf(name, sizeof name, "/SYSV%08x (deleted)", (unsigned)IPC_PRIVATE);
    CHECK(slurp("/proc/self/maps") > 0 && strstr(buf, name));
    // Past its end (mremap made the mapping longer): SIGBUS.
    char *grown = mremap(r, 4096, 8192, MREMAP_MAYMOVE);
    CHECK(grown != MAP_FAILED);
    CHECK(touch_faults(grown + 4096) == SIGBUS && touch_faults(grown) == 0);
    CHECK(shmdt(grown) == 0 && shmctl(ro, IPC_RMID, NULL) == 0);
    return 0;
}

// Without fs_write the filesystem is read-only, and on Linux a name that
// exists is EEXIST before that's EROFS: `mkdir -p` (busybox's tries "/"
// too) and Python's makedirs stop at existing directories.
static int mkdirexist(void) {
    CHECK(mkdir("/", 0755) == -1 && errno == EEXIST);
    CHECK(mkdir("/tmp", 0755) == -1 && errno == EEXIST);
    CHECK(mkdir("/tmp/.", 0755) == -1 && errno == EEXIST);
    CHECK(mkdir("/proc/self/exe", 0755) == -1 && errno == EEXIST);
    CHECK(mkdir("/nope/x", 0755) == -1 && errno == ENOENT);
    // Something new still needs fs_write.
    CHECK(mkdir("/tmp/new", 0755) == -1 && errno == EPERM);
    return 0;
}

/// A field of `addr`'s mapping in /proc/self/smaps, in kB, or -1.
static long smaps_field(void *addr, const char *field) {
    if (slurp("/proc/self/smaps") <= 0) return -1;
    char head[32];
    snprintf(head, sizeof head, "%lx-", (unsigned long)addr);
    for (char *line = buf; line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (strncmp(line, head, strlen(head)) != 0) continue;
        for (char *f = strchr(line, '\n'); f; f = strchr(f + 1, '\n')) {
            if (strncmp(f + 1, field, strlen(field)) == 0) return strtol(f + 1 + strlen(field), NULL, 10);
            if (strncmp(f + 1, "VmFlags:", 8) == 0) return -1;
        }
    }
    return -1;
}

// Redis checks for an arm64 kernel bug that loses data in a fork's
// background save: a page written after MADV_FREE must show in the
// forked child's /proc/self/smaps as Shared_Dirty. It refuses to start
// if it can't tell.
static int smaps(void) {
    char *p = mmap(NULL, 2 * 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *q = p + 4096;
    CHECK(p != MAP_FAILED && mprotect(q, 4096, PROT_READ | PROT_WRITE) == 0);
    *(volatile char *)q = 1;
    CHECK(madvise(q, 4096, MADV_FREE) == 0);
    *(volatile char *)q = 2;
    int fds[2];
    CHECK(pipe(fds) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        long kb = smaps_field(q, "Shared_Dirty:");
        _exit(write(fds[1], &kb, sizeof kb) == sizeof kb ? 0 : 1);
    }
    long child = -1;
    int status;
    CHECK(read(fds[0], &child, sizeof child) == sizeof child && waitpid(pid, &status, 0) == pid);
    CHECK(child == 4);
    // The child is gone: the page is this process's alone again.
    CHECK(smaps_field(q, "Private_Dirty:") == 4 && smaps_field(q, "Rss:") == 4 && smaps_field(q, "Size:") == 4);
    CHECK(smaps_field(p, "Rss:") == 0 && smaps_field(p, "Size:") == 4);
    CHECK(slurp("/proc/self/smaps_rollup") > 0 && strstr(buf, "[rollup]") && strstr(buf, "\nPss:"));
    return 0;
}

extern char **environ;

// Linux lays out the strings at the top of the stack in order: the
// arguments, then the environment, each ascending and contiguous, then
// the program's name and a zero word. setproctitle code (libuv's, which
// Node and mongosh use; nginx's; PostgreSQL's) rewrites that area,
// measuring it by that order.
static int argvlayout(int argc, char **argv) {
    for (int i = 0; i + 1 < argc; i++) CHECK(argv[i] + strlen(argv[i]) + 1 == argv[i + 1]);
    char *end = argv[argc - 1] + strlen(argv[argc - 1]) + 1;
    int n = 0;
    for (char **e = environ; *e; e++, n++) {
        CHECK(*e == end);
        end = *e + strlen(*e) + 1;
    }
    CHECK(n == 2);
    char *name = (char *)getauxval(AT_EXECFN);
    CHECK(name == end && strcmp(name, "/bin/popular") == 0);
    end = name + strlen(name) + 1;
    unsigned long zero;
    memcpy(&zero, end, sizeof zero);
    CHECK(zero == 0 && ((unsigned long)end + 8) % 4096 == 0);
    return 0;
}

// rsync opens what it copies with openat2 and RESOLVE_*, keeping its walk
// inside the tree it was given.
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
struct how {
    unsigned long long flags, mode, resolve;
};
#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#define RESOLVE_CACHED 0x20

static int o2(int dirfd, const char *path, unsigned long long flags, unsigned long long mode,
              unsigned long long resolve) {
    struct how h = {flags, mode, resolve};
    return syscall(SYS_openat2, dirfd, path, &h, sizeof h);
}

/// openat2 fails with `err` (and so returns -1).
#define FAILS(call, err) CHECK((call) == -1 && errno == (err))
/// openat2 opens something (which is closed again).
#define OPENS(call) do { int fd_ = (call); CHECK(fd_ >= 0); close(fd_); } while (0)

static int openat2_check(void) {
    CHECK(mkdir("/tmp/o2", 0755) == 0 && mkdir("/tmp/o2/d", 0755) == 0);
    int fd = open("/tmp/o2/d/f", O_WRONLY | O_CREAT, 0644);
    CHECK(fd >= 0 && write(fd, "in d", 4) == 4 && close(fd) == 0);
    CHECK(symlink("d/f", "/tmp/o2/rel") == 0);
    CHECK(symlink("/tmp/o2/d/f", "/tmp/o2/abs") == 0);
    CHECK(symlink("../o2/d/f", "/tmp/o2/up") == 0);
    CHECK(symlink("/d/f", "/tmp/o2/rootabs") == 0);
    CHECK(symlink("/tmp/o2/made", "/tmp/o2/dangling") == 0);
    int dir = open("/tmp/o2", O_PATH | O_DIRECTORY);
    CHECK(dir >= 0);

    // The struct: at least version 0's 24 bytes, at most a page, and
    // anything past what the kernel knows zero.
    fd = o2(dir, "d/f", O_RDONLY, 0, 0);
    char got[8] = {0};
    CHECK(fd >= 0 && read(fd, got, sizeof got) == 4 && memcmp(got, "in d", 4) == 0);
    close(fd);
    unsigned long long big[5] = {O_RDONLY, 0, 0, 0, 0};
    OPENS(syscall(SYS_openat2, dir, "d/f", big, sizeof big));
    big[4] = 1;
    FAILS(syscall(SYS_openat2, dir, "d/f", big, sizeof big), E2BIG);
    FAILS(syscall(SYS_openat2, dir, "d/f", big, 16), EINVAL);
    FAILS(syscall(SYS_openat2, dir, "d/f", big, 4097), E2BIG);
    FAILS(syscall(SYS_openat2, dir, "d/f", NULL, 24), EFAULT);
    // Flags are checked, not ignored.
    FAILS(o2(dir, "d/f", O_RDONLY | (1ULL << 40), 0, 0), EINVAL);
    FAILS(o2(dir, "d/f", O_RDONLY, 0, 0x40), EINVAL);
    FAILS(o2(dir, "d/f", O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT), EINVAL);
    FAILS(o2(dir, "d/f", O_RDONLY, 0644, 0), EINVAL);
    FAILS(o2(dir, "d/g", O_RDWR | O_CREAT, 010000, 0), EINVAL);
    FAILS(o2(dir, "d", O_DIRECTORY | O_CREAT, 0644, 0), EINVAL);
    FAILS(o2(dir, "d", O_PATH | O_RDWR, 0, 0), EINVAL);
    OPENS(o2(dir, "d", O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0));

    // RESOLVE_NO_SYMLINKS: none at all, but a last one not followed.
    FAILS(o2(dir, "rel", O_RDONLY, 0, RESOLVE_NO_SYMLINKS), ELOOP);
    OPENS(o2(dir, "rel", O_PATH | O_NOFOLLOW, 0, RESOLVE_NO_SYMLINKS));
    FAILS(o2(dir, "dangling", O_WRONLY | O_CREAT, 0644, RESOLVE_NO_SYMLINKS), ELOOP);
    OPENS(o2(dir, "d/f", O_RDONLY, 0, RESOLVE_NO_SYMLINKS));

    // RESOLVE_BENEATH: never above the directory, nor absolute.
    OPENS(o2(dir, "rel", O_RDONLY, 0, RESOLVE_BENEATH));
    OPENS(o2(dir, "d/../d/f", O_RDONLY, 0, RESOLVE_BENEATH));
    FAILS(o2(dir, "abs", O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    FAILS(o2(dir, "up", O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    FAILS(o2(dir, "../o2/d/f", O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    FAILS(o2(dir, "/tmp/o2/d/f", O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    FAILS(o2(dir, "dangling", O_WRONLY | O_CREAT, 0644, RESOLVE_BENEATH), EXDEV);
    OPENS(o2(dir, "d/new", O_WRONLY | O_CREAT, 0644, RESOLVE_BENEATH));
    OPENS(o2(dir, "d", O_TMPFILE | O_RDWR, 0600, RESOLVE_BENEATH));

    // RESOLVE_IN_ROOT: the directory is "/", and ".." stops there.
    OPENS(o2(dir, "/d/f", O_RDONLY, 0, RESOLVE_IN_ROOT));
    OPENS(o2(dir, "rootabs", O_RDONLY, 0, RESOLVE_IN_ROOT));
    OPENS(o2(dir, "../../d/f", O_RDONLY, 0, RESOLVE_IN_ROOT));
    FAILS(o2(dir, "abs", O_RDONLY, 0, RESOLVE_IN_ROOT), ENOENT);
    FAILS(o2(dir, "rootabs", O_RDONLY, 0, 0), ENOENT);
    OPENS(o2(dir, "/d/made", O_WRONLY | O_CREAT, 0644, RESOLVE_IN_ROOT));
    CHECK(access("/tmp/o2/d/made", F_OK) == 0);

    // RESOLVE_NO_XDEV: /proc and /dev are mounts of their own.
    int root = open("/", O_PATH | O_DIRECTORY);
    CHECK(root >= 0);
    OPENS(o2(root, "tmp/o2/d/f", O_RDONLY, 0, RESOLVE_NO_XDEV));
    FAILS(o2(root, "proc/self/status", O_RDONLY, 0, RESOLVE_NO_XDEV), EXDEV);
    FAILS(o2(AT_FDCWD, "/dev/null", O_RDONLY, 0, RESOLVE_NO_XDEV), EXDEV);
    int proc = open("/proc", O_PATH | O_DIRECTORY);
    CHECK(proc >= 0);
    OPENS(o2(proc, "self/status", O_RDONLY, 0, RESOLVE_NO_XDEV));
    FAILS(o2(proc, "../tmp", O_RDONLY, 0, RESOLVE_NO_XDEV), EXDEV);
    FAILS(o2(proc, "self/exe", O_RDONLY, 0, RESOLVE_NO_XDEV), EXDEV);

    // RESOLVE_NO_MAGICLINKS: /proc/<pid>/{exe,cwd,root,fd/N}, however
    // reached; /proc/self itself is an ordinary link.
    OPENS(o2(AT_FDCWD, "/proc/self/exe", O_RDONLY, 0, 0));
    FAILS(o2(AT_FDCWD, "/proc/self/exe", O_RDONLY, 0, RESOLVE_NO_MAGICLINKS), ELOOP);
    FAILS(o2(AT_FDCWD, "/proc/self/cwd/", O_RDONLY, 0, RESOLVE_NO_MAGICLINKS), ELOOP);
    FAILS(o2(AT_FDCWD, "/proc/self/fd/1", O_WRONLY, 0, RESOLVE_NO_MAGICLINKS), ELOOP);
    FAILS(o2(AT_FDCWD, "/dev/stdout", O_WRONLY, 0, RESOLVE_NO_MAGICLINKS), ELOOP);
    OPENS(o2(AT_FDCWD, "/proc/self/exe", O_PATH | O_NOFOLLOW, 0, RESOLVE_NO_MAGICLINKS));
    OPENS(o2(AT_FDCWD, "/proc/self/status", O_RDONLY, 0, RESOLVE_NO_MAGICLINKS));
    fd = o2(AT_FDCWD, "/dev/stderr", O_WRONLY, 0, 0);
    CHECK(fd >= 0 && write(fd, "via openat2\n", 12) == 12);
    close(fd);
    // Scoped lookups don't follow them at all.
    FAILS(o2(proc, "self/exe", O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    FAILS(o2(proc, "self/fd/1", O_WRONLY, 0, RESOLVE_IN_ROOT), EXDEV);

    // RESOLVE_CACHED: everything here is in memory; creating isn't tried.
    OPENS(o2(dir, "d/f", O_RDONLY, 0, RESOLVE_CACHED));
    FAILS(o2(dir, "d/f", O_RDONLY | O_TRUNC, 0, RESOLVE_CACHED), EAGAIN);
    FAILS(o2(dir, "d/h", O_WRONLY | O_CREAT, 0644, RESOLVE_CACHED), EAGAIN);
    return 0;
}

// Without fs_write: reading as openat would, writing denied (and named).
static int openat2_ro(void) {
    OPENS(o2(AT_FDCWD, "/bin/popular", O_RDONLY, 0, RESOLVE_NO_SYMLINKS));
    FAILS(o2(AT_FDCWD, "/bin/popular", O_WRONLY, 0, 0), EPERM);
    return 0;
}

// Redis raises RLIMIT_NOFILE to what it wants for its clients (and lowered
// maxclients to 992 when the hard limit was 1024).
static int nofile(void) {
    struct rlimit rl;
    CHECK(getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur == 1024 && rl.rlim_max == 65536);
    CHECK(slurp("/proc/self/limits") > 0 && strstr(buf, "Max open files            1024                 65536"));
    CHECK(slurp("/proc/sys/fs/nr_open") > 0 && strcmp(buf, "65536\n") == 0);
    // The soft limit holds: EMFILE, and EBADF/EINVAL for descriptors past it.
    int last = -1, fd;
    while ((fd = dup(0)) >= 0) last = fd;
    CHECK(errno == EMFILE && last == 1023);
    CHECK(dup2(0, 1024) == -1 && errno == EBADF);
    CHECK(fcntl(0, F_DUPFD, 1024) == -1 && errno == EINVAL);
    for (fd = 3; fd <= last; fd++) close(fd);
    // Up to the hard limit, not past it.
    rl.rlim_max = 65537;
    CHECK(setrlimit(RLIMIT_NOFILE, &rl) == -1 && errno == EPERM);
    rl.rlim_cur = rl.rlim_max = 65536;
    CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
    for (fd = 3; fd < 5000; fd++) CHECK(dup(0) == fd);
    CHECK(fcntl(0, F_DUPFD, 60000) == 60000 && dup2(0, 65535) == 65535);
    CHECK(dup2(0, 65536) == -1 && errno == EBADF);
    // /proc/self/fd lists them all, in order (and its own descriptor).
    DIR *d = opendir("/proc/self/fd");
    CHECK(d != NULL);
    struct dirent *e;
    int listed = 0, highest = -1, sorted = 1;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        int n = atoi(e->d_name);
        sorted &= n > highest;
        highest = n;
        listed++;
    }
    closedir(d);
    CHECK(listed == 5003 && highest == 65535 && sorted);
    // poll takes as many as the limit.
    static struct pollfd pfds[5000];
    for (int i = 0; i < 5000; i++) pfds[i] = (struct pollfd){.fd = i, .events = POLLIN};
    CHECK(poll(pfds, 5000, 0) >= 0);
    // A child gets a copy of the table.
    int status;
    pid_t pid = fork();
    if (pid == 0) _exit(fcntl(65535, F_GETFD) == 0 && fcntl(4999, F_GETFD) == 0 ? 0 : 1);
    CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && status == 0);
    // Open files are still limited for all processes together (ENFILE)...
    static int nulls[60000];
    int n = 0;
    while (n < 60000 && (nulls[n] = open("/dev/null", O_RDONLY)) >= 0) n++;
    CHECK(n < 60000 && errno == ENFILE && n > 3000);
    while (n > 0) close(nulls[--n]);
    // ... and tables cost kernel memory: forking a big one, again and
    // again, runs out of it (ENOMEM) before the kernel's heap does.
    int hold[2];
    CHECK(pipe(hold) == 0);
    pid_t kids[64];
    int forked = 0;
    for (; forked < 64; forked++) {
        kids[forked] = fork();
        if (kids[forked] == 0) {
            char c;
            close(hold[1]);
            read(hold[0], &c, 1);
            _exit(0);
        }
        if (kids[forked] < 0) break;
    }
    CHECK(forked < 64 && errno == ENOMEM && forked > 2);
    close(hold[1]);
    for (int i = 0; i < forked; i++) CHECK(waitpid(kids[i], &status, 0) == kids[i]);
    // Closing them all leaves a table that's cheap to copy again.
    for (fd = 3; fd < 65536; fd++) close(fd);
    pid = fork();
    if (pid == 0) _exit(0);
    CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && status == 0);
    return 0;
}

// cp -a and tar --xattrs keep extended attributes (and cp -a reported
// setxattr as unimplemented).
static int xattrs(void) {
    CHECK(mkdir("/tmp/x", 0755) == 0 && mkdir("/tmp/x/d", 0755) == 0);
    int fd = open("/tmp/x/f", O_RDWR | O_CREAT, 0644);
    CHECK(fd >= 0 && symlink("f", "/tmp/x/l") == 0);
    char v[256];
    CHECK(setxattr("/tmp/x/f", "user.a", "one", 3, 0) == 0);
    CHECK(setxattr("/tmp/x/f", "user.b", "", 0, 0) == 0);
    CHECK(getxattr("/tmp/x/f", "user.a", NULL, 0) == 3);
    CHECK(getxattr("/tmp/x/f", "user.a", v, sizeof v) == 3 && memcmp(v, "one", 3) == 0);
    CHECK(getxattr("/tmp/x/f", "user.a", v, 2) == -1 && errno == ERANGE);
    CHECK(getxattr("/tmp/x/f", "user.b", v, sizeof v) == 0);
    CHECK(getxattr("/tmp/x/f", "user.c", v, sizeof v) == -1 && errno == ENODATA);
    CHECK(listxattr("/tmp/x/f", NULL, 0) == 14);
    CHECK(listxattr("/tmp/x/f", v, sizeof v) == 14 && memcmp(v, "user.a\0user.b\0", 14) == 0);
    CHECK(listxattr("/tmp/x/f", v, 13) == -1 && errno == ERANGE);
    // Create, replace, and flags that are neither.
    CHECK(setxattr("/tmp/x/f", "user.a", "two", 3, XATTR_CREATE) == -1 && errno == EEXIST);
    CHECK(setxattr("/tmp/x/f", "user.c", "x", 1, XATTR_REPLACE) == -1 && errno == ENODATA);
    CHECK(setxattr("/tmp/x/f", "user.a", "two", 3, XATTR_REPLACE) == 0);
    CHECK(fgetxattr(fd, "user.a", v, sizeof v) == 3 && memcmp(v, "two", 3) == 0);
    CHECK(setxattr("/tmp/x/f", "user.a", "x", 1, 4) == -1 && errno == EINVAL);
    // Names up to 255 bytes, values up to 64 KiB.
    char name[300] = "user.";
    memset(name + 5, 'n', 250);
    CHECK(setxattr("/tmp/x/d", name, "", 0, 0) == 0);
    name[255] = 'n';
    CHECK(setxattr("/tmp/x/d", name, "", 0, 0) == -1 && errno == ERANGE);
    CHECK(getxattr("/tmp/x/d", name, v, sizeof v) == -1 && errno == ERANGE);
    CHECK(setxattr("/tmp/x/d", "", "", 0, 0) == -1 && errno == ERANGE);
    static char big[65537];
    CHECK(setxattr("/tmp/x/d", "user.big", big, 65536, 0) == 0);
    CHECK(setxattr("/tmp/x/d", "user.big", big, 65537, 0) == -1 && errno == E2BIG);
    CHECK(getxattr("/tmp/x/d", "user.big", big, sizeof big) == 65536);
    CHECK(removexattr("/tmp/x/d", "user.big") == 0);
    // Namespaces: unknown ones, a bare prefix, POSIX ACLs.
    CHECK(setxattr("/tmp/x/f", "other.a", "", 0, 0) == -1 && errno == EOPNOTSUPP);
    CHECK(setxattr("/tmp/x/f", "user.", "", 0, 0) == -1 && errno == EINVAL);
    CHECK(setxattr("/tmp/x/f", "system.posix_acl_access", "", 0, 0) == -1 && errno == EOPNOTSUPP);
    // trusted.* and security.* are root's to set; trusted.* to see.
    CHECK(setxattr("/tmp/x/f", "trusted.a", "", 0, 0) == -1 && errno == EPERM);
    CHECK(getxattr("/tmp/x/f", "trusted.a", v, sizeof v) == -1 && errno == ENODATA);
    CHECK(setxattr("/tmp/x/f", "security.a", "", 0, 0) == -1 && errno == EPERM);
    // user.* only on files and directories; links are followed, or not.
    CHECK(lsetxattr("/tmp/x/l", "user.a", "", 0, 0) == -1 && errno == EPERM);
    CHECK(lgetxattr("/tmp/x/l", "user.a", v, sizeof v) == -1 && errno == ENODATA);
    CHECK(llistxattr("/tmp/x/l", v, sizeof v) == 0);
    CHECK(getxattr("/tmp/x/l", "user.a", v, sizeof v) == 3);
    // Permission to write the file, as for its contents.
    CHECK(chmod("/tmp/x/f", 0444) == 0);
    CHECK(setxattr("/tmp/x/f", "user.c", "", 0, 0) == -1 && errno == EACCES);
    CHECK(chmod("/tmp/x/f", 0644) == 0);
    // Removing; through descriptors; hard links share them.
    CHECK(removexattr("/tmp/x/f", "user.b") == 0);
    CHECK(removexattr("/tmp/x/f", "user.b") == -1 && errno == ENODATA);
    CHECK(fsetxattr(fd, "user.fd", "y", 1, 0) == 0 && fremovexattr(fd, "user.fd") == 0);
    CHECK(flistxattr(fd, v, sizeof v) == 7 && memcmp(v, "user.a\0", 7) == 0);
    CHECK(link("/tmp/x/f", "/tmp/x/h") == 0 && getxattr("/tmp/x/h", "user.a", v, sizeof v) == 3);
    int path = open("/tmp/x/f", O_PATH);
    CHECK(fgetxattr(path, "user.a", v, sizeof v) == -1 && errno == EBADF);
    int pfd[2];
    CHECK(pipe(pfd) == 0);
    CHECK(fsetxattr(pfd[0], "user.a", "", 0, 0) == -1 && errno == EOPNOTSUPP);
    // /proc and /dev keep none.
    CHECK(setxattr("/proc/self/status", "user.a", "", 0, 0) == -1 && errno == EOPNOTSUPP);
    CHECK(listxattr("/proc/self/status", v, sizeof v) == 0);
    CHECK(getxattr("/dev/null", "user.a", v, sizeof v) == -1 && errno == EOPNOTSUPP);
    // They're charged to the filesystem's metadata: ENOSPC, not the
    // kernel's heap, and the room comes back.
    int n = 0;
    for (; n < 4096; n++) {
        snprintf(name, sizeof name, "user.%d", n);
        if (setxattr("/tmp/x/d", name, big, 65536, 0) < 0) break;
    }
    CHECK(n < 4096 && errno == ENOSPC && n > 10);
    for (int i = 0; i < n; i++) {
        snprintf(name, sizeof name, "user.%d", i);
        CHECK(removexattr("/tmp/x/d", name) == 0);
    }
    CHECK(setxattr("/tmp/x/d", "user.again", big, 65536, 0) == 0);
    return 0;
}

// As root (Debian's image): trusted.* and security.capability too, on a
// tree cp -a and tar copy (`xattrcopied` checks the copies).
static const char cap[20] = {0, 0, 0, 2, 0, 4, 0, 0};  // v2: cap_net_bind_service (10)
static int xattrset(void) {
    CHECK(mkdir("/tmp/src", 0755) == 0);
    int fd = open("/tmp/src/f", O_WRONLY | O_CREAT, 0755);
    CHECK(fd >= 0 && write(fd, "data", 4) == 4 && close(fd) == 0);
    CHECK(setxattr("/tmp/src/f", "user.mime_type", "text/plain", 10, 0) == 0);
    CHECK(setxattr("/tmp/src/f", "trusted.t", "t", 1, 0) == 0);
    CHECK(setxattr("/tmp/src/f", "security.capability", "short", 5, 0) == -1 && errno == EINVAL);
    CHECK(setxattr("/tmp/src/f", "security.capability", cap, sizeof cap, 0) == 0);
    CHECK(setxattr("/tmp/src", "user.dir", "d", 1, 0) == 0);
    char v[128];
    CHECK(listxattr("/tmp/src/f", v, sizeof v) == 45);
    return 0;
}

static int copied(const char *dir) {
    char path[64], v[32];
    snprintf(path, sizeof path, "%s/f", dir);
    CHECK(getxattr(path, "user.mime_type", v, sizeof v) == 10 && memcmp(v, "text/plain", 10) == 0);
    CHECK(getxattr(path, "trusted.t", v, sizeof v) == 1 && v[0] == 't');
    CHECK(getxattr(path, "security.capability", v, sizeof v) == 20 && memcmp(v, cap, 20) == 0);
    CHECK(getxattr(dir, "user.dir", v, sizeof v) == 1 && v[0] == 'd');
    return 0;
}

// Without fs_write: reading them, but not setting them.
static int xattrro(void) {
    char v[8];
    CHECK(getxattr("/bin/popular", "user.a", v, sizeof v) == -1 && errno == ENODATA);
    CHECK(setxattr("/bin/popular", "user.a", "", 0, 0) == -1 && errno == EPERM);
    return 0;
}

// The host's directories: a lazy import's file shows none of the host's,
// and setting one makes it the sandbox's; a live mount's keep none.
static int xattrmounts(void) {
    char v[8];
    CHECK(getxattr("/lazy/a", "user.a", v, sizeof v) == -1 && errno == ENODATA);
    CHECK(listxattr("/lazy/a", v, sizeof v) == 0);
    CHECK(removexattr("/lazy/a", "user.a") == -1 && errno == ENODATA);
    CHECK(setxattr("/lazy/a", "user.a", "1", 1, 0) == 0);
    CHECK(getxattr("/lazy/a", "user.a", v, sizeof v) == 1 && v[0] == '1');
    CHECK(slurp("/lazy/a") == 6 && strcmp(buf, "lazy!\n") == 0);
    CHECK(setxattr("/live/a", "user.a", "1", 1, 0) == -1 && errno == EOPNOTSUPP);
    CHECK(getxattr("/live/a", "user.a", v, sizeof v) == -1 && errno == EOPNOTSUPP);
    CHECK(listxattr("/live/a", v, sizeof v) == 0);
    return 0;
}

static int xattrcopied(void) {
    return copied("/tmp/dst") || copied("/tmp/t/src");
}

// Settings programs read and warn about: Redis wants overcommit_memory 1
// (grix takes memory only as it's touched, never reserving it), Chromium
// reads inotify's limits; each says what grix does.
static int sysctls(void) {
    CHECK(slurp("/proc/sys/vm/overcommit_memory") > 0 && strcmp(buf, "1\n") == 0);
    CHECK(slurp("/proc/sys/vm/max_map_count") > 0 && strcmp(buf, "32768\n") == 0);
    CHECK(slurp("/proc/sys/fs/inotify/max_user_watches") > 0 && strcmp(buf, "8192\n") == 0);
    CHECK(slurp("/proc/sys/fs/inotify/max_queued_events") > 0 && strcmp(buf, "16384\n") == 0);
    return 0;
}

// .NET's Thread.Priority asks for the policy's priority range (MSBuild
// sets it on every worker): SCHED_OTHER's is 0..0. Real-time policies
// need CAP_SYS_NICE, which nothing has, as under Docker. (musl's
// sched_setscheduler doesn't make the call: syscall() does.)
static int schedprio(void) {
    CHECK(sched_get_priority_max(SCHED_OTHER) == 0 && sched_get_priority_min(SCHED_OTHER) == 0);
    CHECK(sched_get_priority_max(SCHED_FIFO) == 99 && sched_get_priority_min(SCHED_RR) == 1);
    CHECK(sched_get_priority_max(SCHED_BATCH) == 0 && sched_get_priority_min(SCHED_IDLE) == 0);
    errno = 0;
    CHECK(sched_get_priority_max(42) == -1 && errno == EINVAL);
    struct sched_param sp = {0};
    CHECK(pthread_setschedparam(pthread_self(), SCHED_OTHER, &sp) == 0);
    CHECK(syscall(SYS_sched_setscheduler, 0, SCHED_OTHER, &sp) == 0);
    sp.sched_priority = 10;
    CHECK(syscall(SYS_sched_setscheduler, 0, SCHED_FIFO, &sp) == -1 && errno == EPERM);
    CHECK(syscall(SYS_sched_setparam, 0, &sp) == -1 && errno == EINVAL);
    sp.sched_priority = 0;
    CHECK(syscall(SYS_sched_setscheduler, 0, SCHED_OTHER, &sp) == 0);
    return 0;
}

// NUMA policies (numactl, ClickHouse, .NET, NumPy's allocators): one
// node, 0, so a policy naming it is kept and changes nothing, and one
// naming another node is EINVAL.
static int numa(void) {
    enum { MPOL_DEFAULT, MPOL_PREFERRED, MPOL_BIND, MPOL_INTERLEAVE };
    int mode = -1;
    unsigned long mask[2] = {~0ul, ~0ul};
    CHECK(syscall(SYS_get_mempolicy, &mode, mask, 128, 0, 0) == 0);
    CHECK(mode == MPOL_DEFAULT && mask[0] == 0 && mask[1] == 0);
    CHECK(syscall(SYS_get_mempolicy, &mode, mask, 65, 0, 4 /* MPOL_F_MEMS_ALLOWED */) == 0 && mask[0] == 1);
    unsigned long one = 1, two = 2;
    CHECK(syscall(SYS_set_mempolicy, MPOL_BIND, &two, 64) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_set_mempolicy, MPOL_DEFAULT, &one, 64) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_set_mempolicy, 99, &one, 64) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_set_mempolicy, MPOL_INTERLEAVE, &one, 64) == 0);
    CHECK(syscall(SYS_get_mempolicy, &mode, mask, 65, 0, 0) == 0 && mode == MPOL_INTERLEAVE && mask[0] == 1);
    CHECK(syscall(SYS_get_mempolicy, &mode, NULL, 0, 0, 1 /* MPOL_F_NODE */) == 0 && mode == 0);
    char *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED);
    CHECK(syscall(SYS_mbind, p, 8192, MPOL_BIND, &one, 64, 0) == 0);
    CHECK(syscall(SYS_get_mempolicy, &mode, NULL, 0, p, 3 /* MPOL_F_NODE | MPOL_F_ADDR */) == 0 && mode == 0);
    CHECK(syscall(SYS_mbind, p + 1, 4096, MPOL_BIND, &one, 64, 0) == -1 && errno == EINVAL);
    munmap(p + 4096, 4096);
    CHECK(syscall(SYS_mbind, p, 8192, MPOL_BIND, &one, 64, 0) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_get_mempolicy, &mode, NULL, 0, p + 4096, 2 /* MPOL_F_ADDR */) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_set_mempolicy, MPOL_DEFAULT, NULL, 0) == 0);
    CHECK(syscall(SYS_get_mempolicy, &mode, NULL, 0, 0, 1) == -1 && errno == EINVAL);
    munmap(p, 4096);
    return 0;
}

// prctl options Linux refuses here too, quietly: PR_SET_MM (some JDKs'
// setproctitle) needs CAP_SYS_RESOURCE; there's no SVE; and an option
// Linux doesn't have (OpenSearch's seccomp self-test) is EINVAL.
static int prctls(void) {
    char arg[] = "x";
    CHECK(prctl(35 /* PR_SET_MM */, 8 /* PR_SET_MM_ARG_START */, (unsigned long)arg, 0, 0) == -1 && errno == EPERM);
    CHECK(prctl(51 /* PR_SVE_GET_VL */, 0, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_prctl, 0xfffffffff7a46a5cul, 0, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_prctl, 0x100000000ul | PR_GET_DUMPABLE, 0, 0, 0, 0) == 1);
    return 0;
}

// /proc/<pid>/task: a directory per thread. Chromium's zygote checks that
// it's alone by the link count (2 + threads); ps -L and psutil list it.
static pthread_mutex_t task_mu = PTHREAD_MUTEX_INITIALIZER;
static void *task_park(void *arg) {
    *(pid_t *)arg = gettid();
    pthread_mutex_lock(&task_mu);
    pthread_mutex_unlock(&task_mu);
    return NULL;
}

static int task_count(void) {
    struct stat st;
    if (stat("/proc/self/task", &st) != 0 || !S_ISDIR(st.st_mode)) return -1;
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    for (struct dirent *e; (e = readdir(d));) n += e->d_name[0] != '.';
    closedir(d);
    return st.st_nlink == (nlink_t)n + 2 ? n : -1;
}

static int tasks(void) {
    CHECK(task_count() == 1);
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", getpid());
    CHECK(slurp(path) > 0 && atoi(buf) == getpid());
    pthread_mutex_lock(&task_mu);
    pthread_t t[2];
    volatile pid_t tid[2] = {0, 0};
    for (int i = 0; i < 2; i++) CHECK(pthread_create(&t[i], NULL, task_park, (void *)&tid[i]) == 0);
    while (!tid[0] || !tid[1]) sched_yield();
    CHECK(task_count() == 3);
    snprintf(path, sizeof path, "/proc/%d/task/%d/comm", getpid(), tid[1]);
    CHECK(slurp(path) > 0 && strcmp(buf, "popular\n") == 0);
    snprintf(path, sizeof path, "/proc/self/task/%d/status", tid[0]);
    CHECK(slurp(path) > 0 && strstr(buf, "Threads:\t3\n"));
    pthread_mutex_unlock(&task_mu);
    for (int i = 0; i < 2; i++) CHECK(pthread_join(t[i], NULL) == 0);
    CHECK(task_count() == 1);
    snprintf(path, sizeof path, "/proc/self/task/%d", tid[0]);
    struct stat st;
    CHECK(stat(path, &st) == -1 && errno == ENOENT);
    return 0;
}

// SO_PASSCRED: a message socket's messages come with SCM_CREDENTIALS, the
// sender's (Chromium's zygote learns its children's pids so).
static int recv_cred(int s, struct ucred *uc, char *data) {
    char control[CMSG_SPACE(sizeof(struct ucred))];
    struct iovec iov = {data, 16};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control};
    ssize_t n = recvmsg(s, &m, 0);
    if (n < 0) return -1;
    data[n] = 0;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c) return 0;
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS || c->cmsg_len != CMSG_LEN(sizeof *uc)) return -1;
    memcpy(uc, CMSG_DATA(c), sizeof *uc);
    return 1;
}

static int passcred(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
    int on = 1, v = -1;
    socklen_t len = sizeof v;
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &v, &len) == 0 && v == 0);
    // Without it, no credentials.
    struct ucred uc;
    char data[17];
    CHECK(write(sv[1], "a", 1) == 1);
    CHECK(recv_cred(sv[0], &uc, data) == 0 && strcmp(data, "a") == 0);
    CHECK(setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &on, sizeof on) == 0);
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &v, &len) == 0 && v == 1);
    pid_t child = fork();
    if (child == 0) _exit(write(sv[1], "ping", 4) == 4 ? 0 : 1);
    CHECK(child > 0);
    CHECK(recv_cred(sv[0], &uc, data) == 1 && strcmp(data, "ping") == 0);
    CHECK(uc.pid == child && uc.uid == getuid() && uc.gid == getgid());
    int st;
    CHECK(waitpid(child, &st, 0) == child && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    // A sender may say who it is, within its own ids.
    struct ucred mine = {getpid(), getuid(), getgid()};
    char control[CMSG_SPACE(sizeof mine)] = {0};
    struct iovec iov = {"me", 2};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control};
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_CREDENTIALS;
    c->cmsg_len = CMSG_LEN(sizeof mine);
    memcpy(CMSG_DATA(c), &mine, sizeof mine);
    CHECK(sendmsg(sv[1], &m, 0) == 2);
    CHECK(recv_cred(sv[0], &uc, data) == 1 && uc.pid == getpid() && strcmp(data, "me") == 0);
    // No room for them: cut off.
    char small[8];
    struct iovec iov2 = {data, 16};
    struct msghdr m2 = {.msg_iov = &iov2, .msg_iovlen = 1, .msg_control = small, .msg_controllen = sizeof small};
    CHECK(write(sv[1], "b", 1) == 1);
    CHECK(recvmsg(sv[0], &m2, 0) == 1 && (m2.msg_flags & MSG_CTRUNC) && m2.msg_controllen == 0);
    close(sv[0]);
    close(sv[1]);
    return 0;
}

// SO_PASSCRED on a stream: each read is one writer's bytes, with their
// credentials, as Linux never glues different writers' together then;
// without it, reads go across. Set before connecting, or on a listener
// (which its accepted sockets inherit), it stays.
static int streamcred(void) {
    int sv[2], st;
    struct ucred uc;
    char data[17];
    for (int pass = 0; pass < 2; pass++) {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        int on = 1, v = -1;
        socklen_t len = sizeof v;
        if (pass) CHECK(setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &on, sizeof on) == 0);
        CHECK(getsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &v, &len) == 0 && v == pass);
        CHECK(write(sv[1], "aa", 2) == 2);
        pid_t child = fork();
        if (child == 0) _exit(write(sv[1], "bbb", 3) == 3 ? 0 : 1);
        CHECK(waitpid(child, &st, 0) == child && WIFEXITED(st) && WEXITSTATUS(st) == 0);
        CHECK(write(sv[1], "c", 1) == 1 && write(sv[1], "d", 1) == 1);
        if (!pass) {
            CHECK(recv_cred(sv[0], &uc, data) == 0 && strcmp(data, "aabbbcd") == 0);
        } else {
            CHECK(recv_cred(sv[0], &uc, data) == 1 && strcmp(data, "aa") == 0 && uc.pid == getpid());
            CHECK(uc.uid == getuid() && uc.gid == getgid());
            // Peeking doesn't go further, and two buffers don't either.
            CHECK(recv(sv[0], data, 16, MSG_PEEK) == 3);
            char a[2], b[8];
            struct iovec iov[2] = {{a, 2}, {b, 8}};
            char control[CMSG_SPACE(sizeof uc)];
            struct msghdr m = {.msg_iov = iov, .msg_iovlen = 2, .msg_control = control, .msg_controllen = sizeof control};
            CHECK(recvmsg(sv[0], &m, 0) == 3 && !memcmp(a, "bb", 2) && b[0] == 'b');
            memcpy(&uc, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof uc);
            CHECK(uc.pid == child);
            // Same writer twice: one read. read() stops at writers too.
            CHECK(write(sv[1], "e", 1) == 1);
            CHECK(read(sv[0], data, 16) == 3 && !memcmp(data, "cde", 3));
        }
        close(sv[0]);
        close(sv[1]);
    }
    // Before connecting, and inherited from a listener.
    int l = socket(AF_UNIX, SOCK_STREAM, 0), c = socket(AF_UNIX, SOCK_STREAM, 0), on = 1, v = 0;
    socklen_t len = sizeof v;
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    memcpy(sa.sun_path, "\0streamcred", 11);
    socklen_t salen = offsetof(struct sockaddr_un, sun_path) + 11;
    CHECK(bind(l, (void *)&sa, salen) == 0 && listen(l, 1) == 0);
    CHECK(setsockopt(l, SOL_SOCKET, SO_PASSCRED, &on, sizeof on) == 0);
    CHECK(setsockopt(c, SOL_SOCKET, SO_PASSCRED, &on, sizeof on) == 0);
    CHECK(connect(c, (void *)&sa, salen) == 0);
    int a = accept(l, NULL, NULL);
    CHECK(a >= 0);
    CHECK(getsockopt(a, SOL_SOCKET, SO_PASSCRED, &v, &len) == 0 && v == 1);
    v = 0;
    CHECK(getsockopt(c, SOL_SOCKET, SO_PASSCRED, &v, &len) == 0 && v == 1);
    // A sender may say who it is (within its own ids), on a stream too.
    struct ucred mine = {getpid(), getuid(), getgid()};
    char control[CMSG_SPACE(sizeof mine)] = {0};
    struct iovec iov = {"me", 2};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control};
    struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_CREDENTIALS;
    cm->cmsg_len = CMSG_LEN(sizeof mine);
    memcpy(CMSG_DATA(cm), &mine, sizeof mine);
    CHECK(sendmsg(c, &m, 0) == 2);
    CHECK(recv_cred(a, &uc, data) == 1 && uc.pid == getpid() && strcmp(data, "me") == 0);
    mine.pid = 1;
    memcpy(CMSG_DATA(cm), &mine, sizeof mine);
    CHECK(getpid() == 1 || (sendmsg(c, &m, 0) == -1 && errno == EPERM));
    close(a);
    close(c);
    close(l);
    return 0;
}

// capset: nothing has a capability, so dropping them all is allowed
// (Chromium's zygote does before it forks); raising one is denied.
struct cap_header { unsigned version; int pid; };
struct cap_data { unsigned effective, permitted, inheritable; };
static int capdrop(void) {
    struct cap_header h = {0x20080522, 0};
    struct cap_data d[2] = {{0}};
    CHECK(syscall(SYS_capget, &h, d) == 0 && d[0].effective == 0 && d[0].permitted == 0);
    CHECK(syscall(SYS_capset, &h, d) == 0);
    h.pid = getpid() + 1000;
    CHECK(syscall(SYS_capset, &h, d) == -1 && errno == EPERM);
    h = (struct cap_header){0x12345678, 0};
    CHECK(syscall(SYS_capset, &h, d) == -1 && errno == EINVAL && h.version == 0x20080522);
    h.pid = 0;
    d[0].effective = d[0].permitted = 1 << 10;  // CAP_NET_BIND_SERVICE
    CHECK(syscall(SYS_capset, &h, d) == -1 && errno == EPERM);
    return 0;
}

// ---- Round 3: what the hardening and old limits kept from real programs

/// An O_PATH descriptor opened again through its magic link is a new open,
/// and can do what the descriptor can't (runc, systemd, libpathrs, and
/// Python's listdir of the link), as a write-only O_TMPFILE read back.
static int reopen(void) {
    char link[64], got[16];
    CHECK(mkdir("/tmp/re", 0755) == 0 && mkdir("/tmp/re/d", 0755) == 0);
    int fd = open("/tmp/re/f", O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0 && write(fd, "hello", 5) == 5 && close(fd) == 0);
    CHECK(close(open("/tmp/re/d/g", O_CREAT | O_WRONLY, 0644)) == 0);
    int path = open("/tmp/re/f", O_PATH), dir = open("/tmp/re/d", O_PATH | O_DIRECTORY);
    CHECK(path >= 0 && dir >= 0 && read(path, got, 1) == -1 && errno == EBADF);
    snprintf(link, sizeof link, "/proc/self/fd/%d", path);
    int r = open(link, O_RDONLY);
    CHECK(r >= 0 && !(fcntl(r, F_GETFL) & O_PATH));
    CHECK(read(r, got, 5) == 5 && memcmp(got, "hello", 5) == 0);
    // Each with its own offset.
    int r2 = open(link, O_RDONLY);
    CHECK(r2 >= 0 && read(r2, got, 1) == 1 && got[0] == 'h');
    int w = open(link, O_WRONLY | O_APPEND);
    CHECK(w >= 0 && write(w, "!", 1) == 1 && read(r, got, 1) == 1 && got[0] == '!');
    CHECK(open(link, O_RDONLY | O_DIRECTORY) == -1 && errno == ENOTDIR);
    // A file, so it's looked at as one: no reference to what's open.
    CHECK(chmod("/tmp/re/f", 0) == 0);
    int root = geteuid() == 0;
    CHECK(!root || seteuid(1000) == 0);
    CHECK(open(link, O_RDONLY) == -1 && errno == EACCES);
    CHECK(!root || seteuid(0) == 0);
    snprintf(link, sizeof link, "/proc/self/fd/%d", dir);
    DIR *d = opendir(link);
    CHECK(d != NULL);
    int seen = 0;
    for (struct dirent *e; (e = readdir(d));) seen += strcmp(e->d_name, "g") == 0;
    CHECK(seen == 1 && closedir(d) == 0);
    CHECK(open(link, O_WRONLY) == -1 && errno == EISDIR);
    int t = open("/tmp/re", O_TMPFILE | O_WRONLY, 0600);
    CHECK(t >= 0 && write(t, "x", 1) == 1);
    snprintf(link, sizeof link, "/proc/self/fd/%d", t);
    int back = open(link, O_RDONLY);
    CHECK(back >= 0 && read(back, got, 1) == 1 && got[0] == 'x');
    // readlinkat with an empty path: the link the descriptor holds.
    CHECK(symlink("f", "/tmp/re/l") == 0);
    int l = open("/tmp/re/l", O_PATH | O_NOFOLLOW);
    CHECK(l >= 0 && readlinkat(l, "", got, sizeof got) == 1 && got[0] == 'f');
    CHECK(readlinkat(path, "", got, sizeof got) == -1 && errno == EINVAL);
    CHECK(readlinkat(AT_FDCWD, "", got, sizeof got) == -1 && errno == ENOENT);
    return 0;
}

static void nothing(int sig) { (void)sig; }

/// No page for a signal frame ends the program as a fault with no page
/// does: there's nothing wrong with its stack. Returns only on failure.
static int framemem(void) {
    size_t big = 1UL << 32;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    char *p = mmap(NULL, big, PROT_READ | PROT_WRITE, flags, -1, 0), *alt = mmap(NULL, 1 << 16, PROT_READ | PROT_WRITE, flags, -1, 0);
    CHECK(p != MAP_FAILED && alt != MAP_FAILED);
    stack_t ss = {.ss_sp = alt, .ss_size = 1 << 16};
    struct sigaction sa = {.sa_handler = nothing, .sa_flags = SA_ONSTACK};
    CHECK(sigaltstack(&ss, NULL) == 0 && sigaction(SIGUSR1, &sa, NULL) == 0);
    int zero = open("/dev/zero", O_RDONLY);
    // read says so where touching the pages would be the end of it.
    size_t at = 0;
    for (size_t step = 1 << 20; step >= 4096; step /= 2) {
        ssize_t r;
        while (at + step <= big && (r = read(zero, p + at, step)) > 0) at += r;
    }
    raise(SIGUSR1);
    printf("FAILED: the handler ran with no memory left\n");
    return 1;
}

/// Go's io.Copy between sockets waits in splice, a pipe for each connection:
/// none of them may hold room for what hasn't come.
static int spliceidle(void) {
    struct rlimit rl = {16384, 16384};
    CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
    int sv[2], pf[2];
    for (int i = 0; i < 1500; i++) {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && pipe(pf) == 0);
        CHECK(splice(sv[0], NULL, pf[1], NULL, 65536, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
    }
    char b[4096] = {0};
    CHECK(write(sv[1], "x", 1) == 1 && splice(sv[0], NULL, pf[1], NULL, 65536, SPLICE_F_NONBLOCK) == 1);
    CHECK(read(pf[0], b, sizeof b) == 1 && b[0] == 'x');
    CHECK(fcntl(pf[1], F_SETFL, O_NONBLOCK) == 0);
    for (int i = 0; i < 16; i++) CHECK(write(pf[1], b, sizeof b) == sizeof b);
    return 0;
}

/// Thousands of open files in all, of more than one kind.
static int openfiles(void) {
    struct rlimit rl = {32768, 32768};
    CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
    FILE *f = fopen("/proc/sys/fs/file-max", "r");
    long max = 0;
    CHECK(f != NULL && fscanf(f, "%ld", &max) == 1 && max >= 12000 && fclose(f) == 0);
    int pf[2];
    for (int i = 0; i < 5000; i++) CHECK(pipe(pf) == 0);
    for (int i = 0; i < 2000; i++) CHECK(timerfd_create(CLOCK_MONOTONIC, 0) >= 0);
    return 0;
}

static void *accept_later(void *arg) {
    int l = *(int *)arg;
    usleep(100000);
    for (int i = 0; i < 3000; i++)
        if (accept(l, NULL, NULL) < 0) return (void *)1;
    return NULL;
}

/// More connects at once than the backlog: on Linux they wait for accept,
/// and none is refused.
static int burst(void) {
    struct rlimit rl = {16384, 16384};
    CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(7010), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 8) == 0);
    pthread_t t;
    CHECK(pthread_create(&t, NULL, accept_later, &l) == 0);
    for (int i = 0; i < 3000; i++) {
        int c = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(c >= 0 && connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    }
    void *failed;
    CHECK(pthread_join(t, &failed) == 0 && failed == NULL);
    return 0;
}

/// As much as glibc's sysconf(_SC_ARG_MAX) says, as `find -exec {} +`
/// passes, and no more: strings and their pointers count. Ends in
/// "argmaxed".
static int argmax(char *self) {
    enum { LEN = 100, OK = 18000, OVER = 25000 };
    char **args = calloc(OVER + 3, sizeof *args), *one = malloc(LEN + 1);
    CHECK(args != NULL && one != NULL);
    memset(one, 'x', LEN);
    one[LEN] = 0;
    args[0] = self;
    args[1] = "argmaxed";
    for (int i = 2; i < OVER + 2; i++) args[i] = one;
    CHECK(execv(self, args) == -1 && errno == E2BIG);
    args[OK + 2] = NULL;
    execv(self, args);
    CHECK(0);
}

/// More files than 12 MiB of names and nodes hold.
static int manyfiles(void) {
    char name[64];
    CHECK(mkdir("/tmp/many", 0755) == 0);
    for (int i = 0; i < 50000; i++) {
        snprintf(name, sizeof name, "/tmp/many/file-%d", i);
        int fd = open(name, O_CREAT | O_WRONLY, 0644);
        CHECK(fd >= 0 && close(fd) == 0);
    }
    DIR *d = opendir("/tmp/many");
    CHECK(d != NULL);
    int seen = 0;
    while (readdir(d)) seen++;
    CHECK(seen == 50002 && closedir(d) == 0);
    return 0;
}

/// What a big image leaves is the program's: `touch` touches this much.
static int touch(void) {
    size_t n = 140 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED);
    memset(p, 1, n);
    return 0;
}

/// A server behind a forwarded port, past what 256 connections were: each
/// answers a byte and stays open.
static int manyconns(void) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(8100), .sin_addr.s_addr = htonl(INADDR_ANY)};
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 128) == 0);
    // Only the test's count: tools on the host probe new ports.
    for (int i = 0; i < 400;) {
        int c = accept(l, NULL, NULL);
        char b;
        CHECK(c >= 0);
        if (read(c, &b, 1) == 1 && b == 'x') {
            CHECK(write(c, &b, 1) == 1);
            i++;
        } else {
            close(c);
        }
    }
    return 0;
}

#define FUTEX_WAIT_SHARED 0
#define FUTEX_WAKE_SHARED 1
#define FUTEX_CMP_REQUEUE_SHARED 4

static long fx(unsigned *w, int op, unsigned val, const struct timespec *t, unsigned *w2, unsigned val3) {
    return syscall(SYS_futex, w, op, val, t, w2, val3);
}

/// A child waits on `w` (`on`'s word, in its own mapping or not): wake it
/// from here. Whether it's got there yet only the wake's count says.
static int wake_child(unsigned *w, pid_t child) {
    int status;
    long woken = 0;
    for (int i = 0; i < 5000 && woken == 0; i++) {
        woken = fx(w, FUTEX_WAKE_SHARED, 1, NULL, NULL, 0);
        if (woken == 0) usleep(1000);
    }
    return woken == 1 && waitpid(child, &status, 0) == child && status == 0;
}

/// Futex words processes share: found by what they're in, wherever each
/// process has them.
static int pshared(void) {
    // Semaphores, ping-pong: PostgreSQL's LWLocks, Python's multiprocessing.
    int prot = PROT_READ | PROT_WRITE;
    sem_t *s = mmap(NULL, 4096, prot, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(s != MAP_FAILED && sem_init(&s[0], 1, 0) == 0 && sem_init(&s[1], 1, 0) == 0);
    pid_t pid = fork();
    if (pid == 0) {
        for (int i = 0; i < 2000; i++) {
            sem_wait(&s[0]);
            sem_post(&s[1]);
        }
        _exit(0);
    }
    for (int i = 0; i < 2000; i++) {
        CHECK(sem_post(&s[0]) == 0 && sem_wait(&s[1]) == 0);
    }
    int status;
    CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && status == 0);
    // A process-shared mutex and condition variable.
    struct both { pthread_mutex_t m; pthread_cond_t c; int turn; } *b = mmap(NULL, 4096, prot, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(b != MAP_FAILED);
    pthread_mutexattr_t ma;
    pthread_condattr_t ca;
    CHECK(pthread_mutexattr_init(&ma) == 0 && pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_condattr_init(&ca) == 0 && pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED) == 0);
    CHECK(pthread_mutex_init(&b->m, &ma) == 0 && pthread_cond_init(&b->c, &ca) == 0);
    pid = fork();
    if (pid == 0) {
        pthread_mutex_lock(&b->m);
        for (int i = 0; i < 500; i++) {
            while (b->turn != 1) pthread_cond_wait(&b->c, &b->m);
            b->turn = 0;
            pthread_cond_broadcast(&b->c);
        }
        pthread_mutex_unlock(&b->m);
        _exit(0);
    }
    pthread_mutex_lock(&b->m);
    for (int i = 0; i < 500; i++) {
        b->turn = 1;
        pthread_cond_broadcast(&b->c);
        while (b->turn != 0) pthread_cond_wait(&b->c, &b->m);
    }
    pthread_mutex_unlock(&b->m);
    CHECK(waitpid(pid, &status, 0) == pid && status == 0);
    // A file's word, at another address in each process.
    int fd = open("/tmp/futexword", O_CREAT | O_RDWR, 0600);
    CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
    unsigned *here = mmap(NULL, 4096, prot, MAP_SHARED, fd, 0);
    CHECK(here != MAP_FAILED);
    pid = fork();
    if (pid == 0) {
        unsigned *there = mmap(NULL, 4096, prot, MAP_SHARED, fd, 0);
        _exit(there != here && there != MAP_FAILED && fx(there, FUTEX_WAIT_SHARED, 0, NULL, NULL, 0) == 0 ? 0 : 1);
    }
    CHECK(pid > 0 && wake_child(here, pid));
    // A System V segment's, likewise.
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    unsigned *seg = shmat(id, NULL, 0);
    CHECK(id >= 0 && seg != (void *)-1);
    pid = fork();
    if (pid == 0) {
        unsigned *other = shmat(id, NULL, 0);
        _exit(other != seg && other != (void *)-1 && fx(other, FUTEX_WAIT_SHARED, 0, NULL, NULL, 0) == 0 ? 0 : 1);
    }
    CHECK(pid > 0 && wake_child(seg, pid));
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    // Moved to another word, still in another process.
    unsigned *w = (unsigned *)s + 512;
    pid = fork();
    if (pid == 0) _exit(fx(w, FUTEX_WAIT_SHARED, 0, NULL, NULL, 0) == 0 ? 0 : 1);
    long moved = 0;
    for (int i = 0; i < 5000 && moved == 0; i++) {
        moved = fx(w, FUTEX_CMP_REQUEUE_SHARED, 0, (void *)1L, w + 1, 0);
        if (moved == 0) usleep(1000);
    }
    CHECK(moved == 1 && pid > 0 && wake_child(w + 1, pid));
    // A wait that timed out, or was killed, has left the queue.
    struct timespec soon = {0, 5000000};
    CHECK(fx(w, FUTEX_WAIT_SHARED, 0, &soon, NULL, 0) == -1 && errno == ETIMEDOUT);
    CHECK(fx(w, FUTEX_WAKE_SHARED, 1, NULL, NULL, 0) == 0);
    pid = fork();
    if (pid == 0) _exit(fx(w, FUTEX_WAIT_SHARED, 0, NULL, NULL, 0) == 0 ? 3 : 4);
    usleep(50000);
    CHECK(pid > 0 && kill(pid, SIGKILL) == 0 && waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status) && fx(w, FUTEX_WAKE_SHARED, 1, NULL, NULL, 0) == 0);
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        int r = 1;
        if (strcmp(argv[i], "auxv") == 0) r = auxv();
        if (strcmp(argv[i], "fdlink") == 0) r = fdlink();
        if (strcmp(argv[i], "v6only") == 0) r = v6only();
        if (strcmp(argv[i], "smaps") == 0) r = smaps();
        if (strcmp(argv[i], "anyaddr") == 0) r = anyaddr();
        if (strcmp(argv[i], "cacheflush") == 0) r = cacheflush();
        if (strcmp(argv[i], "udproute") == 0) r = udproute();
        if (strcmp(argv[i], "hostname") == 0) r = hostname();
        if (strcmp(argv[i], "sigio") == 0) r = sigio();
        if (strcmp(argv[i], "sigioinit") == 0) r = sigioinit();
        if (strcmp(argv[i], "sendfile") == 0) r = sendfile_out();
        if (strcmp(argv[i], "rwv2") == 0) r = rwv2();
        if (strcmp(argv[i], "sysvshm") == 0) r = sysvshm();
        if (strcmp(argv[i], "mkdirexist") == 0) r = mkdirexist();
        if (strcmp(argv[i], "openat2") == 0) r = openat2_check();
        if (strcmp(argv[i], "openat2ro") == 0) r = openat2_ro();
        if (strcmp(argv[i], "nofile") == 0) r = nofile();
        if (strcmp(argv[i], "xattrs") == 0) r = xattrs();
        if (strcmp(argv[i], "xattrset") == 0) r = xattrset();
        if (strcmp(argv[i], "xattrro") == 0) r = xattrro();
        if (strcmp(argv[i], "xattrmounts") == 0) r = xattrmounts();
        if (strcmp(argv[i], "xattrcopied") == 0) r = xattrcopied();
        if (strcmp(argv[i], "sysctls") == 0) r = sysctls();
        if (strcmp(argv[i], "schedprio") == 0) r = schedprio();
        if (strcmp(argv[i], "numa") == 0) r = numa();
        if (strcmp(argv[i], "prctls") == 0) r = prctls();
        if (strcmp(argv[i], "tasks") == 0) r = tasks();
        if (strcmp(argv[i], "passcred") == 0) r = passcred();
        if (strcmp(argv[i], "streamcred") == 0) r = streamcred();
        if (strcmp(argv[i], "capdrop") == 0) r = capdrop();
        if (strcmp(argv[i], "reopen") == 0) r = reopen();
        if (strcmp(argv[i], "framemem") == 0) r = framemem();
        if (strcmp(argv[i], "spliceidle") == 0) r = spliceidle();
        if (strcmp(argv[i], "openfiles") == 0) r = openfiles();
        if (strcmp(argv[i], "burst") == 0) r = burst();
        if (strcmp(argv[i], "argmax") == 0) r = argmax(argv[0]);
        if (strcmp(argv[i], "manyfiles") == 0) r = manyfiles();
        if (strcmp(argv[i], "touch") == 0) r = touch();
        if (strcmp(argv[i], "manyconns") == 0) r = manyconns();
        if (strcmp(argv[i], "pshared") == 0) r = pshared();
        // The arguments after it are only there to be counted.
        if (strcmp(argv[i], "argmaxed") == 0) {
            printf("argmax %s\n", argc == 18002 ? "ok" : "failed");
            return argc != 18002;
        }
        // The arguments after it are only there to be laid out.
        if (strcmp(argv[i], "argvlayout") == 0) {
            r = argvlayout(argc, argv);
            printf("%s %s\n", argv[i], r ? "failed" : "ok");
            return r;
        }
        if (r) {
            printf("%s failed\n", argv[i]);
            return 1;
        }
        printf("%s ok\n", argv[i]);
    }
    return 0;
}
