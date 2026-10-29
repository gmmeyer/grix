// What popular software expects of Linux, found running it in grix (see
// COMPAT.md): one check per argument.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        int r = 1;
        if (strcmp(argv[i], "auxv") == 0) r = auxv();
        if (strcmp(argv[i], "fdlink") == 0) r = fdlink();
        if (strcmp(argv[i], "v6only") == 0) r = v6only();
        if (strcmp(argv[i], "smaps") == 0) r = smaps();
        if (strcmp(argv[i], "anyaddr") == 0) r = anyaddr();
        if (r) {
            printf("%s failed\n", argv[i]);
            return 1;
        }
        printf("%s ok\n", argv[i]);
    }
    return 0;
}
