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

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        int r = 1;
        if (strcmp(argv[i], "auxv") == 0) r = auxv();
        if (r) {
            printf("%s failed\n", argv[i]);
            return 1;
        }
        printf("%s ok\n", argv[i]);
    }
    return 0;
}
