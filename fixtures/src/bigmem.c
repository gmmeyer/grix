// Guests bigger than 3 GiB: memory and files past what fit before.
//   bigmem mem MIB        touch MIB of private memory, then check it
//   bigmem shared MIB     MAP_SHARED memory a child fills and the parent checks
//   bigmem file MIB PATH  write a MIB file and read it back; a sparse file;
//                         then fill PATH.fill until ENOSPC and say how much fit
//   bigmem wait MIB       fill MIB, read a line from stdin, check, echo it
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); exit(1); } } while (0)

static uint64_t word(uint64_t page, int k) {
    return (page + 1) * 0x9e3779b97f4a7c15ull ^ (uint64_t)k << 56;
}

// Three words of each page: its start, middle and end.
static void fill(unsigned char *p, size_t len) {
    for (size_t off = 0; off < len; off += 4096) {
        uint64_t *w = (uint64_t *)(p + off), page = off / 4096;
        w[0] = word(page, 0);
        w[256] = word(page, 1);
        w[511] = word(page, 2);
    }
}

static size_t check(const unsigned char *p, size_t len) {
    size_t bad = 0;
    for (size_t off = 0; off < len; off += 4096) {
        const uint64_t *w = (const uint64_t *)(p + off), page = off / 4096;
        if (w[0] != word(page, 0) || w[256] != word(page, 1) || w[511] != word(page, 2) || w[1] != 0) bad++;
    }
    return bad;
}

static unsigned char *map(size_t len, int flags) {
    unsigned char *p = mmap(0, len, PROT_READ | PROT_WRITE, flags | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED);
    return p;
}

static void file_mode(size_t len, const char *path) {
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    CHECK(fd >= 0);
    size_t chunk = 1 << 20;
    unsigned char *buf = malloc(chunk);
    CHECK(buf);
    for (size_t at = 0; at < len; at += chunk) {
        memset(buf, 0, chunk);
        for (size_t off = 0; off < chunk; off += 4096) {
            uint64_t *w = (uint64_t *)(buf + off), page = (at + off) / 4096;
            w[0] = word(page, 0), w[256] = word(page, 1), w[511] = word(page, 2);
        }
        CHECK(write(fd, buf, chunk) == (ssize_t)chunk);
    }
    CHECK(lseek(fd, 0, SEEK_END) == (off_t)len);
    size_t bad = 0;
    for (size_t at = 0; at < len; at += chunk) {
        CHECK(pread(fd, buf, chunk, at) == (ssize_t)chunk);
        for (size_t off = 0; off < chunk; off += 4096) {
            uint64_t *w = (uint64_t *)(buf + off), page = (at + off) / 4096;
            if (w[0] != word(page, 0) || w[256] != word(page, 1) || w[511] != word(page, 2)) bad++;
        }
    }
    printf("file %zu MiB, %zu bad pages\n", len >> 20, bad);
    close(fd);

    // A sparse file: pages far apart, the index's levels grown and cut.
    char sparse[256];
    snprintf(sparse, sizeof sparse, "%s.sparse", path);
    fd = open(sparse, O_CREAT | O_TRUNC | O_RDWR, 0644);
    CHECK(fd >= 0);
    off_t offs[] = {0, 1 << 20, (off_t)1 << 30, (off_t)1 << 40, ((off_t)1 << 50) + 4096};
    for (int i = 0; i < 5; i++) CHECK(pwrite(fd, &offs[i], 8, offs[i]) == 8);
    int sparse_ok = 1;
    for (int i = 0; i < 5; i++) {
        off_t v = -1;
        CHECK(pread(fd, &v, 8, offs[i]) == 8);
        sparse_ok &= v == offs[i];
        CHECK(pread(fd, &v, 8, offs[i] + 8192) >= 0);
    }
    CHECK(ftruncate(fd, (off_t)1 << 30) == 0);
    off_t v = -1;
    CHECK(pread(fd, &v, 8, 1 << 20) == 8);
    sparse_ok &= v == 1 << 20;
    CHECK(pread(fd, &v, 8, (off_t)1 << 40) == 0);
    CHECK(ftruncate(fd, (off_t)1 << 41) == 0);
    v = -1;
    CHECK(pread(fd, &v, 8, (off_t)1 << 40) == 8);
    sparse_ok &= v == 0;
    close(fd);
    unlink(sparse);
    printf("sparse %s\n", sparse_ok ? "ok" : "wrong");

    // Then as much again as fits.
    char more[256];
    snprintf(more, sizeof more, "%s.fill", path);
    fd = open(more, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    CHECK(fd >= 0);
    memset(buf, 0x5a, chunk);
    size_t total = 0;
    for (;;) {
        ssize_t n = write(fd, buf, chunk);
        if (n < 0) {
            CHECK(errno == ENOSPC);
            break;
        }
        total += n;
        if (n < (ssize_t)chunk) break;
    }
    printf("filled %zu MiB more\n", total >> 20);
}

int main(int argc, char **argv) {
    CHECK(argc >= 3);
    size_t len = (size_t)atol(argv[2]) << 20;
    if (!strcmp(argv[1], "mem")) {
        unsigned char *p = map(len, MAP_PRIVATE);
        fill(p, len);
        printf("mem %zu MiB, %zu bad pages\n", len >> 20, check(p, len));
    } else if (!strcmp(argv[1], "shared")) {
        unsigned char *p = map(len, MAP_SHARED);
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            fill(p, len);
            _exit(0);
        }
        int status;
        CHECK(waitpid(pid, &status, 0) == pid && status == 0);
        printf("shared %zu MiB, %zu bad pages\n", len >> 20, check(p, len));
    } else if (!strcmp(argv[1], "file") && argc == 4) {
        file_mode(len, argv[3]);
    } else if (!strcmp(argv[1], "wait")) {
        unsigned char *p = map(len, MAP_PRIVATE);
        fill(p, len);
        printf("filled %zu MiB\n", len >> 20);
        fflush(stdout);
        char line[64] = {0};
        CHECK(fgets(line, sizeof line, stdin));
        printf("%s%zu bad pages\n", line, check(p, len));
    } else {
        CHECK(0);
    }
    return 0;
}
