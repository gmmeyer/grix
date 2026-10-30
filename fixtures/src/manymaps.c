// Many mappings: mmap without a hint stays fast with thousands of them
// (the time per call goes to stderr, for measuring), each lands in the
// highest gap that fits, and munmap gives back the page tables it emptied
// (MemFree comes back after touching a page in each of thousands of
// 2 MiB regions).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

#define N 20000
static char *maps[N];

static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000 + t.tv_nsec / 1000;
}

static long mem_free_kb(void) {
    char buf[4096];
    int fd = open("/proc/meminfo", O_RDONLY);
    CHECK(fd >= 0);
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    CHECK(n > 0);
    buf[n] = 0;
    char *at = strstr(buf, "MemFree:");
    CHECK(at);
    return strtol(at + 8, 0, 10);
}

// A page, not merged with its neighbours: every other one is read-only.
static char *one(int i) {
    int prot = i % 2 ? PROT_READ : PROT_READ | PROT_WRITE;
    char *p = mmap(0, 4096, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED);
    return p;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    // Thousands of mappings: the last thousand cost about what the first did.
    long t0 = now_us();
    for (int i = 0; i < 1000; i++) maps[i] = one(i);
    long first = now_us() - t0;
    for (int i = 1000; i < N - 1000; i++) maps[i] = one(i);
    t0 = now_us();
    for (int i = N - 1000; i < N; i++) maps[i] = one(i);
    long last = now_us() - t0;
    fprintf(stderr, "mmap: first 1000 %ld us, last 1000 (of %d) %ld us\n", first, N, last);
    // Top down, each below the one before.
    for (int i = 1; i < N; i++) CHECK(maps[i] == maps[i - 1] - 4096);

    // Holes are reused, the highest first, and only where they fit.
    CHECK(munmap(maps[100], 4096) == 0);
    CHECK(munmap(maps[5000], 4096) == 0);
    CHECK(munmap(maps[5001], 4096) == 0);
    char *two = mmap(0, 8192, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(two == maps[5001]);
    CHECK(one(0) == maps[100]);
    CHECK(one(0) == maps[N - 1] - 4096);
    // The hole at the top (above every mapping made here) is found again.
    CHECK(munmap(maps[0], 4096) == 0);
    CHECK(one(0) == maps[0]);
    for (int i = 0; i < N; i++) munmap(maps[i], 4096);
    munmap(two, 8192);
    printf("mappings ok\n");

    // A page touched in each of 2000 2 MiB regions takes a page table
    // each; unmapped, they all come back.
    long before = mem_free_kb();
    size_t span = 2000UL << 21;
    char *big = mmap(0, span + (2 << 20), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(big != MAP_FAILED);
    char *base = (char *)(((uintptr_t)big + (2 << 20) - 1) & ~(uintptr_t)((2 << 20) - 1));
    for (size_t off = 0; off < span; off += 2 << 20) base[off] = 1;
    long touched = mem_free_kb();
    CHECK(before - touched >= 2000 * 8 - 1024);  // a page and a table each
    t0 = now_us();
    CHECK(munmap(big, span + (2 << 20)) == 0);
    fprintf(stderr, "munmap of 2000 regions: %ld us\n", now_us() - t0);
    long after = mem_free_kb();
    fprintf(stderr, "MemFree: %ld kB before, %ld touched, %ld after\n", before, touched, after);
    CHECK(before - after < 512);
    // And the space is there to use again.
    char *again = mmap(0, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(again != MAP_FAILED);
    again[0] = again[span - 1] = 2;
    CHECK(munmap(again, span) == 0);
    printf("page tables ok\n");
    return 0;
}
