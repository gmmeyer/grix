// Exercise malloc (brk + mmap paths), realloc (mremap), mmap/mprotect/munmap, madvise.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d)\n", #c, __LINE__); return 1; } } while (0)

int main(void) {
    // Many small allocations, some freed.
    char *keep[1000] = {0};
    for (int i = 0; i < 1000; i++) {
        keep[i] = malloc(100 + i);
        CHECK(keep[i]);
        memset(keep[i], i & 0xff, 100 + i);
    }
    for (int i = 0; i < 1000; i++) {
        CHECK((unsigned char)keep[i][99 + i] == (i & 0xff));
        if (i % 3) free(keep[i]);
    }

    // A large allocation touched page by page, then grown (mremap).
    size_t n = 64 << 20;
    unsigned char *big = malloc(n);
    CHECK(big);
    for (size_t i = 0; i < n; i += 4096) big[i] = (unsigned char)(i >> 12);
    big = realloc(big, 2 * n);
    CHECK(big);
    for (size_t i = 0; i < n; i += 4096) CHECK(big[i] == (unsigned char)(i >> 12));
    big[2 * n - 1] = 1;
    free(big);

    // mmap / mprotect round trip keeps contents; madvise(DONTNEED) zeroes them.
    size_t len = 1 << 20;
    unsigned char *m = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED);
    m[0] = 42;
    m[len - 1] = 43;
    CHECK(mprotect(m, len, PROT_NONE) == 0);
    CHECK(mprotect(m, len, PROT_READ) == 0);
    CHECK(m[0] == 42 && m[len - 1] == 43);
    CHECK(mprotect(m, len, PROT_READ | PROT_WRITE) == 0);
    CHECK(madvise(m, len, MADV_DONTNEED) == 0);
    CHECK(m[0] == 0 && m[len - 1] == 0);
    CHECK(munmap(m, len) == 0);

    // brk grows and shrinks.
    uintptr_t b0 = syscall(SYS_brk, 0);
    uintptr_t b1 = syscall(SYS_brk, b0 + (1 << 20));
    CHECK(b1 == b0 + (1 << 20));
    ((volatile char *)b0)[(1 << 20) - 1] = 7;
    CHECK(syscall(SYS_brk, b0) == (long)b0);

    printf("mem ok\n");
    return 0;
}
