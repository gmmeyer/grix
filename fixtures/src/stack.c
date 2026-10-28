// The stack is as big as RLIMIT_STACK says at exec: `stack MB` uses that
// much of it, and mmap keeps clear of it. Run under a shell's `ulimit -s`.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>

// Each call takes about 64 KiB of stack, kept until the calls below return.
static int deep(int n, volatile char *up) {
    volatile char frame[64 << 10];
    for (unsigned i = 0; i < sizeof frame; i += 4096) frame[i] = (char)n;
    int below = n == 0 ? 0 : deep(n - 1, frame);
    return below + (frame[0] != (char)n) + (up && up[0] != (char)(n + 1));
}

int main(int argc, char **argv) {
    int mb = argc > 1 ? atoi(argv[1]) : 1;
    struct rlimit r;
    getrlimit(RLIMIT_STACK, &r);
    // Nothing mmap places is within the guard gap below the stack.
    char *here = (char *)&r;
    for (int i = 0; i < 64; i++) {
        char *m = mmap(NULL, 1 << 20, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED || (m < here && here - (m + (1 << 20)) < (long)(r.rlim_cur < (64L << 20) ? r.rlim_cur : 0))) {
            printf("mmap at %p, too close to the stack at %p\n", (void *)m, (void *)here);
            return 1;
        }
    }
    printf("depth %d\n", deep(mb * 16, NULL) == 0 ? mb : -1);
    return 0;
}
