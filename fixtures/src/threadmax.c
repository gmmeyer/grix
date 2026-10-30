// Threads until the kernel says no: more than the 1024 grix used to allow,
// as many as threads-max, then EAGAIN (never a kernel panic). Again with
// the kernel's memory budget taken by pipe buffers: EAGAIN sooner. Then
// everything goes and the program ends cleanly.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

#define STACK (16 * 1024)

static atomic_int go, started;
static char *stacks;
static pthread_t *ids;

static void *waiter(void *arg) {
    (void)arg;
    started++;
    while (!go) syscall(SYS_futex, &go, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    return NULL;
}

static long read_long(const char *path, const char *key) {
    static char buf[4096];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    char *at = key ? strstr(buf, key) : buf;
    return at ? atol(at + (key ? strlen(key) : 0)) : -1;
}

/// Make threads until one can't be made (at most `max`): how many were.
static int spawn(int max) {
    int n = 0;
    while (n < max) {
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setstack(&a, stacks + (size_t)n * STACK, STACK);
        int r = pthread_create(&ids[n], &a, waiter, NULL);
        pthread_attr_destroy(&a);
        if (r == EAGAIN) break;
        if (r) {
            printf("pthread_create: %d\n", r);
            return -1;
        }
        n++;
    }
    return n;
}

static void release(int n) {
    go = 1;
    syscall(SYS_futex, &go, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL, NULL, 0);
    for (int i = 0; i < n; i++) pthread_join(ids[i], NULL);
    go = 0;
    started = 0;
}

int main(void) {
    long max = read_long("/proc/sys/kernel/threads-max", NULL);
    CHECK(max > 1024);
    CHECK(read_long("/sys/fs/cgroup/pids.max", NULL) == max);
    stacks = mmap(NULL, (size_t)max * STACK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    CHECK(stacks != MAP_FAILED);
    ids = calloc(max, sizeof *ids);
    CHECK(ids);

    // As many as threads-max (all processes' threads, this one's main
    // thread too), unless kernel memory runs out first.
    int n = spawn(max);
    CHECK(n > 1024 && n < max);
    while (started < n) sched_yield();
    CHECK(read_long("/proc/self/status", "Threads:\t") == n + 1);
    release(n);
    CHECK(read_long("/proc/self/status", "Threads:\t") == 1);

    // Kernel memory mostly taken by pipe buffers: threads run out sooner,
    // and the pipes still work.
    int fds[2048], nfds = 0;
    for (;;) {
        int p[2];
        if (nfds + 2 > (int)(sizeof fds / sizeof *fds) || pipe2(p, O_NONBLOCK) != 0) break;
        fds[nfds++] = p[0];
        fds[nfds++] = p[1];
        fcntl(p[1], F_SETPIPE_SZ, 1 << 20);
        static char junk[65536];
        long put = 0, w;
        while ((w = write(p[1], junk, sizeof junk)) > 0) put += w;
        if (put == 0) break; // nothing left for it
    }
    int m = spawn(max);
    CHECK(m >= 0 && m < n);
    while (started < m) sched_yield();
    release(m);
    for (int i = 0; i < nfds; i++) close(fds[i]);
    // All given back: as many as before.
    int again = spawn(max);
    CHECK(again == n);
    while (started < again) sched_yield();
    release(again);
    fprintf(stderr, "threads-max %ld: %d threads, %d with pipes full\n", max, n, m);
    printf("threadmax ok\n");
    return 0;
}
