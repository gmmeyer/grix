// futex_waitv(2): waiting on several futex words at once. The wake that
// ends it gives the index of its word, the other words' queues let go of
// the waiter, requeues carry it along, deadlines are absolute on
// CLOCK_MONOTONIC or CLOCK_REALTIME, and bad arguments are EINVAL.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif
#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32 0x02
#define FUTEX2_PRIVATE 128
#endif

struct waitv {
    uint64_t val;
    uint64_t uaddr;
    uint32_t flags;
    uint32_t reserved;
};

static uint32_t words[4];

static long waitv(struct waitv *w, unsigned n, unsigned flags, struct timespec *t, int clock) {
    return syscall(SYS_futex_waitv, w, n, flags, t, clock);
}

static long wake(uint32_t *addr, int n) { return syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, n, 0, 0, 0); }

static void set(struct waitv *w, uint32_t *addr, uint32_t val) {
    memset(w, 0, sizeof *w);
    w->uaddr = (uintptr_t)addr;
    w->val = val;
    w->flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

// A thread waiting on words 0, 1 and 2 (each expected 0).
static volatile long result = -100;
static volatile int result_errno;

static void *waiter(void *arg) {
    (void)arg;
    struct waitv w[3];
    for (int i = 0; i < 3; i++) set(&w[i], &words[i], 0);
    long r = waitv(w, 3, 0, NULL, 0);
    result_errno = errno;
    result = r;
    return 0;
}

// Wake `addr` until someone's there to wake (the waiter may not be queued yet).
static void wake_one(uint32_t *addr) {
    for (int i = 0; i < 2000; i++) {
        if (wake(addr, 1) == 1) return;
        usleep(1000);
    }
    CHECK(!"nobody waited");
}

static void on_usr1(int sig) { (void)sig; }

int main(void) {
    struct waitv w[129];

    // Bad arguments.
    set(&w[0], &words[0], 0);
    CHECK(waitv(w, 0, 0, NULL, 0) == -1 && errno == EINVAL);
    CHECK(waitv(w, 129, 0, NULL, 0) == -1 && errno == EINVAL);
    CHECK(waitv(w, 1, 1, NULL, 0) == -1 && errno == EINVAL);
    w[0].flags = FUTEX2_PRIVATE;  // no size
    CHECK(waitv(w, 1, 0, NULL, 0) == -1 && errno == EINVAL);
    set(&w[0], &words[0], 0);
    w[0].reserved = 1;
    CHECK(waitv(w, 1, 0, NULL, 0) == -1 && errno == EINVAL);
    set(&w[0], (uint32_t *)((char *)&words[0] + 1), 0);
    CHECK(waitv(w, 1, 0, NULL, 0) == -1 && errno == EINVAL);
    set(&w[0], &words[0], 0);
    struct timespec soon = {0, 0};
    CHECK(waitv(w, 1, 0, &soon, CLOCK_BOOTTIME) == -1 && errno == EINVAL);
    CHECK(waitv((struct waitv *)8, 1, 0, NULL, 0) == -1 && errno == EFAULT);

    // A word that isn't what's expected: EAGAIN at once.
    words[1] = 7;
    set(&w[0], &words[0], 0);
    set(&w[1], &words[1], 0);
    CHECK(waitv(w, 2, 0, NULL, 0) == -1 && errno == EAGAIN);
    words[1] = 0;

    // A deadline, absolute, on either clock.
    long t0 = now_ms();
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    t.tv_nsec += 50 * 1000000L;
    if (t.tv_nsec >= 1000000000L) t.tv_sec++, t.tv_nsec -= 1000000000L;
    CHECK(waitv(w, 2, 0, &t, CLOCK_MONOTONIC) == -1 && errno == ETIMEDOUT);
    CHECK(now_ms() - t0 >= 49);
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_nsec += 20 * 1000000L;
    if (t.tv_nsec >= 1000000000L) t.tv_sec++, t.tv_nsec -= 1000000000L;
    CHECK(waitv(w, 2, 0, &t, CLOCK_REALTIME) == -1 && errno == ETIMEDOUT);
    printf("arguments ok\n");

    // Woken through its third word: the call returns 2, and the waiter
    // left the other words' queues.
    pthread_t th;
    CHECK(pthread_create(&th, 0, waiter, 0) == 0);
    wake_one(&words[2]);
    CHECK(pthread_join(th, 0) == 0);
    CHECK(result == 2);
    CHECK(wake(&words[0], 1) == 0 && wake(&words[1], 1) == 0);
    printf("woken by word 2\n");

    // Requeued from word 1 to word 3, then woken there: index 1.
    result = -100;
    CHECK(pthread_create(&th, 0, waiter, 0) == 0);
    long moved = 0;
    for (int i = 0; i < 2000 && moved == 0; i++) {
        moved = syscall(SYS_futex, &words[1], FUTEX_CMP_REQUEUE_PRIVATE, 0, 1, &words[3], 0);
        if (moved == 0) usleep(1000);
    }
    CHECK(moved == 1);
    CHECK(wake(&words[1], 1) == 0);
    CHECK(wake(&words[3], 1) == 1);
    CHECK(pthread_join(th, 0) == 0);
    CHECK(result == 1);
    printf("requeued and woken\n");

    // A signal with a handler (no SA_RESTART) ends the wait with EINTR.
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    CHECK(sigaction(SIGUSR1, &sa, 0) == 0);
    result = -100;
    CHECK(pthread_create(&th, 0, waiter, 0) == 0);
    usleep(30000);
    CHECK(pthread_kill(th, SIGUSR1) == 0);
    CHECK(pthread_join(th, 0) == 0);
    CHECK(result == -1 && result_errno == EINTR);
    CHECK(wake(&words[0], 1) == 0);
    printf("interrupted\n");

    // 128 words, the most.
    static uint32_t many[128];
    for (int i = 0; i < 128; i++) set(&w[i], &many[i], 0);
    struct timespec past = {0, 1};
    CHECK(waitv(w, 128, 0, &past, CLOCK_MONOTONIC) == -1 && errno == ETIMEDOUT);
    many[5] = 1;
    CHECK(waitv(w, 128, 0, NULL, 0) == -1 && errno == EAGAIN);
    printf("futexv ok\n");
    return 0;
}
