// More than one CPU: the count programs see, threads running in parallel
// (and on different CPUs), shared counters under contention, and execve
// and exit while other threads spin on other CPUs.
//
//   smp          report and measure; prints "smp ok cpus=N speedup=X.Y cpus_used=K"
//   smp exec     a spinning thread, then execve from another thread
//   smp exit     spinning threads, then exit(3) from main
//   smp fork     a spinning thread, then fork and wait for the child
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <linux/membarrier.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                                 \
    do {                                                         \
        if (!(c)) {                                              \
            printf("FAILED: %s (line %d)\n", #c, __LINE__);      \
            exit(1);                                             \
        }                                                        \
    } while (0)

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

// CPU-bound work the compiler can't skip.
static volatile unsigned long sink;
static void work(long n) {
    unsigned long x = 1;
    for (long i = 0; i < n; i++) x = x * 6364136223846793005UL + 1442695040888963407UL;
    sink = x;
}

static long WORK = 40 * 1000 * 1000;
static _Atomic int seen_cpus;  // bit per CPU a worker ran on

static void *worker(void *arg) {
    (void)arg;
    work(WORK);
    atomic_fetch_or(&seen_cpus, 1 << sched_getcpu());
    return 0;
}

static _Atomic long atomic_count;
static long locked_count;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void *contender(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) {
        atomic_fetch_add(&atomic_count, 1);
        pthread_mutex_lock(&lock);
        locked_count++;
        pthread_mutex_unlock(&lock);
    }
    return 0;
}

static _Atomic int spinning;
static void *spinner(void *arg) {
    (void)arg;
    atomic_fetch_add(&spinning, 1);
    for (;;) sink++;
    return 0;
}

static void start_spinners(int n) {
    for (int i = 0; i < n; i++) {
        pthread_t t;
        CHECK(pthread_create(&t, 0, spinner, 0) == 0);
    }
    while (atomic_load(&spinning) < n) sched_yield();
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "exec-done") == 0) {
        printf("exec ok\n");
        return 0;
    }
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (argc > 1 && strcmp(argv[1], "exec") == 0) {
        start_spinners(cpus > 1 ? cpus - 1 : 1);
        char *args[] = {argv[0], "exec-done", 0};
        execv(argv[0], args);
        printf("FAILED: execv\n");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "exit") == 0) {
        start_spinners(cpus);
        exit(3);
    }
    if (argc > 1 && strcmp(argv[1], "fork") == 0) {
        // The child is another process: the spinning thread's CPU has to
        // give way for it to run at all.
        start_spinners(1);
        // membarrier reaches the spinning thread's CPU, and comes back.
        CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0) == 0);
        CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0) == 0);
        CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == 0);
        for (int i = 0; i < 3; i++) {
            pid_t pid = fork();
            CHECK(pid >= 0);
            if (pid == 0) _exit(10 + i);
            int status;
            CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 10 + i);
        }
        printf("fork ok\n");
        exit(0);
    }

    cpu_set_t set;
    CHECK(sched_getaffinity(0, sizeof set, &set) == 0);
    CHECK(CPU_COUNT(&set) == cpus);

    // One thread's worth of work, then that much on each of `cpus` threads.
    double t0 = now();
    work(WORK);
    double one = now() - t0;
    pthread_t t[8];
    int n = cpus < 8 ? cpus : 8;
    t0 = now();
    for (int i = 0; i < n; i++) CHECK(pthread_create(&t[i], 0, worker, 0) == 0);
    for (int i = 0; i < n; i++) pthread_join(t[i], 0);
    double all = now() - t0;

    for (int i = 0; i < 4; i++) CHECK(pthread_create(&t[i], 0, contender, 0) == 0);
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    CHECK(atomic_load(&atomic_count) == 400000);
    CHECK(locked_count == 400000);

    printf("smp ok cpus=%ld speedup=%.1f cpus_used=%d\n", cpus, n * one / all,
           __builtin_popcount(atomic_load(&seen_cpus)));
    return 0;
}
