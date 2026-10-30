// More than one CPU: the count programs see, threads running in parallel
// (and on different CPUs), shared counters under contention, and execve
// and exit while other threads spin on other CPUs.
//
//   smp          report and measure; prints "smp ok cpus=N speedup=X.Y cpus_used=K"
//   smp exec     a spinning thread, then execve from another thread
//   smp exit     spinning threads, then exit(3) from main
//   smp fork     a spinning thread, then fork and wait for the child
//   smp idle     the machine idles half a second first (every CPU halted,
//                no timer due), then as `smp`
//   smp cow      threads write while main forks again and again: each
//                child sees a consistent snapshot, the parent's reader
//                never sees a page as it was (prints "cow ok")
//   smp discard  one thread keeps writing a page while another gives the
//                pages up (MADV_DONTNEED) again and again, then that page
//                is where both see it: no CPU keeps a mapping of a page
//                that went (prints "discard ok")
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <linux/membarrier.h>
#include <sys/mman.h>
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

// `cow`: each writer fills its page with round numbers, then publishes
// the round in its flag; every store is a release, so any prefix of them
// is what anyone can see.
#define WORDS 512
static _Atomic unsigned long (*pages)[WORDS];
static _Atomic unsigned long *flags;
static _Atomic int done;

static void *cow_writer(void *arg) {
    long w = (long)arg;
    for (unsigned long round = 1; !atomic_load(&done); round++) {
        for (int i = 0; i < WORDS; i++) atomic_store_explicit(&pages[w][i], round, memory_order_release);
        atomic_store_explicit(&flags[w * 8], round, memory_order_release);
    }
    return 0;
}

// The parent's view: once a round is published, its page has it (a CPU
// still reading the page as it was before a copy would see less).
static void *cow_reader(void *arg) {
    long writers = (long)arg;
    while (!atomic_load(&done)) {
        for (long w = 0; w < writers; w++) {
            unsigned long f = atomic_load_explicit(&flags[w * 8], memory_order_acquire);
            for (int i = 0; i < WORDS; i += 64) {
                unsigned long v = atomic_load_explicit(&pages[w][i], memory_order_relaxed);
                if (v < f) {
                    printf("FAILED: parent read %lu in page %ld word %d after round %lu\n", v, w, i, f);
                    exit(1);
                }
            }
        }
    }
    return 0;
}

// The child's view, from fork's moment: each page is round f+1 up to
// some word and round f after it, f being its flag, and stays that way.
static int cow_check(long writers) {
    for (long w = 0; w < writers; w++) {
        unsigned long f = atomic_load(&flags[w * 8]);
        unsigned long last = f + 1;
        for (int i = 0; i < WORDS; i++) {
            unsigned long v = atomic_load(&pages[w][i]);
            if (v > last || v < f) {
                printf("FAILED: child read %lu in page %ld word %d, round %lu\n", v, w, i, f);
                return 1;
            }
            last = v;
        }
        if (atomic_load(&flags[w * 8]) != f || atomic_load(&pages[w][0]) < atomic_load(&pages[w][WORDS - 1])) {
            printf("FAILED: page %ld changed in the child\n", w);
            return 1;
        }
    }
    return 0;
}

static int cow(long cpus) {
    long writers = cpus > 3 ? cpus - 2 : 1;
    pages = mmap(0, writers * WORDS * 8, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    flags = mmap(0, writers * 64, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED && flags != MAP_FAILED);
    pthread_t t[8];
    for (long w = 0; w < writers; w++) CHECK(pthread_create(&t[w], 0, cow_writer, (void *)w) == 0);
    CHECK(pthread_create(&t[writers], 0, cow_reader, (void *)writers) == 0);
    int forks = 200;
    for (int i = 0; i < forks; i++) {
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) _exit(cow_check(writers));
        int status;
        CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
        if (WEXITSTATUS(status) != 0) exit(1);
    }
    atomic_store(&done, 1);
    for (long i = 0; i <= writers; i++) pthread_join(t[i], 0);
    printf("cow ok\n");
    return 0;
}

// smp discard. The page that ends a batch of the kernel's frees (each
// resident page in turn: the 256th, and it's the last here) is the one
// written: it must be gone from every TLB with the rest. The word written
// isn't the first, which a free frame's may be the kernel's.
#define DISCARD_PAGES 256
static _Atomic unsigned long discard_want, discard_got;
static _Atomic int discard_done;

static void *discard_writer(void *arg) {
    volatile unsigned long *w = (volatile unsigned long *)arg + 1;
    unsigned long round = 0;
    while (!atomic_load(&discard_done)) {
        // Keep it in this CPU's TLB, whatever the other thread is doing.
        while (atomic_load(&discard_want) == round && !atomic_load(&discard_done)) *w = round;
        round = atomic_load(&discard_want);
        *w = round;
        atomic_store(&discard_got, round);
    }
    return 0;
}

static int discard(void) {
    char *p = mmap(0, DISCARD_PAGES * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED);
    char *last = p + (DISCARD_PAGES - 1) * 4096;
    pthread_t t;
    CHECK(pthread_create(&t, 0, discard_writer, last) == 0);
    unsigned long round = 0;
    for (double t0 = now(); now() - t0 < 2.0;) {
        for (int i = 0; i < DISCARD_PAGES; i++) p[i * 4096] = 1;
        CHECK(madvise(p, DISCARD_PAGES * 4096, MADV_DONTNEED) == 0);
        atomic_store(&discard_want, ++round);
        while (atomic_load(&discard_got) != round) {
        }
        // What the other thread just wrote, if it wrote it here.
        unsigned long seen = ((volatile unsigned long *)last)[1];
        if (seen != round) {
            printf("FAILED: round %lu: the page holds %lu\n", round, seen);
            return 1;
        }
    }
    atomic_store(&discard_done, 1);
    pthread_join(t, 0);
    CHECK(round > 0);
    fprintf(stderr, "discard: %lu rounds\n", round);
    printf("discard ok\n");
    return 0;
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
    if (argc > 1 && strcmp(argv[1], "cow") == 0) return cow(cpus);
    if (argc > 1 && strcmp(argv[1], "discard") == 0) return discard();
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

    if (argc > 1 && strcmp(argv[1], "idle") == 0) {
        struct timespec half = {0, 500000000};
        nanosleep(&half, 0);
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

    int used = __builtin_popcount(atomic_load(&seen_cpus));
    // What the kernel counted, for whoever wonders why they didn't spread.
    if (cpus > 1 && used < 2) {
        FILE *f = fopen("/proc/grix/smp", "r");
        char line[512];
        while (f && fgets(line, sizeof line, f)) fputs(line, stderr);
        if (f) fclose(f);
    }
    printf("smp ok cpus=%ld speedup=%.1f cpus_used=%d\n", cpus, n * one / all, used);
    return 0;
}
