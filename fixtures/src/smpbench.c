// What more CPUs cost the kernel: each mode runs on one thread (or
// process) and then on n (the CPUs, or -n), for a fixed time, and prints
// its operations per second, the speedup, and what the kernel counted
// meanwhile (the deltas of /proc/grix/smp's totals; its maximums are
// since boot).
//
//   smpbench [-t MS] [-n N] [-s] [MODE...]  (default: every mode, 300 ms)
//
//   -s        only the run on n (to load the machine, say)
//   -b N      with N idle processes besides, each with a thread asleep
//             and one waiting to read a pipe (what the kernel walks)
//
//   compute   arithmetic only
//   syscall   getppid in a loop
//   mmap      mmap 16 pages, touch each, munmap
//   futex     ping-pong between pairs of threads (n/2 pairs)
//   procs     n processes doing what mmap does
//   sleeper   a thread sleeping 1 ms at a time beside n-1 spinning
//
// One line per run:
//   smpbench mode=M n=N ops=X ops_s=Y speedup=Z <counter>=<delta>...
#define _GNU_SOURCE
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                 \
    do {                                                         \
        if (!(c)) {                                              \
            printf("FAILED: %s (line %d)\n", #c, __LINE__);      \
            exit(1);                                             \
        }                                                        \
    } while (0)

#define MAX_THREADS 16
#define MAX_COUNTERS 32

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, ms % 1000 * 1000000};
    while (nanosleep(&ts, &ts) != 0) {
    }
}

// /proc/grix/smp's header and "all" line.
static int ncounters;
static char names[MAX_COUNTERS][32];

static int read_counters(unsigned long long *v) {
    FILE *f = fopen("/proc/grix/smp", "r");
    if (!f) return 0;
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof line, f)) {
        char *save, *tok = strtok_r(line, " \n", &save);
        if (!tok) continue;
        if (strcmp(tok, "cpu") == 0) {
            ncounters = 0;
            while ((tok = strtok_r(0, " \n", &save)) && ncounters < MAX_COUNTERS)
                snprintf(names[ncounters++], sizeof names[0], "%s", tok);
        } else if (strcmp(tok, "all") == 0) {
            while ((tok = strtok_r(0, " \n", &save)) && n < MAX_COUNTERS) v[n++] = strtoull(tok, 0, 10);
        }
    }
    fclose(f);
    return n == ncounters && n > 0;
}

// The current run's: when to stop, and the operations done.
static _Atomic int stop;
static _Atomic long total;
static _Atomic long wakeups;

static volatile unsigned long sink;
static void *compute(void *arg) {
    (void)arg;
    unsigned long x = 1;
    long ops = 0;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        for (int i = 0; i < 1000; i++) x = x * 6364136223846793005UL + 1442695040888963407UL;
        ops++;
    }
    sink = x;
    atomic_fetch_add(&total, ops);
    return 0;
}

static void *getppids(void *arg) {
    (void)arg;
    long ops = 0;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        syscall(SYS_getppid);
        ops++;
    }
    atomic_fetch_add(&total, ops);
    return 0;
}

static long map_touch_unmap(volatile _Atomic int *halt) {
    long ops = 0;
    long page = sysconf(_SC_PAGESIZE);
    while (!atomic_load_explicit(halt, memory_order_relaxed)) {
        char *p = mmap(0, 16 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(p != MAP_FAILED);
        for (int i = 0; i < 16; i++) p[i * page] = 1;
        CHECK(munmap(p, 16 * page) == 0);
        ops++;
    }
    return ops;
}

static void *mmaps(void *arg) {
    (void)arg;
    atomic_fetch_add(&total, map_touch_unmap(&stop));
    return 0;
}

// A pair's word, on its own cache line: 0, the first thread's turn; 1,
// the second's.
struct pair {
    _Atomic int turn;
    char pad[60];
};
static struct pair pairs[MAX_THREADS];

static long futex(_Atomic int *uaddr, int op, int val, const struct timespec *ts) {
    return syscall(SYS_futex, uaddr, op | FUTEX_PRIVATE_FLAG, val, ts, 0, 0);
}

static void *ponger(void *arg) {
    long i = (long)arg;
    struct pair *p = &pairs[i / 2];
    int mine = i % 2;
    // A wait times out now and then, to see `stop`.
    struct timespec ts = {0, 10 * 1000000};
    long ops = 0;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        if (atomic_load(&p->turn) != mine) {
            futex(&p->turn, FUTEX_WAIT, !mine, &ts);
            continue;
        }
        atomic_store(&p->turn, !mine);
        futex(&p->turn, FUTEX_WAKE, 1, 0);
        ops++;
    }
    // The other one may wait for a turn that won't come.
    atomic_store(&p->turn, !mine);
    futex(&p->turn, FUTEX_WAKE, 1, 0);
    atomic_fetch_add(&total, ops);
    return 0;
}

static void *sleeper(void *arg) {
    (void)arg;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        sleep_ms(1);
        atomic_fetch_add(&wakeups, 1);
    }
    return 0;
}

static long run_ms = 300;

// Idle processes: each sleeps in one thread and waits for its pipe in the
// other, until the pipe closes.
static int background_pipe[2] = {-1, -1};
static pid_t background[64];
static int nbackground;

static void *asleep(void *arg) {
    (void)arg;
    sleep_ms(1000000);
    return 0;
}

static void start_background(int n) {
    CHECK(pipe(background_pipe) == 0);
    for (int i = 0; i < n; i++) {
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            close(background_pipe[1]);
            pthread_t t;
            CHECK(pthread_create(&t, 0, asleep, 0) == 0);
            char c;
            while (read(background_pipe[0], &c, 1) > 0) {
            }
            _exit(0);
        }
        background[nbackground++] = pid;
    }
    close(background_pipe[0]);
}

static void stop_background(void) {
    if (background_pipe[1] < 0) return;
    close(background_pipe[1]);
    for (int i = 0; i < nbackground; i++) {
        int status;
        CHECK(waitpid(background[i], &status, 0) == background[i] && WIFEXITED(status));
    }
}

// Run `mode` on `n`; print its line. Returns its operations per second.
static double run(const char *mode, int n, double one) {
    unsigned long long before[MAX_COUNTERS], after[MAX_COUNTERS];
    int counted = read_counters(before);
    atomic_store(&stop, 0);
    atomic_store(&total, 0);
    atomic_store(&wakeups, 0);
    pthread_t t[MAX_THREADS];
    int threads = 0;
    double t0 = now();
    if (strcmp(mode, "procs") == 0) {
        // The children's stop flag and counts, shared.
        struct shared {
            _Atomic int stop;
            _Atomic long ops;
        } *sh = mmap(0, sizeof *sh, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        CHECK(sh != MAP_FAILED);
        pid_t pids[MAX_THREADS];
        for (int i = 0; i < n; i++) {
            pids[i] = fork();
            CHECK(pids[i] >= 0);
            if (pids[i] == 0) {
                atomic_fetch_add(&sh->ops, map_touch_unmap(&sh->stop));
                _exit(0);
            }
        }
        sleep_ms(run_ms);
        atomic_store(&sh->stop, 1);
        for (int i = 0; i < n; i++) {
            int status;
            CHECK(waitpid(pids[i], &status, 0) == pids[i] && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        }
        atomic_store(&total, atomic_load(&sh->ops));
        munmap(sh, sizeof *sh);
    } else {
        void *(*fn)(void *) = 0;
        int count = n;
        if (strcmp(mode, "compute") == 0) fn = compute;
        if (strcmp(mode, "syscall") == 0) fn = getppids;
        if (strcmp(mode, "mmap") == 0) fn = mmaps;
        if (strcmp(mode, "futex") == 0) {
            fn = ponger;
            count = (n < 2 ? 1 : n / 2) * 2;
            memset(pairs, 0, sizeof pairs);
        }
        if (strcmp(mode, "sleeper") == 0) {
            fn = compute;
            count = n > 1 ? n - 1 : 1;
            CHECK(pthread_create(&t[threads++], 0, sleeper, 0) == 0);
        }
        if (!fn) {
            printf("FAILED: no mode %s\n", mode);
            exit(2);
        }
        for (long i = 0; i < count && threads < MAX_THREADS; i++) CHECK(pthread_create(&t[threads++], 0, fn, (void *)i) == 0);
        sleep_ms(run_ms);
        atomic_store(&stop, 1);
        for (int i = 0; i < threads; i++) pthread_join(t[i], 0);
    }
    double secs = now() - t0;
    long ops = atomic_load(&total);
    double rate = ops / secs;
    printf("smpbench mode=%s n=%d", mode, n);
    if (nbackground) printf(" bg=%d", nbackground);
    printf(" ops=%ld ops_s=%.0f speedup=%.2f", ops, rate, one > 0 ? rate / one : 1.0);
    if (strcmp(mode, "sleeper") == 0) printf(" wakeups=%ld", atomic_load(&wakeups));
    if (counted && read_counters(after)) {
        // A maximum is since boot, not a delta.
        for (int i = 0; i < ncounters; i++)
            printf(" %s=%llu", names[i], strstr(names[i], "_max") ? after[i] : after[i] - before[i]);
    } else {
        printf(" counters=none");
    }
    printf("\n");
    fflush(stdout);
    return rate;
}

int main(int argc, char **argv) {
    static const char *all[] = {"compute", "syscall", "mmap", "futex", "procs", "sleeper"};
    int n = sysconf(_SC_NPROCESSORS_ONLN);
    const char *modes[16];
    int nmodes = 0, skip_one = 0, bg = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            run_ms = atol(argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0) {
            skip_one = 1;
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bg = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = atoi(argv[++i]);
        } else if (nmodes < 16) {
            modes[nmodes++] = argv[i];
        }
    }
    if (n < 1) n = 1;
    if (n > MAX_THREADS) n = MAX_THREADS;
    if (nmodes == 0) {
        for (unsigned i = 0; i < sizeof all / sizeof *all; i++) modes[nmodes++] = all[i];
    }
    if (bg > 64) bg = 64;
    if (bg > 0) start_background(bg);
    for (int i = 0; i < nmodes; i++) {
        double one = skip_one ? 0 : run(modes[i], 1, 0);
        if (n > 1 || skip_one) run(modes[i], n, one);
    }
    stop_background();
    printf("smpbench ok\n");
    return 0;
}
