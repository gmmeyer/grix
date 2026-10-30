// /proc/<pid>/task/<tid>: each thread's own name (PR_SET_NAME,
// pthread_setname_np, writes to its comm file), state and CPU time, as
// `top -H` and `ps -L` read them.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n%s", #c, __LINE__, errno, text); return 1; } } while (0)

static atomic_int stage, tid_a, tid_b;
static char text[4096];

static int slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, text, sizeof text - 1);
    close(fd);
    text[n < 0 ? 0 : n] = 0;
    return n;
}

static int put(const char *path, const char *s) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int n = write(fd, s, strlen(s));
    int e = errno;
    close(fd);
    errno = e;
    return n;
}

static long cpu_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void wait_stage(int want) {
    int s;
    while ((s = stage) < want) syscall(SYS_futex, &stage, FUTEX_WAIT_PRIVATE, s, NULL, NULL, 0);
}

static void set_stage(int s) {
    stage = s;
    syscall(SYS_futex, &stage, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL, NULL, 0);
}

/// Names itself, spins for 200 ms of CPU, then waits.
static void *busy(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "worker-a");
    char name[16];
    prctl(PR_GET_NAME, name);
    if (strcmp(name, "worker-a")) return (void *)1;
    tid_a = syscall(SYS_gettid);
    long start = cpu_ms();
    while (cpu_ms() - start < 200) {}
    set_stage(1);
    wait_stage(3);
    return NULL;
}

/// Named by the main thread, waits from the start.
static void *idle(void *arg) {
    (void)arg;
    tid_b = syscall(SYS_gettid);
    wait_stage(3);
    // What was written to its comm file is its name.
    char name[16];
    prctl(PR_GET_NAME, name);
    return strcmp(name, "renamed-b") ? (void *)1 : NULL;
}

/// Field `n` (1-based) of a stat line, after the comm in parentheses.
static long stat_field(const char *stat, int n) {
    const char *p = strrchr(stat, ')');
    if (!p || n < 3) return -1;
    p += 2;
    for (int i = 3; i < n; i++) {
        p = strchr(p, ' ');
        if (!p) return -1;
        p++;
    }
    return *p >= '0' && *p <= '9' ? atol(p) : *p;
}

int main(void) {
    int pid = getpid();
    CHECK(prctl(PR_SET_NAME, "taskmain") == 0);
    pthread_t a, b;
    CHECK(pthread_create(&b, NULL, idle, NULL) == 0);
    CHECK(pthread_create(&a, NULL, busy, NULL) == 0);
    wait_stage(1);
    while (!tid_b) sched_yield();
    char path[128], name[32];
    // A new thread is named as its creator was.
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", tid_b);
    CHECK(slurp(path) > 0 && !strcmp(text, "taskmain\n"));
    // musl names another thread through its comm file.
    CHECK(pthread_setname_np(b, "worker-b") == 0);
    CHECK(pthread_getname_np(b, name, sizeof name) == 0 && !strcmp(name, "worker-b"));

    // Each thread's comm, stat and status are its own. (Both wait, soon.)
    for (int i = 0; i < 1000; i++) {
        snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid_a);
        int sa = slurp(path) > 0 && strstr(text, ") S ");
        snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid_b);
        if (sa && slurp(path) > 0 && strstr(text, ") S ")) break;
        usleep(1000);
    }
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", tid_a);
    CHECK(slurp(path) > 0 && !strcmp(text, "worker-a\n"));
    snprintf(path, sizeof path, "/proc/%d/task/%d/stat", pid, tid_a);
    CHECK(slurp(path) > 0 && atoi(text) == tid_a && strstr(text, " (worker-a) S "));
    long a_ticks = stat_field(text, 14);
    CHECK(a_ticks >= 15 && stat_field(text, 20) == 3);
    snprintf(path, sizeof path, "/proc/self/task/%d/status", tid_a);
    CHECK(slurp(path) > 0 && strstr(text, "Name:\tworker-a\n") && strstr(text, "State:\tS (sleeping)\n"));
    char want[64];
    snprintf(want, sizeof want, "\nTgid:\t%d\n", pid);
    CHECK(strstr(text, want));
    snprintf(want, sizeof want, "\nPid:\t%d\n", tid_a);
    CHECK(strstr(text, want));
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid_b);
    CHECK(slurp(path) > 0 && strstr(text, " (worker-b) S ") && stat_field(text, 14) < a_ticks);
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", pid);
    CHECK(slurp(path) > 0 && strstr(text, " (taskmain) R "));
    // The process's own are the main thread's name and everyone's time.
    CHECK(slurp("/proc/self/comm") > 0 && !strcmp(text, "taskmain\n"));
    CHECK(slurp("/proc/self/stat") > 0 && strstr(text, " (taskmain) ") && stat_field(text, 14) >= a_ticks);

    // Writing a comm file renames that thread (at most 15 bytes); the
    // process's names the main thread.
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", tid_b);
    CHECK(put(path, "renamed-b") == 9);
    CHECK(slurp(path) > 0 && !strcmp(text, "renamed-b\n"));
    CHECK(put("/proc/self/comm", "a-very-long-main-name") == 21);
    CHECK(slurp("/proc/self/comm") > 0 && !strcmp(text, "a-very-long-mai\n"));
    CHECK(prctl(PR_GET_NAME, name) == 0 && !strcmp(name, "a-very-long-mai"));
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", pid);
    CHECK(slurp(path) > 0 && !strcmp(text, "a-very-long-mai\n"));

    // Another process can read them, not rename them (Linux's comm_write:
    // only its own threads); a fork is named as the thread that made it.
    pid_t child = fork();
    if (child == 0) {
        snprintf(path, sizeof path, "/proc/%d/task/%d/comm", pid, tid_a);
        if (slurp(path) <= 0 || strcmp(text, "worker-a\n")) _exit(2);
        if (put(path, "nope") != -1 || errno != EINVAL) _exit(3);
        if (slurp("/proc/self/comm") <= 0 || strcmp(text, "a-very-long-mai\n")) _exit(4);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    set_stage(3);
    void *ra, *rb;
    CHECK(pthread_join(a, &ra) == 0 && pthread_join(b, &rb) == 0 && !ra && !rb);
    // Gone from the listing.
    snprintf(path, sizeof path, "/proc/self/task/%d", tid_a);
    CHECK(access(path, F_OK) == -1 && errno == ENOENT);
    printf("taskproc ok\n");
    return 0;
}
