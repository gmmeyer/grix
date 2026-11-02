// clone(CLONE_VM) without CLONE_THREAD: processes of their own in one address
// space. Passes on Linux as it is.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                 \
    do {                                                                         \
        if (!(c)) {                                                              \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);     \
            exit(1);                                                             \
        }                                                                        \
    } while (0)
#define FAILS(call, e) CHECK((long)(call) == -1 && errno == (e))

static char stack[64 * 1024] __attribute__((aligned(16)));
static char stack2[64 * 1024] __attribute__((aligned(16)));
#define TOP(s) ((s) + sizeof(s))

static long futex(_Atomic int *w, int op, int v) {
    return syscall(SYS_futex, w, op, v, NULL, NULL, 0);
}

// A child can't use libc's own state much: this is all raw calls.
static void wait_for(_Atomic int *w, int v) {
    while (atomic_load(w) != v) futex(w, FUTEX_WAIT_PRIVATE, atomic_load(w));
}
static void set(_Atomic int *w, int v) {
    atomic_store(w, v);
    futex(w, FUTEX_WAKE_PRIVATE, 1 << 30);
}

static int reap(pid_t pid) {
    int status;
    CHECK(waitpid(pid, &status, __WALL) == pid);
    return status;
}

// ---------------------------------------------------------------- memory

static volatile long shared_word;
static volatile char *made;
static pid_t seen_pid, seen_ppid;

static int writes(void *arg) {
    (void)arg;
    seen_pid = syscall(SYS_getpid);
    seen_ppid = syscall(SYS_getppid);
    shared_word = 42;
    char *m = (void *)syscall(SYS_mmap, NULL, 8192, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    m[0] = 'm', m[4096] = 'n';
    made = m;
    return 7;
}

static void memory(void) {
    pid_t pid = clone(writes, TOP(stack), CLONE_VM | SIGCHLD, NULL);
    CHECK(pid > 0);
    CHECK(reap(pid) == 7 << 8);
    // A process of its own, and everything it did to memory is ours.
    CHECK(seen_pid == pid && seen_ppid == getpid());
    CHECK(shared_word == 42);
    CHECK(made && made[0] == 'm' && made[4096] == 'n');
    // That it's gone hasn't taken anything with it.
    made[1] = 'o';
    CHECK(munmap((void *)made, 8192) == 0);
}

// ---------------------------------------------------------------- futexes

static _Atomic int word, reply;

static int ping(void *arg) {
    (void)arg;
    wait_for(&word, 1);
    set(&reply, 1);
    return 0;
}

static void futexes(void) {
    pid_t pid = clone(ping, TOP(stack), CLONE_VM | SIGCHLD, NULL);
    CHECK(pid > 0);
    set(&word, 1);
    wait_for(&reply, 1);
    CHECK(reap(pid) == 0);
}

// A thread already asleep when memory came to be shared.
static _Atomic int sleeper, asleep;

static void *sleeps(void *arg) {
    (void)arg;
    atomic_store(&asleep, 1);
    wait_for(&sleeper, 1);
    return NULL;
}

static int wakes(void *arg) {
    (void)arg;
    set(&sleeper, 1);
    return 0;
}

static void waiter_from_before(void) {
    pthread_t t;
    CHECK(pthread_create(&t, NULL, sleeps, NULL) == 0);
    while (!atomic_load(&asleep)) sched_yield();
    usleep(20000);
    pid_t pid = clone(wakes, TOP(stack), CLONE_VM | SIGCHLD, NULL);
    CHECK(pid > 0);
    CHECK(pthread_join(t, NULL) == 0);
    CHECK(reap(pid) == 0);
}

// Once they've stopped sharing, one that's left still finds its waiters.
static _Atomic int after, after_ready;

static void *waits_after(void *arg) {
    (void)arg;
    atomic_store(&after_ready, 1);
    wait_for(&after, 1);
    return NULL;
}

static int leaves(void *arg) {
    (void)arg;
    return 0;
}

static void after_sharing(void) {
    pid_t pid = clone(leaves, TOP(stack), CLONE_VM | SIGCHLD, NULL);
    CHECK(pid > 0);
    pthread_t t;
    CHECK(pthread_create(&t, NULL, waits_after, NULL) == 0);
    while (!atomic_load(&after_ready)) sched_yield();
    usleep(20000);
    CHECK(reap(pid) == 0);
    set(&after, 1);
    CHECK(pthread_join(t, NULL) == 0);
}

// clone with a word to clear: musl's clone() won't have CLONE_CHILD_CLEARTID.
static long clone_clearing(int (*fn)(void *), void *sp, long flags, void *arg, _Atomic int *word) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = (long)word;
    register long r8 __asm__("r8") = 0;
    long ret = SYS_clone;
    __asm__ volatile("syscall\n"
                     "testq %%rax, %%rax\n"
                     "jnz 1f\n"
                     "movq %[arg], %%rdi\n"
                     "callq *%[fn]\n"
                     "movq %%rax, %%rdi\n"
                     "movq $60, %%rax\n"
                     "syscall\n"
                     "1:"
                     : "+a"(ret)
                     : "D"(flags), "S"(sp), "d"(0), "r"(r10), "r"(r8), [fn] "r"(fn), [arg] "r"(arg)
                     : "rcx", "r11", "memory");
    if (ret < 0) errno = -ret, ret = -1;
    return ret;
#else
    register long x8 __asm__("x8") = SYS_clone;
    register long x0 __asm__("x0") = flags;
    register void *x1 __asm__("x1") = sp;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register void *x4 __asm__("x4") = word;
    register void *x19 __asm__("x19") = fn;
    register void *x20 __asm__("x20") = arg;
    __asm__ volatile("svc 0\n"
                     "cbnz x0, 1f\n"
                     "mov x0, x20\n"
                     "blr x19\n"
                     "mov x8, #93\n"
                     "svc 0\n"
                     "1:"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x19), "r"(x20)
                     : "x30", "memory");
    if (x0 < 0) errno = -x0, x0 = -1;
    return x0;
#endif
}

// CLONE_CHILD_CLEARTID: whoever's left in the memory hears of an end.
static _Atomic int tid_word;

static int ends(void *arg) {
    (void)arg;
    return 0;
}

static int killed(void *arg) {
    struct timespec hour = {3600, 0};
    while (arg == NULL) syscall(SYS_nanosleep, &hour, NULL);
    return 0;
}

static void clear_tid(void) {
    atomic_store(&tid_word, 1);
    pid_t pid = clone_clearing(ends, TOP(stack), CLONE_VM | CLONE_CHILD_CLEARTID | SIGCHLD, NULL, &tid_word);
    CHECK(pid > 0);
    while (atomic_load(&tid_word) == 1) futex(&tid_word, FUTEX_WAIT, 1);
    CHECK(reap(pid) == 0);
    // However it ends.
    atomic_store(&tid_word, 1);
    pid = clone_clearing(killed, TOP(stack), CLONE_VM | CLONE_CHILD_CLEARTID | SIGCHLD, NULL, &tid_word);
    CHECK(pid > 0);
    CHECK(kill(pid, SIGKILL) == 0);
    while (atomic_load(&tid_word) == 1) futex(&tid_word, FUTEX_WAIT, 1);
    CHECK(reap(pid) == SIGKILL);
}

// ---------------------------------------------------------------- exec, fork

static int execs(void *arg) {
    char *const argv[] = {(char *)arg, "ran", NULL};
    syscall(SYS_execve, arg, argv, NULL);
    return 99;
}

static void exec_leaves_it(const char *self) {
    shared_word = 5;
    pid_t pid = clone(execs, TOP(stack), CLONE_VM | SIGCHLD, (void *)self);
    CHECK(pid > 0);
    CHECK(reap(pid) == 3 << 8);
    CHECK(shared_word == 5);
    // It's left the memory, and says so as an end would.
    atomic_store(&tid_word, 1);
    pid = clone_clearing(execs, TOP(stack), CLONE_VM | CLONE_CHILD_CLEARTID | SIGCHLD, (void *)self, &tid_word);
    CHECK(pid > 0);
    while (atomic_load(&tid_word) == 1) futex(&tid_word, FUTEX_WAIT, 1);
    CHECK(reap(pid) == 3 << 8);
}

static int forks(void *arg) {
    (void)arg;
    pid_t c = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (c == 0) {
        // A copy: this isn't the sharers' memory.
        shared_word = 1000;
        syscall(SYS_exit, 0);
    }
    int status;
    syscall(SYS_wait4, c, &status, 0, 0);
    return shared_word == 1000 ? 1 : 0;
}

static void fork_copies(void) {
    shared_word = 6;
    pid_t pid = clone(forks, TOP(stack), CLONE_VM | SIGCHLD, NULL);
    CHECK(pid > 0);
    CHECK(reap(pid) == 0);
    CHECK(shared_word == 6);
}

// ---------------------------------------------------------------- the rest

static int shares_sigactions(void *arg) {
    (void)arg;
    struct sigaction a;
    syscall(SYS_rt_sigaction, SIGUSR1, NULL, &a, 8);
    return a.sa_handler == SIG_IGN ? 0 : 1;
}

static void with_others(void) {
    CHECK(signal(SIGUSR1, SIG_IGN) != SIG_ERR);
    pid_t pid = clone(shares_sigactions, TOP(stack), CLONE_VM | CLONE_SIGHAND | CLONE_FILES | SIGCHLD,
                      NULL);
    CHECK(pid > 0);
    CHECK(reap(pid) == 0);
    CHECK(signal(SIGUSR1, SIG_DFL) != SIG_ERR);
    FAILS(clone(ends, TOP(stack), CLONE_SIGHAND | SIGCHLD, NULL), EINVAL);
}

// An exit-signal of nothing: only __WCLONE/__WALL hears of it.
static void no_signal(void) {
    pid_t pid = clone(ends, TOP(stack), CLONE_VM, NULL);
    CHECK(pid > 0);
    int status;
    FAILS(waitpid(pid, &status, WNOHANG), ECHILD);
    CHECK(waitpid(pid, &status, __WCLONE) == pid && status == 0);
}

// One's end, the other's memory goes on. Then the other way: in a process
// of their own, as the program's first ends the run.
static _Atomic int go;
static volatile long left_behind;

static int outlives(void *arg) {
    (void)arg;
    wait_for(&go, 1);
    left_behind = 1;
    return left_behind == 1 ? 0 : 1;
}

static void parent_goes_first(void) {
    pid_t mid = fork();
    CHECK(mid >= 0);
    if (mid == 0) {
        CHECK(clone(outlives, TOP(stack), CLONE_VM | CLONE_PARENT | SIGCHLD, NULL) > 0);
        atomic_store(&go, 1);
        syscall(SYS_futex, &go, FUTEX_WAKE_PRIVATE, 1 << 30, 0, 0, 0);
        syscall(SYS_exit_group, 0);
    }
    // Ours: it, then its child, which is ours too.
    int a = reap(mid), b;
    CHECK(wait(&b) > 0);
    CHECK(a == 0 && b == 0);
}

// Two processes at it at once, faulting pages in and out of the same tables.
#define PAGES 256
static volatile char *area;
static _Atomic int running;

static int hammers(void *arg) {
    long me = (long)arg;
    for (int round = 0; round < 40; round++) {
        for (int i = 0; i < PAGES; i++) area[i * 4096 + me] = (char)round;
        syscall(SYS_madvise, area, PAGES * 4096, MADV_DONTNEED);
    }
    atomic_fetch_sub(&running, 1);
    return 0;
}

static void at_once(void) {
    area = mmap(NULL, PAGES * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(area != MAP_FAILED);
    atomic_store(&running, 2);
    pid_t a = clone(hammers, TOP(stack), CLONE_VM | SIGCHLD, (void *)0);
    pid_t b = clone(hammers, TOP(stack2), CLONE_VM | SIGCHLD, (void *)1);
    CHECK(a > 0 && b > 0);
    CHECK(reap(a) == 0 && reap(b) == 0);
    CHECK(atomic_load(&running) == 0);
    CHECK(munmap((void *)area, PAGES * 4096) == 0);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "ran")) return 3;
    setvbuf(stdout, 0, _IOLBF, 0);
    // First: it's about the very first time memory comes to be shared.
    waiter_from_before();
    memory();
    futexes();
    after_sharing();
    clear_tid();
    exec_leaves_it(argv[0]);
    fork_copies();
    with_others();
    no_signal();
    parent_goes_first();
    at_once();
    printf("clonevm ok\n");
    return 0;
}
