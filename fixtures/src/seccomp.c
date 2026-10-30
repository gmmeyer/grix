// seccomp: strict mode, classic BPF filters (checked as Linux checks
// them, stacked, inherited across fork, threads and execve, synced with
// TSYNC), every return action (a SIGSYS handler reads si_syscall and
// emulates the call), the kernel's budget for filters, and grix's own
// gates coming first. Needs `process` and `threads`.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            fflush(stdout);                                                       \
            _exit(1);                                                             \
        }                                                                         \
    } while (0)

#if defined(__aarch64__)
#define ARCH AUDIT_ARCH_AARCH64
#else
#define ARCH AUDIT_ARCH_X86_64
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH 16
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER 8
#endif

static long sc(unsigned op, unsigned flags, void *args) { return syscall(SYS_seccomp, op, flags, args); }

static long install(struct sock_filter *f, unsigned short n, unsigned flags) {
    struct sock_fprog prog = {n, f};
    return sc(SECCOMP_SET_MODE_FILTER, flags, &prog);
}

// The same for a filter that's expected to fail: its errno.
static int refused(struct sock_filter *f, unsigned short n) {
    errno = 0;
    CHECK(install(f, n, 0) == -1);
    return errno;
}

// One call's action: `nr` gets `ret`, everything else is allowed, after a
// libseccomp-style architecture check. (musl's getpid and getppid can't fail: the
// fixture makes those calls with syscall(2).)
static long only(long nr, unsigned ret, unsigned flags) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, ret),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    return install(f, sizeof f / sizeof f[0], flags);
}

static void no_new_privs(void) { CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0); }

// Run `f` in a child; its wait status.
static int in_child(void (*f)(void)) {
    fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        f();
        _exit(0);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    return status;
}

static void expect_ok(void (*f)(void)) {
    int st = in_child(f);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("FAILED: child status %#x\n", st);
        exit(1);
    }
}

static void expect_signal(void (*f)(void), int sig) {
    int st = in_child(f);
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig) {
        printf("FAILED: child status %#x, wanted signal %d\n", st, sig);
        exit(1);
    }
}

static int status_field(const char *name) {
    char buf[4096];
    FILE *f = fopen("/proc/self/status", "r");
    CHECK(f);
    int v = -1;
    size_t n = strlen(name);
    while (fgets(buf, sizeof buf, f)) {
        if (!strncmp(buf, name, n) && buf[n] == ':') v = atoi(buf + n + 1);
    }
    fclose(f);
    return v;
}

// ------------------------------------------------------------ checking programs

static void check_programs(void) {
    struct sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    // Neither no_new_privs nor root: EACCES (only uid 0 may skip it).
    if (getuid() != 0) CHECK(refused(allow, 1) == EACCES);
    no_new_privs();
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == -1 && errno == EINVAL);

    CHECK(refused(allow, 0) == EINVAL);
    static struct sock_filter big[4097];
    for (int i = 0; i < 4097; i++) big[i] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    CHECK(refused(big, 4097) == EINVAL);
    struct sock_fprog bad = {1, (void *)8};
    errno = 0;
    CHECK(sc(SECCOMP_SET_MODE_FILTER, 0, &bad) == -1 && errno == EFAULT);
    CHECK(sc(SECCOMP_SET_MODE_FILTER, 0, (void *)8) == -1 && errno == EFAULT);
    CHECK(sc(SECCOMP_SET_MODE_FILTER, 0x40, allow) == -1 && errno == EINVAL);
    CHECK(sc(99, 0, NULL) == -1 && errno == EINVAL);
    CHECK(sc(SECCOMP_SET_MODE_STRICT, 1, NULL) == -1 && errno == EINVAL);

    struct sock_filter misaligned[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 2), BPF_STMT(BPF_RET | BPF_A, 0)};
    CHECK(refused(misaligned, 2) == EINVAL);
    struct sock_filter past[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 64), BPF_STMT(BPF_RET | BPF_A, 0)};
    CHECK(refused(past, 2) == EINVAL);
    struct sock_filter half[] = {BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0), BPF_STMT(BPF_RET | BPF_A, 0)};
    CHECK(refused(half, 2) == EINVAL);
    struct sock_filter no_ret[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0)};
    CHECK(refused(no_ret, 1) == EINVAL);
    struct sock_filter jump_out[] = {BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0), BPF_STMT(BPF_RET | BPF_K, 0)};
    CHECK(refused(jump_out, 2) == EINVAL);
    struct sock_filter ja_out[] = {BPF_STMT(BPF_JMP | BPF_JA, 1), BPF_STMT(BPF_RET | BPF_K, 0)};
    CHECK(refused(ja_out, 2) == EINVAL);
    struct sock_filter div0[] = {BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 0), BPF_STMT(BPF_RET | BPF_A, 0)};
    CHECK(refused(div0, 2) == EINVAL);
    struct sock_filter mod[] = {BPF_STMT(BPF_ALU | BPF_MOD | BPF_K, 3), BPF_STMT(BPF_RET | BPF_A, 0)};
    CHECK(refused(mod, 2) == EINVAL);
    struct sock_filter shift[] = {BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 32), BPF_STMT(BPF_RET | BPF_A, 0)};
    CHECK(refused(shift, 2) == EINVAL);
    struct sock_filter unset_mem[] = {BPF_STMT(BPF_LD | BPF_MEM, 3), BPF_STMT(BPF_RET | BPF_A, 0)};
    CHECK(refused(unset_mem, 2) == EINVAL);
    // Written on one path only.
    struct sock_filter one_path[] = {
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
        BPF_STMT(BPF_ST, 3),
        BPF_STMT(BPF_LD | BPF_MEM, 3),
        BPF_STMT(BPF_RET | BPF_A, 0),
    };
    CHECK(refused(one_path, 4) == EINVAL);
    struct sock_filter mem_over[] = {BPF_STMT(BPF_ST, 16), BPF_STMT(BPF_RET | BPF_A, 0)};
    CHECK(refused(mem_over, 2) == EINVAL);
    // None of those were installed.
    CHECK(prctl(PR_GET_SECCOMP) == 0);
    CHECK(status_field("Seccomp") == 0 && status_field("NoNewPrivs") == 1);
}

// ------------------------------------------------------------ what filters see and return

// The scratch memory, X, ALU and the length load: A = len(seccomp_data)
// (64) + 2*4 - 8 = 64, through M[5]; then the low half of argument 1.
static void computing(void) {
    no_new_privs();
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
        BPF_STMT(BPF_LDX | BPF_IMM, 2),
        BPF_STMT(BPF_ST, 5),
        BPF_STMT(BPF_LD | BPF_IMM, 4),
        BPF_STMT(BPF_ALU | BPF_MUL | BPF_X, 0),
        BPF_STMT(BPF_MISC | BPF_TAX, 0),
        BPF_STMT(BPF_LD | BPF_MEM, 5),
        BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
        BPF_STMT(BPF_ALU | BPF_SUB | BPF_K, 8),
        BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 1), // 32
        BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 4), // 8
        BPF_STMT(BPF_ALU | BPF_OR | BPF_K, 0x100), // 0x108
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x108, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xfff),
        BPF_STMT(BPF_ALU | BPF_OR | BPF_K, SECCOMP_RET_ERRNO),
        BPF_STMT(BPF_RET | BPF_A, 0),
    };
    CHECK(install(f, sizeof f / sizeof f[0], 0) == 0);
    errno = 0;
    CHECK(syscall(SYS_getpid, 0, 0x123456789abcULL) == -1 && errno == 0xabc);
    CHECK(syscall(SYS_getpid, 0, 0x100000000ULL) == 0); // ERRNO with 0: success, as on Linux
}

static void actions(void) {
    no_new_privs();
    CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL) == -1 && errno == EFAULT);
    // ERRNO, capped at 4095.
    CHECK(only(SYS_getppid, SECCOMP_RET_ERRNO | 0xffff, 0) == 0);
    errno = 0;
    CHECK(syscall(SYS_getppid) == -1 && errno == 4095);
    // TRACE without a tracer: ENOSYS.
    CHECK(only(SYS_getuid, SECCOMP_RET_TRACE | 7, 0) == 0);
    CHECK(syscall(SYS_getuid) == -1 && errno == ENOSYS);
    // LOG: allowed.
    CHECK(only(SYS_getgid, SECCOMP_RET_LOG, 0) == 0);
    CHECK(getgid() == getegid());
    // Arguments: dup(200) only.
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_dup, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 200, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 77),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    CHECK(install(f, sizeof f / sizeof f[0], 0) == 0);
    CHECK(dup(200) == -1 && errno == 77);
    int fd = dup(1);
    CHECK(fd > 2);
    close(fd);
    // x86_64's x32 bit is in the number filters see.
    struct sock_filter x32[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 55),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    CHECK(install(x32, 4, 0) == 0);
    CHECK(syscall(0x40000000 | SYS_getpid) == -1 && errno == 55);
    CHECK(prctl(PR_GET_SECCOMP) == 2);
    CHECK(status_field("Seccomp") == 2 && status_field("Seccomp_filters") == 5);
}

// Stacked filters: the strictest action wins, and the newest of equals.
static void stacking(void) {
    no_new_privs();
    CHECK(only(SYS_getpid, SECCOMP_RET_ERRNO | 5, 0) == 0);
    CHECK(only(SYS_getpid, SECCOMP_RET_ALLOW, 0) == 0);
    CHECK(syscall(SYS_getpid) == -1 && errno == 5);
    CHECK(only(SYS_getpid, SECCOMP_RET_ERRNO | 6, 0) == 0);
    CHECK(syscall(SYS_getpid) == -1 && errno == 6);
    CHECK(only(SYS_getpid, SECCOMP_RET_ERRNO | 7, 0) == 0);
    CHECK(syscall(SYS_getpid) == -1 && errno == 7);
}

// ------------------------------------------------------------ TRAP

static volatile int trapped_nr, trapped_errno, trapped_code, trapped_arch;
static volatile unsigned long trapped_arg0, trapped_addr;

static void on_sigsys(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = uc_;
    CHECK(sig == SIGSYS && si->si_signo == SIGSYS);
    trapped_nr = si->si_syscall;
    trapped_errno = si->si_errno;
    trapped_code = si->si_code;
    trapped_arch = si->si_arch;
    trapped_addr = (unsigned long)si->si_call_addr;
    // The registers are the call's own, and the handler emulates it.
#if defined(__aarch64__)
    trapped_arg0 = uc->uc_mcontext.regs[0];
    CHECK(uc->uc_mcontext.regs[8] == (unsigned long)si->si_syscall);
    CHECK(uc->uc_mcontext.pc == trapped_addr);
    uc->uc_mcontext.regs[0] = 4242;
#else
    trapped_arg0 = uc->uc_mcontext.gregs[REG_RDI];
    CHECK(uc->uc_mcontext.gregs[REG_RAX] == si->si_syscall);
    CHECK((unsigned long)uc->uc_mcontext.gregs[REG_RIP] == trapped_addr);
    uc->uc_mcontext.gregs[REG_RAX] = 4242;
#endif
}

static void trap(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGSYS, &sa, NULL) == 0);
    no_new_privs();
    CHECK(only(SYS_getpriority, SECCOMP_RET_TRAP | 0x1234, 0) == 0);
    errno = 0;
    long r = syscall(SYS_getpriority, 0xabcdef, 0);
    CHECK(r == 4242);
    CHECK(trapped_nr == SYS_getpriority && trapped_errno == 0x1234 && trapped_code == 1 /* SYS_SECCOMP */);
    CHECK(trapped_arch == (int)ARCH && trapped_arg0 == 0xabcdef && trapped_addr != 0);
}

// A TRAP with SIGSYS blocked ends the process with SIGSYS.
static void trap_blocked(void) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGSYS);
    CHECK(sigprocmask(SIG_BLOCK, &s, NULL) == 0);
    no_new_privs();
    CHECK(only(SYS_getpriority, SECCOMP_RET_TRAP, 0) == 0);
    syscall(SYS_getpriority, 0, 0);
    _exit(9);
}

// ------------------------------------------------------------ kills

static void kill_process(void) {
    no_new_privs();
    CHECK(only(SYS_getppid, SECCOMP_RET_KILL_PROCESS, 0) == 0);
    syscall(SYS_getppid);
    _exit(9);
}

static void kill_thread_alone(void) {
    no_new_privs();
    CHECK(only(SYS_getppid, SECCOMP_RET_KILL_THREAD, 0) == 0);
    syscall(SYS_getppid);
    _exit(9);
}

static void unknown_action(void) {
    no_new_privs();
    CHECK(only(SYS_getppid, 0x00010000, 0) == 0);
    syscall(SYS_getppid);
    _exit(9);
}

static volatile long doomed_tid;

static void *calls_getppid(void *arg) {
    (void)arg;
    doomed_tid = syscall(SYS_gettid);
    syscall(SYS_getppid);
    for (;;) pause(); // never: the thread is killed
}

// KILL_THREAD with other threads: only the caller ends. (Not joined: the
// kernel clears musl's thread list lock, not the thread's join state, at
// a thread's end, so joining one that didn't end through pthread_exit
// waits forever, on Linux too.)
static void kill_thread(void) {
    no_new_privs();
    CHECK(only(SYS_getppid, SECCOMP_RET_KILL_THREAD, 0) == 0);
    pthread_t t;
    CHECK(pthread_create(&t, NULL, calls_getppid, NULL) == 0);
    while (!doomed_tid) sched_yield();
    while (syscall(SYS_tgkill, getpid(), doomed_tid, 0) == 0) sched_yield();
    CHECK(errno == ESRCH);
    _exit(0);
}

static void strict_mode(void) {
    CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) == 0);
    write(1, "", 0);
    syscall(SYS_getpid);
    syscall(SYS_exit, 9);
}

static void strict_exit(void) {
    CHECK(sc(SECCOMP_SET_MODE_STRICT, 0, NULL) == 0);
    write(1, "", 0);
    syscall(SYS_exit, 3);
}

// ------------------------------------------------------------ inheritance

static char *self_exe;

static void inherited(void) {
    no_new_privs();
    CHECK(only(SYS_getppid, SECCOMP_RET_ERRNO | 99, 0) == 0);
    // A child has it.
    fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(syscall(SYS_getppid) == -1 && errno == 99);
        _exit(0);
    }
    int st;
    CHECK(waitpid(pid, &st, 0) == pid && st == 0);
    // And a new program.
    char *argv[] = {self_exe, "after-exec", NULL};
    execv(self_exe, argv);
    CHECK(0);
}

static void after_exec(void) {
    CHECK(prctl(PR_GET_SECCOMP) == 2 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    CHECK(status_field("Seccomp_filters") == 1);
    CHECK(syscall(SYS_getppid) == -1 && errno == 99);
    _exit(0);
}

// ------------------------------------------------------------ threads and TSYNC

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int stage;
static volatile long other_result, other_errno, other_tid;

static void wait_stage(int s) {
    pthread_mutex_lock(&mu);
    while (stage < s) pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
}

static void set_stage(int s) {
    pthread_mutex_lock(&mu);
    stage = s;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
}

// Stage 1: tell its tid; 2: call getppid (unfiltered); 4: call it again.
static void *other(void *arg) {
    (void)arg;
    other_tid = syscall(SYS_gettid);
    set_stage(1);
    wait_stage(2);
    errno = 0;
    other_result = syscall(SYS_getppid);
    other_errno = errno;
    set_stage(3);
    wait_stage(4);
    errno = 0;
    other_result = syscall(SYS_getppid);
    other_errno = errno;
    set_stage(5);
    return NULL;
}

static void tsync(void) {
    no_new_privs();
    pthread_t t;
    CHECK(pthread_create(&t, NULL, other, NULL) == 0);
    wait_stage(1);
    // Without TSYNC, only this thread.
    CHECK(only(SYS_getppid, SECCOMP_RET_ERRNO | 11, 0) == 0);
    CHECK(syscall(SYS_getppid) == -1 && errno == 11);
    set_stage(2);
    wait_stage(3);
    CHECK(other_result > 0 && other_errno == 0);
    // The other thread has no filter, which every stack descends from:
    // TSYNC gives it this thread's.
    CHECK(only(SYS_getppid, SECCOMP_RET_ERRNO | 12, SECCOMP_FILTER_FLAG_TSYNC) == 0);
    set_stage(4);
    wait_stage(5);
    // Newest first, and equal actions: the TSYNC'd filter's.
    CHECK(other_result == -1 && other_errno == 12);
    CHECK(pthread_join(t, NULL) == 0);
    _exit(0);
}

// A thread with a filter of its own can't be synced: TSYNC fails with
// its id (or ESRCH, with TSYNC_ESRCH).
static volatile int diverged;
static void *diverge(void *arg) {
    (void)arg;
    other_tid = syscall(SYS_gettid);
    CHECK(only(SYS_getuid, SECCOMP_RET_ERRNO | 1, 0) == 0);
    diverged = 1;
    wait_stage(9);
    return NULL;
}

static void tsync_fails(void) {
    no_new_privs();
    pthread_t t;
    CHECK(pthread_create(&t, NULL, diverge, NULL) == 0);
    while (!diverged) sched_yield();
    long r = only(SYS_getppid, SECCOMP_RET_ERRNO | 13, SECCOMP_FILTER_FLAG_TSYNC);
    CHECK(r == other_tid);
    CHECK(only(SYS_getppid, SECCOMP_RET_ERRNO | 13, SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH) ==
          -1 && errno == ESRCH);
    // Nothing was installed.
    CHECK(syscall(SYS_getppid) > 0);
    set_stage(9);
    CHECK(pthread_join(t, NULL) == 0);
    _exit(0);
}

// ------------------------------------------------------------ budgets

static struct sock_filter big_filter[4096];

static int install_big(int max) {
    for (int i = 0; i < 4096; i++) big_filter[i] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    int n = 0;
    while (n < max && install(big_filter, 4096, 0) == 0) n++;
    return n;
}

// One thread's filters may hold 32768 instructions, each filter counting 4 more.
static void per_path(void) {
    no_new_privs();
    CHECK(install_big(100) == 7 && errno == ENOMEM);
}

// Every process's filters together: two children hold 7 * 4096
// instructions each, leaving room for two more of 64 Ki; once one of them
// is gone, there's room again.
static pid_t holder(int go) {
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(install_big(7) == 7);
        char c = 1;
        write(ready[1], &c, 1);
        read(go, &c, 1);
        _exit(0);
    }
    char c;
    CHECK(read(ready[0], &c, 1) == 1);
    close(ready[0]);
    close(ready[1]);
    return pid;
}

static void global_budget(void) {
    no_new_privs();
    int go[2];
    CHECK(pipe(go) == 0);
    pid_t a = holder(go[0]), b = holder(go[0]);
    int st;
    pid_t pid = fork();
    if (pid == 0) {
        CHECK(install_big(7) == 2 && errno == ENOMEM);
        _exit(0);
    }
    CHECK(waitpid(pid, &st, 0) == pid && st == 0);
    char c = 1;
    write(go[1], &c, 1);
    pid_t gone = wait(&st);
    CHECK((gone == a || gone == b) && st == 0);
    pid = fork();
    if (pid == 0) {
        CHECK(install_big(7) == 7);
        _exit(0);
    }
    CHECK(waitpid(pid, &st, 0) == pid && st == 0);
    write(go[1], &c, 1);
    CHECK(waitpid(gone == a ? b : a, &st, 0) > 0 && st == 0);
    _exit(0);
}

// At most 1024 filters alive, however small (and a stack that deep goes
// away without trouble).
static void filter_count(void) {
    no_new_privs();
    struct sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    int n = 0;
    while (n < 5000 && install(allow, 1, 0) == 0) n++;
    CHECK(n == 1024 && errno == ENOMEM);
    _exit(0);
}

// ------------------------------------------------------------ grix's gates first

// mount is denied by the policy: the filter's ERRNO never decides it,
// and the denial is reported.
static void gate_first(void) {
    no_new_privs();
    CHECK(only(SYS_mount, SECCOMP_RET_ERRNO | EACCES, 0) == 0);
    errno = 0;
    CHECK(mount("none", "/tmp", "tmpfs", 0, NULL) == -1 && errno == EPERM);
}

static void avail(void) {
    unsigned a;
    unsigned ok[] = {SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_TRAP, SECCOMP_RET_ERRNO,
                     SECCOMP_RET_TRACE,        SECCOMP_RET_LOG,         SECCOMP_RET_ALLOW};
    for (unsigned i = 0; i < sizeof ok / sizeof ok[0]; i++) CHECK(sc(SECCOMP_GET_ACTION_AVAIL, 0, &ok[i]) == 0);
    a = 0x12340000;
    CHECK(sc(SECCOMP_GET_ACTION_AVAIL, 0, &a) == -1 && errno == EOPNOTSUPP);
    CHECK(sc(SECCOMP_GET_ACTION_AVAIL, 1, &ok[0]) == -1 && errno == EINVAL);
    // User notification is unimplemented (reported).
    a = SECCOMP_RET_USER_NOTIF;
    CHECK(sc(SECCOMP_GET_ACTION_AVAIL, 0, &a) == -1 && errno == EOPNOTSUPP);
    struct sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    no_new_privs();
    CHECK(install(allow, 1, SECCOMP_FILTER_FLAG_NEW_LISTENER) == -1 && errno == EINVAL);
}

int main(int argc, char **argv) {
    self_exe = argv[0];
    if (argc > 1 && !strcmp(argv[1], "after-exec")) after_exec();
    CHECK(prctl(PR_GET_SECCOMP) == 0 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
    CHECK(status_field("Seccomp") == 0 && status_field("NoNewPrivs") == 0);
    expect_ok(check_programs);
    expect_ok(computing);
    expect_ok(actions);
    expect_ok(stacking);
    expect_ok(trap);
    expect_signal(trap_blocked, SIGSYS);
    expect_signal(kill_process, SIGSYS);
    expect_signal(kill_thread_alone, SIGSYS);
    expect_signal(unknown_action, SIGSYS);
    expect_ok(kill_thread);
    expect_signal(strict_mode, SIGKILL);
    int st = in_child(strict_exit);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 3);
    expect_ok(inherited);
    expect_ok(tsync);
    expect_ok(tsync_fails);
    expect_ok(per_path);
    expect_ok(global_budget);
    expect_ok(filter_count);
    expect_ok(gate_first);
    expect_ok(avail);
    printf("seccomp ok\n");
    return 0;
}
