// Signal delivery: handlers and SA_SIGINFO, masks and pending signals,
// queued real-time signals, SA_RESETHAND/SA_NODEFER, sigaltstack, FP/SIMD
// state across a handler, the ucontext (FP record, editable pc), SIGSEGV
// recovery, thread-directed signals, SA_RESTART vs EINTR, nanosleep's
// remaining time, sigsuspend, sigtimedwait, and a handled SIGPIPE.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d)\n", #c, __LINE__); return 1; } } while (0)
#define RUN(t) do { if (t()) return 1; } while (0)

static volatile sig_atomic_t got[65];
static volatile int last_code, last_pid, last_value, values[8], nvalues;
static volatile long handler_tid;
static void *volatile last_addr;
static volatile uintptr_t handler_sp;

static void on_sig(int sig) { got[sig]++; }

static void on_info(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    got[sig]++;
    last_code = si->si_code;
    last_pid = si->si_pid;
    last_addr = si->si_addr;
    if (sig >= SIGRTMIN && nvalues < 8) values[nvalues++] = si->si_value.sival_int;
}

static void handle(int sig, void (*fn)(int, siginfo_t *, void *), int flags) {
    struct sigaction sa = {0};
    sa.sa_sigaction = fn;
    sa.sa_flags = flags | SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, 0);
}

static void handle_simple(int sig, void (*fn)(int), int flags) {
    struct sigaction sa = {0};
    sa.sa_handler = fn;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, 0);
}

static void reset(void) { memset((void *)got, 0, sizeof got); }

static int test_basic(void) {
    reset();
    handle_simple(SIGUSR1, on_sig, 0);
    CHECK(raise(SIGUSR1) == 0);
    CHECK(got[SIGUSR1] == 1);
    handle(SIGUSR2, on_info, 0);
    CHECK(kill(getpid(), SIGUSR2) == 0);
    CHECK(got[SIGUSR2] == 1 && last_code == SI_USER && last_pid == getpid());
    CHECK(syscall(SYS_tgkill, getpid(), gettid(), SIGUSR2) == 0);
    CHECK(got[SIGUSR2] == 2 && last_code == SI_TKILL);
    // Ignored, and ignored by default: nothing happens.
    signal(SIGUSR1, SIG_IGN);
    raise(SIGUSR1);
    raise(SIGURG);
    raise(SIGCHLD);
    CHECK(kill(getpid(), 0) == 0);
    CHECK(kill(12345, SIGUSR1) == -1 && errno == ESRCH);
    CHECK(kill(getpid(), 65) == -1 && errno == EINVAL);
    // SA_UNSUPPORTED reads back as cleared: how programs probe for flag support.
    struct sigaction sa = {.sa_handler = on_sig, .sa_flags = 0x400}, old;
    CHECK(sigaction(SIGUSR1, &sa, 0) == 0 && sigaction(SIGUSR1, 0, &old) == 0);
    CHECK(old.sa_handler == on_sig && !(old.sa_flags & 0x400));
    return 0;
}

static int test_masks(void) {
    reset();
    handle_simple(SIGUSR1, on_sig, 0);
    sigset_t s, old, pend;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK, &s, &old) == 0);
    raise(SIGUSR1);
    raise(SIGUSR1);  // standard signals don't queue
    CHECK(got[SIGUSR1] == 0);
    CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGUSR1));
    CHECK(sigprocmask(SIG_SETMASK, &old, 0) == 0);
    CHECK(got[SIGUSR1] == 1);
    CHECK(sigpending(&pend) == 0 && !sigismember(&pend, SIGUSR1));
    // Real-time signals queue in order, with their values.
    nvalues = 0;
    handle(SIGRTMIN, on_info, 0);
    sigemptyset(&s);
    sigaddset(&s, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &s, 0);
    for (int i = 0; i < 3; i++) CHECK(sigqueue(getpid(), SIGRTMIN, (union sigval){.sival_int = 40 + i}) == 0);
    sigprocmask(SIG_UNBLOCK, &s, 0);
    CHECK(nvalues == 3 && values[0] == 40 && values[1] == 41 && values[2] == 42);
    CHECK(last_code == SI_QUEUE);
    // A pending signal set to SIG_IGN is discarded.
    sigaddset(&s, SIGUSR1);
    sigprocmask(SIG_BLOCK, &s, 0);
    raise(SIGUSR1);
    signal(SIGUSR1, SIG_IGN);
    CHECK(sigpending(&pend) == 0 && !sigismember(&pend, SIGUSR1));
    sigprocmask(SIG_UNBLOCK, &s, 0);
    return 0;
}

static volatile int mask_seen, nested_order[4], nested_n;
static void on_mask_probe(int sig) {
    sigset_t cur;
    sigprocmask(SIG_BLOCK, 0, &cur);
    mask_seen = sigismember(&cur, sig) | sigismember(&cur, SIGUSR2) << 1;
    got[sig]++;
}
static void on_inner(int sig) { nested_order[nested_n++] = sig; }
static void on_outer(int sig) {
    nested_order[nested_n++] = sig;
    raise(SIGUSR2);  // not blocked here: runs nested, before we continue
    nested_order[nested_n++] = -sig;
}

static int test_flags(void) {
    reset();
    // The handler runs with its signal and sa_mask blocked...
    struct sigaction sa = {.sa_handler = on_mask_probe};
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    sigaction(SIGUSR1, &sa, 0);
    raise(SIGUSR1);
    CHECK(mask_seen == 3);
    // ...unless SA_NODEFER, and the mask is restored afterwards.
    sa.sa_flags = SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, 0);
    raise(SIGUSR1);
    CHECK(mask_seen == 0);
    sigset_t cur;
    sigprocmask(SIG_BLOCK, 0, &cur);
    CHECK(!sigismember(&cur, SIGUSR1));
    // SA_RESETHAND: one-shot.
    handle_simple(SIGUSR1, on_sig, SA_RESETHAND);
    raise(SIGUSR1);
    struct sigaction now;
    sigaction(SIGUSR1, 0, &now);
    CHECK(got[SIGUSR1] == 3 && now.sa_handler == SIG_DFL);
    // Nested handlers.
    handle_simple(SIGUSR1, on_outer, 0);
    handle_simple(SIGUSR2, on_inner, 0);
    nested_n = 0;
    raise(SIGUSR1);
    CHECK(nested_n == 3 && nested_order[0] == SIGUSR1 && nested_order[1] == SIGUSR2 && nested_order[2] == -SIGUSR1);
    return 0;
}

static char altstack[64 * 1024];
static volatile int alt_flags, alt_change;
static void on_alt(int sig) {
    char local;
    handler_sp = (uintptr_t)&local;
    stack_t ss;
    sigaltstack(0, &ss);
    alt_flags = ss.ss_flags;
    stack_t other = {.ss_sp = altstack, .ss_size = sizeof altstack};
    alt_change = sigaltstack(&other, 0) == -1 ? errno : 0;
    got[sig]++;
}

static int test_altstack(void) {
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack}, old;
    CHECK(sigaltstack(0, &old) == 0 && old.ss_flags == SS_DISABLE);
    stack_t tiny = {.ss_sp = altstack, .ss_size = 1024};
    CHECK(sigaltstack(&tiny, 0) == -1 && errno == ENOMEM);
    CHECK(sigaltstack(&ss, 0) == 0);
    CHECK(sigaltstack(0, &old) == 0 && old.ss_flags == 0 && old.ss_sp == altstack && old.ss_size == sizeof altstack);
    handle_simple(SIGUSR1, on_alt, SA_ONSTACK);
    raise(SIGUSR1);
    CHECK(handler_sp > (uintptr_t)altstack && handler_sp < (uintptr_t)altstack + sizeof altstack);
    CHECK(alt_flags == SS_ONSTACK && alt_change == EPERM);
    // Without SA_ONSTACK the handler stays on the normal stack.
    handle_simple(SIGUSR1, on_alt, 0);
    raise(SIGUSR1);
    CHECK(!(handler_sp > (uintptr_t)altstack && handler_sp < (uintptr_t)altstack + sizeof altstack));
    CHECK(alt_flags == 0);
    stack_t off = {.ss_flags = SS_DISABLE};
    CHECK(sigaltstack(&off, 0) == 0);
    return 0;
}

static void on_clobber(int sig) {
    // Caller-saved FP/SIMD registers the compiler won't preserve for us.
    __asm__ volatile("movi v16.2d, #0\n movi v31.2d, #0\n" ::: "v16", "v31");
    got[sig]++;
}

// Hold a pattern in v16 across a tkill whose handler zeroes v16.
static uint64_t fp_across_signal(uint64_t pattern) {
    uint64_t out;
    register long x0 __asm__("x0") = gettid();
    register long x1 __asm__("x1") = SIGUSR1;
    register long x8 __asm__("x8") = SYS_tkill;
    __asm__ volatile("fmov d16, %[pat]\n svc #0\n fmov %[out], d16"
                     : [out] "=r"(out), "+r"(x0)
                     : [pat] "r"(pattern), "r"(x1), "r"(x8)
                     : "v16", "memory");
    return out;
}

static volatile uint32_t fp_magic;
static void on_trap(int sig, siginfo_t *si, void *ctx) {
    ucontext_t *uc = ctx;
    got[sig]++;
    last_addr = si->si_addr;
    // The first record in __reserved is the FP/SIMD state (FPSIMD_MAGIC).
    memcpy((void *)&fp_magic, &uc->uc_mcontext.__reserved, 4);
    uc->uc_mcontext.pc += 4;  // skip the brk
}

static int test_context(void) {
    reset();
    handle_simple(SIGUSR1, on_clobber, 0);
    CHECK(fp_across_signal(0x0123456789abcdefull) == 0x0123456789abcdefull);
    CHECK(got[SIGUSR1] == 1);
    // A handler can resume somewhere else by editing the saved pc.
    handle(SIGTRAP, on_trap, 0);
    __asm__ volatile("brk #7");
    CHECK(got[SIGTRAP] == 1 && fp_magic == 0x46508001);
    return 0;
}

static sigjmp_buf jb;
static void on_segv(int sig, siginfo_t *si, void *uc) {
    on_info(sig, si, uc);
    siglongjmp(jb, 1);
}

static int test_segv(void) {
    reset();
    handle(SIGSEGV, on_segv, 0);
    if (!sigsetjmp(jb, 1)) {
        *(volatile int *)0x10 = 1;
        CHECK(!"unreachable");
    }
    CHECK(got[SIGSEGV] == 1 && last_addr == (void *)0x10 && last_code == SEGV_MAPERR);
    volatile int *ro = mmap(0, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!sigsetjmp(jb, 1)) {
        *ro = 1;
        CHECK(!"unreachable");
    }
    CHECK(got[SIGSEGV] == 2 && last_addr == ro && last_code == SEGV_ACCERR);
    // siglongjmp restored the mask, so SIGSEGV isn't left blocked.
    sigset_t cur;
    sigprocmask(SIG_BLOCK, 0, &cur);
    CHECK(!sigismember(&cur, SIGSEGV));
    signal(SIGSEGV, SIG_DFL);
    return 0;
}

static int pipefd[2];
static volatile long reader_result, reader_errno, reader_tid;
static volatile struct timespec rem;
static volatile int sleep_ret, sleep_errno;

static void on_tid(int sig) {
    handler_tid = gettid();
    got[sig]++;
}

static void *reader(void *arg) {
    (void)arg;
    reader_tid = gettid();
    char c;
    reader_result = read(pipefd[0], &c, 1);
    reader_errno = errno;
    return 0;
}

static void *sleeper(void *arg) {
    (void)arg;
    struct timespec req = {2, 0}, r = {0, 0};
    sleep_ret = nanosleep(&req, &r);
    sleep_errno = errno;
    rem = r;
    return 0;
}

static int test_threads(void) {
    reset();
    // pthread_kill reaches that thread; SA_RESTART resumes its read.
    for (int restart = 1; restart >= 0; restart--) {
        handle_simple(SIGUSR1, on_tid, restart ? SA_RESTART : 0);
        CHECK(pipe(pipefd) == 0);
        pthread_t t;
        pthread_create(&t, 0, reader, 0);
        usleep(20000);  // let it block in read
        CHECK(pthread_kill(t, SIGUSR1) == 0);
        usleep(20000);
        CHECK(write(pipefd[1], "x", 1) == 1);
        pthread_join(t, 0);
        CHECK(handler_tid == reader_tid);
        if (restart) CHECK(reader_result == 1);
        else CHECK(reader_result == -1 && reader_errno == EINTR);
        close(pipefd[0]);
        close(pipefd[1]);
    }
    // Unrelated I/O wakes every blocked reader to re-check; a signal sent
    // before the reader runs again must still interrupt its read.
    int other[2];
    CHECK(pipe(pipefd) == 0 && pipe(other) == 0);
    pthread_t r;
    pthread_create(&r, 0, reader, 0);
    usleep(20000);
    CHECK(write(other[1], "y", 1) == 1);
    CHECK(pthread_kill(r, SIGUSR1) == 0);
    pthread_join(r, 0);
    CHECK(reader_result == -1 && reader_errno == EINTR);
    close(pipefd[0]);
    close(pipefd[1]);
    close(other[0]);
    close(other[1]);
    // An interrupted nanosleep reports the time left.
    pthread_t t;
    pthread_create(&t, 0, sleeper, 0);
    usleep(50000);
    pthread_kill(t, SIGUSR1);
    pthread_join(t, 0);
    CHECK(sleep_ret == -1 && sleep_errno == EINTR);
    long left_ms = rem.tv_sec * 1000 + rem.tv_nsec / 1000000;
    CHECK(left_ms > 1500 && left_ms < 2000);
    return 0;
}

static void *send_later(void *arg) {
    usleep(30000);
    kill(getpid(), (int)(long)arg);
    return 0;
}

static int test_waiting(void) {
    reset();
    handle_simple(SIGUSR1, on_sig, 0);
    sigset_t block, empty, cur;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigaddset(&block, SIGUSR2);
    sigemptyset(&empty);
    // kill() goes to the main thread first, even when the sender doesn't block it.
    pthread_t t;
    pthread_create(&t, 0, send_later, (void *)(long)SIGUSR1);
    CHECK(pause() == -1 && errno == EINTR);
    CHECK(got[SIGUSR1] == 1);
    pthread_join(t, 0);
    sigprocmask(SIG_BLOCK, &block, 0);
    // sigsuspend: wait with SIGUSR1 unblocked, then the old mask is back.
    pthread_create(&t, 0, send_later, (void *)(long)SIGUSR1);
    CHECK(sigsuspend(&empty) == -1 && errno == EINTR);
    CHECK(got[SIGUSR1] == 2);
    sigprocmask(SIG_BLOCK, 0, &cur);
    CHECK(sigismember(&cur, SIGUSR1));
    pthread_join(t, 0);
    // sigtimedwait: take a blocked signal without running a handler.
    sigset_t want;
    sigemptyset(&want);
    sigaddset(&want, SIGUSR2);
    siginfo_t si;
    pthread_create(&t, 0, send_later, (void *)(long)SIGUSR2);
    struct timespec ts = {1, 0};
    CHECK(sigtimedwait(&want, &si, &ts) == SIGUSR2 && si.si_code == SI_USER);
    pthread_join(t, 0);
    raise(SIGUSR2);
    CHECK(sigwaitinfo(&want, &si) == SIGUSR2);
    struct timespec short_ts = {0, 50 * 1000000};
    CHECK(sigtimedwait(&want, &si, &short_ts) == -1 && errno == EAGAIN);
    sigprocmask(SIG_UNBLOCK, &block, 0);
    return 0;
}

static int test_sigpipe(void) {
    reset();
    handle_simple(SIGPIPE, on_sig, 0);
    int p[2];
    pipe(p);
    close(p[0]);
    CHECK(write(p[1], "x", 1) == -1 && errno == EPIPE);
    CHECK(got[SIGPIPE] == 1);
    close(p[1]);
    return 0;
}

int main(void) {
    RUN(test_basic);
    RUN(test_masks);
    RUN(test_flags);
    RUN(test_altstack);
    RUN(test_context);
    RUN(test_segv);
    RUN(test_threads);
    RUN(test_waiting);
    RUN(test_sigpipe);
    printf("signals ok\n");
    return 0;
}
