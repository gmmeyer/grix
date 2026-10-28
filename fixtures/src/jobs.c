// Job control: stop signals stop a process (every thread of it), SIGCONT
// continues it, and the parent hears of both (wait4/waitid with WUNTRACED
// and WCONTINUED, SIGCHLD with CLD_STOPPED/CLD_CONTINUED unless
// SA_NOCLDSTOP). Needs `process` and `threads`.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

static void ms(int n) {
    struct timespec t = {n / 1000, (n % 1000) * 1000000L};
    while (nanosleep(&t, &t) == -1 && errno == EINTR) {
    }
}

// Counters the children bump, in memory shared with the parent.
static _Atomic long *counters;

static void *spin(void *arg) {
    _Atomic long *c = arg;
    for (;;) atomic_fetch_add(c, 1);
    return 0;
}

// A child whose threads (main and one more) count as fast as they can.
static pid_t spinner(void) {
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pthread_t t;
        CHECK(pthread_create(&t, 0, spin, (void *)&counters[1]) == 0);
        spin((void *)&counters[0]);
    }
    while (atomic_load(&counters[0]) == 0 || atomic_load(&counters[1]) == 0) ms(1);
    return pid;
}

static volatile sig_atomic_t chld_codes[8], nchld;
static void on_chld(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)uc;
    if (nchld < 8) chld_codes[nchld++] = si->si_code;
}

static volatile sig_atomic_t tstp_handled;
static void on_tstp(int sig) { (void)sig; tstp_handled = 1; }

int main(void) {
    counters = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(counters != MAP_FAILED);
    struct sigaction sa = {.sa_sigaction = on_chld, .sa_flags = SA_SIGINFO | SA_RESTART};
    CHECK(sigaction(SIGCHLD, &sa, 0) == 0);

    // SIGSTOP stops both threads; SIGCONT starts them again.
    pid_t pid = spinner();
    int st;
    CHECK(kill(pid, SIGSTOP) == 0);
    CHECK(waitpid(pid, &st, WUNTRACED) == pid && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
    long a = atomic_load(&counters[0]), b = atomic_load(&counters[1]);
    ms(100);
    CHECK(atomic_load(&counters[0]) == a && atomic_load(&counters[1]) == b);
    // Without WUNTRACED a stop isn't reported; and it's reported once.
    CHECK(waitpid(pid, &st, WNOHANG) == 0);
    CHECK(waitpid(pid, &st, WNOHANG | WUNTRACED) == 0);
    CHECK(kill(pid, SIGCONT) == 0);
    CHECK(waitpid(pid, &st, WCONTINUED) == pid && WIFCONTINUED(st));
    // Both threads run again (in time: slow emulation may take a while).
    for (int i = 0; i < 500 && (atomic_load(&counters[0]) == a || atomic_load(&counters[1]) == b); i++) ms(10);
    CHECK(atomic_load(&counters[0]) > a && atomic_load(&counters[1]) > b);
    CHECK(nchld == 2 && chld_codes[0] == CLD_STOPPED && chld_codes[1] == CLD_CONTINUED);

    // waitid sees a stop too, and SIGKILL ends a stopped process.
    CHECK(kill(pid, SIGTSTP) == 0);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    CHECK(waitid(P_PID, pid, &si, WSTOPPED) == 0);
    CHECK(si.si_pid == pid && si.si_code == CLD_STOPPED && si.si_status == SIGTSTP);
    CHECK(kill(pid, SIGKILL) == 0);
    CHECK(waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);

    // SA_NOCLDSTOP: no SIGCHLD for stopping and continuing, only the end.
    sa.sa_flags |= SA_NOCLDSTOP;
    CHECK(sigaction(SIGCHLD, &sa, 0) == 0);
    nchld = 0;
    atomic_store(&counters[0], 0);
    atomic_store(&counters[1], 0);
    pid = spinner();
    CHECK(kill(pid, SIGSTOP) == 0);
    CHECK(waitpid(pid, &st, WUNTRACED) == pid && WIFSTOPPED(st));
    CHECK(kill(pid, SIGCONT) == 0);
    CHECK(waitpid(pid, &st, WCONTINUED) == pid && WIFCONTINUED(st));
    CHECK(kill(pid, SIGKILL) == 0);
    CHECK(waitpid(pid, &st, 0) == pid);
    CHECK(nchld == 1 && chld_codes[0] == CLD_KILLED);

    // A child that stops itself, and one whose SIGTSTP has a handler.
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        raise(SIGTSTP);
        _exit(7);
    }
    CHECK(waitpid(pid, &st, WUNTRACED) == pid && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTSTP);
    CHECK(kill(pid, SIGCONT) == 0);
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 7);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        signal(SIGTSTP, on_tstp);
        raise(SIGTSTP);
        _exit(tstp_handled ? 8 : 9);
    }
    CHECK(waitpid(pid, &st, WUNTRACED) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 8);

    // A blocked stop signal waits; SIGCONT throws it away, and a stop
    // throws away a pending SIGCONT.
    sigset_t set, pending;
    sigemptyset(&set);
    sigaddset(&set, SIGTSTP);
    sigaddset(&set, SIGCONT);
    CHECK(sigprocmask(SIG_BLOCK, &set, 0) == 0);
    raise(SIGTSTP);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGTSTP));
    raise(SIGCONT);
    CHECK(sigpending(&pending) == 0 && !sigismember(&pending, SIGTSTP) && sigismember(&pending, SIGCONT));
    raise(SIGTSTP);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGTSTP) && !sigismember(&pending, SIGCONT));
    signal(SIGTSTP, SIG_IGN);
    CHECK(sigprocmask(SIG_UNBLOCK, &set, 0) == 0);

    printf("jobs ok\n");
    return 0;
}
