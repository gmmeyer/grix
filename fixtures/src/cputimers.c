// Timers on CPU time: setitimer's ITIMER_VIRTUAL and ITIMER_PROF, and
// POSIX timers on CPU-time clocks (the process's, a thread's). They only
// run while the program does. Needs `process` and `threads`.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timerfd.h>
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

static volatile sig_atomic_t prof, vt, usr1, usr2;
static void on_signal(int sig) {
    if (sig == SIGPROF) prof++;
    if (sig == SIGVTALRM) vt++;
    if (sig == SIGUSR1) usr1++;
    if (sig == SIGUSR2) usr2++;
}

static long cpu_ms(clockid_t clock) {
    struct timespec t;
    CHECK(clock_gettime(clock, &t) == 0);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

// Burn CPU until `flag` is set or `ms` of CPU time on `clock` have passed.
static void spin(clockid_t clock, long ms, volatile sig_atomic_t *flag) {
    long end = cpu_ms(clock) + ms;
    while ((!flag || !*flag) && cpu_ms(clock) < end) {
    }
}

static void sleep_ms(int n) {
    struct timespec t = {n / 1000, (n % 1000) * 1000000L};
    while (nanosleep(&t, &t) == -1 && errno == EINTR) {
    }
}

static long left_ms(int which) {
    struct itimerval v;
    CHECK(getitimer(which, &v) == 0);
    return v.it_value.tv_sec * 1000 + v.it_value.tv_usec / 1000;
}

static atomic_int stop_spinning;
static void *spinner(void *arg) {
    (void)arg;
    while (!atomic_load(&stop_spinning)) {
    }
    return NULL;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    CHECK(sigaction(SIGPROF, &sa, NULL) == 0);
    CHECK(sigaction(SIGVTALRM, &sa, NULL) == 0);
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    CHECK(sigaction(SIGUSR2, &sa, NULL) == 0);

    // ITIMER_PROF, every 10ms of CPU time: about 20 signals in 200ms of it.
    struct itimerval every = {{0, 10000}, {0, 10000}};
    CHECK(setitimer(ITIMER_PROF, &every, NULL) == 0);
    long left = left_ms(ITIMER_PROF);
    CHECK(left >= 0 && left <= 10);
    spin(CLOCK_PROCESS_CPUTIME_ID, 200, NULL);
    struct itimerval off = {{0, 0}, {0, 0}};
    CHECK(setitimer(ITIMER_PROF, &off, NULL) == 0);
    CHECK(prof >= 8 && prof <= 25);
    int seen = prof;
    spin(CLOCK_PROCESS_CPUTIME_ID, 50, NULL);
    CHECK(prof == seen);

    // ITIMER_VIRTUAL doesn't run while the program sleeps.
    // (Generous margins: under emulation, even a little work takes a while.)
    struct itimerval once = {{0, 0}, {0, 300000}};
    CHECK(setitimer(ITIMER_VIRTUAL, &once, NULL) == 0);
    sleep_ms(200);
    CHECK(vt == 0);
    CHECK(left_ms(ITIMER_VIRTUAL) > 200);
    spin(CLOCK_PROCESS_CPUTIME_ID, 2000, &vt);
    CHECK(vt == 1);
    CHECK(left_ms(ITIMER_VIRTUAL) == 0);

    // A child doesn't inherit them.
    CHECK(setitimer(ITIMER_PROF, &every, NULL) == 0);
    pid_t kid = fork();
    CHECK(kid >= 0);
    if (kid == 0) {
        _exit(left_ms(ITIMER_PROF) == 0 ? 0 : 1);
    }
    int status;
    CHECK(waitpid(kid, &status, 0) == kid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(setitimer(ITIMER_PROF, &off, NULL) == 0);

    // A POSIX timer on the process's CPU time.
    struct sigevent ev;
    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGUSR1;
    timer_t t;
    CHECK(timer_create(CLOCK_PROCESS_CPUTIME_ID, &ev, &t) == 0);
    struct itimerspec in20 = {{0, 0}, {0, 20000000}}, in300 = {{0, 0}, {0, 300000000}};
    CHECK(timer_settime(t, 0, &in300, NULL) == 0);
    sleep_ms(100);
    CHECK(usr1 == 0);
    struct itimerspec cur;
    CHECK(timer_gettime(t, &cur) == 0);
    CHECK(cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec > 0 && cur.it_value.tv_nsec <= 300000000);
    long start = cpu_ms(CLOCK_PROCESS_CPUTIME_ID);
    spin(CLOCK_PROCESS_CPUTIME_ID, 2000, &usr1);
    CHECK(usr1 == 1);
    CHECK(cpu_ms(CLOCK_PROCESS_CPUTIME_ID) - start >= 5);
    // Absolute: a CPU time already passed fires at once.
    struct itimerspec past = {{0, 0}, {0, 1}};
    CHECK(timer_settime(t, TIMER_ABSTIME, &past, NULL) == 0);
    spin(CLOCK_PROCESS_CPUTIME_ID, 2000, &usr1);
    CHECK(usr1 == 2);
    CHECK(timer_delete(t) == 0);

    // A thread's CPU time: another thread spinning doesn't count.
    ev.sigev_signo = SIGUSR2;
    CHECK(timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &t) == 0);
    CHECK(timer_settime(t, 0, &in300, NULL) == 0);
    pthread_t th;
    CHECK(pthread_create(&th, NULL, spinner, NULL) == 0);
    sleep_ms(150);
    CHECK(usr2 == 0);
    atomic_store(&stop_spinning, 1);
    CHECK(pthread_join(th, NULL) == 0);
    spin(CLOCK_THREAD_CPUTIME_ID, 2000, &usr2);
    CHECK(usr2 == 1);
    CHECK(timer_delete(t) == 0);
    // pthread_getcpuclockid's clock works too.
    clockid_t mine;
    CHECK(pthread_getcpuclockid(pthread_self(), &mine) == 0);
    CHECK(timer_create(mine, &ev, &t) == 0);
    CHECK(timer_settime(t, 0, &in20, NULL) == 0);
    usr2 = 0;
    spin(mine, 2000, &usr2);
    CHECK(usr2 == 1);
    CHECK(timer_delete(t) == 0);

    // timerfds only take wall clocks.
    CHECK(timerfd_create(CLOCK_PROCESS_CPUTIME_ID, 0) == -1 && errno == EINVAL);

    printf("cputimers ok\n");
    return 0;
}
