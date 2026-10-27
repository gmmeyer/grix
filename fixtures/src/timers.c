// Timers: setitimer/alarm (SIGALRM), POSIX timers (signals, overruns,
// SIGEV_THREAD_ID, SIGEV_NONE, absolute times) and timerfds (blocking,
// non-blocking, periodic, epoll). `timers alarm` lets SIGALRM's default
// action end the program.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)
#define RUN(t) do { if (t()) return 1; } while (0)

static volatile sig_atomic_t alarms, usr1, usr2;
static volatile int last_code, last_value, last_overrun, last_tid;

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void on_alarm(int sig) { (void)sig; alarms++; }

static void on_timer(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    if (sig == SIGUSR1) usr1++;
    if (sig == SIGUSR2) usr2++;
    last_code = si->si_code;
    last_value = si->si_value.sival_int;
    last_overrun = si->si_overrun;
    last_tid = gettid();
}

static void handle(int sig, void (*fn)(int, siginfo_t *, void *)) {
    struct sigaction sa = {.sa_sigaction = fn, .sa_flags = SA_SIGINFO};
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, 0);
}

static int test_itimer(void) {
    signal(SIGALRM, on_alarm);
    // One-shot: pause() returns when it fires.
    struct itimerval it = {{0, 0}, {0, 50000}}, cur;
    long t0 = now_ms();
    CHECK(setitimer(ITIMER_REAL, &it, 0) == 0);
    CHECK(getitimer(ITIMER_REAL, &cur) == 0 && cur.it_value.tv_usec > 0 && cur.it_value.tv_usec <= 50000);
    CHECK(pause() == -1 && errno == EINTR && alarms == 1);
    CHECK(now_ms() - t0 >= 45);
    CHECK(getitimer(ITIMER_REAL, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0);
    // Periodic, then disarmed.
    it = (struct itimerval){{0, 10000}, {0, 10000}};
    CHECK(setitimer(ITIMER_REAL, &it, 0) == 0);
    while (alarms < 6) pause();
    it = (struct itimerval){0};
    CHECK(setitimer(ITIMER_REAL, &it, 0) == 0);
    int seen = alarms;
    usleep(50000);
    CHECK(alarms == seen);
    // alarm() reports what was left.
    CHECK(alarm(5) == 0 && alarm(0) == 5);
    CHECK(setitimer(ITIMER_VIRTUAL, &it, 0) == -1 && errno == EINVAL);
    return 0;
}

static int test_posix(void) {
    handle(SIGUSR1, on_timer);
    handle(SIGUSR2, on_timer);
    // A one-shot timer carrying a value.
    timer_t t;
    struct sigevent ev = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1, .sigev_value.sival_int = 42};
    CHECK(timer_create(CLOCK_MONOTONIC, &ev, &t) == 0);
    struct itimerspec its = {{0, 0}, {0, 30000000}}, cur;
    CHECK(timer_settime(t, 0, &its, 0) == 0);
    CHECK(timer_gettime(t, &cur) == 0 && cur.it_value.tv_nsec > 0);
    while (!usr1) pause();
    CHECK(last_code == SI_TIMER && last_value == 42);
    CHECK(timer_gettime(t, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec == 0);
    // musl's timer_delete returns the raw -EINVAL rather than setting errno.
    CHECK(timer_delete(t) == 0 && timer_delete(t) != 0);
    // Absolute time on the realtime clock.
    CHECK(timer_create(CLOCK_REALTIME, &ev, &t) == 0);
    struct timespec rt;
    clock_gettime(CLOCK_REALTIME, &rt);
    rt.tv_nsec += 20000000;
    if (rt.tv_nsec >= 1000000000) { rt.tv_sec++; rt.tv_nsec -= 1000000000; }
    its = (struct itimerspec){{0, 0}, rt};
    CHECK(timer_settime(t, TIMER_ABSTIME, &its, 0) == 0);
    while (usr1 < 2) pause();
    CHECK(timer_delete(t) == 0);
    // Expiries while the signal is blocked fold into one signal's overrun.
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR2);
    sigprocmask(SIG_BLOCK, &s, 0);
    ev = (struct sigevent){.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR2};
    CHECK(timer_create(CLOCK_MONOTONIC, &ev, &t) == 0);
    its = (struct itimerspec){{0, 5000000}, {0, 5000000}};
    CHECK(timer_settime(t, 0, &its, 0) == 0);
    usleep(60000);
    // As on Linux, the overrun is counted when the signal is taken (so take
    // it before disarming: timer_settime resets the count).
    siginfo_t si;
    CHECK(sigwaitinfo(&s, &si) == SIGUSR2 && si.si_code == SI_TIMER && si.si_overrun >= 5);
    CHECK(timer_getoverrun(t) == si.si_overrun);
    its = (struct itimerspec){0};
    CHECK(timer_settime(t, 0, &its, 0) == 0 && timer_getoverrun(t) == 0);
    struct timespec zero = {0, 0};
    while (sigtimedwait(&s, &si, &zero) > 0) {}
    sigprocmask(SIG_UNBLOCK, &s, 0);
    timer_delete(t);
    // SIGEV_NONE: nothing is sent, but the time runs down.
    ev = (struct sigevent){.sigev_notify = SIGEV_NONE};
    CHECK(timer_create(CLOCK_MONOTONIC, &ev, &t) == 0);
    its = (struct itimerspec){{0, 0}, {1, 0}};
    CHECK(timer_settime(t, 0, &its, 0) == 0);
    usleep(20000);
    CHECK(timer_gettime(t, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec < 990000000);
    // Once it has run out, it reads as disarmed (a poll loop on it ends).
    its = (struct itimerspec){{0, 0}, {0, 5000000}};
    CHECK(timer_settime(t, 0, &its, 0) == 0);
    long t1 = now_ms();
    do {
        CHECK(timer_gettime(t, &cur) == 0);
        CHECK(now_ms() - t1 < 1000);
    } while (cur.it_value.tv_sec || cur.it_value.tv_nsec);
    timer_delete(t);
    return 0;
}

static long spin_ms(long ms) {
    long t0 = now_ms(), spins = 0;
    while (now_ms() - t0 < ms) spins++;
    return spins;
}

static int test_tiny_intervals(void) {
    // A 1 ns periodic timer re-arms only once its expiry is consumed, so it
    // can't starve the program: with SIGALRM ignored, blocked, or a timerfd
    // nobody reads.
    struct itimerval it = {{0, 1}, {0, 1}}, off = {0};
    signal(SIGALRM, SIG_IGN);
    CHECK(setitimer(ITIMER_REAL, &it, 0) == 0);
    CHECK(spin_ms(30) > 10);
    setitimer(ITIMER_REAL, &off, 0);
    signal(SIGALRM, on_alarm);
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGALRM);
    sigprocmask(SIG_BLOCK, &s, 0);
    alarms = 0;
    CHECK(setitimer(ITIMER_REAL, &it, 0) == 0);
    CHECK(spin_ms(30) > 10);
    setitimer(ITIMER_REAL, &off, 0);
    sigprocmask(SIG_UNBLOCK, &s, 0);
    CHECK(alarms == 1);
    // A POSIX timer with its signal blocked: one signal, a large overrun.
    sigemptyset(&s);
    sigaddset(&s, SIGUSR2);
    sigprocmask(SIG_BLOCK, &s, 0);
    timer_t t;
    struct sigevent ev = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR2};
    CHECK(timer_create(CLOCK_MONOTONIC, &ev, &t) == 0);
    struct itimerspec its = {{0, 1}, {0, 1}};
    CHECK(timer_settime(t, 0, &its, 0) == 0);
    CHECK(spin_ms(30) > 10);
    // Take it while still blocked (unblocked, a 1 ns timer's handler would
    // run back to back, on Linux too).
    siginfo_t si;
    CHECK(sigwaitinfo(&s, &si) == SIGUSR2 && si.si_overrun > 1000);
    timer_delete(t);
    struct timespec zero = {0, 0};
    while (sigtimedwait(&s, &si, &zero) > 0) {}  // drop any expiry since
    sigprocmask(SIG_UNBLOCK, &s, 0);
    // A timerfd that isn't read.
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    its = (struct itimerspec){{0, 1}, {0, 1}};
    CHECK(timerfd_settime(fd, 0, &its, 0) == 0);
    CHECK(spin_ms(30) > 10);
    uint64_t ticks;
    CHECK(read(fd, &ticks, 8) == 8 && ticks > 1000);
    close(fd);
    return 0;
}

static int tfd_shared;
static volatile uint64_t reader_ticks;
static void *tfd_reader(void *arg) {
    (void)arg;
    uint64_t t;
    if (read(tfd_shared, &t, 8) == 8) reader_ticks = t;
    return 0;
}

static int test_timerfd_poll_race(void) {
    // Another thread polling the timerfd counts the expiry; the reader
    // blocked in read() must still wake up.
    tfd_shared = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its = {{0, 0}, {0, 20000000}};
    CHECK(timerfd_settime(tfd_shared, 0, &its, 0) == 0);
    pthread_t th;
    pthread_create(&th, 0, tfd_reader, 0);
    struct pollfd pfd = {.fd = tfd_shared, .events = POLLIN};
    // Whichever sees the one-shot expiry first: the poll here (the case
    // that matters) or the reader, which then consumes it.
    while (!reader_ticks && poll(&pfd, 1, 0) == 0) {}
    pthread_join(th, 0);
    CHECK(reader_ticks == 1);
    close(tfd_shared);
    return 0;
}

static volatile long target_tid;
static volatile int target_done;
static void *target(void *arg) {
    (void)arg;
    target_tid = gettid();
    sigset_t none;
    sigemptyset(&none);
    while (!target_done) sigsuspend(&none);
    return 0;
}

static int test_thread_target(void) {
    // SIGEV_THREAD_ID: the signal goes to that thread, even though the main
    // thread doesn't block it either.
    usr1 = 0;
    pthread_t th;
    pthread_create(&th, 0, target, 0);
    while (!target_tid) usleep(1000);
    timer_t t;
    struct sigevent ev = {.sigev_notify = SIGEV_THREAD_ID, .sigev_signo = SIGUSR1};
    ev.sigev_notify_thread_id = target_tid;
    CHECK(timer_create(CLOCK_MONOTONIC, &ev, &t) == 0);
    struct itimerspec its = {{0, 0}, {0, 10000000}};
    CHECK(timer_settime(t, 0, &its, 0) == 0);
    while (!usr1) usleep(1000);
    CHECK(last_tid == target_tid);
    target_done = 1;
    pthread_kill(th, SIGUSR1);
    pthread_join(th, 0);
    timer_delete(t);
    return 0;
}

static int test_timerfd(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    CHECK(fd >= 0);
    uint64_t ticks;
    struct itimerspec its = {{0, 0}, {0, 30000000}}, cur;
    long t0 = now_ms();
    CHECK(timerfd_settime(fd, 0, &its, 0) == 0);
    CHECK(timerfd_gettime(fd, &cur) == 0 && cur.it_value.tv_nsec > 0);
    CHECK(read(fd, &ticks, 8) == 8 && ticks == 1);  // blocks until it fires
    CHECK(now_ms() - t0 >= 25);
    CHECK(read(fd, &ticks, 4) == -1 && errno == EINVAL);
    // Periodic: expiries add up until read.
    its = (struct itimerspec){{0, 10000000}, {0, 10000000}};
    long armed = now_ms();
    CHECK(timerfd_settime(fd, 0, &its, 0) == 0);
    usleep(55000);
    CHECK(read(fd, &ticks, 8) == 8);
    long periods = (now_ms() - armed) / 10;  // however long the sleep really took
    CHECK(ticks >= 4 && (long)ticks <= periods + 1 && (long)ticks >= periods - 1);
    its = (struct itimerspec){0};
    CHECK(timerfd_settime(fd, 0, &its, &cur) == 0 && cur.it_interval.tv_nsec == 10000000);
    close(fd);
    // Non-blocking, absolute, and woken through epoll.
    fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    CHECK(read(fd, &ticks, 8) == -1 && errno == EAGAIN);
    struct timespec rt;
    clock_gettime(CLOCK_REALTIME, &rt);
    rt.tv_sec += 0;
    rt.tv_nsec += 20000000;
    if (rt.tv_nsec >= 1000000000) { rt.tv_sec++; rt.tv_nsec -= 1000000000; }
    its = (struct itimerspec){{0, 0}, rt};
    CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, 0) == 0);
    int ep = epoll_create1(0);
    struct epoll_event e = {.events = EPOLLIN, .data.u32 = 7};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e) == 0);
    CHECK(epoll_wait(ep, &e, 1, 1000) == 1 && e.data.u32 == 7);
    CHECK(read(fd, &ticks, 8) == 8 && ticks == 1);
    close(ep);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "alarm")) {
        alarm(1);
        for (;;) pause();
    }
    RUN(test_itimer);
    RUN(test_posix);
    RUN(test_thread_target);
    RUN(test_timerfd);
    RUN(test_tiny_intervals);
    RUN(test_timerfd_poll_race);
    printf("timers ok\n");
    return 0;
}
