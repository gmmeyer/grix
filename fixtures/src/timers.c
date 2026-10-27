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
    its = (struct itimerspec){0};
    CHECK(timer_settime(t, 0, &its, 0) == 0);
    sigprocmask(SIG_UNBLOCK, &s, 0);
    CHECK(usr2 == 1 && last_overrun >= 5);
    CHECK(timer_getoverrun(t) >= 5);
    timer_delete(t);
    // SIGEV_NONE: nothing is sent, but the time runs down.
    ev = (struct sigevent){.sigev_notify = SIGEV_NONE};
    CHECK(timer_create(CLOCK_MONOTONIC, &ev, &t) == 0);
    its = (struct itimerspec){{0, 0}, {1, 0}};
    CHECK(timer_settime(t, 0, &its, 0) == 0);
    usleep(20000);
    CHECK(timer_gettime(t, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec < 990000000);
    timer_delete(t);
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
    CHECK(timerfd_settime(fd, 0, &its, 0) == 0);
    usleep(55000);
    CHECK(read(fd, &ticks, 8) == 8 && ticks >= 4 && ticks <= 6);
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
    printf("timers ok\n");
    return 0;
}
