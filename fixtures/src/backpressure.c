// Writing to stdout while the host is slow to read. Blocking writes and
// writevs, however big, complete in one call, even with nothing else to
// wake the program. A nonblocking write fails with EAGAIN and epoll says
// when there's room again. A blocking write waits without stopping the
// program's other threads, and a signal handler interrupting it makes it
// return what it sent (or EINTR if nothing). Writes 14 MiB of
// (i % 1 MiB) % 251 to stdout and reports on stderr.
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define MIB (1 << 20)

static atomic_long ticks;
static char buf[MIB];

static void *ticker(void *arg) {
    (void)arg;
    for (;;) {
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, 0);
        ticks++;
    }
}

static void on_alarm(int sig) { (void)sig; }

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(void) {
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (char)(i % 251);

    // One thread and no timers: only the host taking output can wake it.
    int full = write(1, buf, MIB) == MIB;
    struct iovec iov[2] = {{buf, 100}, {buf + 100, MIB - 100}};
    full &= writev(1, iov, 2) == MIB;

    pthread_t t;
    pthread_create(&t, 0, ticker, 0);

    // Nonblocking: 4 MiB, waiting in epoll whenever stdout is full.
    fcntl(1, F_SETFL, fcntl(1, F_GETFL) | O_NONBLOCK);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLOUT};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, 1, &ev) != 0) {
        fprintf(stderr, "epoll_ctl: errno %d\n", errno);
        return 1;
    }
    long eagain = 0;
    for (int round = 0; round < 4; round++) {
        for (size_t off = 0; off < sizeof buf;) {
            ssize_t n = write(1, buf + off, sizeof buf - off);
            if (n < 0 && errno == EAGAIN) {
                eagain++;
                if (epoll_wait(ep, &ev, 1, -1) != 1 || !(ev.events & EPOLLOUT)) {
                    fprintf(stderr, "epoll_wait failed\n");
                    return 1;
                }
                continue;
            }
            if (n <= 0) {
                fprintf(stderr, "write: errno %d\n", errno);
                return 1;
            }
            off += n;
        }
    }

    // Blocking again: 4 MiB in 64 KiB writes while the ticker runs.
    fcntl(1, F_SETFL, fcntl(1, F_GETFL) & ~O_NONBLOCK);
    long slow = 0, ran = 0;
    for (int i = 0; i < 64; i++) {
        long t0 = ticks, start = now_ms();
        full &= write(1, buf + (i % 16) * 65536, 65536) == 65536;
        if (now_ms() - start > 50) {
            slow++;
            ran += ticks > t0;
        }
    }
    // 4 MiB in 1 MiB writes with SIGALRM every 5 ms (no SA_RESTART): each
    // write sends all of it, or returns early with what it sent, or fails
    // with EINTR having sent nothing. Resuming from there keeps the stream
    // intact (the host checks it).
    struct sigaction sa = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &sa, 0);
    struct itimerval every = {{0, 5000}, {0, 5000}}, off = {0};
    setitimer(ITIMER_REAL, &every, 0);
    long interrupted = 0;
    for (int round = 0; round < 4; round++) {
        for (size_t at = 0; at < sizeof buf;) {
            ssize_t n = write(1, buf + at, sizeof buf - at);
            if (n < 0 && errno == EINTR) {
                interrupted++;
                continue;
            }
            if (n <= 0) {
                fprintf(stderr, "write: errno %d\n", errno);
                return 1;
            }
            interrupted += (size_t)n < sizeof buf - at;
            at += n;
        }
    }
    setitimer(ITIMER_REAL, &off, 0);
    fprintf(stderr, "full=%d eagain=%d waited=%d ticker_ran=%d interrupted=%d\n", full, eagain > 0, slow > 0,
            ran > 0, interrupted > 0);
    return 0;
}
