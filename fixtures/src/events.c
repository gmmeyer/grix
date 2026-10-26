// Pipes, eventfd, epoll (level + edge triggered), poll and select, all
// blocking across threads.
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

#define TOTAL (1 << 20)

static void *bulk_writer(void *arg) {
    int fd = (int)(intptr_t)arg;
    static unsigned char buf[10000];
    size_t sent = 0;
    while (sent < TOTAL) {
        size_t n = TOTAL - sent < sizeof buf ? TOTAL - sent : sizeof buf;
        for (size_t i = 0; i < n; i++) buf[i] = (unsigned char)(sent + i);
        ssize_t w = write(fd, buf, n);
        if (w <= 0) return (void *)1;
        sent += (size_t)w;
    }
    close(fd);
    return 0;
}

static void *delayed_write(void *arg) {
    usleep(20 * 1000);
    int fd = (int)(intptr_t)arg;
    uint64_t one = 1;
    write(fd, &one, 8);
    return 0;
}

static void *delayed_pipe_write(void *arg) {
    usleep(20 * 1000);
    write((int)(intptr_t)arg, "x", 1);
    return 0;
}

int main(void) {
    // 1. A writer thread pushes 1 MiB through a 64 KiB pipe; both sides block.
    int p[2];
    CHECK(pipe(p) == 0);
    pthread_t t;
    CHECK(pthread_create(&t, 0, bulk_writer, (void *)(intptr_t)p[1]) == 0);
    unsigned char buf[7000];
    size_t got = 0;
    ssize_t n;
    while ((n = read(p[0], buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++) CHECK(buf[i] == (unsigned char)(got + i));
        got += (size_t)n;
    }
    CHECK(n == 0 && got == TOTAL);  // EOF once the writer closed
    void *ret;
    CHECK(pthread_join(t, &ret) == 0 && ret == 0);
    close(p[0]);

    // 2. Non-blocking read on an empty pipe; EPIPE once the reader is gone.
    CHECK(pipe2(p, O_NONBLOCK | O_CLOEXEC) == 0);
    CHECK(read(p[0], buf, 1) == -1 && errno == EAGAIN);
    signal(SIGPIPE, SIG_IGN);
    close(p[0]);
    CHECK(write(p[1], "x", 1) == -1 && errno == EPIPE);
    close(p[1]);

    // 3. eventfd counter and semaphore modes.
    int efd = eventfd(0, 0);
    CHECK(efd >= 0);
    uint64_t v = 2;
    CHECK(write(efd, &v, 8) == 8);
    v = 3;
    CHECK(write(efd, &v, 8) == 8);
    CHECK(read(efd, &v, 8) == 8 && v == 5);
    int sem = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    CHECK(read(sem, &v, 8) == 8 && v == 1);
    CHECK(read(sem, &v, 8) == 8 && v == 1);
    CHECK(read(sem, &v, 8) == -1 && errno == EAGAIN);

    // 4. epoll blocks until another thread signals the eventfd.
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    struct epoll_event ev = {.events = EPOLLIN, .data.u64 = 42};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev) == -1 && errno == EEXIST);
    struct epoll_event out[4];
    long t0 = now_ms();
    CHECK(epoll_wait(ep, out, 4, 30) == 0);  // times out
    CHECK(now_ms() - t0 >= 25);
    CHECK(pthread_create(&t, 0, delayed_write, (void *)(intptr_t)efd) == 0);
    t0 = now_ms();
    CHECK(epoll_wait(ep, out, 4, 5000) == 1);
    CHECK(out[0].data.u64 == 42 && (out[0].events & EPOLLIN));
    CHECK(now_ms() - t0 >= 15);
    pthread_join(t, 0);
    CHECK(epoll_wait(ep, out, 4, 0) == 1);  // level triggered: still readable
    CHECK(read(efd, &v, 8) == 8 && v == 1);
    CHECK(epoll_wait(ep, out, 4, 0) == 0);

    // 5. Edge triggered: one event per change, not per wait.
    CHECK(pipe(p) == 0);
    struct epoll_event et = {.events = EPOLLIN | EPOLLET, .data.u64 = 7};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &et) == 0);
    CHECK(write(p[1], "ab", 2) == 2);
    CHECK(epoll_wait(ep, out, 4, 0) == 1 && out[0].data.u64 == 7);
    CHECK(epoll_wait(ep, out, 4, 0) == 0);
    CHECK(write(p[1], "c", 1) == 1);
    CHECK(epoll_wait(ep, out, 4, 0) == 1);
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, p[0], 0) == 0);
    CHECK(read(p[0], buf, sizeof buf) == 3);

    // 6. poll() and select() wake when another thread writes.
    CHECK(pthread_create(&t, 0, delayed_pipe_write, (void *)(intptr_t)p[1]) == 0);
    struct pollfd pfd = {.fd = p[0], .events = POLLIN};
    CHECK(poll(&pfd, 1, 5000) == 1 && (pfd.revents & POLLIN));
    pthread_join(t, 0);
    CHECK(read(p[0], buf, 1) == 1);
    CHECK(pthread_create(&t, 0, delayed_pipe_write, (void *)(intptr_t)p[1]) == 0);
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(p[0], &rs);
    struct timeval tv = {5, 0};
    CHECK(select(p[0] + 1, &rs, 0, 0, &tv) == 1 && FD_ISSET(p[0], &rs));
    pthread_join(t, 0);

    // 7. AF_UNIX socket pair: both directions, peek, non-blocking, shutdown.
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);
    CHECK(send(sv[0], "ping", 4, 0) == 4);
    CHECK(recv(sv[1], buf, sizeof buf, MSG_PEEK) == 4);
    CHECK(recv(sv[1], buf, sizeof buf, 0) == 4 && memcmp(buf, "ping", 4) == 0);
    CHECK(write(sv[1], "pong", 4) == 4);
    CHECK(read(sv[0], buf, sizeof buf) == 4 && memcmp(buf, "pong", 4) == 0);
    CHECK(recv(sv[0], buf, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    int type = 0;
    socklen_t len = sizeof type;
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &type, &len) == 0 && type == SOCK_STREAM);
    CHECK(shutdown(sv[1], SHUT_WR) == 0);
    CHECK(recv(sv[0], buf, sizeof buf, 0) == 0);  // EOF
    CHECK(socket(AF_INET, SOCK_STREAM, 0) == -1 && errno == EPERM);  // network still gated

    printf("events ok\n");
    return 0;
}
