// POSIX message queues. Passes on Linux as it is.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static char name[32];
static volatile sig_atomic_t notified, code, value;

static void on_message(int sig, siginfo_t *i, void *u) {
    (void)u;
    notified = sig;
    code = i->si_code;
    value = i->si_value.sival_int;
}

static void wait_ok(pid_t c) {
    int status;
    CHECK(waitpid(c, &status, 0) == c && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static struct timespec soon(void) {
    struct timespec t;
    CHECK(clock_gettime(CLOCK_REALTIME, &t) == 0);
    t.tv_nsec += 20000000;
    if (t.tv_nsec >= 1000000000) {
        t.tv_nsec -= 1000000000;
        t.tv_sec++;
    }
    return t;
}

static void opening(void) {
    struct mq_attr a = {.mq_maxmsg = 4, .mq_msgsize = 16};
    FAILS(mq_open(name, O_RDWR), ENOENT);
    mqd_t q = mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &a);
    CHECK(q != (mqd_t)-1);
    FAILS(mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &a), EEXIST);
    mqd_t again = mq_open(name, O_RDONLY);
    CHECK(again != (mqd_t)-1);
    // A descriptor says what it is.
    struct stat st;
    CHECK(fstat(q, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600);
    struct mq_attr got;
    CHECK(mq_getattr(q, &got) == 0);
    CHECK(got.mq_maxmsg == 4 && got.mq_msgsize == 16 && got.mq_curmsgs == 0 && got.mq_flags == 0);
    // Limits.
    struct mq_attr bad = {.mq_maxmsg = 0, .mq_msgsize = 16};
    char other[40];
    snprintf(other, sizeof other, "%s.bad", name);
    FAILS(mq_open(other, O_CREAT | O_RDWR, 0600, &bad), EINVAL);
    bad = (struct mq_attr){.mq_maxmsg = 4, .mq_msgsize = 0};
    FAILS(mq_open(other, O_CREAT | O_RDWR, 0600, &bad), EINVAL);
    bad = (struct mq_attr){.mq_maxmsg = -1, .mq_msgsize = 16};
    FAILS(mq_open(other, O_CREAT | O_RDWR, 0600, &bad), EINVAL);
    // Without attributes: what the system's defaults are.
    mqd_t d = mq_open(other, O_CREAT | O_RDWR, 0600, 0);
    CHECK(d != (mqd_t)-1 && mq_getattr(d, &got) == 0 && got.mq_maxmsg == 10 && got.mq_msgsize == 8192);
    CHECK(mq_close(d) == 0 && mq_unlink(other) == 0);
    FAILS(mq_close(d), EBADF);
    CHECK(mq_close(again) == 0 && mq_close(q) == 0);
    printf("opening ok\n");
}

static void messages(void) {
    mqd_t q = mq_open(name, O_RDWR);
    CHECK(q != (mqd_t)-1);
    mqd_t w = mq_open(name, O_WRONLY), r = mq_open(name, O_RDONLY);
    CHECK(w != (mqd_t)-1 && r != (mqd_t)-1);
    char b[16];
    unsigned prio = 99;
    FAILS(mq_send(r, "x", 1, 0), EBADF);
    FAILS(mq_receive(w, b, sizeof b, 0), EBADF);
    FAILS(mq_send(q, "x", 17, 0), EMSGSIZE);
    FAILS(mq_send(q, "x", 1, 32768), EINVAL);
    FAILS(mq_receive(q, b, 15, 0), EMSGSIZE);
    FAILS(mq_send(1234, "x", 1, 0), EBADF);

    // The highest priority first, and of those the oldest.
    CHECK(mq_send(q, "low", 3, 1) == 0);
    CHECK(mq_send(q, "high", 4, 5) == 0);
    CHECK(mq_send(q, "HIGH", 4, 5) == 0);
    CHECK(mq_send(q, "mid", 3, 3) == 0);
    struct mq_attr got;
    CHECK(mq_getattr(q, &got) == 0 && got.mq_curmsgs == 4);
    CHECK(mq_receive(q, b, sizeof b, &prio) == 4 && prio == 5 && !memcmp(b, "high", 4));
    CHECK(mq_receive(q, b, sizeof b, &prio) == 4 && prio == 5 && !memcmp(b, "HIGH", 4));
    CHECK(mq_receive(q, b, sizeof b, &prio) == 3 && prio == 3 && !memcmp(b, "mid", 3));
    CHECK(mq_receive(q, b, sizeof b, 0) == 3 && !memcmp(b, "low", 3));
    CHECK(mq_send(q, "", 0, 0) == 0 && mq_receive(q, b, sizeof b, 0) == 0);

    // Time runs out on a full queue and an empty one.
    struct timespec t = soon();
    FAILS(mq_timedreceive(q, b, sizeof b, 0, &t), ETIMEDOUT);
    struct timespec bad = {0, 2000000000};
    FAILS(mq_timedreceive(q, b, sizeof b, 0, &bad), EINVAL);
    for (int i = 0; i < 4; i++) CHECK(mq_send(q, "m", 1, 0) == 0);
    t = soon();
    FAILS(mq_timedsend(q, "m", 1, 0, &t), ETIMEDOUT);

    // Not waiting at all, on one descriptor and not another.
    struct mq_attr set = {.mq_flags = O_NONBLOCK}, was;
    CHECK(mq_setattr(q, &set, &was) == 0 && was.mq_flags == 0);
    FAILS(mq_send(q, "m", 1, 0), EAGAIN);
    CHECK(mq_getattr(q, &got) == 0 && got.mq_flags == O_NONBLOCK);
    CHECK(mq_getattr(r, &got) == 0 && got.mq_flags == 0);

    // What poll says, either way.
    struct pollfd p = {.fd = q, .events = POLLIN | POLLOUT};
    CHECK(poll(&p, 1, 0) == 1 && p.revents == POLLIN);
    for (int i = 0; i < 4; i++) CHECK(mq_receive(q, b, sizeof b, 0) == 1);
    FAILS(mq_receive(q, b, sizeof b, 0), EAGAIN);
    p.revents = 0;
    CHECK(poll(&p, 1, 0) == 1 && p.revents == POLLOUT);

    // A blocked process goes on as there's room, or a message.
    set.mq_flags = 0;
    CHECK(mq_setattr(q, &set, 0) == 0);
    pid_t c = fork();
    CHECK(c >= 0);
    if (!c) {
        CHECK(mq_receive(q, b, sizeof b, &prio) == 5 && !memcmp(b, "hello", 5) && prio == 2);
        _exit(0);
    }
    usleep(20000);
    CHECK(mq_send(q, "hello", 5, 2) == 0);
    wait_ok(c);
    for (int i = 0; i < 4; i++) CHECK(mq_send(q, "m", 1, 0) == 0);
    c = fork();
    CHECK(c >= 0);
    if (!c) {
        CHECK(mq_send(q, "z", 1, 9) == 0);
        _exit(0);
    }
    usleep(20000);
    CHECK(mq_receive(q, b, sizeof b, 0) == 1 && b[0] == 'm');
    wait_ok(c);
    CHECK(mq_receive(q, b, sizeof b, &prio) == 1 && b[0] == 'z' && prio == 9);
    for (int i = 0; i < 3; i++) CHECK(mq_receive(q, b, sizeof b, 0) == 1);
    CHECK(mq_close(q) == 0 && mq_close(w) == 0 && mq_close(r) == 0);
    printf("messages ok\n");
}

static void notifying(void) {
    mqd_t q = mq_open(name, O_RDWR);
    CHECK(q != (mqd_t)-1);
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_sigaction = on_message;
    a.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGUSR1, &a, 0) == 0);
    struct sigevent e = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1};
    e.sigev_value.sival_int = 42;
    CHECK(mq_notify(q, &e) == 0);
    // One at a time.
    pid_t c = fork();
    CHECK(c >= 0);
    if (!c) {
        struct sigevent other = {.sigev_notify = SIGEV_NONE};
        FAILS(mq_notify(q, &other), EBUSY);
        _exit(0);
    }
    wait_ok(c);
    FAILS(mq_notify(1234, &e), EBADF);
    CHECK(mq_send(q, "a", 1, 0) == 0);
    for (int i = 0; i < 200 && !notified; i++) usleep(1000);
    CHECK(notified == SIGUSR1 && code == SI_MESGQ && value == 42);
    // Once: the next wants asking for.
    notified = 0;
    CHECK(mq_send(q, "b", 1, 0) == 0);
    usleep(5000);
    CHECK(!notified);
    char b[16];
    CHECK(mq_receive(q, b, sizeof b, 0) == 1 && mq_receive(q, b, sizeof b, 0) == 1);
    // Taken back, nothing comes.
    CHECK(mq_notify(q, &e) == 0 && mq_notify(q, 0) == 0);
    CHECK(mq_send(q, "c", 1, 0) == 0);
    usleep(5000);
    CHECK(!notified);
    CHECK(mq_receive(q, b, sizeof b, 0) == 1);
    // Only for an empty queue that gets something.
    CHECK(mq_send(q, "d", 1, 0) == 0 && mq_notify(q, &e) == 0);
    CHECK(mq_send(q, "e", 1, 0) == 0);
    usleep(5000);
    CHECK(!notified);
    CHECK(mq_receive(q, b, sizeof b, 0) == 1 && mq_receive(q, b, sizeof b, 0) == 1);
    CHECK(mq_notify(q, 0) == 0);
    FAILS(mq_notify(q, &(struct sigevent){.sigev_notify = 99}), EINVAL);
    CHECK(mq_close(q) == 0);
    printf("notifying ok\n");
}

static void removing(void) {
    mqd_t q = mq_open(name, O_RDWR);
    CHECK(q != (mqd_t)-1 && mq_send(q, "kept", 4, 0) == 0);
    CHECK(mq_unlink(name) == 0);
    FAILS(mq_unlink(name), ENOENT);
    FAILS(mq_open(name, O_RDWR), ENOENT);
    // Gone by name, not for those who have it open.
    char b[16];
    CHECK(mq_receive(q, b, sizeof b, 0) == 4 && !memcmp(b, "kept", 4));
    CHECK(mq_close(q) == 0);
    printf("removing ok\n");
}

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    snprintf(name, sizeof name, "/mq%d", getpid());
    opening();
    messages();
    notifying();
    removing();
    printf("mqueue ok\n");
    return 0;
}
