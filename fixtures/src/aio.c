// Linux AIO: io_setup, io_submit (pread, pwrite, preadv, pwritev, fsync,
// fdsync, poll), io_getevents and io_pgetevents (waiting, timeouts,
// signals), io_cancel, io_destroy; the ring in the program's memory (as
// libaio and user-space reapers read it), eventfd notification, Linux's
// errors, the global budget (aio-max-nr), and io_uring reported as
// unimplemented. Needs `fs_write`, `threads` and `process`.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            fflush(stdout);                                                       \
            _exit(1);                                                             \
        }                                                                         \
    } while (0)

// struct aio_ring, as Linux lays it out at the context's address.
struct aio_ring {
    unsigned id, nr, head, tail, magic, compat_features, incompat_features, header_length;
    struct io_event events[];
};

static long io_setup(unsigned n, aio_context_t *ctx) { return syscall(SYS_io_setup, n, ctx); }
static long io_destroy(aio_context_t ctx) { return syscall(SYS_io_destroy, ctx); }
static long io_submit(aio_context_t ctx, long n, struct iocb **iocbs) { return syscall(SYS_io_submit, ctx, n, iocbs); }
static long io_cancel(aio_context_t ctx, struct iocb *iocb, struct io_event *ev) {
    return syscall(SYS_io_cancel, ctx, iocb, ev);
}
static long io_getevents(aio_context_t ctx, long min, long max, struct io_event *ev, struct timespec *t) {
    return syscall(SYS_io_getevents, ctx, min, max, ev, t);
}

static struct iocb prep(int op, int fd, void *buf, size_t n, long long off, uint64_t data) {
    struct iocb cb;
    memset(&cb, 0, sizeof cb);
    cb.aio_lio_opcode = op;
    cb.aio_fildes = fd;
    cb.aio_buf = (uint64_t)(uintptr_t)buf;
    cb.aio_nbytes = n;
    cb.aio_offset = off;
    cb.aio_data = data;
    return cb;
}

static long submit1(aio_context_t ctx, struct iocb *cb) { return io_submit(ctx, 1, &cb); }

// One event, waiting for it.
static struct io_event one(aio_context_t ctx) {
    struct io_event ev;
    CHECK(io_getevents(ctx, 1, 1, &ev, NULL) == 1);
    return ev;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static long aio_nr(void) {
    FILE *f = fopen("/proc/sys/fs/aio-nr", "r");
    CHECK(f);
    long v = -1;
    CHECK(fscanf(f, "%ld", &v) == 1);
    fclose(f);
    return v;
}

static int pipe_w;
static void *write_later(void *arg) {
    (void)arg;
    usleep(100 * 1000);
    CHECK(write(pipe_w, "x", 1) == 1);
    return NULL;
}

static pthread_t main_thread;
static volatile int got_usr1;
static void on_usr1(int sig) { (void)sig; got_usr1 = 1; }
static void *signal_later(void *arg) {
    (void)arg;
    usleep(100 * 1000);
    pthread_kill(main_thread, SIGUSR1);
    return NULL;
}

int main(void) {
    aio_context_t ctx = 1;
    // Setting up: *ctxp must be 0, and the number sensible.
    CHECK(io_setup(8, &ctx) == -1 && errno == EINVAL);
    ctx = 0;
    CHECK(io_setup(0, &ctx) == -1 && errno == EINVAL);
    CHECK(io_setup(0x7fffffff, &ctx) == -1 && errno == EINVAL);
    CHECK(io_setup(70000, &ctx) == -1 && errno == EAGAIN);
    CHECK(io_setup(8, NULL) == -1 && errno == EFAULT);
    CHECK(io_setup(128, &ctx) == 0 && ctx != 0);
    CHECK(aio_nr() == 128);
    struct aio_ring *ring = (struct aio_ring *)ctx;
    CHECK(ring->magic == 0xa10a10a1 && ring->header_length == sizeof(struct aio_ring));
    CHECK(ring->nr > 2 * 128 && ring->head == 0 && ring->tail == 0);

    // Writes, a sync and reads on a file opened with O_DIRECT, as MariaDB does.
    int fd = open("/tmp/aio.dat", O_RDWR | O_CREAT | O_TRUNC | O_DIRECT, 0644);
    CHECK(fd >= 0);
    char a[] = "hello ", b[] = "async ", c[] = "world";
    struct iovec wv[2] = {{b, 6}, {c, 5}};
    struct iocb w1 = prep(IOCB_CMD_PWRITE, fd, a, 6, 0, 1);
    struct iocb w2 = prep(IOCB_CMD_PWRITEV, fd, wv, 2, 6, 2);
    struct iocb s1 = prep(IOCB_CMD_FSYNC, fd, NULL, 0, 0, 3);
    struct iocb s2 = prep(IOCB_CMD_FDSYNC, fd, NULL, 0, 0, 4);
    w1.aio_key = 0xdead;
    struct iocb *batch[] = {&w1, &w2, &s1, &s2};
    CHECK(io_submit(ctx, 4, batch) == 4);
    CHECK(w1.aio_key == 0); // KIOCB_KEY
    struct io_event evs[8];
    CHECK(io_getevents(ctx, 4, 8, evs, NULL) == 4);
    long long want_res[] = {6, 11, 0, 0};
    for (int i = 0; i < 4; i++) {
        CHECK(evs[i].data == (uint64_t)(i + 1) && evs[i].obj == (uint64_t)(uintptr_t)batch[i]);
        CHECK(evs[i].res == want_res[i] && evs[i].res2 == 0);
    }
    char buf[64] = {0}, p1[6] = {0}, p2[16] = {0};
    struct iocb r1 = prep(IOCB_CMD_PREAD, fd, buf, sizeof buf, 0, 5);
    CHECK(submit1(ctx, &r1) == 1);
    struct io_event ev = one(ctx);
    CHECK(ev.res == 17 && !memcmp(buf, "hello async world", 17));
    struct iovec rv[2] = {{p1, 6}, {p2, sizeof p2}};
    struct iocb r2 = prep(IOCB_CMD_PREADV, fd, rv, 2, 0, 6);
    CHECK(submit1(ctx, &r2) == 1);
    ev = one(ctx);
    CHECK(ev.res == 17 && !memcmp(p1, "hello ", 6) && !memcmp(p2, "async world", 11));
    // At the end, and past it.
    struct iocb r3 = prep(IOCB_CMD_PREAD, fd, buf, 4, 15, 7);
    CHECK(submit1(ctx, &r3) == 1);
    CHECK(one(ctx).res == 2);
    r3.aio_offset = 100;
    CHECK(submit1(ctx, &r3) == 1);
    CHECK(one(ctx).res == 0);
    // RWF_APPEND, with the file's own offset ignored.
    char tail[] = "!";
    struct iocb wa = prep(IOCB_CMD_PWRITE, fd, tail, 1, 0, 8);
    wa.aio_rw_flags = RWF_APPEND;
    CHECK(submit1(ctx, &wa) == 1 && one(ctx).res == 1);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == 18);

    // A user-space reaper reads the ring itself (libaio's zero-timeout
    // check looks at head and tail).
    CHECK(submit1(ctx, &r1) == 1);
    CHECK(ring->tail != ring->head);
    struct io_event *e = &ring->events[ring->head];
    CHECK(e->data == 5 && e->res == 18);
    ring->head = (ring->head + 1) % ring->nr;
    struct timespec zero = {0, 0};
    CHECK(io_getevents(ctx, 0, 8, evs, &zero) == 0);

    // An eventfd hears of each completion.
    int efd = eventfd(0, EFD_NONBLOCK);
    CHECK(efd >= 0);
    r1.aio_flags = IOCB_FLAG_RESFD;
    r1.aio_resfd = efd;
    CHECK(submit1(ctx, &r1) == 1 && submit1(ctx, &r1) == 1);
    uint64_t count;
    CHECK(read(efd, &count, 8) == 8 && count == 2);
    CHECK(io_getevents(ctx, 2, 2, evs, NULL) == 2);
    r1.aio_flags = 0;

    // Errors at submission: the first request's errno, or how many went in.
    struct iocb bad = prep(IOCB_CMD_PREAD, 999, buf, 1, 0, 0);
    CHECK(submit1(ctx, &bad) == -1 && errno == EBADF);
    struct iocb *two[] = {&r1, &bad};
    CHECK(io_submit(ctx, 2, two) == 1);
    CHECK(one(ctx).data == 5);
    bad = prep(6 /* IOCB_CMD_NOOP */, fd, buf, 1, 0, 0);
    CHECK(submit1(ctx, &bad) == -1 && errno == EINVAL);
    bad = prep(IOCB_CMD_PREAD, fd, buf, 1, -1, 0);
    CHECK(submit1(ctx, &bad) == -1 && errno == EINVAL);
    bad = prep(IOCB_CMD_PREAD, fd, buf, 1, 0, 0);
    bad.aio_reserved2 = 1;
    CHECK(submit1(ctx, &bad) == -1 && errno == EINVAL);
    bad.aio_reserved2 = 0;
    bad.aio_rw_flags = 0x1000;
    CHECK(submit1(ctx, &bad) == -1 && errno == EOPNOTSUPP);
    bad.aio_rw_flags = 0;
    bad.aio_flags = IOCB_FLAG_RESFD;
    bad.aio_resfd = fd; // not an eventfd
    CHECK(submit1(ctx, &bad) == -1 && errno == EINVAL);
    int wo = open("/tmp/aio.dat", O_WRONLY);
    CHECK(wo >= 0);
    bad = prep(IOCB_CMD_PREAD, wo, buf, 1, 0, 0);
    CHECK(submit1(ctx, &bad) == -1 && errno == EBADF);
    int pfd[2];
    CHECK(pipe(pfd) == 0);
    bad = prep(IOCB_CMD_FSYNC, pfd[0], NULL, 0, 0, 0);
    CHECK(submit1(ctx, &bad) == -1 && errno == EINVAL);
    CHECK(io_submit(ctx, 1, (struct iocb **)8) == -1 && errno == EFAULT);
    CHECK(io_submit(ctx, -1, two) == -1 && errno == EINVAL);
    CHECK(io_submit(12345, 1, two) == -1 && errno == EINVAL);
    CHECK(io_getevents(ctx, 2, 1, evs, NULL) == -1 && errno == EINVAL);
    CHECK(io_getevents(ctx, -1, 1, evs, NULL) == -1 && errno == EINVAL);
    CHECK(io_submit(ctx, 0, two) == 0);

    // A read from a pipe that isn't ready doesn't wait: EAGAIN in its event.
    struct iocb rp = prep(IOCB_CMD_PREAD, pfd[0], buf, 1, 0, 9);
    CHECK(submit1(ctx, &rp) == 1 && one(ctx).res == -EAGAIN);

    // On a datagram socket, a request's buffers are one message.
    int sp[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == 0);
    struct iocb dw = prep(IOCB_CMD_PWRITEV, sp[0], wv, 2, 0, 13);
    CHECK(submit1(ctx, &dw) == 1 && one(ctx).res == 11);
    char d1[4] = {0}, d2[16] = {0};
    struct iovec dv[2] = {{d1, 4}, {d2, sizeof d2}};
    struct iocb dr = prep(IOCB_CMD_PREADV, sp[1], dv, 2, 0, 14);
    CHECK(submit1(ctx, &dr) == 1 && one(ctx).res == 11);
    CHECK(!memcmp(d1, "asyn", 4) && !memcmp(d2, "c world", 7));
    CHECK(recv(sp[1], d2, sizeof d2, MSG_DONTWAIT) == -1 && errno == EAGAIN);

    // Polls wait for their file: not yet, not within a timeout, then yes.
    struct iocb pl = prep(IOCB_CMD_POLL, pfd[0], (void *)(uintptr_t)POLLIN, 0, 0, 10);
    CHECK(submit1(ctx, &pl) == 1);
    CHECK(io_getevents(ctx, 1, 1, evs, &zero) == 0);
    struct timespec t30 = {0, 30 * 1000 * 1000};
    long t0 = now_ms();
    CHECK(io_getevents(ctx, 1, 1, evs, &t30) == 0);
    CHECK(now_ms() - t0 >= 25);
    // Another thread writes while this one waits.
    pipe_w = pfd[1];
    pthread_t th;
    CHECK(pthread_create(&th, NULL, write_later, NULL) == 0);
    ev = one(ctx);
    CHECK(ev.data == 10 && (ev.res & POLLIN));
    CHECK(pthread_join(th, NULL) == 0);
    // Ready at once.
    CHECK(submit1(ctx, &pl) == 1 && (one(ctx).res & POLLIN));
    // Cancelled: its event (0) is in the ring, and io_cancel says EINPROGRESS.
    int q[2];
    CHECK(pipe(q) == 0);
    struct iocb pc = prep(IOCB_CMD_POLL, q[0], (void *)(uintptr_t)POLLIN, 0, 0, 11);
    CHECK(submit1(ctx, &pc) == 1);
    CHECK(io_cancel(ctx, &pc, &ev) == -1 && errno == EINPROGRESS);
    ev = one(ctx);
    CHECK(ev.data == 11 && ev.res == 0);
    CHECK(io_cancel(ctx, &pc, &ev) == -1 && errno == EINVAL);
    CHECK(io_cancel(ctx, &r1, &ev) == -1 && errno == EINVAL); // done already
    // The poll's eventfd tells an epoll-style waiter, without io_getevents.
    pc.aio_flags = IOCB_FLAG_RESFD;
    pc.aio_resfd = efd;
    CHECK(submit1(ctx, &pc) == 1);
    CHECK(write(q[1], "y", 1) == 1);
    struct pollfd pw = {efd, POLLIN, 0};
    CHECK(poll(&pw, 1, 5000) == 1);
    CHECK(read(efd, &count, 8) == 8 && count == 1);
    ev = one(ctx);
    CHECK(ev.data == 11 && (ev.res & POLLIN));

    // Waits end for a signal: EINTR, with io_pgetevents's mask in place
    // only while it waits.
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    sigset_t blocked, open_mask;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    sigemptyset(&open_mask);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0);
    main_thread = pthread_self();
    CHECK(pthread_create(&th, NULL, signal_later, NULL) == 0);
    struct {
        const sigset_t *mask;
        size_t size;
    } usig = {&open_mask, 8};
    char drain;
    CHECK(read(q[0], &drain, 1) == 1);
    pc.aio_flags = 0;
    CHECK(submit1(ctx, &pc) == 1); // a poll that never completes
    errno = 0;
    CHECK(syscall(SYS_io_pgetevents, ctx, 1, 1, evs, NULL, &usig) == -1 && errno == EINTR);
    CHECK(got_usr1);
    CHECK(pthread_join(th, NULL) == 0);
    sigset_t now;
    CHECK(sigprocmask(SIG_SETMASK, NULL, &now) == 0 && sigismember(&now, SIGUSR1));
    usig.size = 4;
    CHECK(syscall(SYS_io_pgetevents, ctx, 1, 1, evs, NULL, &usig) == -1 && errno == EINVAL);
    CHECK(sigprocmask(SIG_UNBLOCK, &blocked, NULL) == 0);

    // A full ring: as many requests as it holds, then EAGAIN until reaped.
    aio_context_t small = 0;
    CHECK(io_setup(1, &small) == 0);
    struct aio_ring *sr = (struct aio_ring *)small;
    struct iocb r4 = prep(IOCB_CMD_PREAD, fd, buf, 1, 0, 12);
    unsigned n = 0;
    while (submit1(small, &r4) == 1) n++;
    CHECK(errno == EAGAIN && n == sr->nr - 1);
    struct io_event many[512];
    CHECK(io_getevents(small, 0, 512, many, NULL) == (long)n);
    CHECK(submit1(small, &r4) == 1);

    // The budget is everyone's (aio-max-nr): a child holding all of it
    // leaves nothing for the parent until it's gone.
    // Something the program mapped over its ring isn't io_destroy's.
    void *over = mmap((void *)small, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(over == (void *)small);
    *(volatile char *)over = 7;
    CHECK(io_destroy(small) == 0);
    CHECK(*(volatile char *)over == 7);
    CHECK(munmap(over, 4096) == 0);
    CHECK(io_destroy(small) == -1 && errno == EINVAL);
    unsigned char vec;
    CHECK(mincore((void *)small, 4096, &vec) == -1 && errno == ENOMEM); // unmapped
    CHECK(aio_nr() == 128);
    int ready[2], go[2];
    CHECK(pipe(ready) == 0 && pipe(go) == 0);
    fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        // The parent's contexts aren't the child's.
        CHECK(submit1(ctx, &r1) == -1 && errno == EINVAL);
        aio_context_t big = 0;
        CHECK(io_setup(65536 - 128, &big) == 0);
        char x = 1;
        write(ready[1], &x, 1);
        read(go[0], &x, 1);
        _exit(0);
    }
    char x;
    CHECK(read(ready[0], &x, 1) == 1);
    CHECK(aio_nr() == 65536);
    small = 0;
    CHECK(io_setup(1, &small) == -1 && errno == EAGAIN);
    write(go[1], &x, 1);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && status == 0);
    CHECK(aio_nr() == 128);
    CHECK(io_setup(1, &small) == 0 && io_destroy(small) == 0);

    CHECK(io_destroy(ctx) == 0);
    CHECK(mincore((void *)ctx, 4096, &vec) == -1 && errno == ENOMEM); // its ring is gone
    CHECK(aio_nr() == 0);
    CHECK(submit1(ctx, &r1) == -1 && errno == EINVAL);

    // io_uring is unimplemented (reported).
    char params[120] = {0};
    CHECK(syscall(SYS_io_uring_setup, 8, params) == -1 && errno == ENOSYS);
    printf("aio ok\n");
    return 0;
}
