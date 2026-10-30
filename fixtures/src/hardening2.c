// What a security review found, each subcommand a program doing what it
// did: mode 3 and O_PATH descriptors, what may be read and when (a socket
// address changed under connect), every budget filled at once, a terminal's
// column, fasync's permissions, a passed timerfd, fexecve, device nodes,
// /proc/self/fd/N/name, the sigaltstack's end, a ruleset's size. Prints
// "<subcommand> ok". Needs `process`, `threads`, `net` and `fs_write`.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/aio_abi.h>
#include <linux/openat2.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            fflush(stdout);                                                       \
            _exit(1);                                                             \
        }                                                                         \
    } while (0)
// A call that must fail with `e`.
#define FAILS(call, e)                                                            \
    do {                                                                          \
        errno = 0;                                                                \
        CHECK((long)(call) == -1 && errno == (e));                                \
    } while (0)

// include/uapi/linux/landlock.h.
#define EXECUTE (1ULL << 0)
#define WRITE_FILE (1ULL << 1)
#define READ_FILE (1ULL << 2)
#define READ_DIR (1ULL << 3)
#define BIND_TCP 1ULL
#define CONNECT_TCP 2ULL
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#endif

struct attr { uint64_t fs, net; };
struct beneath { uint64_t access; int32_t fd; } __attribute__((packed));
struct netport { uint64_t access, port; };

static int create_ruleset(uint64_t fs, uint64_t net) {
    struct attr a = {fs, net};
    return syscall(SYS_landlock_create_ruleset, &a, sizeof a, 0);
}
static void allow(int rs, const char *path, uint64_t access) {
    struct beneath b = {access, open(path, O_PATH)};
    CHECK(b.fd >= 0 && syscall(SYS_landlock_add_rule, rs, 1, &b, 0) == 0);
    close(b.fd);
}
static void restrict_self(int rs) {
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && syscall(SYS_landlock_restrict_self, rs, 0) == 0);
    close(rs);
}
// Only /w/ok has what `handled` handles.
static void jail(uint64_t handled) {
    int rs = create_ruleset(handled, 0);
    allow(rs, "/w/ok", handled);
    allow(rs, "/bin", handled);
    restrict_self(rs);
}

static void put(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    CHECK(fd >= 0 && write(fd, data, strlen(data)) == (ssize_t)strlen(data));
    close(fd);
}
static void tree(void) {
    mkdir("/w", 0755);
    mkdir("/w/ok", 0755);
    mkdir("/w/deny", 0755);
    put("/w/deny/secret", "topsecret");
    put("/w/ok/mine", "mine");
}
static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
// Run `f` in a child (restrictions don't come off); it must end well.
static void isolated(void (*f)(void)) {
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        f();
        fflush(stdout);
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

// ---- access mode 3: for ioctls, it can neither read nor write

static void aio_fails(int fd, int opcode) {
    aio_context_t ctx = 0;
    CHECK(syscall(SYS_io_setup, 4, &ctx) == 0);
    static char buf[16];
    struct iocb cb = {.aio_fildes = fd, .aio_lio_opcode = opcode, .aio_buf = (uintptr_t)buf, .aio_nbytes = 4};
    struct iocb *list[] = {&cb};
    FAILS(syscall(SYS_io_submit, ctx, 1, list), EBADF);
    CHECK(syscall(SYS_io_destroy, ctx) == 0);
}

static void mode3_calls(int fd) {
    char b[16];
    struct iovec iov = {b, 4};
    FAILS(read(fd, b, 4), EBADF);
    FAILS(write(fd, "OWNED", 5), EBADF);
    FAILS(pread(fd, b, 4, 0), EBADF);
    FAILS(pwrite(fd, "OWNED", 5, 0), EBADF);
    FAILS(readv(fd, &iov, 1), EBADF);
    FAILS(writev(fd, &iov, 1), EBADF);
    FAILS(preadv(fd, &iov, 1, 0), EBADF);
    FAILS(pwritev(fd, &iov, 1, 0), EBADF);
    int p[2];
    CHECK(pipe(p) == 0);
    int mem = syscall(SYS_memfd_create, "x", 0);
    CHECK(mem >= 0 && write(mem, "abcd", 4) == 4 && lseek(mem, 0, SEEK_SET) == 0);
    FAILS(sendfile(p[1], fd, 0, 4), EBADF);
    FAILS(sendfile(fd, mem, 0, 4), EBADF);
    FAILS(splice(fd, 0, p[1], 0, 4, 0), EBADF);
    CHECK(write(p[1], "x", 1) == 1);
    FAILS(splice(p[0], 0, fd, 0, 1, 0), EBADF);
    FAILS(syscall(SYS_copy_file_range, fd, 0, mem, 0, 4, 0), EBADF);
    FAILS(syscall(SYS_copy_file_range, mem, 0, fd, 0, 4, 0), EBADF);
    CHECK(mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED && errno == EACCES);
    CHECK(mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED && errno == EACCES);
    FAILS(ftruncate(fd, 1), EINVAL);
    FAILS(fallocate(fd, 0, 0, 1), EBADF);
    aio_fails(fd, IOCB_CMD_PREAD);
    aio_fails(fd, IOCB_CMD_PWRITE);
    struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_len = 1};
    FAILS(fcntl(fd, F_SETLK, &lock), EBADF);
    lock.l_type = F_WRLCK;
    FAILS(fcntl(fd, F_SETLK, &lock), EBADF);
    close(p[0]);
    close(p[1]);
    close(mem);
}

static void mode3_jailed(void) {
    jail(READ_FILE | WRITE_FILE);
    FAILS(open("/w/deny/secret", O_RDONLY), EACCES);
    int fd = open("/w/deny/secret", 3);
    CHECK(fd >= 0);
    CHECK((fcntl(fd, F_GETFL) & O_ACCMODE) == 3);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == 9);
    mode3_calls(fd);
}

static void t_mode3(void) {
    tree();
    int fd = open("/w/ok/mine", 3);
    CHECK(fd >= 0);
    mode3_calls(fd);
    close(fd);
    // Permission as for reading and writing; no directory, no FIFO.
    FAILS(open("/w/ok", 3), EISDIR);
    CHECK(mkfifo("/w/ok/fifo", 0644) == 0);
    FAILS(open("/w/ok/fifo", 3 | O_NONBLOCK), EINVAL);
    CHECK(chmod("/w/ok/mine", 0400) == 0);
    FAILS(open("/w/ok/mine", 3), EACCES);
    CHECK(chmod("/w/ok/mine", 0644) == 0);
    isolated(mode3_jailed);
    // Nothing got through.
    char b[16] = {0};
    fd = open("/w/deny/secret", O_RDONLY);
    CHECK(fd >= 0 && read(fd, b, sizeof b) == 9 && strcmp(b, "topsecret") == 0);
}

// ---- O_PATH: Linux's fdget_raw, and EBADF from everything else

static void pathdents_jailed(void) {
    int before = open("/w/deny", O_PATH | O_DIRECTORY);
    jail(READ_DIR);
    char b[512];
    FAILS(syscall(SYS_getdents64, before, b, sizeof b), EBADF);
    int after = open("/w/deny", O_PATH | O_DIRECTORY);
    CHECK(after >= 0);
    FAILS(syscall(SYS_getdents64, after, b, sizeof b), EBADF);
    FAILS(open("/w/deny", O_RDONLY), EACCES);
}

static void t_opath(void) {
    tree();
    int fd = open("/w/ok/mine", O_PATH), dir = open("/w/ok", O_PATH | O_DIRECTORY);
    CHECK(fd >= 0 && dir >= 0);
    char b[64];
    struct iovec iov = {b, 4};
    FAILS(read(fd, b, 1), EBADF);
    FAILS(write(fd, "x", 1), EBADF);
    FAILS(pread(fd, b, 1, 0), EBADF);
    FAILS(pwrite(fd, "x", 1, 0), EBADF);
    FAILS(readv(fd, &iov, 1), EBADF);
    FAILS(writev(fd, &iov, 1), EBADF);
    FAILS(lseek(fd, 0, SEEK_SET), EBADF);
    FAILS(syscall(SYS_getdents64, dir, b, sizeof b), EBADF);
    FAILS(ioctl(fd, FIONREAD, b), EBADF);
    CHECK(mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED && errno == EBADF);
    FAILS(fsync(fd), EBADF);
    FAILS(fdatasync(fd), EBADF);
    FAILS(ftruncate(fd, 0), EBADF);
    FAILS(fallocate(fd, 0, 0, 1), EBADF);
    // (Not libc's: musl's go through /proc/self/fd for O_PATH.)
    FAILS(syscall(SYS_fchmod, fd, 0644), EBADF);
    FAILS(syscall(SYS_fchown, fd, -1, -1), EBADF);
    struct timespec times[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    FAILS(futimens(fd, times), EBADF);
    FAILS(fgetxattr(fd, "user.a", b, sizeof b), EBADF);
    FAILS(fsetxattr(fd, "user.a", "1", 1, 0), EBADF);
    FAILS(flistxattr(fd, b, sizeof b), EBADF);
    FAILS(fremovexattr(fd, "user.a"), EBADF);
    FAILS(flock(fd, LOCK_SH), EBADF);
    FAILS(posix_fadvise(fd, 0, 0, 0) == 0 ? 0 : (errno = EBADF, -1), EBADF);
    struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET};
    FAILS(fcntl(fd, F_GETLK, &lock), EBADF);
    FAILS(fcntl(fd, F_SETLK, &lock), EBADF);
    FAILS(fcntl(fd, F_SETFL, O_NONBLOCK), EBADF);
    FAILS(fcntl(fd, F_SETOWN, getpid()), EBADF);
    FAILS(fcntl(fd, F_GETOWN), EBADF);
    FAILS(fcntl(fd, F_SETSIG, SIGUSR1), EBADF);
    FAILS(fcntl(fd, F_GETPIPE_SZ), EBADF);
    int p[2];
    CHECK(pipe(p) == 0);
    FAILS(splice(fd, 0, p[1], 0, 1, 0), EBADF);
    FAILS(splice(p[0], 0, fd, 0, 1, 0), EBADF);
    FAILS(sendfile(p[1], fd, 0, 1), EBADF);
    int mem = syscall(SYS_memfd_create, "x", 0);
    FAILS(syscall(SYS_copy_file_range, fd, 0, mem, 0, 1, 0), EBADF);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN};
    FAILS(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev), EBADF);
    struct pollfd pf = {.fd = fd, .events = POLLIN};
    CHECK(poll(&pf, 1, 0) == 1 && pf.revents == POLLNVAL);
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    struct timeval zero = {0, 0};
    FAILS(select(fd + 1, &set, 0, 0, &zero), EBADF);
    struct sockaddr_in a = {.sin_family = AF_INET};
    FAILS(connect(fd, (void *)&a, sizeof a), EBADF);
    FAILS(bind(fd, (void *)&a, sizeof a), EBADF);
    FAILS(listen(fd, 1), EBADF);
    socklen_t len = sizeof a;
    FAILS(getsockname(fd, (void *)&a, &len), EBADF);
    FAILS(send(fd, b, 1, 0), EBADF);
    struct itimerspec its = {{0, 0}, {0, 0}};
    FAILS(timerfd_settime(fd, 0, &its, 0), EBADF);
    FAILS(syscall(SYS_pidfd_send_signal, fd, 0, 0, 0), EBADF);

    // What takes one: its name is all they use.
    struct stat st;
    struct statfs sf;
    CHECK(fstat(fd, &st) == 0 && st.st_size == 4);
    CHECK(fstatat(fd, "", &st, AT_EMPTY_PATH) == 0 && st.st_size == 4);
    CHECK(fstatfs(fd, &sf) == 0);
    int d = dup(fd);
    CHECK(d >= 0 && dup3(fd, d, O_CLOEXEC) == d && fcntl(d, F_DUPFD_CLOEXEC, 50) >= 50);
    CHECK(fcntl(d, F_GETFD) == FD_CLOEXEC && fcntl(d, F_SETFD, 0) == 0);
    CHECK(fcntl(fd, F_GETFL) & O_PATH);
    int file = openat(dir, "mine", O_RDONLY);
    CHECK(file >= 0 && read(file, b, 4) == 4 && memcmp(b, "mine", 4) == 0);
    CHECK(faccessat(dir, "mine", R_OK, 0) == 0 && utimensat(dir, "mine", 0, 0) == 0);
    snprintf(b, sizeof b, "/proc/self/fd/%d", fd);
    char link[64];
    ssize_t n = readlink(b, link, sizeof link - 1);
    CHECK(n > 0 && strncmp(link, "/w/ok/mine", n) == 0);
    CHECK(fchdir(dir) == 0 && access("mine", R_OK) == 0 && chdir("/") == 0);
    // SCM_RIGHTS takes one too.
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    char c = 'x';
    struct iovec one = {&c, 1};
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } u;
    struct msghdr m = {.msg_iov = &one, .msg_iovlen = 1, .msg_control = u.b, .msg_controllen = sizeof u.b};
    struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof fd);
    CHECK(sendmsg(sv[0], &m, 0) == 1 && recvmsg(sv[1], &m, 0) == 1);
    int got;
    memcpy(&got, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof got);
    CHECK(fstat(got, &st) == 0 && st.st_size == 4);
    FAILS(read(got, b, 1), EBADF);

    isolated(pathdents_jailed);
}

// ---- what's read of user memory is read once

static volatile struct sockaddr_in race_addr;
static volatile int race_stop;
static void *flipper(void *arg) {
    uint16_t a = htons(1111), b = htons(2222);
    (void)arg;
    while (!race_stop) {
        race_addr.sin_port = a;
        for (volatile int i = 0; i < 16; i++) {}
        race_addr.sin_port = b;
        for (volatile int i = 0; i < 16; i++) {}
    }
    return 0;
}
static int listener(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(s, (void *)&a, sizeof a) == 0 && listen(s, 64) == 0);
    return s;
}
// Only port 1111 is allowed: however the address changes meanwhile,
// nothing reaches 2222 (connect) or gets it (bind).
static void connect_race(void) {
    int l1 = listener(1111), l2 = listener(2222);
    pid_t acceptor = fork();
    CHECK(acceptor >= 0);
    if (acceptor == 0) {
        for (;;) {
            fd_set r;
            FD_ZERO(&r);
            FD_SET(l1, &r);
            FD_SET(l2, &r);
            select(l2 + 1, &r, 0, 0, 0);
            if (FD_ISSET(l1, &r)) close(accept(l1, 0, 0));
            if (FD_ISSET(l2, &r)) close(accept(l2, 0, 0));
        }
    }
    close(l1);
    close(l2);
    int rs = create_ruleset(0, CONNECT_TCP);
    struct netport np = {CONNECT_TCP, 1111};
    CHECK(syscall(SYS_landlock_add_rule, rs, 2, &np, 0) == 0);
    restrict_self(rs);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(2222), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int s = socket(AF_INET, SOCK_STREAM, 0);
    FAILS(connect(s, (void *)&a, sizeof a), EACCES);
    close(s);
    memcpy((void *)&race_addr, &a, sizeof a);
    pthread_t t;
    CHECK(pthread_create(&t, 0, flipper, 0) == 0);
    long denied = 0;
    for (long tries = 0; tries < 20000; tries++) {
        s = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(s >= 0);
        if (connect(s, (void *)&race_addr, sizeof a) == 0) {
            struct sockaddr_in peer;
            socklen_t len = sizeof peer;
            CHECK(getpeername(s, (void *)&peer, &len) == 0 && ntohs(peer.sin_port) == 1111);
        } else {
            // (Port 1111's queue may be full.)
            CHECK(errno == EACCES || errno == ECONNREFUSED);
            denied += errno == EACCES;
        }
        close(s);
    }
    CHECK(denied > 0);
    race_stop = 1;
    pthread_join(t, 0);
    kill(acceptor, SIGKILL);
    waitpid(acceptor, 0, 0);
}
static void bind_race(void) {
    int rs = create_ruleset(0, BIND_TCP);
    struct netport np = {BIND_TCP, 1111};
    CHECK(syscall(SYS_landlock_add_rule, rs, 2, &np, 0) == 0);
    restrict_self(rs);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(2222), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    memcpy((void *)&race_addr, &a, sizeof a);
    race_stop = 0;
    pthread_t t;
    CHECK(pthread_create(&t, 0, flipper, 0) == 0);
    for (long tries = 0; tries < 20000; tries++) {
        int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        CHECK(s >= 0);
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(s, (void *)&race_addr, sizeof a) == 0) {
            struct sockaddr_in me;
            socklen_t len = sizeof me;
            CHECK(getsockname(s, (void *)&me, &len) == 0 && ntohs(me.sin_port) == 1111);
        } else {
            CHECK(errno == EACCES);
        }
        close(s);
    }
    race_stop = 1;
    pthread_join(t, 0);
}
static void t_race(void) {
    isolated(connect_race);
    isolated(bind_race);
}

// ---- every budget at once

static int make_timers(int want) {
    int made = 0;
    for (; made < want; made++) {
        timer_t id;
        struct sigevent e = {.sigev_notify = SIGEV_NONE};
        if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &e, &id)) {
            CHECK(errno == EAGAIN);
            break;
        }
    }
    return made;
}

// Timers and mappings in every process there can be, then full pipes and
// file names: everything fails with an errno, and nothing panics.
static void t_heap(void) {
    int gate[2], counts[2];
    CHECK(pipe(gate) == 0 && pipe(counts) == 0);
    int kids = 0;
    for (; kids < 120; kids++) {
        pid_t c = fork();
        if (c < 0) break;
        if (c == 0) {
            close(gate[1]);
            int made = make_timers(1024);
            char *base = mmap(0, 4096 * 2000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            for (int j = 0; j < 2000 && base != MAP_FAILED; j += 2) {
                if (mprotect(base + j * 4096, 4096, PROT_READ | PROT_WRITE)) {
                    CHECK(errno == ENOMEM);
                    break;
                }
            }
            CHECK(write(counts[1], &made, sizeof made) == sizeof made);
            char b;
            CHECK(read(gate[0], &b, 1) == 0);
            _exit(0);
        }
    }
    CHECK(kids > 10);
    long timers = 0;
    int capped = 0;
    for (int i = 0; i < kids; i++) {
        int made;
        CHECK(read(counts[0], &made, sizeof made) == sizeof made);
        timers += made;
        capped += made < 1024;
    }
    static char page[65536];
    long pipes = 0;
    for (;;) {
        int p[2];
        if (pipe2(p, O_NONBLOCK)) {
            CHECK(errno == EMFILE || errno == ENFILE || errno == ENOMEM);
            break;
        }
        pipes++;
        while (write(p[1], page, sizeof page) > 0) {}
        if (errno == ENOMEM || pipes > 400) break;
    }
    char name[300];
    memset(name, 'n', 200);
    CHECK(mkdir("/w", 0755) == 0 && mkdir("/w/many", 0755) == 0);
    for (long files = 0;; files++) {
        snprintf(name + 200, 40, "%ld", files);
        char path[320];
        snprintf(path, sizeof path, "/w/many/%s", name);
        int f = open(path, O_CREAT | O_WRONLY, 0644);
        if (f < 0) {
            CHECK(errno == ENOSPC);
            break;
        }
        close(f);
    }
    close(gate[1]);
    for (int i = 0; i < kids; i++) CHECK(wait(0) > 0);
    // A global limit, not only each process's.
    CHECK(capped > 0 && timers < 120 * 1024);
}

// Timers are limited for everyone together, and come back.
static void t_timers(void) {
    int gate[2], counts[2];
    CHECK(pipe(gate) == 0 && pipe(counts) == 0);
    int kids = 16;
    for (int i = 0; i < kids; i++) {
        pid_t c = fork();
        CHECK(c >= 0);
        if (c == 0) {
            close(gate[1]);
            int made = make_timers(2048);
            CHECK(write(counts[1], &made, sizeof made) == sizeof made);
            char b;
            CHECK(read(gate[0], &b, 1) == 0);
            _exit(0);
        }
    }
    long total = 0;
    for (int i = 0; i < kids; i++) {
        int made;
        CHECK(read(counts[0], &made, sizeof made) == sizeof made);
        CHECK(made <= 1024);
        total += made;
    }
    CHECK(total >= 1024 && total <= 8192);
    close(gate[1]);
    for (int i = 0; i < kids; i++) CHECK(wait(0) > 0);
    CHECK(make_timers(1024) == 1024);
}

// Interest lists: an instance per descriptor, each with every descriptor.
static void t_epoll(void) {
    struct rlimit lim = {3900, 3900};
    CHECK(setrlimit(RLIMIT_NOFILE, &lim) == 0);
    int p[2];
    CHECK(pipe(p) == 0);
    static int targets[2400], eps[1400];
    int n = 0;
    for (; n < 2400; n++) CHECK((targets[n] = dup(p[0])) >= 0);
    int full = 0, eps_made = 0;
    long regs = 0;
    for (; eps_made < 1400 && !full; eps_made++) {
        int ep = eps[eps_made] = epoll_create1(0);
        CHECK(ep >= 0);
        for (int i = 0; i < n; i++) {
            struct epoll_event ev = {.events = EPOLLIN};
            if (epoll_ctl(ep, EPOLL_CTL_ADD, targets[i], &ev)) {
                CHECK(errno == ENOSPC);
                full = 1;
                break;
            }
            regs++;
        }
    }
    CHECK(full && regs > 1000);
    // What goes comes back.
    for (int i = 0; i < eps_made; i++) close(eps[i]);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, targets[0], &ev) == 0);
}

// argv of empty strings: more heap than bytes, and fork copies it.
static char *self_path = "/bin/hardening2";
static void t_argv(void) {
    static char *argv[116000];
    argv[0] = self_path;
    argv[1] = "hold";
    for (int i = 2; i < 115000; i++) argv[i] = "";
    char *envp[] = {0};
    int gate[2];
    CHECK(pipe(gate) == 0);
    int kids = 0, refused = 0;
    for (; kids < 100; kids++) {
        pid_t c = fork();
        if (c < 0) {
            refused = 1;
            break;
        }
        if (c == 0) {
            close(gate[1]);
            dup2(gate[0], 99);
            execve(argv[0], argv, envp);
            _exit(errno == ENOMEM ? 42 : 43);
        }
        int st;
        if (waitpid(c, &st, WNOHANG) == c) {
            CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 42);
            refused = 1;
            break;
        }
    }
    close(gate[1]);
    int st;
    while (wait(&st) > 0) {
        if (WIFEXITED(st) && WEXITSTATUS(st) == 42) refused = 1;
    }
    CHECK(refused);
}

// ---- terminals

static int open_pty(int *slave) {
    int m = open("/dev/ptmx", O_RDWR | O_NOCTTY), unlock = 0, index = 0;
    CHECK(m >= 0 && ioctl(m, TIOCSPTLCK, &unlock) == 0 && ioctl(m, TIOCGPTN, &index) == 0);
    char path[32];
    snprintf(path, sizeof path, "/dev/pts/%d", index);
    *slave = open(path, O_RDWR | O_NOCTTY);
    CHECK(*slave >= 0);
    return m;
}

static int drain(int m, char *out, int room) {
    int n = 0;
    struct pollfd pf = {.fd = m, .events = POLLIN};
    while (n < room && poll(&pf, 1, 0) == 1 && pf.revents & POLLIN) {
        int r = read(m, out + n, room - n);
        if (r <= 0) break;
        n += r;
    }
    return n;
}

static void t_tabs(void) {
    int s, m = open_pty(&s);
    static char tabs[4096], out[65536];
    memset(tabs, '\t', sizeof tabs);
    // Each erased tab goes back as far as it went, from what's before it.
    struct { const char *line; int back; } cases[] = {
        {"\t", 8}, {"ab\t", 6}, {"abcdefgh\t", 8}, {"a\tb\t", 7}, {"\t\t", 8},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        CHECK(write(m, cases[i].line, strlen(cases[i].line)) == (ssize_t)strlen(cases[i].line));
        drain(m, out, sizeof out);
        CHECK(write(m, "\x7f", 1) == 1);
        int n = drain(m, out, sizeof out);
        CHECK(n == cases[i].back);
        for (int j = 0; j < n; j++) CHECK(out[j] == '\b');
        CHECK(write(m, "\n", 1) == 1);
        drain(m, out, sizeof out);
        CHECK(tcflush(s, TCIFLUSH) == 0);
    }
    // After a line that started further on, with the column from the output.
    CHECK(write(s, "abc", 3) == 3);
    drain(m, out, sizeof out);
    CHECK(write(m, "\t", 1) == 1);
    drain(m, out, sizeof out);
    CHECK(write(m, "\x7f", 1) == 1);
    CHECK(drain(m, out, sizeof out) == 5);
    CHECK(tcflush(s, TCIFLUSH) == 0);
    // A column in the billions, and a whole line of tabs: at most 8
    // backspaces, whatever the slave has written, and no time at all.
    CHECK(write(m, "\t", 1) == 1);
    drain(m, out, sizeof out);
    for (int i = 0; i < 2000; i++) {
        CHECK(write(s, tabs, sizeof tabs) == sizeof tabs);
        drain(m, out, sizeof out);
    }
    long t0 = now_ms();
    CHECK(write(m, "\x7f", 1) == 1);
    CHECK(now_ms() - t0 < 500);
    int n = drain(m, out, sizeof out);
    CHECK(n >= 1 && n <= 8);
    CHECK(tcflush(s, TCIFLUSH) == 0);
    CHECK(write(m, tabs, 4095) == 4095);
    drain(m, out, sizeof out);
    t0 = now_ms();
    char kill_char = 0x15;
    CHECK(write(m, &kill_char, 1) == 1);
    CHECK(now_ms() - t0 < 500);
    CHECK(drain(m, out, sizeof out) <= 4095 * 8);
    close(s);
    close(m);
}

// Run as root: another uid's terminal is another uid's.
static void t_ptsperm(void) {
    CHECK(getuid() == 0);
    int up[2], down[2];
    CHECK(pipe(up) == 0 && pipe(down) == 0);
    fflush(stdout);
    pid_t owner = fork();
    CHECK(owner >= 0);
    if (owner == 0) {
        CHECK(setgid(1000) == 0 && setuid(1000) == 0);
        int s, m = open_pty(&s);
        int index = 0;
        CHECK(ioctl(m, TIOCGPTN, &index) == 0);
        CHECK(write(up[1], &index, sizeof index) == sizeof index);
        char b;
        CHECK(read(down[0], &b, 1) == 1);
        _exit(0);
    }
    int index;
    CHECK(read(up[0], &index, sizeof index) == sizeof index);
    char path[32];
    snprintf(path, sizeof path, "/dev/pts/%d", index);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0620 && st.st_uid == 1000);
    pid_t other = fork();
    CHECK(other >= 0);
    if (other == 0) {
        CHECK(setgroups(0, 0) == 0 && setgid(2000) == 0 && setuid(2000) == 0);
        FAILS(open(path, O_RDWR | O_NOCTTY), EACCES);
        FAILS(open(path, O_RDONLY | O_NOCTTY), EACCES);
        // Devices anyone may use still work.
        int null = open("/dev/null", O_RDWR);
        CHECK(null >= 0 && open("/dev/ptmx", O_RDWR | O_NOCTTY) >= 0);
        _exit(0);
    }
    int status;
    CHECK(waitpid(other, &status, 0) == other && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    int fd = open(path, O_RDWR | O_NOCTTY);
    CHECK(fd >= 0);
    CHECK(write(down[1], "x", 1) == 1);
    CHECK(waitpid(owner, &status, 0) == owner && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// Run as root: O_ASYNC's signals are as F_SETOWN's caller's ids allow.
static volatile int sigio;
static void on_sigio(int s) {
    (void)s;
    sigio++;
}
static void t_sigioperm(void) {
    CHECK(getuid() == 0);
    int sv[2], ready[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && pipe(ready) == 0);
    signal(SIGIO, on_sigio);
    pid_t target = getpid();
    CHECK(setresuid(1000, 1000, 0) == 0);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        CHECK(setresuid(0, 0, 0) == 0 && setresuid(2000, 2000, 2000) == 0);
        CHECK(fcntl(sv[0], F_SETOWN, target) == 0 && fcntl(sv[0], F_SETFL, O_ASYNC) == 0);
        // Its ids then count: root's later wouldn't be asked.
        CHECK(write(sv[1], "x", 1) == 1);
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    struct timespec t = {0, 100000000};
    nanosleep(&t, 0);
    CHECK(sigio == 0);
    // Its own: it's signalled.
    CHECK(fcntl(sv[0], F_SETOWN, target) == 0);
    CHECK(write(sv[1], "y", 1) == 1);
    for (int i = 0; i < 100 && !sigio; i++) nanosleep(&t, 0);
    CHECK(sigio > 0);
}

// ---- fasync and init (pid 1)

static void t_fasync(void) {
    CHECK(getpid() == 1);
    int p[2];
    CHECK(pipe(p) == 0);
    CHECK(fcntl(p[0], F_SETOWN, getpid()) == 0 && fcntl(p[0], F_SETFL, O_ASYNC) == 0);
    signal(SIGIO, SIG_DFL);
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        CHECK(fcntl(p[0], F_SETSIG, SIGKILL) == 0);
        CHECK(write(p[1], "x", 1) == 1);
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    struct timespec t = {0, 200000000};
    nanosleep(&t, 0);
    // F_SETSIG the other way round: a child's choice is a child's, whoever
    // named the owner last.
    c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        CHECK(fcntl(p[0], F_SETSIG, SIGTERM) == 0);
        _exit(0);
    }
    CHECK(waitpid(c, &st, 0) == c);
    CHECK(fcntl(p[0], F_SETOWN, getpid()) == 0);
    c = fork();
    CHECK(c >= 0);
    if (c == 0) _exit(write(p[1], "y", 1) == 1 ? 0 : 1);
    CHECK(waitpid(c, &st, 0) == c);
    nanosleep(&t, 0);
}

// ---- a timerfd belongs to its file

static void send_fd(int sock, int fd) {
    char c = 'x';
    struct iovec iov = {&c, 1};
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } u;
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.b, .msg_controllen = sizeof u.b};
    struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof fd);
    CHECK(sendmsg(sock, &m, 0) == 1);
}
static int recv_fd(int sock) {
    char c;
    struct iovec iov = {&c, 1};
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } u;
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.b, .msg_controllen = sizeof u.b};
    CHECK(recvmsg(sock, &m, 0) == 1);
    int fd;
    memcpy(&fd, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof fd);
    return fd;
}
static void t_timerfd(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        int t = timerfd_create(CLOCK_MONOTONIC, 0);
        struct itimerspec its = {{0, 50000000}, {0, 200000000}};
        CHECK(t >= 0 && timerfd_settime(t, 0, &its, 0) == 0);
        send_fd(sv[0], t);
        _exit(0);
    }
    int t = recv_fd(sv[1]), st;
    CHECK(waitpid(c, &st, 0) == c);
    long t0 = now_ms();
    uint64_t n = 0;
    // Blocking, with nothing else running: its deadline wakes it.
    CHECK(read(t, &n, sizeof n) == sizeof n && n >= 1);
    CHECK(now_ms() - t0 < 2000);
    // And goes on with the period.
    CHECK(read(t, &n, sizeof n) == sizeof n && n >= 1);
    // After a fork that closed it in the parent.
    pid_t k = fork();
    CHECK(k >= 0);
    if (k == 0) {
        CHECK(read(t, &n, sizeof n) == sizeof n && n >= 1);
        _exit(0);
    }
    close(t);
    CHECK(waitpid(k, &st, 0) == k && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

// ---- fexecve: the file, not what's at its name

static void copy_self(const char *path) {
    int src = open("/bin/hardening2", O_RDONLY), dst = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    CHECK(src >= 0 && dst >= 0);
    static char b[1 << 16];
    ssize_t n;
    while ((n = read(src, b, sizeof b)) > 0) CHECK(write(dst, b, n) == n);
    close(src);
    close(dst);
}
// `fd` execs, as `tag`; the program says what it was.
static int exec_fd(int fd, const char *tag) {
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        char *argv[] = {"prog", "ran", (char *)tag, 0}, *envp[] = {0};
        syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
        _exit(100 + (errno & 63));
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st));
    return WEXITSTATUS(st);
}

static void fexec_jailed(void) {
    int denied = open("/w/deny/prog", O_RDONLY), path = open("/w/deny/prog", O_PATH);
    int allowed = open("/w/ok/prog2", O_RDONLY);
    CHECK(denied >= 0 && path >= 0 && allowed >= 0);
    jail(EXECUTE | READ_FILE);
    // Open before, but its node is what's checked.
    CHECK(exec_fd(denied, "") == 100 + EACCES);
    CHECK(exec_fd(path, "") == 100 + EACCES);
    CHECK(exec_fd(allowed, "jailed") == 0);
}

static void t_fexec(void) {
    tree();
    copy_self("/w/ok/prog");
    copy_self("/w/ok/prog2");
    copy_self("/w/deny/prog");
    int fd = open("/w/ok/prog", O_RDONLY), pathfd = open("/w/ok/prog", O_PATH);
    CHECK(fd >= 0 && pathfd >= 0);
    CHECK(exec_fd(fd, "plain") == 0);
    CHECK(exec_fd(pathfd, "o_path") == 0);
    // Unlinked, with something else at its name now.
    CHECK(unlink("/w/ok/prog") == 0);
    put("/w/ok/prog", "#!/bin/hardening2 wrongfile\n");
    CHECK(exec_fd(fd, "unlinked") == 0);
    CHECK(exec_fd(pathfd, "unlinked_o_path") == 0);
    // Scripts read themselves through /dev/fd/N, while it's open.
    put("/w/ok/script", "#!/bin/hardening2 script\n");
    int script = open("/w/ok/script", O_RDONLY);
    CHECK(script >= 0 && exec_fd(script, "") == 0);
    CHECK(fcntl(script, F_SETFD, FD_CLOEXEC) == 0);
    CHECK(exec_fd(script, "") == 100 + ENOENT);
    // Only regular files, executable ones.
    int dir = open("/w/ok", O_RDONLY | O_DIRECTORY), p[2];
    CHECK(dir >= 0 && pipe(p) == 0);
    CHECK(exec_fd(dir, "") == 100 + EACCES);
    CHECK(exec_fd(p[0], "") == 100 + EACCES);
    CHECK(exec_fd(AT_FDCWD, "") == 100 + EACCES);
    CHECK(exec_fd(77, "") == 100 + EBADF);
    put("/w/ok/plain", "nothing");
    CHECK(chmod("/w/ok/plain", 0644) == 0);
    int plain = open("/w/ok/plain", O_RDONLY);
    CHECK(exec_fd(plain, "") == 100 + EACCES);
    // AT_SYMLINK_NOFOLLOW.
    CHECK(symlink("/w/ok/prog2", "/w/ok/link") == 0);
    char *argv[] = {"prog", 0}, *envp[] = {0};
    FAILS(syscall(SYS_execveat, AT_FDCWD, "/w/ok/link", argv, envp, AT_SYMLINK_NOFOLLOW), ELOOP);
    isolated(fexec_jailed);
}

// Run as root, with a copy at /app/mine only root may run: execute
// permission is the caller's, as read and write are.
static void t_execperm(void) {
    CHECK(getuid() == 0);
    struct stat st;
    CHECK(stat("/app/mine", &st) == 0 && (st.st_mode & 0777) == 0700);
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        CHECK(setgid(1000) == 0 && setuid(1000) == 0);
        char *argv[] = {"mine", "ran", "", 0}, *envp[] = {0};
        FAILS(execve("/app/mine", argv, envp), EACCES);
        _exit(0);
    }
    int status;
    CHECK(waitpid(c, &status, 0) == c && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void as_user(void (*f)(void)) {
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        f();
        _exit(0);
    }
    int status;
    CHECK(waitpid(c, &status, 0) == c && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void in_group(void) {
    gid_t groups[] = {3000};
    CHECK(setgroups(1, groups) == 0 && setgid(2000) == 0 && setuid(2000) == 0);
    CHECK(open("/tmp/f", O_RDONLY) >= 0 && access("/tmp/f", R_OK) == 0);
    FAILS(open("/tmp/f", O_WRONLY), EACCES);
    FAILS(access("/tmp/f", W_OK), EACCES);
    // One of its groups, and no other.
    CHECK(chown("/tmp/own", -1, 3000) == 0);
    FAILS(chown("/tmp/own", -1, 4000), EPERM);
}

static void not_in_group(void) {
    CHECK(setgroups(0, 0) == 0 && setgid(2000) == 0 && setuid(2000) == 0);
    FAILS(open("/tmp/f", O_RDONLY), EACCES);
    FAILS(access("/tmp/f", R_OK), EACCES);
}

// access asks for the real ids, AT_EACCESS and open for the effective.
static void other_effective(void) {
    CHECK(setgroups(0, 0) == 0 && setgid(2000) == 0 && setresuid(2000, 2001, 2000) == 0);
    CHECK(access("/tmp/own", R_OK) == 0);
    FAILS(syscall(SYS_faccessat2, AT_FDCWD, "/tmp/own", R_OK, AT_EACCESS), EACCES);
    FAILS(open("/tmp/own", O_RDONLY), EACCES);
}

static void t_groupperm(void) {
    CHECK(getuid() == 0);
    int f = open("/tmp/f", O_CREAT | O_WRONLY, 0640), own = open("/tmp/own", O_CREAT | O_WRONLY, 0400);
    CHECK(f >= 0 && own >= 0 && fchown(f, 0, 3000) == 0 && fchown(own, 2000, 2000) == 0);
    as_user(in_group);
    as_user(not_in_group);
    as_user(other_effective);
}

// A dynamic program takes execute permission on its interpreter too.
static void busybox_runs(void) {
    CHECK(setgroups(0, 0) == 0 && setgid(2000) == 0 && setuid(2000) == 0);
    char *argv[] = {"busybox", "true", 0}, *envp[] = {0};
    execve("/bin/busybox", argv, envp);
    CHECK(!"execve failed");
}

static void busybox_refused(void) {
    CHECK(setgroups(0, 0) == 0 && setgid(2000) == 0 && setuid(2000) == 0);
    // `false`: if it runs after all, this child doesn't end as a success.
    char *argv[] = {"busybox", "false", 0}, *envp[] = {0};
    FAILS(execve("/bin/busybox", argv, envp), EACCES);
}

static void t_interpperm(void) {
    CHECK(getuid() == 0);
    const char *ld[] = {"/lib/ld-musl-aarch64.so.1", "/lib/ld-musl-x86_64.so.1"};
    as_user(busybox_runs);
    CHECK(chmod(ld[0], 0700) == 0 || chmod(ld[1], 0700) == 0);
    as_user(busybox_refused);
}

// ---- /proc/self/fd/N/name

static void fdpath_jailed(void) {
    int dir = open("/w/deny", O_PATH);
    CHECK(dir >= 0);
    jail(READ_FILE);
    char p[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d/secret", dir);
    FAILS(open(p, O_RDONLY), EACCES);
    snprintf(p, sizeof p, "/dev/fd/%d/secret", dir);
    FAILS(open(p, O_RDONLY), EACCES);
}

static void t_fdpath(void) {
    tree();
    int dir = open("/w/ok", O_RDONLY | O_DIRECTORY), file = open("/w/ok/mine", O_RDONLY), p2[2];
    CHECK(dir >= 0 && file >= 0 && pipe(p2) == 0);
    char p[64], b[16] = {0};
    snprintf(p, sizeof p, "/proc/self/fd/%d/mine", dir);
    int fd = open(p, O_RDONLY);
    CHECK(fd >= 0 && read(fd, b, 4) == 4 && memcmp(b, "mine", 4) == 0);
    struct stat st;
    CHECK(stat(p, &st) == 0 && st.st_size == 4 && access(p, R_OK) == 0);
    snprintf(p, sizeof p, "/dev/fd/%d/mine", dir);
    CHECK(stat(p, &st) == 0);
    snprintf(p, sizeof p, "/proc/%d/fd/%d/mine", getpid(), dir);
    CHECK(stat(p, &st) == 0);
    // From the directory: relative, and every kind of call.
    int proc = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    snprintf(p, sizeof p, "%d/mine", dir);
    CHECK(proc >= 0 && fstatat(proc, p, &st, 0) == 0);
    snprintf(p, sizeof p, "/proc/self/fd/%d/made", dir);
    fd = open(p, O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0 && close(fd) == 0 && access("/w/ok/made", F_OK) == 0);
    CHECK(unlink(p) == 0 && access("/w/ok/made", F_OK) == -1);
    snprintf(p, sizeof p, "/proc/self/fd/%d/sub", dir);
    CHECK(mkdir(p, 0755) == 0 && rmdir(p) == 0);
    snprintf(p, sizeof p, "/proc/self/fd/%d/.", dir);
    CHECK(stat(p, &st) == 0 && S_ISDIR(st.st_mode));
    snprintf(p, sizeof p, "/proc/self/fd/%d/../deny/secret", dir);
    CHECK(stat(p, &st) == 0 && st.st_size == 9);
    // What's no directory, or no descriptor.
    snprintf(p, sizeof p, "/proc/self/fd/%d/x", file);
    FAILS(stat(p, &st), ENOTDIR);
    snprintf(p, sizeof p, "/proc/self/fd/%d/x", p2[0]);
    FAILS(stat(p, &st), ENOTDIR);
    FAILS(stat("/proc/self/fd/777/x", &st), ENOENT);
    FAILS(stat("/proc/self/fd/notanumber/x", &st), ENOENT);
    // openat2 knows it for a magic link.
    snprintf(p, sizeof p, "/proc/self/fd/%d/mine", dir);
    struct open_how how = {.flags = O_RDONLY, .resolve = RESOLVE_NO_MAGICLINKS};
    FAILS(syscall(SYS_openat2, AT_FDCWD, p, &how, sizeof how), ELOOP);
    how.resolve = RESOLVE_NO_SYMLINKS;
    FAILS(syscall(SYS_openat2, AT_FDCWD, p, &how, sizeof how), ELOOP);
    how.resolve = RESOLVE_NO_XDEV;
    FAILS(syscall(SYS_openat2, AT_FDCWD, p, &how, sizeof how), EXDEV);
    isolated(fdpath_jailed);
}

// ---- the end of the alternate stack

// The kernel's MINSIGSTKSZ: musl's arm64 one is bigger, and its sigaltstack refuses less.
#ifdef __aarch64__
#define KERNEL_MINSIGSTKSZ 5120
#else
#define KERNEL_MINSIGSTKSZ 2048
#endif

static volatile int depth;
static void on_usr2(int s) {
    (void)s;
    depth = 2;
}
static void on_usr1(int s) {
    (void)s;
    depth = 1;
    raise(SIGUSR2);
    depth = 3;
}
static void alt_nested(void) {
    long size = getauxval(AT_MINSIGSTKSZ);
    CHECK(size >= 1024);
    // One frame fits with room for its handler to run, not two, with
    // memory below to write the second to: only the kernel's check stops
    // it there. (A handler that runs off the stack is off it, to the
    // kernel as to Linux's on_sig_stack: the next frame starts again at
    // the top, over this one's.)
    char *m = mmap(0, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED);
    long room = size + 768 < KERNEL_MINSIGSTKSZ ? KERNEL_MINSIGSTKSZ : size + 768;
    stack_t ss = {.ss_sp = m + 32768, .ss_size = room};
    CHECK(syscall(SYS_sigaltstack, &ss, 0) == 0);
    struct sigaction sa = {.sa_handler = on_usr1, .sa_flags = SA_ONSTACK};
    sigaction(SIGUSR1, &sa, 0);
    sa.sa_handler = on_usr2;
    sigaction(SIGUSR2, &sa, 0);
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        raise(SIGUSR1);
        _exit(depth == 3 ? 7 : 8);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
}
static void alt_small(void) {
    char *m = mmap(0, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED);
    stack_t ss = {.ss_sp = m, .ss_size = KERNEL_MINSIGSTKSZ - 1};
    FAILS(syscall(SYS_sigaltstack, &ss, 0), ENOMEM);
    ss.ss_size = KERNEL_MINSIGSTKSZ;
    CHECK(syscall(SYS_sigaltstack, &ss, 0) == 0);
    // A stack too small for this CPU's frame: SIGSEGV, or the handler.
    memset(m, 0x5a, 1 << 16);
    ss.ss_sp = m + 32768;
    CHECK(syscall(SYS_sigaltstack, &ss, 0) == 0);
    struct sigaction sa = {.sa_handler = on_usr2, .sa_flags = SA_ONSTACK};
    sigaction(SIGUSR1, &sa, 0);
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        for (int i = 0; i < 3; i++) raise(SIGUSR1);
        for (int i = 0; i < 32768; i++) CHECK((unsigned char)m[i] == 0x5a);
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c);
    long need = getauxval(AT_MINSIGSTKSZ);
    if (need > KERNEL_MINSIGSTKSZ) CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
    else CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}
static void t_altstack(void) {
    isolated(alt_small);
    isolated(alt_nested);
}

// ---- a ruleset as big as they get is enforced

static void t_rules(void) {
    int rs = create_ruleset(READ_FILE, CONNECT_TCP);
    CHECK(rs >= 0);
    for (int port = 0; port < 40000; port++) {
        struct netport np = {CONNECT_TCP, port};
        CHECK(syscall(SYS_landlock_add_rule, rs, 2, &np, 0) == 0);
    }
    // Rules on files too, each keeping its node, paid for once however
    // many tables hold it.
    CHECK(mkdir("/w", 0755) == 0);
    for (int i = 0; i < 20000; i++) {
        char p[32];
        snprintf(p, sizeof p, "/w/%d", i);
        int f = open(p, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
        CHECK(f >= 0);
        close(f);
        allow(rs, p, READ_FILE);
    }
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        CHECK(syscall(SYS_landlock_restrict_self, rs, 0) == 0);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(40000), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        FAILS(connect(s, (void *)&a, sizeof a), EACCES);
        CHECK(access("/w/19999", R_OK) == 0);
        FAILS(open("/bin/hardening2", O_RDONLY), EACCES);
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    // A whole domain's copy for each child: the budget says when.
    int domains = 0;
    for (int i = 0; i < 40; i++) {
        pid_t k = fork();
        CHECK(k >= 0);
        if (k == 0) _exit(syscall(SYS_landlock_restrict_self, rs, 0) == 0 ? 0 : 1);
        CHECK(waitpid(k, &st, 0) == k && WIFEXITED(st));
        domains += WEXITSTATUS(st) == 0;
    }
    CHECK(domains == 40);
}

// ---- watches can't use up the host's descriptors

// A watch on DIR and each of its directories, then what the host must
// still do for the program: every file of DIR/big, and a connection.
static void t_watchmany(const char *dir, int port) {
    int ifd = inotify_init1(IN_NONBLOCK);
    CHECK(ifd >= 0 && inotify_add_watch(ifd, dir, IN_CREATE) >= 0);
    DIR *d = opendir(dir);
    CHECK(d != 0);
    struct dirent *e;
    int watched = 0;
    while ((e = readdir(d))) {
        char p[512];
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        CHECK(inotify_add_watch(ifd, p, IN_CREATE) >= 0);
        watched++;
    }
    closedir(d);
    CHECK(watched > 100);
    char p[512], b[16];
    for (int i = 0; i < 1500; i++) {
        snprintf(p, sizeof p, "%s/big/f%d", dir, i);
        int fd = open(p, O_RDONLY);
        CHECK(fd >= 0 && read(fd, b, sizeof b) == 1 && b[0] == 'x');
        close(fd);
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(0x0a000202)};
    CHECK(connect(s, (void *)&a, sizeof a) == 0);
    CHECK(write(s, "ping", 4) == 4 && read(s, b, 4) == 4 && memcmp(b, "ping", 4) == 0);
    // What wasn't watched is said: nothing to expect on Linux, where a
    // watch takes no descriptor; macOS's come within a tick or so.
    struct pollfd pf = {.fd = ifd, .events = POLLIN};
    int lost = 0;
    while (poll(&pf, 1, 1500) == 1) {
        char ev[4096] __attribute__((aligned(8)));
        ssize_t n = read(ifd, ev, sizeof ev);
        CHECK(n > 0);
        for (ssize_t at = 0; at < n;) {
            struct inotify_event *i = (void *)(ev + at);
            lost |= (i->mask & IN_Q_OVERFLOW) != 0;
            at += sizeof *i + i->len;
        }
    }
    printf("watched %d, %s\n", watched, lost ? "overflow" : "all");
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    const char *c = argc > 1 ? argv[1] : "";
    if (!strcmp(c, "watchmany")) {
        CHECK(argc > 3);
        t_watchmany(argv[2], atoi(argv[3]));
        printf("watchmany ok\n");
        return 0;
    }
    // What the other tests exec.
    if (!strcmp(c, "hold")) {
        char b;
        (void)!read(99, &b, 1);
        return 0;
    }
    if (!strcmp(c, "ran")) {
        if (argc > 2 && argv[2][0]) printf("ran %s\n", argv[2]);
        return 0;
    }
    if (!strcmp(c, "script")) return !(argc > 2 && !strncmp(argv[2], "/dev/fd/", 8));
    if (!strcmp(c, "wrongfile")) {
        printf("FAILED: ran what's at the old name\n");
        return 9;
    }
    struct { const char *name; void (*f)(void); } tests[] = {
        {"mode3", t_mode3}, {"opath", t_opath}, {"race", t_race}, {"heap", t_heap}, {"timers", t_timers},
        {"epoll", t_epoll}, {"argv", t_argv}, {"tabs", t_tabs}, {"ptsperm", t_ptsperm}, {"sigioperm", t_sigioperm},
        {"execperm", t_execperm}, {"groupperm", t_groupperm}, {"interpperm", t_interpperm},
        {"fasync", t_fasync}, {"timerfd", t_timerfd}, {"fexec", t_fexec}, {"fdpath", t_fdpath},
        {"altstack", t_altstack}, {"rules", t_rules},
    };
    for (unsigned i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        if (!strcmp(c, tests[i].name)) {
            tests[i].f();
            printf("%s ok\n", c);
            return 0;
        }
    }
    printf("usage: hardening2 <subcommand>\n");
    return 2;
}
