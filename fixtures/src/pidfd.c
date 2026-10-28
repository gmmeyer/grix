// pidfds: pidfd_open, pidfd_send_signal, pidfd_getfd, clone's CLONE_PIDFD,
// waitid(P_PIDFD), and polling one for the process's end. Needs `process`.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x1000
#endif
#define PIDFD_NONBLOCK O_NONBLOCK

static int pidfd_open(pid_t pid, unsigned flags) { return syscall(SYS_pidfd_open, pid, flags); }
static int pidfd_send_signal(int fd, int sig, siginfo_t *info, unsigned flags) {
    return syscall(SYS_pidfd_send_signal, fd, sig, info, flags);
}
static int pidfd_getfd(int fd, int target, unsigned flags) { return syscall(SYS_pidfd_getfd, fd, target, flags); }

static int ready(int fd, int timeout) {
    struct pollfd p = {fd, POLLIN, 0};
    int n = poll(&p, 1, timeout);
    CHECK(n >= 0);
    return n == 1 && (p.revents & POLLIN);
}

// A child that waits to be killed.
static pid_t sleeper(void) {
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        for (;;) pause();
    }
    return pid;
}

int main(void) {
    // Our own: signal 0 works, and we can't wait for ourselves.
    int self = pidfd_open(getpid(), 0);
    CHECK(self >= 0);
    CHECK(fcntl(self, F_GETFD) == FD_CLOEXEC);
    CHECK(pidfd_send_signal(self, 0, NULL, 0) == 0);
    siginfo_t info;
    CHECK(waitid(P_PIDFD, self, &info, WEXITED | WNOHANG) == -1 && errno == ECHILD);
    CHECK(!ready(self, 0));
    char link[64] = {0}, path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", self);
    CHECK(readlink(path, link, sizeof link - 1) > 0 && strcmp(link, "anon_inode:[pidfd]") == 0);
    CHECK(pidfd_send_signal(self, 0, NULL, 1) == -1 && errno == EINVAL);
    CHECK(pidfd_open(0, 0) == -1 && errno == EINVAL);
    CHECK(pidfd_open(99999, 0) == -1 && errno == ESRCH);
    char junk;
    CHECK(read(self, &junk, 1) == -1 && errno == EINVAL);

    // Killing a child through its pidfd, which becomes readable when it ends.
    pid_t kid = sleeper();
    int fd = pidfd_open(kid, 0);
    CHECK(fd >= 0);
    CHECK(!ready(fd, 50));
    CHECK(pidfd_send_signal(fd, SIGTERM, NULL, 0) == 0);
    CHECK(ready(fd, 5000));
    memset(&info, 0, sizeof info);
    CHECK(waitid(P_PIDFD, fd, &info, WEXITED) == 0);
    CHECK(info.si_pid == kid && info.si_code == CLD_KILLED && info.si_status == SIGTERM);
    CHECK(ready(fd, 0));
    CHECK(pidfd_send_signal(fd, SIGTERM, NULL, 0) == -1 && errno == ESRCH);
    CHECK(waitid(P_PIDFD, fd, &info, WEXITED) == -1 && errno == ECHILD);
    close(fd);

    // A non-blocking pidfd: waitid doesn't wait.
    kid = sleeper();
    fd = pidfd_open(kid, PIDFD_NONBLOCK);
    CHECK(fd >= 0);
    CHECK(waitid(P_PIDFD, fd, &info, WEXITED) == -1 && errno == EAGAIN);
    // Only the process itself may claim a kill(2) sent the signal.
    memset(&info, 0, sizeof info);
    info.si_signo = SIGKILL;
    info.si_code = SI_USER;
    CHECK(pidfd_send_signal(fd, SIGKILL, &info, 0) == -1 && errno == EPERM);
    info.si_code = SI_QUEUE;
    CHECK(pidfd_send_signal(fd, SIGKILL, &info, 0) == 0);
    CHECK(waitpid(kid, NULL, 0) == kid);
    close(fd);

    // clone with CLONE_PIDFD: the parent gets the pidfd, the child doesn't.
    int cfd = -1;
    long r = syscall(SYS_clone, CLONE_PIDFD | SIGCHLD, 0, &cfd, 0, 0);
    CHECK(r >= 0);
    if (r == 0) {
        _exit(fcntl(cfd, F_GETFD) == -1 && errno == EBADF ? 7 : 1);
    }
    CHECK(cfd >= 0 && fcntl(cfd, F_GETFD) == FD_CLOEXEC);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = cfd};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &ev) == 0);
    CHECK(epoll_wait(ep, &ev, 1, 5000) == 1 && ev.data.fd == cfd);
    CHECK(waitid(P_PIDFD, cfd, &info, WEXITED) == 0);
    CHECK(info.si_pid == r && info.si_code == CLD_EXITED && info.si_status == 7);
    close(ep);
    close(cfd);
    // clone can't put both at parent_tid.
    CHECK(syscall(SYS_clone, CLONE_PIDFD | CLONE_PARENT_SETTID | SIGCHLD, 0, &cfd, 0, 0) == -1 && errno == EINVAL);

    // pidfd_getfd: a child's pipe, read here.
    int tell[2];
    CHECK(pipe(tell) == 0);
    kid = fork();
    CHECK(kid >= 0);
    if (kid == 0) {
        int q[2];
        CHECK(pipe(q) == 0);
        CHECK(write(q[1], "hello", 5) == 5);
        CHECK(write(tell[1], &q[0], sizeof q[0]) == sizeof q[0]);
        for (;;) pause();
    }
    int theirs;
    CHECK(read(tell[0], &theirs, sizeof theirs) == sizeof theirs);
    fd = pidfd_open(kid, 0);
    CHECK(fd >= 0);
    int mine = pidfd_getfd(fd, theirs, 0);
    CHECK(mine >= 0 && fcntl(mine, F_GETFD) == FD_CLOEXEC);
    char buf[8] = {0};
    CHECK(read(mine, buf, sizeof buf) == 5 && memcmp(buf, "hello", 5) == 0);
    CHECK(pidfd_getfd(fd, 1000, 0) == -1 && errno == EBADF);
    CHECK(pidfd_getfd(fd, theirs, 1) == -1 && errno == EINVAL);
    CHECK(pidfd_getfd(mine, theirs, 0) == -1 && errno == EINVAL);
    // And /proc/<pid>/fd names it too.
    snprintf(path, sizeof path, "/proc/%d/fd/%d", kid, theirs);
    memset(link, 0, sizeof link);
    CHECK(readlink(path, link, sizeof link - 1) > 0 && strncmp(link, "pipe:[", 6) == 0);
    CHECK(pidfd_send_signal(fd, SIGKILL, NULL, 0) == 0);
    CHECK(waitid(P_PIDFD, fd, &info, WEXITED) == 0 && info.si_code == CLD_KILLED);

    printf("pidfd ok\n");
    return 0;
}
