// AF_UNIX sockets: streams to a path (a socket node), to an abstract
// name and to an autobound one; datagrams and seqpackets keep their
// boundaries; names, credentials, and descriptors passed with SCM_RIGHTS
// (to another process too). Needs `fs_write` (for the path) and `process`.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

static socklen_t addr(struct sockaddr_un *a, const char *path, int abstract) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (abstract) {
        memcpy(a->sun_path + 1, path, n);
        return offsetof(struct sockaddr_un, sun_path) + 1 + n;
    }
    memcpy(a->sun_path, path, n);
    return offsetof(struct sockaddr_un, sun_path) + n + 1;
}

static void send_fd(int sock, int fd, const char *data) {
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {(void *)data, strlen(data)};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf};
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof fd);
    CHECK(sendmsg(sock, &m, 0) == (ssize_t)strlen(data));
}

static int recv_fd(int sock, char *data, size_t len, int *flags) {
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {data, len};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf};
    ssize_t n = recvmsg(sock, &m, 0);
    CHECK(n > 0);
    data[n] = 0;
    *flags = m.msg_flags;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c) return -1;
    CHECK(c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int)));
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof fd);
    return fd;
}

static void streams(void) {
    struct sockaddr_un a, got;
    socklen_t len = addr(&a, "/tmp/sock", 0), glen;
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(srv >= 0 && bind(srv, (void *)&a, len) == 0 && listen(srv, 4) == 0);
    struct stat st;
    CHECK(stat("/tmp/sock", &st) == 0 && S_ISSOCK(st.st_mode));
    CHECK(open("/tmp/sock", O_RDWR) == -1 && errno == ENXIO);
    int again = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(again, (void *)&a, len) == -1 && errno == EADDRINUSE);
    close(again);

    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(c, (void *)&a, len) == 0);
    int s = accept(srv, (void *)&got, &(socklen_t){sizeof got});
    CHECK(s >= 0);
    CHECK(write(c, "ping", 4) == 4);
    char buf[64] = {0};
    CHECK(read(s, buf, sizeof buf) == 4 && memcmp(buf, "ping", 4) == 0);
    CHECK(write(s, "pong", 4) == 4 && read(c, buf, sizeof buf) == 4 && memcmp(buf, "pong", 4) == 0);
    glen = sizeof got;
    CHECK(getpeername(c, (void *)&got, &glen) == 0 && strcmp(got.sun_path, "/tmp/sock") == 0);
    glen = sizeof got;
    CHECK(getsockname(s, (void *)&got, &glen) == 0 && strcmp(got.sun_path, "/tmp/sock") == 0);
    struct ucred cr;
    CHECK(getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &(socklen_t){sizeof cr}) == 0 && cr.pid == getpid());
    close(c);
    CHECK(read(s, buf, sizeof buf) == 0);
    close(s);

    // Bound but not listening: refused. Gone: ENOENT.
    struct sockaddr_un b;
    socklen_t blen = addr(&b, "/tmp/idle", 0);
    int idle = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(idle, (void *)&b, blen) == 0);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(c, (void *)&b, blen) == -1 && errno == ECONNREFUSED);
    CHECK(unlink("/tmp/sock") == 0);
    CHECK(connect(c, (void *)&a, len) == -1 && errno == ENOENT);
    close(c);
    close(srv);
    close(idle);

    // An abstract name, and an autobound one.
    len = addr(&a, "grix-test", 1);
    srv = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(srv, (void *)&a, len) == 0 && listen(srv, 1) == 0);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un any = {.sun_family = AF_UNIX};
    CHECK(bind(c, (void *)&any, sizeof(sa_family_t)) == 0);
    glen = sizeof got;
    CHECK(getsockname(c, (void *)&got, &glen) == 0 && glen > sizeof(sa_family_t) + 1 && got.sun_path[0] == 0);
    CHECK(connect(c, (void *)&a, len) == 0);
    s = accept(srv, (void *)&got, &(socklen_t){sizeof got});
    CHECK(s >= 0 && got.sun_path[0] == 0);
    close(s);
    close(c);
    close(srv);
}

static void messages(void) {
    struct sockaddr_un a, b, got;
    socklen_t alen = addr(&a, "/tmp/dga", 0), blen = addr(&b, "/tmp/dgb", 0), glen;
    int x = socket(AF_UNIX, SOCK_DGRAM, 0), y = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(bind(x, (void *)&a, alen) == 0 && bind(y, (void *)&b, blen) == 0);
    CHECK(sendto(x, "one", 3, 0, (void *)&b, blen) == 3 && sendto(x, "", 0, 0, (void *)&b, blen) == 0);
    CHECK(sendto(x, "three", 5, 0, (void *)&b, blen) == 5);
    char buf[16];
    glen = sizeof got;
    CHECK(recvfrom(y, buf, sizeof buf, 0, (void *)&got, &glen) == 3 && strcmp(got.sun_path, "/tmp/dga") == 0);
    CHECK(recv(y, buf, sizeof buf, 0) == 0);
    // Too small: the rest of the datagram goes, and MSG_TRUNC says so.
    struct iovec iov = {buf, 2};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    CHECK(recvmsg(y, &m, 0) == 2 && (m.msg_flags & MSG_TRUNC));
    CHECK(recv(y, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    // Connected: send() goes there; an unbound sender is unnamed.
    CHECK(connect(x, (void *)&b, blen) == 0 && send(x, "hi", 2, 0) == 2 && recv(y, buf, sizeof buf, 0) == 2);
    int u = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(sendto(u, "u", 1, 0, (void *)&a, alen) == 1);
    glen = sizeof got;
    CHECK(recvfrom(x, buf, sizeof buf, 0, (void *)&got, &glen) == 1 && glen == 0);
    // Connected to itself.
    CHECK(connect(x, (void *)&a, alen) == 0 && send(x, "self", 4, 0) == 4 && recv(x, buf, sizeof buf, 0) == 4);
    glen = sizeof got;
    CHECK(getpeername(x, (void *)&got, &glen) == 0 && strcmp(got.sun_path, "/tmp/dga") == 0);
    struct pollfd pf = {x, POLLOUT, 0};
    CHECK(poll(&pf, 1, 0) == 1 && (pf.revents & POLLOUT));
    // writev is one datagram.
    struct iovec two[2] = {{"ab", 2}, {"cd", 2}};
    CHECK(writev(x, two, 2) == 4 && recv(x, buf, sizeof buf, 0) == 4);
    close(x);
    close(y);
    close(u);

    // Pairs keep message boundaries; a seqpacket peer's close is EOF.
    int dp[2], sp[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, dp) == 0 && socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp) == 0);
    CHECK(write(dp[0], "ab", 2) == 2 && write(dp[0], "cde", 3) == 3);
    CHECK(read(dp[1], buf, sizeof buf) == 2 && read(dp[1], buf, sizeof buf) == 3);
    CHECK(write(sp[0], "x", 1) == 1 && write(sp[0], "yz", 2) == 2);
    CHECK(read(sp[1], buf, sizeof buf) == 1 && read(sp[1], buf, sizeof buf) == 2);
    close(sp[0]);
    CHECK(read(sp[1], buf, sizeof buf) == 0);
    close(sp[1]);
    close(dp[0]);
    close(dp[1]);

    // Seqpacket through a listener.
    socklen_t len = addr(&a, "grix-seq", 1);
    int srv = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    CHECK(bind(srv, (void *)&a, len) == 0 && listen(srv, 1) == 0);
    int c = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    CHECK(connect(c, (void *)&a, len) == 0);
    int s = accept(srv, 0, 0);
    CHECK(s >= 0 && send(c, "pkt1", 4, 0) == 4 && send(c, "p2", 2, 0) == 2);
    CHECK(recv(s, buf, sizeof buf, 0) == 4 && recv(s, buf, sizeof buf, 0) == 2);
    CHECK(connect(c, (void *)&a, len) == -1 && errno == EISCONN);
    CHECK(connect(srv, (void *)&a, len) == -1 && errno == EINVAL);
    // Half-closed: readable to the end, not hung up.
    CHECK(shutdown(c, SHUT_WR) == 0);
    struct pollfd hp = {s, POLLIN, 0};
    CHECK(poll(&hp, 1, 0) == 1 && (hp.revents & POLLIN) && !(hp.revents & POLLHUP));
    CHECK(recv(s, buf, sizeof buf, 0) == 0 && send(s, "reply", 5, 0) == 5 && recv(c, buf, sizeof buf, 0) == 5);
    close(c);
    close(s);
    close(srv);
}

static void rights(void) {
    // Over a stream pair to another process: the child gets a pipe's write
    // end and the parent reads what it wrote there.
    int sv[2], pp[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && pipe(pp) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        close(sv[0]);
        close(pp[1]);
        char data[16];
        int flags;
        int fd = recv_fd(sv[1], data, sizeof data - 1, &flags);
        CHECK(fd >= 0 && strcmp(data, "take") == 0);
        CHECK(write(fd, "via passed fd", 13) == 13);
        _exit(0);
    }
    close(sv[1]);
    send_fd(sv[0], pp[1], "take");
    close(pp[1]);
    char buf[32] = {0};
    CHECK(read(pp[0], buf, sizeof buf) == 13 && strcmp(buf, "via passed fd") == 0);
    int st;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    // Over a datagram pair, and with no room for it: MSG_CTRUNC.
    int dp[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, dp) == 0);
    int f = open("/bin/unixsock", O_RDONLY);
    send_fd(dp[0], f, "d");
    int flags;
    int g = recv_fd(dp[1], buf, sizeof buf - 1, &flags);
    struct stat s1, s2;
    CHECK(g >= 0 && fstat(f, &s1) == 0 && fstat(g, &s2) == 0 && s1.st_ino == s2.st_ino);
    send_fd(dp[0], f, "e");
    struct iovec iov = {buf, sizeof buf};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    CHECK(recvmsg(dp[1], &m, 0) == 1 && (m.msg_flags & MSG_CTRUNC));
    // A plain read of bytes that came with descriptors drops them; the
    // next descriptors arrive with their own bytes.
    int sp[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    send_fd(sp[0], f, "r");
    send_fd(sp[0], f, "s");
    char ch;
    CHECK(read(sp[1], &ch, 1) == 1 && ch == 'r');
    g = recv_fd(sp[1], buf, sizeof buf - 1, &flags);
    CHECK(g >= 0 && strcmp(buf, "s") == 0);
    // A socket can't be sent through itself (it would hold itself open).
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct iovec one = {"x", 1};
    struct msghdr sm = {.msg_iov = &one, .msg_iovlen = 1, .msg_control = cbuf, .msg_controllen = sizeof cbuf};
    struct cmsghdr *c = CMSG_FIRSTHDR(&sm);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &sp[1], sizeof(int));
    CHECK(sendmsg(sp[0], &sm, 0) == -1 && errno == ETOOMANYREFS);
}

int main(void) {
    streams();
    messages();
    rights();
    printf("unixsock ok\n");
    return 0;
}
