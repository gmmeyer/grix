// Networking through the host.
//   inet client PORT CLOSED  - talk to an echo server on the host's PORT (via
//                             host.grix.internal); CLOSED has nothing on it
//   inet resolve NAME       - print what getaddrinfo says NAME is
//   inet server PORT        - answer one "line\n" with "pong: line\n"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)
#define RUN(t) do { if (t) return 1; } while (0)

static struct sockaddr_in host_addr(int port) {
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *res;
    struct sockaddr_in sa = {0};
    if (getaddrinfo("host.grix.internal", NULL, &hints, &res) == 0) {
        sa = *(struct sockaddr_in *)res->ai_addr;
        freeaddrinfo(res);
    }
    sa.sin_port = htons(port);
    return sa;
}

static int connect_to(struct sockaddr_in sa) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) {
        int e = errno;
        close(s);
        errno = e;
        return -1;
    }
    return s;
}

static int test_blocking(int port) {
    struct sockaddr_in sa = host_addr(port);
    CHECK(sa.sin_addr.s_addr == inet_addr("10.0.2.2"));
    int s = connect_to(sa);
    CHECK(s >= 0);
    int one = 1;
    CHECK(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0);
    struct sockaddr_in me, peer;
    socklen_t len = sizeof me;
    CHECK(getsockname(s, (struct sockaddr *)&me, &len) == 0 && me.sin_addr.s_addr == inet_addr("10.0.2.15"));
    len = sizeof peer;
    CHECK(getpeername(s, (struct sockaddr *)&peer, &len) == 0 && ntohs(peer.sin_port) == port);
    CHECK(write(s, "hello", 5) == 5);
    char buf[16] = {0};
    int got = 0;
    while (got < 5) {
        ssize_t n = read(s, buf + got, sizeof buf - 1 - got);
        CHECK(n > 0);
        got += n;
    }
    CHECK(strcmp(buf, "hello") == 0);
    // Half-close: the echo server sees end-of-file, closes, and so do we.
    CHECK(shutdown(s, SHUT_WR) == 0);
    CHECK(read(s, buf, sizeof buf) == 0);
    close(s);
    return 0;
}

static uint64_t fnv(uint64_t h, const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001b3ull;
    return h;
}

static int test_nonblocking_bulk(int port) {
    // EINPROGRESS, epoll, SO_ERROR, then 1 MiB each way through the windows.
    struct sockaddr_in sa = host_addr(port);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(s >= 0);
    CHECK(connect(s, (struct sockaddr *)&sa, sizeof sa) == -1 && errno == EINPROGRESS);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLOUT};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev) == 0);
    CHECK(epoll_wait(ep, &ev, 1, 10000) == 1 && (ev.events & EPOLLOUT));
    int err = -1;
    socklen_t len = sizeof err;
    CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0);
    CHECK(connect(s, (struct sockaddr *)&sa, sizeof sa) == -1 && errno == EISCONN);
    static unsigned char out[1 << 20], in[1 << 20];
    for (size_t i = 0; i < sizeof out; i++) out[i] = (unsigned char)(i * 7 + (i >> 11));
    size_t sent = 0, recvd = 0;
    while (recvd < sizeof in) {
        struct pollfd pf = {.fd = s, .events = POLLIN | (sent < sizeof out ? POLLOUT : 0)};
        CHECK(poll(&pf, 1, 10000) == 1);
        if ((pf.revents & POLLOUT) && sent < sizeof out) {
            ssize_t n = write(s, out + sent, sizeof out - sent);
            CHECK(n > 0 || errno == EAGAIN);
            if (n > 0) sent += n;
        }
        if (pf.revents & POLLIN) {
            ssize_t n = read(s, in + recvd, sizeof in - recvd);
            CHECK(n > 0 || errno == EAGAIN);
            if (n > 0) recvd += n;
        }
    }
    CHECK(fnv(0xcbf29ce484222325ull, in, sizeof in) == fnv(0xcbf29ce484222325ull, out, sizeof out));
    close(ep);
    close(s);
    return 0;
}

static int test_refused_and_denied(int port, int closed) {
    // Nothing listens on `closed`; port+1 and the internet aren't allowed.
    CHECK(connect_to(host_addr(closed)) == -1 && errno == ECONNREFUSED);
    CHECK(connect_to(host_addr(port + 1)) == -1 && errno == EPERM);
    struct sockaddr_in far = {.sin_family = AF_INET, .sin_port = htons(80)};
    far.sin_addr.s_addr = inet_addr("93.184.216.34");
    CHECK(connect_to(far) == -1 && errno == EPERM);
    // Nothing listens on the guest's own port 9 either.
    struct sockaddr_in lo = {.sin_family = AF_INET, .sin_port = htons(9)};
    lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(connect_to(lo) == -1 && errno == ECONNREFUSED);
    return 0;
}

static int test_loopback(void) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET};
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(l, (struct sockaddr *)&sa, sizeof sa) == 0);
    socklen_t len = sizeof sa;
    CHECK(getsockname(l, (struct sockaddr *)&sa, &len) == 0 && sa.sin_port != 0);
    CHECK(listen(l, 4) == 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(c, (struct sockaddr *)&sa, sizeof sa) == 0);
    struct sockaddr_in peer;
    len = sizeof peer;
    int a = accept4(l, (struct sockaddr *)&peer, &len, SOCK_CLOEXEC);
    CHECK(a >= 0 && peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    CHECK(write(c, "ping", 4) == 4);
    char buf[8] = {0};
    CHECK(read(a, buf, sizeof buf) == 4 && memcmp(buf, "ping", 4) == 0);
    close(c);
    CHECK(read(a, buf, sizeof buf) == 0);
    close(a);
    // The guest's own address reaches it only if it listens on all of them.
    struct sockaddr_in own = sa;
    own.sin_addr.s_addr = inet_addr("10.0.2.15");
    CHECK(connect_to(own) == -1 && errno == ECONNREFUSED);
    close(l);
    l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in any = {.sin_family = AF_INET};
    CHECK(bind(l, (struct sockaddr *)&any, sizeof any) == 0 && listen(l, 4) == 0);
    len = sizeof any;
    CHECK(getsockname(l, (struct sockaddr *)&any, &len) == 0);
    own.sin_port = any.sin_port;
    c = connect_to(own);
    CHECK(c >= 0);
    a = accept(l, NULL, NULL);
    CHECK(a >= 0);
    // SO_RCVTIMEO: a read with nothing to read gives up.
    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000}, got_tv;
    CHECK(setsockopt(a, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0);
    len = sizeof got_tv;
    CHECK(getsockopt(a, SOL_SOCKET, SO_RCVTIMEO, &got_tv, &len) == 0 && got_tv.tv_usec == 100000);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK(read(a, buf, sizeof buf) == -1 && errno == EAGAIN);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    CHECK(ms >= 90 && ms < 5000);
    // And with data, it doesn't wait.
    CHECK(write(c, "x", 1) == 1 && read(a, buf, sizeof buf) == 1);
    close(c);
    close(a);
    // Connecting to the unspecified address is connecting to loopback, as
    // on Linux (Go dials ":port" so).
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    c = connect_to(any);
    CHECK(c >= 0 && (a = accept(l, (struct sockaddr *)&peer, &len)) >= 0);
    CHECK(peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    close(c);
    close(a);
    close(l);
    l = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 any6 = {.sin6_family = AF_INET6};
    CHECK(bind(l, (struct sockaddr *)&any6, sizeof any6) == 0 && listen(l, 4) == 0);
    len = sizeof any6;
    CHECK(getsockname(l, (struct sockaddr *)&any6, &len) == 0);
    c = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(connect(c, (struct sockaddr *)&any6, sizeof any6) == 0);
    struct sockaddr_in6 peer6;
    len = sizeof peer6;
    CHECK((a = accept(l, (struct sockaddr *)&peer6, &len)) >= 0 && IN6_IS_ADDR_LOOPBACK(&peer6.sin6_addr));
    close(c);
    close(a);
    close(l);
    return 0;
}

static int test_dns_query(void) {
    // A raw A query for host.grix.internal to the virtual nameserver.
    unsigned char q[64] = {0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    int at = 12;
    const char *labels[] = {"host", "grix", "internal"};
    for (int i = 0; i < 3; i++) {
        q[at++] = (unsigned char)strlen(labels[i]);
        memcpy(q + at, labels[i], strlen(labels[i]));
        at += strlen(labels[i]);
    }
    q[at++] = 0;
    q[at++] = 0, q[at++] = 1;  // A
    q[at++] = 0, q[at++] = 1;  // IN
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ns = {.sin_family = AF_INET, .sin_port = htons(53)};
    ns.sin_addr.s_addr = inet_addr("10.0.2.3");
    CHECK(sendto(s, q, at, 0, (struct sockaddr *)&ns, sizeof ns) == at);
    unsigned char a[512];
    struct sockaddr_in from;
    socklen_t len = sizeof from;
    unsigned char peeked[512];
    ssize_t p = recv(s, peeked, sizeof peeked, MSG_PEEK);
    ssize_t n = recvfrom(s, a, sizeof a, 0, (struct sockaddr *)&from, &len);
    CHECK(p == n && memcmp(peeked, a, n) == 0);
    CHECK(n > at && a[0] == 0xab && a[1] == 0xcd && (a[3] & 0xf) == 0 && a[7] == 1);
    CHECK(from.sin_addr.s_addr == ns.sin_addr.s_addr && from.sin_port == htons(53));
    CHECK(memcmp(a + n - 4, "\x0a\x00\x02\x02", 4) == 0);
    close(s);
    return 0;
}

static int resolve(const char *name) {
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *res;
    int r = getaddrinfo(name, NULL, &hints, &res);
    if (r != 0) {
        printf("%s: %s\n", name, gai_strerror(r));
        return 0;
    }
    char buf[64];
    printf("%s is %s\n", name, inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, buf, sizeof buf));
    freeaddrinfo(res);
    return 0;
}

static int server(int port) {
    int l = socket(AF_INET6, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in6 sa = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    CHECK(bind(l, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(l, 8) == 0);
    struct sockaddr_in6 peer;
    socklen_t len = sizeof peer;
    // Only the test's "ping": tools on the host probe new ports.
    int c;
    char line[256];
    for (;;) {
        c = accept(l, (struct sockaddr *)&peer, &len);
        CHECK(c >= 0);
        if (read(c, line, 1) == 1 && line[0] == 'p') break;
        close(c);
    }
    int got = 1;
    while (got < (int)sizeof line - 1 && line[got - 1] != '\n') {
        ssize_t n = read(c, line + got, 1);
        CHECK(n == 1);
        got++;
    }
    line[got] = 0;
    char reply[300];
    int n = snprintf(reply, sizeof reply, "pong: %s", line);
    CHECK(write(c, reply, n) == n);
    close(c);
    close(l);
    printf("served one\n");
    return 0;
}

// Forwarded ports: a listener bound to loopback only isn't reachable from
// outside; one on the guest's own address is. The host connects to the
// loopback one (and is turned away) while this one's client waits, then
// says "done".
static int server_pair(int lo_port, int port) {
    int lo = socket(AF_INET, SOCK_STREAM, 0), g = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(lo_port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(lo, (struct sockaddr *)&a, sizeof a) == 0 && listen(lo, 8) == 0);
    a.sin_port = htons(port);
    CHECK(inet_pton(AF_INET, "10.0.2.15", &a.sin_addr) == 1);
    CHECK(bind(g, (struct sockaddr *)&a, sizeof a) == 0 && listen(g, 8) == 0);
    // Only the test's "ping": tools on the host probe new ports.
    int c;
    char line[64];
    for (;;) {
        c = accept(g, 0, 0);
        CHECK(c >= 0);
        if (read(c, line, 1) == 1 && line[0] == 'p') break;
        close(c);
    }
    int got = 1;
    while (got < (int)sizeof line - 1 && line[got - 1] != '\n') {
        ssize_t n = read(c, line + got, 1);
        CHECK(n == 1);
        got++;
    }
    CHECK(write(c, "pong\n", 5) == 5);
    // The host's connection to the loopback-only port has been turned
    // away by now (it saw the close before it said "done").
    char done[5];
    CHECK(read(c, done, 5) == 5 && memcmp(done, "done\n", 5) == 0);
    CHECK(fcntl(lo, F_SETFL, O_NONBLOCK) == 0);
    CHECK(accept(lo, 0, 0) < 0 && errno == EAGAIN);
    printf("served one; loopback-only: nothing\n");
    return 0;
}

// Forwarded ports: more than any one buffer on the way holds, and the end
// of the program with nothing closed. On Linux it would all still arrive.
static int parting(int port) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 8) == 0);
    int c;
    char first;
    for (;;) {
        c = accept(l, 0, 0);
        CHECK(c >= 0);
        if (read(c, &first, 1) == 1 && first == 'p') break;
        close(c);
    }
    static unsigned char data[1 << 20];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (unsigned char)(i * 7 + (i >> 11));
    for (size_t sent = 0; sent < sizeof data;) {
        ssize_t n = write(c, data + sent, sizeof data - sent);
        CHECK(n > 0);
        sent += n;
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "resolve") == 0) return resolve(argv[2]);
    if (argc == 3 && strcmp(argv[1], "parting") == 0) return parting(atoi(argv[2]));
    if (argc == 4 && strcmp(argv[1], "server-pair") == 0) return server_pair(atoi(argv[2]), atoi(argv[3]));
    if (argc == 3 && strcmp(argv[1], "server") == 0) return server(atoi(argv[2]));
    if (argc != 4 || strcmp(argv[1], "client") != 0) return 2;
    int port = atoi(argv[2]), closed = atoi(argv[3]);
    RUN(test_blocking(port));
    RUN(test_nonblocking_bulk(port));
    RUN(test_refused_and_denied(port, closed));
    RUN(test_loopback());
    RUN(test_dns_query());
    printf("net ok\n");
    return 0;
}
