// Socket options read back as they were set, with Linux's defaults and
// checks, and TCP_INFO says what state a connection is in. Passes on Linux
// as it is, given a port that echoes.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(c)                                                                 \
    do {                                                                         \
        if (!(c)) {                                                              \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);     \
            exit(1);                                                             \
        }                                                                        \
    } while (0)
#define FAILS(call, e) CHECK((long)(call) == -1 && errno == (e))

static int get(int s, int level, int name) {
    int v = -999;
    socklen_t len = sizeof v;
    CHECK(getsockopt(s, level, name, &v, &len) == 0 && len == sizeof v);
    return v;
}

static void set(int s, int level, int name, int v) {
    CHECK(setsockopt(s, level, name, &v, sizeof v) == 0);
}

// An option that's on or off: off, says what's set, and any true is 1.
static void flag(int s, int level, int name, int by_default) {
    CHECK(get(s, level, name) == by_default);
    set(s, level, name, 1);
    CHECK(get(s, level, name) == 1);
    set(s, level, name, 7);
    CHECK(get(s, level, name) == 1);
    set(s, level, name, 0);
    CHECK(get(s, level, name) == 0);
    set(s, level, name, by_default);
}

static void options(void) {
    int t = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(t >= 0);
    flag(t, SOL_SOCKET, SO_KEEPALIVE, 0);
    flag(t, SOL_SOCKET, SO_REUSEADDR, 0);
    flag(t, SOL_SOCKET, SO_REUSEPORT, 0);
    flag(t, SOL_SOCKET, SO_OOBINLINE, 0);
    flag(t, IPPROTO_TCP, TCP_NODELAY, 0);
    flag(t, IPPROTO_TCP, TCP_CORK, 0);
    // TCP's numbers, with Linux's defaults, and what it won't take.
    CHECK(get(t, IPPROTO_TCP, TCP_KEEPIDLE) == 7200);
    CHECK(get(t, IPPROTO_TCP, TCP_KEEPINTVL) == 75);
    CHECK(get(t, IPPROTO_TCP, TCP_KEEPCNT) == 9);
    set(t, IPPROTO_TCP, TCP_KEEPIDLE, 30);
    set(t, IPPROTO_TCP, TCP_KEEPINTVL, 5);
    set(t, IPPROTO_TCP, TCP_KEEPCNT, 3);
    CHECK(get(t, IPPROTO_TCP, TCP_KEEPIDLE) == 30);
    CHECK(get(t, IPPROTO_TCP, TCP_KEEPINTVL) == 5);
    CHECK(get(t, IPPROTO_TCP, TCP_KEEPCNT) == 3);
    int v = 0;
    FAILS(setsockopt(t, IPPROTO_TCP, TCP_KEEPIDLE, &v, sizeof v), EINVAL);
    v = 40000;
    FAILS(setsockopt(t, IPPROTO_TCP, TCP_KEEPIDLE, &v, sizeof v), EINVAL);
    v = 0;
    FAILS(setsockopt(t, IPPROTO_TCP, TCP_KEEPCNT, &v, sizeof v), EINVAL);
    v = 1;
    FAILS(setsockopt(t, IPPROTO_TCP, TCP_KEEPIDLE, &v, 1), EINVAL);
    // IP's.
    CHECK(get(t, IPPROTO_IP, IP_TOS) == 0);
    // (Whatever the system's default is, which a machine can change.)
    int ttl = get(t, IPPROTO_IP, IP_TTL);
    CHECK(ttl > 0);
    set(t, IPPROTO_IP, IP_TTL, 12);
    CHECK(get(t, IPPROTO_IP, IP_TTL) == 12);
    v = 0;
    FAILS(setsockopt(t, IPPROTO_IP, IP_TTL, &v, sizeof v), EINVAL);
    v = 256;
    FAILS(setsockopt(t, IPPROTO_IP, IP_TTL, &v, sizeof v), EINVAL);
    set(t, IPPROTO_IP, IP_TTL, -1);
    CHECK(get(t, IPPROTO_IP, IP_TTL) == ttl);
    set(t, IPPROTO_IP, IP_TOS, 0x10);
    CHECK(get(t, IPPROTO_IP, IP_TOS) == 0x10);
    // Asked for twice over, as Linux keeps it, within its limits.
    CHECK(get(t, SOL_SOCKET, SO_SNDBUF) > 0 && get(t, SOL_SOCKET, SO_RCVBUF) > 0);
    set(t, SOL_SOCKET, SO_RCVBUF, 8192);
    CHECK(get(t, SOL_SOCKET, SO_RCVBUF) == 16384);
    set(t, SOL_SOCKET, SO_SNDBUF, 8192);
    CHECK(get(t, SOL_SOCKET, SO_SNDBUF) == 16384);
    set(t, SOL_SOCKET, SO_SNDBUF, 1);
    CHECK(get(t, SOL_SOCKET, SO_SNDBUF) == 4608);
    set(t, SOL_SOCKET, SO_RCVBUF, 1);
    CHECK(get(t, SOL_SOCKET, SO_RCVBUF) == 2304);
    // A struct of its own.
    struct linger l = {1, 3}, got;
    socklen_t len = sizeof got;
    CHECK(setsockopt(t, SOL_SOCKET, SO_LINGER, &l, sizeof l) == 0);
    CHECK(getsockopt(t, SOL_SOCKET, SO_LINGER, &got, &len) == 0 && len == sizeof got);
    CHECK(got.l_onoff == 1 && got.l_linger == 3);
    FAILS(setsockopt(t, SOL_SOCKET, SO_LINGER, &l, 1), EINVAL);
    // Nothing of a name there isn't.
    FAILS(setsockopt(t, IPPROTO_TCP, 9999, &v, sizeof v), ENOPROTOOPT);
    FAILS(getsockopt(t, IPPROTO_TCP, 9999, &v, &len), ENOPROTOOPT);
    FAILS(setsockopt(t, IPPROTO_IP, 9999, &v, sizeof v), ENOPROTOOPT);
    FAILS(setsockopt(t, SOL_SOCKET, 9999, &v, sizeof v), ENOPROTOOPT);
    FAILS(setsockopt(t, 9999, 1, &v, sizeof v), ENOPROTOOPT);
    char name[16] = {0};
    len = sizeof name;
    CHECK(getsockopt(t, IPPROTO_TCP, TCP_CONGESTION, name, &len) == 0 && name[0] != 0);
    close(t);

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(u >= 0);
    flag(u, SOL_SOCKET, SO_BROADCAST, 0);
    flag(u, IPPROTO_IP, IP_PKTINFO, 0);
    flag(u, IPPROTO_IP, IP_RECVTTL, 0);
    FAILS(setsockopt(u, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v), ENOPROTOOPT);
    close(u);

    int six = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(six >= 0);
    int hops = get(six, IPPROTO_IPV6, IPV6_UNICAST_HOPS);
    CHECK(hops > 0);
    set(six, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 9);
    CHECK(get(six, IPPROTO_IPV6, IPV6_UNICAST_HOPS) == 9);
    set(six, IPPROTO_IPV6, IPV6_UNICAST_HOPS, -1);
    CHECK(get(six, IPPROTO_IPV6, IPV6_UNICAST_HOPS) == hops);
    v = 256;
    FAILS(setsockopt(six, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, sizeof v), EINVAL);
    CHECK(get(six, IPPROTO_IPV6, IPV6_TCLASS) == 0);
    set(six, IPPROTO_IPV6, IPV6_TCLASS, 8);
    CHECK(get(six, IPPROTO_IPV6, IPV6_TCLASS) == 8);
    close(six);
    printf("options ok\n");
}

static void info(const char *host, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s >= 0);
    struct tcp_info i;
    socklen_t len = sizeof i;
    CHECK(getsockopt(s, IPPROTO_TCP, TCP_INFO, &i, &len) == 0 && len > 0);
    CHECK(i.tcpi_state == 7); // TCP_CLOSE
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, host, &a.sin_addr) == 1);
    CHECK(connect(s, (void *)&a, sizeof a) == 0);
    set(s, IPPROTO_TCP, TCP_NODELAY, 1);
    CHECK(write(s, "ping", 4) == 4);
    char b[8];
    CHECK(read(s, b, sizeof b) == 4);
    len = sizeof i;
    memset(&i, 0xff, sizeof i);
    CHECK(getsockopt(s, IPPROTO_TCP, TCP_INFO, &i, &len) == 0 && len >= 104);
    CHECK(i.tcpi_state == 1); // TCP_ESTABLISHED
    CHECK(i.tcpi_snd_mss > 0 && i.tcpi_rcv_mss > 0);
    CHECK(i.tcpi_unacked == 0);
    // Cut short, as asked.
    len = 8;
    CHECK(getsockopt(s, IPPROTO_TCP, TCP_INFO, &i, &len) == 0 && len == 8);
    CHECK(get(s, IPPROTO_TCP, TCP_MAXSEG) > 0);
    close(s);
    printf("info ok\n");
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    options();
    if (argc > 2) info(argv[1], atoi(argv[2]));
    printf("sockopts ok\n");
    return 0;
}
