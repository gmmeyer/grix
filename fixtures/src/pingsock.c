// ICMP echo, by ping socket and raw socket, with net_raw. It passes on Linux
// too, built with -DON_LINUX, for what the host there lets it do.
//   pingsock local          the machine's own addresses
//   pingsock host ADDR      a real answer from ADDR
//   pingsock refused ADDR   a destination the policy refuses
//   pingsock denied         without the capability
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);  \
            fflush(stdout);                                                   \
            _exit(1);                                                         \
        }                                                                     \
    } while (0)
#define FAILS(c, e) CHECK((long)(c) == -1 && errno == (e))
#define ID 0x1234
#define SEQ 7
static const char payload[] = "grix ping payload!";

static uint16_t sum16(const uint8_t *p, size_t n) {
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)p[i] << 8 | p[i + 1];
    if (n & 1) s += (uint32_t)p[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}

static size_t request(uint8_t *m, int v6) {
    memset(m, 0, 8);
    m[0] = v6 ? 128 : 8;
    m[4] = ID >> 8, m[5] = ID & 0xff;
    m[6] = SEQ >> 8, m[7] = SEQ & 0xff;
    memcpy(m + 8, payload, sizeof payload);
    size_t len = 8 + sizeof payload;
    // A raw socket's is the program's to fill in (the kernel does IPv6's).
    if (!v6) {
        uint16_t c = sum16(m, len);
        m[2] = c >> 8, m[3] = c & 0xff;
    }
    return len;
}

static socklen_t address(struct sockaddr_storage *st, const char *text) {
    memset(st, 0, sizeof *st);
    if (strchr(text, ':')) {
        struct sockaddr_in6 *a = (void *)st;
        a->sin6_family = AF_INET6;
        CHECK(inet_pton(AF_INET6, text, &a->sin6_addr) == 1);
        return sizeof *a;
    }
    struct sockaddr_in *a = (void *)st;
    a->sin_family = AF_INET;
    CHECK(inet_pton(AF_INET, text, &a->sin_addr) == 1);
    return sizeof *a;
}

static int open_icmp(int v6, int type) {
    int s = socket(v6 ? AF_INET6 : AF_INET, type, v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    CHECK(s >= 0);
    int got;
    socklen_t len = sizeof got;
    CHECK(getsockopt(s, SOL_SOCKET, SO_TYPE, &got, &len) == 0 && got == type);
    CHECK(getsockopt(s, SOL_SOCKET, SO_PROTOCOL, &got, &len) == 0 && got == (v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP));
    return s;
}

// What comes back is a reply to `request`, from `text`.
static void reply_from(int s, const char *text, int v6, int type) {
    uint8_t b[512];
    struct sockaddr_storage from;
    socklen_t flen = sizeof from;
    ssize_t n;
    uint8_t *m;
again:
    {
        struct pollfd pf = {.fd = s, .events = POLLIN};
        CHECK(poll(&pf, 1, 10000) == 1 && pf.revents & POLLIN);
    }
    flen = sizeof from;
    n = recvfrom(s, b, sizeof b, 0, (void *)&from, &flen);
    CHECK(n > 0);
    m = b;
    // A raw socket on Linux hears all of it, its own request on loopback too.
    if (type == SOCK_RAW && (v6 ? m[0] == 128 : n > 20 && m[20] == 8)) goto again;
    if (type == SOCK_RAW && !v6) {
        // As Linux hands it to a raw socket: its IP header first.
        CHECK(n >= 28 && b[0] == 0x45 && b[9] == IPPROTO_ICMP && sum16(b, 20) == 0);
        CHECK((b[2] << 8 | b[3]) == n);
        struct in_addr src;
        memcpy(&src, b + 12, 4);
        CHECK(!strcmp(inet_ntoa(src), text));
        m += 20;
        n -= 20;
    }
    CHECK((size_t)n == 8 + sizeof payload);
    CHECK(m[0] == (v6 ? 129 : 0) && m[1] == 0);
    // A ping socket's identifier is the socket's on Linux, and nothing to
    // go by; a raw one's is what the program sent.
    if (type == SOCK_RAW) CHECK((m[4] << 8 | m[5]) == ID);
    CHECK((m[6] << 8 | m[7]) == SEQ && !memcmp(m + 8, payload, sizeof payload));
    if (!v6) CHECK(sum16(m, n) == 0);
    if (v6) {
        struct sockaddr_in6 *a = (void *)&from;
        char shown[64];
        CHECK(inet_ntop(AF_INET6, &a->sin6_addr, shown, sizeof shown));
        CHECK(!strcmp(shown, text));
    } else {
        struct sockaddr_in *a = (void *)&from;
        CHECK(!strcmp(inet_ntoa(a->sin_addr), text));
    }
}

static void echo(const char *to, int type) {
    int v6 = strchr(to, ':') != 0;
    int s = open_icmp(v6, type);
    uint8_t m[128];
    size_t len = request(m, v6);
    struct sockaddr_storage st;
    socklen_t alen = address(&st, to);
    CHECK(sendto(s, m, len, 0, (void *)&st, alen) == (ssize_t)len);
    reply_from(s, to, v6, type);
    // Connected, it needs no address.
    CHECK(connect(s, (void *)&st, alen) == 0);
    CHECK(send(s, m, len, 0) == (ssize_t)len);
    reply_from(s, to, v6, type);
    close(s);
}

static void refusals(void) {
    int s = open_icmp(0, SOCK_DGRAM);
    uint8_t m[128];
    size_t len = request(m, 0);
    struct sockaddr_storage st;
    socklen_t alen = address(&st, "127.0.0.1");
    // Too short to be one, and not an echo request.
    FAILS(sendto(s, m, 4, 0, (void *)&st, alen), EINVAL);
    m[0] = 13;
    FAILS(sendto(s, m, len, 0, (void *)&st, alen), EINVAL);
    close(s);
#ifndef ON_LINUX
    // A raw socket may send anything on Linux. Here, only an echo request:
    // it's all the host would send.
    s = open_icmp(0, SOCK_RAW);
    FAILS(sendto(s, m, len, 0, (void *)&st, alen), EINVAL);
    close(s);
    // Raw IP of any other kind isn't here at all.
    FAILS(socket(AF_INET, SOCK_RAW, IPPROTO_UDP), EPROTONOSUPPORT);
#endif
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    CHECK(argc > 1);
    const char *c = argv[1];
    if (!strcmp(c, "denied")) {
        FAILS(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), EPERM);
        FAILS(socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP), EPERM);
        printf("pingsock denied ok\n");
        return 0;
    }
    if (!strcmp(c, "local")) {
        echo("127.0.0.1", SOCK_DGRAM);
        echo("127.0.0.1", SOCK_RAW);
        echo("::1", SOCK_DGRAM);
        echo("::1", SOCK_RAW);
#ifndef ON_LINUX
        // The guest's own address, and its nameserver.
        echo("10.0.2.15", SOCK_DGRAM);
        echo("10.0.2.3", SOCK_RAW);
#endif
        refusals();
        printf("pingsock local ok\n");
        return 0;
    }
    CHECK(argc > 2);
    if (!strcmp(c, "host")) {
        echo(argv[2], SOCK_DGRAM);
        echo(argv[2], SOCK_RAW);
        printf("pingsock host ok\n");
        return 0;
    }
    if (!strcmp(c, "refused")) {
        int s = open_icmp(0, SOCK_DGRAM);
        uint8_t m[128];
        size_t len = request(m, 0);
        struct sockaddr_storage st;
        socklen_t alen = address(&st, argv[2]);
        FAILS(sendto(s, m, len, 0, (void *)&st, alen), EPERM);
        printf("pingsock refused ok\n");
        return 0;
    }
    return 2;
}
