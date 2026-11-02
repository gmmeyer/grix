// Raw IP sockets, with the capability for them. Passes on Linux as root, or
// in grix on the vm stack.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdint.h>
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

#define PROTO 253 // for experiments, RFC 3692

static struct sockaddr_in loopback(int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

static int readable(int s) {
    struct pollfd p = {.fd = s, .events = POLLIN};
    return poll(&p, 1, 2000) == 1;
}

// As it arrives: the IP header, then what was sent.
static void received(int s, const char *want) {
    char b[128];
    struct sockaddr_in from;
    socklen_t len = sizeof from;
    CHECK(readable(s));
    ssize_t n = recvfrom(s, b, sizeof b, 0, (void *)&from, &len);
    size_t size = strlen(want);
    CHECK(n == (ssize_t)(20 + size));
    CHECK((b[0] >> 4) == 4 && (b[0] & 15) == 5 && (uint8_t)b[9] == PROTO);
    CHECK(!memcmp(b + 20, want, size));
    CHECK(from.sin_family == AF_INET && from.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
}

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    int r = socket(AF_INET, SOCK_RAW, PROTO), w = socket(AF_INET, SOCK_RAW, PROTO);
    CHECK(r >= 0 && w >= 0);
    int ty = 0, proto = 0;
    socklen_t len = sizeof ty;
    CHECK(getsockopt(r, SOL_SOCKET, SO_TYPE, &ty, &len) == 0 && ty == SOCK_RAW);
    CHECK(getsockopt(r, SOL_SOCKET, SO_PROTOCOL, &proto, &len) == 0 && proto == PROTO);
    struct sockaddr_in to = loopback(0);

    // What's sent comes with a header, to every socket of that protocol
    // (the sender too, as it's one).
    CHECK(sendto(w, "hello", 5, 0, (void *)&to, sizeof to) == 5);
    received(r, "hello");
    received(w, "hello");

    // Of another protocol, nothing comes.
    int other = socket(AF_INET, SOCK_RAW, 252);
    CHECK(other >= 0);
    CHECK(sendto(other, "no", 2, 0, (void *)&to, sizeof to) == 2);
    CHECK(sendto(w, "yes", 3, 0, (void *)&to, sizeof to) == 3);
    received(r, "yes");
    received(w, "yes");
    char b[64];
    struct sockaddr_in from;
    socklen_t flen = sizeof from;
    CHECK(recvfrom(other, b, sizeof b, 0, (void *)&from, &flen) == 22);

    // Connected, it needs no address, and hears from there alone.
    CHECK(connect(w, (void *)&to, sizeof to) == 0);
    CHECK(send(w, "conn", 4, 0) == 4);
    received(r, "conn");
    received(w, "conn");

    // Its own header, asked for: what's in it is what goes.
    int yes = 1, hdr = socket(AF_INET, SOCK_RAW, PROTO);
    CHECK(hdr >= 0 && setsockopt(hdr, IPPROTO_IP, IP_HDRINCL, &yes, sizeof yes) == 0);
    uint8_t p[24] = {0x45, 0, 0, 24, 0, 1, 0, 0, 64, PROTO, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1};
    memcpy(p + 20, "mine", 4);
    CHECK(sendto(hdr, p, sizeof p, 0, (void *)&to, sizeof to) == sizeof p);
    received(r, "mine");
    received(w, "mine");
    received(hdr, "mine");

    // Bound to an address, only what's sent there.
    int bound = socket(AF_INET, SOCK_RAW, PROTO);
    struct sockaddr_in at = to;
    at.sin_addr.s_addr = inet_addr("127.0.0.2");
    CHECK(bound >= 0 && bind(bound, (void *)&at, sizeof at) == 0);
    CHECK(sendto(r, "x", 1, 0, (void *)&to, sizeof to) == 1);
    received(r, "x");
    received(w, "x");
    received(hdr, "x");
    struct pollfd none = {.fd = bound, .events = POLLIN};
    CHECK(poll(&none, 1, 50) == 0);

    // A datagram is a UDP socket's, however it was made.
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in here = loopback(0);
    CHECK(u >= 0 && bind(u, (void *)&here, sizeof here) == 0);
    socklen_t l2 = sizeof here;
    CHECK(getsockname(u, (void *)&here, &l2) == 0);
    int rawudp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    CHECK(rawudp >= 0);
    uint16_t head[4] = {htons(40000), here.sin_port, htons(10), 0};
    char dgram[10];
    memcpy(dgram, head, 8);
    memcpy(dgram + 8, "hi", 2);
    struct sockaddr_in dest = loopback(0);
    CHECK(sendto(rawudp, dgram, sizeof dgram, 0, (void *)&dest, sizeof dest) == sizeof dgram);
    CHECK(readable(u) && read(u, b, sizeof b) == 2 && !memcmp(b, "hi", 2));
    printf("rawsock ok\n");
    return 0;
}
