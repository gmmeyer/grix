// UDP beyond DNS.
//   udp local        between two of the guest's own sockets (no host)
//   udp echo PORT    to an echo server on the host (host.grix.internal:PORT)
//   udp denied PORT  to a port the policy doesn't allow: EPERM
//   udp serve PORT   an echo server on PORT, forwarded from the host: echoes
//                    each datagram to its sender (seen as 10.0.2.2, the
//                    host's loopback) until "quit"; a send to a peer that
//                    never sent gets EPERM
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

static struct sockaddr_in at(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static void local(void) {
    int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in aa = at("127.0.0.1", 5353), got;
    socklen_t len = sizeof got;
    CHECK(bind(a, (void *)&aa, sizeof aa) == 0);
    int again = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(bind(again, (void *)&aa, sizeof aa) == -1 && errno == EADDRINUSE);
    // Still unbound: another port will do.
    struct sockaddr_in other = at("127.0.0.1", 5354);
    CHECK(bind(again, (void *)&other, sizeof other) == 0);
    CHECK(sendto(b, "one", 3, 0, (void *)&aa, sizeof aa) == 3 && sendto(b, "two!", 4, 0, (void *)&aa, sizeof aa) == 4);
    struct sockaddr_in bb;
    socklen_t blen = sizeof bb;
    CHECK(getsockname(b, (void *)&bb, &blen) == 0 && bb.sin_port != 0);
    char buf[16];
    CHECK(recvfrom(a, buf, sizeof buf, 0, (void *)&got, &len) == 3 && got.sin_port == bb.sin_port);
    CHECK(got.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    CHECK(recv(a, buf, sizeof buf, 0) == 4 && memcmp(buf, "two!", 4) == 0);
    // Replies, and a connected socket takes only its peer's.
    CHECK(sendto(a, "back", 4, 0, (void *)&got, len) == 4 && recv(b, buf, sizeof buf, 0) == 4);
    CHECK(connect(b, (void *)&aa, sizeof aa) == 0 && send(b, "c", 1, 0) == 1 && recv(a, buf, sizeof buf, 0) == 1);
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(sendto(c, "x", 1, 0, (void *)&bb, sizeof bb) == 1);
    CHECK(recv(b, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    struct pollfd pf = {a, POLLIN, 0};
    CHECK(poll(&pf, 1, 0) == 0);
    printf("udp local ok\n");
}

static void echo(int port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = at("10.0.2.2", port), got;
    socklen_t len = sizeof got;
    for (int i = 0; i < 3; i++) {
        char msg[16], buf[32];
        int n = snprintf(msg, sizeof msg, "ping %d", i);
        CHECK(sendto(s, msg, n, 0, (void *)&to, sizeof to) == n);
        CHECK(recvfrom(s, buf, sizeof buf, 0, (void *)&got, &len) == n && memcmp(buf, msg, n) == 0);
        CHECK(got.sin_port == htons(port) && got.sin_addr.s_addr == to.sin_addr.s_addr);
    }
    printf("udp echo ok\n");
}

static void denied(int port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = at("10.0.2.2", port);
    CHECK(sendto(s, "no", 2, 0, (void *)&to, sizeof to) == -1 && errno == EPERM);
    CHECK(sendto(s, "no", 2, 0, (void *)&to, sizeof to) == -1 && errno == EPERM);
    printf("udp denied ok\n");
}

static void serve(int port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in any = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(bind(s, (void *)&any, sizeof any) == 0);
    struct sockaddr_in host = at("10.0.2.2", 0);
    for (int first = 1;; first = 0) {
        char buf[8192], reply[8200];
        struct sockaddr_in from;
        socklen_t len = sizeof from;
        ssize_t n = recvfrom(s, buf, sizeof buf, 0, (void *)&from, &len);
        CHECK(n >= 0 && from.sin_addr.s_addr == host.sin_addr.s_addr && from.sin_port != 0);
        if (first) {
            // Nobody at the next port sent here: no way out through the
            // forward, and the policy doesn't allow the host itself.
            struct sockaddr_in stranger = from;
            stranger.sin_port = htons(ntohs(from.sin_port) ^ 1);
            CHECK(sendto(s, "no", 2, 0, (void *)&stranger, sizeof stranger) == -1 && errno == EPERM);
        }
        int m = snprintf(reply, sizeof reply, "echo %zd: %.*s", n, (int)n, buf);
        CHECK(sendto(s, reply, m, 0, (void *)&from, len) == m);
        if (n == 4 && memcmp(buf, "quit", 4) == 0) break;
    }
    printf("udp serve ok\n");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "local") == 0) local();
    else if (argc > 2 && strcmp(argv[1], "echo") == 0) echo(atoi(argv[2]));
    else if (argc > 2 && strcmp(argv[1], "denied") == 0) denied(atoi(argv[2]));
    else if (argc > 2 && strcmp(argv[1], "serve") == 0) serve(atoi(argv[2]));
    else return 2;
    return 0;
}
