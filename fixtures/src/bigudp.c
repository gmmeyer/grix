// Datagrams as big as IP carries, whatever the link's frames hold, and path
// MTU's options. Passes on Linux as it is. With "host PORT" it goes through a
// UDP echo server at 10.0.2.2, or at the address in the third argument, and
// asks about the path to the fourth (Linux's way to its own address is lo).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(c)                                                                   \
    do {                                                                           \
        if (!(c)) {                                                                \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);       \
            exit(1);                                                               \
        }                                                                          \
    } while (0)
#define FAILS(call, e) CHECK((long)(call) == -1 && errno == (e))

#define MAX_V4 65507
#define MAX_V6 65527

static unsigned char out[70000], in[70000];

static void pattern(size_t n, unsigned seed) {
    for (size_t i = 0; i < n; i++) out[i] = (unsigned char)(i * 31 + (i >> 8) + seed);
}

static void readable(int s, int ms) {
    struct pollfd p = {.fd = s, .events = POLLIN};
    CHECK(poll(&p, 1, ms) == 1);
}

static void loopback4(void) {
    int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(a >= 0 && b >= 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(b, (struct sockaddr *)&to, sizeof to) == 0);
    socklen_t len = sizeof to;
    CHECK(getsockname(b, (struct sockaddr *)&to, &len) == 0);

    size_t sizes[] = {1, 1472, 1473, 4092, 8192, 40000, MAX_V4};
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        pattern(sizes[i], i);
        CHECK(sendto(a, out, sizes[i], 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)sizes[i]);
        readable(b, 2000);
        CHECK(recv(b, in, sizeof in, 0) == (ssize_t)sizes[i]);
        CHECK(!memcmp(in, out, sizes[i]));
    }
    FAILS(sendto(a, out, MAX_V4 + 1, 0, (struct sockaddr *)&to, sizeof to), EMSGSIZE);

    // Too small a buffer: the rest of it's gone, and MSG_TRUNC says how much
    // there was.
    pattern(MAX_V4, 9);
    CHECK(sendto(a, out, MAX_V4, 0, (struct sockaddr *)&to, sizeof to) == MAX_V4);
    readable(b, 2000);
    CHECK(recv(b, in, 100, MSG_TRUNC) == MAX_V4);
    CHECK(!memcmp(in, out, 100));

    // The size of what's next, without reading it, and without a buffer.
    CHECK(sendto(a, out, 5000, 0, (struct sockaddr *)&to, sizeof to) == 5000);
    readable(b, 2000);
    CHECK(recv(b, NULL, 0, MSG_PEEK | MSG_TRUNC) == 5000);

    // One datagram across all a read's buffers.
    static unsigned char first[3000], second[3000];
    struct iovec iov[2] = {{first, sizeof first}, {second, sizeof second}};
    struct msghdr m = {.msg_iov = iov, .msg_iovlen = 2};
    CHECK(recvmsg(b, &m, 0) == 5000);
    CHECK(m.msg_flags == 0);
    CHECK(!memcmp(first, out, 3000) && !memcmp(second, out + 3000, 2000));
    CHECK(sendto(a, out, 5000, 0, (struct sockaddr *)&to, sizeof to) == 5000);
    readable(b, 2000);
    memset(second, 0, sizeof second);
    CHECK(readv(b, iov, 2) == 5000);
    CHECK(!memcmp(second, out + 3000, 2000));
    // And one writev is one datagram, however many buffers.
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(c >= 0);
    CHECK(connect(c, (struct sockaddr *)&to, sizeof to) == 0);
    struct iovec two[2] = {{out, 100}, {out + 100, 200}};
    CHECK(writev(c, two, 2) == 300);
    readable(b, 2000);
    CHECK(recv(b, in, sizeof in, 0) == 300);
    close(c);
    // Too much for them: what fits, and it's said the rest went.
    CHECK(sendto(a, out, 7000, 0, (struct sockaddr *)&to, sizeof to) == 7000);
    readable(b, 2000);
    memset(&m, 0, sizeof m);
    m.msg_iov = iov, m.msg_iovlen = 2;
    CHECK(recvmsg(b, &m, 0) == 6000);
    CHECK(m.msg_flags == MSG_TRUNC);
    // What's left is nothing: the next read has the next datagram.
    CHECK(sendto(a, "z", 1, 0, (struct sockaddr *)&to, sizeof to) == 1);
    readable(b, 2000);
    CHECK(recv(b, in, sizeof in, 0) == 1 && in[0] == 'z');

    // A connected socket's MTU is loopback's, and a socket that isn't
    // connected has none.
    int mtu;
    socklen_t mlen = sizeof mtu;
    FAILS(getsockopt(a, IPPROTO_IP, IP_MTU, &mtu, &mlen), ENOTCONN);
    CHECK(connect(a, (struct sockaddr *)&to, sizeof to) == 0);
    mlen = sizeof mtu;
    CHECK(getsockopt(a, IPPROTO_IP, IP_MTU, &mtu, &mlen) == 0);
    // (IPv4's path MTU stops at IP_MAX_MTU, whatever the device says.)
    CHECK(mtu == 65535);
    // Not to be fragmented: and it needn't be, on loopback.
    int v = IP_PMTUDISC_DO;
    CHECK(setsockopt(a, IPPROTO_IP, IP_MTU_DISCOVER, &v, sizeof v) == 0);
    CHECK(send(a, out, mtu - 28, 0) == mtu - 28);
    readable(b, 2000);
    CHECK(recv(b, in, sizeof in, 0) == mtu - 28);
    close(a), close(b);
}

static void loopback6(void) {
    int a = socket(AF_INET6, SOCK_DGRAM, 0), b = socket(AF_INET6, SOCK_DGRAM, 0);
    CHECK(a >= 0 && b >= 0);
    struct sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    CHECK(bind(b, (struct sockaddr *)&to, sizeof to) == 0);
    socklen_t len = sizeof to;
    CHECK(getsockname(b, (struct sockaddr *)&to, &len) == 0);
    pattern(MAX_V6, 3);
    CHECK(sendto(a, out, MAX_V6, 0, (struct sockaddr *)&to, sizeof to) == MAX_V6);
    readable(b, 2000);
    CHECK(recv(b, in, sizeof in, 0) == MAX_V6);
    CHECK(!memcmp(in, out, MAX_V6));
    FAILS(sendto(a, out, MAX_V6 + 1, 0, (struct sockaddr *)&to, sizeof to), EMSGSIZE);
    int mtu;
    socklen_t mlen = sizeof mtu;
    FAILS(getsockopt(a, IPPROTO_IPV6, IPV6_MTU, &mtu, &mlen), ENOTCONN);
    CHECK(connect(a, (struct sockaddr *)&to, sizeof to) == 0);
    mlen = sizeof mtu;
    CHECK(getsockopt(a, IPPROTO_IPV6, IPV6_MTU, &mtu, &mlen) == 0);
    CHECK(mtu == 65536);
    close(a), close(b);
}

// What eth0 says of itself, each way a program asks.
static int eth0_mtu(int s) {
    struct ifreq r;
    memset(&r, 0, sizeof r);
    strcpy(r.ifr_name, "eth0");
    CHECK(ioctl(s, SIOCGIFMTU, &r) == 0);
    FILE *f = fopen("/sys/class/net/eth0/mtu", "r");
    CHECK(f != NULL);
    int mtu;
    CHECK(fscanf(f, "%d", &mtu) == 1);
    fclose(f);
    CHECK(mtu == r.ifr_mtu);
    return mtu;
}

static void through(const char *host, int port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s >= 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, host, &to.sin_addr) == 1);
    CHECK(connect(s, (struct sockaddr *)&to, sizeof to) == 0);

    size_t sizes[] = {1, 1472, 1473, 4064, 4065, 4092, 8192, 40000, MAX_V4};
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        pattern(sizes[i], i);
        ssize_t got = -1;
        // UDP: it may take more than one try.
        for (int tries = 0; tries < 5 && got != (ssize_t)sizes[i]; tries++) {
            CHECK(send(s, out, sizes[i], 0) == (ssize_t)sizes[i]);
            struct pollfd p = {.fd = s, .events = POLLIN};
            if (poll(&p, 1, 1000) == 1) got = recv(s, in, sizeof in, 0);
        }
        CHECK(got == (ssize_t)sizes[i]);
        CHECK(!memcmp(in, out, sizes[i]));
    }

    close(s);
}

// A socket that won't have a datagram fragmented: the most that fits goes,
// and a byte more doesn't.
static void path(const char *host) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s >= 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(9)};
    CHECK(inet_pton(AF_INET, host, &to.sin_addr) == 1);
    CHECK(connect(s, (struct sockaddr *)&to, sizeof to) == 0);
    int link = eth0_mtu(s), mtu;
    socklen_t len = sizeof mtu;
    CHECK(getsockopt(s, IPPROTO_IP, IP_MTU, &mtu, &len) == 0);
    CHECK(mtu == link);
    int v = IP_PMTUDISC_DO;
    CHECK(setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &v, sizeof v) == 0);
    CHECK(send(s, out, mtu - 28, 0) == mtu - 28);
    FAILS(send(s, out, mtu - 27, 0), EMSGSIZE);
    close(s);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && strcmp(argv[1], "mtu") == 0) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(s >= 0);
        printf("eth0 mtu %d\n", eth0_mtu(s));
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "host") == 0) {
        through(argc > 3 ? argv[3] : "10.0.2.2", atoi(argv[2]));
        path(argc > 4 ? argv[4] : "10.0.2.2");
    } else {
        loopback4();
        loopback6();
    }
    printf("bigudp ok\n");
    return 0;
}
