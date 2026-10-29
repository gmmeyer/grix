// Attempts to reach the network with no `net` capability: every socket
// family, the resolver, netlink's view of the interfaces, and the paths
// that stay local. Each must fail with a clean errno (a denial, or
// unimplemented) or stay entirely in the sandbox — nothing egresses.
// Portable: the network code isn't architecture-specific.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what, const char *detail) {
    if (!ok) {
        printf("FAILED: %s (%s)\n", what, detail);
        fails++;
    }
}

// Linux netlink constants (linux/netlink.h, linux/rtnetlink.h): a route
// socket's protocol, the link dump request, and the reply messages.
#define NETLINK_ROUTE 0
#define NLMSG_DONE 3
#define RTM_NEWLINK 16
#define RTM_GETLINK 18
#define NLM_F_REQUEST 1
#define NLM_F_DUMP 0x300
#define IFLA_IFNAME 3

#define NLMSG_ALIGN(len) (((len) + 3) & ~3)

// struct nlmsghdr: the flags and type are u16s (16 bytes, not 20).
struct nlmsghdr_ {
    unsigned int len;
    unsigned short type, flags;
    unsigned int seq, pid;
};

// The interfaces a route socket shows: only ever `lo` (what the host gave
// the guest). Prints each name; the caller checks they were all `lo`.
static void dump_links(void) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(s >= 0, "netlink route socket", strerror(errno));
    if (s < 0) return;
    struct {
        struct nlmsghdr_ h;
        unsigned char ifi[16]; // struct ifinfomsg
    } req;
    memset(&req, 0, sizeof req);
    req.h.len = sizeof req;
    req.h.type = RTM_GETLINK;
    req.h.flags = NLM_F_REQUEST | NLM_F_DUMP;
    check(send(s, &req, sizeof req, 0) == (int)sizeof req, "netlink dump request", strerror(errno));

    // Read the dump until its DONE, collecting interface names.
    char names[512] = {0};
    int seen = 0, done = 0;
    for (int reads = 0; reads < 16 && !done; reads++) {
        char buf[4096];
        ssize_t n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (size_t off = 0; off + sizeof(struct nlmsghdr_) <= (size_t)n; off = NLMSG_ALIGN(off + ((struct nlmsghdr_ *)(buf + off))->len)) {
            struct nlmsghdr_ *h = (struct nlmsghdr_ *)(buf + off);
            if (h->len < sizeof *h || off + h->len > (size_t)n) break;
            if (h->type == NLMSG_DONE) {
                done = 1;
                break;
            }
            if (h->type != RTM_NEWLINK) continue;
            // ifinfomsg (16 bytes), then the attributes (struct rtattr:
            // u16 len, u16 type, then the value).
            size_t a = off + sizeof *h + 16;
            for (; a + 4 <= off + h->len;) {
                unsigned short alen, atype;
                memcpy(&alen, buf + a, 2);
                memcpy(&atype, buf + a + 2, 2);
                if (alen < 4 || a + alen > off + h->len) break;
                if (atype == IFLA_IFNAME && alen >= 5) {
                    size_t vlen = alen - 4;
                    if (vlen > 127) vlen = 127;
                    // The value is NUL-terminated in the attribute.
                    seen++;
                    if (names[0]) strncat(names, ",", sizeof names - strlen(names) - 1);
                    strncat(names, buf + a + 4, vlen);
                    names[sizeof names - 1] = 0;
                }
                a = NLMSG_ALIGN(a + alen);
            }
        }
    }
    close(s);
    printf("netlink interfaces: %s\n", names);
    check(done, "netlink dump ends", "no DONE");
    check(seen == 1 && strcmp(names, "lo") == 0, "netlink shows only lo", names);
}

int main(int argc, char **argv) {
    const char *what = argc > 1 ? argv[1] : "without";
    if (strcmp(what, "without") != 0 && strcmp(what, "netlink") != 0) {
        printf("usage: netescape without|netlink\n");
        return 1;
    }

    if (strcmp(what, "netlink") == 0) {
        dump_links();
        printf("netescape %s %s\n", what, fails ? "FAILED" : "ok");
        return fails ? 1 : 0;
    }

    // The families that would egress: each denied (net) or unimplemented.
    check(socket(AF_INET, SOCK_STREAM, 0) == -1 && errno == EPERM, "socket AF_INET stream", strerror(errno));
    check(socket(AF_INET, SOCK_DGRAM, 0) == -1 && errno == EPERM, "socket AF_INET dgram", strerror(errno));
    check(socket(AF_INET6, SOCK_STREAM, 0) == -1 && errno == EPERM, "socket AF_INET6 stream", strerror(errno));
    check(socket(AF_INET6, SOCK_DGRAM, 0) == -1 && errno == EPERM, "socket AF_INET6 dgram", strerror(errno));
    check(socket(AF_INET, SOCK_RAW, IPPROTO_RAW) == -1 && errno == EPERM, "socket AF_INET raw", strerror(errno));
    check(socket(AF_PACKET, SOCK_RAW, 0) == -1, "socket AF_PACKET raw", strerror(errno));
    check(socket(AF_AX25, SOCK_STREAM, 0) == -1, "socket AF_AX25", strerror(errno));
    check(socket(AF_APPLETALK, SOCK_STREAM, 0) == -1, "socket AF_APPLETALK", strerror(errno));

    // A network socket pair isn't a thing either.
    int sv[2];
    check(socketpair(AF_INET, SOCK_STREAM, 0, sv) == -1, "socketpair AF_INET", strerror(errno));
    // Local IPC is: not gated by net.
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair AF_UNIX", strerror(errno));
    if (sv[0] >= 0) {
        check(write(sv[0], "x", 1) == 1, "socketpair write", strerror(errno));
        char c;
        check(read(sv[1], &c, 1) == 1 && c == 'x', "socketpair read", strerror(errno));
        close(sv[0]);
        close(sv[1]);
    }

    // A Unix socket by name: the sandbox's own filesystem (nothing of the
    // host's is in it), so no path reaches a host service.
    int u = socket(AF_UNIX, SOCK_STREAM, 0);
    check(u >= 0, "socket AF_UNIX", strerror(errno));
    if (u >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof addr);
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/var/run/echo.sock", sizeof addr.sun_path - 1);
        check(connect(u, (struct sockaddr *)&addr, sizeof addr) == -1 && errno == ENOENT, "connect unix path",
              strerror(errno));
        close(u);
    }

    // The resolver: a name in the synthetic hosts file resolves (no socket
    // needed); anything else would have to ask the host, which needs net.
    // (The answer list has the v4 and the v6 address; look for either.)
    struct addrinfo *ai;
    int r = getaddrinfo("localhost", NULL, NULL, &ai);
    char v4[INET_ADDRSTRLEN] = {0}, v6[INET6_ADDRSTRLEN] = {0};
    for (struct addrinfo *a = r == 0 ? ai : NULL; a; a = a->ai_next) {
        char name[INET6_ADDRSTRLEN] = {0};
        getnameinfo(a->ai_addr, a->ai_addrlen, name, sizeof name, NULL, 0, NI_NUMERICHOST);
        if (a->ai_family == AF_INET && !v4[0]) strncpy(v4, name, sizeof v4 - 1);
        if (a->ai_family == AF_INET6 && !v6[0]) strncpy(v6, name, sizeof v6 - 1);
    }
    check(r == 0 && v4[0], "getaddrinfo localhost", r ? gai_strerror(r) : "no address");
    if (r == 0) freeaddrinfo(ai);
    if (v4[0]) {
        printf("localhost is %s%s%s\n", v4, v6[0] ? " " : "", v6);
        check(strcmp(v4, "127.0.0.1") == 0, "localhost is 127.0.0.1", v4);
    }
    r = getaddrinfo("example.com", NULL, NULL, &ai);
    check(r != 0, "getaddrinfo example.com (no net)", r == 0 ? "resolved!" : gai_strerror(r));
    if (r == 0 && ai) freeaddrinfo(ai);

    // Netlink: what it shows of the world, and that the old interface
    // ioctls on a Unix socket only ever answer for `lo`.
    dump_links();
    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nl >= 0) {
        // SIOCGIFCONF (0x8912): the one interface ioctl with host state in
        // it — not one grix answers.
        char buf[4096];
        check(ioctl(nl, 0x8912, buf) == -1, "ioctl SIOCGIFCONF", strerror(errno));
        // SIOCGIFHWADDR (0x8927) for `lo`: synthetic, like everything else.
        struct {
            char name[16];
            unsigned char hw[24];
        } ifr;
        memset(&ifr, 0, sizeof ifr);
        strcpy(ifr.name, "lo");
        check(ioctl(nl, 0x8927, &ifr) == 0, "ioctl SIOCGIFHWADDR lo", strerror(errno));
        close(nl);
    }

    printf("netescape %s %s\n", what, fails ? "FAILED" : "ok");
    return fails ? 1 : 0;
}