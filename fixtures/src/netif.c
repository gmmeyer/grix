// Network interface listing without the `net` capability: getifaddrs and
// if_nameindex (netlink), if_nametoindex (interface ioctls), raw netlink
// requests, refusals and garbage. The only interface is lo.
#define _GNU_SOURCE
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

int main(void) {
    // getifaddrs: lo as a link, an IPv4 address and an IPv6 address.
    struct ifaddrs *ifa, *i;
    CHECK(getifaddrs(&ifa) == 0);
    int v4 = 0, v6 = 0, link = 0, other = 0;
    for (i = ifa; i; i = i->ifa_next) {
        if (strcmp(i->ifa_name, "lo")) other++;
        CHECK(i->ifa_flags & IFF_LOOPBACK && i->ifa_flags & IFF_UP);
        if (!i->ifa_addr) continue;
        if (i->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *a = (void *)i->ifa_addr, *m = (void *)i->ifa_netmask;
            CHECK(a->sin_addr.s_addr == htonl(INADDR_LOOPBACK) && m->sin_addr.s_addr == htonl(0xff000000));
            v4++;
        } else if (i->ifa_addr->sa_family == AF_INET6) {
            CHECK(!memcmp(&((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr, &in6addr_loopback, 16));
            v6++;
        } else if (i->ifa_addr->sa_family == AF_PACKET) {
            link++;
        }
    }
    freeifaddrs(ifa);
    CHECK(v4 == 1 && v6 == 1 && link == 1 && other == 0);

    // Names and indexes.
    struct if_nameindex *ni = if_nameindex();
    CHECK(ni && ni[0].if_index == 1 && !strcmp(ni[0].if_name, "lo") && ni[1].if_index == 0);
    if_freenameindex(ni);
    CHECK(if_nametoindex("lo") == 1);
    CHECK(if_nametoindex("eth0") == 0 && errno == ENODEV);
    char name[IF_NAMESIZE];
    CHECK(if_indextoname(1, name) && !strcmp(name, "lo"));
    int u = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo");
    CHECK(ioctl(u, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu == 65536);
    CHECK(ioctl(u, SIOCSIFMTU, &ifr) == -1 && errno == EPERM);
    int type;
    socklen_t len = sizeof type;
    CHECK(getsockopt(u, SOL_SOCKET, SO_TYPE, &type, &len) == 0 && type == SOCK_DGRAM);
    close(u);

    // Raw netlink: a dump comes back as one datagram; peeking with
    // MSG_TRUNC reports its full length.
    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    CHECK(nl >= 0);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    CHECK(bind(nl, (void *)&sa, sizeof sa) == 0);
    len = sizeof sa;
    CHECK(getsockname(nl, (void *)&sa, &len) == 0 && sa.nl_family == AF_NETLINK && sa.nl_pid != 0);
    struct { struct nlmsghdr h; struct rtgenmsg g; } req = {
        .h = {.nlmsg_len = sizeof req, .nlmsg_type = RTM_GETADDR, .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP, .nlmsg_seq = 7},
        .g = {.rtgen_family = AF_INET},
    };
    CHECK(send(nl, &req, sizeof req, 0) == sizeof req);
    char buf[8192];
    int full = recv(nl, buf, 4, MSG_PEEK | MSG_TRUNC);
    CHECK(full > 4);
    CHECK(recv(nl, buf, sizeof buf, 0) == full);
    struct nlmsghdr *h = (void *)buf;
    CHECK(h->nlmsg_type == RTM_NEWADDR && h->nlmsg_seq == 7);
    h = NLMSG_NEXT(h, full);
    CHECK(NLMSG_OK(h, full) && h->nlmsg_type == NLMSG_DONE);
    // Changing an address is refused like it is for any unprivileged user.
    req.h.nlmsg_type = RTM_NEWADDR;
    req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    CHECK(send(nl, &req, sizeof req, 0) == sizeof req);
    CHECK(recv(nl, buf, sizeof buf, 0) > 0);
    h = (void *)buf;
    CHECK(h->nlmsg_type == NLMSG_ERROR && ((struct nlmsgerr *)NLMSG_DATA(h))->error == -EPERM);
    // Garbage gets no answer.
    memset(buf, 0xff, 64);
    CHECK(send(nl, buf, 64, 0) == 64 && send(nl, buf, 3, 0) == 3);
    CHECK(recv(nl, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    // A flood of requests that are never read runs out of buffer space
    // (ENOBUFS), not kernel memory.
    static char flood[65536];
    for (int i = 0; i + 20 <= (int)sizeof flood; i += 20) {
        struct nlmsghdr *f = (void *)(flood + i);
        *f = (struct nlmsghdr){.nlmsg_len = 20, .nlmsg_type = RTM_GETADDR, .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP};
    }
    int sends = 0;
    while (send(nl, flood, sizeof flood, 0) > 0 && sends < 1000) sends++;
    CHECK(errno == ENOBUFS && sends < 1000);
    close(nl);

    // Network sockets still need `net`.
    CHECK(socket(AF_INET, SOCK_DGRAM, 0) == -1 && errno == EPERM);
    printf("netif ok\n");
    return 0;
}
