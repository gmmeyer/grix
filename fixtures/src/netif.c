// Network interface listing without the `net` capability: getifaddrs and
// if_nameindex (netlink), if_nametoindex (interface ioctls), raw netlink
// requests, refusals and garbage. The only interface is lo. With `net`
// (`netif eth0`), eth0 too, and the default route through the host.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
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

static char text[4096];

/// The whole of a (small) file, in `text`; its length, or -1.
static int slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = 0, r;
    while (n < (int)sizeof text - 1 && (r = read(fd, text + n, sizeof text - 1 - n)) > 0) n += r;
    close(fd);
    text[n] = 0;
    return n;
}

/// A dump of routes (RTM_GETROUTE, AF_INET) into `buf`: how many there are.
static int routes(char *buf, int size) {
    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct { struct nlmsghdr h; struct rtmsg r; } req = {
        .h = {.nlmsg_len = sizeof req, .nlmsg_type = RTM_GETROUTE, .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP},
        .r = {.rtm_family = AF_INET},
    };
    if (nl < 0 || send(nl, &req, sizeof req, 0) != sizeof req) return -1;
    int len = recv(nl, buf, size, 0), n = 0;
    close(nl);
    for (struct nlmsghdr *h = (void *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
        if (h->nlmsg_type == NLMSG_DONE) return n;
        if (h->nlmsg_type != RTM_NEWROUTE) return -1;
        n++;
    }
    return -1;
}

/// The attribute `type` of route message `h`, or NULL.
static void *route_attr(struct nlmsghdr *h, int type) {
    struct rtmsg *r = NLMSG_DATA(h);
    int len = RTM_PAYLOAD(h);
    for (struct rtattr *a = RTM_RTA(r); RTA_OK(a, len); a = RTA_NEXT(a, len))
        if (a->rta_type == type) return RTA_DATA(a);
    return NULL;
}

static const char route_header[] =
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT";

/// With `net`: eth0 everywhere lo is, and routes through the host.
static int eth0(void) {
    struct ifaddrs *ifa, *i;
    CHECK(getifaddrs(&ifa) == 0);
    int v4 = 0, link = 0, lo = 0;
    for (i = ifa; i; i = i->ifa_next) {
        if (!strcmp(i->ifa_name, "lo")) {
            lo++;
            continue;
        }
        CHECK(!strcmp(i->ifa_name, "eth0"));
        CHECK(i->ifa_flags & IFF_UP && i->ifa_flags & IFF_RUNNING && i->ifa_flags & IFF_BROADCAST);
        CHECK(!(i->ifa_flags & IFF_LOOPBACK));
        if (i->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *a = (void *)i->ifa_addr, *m = (void *)i->ifa_netmask, *b = (void *)i->ifa_broadaddr;
            CHECK(a->sin_addr.s_addr == inet_addr("10.0.2.15") && m->sin_addr.s_addr == inet_addr("255.255.255.0"));
            CHECK(b && b->sin_addr.s_addr == inet_addr("10.0.2.255"));
            v4++;
        } else if (i->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *l = (void *)i->ifa_addr;
            CHECK(l->sll_halen == 6 && !memcmp(l->sll_addr, "\x52\x54\x00\x12\x34\x56", 6));
            link++;
        } else {
            CHECK(0); // no IPv6 address
        }
    }
    freeifaddrs(ifa);
    CHECK(v4 == 1 && link == 1 && lo == 3);
    struct if_nameindex *ni = if_nameindex();
    CHECK(ni && ni[1].if_index == 2 && !strcmp(ni[1].if_name, "eth0") && ni[2].if_index == 0);
    if_freenameindex(ni);
    CHECK(if_nametoindex("eth0") == 2);
    char name[IF_NAMESIZE];
    CHECK(if_indextoname(2, name) && !strcmp(name, "eth0"));

    // The interface ioctls (busybox ifconfig, older programs).
    int u = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(u >= 0);
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "eth0");
    struct sockaddr_in *sin = (void *)&ifr.ifr_addr;
    CHECK(ioctl(u, SIOCGIFADDR, &ifr) == 0 && sin->sin_addr.s_addr == inet_addr("10.0.2.15"));
    CHECK(ioctl(u, SIOCGIFNETMASK, &ifr) == 0 && sin->sin_addr.s_addr == inet_addr("255.255.255.0"));
    CHECK(ioctl(u, SIOCGIFBRDADDR, &ifr) == 0 && sin->sin_addr.s_addr == inet_addr("10.0.2.255"));
    CHECK(ioctl(u, SIOCGIFFLAGS, &ifr) == 0 && ifr.ifr_flags & IFF_UP && !(ifr.ifr_flags & IFF_LOOPBACK));
    CHECK(ioctl(u, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu == 1500);
    CHECK(ioctl(u, SIOCGIFHWADDR, &ifr) == 0 && ifr.ifr_hwaddr.sa_family == 1);
    CHECK(!memcmp(ifr.ifr_hwaddr.sa_data, "\x52\x54\x00\x12\x34\x56", 6));
    CHECK(ioctl(u, SIOCSIFADDR, &ifr) == -1 && errno == EPERM);
    struct ifreq all[4];
    struct ifconf ifc = {.ifc_len = sizeof all, .ifc_req = all};
    CHECK(ioctl(u, SIOCGIFCONF, &ifc) == 0 && ifc.ifc_len == 2 * sizeof(struct ifreq));
    CHECK(!strcmp(all[0].ifr_name, "lo") && !strcmp(all[1].ifr_name, "eth0"));
    ifc.ifc_len = sizeof(struct ifreq);
    CHECK(ioctl(u, SIOCGIFCONF, &ifc) == 0 && ifc.ifc_len == sizeof(struct ifreq));
    close(u);

    // Routes: eth0's network, and the default one through the host
    // (netlink, as `ip route` asks, and /proc/net/route).
    static char buf[8192];
    CHECK(routes(buf, sizeof buf) == 2);
    struct nlmsghdr *h = (void *)buf;
    struct rtmsg *r = NLMSG_DATA(h);
    CHECK(r->rtm_dst_len == 0 && r->rtm_table == RT_TABLE_MAIN);
    CHECK(*(in_addr_t *)route_attr(h, RTA_GATEWAY) == inet_addr("10.0.2.2") && *(int *)route_attr(h, RTA_OIF) == 2);
    h = NLMSG_NEXT(h, (int){sizeof buf});
    r = NLMSG_DATA(h);
    CHECK(r->rtm_dst_len == 24 && r->rtm_scope == RT_SCOPE_LINK && !route_attr(h, RTA_GATEWAY));
    CHECK(*(in_addr_t *)route_attr(h, RTA_DST) == inet_addr("10.0.2.0"));
    CHECK(*(in_addr_t *)route_attr(h, RTA_PREFSRC) == inet_addr("10.0.2.15"));
    CHECK(slurp("/proc/net/route") == 3 * 128 && !strncmp(text, route_header, strlen(route_header)));
    CHECK(!strncmp(text + 128, "eth0\t00000000\t0202000A\t0003\t0\t0\t0\t00000000\t0\t0\t0 ", 49));
    CHECK(!strncmp(text + 256, "eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0 ", 49));
    CHECK(slurp("/proc/net/dev") > 0 && strstr(text, "\n    lo:       0") && strstr(text, "\n  eth0:       0"));
    CHECK(slurp("/sys/class/net/eth0/address") > 0 && !strcmp(text, "52:54:00:12:34:56\n"));
    CHECK(slurp("/sys/class/net/eth0/operstate") > 0 && !strcmp(text, "up\n"));
    CHECK(slurp("/sys/class/net/eth0/ifindex") > 0 && !strcmp(text, "2\n"));
    printf("netif eth0 ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "eth0")) return eth0();
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
    // Looking a link up by name: lo exists, eth0 doesn't.
    struct { struct nlmsghdr h; struct ifinfomsg i; struct rtattr a; char name[8]; } byname = {
        .h = {.nlmsg_len = sizeof byname, .nlmsg_type = RTM_GETLINK, .nlmsg_flags = NLM_F_REQUEST, .nlmsg_seq = 9},
        .a = {.rta_len = RTA_LENGTH(5), .rta_type = IFLA_IFNAME},
        .name = "eth0",
    };
    CHECK(send(nl, &byname, sizeof byname, 0) == sizeof byname && recv(nl, buf, sizeof buf, 0) > 0);
    h = (void *)buf;
    CHECK(h->nlmsg_type == NLMSG_ERROR && ((struct nlmsgerr *)NLMSG_DATA(h))->error == -ENODEV);
    strcpy(byname.name, "lo");
    byname.a.rta_len = RTA_LENGTH(3);
    CHECK(send(nl, &byname, sizeof byname, 0) == sizeof byname && recv(nl, buf, sizeof buf, 0) > 0);
    CHECK(h->nlmsg_type == RTM_NEWLINK && ((struct ifinfomsg *)NLMSG_DATA(h))->ifi_index == 1);
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

    // No routes and no eth0 anywhere else either.
    CHECK(routes(buf, sizeof buf) == 0);
    CHECK(slurp("/proc/net/route") == 128 && !strncmp(text, route_header, strlen(route_header)));
    CHECK(slurp("/proc/net/dev") > 0 && strstr(text, "    lo:") && !strstr(text, "eth0"));
    CHECK(access("/sys/class/net/eth0", F_OK) == -1 && access("/sys/class/net/lo", F_OK) == 0);

    // Network sockets still need `net`.
    CHECK(socket(AF_INET, SOCK_DGRAM, 0) == -1 && errno == EPERM);
    printf("netif ok\n");
    return 0;
}
