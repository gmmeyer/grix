// Network interface listing without the `net` capability: getifaddrs and
// if_nameindex (netlink), if_nametoindex (interface ioctls), raw netlink
// requests, refusals and garbage. The only interface is lo. With `net`
// (`netif eth0`), eth0 too, and the default route through the host.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <netdb.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>
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

/// A dump of routes (RTM_GETROUTE, `family`) into `buf`: how many there are.
static int routes_of(int family, char *buf, int size) {
    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct { struct nlmsghdr h; struct rtmsg r; } req = {
        .h = {.nlmsg_len = sizeof req, .nlmsg_type = RTM_GETROUTE, .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP},
        .r = {.rtm_family = family},
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

static int routes(char *buf, int size) { return routes_of(AF_INET, buf, size); }

/// SIOCETHTOOL command `cmd` on interface `name`, with `data` its structure.
static int ethtool(const char *name, void *data) {
    int u = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, name);
    ifr.ifr_data = data;
    int r = ioctl(u, SIOCETHTOOL, &ifr), e = errno;
    close(u);
    errno = e;
    return r;
}

/// A udev monitor's socket: it binds, never hears anything, and what's sent
/// to it is refused as for anyone without CAP_SYS_ADMIN.
static int uevent(void) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
    CHECK(s >= 0);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = 1};
    CHECK(bind(s, (void *)&sa, sizeof sa) == 0);
    char buf[512];
    CHECK(recv(s, buf, sizeof buf, 0) == -1 && errno == EAGAIN);
    struct pollfd pfd = {.fd = s, .events = POLLIN};
    CHECK(poll(&pfd, 1, 50) == 0);
    struct nlmsghdr h = {.nlmsg_len = sizeof h, .nlmsg_type = 0x10, .nlmsg_flags = NLM_F_REQUEST, .nlmsg_seq = 3};
    CHECK(send(s, &h, sizeof h, 0) == sizeof h);
    CHECK(recv(s, buf, sizeof buf, 0) > 0);
    struct nlmsghdr *r = (void *)buf;
    CHECK(r->nlmsg_type == NLMSG_ERROR && r->nlmsg_seq == 3 && ((struct nlmsgerr *)NLMSG_DATA(r))->error == -EPERM);
    close(s);
    return 0;
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
    int v4 = 0, v6 = 0, link = 0, lo = 0;
    struct in6_addr ula;
    inet_pton(AF_INET6, "fd00::15", &ula);
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
            // A unique local address, fd00::15/64.
            CHECK(i->ifa_addr->sa_family == AF_INET6);
            struct sockaddr_in6 *a = (void *)i->ifa_addr, *m = (void *)i->ifa_netmask;
            CHECK(!memcmp(&a->sin6_addr, &ula, 16));
            CHECK(!memcmp(&m->sin6_addr, "\xff\xff\xff\xff\xff\xff\xff\xff\0\0\0\0\0\0\0\0", 16));
            v6++;
        }
    }
    freeifaddrs(ifa);
    CHECK(v4 == 1 && v6 == 1 && link == 1 && lo == 3);
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
    // (Ethernet's, or the link's on the vm stack: sockopts and bigudp go
    // by which.)
    CHECK(ioctl(u, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu >= 1500);
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

    // IPv6: the prefix route, lo's, and the default one through the host.
    CHECK(routes_of(AF_INET6, buf, sizeof buf) == 3);
    h = (void *)buf;
    r = NLMSG_DATA(h);
    CHECK(r->rtm_family == AF_INET6 && r->rtm_dst_len == 64 && !route_attr(h, RTA_GATEWAY));
    CHECK(!memcmp(route_attr(h, RTA_DST), "\xfd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16));
    for (int k = 0; k < 2; k++) h = NLMSG_NEXT(h, (int){sizeof buf});
    r = NLMSG_DATA(h);
    struct in6_addr host6;
    inet_pton(AF_INET6, "fd00::2", &host6);
    CHECK(r->rtm_dst_len == 0 && !memcmp(route_attr(h, RTA_GATEWAY), &host6, 16));
    CHECK(*(int *)route_attr(h, RTA_OIF) == 2 && *(int *)route_attr(h, RTA_PRIORITY) == 1024);
    CHECK(slurp("/proc/net/if_inet6") > 0);
    CHECK(!strcmp(text, "00000000000000000000000000000001 01 80 10 80       lo\n"
                        "fd000000000000000000000000000015 02 40 00 80     eth0\n"));
    CHECK(slurp("/proc/net/ipv6_route") > 0);
    CHECK(strstr(text, "fd000000000000000000000000000000 40 00000000000000000000000000000000 00 "
                       "00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"));
    CHECK(strstr(text, "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
                       "fd000000000000000000000000000002 00000400 00000001 00000000 00000003     eth0\n"));
    CHECK(slurp("/etc/hosts") > 0 && strstr(text, "\nfd00::15\tgrix\n"));

    // AI_ADDRCONFIG finds an IPv6 address, so a passive lookup gives [::]
    // (ClickHouse's listeners).
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE | AI_ADDRCONFIG};
    struct addrinfo *res, *ai;
    CHECK(getaddrinfo(NULL, "9000", &hints, &res) == 0);
    int any6 = 0;
    for (ai = res; ai; ai = ai->ai_next) any6 |= ai->ai_family == AF_INET6;
    freeaddrinfo(res);
    CHECK(any6);
    // A listener on [::] takes connections to fd00::15 and to 10.0.2.15.
    int l = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in6 s6 = {.sin6_family = AF_INET6, .sin6_port = htons(9000)};
    CHECK(l >= 0 && bind(l, (void *)&s6, sizeof s6) == 0 && listen(l, 4) == 0);
    int c = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    s6.sin6_addr = ula;
    CHECK(connect(c, (void *)&s6, sizeof s6) == 0);
    int a = accept(l, NULL, NULL);
    CHECK(a >= 0 && write(c, "x", 1) == 1 && read(a, buf, 1) == 1 && buf[0] == 'x');
    struct sockaddr_in6 got;
    socklen_t glen = sizeof got;
    CHECK(getsockname(a, (void *)&got, &glen) == 0 && !memcmp(&got.sin6_addr, &ula, 16));
    close(a);
    close(c);
    close(l);
    // Binding to it works; to someone else's doesn't.
    int b = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    s6.sin6_port = 0;
    CHECK(bind(b, (void *)&s6, sizeof s6) == 0);
    close(b);
    b = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    inet_pton(AF_INET6, "fd00::99", &s6.sin6_addr);
    CHECK(bind(b, (void *)&s6, sizeof s6) == -1 && errno == EADDRNOTAVAIL);
    // The route to a global IPv6 address leaves from the ULA, so RFC 6724
    // sorting (which compares labels: fc00::/7's differs from 2000::/3's,
    // while an IPv4 destination and its source match) tries IPv4 first.
    inet_pton(AF_INET6, "2001:db8::1", &s6.sin6_addr);
    s6.sin6_port = htons(53);
    CHECK(connect(b, (void *)&s6, sizeof s6) == 0);
    glen = sizeof got;
    CHECK(getsockname(b, (void *)&got, &glen) == 0 && !memcmp(&got.sin6_addr, &ula, 16));
    close(b);
    // ethtool: eth0 is a container's veth.
    struct ethtool_drvinfo drv = {.cmd = ETHTOOL_GDRVINFO};
    CHECK(ethtool("eth0", &drv) == 0 && !strcmp(drv.driver, "veth") && !strcmp(drv.bus_info, ""));
    struct ethtool_value link_up = {.cmd = ETHTOOL_GLINK};
    CHECK(ethtool("eth0", &link_up) == 0 && link_up.data == 1);
    struct ethtool_cmd old = {.cmd = ETHTOOL_GSET};
    CHECK(ethtool("eth0", &old) == 0 && ethtool_cmd_speed(&old) == 10000 && old.duplex == DUPLEX_FULL);
    static __u32 lsbuf[64];
    struct ethtool_link_settings *ls = (void *)lsbuf;
    ls->cmd = ETHTOOL_GLINKSETTINGS;
    CHECK(ethtool("eth0", ls) == 0 && ls->link_mode_masks_nwords < 0);
    ls->link_mode_masks_nwords = -ls->link_mode_masks_nwords;
    CHECK(ethtool("eth0", ls) == 0 && ls->speed == 10000 && ls->duplex == DUPLEX_FULL && ls->link_mode_masks_nwords > 0);
    static __u32 permbuf[4];
    struct ethtool_perm_addr *perm = (void *)permbuf;
    *perm = (struct ethtool_perm_addr){.cmd = ETHTOOL_GPERMADDR, .size = 8};
    CHECK(ethtool("eth0", perm) == 0 && perm->size == 6 && !memcmp(perm->data, "\x52\x54\x00\x12\x34\x56", 6));
    perm->size = 2;
    CHECK(ethtool("eth0", perm) == -1 && errno == E2BIG);
    struct ethtool_ringparam ring = {.cmd = ETHTOOL_GRINGPARAM};
    CHECK(ethtool("eth0", &ring) == -1 && errno == EOPNOTSUPP);
    ring.cmd = ETHTOOL_SRINGPARAM;
    CHECK(ethtool("eth0", &ring) == -1 && errno == EPERM);
    if (uevent()) return 1;
    printf("netif eth0 ok\n");
    return 0;
}

/// A name with a global IPv6 address and an IPv4 one (the test's
/// /etc/hosts): IPv4's comes first, as the ULA's label doesn't match.
static int dual(void) {
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *res;
    CHECK(getaddrinfo("dual.example", "80", &hints, &res) == 0);
    CHECK(res->ai_family == AF_INET && res->ai_next && res->ai_next->ai_family == AF_INET6);
    freeaddrinfo(res);
    printf("netif dual ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "eth0")) return eth0();
    if (argc > 1 && !strcmp(argv[1], "dual")) return dual();
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

    // ethtool: lo has a link and nothing else; eth0 isn't there.
    struct ethtool_value link_up = {.cmd = ETHTOOL_GLINK};
    CHECK(ethtool("lo", &link_up) == 0 && link_up.data == 1);
    struct ethtool_drvinfo drv = {.cmd = ETHTOOL_GDRVINFO};
    CHECK(ethtool("lo", &drv) == -1 && errno == EOPNOTSUPP);
    CHECK(ethtool("eth0", &drv) == -1 && errno == ENODEV);
    CHECK(ethtool("lo", (void *)8) == -1 && errno == EFAULT);
    if (uevent()) return 1;

    // Network sockets still need `net`.
    CHECK(socket(AF_INET, SOCK_DGRAM, 0) == -1 && errno == EPERM);
    printf("netif ok\n");
    return 0;
}
