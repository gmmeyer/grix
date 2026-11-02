// What /proc/net says of a program's sockets, and that the inodes in it are
// the ones fstat and /proc/self/fd give: it's how lsof, ss and netstat -p tie a
// connection to a process. Passes on Linux as root, on the arguments given.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                                                   \
    do {                                                                           \
        if (!(c)) {                                                                \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);       \
            exit(1);                                                               \
        }                                                                          \
    } while (0)

struct entry {
    char local[40], remote[40];
    unsigned lport, rport, state, tx, rx, uid;
    unsigned long inode;
};

// The entry in `file` with this local port, and this remote port unless it's
// 0; 0 if there isn't one.
static int find(const char *file, unsigned lport, unsigned rport, struct entry *e) {
    static char line[512];
    FILE *f = fopen(file, "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    int found = 0;
    while (!found && fgets(line, sizeof line, f)) {
        int n = sscanf(line, " %*d: %39[0-9A-F]:%x %39[0-9A-F]:%x %x %x:%x %*x:%*x %*x %u %*d %lu",
                       e->local, &e->lport, e->remote, &e->rport, &e->state, &e->tx, &e->rx,
                       &e->uid, &e->inode);
        CHECK(n == 9);
        found = e->lport == lport && (rport == 0 || e->rport == rport);
    }
    fclose(f);
    return found;
}

static unsigned long ino_of(int fd) {
    struct stat st;
    CHECK(fstat(fd, &st) == 0);
    return st.st_ino;
}

static unsigned port_of(int fd) {
    struct sockaddr_in6 a;
    socklen_t len = sizeof a;
    CHECK(getsockname(fd, (struct sockaddr *)&a, &len) == 0);
    return ntohs(a.sin6_port);
}

static int bound4(int type) {
    int s = socket(AF_INET, type, 0);
    CHECK(s >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    return s;
}

static int connected4(unsigned port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(connect(s, (struct sockaddr *)&a, sizeof a) == 0);
    return s;
}

static void same_inode_everywhere(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s >= 0);
    char path[64], target[64], want[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", s);
    ssize_t n = readlink(path, target, sizeof target - 1);
    CHECK(n > 0);
    target[n] = 0;
    snprintf(want, sizeof want, "socket:[%lu]", ino_of(s));
    CHECK(strcmp(target, want) == 0);
    // A second descriptor of it is the same socket.
    int d = dup(s);
    CHECK(ino_of(d) == ino_of(s));
    // Another socket isn't.
    int other = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(ino_of(other) != ino_of(s));
    // Nor a socket pair's two ends, which are a socket each.
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    CHECK(ino_of(pair[0]) != ino_of(pair[1]));
    snprintf(path, sizeof path, "/proc/self/fd/%d", pair[0]);
    n = readlink(path, target, sizeof target - 1);
    CHECK(n > 0);
    target[n] = 0;
    snprintf(want, sizeof want, "socket:[%lu]", ino_of(pair[0]));
    CHECK(strcmp(target, want) == 0);
    // A child sees what its parent does.
    unsigned long ino = ino_of(s);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(ino_of(s) == ino ? 0 : 1);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && status == 0);
    // A pipe's the same way.
    int p[2];
    CHECK(pipe(p) == 0);
    CHECK(ino_of(p[0]) == ino_of(p[1]));
    snprintf(path, sizeof path, "/proc/self/fd/%d", p[0]);
    n = readlink(path, target, sizeof target - 1);
    CHECK(n > 0);
    target[n] = 0;
    snprintf(want, sizeof want, "pipe:[%lu]", ino_of(p[0]));
    CHECK(strcmp(target, want) == 0);
    close(s), close(d), close(other), close(pair[0]), close(pair[1]), close(p[0]), close(p[1]);
}

static void headers(void) {
    static char line[512];
    FILE *f = fopen("/proc/net/tcp", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strlen(line) == 150);
    CHECK(strncmp(line, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
                        "retrnsmt   uid  timeout inode ", 97) == 0);
    fclose(f);
    f = fopen("/proc/net/udp", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strlen(line) == 128);
    CHECK(strncmp(line, "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
                        "retrnsmt   uid  timeout inode ref pointer drops ", 115) == 0);
    fclose(f);
    f = fopen("/proc/net/tcp6", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strcmp(line, "  sl  local_address                         remote_address                "
                       "        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n") == 0);
    fclose(f);
    f = fopen("/proc/net/udp6", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strcmp(line, "  sl  local_address                         remote_address                "
                       "        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref "
                       "pointer drops\n") == 0);
    fclose(f);
    f = fopen("/proc/net/raw", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strcmp(line, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
                       "retrnsmt   uid  timeout inode ref pointer drops\n") == 0);
    fclose(f);
    f = fopen("/proc/net/raw6", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strcmp(line, "  sl  local_address                         remote_address                "
                       "        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref "
                       "pointer drops\n") == 0);
    fclose(f);
    f = fopen("/proc/net/unix", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strcmp(line, "Num       RefCount Protocol Flags    Type St Inode Path\n") == 0);
    fclose(f);
}

static void tcp(void) {
    struct entry e;
    // Neither a new socket nor a bound one is anywhere yet.
    int l = bound4(SOCK_STREAM);
    unsigned port = port_of(l);
    CHECK(!find("/proc/net/tcp", port, 0, &e));

    CHECK(listen(l, 5) == 0);
    CHECK(find("/proc/net/tcp", port, 0, &e));
    CHECK(strcmp(e.local, "0100007F") == 0 && strcmp(e.remote, "00000000") == 0);
    CHECK(e.rport == 0 && e.state == 0x0A && e.tx == 0 && e.rx == 0);
    CHECK(e.inode == ino_of(l));
    // An IPv4 socket is only in tcp.
    CHECK(!find("/proc/net/tcp6", port, 0, &e));

    int c = connected4(port);
    unsigned cport = port_of(c);
    CHECK(find("/proc/net/tcp", cport, port, &e));
    CHECK(strcmp(e.local, "0100007F") == 0 && strcmp(e.remote, "0100007F") == 0);
    CHECK(e.state == 0x01 && e.inode == ino_of(c));
    // Before it's accepted it's established too, and no file has it. A
    // listener's queue is its rx_queue.
    CHECK(find("/proc/net/tcp", port, cport, &e));
    CHECK(e.state == 0x01 && e.inode == 0);
    CHECK(find("/proc/net/tcp", port, 0, &e));
    CHECK(e.state == 0x0A && e.rx == 1);

    int a = accept(l, NULL, NULL);
    CHECK(a >= 0);
    CHECK(find("/proc/net/tcp", port, cport, &e));
    CHECK(e.state == 0x01 && e.inode == ino_of(a));
    CHECK(find("/proc/net/tcp", port, 0, &e));
    CHECK(e.rx == 0);

    // What's waiting to be read.
    CHECK(write(c, "hello", 5) == 5);
    usleep(50000);
    CHECK(find("/proc/net/tcp", port, cport, &e));
    CHECK(e.rx == 5);
    char buf[8];
    CHECK(read(a, buf, sizeof buf) == 5);
    CHECK(find("/proc/net/tcp", port, cport, &e));
    CHECK(e.rx == 0);

    // The peer's gone: this end has yet to close.
    close(c);
    usleep(50000);
    CHECK(find("/proc/net/tcp", port, cport, &e));
    CHECK(e.state == 0x08);
    close(a);
    close(l);
    usleep(50000);
    // The side that closed last leaves nothing behind.
    CHECK(!find("/proc/net/tcp", port, cport, &e));
    // (On a shared machine someone may use the port on another address.)
    CHECK(!find("/proc/net/tcp", port, 0, &e) || e.state != 0x0A || strcmp(e.local, "0100007F") != 0);
}

static void udp(void) {
    struct entry e;
    int u = bound4(SOCK_DGRAM);
    unsigned port = port_of(u);
    CHECK(find("/proc/net/udp", port, 0, &e));
    CHECK(strcmp(e.local, "0100007F") == 0 && strcmp(e.remote, "00000000") == 0);
    CHECK(e.state == 0x07 && e.inode == ino_of(u) && e.rx == 0);

    int v = bound4(SOCK_DGRAM);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(sendto(v, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == 1);
    usleep(50000);
    CHECK(find("/proc/net/udp", port, 0, &e));
    CHECK(e.rx != 0);

    // connect: established, with its peer.
    CHECK(connect(v, (struct sockaddr *)&to, sizeof to) == 0);
    CHECK(find("/proc/net/udp", port_of(v), port, &e));
    CHECK(e.state == 0x01 && e.rport == port);
    close(u);
    CHECK(!find("/proc/net/udp", port, 0, &e));
    close(v);

    // Unbound, it isn't there; its first send gives it a port.
    int w = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(w >= 0);
    int taken = bound4(SOCK_DGRAM);
    to.sin_port = htons(port_of(taken));
    CHECK(sendto(w, "x", 1, 0, (struct sockaddr *)&to, sizeof to) == 1);
    CHECK(port_of(w) != 0);
    CHECK(find("/proc/net/udp", port_of(w), 0, &e));
    CHECK(e.inode == ino_of(w));
    CHECK(strcmp(e.local, "00000000") == 0);
    close(w), close(taken);
}

static void six(void) {
    struct entry e;
    int l = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(l >= 0);
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(listen(l, 5) == 0);
    unsigned port = port_of(l);
    CHECK(find("/proc/net/tcp6", port, 0, &e));
    CHECK(strcmp(e.local, "00000000000000000000000001000000") == 0);
    CHECK(strcmp(e.remote, "00000000000000000000000000000000") == 0);
    CHECK(e.state == 0x0A && e.inode == ino_of(l));
    CHECK(!find("/proc/net/tcp", port, 0, &e));
    close(l);

    // A wildcard listener takes IPv4 too: it's still an IPv6 socket, in
    // tcp6, and so is what it accepts.
    l = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(l >= 0);
    int off = 0;
    CHECK(setsockopt(l, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off) == 0);
    a.sin6_addr = in6addr_any;
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(listen(l, 5) == 0);
    port = port_of(l);
    CHECK(find("/proc/net/tcp6", port, 0, &e));
    CHECK(strcmp(e.local, "00000000000000000000000000000000") == 0);
    int c = connected4(port);
    unsigned cport = port_of(c);
    CHECK(find("/proc/net/tcp6", port, cport, &e));
    CHECK(strcmp(e.local, "0000000000000000FFFF00000100007F") == 0);
    CHECK(strcmp(e.remote, "0000000000000000FFFF00000100007F") == 0);
    // The client is an IPv4 socket, in tcp.
    CHECK(find("/proc/net/tcp", cport, port, &e));
    CHECK(e.inode == ino_of(c));
    close(c), close(l);

    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    CHECK(u >= 0);
    a.sin6_addr = in6addr_loopback;
    CHECK(bind(u, (struct sockaddr *)&a, sizeof a) == 0);
    port = port_of(u);
    CHECK(find("/proc/net/udp6", port, 0, &e));
    CHECK(strcmp(e.local, "00000000000000000000000001000000") == 0);
    CHECK(e.state == 0x07 && e.inode == ino_of(u));
    CHECK(!find("/proc/net/udp", port, 0, &e));
    close(u);
}

static void owners(void) {
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(setuid(65534) == 0);
        int s = bound4(SOCK_STREAM);
        CHECK(listen(s, 5) == 0);
        struct entry e;
        CHECK(find("/proc/net/tcp", port_of(s), 0, &e));
        CHECK(e.uid == 65534);
        int u = bound4(SOCK_DGRAM);
        CHECK(find("/proc/net/udp", port_of(u), 0, &e));
        CHECK(e.uid == 65534);
        _exit(0);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && status == 0);
}

// A line of /proc/net/unix with this path: 0 if there's none.
static int unix_entry(const char *path, unsigned *ref, unsigned *flags, unsigned *type, unsigned *st,
                      unsigned long *inode) {
    static char line[512];
    FILE *f = fopen("/proc/net/unix", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    int found = 0;
    char name[128];
    while (!found && fgets(line, sizeof line, f)) {
        name[0] = 0;
        int n = sscanf(line, "%*[0-9a-f]: %x %*x %x %x %x %lu %127s", ref, flags, type, st, inode, name);
        CHECK(n >= 5);
        found = strcmp(name, path) == 0;
    }
    fclose(f);
    return found;
}

static void unix_sockets(void) {
    unsigned ref, flags, type, st;
    unsigned long ino;
    char path[64];
    snprintf(path, sizeof path, "/tmp/procnet-%d.sock", getpid());
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(l >= 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, path);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(unix_entry(path, &ref, &flags, &type, &st, &ino));
    CHECK(flags == 0 && type == 1 && st == 1 && ino == ino_of(l));
    CHECK(listen(l, 5) == 0);
    CHECK(unix_entry(path, &ref, &flags, &type, &st, &ino));
    CHECK(flags == 0x10000 && type == 1 && st == 1 && ino == ino_of(l));
    close(l);
    CHECK(!unix_entry(path, &ref, &flags, &type, &st, &ino));
    unlink(path);

    // A name in the abstract namespace starts with an @.
    int u = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(u >= 0);
    struct sockaddr_un b = {.sun_family = AF_UNIX};
    char name[32];
    int n = snprintf(name, sizeof name, "procnet-%d", getpid());
    memcpy(b.sun_path + 1, name, n);
    CHECK(bind(u, (struct sockaddr *)&b, offsetof(struct sockaddr_un, sun_path) + 1 + n) == 0);
    char shown[40];
    snprintf(shown, sizeof shown, "@%s", name);
    CHECK(unix_entry(shown, &ref, &flags, &type, &st, &ino));
    CHECK(flags == 0 && type == 2 && st == 1 && ino == ino_of(u));
    close(u);
}

// /proc/<pid>/net is /proc/net, for a process's own network namespace.
static void per_process(void) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/net/tcp", getpid());
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    fclose(f);
    f = fopen("/proc/self/net/udp", "r");
    CHECK(f != NULL);
    fclose(f);
}

static void sockstat(void) {
    int l = bound4(SOCK_STREAM);
    CHECK(listen(l, 5) == 0);
    int u = bound4(SOCK_DGRAM);
    static char text[1024];
    FILE *f = fopen("/proc/net/sockstat", "r");
    CHECK(f != NULL);
    size_t n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    text[n] = 0;
    unsigned used, tcp_inuse, orphan, tw, alloc, mem, udp_inuse, udp_mem, lite, raw, frag, frag_mem;
    int got = sscanf(text,
                     "sockets: used %u\nTCP: inuse %u orphan %u tw %u alloc %u mem %u\n"
                     "UDP: inuse %u mem %u\nUDPLITE: inuse %u\nRAW: inuse %u\n"
                     "FRAG: inuse %u memory %u\n",
                     &used, &tcp_inuse, &orphan, &tw, &alloc, &mem, &udp_inuse, &udp_mem, &lite,
                     &raw, &frag, &frag_mem);
    CHECK(got == 12);
    CHECK(used >= 2 && tcp_inuse >= 1 && alloc >= tcp_inuse && udp_inuse >= 1);
    f = fopen("/proc/net/sockstat6", "r");
    CHECK(f != NULL);
    n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    text[n] = 0;
    unsigned a, b, c, d, e;
    got = sscanf(text, "TCP6: inuse %u\nUDP6: inuse %u\nUDPLITE6: inuse %u\nRAW6: inuse %u\n"
                       "FRAG6: inuse %u memory %u\n", &a, &b, &c, &d, &e, &frag_mem);
    CHECK(got == 6);
    close(l), close(u);
}

// A connection's last words shouldn't break anything that reads the table: the
// table's files read in small pieces, and all of it fits.
static void small_reads(void) {
    int l = bound4(SOCK_STREAM);
    CHECK(listen(l, 5) == 0);
    int fd = open("/proc/net/tcp", O_RDONLY);
    CHECK(fd >= 0);
    char c;
    size_t total = 0;
    ssize_t n;
    while ((n = read(fd, &c, 1)) == 1) total++;
    CHECK(n == 0 && total >= 300);
    close(fd), close(l);
}

// Raw and ping sockets, for a program that may have them.
static void raw_tables(void) {
    static char line[512];
    FILE *f = fopen("/proc/net/icmp", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strlen(line) == 128);
    CHECK(strncmp(line, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
                        "retrnsmt   uid  timeout inode ref pointer drops ", 114) == 0);
    fclose(f);
    f = fopen("/proc/net/icmp6", "r");
    CHECK(f != NULL);
    CHECK(fgets(line, sizeof line, f) != NULL);
    CHECK(strcmp(line, "  sl  local_address                         remote_address                "
                       "        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref "
                       "pointer drops\n") == 0);
    fclose(f);

    // Its port is its protocol.
    struct entry e;
    int r = socket(AF_INET, SOCK_RAW, 253);
    CHECK(r >= 0);
    CHECK(find("/proc/net/raw", 253, 0, &e));
    CHECK(strcmp(e.local, "00000000") == 0 && e.state == 0x07 && e.inode == ino_of(r));
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(connect(r, (struct sockaddr *)&to, sizeof to) == 0);
    CHECK(find("/proc/net/raw", 253, 0, &e));
    CHECK(e.state == 0x01 && strcmp(e.remote, "0100007F") == 0);
    close(r);
    CHECK(!find("/proc/net/raw", 253, 0, &e));
    int r6 = socket(AF_INET6, SOCK_RAW, 253);
    CHECK(r6 >= 0);
    CHECK(find("/proc/net/raw6", 253, 0, &e));
    CHECK(e.inode == ino_of(r6));
    close(r6);

    // A ping socket's port is its identifier, once it has one.
    int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    CHECK(p >= 0);
    unsigned char echo[8] = {8, 0, 0, 0, 0x12, 0x34, 0, 1};
    CHECK(sendto(p, echo, sizeof echo, 0, (struct sockaddr *)&to, sizeof to) == sizeof echo);
    unsigned ident = port_of(p);
    CHECK(ident != 0);
    CHECK(find("/proc/net/icmp", ident, 0, &e));
    CHECK(e.inode == ino_of(p));
    // Two of them are told apart by it, whatever the program wrote.
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    CHECK(q >= 0);
    CHECK(sendto(q, echo, sizeof echo, 0, (struct sockaddr *)&to, sizeof to) == sizeof echo);
    CHECK(port_of(q) != ident);
    unsigned char reply[16];
    CHECK(recv(p, reply, sizeof reply, 0) == 8);
    CHECK(reply[0] == 0 && (reply[4] << 8 | reply[5]) == ident);
    CHECK(recv(q, reply, sizeof reply, 0) == 8);
    CHECK((reply[4] << 8 | reply[5]) == port_of(q));
    close(q);
    close(p);
    CHECK(!find("/proc/net/icmp", ident, 0, &e));
    // bind says which, and Linux doesn't mind two having it (ping sockets
    // are all SO_REUSEADDR's, its ping_get_port asks "BUG?").
    p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    CHECK(p >= 0);
    q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    CHECK(q >= 0);
    struct sockaddr_in at = {.sin_family = AF_INET, .sin_port = htons(40123),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(p, (struct sockaddr *)&at, sizeof at) == 0);
    CHECK(port_of(p) == 40123);
    CHECK(bind(q, (struct sockaddr *)&at, sizeof at) == 0);
    // A program's raw ICMP socket is a raw one.
    close(p), close(q);
    r = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    CHECK(r >= 0);
    CHECK(find("/proc/net/raw", IPPROTO_ICMP, 0, &e));
    CHECK(e.inode == ino_of(r));
    close(r);
}

// A connection through the host, to a server the test runs at 10.0.2.2.
static void through_host(unsigned port) {
    struct entry e;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s >= 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(inet_pton(AF_INET, "10.0.2.2", &to.sin_addr) == 1);
    CHECK(connect(s, (struct sockaddr *)&to, sizeof to) == 0);
    unsigned local = port_of(s);
    CHECK(find("/proc/net/tcp", local, port, &e));
    CHECK(strcmp(e.local, "0F02000A") == 0 && strcmp(e.remote, "0202000A") == 0);
    CHECK(e.state == 0x01 && e.inode == ino_of(s));
    // The server says something and hangs up. Nobody's read it yet.
    CHECK(write(s, "x", 1) == 1);
    for (int i = 0; i < 2000 && (!find("/proc/net/tcp", local, port, &e) || e.state != 0x08); i++)
        usleep(5000);
    // Linux counts sequence numbers there, and the FIN has one, until a
    // read gets to it.
    CHECK(e.state == 0x08 && e.rx == 6);
    char buf[8];
    CHECK(read(s, buf, sizeof buf) == 5);
    CHECK(find("/proc/net/tcp", local, port, &e));
    CHECK(e.rx == 0);
    close(s);
    CHECK(!find("/proc/net/tcp", local, port, &e));
}

// A connection forwarded from the host, waiting and accepted.
static void forwarded(unsigned port) {
    struct entry e;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(l >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(listen(l, 5) == 0);
    printf("listening\n");
    for (int i = 0; i < 2000 && (!find("/proc/net/tcp", port, 0, &e) || e.rx == 0); i++)
        usleep(5000);
    CHECK(e.rx == 1 && e.state == 0x0A);
    struct entry c;
    int s = accept(l, NULL, NULL);
    CHECK(s >= 0);
    struct sockaddr_in peer;
    socklen_t len = sizeof peer;
    CHECK(getpeername(s, (struct sockaddr *)&peer, &len) == 0);
    CHECK(find("/proc/net/tcp", port, ntohs(peer.sin_port), &c));
    CHECK(c.state == 0x01 && c.inode == ino_of(s) && strcmp(c.remote, "0202000A") == 0);
    close(s), close(l);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 && strcmp(argv[1], "host") == 0) {
        through_host(atoi(argv[2]));
        printf("procnet ok\n");
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "forwarded") == 0) {
        forwarded(atoi(argv[2]));
        printf("procnet ok\n");
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "raw") == 0) {
        raw_tables();
        printf("procnet ok\n");
        return 0;
    }
    same_inode_everywhere();
    headers();
    tcp();
    udp();
    six();
    owners();
    unix_sockets();
    per_process();
    sockstat();
    small_reads();
    printf("procnet ok\n");
    return 0;
}
