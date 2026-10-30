// Kernel memory a program can make the kernel hold is bounded: each of
// these runs into an errno, never a kernel panic, and works again once the
// program lets go. Netlink replies across many sockets, pipe buffers,
// queued real-time signals, mappings, inotify watches, generated /proc files.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)
#define RUN(t) do { if (t()) return 1; } while (0)

static char big[65536];

static int test_netlink(void) {
    // Unread replies on many sockets: ENOBUFS once the budget is spent.
    for (int i = 0; i + 20 <= (int)sizeof big; i += 20) {
        struct nlmsghdr *h = (void *)(big + i);
        *h = (struct nlmsghdr){.nlmsg_len = 20, .nlmsg_type = RTM_GETLINK, .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP};
    }
    static int fds[400];
    int n = 0, full = 0;
    for (; n < 400; n++) {
        fds[n] = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        CHECK(fds[n] >= 0);
        while (send(fds[n], big, sizeof big, MSG_DONTWAIT) > 0) {}
        if (errno == ENOBUFS && n > 0 && send(fds[n], big, 20, 0) < 0 && errno == ENOBUFS) full++;
    }
    CHECK(full > 0);
    for (int i = 0; i < n; i++) close(fds[i]);
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    CHECK(send(s, big, 20, 0) == 20);
    close(s);
    return 0;
}

static int test_pipes(void) {
    // Hundreds of full pipes: writes stop with EAGAIN, then work again.
    // (500 of them hold 31 MiB, more than the budget has at 512 MiB.)
    static int p[500][2];
    int n = 0, stopped = 0;
    for (; n < 500 && stopped < 8; n++) {
        CHECK(pipe2(p[n], O_NONBLOCK) == 0);
        ssize_t w, total = 0;
        while ((w = write(p[n][1], big, sizeof big)) > 0) total += w;
        CHECK(errno == EAGAIN);
        if (total < 65536) stopped++;
    }
    CHECK(stopped > 0);
    for (int i = 0; i < n; i++) {
        close(p[i][0]);
        close(p[i][1]);
    }
    int q[2];
    CHECK(pipe(q) == 0 && write(q[1], big, 65536) == 65536);
    close(q[0]);
    close(q[1]);
    return 0;
}

static int test_signals(void) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &s, 0);
    int n = 0;
    while (sigqueue(getpid(), SIGRTMIN, (union sigval){0}) == 0) n++;
    CHECK(errno == EAGAIN && n >= 1000);
    signal(SIGRTMIN, SIG_IGN);  // discards them all
    signal(SIGRTMIN, SIG_DFL);
    CHECK(sigqueue(getpid(), SIGRTMIN, (union sigval){0}) == 0);
    signal(SIGRTMIN, SIG_IGN);
    sigprocmask(SIG_UNBLOCK, &s, 0);
    return 0;
}

static int test_mappings(void) {
    // Alternating protections so neighbouring mappings can't merge.
    char *base = mmap(0, 40000 * 4096L, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    CHECK(base != MAP_FAILED);
    int n = 0;
    for (; n < 40000; n += 2) {
        if (mprotect(base + n * 4096L, 4096, PROT_READ) < 0) break;
    }
    CHECK(errno == ENOMEM && n < 40000);
    // Generated /proc files are charged too: a huge maps file, many times.
    int fds[64], opened = 0;
    for (; opened < 64; opened++) {
        fds[opened] = open("/proc/self/maps", O_RDONLY);
        if (fds[opened] < 0) break;
    }
    CHECK(opened < 64 && errno == ENOMEM);
    for (int i = 0; i < opened; i++) close(fds[i]);
    CHECK(munmap(base, 40000 * 4096L) == 0);
    int fd = open("/proc/self/maps", O_RDONLY);
    CHECK(fd >= 0);
    close(fd);
    return 0;
}

static int test_watches(void) {
    int in = inotify_init1(0);
    int n = 0;
    char path[32];
    // Distinct paths: watching the same path again reuses the watch.
    static const char *paths[] = {"/", "/bin", "/dev", "/etc", "/proc", "/sys", "/tmp", "/dev/null",
                                  "/dev/zero", "/dev/random", "/etc/passwd", "/proc/self"};
    int fds[2000], k = 0;
    for (;;) {
        int fd = inotify_init1(0);
        if (fd < 0) break;
        fds[k++] = fd;
        int ok = 1;
        for (int j = 0; j < 12 && ok; j++) {
            if (inotify_add_watch(fd, paths[j], IN_MODIFY) < 0) ok = 0;
            else n++;
        }
        if (!ok || k == 2000) break;
    }
    CHECK(errno == ENOSPC && n >= 8000);
    for (int i = 0; i < k; i++) close(fds[i]);
    snprintf(path, sizeof path, "/tmp");
    CHECK(inotify_add_watch(in, path, IN_MODIFY) > 0);
    close(in);
    return 0;
}

int main(void) {
    RUN(test_netlink);
    RUN(test_pipes);
    RUN(test_signals);
    RUN(test_mappings);
    RUN(test_watches);
    printf("limits ok\n");
    return 0;
}
