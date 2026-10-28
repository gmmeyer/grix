// Assorted Linux interfaces: memfd_create (with seals), signalfd, CPU-time
// clocks, membarrier, mincore, prctl, /etc/localtime, sendmmsg/recvmmsg and
// user ids. No capabilities beyond `threads` are needed for any of them.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/membarrier.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)
#define RUN(t) do { if (t()) return 1; } while (0)

static long ns(clockid_t c) {
    struct timespec t;
    clock_gettime(c, &t);
    return t.tv_sec * 1000000000L + t.tv_nsec;
}

static int test_memfd(void) {
    int fd = memfd_create("scratch", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    CHECK(fd >= 0);
    CHECK(write(fd, "memory file", 11) == 11);
    char buf[64], path[64];
    CHECK(pread(fd, buf, sizeof buf, 0) == 11 && !memcmp(buf, "memory file", 11));
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, buf, sizeof buf);
    CHECK(n > 0 && !memcmp(buf, "/memfd:scratch (deleted)", n));
    char *m = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(m != MAP_FAILED && !memcmp(m, "memory file", 11));
    munmap(m, 4096);
    // Seals: no shrinking, then no writing at all.
    CHECK(fcntl(fd, F_GET_SEALS) == 0);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) == 0);
    CHECK(ftruncate(fd, 4) == -1 && errno == EPERM);
    CHECK(ftruncate(fd, 100) == 0);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SEAL) == 0);
    CHECK(write(fd, "x", 1) == -1 && errno == EPERM);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_GROW) == -1 && errno == EPERM);
    CHECK(fcntl(fd, F_GET_SEALS) == (F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL));
    close(fd);
    // Without MFD_ALLOW_SEALING it's sealed against sealing.
    fd = memfd_create("plain", 0);
    CHECK(fcntl(fd, F_GET_SEALS) == F_SEAL_SEAL && fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == -1 && errno == EPERM);
    close(fd);
    // Ordinary files can't be sealed.
    fd = open("/etc/passwd", O_RDONLY);
    CHECK(fcntl(fd, F_GET_SEALS) == -1 && errno == EINVAL);
    close(fd);
    return 0;
}

static void *kill_later(void *arg) {
    usleep(30000);
    kill(getpid(), (int)(long)arg);
    return 0;
}

static int test_signalfd(void) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigaddset(&s, SIGUSR2);
    sigprocmask(SIG_BLOCK, &s, 0);
    int fd = signalfd(-1, &s, SFD_NONBLOCK | SFD_CLOEXEC);
    CHECK(fd >= 0);
    struct signalfd_siginfo si;
    CHECK(read(fd, &si, sizeof si) == -1 && errno == EAGAIN);
    CHECK(read(fd, &si, 8) == -1 && errno == EINVAL);
    union sigval v = {.sival_int = 99};
    CHECK(sigqueue(getpid(), SIGUSR1, v) == 0);
    raise(SIGUSR2);
    // epoll sees it, and one read returns both.
    int ep = epoll_create1(0);
    struct epoll_event e = {.events = EPOLLIN};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e) == 0 && epoll_wait(ep, &e, 1, 0) == 1);
    struct signalfd_siginfo two[2];
    CHECK(read(fd, two, sizeof two) == sizeof two);
    // The thread's own signals come before the process's, as on Linux.
    CHECK(two[0].ssi_signo == SIGUSR2 && two[0].ssi_code == SI_TKILL);
    CHECK(two[1].ssi_signo == SIGUSR1 && two[1].ssi_code == SI_QUEUE && two[1].ssi_int == 99 && two[1].ssi_pid == (uint32_t)getpid());
    CHECK(epoll_wait(ep, &e, 1, 0) == 0);
    close(ep);
    // A blocking read waits for a signal from another thread.
    int bfd = signalfd(-1, &s, 0);
    pthread_t t;
    pthread_create(&t, 0, kill_later, (void *)(long)SIGUSR2);
    CHECK(read(bfd, &si, sizeof si) == sizeof si && si.ssi_signo == SIGUSR2);
    pthread_join(t, 0);
    // The mask can be changed.
    sigemptyset(&s);
    CHECK(signalfd(fd, &s, 0) == fd);
    close(bfd);
    close(fd);
    return 0;
}

static volatile int spin_stop;
// Spins until its own CPU clock says 40 ms (or 2 s pass, if it's stuck).
// Not 40 ms of wall time: the host may deschedule the VM while another
// thread is current, which takes wall time from this one's share.
static void *spinner(void *arg) {
    (void)arg;
    long w0 = ns(CLOCK_MONOTONIC);
    while (ns(CLOCK_THREAD_CPUTIME_ID) < 40000000L && ns(CLOCK_MONOTONIC) - w0 < 2000000000L) {}
    return (void *)ns(CLOCK_THREAD_CPUTIME_ID);
}

static int test_cpu_clocks(void) {
    long p0 = ns(CLOCK_PROCESS_CPUTIME_ID), t0 = ns(CLOCK_THREAD_CPUTIME_ID);
    usleep(50000);  // sleeping uses no CPU (allowing for a busy host)
    long slept = ns(CLOCK_THREAD_CPUTIME_ID) - t0;
    CHECK(slept < 35000000L);
    long w0 = ns(CLOCK_MONOTONIC);
    while (ns(CLOCK_MONOTONIC) - w0 < 50000000L) {}  // spinning does
    long spun = ns(CLOCK_THREAD_CPUTIME_ID) - t0;
    CHECK(spun >= 40000000L && spun < 200000000L);
    // Another thread's CPU time adds to the process's.
    pthread_t t;
    void *theirs;
    pthread_create(&t, 0, spinner, 0);
    pthread_join(t, &theirs);
    CHECK((long)theirs >= 40000000L);
    long proc = ns(CLOCK_PROCESS_CPUTIME_ID) - p0;
    CHECK(proc >= spun + 40000000L);
    clockid_t c;
    CHECK(clock_getcpuclockid(0, &c) == 0 && ns(c) >= proc);
    CHECK(pthread_getcpuclockid(pthread_self(), &c) == 0 && ns(c) >= spun);
    struct rusage ru;
    CHECK(getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec >= 70000);
    CHECK(getrusage(RUSAGE_CHILDREN, &ru) == 0 && ru.ru_utime.tv_sec == 0 && ru.ru_utime.tv_usec == 0);
    return 0;
}

static int test_misc(void) {
    // membarrier: everything is supported; expedited ones need registering.
    long cmds = syscall(SYS_membarrier, MEMBARRIER_CMD_QUERY, 0, 0);
    CHECK(cmds & MEMBARRIER_CMD_PRIVATE_EXPEDITED);
    CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == -1 && errno == EPERM);
    CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0) == 0);
    CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == 0);
    CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0) == 0);
    // mincore: touched pages are resident, untouched ones aren't.
    char *m = mmap(0, 3 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    m[4096] = 1;
    unsigned char vec[3];
    CHECK(mincore(m, 3 * 4096, vec) == 0 && vec[0] == 0 && vec[1] == 1 && vec[2] == 0);
    munmap(m + 4096, 4096);
    CHECK(mincore(m, 3 * 4096, vec) == -1 && errno == ENOMEM);
    CHECK(mincore(m + 1, 4096, vec) == -1 && errno == EINVAL);
    // prctl.
    int v = -1;
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0 && prctl(PR_GET_CHILD_SUBREAPER, &v) == 0 && v == 1);
    int *tidp = 0;
    CHECK(prctl(PR_GET_TID_ADDRESS, &tidp) == 0 && tidp != 0);
    CHECK(prctl(PR_GET_TIMERSLACK) == 50000);
    CHECK(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 0, 0, 0) == -1 && errno == EPERM);
    CHECK(prctl(4242) == -1 && errno == EINVAL);  // reported as unimplemented
    // The timezone is UTC unless the host imports one.
    struct stat st;
    CHECK(stat("/etc/localtime", &st) == 0 && st.st_size == 114);
    time_t now = time(0);
    struct tm tm;
    CHECK(localtime_r(&now, &tm) && !strcmp(tm.tm_zone, "UTC") && tm.tm_gmtoff == 0);
    return 0;
}

static int sock[2];
static volatile sig_atomic_t alarms;
static void on_alarm(int sig) { (void)sig; alarms++; }
static void *late_writer(void *arg) {
    (void)arg;
    usleep(200 * 1000);
    write(sock[1], "late", 4);
    return 0;
}

// glibc's resolver sends its A and AAAA queries with one sendmmsg.
static int test_mmsg(void) {
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sock) == 0);
    char *out[] = {"a", "bb", "ccc"};
    struct iovec oiov[3];
    struct mmsghdr omsg[3];
    memset(omsg, 0, sizeof omsg);
    for (int i = 0; i < 3; i++) {
        oiov[i] = (struct iovec){out[i], strlen(out[i])};
        omsg[i].msg_hdr.msg_iov = &oiov[i];
        omsg[i].msg_hdr.msg_iovlen = 1;
    }
    CHECK(sendmmsg(sock[0], omsg, 3, 0) == 3);
    CHECK(omsg[0].msg_len == 1 && omsg[1].msg_len == 2 && omsg[2].msg_len == 3);

    // A stream: each message takes what its buffer holds; the fourth finds
    // nothing left and isn't waited for.
    char in[4][8];
    size_t sizes[4] = {1, 2, 3, 8};
    struct iovec iiov[4];
    struct mmsghdr imsg[4];
    memset(imsg, 0, sizeof imsg);
    for (int i = 0; i < 4; i++) {
        iiov[i] = (struct iovec){in[i], sizes[i]};
        imsg[i].msg_hdr.msg_iov = &iiov[i];
        imsg[i].msg_hdr.msg_iovlen = 1;
    }
    CHECK(recvmmsg(sock[1], imsg, 4, 0, 0) == 3);
    CHECK(imsg[0].msg_len == 1 && imsg[1].msg_len == 2 && imsg[2].msg_len == 3);
    CHECK(memcmp(in[0], "a", 1) == 0 && memcmp(in[1], "bb", 2) == 0 && memcmp(in[2], "ccc", 3) == 0);
    CHECK(recvmmsg(sock[1], imsg, 4, MSG_DONTWAIT, 0) == -1 && errno == EAGAIN);

    // A blocked recvmmsg restarts after an SA_RESTART handler, and wakes
    // for data (the other way round: sock[0] reads what sock[1] writes).
    struct sigaction sa = {.sa_handler = on_alarm, .sa_flags = SA_RESTART};
    CHECK(sigaction(SIGALRM, &sa, 0) == 0);
    struct itimerval it = {.it_value = {0, 50 * 1000}};
    CHECK(setitimer(ITIMER_REAL, &it, 0) == 0);
    pthread_t t;
    CHECK(pthread_create(&t, 0, late_writer, 0) == 0);
    iiov[0] = (struct iovec){in[3], 8};
    CHECK(recvmmsg(sock[0], imsg, 1, 0, 0) == 1);
    CHECK(alarms == 1 && imsg[0].msg_len == 4 && memcmp(in[3], "late", 4) == 0);
    pthread_join(t, 0);
    close(sock[0]);
    close(sock[1]);
    return 0;
}

// Not root: ids can only move among the real, effective and saved ones.
static int test_ids(void) {
    uid_t r, e, s;
    CHECK(getresuid(&r, &e, &s) == 0 && r == 1000 && e == 1000 && s == 1000);
    CHECK(setuid(1000) == 0 && setresuid(-1, -1, -1) == 0 && setreuid(1000, 1000) == 0);
    CHECK(setuid(0) == -1 && errno == EPERM);
    CHECK(seteuid(0) == -1 && errno == EPERM);
    CHECK(setgid(0) == -1 && errno == EPERM);
    CHECK(syscall(SYS_setuid, -1) == -1 && errno == EINVAL);
    gid_t groups[4];
    CHECK(getgroups(0, 0) == 1 && getgroups(4, groups) == 1 && groups[0] == 1000);
    CHECK(setgroups(1, groups) == -1 && errno == EPERM);
    return 0;
}

int main(void) {
    RUN(test_memfd);
    RUN(test_signalfd);
    RUN(test_cpu_clocks);
    RUN(test_misc);
    RUN(test_mmsg);
    RUN(test_ids);
    printf("linux ok\n");
    return 0;
}
