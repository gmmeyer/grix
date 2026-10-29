// Named pipes (mkfifo/mknod), as s6 and shell scripts use them: opens that
// wait for the other side (from another thread), O_NONBLOCK and O_RDWR
// opens, what's left in one when everything closes, mknod's other kinds,
// and many rendezvous with another thread and another process, each side
// blocking in opens, reads and writes (on more CPUs, woken from another
// CPU). Needs `threads`, `process` and `fs_write`.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

static void *reader(void *arg) {
    // Waits for the writer's open, then reads until it closes.
    int fd = open("/tmp/f", O_RDONLY);
    static char got[64];
    ssize_t n, total = 0;
    while (fd >= 0 && (n = read(fd, got + total, sizeof got - 1 - total)) > 0) total += n;
    got[total] = 0;
    close(fd);
    return got;
}

static void *writer(void *arg) {
    int fd = open("/tmp/f", O_WRONLY);
    if (fd >= 0) {
        write(fd, "second", 6);
        close(fd);
    }
    return NULL;
}

// Rendezvous: each round, one side sends through /tmp/a and the other
// answers through /tmp/b. Opens find the other side there or not, by
// chance. Odd rounds send more than a pipe holds (the writer blocks too);
// even ones little, so a writer may open, write and close while the
// reader's open waits to run again.
#define ROUNDS 100
#define BIG (96 * 1024)

static unsigned char pattern(int round, size_t i) { return (unsigned char)(round * 31 + i * 7); }
static size_t size(int round) { return round % 2 ? BIG : 16; }

static int send_round(const char *path, int round) {
    static unsigned char buf[BIG];
    size_t len = size(round);
    for (size_t i = 0; i < len; i++) buf[i] = pattern(round, i);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    for (size_t done = 0; done < len;) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n <= 0) return close(fd), -1;
        done += n;
    }
    return close(fd);
}

static int receive_round(const char *path, int round) {
    unsigned char buf[8192];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++)
            if (buf[i] != pattern(round, total + i)) return close(fd), -1;
        total += n;
    }
    close(fd);
    return n == 0 && total == size(round) ? 0 : -1;
}

static void *partner(void *arg) {
    int rounds = arg ? (int)(long)arg : ROUNDS;
    for (int r = 0; r < rounds; r++) {
        if (receive_round("/tmp/a", r) != 0 || send_round("/tmp/b", r) != 0) return (void *)1;
    }
    return NULL;
}

// Busy threads, so a woken thread waits its turn (and the other side gets
// ahead meanwhile).
static volatile int spinning;
static void *spin(void *arg) {
    while (spinning) {}
    return NULL;
}

static int rendezvous(int rounds) {
    for (int r = 0; r < rounds; r++) {
        CHECK(send_round("/tmp/a", r) == 0);
        CHECK(receive_round("/tmp/b", r) == 0);
    }
    return 0;
}

int main(void) {
    struct stat st;
    CHECK(mkfifo("/tmp/f", 0640) == 0);
    CHECK(stat("/tmp/f", &st) == 0 && S_ISFIFO(st.st_mode) && (st.st_mode & 0777) == 0640);
    CHECK(mkfifo("/tmp/f", 0640) == -1 && errno == EEXIST);

    // Without a reader, a nonblocking writer gets ENXIO; a nonblocking
    // reader doesn't wait, and reads EOF with no writer.
    CHECK(open("/tmp/f", O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
    int r = open("/tmp/f", O_RDONLY | O_NONBLOCK);
    CHECK(r >= 0);
    char buf[64];
    CHECK(read(r, buf, sizeof buf) == 0);
    int w = open("/tmp/f", O_WRONLY | O_NONBLOCK);
    CHECK(w >= 0);
    CHECK(fstat(w, &st) == 0 && S_ISFIFO(st.st_mode));
    CHECK(lseek(w, 0, SEEK_SET) == -1 && errno == ESPIPE);
    CHECK(read(w, buf, 1) == -1 && errno == EBADF);
    CHECK(write(w, "hello", 5) == 5);
    struct pollfd pfd = {.fd = r, .events = POLLIN};
    CHECK(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN));
    CHECK(read(r, buf, sizeof buf) == 5 && memcmp(buf, "hello", 5) == 0);
    CHECK(read(r, buf, sizeof buf) == -1 && errno == EAGAIN);
    char link[64] = {0};
    char self[32];
    snprintf(self, sizeof self, "/proc/self/fd/%d", r);
    CHECK(readlink(self, link, sizeof link - 1) > 0 && strcmp(link, "/tmp/f") == 0);
    // What nobody read goes when the last end closes.
    CHECK(write(w, "lost", 4) == 4);
    close(w);
    close(r);
    r = open("/tmp/f", O_RDONLY | O_NONBLOCK);
    CHECK(read(r, buf, sizeof buf) == 0);
    close(r);

    // O_RDWR never waits, and is both ends.
    int rw = open("/tmp/f", O_RDWR);
    CHECK(rw >= 0);
    CHECK(write(rw, "rw", 2) == 2 && read(rw, buf, sizeof buf) == 2 && memcmp(buf, "rw", 2) == 0);
    close(rw);

    // Blocking opens wait for each other: the reader first...
    pthread_t t;
    void *got;
    CHECK(pthread_create(&t, NULL, reader, NULL) == 0);
    w = open("/tmp/f", O_WRONLY);
    CHECK(w >= 0);
    CHECK(write(w, "first", 5) == 5);
    close(w);
    CHECK(pthread_join(t, &got) == 0 && strcmp(got, "first") == 0);
    // ...or the writer.
    CHECK(pthread_create(&t, NULL, writer, NULL) == 0);
    usleep(20000);
    r = open("/tmp/f", O_RDONLY);
    CHECK(r >= 0);
    ssize_t n, total = 0;
    while ((n = read(r, buf + total, sizeof buf - total)) > 0) total += n;
    CHECK(total == 6 && memcmp(buf, "second", 6) == 0);
    close(r);
    CHECK(pthread_join(t, NULL) == 0);

    // Many rendezvous with a thread and with another process, then with a
    // thread again while busy threads keep the CPUs, all with a fast timer
    // interrupting whatever runs (its signal ignored): a woken open may be
    // interrupted before it runs again, or wait its turn while the other
    // side opens, writes and closes.
    CHECK(signal(SIGALRM, SIG_IGN) != SIG_ERR);
    struct itimerval fast = {{0, 200}, {0, 200}}, off = {{0, 0}, {0, 0}};
    CHECK(setitimer(ITIMER_REAL, &fast, NULL) == 0);
    CHECK(mkfifo("/tmp/a", 0600) == 0 && mkfifo("/tmp/b", 0600) == 0);
    CHECK(pthread_create(&t, NULL, partner, NULL) == 0);
    CHECK(rendezvous(ROUNDS) == 0);
    CHECK(pthread_join(t, &got) == 0 && got == NULL);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(partner(NULL) != NULL);
    CHECK(rendezvous(ROUNDS) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    // (One fewer than the CPUs: with the two sides, there's always one
    // more thread than CPUs.)
    long cpus = sysconf(_SC_NPROCESSORS_ONLN), spinners_n = cpus > 4 ? 3 : cpus - 1;
    pthread_t spinners[3];
    spinning = 1;
    for (int i = 0; i < spinners_n; i++) CHECK(pthread_create(&spinners[i], NULL, spin, NULL) == 0);
    CHECK(pthread_create(&t, NULL, partner, (void *)30L) == 0);
    CHECK(rendezvous(30) == 0);
    CHECK(pthread_join(t, &got) == 0 && got == NULL);
    spinning = 0;
    for (int i = 0; i < spinners_n; i++) CHECK(pthread_join(spinners[i], NULL) == 0);
    CHECK(unlink("/tmp/a") == 0 && unlink("/tmp/b") == 0);
    CHECK(setitimer(ITIMER_REAL, &off, NULL) == 0);

    // mknod: FIFOs and regular files; device nodes are denied.
    CHECK(mknod("/tmp/f2", S_IFIFO | 0600, 0) == 0 && stat("/tmp/f2", &st) == 0 && S_ISFIFO(st.st_mode));
    CHECK(mknod("/tmp/reg", S_IFREG | 0600, 0) == 0 && stat("/tmp/reg", &st) == 0 && S_ISREG(st.st_mode));
    CHECK(st.st_size == 0);
    CHECK(mknod("/tmp/null", S_IFCHR | 0666, makedev(1, 3)) == -1 && errno == EPERM);
    CHECK(unlink("/tmp/f") == 0 && unlink("/tmp/f2") == 0 && unlink("/tmp/reg") == 0);
    printf("fifo ok\n");
    return 0;
}
