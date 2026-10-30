// Shared file mappings (writes through them are the file's, and the
// file's show in them, across fork; past the end of the file is SIGBUS)
// and file locks: flock, POSIX record locks (with F_GETLK, waiting,
// release on any close and on exit, deadlock detection) and open file
// description locks. Needs `process` and `fs_write`.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

static const char *path = "/tmp/locked";

static void ms(int n) {
    struct timespec t = {n / 1000, (n % 1000) * 1000000L};
    nanosleep(&t, 0);
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static sigjmp_buf bus;
static void on_bus(int sig) { siglongjmp(bus, sig); }

// Does touching `p` raise SIGBUS?
static int bus_error(volatile char *p) {
    if (sigsetjmp(bus, 1) == 0) {
        (void)*p;
        return 0;
    }
    return 1;
}

// A shared mapping that reads a hole holds a read-only copy of it. Whatever
// happens to that mapping, a write must fault and reach the file: it's
// seen by read() and by another mapping.
static void written_through(int fd, char *other, char *m, off_t at, char c) {
    char b = 0;
    m[0] = c;
    CHECK(other[at] == c);
    CHECK(pread(fd, &b, 1, at) == 1 && b == c);
}

static void read_only_copies(void) {
    enum { PAGE = 4096, PAGES = 6 };
    int fd = open("/tmp/holes", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0 && ftruncate(fd, PAGES * PAGE) == 0);
    char *other = mmap(0, PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *ro = mmap(0, PAGES * PAGE, PROT_READ, MAP_SHARED, fd, 0);
    char *rw = mmap(0, PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(other != MAP_FAILED && ro != MAP_FAILED && rw != MAP_FAILED);
    volatile char seen;

    // mprotect, from read-only and from nothing at all.
    seen = ro[0];
    CHECK(mprotect(ro, PAGE, PROT_READ | PROT_WRITE) == 0);
    written_through(fd, other, ro, 0, 'p');
    seen = ro[PAGE];
    CHECK(mprotect(ro + PAGE, PAGE, PROT_NONE) == 0);
    CHECK(mprotect(ro + PAGE, PAGE, PROT_READ | PROT_WRITE) == 0);
    written_through(fd, other, ro + PAGE, PAGE, 'n');
    // And back: read-only and writable again, a frame this time.
    CHECK(mprotect(ro, PAGE, PROT_READ) == 0);
    CHECK(mprotect(ro, PAGE, PROT_READ | PROT_WRITE) == 0);
    written_through(fd, other, ro, 0, 'b');

    // mremap moves the copy.
    seen = rw[2 * PAGE];
    char *moved = mremap(rw + 2 * PAGE, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, ro + 2 * PAGE);
    CHECK(moved == ro + 2 * PAGE);
    written_through(fd, other, moved, 2 * PAGE, 'm');

    // fork copies it, into a child that writes.
    seen = rw[3 * PAGE];
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        rw[3 * PAGE] = 'f';
        _exit(0);
    }
    int st;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    written_through(fd, other, rw + 3 * PAGE, 3 * PAGE, 'F');
    CHECK(other[3 * PAGE] == 'F');

    // Something else writes the page: a copy still in a read-only mapping
    // shows it, and goes writable like any other.
    seen = ro[4 * PAGE];
    CHECK(pwrite(fd, "w", 1, 4 * PAGE) == 1 && ro[4 * PAGE] == 'w');
    CHECK(mprotect(ro + 4 * PAGE, PAGE, PROT_READ | PROT_WRITE) == 0);
    written_through(fd, other, ro + 4 * PAGE, 4 * PAGE, 'W');
    (void)seen;
    munmap(ro, PAGES * PAGE);
    munmap(rw, PAGES * PAGE);
    munmap(other, PAGES * PAGE);
    close(fd);
    unlink("/tmp/holes");
}

static void shared_mappings(void) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0 && ftruncate(fd, 8192) == 0);
    char *m = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED);
    char buf[16] = {0};
    strcpy(m, "via map");
    CHECK(pread(fd, buf, 7, 0) == 7 && memcmp(buf, "via map", 7) == 0);
    CHECK(pwrite(fd, "via write", 9, 4096) == 9 && memcmp(m + 4096, "via write", 9) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        m[100] = 'c';
        _exit(0);
    }
    int st;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st));
    CHECK(m[100] == 'c' && pread(fd, buf, 1, 100) == 1 && buf[0] == 'c');
    CHECK(msync(m, 8192, MS_SYNC) == 0);

    // Past the end of the file, and once it shrinks: SIGBUS.
    signal(SIGBUS, on_bus);
    char *big = mmap(0, 3 * 4096, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(big != MAP_FAILED);
    CHECK(!bus_error(big + 4096) && bus_error(big + 8192));
    CHECK(ftruncate(fd, 4096) == 0);
    CHECK(bus_error(m + 4096) && !bus_error(m));
    CHECK(munmap(big, 3 * 4096) == 0 && munmap(m, 8192) == 0);

    // Not open for writing: no writable shared mapping, now or later.
    int ro = open(path, O_RDONLY);
    CHECK(mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, ro, 0) == MAP_FAILED && errno == EACCES);
    char *r = mmap(0, 4096, PROT_READ, MAP_SHARED, ro, 0);
    CHECK(r != MAP_FAILED && memcmp(r, "via map", 7) == 0);
    CHECK(mprotect(r, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    // A later write to the file shows in it.
    CHECK(pwrite(fd, "again", 5, 0) == 5 && memcmp(r, "again", 5) == 0);
    munmap(r, 4096);
    close(ro);
    close(fd);

    // An imported file (two pages of 'A'): reading it through a shared
    // mapping takes copies, and a write, through a mapping or not, shows
    // in every mapping.
    int blob = open("/data/blob", O_RDWR);
    char *rd = mmap(0, 8192, PROT_READ, MAP_SHARED, blob, 0);
    char *rw = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, blob, 0);
    CHECK(rd != MAP_FAILED && rw != MAP_FAILED);
    CHECK(rd[0] == 'A' && rw[0] == 'A' && rd[4096] == 'A');
    CHECK(pwrite(blob, "B", 1, 0) == 1 && rd[0] == 'B' && rw[0] == 'B');
    rw[1] = 'C';
    CHECK(rd[1] == 'C' && pread(blob, buf, 1, 1) == 1 && buf[0] == 'C');
    rw[4096] = 'D';
    CHECK(rd[4096] == 'D');
    munmap(rd, 8192);
    munmap(rw, 8192);
    close(blob);

    read_only_copies();

    // Sealed memfds can't be written through mappings, and can't be sealed
    // while a mapping may write.
    int mf = memfd_create("sealed", MFD_ALLOW_SEALING);
    CHECK(mf >= 0 && ftruncate(mf, 4096) == 0);
    char *w = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, mf, 0);
    CHECK(w != MAP_FAILED);
    CHECK(fcntl(mf, F_ADD_SEALS, F_SEAL_WRITE) == -1 && errno == EBUSY);
    munmap(w, 4096);
    CHECK(fcntl(mf, F_ADD_SEALS, F_SEAL_WRITE) == 0);
    CHECK(mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, mf, 0) == MAP_FAILED && errno == EPERM);
    char *rs = mmap(0, 4096, PROT_READ, MAP_SHARED, mf, 0);
    CHECK(rs != MAP_FAILED && mprotect(rs, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    munmap(rs, 4096);
    close(mf);
}

static void flocks(void) {
    int a = open(path, O_RDWR), b = open(path, O_RDWR);
    CHECK(a >= 0 && b >= 0);
    CHECK(flock(a, LOCK_EX) == 0);
    CHECK(flock(b, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
    CHECK(flock(b, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK);
    // The same open file (dup) holds it already.
    int d = dup(a);
    CHECK(flock(d, LOCK_EX | LOCK_NB) == 0);
    close(d);
    // A child with its own open file waits for it.
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        int c = open(path, O_RDWR);
        long t0 = now_ms();
        if (flock(c, LOCK_EX) != 0) _exit(1);
        _exit(now_ms() - t0 >= 80 ? 0 : 2);
    }
    ms(150);
    CHECK(flock(a, LOCK_UN) == 0);
    int st;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    // Shared locks share; closing the open file drops its lock.
    CHECK(flock(a, LOCK_SH) == 0 && flock(b, LOCK_SH | LOCK_NB) == 0);
    close(b);
    CHECK(flock(a, LOCK_EX | LOCK_NB) == 0);
    close(a);
}

static int setlk(int fd, int cmd, short type, off_t start, off_t len) {
    struct flock fl = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len};
    return fcntl(fd, cmd, &fl);
}

static struct flock getlk(int fd, int cmd, short type, off_t start, off_t len) {
    struct flock fl = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len};
    CHECK(fcntl(fd, cmd, &fl) == 0);
    return fl;
}

static void record_locks(void) {
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    pid_t me = getpid();
    CHECK(setlk(fd, F_SETLK, F_WRLCK, 0, 10) == 0);
    // Our own locks never conflict: this replaces part of it.
    CHECK(setlk(fd, F_SETLK, F_RDLCK, 2, 3) == 0);
    // Neighbours merge.
    CHECK(setlk(fd, F_SETLK, F_WRLCK, 200, 5) == 0 && setlk(fd, F_SETLK, F_WRLCK, 205, 5) == 0);
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        int c = open(path, O_RDWR);
        CHECK(setlk(c, F_SETLK, F_WRLCK, 5, 10) == -1 && (errno == EAGAIN || errno == EACCES));
        struct flock fl = getlk(c, F_GETLK, F_WRLCK, 5, 10);
        CHECK(fl.l_type == F_WRLCK && fl.l_pid == me && fl.l_start == 5 && fl.l_len == 5);
        fl = getlk(c, F_GETLK, F_RDLCK, 2, 3);
        CHECK(fl.l_type == F_UNLCK); // read locks share
        fl = getlk(c, F_GETLK, F_WRLCK, 10, 10);
        CHECK(fl.l_type == F_UNLCK);
        fl = getlk(c, F_GETLK, F_WRLCK, 200, 10);
        CHECK(fl.l_type == F_WRLCK && fl.l_start == 200 && fl.l_len == 10);
        // A range ending at 2^63 is fine.
        CHECK(setlk(c, F_SETLK, F_RDLCK, 1000, 0x7fffffffffffffffLL - 999) == 0);
        CHECK(setlk(c, F_SETLK, F_RDLCK, 10, 10) == 0);
        // Wait for [0, 5): the parent drops it by closing any descriptor
        // for the file.
        write(ready[1], "w", 1);
        long t0 = now_ms();
        CHECK(setlk(c, F_SETLKW, F_WRLCK, 0, 5) == 0);
        CHECK(now_ms() - t0 >= 80);
        _exit(0);
    }
    char ch;
    CHECK(read(ready[0], &ch, 1) == 1);
    ms(150);
    close(open(path, O_RDONLY));
    int st;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    // The child's locks went when it ended.
    CHECK(setlk(fd, F_SETLK, F_WRLCK, 0, 0) == 0);
    CHECK(setlk(fd, F_SETLK, F_UNLCK, 0, 0) == 0);

    // Deadlock: each holds what the other waits for.
    CHECK(setlk(fd, F_SETLK, F_WRLCK, 0, 1) == 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        int c = open(path, O_RDWR);
        CHECK(setlk(c, F_SETLK, F_WRLCK, 1, 1) == 0);
        write(ready[1], "w", 1);
        CHECK(setlk(c, F_SETLKW, F_WRLCK, 0, 1) == 0);
        _exit(0);
    }
    CHECK(read(ready[0], &ch, 1) == 1);
    ms(100);
    CHECK(setlk(fd, F_SETLKW, F_WRLCK, 1, 1) == -1 && errno == EDEADLK);
    CHECK(setlk(fd, F_SETLK, F_UNLCK, 0, 1) == 0);
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    // Open file description locks: two open files in one process conflict.
    int a = open(path, O_RDWR), b = open(path, O_RDWR);
    CHECK(setlk(a, F_OFD_SETLK, F_WRLCK, 100, 10) == 0);
    CHECK(setlk(b, F_OFD_SETLK, F_WRLCK, 105, 1) == -1 && errno == EAGAIN);
    struct flock fl = getlk(b, F_OFD_GETLK, F_WRLCK, 105, 1);
    CHECK(fl.l_type == F_WRLCK && fl.l_pid == -1);
    // And POSIX ones see them.
    CHECK(setlk(fd, F_SETLK, F_WRLCK, 100, 1) == -1 && errno == EAGAIN);
    close(a);
    CHECK(setlk(b, F_OFD_SETLK, F_WRLCK, 105, 1) == 0);
    close(b);
    close(fd);
}

int main(void) {
    shared_mappings();
    flocks();
    record_locks();
    printf("filelocks ok\n");
    return 0;
}
