// Holes in files and shared memory: fallocate(FALLOC_FL_PUNCH_HOLE) and
// MADV_REMOVE, on memory-backed files as Linux's tmpfs does them. The same
// program passes on Linux: pass it a scratch file's path, of 3 pages of 'I'.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096
#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);  \
            fflush(stdout);                                                   \
            _exit(1);                                                         \
        }                                                                     \
    } while (0)
#define FAILS(c, e) CHECK((long)(c) == -1 && errno == (e))
#define PUNCH (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)

// A memory file of `n` pages of 'A'.
static int file(int n, unsigned flags) {
    int fd = memfd_create("holes", flags);
    CHECK(fd >= 0);
    static char page[PAGE];
    memset(page, 'A', PAGE);
    for (int i = 0; i < n; i++) CHECK(write(fd, page, PAGE) == PAGE);
    return fd;
}

static void reads_as(int fd, off_t at, int n, char byte) {
    static char b[PAGE * 4];
    CHECK(n <= (int)sizeof b && pread(fd, b, n, at) == n);
    for (int i = 0; i < n; i++) CHECK(b[i] == byte);
}

// What a child sees at `p`, whoever made it.
static int peek(char *p) {
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) _exit(*(volatile char *)p);
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st));
    return WEXITSTATUS(st);
}

static void whole_pages(void) {
    int fd = file(3, 0);
    struct stat before, after;
    CHECK(fstat(fd, &before) == 0);
    CHECK(fallocate(fd, PUNCH, PAGE, PAGE) == 0);
    CHECK(fstat(fd, &after) == 0 && after.st_size == 3 * PAGE && after.st_blocks < before.st_blocks);
    reads_as(fd, 0, PAGE, 'A');
    reads_as(fd, PAGE, PAGE, 0);
    reads_as(fd, 2 * PAGE, PAGE, 'A');
    // It's a hole, not a file that's shrunk or gone: written, it's there.
    CHECK(pwrite(fd, "B", 1, PAGE + 7) == 1);
    reads_as(fd, PAGE + 7, 1, 'B');
    reads_as(fd, PAGE, 7, 0);
    close(fd);
}

static void part_of_a_page(void) {
    int fd = file(3, 0);
    // Across a page's end: both pages keep what's outside it.
    CHECK(fallocate(fd, PUNCH, PAGE - 10, 20) == 0);
    reads_as(fd, 0, PAGE - 10, 'A');
    reads_as(fd, PAGE - 10, 20, 0);
    reads_as(fd, PAGE + 10, PAGE - 10, 'A');
    // Within one.
    CHECK(fallocate(fd, PUNCH, 2 * PAGE + 100, 5) == 0);
    reads_as(fd, 2 * PAGE + 95, 5, 'A');
    reads_as(fd, 2 * PAGE + 100, 5, 0);
    reads_as(fd, 2 * PAGE + 105, 5, 'A');
    close(fd);
}

static void past_the_end(void) {
    int fd = file(2, 0);
    CHECK(fallocate(fd, PUNCH, PAGE, 10 * PAGE) == 0);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == 2 * PAGE);
    reads_as(fd, 0, PAGE, 'A');
    reads_as(fd, PAGE, PAGE, 0);
    // All of it past the end.
    CHECK(fallocate(fd, PUNCH, 8 * PAGE, PAGE) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 2 * PAGE);
    close(fd);
}

static void refusals(void) {
    int fd = file(2, MFD_ALLOW_SEALING);
    // Only with KEEP_SIZE.
    FAILS(fallocate(fd, FALLOC_FL_PUNCH_HOLE, 0, PAGE), EOPNOTSUPP);
    FAILS(fallocate(fd, PUNCH, -1, PAGE), EINVAL);
    FAILS(fallocate(fd, PUNCH, 0, 0), EINVAL);
    FAILS(fallocate(fd, PUNCH, 0, -1), EINVAL);
    FAILS(fallocate(fd, PUNCH, 1, 0x7fffffffffffffffll), EFBIG);
    char path[32];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    int ro = open(path, O_RDONLY);
    CHECK(ro >= 0);
    FAILS(fallocate(ro, PUNCH, 0, PAGE), EBADF);
    close(ro);
    reads_as(fd, 0, 2 * PAGE, 'A');
    // A seal against writing is one against this.
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == 0);
    FAILS(fallocate(fd, PUNCH, 0, PAGE), EPERM);
    reads_as(fd, 0, PAGE, 'A');
    close(fd);
}

// Bytes that came with the file: they're not to show through.
static void imported(const char *path) {
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0);
    CHECK(fallocate(fd, PUNCH, PAGE, PAGE) == 0);
    reads_as(fd, 0, PAGE, 'I');
    reads_as(fd, PAGE, PAGE, 0);
    reads_as(fd, 2 * PAGE, PAGE, 'I');
    CHECK(fallocate(fd, PUNCH, 2 * PAGE - 5, 10) == 0);
    reads_as(fd, 2 * PAGE - 5, 10, 0);
    reads_as(fd, 2 * PAGE + 5, 5, 'I');
    close(fd);
}

// Mappings of it see the hole, in every process, and go on working.
static void mapped(void) {
    int fd = file(3, 0);
    char *m = mmap(0, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED && m[PAGE] == 'A' && m[2 * PAGE] == 'A');
    fflush(stdout);
    int up[2], down[2];
    CHECK(pipe(up) == 0 && pipe(down) == 0);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        char b;
        // Mapped here too, and read.
        CHECK(m[PAGE] == 'A' && write(up[1], "r", 1) == 1 && read(down[0], &b, 1) == 1);
        CHECK(m[PAGE] == 0 && m[0] == 'A');
        m[PAGE] = 'C';
        _exit(0);
    }
    char b;
    CHECK(read(up[0], &b, 1) == 1);
    CHECK(fallocate(fd, PUNCH, PAGE, PAGE) == 0);
    CHECK(m[PAGE] == 0 && m[0] == 'A' && m[2 * PAGE] == 'A');
    CHECK(write(down[1], "g", 1) == 1);
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    // The child's write is the file's, and so this mapping's.
    CHECK(m[PAGE] == 'C');
    reads_as(fd, PAGE, 1, 'C');
    close(fd);
}

// A read of a hole maps a copy: it can't be left showing what was there.
static void mapped_before_it_was_written(void) {
    int fd = file(1, 0);
    CHECK(ftruncate(fd, 2 * PAGE) == 0);
    char *m = mmap(0, 2 * PAGE, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED && m[PAGE] == 0);
    CHECK(pwrite(fd, "w", 1, PAGE) == 1 && m[PAGE] == 'w');
    CHECK(fallocate(fd, PUNCH, PAGE, PAGE) == 0 && m[PAGE] == 0);
    close(fd);
}

// However big it is, it takes as long as what's there.
static void huge(void) {
    int fd = file(0, 0);
    off_t top = 1ll << 45;
    CHECK(ftruncate(fd, top) == 0);
    for (int i = 1; i < 8; i++) CHECK(pwrite(fd, "x", 1, top / 8 * i) == 1);
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    CHECK(fallocate(fd, PUNCH, 0, top) == 0);
    clock_gettime(CLOCK_MONOTONIC, &b);
    CHECK(b.tv_sec - a.tv_sec < 5);
    reads_as(fd, top / 8, 1, 0);
    close(fd);
}

// What's punched is given back: this much at once wouldn't fit.
static void given_back(long mb) {
    int fd = file(0, 0);
    static char chunk[1 << 20];
    memset(chunk, 'x', sizeof chunk);
    for (int round = 0; round < 16; round++) {
        for (long i = 0; i < mb; i++) CHECK(pwrite(fd, chunk, sizeof chunk, i << 20) == sizeof chunk);
        CHECK(fallocate(fd, PUNCH, 0, mb << 20) == 0);
    }
    close(fd);
}

// MADV_REMOVE: the same, by address.
static void removing_by_address(void) {
    char *s = mmap(0, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(s != MAP_FAILED);
    memset(s, 'S', 3 * PAGE);
    CHECK(peek(s + PAGE) == 'S');
    CHECK(madvise(s + PAGE, PAGE, MADV_REMOVE) == 0);
    CHECK(s[0] == 'S' && s[PAGE] == 0 && s[2 * PAGE] == 'S');
    CHECK(peek(s + PAGE) == 0);
    s[PAGE] = 'T';
    CHECK(peek(s + PAGE) == 'T');

    int fd = file(3, 0);
    char *m = mmap(0, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, PAGE);
    CHECK(m != MAP_FAILED && m[PAGE] == 'A');
    CHECK(madvise(m + PAGE, PAGE, MADV_REMOVE) == 0 && m[PAGE] == 0);
    reads_as(fd, 2 * PAGE, PAGE, 0);
    reads_as(fd, PAGE, PAGE, 'A');
    // A mapping that can't write, of a file that can.
    char *ro = mmap(0, PAGE, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(ro != MAP_FAILED && ro[0] == 'A');
    CHECK(madvise(ro, PAGE, MADV_REMOVE) == 0 && ro[0] == 0);
    close(fd);

    int id = shmget(IPC_PRIVATE, 2 * PAGE, IPC_CREAT | 0600);
    CHECK(id >= 0);
    char *seg = shmat(id, 0, 0);
    CHECK(seg != (void *)-1 && shmctl(id, IPC_RMID, 0) == 0);
    memset(seg, 'V', 2 * PAGE);
    CHECK(madvise(seg, PAGE, MADV_REMOVE) == 0 && seg[0] == 0 && seg[PAGE] == 'V');
    CHECK(shmdt(seg) == 0);

    // A seal stops this way too.
    fd = file(1, MFD_ALLOW_SEALING);
    m = mmap(0, PAGE, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED && m[0] == 'A');
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == 0);
    FAILS(madvise(m, PAGE, MADV_REMOVE), EPERM);
    CHECK(m[0] == 'A');
    close(fd);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    CHECK(argc > 2);
    whole_pages();
    part_of_a_page();
    past_the_end();
    refusals();
    imported(argv[1]);
    mapped();
    mapped_before_it_was_written();
    huge();
    given_back(atol(argv[2]));
    removing_by_address();
    printf("holes ok\n");
    return 0;
}
