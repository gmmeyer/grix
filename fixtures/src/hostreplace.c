// What a program has open or mapped in a live mount stays what it opened,
// whatever the host does to the name meanwhile, as on Linux; a new open
// gets what's there now. Run from the mount, so the program is one of them.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SIZE (1 << 20)
#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);  \
            fflush(stdout);                                                   \
            _exit(1);                                                         \
        }                                                                     \
    } while (0)

static void wait_for(const char *path) {
    struct stat st;
    struct timespec t = {0, 5000000};
    for (int i = 0; i < 12000; i++) {
        if (stat(path, &st) == 0) return;
        nanosleep(&t, 0);
    }
    CHECK(!"the host never answered");
}

// All of [at, at + n) of `fd` is `byte`.
static void reads_as(int fd, off_t at, int n, char byte) {
    char b[4096];
    CHECK(n <= (int)sizeof b && pread(fd, b, n, at) == n);
    for (int i = 0; i < n; i++) CHECK(b[i] == byte);
}

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    int fd = open("/work/f", O_RDONLY);
    CHECK(fd >= 0);
    reads_as(fd, 0, 16, 'A');
    // A mapping outlives its descriptor, and its pages come as they're used.
    int mapped = open("/work/m", O_RDONLY);
    CHECK(mapped >= 0);
    char *m = mmap(0, SIZE, PROT_READ, MAP_PRIVATE, mapped, 0);
    CHECK(m != MAP_FAILED && m[0] == 'A');
    CHECK(close(mapped) == 0);
    int w = open("/work/w", O_RDWR);
    CHECK(w >= 0);
    int gone = open("/work/gone", O_RDONLY);
    CHECK(gone >= 0);
    close(creat("/work/ready", 0644));
    wait_for("/work/go");

    // Whatever the host keeps open for other reasons goes first.
    char path[32], b[16];
    for (int i = 0; i < 40; i++) {
        snprintf(path, sizeof path, "/work/other%d", i);
        int o = open(path, O_RDONLY);
        CHECK(o >= 0 && read(o, b, sizeof b) > 0 && close(o) == 0);
    }
    // And what was read ahead (FRESH_NS).
    struct timespec t = {1, 200000000};
    nanosleep(&t, 0);

    reads_as(fd, SIZE / 2, 4096, 'A');
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == SIZE);
    CHECK(m[SIZE / 2] == 'A');
    // Removed on the host: still there for who has it.
    reads_as(gone, SIZE / 2, 4096, 'A');
    // Written after it's replaced: into what it had, not the new file.
    CHECK(pwrite(w, "x", 1, SIZE / 2) == 1);
    // The name is the new file now.
    int fresh = open("/work/f", O_RDONLY);
    CHECK(fresh >= 0);
    reads_as(fresh, 0, 16, 'B');
    reads_as(fresh, SIZE / 2, 4096, 'B');
    CHECK(fstat(fresh, &st) == 0 && st.st_size == SIZE + 4096);
    CHECK(stat("/work/f", &st) == 0 && st.st_size == SIZE + 4096);
    // Both at once.
    reads_as(fd, SIZE / 4, 4096, 'A');
    reads_as(fresh, SIZE / 4, 4096, 'B');
    // Code this program hasn't run yet is in pages it hasn't read, of a
    // file that's gone from the host by now.
    printf("float %.2f\n", strtod("1.5", 0) * 2);
    printf("hostreplace ok\n");
    return 0;
}
