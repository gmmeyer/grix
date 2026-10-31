// O_TMPFILE in a directory of a live mount, and linkat naming the file
// there. Built with -DON_LINUX it runs on Linux itself, to check what this
// expects: `dir` on one file system and `other` on another.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);  \
            fflush(stdout);                                                   \
            _exit(1);                                                         \
        }                                                                     \
    } while (0)
#define FAILS(c, e) CHECK((long)(c) == -1 && errno == (e))

static const char *dir, *other;
static char paths[8][256];

static const char *at(const char *d, const char *name) {
    static int i;
    char *p = paths[i++ % 8];
    snprintf(p, sizeof paths[0], "%s/%s", d, name);
    return p;
}

// Names `fd`, as glibc's documentation says to.
static int name_it(int fd, const char *path) {
    char self[64];
    snprintf(self, sizeof self, "/proc/self/fd/%d", fd);
    return linkat(AT_FDCWD, self, AT_FDCWD, path, AT_SYMLINK_FOLLOW);
}

static int entries(const char *d) {
    DIR *h = opendir(d);
    CHECK(h);
    int n = 0;
    while (readdir(h)) n++;
    closedir(h);
    return n;
}

static void gets_a_name(void) {
    int before = entries(dir);
    int fd = open(dir, O_TMPFILE | O_RDWR, 0640);
    CHECK(fd >= 0);
    // Past a chunk of what crosses to the host at once, with a hole.
    static char big[300000];
    memset(big, 'x', sizeof big);
    CHECK(write(fd, big, sizeof big) == sizeof big);
    CHECK(pwrite(fd, "tail", 4, 3 << 20) == 4);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_nlink == 0 && st.st_size == (3 << 20) + 4);
    CHECK(S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0640);
    // Nobody can see it.
    CHECK(entries(dir) == before);
    CHECK(name_it(fd, at(dir, "named")) == 0);
    CHECK(entries(dir) == before + 1);
    CHECK(fstat(fd, &st) == 0 && st.st_nlink == 1 && st.st_size == (3 << 20) + 4);
    struct stat by_name;
    CHECK(stat(at(dir, "named"), &by_name) == 0);
    CHECK(by_name.st_size == st.st_size && (by_name.st_mode & 0777) == 0640);
    // What was written is there, by the name.
    int again = open(at(dir, "named"), O_RDONLY);
    CHECK(again >= 0);
    static char got[300000];
    CHECK(read(again, got, sizeof got) == sizeof got && !memcmp(got, big, sizeof big));
    char b[8] = {0};
    CHECK(pread(again, b, 4, 1 << 20) == 4 && !memcmp(b, "\0\0\0\0", 4));
    CHECK(pread(again, b, 4, 3 << 20) == 4 && !memcmp(b, "tail", 4));
    // The descriptor it had is that file: each sees what the other wrote.
    CHECK(pwrite(fd, "more", 4, 0) == 4);
    CHECK(pread(again, b, 4, 0) == 4 && !memcmp(b, "more", 4));
    CHECK(lseek(fd, 0, SEEK_SET) == 0 && read(fd, b, 4) == 4 && !memcmp(b, "more", 4));
    CHECK(close(fd) == 0 && close(again) == 0);
    CHECK(unlink(at(dir, "named")) == 0);
    CHECK(entries(dir) == before);
}

static void stays_unnamed(void) {
    int before = entries(dir);
    // Closed unnamed: gone, and nothing was left behind.
    int fd = open(dir, O_TMPFILE | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
    CHECK(entries(dir) == before);
    // A name that's taken: EEXIST, and both go on as they were.
    int taken = open(at(dir, "taken"), O_CREAT | O_WRONLY, 0644);
    CHECK(taken >= 0 && write(taken, "old", 3) == 3 && close(taken) == 0);
    fd = open(dir, O_TMPFILE | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "new", 3) == 3);
    FAILS(name_it(fd, at(dir, "taken")), EEXIST);
    char b[4] = {0};
    CHECK(pread(fd, b, 3, 0) == 3 && !memcmp(b, "new", 3));
    int r = open(at(dir, "taken"), O_RDONLY);
    CHECK(r >= 0 && read(r, b, 3) == 3 && !memcmp(b, "old", 3) && close(r) == 0);
    // Still able to take another.
    CHECK(name_it(fd, at(dir, "second")) == 0);
    CHECK(unlink(at(dir, "second")) == 0 && unlink(at(dir, "taken")) == 0 && close(fd) == 0);
}

static void o_excl_never_gets_one(void) {
    int fd = open(dir, O_TMPFILE | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "x", 1) == 1);
    FAILS(name_it(fd, at(dir, "excl")), ENOENT);
    CHECK(access(at(dir, "excl"), F_OK) == -1 && errno == ENOENT);
    CHECK(close(fd) == 0);
    fd = open(other, O_TMPFILE | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0);
    FAILS(name_it(fd, at(other, "excl")), ENOENT);
    CHECK(close(fd) == 0);
}

static void only_in_its_own_mount(void) {
    int fd = open(dir, O_TMPFILE | O_RDWR, 0600);
    CHECK(fd >= 0);
    FAILS(name_it(fd, at(other, "crossed")), EXDEV);
    CHECK(close(fd) == 0);
    fd = open(other, O_TMPFILE | O_RDWR, 0600);
    CHECK(fd >= 0);
    FAILS(name_it(fd, at(dir, "crossed")), EXDEV);
    CHECK(close(fd) == 0);
}

static void mapped_privately(void) {
    int fd = open(dir, O_TMPFILE | O_RDWR, 0600);
    CHECK(fd >= 0 && pwrite(fd, "mapped", 6, 0) == 6);
    char *m = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(m != MAP_FAILED && !memcmp(m, "mapped", 6));
    CHECK(name_it(fd, at(dir, "mapped")) == 0);
    CHECK(!memcmp(m, "mapped", 6));
    CHECK(unlink(at(dir, "mapped")) == 0 && close(fd) == 0);
}

// A shared mapping is the file's own pages, which here are the sandbox's.
static void mapped_shared(void) {
    int fd = open(dir, O_TMPFILE | O_RDWR, 0600);
    CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
    char *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED);
    m[0] = 's';
#ifdef ON_LINUX
    CHECK(name_it(fd, at(dir, "shared")) == 0);
    CHECK(unlink(at(dir, "shared")) == 0);
#else
    FAILS(name_it(fd, at(dir, "shared")), EOPNOTSUPP);
    CHECK(access(at(dir, "shared"), F_OK) == -1 && m[0] == 's');
    // Unmapped, it can.
    CHECK(munmap(m, 4096) == 0);
    CHECK(name_it(fd, at(dir, "shared")) == 0);
    int r = open(at(dir, "shared"), O_RDONLY);
    char b;
    CHECK(r >= 0 && read(r, &b, 1) == 1 && b == 's' && close(r) == 0);
    CHECK(unlink(at(dir, "shared")) == 0);
#endif
    CHECK(close(fd) == 0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    CHECK(argc > 2);
    dir = argv[1];
    other = argv[2];
    umask(022);
    if (argc > 3 && !strcmp(argv[3], "shared")) {
        mapped_shared();
        printf("hosttmpfile shared ok\n");
        return 0;
    }
    if (argc > 3 && !strcmp(argv[3], "plain")) {
        int fd = open(dir, O_TMPFILE | O_RDWR, 0600);
        CHECK(fd >= 0 && write(fd, "x", 1) == 1);
        CHECK(name_it(fd, at(dir, "plain")) == 0 && unlink(at(dir, "plain")) == 0);
        printf("plain ok\n");
        return 0;
    }
    if (argc > 3 && !strcmp(argv[3], "readonly")) {
        FAILS(open(dir, O_TMPFILE | O_RDWR, 0600), EROFS);
        printf("hosttmpfile readonly ok\n");
        return 0;
    }
    gets_a_name();
    stays_unnamed();
    o_excl_never_gets_one();
    only_in_its_own_mount();
    mapped_privately();
    printf("hosttmpfile ok\n");
    return 0;
}
