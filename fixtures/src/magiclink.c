// /proc/self/fd/N as the magic link it is: O_PATH | O_NOFOLLOW opens the
// link itself, and each of openat2's RESOLVE_* says what it says on Linux.
// Passes on Linux as it is.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(c)                                                                          \
    do {                                                                                  \
        if (!(c)) {                                                                       \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);              \
            exit(1);                                                                      \
        }                                                                                 \
    } while (0)
#define FAILS(call, e) CHECK((long)(call) == -1 && errno == (e))

static int open2(int dir, const char *p, long long flags, long long resolve) {
    struct open_how h = {.flags = flags, .resolve = resolve};
    return syscall(SYS_openat2, dir, p, &h, sizeof h);
}

// The descriptor is the link: its type says so, and it reads as the file.
static void is_link_to(int f, const char *want) {
    CHECK(f >= 0);
    struct stat st;
    CHECK(fstat(f, &st) == 0 && S_ISLNK(st.st_mode));
    char b[256] = {0};
    CHECK(readlinkat(f, "", b, sizeof b - 1) > 0);
    CHECK(!strcmp(b, want));
    // A link can be neither read nor listed.
    char c;
    FAILS(read(f, &c, 1), EBADF);
    CHECK(close(f) == 0);
}

int main(int argc, char **argv) {
    const char *file = argc > 1 ? argv[1] : "/bin/magiclink";
    int t = open(file, O_RDONLY);
    CHECK(t >= 0);
    char p[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d", t);
    is_link_to(open(p, O_PATH | O_NOFOLLOW), file);
    FAILS(open(p, O_RDONLY | O_NOFOLLOW), ELOOP);
    // Followed, it's the file.
    int f = open(p, O_PATH);
    struct stat st;
    CHECK(f >= 0 && fstat(f, &st) == 0 && S_ISREG(st.st_mode));
    close(f);
    // From here, with nothing on the way (/proc/self is a link, and /proc
    // another mount), only the link is left for RESOLVE_* to say anything of,
    // and it's only about following one.
    int dir = open("/proc/self/fd", O_PATH | O_DIRECTORY);
    CHECK(dir >= 0);
    char name[16];
    snprintf(name, sizeof name, "%d", t);
    long long all[] = {RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV, RESOLVE_BENEATH};
    for (int i = 0; i < 4; i++) is_link_to(open2(dir, name, O_PATH | O_NOFOLLOW, all[i]), file);
    FAILS(open2(dir, name, O_RDONLY | O_NOFOLLOW, RESOLVE_NO_MAGICLINKS), ELOOP);
    FAILS(open2(dir, name, O_PATH, RESOLVE_NO_MAGICLINKS), ELOOP);
    FAILS(open2(dir, name, O_PATH, RESOLVE_NO_SYMLINKS), ELOOP);
    FAILS(open2(dir, name, O_PATH, RESOLVE_NO_XDEV), EXDEV);
    FAILS(open2(dir, name, O_PATH, RESOLVE_BENEATH), EXDEV);
    FAILS(open2(dir, name, O_PATH, RESOLVE_IN_ROOT), EXDEV);
    // By the whole path the walk has something to say first.
    is_link_to(open2(AT_FDCWD, p, O_PATH | O_NOFOLLOW, RESOLVE_NO_MAGICLINKS), file);
    FAILS(open2(AT_FDCWD, p, O_PATH | O_NOFOLLOW, RESOLVE_NO_SYMLINKS), ELOOP);
    FAILS(open2(AT_FDCWD, p, O_PATH | O_NOFOLLOW, RESOLVE_BENEATH), EXDEV);
    // Many of them cost what any node does, and go when they close.
    for (int i = 0; i < 20000; i++) {
        int l = open(p, O_PATH | O_NOFOLLOW);
        CHECK(l >= 0);
        close(l);
    }
    printf("magiclink ok\n");
    return 0;
}
