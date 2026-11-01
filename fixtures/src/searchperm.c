// A path's directories need search permission, whoever asks: EACCES at the
// first that refuses, for every way of naming something through one. Starts
// as root, to give things owners, and gives that up. Passes on Linux as it is.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                                                    \
    do {                                                                            \
        if (!(c)) {                                                                 \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);        \
            exit(1);                                                                \
        }                                                                           \
    } while (0)
#define FAILS(call, e) CHECK((long)(call) == -1 && errno == (e))

#define USER 1000
#define GROUP 1000
#define OTHER_USER 1001
#define IN_GROUP 2000
#define BASE "/tmp/searchperm"

static void make(const char *dir, int mode, int uid, int gid) {
    CHECK(mkdir(dir, 0700) == 0);
    char f[128];
    snprintf(f, sizeof f, "%s/f", dir);
    int fd = open(f, O_CREAT | O_WRONLY, 0666);
    CHECK(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
    CHECK(chmod(f, 0666) == 0);
    CHECK(mkdir(strcat(strcpy(f, dir), "/sub"), 0777) == 0);
    CHECK(chmod(f, 0777) == 0);
    CHECK(chown(dir, uid, gid) == 0 && chmod(dir, mode) == 0);
}

// What everyone may do with `d`/f, or not.
static void through(const char *d, int may) {
    char f[128], g[128];
    struct stat st;
    snprintf(f, sizeof f, "%s/f", d);
    if (may) {
        CHECK(stat(f, &st) == 0);
        int fd = open(f, O_RDONLY);
        CHECK(fd >= 0);
        close(fd);
        return;
    }
    FAILS(stat(f, &st), EACCES);
    FAILS(lstat(f, &st), EACCES);
    FAILS(open(f, O_RDONLY), EACCES);
    FAILS(access(f, F_OK), EACCES);
    FAILS(readlink(f, g, sizeof g), EACCES);
    FAILS(chmod(f, 0600), EACCES);
    FAILS(truncate(f, 0), EACCES);
    FAILS(unlink(f), EACCES);
    snprintf(g, sizeof g, "%s/new", d);
    FAILS(open(g, O_CREAT | O_WRONLY, 0600), EACCES);
    FAILS(mkdir(g, 0700), EACCES);
    FAILS(symlink("x", g), EACCES);
    FAILS(link("/tmp", g), EACCES);
    FAILS(rename(f, g), EACCES);
    // Further down, and ".." and "." on the way.
    snprintf(g, sizeof g, "%s/sub/..", d);
    FAILS(stat(g, &st), EACCES);
    snprintf(g, sizeof g, "%s/.", d);
    FAILS(stat(g, &st), EACCES);
    snprintf(g, sizeof g, "%s/sub", d);
    FAILS(chdir(g), EACCES);
    // Through a link, too.
    CHECK(symlink(f, BASE "/link") == 0);
    FAILS(stat(BASE "/link", &st), EACCES);
    CHECK(unlink(BASE "/link") == 0);
}

int main(void) {
    struct stat st;
    CHECK(geteuid() == 0);
    CHECK(mkdir(BASE, 0777) == 0 && chmod(BASE, 0777) == 0);
    make(BASE "/owner_x", 0100, USER, GROUP);
    make(BASE "/owner_rw", 0600, USER, GROUP);
    make(BASE "/group_x", 0010, 0, IN_GROUP);
    make(BASE "/group_none", 0601, USER, GROUP);
    make(BASE "/other_x", 0001, 0, 0);
    make(BASE "/other_none", 0770, 0, 0);
    make(BASE "/nothing", 0000, USER, GROUP);
    // An open directory, for what a descriptor keeps.
    int fix = open(BASE "/owner_rw", O_PATH | O_DIRECTORY);
    CHECK(fix >= 0);
    // Root goes through anything.
    through(BASE "/nothing", 1);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid) {
        int status;
        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFEXITED(status));
        if (WEXITSTATUS(status)) return WEXITSTATUS(status);
        through(BASE "/nothing", 1);
        printf("searchperm ok\n");
        return 0;
    }
    gid_t groups[] = {IN_GROUP};
    CHECK(setgroups(1, groups) == 0 && setgid(GROUP) == 0 && setuid(USER) == 0);
    // By the class that applies, and no other: the owner's bits for the
    // owner, whatever the others say, and so on.
    through(BASE "/owner_x", 1);
    through(BASE "/owner_rw", 0);
    through(BASE "/group_x", 1);
    through(BASE "/group_none", 0);
    through(BASE "/other_x", 1);
    through(BASE "/other_none", 0);
    through(BASE "/nothing", 0);
    // Listing is read, not search: names without what they are.
    DIR *d = opendir(BASE "/owner_rw");
    CHECK(d != 0);
    int names = 0;
    while (readdir(d)) names++;
    CHECK(names == 4);
    closedir(d);
    // And search isn't read.
    CHECK(opendir(BASE "/owner_x") == 0 && errno == EACCES);
    // The directory itself, by its own name, needs only what's above it.
    CHECK(stat(BASE "/nothing", &st) == 0);
    // A descriptor is past what's above it, but not what's in it.
    FAILS(openat(fix, "f", O_RDONLY), EACCES);
    // Where a process already is, as in any directory.
    CHECK(chdir(BASE "/owner_x") == 0);
    CHECK(stat("f", &st) == 0 && stat(".", &st) == 0);
    FAILS(chdir(BASE "/owner_rw"), EACCES);
    // A magic link goes straight there.
    char p[64];
    int t = open(BASE "/owner_x/f", O_RDONLY);
    CHECK(t >= 0);
    CHECK(chdir("/") == 0);
    CHECK(chmod(BASE "/owner_x", 0) == 0);
    snprintf(p, sizeof p, "/proc/self/fd/%d", t);
    CHECK(stat(p, &st) == 0);
    FAILS(stat(BASE "/owner_x/f", &st), EACCES);
    exit(0);
}
