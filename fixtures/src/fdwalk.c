// A path going on through another process's descriptor: /proc/<pid>/fd/N/name.
// Passes on Linux as it is, as root.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                                                 \
    do {                                                                         \
        if (!(c)) {                                                              \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);     \
            exit(1);                                                             \
        }                                                                        \
    } while (0)
#define FAILS(call, e) CHECK((long)(call) == -1 && errno == (e))

static char dir[64];

// A child with `dir` open on `fd` and a pipe's read end, until it's told.
static int sock;

static pid_t holder(int *fd, int *gone, uid_t uid) {
    int ready[2], stop[2];
    CHECK(pipe(ready) == 0 && pipe(stop) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        close(stop[1]);
        if (uid) CHECK(setuid(uid) == 0);
        int d = open(dir, O_RDONLY | O_DIRECTORY);
        CHECK(d >= 0);
        CHECK(write(ready[1], &d, sizeof d) == sizeof d);
        char c;
        (void)!read(stop[0], &c, 1);
        _exit(0);
    }
    close(ready[1]), close(stop[0]);
    CHECK(read(ready[0], fd, sizeof *fd) == sizeof *fd);
    close(ready[0]);
    *gone = stop[1];
    return pid;
}

static void release(pid_t pid, int stop) {
    close(stop);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && status == 0);
}

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    snprintf(dir, sizeof dir, "/tmp/fdwalk-%d", getpid());
    CHECK(mkdir(dir, 0755) == 0);
    char file[96];
    snprintf(file, sizeof file, "%s/name", dir);
    int f = open(file, O_CREAT | O_WRONLY, 0644);
    CHECK(f >= 0 && write(f, "hello", 5) == 5);
    close(f);
    char sub[96];
    snprintf(sub, sizeof sub, "%s/sub", dir);
    CHECK(mkdir(sub, 0755) == 0);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(sock >= 0);
    int fd, stop;
    pid_t pid = holder(&fd, &stop, 0);
    char path[128], buf[16];

    // Reading through it.
    snprintf(path, sizeof path, "/proc/%d/fd/%d/name", pid, fd);
    int r = open(path, O_RDONLY);
    CHECK(r >= 0);
    CHECK(read(r, buf, sizeof buf) == 5 && !memcmp(buf, "hello", 5));
    close(r);
    struct stat st;
    CHECK(stat(path, &st) == 0 && st.st_size == 5);
    CHECK(access(path, R_OK) == 0);

    // What's missing is missing, and a directory goes on.
    snprintf(path, sizeof path, "/proc/%d/fd/%d/nothing", pid, fd);
    FAILS(open(path, O_RDONLY), ENOENT);
    snprintf(path, sizeof path, "/proc/%d/fd/%d/sub/..", pid, fd);
    CHECK(stat(path, &st) == 0 && S_ISDIR(st.st_mode));

    // Listing it.
    snprintf(path, sizeof path, "/proc/%d/fd/%d/", pid, fd);
    DIR *d = opendir(path);
    CHECK(d != NULL);
    int seen = 0;
    for (struct dirent *e; (e = readdir(d));) seen += !strcmp(e->d_name, "name");
    CHECK(seen == 1);
    closedir(d);

    // Making something there.
    snprintf(path, sizeof path, "/proc/%d/fd/%d/made", pid, fd);
    int m = open(path, O_CREAT | O_WRONLY, 0644);
    CHECK(m >= 0);
    close(m);
    CHECK(unlink(path) == 0);

    // Its descriptor itself: a new open of what's there, and a socket
    // can't be opened that way, its own or another's.
    snprintf(path, sizeof path, "/proc/%d/fd/%d", pid, fd);
    int again = open(path, O_RDONLY | O_DIRECTORY);
    CHECK(again >= 0);
    close(again);
    snprintf(path, sizeof path, "/proc/%d/fd/%d", pid, sock);
    FAILS(open(path, O_RDONLY), ENXIO);
    snprintf(path, sizeof path, "/proc/self/fd/%d", sock);
    FAILS(open(path, O_RDONLY), ENXIO);

    // A descriptor it hasn't got, and one that's no directory.
    snprintf(path, sizeof path, "/proc/%d/fd/%d/name", pid, 900);
    FAILS(open(path, O_RDONLY), ENOENT);
    snprintf(path, sizeof path, "/proc/%d/fd/1/name", pid);
    FAILS(open(path, O_RDONLY), ENOTDIR);
    release(pid, stop);

    // Once it's gone, so is that.
    snprintf(path, sizeof path, "/proc/%d/fd/%d/name", pid, fd);
    FAILS(open(path, O_RDONLY), ENOENT);

    // Another user's isn't open to anyone but root.
    pid = holder(&fd, &stop, 65534);
    snprintf(path, sizeof path, "/proc/%d/fd/%d/name", pid, fd);
    r = open(path, O_RDONLY);
    CHECK(r >= 0);
    close(r);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(setuid(1000) == 0);
        FAILS(open(path, O_RDONLY), EACCES);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && status == 0);
    release(pid, stop);

    CHECK(unlink(file) == 0 && rmdir(sub) == 0 && rmdir(dir) == 0);
    printf("fdwalk ok\n");
    return 0;
}
