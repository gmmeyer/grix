// /proc/<pid>/environ and auxv are their process's owner's (0400), and
// another process opens them only if it may inspect that one: a uid-1000
// child can't read its root parent's, root can read the child's. Run as
// root, with `process`.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

// Bytes read from `path`, or -1 with errno set by open or read.
static ssize_t slurp(const char *path) {
    char buf[4096];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n, total = 0;
    while ((n = read(fd, buf, sizeof buf)) > 0) total += n;
    close(fd);
    return n < 0 ? -1 : total;
}

static int private_mode(const char *path, uid_t owner) {
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & 0777) == 0400 && st.st_uid == owner;
}

static int child(pid_t parent, int ready, int go) {
    char path[64];
    CHECK(setuid(1000) == 0 && getuid() == 1000 && geteuid() == 1000);
    const char *files[] = {"environ", "auxv"};
    for (int i = 0; i < 2; i++) {
        snprintf(path, sizeof path, "/proc/%d/%s", parent, files[i]);
        CHECK(private_mode(path, 0));
        errno = 0;
        CHECK(slurp(path) == -1 && errno == EACCES);
        snprintf(path, sizeof path, "/proc/self/%s", files[i]);
        CHECK(slurp(path) > 0);
    }
    // What isn't private still reads.
    snprintf(path, sizeof path, "/proc/%d/cmdline", parent);
    CHECK(slurp(path) > 0);
    CHECK(write(ready, "r", 1) == 1);
    char c;
    CHECK(read(go, &c, 1) == 1);
    return 0;
}

int main(void) {
    CHECK(getuid() == 0);
    int ready[2], go[2];
    CHECK(pipe(ready) == 0 && pipe(go) == 0);
    pid_t parent = getpid();
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        fflush(stdout);
        _exit(child(parent, ready[1], go[0]));
    }
    char r;
    CHECK(read(ready[0], &r, 1) == 1);
    // Root may inspect anyone: the uid-1000 child's are root's to read.
    char path[64];
    const char *files[] = {"environ", "auxv"};
    for (int i = 0; i < 2; i++) {
        snprintf(path, sizeof path, "/proc/%d/%s", c, files[i]);
        CHECK(private_mode(path, 1000));
        CHECK(slurp(path) > 0);
    }
    CHECK(write(go[1], "g", 1) == 1);
    int status;
    CHECK(waitpid(c, &status, 0) == c && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("procperm ok\n");
    return 0;
}
