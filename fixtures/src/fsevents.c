// inotify for a program's own changes: each step does something and prints
// the events it made, one line each. What it prints is what Linux prints
// (build it natively and run it in an empty directory to see): the test
// compares them line by line.
#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);  \
            fflush(stdout);                                                   \
            _exit(1);                                                         \
        }                                                                     \
    } while (0)

static int ifd;
static struct { int wd; char label[16]; } labels[64];
static int nlabels;
static unsigned cookies[16];
static int ncookies;

static int watch(const char *path, unsigned mask, const char *label) {
    int wd = inotify_add_watch(ifd, path, mask);
    CHECK(wd >= 0);
    labels[nlabels].wd = wd;
    snprintf(labels[nlabels].label, sizeof labels[0].label, "%s", label);
    nlabels++;
    return wd;
}

static const char *label(int wd) {
    for (int i = nlabels - 1; i >= 0; i--) {
        if (labels[i].wd == wd) return labels[i].label;
    }
    return "?";
}

static const struct { unsigned bit; const char *name; } names[] = {
    {IN_ACCESS, "ACCESS"}, {IN_MODIFY, "MODIFY"}, {IN_ATTRIB, "ATTRIB"},
    {IN_CLOSE_WRITE, "CLOSE_WRITE"}, {IN_CLOSE_NOWRITE, "CLOSE_NOWRITE"}, {IN_OPEN, "OPEN"},
    {IN_MOVED_FROM, "MOVED_FROM"}, {IN_MOVED_TO, "MOVED_TO"}, {IN_CREATE, "CREATE"},
    {IN_DELETE, "DELETE"}, {IN_DELETE_SELF, "DELETE_SELF"}, {IN_MOVE_SELF, "MOVE_SELF"},
    {IN_IGNORED, "IGNORED"}, {IN_Q_OVERFLOW, "OVERFLOW"}, {IN_ISDIR, "ISDIR"},
};

// A rename's two halves have one cookie, and nothing else has any: which
// one is its own business, so each prints as the first, second, ...
static int cookie_number(unsigned c) {
    for (int i = 0; i < ncookies; i++) {
        if (cookies[i] == c) return i + 1;
    }
    CHECK(ncookies < 16);
    cookies[ncookies++] = c;
    return ncookies;
}

static void events(const char *step) {
    printf("%s\n", step);
    char buf[8192] __attribute__((aligned(8)));
    for (;;) {
        ssize_t n = read(ifd, buf, sizeof buf);
        if (n < 0) {
            CHECK(errno == EAGAIN);
            return;
        }
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *e = (void *)p;
            printf("  %s", label(e->wd));
            for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) {
                if (e->mask & names[i].bit) printf(" %s", names[i].name);
            }
            if (e->len) printf(" [%s]", e->name);
            if (e->cookie) printf(" cookie%d", cookie_number(e->cookie));
            printf("\n");
            p += sizeof *e + e->len;
        }
    }
}

// What a step made, in no order and once each: how sendfile goes about it
// is Linux's own (it reports MODIFY twice).
static void events_as_a_set(const char *step) {
    printf("%s\n", step);
    char buf[8192] __attribute__((aligned(8)));
    static char lines[16][64];
    int n = 0;
    ssize_t got;
    while ((got = read(ifd, buf, sizeof buf)) > 0) {
        for (char *p = buf; p < buf + got;) {
            struct inotify_event *e = (void *)p;
            char line[64];
            snprintf(line, sizeof line, "  %s %x [%s]", label(e->wd), e->mask, e->len ? e->name : "");
            int seen = 0;
            for (int i = 0; i < n; i++) seen |= !strcmp(lines[i], line);
            if (!seen && n < 16) strcpy(lines[n++], line);
            p += sizeof *e + e->len;
        }
    }
    CHECK(errno == EAGAIN);
    qsort(lines, n, sizeof lines[0], (int (*)(const void *, const void *))strcmp);
    for (int i = 0; i < n; i++) printf("%s\n", lines[i]);
}

static void put(const char *path, const char *text) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text) && close(fd) == 0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc > 1 && !strcmp(argv[1], "--ran")) return 0;
    CHECK(argc > 1 && chdir(argv[1]) == 0);
    ifd = inotify_init1(IN_NONBLOCK);
    CHECK(ifd >= 0);
    CHECK(mkdir("w", 0755) == 0 && mkdir("w/sub", 0755) == 0);
    int wdir = watch("w", IN_ALL_EVENTS, "dir");
    int wsub = watch("w/sub", IN_ALL_EVENTS, "sub");
    (void)wdir;
    (void)wsub;
    char b[64];

    int fd = open("w/f", O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0);
    events("create");
    CHECK(write(fd, "hello", 5) == 5);
    events("write");
    CHECK(pwrite(fd, "x", 1, 1) == 1);
    events("pwrite");
    struct iovec iov = {"yy", 2};
    CHECK(writev(fd, &iov, 1) == 2);
    events("writev");
    CHECK(close(fd) == 0);
    events("close after writing");
    // No write made: still written-for.
    fd = open("w/f", O_WRONLY);
    CHECK(fd >= 0 && close(fd) == 0);
    events("open and close for writing");

    watch("w/f", IN_ALL_EVENTS, "file");
    fd = open("w/f", O_RDONLY);
    CHECK(fd >= 0);
    events("open a watched file");
    CHECK(read(fd, b, sizeof b) == 7);
    events("read");
    CHECK(read(fd, b, sizeof b) == 0);
    events("read at the end");
    CHECK(pread(fd, b, 1, 0) == 1);
    events("pread");
    CHECK(close(fd) == 0);
    events("close after reading");
    CHECK(chmod("w/f", 0600) == 0);
    events("chmod");
    CHECK(chown("w/f", getuid(), getgid()) == 0);
    events("chown");
    struct timeval tv[2] = {{1, 0}, {2, 0}};
    CHECK(utimes("w/f", tv) == 0);
    events("utimes");
    CHECK(setxattr("w/f", "user.a", "1", 1, 0) == 0);
    events("setxattr");
    CHECK(removexattr("w/f", "user.a") == 0);
    events("removexattr");
    CHECK(truncate("w/f", 3) == 0);
    events("truncate");
    fd = open("w/f", O_WRONLY);
    CHECK(fd >= 0 && ftruncate(fd, 2) == 0 && close(fd) == 0);
    events("ftruncate");
    fd = open("w/f", O_WRONLY | O_TRUNC);
    CHECK(fd >= 0 && close(fd) == 0);
    events("open with O_TRUNC");
    fd = open("w/f", O_RDWR);
    CHECK(fd >= 0 && fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 1) == 0 && close(fd) == 0);
    events("a hole");
    // Nothing to read or write: no event.
    fd = open("w/f", O_RDWR);
    CHECK(fd >= 0 && write(fd, "", 0) == 0);
    events("an empty write");
    CHECK(write(fd, "abcd", 4) == 4 && close(fd) == 0);
    fd = open("w/f", O_PATH);
    CHECK(fd >= 0 && close(fd) == 0);
    events("O_PATH");
    struct stat st;
    CHECK(stat("w/f", &st) == 0 && access("w/f", R_OK) == 0);
    events("stat and access");
    fd = open("w/f", O_RDWR);
    char *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(fd >= 0 && m != MAP_FAILED);
    events("mmap");
    m[0] = 'z';
    CHECK(msync(m, 4096, MS_SYNC) == 0 && munmap(m, 4096) == 0 && close(fd) == 0);
    events("written through a mapping");

    int src = open("w/f", O_RDONLY), dst = open("w/copy", O_CREAT | O_WRONLY, 0644);
    CHECK(src >= 0 && dst >= 0);
    events("for copying");
    off_t off = 0;
    CHECK(sendfile(dst, src, &off, 2) == 2);
    events_as_a_set("sendfile");
    CHECK(close(src) == 0 && close(dst) == 0);
    events("copied");

    DIR *d = opendir("w");
    CHECK(d);
    events("opendir");
    while (readdir(d)) {}
    events("readdir");
    CHECK(closedir(d) == 0);
    events("closedir");

    CHECK(mkdir("w/d", 0755) == 0);
    events("mkdir");
    CHECK(symlink("f", "w/l") == 0);
    events("symlink");
    CHECK(link("w/f", "w/h") == 0);
    events("link");
    CHECK(unlink("w/h") == 0);
    events("unlink one of two names");
    CHECK(unlink("w/l") == 0);
    events("unlink a symlink");
    CHECK(mkfifo("w/p", 0600) == 0);
    events("mkfifo");
    CHECK(unlink("w/p") == 0 && rmdir("w/d") == 0);
    events("unlink and rmdir");

    CHECK(rename("w/f", "w/g") == 0);
    events("rename in a directory");
    CHECK(rename("w/g", "w/sub/g") == 0);
    events("rename to another directory");
    CHECK(rename("w/sub/g", "w/f") == 0);
    events("rename back");
    put("w/t", "target");
    watch("w/t", IN_ALL_EVENTS, "target");
    events("a file to replace");
    CHECK(rename("w/f", "w/t") == 0);
    events("rename over a watched file");
    CHECK(rename("w/t", "w/f") == 0);
    events("rename back again");
    CHECK(mkdir("w/m", 0755) == 0);
    watch("w/m", IN_ALL_EVENTS, "moved");
    events("a directory to move");
    CHECK(rename("w/m", "w/sub/m") == 0);
    events("rename a directory");
    CHECK(rmdir("w/sub/m") == 0);
    events("rmdir a watched directory");

    CHECK(unlink("w/f") == 0);
    events("unlink a watched file");

    put("w/open", "x");
    watch("w/open", IN_ALL_EVENTS, "open");
    events("a file to unlink while open");
    fd = open("w/open", O_RDWR);
    CHECK(fd >= 0);
    events("opened");
    CHECK(unlink("w/open") == 0);
    events("unlinked");
    CHECK(write(fd, "y", 1) == 1);
    events("written after unlinking");
    CHECK(close(fd) == 0);
    events("closed after unlinking");

    put("w/one", "x");
    watch("w/one", IN_ACCESS | IN_ONESHOT, "oneshot");
    events("a file to watch once");
    fd = open("w/one", O_RDONLY);
    CHECK(fd >= 0 && read(fd, b, 1) == 1 && read(fd, b, 1) == 0);
    CHECK(pread(fd, b, 1, 0) == 1 && close(fd) == 0);
    events("IN_ONESHOT");

    put("w/narrow", "x");
    int wd = watch("w/narrow", IN_MODIFY, "narrow");
    events("a file to watch for one thing");
    fd = open("w/narrow", O_RDWR);
    CHECK(fd >= 0 && read(fd, b, 1) == 1 && write(fd, "y", 1) == 1 && close(fd) == 0);
    events("IN_MODIFY only");
    CHECK(inotify_add_watch(ifd, "w/narrow", IN_CLOSE) == wd);
    fd = open("w/narrow", O_RDWR);
    CHECK(fd >= 0 && write(fd, "y", 1) == 1 && close(fd) == 0);
    events("changed to IN_CLOSE");
    CHECK(inotify_add_watch(ifd, "w/narrow", IN_ATTRIB | IN_MASK_ADD) == wd);
    CHECK(chmod("w/narrow", 0600) == 0);
    events("IN_MASK_ADD");
    CHECK(inotify_rm_watch(ifd, wd) == 0);
    events("inotify_rm_watch");
    CHECK(unlink("w/narrow") == 0 && unlink("w/one") == 0 && unlink("w/copy") == 0);
    events("unwatched");

    // A program that runs: how many reads it takes is the loader's own.
    char self[256];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 1);
    CHECK(len > 0);
    self[len] = 0;
    int in = open(self, O_RDONLY), out = open("w/prog", O_CREAT | O_WRONLY, 0755);
    CHECK(in >= 0 && out >= 0);
    static char chunk[65536];
    ssize_t got;
    while ((got = read(in, chunk, sizeof chunk)) > 0) CHECK(write(out, chunk, got) == got);
    CHECK(close(in) == 0 && close(out) == 0);
    events_as_a_set("a program to run");
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        execl("w/prog", "prog", "--ran", (char *)0);
        _exit(9);
    }
    int status;
    CHECK(waitpid(c, &status, 0) == c && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    events_as_a_set("exec");
    CHECK(unlink("w/prog") == 0);
    events("no more of it");

    put("w/ex", "x");
    int excl = inotify_add_watch(ifd, "w", IN_ALL_EVENTS | IN_EXCL_UNLINK);
    events("IN_EXCL_UNLINK");
    fd = open("w/ex", O_RDWR);
    CHECK(fd >= 0 && unlink("w/ex") == 0);
    events("unlinked while open");
    CHECK(write(fd, "z", 1) == 1 && close(fd) == 0);
    events("what it does then");
    (void)excl;
    CHECK(rmdir("w/sub") == 0);
    events("rmdir a watched directory in a watched one");
    CHECK(rmdir("w") == 0);
    events("rmdir the last");
    printf("fsevents ok\n");
    return 0;
}
