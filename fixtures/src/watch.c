// inotify on a live mount, for changes made on the host. Usage:
//   watch DIR CTL
// Watches DIR (and DIR/sub), and for each step: reads what it has of DIR
// (so the kernel has it fresh), says it's ready by making CTL/<step>, and
// waits for the host's change to show up as events, and in what it reads.
//   watch --snap DIR CTL
// Watches DIR, then waits for a line on stdin (where a snapshot is taken),
// then for the host to make DIR/new.txt.
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static int ifd;
static const char *dir, *ctl;
static char buf[4096] __attribute__((aligned(8)));
static size_t have, at;

static void die(const char *what) {
    printf("FAIL: %s (errno %d)\n", what, errno);
    exit(1);
}

static void path(char *out, const char *name) { snprintf(out, 512, "%s/%s", dir, name); }

// Everything the kernel might keep of DIR: its listing, and each file's
// attributes and first bytes.
static void warm(void) {
    DIR *d = opendir(dir);
    if (!d) die("opendir");
    struct dirent *e;
    while ((e = readdir(d))) {
        char p[512];
        path(p, e->d_name);
        struct stat st;
        stat(p, &st);
        int fd = open(p, O_RDONLY);
        if (fd >= 0) {
            char b[64];
            read(fd, b, sizeof b);
            close(fd);
        }
    }
    closedir(d);
}

static void ready(int step) {
    warm();
    char p[512];
    snprintf(p, sizeof p, "%s/%d", ctl, step);
    int fd = open(p, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) die("ready");
    close(fd);
}

// The next event, waiting for it with poll (60 s at most).
static struct inotify_event *next(void) {
    if (at >= have) {
        struct pollfd p = {ifd, POLLIN, 0};
        if (poll(&p, 1, 60000) != 1) die("no event in time");
        ssize_t n = read(ifd, buf, sizeof buf);
        if (n <= 0) die("read");
        have = n;
        at = 0;
    }
    struct inotify_event *ev = (struct inotify_event *)(buf + at);
    at += sizeof *ev + ev->len;
    return ev;
}

// Events until one for `wd` with all of `mask` named `name` ("" for none).
static struct inotify_event *expect(int wd, unsigned mask, const char *name) {
    for (;;) {
        struct inotify_event *ev = next();
        if (ev->mask & IN_Q_OVERFLOW) die("overflow");
        const char *n = ev->len ? ev->name : "";
        if (ev->wd == wd && (ev->mask & mask) == mask && strcmp(n, name) == 0) return ev;
    }
}

// What the file holds now ("-" for none), and its size.
static void show(const char *name) {
    char p[512], b[256];
    path(p, name);
    struct stat st;
    int fd = open(p, O_RDONLY);
    if (fd < 0) {
        printf("  %s: errno %d\n", name, errno);
        return;
    }
    ssize_t n = read(fd, b, sizeof b - 1);
    if (n < 0) die("read file");
    b[n] = 0;
    if (fstat(fd, &st) < 0) die("fstat");
    close(fd);
    for (char *c = b; *c; c++)
        if (*c == '\n') *c = '|';
    printf("  %s: \"%s\" size %lld mode %o\n", name, b, (long long)st.st_size, st.st_mode & 0777);
}

// Until `name` holds `want` (it may take another event or two: a write
// can show up before all of it has been made).
static void until(int wd, const char *name, const char *want) {
    char p[512], b[256];
    path(p, name);
    for (;;) {
        int fd = open(p, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, b, sizeof b - 1);
            close(fd);
            if (n >= 0) {
                b[n] = 0;
                if (strcmp(b, want) == 0) return;
            }
        }
        expect(wd, IN_MODIFY, name);
    }
}

// Watched before a snapshot, and after it's restored.
static int snap(void) {
    int wd = inotify_add_watch(ifd, dir, IN_CREATE);
    if (wd < 0) die("inotify_add_watch");
    char line[64];
    if (!fgets(line, sizeof line, stdin)) die("stdin");
    // What changed while the snapshot sat on disk is lost, and it says so.
    struct inotify_event *ev = next();
    printf("then: %s\n", ev->wd == -1 && ev->mask == IN_Q_OVERFLOW ? "IN_Q_OVERFLOW" : "something else");
    ready(1);
    expect(wd, IN_CREATE, "new.txt");
    printf("IN_CREATE new.txt\n");
    show("new.txt");
    return 0;
}

int main(int argc, char **argv) {
    int snapshot = argc == 4 && strcmp(argv[1], "--snap") == 0;
    if (argc != 3 && !snapshot) return 2;
    dir = argv[argc - 2];
    ctl = argv[argc - 1];
    setvbuf(stdout, NULL, _IONBF, 0);
    ifd = inotify_init1(IN_CLOEXEC);
    if (ifd < 0) die("inotify_init1");
    if (snapshot) return snap();
    unsigned all = IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO;
    int wd = inotify_add_watch(ifd, dir, all);
    char sub[512];
    path(sub, "sub");
    int swd = inotify_add_watch(ifd, sub, IN_DELETE_SELF);
    if (wd < 0 || swd < 0) die("inotify_add_watch");
    // The same node again: the same watch.
    if (inotify_add_watch(ifd, dir, all) != wd) die("watched twice");
    int avail = -1;
    ioctl(ifd, FIONREAD, &avail);
    printf("watching (%d bytes queued)\n", avail);

    ready(1); // the host makes new.txt
    expect(wd, IN_CREATE, "new.txt");
    printf("IN_CREATE new.txt\n");
    until(wd, "new.txt", "one\n");
    show("new.txt");

    ready(2); // ... appends to it
    expect(wd, IN_MODIFY, "new.txt");
    until(wd, "new.txt", "one\ntwo\n");
    printf("IN_MODIFY new.txt\n");
    show("new.txt");

    ready(3); // ... writes it over, shorter
    expect(wd, IN_MODIFY, "new.txt");
    until(wd, "new.txt", "3\n");
    printf("IN_MODIFY new.txt\n");
    show("new.txt");

    ready(4); // ... renames it
    struct inotify_event *from = expect(wd, IN_MOVED_FROM, "new.txt");
    unsigned cookie = from->cookie;
    struct inotify_event *to = expect(wd, IN_MOVED_TO, "renamed.txt");
    printf("IN_MOVED_FROM new.txt, IN_MOVED_TO renamed.txt, cookies %s\n",
           cookie && to->cookie == cookie ? "match" : "differ");
    show("new.txt");
    show("renamed.txt");

    ready(5); // ... changes attr.txt's mode
    expect(wd, IN_ATTRIB, "attr.txt");
    printf("IN_ATTRIB attr.txt\n");
    show("attr.txt");

    ready(6); // ... removes renamed.txt
    expect(wd, IN_DELETE, "renamed.txt");
    printf("IN_DELETE renamed.txt\n");
    show("renamed.txt");

    ready(7); // ... removes sub
    expect(swd, IN_DELETE_SELF, "");
    expect(swd, IN_IGNORED, "");
    printf("sub: IN_DELETE_SELF, IN_IGNORED\n");
    if (inotify_rm_watch(ifd, swd) == 0 || errno != EINVAL) die("sub's watch should be gone");

    // Removing a watch says so too.
    if (inotify_rm_watch(ifd, wd) < 0) die("inotify_rm_watch");
    expect(wd, IN_IGNORED, "");
    printf("removed: IN_IGNORED\n");

    // A buffer too small for the next event.
    int fd2 = inotify_init1(IN_NONBLOCK);
    if (read(fd2, buf, sizeof buf) >= 0 || errno != EAGAIN) die("empty read should be EAGAIN");
    int w2 = inotify_add_watch(fd2, dir, IN_CREATE);
    inotify_rm_watch(fd2, w2);
    if (read(fd2, buf, 8) >= 0 || errno != EINVAL) die("short read should be EINVAL");
    printf("done\n");
    return 0;
}
