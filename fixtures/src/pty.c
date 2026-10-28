// Pseudo-terminals: /dev/ptmx and /dev/pts/N, the line discipline
// (canonical editing, echo, end-of-file, raw mode, VMIN/VTIME, output
// processing), controlling terminals and their signals (^C, ^Z, SIGWINCH,
// SIGTTIN for a background read, SIGHUP when the master closes), and
// /dev/tty. Needs `process`.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/select.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

static int master, slave;
static char sname[64];

static void put(int fd, const char *s) { CHECK(write(fd, s, strlen(s)) == (ssize_t)strlen(s)); }

// Read exactly what's expected (it may come in pieces).
static void expect(int fd, const char *want) {
    char buf[256];
    size_t n = strlen(want), got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        CHECK(r > 0);
        got += r;
    }
    buf[got] = 0;
    if (memcmp(buf, want, n) != 0) {
        printf("FAILED: read %s, wanted %s\n", buf, want);
        exit(1);
    }
}

// Nothing (more) to read right now.
static int quiet(int fd) {
    struct pollfd p = {fd, POLLIN, 0};
    return poll(&p, 1, 50) == 0;
}

static void open_pair(void) {
    master = posix_openpt(O_RDWR | O_NOCTTY);
    CHECK(master >= 0);
    CHECK(grantpt(master) == 0 && unlockpt(master) == 0);
    CHECK(ptsname_r(master, sname, sizeof sname) == 0);
    slave = open(sname, O_RDWR | O_NOCTTY);
    CHECK(slave >= 0);
}

static void line_discipline(void) {
    open_pair();
    CHECK(strncmp(sname, "/dev/pts/", 9) == 0);
    struct stat st;
    CHECK(stat(sname, &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 136);
    CHECK(isatty(slave) && isatty(master));
    char name[64];
    CHECK(ttyname_r(slave, name, sizeof name) == 0 && strcmp(name, sname) == 0);

    // Canonical: a line at a time, echoed (NL as CR NL), editable.
    put(master, "hello\n");
    expect(slave, "hello\n");
    expect(master, "hello\r\n");
    put(master, "abX\x7f" "c\r");
    expect(slave, "abc\n");
    expect(master, "abX\b \bc\r\n");
    put(master, "foo bar\x17" "baz\n");
    expect(slave, "foo baz\n");
    expect(master, "foo bar\b \b\b \b\b \bbaz\r\n");
    put(master, "gone\x15" "kept\n");
    expect(slave, "kept\n");
    CHECK(read(master, name, sizeof name) > 0);
    // A partial line isn't readable; ^D ends it, and alone it's end-of-file.
    put(master, "par");
    CHECK(quiet(slave));
    int avail = -1;
    CHECK(ioctl(slave, FIONREAD, &avail) == 0 && avail == 0);
    put(master, "t\x04");
    char buf[64];
    CHECK(read(slave, buf, sizeof buf) == 4 && memcmp(buf, "part", 4) == 0);
    put(master, "\x04");
    CHECK(read(slave, buf, sizeof buf) == 0);
    CHECK(read(master, buf, sizeof buf) == 4); // the echo of "part"
    // Out of time with nothing to read: select clears the set and poll
    // the revents, as Linux does (programs read them, not the count).
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(master, &rs);
    struct timeval tv = {0, 20000};
    CHECK(select(master + 1, &rs, 0, 0, &tv) == 0 && !FD_ISSET(master, &rs));
    struct pollfd pf = {master, POLLIN, 0x7fff};
    CHECK(poll(&pf, 1, 20) == 0 && pf.revents == 0);
    // Output: NL becomes CR NL.
    put(slave, "a\nb");
    expect(master, "a\r\nb");

    // Raw: bytes as they come, no echo, no signals.
    struct termios t, saved;
    CHECK(tcgetattr(slave, &t) == 0);
    saved = t;
    cfmakeraw(&t);
    CHECK(tcsetattr(slave, TCSANOW, &t) == 0);
    put(master, "\x03q");
    CHECK(read(slave, buf, sizeof buf) == 2 && buf[0] == 3 && buf[1] == 'q');
    CHECK(quiet(master));
    // Non-canonical with echo: Enter (CR, made NL) echoes a newline, a
    // typed ^J shows as ^J.
    struct termios cb = saved;
    cb.c_lflag &= ~ICANON;
    CHECK(tcsetattr(slave, TCSANOW, &cb) == 0);
    put(master, "a\r\n");
    expect(master, "a\r\n^J");
    CHECK(read(slave, buf, sizeof buf) == 3 && memcmp(buf, "a\n\n", 3) == 0);
    CHECK(tcsetattr(slave, TCSAFLUSH, &t) == 0);
    put(slave, "x\n");
    expect(master, "x\n");
    // VMIN 0, VTIME 1: nothing after a tenth of a second.
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 1;
    CHECK(tcsetattr(slave, TCSANOW, &t) == 0);
    struct timespec a, b2;
    clock_gettime(CLOCK_MONOTONIC, &a);
    CHECK(read(slave, buf, sizeof buf) == 0);
    clock_gettime(CLOCK_MONOTONIC, &b2);
    long ms = (b2.tv_sec - a.tv_sec) * 1000 + (b2.tv_nsec - a.tv_nsec) / 1000000;
    CHECK(ms >= 80);
    // The master's settings are the slave's, as on Linux.
    struct termios m;
    CHECK(tcgetattr(master, &m) == 0 && !(m.c_lflag & ICANON));
    CHECK(tcsetattr(slave, TCSANOW, &saved) == 0);

    // The window size.
    struct winsize ws = {.ws_row = 40, .ws_col = 132};
    CHECK(ioctl(master, TIOCSWINSZ, &ws) == 0);
    memset(&ws, 0, sizeof ws);
    CHECK(ioctl(slave, TIOCGWINSZ, &ws) == 0 && ws.ws_row == 40 && ws.ws_col == 132);

    // The slave from the master, as glibc's openpty does.
    int peer = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    CHECK(peer >= 0 && isatty(peer));
    put(master, "peer\n");
    expect(peer, "peer\n");
    close(peer);
    CHECK(read(master, buf, sizeof buf) == 6);

    // No controlling terminal here.
    CHECK(open("/dev/tty", O_RDWR) == -1 && errno == ENXIO);
    // Every slave closed: the master reads EIO.
    close(slave);
    CHECK(read(master, buf, sizeof buf) == -1 && errno == EIO);
    close(master);
    CHECK(access(sname, F_OK) == -1 && errno == ENOENT);
}

static int ready[2];
static volatile sig_atomic_t got;
static void on_sig(int sig) { got = sig; }

// A session with the slave as its controlling terminal, driven from here.
static void sessions(void) {
    open_pair();
    CHECK(pipe(ready) == 0);
    pid_t leader = fork();
    CHECK(leader >= 0);
    if (leader == 0) {
        close(master);
        CHECK(setsid() == getpid());
        CHECK(ioctl(slave, TIOCSCTTY, 0) == 0);
        CHECK(tcgetpgrp(slave) == getpid() && tcgetsid(slave) == getpid());
        int tty = open("/dev/tty", O_RDWR);
        CHECK(tty >= 0);
        close(tty);
        signal(SIGINT, on_sig);
        signal(SIGWINCH, on_sig);
        signal(SIGHUP, on_sig);
        put(ready[1], "r");
        // ^C from the parent, then a window change.
        while (got != SIGINT) pause();
        put(ready[1], "i");
        while (got != SIGWINCH) pause();
        put(ready[1], "w");

        // A job in its own group in the foreground: ^Z stops it.
        pid_t job = fork();
        CHECK(job >= 0);
        if (job == 0) {
            setpgid(0, 0);
            for (;;) pause();
        }
        CHECK(setpgid(job, job) == 0);
        signal(SIGTTOU, SIG_IGN); // a shell's tcsetpgrp from the background
        CHECK(tcsetpgrp(slave, job) == 0);
        put(ready[1], "j");
        int st;
        CHECK(waitpid(job, &st, WUNTRACED) == job && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTSTP);
        CHECK(tcsetpgrp(slave, getpid()) == 0);
        kill(job, SIGKILL);
        waitpid(job, &st, 0);

        // A background job reading the terminal gets SIGTTIN.
        job = fork();
        CHECK(job >= 0);
        if (job == 0) {
            setpgid(0, 0);
            char c;
            read(slave, &c, 1);
            _exit(1);
        }
        setpgid(job, job);
        CHECK(waitpid(job, &st, WUNTRACED) == job && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTTIN);
        kill(job, SIGKILL);
        waitpid(job, &st, 0);
        put(ready[1], "b");

        // The master closes: SIGHUP, then the slave reads end-of-file.
        while (got != SIGHUP) pause();
        char c;
        CHECK(read(slave, &c, 1) == 0);
        CHECK(write(slave, "x", 1) == -1 && errno == EIO);
        _exit(0);
    }
    close(slave);
    char c;
    CHECK(read(ready[0], &c, 1) == 1 && c == 'r');
    pid_t fg = -1;
    CHECK(ioctl(master, TIOCGPGRP, &fg) == 0 && fg == leader);
    put(master, "\x03");
    CHECK(read(ready[0], &c, 1) == 1 && c == 'i');
    struct winsize ws = {.ws_row = 50, .ws_col = 100};
    CHECK(ioctl(master, TIOCSWINSZ, &ws) == 0);
    CHECK(read(ready[0], &c, 1) == 1 && c == 'w');
    CHECK(read(ready[0], &c, 1) == 1 && c == 'j');
    put(master, "\x1a");
    CHECK(read(ready[0], &c, 1) == 1 && c == 'b');
    close(master);
    int st;
    CHECK(waitpid(leader, &st, 0) == leader && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

int main(void) {
    line_discipline();
    sessions();
    printf("pty ok\n");
    return 0;
}
