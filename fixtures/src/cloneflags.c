// clone's sharing flags for new processes, by raw clone and clone3:
// CLONE_FILES (one descriptor table, and the POSIX locks it owns),
// CLONE_FS (working directory and umask), CLONE_SIGHAND (signal actions,
// with CLONE_VM|CLONE_VFORK), CLONE_PARENT, clone3's CLONE_CLEAR_SIGHAND,
// what execve and unshare(2) unshare, and the EINVAL cases. Each flag
// shares only what it names. Needs `process` and `fs_write` (/tmp).
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Written straight to the descriptor: children share no stdio buffers.
#define CHECK(c)                                                                     \
    do {                                                                             \
        if (!(c)) {                                                                  \
            dprintf(1, "FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);     \
            _exit(1);                                                                \
        }                                                                            \
    } while (0)

#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

struct clone_args_v0 {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
};

static const char *self;

// fork-like: no new stack, so the child returns here with 0 (its own copy
// of memory). The argument order differs between arm64 and x86_64, but
// they're all 0.
static long rclone(unsigned long flags) { return syscall(SYS_clone, flags, 0, 0, 0, 0); }

static long rclone3(uint64_t flags, uint64_t exit_signal) {
    struct clone_args_v0 a = {.flags = flags, .exit_signal = exit_signal};
    return syscall(SYS_clone3, &a, sizeof a);
}

static long sys_unshare(unsigned long flags) { return syscall(SYS_unshare, flags); }

// The child's exit status.
static int reap(pid_t pid) {
    int st;
    CHECK(waitpid(pid, &st, __WALL) == pid);
    CHECK(WIFEXITED(st));
    return WEXITSTATUS(st);
}

static int fd_open(int fd) { return fcntl(fd, F_GETFD) >= 0; }

// A /proc/<pid>/status line's value (after "Name:\t"), or "" without one.
static const char *status_field(pid_t pid, const char *name, char *out, size_t size) {
    char path[64], buf[4096];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    ssize_t n = read(fd, buf, sizeof buf - 1);
    CHECK(n > 0 && close(fd) == 0);
    buf[n] = 0;
    out[0] = 0;
    size_t len = strlen(name);
    for (char *line = buf; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : 0) {
        if (strncmp(line, name, len) == 0 && line[len] == ':') {
            char *v = line + len + 1;
            while (*v == '\t' || *v == ' ') v++;
            size_t m = strcspn(v, "\n");
            if (m >= size) m = size - 1;
            memcpy(out, v, m);
            out[m] = 0;
        }
    }
    return out;
}

// Has `pid` ended (a zombie not yet reaped)?
static int zombie(pid_t pid) {
    siginfo_t si;
    si.si_pid = 0;
    CHECK(waitid(P_PID, pid, &si, WEXITED | WNOHANG | WNOWAIT | __WALL) == 0);
    return si.si_pid == pid;
}

static void (*handler(int sig))(int) {
    struct sigaction sa;
    CHECK(sigaction(sig, 0, &sa) == 0);
    return sa.sa_handler;
}

static void on_usr1(int sig) { (void)sig; }

static int same_cwd(const char *want) {
    char cwd[256];
    return getcwd(cwd, sizeof cwd) && strcmp(cwd, want) == 0;
}

static void files(const char *home) {
    int a = open("/dev/null", O_RDONLY), b = open("/dev/null", O_RDONLY);
    CHECK(a >= 0 && b >= 0);

    // What the child opens, closes, dup2s and marks close-on-exec, the
    // parent sees: one table.
    pid_t pid = rclone(CLONE_FILES | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(close(a) == 0);
        int z = open("/dev/zero", O_RDONLY);
        CHECK(z >= 0 && dup2(z, 71) == 71 && close(z) == 0);
        CHECK(dup2(b, 70) == 70 && fcntl(70, F_SETFD, FD_CLOEXEC) == 0);
        // Nothing more: not the working directory, umask or handlers.
        CHECK(chdir("/dev") == 0);
        umask(077);
        signal(SIGUSR2, SIG_IGN);
        _exit(0);
    }
    CHECK(reap(pid) == 0);
    char c = 1;
    CHECK(!fd_open(a) && read(71, &c, 1) == 1 && c == 0);
    CHECK(fcntl(70, F_GETFD) == FD_CLOEXEC);
    CHECK(same_cwd(home) && umask(022) == 022 && handler(SIGUSR2) == SIG_DFL);
    CHECK(close(70) == 0 && close(71) == 0);

    // A zombie that shared the table has none (Linux's exit_files), nor a
    // working directory (exit_fs): no FDSize count, no Umask line.
    pid = rclone(CLONE_FILES | CLONE_FS | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) _exit(0);
    while (!zombie(pid)) sched_yield();
    char v[64];
    CHECK(strcmp(status_field(pid, "FDSize", v, sizeof v), "0") == 0);
    CHECK(strcmp(status_field(pid, "Umask", v, sizeof v), "") == 0);
    CHECK(fd_open(b) && reap(pid) == 0);

    // A fork's table is a copy.
    pid = rclone(SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(close(b) == 0 && dup2(1, 72) == 72);
        _exit(0);
    }
    CHECK(reap(pid) == 0);
    CHECK(fd_open(b) && !fd_open(72));

    // execve makes the table the child's own before closing close-on-exec
    // descriptors: the parent keeps them, and what it does after is its own.
    int cx = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(cx >= 0);
    pid = rclone(CLONE_FILES | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        char keep[16], gone[16];
        snprintf(keep, sizeof keep, "%d", b);
        snprintf(gone, sizeof gone, "%d", cx);
        execl(self, self, "exec-files", keep, gone, (char *)0);
        _exit(127);
    }
    CHECK(reap(pid) == 0);
    CHECK(fd_open(b) && fd_open(cx) && !fd_open(73));

    // So does unshare(CLONE_FILES).
    pid = rclone(CLONE_FILES | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(dup2(1, 74) == 74);
        CHECK(sys_unshare(CLONE_FILES) == 0);
        CHECK(close(b) == 0 && dup2(1, 75) == 75);
        _exit(0);
    }
    CHECK(reap(pid) == 0);
    CHECK(fd_open(74) && fd_open(b) && !fd_open(75));
    CHECK(close(74) == 0 && close(b) == 0 && close(cx) == 0);
}

// After exec in a child that shared the parent's table: argv[2] is still
// open, argv[3] (close-on-exec) isn't.
static int exec_files(char **argv) {
    int keep = atoi(argv[2]), gone = atoi(argv[3]);
    CHECK(fd_open(keep) && !fd_open(gone));
    CHECK(close(keep) == 0 && dup2(1, 73) == 73);
    return 0;
}

// What F_GETLK says of a write lock on the first 10 bytes.
static int lock_type(int fd) {
    struct flock l = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 10};
    CHECK(fcntl(fd, F_GETLK, &l) == 0);
    return l.l_type;
}

// POSIX record locks are the descriptor table's (Linux's files_struct).
static void locks(void) {
    const char *path = "/tmp/cloneflags";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    struct flock l = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 10};
    CHECK(fcntl(fd, F_SETLK, &l) == 0);

    // A process sharing the table holds the lock too, unlike a fork.
    pid_t pid = rclone(CLONE_FILES | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) _exit(lock_type(fd) == F_UNLCK ? 0 : 1);
    CHECK(reap(pid) == 0);
    // Its end left the lock (the table is still the parent's).
    pid = rclone(SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) _exit(lock_type(fd) == F_WRLCK ? 0 : 1);
    CHECK(reap(pid) == 0);

    // Its closing any descriptor for the file drops it.
    pid = rclone(CLONE_FILES | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        int other = open(path, O_RDONLY);
        CHECK(other >= 0 && close(other) == 0);
        _exit(0);
    }
    CHECK(reap(pid) == 0);
    pid = rclone(SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) _exit(lock_type(fd) == F_UNLCK ? 0 : 1);
    CHECK(reap(pid) == 0);
    CHECK(close(fd) == 0 && unlink(path) == 0);
}

static void fs(const char *home) {
    int a = open("/dev/null", O_RDONLY);
    CHECK(a >= 0);

    // chdir and umask in the child are the parent's: one fs_struct.
    pid_t pid = rclone(CLONE_FS | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(chdir("/dev") == 0);
        umask(077);
        // Nothing more: not the descriptors or handlers.
        CHECK(close(a) == 0);
        signal(SIGUSR2, SIG_IGN);
        _exit(0);
    }
    CHECK(reap(pid) == 0);
    char link[256] = {0};
    CHECK(same_cwd("/dev") && umask(022) == 077);
    CHECK(readlink("/proc/self/cwd", link, sizeof link - 1) == 4 && strcmp(link, "/dev") == 0);
    CHECK(fd_open(a) && handler(SIGUSR2) == SIG_DFL);
    CHECK(chdir(home) == 0);

    // A fork's are copies.
    pid = rclone(SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(chdir("/dev") == 0);
        umask(077);
        _exit(0);
    }
    CHECK(reap(pid) == 0);
    CHECK(same_cwd(home) && umask(022) == 022);

    // So are they after unshare(CLONE_FS) (and it has fchdir too).
    pid = rclone(CLONE_FS | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        int dev = open("/dev", O_RDONLY | O_DIRECTORY);
        CHECK(dev >= 0 && fchdir(dev) == 0);
        CHECK(sys_unshare(CLONE_FS) == 0);
        CHECK(chdir("/") == 0);
        umask(077);
        _exit(0);
    }
    CHECK(reap(pid) == 0);
    CHECK(same_cwd("/dev") && umask(022) == 022);
    CHECK(chdir(home) == 0);

    // execve keeps them shared.
    pid = rclone(CLONE_FS | SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        execl(self, self, "exec-fs", (char *)0);
        _exit(127);
    }
    CHECK(reap(pid) == 0);
    CHECK(same_cwd("/proc") && umask(022) == 027);
    CHECK(chdir(home) == 0 && close(a) == 0);
}

static int exec_fs(void) {
    CHECK(chdir("/proc") == 0);
    umask(027);
    return 0;
}

// CLONE_SIGHAND needs CLONE_VM; CLONE_VM here is vfork's (the parent
// waits), so the children only make system calls, on their own stack.
static char stack[64 * 1024] __attribute__((aligned(16)));

static int ignore_usr2(void *arg) {
    signal(SIGUSR2, SIG_IGN);
    // Not the descriptors.
    close(*(int *)arg);
    _exit(0);
}

static int exec_sighand(void *arg) {
    (void)arg;
    execl(self, self, "exec-sighand", (char *)0);
    _exit(127);
}

static int unshare_sighand(void *arg) {
    (void)arg;
    // Linux refuses while the actions are shared.
    _exit(sys_unshare(CLONE_SIGHAND) == -1 && errno == EINVAL ? 0 : 1);
}

static pid_t vfork_clone(int (*fn)(void *), unsigned long flags, void *arg) {
    return clone(fn, stack + sizeof stack, CLONE_VM | CLONE_VFORK | flags | SIGCHLD, arg);
}

static void sighand(void) {
    errno = 0;
    CHECK(rclone(CLONE_SIGHAND | SIGCHLD) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(rclone3(CLONE_SIGHAND, SIGCHLD) == -1 && errno == EINVAL);

    int a = open("/dev/null", O_RDONLY);
    CHECK(a >= 0);
    CHECK(signal(SIGUSR1, on_usr1) != SIG_ERR);
    pid_t pid = vfork_clone(ignore_usr2, CLONE_SIGHAND, &a);
    CHECK(pid > 0 && zombie(pid));
    // Its /proc/<pid> shows the actions it shared: SIGUSR1 caught, SIGUSR2
    // (its own doing) ignored.
    char v[64];
    unsigned long long ign = strtoull(status_field(pid, "SigIgn", v, sizeof v), 0, 16);
    unsigned long long cgt = strtoull(status_field(pid, "SigCgt", v, sizeof v), 0, 16);
    CHECK((ign >> (SIGUSR2 - 1) & 1) && (cgt >> (SIGUSR1 - 1) & 1));
    CHECK(reap(pid) == 0);
    CHECK(handler(SIGUSR2) == SIG_IGN && fd_open(a));
    CHECK(signal(SIGUSR2, SIG_DFL) != SIG_ERR);

    // Without it, the child's are a copy.
    pid = vfork_clone(ignore_usr2, 0, &a);
    CHECK(pid > 0 && reap(pid) == 0);
    CHECK(handler(SIGUSR2) == SIG_DFL && fd_open(a));

    // execve makes them the child's own before resetting its handlers.
    pid = vfork_clone(exec_sighand, CLONE_SIGHAND, 0);
    CHECK(pid > 0 && reap(pid) == 0);
    CHECK(handler(SIGUSR1) == on_usr1 && handler(SIGTERM) == SIG_DFL);

    // unshare(CLONE_SIGHAND) only works with nothing shared, doing nothing.
    CHECK(sys_unshare(CLONE_SIGHAND) == 0);
    pid = vfork_clone(unshare_sighand, CLONE_SIGHAND, 0);
    CHECK(pid > 0 && reap(pid) == 0);

    // clone3's CLONE_CLEAR_SIGHAND: handled signals are the default in the
    // child, ignored ones stay ignored; and it can't share them too.
    CHECK(signal(SIGUSR2, SIG_IGN) != SIG_ERR);
    errno = 0;
    CHECK(rclone3(CLONE_VM | CLONE_VFORK | CLONE_SIGHAND | CLONE_CLEAR_SIGHAND, SIGCHLD) == -1 && errno == EINVAL);
    pid = rclone3(CLONE_CLEAR_SIGHAND, SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) _exit(handler(SIGUSR1) == SIG_DFL && handler(SIGUSR2) == SIG_IGN ? 0 : 1);
    CHECK(reap(pid) == 0);
    CHECK(handler(SIGUSR1) == on_usr1);
    CHECK(signal(SIGUSR1, SIG_DFL) != SIG_ERR && signal(SIGUSR2, SIG_DFL) != SIG_ERR);
    CHECK(close(a) == 0);
}

static int exec_sighand_child(void) {
    // Reset by exec in its own copy (the parent's handler stays) ...
    CHECK(handler(SIGUSR1) == SIG_DFL);
    // ... which it now changes alone.
    CHECK(signal(SIGTERM, SIG_IGN) != SIG_ERR);
    return 0;
}

static void parent(void) {
    pid_t top = getpid();
    // clone3 takes no exit signal with it: the child's is the caller's.
    errno = 0;
    CHECK(rclone3(CLONE_PARENT, SIGCHLD) == -1 && errno == EINVAL);
    if (top == 1) {
        // Init's siblings would have no parent to reap them.
        errno = 0;
        CHECK(rclone(CLONE_PARENT | SIGCHLD) == -1 && errno == EINVAL);
        errno = 0;
        CHECK(rclone3(CLONE_PARENT, 0) == -1 && errno == EINVAL);
    }

    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK, &usr1, 0) == 0);
    int found[2], done[2];
    CHECK(pipe(found) == 0 && pipe(done) == 0);
    // A child that tells its end with SIGUSR1 makes a sibling, which
    // tells its own end to this process the same way.
    pid_t a = rclone(SIGUSR1);
    CHECK(a >= 0);
    if (a == 0) {
        pid_t g = rclone(CLONE_PARENT | SIGCHLD);
        CHECK(g >= 0);
        if (g == 0) _exit(getppid() == top ? 7 : 1);
        int st;
        errno = 0;
        CHECK(waitpid(g, &st, __WALL) == -1 && errno == ECHILD);
        CHECK(write(found[1], &g, sizeof g) == sizeof g);
        char c;
        CHECK(read(done[0], &c, 1) == 1);
        _exit(0);
    }
    pid_t g;
    CHECK(read(found[0], &g, sizeof g) == sizeof g);
    siginfo_t si;
    struct timespec ts = {10, 0};
    CHECK(sigtimedwait(&usr1, &si, &ts) == SIGUSR1 && si.si_pid == g);
    // Its zombie is this process's to reap, and says so.
    char v[64], want[16];
    snprintf(want, sizeof want, "%d", top);
    CHECK(zombie(g) && strcmp(status_field(g, "PPid", v, sizeof v), want) == 0);
    CHECK(status_field(g, "State", v, sizeof v)[0] == 'Z');
    CHECK(reap(g) == 7);
    CHECK(write(done[1], "x", 1) == 1);
    CHECK(reap(a) == 0);
    CHECK(sigtimedwait(&usr1, &si, &ts) == SIGUSR1 && si.si_pid == a);
    CHECK(sigprocmask(SIG_UNBLOCK, &usr1, 0) == 0);
    for (int i = 0; i < 2; i++) CHECK(close(found[i]) == 0 && close(done[i]) == 0);
}

// clone3 shares the same way.
static void clone3_shares(const char *home) {
    pid_t pid = rclone3(CLONE_FILES | CLONE_FS, SIGCHLD);
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(dup2(1, 76) == 76 && chdir("/dev") == 0);
        _exit(0);
    }
    CHECK(reap(pid) == 0);
    CHECK(fd_open(76) && same_cwd("/dev"));
    CHECK(close(76) == 0 && chdir(home) == 0);
}

static void *idle(void *arg) {
    (void)arg;
    for (;;) pause();
}

// Not Linux's behaviour: a thread can't have a table or directory of its
// own here, which grix reports (`cloneflags threads`).
static int threads(void) {
    pthread_t t;
    CHECK(pthread_create(&t, 0, idle, 0) == 0);
    errno = 0;
    CHECK(sys_unshare(CLONE_FILES) == -1 && errno == EINVAL);
    // Nothing to unshare (one thread's own) is fine.
    CHECK(sys_unshare(CLONE_SYSVSEM) == 0);
    dprintf(1, "cloneflags threads ok\n");
    _exit(0);
}

// Not Linux's behaviour either: new namespaces are refused (EPERM), by
// clone, clone3 and unshare, each kind reported (`cloneflags namespaces`).
static int namespaces(void) {
    static const unsigned long kinds[] = {CLONE_NEWNS,  CLONE_NEWUSER, CLONE_NEWPID,    CLONE_NEWNET,
                                          CLONE_NEWUTS, CLONE_NEWIPC,  CLONE_NEWCGROUP, 0x80 /* CLONE_NEWTIME */};
    for (unsigned i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        unsigned long k = kinds[i];
        errno = 0;
        CHECK(sys_unshare(k) == -1 && errno == EPERM);
        if (k == 0x80) continue; // clone's exit signal bits
        errno = 0;
        CHECK(rclone(k | SIGCHLD) == -1 && errno == EPERM);
        errno = 0;
        CHECK(rclone3(k, SIGCHLD) == -1 && errno == EPERM);
    }
    dprintf(1, "cloneflags namespaces ok\n");
    return 0;
}

int main(int argc, char **argv) {
    self = argv[0];
    if (argc >= 4 && strcmp(argv[1], "exec-files") == 0) return exec_files(argv);
    if (argc >= 2 && strcmp(argv[1], "exec-fs") == 0) return exec_fs();
    if (argc >= 2 && strcmp(argv[1], "exec-sighand") == 0) return exec_sighand_child();
    if (argc >= 2 && strcmp(argv[1], "threads") == 0) return threads();
    if (argc >= 2 && strcmp(argv[1], "namespaces") == 0) return namespaces();
    char home[256];
    CHECK(getcwd(home, sizeof home));
    umask(022);
    files(home);
    locks();
    fs(home);
    sighand();
    parent();
    clone3_shares(home);
    dprintf(1, "cloneflags ok\n");
    return 0;
}
