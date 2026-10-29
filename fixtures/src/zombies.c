// /proc/<pid> of zombies: it stays until the zombie is reaped, with state
// Z and what Linux keeps of an ended process (no memory, files, cwd or
// root), then goes. Also for a zombie whose parent ended (init's now), and
// none at all when SIGCHLD is ignored. With /bin/busybox, ps lists it as Z.
//
// Run as /bin/zombies (pid 1).
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)
#define RUN(t) do { if (t()) return 1; } while (0)

extern char **environ;

// The whole of a /proc file (-1 and errno if it can't be opened).
static int slurp(pid_t pid, const char *name, char *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/%s", pid, name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t n = 0;
    ssize_t r;
    while (n + 1 < size && (r = read(fd, buf + n, size - 1 - n)) > 0) n += r;
    buf[n] = 0;
    close(fd);
    return (int)n;
}

// Field `n` (from 3: after the parenthesised name) of /proc/<pid>/stat.
static long stat_field(const char *stat, int n) {
    const char *p = strrchr(stat, ')');
    if (!p) return -1;
    p += 2;
    for (int i = 3; i < n; i++) {
        p = strchr(p, ' ');
        if (!p) return -1;
        p++;
    }
    return *p == 'Z' ? 'Z' : strtol(p, NULL, 10);
}

// Wait until `pid` has ended, leaving it a zombie.
static int until_zombie(pid_t pid) {
    siginfo_t si = {0};
    if (waitid(P_PID, pid, &si, WEXITED | WNOWAIT) != 0) return -1;
    return si.si_pid == pid ? 0 : -1;
}

static int gone(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d", pid);
    struct stat st;
    return stat(path, &st) == -1 && errno == ENOENT;
}

// What ps says of `pid`: its STAT and ARGS columns.
static int ps_line(pid_t pid, char *out, size_t size) {
    int fds[2];
    if (pipe(fds) != 0) return -1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[1], 1);
    posix_spawn_file_actions_addclose(&fa, fds[0]);
    char *argv[] = {"/bin/busybox", "ps", "-o", "pid,stat,args", NULL};
    pid_t ps;
    if (posix_spawn(&ps, argv[0], &fa, NULL, argv, environ) != 0) return -1;
    close(fds[1]);
    static char text[4096];
    size_t n = 0;
    ssize_t r;
    while (n + 1 < sizeof text && (r = read(fds[0], text + n, sizeof text - 1 - n)) > 0) n += r;
    text[n] = 0;
    close(fds[0]);
    int st;
    if (waitpid(ps, &st, 0) != ps || st != 0) return -1;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        char *end;
        if (strtol(line, &end, 10) == pid && end != line) {
            while (*end == ' ') end++;
            // Squeeze the columns' padding.
            size_t o = 0;
            for (char *c = end; *c && o + 1 < size; c++)
                if (*c != ' ' || (o > 0 && out[o - 1] != ' ')) out[o++] = *c;
            out[o] = 0;
            return 0;
        }
    }
    return -1;
}

static int test_zombie(void) {
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        setpgid(0, 0);
        signal(SIGUSR1, SIG_IGN);
        _exit(5);
    }
    CHECK(until_zombie(pid) == 0);

    char buf[4096];
    CHECK(slurp(pid, "stat", buf, sizeof buf) > 0);
    char name[32];
    snprintf(name, sizeof name, "%d (zombies) Z 1 ", pid);
    CHECK(strncmp(buf, name, strlen(name)) == 0);
    printf("stat: state %c ppid %ld pgrp=pid %d threads %ld vsize %ld rss %ld exit_code %#lx\n",
           (int)stat_field(buf, 3), stat_field(buf, 4), stat_field(buf, 5) == pid, stat_field(buf, 20),
           stat_field(buf, 23), stat_field(buf, 24), stat_field(buf, 52));

    CHECK(slurp(pid, "status", buf, sizeof buf) > 0);
    CHECK(strncmp(buf, "Name:\tzombies\nState:\tZ (zombie)\n", 32) == 0);
    printf("status: %s ppid=%d threads=%d fdsize=%d umask=%d vm=%d sigign_usr1=%d\n", strstr(buf, "State:\tZ (zombie)\n") ? "Z" : "?",
           strstr(buf, "\nPPid:\t1\n") != NULL, strstr(buf, "\nThreads:\t1\n") != NULL,
           strstr(buf, "\nFDSize:\t0\n") != NULL, strstr(buf, "Umask:") != NULL, strstr(buf, "VmSize:") != NULL,
           strstr(buf, "\nSigIgn:\t0000000000000200\n") != NULL);

    int cmdline = slurp(pid, "cmdline", buf, sizeof buf);
    int environ_ = slurp(pid, "environ", buf, sizeof buf);
    int maps = slurp(pid, "maps", buf, sizeof buf);
    printf("empty: cmdline %d environ %d maps %d\n", cmdline, environ_, maps);
    CHECK(slurp(pid, "statm", buf, sizeof buf) > 0);
    printf("statm: %s", buf);
    CHECK(slurp(pid, "comm", buf, sizeof buf) > 0);
    printf("comm: %s", buf);
    CHECK(slurp(pid, "limits", buf, sizeof buf) > 0 && strstr(buf, "Max open files"));
    errno = 0;
    printf("mountinfo: %d %s\n", slurp(pid, "mountinfo", buf, sizeof buf), strerror(errno));

    const char *links[] = {"exe", "cwd", "root"};
    for (int i = 0; i < 3; i++) {
        char path[64], target[256];
        snprintf(path, sizeof path, "/proc/%d/%s", pid, links[i]);
        errno = 0;
        ssize_t n = readlink(path, target, sizeof target);
        int readlink_errno = errno;
        struct stat st;
        errno = 0;
        int followed = stat(path, &st);
        int stat_errno = errno;
        CHECK(lstat(path, &st) == 0 && S_ISLNK(st.st_mode));
        printf("%s: readlink %zd %s, stat %d %s\n", links[i], n, strerror(readlink_errno), followed,
               strerror(stat_errno));
    }

    char path[64];
    snprintf(path, sizeof path, "/proc/%d/fd", pid);
    DIR *d = opendir(path);
    CHECK(d);
    int entries = 0;
    for (struct dirent *e; (e = readdir(d));) entries += strcmp(e->d_name, ".") && strcmp(e->d_name, "..");
    closedir(d);
    snprintf(path, sizeof path, "/proc/%d/fd/0", pid);
    errno = 0;
    int fd0 = open(path, O_RDONLY);
    printf("fd: %d entries, fd/0 %d %s\n", entries, fd0, strerror(errno));

    // Signals and process ids still reach it.
    CHECK(kill(pid, 0) == 0);
    CHECK(getpgid(pid) == pid && getsid(pid) == getsid(0));

    if (access("/bin/busybox", X_OK) == 0) {
        char line[256];
        CHECK(ps_line(pid, line, sizeof line) == 0);
        printf("ps: %s\n", line);
    }

    int st;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 5);
    printf("reaped: gone %d\n", gone(pid));
    return 0;
}

// A zombie whose parent ends is init's: its /proc/<pid> says so.
static int test_orphan(void) {
    int fds[2];
    CHECK(pipe(fds) == 0);
    pid_t mid = fork();
    CHECK(mid >= 0);
    if (mid == 0) {
        pid_t kid = fork();
        if (kid == 0) _exit(9);
        if (until_zombie(kid) != 0) _exit(1);
        write(fds[1], &kid, sizeof kid);
        _exit(0);
    }
    close(fds[1]);
    pid_t kid = 0;
    CHECK(read(fds[0], &kid, sizeof kid) == sizeof kid);
    close(fds[0]);
    int st;
    CHECK(waitpid(mid, &st, 0) == mid && st == 0);
    CHECK(gone(mid));
    char buf[4096];
    CHECK(slurp(kid, "stat", buf, sizeof buf) > 0);
    printf("orphan: state %c ppid %ld\n", (int)stat_field(buf, 3), stat_field(buf, 4));
    CHECK(waitpid(kid, &st, 0) == kid && WIFEXITED(st) && WEXITSTATUS(st) == 9);
    printf("orphan reaped: gone %d\n", gone(kid));
    return 0;
}

// A parent that ignores SIGCHLD (or sets SA_NOCLDWAIT) leaves no zombie.
static int test_no_zombie(void) {
    for (int nocldwait = 0; nocldwait < 2; nocldwait++) {
        struct sigaction sa = {0}, old;
        sa.sa_handler = nocldwait ? SIG_DFL : SIG_IGN;
        sa.sa_flags = nocldwait ? SA_NOCLDWAIT : 0;
        CHECK(sigaction(SIGCHLD, &sa, &old) == 0);
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) _exit(0);
        // Waits for the last child to end, then finds none.
        int st;
        errno = 0;
        CHECK(waitpid(pid, &st, 0) == -1 && errno == ECHILD);
        printf("%s: gone %d\n", nocldwait ? "SA_NOCLDWAIT" : "SIG_IGN", gone(pid));
        CHECK(sigaction(SIGCHLD, &old, NULL) == 0);
    }
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getpid() != 1) {
        printf("FAILED: not pid 1\n");
        return 1;
    }
    RUN(test_zombie);
    RUN(test_orphan);
    RUN(test_no_zombie);
    printf("zombies ok\n");
    return 0;
}
