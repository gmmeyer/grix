// Processes: fork, vfork, posix_spawn, execve (imported and written
// programs, #! scripts, close-on-exec), wait4/waitid, exit statuses,
// SIGCHLD, killing children, orphans, process groups and sessions,
// copy-on-write memory, forking a multi-threaded process, the process
// limit, and memory coming back when processes end.
//
// Run as /bin/procs. "/bin/procs child ARGS..." prints its arguments and K
// and exits 3; "/bin/procs fds A B" exits with a bit per open descriptor.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)
#define RUN(t) do { if (t()) return 1; } while (0)

extern char **environ;
static char *const child_env[] = {"K=from-parent", NULL};

static int wait_status(pid_t pid) {
    int st = -1;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return st;
}

static int exit_code(pid_t pid) {
    int st = wait_status(pid);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int test_fork_and_wait(void) {
    pid_t me = getpid();
    CHECK(me == 1);
    int fds[2];
    CHECK(pipe(fds) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        char msg[64];
        int n = snprintf(msg, sizeof msg, "ppid=%d same=%d", getppid(), getpid() == me);
        write(fds[1], msg, n);
        _exit(7);
    }
    close(fds[1]);
    char buf[64] = {0};
    CHECK(read(fds[0], buf, sizeof buf - 1) > 0);
    CHECK(strcmp(buf, "ppid=1 same=0") == 0);
    CHECK(read(fds[0], buf, 1) == 0);  // EOF once the child is gone
    close(fds[0]);
    CHECK(exit_code(pid) == 7);
    CHECK(waitpid(-1, NULL, 0) == -1 && errno == ECHILD);
    return 0;
}

static volatile int shared_word = 1;
static char big[1 << 20];

static int test_copy_on_write(void) {
    memset(big, 'p', sizeof big);
    int to_child[2], to_parent[2];
    CHECK(pipe(to_child) == 0 && pipe(to_parent) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        char go;
        read(to_child[0], &go, 1);
        // The parent changed both after the fork: the child still sees the old values.
        char seen[2] = {(char)('0' + shared_word), big[12345]};
        shared_word = 9;
        memset(big, 'c', sizeof big);
        write(to_parent[1], seen, 2);
        _exit(0);
    }
    shared_word = 2;
    big[12345] = 'P';
    CHECK(write(to_child[1], "g", 1) == 1);
    char seen[2];
    CHECK(read(to_parent[0], seen, 2) == 2);
    CHECK(seen[0] == '1' && seen[1] == 'p');
    CHECK(exit_code(pid) == 0);
    // And the child's writes stayed in the child.
    CHECK(shared_word == 2 && big[12345] == 'P' && big[0] == 'p');
    close(to_child[0]), close(to_child[1]), close(to_parent[0]), close(to_parent[1]);
    return 0;
}

static int test_exec(void) {
    fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        char *argv[] = {"procs", "child", "via-execve", NULL};
        execve("/bin/procs", argv, child_env);
        _exit(100 + errno);
    }
    CHECK(exit_code(pid) == 3);
    // A missing program, and one that isn't executable.
    pid = fork();
    if (pid == 0) {
        char *argv[] = {"nope", NULL};
        execve("/no/such/program", argv, child_env);
        _exit(errno);
    }
    CHECK(exit_code(pid) == ENOENT);
    pid = fork();
    if (pid == 0) {
        char *argv[] = {"data", NULL};
        execve("/data/plain.txt", argv, child_env);
        _exit(errno);
    }
    CHECK(exit_code(pid) == EACCES);
    return 0;
}

static int test_cloexec(void) {
    int keep = open("/data/plain.txt", O_RDONLY);
    int drop = open("/data/plain.txt", O_RDONLY | O_CLOEXEC);
    CHECK(keep >= 0 && drop >= 0);
    char a[16], b[16];
    snprintf(a, sizeof a, "%d", keep);
    snprintf(b, sizeof b, "%d", drop);
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {"procs", "fds", a, b, NULL};
        execve("/bin/procs", argv, child_env);
        _exit(100);
    }
    CHECK(exit_code(pid) == 1);  // only `keep` survived
    close(keep), close(drop);
    return 0;
}

static int test_vfork_and_spawn(void) {
    fflush(stdout);
    pid_t pid = vfork();
    if (pid == 0) {
        char *argv[] = {"procs", "child", "via-vfork", NULL};
        execve("/bin/procs", argv, child_env);
        _exit(127);
    }
    CHECK(pid > 0 && exit_code(pid) == 3);
    char *argv[] = {"procs", "child", "via-posix_spawn", NULL};
    CHECK(posix_spawn(&pid, "/bin/procs", NULL, NULL, argv, child_env) == 0);
    CHECK(exit_code(pid) == 3);
    // posix_spawn reports a failed exec.
    char *bad[] = {"x", NULL};
    CHECK(posix_spawn(&pid, "/no/such/program", NULL, NULL, bad, child_env) == ENOENT);
    return 0;
}

static int test_written_programs(void) {
    // Copy ourselves to /tmp and run the copy, and a #! script naming it.
    int in = open("/bin/procs", O_RDONLY), out = open("/tmp/procs2", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    CHECK(in >= 0 && out >= 0);
    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0) CHECK(write(out, buf, n) == n);
    close(in), close(out);
    int s = open("/tmp/script", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    CHECK(s >= 0);
    const char *line = "#!/tmp/procs2 child\n";
    CHECK(write(s, line, strlen(line)) == (ssize_t)strlen(line));
    close(s);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {"procs2", "child", "written", NULL};
        execve("/tmp/procs2", argv, child_env);
        _exit(100 + errno);
    }
    CHECK(exit_code(pid) == 3);
    pid = fork();
    if (pid == 0) {
        char *argv[] = {"script", "arg", NULL};
        execve("/tmp/script", argv, child_env);
        _exit(100 + errno);
    }
    CHECK(exit_code(pid) == 3);
    return 0;
}

static volatile sig_atomic_t sigchld_count;
static void on_sigchld(int sig) { (void)sig; sigchld_count++; }

static int test_signals(void) {
    // A child killed by a signal, a child that crashes, and SIGCHLD.
    struct sigaction sa = {.sa_handler = on_sigchld};
    sigaction(SIGCHLD, &sa, NULL);
    pid_t pid = fork();
    if (pid == 0) {
        for (;;) pause();
    }
    int st;
    CHECK(waitpid(pid, &st, WNOHANG) == 0);
    CHECK(kill(pid, SIGTERM) == 0);
    st = wait_status(pid);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
    pid = fork();
    if (pid == 0) {
        *(volatile int *)16 = 1;
        _exit(0);
    }
    st = wait_status(pid);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
    CHECK(sigchld_count == 2);
    // waitid can look without reaping.
    pid = fork();
    if (pid == 0) _exit(5);
    siginfo_t si = {0};
    CHECK(waitid(P_PID, pid, &si, WEXITED | WNOWAIT) == 0);
    CHECK(si.si_pid == pid && si.si_code == CLD_EXITED && si.si_status == 5);
    CHECK(exit_code(pid) == 5);
    // Ignoring SIGCHLD reaps children at once.
    sa.sa_handler = SIG_IGN;
    sigaction(SIGCHLD, &sa, NULL);
    pid = fork();
    if (pid == 0) _exit(0);
    CHECK(waitpid(pid, NULL, 0) == -1 && errno == ECHILD);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &sa, NULL);
    return 0;
}

static int test_orphans_and_groups(void) {
    int fds[2];
    CHECK(pipe(fds) == 0);
    pid_t mid = fork();
    if (mid == 0) {
        setpgid(0, 0);
        pid_t grandchild = fork();
        if (grandchild == 0) {
            // Once its parent is gone, init (us) is its parent.
            struct timespec ts = {0, 1000000};
            for (int i = 0; i < 2000 && getppid() != 1; i++) nanosleep(&ts, NULL);
            char msg[48];
            int n = snprintf(msg, sizeof msg, "ppid=%d pgid_same=%d", getppid(), getpgid(0) == getpgid(getppid()));
            write(fds[1], msg, n);
            _exit(4);
        }
        _exit(0);
    }
    close(fds[1]);
    CHECK(exit_code(mid) == 0);
    char buf[64] = {0};
    CHECK(read(fds[0], buf, sizeof buf - 1) > 0);
    CHECK(strcmp(buf, "ppid=1 pgid_same=0") == 0);
    close(fds[0]);
    // The orphan is ours to wait for.
    int st;
    pid_t got = wait(&st);
    CHECK(got > mid && WIFEXITED(st) && WEXITSTATUS(st) == 4);
    // A new session, and signalling a process group.
    pid_t pid = fork();
    if (pid == 0) {
        pid_t sid = setsid();
        _exit(sid == getpid() && getsid(0) == getpid() && getpgid(0) == getpid() ? 0 : 1);
    }
    CHECK(exit_code(pid) == 0);
    CHECK(setsid() == -1 && errno == EPERM);  // init leads its group
    pid = fork();
    if (pid == 0) {
        setpgid(0, 0);
        for (;;) pause();
    }
    for (int i = 0; i < 1000 && getpgid(pid) != pid; i++) sched_yield();
    CHECK(getpgid(pid) == pid);
    CHECK(kill(-pid, SIGKILL) == 0);
    int s = wait_status(pid);
    CHECK(WIFSIGNALED(s) && WTERMSIG(s) == SIGKILL);
    CHECK(kill(-pid, 0) == -1 && errno == ESRCH);
    return 0;
}

static void *sleeper(void *arg) {
    (void)arg;
    for (;;) pause();
    return NULL;
}

static int test_threads_and_fork(void) {
    pthread_t t;
    CHECK(pthread_create(&t, NULL, sleeper, NULL) == 0);
    pid_t pid = fork();
    if (pid == 0) {
        // Only the forking thread is copied.
        FILE *f = fopen("/proc/self/status", "r");
        char line[128];
        int threads = -1;
        while (f && fgets(line, sizeof line, f)) sscanf(line, "Threads: %d", &threads);
        _exit(threads == 1 ? 0 : 10 + threads);
    }
    CHECK(exit_code(pid) == 0);
    return 0;
}

static long mem_free_kb(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    char line[128];
    long kb = -1;
    while (f && fgets(line, sizeof line, f)) sscanf(line, "MemFree: %ld kB", &kb);
    if (f) fclose(f);
    return kb;
}

static int test_limits_and_cleanup(void) {
    // Hundreds of processes come and go without leaking memory.
    long before = mem_free_kb();
    for (int i = 0; i < 300; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            big[i * 4096 % sizeof big] = 1;  // a private copy of a page
            _exit(i & 0x7f);
        }
        CHECK(pid > 0 && exit_code(pid) == (i & 0x7f));
    }
    long after = mem_free_kb();
    CHECK(before > 0 && after > before - 512);
    // A fork bomb runs into the process limit instead of the kernel's memory.
    static pid_t kids[200];
    int n = 0;
    for (; n < 200; n++) {
        pid_t pid = fork();
        if (pid == 0) {
            for (;;) pause();
        }
        if (pid < 0) break;
        kids[n] = pid;
    }
    CHECK(n >= 64 && n < 200 && errno == EAGAIN);
    for (int i = 0; i < n; i++) kill(kids[i], SIGKILL);
    for (int i = 0; i < n; i++) CHECK(waitpid(kids[i], NULL, 0) == kids[i]);
    CHECK(mem_free_kb() > before - 512);
    return 0;
}

static int test_shared_memory(void) {
    // MAP_SHARED anonymous memory stays shared across fork (a page touched
    // before, and one first touched by the child); MAP_PRIVATE is copied.
    int *shared = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    int *private = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED && private != MAP_FAILED);
    shared[0] = 1;
    private[0] = 1;
    pid_t pid = fork();
    if (pid == 0) {
        shared[0] = 42;
        shared[1024] = 7;
        private[0] = 9;
        _exit(0);
    }
    CHECK(exit_code(pid) == 0);
    CHECK(shared[0] == 42 && shared[1024] == 7 && private[0] == 1);
    // Still shared after mprotect.
    CHECK(mprotect(shared, 8192, PROT_READ) == 0 && mprotect(shared, 8192, PROT_READ | PROT_WRITE) == 0);
    pid = fork();
    if (pid == 0) {
        shared[0] = 43;
        _exit(0);
    }
    CHECK(exit_code(pid) == 0 && shared[0] == 43);
    munmap(shared, 8192);
    munmap(private, 4096);
    return 0;
}

static int test_bad_clones(void) {
    // An exit signal past the last one.
    CHECK(syscall(SYS_clone, 100, 0, 0, 0, 0) == -1 && errno == EINVAL);
    // Mappings count for every process together: copying many of them
    // eventually fails with ENOMEM instead of exhausting kernel memory.
    enum { N = 25000 };
    char *base = mmap(NULL, N * 4096L, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(base != MAP_FAILED);
    for (int i = 0; i < N; i += 2) CHECK(mprotect(base + i * 4096L, 4096, PROT_READ) == 0);
    pid_t kids[4];
    int n = 0, err = 0;
    for (; n < 4; n++) {
        kids[n] = fork();
        if (kids[n] == 0) {
            for (;;) pause();
        }
        if (kids[n] < 0) {
            err = errno;
            break;
        }
    }
    CHECK(n >= 1 && n < 4 && err == ENOMEM);
    for (int i = 0; i < n; i++) kill(kids[i], SIGKILL), waitpid(kids[i], NULL, 0);
    munmap(base, N * 4096L);
    return 0;
}

static int child_main(int argc, char **argv) {
    printf("child:");
    for (int i = 0; i < argc; i++) printf(" %s", argv[i]);
    const char *k = getenv("K");
    printf(" K=%s pid_is_new=%d\n", k ? k : "(unset)", getpid() > 1);
    return 3;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) return child_main(argc, argv);
    if (argc > 3 && strcmp(argv[1], "fds") == 0)
        return (fcntl(atoi(argv[2]), F_GETFD) >= 0) | (fcntl(atoi(argv[3]), F_GETFD) >= 0) << 1;
    RUN(test_fork_and_wait);
    RUN(test_copy_on_write);
    RUN(test_exec);
    RUN(test_cloexec);
    RUN(test_vfork_and_spawn);
    RUN(test_written_programs);
    RUN(test_signals);
    RUN(test_orphans_and_groups);
    RUN(test_threads_and_fork);
    RUN(test_shared_memory);
    RUN(test_bad_clones);
    RUN(test_limits_and_cleanup);
    printf("procs ok\n");
    return 0;
}
