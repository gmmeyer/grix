// Smaller Linux interfaces, one check per argument:
//   auxv     AT_HWCAP2 and AT_MINSIGSTKSZ (a handler's frame fits an
//            alternate stack that size, with room for the handler)
//   handles  name_to_handle_at: EOPNOTSUPP once the path resolves, as a
//            filesystem without file handles answers; open_by_handle_at
//            is privileged
//   sleep    nanosleep across a stop and continue: no handler, so it
//            goes on to its first deadline, as Linux's restart_syscall
//   links    hard links and RENAME_EXCHANGE in /work (a live mount), and
//            neither across into /tmp
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

#ifndef AT_MINSIGSTKSZ
#define AT_MINSIGSTKSZ 51
#endif

static char buf[1 << 14];

static ssize_t slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = 0, r;
    while (n < (ssize_t)sizeof buf - 1 && (r = read(fd, buf + n, sizeof buf - 1 - n)) > 0) n += r;
    close(fd);
    return n;
}

static char *alt;
static size_t alt_size;
static volatile int on_alt;

static void on_usr1(int sig) {
    (void)sig;
    char here;
    on_alt = &here >= alt && &here < alt + alt_size;
}

static int auxv(void) {
    unsigned long min = getauxval(AT_MINSIGSTKSZ);
    CHECK(min >= 1024 && min <= 65536 && min % 16 == 0);
#if defined(__aarch64__)
    // The frame (4688 bytes with the FP/SIMD record), its frame record and
    // alignment, as Linux has it without SVE.
    CHECK(min == 4720);
#endif
    // /proc/self/auxv says the same, AT_HWCAP2 included.
    ssize_t n = slurp("/proc/self/auxv");
    CHECK(n > 0 && n % 16 == 0);
    unsigned long *v = (unsigned long *)buf;
    int seen = 0;
    for (ssize_t i = 0; i < n / 8 && v[i] != AT_NULL; i += 2) {
        if (v[i] == AT_HWCAP2) seen |= (v[i + 1] == getauxval(AT_HWCAP2)) << 0;
        if (v[i] == AT_MINSIGSTKSZ) seen |= (v[i + 1] == min) << 1;
    }
    CHECK(seen == 3);
    // A handler runs on an alternate stack that size, and room for itself.
    alt_size = min + 4096;
    alt = mmap(0, alt_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(alt != MAP_FAILED);
    stack_t ss = {.ss_sp = alt, .ss_size = alt_size};
    CHECK(sigaltstack(&ss, 0) == 0);
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_ONSTACK;
    CHECK(sigaction(SIGUSR1, &sa, 0) == 0);
    CHECK(raise(SIGUSR1) == 0);
    CHECK(on_alt);
    return 0;
}

struct handle {
    unsigned int bytes;
    int type;
    unsigned char f[128];
};

static int handles(void) {
    struct handle h = {.bytes = sizeof h.f};
    int mount_id = -1;
    CHECK(syscall(SYS_name_to_handle_at, AT_FDCWD, "/bin/newcalls", &h, &mount_id, 0) == -1 && errno == EOPNOTSUPP);
    CHECK(syscall(SYS_name_to_handle_at, AT_FDCWD, "/bin", &h, &mount_id, AT_SYMLINK_FOLLOW) == -1 &&
          errno == EOPNOTSUPP);
    int fd = open("/bin", O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 0);
    CHECK(syscall(SYS_name_to_handle_at, fd, "", &h, &mount_id, AT_EMPTY_PATH) == -1 && errno == EOPNOTSUPP);
    // The path is looked up first.
    CHECK(syscall(SYS_name_to_handle_at, AT_FDCWD, "/nope", &h, &mount_id, 0) == -1 && errno == ENOENT);
    CHECK(syscall(SYS_name_to_handle_at, AT_FDCWD, "/bin", &h, &mount_id, 0x8000) == -1 && errno == EINVAL);
    // Opening by handle needs CAP_DAC_READ_SEARCH: denied.
    CHECK(syscall(SYS_open_by_handle_at, fd, &h, O_RDONLY) == -1 && errno == EPERM);
    return 0;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int put(const char *path, const char *s) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    int r = write(fd, s, strlen(s)) == (ssize_t)strlen(s) ? 0 : -1;
    close(fd);
    return r;
}

static const char *get(const char *path) {
    static char b[64];
    memset(b, 0, sizeof b);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return "";
    read(fd, b, sizeof b - 1);
    close(fd);
    return b;
}

#ifndef RENAME_EXCHANGE
#define RENAME_NOREPLACE 1
#define RENAME_EXCHANGE 2
#endif

static int rename2(const char *a, const char *b, int flags) {
    return syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, flags);
}

static int links(void) {
    // Another name for a file: the same bytes through either, on the host
    // too (the test looks), and it outlives the first.
    CHECK(put("/work/a", "one\n") == 0);
    CHECK(link("/work/a", "/work/hard") == 0);
    CHECK(!strcmp(get("/work/hard"), "one\n"));
    CHECK(put("/work/hard", "two\n") == 0);
    CHECK(!strcmp(get("/work/a"), "two\n"));
    CHECK(link("/work/a", "/work/hard") == -1 && errno == EEXIST);
    CHECK(link("/work/sub", "/work/subhard") == -1 && errno == EPERM);
    CHECK(link("/work/nothing", "/work/x") == -1 && errno == ENOENT);
    // A link to a symbolic link is to the link.
    CHECK(symlink("a", "/work/sym") == 0);
    CHECK(linkat(AT_FDCWD, "/work/sym", AT_FDCWD, "/work/sym2", 0) == 0);
    char t[16] = {0};
    CHECK(readlink("/work/sym2", t, sizeof t) == 1 && t[0] == 'a');
    // Not across mounts (/tmp is the sandbox's own).
    CHECK(put("/tmp/local", "x") == 0);
    CHECK(link("/tmp/local", "/work/local") == -1 && errno == EXDEV);
    CHECK(link("/work/a", "/tmp/a") == -1 && errno == EXDEV);

    // Two names swapped at once: a file and a directory too.
    CHECK(put("/work/x", "x\n") == 0 && put("/work/y", "y\n") == 0);
    CHECK(rename2("/work/x", "/work/y", RENAME_EXCHANGE) == 0);
    CHECK(!strcmp(get("/work/x"), "y\n") && !strcmp(get("/work/y"), "x\n"));
    CHECK(rename2("/work/x", "/work/sub", RENAME_EXCHANGE) == 0);
    struct stat st;
    CHECK(stat("/work/x", &st) == 0 && S_ISDIR(st.st_mode));
    CHECK(!strcmp(get("/work/sub"), "y\n"));
    CHECK(stat("/work/x/inside", &st) == 0);
    CHECK(rename2("/work/x", "/work/sub", RENAME_EXCHANGE) == 0);
    CHECK(rename2("/work/x", "/work/none", RENAME_EXCHANGE) == -1 && errno == ENOENT);
    CHECK(rename2("/work/x", "/work/y", RENAME_EXCHANGE | RENAME_NOREPLACE) == -1 && errno == EINVAL);
    CHECK(rename2("/work/x", "/tmp/local", RENAME_EXCHANGE) == -1 && errno == EXDEV);
    // A directory can't go inside itself.
    CHECK(rename2("/work/sub", "/work/sub/inside", RENAME_EXCHANGE) == -1 && errno == EINVAL);
    return 0;
}

static int sleep_restart(void) {
    int p[2];
    CHECK(pipe(p) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        long t0 = now_ms();
        struct timespec req = {0, 300 * 1000000L}, rem = {9, 9};
        int r = nanosleep(&req, &rem);
        long took = now_ms() - t0;
        char line[64];
        int n = snprintf(line, sizeof line, "%d %d %ld\n", r, r ? errno : 0, took);
        write(p[1], line, n);
        _exit(0);
    }
    close(p[1]);
    usleep(50000);
    CHECK(kill(pid, SIGSTOP) == 0);
    int status;
    CHECK(waitpid(pid, &status, WUNTRACED) == pid && WIFSTOPPED(status));
    usleep(100000);
    CHECK(kill(pid, SIGCONT) == 0);
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    char line[64] = {0};
    CHECK(read(p[0], line, sizeof line - 1) > 0);
    int r, e;
    long took;
    CHECK(sscanf(line, "%d %d %ld", &r, &e, &took) == 3);
    // Not EINTR, and not started over at the continue (which would be
    // 150 ms + 300 ms).
    CHECK(r == 0 && e == 0);
    CHECK(took >= 299 && took < 440);
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        int r = !strcmp(argv[i], "auxv")      ? auxv()
                : !strcmp(argv[i], "handles") ? handles()
                : !strcmp(argv[i], "sleep")   ? sleep_restart()
                : !strcmp(argv[i], "links")   ? links()
                                              : (printf("unknown check %s\n", argv[i]), 1);
        if (r) return r;
        printf("%s ok\n", argv[i]);
    }
    return 0;
}
