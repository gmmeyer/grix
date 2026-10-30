// What a hostile program tries, each subcommand one way of hurting the
// kernel (a heap with no budget, a lock taken twice) or getting past a
// check. A kernel bug shows as a panic or a hang, not as this program's
// output. Run as /bin/hardening <what> [args].
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

#define SPLICE_F_NONBLOCK 2
#define PAGE 4096L

static long tee_(int in, int out, size_t len, unsigned flags) {
    return syscall(SYS_tee, in, out, len, flags);
}

// tee on one file: both sides are one lock. Linux's do_tee wants two
// different pipes, so all of these are EINVAL.
static int do_tee(void) {
    int null = open("/dev/null", O_RDWR);
    CHECK(null >= 0);
    errno = 0;
    CHECK(tee_(null, null, 1, 0) == -1 && errno == EINVAL);
    int dup = fcntl(null, F_DUPFD, 10);
    CHECK(tee_(null, dup, 1, 0) == -1 && errno == EINVAL);
    int fds[2];
    CHECK(pipe(fds) == 0);
    CHECK(tee_(fds[0], fds[1], 1, 0) == -1 && errno == EINVAL);
    CHECK(tee_(null, fds[1], 1, 0) == -1 && errno == EINVAL);
    CHECK(tee_(fds[0], null, 1, 0) == -1 && errno == EINVAL);
    // The wrong way round is a bad descriptor, not a lock.
    CHECK(tee_(fds[1], fds[0], 1, 0) == -1 && errno == EBADF);
    CHECK(tee_(fds[1], fds[1], 1, 0) == -1 && errno == EBADF);
    CHECK(tee_(fds[0], fds[0], 1, 0) == -1 && errno == EBADF);
    // A FIFO opened for both is one file, for reading and for writing.
    CHECK(mkfifo("/tmp/one", 0600) == 0);
    int fifo = open("/tmp/one", O_RDWR | O_NONBLOCK);
    CHECK(fifo >= 0);
    CHECK(write(fifo, "x", 1) == 1);
    CHECK(tee_(fifo, fifo, 1, 0) == -1 && errno == EINVAL);
    int fifo2 = open("/tmp/one", O_RDWR | O_NONBLOCK);
    CHECK(fifo2 >= 0);
    CHECK(tee_(fifo, fifo2, 1, 0) == -1 && errno == EINVAL);
    // splice's own check, for the same file both ways.
    CHECK(syscall(SYS_splice, fifo, NULL, fifo, NULL, 1, 0) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_splice, fifo, NULL, fifo2, NULL, 1, 0) == -1 && errno == EINVAL);
    printf("tee refused\n");
    return 0;
}

// tee(a, b) on one CPU and tee(b, a) on another: two locks, in opposite
// orders if the kernel takes them as given.
struct cross { int a, b; long calls; long copied; };

static void *tee_loop(void *arg) {
    struct cross *c = arg;
    char buf[512];
    for (long i = 0; i < c->calls; i++) {
        long n = i & 1 ? syscall(SYS_splice, c->a, NULL, c->b, NULL, sizeof buf, SPLICE_F_NONBLOCK)
                       : tee_(c->a, c->b, sizeof buf, SPLICE_F_NONBLOCK);
        if (n > 0) c->copied += n;
        else if (n < 0 && errno != EAGAIN && errno != EINVAL) { printf("tee: errno %d\n", errno); exit(1); }
        // Keep room in the pipe, and something in it.
        if (read(c->b, buf, sizeof buf) > 0) write(c->b, "y", 1);
        write(c->a, "x", 1);
    }
    return NULL;
}

static int do_teecross(long calls) {
    CHECK(mkfifo("/tmp/a", 0600) == 0 && mkfifo("/tmp/b", 0600) == 0);
    int a = open("/tmp/a", O_RDWR | O_NONBLOCK), b = open("/tmp/b", O_RDWR | O_NONBLOCK);
    CHECK(a >= 0 && b >= 0);
    int n1 = open("/dev/null", O_RDWR), n2 = open("/dev/null", O_RDWR);
    CHECK(n1 >= 0 && n2 >= 0);
    CHECK(write(a, "seed", 4) == 4 && write(b, "seed", 4) == 4);
    struct cross c[4] = {{a, b, calls}, {b, a, calls}, {n1, n2, calls}, {n2, n1, calls}};
    pthread_t t[4];
    for (int i = 0; i < 4; i++) CHECK(pthread_create(&t[i], NULL, tee_loop, &c[i]) == 0);
    for (int i = 0; i < 4; i++) CHECK(pthread_join(t[i], NULL) == 0);
    CHECK(c[0].copied + c[1].copied > 0);
    printf("tee crossed %ld times\n", calls);
    return 0;
}

// A thread with no libc state, which only yields: none of them returns,
// and none uses the stack they share.
static char shared_stack[4096] __attribute__((aligned(16)));

static long raw_thread(void) {
    long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
    long top = (long)(shared_stack + sizeof shared_stack);
#if defined(__aarch64__)
    register long x8 __asm__("x8") = SYS_clone;
    register long x0 __asm__("x0") = flags;
    register long x1 __asm__("x1") = top;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    __asm__ volatile(
        "svc 0\n"
        "cbnz x0, 1f\n"
        "0: mov x8, %[yield]\n"
        "svc 0\n"
        "b 0b\n"
        "1:\n"
        : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), [yield] "i"(SYS_sched_yield) : "memory", "cc");
    return x0;
#elif defined(__x86_64__)
    long ret;
    register long r10 __asm__("r10") = 0;
    register long r8 __asm__("r8") = 0;
    __asm__ volatile(
        "syscall\n"
        "test %%rax, %%rax\n"
        "jnz 1f\n"
        "0: mov %[yield], %%eax\n"
        "syscall\n"
        "jmp 0b\n"
        "1:\n"
        : "=a"(ret)
        : "0"(SYS_clone), "D"(flags), "S"(top), "d"(0), "r"(r10), "r"(r8), [yield] "i"(SYS_sched_yield)
        : "rcx", "r11", "memory", "cc");
    return ret;
#else
#error which architecture?
#endif
}

// Each child makes as many threads as it may and ends, and stays a zombie.
// Its threads gave back what they cost, so nothing may be left of them: a
// zombie's /proc/<pid>/task is its leader alone, as on Linux.
static int do_zombies(int rounds) {
    int others = 0;
    for (int r = 0; r < rounds; r++) {
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            long made = 0;
            while (raw_thread() >= 0) made++;
            char line[64];
            write(1, line, snprintf(line, sizeof line, "round %d: %s\n", r, made > 100 ? "threads" : "few threads"));
            syscall(SYS_exit_group, 0);
        }
        // Not reaped.
        siginfo_t si;
        CHECK(waitid(P_PID, pid, &si, WEXITED | WNOWAIT) == 0);
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/task", pid);
        int dir = open(path, O_RDONLY | O_DIRECTORY);
        CHECK(dir >= 0);
        char buf[4096];
        long n = syscall(SYS_getdents64, dir, buf, sizeof buf);
        CHECK(n > 0);
        int leader = 0;
        for (long at = 0; at < n; at += *(unsigned short *)(buf + at + 16)) {
            const char *name = buf + at + 19;
            if (atoi(name) == pid) leader = 1;
            else if (strcmp(name, ".") && strcmp(name, "..")) others++;
        }
        others += !leader;
        close(dir);
    }
    CHECK(others == 0);
    printf("survived %d rounds of zombies\n", rounds);
    return 0;
}

// `copies` mappings side by side of one memfd of `mb` MiB, every page read:
// page table entries by the million, on a few frames. How they then go is
// the point: every one has to pass through the kernel's hands at once.
static char *many_mappings(long mb, long copies, long *total) {
    long pages = mb * 256, len = pages * PAGE;
    *total = len * copies;
    int fd = memfd_create("many", 0);
    if (fd < 0 || ftruncate(fd, len)) return NULL;
    char *w = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (w == MAP_FAILED) return NULL;
    for (long i = 0; i < pages; i++) w[i * PAGE] = 1;
    char *base = mmap(NULL, *total, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;
    volatile char sink = 0;
    for (long c = 0; c < copies; c++) {
        char *at = mmap(base + c * len, len, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0);
        if (at != base + c * len) return NULL;
        for (long i = 0; i < pages; i++) sink += at[i * PAGE];
    }
    printf("mapped %ld pages\n", pages * copies);
    close(fd);
    return base;
}

static int do_entries(const char *how, long mb, long copies) {
    long total;
    char *base = many_mappings(mb, copies, &total);
    CHECK(base);
    if (!strcmp(how, "munmap")) {
        CHECK(munmap(base, total) == 0);
    } else if (!strcmp(how, "dontneed")) {
        CHECK(madvise(base, total, MADV_DONTNEED) == 0);
        CHECK(base[0] == 1 && base[total - PAGE] == 1);
    } else if (!strcmp(how, "fixed")) {
        CHECK(mmap(base, total, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == base);
        CHECK(base[0] == 0);
    } else if (!strcmp(how, "fork")) {
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) _exit(base[total - PAGE] == 1 ? 0 : 1);
        int status;
        CHECK(waitpid(pid, &status, 0) == pid && status == 0);
    } else if (!strcmp(how, "exec")) {
        char *argv[] = {"/bin/hardening", "execed", NULL};
        execv(argv[0], argv);
        CHECK(0);
    } else if (!strcmp(how, "kill")) {
        // The address space goes with a process killed in another one.
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) { pause(); _exit(1); }
        kill(pid, SIGKILL);
        CHECK(waitpid(pid, NULL, 0) == pid);
    } else if (strcmp(how, "exit")) {
        printf("which way?\n");
        return 2;
    }
    printf("%s survived\n", how);
    return 0;
}

// A page in every 2 MiB: a page table for each, which munmap frees.
static int do_tables(long tables) {
    long stride = 2L << 20, total = tables * stride;
    char *base = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    CHECK(base != MAP_FAILED);
    for (long i = 0; i < tables; i++) base[i * stride] = 1;
    CHECK(munmap(base, total) == 0);
    printf("tables survived\n");
    return 0;
}

// mremap moves a mapping's entries: all still there, in the new place, and
// none in the old one.
static int do_mremap(long mb) {
    long pages = mb * 256, len = pages * PAGE;
    char *old = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(old != MAP_FAILED);
    for (long i = 0; i < pages; i += 7) *(long *)(old + i * PAGE) = i;
    // Longer, so it has to move: something is in the way.
    char *in_the_way = mmap(old + len, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(in_the_way == old + len);
    char *new = mremap(old, len, len + PAGE, MREMAP_MAYMOVE);
    CHECK(new != MAP_FAILED && new != old);
    for (long i = 0; i < pages; i++) CHECK(*(long *)(new + i * PAGE) == (i % 7 ? 0 : i));
    CHECK(mincore(old, PAGE, (unsigned char[1]){0}) == -1 && errno == ENOMEM);
    printf("moved %ld pages\n", pages);
    return 0;
}

// Pages read from a hole in a shared file get a read-only copy. All it
// takes is a read and a madvise: nothing of the program's stays in memory,
// so whatever the kernel keeps per page has no bound.
static int do_holes(long pages) {
    long len = pages * PAGE;
    int fd = memfd_create("holes", 0);
    CHECK(fd >= 0 && ftruncate(fd, len) == 0);
    char *m = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED);
    volatile char sink = 0;
    long step = 4096;
    for (long at = 0; at < pages; at += step) {
        long n = pages - at < step ? pages - at : step;
        for (long i = 0; i < n; i++) sink += m[(at + i) * PAGE];
        CHECK(madvise(m + at * PAGE, n * PAGE, MADV_DONTNEED) == 0);
    }
    printf("read %ld holes\n", pages);
    return 0;
}

// Every hole a mapping has a copy of gets a frame, in one write: the
// mapping sees them all, in this process and another.
static int do_holefill(long pages) {
    long len = pages * PAGE;
    int fd = memfd_create("fill", 0);
    CHECK(fd >= 0 && ftruncate(fd, len) == 0);
    unsigned char *m = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED);
    volatile int sum = 0;
    for (long i = 0; i < pages; i++) sum += m[i * PAGE];
    CHECK(sum == 0);
    int go[2], done[2];
    CHECK(pipe(go) == 0 && pipe(done) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        char c;
        for (long i = 0; i < pages; i++) sum += m[i * PAGE];
        if (read(go[0], &c, 1) != 1) _exit(2);
        for (long i = 0; i < pages; i++) if (m[i * PAGE] != 0x5a) _exit(3);
        _exit(0);
    }
    char *chunk = malloc(len);
    CHECK(chunk);
    memset(chunk, 0x5a, len);
    CHECK(pwrite(fd, chunk, len, 0) == len);
    free(chunk);
    for (long i = 0; i < pages; i++) CHECK(m[i * PAGE] == 0x5a);
    CHECK(write(go[1], "x", 1) == 1);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    // A hole read after that, and a write there: the same again.
    CHECK(ftruncate(fd, len + 2 * PAGE) == 0);
    unsigned char *more = mmap(NULL, 2 * PAGE, PROT_READ, MAP_SHARED, fd, len);
    CHECK(more != MAP_FAILED && more[0] == 0 && more[PAGE] == 0);
    CHECK(pwrite(fd, "y", 1, len) == 1);
    CHECK(more[0] == 'y' && more[PAGE] == 0);
    CHECK(pwrite(fd, "z", 1, len + PAGE) == 1);
    CHECK(more[PAGE] == 'z' && more[0] == 'y');
    // Past a truncate, and back: a hole again.
    CHECK(ftruncate(fd, len + PAGE) == 0);
    printf("holes filled\n");
    return 0;
}

// One file dup'ed to every descriptor there may be, and each registered
// with epoll instance after instance: the file's the same, so no limit on
// files or descriptors applies to what epoll keeps.
static int do_epolls(long instances) {
    struct rlimit rl = {65536, 65536};
    CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
    int ev = syscall(SYS_eventfd2, 0, 0);
    CHECK(ev >= 0);
    int low = 1000, high = 60000;
    for (int i = low; i < high; i++) CHECK(dup2(ev, i) == i);
    struct epoll_event event = {.events = EPOLLIN};
    long added = 0, refused = 0;
    for (long e = 0; e < instances && !refused; e++) {
        int ep = epoll_create1(0);
        CHECK(ep >= 0);
        for (int i = low; i < high; i++) {
            if (epoll_ctl(ep, EPOLL_CTL_ADD, i, &event) == 0) added++;
            else if (errno == ENOSPC) { refused = 1; break; }
            else CHECK(0);
        }
    }
    CHECK(refused);
    printf("%s after a while\n", added > 10000 ? "refused" : "refused early");
    return 0;
}

// mmap and munmap of one file, over and over: nothing of a mapping that's
// gone may stay behind with the file.
static int do_remaps(long times) {
    int fd = memfd_create("remaps", 0);
    CHECK(fd >= 0 && ftruncate(fd, PAGE) == 0);
    for (long i = 0; i < times; i++) {
        char *m = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(m != MAP_FAILED);
        CHECK(munmap(m, PAGE) == 0);
    }
    printf("mapped %ld times\n", times);
    return 0;
}

// A magic link isn't followed with O_NOFOLLOW, whatever else is asked.
static int do_magic(void) {
    struct { unsigned long long flags, mode, resolve; } how = {O_RDONLY | O_NOFOLLOW, 0, 0};
    int f = open("/bin/hardening", O_RDONLY);
    CHECK(f >= 0);
    int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    CHECK(dir >= 0);
    char name[16], path[32];
    snprintf(name, sizeof name, "%d", f);
    snprintf(path, sizeof path, "/proc/self/fd/%d", f);
    errno = 0;
    CHECK(open(path, O_RDONLY | O_NOFOLLOW) == -1 && errno == ELOOP);
    CHECK(openat(dir, name, O_RDONLY | O_NOFOLLOW) == -1 && errno == ELOOP);
    unsigned long long modes[] = {0, 0x02 | 0x08, 0x02, 0x08, 0x10 | 0x04};
    for (int i = 0; i < 5; i++) {
        how.resolve = modes[i];
        errno = 0;
        CHECK(syscall(SYS_openat2, dir, name, &how, sizeof how) == -1 && errno == ELOOP);
    }
    // Followed, it's refused for what it is, and without any of it it opens.
    how.flags = O_RDONLY;
    how.resolve = 0x02;
    errno = 0;
    CHECK(syscall(SYS_openat2, dir, name, &how, sizeof how) == -1 && errno == ELOOP);
    how.resolve = 0;
    int opened = syscall(SYS_openat2, dir, name, &how, sizeof how);
    CHECK(opened >= 0);
    CHECK(open(path, O_RDONLY) >= 0);
    CHECK(open(path, O_RDONLY | O_CREAT | O_EXCL, 0600) == -1 && errno == EEXIST);
    printf("magic links refused\n");
    return 0;
}

// Writes that fail, or say nothing, from one process after another: a
// stream with no bytes in it must not fill up with who wrote them.
static int do_creds(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    int on = 1;
    CHECK(setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &on, sizeof on) == 0);
    CHECK(setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on) == 0);
    CHECK(fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
    for (int i = 0; i < 300; i++) {
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            errno = 0;
            if (write(sv[0], (void *)1, 16) != -1 || errno != EFAULT) _exit(1);
            if (send(sv[0], "", 0, 0) != 0) _exit(2);
            _exit(0);
        }
        int status;
        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(write(sv[0], "hi", 2) == 2);
    char buf[8], control[64];
    struct iovec iov = {buf, sizeof buf};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control};
    CHECK(recvmsg(sv[1], &msg, 0) == 2 && buf[0] == 'h');
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    CHECK(cm && cm->cmsg_type == SCM_CREDENTIALS);
    CHECK(((struct ucred *)CMSG_DATA(cm))->pid == getpid());
    printf("stream still works\n");
    return 0;
}

// More names than any list may be.
static int do_xattrs(long names) {
    const char *path = "/tmp/names";
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    CHECK(fd >= 0);
    char name[255];
    memset(name, 'n', sizeof name);
    memcpy(name, "user.", 5);
    name[sizeof name - 1] = 0;
    long made = 0, length = 0;
    for (; made < names; made++) {
        snprintf(name + 5, 20, "%019ld", made);
        name[24] = 'n';
        if (fsetxattr(fd, name, "", 0, 0)) break;
        length += sizeof name;
    }
    CHECK(made > 65536 / 255);
    printf("%ld names\n", made);
    static char list[1 << 20];
    CHECK(flistxattr(fd, NULL, 0) == length);
    errno = 0;
    CHECK(flistxattr(fd, list, sizeof list) == -1 && errno == E2BIG);
    errno = 0;
    CHECK(flistxattr(fd, list, 65536) == -1 && errno == E2BIG);
    errno = 0;
    CHECK(flistxattr(fd, list, 100) == -1 && errno == ERANGE);
    // Few enough, it works as ever.
    for (long i = made - 1; i >= 10; i--) {
        snprintf(name + 5, 20, "%019ld", i);
        name[24] = 'n';
        CHECK(fremovexattr(fd, name) == 0);
    }
    CHECK(flistxattr(fd, list, sizeof list) == 10 * (long)sizeof name);
    printf("lists refused\n");
    return 0;
}

// /proc/self/mem is the memory it was opened on: a descriptor that survives
// execve doesn't reach the new program (Linux: reads and writes do nothing).
static volatile long secret = 0x5ec2e7;

static int do_procmem(void) {
    int fd = open("/proc/self/mem", O_RDWR);
    CHECK(fd >= 0);
    long got = 0;
    CHECK(pread(fd, &got, sizeof got, (long)&secret) == sizeof got && got == secret);
    CHECK(fcntl(fd, F_SETFD, 0) == 0);
    char arg[16];
    snprintf(arg, sizeof arg, "%d", fd);
    char *argv[] = {"/bin/hardening", "procmem-after", arg, NULL};
    execv(argv[0], argv);
    CHECK(0);
    return 1;
}

static int do_procmem_after(int fd) {
    long got = -1, mine = 0x1234;
    secret = 0x7777;
    CHECK(pread(fd, &got, sizeof got, (long)&secret) == 0);
    CHECK(pwrite(fd, &mine, sizeof mine, (long)&secret) == 0);
    CHECK(secret == 0x7777);
    int again = open("/proc/self/mem", O_RDONLY);
    CHECK(again >= 0);
    CHECK(pread(again, &got, sizeof got, (long)&secret) == sizeof got && got == 0x7777);
    // After fork it's another's, as before.
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        errno = 0;
        _exit(pread(again, &got, sizeof got, (long)&secret) == -1 && errno == EIO ? 0 : 1);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && status == 0);
    printf("the old memory is gone\n");
    return 0;
}

int main(int argc, char **argv) {
    const char *what = argc > 1 ? argv[1] : "";
    long a = argc > 2 ? atol(argv[2]) : 0, b = argc > 3 ? atol(argv[3]) : 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!strcmp(what, "tee")) return do_tee();
    if (!strcmp(what, "teecross")) return do_teecross(a ? a : 20000);
    if (!strcmp(what, "zombies")) return do_zombies(a ? a : 40);
    if (!strcmp(what, "entries")) return do_entries(argv[2], b ? b : 64, argc > 4 ? atol(argv[4]) : 140);
    if (!strcmp(what, "execed")) { printf("exec survived\n"); return 0; }
    if (!strcmp(what, "tables")) return do_tables(a ? a : 20000);
    if (!strcmp(what, "mremap")) return do_mremap(a ? a : 256);
    if (!strcmp(what, "holes")) return do_holes(a ? a : 4000000);
    if (!strcmp(what, "holefill")) return do_holefill(a ? a : 4096);
    if (!strcmp(what, "remaps")) return do_remaps(a ? a : 2000000);
    if (!strcmp(what, "epolls")) return do_epolls(a ? a : 500);
    if (!strcmp(what, "magic")) return do_magic();
    if (!strcmp(what, "creds")) return do_creds();
    if (!strcmp(what, "xattrs")) return do_xattrs(a ? a : 5000);
    if (!strcmp(what, "procmem")) return do_procmem();
    if (!strcmp(what, "procmem-after")) return do_procmem_after(a);
    printf("usage\n");
    return 2;
}
