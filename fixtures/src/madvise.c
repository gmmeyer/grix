// madvise as Linux 6.1 has it: what each advice does, and what it refuses.
// Built with -DON_LINUX it runs on Linux itself, to check what this expects;
// the only differences are grix's own, and marked.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 4096
#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            fflush(stdout);                                                       \
            _exit(1);                                                             \
        }                                                                         \
    } while (0)
#define FAILS(c, e) CHECK((long)(c) == -1 && errno == (e))

#ifndef MADV_COLD
#define MADV_COLD 20
#define MADV_PAGEOUT 21
#endif
#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22
#define MADV_POPULATE_WRITE 23
#endif
#ifndef MADV_DONTNEED_LOCKED
#define MADV_DONTNEED_LOCKED 24
#endif
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif

static char *pages(int n, int prot, int flags) {
    char *p = mmap(0, n * PAGE, prot, flags, -1, 0);
    CHECK(p != MAP_FAILED);
    return p;
}

static char *anon(int n) {
    return pages(n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
}

static char *shared(int n) {
    return pages(n, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS);
}

// A file of `n` pages, each starting with 'f'.
static int file(int n) {
    int fd = memfd_create("madvise", 0);
    CHECK(fd >= 0 && ftruncate(fd, n * PAGE) == 0);
    for (int i = 0; i < n; i++) CHECK(pwrite(fd, "f", 1, i * PAGE) == 1);
    return fd;
}

static char *mapped(int fd, int n, int prot, int flags) {
    char *p = mmap(0, n * PAGE, prot, flags, fd, 0);
    CHECK(p != MAP_FAILED);
    return p;
}

static void on_segv(int s) {
    (void)s;
    _exit(200);
}

// What a child finds at `p`: the byte there, or -1 for nothing mapped.
static int peek(char *p) {
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        signal(SIGSEGV, on_segv);
        _exit(*(volatile char *)p);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st));
    return WEXITSTATUS(st) == 200 ? -1 : WEXITSTATUS(st);
}

// And a vfork child, which on Linux is in the caller's memory.
static int vfork_peek(char *p) {
    fflush(stdout);
    pid_t c = vfork();
    CHECK(c >= 0);
    if (c == 0) _exit(*(volatile char *)p);
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st));
    return WEXITSTATUS(st);
}

// Does the mapping holding `p` have `flag` in its VmFlags?
static int vm_flag(char *p, const char *flag) {
    FILE *f = fopen("/proc/self/smaps", "r");
    CHECK(f);
    char line[512];
    int in = 0, found = -1;
    while (fgets(line, sizeof line, f)) {
        unsigned long start, end;
        // (Linux joins neighbours: a mapping may start before `p`.)
        if (sscanf(line, "%lx-%lx ", &start, &end) == 2) in = start <= (unsigned long)p && (unsigned long)p < end;
        if (in && !strncmp(line, "VmFlags:", 8)) {
            found = strstr(line, flag) != 0;
            break;
        }
    }
    fclose(f);
    CHECK(found >= 0);
    return found;
}

static int resident(char *p, int n) {
    unsigned char v[64];
    CHECK(n <= 64 && mincore(p, n * PAGE, v) == 0);
    int count = 0;
    for (int i = 0; i < n; i++) count += v[i] & 1;
    return count;
}

// Advice that changes nothing a program can see, and its checks.
static void advice_values(void) {
    char *p = anon(2);
    p[0] = 'x';
    int hints[] = {MADV_NORMAL,      MADV_RANDOM,   MADV_SEQUENTIAL, MADV_WILLNEED, MADV_MERGEABLE,
                   MADV_UNMERGEABLE, MADV_HUGEPAGE, MADV_NOHUGEPAGE, MADV_DONTDUMP, MADV_DODUMP,
                   MADV_COLD,        MADV_PAGEOUT};
    for (unsigned i = 0; i < sizeof hints / sizeof hints[0]; i++) {
        CHECK(madvise(p, 2 * PAGE, hints[i]) == 0);
        // Even one that pages out reads the same.
        CHECK(p[0] == 'x');
    }
    int bad[] = {5, 6, 7, 26, 99, 102, 103, 1000, -1};
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        FAILS(madvise(p, PAGE, bad[i]), EINVAL);
        // First: no length makes it right.
        FAILS(madvise(p, 0, bad[i]), EINVAL);
    }
#ifndef ON_LINUX
    // No CONFIG_MEMORY_FAILURE here. (On Linux, as root, they'd do it.)
    FAILS(madvise(p, PAGE, 100), EINVAL);
    FAILS(madvise(p, PAGE, 101), EINVAL);
    // Nothing is a huge page. (On Linux it depends on the machine.)
    FAILS(madvise(p, PAGE, MADV_COLLAPSE), EINVAL);
#endif
    FAILS(madvise(p + 1, PAGE, MADV_NORMAL), EINVAL);
    FAILS(madvise(p + 1, 0, MADV_NORMAL), EINVAL);
    // A length that rounds up to nothing, or runs off the end.
    FAILS(madvise(p, (size_t)-1, MADV_NORMAL), EINVAL);
    FAILS(madvise(p, -(uintptr_t)p, MADV_NORMAL), EINVAL);
    // Nothing to do, wherever it is, and whatever would've refused it.
    CHECK(munmap(p + PAGE, PAGE) == 0);
    CHECK(madvise(p + PAGE, 0, MADV_DONTNEED) == 0);
}

// What's mapped of a range is done, and then ENOMEM for what isn't.
static void holes(void) {
    char *p = anon(3);
    CHECK(munmap(p + PAGE, PAGE) == 0);
    p[0] = p[2 * PAGE] = 'x';
    FAILS(madvise(p, 3 * PAGE, MADV_WILLNEED), ENOMEM);
    CHECK(p[0] == 'x' && p[2 * PAGE] == 'x');
    FAILS(madvise(p, 3 * PAGE, MADV_DONTNEED), ENOMEM);
    CHECK(p[0] == 0 && p[2 * PAGE] == 0);
    FAILS(madvise(p + PAGE, PAGE, MADV_NORMAL), ENOMEM);
    // Past what any program can map.
    FAILS(madvise((void *)(uintptr_t)(1ull << 62), PAGE, MADV_NORMAL), ENOMEM);
    FAILS(madvise(p, 3 * PAGE, MADV_POPULATE_READ), ENOMEM);
    // A mapping's own error comes first, and those before it are done.
    char *q = anon(2);
    q[0] = 'x';
    CHECK(munmap(q + PAGE, PAGE) == 0);
    char *after = mmap(q + PAGE, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(after == q + PAGE);
    FAILS(madvise(q, 2 * PAGE, MADV_WIPEONFORK), EINVAL);
    CHECK(vm_flag(q, "wf") == 1);
}

static void discarding(void) {
    char *p = anon(2);
    p[0] = p[PAGE] = 'x';
    CHECK(madvise(p, PAGE, MADV_DONTNEED) == 0);
    CHECK(p[0] == 0 && p[PAGE] == 'x');
    CHECK(madvise(p + PAGE, PAGE, MADV_DONTNEED_LOCKED) == 0);
    CHECK(p[PAGE] == 0);
    p[0] = 'x';
    CHECK(madvise(p, PAGE, MADV_FREE) == 0);
    // A write after it stays, as ever.
    p[0] = 'y';
    CHECK(p[0] == 'y');
    // A private mapping of a file: its copies stay on MADV_FREE, which is
    // only for what's nobody else's, and DONTNEED goes back to the file.
    int fd = file(1);
    char *f = mapped(fd, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE);
    f[0] = 'c';
    FAILS(madvise(f, PAGE, MADV_FREE), EINVAL);
    CHECK(f[0] == 'c');
    CHECK(madvise(f, PAGE, MADV_DONTNEED) == 0);
    CHECK(f[0] == 'f');
    // Shared memory is its own: DONTNEED only drops this mapping's view.
    char *s = shared(1);
    s[0] = 's';
    FAILS(madvise(s, PAGE, MADV_FREE), EINVAL);
    CHECK(s[0] == 's');
    CHECK(madvise(s, PAGE, MADV_DONTNEED) == 0);
    CHECK(s[0] == 's');
}

static void dontfork(void) {
    char *p = anon(3);
    p[0] = 'a';
    p[PAGE] = 'b';
    p[2 * PAGE] = 'c';
    CHECK(madvise(p + PAGE, PAGE, MADV_DONTFORK) == 0);
    CHECK(vm_flag(p + PAGE, "dc") == 1 && vm_flag(p, "dc") == 0 && vm_flag(p + 2 * PAGE, "dc") == 0);
    // Only that page, and only for a child.
    CHECK(peek(p) == 'a' && peek(p + PAGE) == -1 && peek(p + 2 * PAGE) == 'c');
    CHECK(p[PAGE] == 'b');
    // A vfork child is in this memory.
    CHECK(vfork_peek(p + PAGE) == 'b');
    CHECK(madvise(p, 3 * PAGE, MADV_DOFORK) == 0);
    CHECK(peek(p + PAGE) == 'b');
    // Shared memory too.
    char *s = shared(1);
    s[0] = 's';
    CHECK(peek(s) == 's');
    CHECK(madvise(s, PAGE, MADV_DONTFORK) == 0);
    CHECK(peek(s) == -1);
    // A child without a segment isn't attached to it.
    int id = shmget(IPC_PRIVATE, PAGE, IPC_CREAT | 0600);
    CHECK(id >= 0);
    char *seg = shmat(id, 0, 0);
    CHECK(seg != (void *)-1 && shmctl(id, IPC_RMID, 0) == 0);
    CHECK(madvise(seg, PAGE, MADV_DONTFORK) == 0);
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        struct shmid_ds ds;
        CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1);
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(shmdt(seg) == 0);
}

static void wipeonfork(void) {
    char *p = anon(3);
    p[0] = 'a';
    p[PAGE] = 'b';
    p[2 * PAGE] = 'c';
    CHECK(madvise(p + PAGE, PAGE, MADV_WIPEONFORK) == 0);
    CHECK(vm_flag(p + PAGE, "wf") == 1 && vm_flag(p, "wf") == 0 && vm_flag(p + 2 * PAGE, "wf") == 0);
    CHECK(peek(p) == 'a' && peek(p + PAGE) == 0 && peek(p + 2 * PAGE) == 'c');
    CHECK(p[PAGE] == 'b');
    CHECK(vfork_peek(p + PAGE) == 'b');
    // It stays with the mapping: a child's children get it empty too, and
    // it's there to write to.
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        CHECK(p[PAGE] == 0 && vm_flag(p + PAGE, "wf") == 1);
        p[PAGE] = 'd';
        CHECK(peek(p + PAGE) == 0);
        CHECK(p[PAGE] == 'd');
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(p[PAGE] == 'b');
    CHECK(madvise(p + PAGE, PAGE, MADV_KEEPONFORK) == 0);
    CHECK(peek(p + PAGE) == 'b' && vm_flag(p + PAGE, "wf") == 0);
    // Only memory that's nobody else's.
    char *s = shared(1);
    FAILS(madvise(s, PAGE, MADV_WIPEONFORK), EINVAL);
    int fd = file(1);
    char *f = mapped(fd, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE);
    FAILS(madvise(f, PAGE, MADV_WIPEONFORK), EINVAL);
    // Both at once: not there at all, until it's DOFORK and then empty.
    char *b = anon(1);
    b[0] = 'b';
    CHECK(madvise(b, PAGE, MADV_DONTFORK) == 0 && madvise(b, PAGE, MADV_WIPEONFORK) == 0);
    CHECK(peek(b) == -1);
    CHECK(madvise(b, PAGE, MADV_DOFORK) == 0);
    CHECK(peek(b) == 0);
}

static void populate(void) {
    char *p = anon(4);
    CHECK(resident(p, 4) == 0);
    CHECK(madvise(p, 2 * PAGE, MADV_POPULATE_WRITE) == 0);
    CHECK(resident(p, 4) == 2);
    CHECK(madvise(p + 2 * PAGE, 2 * PAGE, MADV_POPULATE_READ) == 0);
    CHECK(resident(p, 4) == 4);
    // Written to after a fork: this copy's own.
    char *c = anon(1);
    c[0] = 'c';
    fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(madvise(c, PAGE, MADV_POPULATE_WRITE) == 0);
        c[0] = 'd';
        _exit(0);
    }
    int st;
    CHECK(waitpid(pid, &st, 0) == pid && WEXITSTATUS(st) == 0 && c[0] == 'c');
    // Permissions are EINVAL here, not EFAULT.
    char *ro = pages(1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS);
    FAILS(madvise(ro, PAGE, MADV_POPULATE_WRITE), EINVAL);
    CHECK(madvise(ro, PAGE, MADV_POPULATE_READ) == 0);
    char *none = pages(1, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS);
    FAILS(madvise(none, PAGE, MADV_POPULATE_READ), EINVAL);
    FAILS(madvise(none, PAGE, MADV_POPULATE_WRITE), EINVAL);
    // Past a file's end is what SIGBUS would be.
    int fd = file(1);
    char *f = mapped(fd, 2, PROT_READ | PROT_WRITE, MAP_SHARED);
    CHECK(madvise(f, PAGE, MADV_POPULATE_READ) == 0);
    FAILS(madvise(f, 2 * PAGE, MADV_POPULATE_READ), EFAULT);
}

static void removing(void) {
    char *p = anon(1);
    FAILS(madvise(p, PAGE, MADV_REMOVE), EINVAL);
    int fd = file(1);
    char *priv = mapped(fd, 1, PROT_READ | PROT_WRITE, MAP_PRIVATE);
    FAILS(madvise(priv, PAGE, MADV_REMOVE), EACCES);
    // What the descriptor could do, not what the mapping does.
    char path[32];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    int rfd = open(path, O_RDONLY);
    CHECK(rfd >= 0);
    char *ro = mapped(rfd, 1, PROT_READ, MAP_SHARED);
    FAILS(madvise(ro, PAGE, MADV_REMOVE), EACCES);
    char *rw = mapped(fd, 1, PROT_READ, MAP_SHARED);
    CHECK(madvise(rw, PAGE, MADV_REMOVE) == 0 && rw[0] == 0);
}

static void cutting(int n) {
    // Mappings cut by what's asked of parts of them count like any others.
    char *p = anon(n);
    int cut = 0;
    for (int i = 1; i < n; i += 2) {
        if (madvise(p + i * PAGE, PAGE, MADV_DONTFORK) != 0) {
            CHECK(errno == EAGAIN);
            cut = 1;
            break;
        }
    }
    CHECK(cut);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc > 1 && !strcmp(argv[1], "remove")) {
        removing();
        printf("madvise remove ok\n");
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "cut")) {
        cutting(atoi(argv[2]));
        printf("madvise cut ok\n");
        return 0;
    }
    advice_values();
    holes();
    discarding();
    dontfork();
    wipeonfork();
    populate();
    printf("madvise ok\n");
    return 0;
}
