// Calls real programs meet less often, one check per way they can go.
// Passes on Linux, built with -DON_LINUX, on a kernel from before the
// marked ones (6.1: cachestat, mseal and futex2's are newer).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                   \
    do {                                                                           \
        if (!(c)) {                                                                \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);       \
            exit(1);                                                               \
        }                                                                          \
    } while (0)
#define FAILS(call, e) CHECK((long)(call) == -1 && errno == (e))

#ifndef SYS_cachestat
#define SYS_cachestat 451
#endif
#ifndef SYS_mseal
#define SYS_mseal 462
#endif
#ifndef SYS_futex_wake
#define SYS_futex_wake 454
#define SYS_futex_wait 455
#define SYS_futex_requeue 456
#endif
#ifndef SYS_memfd_secret
#define SYS_memfd_secret 447
#endif
#ifndef SYS_map_shadow_stack
#define SYS_map_shadow_stack 453
#endif
#ifndef SYS_process_mrelease
#define SYS_process_mrelease 448
#endif
#ifndef SYS_set_mempolicy_home_node
#define SYS_set_mempolicy_home_node 450
#endif
#ifndef SYS_lsm_list_modules
#define SYS_lsm_list_modules 461
#endif

struct sched_attr {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
};

static char *path = "/tmp/linuxcalls";

static void files(void) {
    int f = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(f >= 0 && write(f, "0123456789", 10) == 10);
    int p[2];
    CHECK(pipe(p) == 0);

    CHECK(syncfs(f) == 0);
    FAILS(syncfs(1234), EBADF);

    CHECK(sync_file_range(f, 0, 0, 0) == 0);
    CHECK(sync_file_range(f, 0, 5, SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER) == 0);
    FAILS(sync_file_range(f, 0, 0, 8), EINVAL);
    FAILS(sync_file_range(f, -1, 0, 0), EINVAL);
    FAILS(sync_file_range(f, 0, -1, 0), EINVAL);
    FAILS(sync_file_range(p[0], 0, 0, 0), ESPIPE);
    FAILS(sync_file_range(1234, 0, 0, 0), EBADF);

    CHECK(readahead(f, 0, 4096) == 0);
    CHECK(readahead(f, 1 << 20, 4096) == 0);
    FAILS(readahead(p[0], 0, 4096), EINVAL);
    FAILS(readahead(1234, 0, 4096), EBADF);
    int w = open(path, O_WRONLY);
    FAILS(readahead(w, 0, 4096), EBADF);
    close(w);
    close(p[0]);
    close(p[1]);
    close(f);
    unlink(path);
    printf("files ok\n");
}

static void sched(void) {
    struct timespec ts;
    CHECK(sched_rr_get_interval(0, &ts) == 0);
    CHECK(ts.tv_sec >= 0 && ts.tv_nsec >= 0);
    FAILS(sched_rr_get_interval(-1, &ts), EINVAL);
    FAILS(sched_rr_get_interval(0x3ffffff, &ts), ESRCH);

    struct sched_attr a;
    memset(&a, 0xff, sizeof a);
    CHECK(syscall(SYS_sched_getattr, 0, &a, sizeof a, 0) == 0);
    CHECK(a.size == 48 || a.size == 56);
    CHECK(a.policy == SCHED_OTHER && a.flags == 0 && a.nice == 0);
    CHECK(a.priority == 0 && a.runtime == 0 && a.deadline == 0 && a.period == 0);
    FAILS(syscall(SYS_sched_getattr, 0, &a, 8, 0), EINVAL);
    FAILS(syscall(SYS_sched_getattr, 0, &a, sizeof a, 1), EINVAL);
    FAILS(syscall(SYS_sched_getattr, 0x3ffffff, &a, sizeof a, 0), ESRCH);
    // A nicer one, seen in both ways of asking.
    a.size = 48;
    a.nice = 5;
    CHECK(syscall(SYS_sched_setattr, 0, &a, 0) == 0);
    memset(&a, 0, sizeof a);
    CHECK(syscall(SYS_sched_getattr, 0, &a, sizeof a, 0) == 0 && a.nice == 5);
    errno = 0;
    CHECK(getpriority(PRIO_PROCESS, 0) == 5 && errno == 0);
    CHECK(setpriority(PRIO_PROCESS, 0, 7) == 0);
    errno = 0;
    CHECK(getpriority(PRIO_PROCESS, getpid()) == 7 && errno == 0);
#ifndef ON_LINUX
    // The best of the group: on a real machine, there's more of it.
    CHECK(getpriority(PRIO_PGRP, 0) == 7 && errno == 0);
#endif
    FAILS(setpriority(99, 0, 0), EINVAL);
    FAILS(setpriority(PRIO_PROCESS, 0x3ffffff, 0), ESRCH);
    // Lower takes what a user hasn't got.
    if (geteuid() != 0) FAILS(setpriority(PRIO_PROCESS, 0, 3), EACCES);
    CHECK(setpriority(PRIO_PROCESS, 0, 19) == 0);
    CHECK(setpriority(PRIO_PROCESS, 0, 100) == 0);
    errno = 0;
    CHECK(getpriority(PRIO_PROCESS, 0) == 19 && errno == 0);
    a.nice = 19;
    a.size = 48;
    FAILS(syscall(SYS_sched_setattr, 0, &a, 1), EINVAL);
    a.policy = 99;
    FAILS(syscall(SYS_sched_setattr, 0, &a, 0), EINVAL);
    printf("sched ok\n");
}

static void ioprio(void) {
    enum { WHO_PROCESS = 1, WHO_PGRP = 2, WHO_USER = 3, CLASS_SHIFT = 13 };
    long got = syscall(SYS_ioprio_get, WHO_PROCESS, 0);
    CHECK(got >= 0);
    int best_effort_3 = 2 << CLASS_SHIFT | 3;
    CHECK(syscall(SYS_ioprio_set, WHO_PROCESS, 0, best_effort_3) == 0);
    CHECK(syscall(SYS_ioprio_get, WHO_PROCESS, 0) == best_effort_3);
    CHECK(syscall(SYS_ioprio_get, WHO_PGRP, 0) == best_effort_3);
#ifndef ON_LINUX
    // The best of every process of the user: on a real machine, not only ours.
    CHECK(syscall(SYS_ioprio_get, WHO_USER, 0) == best_effort_3);
#endif
    // A child has what its parent had.
    pid_t c = fork();
    CHECK(c >= 0);
    if (!c) _exit(syscall(SYS_ioprio_get, WHO_PROCESS, 0) == best_effort_3 ? 0 : 1);
    int status;
    CHECK(waitpid(c, &status, 0) == c && status == 0);
    FAILS(syscall(SYS_ioprio_set, 99, 0, best_effort_3), EINVAL);
    FAILS(syscall(SYS_ioprio_get, 99, 0), EINVAL);
    FAILS(syscall(SYS_ioprio_set, WHO_PROCESS, 0, 7 << CLASS_SHIFT), EINVAL);
    FAILS(syscall(SYS_ioprio_set, WHO_PROCESS, 0x3ffffff, best_effort_3), ESRCH);
    printf("ioprio ok\n");
}

static void clocks(void) {
    struct timex t;
    memset(&t, 0, sizeof t);
    int state = adjtimex(&t);
    CHECK(state >= 0 && state <= 5);
    CHECK(t.tick > 0);
    memset(&t, 0, sizeof t);
    CHECK(syscall(SYS_clock_adjtime, CLOCK_REALTIME, &t) >= 0);
    FAILS(syscall(SYS_clock_adjtime, 1234, &t), EINVAL);
    // Changing the clock takes what no one here has.
    if (geteuid() != 0) {
        memset(&t, 0, sizeof t);
        t.modes = ADJ_OFFSET;
        FAILS(adjtimex(&t), EPERM);
    }
    printf("clocks ok\n");
}

static void process(void) {
    // Run directly, restart_syscall says nothing was interrupted.
    FAILS(syscall(SYS_restart_syscall), EINTR);
    int me = syscall(SYS_pidfd_open, getpid(), 0);
    CHECK(me >= 0);
    // Alive and well: nothing to reap the memory of.
    FAILS(syscall(SYS_process_mrelease, me, 0), EINVAL);
    FAILS(syscall(SYS_process_mrelease, me, 1), EINVAL);
    FAILS(syscall(SYS_process_mrelease, 1234, 0), EBADF);
    FAILS(syscall(SYS_process_mrelease, 0, 0), EBADF);
    char page[4096];
    struct iovec v = {page, sizeof page};
    FAILS(syscall(SYS_process_madvise, 1234, &v, 1, MADV_COLD, 0), EBADF);
    FAILS(syscall(SYS_process_madvise, me, &v, 1, MADV_COLD, 1), EINVAL);
    close(me);
    printf("process ok\n");
}

static void memory(void) {
    long size = sysconf(_SC_PAGESIZE);
    char *m = mmap(0, 4 * size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED);
    m[0] = 1;
    // Keys take hardware nothing here has: as Linux without it, which on
    // x86 finds that out setting up a key it had, and on arm64 has none.
#ifdef __x86_64__
    FAILS(syscall(SYS_pkey_alloc, 0, 0), EINVAL);
#else
    FAILS(syscall(SYS_pkey_alloc, 0, 0), ENOSPC);
#endif
    FAILS(syscall(SYS_pkey_alloc, 1, 0), EINVAL);
    FAILS(syscall(SYS_pkey_free, 1), EINVAL);
    FAILS(syscall(SYS_pkey_mprotect, m, size, PROT_READ, 1), EINVAL);
    CHECK(syscall(SYS_pkey_mprotect, m, size, PROT_READ, -1) == 0);
    CHECK(mprotect(m, size, PROT_READ | PROT_WRITE) == 0);

    // One node, and the page that's there is on it.
    void *pages[3] = {m, m + size, (void *)0x10};
    int status[3] = {-99, -99, -99};
    CHECK(syscall(SYS_move_pages, 0, 3, pages, 0, status, 0) == 0);
    CHECK(status[0] == 0 && status[1] == -EFAULT && status[2] == -EFAULT);
    int nodes[1] = {0};
    CHECK(syscall(SYS_move_pages, 0, 1, pages, nodes, status, 0) == 0 && status[0] == 0);
    nodes[0] = 7;
    FAILS(syscall(SYS_move_pages, 0, 1, pages, nodes, status, 0), ENODEV);
    FAILS(syscall(SYS_move_pages, 0, 1, pages, 0, status, 8), EINVAL);
    FAILS(syscall(SYS_move_pages, 0x3ffffff, 1, pages, 0, status, 0), ESRCH);
    unsigned long from = 1, to = 1;
    CHECK(syscall(SYS_migrate_pages, 0, 64, &from, &to) == 0);
    FAILS(syscall(SYS_migrate_pages, 0x3ffffff, 64, &from, &to), ESRCH);
    FAILS(syscall(SYS_set_mempolicy_home_node, m, size, 0, 1), EINVAL);
    FAILS(syscall(SYS_set_mempolicy_home_node, m, size, 7, 0), EINVAL);
    FAILS(syscall(SYS_set_mempolicy_home_node, m + 1, size, 0, 0), EINVAL);

    // Off unless it's asked for at boot, and nothing here asks.
    FAILS(syscall(SYS_memfd_secret, 0), ENOSYS);
    munmap(m, 4 * size);
    printf("memory ok\n");
}

// A file's page moved out from under a shared mapping.
static void remap(void) {
    long size = sysconf(_SC_PAGESIZE);
    int f = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(f >= 0 && ftruncate(f, 2 * size) == 0);
    CHECK(pwrite(f, "a", 1, 0) == 1 && pwrite(f, "b", 1, size) == 1);
    char *m = mmap(0, 2 * size, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
    CHECK(m != MAP_FAILED);
    CHECK(m[0] == 'a' && m[size] == 'b');
    CHECK(syscall(SYS_remap_file_pages, m, size, 0, 1, 0) == 0);
    CHECK(m[0] == 'b' && m[size] == 'b');
    // Not of a private mapping's, or a shared one's prot.
    FAILS(syscall(SYS_remap_file_pages, m, size, PROT_READ, 1, 0), EINVAL);
    char *q = mmap(0, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(q != MAP_FAILED);
    FAILS(syscall(SYS_remap_file_pages, q, size, 0, 0, 0), EINVAL);
    munmap(q, size);
    munmap(m, 2 * size);
    close(f);
    unlink(path);
    printf("remap ok\n");
}

#ifndef ON_LINUX
static void newer(void) {
    long size = sysconf(_SC_PAGESIZE);
    int f = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(f >= 0 && ftruncate(f, 3 * size) == 0 && pwrite(f, "x", 1, size) == 1);
    uint64_t range[2] = {0, 3 * (uint64_t)size}, stat[5];
    memset(stat, 0xff, sizeof stat);
    CHECK(syscall(SYS_cachestat, f, range, stat, 0) == 0);
    CHECK(stat[0] == 1 && stat[1] == 0 && stat[2] == 0 && stat[3] == 0 && stat[4] == 0);
    FAILS(syscall(SYS_cachestat, f, range, stat, 1), EINVAL);
    FAILS(syscall(SYS_cachestat, 1234, range, stat, 0), EBADF);
    int p[2];
    CHECK(pipe(p) == 0);
    FAILS(syscall(SYS_cachestat, p[0], range, stat, 0), ESPIPE);
    close(p[0]);
    close(p[1]);
    close(f);
    unlink(path);

    char *m = mmap(0, 4 * size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED);
    FAILS(syscall(SYS_mseal, m, size, 1), EINVAL);
    FAILS(syscall(SYS_mseal, m + 1, size, 0), EINVAL);
    CHECK(munmap(m + 3 * size, size) == 0);
    // All of it must be mapped, and nothing's sealed if it isn't.
    FAILS(syscall(SYS_mseal, m + 2 * size, 2 * size, 0), ENOMEM);
    CHECK(mprotect(m + 2 * size, size, PROT_READ) == 0);
    CHECK(syscall(SYS_mseal, m + size, size, 0) == 0);
    // Again is nothing.
    CHECK(syscall(SYS_mseal, m + size, size, 0) == 0);
    FAILS(mprotect(m + size, size, PROT_READ), EPERM);
    FAILS(munmap(m + size, size), EPERM);
    FAILS(munmap(m, 2 * size), EPERM);
    FAILS(mremap(m + size, size, 2 * size, MREMAP_MAYMOVE), EPERM);
    CHECK(mmap(m + size, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED && errno == EPERM);
    // Writable, a program could have zeroed it anyway. Read-only, it couldn't.
    CHECK(madvise(m + size, size, MADV_DONTNEED) == 0);
    CHECK(syscall(SYS_mseal, m + 2 * size, size, 0) == 0);
    FAILS(madvise(m + 2 * size, size, MADV_DONTNEED), EPERM);
    // Its neighbours are as they were, and it's still there.
    CHECK(munmap(m, size) == 0);
    m[size] = 1;
    CHECK(m[size] == 1);

    enum { SIZE_U32 = 2, PRIVATE = 128 };
    static uint32_t word = 1, other = 2;
    FAILS(syscall(SYS_futex_wait, &word, 2, ~0ul, SIZE_U32 | PRIVATE, 0, CLOCK_MONOTONIC), EAGAIN);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    now.tv_nsec += 10000000;
    if (now.tv_nsec >= 1000000000) {
        now.tv_nsec -= 1000000000;
        now.tv_sec++;
    }
    FAILS(syscall(SYS_futex_wait, &word, 1, ~0ul, SIZE_U32 | PRIVATE, &now, CLOCK_MONOTONIC), ETIMEDOUT);
    FAILS(syscall(SYS_futex_wait, &word, 1, ~0ul, SIZE_U32 | PRIVATE, &now, 1234), EINVAL);
    CHECK(syscall(SYS_futex_wake, &word, ~0ul, 1, SIZE_U32 | PRIVATE) == 0);
    FAILS(syscall(SYS_futex_wake, &word, 0ul, 1, SIZE_U32 | PRIVATE), EINVAL);
    FAILS(syscall(SYS_futex_wake, &word, ~0ul, 1, 0), EINVAL);
    struct { uint64_t val, uaddr; uint32_t flags, reserved; } w[2] = {
        {1, (uintptr_t)&word, SIZE_U32 | PRIVATE, 0}, {0, (uintptr_t)&other, SIZE_U32 | PRIVATE, 0}};
    CHECK(syscall(SYS_futex_requeue, w, 0, 1, 1) == 0);
    w[0].val = 7;
    FAILS(syscall(SYS_futex_requeue, w, 0, 1, 1), EAGAIN);

    FAILS(syscall(SYS_map_shadow_stack, 0, size, 0), EOPNOTSUPP);
    uint64_t ids[4];
    uint32_t n = sizeof ids;
    CHECK(syscall(SYS_lsm_list_modules, ids, &n, 0) == 1);
    CHECK(n == 8 && ids[0] == 100);
    printf("newer ok\n");
}
#endif

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    files();
    sched();
    ioprio();
    clocks();
    process();
    memory();
    remap();
#ifndef ON_LINUX
    newer();
#endif
    printf("linuxcalls ok\n");
    return 0;
}
