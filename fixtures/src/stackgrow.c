// The stack, and MAP_GROWSDOWN mappings, grow as Linux's do: on a fault
// below them, as far as RLIMIT_STACK says now and a guard gap allows. The
// same program passes on Linux.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 4096L
#define MB (1024L * 1024L)
#define GAP MB
#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);  \
            fflush(stdout);                                                   \
            _exit(1);                                                         \
        }                                                                     \
    } while (0)
#define FAILS(c, e) CHECK((long)(c) == -1 && errno == (e))

static sigjmp_buf back;
static void on_segv(int s) {
    (void)s;
    siglongjmp(back, 1);
}

static void handlers(void) {
    static char alt[65536];
    stack_t ss = {.ss_sp = alt, .ss_size = sizeof alt};
    CHECK(sigaltstack(&ss, 0) == 0);
    struct sigaction sa = {0};
    sa.sa_handler = on_segv;
    sa.sa_flags = SA_ONSTACK;
    CHECK(sigaction(SIGSEGV, &sa, 0) == 0);
}

// Does writing to `p` work (and, below a stack, make it grow)?
static int can_write(char *p) {
    if (sigsetjmp(back, 1)) return 0;
    *(volatile char *)p = 'x';
    return 1;
}

static char *sp(void) {
    return (char *)__builtin_frame_address(0);
}

static void limit(long bytes) {
    struct rlimit r;
    CHECK(getrlimit(RLIMIT_STACK, &r) == 0);
    r.rlim_cur = bytes;
    CHECK(setrlimit(RLIMIT_STACK, &r) == 0);
}

// The mapping holding `p`: [start, end), and its name.
static int mapping(char *p, unsigned long *start, unsigned long *end, char *name) {
    FILE *f = fopen("/proc/self/maps", "r");
    CHECK(f);
    char line[512];
    int found = 0;
    while (!found && fgets(line, sizeof line, f)) {
        char n[256] = "";
        unsigned long s, e;
        if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %255s", &s, &e, n) >= 2 && s <= (unsigned long)p &&
            (unsigned long)p < e) {
            *start = s;
            *end = e;
            if (name) strcpy(name, n);
            found = 1;
        }
    }
    fclose(f);
    return found;
}

static int vm_flag(char *p, const char *flag) {
    FILE *f = fopen("/proc/self/smaps", "r");
    CHECK(f);
    char line[512];
    int in = 0, found = -1;
    while (fgets(line, sizeof line, f)) {
        unsigned long s, e;
        if (sscanf(line, "%lx-%lx ", &s, &e) == 2) in = s <= (unsigned long)p && (unsigned long)p < e;
        if (in && !strncmp(line, "VmFlags:", 8)) {
            found = strstr(line, flag) != 0;
            break;
        }
    }
    fclose(f);
    CHECK(found >= 0);
    return found;
}

// In a child, whose limits and stack are its own.
static void isolated(void (*f)(void)) {
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        handlers();
        f();
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

// It starts small: exec doesn't map what RLIMIT_STACK allows.
static void starts_small(void) {
    unsigned long s, e;
    char name[256];
    CHECK(mapping(sp(), &s, &e, name) && !strcmp(name, "[stack]"));
    CHECK(e - s < 1 * MB);
    CHECK(vm_flag(sp(), "gd") == 1);
}

// Raised after exec, as gcc's cc1 raises it for itself.
static void grows_past_what_exec_saw(void) {
    limit(64 * MB);
    char *below = sp() - 32 * MB;
    CHECK(can_write(below));
    unsigned long s, e;
    char name[256];
    CHECK(mapping(below, &s, &e, name) && !strcmp(name, "[stack]"));
    CHECK(e - s >= 32 * MB && e - s < 33 * MB);
}

static void stops_at_the_limit(void) {
    limit(16 * MB);
    CHECK(can_write(sp() - 15 * MB));
    CHECK(!can_write(sp() - 17 * MB));
}

static void lowered_after_exec(void) {
    limit(1 * MB);
    CHECK(!can_write(sp() - 2 * MB));
    CHECK(can_write(sp() - 512 * 1024));
}

static void the_kernel_grows_it_too(void) {
    int p[2];
    CHECK(pipe(p) == 0 && write(p[1], "abcd", 4) == 4);
    char *below = sp() - 4 * MB;
    CHECK(read(p[0], below, 4) == 4 && !memcmp(below, "abcd", 4));
    // And where it can't, it's an error for the call.
    CHECK(write(p[1], "abcd", 4) == 4);
    FAILS(read(p[0], sp() - 64 * MB, 4), EFAULT);
}

// A place with nothing around it.
static char *clearing(void) {
    char *r = mmap(0, 256 * MB, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(r != MAP_FAILED && munmap(r, 256 * MB) == 0);
    return r + 128 * MB;
}

static char *grows_down_at(char *at) {
    char *p = mmap(at, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED, -1, 0);
    CHECK(p == at);
    return p;
}

static void growsdown_mappings(void) {
    char *p = grows_down_at(clearing());
    unsigned long s, e;
    CHECK(vm_flag(p, "gd") == 1);
    CHECK(mapping(p, &s, &e, 0) && s == (unsigned long)p && e == (unsigned long)p + PAGE);
    // Any way below it, not only the next page.
    CHECK(can_write(p - PAGE));
    CHECK(mapping(p, &s, &e, 0) && s == (unsigned long)p - PAGE);
    CHECK(can_write(p - 100 * PAGE));
    CHECK(mapping(p, &s, &e, 0) && s == (unsigned long)p - 100 * PAGE);
    // Not above it.
    CHECK(!can_write(p + PAGE));
    CHECK(mapping(p, &s, &e, 0) && e == (unsigned long)p + PAGE);
    // As far as the limit, counted from its top.
    limit(8 * MB);
    CHECK(!can_write(p + PAGE - 8 * MB - PAGE));
    CHECK(can_write(p + PAGE - 8 * MB));
    // A child's is its own.
    CHECK(mapping(p, &s, &e, 0));
}

static void not_every_mapping(void) {
    FAILS(mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0), EINVAL);
    // A plain mapping doesn't grow.
    char *p = mmap(clearing(), PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED && !can_write(p - PAGE) && vm_flag(p, "gd") == 0);
}

// It keeps a gap from what's below it.
static void guard_gap(void) {
    char *at = clearing();
    char *p = grows_down_at(at);
    char *below = mmap(at - 2 * GAP - PAGE, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(below == at - 2 * GAP - PAGE);
    char *lowest = below + PAGE + GAP;
    CHECK(can_write(lowest));
    CHECK(!can_write(lowest - PAGE));
    unsigned long s, e;
    CHECK(mapping(p, &s, &e, 0) && s == (unsigned long)lowest);
    // A mapping nobody can use is no reason to stop.
    char *q = grows_down_at(clearing());
    char *none = mmap(q - GAP / 2, PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(none == q - GAP / 2);
    CHECK(can_write(none + PAGE));
}

// mmap keeps out of that gap unless it's told exactly where to go.
static void mmap_keeps_clear(void) {
    char *p = grows_down_at(clearing());
    char *hint = mmap(p - 2 * PAGE, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(hint != MAP_FAILED && hint != p - 2 * PAGE);
    char *fixed = mmap(p - 2 * PAGE, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(fixed == p - 2 * PAGE);
    // Nor does it land there by itself.
    char *a = mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    char *b = mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(a != MAP_FAILED && b != MAP_FAILED && (b > a || b + PAGE + GAP <= a));
    // Below the gap a hint is taken.
    char *r = grows_down_at(clearing());
    char *far = mmap(r - 4 * GAP, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(far == r - 4 * GAP);
}

// PROT_GROWSDOWN: down to the mapping's start.
static void prot_growsdown(void) {
    char *p = grows_down_at(clearing());
    CHECK(can_write(p - 4 * PAGE));
    CHECK(mprotect(p, PAGE, PROT_READ | PROT_GROWSDOWN) == 0);
    CHECK(!can_write(p - 4 * PAGE) && !can_write(p));
    // Not of a mapping that doesn't grow; and not up as well.
    char *q = mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(q != MAP_FAILED);
    FAILS(mprotect(q, PAGE, PROT_READ | PROT_GROWSDOWN), EINVAL);
    FAILS(mprotect(p, PAGE, PROT_READ | PROT_GROWSDOWN | PROT_GROWSUP), EINVAL);
    // Other bits are just refused.
    FAILS(mprotect(q, PAGE, PROT_READ | 0x100), EINVAL);
}

static void forks_and_grows(void) {
    char *p = grows_down_at(clearing());
    CHECK(can_write(p - PAGE));
    fflush(stdout);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        CHECK(can_write(p - 10 * PAGE));
        _exit(0);
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    unsigned long s, e;
    CHECK(mapping(p, &s, &e, 0) && s == (unsigned long)p - PAGE);
    // It keeps growing once part of it has gone, from what's left.
    CHECK(munmap(p, PAGE) == 0);
    CHECK(can_write(p - 2 * PAGE));
}

// Far down, a signal's frame goes there too.
static volatile int ran;
static void on_usr1(int s) {
    (void)s;
    ran = 1;
}
static void a_signal_down_there(void) {
    signal(SIGUSR1, on_usr1);
    limit(64 * MB);
    char *top = sp();
    char *far = (char *)(((uintptr_t)top - 8 * MB) & ~15ul);
    // Only the frame is there: the stack hasn't reached it yet.
#if defined(__x86_64__)
    long ret;
    __asm__ volatile("mov %%rsp, %%rbx\n mov %[far], %%rsp\n syscall\n mov %%rbx, %%rsp\n"
                     : "=a"(ret)
                     : [far] "r"(far), "a"(62L), "D"((long)getpid()), "S"((long)SIGUSR1)
                     : "rbx", "rcx", "r11", "memory");
    CHECK(ret == 0);
#else
    register long x8 __asm__("x8") = 129, x0 __asm__("x0") = getpid(), x1 __asm__("x1") = SIGUSR1;
    __asm__ volatile("mov x19, sp\n mov sp, %3\n svc 0\n mov sp, x19\n"
                     : "+r"(x0) : "r"(x8), "r"(x1), "r"(far) : "x19", "memory");
#endif
    CHECK(ran);
}

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    starts_small();
    isolated(grows_past_what_exec_saw);
    isolated(stops_at_the_limit);
    isolated(lowered_after_exec);
    isolated(the_kernel_grows_it_too);
    isolated(growsdown_mappings);
    isolated(not_every_mapping);
    isolated(guard_gap);
    isolated(mmap_keeps_clear);
    isolated(prot_growsdown);
    isolated(forks_and_grows);
    isolated(a_signal_down_there);
    printf("stackgrow ok\n");
    return 0;
}
