// Vector registers are the program's own (x86_64): AVX's ymm upper halves
// survive context switches (system calls and preemption, two threads on
// one CPU) and signal handlers, whose frame holds them in Linux's XSAVE
// layout. A frame whose XSAVE header the CPU would refuse ends in SIGSEGV
// ("badheader", "badfeatures"). Elsewhere, nothing to try.
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <cpuid.h>

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        printf("FAILED: " __VA_ARGS__);                                                                                \
        printf("\n");                                                                                                  \
        exit(1);                                                                                                       \
    } while (0)

#define XMM_CLOBBERS                                                                                                   \
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13",  \
        "xmm14", "xmm15"

#define LOAD_YMM(p)                                                                                                    \
    "vmovdqu 0(" p "), %%ymm0\n vmovdqu 32(" p "), %%ymm1\n vmovdqu 64(" p "), %%ymm2\n vmovdqu 96(" p "), %%ymm3\n"   \
    "vmovdqu 128(" p "), %%ymm4\n vmovdqu 160(" p "), %%ymm5\n vmovdqu 192(" p "), %%ymm6\n"                          \
    "vmovdqu 224(" p "), %%ymm7\n vmovdqu 256(" p "), %%ymm8\n vmovdqu 288(" p "), %%ymm9\n"                          \
    "vmovdqu 320(" p "), %%ymm10\n vmovdqu 352(" p "), %%ymm11\n vmovdqu 384(" p "), %%ymm12\n"                       \
    "vmovdqu 416(" p "), %%ymm13\n vmovdqu 448(" p "), %%ymm14\n vmovdqu 480(" p "), %%ymm15\n"

#define STORE_YMM(p)                                                                                                   \
    "vmovdqu %%ymm0, 0(" p ")\n vmovdqu %%ymm1, 32(" p ")\n vmovdqu %%ymm2, 64(" p ")\n vmovdqu %%ymm3, 96(" p ")\n"   \
    "vmovdqu %%ymm4, 128(" p ")\n vmovdqu %%ymm5, 160(" p ")\n vmovdqu %%ymm6, 192(" p ")\n"                          \
    "vmovdqu %%ymm7, 224(" p ")\n vmovdqu %%ymm8, 256(" p ")\n vmovdqu %%ymm9, 288(" p ")\n"                          \
    "vmovdqu %%ymm10, 320(" p ")\n vmovdqu %%ymm11, 352(" p ")\n vmovdqu %%ymm12, 384(" p ")\n"                       \
    "vmovdqu %%ymm13, 416(" p ")\n vmovdqu %%ymm14, 448(" p ")\n vmovdqu %%ymm15, 480(" p ")\n"

static void fill(unsigned char *p, unsigned seed) {
    for (int i = 0; i < 512; i++) p[i] = (unsigned char)(seed * 131 + i * 7 + 1);
}

static void check(const unsigned char *want, const unsigned char *got, const char *what) {
    for (int i = 0; i < 512; i++)
        if (want[i] != got[i]) FAIL("%s: ymm%d byte %d is %#x, not %#x", what, i / 32, i % 32, got[i], want[i]);
}

// Load every ymm register, then `yields` sched_yield calls and a busy
// loop of `spins` (preempted by the timer), then store them.
static void hold(const unsigned char *in, unsigned char *out, long yields, long spins) {
    __asm__ volatile(LOAD_YMM("%0") "mov %2, %%r12\n"
                                    "test %%r12, %%r12\n jz 2f\n"
                                    "1: mov $24, %%eax\n syscall\n dec %%r12\n jnz 1b\n"
                                    "2: mov %3, %%r12\n"
                                    "test %%r12, %%r12\n jz 4f\n"
                                    "3: dec %%r12\n jnz 3b\n"
                                    "4:\n" STORE_YMM("%1")
                     :
                     : "r"(in), "r"(out), "r"(yields), "r"(spins)
                     : "rax", "rcx", "r11", "r12", "memory", "cc", XMM_CLOBBERS);
}

static void *worker(void *arg) {
    unsigned seed = (unsigned)(uintptr_t)arg;
    unsigned char in[512], out[512];
    for (int round = 0; round < 4; round++) {
        fill(in, seed + round);
        hold(in, out, 200, 20000000);
        check(in, out, "across a context switch");
    }
    return 0;
}

static unsigned char sig_in[512];
static unsigned avx_offset;
static const char *mode = "";
static volatile int handled;

static void handler(int sig, siginfo_t *si, void *ucv) {
    (void)sig, (void)si;
    ucontext_t *uc = ucv;
    unsigned char *fp = (unsigned char *)uc->uc_mcontext.fpregs;
    uint32_t magic1, extended, xsize, magic2;
    uint64_t features;
    memcpy(&magic1, fp + 464, 4);
    memcpy(&extended, fp + 468, 4);
    memcpy(&features, fp + 472, 8);
    memcpy(&xsize, fp + 480, 4);
    if (!(uc->uc_flags & 1)) FAIL("uc_flags %#lx without UC_FP_XSTATE", uc->uc_flags);
    if (magic1 != 0x46505853 || extended != xsize + 4 || (features & 7) != 7)
        FAIL("fpstate's software bytes: magic1 %#x, extended %u, xstate %u, features %#llx", magic1, extended, xsize,
             (unsigned long long)features);
    memcpy(&magic2, fp + xsize, 4);
    if (magic2 != 0x46505845) FAIL("FP_XSTATE_MAGIC2 is %#x", magic2);
    // ymm0's upper half, in the frame's AVX component.
    if (memcmp(fp + avx_offset, sig_in + 16, 16)) FAIL("the frame's ymm0 upper half");
    uint64_t bv;
    memcpy(&bv, fp + 512, 8);
    if (!(bv & 4)) FAIL("XSTATE_BV %#llx without AVX", (unsigned long long)bv);
    // The handler's own use of the registers mustn't reach the program.
    __asm__ volatile("vpxor %%ymm0, %%ymm0, %%ymm0\n vpxor %%ymm7, %%ymm7, %%ymm7\n vpxor %%ymm15, %%ymm15, %%ymm15"
                     :
                     :
                     : "xmm0", "xmm7", "xmm15");
    // What rt_sigreturn restores is the frame's: change ymm1's upper half there.
    fp[avx_offset + 16] ^= 0xff;
    sig_in[32 + 16] ^= 0xff;
    if (!strcmp(mode, "badheader")) fp[512 + 16] = 1;              // a reserved header byte
    if (!strcmp(mode, "badfeatures")) fp[512 + 7] |= 0x40;         // XSTATE_BV bit 62
    handled = 1;
}

int main(int argc, char **argv) {
    if (argc > 1) mode = argv[1];
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    if (!(c & (1u << 27)) || !(c & (1u << 28))) FAIL("no OSXSAVE or AVX in CPUID (ecx %#x)", c);
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    if ((lo & 7) != 7) FAIL("XCR0 %#x without AVX", lo);
    __cpuid_count(0xd, 2, a, b, c, d);
    avx_offset = b;

    FILE *f = fopen("/proc/cpuinfo", "r");
    char line[4096];
    int listed = 0;
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, "flags", 5) && strstr(line, " avx")) listed = 1;
    if (!listed) FAIL("/proc/cpuinfo's flags without avx");

    // A signal arriving while every ymm register is live.
    struct sigaction sa = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
    sigaction(SIGUSR1, &sa, 0);
    unsigned char out[512];
    fill(sig_in, 99);
    long pid = getpid();
    __asm__ volatile(LOAD_YMM("%0") "mov $62, %%eax\n syscall\n" STORE_YMM("%1")
                     :
                     : "r"(sig_in), "r"(out), "D"(pid), "S"((long)SIGUSR1)
                     : "rax", "rcx", "r11", "memory", "cc", XMM_CLOBBERS);
    if (!handled) FAIL("the handler didn't run");
    check(sig_in, out, "across a signal handler");

    pthread_t t[2];
    for (int i = 0; i < 2; i++) pthread_create(&t[i], 0, worker, (void *)(uintptr_t)(i * 10 + 1));
    for (int i = 0; i < 2; i++) pthread_join(t[i], 0);
    printf("fpstate ok\n");
    return 0;
}
#else
int main(void) {
    printf("fpstate ok\n");
    return 0;
}
#endif
