// arm64: reading the ID registers from user mode (MRS of ID_AA64*,
// MIDR_EL1, MPIDR_EL1, REVIDR_EL1), emulated as Linux emulates it
// (HWCAP_CPUID): sanitized values that agree with HWCAP and
// /proc/cpuinfo, the instruction skipped, other registers untouched; any
// other system register is still SIGILL. Nothing to do on x86_64.
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

#if defined(__aarch64__)

#define MRS(reg)                                                                  \
    ({                                                                            \
        unsigned long v_;                                                         \
        __asm__ volatile("mrs %0, " reg : "=r"(v_));                              \
        v_;                                                                       \
    })

static unsigned long field(unsigned long reg, int shift) { return (reg >> shift) & 0xf; }

static sigjmp_buf env;
static volatile unsigned long ill_addr;

static void on_sigill(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    ill_addr = (unsigned long)si->si_addr;
    siglongjmp(env, si->si_code);
}

// Does reading this register end in SIGILL (ILL_ILLOPC)?
#define TRAPS(reg)                                                                \
    ({                                                                            \
        int code_ = sigsetjmp(env, 1);                                            \
        if (code_ == 0) {                                                         \
            MRS(reg);                                                             \
        }                                                                         \
        code_ == 1;                                                               \
    })

static unsigned long cpuinfo(const char *key) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    CHECK(f);
    char line[512];
    unsigned long v = ~0UL;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, key, strlen(key))) {
            char *colon = strchr(line, ':');
            CHECK(colon);
            if (!strcmp(key, "Features")) {
                v = strstr(colon, " cpuid") != NULL;
            } else {
                v = strtoul(colon + 1, NULL, 0);
            }
            break;
        }
    }
    fclose(f);
    return v;
}

int main(void) {
    unsigned long hw = getauxval(AT_HWCAP);
    CHECK(hw & HWCAP_CPUID);
    CHECK(cpuinfo("Features") == 1);

    unsigned long isar0 = MRS("s3_0_c0_c6_0"); // ID_AA64ISAR0_EL1
    unsigned long pfr0 = MRS("s3_0_c0_c4_0");  // ID_AA64PFR0_EL1
    unsigned long midr = MRS("s3_0_c0_c0_0");  // MIDR_EL1
    // HWCAP is made of the same values.
    CHECK(!!(hw & HWCAP_AES) == (field(isar0, 4) >= 1));
    CHECK(!!(hw & HWCAP_PMULL) == (field(isar0, 4) >= 2));
    CHECK(!!(hw & HWCAP_SHA1) == (field(isar0, 8) >= 1));
    CHECK(!!(hw & HWCAP_SHA2) == (field(isar0, 12) >= 1));
    CHECK(!!(hw & HWCAP_SHA512) == (field(isar0, 12) >= 2));
    CHECK(!!(hw & HWCAP_CRC32) == (field(isar0, 16) >= 1));
    CHECK(!!(hw & HWCAP_ATOMICS) == (field(isar0, 20) >= 2));
    CHECK(!!(hw & HWCAP_ASIMDRDM) == (field(isar0, 28) >= 1));
    CHECK(!!(hw & HWCAP_SHA3) == (field(isar0, 32) >= 1));
    CHECK(!!(hw & HWCAP_ASIMDDP) == (field(isar0, 44) >= 1));
    CHECK(!!(hw & HWCAP_FP) == (field(pfr0, 16) != 0xf));
    CHECK(!!(hw & HWCAP_ASIMD) == (field(pfr0, 20) != 0xf));
    // What HWCAP doesn't advertise is hidden: RNDR, TLB, TS, FHM, SM3, SM4.
    unsigned long visible = 0xfUL << 4 | 0xfUL << 8 | 0xfUL << 12 | 0xfUL << 16 | 0xfUL << 20 | 0xfUL << 28 |
                            0xfUL << 32 | 0xfUL << 44;
    CHECK((isar0 & ~visible) == 0);
    // EL0 and EL1 AArch64 only, and no SVE, DIT, RAS, GIC or EL2/EL3.
    CHECK((pfr0 & ~(0xffUL << 16)) == 0x11);
    // MIDR as /proc/cpuinfo shows it; no CPU's topology or revision.
    CHECK(((midr >> 24) & 0xff) == cpuinfo("CPU implementer"));
    CHECK(((midr >> 4) & 0xfff) == cpuinfo("CPU part"));
    CHECK(MRS("s3_0_c0_c0_5") == 0x80000000UL); // MPIDR_EL1
    CHECK(MRS("s3_0_c0_c0_6") == 0);            // REVIDR_EL1
    // Registers grix shows nothing of read as zero; DFR0's DebugVer is v8.
    CHECK(MRS("s3_0_c0_c4_1") == 0); // ID_AA64PFR1_EL1: no BTI, MTE, SME
    CHECK(MRS("s3_0_c0_c4_4") == 0); // ID_AA64ZFR0_EL1
    CHECK(MRS("s3_0_c0_c6_1") == 0); // ID_AA64ISAR1_EL1: no pointer auth
    CHECK(MRS("s3_0_c0_c7_0") == 0); // ID_AA64MMFR0_EL1
    CHECK(MRS("s3_0_c0_c7_7") == 0); // reserved
    CHECK(MRS("s3_0_c0_c2_0") == 0); // ID_ISAR0_EL1 (AArch32)
    CHECK(MRS("s3_0_c0_c5_0") == 6); // ID_AA64DFR0_EL1

    // Go's x/sys/cpu reads them as raw words into x0 (`mrs x0,
    // ID_AA64ISAR0_EL1`), and XZR discards one; nothing else changes.
    register unsigned long x0 __asm__("x0");
    register unsigned long x1 __asm__("x1") = 0x1111;
    register unsigned long x2 __asm__("x2") = 0x2222;
    __asm__ volatile(".inst 0xd5380600\n.inst 0xd538061f" : "=r"(x0), "+r"(x1), "+r"(x2));
    CHECK(x0 == isar0 && x1 == 0x1111 && x2 == 0x2222);

    // Outside what's emulated: SIGILL at the instruction, as before.
    struct sigaction sa = {0};
    sa.sa_sigaction = on_sigill;
    sa.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGILL, &sa, NULL) == 0);
    CHECK(TRAPS("s3_0_c0_c1_0"));  // ID_PFR0_EL1 (CRm 1)
    CHECK(TRAPS("s3_0_c0_c0_1"));  // CRm 0 but not MIDR, MPIDR or REVIDR
    CHECK(TRAPS("s3_0_c1_c0_0"));  // SCTLR_EL1
    CHECK(TRAPS("s3_1_c0_c0_0"));  // CCSIDR_EL1 (op1 1)
    CHECK(ill_addr != 0);
    printf("idregs ok\n");
    return 0;
}

#else

int main(void) {
    printf("idregs ok\n");
    return 0;
}

#endif
