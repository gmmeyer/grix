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

// Older headers may not have them.
#ifndef HWCAP2_FLAGM2
#define HWCAP2_FLAGM2 (1 << 7)
#define HWCAP2_FRINT (1 << 8)
#define HWCAP2_I8MM (1 << 13)
#define HWCAP2_BF16 (1 << 14)
#define HWCAP2_DGH (1 << 15)
#define HWCAP2_RNG (1 << 16)
#endif

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

// Does /proc/cpuinfo's Features line name `feature`?
static int has_feature(const char *feature) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    char line[512], word[64];
    int found = 0;
    snprintf(word, sizeof word, " %s", feature);
    while (f && fgets(line, sizeof line, f)) {
        if (!strncmp(line, "Features", 8)) {
            char *at = strstr(line, word);
            found = at && (at[strlen(word)] == ' ' || at[strlen(word)] == '\n');
            break;
        }
    }
    if (f) fclose(f);
    return found;
}

int main(void) {
    unsigned long hw = getauxval(AT_HWCAP);
    CHECK(hw & HWCAP_CPUID);
    CHECK(cpuinfo("Features") == 1);

    unsigned long isar0 = MRS("s3_0_c0_c6_0"); // ID_AA64ISAR0_EL1
    unsigned long isar1 = MRS("s3_0_c0_c6_1"); // ID_AA64ISAR1_EL1
    unsigned long hw2 = getauxval(AT_HWCAP2);
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
    CHECK(!!(hw & HWCAP_SM3) == (field(isar0, 36) >= 1));
    CHECK(!!(hw & HWCAP_SM4) == (field(isar0, 40) >= 1));
    CHECK(!!(hw & HWCAP_ASIMDFHM) == (field(isar0, 48) >= 1));
    CHECK(!!(hw & HWCAP_FLAGM) == (field(isar0, 52) >= 1));
    CHECK(!!(hw2 & HWCAP2_FLAGM2) == (field(isar0, 52) >= 2));
    CHECK(!!(hw2 & HWCAP2_RNG) == (field(isar0, 60) >= 1));
    CHECK(!!(hw & HWCAP_JSCVT) == (field(isar1, 12) >= 1));
    CHECK(!!(hw & HWCAP_FCMA) == (field(isar1, 16) >= 1));
    CHECK(!!(hw & HWCAP_LRCPC) == (field(isar1, 20) >= 1));
    CHECK(!!(hw & HWCAP_ILRCPC) == (field(isar1, 20) >= 2));
    CHECK(!!(hw2 & HWCAP2_FRINT) == (field(isar1, 32) >= 1));
    CHECK(!!(hw & HWCAP_SB) == (field(isar1, 36) >= 1));
    CHECK(!!(hw2 & HWCAP2_BF16) == (field(isar1, 44) >= 1));
    CHECK(!!(hw2 & HWCAP2_DGH) == (field(isar1, 48) >= 1));
    CHECK(!!(hw2 & HWCAP2_I8MM) == (field(isar1, 52) >= 1));
    // /proc/cpuinfo names HWCAP2's too.
    CHECK(has_feature("frint") == !!(hw2 & HWCAP2_FRINT));
    CHECK(has_feature("lrcpc") == !!(hw & HWCAP_LRCPC));
    CHECK(!!(hw & HWCAP_FP) == (field(pfr0, 16) != 0xf));
    CHECK(!!(hw & HWCAP_ASIMD) == (field(pfr0, 20) != 0xf));
    // What HWCAP doesn't advertise is hidden (TLB, TME; DPB, pointer
    // authentication, SPECRES, XS, LS64), and nothing shows more than
    // HWCAP says (LRCPC up to ILRCPC, BF16 without EBF16).
    unsigned long visible = 0xfUL << 4 | 0xfUL << 8 | 0xfUL << 12 | 0xfUL << 16 | 0xfUL << 20 | 0xfUL << 28 |
                            0xfUL << 32 | 0xfUL << 36 | 0xfUL << 40 | 0xfUL << 44 | 0xfUL << 48 |
                            0xfUL << 52 | 0xfUL << 60;
    CHECK((isar0 & ~visible) == 0);
    unsigned long visible1 = 0xfUL << 12 | 0xfUL << 16 | 0xfUL << 20 | 0xfUL << 32 | 0xfUL << 36 | 0xfUL << 44 |
                             0xfUL << 48 | 0xfUL << 52;
    CHECK((isar1 & ~visible1) == 0);
    CHECK(field(isar1, 20) <= 2 && field(isar1, 44) <= 1 && field(isar0, 52) <= 2);
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
