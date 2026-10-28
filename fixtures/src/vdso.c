// The vDSO: found through AT_SYSINFO_EHDR, its symbols looked up as musl
// and Go do (program headers, the dynamic section, the hash table and
// symbol versions), and its clocks agreeing with the system calls'.
// Needs `process`.
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

static void *vdso_sym(const char *want, const char *version) {
    Elf64_Ehdr *eh = (void *)getauxval(AT_SYSINFO_EHDR);
    CHECK(eh && memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 && eh->e_type == ET_DYN);
    Elf64_Phdr *ph = (void *)((char *)eh + eh->e_phoff);
    uintptr_t base = 0;
    Elf64_Dyn *dyn = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) base = (uintptr_t)eh + ph[i].p_offset - ph[i].p_vaddr;
        if (ph[i].p_type == PT_DYNAMIC) dyn = (void *)((char *)eh + ph[i].p_offset);
    }
    CHECK(base && dyn);
    char *strings = 0;
    Elf64_Sym *syms = 0;
    Elf32_Word *hash = 0;
    Elf64_Half *versym = 0;
    Elf64_Verdef *verdef = 0;
    for (; dyn->d_tag; dyn++) {
        void *p = (void *)(base + dyn->d_un.d_ptr);
        if (dyn->d_tag == DT_STRTAB) strings = p;
        if (dyn->d_tag == DT_SYMTAB) syms = p;
        if (dyn->d_tag == DT_HASH) hash = p;
        if (dyn->d_tag == DT_VERSYM) versym = p;
        if (dyn->d_tag == DT_VERDEF) verdef = p;
    }
    CHECK(strings && syms && hash && versym && verdef);
    unsigned long h = 0;
    for (const unsigned char *s = (const void *)want; *s; s++) {
        h = (h << 4) + *s;
        unsigned long g = h & 0xf0000000;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    for (Elf32_Word i = hash[2 + h % hash[0]]; i; i = hash[2 + hash[0] + i]) {
        Elf64_Sym *sym = &syms[i];
        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC || sym->st_shndx == SHN_UNDEF) continue;
        if (strcmp(strings + sym->st_name, want)) continue;
        for (Elf64_Verdef *d = verdef;; d = (void *)((char *)d + d->vd_next)) {
            Elf64_Verdaux *aux = (void *)((char *)d + d->vd_aux);
            if (!(d->vd_flags & VER_FLG_BASE) && (d->vd_ndx & 0x7fff) == (versym[i] & 0x7fff))
                return strcmp(strings + aux->vda_name, version) ? 0 : (void *)(base + sym->st_value);
            if (!d->vd_next) return 0;
        }
    }
    return 0;
}

static long long ns(struct timespec t) { return t.tv_sec * 1000000000LL + t.tv_nsec; }

int main(void) {
    int (*gettime)(clockid_t, struct timespec *) = vdso_sym("__kernel_clock_gettime", "LINUX_2.6.39");
    int (*gtod)(struct timeval *, void *) = vdso_sym("__kernel_gettimeofday", "LINUX_2.6.39");
    int (*getres)(clockid_t, struct timespec *) = vdso_sym("__kernel_clock_getres", "LINUX_2.6.39");
    CHECK(gettime && gtod && getres && vdso_sym("__kernel_rt_sigreturn", "LINUX_2.6.39"));
    CHECK(!vdso_sym("__kernel_clock_gettime", "LINUX_2.6.15") && !vdso_sym("__kernel_nope", "LINUX_2.6.39"));

    // Between two system calls, on every clock it handles itself.
    clockid_t clocks[] = {CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
                          CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_TAI};
    for (unsigned i = 0; i < sizeof clocks / sizeof *clocks; i++) {
        struct timespec a, b, c;
        for (int n = 0; n < 1000; n++) {
            CHECK(syscall(SYS_clock_gettime, clocks[i], &a) == 0);
            CHECK(gettime(clocks[i], &b) == 0);
            CHECK(syscall(SYS_clock_gettime, clocks[i], &c) == 0);
            CHECK(ns(a) <= ns(b) && ns(b) <= ns(c) && b.tv_nsec < 1000000000);
        }
    }
    // Others are the system call's.
    struct timespec t;
    CHECK(gettime(CLOCK_PROCESS_CPUTIME_ID, &t) == 0 && ns(t) > 0);
    CHECK(gettime(99, &t) == -EINVAL);
    CHECK(getres(CLOCK_MONOTONIC, &t) == 0 && t.tv_sec == 0 && t.tv_nsec == 1);
    struct timeval tv;
    struct timespec rt;
    CHECK(gtod(&tv, NULL) == 0);
    CHECK(clock_gettime(CLOCK_REALTIME, &rt) == 0);
    long long us = tv.tv_sec * 1000000LL + tv.tv_usec;
    CHECK(tv.tv_usec < 1000000 && us <= ns(rt) / 1000 && ns(rt) / 1000 - us < 1000000);
    CHECK(gtod(NULL, NULL) == 0);
    struct timezone tz;
    CHECK(gtod(&tv, &tz) == 0);

    // libc's own (through the vDSO) never goes back against the system call.
    long long last = 0;
    for (int n = 0; n < 100000; n++) {
        if (n % 2) CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
        else CHECK(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &t) == 0);
        CHECK(ns(t) >= last);
        last = ns(t);
    }

    // It's shown, and stays read-only.
    FILE *maps = fopen("/proc/self/maps", "r");
    CHECK(maps);
    char line[256];
    int seen = 0;
    while (fgets(line, sizeof line, maps)) {
        if (strstr(line, "[vdso]")) seen |= 1;
        if (strstr(line, "[vvar]")) seen |= 2;
    }
    fclose(maps);
    CHECK(seen == 3);
    void *page = (void *)getauxval(AT_SYSINFO_EHDR);
    CHECK(mprotect(page, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);

    // A child has it too.
    pid_t kid = fork();
    CHECK(kid >= 0);
    if (kid == 0) _exit(gettime(CLOCK_MONOTONIC, &t) == 0 && ns(t) > 0 ? 0 : 1);
    int status;
    CHECK(waitpid(kid, &status, 0) == kid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    printf("vdso ok\n");
    return 0;
}
