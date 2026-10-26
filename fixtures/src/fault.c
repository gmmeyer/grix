// Die in various ways: segv (default), abort, illegal instruction, or a
// forged signal frame that asks rt_sigreturn for a privileged mode.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static _Alignas(16) unsigned char frame[4688];

int main(int argc, char **argv) {
    const char *how = argc > 1 ? argv[1] : "segv";
    if (!strcmp(how, "abort")) abort();
    if (!strcmp(how, "ill")) __builtin_trap();
    if (!strcmp(how, "sigreturn")) {
        // A well-formed frame (FP/SIMD record present) whose pstate is EL1h
        // with interrupts masked. Offsets as in arch/arm64/kernel/signal.c.
        uint64_t pstate = 0x3c5;
        uint32_t fpsimd[2] = {0x46508001, 528};
        memcpy(frame + 576, &pstate, 8);
        memcpy(frame + 592, fpsimd, 8);
        register uint64_t sp __asm__("x0") = (uint64_t)frame;
        __asm__ volatile("mov sp, x0\n mov x8, #139\n svc #0" ::"r"(sp) : "x8", "memory");
        return 0;
    }
    *(volatile int *)8 = 1;
    return 0;
}
