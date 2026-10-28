// Die in various ways: segv (default), abort, illegal instruction, or a
// forged signal frame that asks rt_sigreturn for a privileged mode.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__)
static _Alignas(16) unsigned char frame[440];
#else
static _Alignas(16) unsigned char frame[4688];
#endif

int main(int argc, char **argv) {
    const char *how = argc > 1 ? argv[1] : "segv";
    if (!strcmp(how, "abort")) abort();
    if (!strcmp(how, "ill")) __builtin_trap();
    if (!strcmp(how, "sigreturn")) {
#if defined(__x86_64__)
        // A frame whose rip is the kernel's (sigcontext's ip, as in
        // arch/x86/kernel/signal_64.c); rt_sigreturn finds the frame below
        // sp, past its return address.
        uint64_t rip = 0xffff800000000000ull;
        memcpy(frame + 176, &rip, 8);
        __asm__ volatile("lea 8(%0), %%rsp\n mov $15, %%eax\n syscall" ::"r"(frame) : "rax", "memory");
#else
        // A well-formed frame (FP/SIMD record present) whose pstate is EL1h
        // with interrupts masked. Offsets as in arch/arm64/kernel/signal.c.
        uint64_t pstate = 0x3c5;
        uint32_t fpsimd[2] = {0x46508001, 528};
        memcpy(frame + 576, &pstate, 8);
        memcpy(frame + 592, fpsimd, 8);
        register uint64_t sp __asm__("x0") = (uint64_t)frame;
        __asm__ volatile("mov sp, x0\n mov x8, #139\n svc #0" ::"r"(sp) : "x8", "memory");
#endif
        return 0;
    }
    *(volatile int *)8 = 1;
    return 0;
}
