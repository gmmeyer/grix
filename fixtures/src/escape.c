// Adversarial attempts on the kernel's return-to-user path: what a
// sandboxed agent might try to break out with. Each attempt is one argv[1],
// so a crash in one doesn't hide the others' results. Every one must end in
// a clean errno or a signal delivered to the program — never a kernel
// panic (an exception in the kernel is the whole sandbox gone), and never
// registers the kernel didn't mean to load (cs/ss/rflags with privilege).
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <unistd.h>

#if defined(__x86_64__)

// Linux x86_64's struct sigaction the kernel reads (rt_sigaction), with no
// SA_RESTORER: the kernel's sigpage trampoline (mov $15, %eax; syscall)
// then returns through it.
struct k_sigaction {
    void (*handler)(int, siginfo_t *, void *);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
};

static void install(int sig, void (*handler)(int, siginfo_t *, void *)) {
    struct k_sigaction act = { handler, SA_SIGINFO | SA_NODEFER, 0, 0 };
    syscall(SYS_rt_sigaction, sig, &act, 0, 8);
}

// What the handler patches the saved context with.
static volatile unsigned long patched_rip, patched_rsp, patched_rflags;
static volatile int handler_ran;

// Patch the saved context and return: rt_sigreturn reads it back.
static void forge(int sig, siginfo_t *info, void *uc_) {
    ucontext_t *uc = uc_;
    (void)sig;
    (void)info;
    if (patched_rip) uc->uc_mcontext.gregs[REG_RIP] = patched_rip;
    if (patched_rsp) uc->uc_mcontext.gregs[REG_RSP] = patched_rsp;
    if (patched_rflags) uc->uc_mcontext.gregs[REG_EFL] |= patched_rflags;
    handler_ran = 1;
}

// Raise a signal, patching the frame it leaves through the handler.
static long raise_patched(int sig) {
    handler_ran = 0;
    return syscall(SYS_kill, syscall(SYS_getpid), sig);
}

// A system call with a stack pointer of the caller's choosing: on return,
// iretq loads it, and the kernel must not fault on what it loaded.
static void rsp_across_syscall(unsigned long rsp) {
    asm volatile(
        "movq %%rsp, %%r12\n"
        "movq %[rsp], %%rsp\n"
        "syscall\n"
        "movq %%r12, %%rsp\n"
        :
        : "a"((long)SYS_getpid), [rsp] "r"(rsp)
        : "rcx", "r11", "r12", "memory");
}

// The same, but the returned-to code uses the stack (a push): a bad one
// must fault in the program, not in the kernel.
static void rsp_use_on_return(unsigned long rsp) {
    asm volatile(
        "movq %%rsp, %%r12\n"
        "movq %[rsp], %%rsp\n"
        "syscall\n"
        "popq %%rax\n"
        "movq %%r12, %%rsp\n"
        :
        : "a"((long)SYS_getpid), [rsp] "r"(rsp)
        : "rcx", "r11", "r12", "memory");
}

// A round trip through 32-bit compatibility mode, entered by a far return
// to the GDT's 32-bit user code slot (sysret's layout has one), with a
// system call from in there. On AMD, `syscall` in compatibility mode goes
// to CSTAR, which the kernel once left at 0: a jump to 0 in kernel mode,
// on this stack. The slot is empty now, so the far return faults (#GP).
static void compat_roundtrip(void) {
    // A low page for the 32-bit stack (compat mode truncates rsp).
    void *low = mmap((void *)0x20000, 0x1000, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (low == MAP_FAILED) {
        printf("FAILED: mmap low page: %s\n", strerror(errno));
        return;
    }
    long pid;
    asm volatile(
        "movq %%rsp, %%r12\n"
        "leaq 1f(%%rip), %%rax\n"
        "pushq $0x1b\n"       // cs: the 32-bit user code segment (GDT slot 3)
        "pushq %%rax\n"
        "lretq\n"
        ".balign 4\n"
        ".code32\n"
        "1:\n"
        "movl $0x20000, %%esp\n"
        "movl $39, %%eax\n"   // getpid
        "syscall\n"
        "pushl $0x2b\n"       // cs: the 64-bit user code segment
        "pushl $2f\n"
        "lretl\n"
        ".code64\n"
        "2:\n"
        "movq %%r12, %%rsp\n"
        : "=a"(pid)
        :
        : "rcx", "r11", "r12", "memory");
    printf("compat: getpid from 32-bit mode returned %ld\n", pid);
}

#endif

int main(int argc, char **argv) {
    const char *what = argc > 1 ? argv[1] : "";
#if defined(__x86_64__)
    // 0x8000000000000000 is not canonical (bit 47 clear, bits 48.. set);
    // 0xffff800000000000 is canonical, but in the kernel's half.
    if (strcmp(what, "rsp") == 0) {
        rsp_across_syscall(0x8000000000000000ul);
        printf("rsp: returned to a non-canonical stack cleanly\n");
    } else if (strcmp(what, "rsp-kernel") == 0) {
        rsp_across_syscall(0xffff800000000000ul);
        printf("rsp-kernel: returned to a kernel-half stack without using it\n");
    } else if (strcmp(what, "rsp-use") == 0) {
        rsp_use_on_return(0xffff800000000000ul);
        printf("rsp-use: used a kernel-half stack\n");
    } else if (strcmp(what, "compat") == 0) {
        compat_roundtrip();
    } else if (strncmp(what, "sigreturn", 9) == 0) {
        // rt_sigreturn with a forged saved context: what raise_patched
        // leaves in rax is what rt_sigreturn refused to restore.
        install(SIGUSR1, forge);
        if (strcmp(what, "sigreturn-rip") == 0) {
            patched_rip = 0xffff800000000000ul; // the kernel's half
            long r = raise_patched(SIGUSR1);
            printf("sigreturn-rip: kill() = %ld (%s), handler ran %d\n", r,
                   r == -1 ? strerror(errno) : "returned", handler_ran);
        } else if (strcmp(what, "sigreturn-rflags") == 0) {
            patched_rflags = 0x3000 | 0x4000 | 0x80000; // IOPL 3, NT, VM
            long r = raise_patched(SIGUSR1);
            unsigned long flags;
            asm volatile("pushfq\n popq %0" : "=r"(flags));
            printf("sigreturn-rflags: kill() = %ld, rflags = %#lx (IOPL %lu)\n",
                   r, flags, (flags >> 12) & 3);
        } else if (strcmp(what, "sigreturn-rsp") == 0) {
            patched_rsp = 0x8000000000000000ul; // not canonical
            long r = raise_patched(SIGUSR1);
            printf("sigreturn-rsp: kill() = %ld (%s), handler ran %d\n", r,
                   r == -1 ? strerror(errno) : "returned", handler_ran);
        } else if (strcmp(what, "sigreturn-rsp2") == 0) {
            patched_rsp = 0xffff800000000000ul; // the kernel's half
            long r = raise_patched(SIGUSR1);
            printf("sigreturn-rsp2: kill() = %ld (%s)\n", r,
                   r == -1 ? strerror(errno) : "returned");
        } else {
            printf("unknown sigreturn attempt %s\n", what);
            return 1;
        }
    } else if (strcmp(what, "mmap") == 0) {
        void *p;
        p = mmap((void *)0xffff800000000000ul, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        printf("mmap fixed kernel-half: %s\n", p == MAP_FAILED ? strerror(errno) : "MAPPED");
        p = mmap((void *)0xffff800000000000ul, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("mmap hint kernel-half: %p\n", p);
        p = mmap((void *)0x7ffffffff000ul, 0x2000, PROT_READ, // crosses USER_TOP
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        printf("mmap fixed past USER_TOP: %s\n", p == MAP_FAILED ? strerror(errno) : "MAPPED");
        p = mmap((void *)0xfffffffffffff000ul, 0x2000000, PROT_READ, // addr+len wraps
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        printf("mmap fixed wrapping: %s\n", p == MAP_FAILED ? strerror(errno) : "MAPPED");
    } else if (strcmp(what, "gates") == 0) {
        const char *gate = argc > 2 ? argv[2] : "";
        if (strcmp(gate, "int3") == 0)
            asm volatile("int3" ::: "memory"); // DPL 3: a trap for the program
        else if (strcmp(gate, "int80") == 0)
            asm volatile("int $0x80" ::: "memory"); // the 32-bit call vector: #GP
        else if (strcmp(gate, "intdev") == 0)
            asm volatile("int $0x31" ::: "memory"); // a device vector: #GP, never an IRQ
        else if (strcmp(gate, "iret") == 0)
            asm volatile("iretq" ::: "memory"); // privileged: #GP
        else {
            printf("usage: gates int3|int80|intdev|iret\n");
            return 1;
        }
        printf("gates %s: NOT REACHED\n", gate);
        return 1;
    } else {
        printf("unknown attempt %s\n", what);
        return 1;
    }
#else
    (void)argv;
    printf("no %s attempts on this architecture\n", what);
#endif
    return 0;
}