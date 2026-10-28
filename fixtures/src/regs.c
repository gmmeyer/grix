// What user code may do to its own registers that the kernel must not
// take in (x86_64): a system call with RFLAGS.NT set (popf), and a thread
// pointer that isn't a user address. Elsewhere, nothing to try.
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
#if defined(__x86_64__)
    __asm__ volatile("pushfq\n orq $0x4000, (%%rsp)\n popfq" ::: "memory", "cc");
    long pid = syscall(SYS_getpid);
    __asm__ volatile("pushfq\n andq $~0x4000, (%%rsp)\n popfq" ::: "memory", "cc");
    if (pid <= 0) {
        printf("FAILED: getpid with NT set: %ld\n", pid);
        return 1;
    }
    long c = syscall(SYS_clone, CLONE_SETTLS | SIGCHLD, 0, 0, 0, 0xffff800000000000ul);
    if (c != -1 || errno != EPERM) {
        printf("FAILED: clone with a kernel address for TLS: %ld (errno %d)\n", c, errno);
        return 1;
    }
#endif
    printf("regs ok\n");
    return 0;
}
