// Runs a CPU's kernel stack past its end, with a debug kernel's test hook
// (syscall::STACK_OVERFLOW_TEST), which then returns or, with `fault`,
// faults down there: the kernel must report it, naming the CPU, and stop.
// With more CPUs, from a thread on one other than CPU 0 (whose stack is
// the lowest), as threads spin on all of them. With `picked` the kernel
// does it for the next thread a CPU with none picks, the deepest way back
// to user mode there is (it may push a signal frame): that thread mustn't
// get there.
//
//   kstack [THREADS [fault|picked]]   (default 4)
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define STACK_OVERFLOW_TEST 0x67726978L

static atomic_int fired;
static int others, how;

static void *spin(void *arg) {
    (void)arg;
    for (;;) {
        int cpu = sched_getcpu();
        if ((cpu != 0 || !others) && !atomic_exchange(&fired, 1)) {
            printf("overflowing on cpu %d\n", cpu);
            fflush(stdout);
            syscall(STACK_OVERFLOW_TEST, how);
            if (how == 2) usleep(50000);
            printf("still here\n");
            exit(1);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 4;
    others = n > 1;
    how = argc > 2 ? (strcmp(argv[2], "fault") ? 2 : 1) : 0;
    pthread_t t[16];
    for (int i = 0; i < n && i < 16; i++) pthread_create(&t[i], NULL, spin, NULL);
    pthread_join(t[0], NULL);
    return 1;
}
