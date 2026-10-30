// Runs a CPU's kernel stack past its end, with a debug kernel's test hook
// (syscall::STACK_OVERFLOW_TEST), which then returns or, with `fault`,
// faults down there: the kernel must report it, naming the CPU, and stop.
// With more CPUs, from a thread on one other than CPU 0 (whose stack is
// the lowest), as threads spin on all of them.
//
//   kstack [THREADS [fault]]   (default 4)
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define STACK_OVERFLOW_TEST 0x67726978L

static atomic_int fired;
static int others, fault;

static void *spin(void *arg) {
    (void)arg;
    for (;;) {
        int cpu = sched_getcpu();
        if ((cpu != 0 || !others) && !atomic_exchange(&fired, 1)) {
            printf("overflowing on cpu %d\n", cpu);
            fflush(stdout);
            syscall(STACK_OVERFLOW_TEST, fault);
            printf("still here\n");
            exit(1);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 4;
    others = n > 1;
    fault = argc > 2;
    pthread_t t[16];
    for (int i = 0; i < n && i < 16; i++) pthread_create(&t[i], NULL, spin, NULL);
    pthread_join(t[0], NULL);
    return 1;
}
