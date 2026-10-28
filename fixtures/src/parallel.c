// Processes run in parallel, one per CPU: three children each burn 300 ms
// of CPU, and with three or more CPUs their CPU time adds up to well over
// the wall time it took (in the guest's own time, so a busy host doesn't
// change the answer). `parallel N` prints the ratio for N children.
// Needs `process`.
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long ns(clockid_t c) {
    struct timespec t;
    clock_gettime(c, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 3;
    // They all start together, once forked (forking is slow under
    // emulation, and isn't what's measured).
    int go[2];
    if (pipe(go) != 0) return 1;
    for (int i = 0; i < n; i++) {
        pid_t pid = fork();
        if (pid < 0) return 1;
        if (pid == 0) {
            char c;
            close(go[1]);
            if (read(go[0], &c, 1) != 1) _exit(3);
            long long until = ns(CLOCK_PROCESS_CPUTIME_ID) + 300000000LL;
            // Mostly user code: the clock (a system call) only now and then.
            volatile unsigned long x = 0;
            while (ns(CLOCK_PROCESS_CPUTIME_ID) < until)
                for (int i = 0; i < 100000; i++) x++;
            _exit(0);
        }
    }
    close(go[0]);
    long long start = ns(CLOCK_MONOTONIC);
    for (int i = 0; i < n; i++)
        if (write(go[1], "x", 1) != 1) return 1;
    long long cpu = 0;
    for (int i = 0; i < n; i++) {
        int status;
        struct rusage ru;
        if (wait4(-1, &status, 0, &ru) < 0 || !WIFEXITED(status)) return 2;
        cpu += ru.ru_utime.tv_sec * 1000000000LL + ru.ru_utime.tv_usec * 1000LL;
    }
    long long wall = ns(CLOCK_MONOTONIC) - start;
    printf("%.2f\n", (double)cpu / (double)wall);
    return 0;
}
