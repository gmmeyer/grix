// Clocks and sleeping; random numbers.
#include <stdio.h>
#include <sys/random.h>
#include <time.h>

int main(void) {
    struct timespec a, b, d = {0, 20 * 1000 * 1000};
    clock_gettime(CLOCK_MONOTONIC, &a);
    nanosleep(&d, 0);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    unsigned char r[32];
    int got = getrandom(r, sizeof r, 0);
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= r[i];
    printf("slept_ms=%ld now=%lld random=%d/%d\n", ms, (long long)time(0), got, nonzero != 0);
    return ms >= 20 ? 0 : 1;
}
