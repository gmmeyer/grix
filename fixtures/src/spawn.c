// Create one thread and report the result (used to check the `threads` gate).
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static void *run(void *arg) { return arg; }

int main(void) {
    pthread_t t;
    int rc = pthread_create(&t, 0, run, 0);
    if (rc != 0) {
        printf("pthread_create: %s\n", strerror(rc));
        return 1;
    }
    pthread_join(t, 0);
    printf("thread ran\n");
    return 0;
}
