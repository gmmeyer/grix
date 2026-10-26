// Two threads each take one lock and then wait for the other's.
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t a = PTHREAD_MUTEX_INITIALIZER, b = PTHREAD_MUTEX_INITIALIZER;

static void *other(void *arg) {
    pthread_mutex_lock(&b);
    usleep(20 * 1000);
    pthread_mutex_lock(&a);
    return arg;
}

int main(void) {
    pthread_t t;
    if (pthread_create(&t, 0, other, 0) != 0) {
        printf("pthread_create failed\n");
        return 1;
    }
    pthread_mutex_lock(&a);
    usleep(20 * 1000);
    pthread_mutex_lock(&b);
    printf("unreachable\n");
    return 0;
}
