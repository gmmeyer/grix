// pthreads: mutexes, condvars, TLS, FP state across switches, preemption,
// timed waits, concurrent sleeps, detached threads, distinct tids.
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d)\n", #c, __LINE__); return 1; } } while (0)

static __thread long tls_value;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static long counter;
static int ready;
static atomic_int spin_flag, detached_done;
static atomic_long tids[8];

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void *worker(void *arg) {
    long id = (long)arg;
    tls_value = id * 10;
    tids[id] = syscall(SYS_gettid);
    for (int i = 0; i < 20000; i++) {
        pthread_mutex_lock(&mu);
        counter++;
        pthread_mutex_unlock(&mu);
        if (i % 1000 == 0) sched_yield();
    }
    // FP/SIMD registers must survive being preempted and switched.
    double acc = 0;
    for (int i = 1; i <= 300000; i++) acc += 1.0 / ((double)i * i);
    if (tls_value != id * 10) return (void *)1;
    if (acc < 1.64493 || acc > 1.64494) return (void *)2;
    return (void *)(id + 100);
}

static void *waiter(void *arg) {
    pthread_mutex_lock(&mu);
    while (!ready) pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    return arg;
}

static void *spinner(void *arg) {
    while (!atomic_load(&spin_flag)) {}  // never yields: needs preemption
    return arg;
}

static void *sleeper(void *arg) {
    usleep(100 * 1000);
    return arg;
}

static void *detached(void *arg) {
    atomic_store(&detached_done, 1);
    return arg;
}

int main(void) {
    pthread_t t[8];
    for (long i = 0; i < 8; i++) CHECK(pthread_create(&t[i], 0, worker, (void *)i) == 0);
    for (long i = 0; i < 8; i++) {
        void *ret;
        CHECK(pthread_join(t[i], &ret) == 0);
        CHECK((long)ret == i + 100);
    }
    CHECK(counter == 8 * 20000);
    long main_tid = syscall(SYS_gettid);
    CHECK(main_tid == getpid());
    for (int i = 0; i < 8; i++) {
        CHECK(tids[i] != main_tid);
        for (int j = 0; j < i; j++) CHECK(tids[i] != tids[j]);
    }

    // Condition variable wakeup.
    pthread_t w;
    CHECK(pthread_create(&w, 0, waiter, 0) == 0);
    usleep(10 * 1000);
    pthread_mutex_lock(&mu);
    ready = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
    CHECK(pthread_join(w, 0) == 0);

    // Preemption: the spinner never yields, so main only runs again if the
    // kernel preempts it.
    pthread_t s;
    CHECK(pthread_create(&s, 0, spinner, 0) == 0);
    usleep(30 * 1000);
    atomic_store(&spin_flag, 1);
    CHECK(pthread_join(s, 0) == 0);

    // Timed wait that times out.
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 50 * 1000 * 1000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000; }
    long t0 = now_ms();
    pthread_mutex_lock(&mu);
    int rc = pthread_cond_timedwait(&cv, &mu, &deadline);
    pthread_mutex_unlock(&mu);
    CHECK(rc == ETIMEDOUT);
    CHECK(now_ms() - t0 >= 45);

    // Sleeps in different threads overlap instead of adding up.
    t0 = now_ms();
    pthread_t sl[4];
    for (int i = 0; i < 4; i++) CHECK(pthread_create(&sl[i], 0, sleeper, 0) == 0);
    for (int i = 0; i < 4; i++) CHECK(pthread_join(sl[i], 0) == 0);
    long slept = now_ms() - t0;
    CHECK(slept >= 100 && slept < 300);

    // Detached thread.
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t d;
    CHECK(pthread_create(&d, &attr, detached, 0) == 0);
    while (!atomic_load(&detached_done)) usleep(1000);

    printf("threads ok counter=%ld\n", counter);
    return 0;
}
