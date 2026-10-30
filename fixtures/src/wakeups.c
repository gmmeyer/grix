// What a waiter is owed when something changes under it, with nothing else
// going on to bring the kernel round: whoever could run must, and only a
// real deadlock is called one. A spinning thread here makes no system
// call, so only a timer gets anyone else onto its CPU.
//
//   wakeups alarm       an itimer's SIGALRM ends a sleeping child, its
//                       parent alone in wait(): not a deadlock
//   wakeups killtimer   a POSIX timer's SIGKILL does the same
//   wakeups timers      64 fatal timers end a spinning child likewise
//   wakeups killwait    this thread kills a child and spins: a sibling
//                       thread's wait() returns
//   wakeups killpipe    the same for a sibling's read() of a pipe the
//                       child held
//   wakeups timerspin   a timer ends a sleeping child while another process
//                       spins: the parent's wait() returns
//   wakeups sigio       SIGIO wakes a process, the writer spinning
//   wakeups sigcont     O_ASYNC's signal is SIGCONT, for a stopped process
//   wakeups console [S] for S seconds (2) writes to stdout that need the
//                       console's interrupts go on, between the CPU idling
//                       and spinning, with timers firing around them
//   wakeups beneath     a debug x86_64 kernel has the next wait take the
//                       console's vector first, so that what wakes it lands
//                       on top: back in user mode, it has been handled
//
// And deadlocks that must still be called that, just after a process ended
// (these never print "unreachable"):
//   wakeups deadwait    the child reaped, then a futex nobody wakes
//   wakeups deadread    a timer ends a child while the parent reads a pipe
//                       only it can write to
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                 \
    do {                                                         \
        if (!(c)) {                                              \
            printf("FAILED: %s (line %d)\n", #c, __LINE__);      \
            exit(1);                                             \
        }                                                        \
    } while (0)

// How long anyone is given: far more than a time slice, on any machine.
#define PATIENCE 10.0

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void sleep_ms(long ms) {
    struct timespec t = {ms / 1000, ms % 1000 * 1000000};
    while (nanosleep(&t, &t) != 0) {
    }
}

// Spin, with no system call, until *flag is `want`.
static void spin_until(atomic_int *flag, int want, const char *what) {
    double t0 = now();
    while (atomic_load(flag) != want) {
        if (now() - t0 > PATIENCE) {
            printf("FAILED: %s\n", what);
            exit(1);
        }
    }
}

static atomic_int *shared_flag(void) {
    atomic_int *f = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(f != MAP_FAILED);
    return f;
}

// A POSIX timer that sends `sig` `ms` from now, and then every `every_ms`.
static void timer_sends(int sig, long ms, long every_ms) {
    struct sigevent e = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = sig};
    long id = 0;
    CHECK(syscall(SYS_timer_create, CLOCK_MONOTONIC, &e, &id) == 0);
    struct {
        struct timespec interval, value;
    } s = {{every_ms / 1000, every_ms % 1000 * 1000000}, {ms / 1000, ms % 1000 * 1000000}};
    CHECK(syscall(SYS_timer_settime, id, 0, &s, 0) == 0);
}

// A child that a timer ends, in `pause`. The timer fires once: another tick
// due would bring the kernel round to look again, which is what must not be
// needed.
static pid_t ended_by_timer(int sig, long ms) {
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        timer_sends(sig, ms, 0);
        for (;;) pause();
    }
    return c;
}

static int alarm_ends_child(void) {
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        struct itimerval t = {{0, 0}, {0, 50000}};
        CHECK(setitimer(ITIMER_REAL, &t, 0) == 0);
        for (;;) pause();
    }
    int st;
    CHECK(waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGALRM);
    printf("alarm ok\n");
    return 0;
}

static int timer_ends_child(void) {
    int st;
    pid_t c = ended_by_timer(SIGKILL, 50);
    CHECK(waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
    printf("killtimer ok\n");
    return 0;
}

static int timers_end_spinner(void) {
    for (int round = 0; round < 8; round++) {
        pid_t c = fork();
        CHECK(c >= 0);
        if (c == 0) {
            for (int i = 0; i < 64; i++) timer_sends(i % 2 ? SIGTERM : SIGKILL, 1, 1);
            for (;;) {
            }
        }
        int st;
        CHECK(waitpid(c, &st, 0) == c && WIFSIGNALED(st));
    }
    printf("timers ok\n");
    return 0;
}

static atomic_int done;

static void *waits(void *arg) {
    (void)arg;
    wait(0);
    atomic_store(&done, 1);
    return 0;
}

static int kill_then_spin_wait(void) {
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0)
        for (;;) pause();
    pthread_t t;
    CHECK(pthread_create(&t, 0, waits, 0) == 0);
    sleep_ms(50);
    CHECK(kill(c, SIGKILL) == 0);
    spin_until(&done, 1, "wait() in a sibling wasn't woken");
    printf("killwait ok\n");
    return 0;
}

static void *reads(void *arg) {
    char b;
    CHECK(read((int)(long)arg, &b, 1) == 0);
    atomic_store(&done, 1);
    return 0;
}

static int kill_then_spin_read(void) {
    int p[2];
    CHECK(pipe(p) == 0);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        close(p[0]);
        for (;;) pause();
    }
    close(p[1]);
    pthread_t t;
    CHECK(pthread_create(&t, 0, reads, (void *)(long)p[0]) == 0);
    sleep_ms(50);
    CHECK(kill(c, SIGKILL) == 0);
    spin_until(&done, 1, "read() wasn't woken by EOF");
    printf("killpipe ok\n");
    return 0;
}

static int timer_ends_child_beside_spinner(void) {
    atomic_int *reaped = shared_flag();
    pid_t spinner = fork();
    CHECK(spinner >= 0);
    if (spinner == 0) {
        spin_until(reaped, 1, "wait() wasn't woken");
        _exit(0);
    }
    int st;
    pid_t c = ended_by_timer(SIGKILL, 50);
    CHECK(waitpid(c, &st, 0) == c);
    atomic_store(reaped, 1);
    CHECK(waitpid(spinner, &st, 0) == spinner && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("timerspin ok\n");
    return 0;
}

static atomic_int *io_flag;

static void on_sigio(int s) {
    (void)s;
    atomic_store(io_flag, 1);
}

// The child, with SIGIO to come for pipe `fd`, in `pause`.
static pid_t waits_for_sigio(int fd) {
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        signal(SIGIO, on_sigio);
        CHECK(fcntl(fd, F_SETOWN, getpid()) == 0);
        CHECK(fcntl(fd, F_SETFL, O_ASYNC | O_NONBLOCK) == 0);
        atomic_store(io_flag, 2);
        for (;;) pause();
    }
    return c;
}

static int sigio_wakes(void) {
    io_flag = shared_flag();
    int p[2];
    CHECK(pipe(p) == 0);
    pid_t c = waits_for_sigio(p[0]);
    spin_until(io_flag, 2, "the child never started");
    sleep_ms(50);
    CHECK(write(p[1], "x", 1) == 1);
    spin_until(io_flag, 1, "the child SIGIO woke never ran");
    CHECK(kill(c, SIGKILL) == 0);
    CHECK(waitpid(c, 0, 0) == c);
    printf("sigio ok\n");
    return 0;
}

static int sigcont_continues(void) {
    atomic_int *ran = shared_flag();
    int p[2];
    CHECK(pipe(p) == 0);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        CHECK(fcntl(p[0], F_SETOWN, getpid()) == 0);
        CHECK(fcntl(p[0], F_SETSIG, SIGCONT) == 0);
        CHECK(fcntl(p[0], F_SETFL, O_ASYNC | O_NONBLOCK) == 0);
        for (;;) atomic_fetch_add(ran, 1);
    }
    for (double t0 = now(); !atomic_load(ran);) CHECK(now() - t0 < PATIENCE);
    CHECK(kill(c, SIGSTOP) == 0);
    int st;
    CHECK(waitpid(c, &st, WUNTRACED) == c && WIFSTOPPED(st));
    int stopped_at = atomic_load(ran);
    CHECK(write(p[1], "x", 1) == 1);
    double t0 = now();
    while (atomic_load(ran) == stopped_at) {
        if (now() - t0 > PATIENCE) {
            printf("FAILED: the child SIGCONT continued never ran\n");
            return 1;
        }
    }
    CHECK(kill(c, SIGKILL) == 0);
    CHECK(waitpid(c, 0, 0) == c);
    printf("sigcont ok\n");
    return 0;
}

static void *ticker(void *arg) {
    (void)arg;
    for (;;) {
        struct timespec t = {0, 200000};
        nanosleep(&t, 0);
    }
}

static atomic_long written;

static void *writer(void *arg) {
    static char line[16 << 10];
    (void)arg;
    memset(line, 'w', sizeof line - 1);
    line[sizeof line - 1] = '\n';
    for (;;) {
        CHECK(write(1, line, sizeof line) == sizeof line);
        atomic_fetch_add(&written, 1);
    }
}

// Turn by turn: every CPU spinning, while the writer fills the console's
// ring time and again (2 MiB) and needs its interrupts to go on, which an
// interrupt left in service on the CPU taking them would hold up for as long
// as that CPU spins; and sleeping, so the CPUs idle, and take the console's
// interrupts and the timers' around `hlt`.
static void *spinner(void *arg) {
    double end = *(double *)arg;
    while (now() < end) {
        sleep_ms(1);
        long seen = atomic_load(&written);
        double t0 = now();
        while (atomic_load(&written) < seen + 128) {
            if (now() - t0 > PATIENCE) {
                fprintf(stderr, "FAILED: the writer's interrupt never came\n");
                _exit(1);
            }
        }
    }
    return 0;
}

static int console_traffic(double seconds) {
    double end = now() + seconds;
    pthread_t t;
    CHECK(pthread_create(&t, 0, ticker, 0) == 0);
    CHECK(pthread_create(&t, 0, writer, 0) == 0);
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t spinners[8];
    for (long i = 0; i < cpus && i < 8; i++) CHECK(pthread_create(&spinners[i], 0, spinner, &end) == 0);
    for (long i = 0; i < cpus && i < 8; i++) pthread_join(spinners[i], 0);
    fprintf(stderr, "console ok\n");
    exit(0);
}

// /proc/grix/smp's total of device interrupts handled.
static long device_interrupts(void) {
    char line[1024];
    FILE *f = fopen("/proc/grix/smp", "r");
    CHECK(f && fgets(line, sizeof line, f));
    int column = 0;
    for (char *w = strtok(line, " \n"); w && strcmp(w, "device"); w = strtok(0, " \n")) column++;
    long n = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "all ", 4)) continue;
        char *w = strtok(line, " \n");
        for (int i = 0; i < column; i++) w = strtok(0, " \n");
        n = atol(w);
    }
    fclose(f);
    CHECK(n >= 0);
    return n;
}

static int device_beneath_timer(void) {
    long before = device_interrupts();
    syscall(0x67726978L, 3);  // syscall::STACK_OVERFLOW_TEST
    sleep_ms(20);
    CHECK(device_interrupts() > before);
    printf("beneath ok\n");
    return 0;
}

static int deadlock_after_wait(void) {
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) _exit(0);
    CHECK(waitpid(c, 0, 0) == c);
    printf("reaped\n");
    fflush(stdout);
    int word = 0;
    syscall(SYS_futex, &word, FUTEX_WAIT, 0, 0, 0, 0);
    printf("unreachable\n");
    return 1;
}

static int deadlock_after_timer(void) {
    int p[2];
    CHECK(pipe(p) == 0);
    pid_t c = ended_by_timer(SIGKILL, 50);
    (void)c;
    char b;
    read(p[0], &b, 1);
    printf("unreachable\n");
    return 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    const char *c = argc > 1 ? argv[1] : "";
    if (!strcmp(c, "alarm")) return alarm_ends_child();
    if (!strcmp(c, "killtimer")) return timer_ends_child();
    if (!strcmp(c, "timers")) return timers_end_spinner();
    if (!strcmp(c, "killwait")) return kill_then_spin_wait();
    if (!strcmp(c, "killpipe")) return kill_then_spin_read();
    if (!strcmp(c, "timerspin")) return timer_ends_child_beside_spinner();
    if (!strcmp(c, "sigio")) return sigio_wakes();
    if (!strcmp(c, "sigcont")) return sigcont_continues();
    if (!strcmp(c, "console")) return console_traffic(argc > 2 ? atof(argv[2]) : 2);
    if (!strcmp(c, "beneath")) return device_beneath_timer();
    if (!strcmp(c, "deadwait")) return deadlock_after_wait();
    if (!strcmp(c, "deadread")) return deadlock_after_timer();
    return 2;
}
