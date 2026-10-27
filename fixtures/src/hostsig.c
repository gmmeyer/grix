// Signals from the host. Prints "ready" once its handlers are in place and a
// child (in the same process group) waits too; then waits for signals.
// SIGINT or SIGTERM: both say so (the child then exits). SIGTERM: the parent
// writes /out/result.txt, reaps the child, exits 0. Signals are blocked
// except inside sigsuspend, so none slips by between a check and a wait.
//   hostsig plain   - no handlers: just pause()
//   hostsig chatty  - no handlers: print a line every 5 ms
//   hostsig child   - no handlers: pause() while a child exits a little later
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t got_int, got_term;

static void on_int(int s) { (void)s; got_int = 1; }
static void on_term(int s) { (void)s; got_term = 1; }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && strcmp(argv[1], "plain") == 0) {
        printf("ready\n");
        pause();
        printf("not reached\n");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        if (fork() == 0) {
            usleep(100 * 1000);
            _exit(0);
        }
        printf("ready\n");
        pause();
        printf("not reached\n");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "chatty") == 0) {
        printf("ready\n");
        for (;;) {
            printf("still here\n");
            usleep(5000);
        }
    }
    struct sigaction sa = {0};
    sa.sa_handler = on_int;
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigprocmask(SIG_BLOCK, &block, &old);
    int ready[2];
    if (pipe(ready) != 0) return 2;
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]);
        write(ready[1], "x", 1);
        while (!got_int && !got_term) sigsuspend(&old);
        printf(got_int ? "child got SIGINT\n" : "child got SIGTERM\n");
        _exit(0);
    }
    char c;
    close(ready[1]);
    if (read(ready[0], &c, 1) != 1) return 3;
    printf("ready\n");
    for (;;) {
        while (!got_int && !got_term) sigsuspend(&old);
        if (got_int) {
            got_int = 0;
            printf("parent got SIGINT\n");
        }
        if (got_term) {
            FILE *f = fopen("/out/result.txt", "w");
            if (!f) return 4;
            fprintf(f, "cleaned up\n");
            fclose(f);
            waitpid(child, NULL, 0);
            printf("got SIGTERM\n");
            return 0;
        }
    }
}
