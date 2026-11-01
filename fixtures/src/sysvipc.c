// System V message queues and semaphores. Passes on Linux as it is.
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                 \
    do {                                                                         \
        if (!(c)) {                                                              \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);     \
            exit(1);                                                             \
        }                                                                        \
    } while (0)
#define FAILS(call, e) CHECK((long)(call) == -1 && errno == (e))

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

struct text {
    long type;
    char body[64];
};

static void sent(int q, long type, const char *s) {
    struct text m = {type, {0}};
    strcpy(m.body, s);
    CHECK(msgsnd(q, &m, strlen(s) + 1, 0) == 0);
}

static void received(int q, long type, int flags, long want_type, const char *want) {
    struct text m;
    ssize_t n = msgrcv(q, &m, sizeof m.body, type, flags);
    CHECK(n == (ssize_t)strlen(want) + 1);
    CHECK(m.type == want_type && !strcmp(m.body, want));
}

static void wait_ok(pid_t c) {
    int status;
    CHECK(waitpid(c, &status, 0) == c && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void queues(void) {
    int key = getpid() * 31 + 1;
    FAILS(msgget(key, 0), ENOENT);
    int q = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(q >= 0);
    CHECK(msgget(key, 0) == q && msgget(key, IPC_CREAT) == q);
    FAILS(msgget(key, IPC_CREAT | IPC_EXCL | 0600), EEXIST);
    CHECK(msgget(IPC_PRIVATE, 0600) != q);

    // Which one comes back.
    sent(q, 3, "three");
    sent(q, 1, "one");
    sent(q, 2, "two");
    sent(q, 1, "uno");
    received(q, 0, 0, 3, "three");
    received(q, 2, 0, 2, "two");
    received(q, -2, 0, 1, "one");
    sent(q, 5, "five");
    received(q, 1, MSG_EXCEPT, 5, "five");
    received(q, -9, 0, 1, "uno");
    struct text m;
    FAILS(msgrcv(q, &m, sizeof m.body, 0, IPC_NOWAIT), ENOMSG);
    FAILS(msgrcv(q, &m, sizeof m.body, 7, IPC_NOWAIT), ENOMSG);

    // Too long for the buffer: refused and left, unless it's let go.
    sent(q, 1, "a long one");
    FAILS(msgrcv(q, &m, 3, 0, 0), E2BIG);
    CHECK(msgrcv(q, &m, 3, 0, MSG_NOERROR) == 3 && !memcmp(m.body, "a l", 3));

    // What a send won't take.
    m.type = 0;
    FAILS(msgsnd(q, &m, 1, 0), EINVAL);
    m.type = 1;
    FAILS(msgsnd(q, &m, 8193, 0), EINVAL);
    FAILS(msgsnd(q, &m, (size_t)-1, 0), EINVAL);
    FAILS(msgsnd(1234567, &m, 1, 0), EINVAL);
    FAILS(msgrcv(q, &m, (size_t)-1, 0, IPC_NOWAIT), EINVAL);
    CHECK(msgsnd(q, &m, 0, 0) == 0);
    CHECK(msgrcv(q, &m, 0, 0, 0) == 0);

    // As much as the queue says it holds, and no more.
    struct msqid_ds st;
    CHECK(msgctl(q, IPC_STAT, &st) == 0);
    CHECK(st.msg_qbytes == 16384 && st.msg_qnum == 0 && st.__msg_cbytes == 0);
    CHECK(st.msg_perm.mode == 0600 && st.msg_perm.uid == geteuid() && st.msg_lspid == getpid());
    CHECK(st.msg_perm.__key == key);
    st.msg_qbytes = 10;
    CHECK(msgctl(q, IPC_SET, &st) == 0);
    sent(q, 1, "12345678");
    CHECK(msgctl(q, IPC_STAT, &st) == 0 && st.msg_qnum == 1 && st.__msg_cbytes == 9 && st.msg_lrpid == getpid());
    m.type = 1;
    FAILS(msgsnd(q, &m, 2, IPC_NOWAIT), EAGAIN);

    // A blocked sender goes on as room comes, a blocked receiver as a
    // message does.
    pid_t c = fork();
    CHECK(c >= 0);
    if (!c) {
        struct text big = {1, "xy"};
        CHECK(msgsnd(q, &big, 3, 0) == 0);
        _exit(0);
    }
    usleep(20000);
    received(q, 0, 0, 1, "12345678");
    wait_ok(c);
    received(q, 0, 0, 1, "xy");
    st.msg_qbytes = 100;
    CHECK(msgctl(q, IPC_SET, &st) == 0);
    c = fork();
    CHECK(c >= 0);
    if (!c) {
        received(q, 9, 0, 9, "nine");
        _exit(0);
    }
    usleep(20000);
    sent(q, 8, "eight");
    sent(q, 9, "nine");
    wait_ok(c);
    received(q, 0, 0, 8, "eight");

    // Removed: its waiters are told, and nothing else finds it.
    c = fork();
    CHECK(c >= 0);
    if (!c) {
        FAILS(msgrcv(q, &m, sizeof m.body, 0, 0), EIDRM);
        _exit(0);
    }
    usleep(20000);
    CHECK(msgctl(q, IPC_RMID, 0) == 0);
    wait_ok(c);
    FAILS(msgsnd(q, &m, 1, IPC_NOWAIT), EINVAL);
    FAILS(msgget(key, 0), ENOENT);
    FAILS(msgctl(q, IPC_STAT, &st), EINVAL);
    printf("queues ok\n");
}

static void handler(int sig) {
    (void)sig;
}

// A signal ends the wait, whatever SA_RESTART says: not one of those calls.
static void interrupted(void) {
    int q = msgget(IPC_PRIVATE, 0600);
    int s = semget(IPC_PRIVATE, 1, 0600);
    CHECK(q >= 0 && s >= 0);
    struct sigaction a;
    memset(&a, 0, sizeof a);
    a.sa_handler = handler;
    a.sa_flags = SA_RESTART;
    CHECK(sigaction(SIGALRM, &a, 0) == 0);
    struct text m;
    alarm(1);
    FAILS(msgrcv(q, &m, sizeof m.body, 0, 0), EINTR);
    struct sembuf take = {0, -1, 0};
    alarm(1);
    FAILS(semop(s, &take, 1), EINTR);
    CHECK(msgctl(q, IPC_RMID, 0) == 0 && semctl(s, 0, IPC_RMID) == 0);
    printf("interrupted ok\n");
}

static void semaphores(void) {
    int key = getpid() * 31 + 2;
    FAILS(semget(key, 1, 0), ENOENT);
    FAILS(semget(key, 0, IPC_CREAT | 0600), EINVAL);
    FAILS(semget(key, 40000, IPC_CREAT | 0600), EINVAL);
    int s = semget(key, 3, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(s >= 0);
    CHECK(semget(key, 0, 0) == s && semget(key, 3, 0) == s);
    FAILS(semget(key, 4, 0), EINVAL);
    FAILS(semget(key, 3, IPC_CREAT | IPC_EXCL), EEXIST);

    struct semid_ds st;
    union semun u = {.buf = &st};
    CHECK(semctl(s, 0, IPC_STAT, u) == 0);
    CHECK(st.sem_nsems == 3 && st.sem_perm.mode == 0600 && st.sem_otime == 0 && st.sem_ctime != 0);

    // Values.
    u.val = 7;
    CHECK(semctl(s, 1, SETVAL, u) == 0 && semctl(s, 1, GETVAL) == 7 && semctl(s, 0, GETVAL) == 0);
    u.val = 32768;
    FAILS(semctl(s, 1, SETVAL, u), ERANGE);
    u.val = -1;
    FAILS(semctl(s, 1, SETVAL, u), ERANGE);
    FAILS(semctl(s, 9, GETVAL), EINVAL);
    unsigned short all[3] = {1, 2, 3}, got[3] = {0, 0, 0};
    u.array = all;
    CHECK(semctl(s, 0, SETALL, u) == 0);
    u.array = got;
    CHECK(semctl(s, 0, GETALL, u) == 0 && got[0] == 1 && got[1] == 2 && got[2] == 3);

    // All of an array, or none of it.
    struct sembuf both[2] = {{0, -1, IPC_NOWAIT}, {1, -5, IPC_NOWAIT}};
    FAILS(semop(s, both, 2), EAGAIN);
    CHECK(semctl(s, 0, GETVAL) == 1 && semctl(s, 1, GETVAL) == 2);
    both[1].sem_op = -2;
    CHECK(semop(s, both, 2) == 0);
    CHECK(semctl(s, 0, GETVAL) == 0 && semctl(s, 1, GETVAL) == 0);
    CHECK(semctl(s, 0, GETPID) == getpid());
    CHECK(semctl(s, 0, IPC_STAT, (union semun){.buf = &st}) == 0 && st.sem_otime != 0);

    // Waiting for zero, and past the end, and too many at once.
    struct sembuf zero = {2, 0, IPC_NOWAIT};
    FAILS(semop(s, &zero, 1), EAGAIN);
    struct sembuf out = {3, 1, 0};
    FAILS(semop(s, &out, 1), EFBIG);
    FAILS(semop(s, &zero, 0), EINVAL);
    static struct sembuf many[501];
    FAILS(semop(s, many, 501), E2BIG);
    struct sembuf over = {2, 32767, IPC_NOWAIT};
    FAILS(semop(s, &over, 1), ERANGE);
    FAILS(semop(1234567, &zero, 1), EINVAL);

    // Time runs out.
    struct sembuf take = {0, -1, 0};
    struct timespec t = {0, 20000000};
    FAILS(semtimedop(s, &take, 1, &t), EAGAIN);

    // A blocked process goes on as the value's there, counted while it waits.
    pid_t c = fork();
    CHECK(c >= 0);
    if (!c) {
        CHECK(semop(s, &take, 1) == 0);
        _exit(0);
    }
    for (int i = 0; i < 200 && semctl(s, 0, GETNCNT) != 1; i++) usleep(5000);
    CHECK(semctl(s, 0, GETNCNT) == 1 && semctl(s, 0, GETZCNT) == 0);
    struct sembuf give = {0, 1, 0};
    CHECK(semop(s, &give, 1) == 0);
    wait_ok(c);
    CHECK(semctl(s, 0, GETNCNT) == 0);
    u.val = 1;
    CHECK(semctl(s, 2, SETVAL, u) == 0);
    c = fork();
    CHECK(c >= 0);
    if (!c) {
        struct sembuf z = {2, 0, 0};
        CHECK(semop(s, &z, 1) == 0);
        _exit(0);
    }
    for (int i = 0; i < 200 && semctl(s, 2, GETZCNT) != 1; i++) usleep(5000);
    CHECK(semctl(s, 2, GETZCNT) == 1);
    u.val = 0;
    CHECK(semctl(s, 2, SETVAL, u) == 0);
    wait_ok(c);

    // SEM_UNDO: what a process did is undone as it ends, and only that.
    c = fork();
    CHECK(c >= 0);
    if (!c) {
        struct sembuf undone = {1, 5, SEM_UNDO};
        CHECK(semop(s, &undone, 1) == 0);
        _exit(semctl(s, 1, GETVAL) == 5 ? 0 : 1);
    }
    wait_ok(c);
    CHECK(semctl(s, 1, GETVAL) == 0);
    // A value set by hand clears what's to be undone.
    c = fork();
    CHECK(c >= 0);
    if (!c) {
        struct sembuf undone = {1, 5, SEM_UNDO};
        CHECK(semop(s, &undone, 1) == 0);
        union semun v = {.val = 2};
        CHECK(semctl(s, 1, SETVAL, v) == 0);
        _exit(0);
    }
    wait_ok(c);
    CHECK(semctl(s, 1, GETVAL) == 2);

    // Removed, with someone waiting.
    c = fork();
    CHECK(c >= 0);
    if (!c) {
        FAILS(semop(s, &take, 1), EIDRM);
        _exit(0);
    }
    for (int i = 0; i < 200 && semctl(s, 0, GETNCNT) != 1; i++) usleep(5000);
    CHECK(semctl(s, 0, IPC_RMID) == 0);
    wait_ok(c);
    FAILS(semop(s, &zero, 1), EINVAL);
    FAILS(semctl(s, 0, GETVAL), EINVAL);
    FAILS(semget(key, 0, 0), ENOENT);
    printf("semaphores ok\n");
}

// Whose they are, by mode, for someone else. Needs root to start.
static void access_rights(void) {
    if (geteuid() != 0) return;
    int q = msgget(IPC_PRIVATE, 0640);
    int s = semget(IPC_PRIVATE, 1, 0640);
    CHECK(q >= 0 && s >= 0);
    pid_t c = fork();
    CHECK(c >= 0);
    if (!c) {
        CHECK(setgroups(0, 0) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
        struct text m = {1, "x"};
        FAILS(msgsnd(q, &m, 1, IPC_NOWAIT), EACCES);
        FAILS(msgrcv(q, &m, 1, 0, IPC_NOWAIT), EACCES);
        struct msqid_ds st;
        FAILS(msgctl(q, IPC_STAT, &st), EACCES);
        FAILS(msgctl(q, IPC_RMID, 0), EPERM);
        FAILS(semctl(s, 0, GETVAL), EACCES);
        struct sembuf take = {0, 1, IPC_NOWAIT};
        FAILS(semop(s, &take, 1), EACCES);
        FAILS(semctl(s, 0, IPC_RMID), EPERM);
        _exit(0);
    }
    wait_ok(c);
    CHECK(msgctl(q, IPC_RMID, 0) == 0 && semctl(s, 0, IPC_RMID) == 0);
    printf("rights ok\n");
}

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    queues();
    semaphores();
    interrupted();
    access_rights();
    printf("sysvipc ok\n");
    return 0;
}
