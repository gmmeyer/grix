// Landlock: the version query, the calls' errors, and rulesets enforced
// as Linux enforces them: reads, writes, directory listings, making and
// removing each kind of node, execve, truncate (by path, O_TRUNC and
// ftruncate, decided at open), rename and link between hierarchies
// (REFER, EXDEV), stacked layers (at most 16), inheritance across fork,
// threads and execve (threads that were there before keep their own),
// files with several names, no looking into processes outside the
// domain, no_new_privs for non-root, TCP bind and connect by port, device
// ioctls (IOCTL_DEV), and, given `mounts`, rules on a live mount and a
// lazy import. Every check is in a child of its own: restrictions don't come
// off. Needs `process`, `threads`, `net` and `fs_write`.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <termios.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno);      \
            fflush(stdout);                                                       \
            _exit(1);                                                             \
        }                                                                         \
    } while (0)
// A call that must fail with `e`.
#define FAILS(call, e) CHECK((call) == -1 && errno == (e))

// include/uapi/linux/landlock.h, as of ABI 5.
#define EXECUTE (1ULL << 0)
#define WRITE_FILE (1ULL << 1)
#define READ_FILE (1ULL << 2)
#define READ_DIR (1ULL << 3)
#define REMOVE_DIR (1ULL << 4)
#define REMOVE_FILE (1ULL << 5)
#define MAKE_CHAR (1ULL << 6)
#define MAKE_DIR (1ULL << 7)
#define MAKE_REG (1ULL << 8)
#define MAKE_SOCK (1ULL << 9)
#define MAKE_FIFO (1ULL << 10)
#define MAKE_BLOCK (1ULL << 11)
#define MAKE_SYM (1ULL << 12)
#define REFER (1ULL << 13)
#define TRUNCATE (1ULL << 14)
#define IOCTL_DEV (1ULL << 15)
#define FS_ALL ((1ULL << 16) - 1)
#define BIND_TCP (1ULL << 0)
#define CONNECT_TCP (1ULL << 1)
#define RULE_PATH_BENEATH 1
#define RULE_NET_PORT 2
#define VERSION 1

struct ruleset_attr { uint64_t fs, net; };
struct path_beneath { uint64_t allowed; int32_t fd; } __attribute__((packed));
struct net_port { uint64_t allowed, port; };

static long create(void *attr, size_t size, unsigned flags) { return syscall(444, attr, size, flags); }
static long add(int rs, int type, void *attr, unsigned flags) { return syscall(445, rs, type, attr, flags); }
static long restrict_self(int rs, unsigned flags) { return syscall(446, rs, flags); }

static int ruleset(uint64_t fs, uint64_t net) {
    struct ruleset_attr a = {fs, net};
    int rs = create(&a, sizeof a, 0);
    CHECK(rs >= 0);
    return rs;
}

static void allow(int rs, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    CHECK(fd >= 0);
    struct path_beneath pb = {access, fd};
    CHECK(add(rs, RULE_PATH_BENEATH, &pb, 0) == 0);
    close(fd);
}

static void allow_port(int rs, uint64_t port, uint64_t access) {
    struct net_port np = {access, port};
    CHECK(add(rs, RULE_NET_PORT, &np, 0) == 0);
}

// renameat2, which this musl doesn't wrap.
#define RENAME_NOREPLACE 1
#define RENAME_EXCHANGE 2
static int renameat2(int od, const char *o, int nd, const char *n, unsigned flags) {
    return syscall(SYS_renameat2, od, o, nd, n, flags);
}

static void enforce(int rs) {
    CHECK(restrict_self(rs, 0) == 0);
    close(rs);
}

static void put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    close(fd);
}

static int can_open(const char *path, int flags) {
    int fd = open(path, flags | O_CLOEXEC, 0644);
    if (fd < 0) return -errno;
    close(fd);
    return 0;
}

// Run `f` in a child with no_new_privs (the sandbox's user isn't root);
// it must exit 0.
static void in_child(const char *what, void (*f)(void)) {
    fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        f();
        fflush(stdout);
        _exit(0);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("FAILED: %s (status %#x)\n", what, status);
        exit(1);
    }
}

static void mkdirs(const char *path) {
    char buf[256];
    snprintf(buf, sizeof buf, "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(buf, 0755);
            *p = '/';
        }
    }
    mkdir(buf, 0755);
}

static void version_and_errors(void) {
    CHECK(create(NULL, 0, VERSION) == 5);
    struct ruleset_attr a = {READ_FILE, 0};
    FAILS(create(&a, 0, VERSION), EINVAL);
    FAILS(create(NULL, 8, VERSION), EINVAL);
    FAILS(create(NULL, 0, 2), EINVAL); // ERRATA: ABI 7
    FAILS(create(&a, sizeof a, 4), EINVAL);
    FAILS(create(NULL, sizeof a, 0), EFAULT);
    FAILS(create(&a, 4, 0), EINVAL);
    a.fs = 1ULL << 16; // RESOLVE_UNIX, not in ABI 5
    FAILS(create(&a, sizeof a, 0), EINVAL);
    a = (struct ruleset_attr){0, 1ULL << 2}; // BIND_UDP
    FAILS(create(&a, sizeof a, 0), EINVAL);
    a = (struct ruleset_attr){0, 0};
    FAILS(create(&a, sizeof a, 0), ENOMSG);
    // ABI 6's `scoped`: zero is fine, anything else isn't known.
    uint64_t three[3] = {READ_FILE, 0, 0};
    int rs = create(three, sizeof three, 0);
    CHECK(rs >= 0);
    close(rs);
    three[2] = 1;
    FAILS(create(three, sizeof three, 0), E2BIG);
    // Only the handled_access_fs field.
    uint64_t one = READ_FILE;
    rs = create(&one, sizeof one, 0);
    CHECK(rs >= 0);
    close(rs);

    rs = ruleset(READ_FILE | READ_DIR | MAKE_DIR, CONNECT_TCP);
    // The descriptor: close-on-exec, anonymous, neither read nor written.
    CHECK(fcntl(rs, F_GETFD) == FD_CLOEXEC);
    char link[64], buf[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", rs);
    ssize_t n = readlink(link, buf, sizeof buf - 1);
    CHECK(n > 0);
    buf[n] = 0;
    CHECK(strcmp(buf, "anon_inode:[landlock-ruleset]") == 0);
    FAILS(read(rs, buf, 1), EINVAL);
    FAILS(write(rs, buf, 1), EINVAL);

    int dir = open("/tmp", O_PATH);
    CHECK(dir >= 0);
    struct path_beneath pb = {READ_FILE, dir};
    FAILS(add(rs, RULE_PATH_BENEATH, &pb, 1), EINVAL);
    FAILS(add(rs, 3, &pb, 0), EINVAL);
    // Not a ruleset; and an O_PATH descriptor isn't one to look at (fdget).
    int other = open("/tmp", O_RDONLY | O_DIRECTORY);
    FAILS(add(other, RULE_PATH_BENEATH, &pb, 0), EBADFD);
    close(other);
    FAILS(add(dir, RULE_PATH_BENEATH, &pb, 0), EBADF);
    FAILS(add(-1, RULE_PATH_BENEATH, &pb, 0), EBADF);
    FAILS(add(rs, RULE_PATH_BENEATH, NULL, 0), EFAULT);
    pb.allowed = 0;
    FAILS(add(rs, RULE_PATH_BENEATH, &pb, 0), ENOMSG);
    pb.allowed = WRITE_FILE; // not handled
    FAILS(add(rs, RULE_PATH_BENEATH, &pb, 0), EINVAL);
    pb = (struct path_beneath){READ_FILE, -1};
    FAILS(add(rs, RULE_PATH_BENEATH, &pb, 0), EBADF);
    int pipes[2];
    CHECK(pipe(pipes) == 0);
    pb.fd = pipes[0];
    FAILS(add(rs, RULE_PATH_BENEATH, &pb, 0), EBADFD);
    pb.fd = rs;
    FAILS(add(rs, RULE_PATH_BENEATH, &pb, 0), EBADFD);
    // A file's rule grants only what a file can be done.
    put("/tmp/ll-file", "x");
    pb.fd = open("/tmp/ll-file", O_PATH);
    pb.allowed = READ_DIR;
    FAILS(add(rs, RULE_PATH_BENEATH, &pb, 0), EINVAL);
    pb.allowed = READ_FILE;
    CHECK(add(rs, RULE_PATH_BENEATH, &pb, 0) == 0);
    struct net_port np = {CONNECT_TCP, 65536};
    FAILS(add(rs, RULE_NET_PORT, &np, 0), EINVAL);
    np = (struct net_port){BIND_TCP, 80};
    FAILS(add(rs, RULE_NET_PORT, &np, 0), EINVAL);
    np = (struct net_port){0, 80};
    FAILS(add(rs, RULE_NET_PORT, &np, 0), ENOMSG);
    np.allowed = CONNECT_TCP;
    CHECK(add(rs, RULE_NET_PORT, &np, 0) == 0);
    int fsonly = ruleset(READ_FILE, 0);
    FAILS(add(fsonly, RULE_NET_PORT, &np, 0), EINVAL);

    FAILS(restrict_self(rs, 1), EINVAL);
    // Privileges come before the descriptor (and here before no_new_privs).
    FAILS(restrict_self(dir, 0), EPERM);
    close(dir);
    close(rs);
    close(fsonly);
    close(pipes[0]);
    close(pipes[1]);
}

static void restrict_errors(void) {
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    FAILS(restrict_self(fd, 0), EBADFD);
    close(fd);
    fd = open("/tmp", O_PATH);
    FAILS(restrict_self(fd, 0), EBADF);
    FAILS(restrict_self(-1, 0), EBADF);
    close(fd);
}

// Read-only /usr and /etc, read-write /tmp.
static void basic(void) {
    int before = open("/srv/ll/secret", O_RDONLY);
    CHECK(before >= 0);
    int rs = ruleset(FS_ALL, 0);
    allow(rs, "/usr", READ_FILE | READ_DIR | EXECUTE);
    allow(rs, "/etc", READ_FILE | READ_DIR);
    allow(rs, "/tmp", FS_ALL);
    enforce(rs);

    char buf[32] = {0};
    int fd = open("/usr/lib/ll/data", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(read(fd, buf, sizeof buf) == 8 && memcmp(buf, "usr data", 8) == 0);
    close(fd);
    CHECK(can_open("/etc/hosts", O_RDONLY) == 0);
    CHECK(can_open("/usr/lib", O_RDONLY | O_DIRECTORY) == 0);
    DIR *d = opendir("/usr/lib/ll");
    CHECK(d != NULL);
    closedir(d);
    CHECK(can_open("/usr/lib/ll/data", O_WRONLY) == -EACCES);
    CHECK(can_open("/usr/lib/ll/data", O_RDWR) == -EACCES);
    CHECK(can_open("/etc/hosts", O_WRONLY | O_APPEND) == -EACCES);
    // Outside the rules: nothing handled is allowed.
    CHECK(can_open("/srv/ll/secret", O_RDONLY) == -EACCES);
    CHECK(can_open("/srv", O_RDONLY | O_DIRECTORY) == -EACCES);
    CHECK(can_open("/", O_RDONLY | O_DIRECTORY) == -EACCES);
    CHECK(opendir("/srv/ll") == NULL && errno == EACCES);
    // /proc and /dev are filesystems like any other.
    CHECK(can_open("/proc/self/status", O_RDONLY) == -EACCES);
    CHECK(can_open("/dev/null", O_WRONLY) == -EACCES);
    // What Landlock doesn't handle: looking, O_PATH, and descriptors
    // opened before.
    struct stat st;
    CHECK(stat("/srv/ll/secret", &st) == 0);
    CHECK(access("/srv/ll/secret", R_OK) == 0);
    fd = open("/srv/ll/secret", O_PATH);
    CHECK(fd >= 0);
    close(fd);
    CHECK(read(before, buf, sizeof buf) == 6);
    close(before);
    CHECK(chdir("/srv") == 0);
    CHECK(can_open("ll/secret", O_RDONLY) == -EACCES);
    CHECK(chdir("/tmp") == 0);

    // Making and removing.
    FAILS(mkdir("/usr/x", 0755), EACCES);
    FAILS(mkdir("/usr/lib", 0755), EEXIST);
    CHECK(can_open("/usr/new", O_WRONLY | O_CREAT) == -EACCES);
    CHECK(can_open("/usr/lib/ll/data", O_RDONLY | O_CREAT) == 0); // there: just an open
    mkdirs("/tmp/ll");
    put("/tmp/ll/new", "fresh");
    fd = open("/tmp/ll/new", O_RDONLY);
    CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 5);
    close(fd);
    CHECK(mkdir("/tmp/ll/d", 0755) == 0);
    CHECK(rmdir("/tmp/ll/d") == 0);
    CHECK(symlink("new", "/tmp/ll/sym") == 0);
    FAILS(symlink("x", "/usr/sym"), EACCES);
    FAILS(symlink("x", "/srv/ll/sym"), EACCES);
    CHECK(mkfifo("/tmp/ll/fifo", 0644) == 0);
    FAILS(mkfifo("/srv/ll/fifo", 0644), EACCES);
    FAILS(mknod("/usr/reg", S_IFREG | 0644, 0), EACCES);
    CHECK(unlink("/tmp/ll/sym") == 0);
    CHECK(unlink("/tmp/ll/fifo") == 0);
    CHECK(unlink("/tmp/ll/new") == 0);
    FAILS(unlink("/usr/lib/ll/data"), EACCES);
    FAILS(unlink("/usr/lib/ll/none"), ENOENT);
    FAILS(rmdir("/usr/lib/ll"), EACCES);
    FAILS(unlink("/srv/ll/secret"), EACCES);
    // A socket's name is a node made in its directory.
    struct sockaddr_un un = {AF_UNIX, "/tmp/ll/sock"};
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(s >= 0 && bind(s, (struct sockaddr *)&un, sizeof un) == 0);
    close(s);
    strcpy(un.sun_path, "/srv/ll/sock");
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(s >= 0);
    FAILS(bind(s, (struct sockaddr *)&un, sizeof un), EACCES);
    close(s);
    // O_TMPFILE: a file opened in its directory.
    fd = open("/tmp/ll", O_TMPFILE | O_RDWR, 0600);
    CHECK(fd >= 0);
    close(fd);
    FAILS(open("/srv/ll", O_TMPFILE | O_RDWR, 0600), EACCES);
    // execve needs EXECUTE (and READ_FILE) on the program: /bin has none.
    char *argv[] = {"/bin/landlock", "refused", NULL};
    FAILS(execv("/bin/landlock", argv), EACCES);
}

// Truncating: by path, with O_TRUNC, and with ftruncate (as allowed when
// the file was opened).
static void truncation(void) {
    mkdirs("/tmp/tr/a");
    mkdirs("/tmp/tr/b");
    put("/tmp/tr/a/f", "hello");
    put("/tmp/tr/b/f", "hello");
    int old = open("/tmp/tr/b/f", O_RDWR);
    CHECK(old >= 0);
    int rs = ruleset(READ_FILE | WRITE_FILE | TRUNCATE, 0);
    allow(rs, "/tmp/tr/a", READ_FILE | WRITE_FILE | TRUNCATE);
    allow(rs, "/tmp/tr/b", READ_FILE | WRITE_FILE);
    enforce(rs);
    CHECK(truncate("/tmp/tr/a/f", 1) == 0);
    FAILS(truncate("/tmp/tr/b/f", 1), EACCES);
    CHECK(can_open("/tmp/tr/b/f", O_WRONLY | O_TRUNC) == -EACCES);
    CHECK(can_open("/tmp/tr/a/f", O_WRONLY | O_TRUNC) == 0);
    int fd = open("/tmp/tr/b/f", O_WRONLY);
    CHECK(fd >= 0);
    FAILS(ftruncate(fd, 0), EACCES);
    CHECK(write(fd, "J", 1) == 1);
    close(fd);
    fd = open("/tmp/tr/a/f", O_WRONLY);
    CHECK(fd >= 0 && ftruncate(fd, 3) == 0);
    close(fd);
    // A new file isn't truncated: O_CREAT|O_TRUNC makes it.
    CHECK(can_open("/tmp/tr/b/g", O_WRONLY | O_CREAT | O_TRUNC) == 0);
    // Opened before: as allowed then.
    CHECK(ftruncate(old, 2) == 0);
    close(old);
}

// Rename and link: REFER both sides, and nothing gained by moving.
static void refer(void) {
    const char *dirs[] = {"/tmp/r/s1", "/tmp/r/s2", "/tmp/r/s3", "/tmp/r/s4", "/tmp/r/out"};
    for (int i = 0; i < 5; i++) mkdirs(dirs[i]);
    const char *files[] = {"/tmp/r/s1/a", "/tmp/r/s1/x", "/tmp/r/s1/z", "/tmp/r/s1/f", "/tmp/r/s1/e1",
                           "/tmp/r/s2/e2", "/tmp/r/s3/c", "/tmp/r/s4/y", "/tmp/r/s4/e4"};
    for (int i = 0; i < 9; i++) put(files[i], "r");
    uint64_t moves = MAKE_REG | REMOVE_FILE;
    int rs = ruleset(moves | REFER | READ_FILE, 0);
    allow(rs, "/tmp/r/s1", moves | REFER);
    allow(rs, "/tmp/r/s2", moves | REFER);
    allow(rs, "/tmp/r/s3", moves);
    allow(rs, "/tmp/r/s4", moves | REFER | READ_FILE);
    enforce(rs);
    // In one directory, REFER isn't needed.
    CHECK(rename("/tmp/r/s1/a", "/tmp/r/s1/b") == 0);
    CHECK(rename("/tmp/r/s3/c", "/tmp/r/s3/d") == 0);
    // Between directories with the same rights.
    CHECK(rename("/tmp/r/s1/b", "/tmp/r/s2/b") == 0);
    // Without REFER on one side: EXDEV, as a filesystem that can't.
    FAILS(rename("/tmp/r/s2/b", "/tmp/r/s3/b"), EXDEV);
    FAILS(rename("/tmp/r/s3/d", "/tmp/r/s1/d"), EXDEV);
    // Gaining READ_FILE by the move: EXDEV; losing it is fine.
    FAILS(rename("/tmp/r/s1/x", "/tmp/r/s4/x"), EXDEV);
    CHECK(rename("/tmp/r/s4/y", "/tmp/r/s1/y") == 0);
    // Where it may not be made: EACCES, before EXDEV.
    FAILS(rename("/tmp/r/s1/z", "/tmp/r/out/z"), EACCES);
    FAILS(rename("/tmp/r/s3/d", "/tmp/r/out/d"), EACCES);
    // Replacing a file removes it.
    CHECK(rename("/tmp/r/s2/b", "/tmp/r/s1/y") == 0);
    // Links.
    CHECK(link("/tmp/r/s1/f", "/tmp/r/s1/f2") == 0);
    CHECK(link("/tmp/r/s1/f", "/tmp/r/s2/f3") == 0);
    FAILS(link("/tmp/r/s1/f", "/tmp/r/s3/f4"), EXDEV);
    FAILS(link("/tmp/r/s1/f", "/tmp/r/out/f5"), EACCES);
    FAILS(link("/tmp/r/s1/f", "/tmp/r/s1/f2"), EEXIST);
    // Exchanges check both ways.
    CHECK(renameat2(AT_FDCWD, "/tmp/r/s1/e1", AT_FDCWD, "/tmp/r/s2/e2", RENAME_EXCHANGE) == 0);
    FAILS(renameat2(AT_FDCWD, "/tmp/r/s1/e1", AT_FDCWD, "/tmp/r/s4/e4", RENAME_EXCHANGE), EXDEV);
    FAILS(renameat2(AT_FDCWD, "/tmp/r/s1/e1", AT_FDCWD, "/tmp/r/s2/none", RENAME_EXCHANGE), ENOENT);
    FAILS(renameat2(AT_FDCWD, "/tmp/r/s1/f", AT_FDCWD, "/tmp/r/s1/f2", RENAME_NOREPLACE), EEXIST);
}

// REFER is denied unless granted, whether handled or not; a layer with
// no filesystem rights doesn't count.
static void refer_by_default(void) {
    mkdirs("/tmp/rd/a");
    mkdirs("/tmp/rd/b");
    put("/tmp/rd/a/f", "1");
    put("/tmp/rd/a/g", "2");
    int rs = ruleset(0, BIND_TCP);
    enforce(rs);
    CHECK(rename("/tmp/rd/a/g", "/tmp/rd/b/g") == 0);
    rs = ruleset(MAKE_REG | REMOVE_FILE, 0);
    allow(rs, "/tmp/rd", MAKE_REG | REMOVE_FILE);
    enforce(rs);
    FAILS(rename("/tmp/rd/a/f", "/tmp/rd/b/f"), EXDEV);
    CHECK(rename("/tmp/rd/a/f", "/tmp/rd/a/h") == 0);
}

// Two layers: each must allow; one that doesn't handle a right doesn't
// restrict it. At most 16.
static void stacking(void) {
    mkdirs("/tmp/st/a");
    mkdirs("/tmp/st/b");
    put("/tmp/st/b/f", "b");
    int rs = ruleset(READ_FILE | WRITE_FILE | MAKE_REG, 0);
    allow(rs, "/tmp/st", READ_FILE | WRITE_FILE | MAKE_REG);
    enforce(rs);
    rs = ruleset(WRITE_FILE | MAKE_REG, 0);
    allow(rs, "/tmp/st/a", WRITE_FILE | MAKE_REG);
    enforce(rs);
    CHECK(can_open("/tmp/st/a/f", O_WRONLY | O_CREAT) == 0);
    CHECK(can_open("/tmp/st/b/f", O_WRONLY) == -EACCES);
    CHECK(can_open("/tmp/st/b/g", O_WRONLY | O_CREAT) == -EACCES);
    CHECK(can_open("/tmp/st/b/f", O_RDONLY) == 0);
    CHECK(can_open("/usr/lib/ll/data", O_RDONLY) == -EACCES);
    for (int layer = 3; layer <= 16; layer++) {
        rs = ruleset(EXECUTE, 0);
        allow(rs, "/", EXECUTE);
        enforce(rs);
    }
    rs = ruleset(EXECUTE, 0);
    FAILS(restrict_self(rs, 0), E2BIG);
    CHECK(can_open("/tmp/st/a/f", O_WRONLY) == 0);
}

static void *open_secret(void *arg) {
    (void)arg;
    return (void *)(intptr_t)can_open("/srv/ll/secret", O_RDONLY);
}

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static void *waits_then_opens(void *arg) {
    (void)arg;
    pthread_mutex_lock(&gate);
    pthread_mutex_unlock(&gate);
    return open_secret(NULL);
}

// Children, threads and new programs keep the domain; threads that were
// already there have their own.
static void inheritance(char *self) {
    pthread_mutex_lock(&gate);
    pthread_t before;
    CHECK(pthread_create(&before, NULL, waits_then_opens, NULL) == 0);
    int rs = ruleset(FS_ALL, 0);
    allow(rs, "/bin", READ_FILE | EXECUTE);
    allow(rs, "/tmp", FS_ALL);
    enforce(rs);
    pthread_mutex_unlock(&gate);
    void *r;
    CHECK(pthread_join(before, &r) == 0 && r == 0);
    pthread_t after;
    CHECK(pthread_create(&after, NULL, open_secret, NULL) == 0);
    CHECK(pthread_join(after, &r) == 0 && (intptr_t)r == -EACCES);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(can_open("/srv/ll/secret", O_RDONLY) == -EACCES ? 0 : 1);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char *argv[] = {self, "after-exec", NULL};
    execv(self, argv);
    CHECK(!"execv");
}

static void after_exec(void) {
    CHECK(can_open("/srv/ll/secret", O_RDONLY) == -EACCES);
    CHECK(can_open("/tmp/ll-exec", O_WRONLY | O_CREAT) == 0);
    // The program's own directory has no READ_DIR.
    CHECK(can_open("/bin", O_RDONLY | O_DIRECTORY) == -EACCES);
    fflush(stdout);
    _exit(0);
}

// A file with several names is under the directory it was reached
// through, whichever name came first, and whichever is left.
static void hardlinks(void) {
    mkdirs("/tmp/hl/rw");
    mkdirs("/tmp/hl/ro");
    mkdirs("/tmp/hl/gone");
    put("/tmp/hl/rw/f", "1");
    CHECK(link("/tmp/hl/rw/f", "/tmp/hl/ro/f") == 0);
    put("/tmp/hl/ro/g", "2");
    CHECK(link("/tmp/hl/ro/g", "/tmp/hl/rw/g") == 0);
    put("/tmp/hl/gone/h", "3");
    CHECK(link("/tmp/hl/gone/h", "/tmp/hl/rw/h") == 0);
    CHECK(unlink("/tmp/hl/gone/h") == 0);
    CHECK(rmdir("/tmp/hl/gone") == 0);
    mkdirs("/tmp/hl/new-in-its-slot");
    int rs = ruleset(READ_FILE | WRITE_FILE | TRUNCATE, 0);
    allow(rs, "/tmp/hl/rw", READ_FILE | WRITE_FILE | TRUNCATE);
    allow(rs, "/tmp/hl/ro", READ_FILE);
    enforce(rs);
    CHECK(can_open("/tmp/hl/rw/f", O_WRONLY) == 0);
    CHECK(can_open("/tmp/hl/ro/f", O_WRONLY) == -EACCES);
    CHECK(can_open("/tmp/hl/ro/f", O_RDONLY) == 0);
    CHECK(can_open("/tmp/hl/rw/g", O_WRONLY) == 0);
    CHECK(can_open("/tmp/hl/ro/g", O_WRONLY) == -EACCES);
    CHECK(truncate("/tmp/hl/rw/g", 0) == 0);
    FAILS(truncate("/tmp/hl/ro/g", 0), EACCES);
    CHECK(can_open("/tmp/hl/rw/h", O_WRONLY) == 0);
}

// A process in a domain can't look into one outside it, as a tracer; a
// child in the same domain it can.
static void inspection(void) {
    pid_t outside = getppid();
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/environ", outside);
    CHECK(can_open(path, O_RDONLY) == 0);
    int rs = ruleset(READ_FILE | READ_DIR, 0);
    allow(rs, "/proc", READ_FILE | READ_DIR);
    enforce(rs);
    CHECK(can_open(path, O_RDONLY) == -EACCES);
    CHECK(can_open("/proc/self/environ", O_RDONLY) == 0);
    int up[2], down[2];
    CHECK(pipe(up) == 0 && pipe(down) == 0);
    pid_t c = fork();
    CHECK(c >= 0);
    if (c == 0) {
        char b;
        CHECK(write(up[1], "r", 1) == 1);
        read(down[0], &b, 1);
        _exit(0);
    }
    char b;
    CHECK(read(up[0], &b, 1) == 1);
    snprintf(path, sizeof path, "/proc/%d/environ", c);
    CHECK(can_open(path, O_RDONLY) == 0);
    CHECK(write(down[1], "g", 1) == 1);
    int status;
    CHECK(waitpid(c, &status, 0) == c && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// Without no_new_privs only root may restrict itself.
static void privileges(void) {
    CHECK(getuid() != 0);
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
    int rs = ruleset(READ_FILE, 0);
    FAILS(restrict_self(rs, 0), EPERM);
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(restrict_self(rs, 0) == 0);
    CHECK(can_open("/usr/lib/ll/data", O_RDONLY) == -EACCES);
}

static int tcp(int family) {
    int s = socket(family, SOCK_STREAM, 0);
    CHECK(s >= 0);
    return s;
}

static struct sockaddr_in v4(int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

// TCP bind and connect by port; UDP and AF_UNIX aren't TCP.
static void network(void) {
    int rs = ruleset(0, BIND_TCP | CONNECT_TCP);
    allow_port(rs, 8080, BIND_TCP | CONNECT_TCP);
    allow_port(rs, 8081, BIND_TCP);
    enforce(rs);
    struct sockaddr_in a = v4(8080);
    int l = tcp(AF_INET);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 4) == 0);
    int c = tcp(AF_INET);
    CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    int s = accept(l, NULL, NULL);
    CHECK(s >= 0);
    close(s);
    close(c);
    a = v4(8081);
    int l2 = tcp(AF_INET);
    CHECK(bind(l2, (struct sockaddr *)&a, sizeof a) == 0 && listen(l2, 4) == 0);
    c = tcp(AF_INET);
    FAILS(connect(c, (struct sockaddr *)&a, sizeof a), EACCES);
    close(c);
    a = v4(8090);
    s = tcp(AF_INET);
    FAILS(bind(s, (struct sockaddr *)&a, sizeof a), EACCES);
    a = v4(0); // the kernel's choice is port 0's rule
    FAILS(bind(s, (struct sockaddr *)&a, sizeof a), EACCES);
    // An address of the other family: EINVAL, as Linux's check.
    struct sockaddr_in6 six = {.sin6_family = AF_INET6, .sin6_port = htons(8080), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    FAILS(bind(s, (struct sockaddr *)&six, sizeof six), EINVAL);
    close(s);
    s = tcp(AF_INET6);
    six.sin6_port = htons(8090);
    FAILS(bind(s, (struct sockaddr *)&six, sizeof six), EACCES);
    six.sin6_port = htons(8081);
    FAILS(connect(s, (struct sockaddr *)&six, sizeof six), EACCES);
    close(s);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    a = v4(8090);
    CHECK(s >= 0 && bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    close(s);
    close(l);
    close(l2);
}

// Devices opened without IOCTL_DEV: only the descriptor's own ioctls.
static void ioctls(void) {
    int rs = ruleset(READ_FILE | WRITE_FILE | IOCTL_DEV, 0);
    allow(rs, "/dev", READ_FILE | WRITE_FILE);
    allow(rs, "/dev/ptmx", IOCTL_DEV);
    enforce(rs);
    int fd = open("/dev/null", O_RDWR);
    CHECK(fd >= 0);
    int n;
    FAILS(ioctl(fd, FIONREAD, &n), EACCES);
    CHECK(ioctl(fd, FIOCLEX) == 0);
    CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC);
    close(fd);
    fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    CHECK(fd >= 0);
    unsigned pty;
    CHECK(ioctl(fd, TIOCGPTN, &pty) == 0);
    int unlock = 0;
    CHECK(ioctl(fd, TIOCSPTLCK, &unlock) == 0);
    char name[32];
    snprintf(name, sizeof name, "/dev/pts/%u", pty);
    int pts = open(name, O_RDWR | O_NOCTTY);
    CHECK(pts >= 0);
    char t[64];
    FAILS(ioctl(pts, TCGETS, t), EACCES);
    // stdout was opened before: not restricted (and not a terminal).
    errno = 0;
    CHECK(ioctl(1, TCGETS, t) == -1 && errno == ENOTTY);
    close(pts);
    close(fd);
}

// A live mount (/live) and a lazy import (/lazy): rules on their nodes,
// a lazy import's file copied up by the write, and directories the
// kernel lists again.
static void mounts(void) {
    int rs = ruleset(READ_FILE | WRITE_FILE | MAKE_REG | READ_DIR, 0);
    allow(rs, "/live/open", READ_FILE | WRITE_FILE | MAKE_REG | READ_DIR);
    allow(rs, "/lazy/open", READ_FILE | WRITE_FILE | MAKE_REG | READ_DIR);
    enforce(rs);
    const char *roots[] = {"/live", "/lazy"};
    for (int i = 0; i < 2; i++) {
        char p[64];
        snprintf(p, sizeof p, "%s/open/f", roots[i]);
        int fd = open(p, O_WRONLY | O_APPEND);
        CHECK(fd >= 0 && write(fd, "+", 1) == 1);
        close(fd);
        snprintf(p, sizeof p, "%s/open/new", roots[i]);
        CHECK(can_open(p, O_WRONLY | O_CREAT) == 0);
        snprintf(p, sizeof p, "%s/open", roots[i]);
        DIR *d = opendir(p);
        CHECK(d != NULL);
        int n = 0;
        while (readdir(d)) n++;
        closedir(d);
        CHECK(n == 4); // ., .., f, new
        snprintf(p, sizeof p, "%s/shut/f", roots[i]);
        CHECK(can_open(p, O_RDONLY) == -EACCES);
        snprintf(p, sizeof p, "%s/shut/new", roots[i]);
        CHECK(can_open(p, O_WRONLY | O_CREAT) == -EACCES);
        CHECK(can_open(roots[i], O_RDONLY | O_DIRECTORY) == -EACCES);
    }
}

static void expect_text(const char *path, const char *text) {
    char buf[16] = {0};
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    CHECK(read(fd, buf, sizeof buf - 1) == (ssize_t)strlen(text));
    close(fd);
    CHECK(strcmp(buf, text) == 0);
}

// Links and exchanges on a live mount and a lazy import, in <root>/m:
// a and b alike, c without READ_FILE, d without REFER, out with no rule.
// An exchange is checked both ways. Then what fails before Landlock has
// a say: a move across mounts (EXDEV) and a read-only mount (EROFS).
static void mount_moves(void) {
    const char *roots[] = {"/live/m", "/lazy/m"};
    uint64_t moves = MAKE_REG | REMOVE_FILE;
    int rs = ruleset(moves | REFER | READ_FILE | MAKE_DIR | REMOVE_DIR, 0);
    for (int i = 0; i < 2; i++) {
        char p[64];
        snprintf(p, sizeof p, "%s/a", roots[i]);
        allow(rs, p, moves | REFER | READ_FILE);
        snprintf(p, sizeof p, "%s/b", roots[i]);
        allow(rs, p, moves | REFER | READ_FILE);
        snprintf(p, sizeof p, "%s/c", roots[i]);
        allow(rs, p, moves | REFER);
        snprintf(p, sizeof p, "%s/d", roots[i]);
        allow(rs, p, moves | READ_FILE);
    }
    enforce(rs);
    for (int i = 0; i < 2; i++) {
#define AT(var, name)                                                  \
    char var[64];                                                      \
    snprintf(var, sizeof var, "%s/" name, roots[i])
        AT(f, "a/f");
        AT(x, "a/x");
        AT(p, "a/p");
        AT(y, "b/y");
        AT(sub, "b/sub");
        AT(g, "c/g");
        AT(z, "c/z");
        AT(w, "d/w");
        AT(v, "out/v");
        AT(f1, "a/f1");
        AT(f2, "b/f2");
        AT(f3, "c/f3");
        AT(g2, "a/g2");
        AT(f4, "d/f4");
        AT(f5, "out/f5");
        AT(none, "b/none");
        // Links: making the name, and REFER between directories.
        CHECK(link(f, f1) == 0);
        CHECK(link(f, f2) == 0);
        CHECK(link(f, f3) == 0);
        FAILS(link(g, g2), EXDEV);
        FAILS(link(f, f4), EXDEV);
        FAILS(link(f, f5), EACCES);
        FAILS(link(f, f2), EEXIST);
        expect_text(f2, "f");
        CHECK(can_open(f3, O_RDONLY) == -EACCES);
        // Exchanges, both ways.
        CHECK(renameat2(AT_FDCWD, x, AT_FDCWD, y, RENAME_EXCHANGE) == 0);
        expect_text(x, "y");
        expect_text(y, "x");
        FAILS(renameat2(AT_FDCWD, x, AT_FDCWD, z, RENAME_EXCHANGE), EXDEV);
        FAILS(renameat2(AT_FDCWD, z, AT_FDCWD, x, RENAME_EXCHANGE), EXDEV);
        FAILS(renameat2(AT_FDCWD, x, AT_FDCWD, w, RENAME_EXCHANGE), EXDEV);
        FAILS(renameat2(AT_FDCWD, w, AT_FDCWD, x, RENAME_EXCHANGE), EXDEV);
        FAILS(renameat2(AT_FDCWD, x, AT_FDCWD, v, RENAME_EXCHANGE), EACCES);
        FAILS(renameat2(AT_FDCWD, v, AT_FDCWD, x, RENAME_EXCHANGE), EACCES);
        FAILS(renameat2(AT_FDCWD, x, AT_FDCWD, sub, RENAME_EXCHANGE), EACCES); // no MAKE_DIR in a
        FAILS(renameat2(AT_FDCWD, x, AT_FDCWD, none, RENAME_EXCHANGE), ENOENT);
        // In one directory: no REFER, but each kind is made there.
        CHECK(renameat2(AT_FDCWD, x, AT_FDCWD, p, RENAME_EXCHANGE) == 0);
        expect_text(p, "y");
        expect_text(x, "p");
    }
    // Across mounts: EXDEV before any rule is looked at.
    FAILS(rename("/live/m/a/f", "/tmp/elsewhere"), EXDEV);
    FAILS(link("/live/m/a/f", "/tmp/elsewhere"), EXDEV);
    FAILS(rename("/lazy/m/a/f", "/live/m/a/moved"), EXDEV);
    // A read-only mount: EROFS before any rule is looked at.
    FAILS(mkdir("/ro/new", 0755), EROFS);
    FAILS(link("/ro/f", "/ro/g"), EROFS);
    FAILS(rename("/ro/f", "/ro/g"), EROFS);
    FAILS(unlink("/ro/f"), EROFS);
    FAILS(symlink("f", "/ro/l"), EROFS);
    FAILS(truncate("/ro/f", 0), EROFS);
    FAILS(mkfifo("/ro/p", 0644), EROFS);
    CHECK(can_open("/ro/f", O_WRONLY) == -EROFS);
    CHECK(can_open("/ro/g", O_WRONLY | O_CREAT) == -EROFS);
}

// A live mount bigger than the kernel keeps: listing /live/big makes it
// forget directories nothing uses, but not those rules hold (or what's
// above them); what it forgets under them and lists again is still
// under their rules.
static void eviction(void) {
    int rs = ruleset(READ_FILE | WRITE_FILE | MAKE_REG | READ_DIR, 0);
    allow(rs, "/live/keep/open", READ_FILE | WRITE_FILE | MAKE_REG | READ_DIR);
    allow(rs, "/live/big", READ_DIR);
    enforce(rs);
    CHECK(can_open("/live/keep/open/sub/x", O_RDONLY) == 0);
    long entries = 0;
    for (int pass = 0; pass < 2; pass++) {
        DIR *big = opendir("/live/big");
        CHECK(big != NULL);
        struct dirent *e;
        while ((e = readdir(big))) {
            if (e->d_name[0] == '.') continue;
            char p[300];
            snprintf(p, sizeof p, "/live/big/%s", e->d_name);
            DIR *d = opendir(p);
            CHECK(d != NULL);
            while (readdir(d)) entries++;
            closedir(d);
        }
        closedir(big);
        CHECK(can_open("/live/keep/open/sub/x", O_RDONLY) == 0);
        CHECK(can_open("/live/keep/open/f", O_WRONLY | O_APPEND) == 0);
        CHECK(can_open("/live/keep/open/sub/new", O_WRONLY | O_CREAT) == 0);
        CHECK(can_open("/live/keep/shut/f", O_RDONLY) == -EACCES);
        CHECK(can_open("/live/big/d0/f0", O_RDONLY) == -EACCES);
    }
    printf("%ld entries\n", entries);
}

// Without fs_write the policy refuses first (EPERM, reported), whatever
// the program's own rules would say.
static void policy(void) {
    int rs = ruleset(MAKE_DIR | READ_FILE, 0);
    enforce(rs);
    FAILS(syscall(SYS_mkdirat, AT_FDCWD, "/tmp/denied", 0755), EPERM);
    CHECK(can_open("/bin/landlock", O_RDONLY) == -EACCES);
}

// Run a program under rules: everything readable and executable, and
// the directories after `--` writable.
static int wrap(char **argv) {
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    int rs = ruleset(FS_ALL, 0);
    allow(rs, "/", EXECUTE | READ_FILE | READ_DIR);
    for (; *argv && strcmp(*argv, "--"); argv++) allow(rs, *argv, FS_ALL);
    CHECK(*argv != NULL);
    enforce(rs);
    execvp(argv[1], argv + 1);
    CHECK(!"execvp");
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "after-exec")) after_exec();
    // What a refused execve would have run: it ends as no success.
    if (argc > 1 && !strcmp(argv[1], "refused")) {
        printf("FAILED: ran what it may not\n");
        return 9;
    }
    if (argc > 1 && !strcmp(argv[1], "wrap")) return wrap(argv + 2);
    if (argc > 1 && !strcmp(argv[1], "policy")) {
        in_child("policy", policy);
        printf("landlock policy ok\n");
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "evict")) {
        in_child("eviction", eviction);
        printf("landlock evict ok\n");
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "mounts")) {
        in_child("mounts", mounts);
        in_child("mount_moves", mount_moves);
        printf("landlock mounts ok\n");
        return 0;
    }
    mkdirs("/usr/lib/ll");
    put("/usr/lib/ll/data", "usr data");
    mkdirs("/srv/ll");
    put("/srv/ll/secret", "secret");
    version_and_errors();
    in_child("restrict_errors", restrict_errors);
    in_child("basic", basic);
    in_child("truncation", truncation);
    in_child("refer", refer);
    in_child("refer_by_default", refer_by_default);
    in_child("stacking", stacking);
    in_child("hardlinks", hardlinks);
    in_child("inspection", inspection);
    fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        inheritance(argv[0]);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    fflush(stdout);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        privileges();
        _exit(0);
    }
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    in_child("network", network);
    in_child("ioctls", ioctls);
    printf("landlock ok\n");
    return 0;
}
