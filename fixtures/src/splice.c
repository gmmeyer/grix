// splice, tee and vmsplice between pipes, files and sockets (Go copies
// between sockets through a pipe this way), with Linux's errnos.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

static char buf[70000];

static int got(int fd, const char *want) {
    int n = read(fd, buf, sizeof buf - 1);
    if (n < 0) return 0;
    buf[n] = 0;
    return !strcmp(buf, want);
}

int main(void) {
    int a[2], b[2];
    CHECK(pipe(a) == 0 && pipe(b) == 0);

    // Pipe to pipe.
    CHECK(write(a[1], "hello", 5) == 5);
    CHECK(splice(a[0], NULL, b[1], NULL, 100, 0) == 5 && got(b[0], "hello"));

    // A file to a pipe, at an offset (the file's own doesn't move) or at
    // the file's offset (which does).
    int f = open("/tmp/splice", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(f >= 0 && write(f, "0123456789", 10) == 10 && lseek(f, 0, SEEK_SET) == 0);
    loff_t off = 2;
    CHECK(splice(f, &off, a[1], NULL, 4, 0) == 4 && off == 6 && got(a[0], "2345"));
    CHECK(lseek(f, 0, SEEK_CUR) == 0);
    CHECK(splice(f, NULL, a[1], NULL, 3, SPLICE_F_MOVE) == 3 && got(a[0], "012") && lseek(f, 0, SEEK_CUR) == 3);
    off = 10;
    CHECK(splice(f, &off, a[1], NULL, 4, 0) == 0); // at its end

    // A pipe to a file.
    CHECK(write(a[1], "ABC", 3) == 3);
    off = 3;
    CHECK(splice(a[0], NULL, f, &off, 3, 0) == 3 && off == 6);
    CHECK(pread(f, buf, 10, 0) == 10 && !memcmp(buf, "012ABC6789", 10));
    int app = open("/tmp/splice", O_WRONLY | O_APPEND);
    CHECK(write(a[1], "Z", 1) == 1);
    CHECK(splice(a[0], NULL, app, &off, 1, 0) == -1 && errno == EINVAL);
    CHECK(splice(a[0], NULL, app, NULL, 1, 0) == 1);
    CHECK(pread(f, buf, 11, 0) == 11 && buf[10] == 'Z');

    // Sockets to and from pipes, as Go's TCPConn.ReadFrom does it.
    int s[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);
    CHECK(write(s[1], "net", 3) == 3);
    CHECK(splice(s[0], NULL, a[1], NULL, 64, 0) == 3);
    CHECK(splice(a[0], NULL, s[0], NULL, 64, 0) == 3 && got(s[1], "net"));
    // TCP over loopback too.
    int l = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in sin = {.sin_family = AF_INET, .sin_port = htons(7071), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    CHECK(bind(l, (void *)&sin, sizeof sin) == 0 && listen(l, 1) == 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(c, (void *)&sin, sizeof sin) == 0);
    int t = accept(l, NULL, NULL);
    CHECK(t >= 0 && write(c, "tcp!", 4) == 4);
    CHECK(splice(t, NULL, a[1], NULL, 64, 0) == 4);
    CHECK(splice(a[0], NULL, t, NULL, 64, 0) == 4 && got(c, "tcp!"));

    // Into a full pipe: nothing is taken from the socket.
    fcntl(b[1], F_SETFL, O_NONBLOCK);
    while (write(b[1], buf, sizeof buf) > 0) {}
    CHECK(write(s[1], "kept", 4) == 4);
    CHECK(splice(s[0], NULL, b[1], NULL, 64, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
    CHECK(got(s[0], "kept"));
    close(b[0]);
    close(b[1]);
    CHECK(pipe(b) == 0);

    // To stdout.
    CHECK(write(a[1], "spliced to stdout\n", 18) == 18);
    fflush(stdout);
    CHECK(splice(a[0], NULL, 1, NULL, 64, 0) == 18);

    // Linux's errnos.
    CHECK(splice(f, NULL, s[0], NULL, 1, 0) == -1 && errno == EINVAL);         // no pipe
    off = 0;
    CHECK(splice(a[0], &off, b[1], NULL, 1, 0) == -1 && errno == ESPIPE);      // offset on a pipe
    CHECK(splice(a[0], NULL, a[1], NULL, 1, 0) == -1 && errno == EINVAL);      // the same pipe
    CHECK(splice(a[0], NULL, b[1], NULL, 1, 0x100) == -1 && errno == EINVAL);  // unknown flag
    CHECK(splice(a[1], NULL, b[1], NULL, 1, 0) == -1 && errno == EBADF);       // can't read it
    CHECK(splice(a[0], NULL, b[1], NULL, 1, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
    CHECK(splice(a[0], NULL, b[1], NULL, 0, 0) == 0);
    int e[2];
    CHECK(pipe(e) == 0);
    close(e[1]);
    CHECK(splice(e[0], NULL, b[1], NULL, 8, 0) == 0); // no writers: end of file

    // tee: copied, and still there.
    CHECK(write(a[1], "dup", 3) == 3);
    CHECK(tee(a[0], b[1], 10, 0) == 3 && got(b[0], "dup") && got(a[0], "dup"));
    CHECK(tee(f, b[1], 10, 0) == -1 && errno == EINVAL);
    CHECK(tee(a[0], b[1], 10, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);

    // A pipe's capacity (ClickHouse asks): bigger up to pipe-max-size,
    // never smaller than what it holds.
    CHECK(fcntl(a[0], F_GETPIPE_SZ) == 65536);
    CHECK(fcntl(a[1], F_SETPIPE_SZ, 100) == 4096 && fcntl(a[0], F_GETPIPE_SZ) == 4096);
    fcntl(a[1], F_SETFL, O_NONBLOCK);
    CHECK(write(a[1], buf, 5000) == 4096);
    CHECK(fcntl(a[1], F_SETPIPE_SZ, 1 << 20) == 1 << 20);
    CHECK(write(a[1], buf, 60000) == 60000 && read(a[0], buf, sizeof buf) == 64096);
    CHECK(fcntl(a[1], F_SETPIPE_SZ, 2 << 20) == -1 && errno == EPERM);
    CHECK(write(a[1], buf, 8192) == 8192);
    CHECK(fcntl(a[1], F_SETPIPE_SZ, 4096) == -1 && errno == EBUSY);
    CHECK(read(a[0], buf, sizeof buf) == 8192);
    CHECK(fcntl(f, F_GETPIPE_SZ) == -1 && errno == EBADF);
    fcntl(a[1], F_SETFL, 0);

    // vmsplice: buffers into a pipe, or out of one.
    struct iovec iov[2] = {{"ab", 2}, {"cd", 2}};
    CHECK(vmsplice(a[1], iov, 2, 0) == 4);
    char x[3] = {0}, y[3] = {0};
    struct iovec out[2] = {{x, 1}, {y, 3}};
    CHECK(vmsplice(a[0], out, 2, 0) == 4 && x[0] == 'a' && !strcmp(y, "bcd"));
    CHECK(vmsplice(f, iov, 2, 0) == -1 && errno == EBADF);
    printf("splice ok\n");
    return 0;
}
