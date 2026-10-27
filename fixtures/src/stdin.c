// stdin from the host: wait with poll, read everything, report the length
// and an FNV-1a hash (so the test can check every byte arrived in order),
// and check end-of-file stays end-of-file.
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    static unsigned char buf[8192];
    uint64_t hash = 0xcbf29ce484222325ull, total = 0;
    int saw_fionread = 0;
    for (;;) {
        struct pollfd p = {.fd = 0, .events = POLLIN};
        if (poll(&p, 1, -1) != 1 || !(p.revents & POLLIN)) {
            printf("poll failed\n");
            return 1;
        }
        int avail = 0;
        if (ioctl(0, FIONREAD, &avail) == 0 && avail > 0) saw_fionread = 1;
        ssize_t n = read(0, buf, sizeof buf);
        if (n < 0) {
            printf("read: errno %d\n", errno);
            return 1;
        }
        if (n == 0) break;
        for (ssize_t i = 0; i < n; i++) hash = (hash ^ buf[i]) * 0x100000001b3ull;
        total += n;
    }
    // End-of-file is sticky, and poll reports it as readable.
    struct pollfd p = {.fd = 0, .events = POLLIN};
    if (read(0, buf, 1) != 0 || poll(&p, 1, 0) != 1) {
        printf("eof not sticky\n");
        return 1;
    }
    printf("bytes=%llu fnv=%016llx fionread=%d\n", (unsigned long long)total, (unsigned long long)hash,
           total ? saw_fionread : 1);
    return 0;
}
