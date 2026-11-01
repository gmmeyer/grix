// Try to open a socket. Without the `net` capability this must fail with
// EPERM. With "raw", a raw IP socket of a kind that isn't implemented (ICMP's
// is pingsock's).
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int main(int argc, char **argv) {
    int raw = argc > 1 && strcmp(argv[1], "raw") == 0;
    int s = raw ? socket(AF_INET, SOCK_RAW, IPPROTO_UDP) : socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("socket: %s\n", strerror(errno));
        return errno == EPERM ? 0 : 1;
    }
    printf("socket: opened fd %d\n", s);
    return 2;
}
