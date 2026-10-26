// Try to open a socket. Without the `net` capability this must fail with EPERM.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("socket: %s\n", strerror(errno));
        return errno == EPERM ? 0 : 1;
    }
    printf("socket: opened fd %d\n", s);
    return 2;
}
