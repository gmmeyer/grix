// Writing to a pipe with no reader kills the program with SIGPIPE by default.
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int p[2];
    pipe(p);
    close(p[0]);
    write(p[1], "x", 1);
    printf("unreachable\n");
    return 0;
}
