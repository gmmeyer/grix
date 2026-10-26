// Try to create a file. Without `fs_write` this must fail with EPERM.
#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "/tmp/out.txt";
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("fopen %s: %s\n", path, strerror(errno));
        return errno == EPERM ? 0 : 1;
    }
    fputs("written\n", f);
    fclose(f);
    printf("wrote %s\n", path);
    return 2;
}
