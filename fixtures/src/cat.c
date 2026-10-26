// Print files; report errors like coreutils does.
#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    int status = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "r");
        if (!f) {
            fprintf(stderr, "cat: %s: %s\n", argv[i], strerror(errno));
            status = 1;
            continue;
        }
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
        fclose(f);
    }
    return status;
}
