// Leaves results in /out for the host to export: directories, files with
// their modes and times, an empty file, a big one, a symlink, a hard link,
// and files renamed or removed along the way. With "crash" it then dies of
// SIGSEGV, which must not stop the export. With "deep" it instead nests 40
// directories with 120-byte names (deeper than an export path may go) and
// leaves a 100 GiB sparse file, both more than an export takes.
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void put(const char *path, const char *text, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    write(fd, text, strlen(text));
    close(fd);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "deep") == 0) {
        char name[121];
        memset(name, 'd', 120);
        name[120] = 0;
        chdir("/out");
        put("top.txt", "top\n", 0644);
        for (int i = 0; i < 40; i++) {
            mkdir(name, 0755);
            chdir(name);
        }
        put("bottom.txt", "bottom\n", 0644);
        int fd = open("/out/sparse.img", O_WRONLY | O_CREAT, 0644);
        ftruncate(fd, 100LL << 30);
        close(fd);
        printf("export ok\n");
        return 0;
    }
    mkdir("/out/sub", 0750);
    put("/out/sub/hello.txt", "hello\n", 0640);
    struct timespec times[2] = {{1000000000, 0}, {1000000000, 0}};
    utimensat(AT_FDCWD, "/out/sub/hello.txt", times, 0);
    link("/out/sub/hello.txt", "/out/sub/hard");
    symlink("sub/hello.txt", "/out/link");
    put("/out/empty", "", 0644);
    put("/out/run.sh", "#!/bin/sh\necho hi\n", 0755);
    put("/out/old", "renamed\n", 0644);
    rename("/out/old", "/out/new");
    put("/out/gone", "deleted\n", 0644);
    unlink("/out/gone");
    mkdir("/out/a", 0755);
    mkdir("/out/a/b", 0755);
    put("/out/a/b/c.txt", "deep\n", 0644);
    static char big[3 << 20];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (char)(i % 251);
    int fd = open("/out/big.bin", O_WRONLY | O_CREAT, 0644);
    write(fd, big, sizeof big);
    close(fd);
    printf("export ok\n");
    fflush(stdout);
    if (argc > 1 && strcmp(argv[1], "crash") == 0) *(volatile int *)0 = 1;
    return 0;
}
