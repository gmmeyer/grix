// List a directory with types and sizes; exercise stat, getdents, readlink, getcwd, chdir.
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : ".";
    if (chdir(dir) != 0) {
        fprintf(stderr, "ls: chdir %s: %s\n", dir, strerror(errno));
        return 1;
    }
    char cwd[256];
    printf("cwd=%s\n", getcwd(cwd, sizeof cwd) ? cwd : "?");
    DIR *d = opendir(".");
    if (!d) {
        fprintf(stderr, "ls: %s: %s\n", dir, strerror(errno));
        return 1;
    }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        struct stat st;
        if (lstat(e->d_name, &st) != 0) {
            printf("? %s (%s)\n", e->d_name, strerror(errno));
            continue;
        }
        if (S_ISLNK(st.st_mode)) {
            char target[256] = {0};
            readlink(e->d_name, target, sizeof target - 1);
            printf("l %s -> %s\n", e->d_name, target);
        } else {
            printf("%c %s %lld %o\n", S_ISDIR(st.st_mode) ? 'd' : '-', e->d_name, (long long)st.st_size,
                   st.st_mode & 0777);
        }
    }
    closedir(d);
    return 0;
}
