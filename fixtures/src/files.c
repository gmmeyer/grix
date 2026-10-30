// The writable filesystem (needs fs_write): creating, writing, appending,
// truncating and sparse files; directories; rename (replace, noreplace,
// exchange); hard and symbolic links; unlinked-but-open files and
// O_TMPFILE; readdir while deleting; permissions and ownership; timestamps;
// copy-on-write of imported files; mmap, sendfile and copy_file_range;
// hostile inputs (symlink bombs, /proc). Modes: `fill` writes until the size
// limit says ENOSPC, `meta` exhausts the metadata budget, `shared PATH`
// maps a live mount's file MAP_SHARED and changes it.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)
#define RUN(t) do { if (t()) return 1; } while (0)

static int put(const char *path, const char *s) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    int n = write(fd, s, strlen(s));
    close(fd);
    return n == (int)strlen(s) ? 0 : -1;
}

static char buf[65536];

static const char *get(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return "<missing>";
    int n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n < 0 ? 0 : n] = 0;
    return buf;
}

static int test_files(void) {
    umask(022);
    int fd = open("/tmp/a.txt", O_RDWR | O_CREAT | O_EXCL, 0666);
    CHECK(fd >= 0);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && (st.st_mode & 0777) == 0644 && st.st_size == 0 && st.st_uid == getuid());
    CHECK(write(fd, "hello world", 11) == 11);
    CHECK(pwrite(fd, "W", 1, 6) == 1);
    CHECK(pread(fd, buf, 32, 0) == 11 && !memcmp(buf, "hello World", 11));
    CHECK(lseek(fd, 0, SEEK_END) == 11);
    CHECK(lseek(fd, 3, SEEK_DATA) == 3 && lseek(fd, 3, SEEK_HOLE) == 11);
    CHECK(lseek(fd, 20, SEEK_DATA) == -1 && errno == ENXIO);
    close(fd);
    CHECK(open("/tmp/a.txt", O_CREAT | O_EXCL | O_WRONLY, 0644) == -1 && errno == EEXIST);
    // O_APPEND writes at the end, even with pwrite (as on Linux), and pwrite
    // leaves the file offset alone.
    fd = open("/tmp/a.txt", O_WRONLY | O_APPEND);
    CHECK(write(fd, "!", 1) == 1 && lseek(fd, 0, SEEK_CUR) == 12);
    CHECK(pwrite(fd, "?", 1, 0) == 1 && lseek(fd, 0, SEEK_CUR) == 12);
    close(fd);
    CHECK(!strcmp(get("/tmp/a.txt"), "hello World!?"));
    // Sparse growth and truncation read zeros.
    fd = open("/tmp/a.txt", O_RDWR);
    CHECK(pwrite(fd, "end", 3, 10000) == 3);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 10003);
    CHECK(pread(fd, buf, 16, 5000) == 16 && buf[0] == 0 && buf[15] == 0);
    CHECK(ftruncate(fd, 5) == 0 && ftruncate(fd, 8) == 0);
    CHECK(pread(fd, buf, 16, 0) == 8 && !memcmp(buf, "hello\0\0\0", 8));
    close(fd);
    // O_TRUNC empties it.
    CHECK(put("/tmp/a.txt", "short") == 0 && !strcmp(get("/tmp/a.txt"), "short"));
    // Data across page boundaries.
    char *big = malloc(20000);
    for (int i = 0; i < 20000; i++) big[i] = 'a' + i % 26;
    fd = open("/tmp/big", O_RDWR | O_CREAT, 0600);
    CHECK(write(fd, big, 20000) == 20000);
    CHECK(pread(fd, buf, 9000, 4000) == 9000 && !memcmp(buf, big + 4000, 9000));
    close(fd);
    free(big);
    return 0;
}

static int test_dirs(void) {
    CHECK(mkdir("/tmp/d", 0755) == 0);
    CHECK(mkdir("/tmp/d", 0755) == -1 && errno == EEXIST);
    CHECK(mkdir("/tmp/d/e/f", 0755) == -1 && errno == ENOENT);
    CHECK(mkdir("/tmp/d/e", 0755) == 0 && put("/tmp/d/e/x", "x") == 0);
    CHECK(rmdir("/tmp/d") == -1 && errno == ENOTEMPTY);
    CHECK(unlink("/tmp/d") == -1 && errno == EISDIR);
    CHECK(rmdir("/tmp/d/e/x") == -1 && errno == ENOTDIR);
    CHECK(rmdir("/tmp/d/.") == -1 && errno == EINVAL);
    CHECK(chdir("/tmp/d/e") == 0 && !strcmp(get("x"), "x"));
    CHECK(getcwd(buf, sizeof buf) && !strcmp(buf, "/tmp/d/e"));
    CHECK(chdir("/") == 0);
    // rename: replace a file, refuse to move a directory into itself.
    CHECK(put("/tmp/d/old", "old") == 0 && put("/tmp/d/new", "new") == 0);
    CHECK(rename("/tmp/d/old", "/tmp/d/new") == 0 && !strcmp(get("/tmp/d/new"), "old"));
    CHECK(access("/tmp/d/old", F_OK) == -1 && errno == ENOENT);
    CHECK(rename("/tmp/d", "/tmp/d/e/inside") == -1 && errno == EINVAL);
    CHECK(rename("/tmp/d/e", "/tmp/d/new") == -1 && errno == ENOTDIR);
    CHECK(put("/tmp/d/other", "other") == 0);
    CHECK(syscall(SYS_renameat2, AT_FDCWD, "/tmp/d/new", AT_FDCWD, "/tmp/d/other", 1) == -1 && errno == EEXIST);
    CHECK(syscall(SYS_renameat2, AT_FDCWD, "/tmp/d/new", AT_FDCWD, "/tmp/d/other", 2) == 0);
    CHECK(!strcmp(get("/tmp/d/new"), "other") && !strcmp(get("/tmp/d/other"), "old"));
    CHECK(rename("/tmp/d/e", "/tmp/e2") == 0 && !strcmp(get("/tmp/e2/x"), "x"));
    return 0;
}

static int test_links(void) {
    CHECK(put("/tmp/l1", "linked") == 0);
    CHECK(link("/tmp/l1", "/tmp/l2") == 0);
    struct stat st;
    CHECK(stat("/tmp/l2", &st) == 0 && st.st_nlink == 2);
    CHECK(unlink("/tmp/l1") == 0 && !strcmp(get("/tmp/l2"), "linked"));
    CHECK(stat("/tmp/l2", &st) == 0 && st.st_nlink == 1);
    CHECK(link("/tmp", "/tmp/dirlink") == -1 && errno == EPERM);
    CHECK(symlink("l2", "/tmp/sym") == 0);
    CHECK(readlink("/tmp/sym", buf, sizeof buf) == 2 && !memcmp(buf, "l2", 2));
    CHECK(lstat("/tmp/sym", &st) == 0 && S_ISLNK(st.st_mode));
    CHECK(!strcmp(get("/tmp/sym"), "linked"));
    // Creating through a dangling symlink creates its target.
    CHECK(symlink("/tmp/target", "/tmp/dangling") == 0 && put("/tmp/dangling", "via link") == 0);
    CHECK(!strcmp(get("/tmp/target"), "via link"));
    return 0;
}

static int test_unlinked(void) {
    // An unlinked file lives on while it's open.
    int fd = open("/tmp/gone", O_RDWR | O_CREAT, 0600);
    CHECK(fd >= 0 && write(fd, "still here", 10) == 10);
    CHECK(unlink("/tmp/gone") == 0 && access("/tmp/gone", F_OK) == -1);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_nlink == 0 && st.st_size == 10);
    CHECK(pread(fd, buf, 32, 0) == 10 && !memcmp(buf, "still here", 10));
    close(fd);
    // O_TMPFILE: no name until linkat gives it one.
    fd = open("/tmp", O_TMPFILE | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "tmpfile", 7) == 7);
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    CHECK(linkat(AT_FDCWD, path, AT_FDCWD, "/tmp/named", AT_SYMLINK_FOLLOW) == 0);
    close(fd);
    CHECK(!strcmp(get("/tmp/named"), "tmpfile"));
    // A deleted file can't be brought back that way.
    fd = open("/tmp/named", O_RDONLY);
    CHECK(unlink("/tmp/named") == 0);
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    CHECK(linkat(AT_FDCWD, path, AT_FDCWD, "/tmp/back", AT_SYMLINK_FOLLOW) == -1 && errno == ENOENT);
    close(fd);
    // /proc/self/fd/N opens the file again: an offset of its own, and the
    // checks of any open.
    fd = open("/tmp/again", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0 && write(fd, "abcdef", 6) == 6 && lseek(fd, 3, SEEK_SET) == 3);
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    int again = open(path, O_RDONLY);
    char c;
    CHECK(again >= 0 && read(again, &c, 1) == 1 && c == 'a');
    CHECK(read(fd, &c, 1) == 1 && c == 'd');
    close(again);
    CHECK(chmod("/tmp/again", 0400) == 0);
    CHECK(open(path, O_RDWR) == -1 && errno == EACCES);
    close(fd);
    return 0;
}

static int test_readdir(void) {
    // rm -rf reads a directory while deleting from it.
    CHECK(mkdir("/tmp/many", 0755) == 0);
    char name[64];
    for (int i = 0; i < 300; i++) {
        snprintf(name, sizeof name, "/tmp/many/file-%03d", i);
        CHECK(put(name, "x") == 0);
    }
    DIR *d = opendir("/tmp/many");
    CHECK(d);
    int seen = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        CHECK(e->d_type == DT_REG);
        CHECK(unlinkat(dirfd(d), e->d_name, 0) == 0);
        seen++;
    }
    closedir(d);
    CHECK(seen == 300);
    CHECK(rmdir("/tmp/many") == 0);
    return 0;
}

static int test_permissions(void) {
    CHECK(put("/tmp/ro", "ro") == 0 && chmod("/tmp/ro", 0444) == 0);
    CHECK(open("/tmp/ro", O_WRONLY) == -1 && errno == EACCES);
    CHECK(access("/tmp/ro", W_OK) == -1 && errno == EACCES && access("/tmp/ro", R_OK) == 0);
    CHECK(unlink("/tmp/ro") == 0);  // needs the directory's permission, not the file's
    // System files and directories belong to root.
    CHECK(open("/etc/passwd", O_WRONLY) == -1 && errno == EACCES);
    CHECK(mkdir("/proc/x", 0755) == -1 && errno == EACCES);
    struct stat st;
    CHECK(stat("/tmp", &st) == 0 && (st.st_mode & 07777) == 01777 && st.st_uid == 0);
    CHECK(put("/tmp/mine", "m") == 0);
    CHECK(chown("/tmp/mine", 0, -1) == -1 && errno == EPERM);
    CHECK(chown("/tmp/mine", getuid(), getgid()) == 0);
    // Explicit timestamps.
    struct timespec ts[2] = {{1000000000, 5}, {1234567890, 0}};
    CHECK(utimensat(AT_FDCWD, "/tmp/mine", ts, 0) == 0);
    CHECK(stat("/tmp/mine", &st) == 0 && st.st_mtim.tv_sec == 1234567890 && st.st_atim.tv_nsec == 5);
    int fd = open("/tmp/mine", O_WRONLY);
    CHECK(write(fd, "x", 1) == 1);
    CHECK(fstat(fd, &st) == 0 && st.st_mtim.tv_sec > 1600000000);
    close(fd);
    struct statfs sf;
    CHECK(statfs("/tmp", &sf) == 0 && sf.f_bavail > 0 && !(sf.f_flags & 1));
    CHECK(strstr(get("/proc/self/mounts"), "grix / tmpfs rw"));
    // /proc, /sys and /dev are fixed, whoever owns them.
    CHECK(stat("/proc/self", &st) == 0 && st.st_uid == getuid());
    CHECK(mkdir("/proc/self/x", 0755) == -1 && errno == EACCES);
    CHECK(chmod("/proc/self", 0777) == -1 && errno == EPERM);
    CHECK(unlink("/dev/null") == -1 && errno == EACCES);
    CHECK(put("/dev/shm/sem", "ok") == 0);
    // fchmodat2 (452 on both architectures): flags, and a symlink's own
    // mode can't change.
    CHECK(syscall(452, AT_FDCWD, "/tmp/mine", 0600, AT_SYMLINK_NOFOLLOW) == 0);
    CHECK(stat("/tmp/mine", &st) == 0 && (st.st_mode & 07777) == 0600);
    CHECK(symlink("/tmp/mine", "/tmp/mine-link") == 0);
    CHECK(syscall(452, AT_FDCWD, "/tmp/mine-link", 0644, AT_SYMLINK_NOFOLLOW) == -1 && errno == EOPNOTSUPP);
    CHECK(syscall(452, AT_FDCWD, "/tmp/mine-link", 0640, 0) == 0);
    CHECK(stat("/tmp/mine", &st) == 0 && (st.st_mode & 07777) == 0640);
    fd = open("/tmp/mine", O_RDONLY);
    CHECK(syscall(452, fd, "", 0604, AT_EMPTY_PATH) == 0);
    CHECK(fstat(fd, &st) == 0 && (st.st_mode & 07777) == 0604);
    close(fd);
    CHECK(syscall(452, AT_FDCWD, "/tmp/mine", 0600, 1) == -1 && errno == EINVAL);
    CHECK(unlink("/tmp/mine-link") == 0);
    return 0;
}

static int test_hostile(void) {
    // Reading a /proc file far past its end.
    int fd = open("/proc/self/status", O_RDONLY);
    CHECK(fd >= 0 && pread(fd, buf, 10, 1 << 20) == 0);
    CHECK(lseek(fd, 1 << 20, SEEK_SET) == 1 << 20 && read(fd, buf, 10) == 0);
    close(fd);
    // A symlink chain that doubles at every level is cut off after 40 links.
    CHECK(mkdir("/tmp/bomb", 0755) == 0 && chdir("/tmp/bomb") == 0);
    CHECK(symlink(".", "s38") == 0);
    char name[16], target[40];
    for (int i = 37; i >= 0; i--) {
        snprintf(name, sizeof name, "s%d", i);
        snprintf(target, sizeof target, "s%d/s%d", i + 1, i + 1);
        CHECK(symlink(target, name) == 0);
    }
    struct stat st;
    CHECK(stat("s0", &st) == -1 && errno == ELOOP);
    CHECK(chdir("/") == 0);
    return 0;
}

static int test_imported(void) {
    // Imported files can be changed; the host's copy never is.
    CHECK(!strcmp(get("/data/in.txt"), "imported text\n"));
    int fd = open("/data/in.txt", O_RDWR);
    CHECK(fd >= 0 && pwrite(fd, "IMPORTED", 8, 0) == 8);
    close(fd);
    CHECK(!strcmp(get("/data/in.txt"), "IMPORTED text\n"));
    CHECK(truncate("/data/in.txt", 8) == 0 && !strcmp(get("/data/in.txt"), "IMPORTED"));
    CHECK(rename("/data/in.txt", "/data/moved.txt") == 0 && unlink("/data/moved.txt") == 0);
    return 0;
}

static int test_copies(void) {
    CHECK(put("/tmp/src", "copy me please") == 0);
    // mmap of a written file.
    int fd = open("/tmp/src", O_RDONLY);
    char *m = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(m != MAP_FAILED && !memcmp(m, "copy me please", 14) && m[14] == 0);
    munmap(m, 4096);
    int out = open("/tmp/dst", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    off_t off = 5;
    CHECK(sendfile(out, fd, &off, 100) == 9 && off == 14);
    CHECK(lseek(fd, 0, SEEK_CUR) == 0);
    close(out);
    CHECK(!strcmp(get("/tmp/dst"), "me please"));
    out = open("/tmp/dst2", O_WRONLY | O_CREAT, 0644);
    CHECK(copy_file_range(fd, 0, out, 0, 4, 0) == 4);
    close(out);
    close(fd);
    CHECK(!strcmp(get("/tmp/dst2"), "copy"));
    return 0;
}

static int fill(void) {
    // Write until the size limit, then check that deleting frees the space.
    static char chunk[1 << 20];
    memset(chunk, 'z', sizeof chunk);
    int fd = open("/tmp/fill", O_WRONLY | O_CREAT, 0644);
    long total = 0;
    for (;;) {
        ssize_t n = write(fd, chunk, sizeof chunk);
        if (n < 0) break;
        total += n;
    }
    CHECK(errno == ENOSPC && total > 0);
    // A write that stores nothing doesn't grow the file.
    struct stat st;
    CHECK(pwrite(fd, chunk, 4096, 1L << 40) == -1 && errno == ENOSPC);
    CHECK(fstat(fd, &st) == 0 && st.st_size == total);
    close(fd);
    CHECK(put("/tmp/more", "x") == -1 && errno == ENOSPC);
    CHECK(unlink("/tmp/fill") == 0);
    CHECK(put("/tmp/more", "x") == 0);
    printf("filled %ld MiB\n", total >> 20);
    return 0;
}

static int meta(void) {
    // Names and nodes live in kernel memory: they run out with ENOSPC, not a
    // kernel panic, and come back when deleted.
    static char target[4001];
    memset(target, 'a', 4000);
    char name[32];
    int n = 0;
    for (;; n++) {
        snprintf(name, sizeof name, "/tmp/s%d", n);
        if (symlink(target, name) < 0) break;
    }
    CHECK(errno == ENOSPC && n > 100);
    for (int i = 0; i < n; i++) {
        snprintf(name, sizeof name, "/tmp/s%d", i);
        CHECK(unlink(name) == 0);
    }
    CHECK(symlink(target, "/tmp/again") == 0);
    // Removed directories give their slots back.
    for (int i = 0; i < 100000; i++) CHECK(mkdir("/tmp/churn", 0755) == 0 && rmdir("/tmp/churn") == 0);
    printf("meta %d\n", n);
    return 0;
}

static int shared(const char *path) {
    // A live mount's file mapped MAP_SHARED: the mapping holds a copy, so a
    // writable one is refused, and so is making one writable or changing
    // the file (as unimplemented).
    CHECK(put(path, "before") == 0);
    int fd = open(path, O_RDWR);
    CHECK(mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED && errno == ENODEV);
    char *m = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED && !memcmp(m, "before", 6));
    CHECK(mprotect(m, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    CHECK(pwrite(fd, "after", 5, 0) == 5);
    printf("shared ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "fill")) return fill();
    if (argc > 1 && !strcmp(argv[1], "meta")) return meta();
    if (argc > 2 && !strcmp(argv[1], "shared")) return shared(argv[2]);
    RUN(test_files);
    RUN(test_dirs);
    RUN(test_links);
    RUN(test_unlinked);
    RUN(test_readdir);
    RUN(test_permissions);
    RUN(test_imported);
    RUN(test_copies);
    RUN(test_hostile);
    printf("files ok\n");
    return 0;
}
