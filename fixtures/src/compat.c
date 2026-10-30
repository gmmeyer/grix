// Linux surface that ordinary programs expect: users, /proc, /dev links,
// statfs, xattrs, inotify.
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/statfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

static int contains(const char *path, const char *needle) {
    char buf[8192];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) return 0;
    buf[n] = 0;
    return strstr(buf, needle) != NULL;
}

int main(int argc, char **argv) {
    // Users.
    struct passwd *pw = getpwuid(getuid());
    CHECK(pw && strcmp(pw->pw_name, "grix") == 0 && strcmp(pw->pw_dir, "/home/grix") == 0);
    struct group *gr = getgrgid(getgid());
    CHECK(gr && strcmp(gr->gr_name, "grix") == 0);

    // /proc.
    char exe[256] = {0};
    CHECK(readlink("/proc/self/exe", exe, sizeof exe - 1) > 0 && strcmp(exe, "/bin/compat") == 0);
    CHECK(contains("/proc/self/status", "Name:\tcompat"));
    CHECK(contains("/proc/self/maps", "[stack]"));
    CHECK(contains("/proc/self/maps", "/bin/compat"));
    CHECK(contains("/proc/self/cmdline", "/bin/compat"));
    CHECK(contains("/proc/cpuinfo", "processor\t: 0"));
    CHECK(contains("/proc/meminfo", "MemTotal:"));
    CHECK(contains("/proc/stat", "cpu0 "));
    CHECK(contains("/sys/devices/system/cpu/online", "0"));
    CHECK(contains("/proc/sys/kernel/osrelease", "6.1.0-grix"));
    CHECK(contains("/proc/self/mounts", " / "));
    // What monitoring agents read (the Datadog Agent's file_handle, io,
    // memory and network checks, psutil, gohai).
    CHECK(contains("/proc/meminfo", "\nActive:") && contains("/proc/meminfo", "\nInactive:"));
    CHECK(contains("/proc/vmstat", "\npswpin 0\npswpout 0\n"));
    CHECK(contains("/proc/partitions", "major minor"));
    CHECK(access("/proc/diskstats", R_OK) == 0);
    CHECK(contains("/proc/sys/kernel/cap_last_cap", "40\n"));
    char filemax[32] = {0};
    int fm = open("/proc/sys/fs/file-max", O_RDONLY);
    CHECK(fm >= 0 && read(fm, filemax, sizeof filemax - 1) > 0 && atol(filemax) >= 4096 && close(fm) == 0);
    CHECK(contains("/proc/sys/fs/inode-nr", "\t0\n"));
    CHECK(contains("/sys/class/net/lo/mtu", "65536\n"));
    CHECK(contains("/proc/sys/kernel/random/entropy_avail", "256\n"));
    CHECK(contains("/proc/sys/crypto/fips_enabled", "0\n"));
    CHECK(contains("/proc/interrupts", "CPU0"));
    CHECK(contains("/sys/devices/system/cpu/cpu0/topology/core_id", "0\n"));
    // file-nr counts open files, everywhere: one more while this one is open.
    unsigned long nr1, nr2, unused, max;
    FILE *f = fopen("/proc/sys/fs/file-nr", "r");
    CHECK(f && fscanf(f, "%lu %lu %lu", &nr1, &unused, &max) == 3 && unused == 0 && max >= 4096);
    fclose(f);
    int extra = open("/bin/compat", O_RDONLY);
    f = fopen("/proc/sys/fs/file-nr", "r");
    CHECK(f && fscanf(f, "%lu", &nr2) == 1 && nr2 == nr1 + 1);
    fclose(f);
    close(extra);

    // /proc/self/fd and /dev aliases.
    char link[64] = {0};
    CHECK(readlink("/proc/self/fd/0", link, sizeof link - 1) > 0 && strncmp(link, "pipe:", 5) == 0);
    int out = open("/dev/stdout", O_WRONLY);
    CHECK(out >= 3);
    CHECK(write(out, "via /dev/stdout\n", 16) == 16);
    close(out);

    // statfs and xattrs.
    struct statfs sfs;
    CHECK(statfs("/", &sfs) == 0 && sfs.f_bsize == 4096);
    char val[16];
    CHECK(getxattr("/bin/compat", "user.x", val, sizeof val) == -1 && errno == ENODATA);
    CHECK(listxattr("/bin/compat", val, sizeof val) == 0);

    // inotify: watches can be added and removed (and never fire: imports don't change).
    int in = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    CHECK(in >= 0);
    int wd = inotify_add_watch(in, "/bin", IN_CREATE | IN_MODIFY);
    CHECK(wd > 0);
    CHECK(read(in, val, sizeof val) == -1 && errno == EAGAIN);
    CHECK(inotify_rm_watch(in, wd) == 0);
    CHECK(inotify_add_watch(in, "/nope", IN_CREATE) == -1 && errno == ENOENT);

    printf("compat ok %s\n", argc > 1 ? argv[1] : "");
    return 0;
}
