// /proc/self/mem: reads and writes at the process's own addresses (what
// cilium/ebpf's kernel version probe does with the vDSO, and debuggers);
// another process's memory is refused.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("FAILED: %s (line %d, errno %d)\n", #c, __LINE__, errno); return 1; } } while (0)

static volatile long value = 42;
static const char rodata[] = "read only";

int main(void) {
    int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    CHECK(fd >= 0);
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && S_ISREG(st.st_mode));
    CHECK(stat("/proc/self/mem", &st) == 0 && (st.st_mode & 0777) == 0600);

    // Reading and writing a variable.
    long got = 0;
    CHECK(pread(fd, &got, sizeof got, (uintptr_t)&value) == sizeof got && got == 42);
    long put = 1234;
    CHECK(pwrite(fd, &put, sizeof put, (uintptr_t)&value) == sizeof put && value == 1234);
    // At the file position, which moves on.
    CHECK(lseek(fd, (uintptr_t)&value, SEEK_SET) == (off_t)(uintptr_t)&value);
    CHECK(read(fd, &got, sizeof got) == sizeof got && got == 1234);
    CHECK(lseek(fd, 0, SEEK_CUR) == (off_t)((uintptr_t)&value + sizeof got));
    CHECK(lseek(fd, 0, SEEK_END) == -1 && errno == EINVAL);

    // The vDSO's ELF header (where the probe finds the kernel's version).
    unsigned long vdso = getauxval(AT_SYSINFO_EHDR);
    char elf[4];
    CHECK(vdso && pread(fd, elf, 4, vdso) == 4 && !memcmp(elf, "\x7f" "ELF", 4));

    // Nothing mapped there: EIO. Up to the end of a mapping: what's there.
    char buf[8192];
    CHECK(pread(fd, buf, 16, 4096) == -1 && errno == EIO);
    char *m = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED && munmap(m + 4096, 4096) == 0);
    memset(m, 'm', 4096);
    CHECK(pread(fd, buf, 8192, (uintptr_t)m + 4000) == 96 && buf[0] == 'm' && buf[95] == 'm');
    // Read-only memory isn't written (no FOLL_FORCE).
    CHECK(pwrite(fd, "X", 1, (uintptr_t)rodata) == -1 && errno == EIO && rodata[0] == 'r');
    // A bad buffer is the caller's fault.
    CHECK(pread(fd, (void *)8, 8, (uintptr_t)&value) == -1 && errno == EFAULT);

    // Another process's memory: refused at open, and through a descriptor
    // inherited across fork.
    int keep = open("/proc/self/mem", O_RDONLY);
    CHECK(keep >= 0);
    pid_t parent = getpid(), child = fork();
    if (child == 0) {
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/mem", parent);
        if (open(path, O_RDONLY) != -1 || errno != EACCES) _exit(2);
        if (pread(keep, &got, sizeof got, (uintptr_t)&value) != -1 || errno != EIO) _exit(3);
        // Its own is its own.
        int own = open("/proc/self/mem", O_RDONLY);
        if (own < 0 || pread(own, &got, sizeof got, (uintptr_t)&value) != sizeof got || got != 1234) _exit(4);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("procmem ok\n");
    return 0;
}
