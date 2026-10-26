// Die in various ways: segv (default), abort, illegal instruction.
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *how = argc > 1 ? argv[1] : "segv";
    if (!strcmp(how, "abort")) abort();
    if (!strcmp(how, "ill")) __builtin_trap();
    *(volatile int *)8 = 1;
    return 0;
}
