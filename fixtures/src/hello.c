// Arguments, environment, stdout/stderr and exit status.
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    printf("hello from agentbox! argc=%d\n", argc);
    for (int i = 0; i < argc; i++) printf("argv[%d]=%s\n", i, argv[i]);
    const char *g = getenv("GREETING");
    printf("GREETING=%s\n", g ? g : "(unset)");
    fprintf(stderr, "this goes to stderr\n");
    return 7;
}
