#define _GNU_SOURCE
#include "../tracer.h"

int main(int argc, char **argv)
{
    char *new_args[0x10] = {"./output", NULL};
    int pid;

    pid = traceme(new_args);
    find_output(pid, "hello");

    return 0;
}
