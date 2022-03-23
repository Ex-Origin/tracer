#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>
#include <stddef.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <errno.h>

#include "tracer.h"

int main(int argc, char **argv)
{
    int pid, wstatus, result, i, failed;
    char *mmap_buf;
    struct user_regs_struct regs;
    ssize_t return_value, count, image_addr;
    char *new_args[0x10] = {"./main", NULL}, buf[0x1000];

    setbuf(stdout, NULL);

    pid = traceme(new_args);
    image_addr = get_addr(pid, new_args[0] + 2);
    // LOGV(image_addr);
    // set_libc_path(pid, "./libc.so.6");
    // bre(pid, INS, image_addr + 0xcdb);
    // wai(pid);

    // gdb_attach(pid);
    pwntools_attach(pid);

    return 0;
}
