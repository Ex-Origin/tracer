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
    char *new_args[0x10] = {"./getuid", NULL}, buf[0x1000];

    pid = traceme(new_args);
    image_addr = get_image_addr(pid);
    install_break_point(pid, image_addr + 0x1184);
    continue_(pid);

    wait_for_signal(pid, SIGTRAP);
    getregs(pid, &regs);
    print_regs(&regs);
    regs.rsi = 6666;
    setregs(pid, &regs);
    continue_break_point(pid);
    wait(&wstatus);

    return 0;
}
