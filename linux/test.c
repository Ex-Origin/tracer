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

#define G() getregs(pid, &regs);
#define S() setregs(pid, &regs);
#define P() {print_regs(&regs);}
#define B(addr) install_break_point(pid, addr);
#define W() wait_for_signal(pid, SIGTRAP);
#define C() {continue_break_point(pid); wait_for_signal(pid, SIGTRAP);}
#define CB() {continue_break_point(pid);}
#define CC() {continue_(pid);}
#define Q() exit(0);
#define WW() {while(1){CC();W();}}

int main(int argc, char **argv)
{
    int pid, wstatus, result, i, failed;
    char *mmap_buf;
    struct user_regs_struct regs;
    ssize_t return_value, count, image_addr;
    char *new_args[0x10] = {"./main", NULL}, buf[0x1000];

    pid = traceme(new_args);
    image_addr = get_image_addr(pid);
    // B(image_addr + 0x1184);
    // set_libc_addr(pid, 0x12340000);
    // set_heap_addr(pid, 0x56780000);
    // CC();
    gdb_attach(pid, SIGSTOP);

    return 0;
}
