#define _GNU_SOURCE
#include "../tracer.h"

int main(int argc, char **argv)
{
    char *new_args[0x10] = {"./lib", NULL};
    size_t image_addr;
    struct user_regs_struct regs;
    int pid;

    pid = traceme(new_args);
    image_addr = get_addr(pid, "");
    LOGV(image_addr);
    set_libc_path(pid, "/tmp/libc.so.6");

    for(; break_syscall(pid) != SYS_write; )
        ;
    
    gdb_attach(pid);

    return 0;
}
