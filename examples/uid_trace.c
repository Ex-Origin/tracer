#define _GNU_SOURCE
#include "../tracer.h"

int main(int argc, char **argv)
{
    char *new_args[0x10] = {"./uid", NULL};
    size_t image_addr;
    struct user_regs_struct regs;
    int pid;

    pid = traceme(new_args);
    image_addr = get_addr(pid, "");
    LOGV(image_addr);
    bre(pid, INS, image_addr + 0x1176);

    wai(pid);
    getregs(pid, &regs);
    regs.rax = 1234;
    setregs(pid, &regs);

    wai(pid);

    return 0;
}
