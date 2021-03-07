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
#include <sys/uio.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <linux/elf.h>

int main()
{
    pid_t pid, w;
    int wstatus;
    struct user_regs_struct regs;
    struct iovec io;

    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    pid = fork();
    if (pid == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid)
    {
        do
        {
            w = waitpid(pid, &wstatus, WUNTRACED | WCONTINUED);
            if (w == -1)
            {
                perror("waitpid");
                exit(EXIT_FAILURE);
            }

            if (WIFEXITED(wstatus))
            {
                printf("exited, status=%d\n", WEXITSTATUS(wstatus));
            }
            else if (WIFSIGNALED(wstatus))
            {
                printf("killed by signal %d\n", WTERMSIG(wstatus));
            }
            else if (WIFSTOPPED(wstatus))
            {
                printf("stopped by signal %d\n", WSTOPSIG(wstatus));
                if (WSTOPSIG(wstatus) == SIGTRAP)
                {
                    ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, (void *)&io);
                    printf("pc: %lx\n", regs.pc);
                    regs.pc += 4; // Ignore brk instruction.
                    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, (void *)&io) == -1)
                    {
                        perror("ptrace");
                        exit(EXIT_FAILURE);
                    }
                }
                ptrace(PTRACE_CONT, pid, 0, 0);
            }
            else if (WIFCONTINUED(wstatus))
            {
                printf("continued\n");
            }
        } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));
    }
    else
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }

        kill(getpid(), SIGSTOP);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

        // __builtin_trap();
        asm("brk #0");

        exit(EXIT_SUCCESS);
    }

    return 0;
}
