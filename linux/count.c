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

int main(int argc, char **argv)
{
    int pid, wstatus, result, i, failed;
    char *mmap_buf;
    struct user_regs_struct regs;
    ssize_t return_value, count;
    char buf[0x20], *new_args[0x10] = {0};

    if (argc < 2)
    {
        printf("Usage: %s exe_file\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    for (i = 1; i < argc; i++)
    {
        new_args[i - 1] = argv[i];
    }

    pid = fork();
    if (pid == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (!pid)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }

        kill(getpid(), SIGSTOP);

        execv(new_args[0], new_args);
        perror("execv");
        exit(EXIT_SUCCESS);
    }

    wait(&wstatus);
    if (WSTOPSIG(wstatus) != 19)
    {
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
        }
        else if (WIFCONTINUED(wstatus))
        {
            printf("continued\n");
        }
        exit(EXIT_FAILURE);
    }

    ptrace(PTRACE_SETOPTIONS, pid, 0LL, PTRACE_O_EXITKILL);

    while (1)
    {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        wait(&wstatus);

        if (WIFEXITED(wstatus))
        {
            // printf("exited, status=%d\n", WEXITSTATUS(wstatus));
            break;
        }
        else if (WIFSIGNALED(wstatus))
        {
            printf("killed by signal %d\n", WTERMSIG(wstatus));
            exit(EXIT_FAILURE);
        }
        else if (WIFSTOPPED(wstatus))
        {
            if (WSTOPSIG(wstatus) != SIGTRAP)
            {
                printf("stopped by signal %d\n", WSTOPSIG(wstatus));
                exit(EXIT_FAILURE);
            }
        }
        else if (WIFCONTINUED(wstatus))
        {
            fprintf(stderr, "Unknown error!\n");
            exit(EXIT_FAILURE);
        }

        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }

        if (regs.orig_rax == SYS_execve)
        {
            break;
        }
    }

    count = 0;
    while (1)
    {
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wait(&wstatus);

        if (WIFEXITED(wstatus))
        {
            // printf("exited, status=%d\n", WEXITSTATUS(wstatus));
            break;
        }
        else if (WIFSIGNALED(wstatus))
        {
            printf("killed by signal %d\n", WTERMSIG(wstatus));
            exit(EXIT_FAILURE);
        }
        else if (WIFSTOPPED(wstatus))
        {
            if (WSTOPSIG(wstatus) != SIGTRAP)
            {
                printf("stopped by signal %d\n", WSTOPSIG(wstatus));
                exit(EXIT_FAILURE);
            }
        }
        else if (WIFCONTINUED(wstatus))
        {
            fprintf(stderr, "Unknown error!\n");
            exit(EXIT_FAILURE);
        }

        count++;
    }
    printf("%ld\n", count);

    return 0;
}