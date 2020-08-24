/*
 *
 * Author: Ex
 * Time: 2020-08-25
 * Email: 2462148389@qq.com
 * 
 **/
#ifndef TRACER_H
#define TRACER_H

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

int traceme(char **new_args);
void wait_for_signal(int pid, int sig);
void print_regs(struct user_regs_struct *regs);
void interupt(int pid);
int install_break_point(int pid, size_t addr);
int continue_break_point(int pid);
ssize_t get_image_addr(int pid);
void detach(int pid);
void continue_(int pid);
void getregs(int pid, struct user_regs_struct *regs);
void setregs(int pid, struct user_regs_struct *regs);
size_t peekdata(int pid, size_t addr);
void pokedata(int pid, size_t addr, size_t vaule);
ssize_t get_addr(int pid, char *search);
void update_tmp_pid(int pid);

void (*__traceme_hook)();

#define GDB_PID "/tmp/gdb_pid"

#define PERROR(arg)                                                                                \
    {                                                                                              \
        fprintf(stderr, "Error has happened at %s:%d (func: %s)\n", __FILE__, __LINE__, __func__); \
        perror(arg);                                                                               \
    }

#define DPRINTF(arg, ...)                                                                \
    {                                                                                    \
        printf("DEBUG information at %s:%d (func: %s)\n", __FILE__, __LINE__, __func__); \
        printf(arg, __VA_ARGS__);                                                        \
    }

#define LOGV(variable)                           \
    {                                            \
        printf("" #variable ": 0x%llx (%llu)\n", \
               (unsigned long long)(variable),   \
               (unsigned long long)(variable));  \
    }

#define ERROR(arg) arg

typedef struct BreakPoint
{
    size_t addr;
    size_t previous_byte;
} BreakPoint;

BreakPoint global_point[0x100];

size_t global_image_base_addr = 0;

char *error_info[] = {
    "success",
    "Can't find BreakPoint",
    "Run out of BreakPoint",
    "Can't find this address",
};

void print_regs(struct user_regs_struct *regs)
{
    printf("orig_rax: 0x%llx\n", regs->orig_rax);
    printf("rax: 0x%llx\n", regs->rax);
    printf("rdi: 0x%llx\n", regs->rdi);
    printf("rsi: 0x%llx\n", regs->rsi);
    printf("rdx: 0x%llx\n", regs->rdx);
    printf("rsp: 0x%llx\n", regs->rsp);
    printf("rip: 0x%llx\n", regs->rip);
    if (global_image_base_addr != 0 && ((regs->rip - global_image_base_addr) < 0x21000))
    {
        printf("rip(without PIE): 0x%llx\n", regs->rip - global_image_base_addr);
    }
}

void wait_for_signal(int pid, int sig)
{
    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (WSTOPSIG(wstatus) != sig)
    {
        if (WIFEXITED(wstatus))
        {
            DPRINTF("exited, status=%d\n", WEXITSTATUS(wstatus));
        }
        else if (WIFSIGNALED(wstatus))
        {
            DPRINTF("killed by signal %d\n", WTERMSIG(wstatus));
        }
        else if (WIFSTOPPED(wstatus))
        {
            DPRINTF("stopped by signal %d\n", WSTOPSIG(wstatus));
        }
        else if (WIFCONTINUED(wstatus))
        {
            DPRINTF("%s\n", "continued");
        }
        exit(EXIT_FAILURE);
    }
}

void interupt(int pid)
{
    int wstatus;
    kill(pid, SIGINT);
    waitpid(pid, &wstatus, 0);
    wait_for_signal(pid, SIGINT);
}

void update_tmp_pid(int pid)
{
    FILE *fp;
    char buf[0x100];
    int result;
    fp = fopen(GDB_PID, "w");
    if (fp == NULL)
    {
        PERROR("fopen");
        exit(EXIT_FAILURE);
    }
    result = snprintf(buf, sizeof(buf), "%d", pid);
    fwrite(buf, 1, result, fp);
    fclose(fp);
}

void getregs(int pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1)
    {
        PERROR("ptrace");
        exit(EXIT_FAILURE);
    }
}

void setregs(int pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1)
    {
        PERROR("ptrace");
        exit(EXIT_FAILURE);
    }
}

void pokedata(int pid, size_t addr, size_t vaule)
{
    if (ptrace(PTRACE_POKEDATA, pid, addr, vaule) == -1)
    {
        PERROR("ptrace");
        exit(EXIT_FAILURE);
    }
}

size_t peekdata(int pid, size_t addr)
{
    size_t value;
    value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (value == -1 && errno != 0)
    {
        PERROR("ptrace");
        exit(EXIT_FAILURE);
    }
    return value;
}

void detach(int pid)
{
    if (ptrace(PT_DETACH, pid, 0, 0) == -1)
    {
        PERROR("ptrace");
        exit(EXIT_FAILURE);
    }
}

void continue_(int pid)
{
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
    {
        PERROR("ptrace");
        exit(EXIT_FAILURE);
    }
}

int traceme(char **new_args)
{
    int pid, wstatus, i;
    struct user_regs_struct regs;
    pid = fork();
    if (pid == -1)
    {
        PERROR("fork");
        exit(EXIT_FAILURE);
    }

    if (!pid)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        {
            PERROR("ptrace");
            exit(EXIT_FAILURE);
        }

        if (__traceme_hook)
        {
            __traceme_hook();
        }

        kill(getpid(), SIGSTOP);

        execv(new_args[0], new_args);
        PERROR("execv");
        exit(EXIT_FAILURE);
    }

    wait_for_signal(pid, SIGSTOP);

    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    for (i = 0; i < 3; i++)
    {
        while (1)
        {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait_for_signal(pid, SIGTRAP);

            getregs(pid, &regs);

            if (regs.orig_rax == SYS_execve)
            {
                break;
            }
        }
    }
    return pid;
}

int install_break_point(int pid, size_t addr)
{
    size_t value;
    int index;
    value = peekdata(pid, addr);
    for (index = 0; index < sizeof(global_point) / sizeof(BreakPoint); index++)
    {
        if (global_point[index].addr == 0)
        {
            break;
        }
    }
    if (index == sizeof(global_point) / sizeof(BreakPoint))
    {
        return ERROR(2);
    }
    global_point[index].addr = addr;
    global_point[index].previous_byte = value;
    value = (value & ~(0xff)) | (0xcc);
    pokedata(pid, addr, value);
    return 0;
}

int continue_break_point(int pid)
{
    struct user_regs_struct regs;
    size_t value, rip;
    int index, wstatus;

    getregs(pid, &regs);
    rip = regs.rip - 1;

    for (index = 0; index < sizeof(global_point) / sizeof(BreakPoint); index++)
    {
        if (global_point[index].addr == rip)
        {
            break;
        }
    }
    if (index == sizeof(global_point) / sizeof(BreakPoint))
    {
        return ERROR(1);
    }

    regs.rip = rip;
    setregs(pid, &regs);
    pokedata(pid, rip, global_point[index].previous_byte);

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
    {
        PERROR("ptrace");
        exit(EXIT_FAILURE);
    }
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus))
    {
        DPRINTF("exited, status=%d\n", WEXITSTATUS(wstatus));
        exit(EXIT_FAILURE);
    }
    else if (WIFSIGNALED(wstatus))
    {
        DPRINTF("killed by signal %d\n", WTERMSIG(wstatus));
        exit(EXIT_FAILURE);
    }
    else if (WIFSTOPPED(wstatus))
    {
        if (WSTOPSIG(wstatus) != SIGTRAP)
        {
            fprintf(stderr, "Error has happened at %s:%d (func: %s)\n", __FILE__, __LINE__, __func__);
            fprintf(stderr, "stopped by signal %d\n", WSTOPSIG(wstatus));
            getregs(pid, &regs);
            print_regs(&regs);
            exit(EXIT_FAILURE);
        }
    }
    else if (WIFCONTINUED(wstatus))
    {
        DPRINTF("%s\n", "continued");
        exit(EXIT_FAILURE);
    }

    value = global_point[index].previous_byte;
    value = (value & ~(0xff)) | (0xcc);
    pokedata(pid, rip, value);
    continue_(pid);
    return 0;
}

ssize_t get_addr(int pid, char *search)
{
    FILE *fp;
    char buf[0x100];
    char path[0x100];
    ssize_t addr;
    int flag;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    fp = fopen(path, "r");
    flag = 1;
    while (fgets(buf, sizeof(buf), fp) != NULL)
    {
        if (strstr(buf, search))
        {
            sscanf(buf, "%lx", &addr);
            flag = 0;
            break;
        }
    }

    fclose(fp);
    if (flag)
    {
        return ERROR(3);
    }
    return addr;
}

ssize_t get_image_addr(int pid)
{
    char path[0x100];
    char exename[0x100];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    readlink(path, exename, sizeof(exename));

    global_image_base_addr = get_addr(pid, exename);
    return global_image_base_addr;
}

#endif
