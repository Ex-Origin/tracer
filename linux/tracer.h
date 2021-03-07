/*
 *
 * Author: Ex
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
#include <assert.h>

int traceme(char **new_args);
void wait_for_signal(int pid, int sig);
void print_regs(struct user_regs_struct *regs);
void interupt(int pid);
int install_break_point(int pid, size_t addr);
int continue_break_point(int pid);
int restore_break_point(int pid);
ssize_t get_image_addr(int pid);
void detach(int pid);
void continue_(int pid);
void getregs(int pid, struct user_regs_struct *regs);
void setregs(int pid, struct user_regs_struct *regs);
size_t peekdata(int pid, size_t addr);
void pokedata(int pid, size_t addr, size_t vaule);
ssize_t get_addr(int pid, char *search);
void update_tmp_pid(int pid);
void print_hex(unsigned char *addr, int size, int mode);
void *trace_mmap(int pid, void *addr, size_t length, int prot);
void *trace_mprotect(int pid, void *addr, size_t length, int prot);
void set_libc_addr(int pid, size_t addr);
// If sig is SIGSTOP, the child process will be blocked.
void gdb_attach(int pid, int sig);
void set_heap_addr(int pid, size_t addr);
int break_syscall(int pid, size_t syscall_num);

void (*__traceme_hook)();

#define FOR_IDA

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

#define DPUTS(arg)                                                                       \
    {                                                                                    \
        printf("DEBUG information at %s:%d (func: %s)\n", __FILE__, __LINE__, __func__); \
        puts(arg);                                                                       \
    }

#define LOGV(variable)                           \
    {                                            \
        printf("" #variable ": 0x%llx (%llu)\n", \
               (unsigned long long)(variable),   \
               (unsigned long long)(variable));  \
    }

#define ERROR_REPORT()                                                                                  \
    {                                                                                                   \
        fprintf(stderr, "Error has happened at %s:%d (func: %s) , %m\n", __FILE__, __LINE__, __func__); \
    }

#define ASSERT(expression)                           \
    {                                                \
        if (expression)                              \
        {                                            \
            ERROR_REPORT();                          \
            fprintf(stderr, "-> " #expression "\n"); \
            exit_handle(EXIT_FAILURE);                      \
        }                                            \
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

#ifdef __x86_64__
#define XIP rip
#define XAX rax
#define XBX rbx
#define XCX rcx
#define XDX rdx
#define XDI rdi
#define XSI rsi
#define XSP rsp
#define OXAX orig_rax
#define HEX_FORMAT "%16llx"
#elif __i386__
#define XIP eip
#define XAX eax
#define XBX ebx
#define XCX ecx
#define XDX edx
#define XDI edi
#define XSI esi
#define XSP esp
#define OXAX orig_eax
#define HEX_FORMAT "%8lx"
#endif

void exit_handle(int status)
{
    assert(status != EXIT_FAILURE);
    exit(status);
}

void print_regs(struct user_regs_struct *regs)
{
    printf("rdi: " HEX_FORMAT "    rsi: " HEX_FORMAT "  orig_rax: %lld\n", regs->XDI, regs->XSI, regs->OXAX);
    printf("rdx: " HEX_FORMAT "    rcx: " HEX_FORMAT "\n", regs->XDX, regs->XCX);
    printf("rax: " HEX_FORMAT "    rbx: " HEX_FORMAT "\n", regs->XAX, regs->XBX);
#ifdef __x86_64__
    printf("r8 : " HEX_FORMAT "    r9 : " HEX_FORMAT "\n", regs->r8, regs->r9);
#endif
#ifndef FOR_IDA
    printf("rsp: " HEX_FORMAT "    rip: " HEX_FORMAT "\n", regs->XSP, regs->XIP);
#else
#ifdef __x86_64__
    if ((size_t)(regs->XIP - global_image_base_addr) < 0x2000000)
        printf("rsp: " HEX_FORMAT "    rip: " HEX_FORMAT " (%#llx)\n", regs->XSP, regs->XIP, regs->XIP - global_image_base_addr);
    else
        printf("rsp: " HEX_FORMAT "    rip: " HEX_FORMAT "\n", regs->XSP, regs->XIP);
#elif __i386__
    if ((size_t)(regs->XIP - global_image_base_addr) < 0x2000000)
        printf("rsp: " HEX_FORMAT "    rip: " HEX_FORMAT " (%#lx)\n", regs->XSP, regs->XIP, regs->XIP - global_image_base_addr);
    else
        printf("rsp: " HEX_FORMAT "    rip: " HEX_FORMAT "\n", regs->XSP, regs->XIP);
#endif
#endif // !FOR_IDA
}

void gdb_attach(int pid, int sig)
{
    // interupt(pid);
    if(sig == SIGSTOP)
    {
        kill(pid, SIGSTOP);
    }
    detach(pid);
    update_tmp_pid(pid);
    while(1)
    {
        wait_for_signal(pid, SIGTRAP);
    }
}

void set_heap_addr(int pid, size_t addr)
{
    struct user_regs_struct regs;
    int length = 0x21000;
    int i = 0;
    while(1)
    {

        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        {
            PERROR("ptrace");
            exit_handle(EXIT_FAILURE);
        }
        
        wait_for_signal(pid, SIGTRAP);
        getregs(pid, &regs);

#ifdef __x86_64__
        if(regs.XAX == -38 && regs.OXAX == SYS_brk)
        {
            regs.rdi = (size_t)addr;
            regs.rsi = length;
            regs.rdx = 3;
            regs.r10 = 0x22;
            regs.r8 = -1,
            regs.r9 = 0;
            regs.OXAX = SYS_mmap;
            setregs(pid, &regs);
            break;
        }
#elif __i386__

        if(regs.XAX == -38 && regs.OXAX == SYS_brk)
        {
            regs.ebx = (size_t)addr;
            regs.ecx = length;
            regs.edx = 3;
            regs.esi = 0x22;
            regs.edi = -1,
            regs.OXAX = SYS_mmap;
            setregs(pid, &regs);
            break;
        }
#endif
    }

    while(1)
    {

        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        {
            PERROR("ptrace");
            exit_handle(EXIT_FAILURE);
        }
        
        wait_for_signal(pid, SIGTRAP);
        getregs(pid, &regs);

#ifdef __x86_64__
        if(regs.XAX == -38 && regs.OXAX == SYS_brk)
        {
            regs.OXAX = -1;
            setregs(pid, &regs);
            if(regs.XDI != 0)
            {
                break;
            }

            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            {
                PERROR("ptrace");
                exit_handle(EXIT_FAILURE);
            }
            
            wait_for_signal(pid, SIGTRAP);
            getregs(pid, &regs);
            regs.XAX = addr;
            setregs(pid, &regs);
        }
#elif __i386__

        if(regs.XAX == -38 && regs.OXAX == SYS_brk)
        {
            regs.OXAX = -1;
            setregs(pid, &regs);
            if(regs.XBX != 0)
            {
                break;
            }

            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            {
                PERROR("ptrace");
                exit_handle(EXIT_FAILURE);
            }
            
            wait_for_signal(pid, SIGTRAP);
            getregs(pid, &regs);
            regs.XAX = addr;
            setregs(pid, &regs);
        }
#endif
    }

    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
    {
        PERROR("ptrace");
        exit_handle(EXIT_FAILURE);
    }
    
    wait_for_signal(pid, SIGTRAP);
    getregs(pid, &regs);
    regs.XAX = addr + length;
    setregs(pid, &regs);
}

int break_syscall(int pid, size_t syscall_num)
{
     struct user_regs_struct regs;
    int i = 0;
    while(1)
    {

        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        {
            PERROR("ptrace");
            exit_handle(EXIT_FAILURE);
        }
        
        wait_for_signal(pid, SIGTRAP);
        getregs(pid, &regs);
        if(regs.XAX == -38 && regs.OXAX == syscall_num)
        {
            break;
        }
    }
}

void set_libc_addr(int pid, size_t addr)
{
    struct user_regs_struct regs;
    while(1)
    {

        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        {
            PERROR("ptrace");
            exit_handle(EXIT_FAILURE);
        }
        
        wait_for_signal(pid, SIGTRAP);
        getregs(pid, &regs);
#ifdef __x86_64__
        if(regs.XAX == -38 && regs.OXAX == SYS_mmap && regs.XDI == 0 && regs.XSI > 0x100000)
        {
            regs.XDI = addr;
            setregs(pid, &regs);
            break;
        }
#elif __i386__
        if(regs.XAX == -38 && regs.OXAX == SYS_mmap && regs.XBX == 0 && regs.XCX > 0x100000)
        {
            regs.XBX = addr;
            setregs(pid, &regs);
            break;
        }
#endif
    }
}

void wait_for_signal(int pid, int sig)
{
    int wstatus;
    struct user_regs_struct regs;
    waitpid(pid, &wstatus, 0);
    if (WSTOPSIG(wstatus) != sig)
    {
        if (WIFEXITED(wstatus))
        {
            DPRINTF("exited, status=%d\n", WEXITSTATUS(wstatus));
        }
        else if (WIFSIGNALED(wstatus))
        {
            if (WTERMSIG(wstatus) == SIGSEGV)
            {
                getregs(pid, &regs);
                print_regs(&regs);
                DPUTS("EXCEPTION_ACCESS_VIOLATION (SIGSEGV):    The thread tried to read from or write to a virtual address for which it does not have the appropriate access.\n");
            }
            else if (WTERMSIG(wstatus) == SIGABRT)
            {
                getregs(pid, &regs);
                print_regs(&regs);
                DPUTS("EXCEPTION_ABORT (SIGABRT):    The thread received a SIGABRT.\n");
            }
            else
            {
                DPRINTF("killed by signal %d\n", WTERMSIG(wstatus));
            }
        }
        else if (WIFSTOPPED(wstatus))
        {
            if (WSTOPSIG(wstatus) == SIGSEGV)
            {
                getregs(pid, &regs);
                print_regs(&regs);
                DPUTS("EXCEPTION_ACCESS_VIOLATION (SIGSEGV):    The thread tried to read from or write to a virtual address for which it does not have the appropriate access.\n");
            }
            else if (WSTOPSIG(wstatus) == SIGABRT)
            {
                getregs(pid, &regs);
                print_regs(&regs);
                DPUTS("EXCEPTION_ABORT (SIGABRT):    The thread received a SIGABRT.\n");
            }
            else
            {
                DPRINTF("stopped by signal %d\n", WSTOPSIG(wstatus));
            }
        }
        else if (WIFCONTINUED(wstatus))
        {
            DPRINTF("%s\n", "continued");
        }
        exit_handle(EXIT_FAILURE);
    }
}

void interupt(int pid)
{
    int wstatus;
    kill(pid, SIGINT);
    wait_for_signal(pid, SIGINT);
}

void *trace_mmap(int pid, void *addr, size_t length, int prot)
{
    struct user_regs_struct bak, regs;
    size_t instruction, new_instruction;
    getregs(pid, &regs);

    instruction = peekdata(pid, regs.XIP);
#ifdef __x86_64__
    new_instruction = 0xcc050f;
#elif __i386__
    new_instruction = 0xcc80cd;
#endif
    pokedata(pid, regs.XIP, new_instruction);
#ifdef __x86_64__
    regs.rdi = (size_t)addr;
    regs.rsi = length;
    regs.rdx = prot;
    regs.r10 = 0x22;
    regs.r8 = -1,
    regs.r9 = 0;
    regs.rax = SYS_mmap;
#elif __i386__
    regs.ebx = (size_t)addr;
    regs.ecx = length;
    regs.edx = prot;
    regs.esi = 0x22;
    regs.edi = -1,
    regs.eax = SYS_mmap;
#endif
    setregs(pid, &regs);
    continue_(pid);
    wait_for_signal(pid, SIGTRAP);
    getregs(pid, &regs);
    pokedata(pid, bak.XIP, instruction);
    setregs(pid, &bak);
    return (void *)regs.XAX;
}

void *trace_mprotect(int pid, void *addr, size_t length, int prot)
{
    struct user_regs_struct bak, regs;
    size_t instruction, new_instruction;
    getregs(pid, &regs);

    instruction = peekdata(pid, regs.XIP);
#ifdef __x86_64__
    new_instruction = 0xcc050f;
#elif __i386__
    new_instruction = 0xcc80cd;
#endif
    pokedata(pid, regs.XIP, new_instruction);
#ifdef __x86_64__
    regs.rdi = (size_t)addr;
    regs.rsi = length;
    regs.rdx = prot;
    regs.rax = SYS_mprotect;
#elif __i386__
    regs.ebx = (size_t)addr;
    regs.ecx = length;
    regs.edx = prot;
    regs.eax = SYS_mprotect;
#endif
    setregs(pid, &regs);
    continue_(pid);
    wait_for_signal(pid, SIGTRAP);
    getregs(pid, &regs);
    pokedata(pid, bak.XIP, instruction);
    setregs(pid, &bak);
    return (void *)regs.XAX;
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
        exit_handle(EXIT_FAILURE);
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
        exit_handle(EXIT_FAILURE);
    }
}

void setregs(int pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1)
    {
        PERROR("ptrace");
        exit_handle(EXIT_FAILURE);
    }
}

void pokedata(int pid, size_t addr, size_t vaule)
{
    if (ptrace(PTRACE_POKEDATA, pid, addr, vaule) == -1)
    {
        PERROR("ptrace");
        exit_handle(EXIT_FAILURE);
    }
}

size_t peekdata(int pid, size_t addr)
{
    size_t value;
    value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (value == -1 && errno != 0)
    {
        PERROR("ptrace");
        exit_handle(EXIT_FAILURE);
    }
    return value;
}

void detach(int pid)
{
    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1)
    {
        PERROR("ptrace");
        exit_handle(EXIT_FAILURE);
    }
}

void continue_(int pid)
{
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
    {
        PERROR("ptrace");
        exit_handle(EXIT_FAILURE);
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
        exit_handle(EXIT_FAILURE);
    }

    if (!pid)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
        {
            PERROR("ptrace");
            exit_handle(EXIT_FAILURE);
        }

        if (__traceme_hook)
        {
            __traceme_hook();
        }

        kill(getpid(), SIGSTOP);

        execv(new_args[0], new_args);
        PERROR("execv");
        exit_handle(EXIT_FAILURE);
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

            if (regs.OXAX == SYS_execve)
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

int restore_break_point(int pid)
{
    struct user_regs_struct regs;
    size_t value, rip;
    int index, wstatus;

    getregs(pid, &regs);
    rip = regs.XIP - 1;

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

    regs.XIP = rip;
    setregs(pid, &regs);
    pokedata(pid, rip, global_point[index].previous_byte);

    return 0;
}

int continue_break_point(int pid)
{
    struct user_regs_struct regs;
    size_t value, rip;
    int index, wstatus;

    restore_break_point(pid);

    getregs(pid, &regs);
    rip = regs.XIP;

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
    

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
    {
        PERROR("ptrace");
        exit_handle(EXIT_FAILURE);
    }
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus))
    {
        DPRINTF("exited, status=%d\n", WEXITSTATUS(wstatus));
        exit_handle(EXIT_FAILURE);
    }
    else if (WIFSIGNALED(wstatus))
    {
        DPRINTF("killed by signal %d\n", WTERMSIG(wstatus));
        exit_handle(EXIT_FAILURE);
    }
    else if (WIFSTOPPED(wstatus))
    {
        if (WSTOPSIG(wstatus) != SIGTRAP)
        {
            fprintf(stderr, "Error has happened at %s:%d (func: %s)\n", __FILE__, __LINE__, __func__);
            fprintf(stderr, "stopped by signal %d\n", WSTOPSIG(wstatus));
            getregs(pid, &regs);
            print_regs(&regs);
            exit_handle(EXIT_FAILURE);
        }
    }
    else if (WIFCONTINUED(wstatus))
    {
        DPRINTF("%s\n", "continued");
        exit_handle(EXIT_FAILURE);
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
#ifdef __x86_64__
            sscanf(buf, "%lx", &addr);
#elif __i386__
            sscanf(buf, "%x", &addr);
#endif
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
    memset(exename, 0, sizeof(exename));
    memset(path, 0, sizeof(path));
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    readlink(path, exename, sizeof(exename));

    global_image_base_addr = get_addr(pid, exename);
    return global_image_base_addr;
}

void print_hex(unsigned char *addr, int size, int mode)
{
    int i, ii;
    unsigned long long temp;
    switch (mode)
    {
    case 0:
        for (i = 0; i < size;)
        {
            for (ii = 0; i < size && ii < 8; i++, ii++)
            {
                printf("%02X ", addr[i]);
            }
            printf("    ");
            for (ii = 0; i < size && ii < 8; i++, ii++)
            {
                printf("%02X ", addr[i]);
            }
            puts("");
        }
        break;

    case 1:
        for (i = 0; i < size;)
        {
            temp = *(unsigned long long *)(addr + i);
            for (ii = 0; i < size && ii < 8; i++, ii++)
            {
                printf("%02X ", addr[i]);
            }
            printf("    ");
            printf("0x%llx\n", temp);
        }
        break;
    }
}

#endif
