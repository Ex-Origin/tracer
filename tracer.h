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

/**
 * Breakpoint
 *
 * option:
 *
 *   INS: Install addr
 *   DEL: Remove addr and recover register
 *   ALL: Remove all and recover register
 *   EXI: Is existed
 *   SIN: Single step
 */
int bre(int pid, int option, size_t addr);

/**
 * @brief ptrace(PTRACE_GETREGS, pid, 0, regs);
 *
 * Error: return -1
 */
int getregs(int pid, struct user_regs_struct *regs);

/**
 * @brief ptrace(PTRACE_SETREGS, pid, 0, regs);
 *
 * Error: return -1
 */
int setregs(int pid, struct user_regs_struct *regs);

// ptrace(PTRACE_PEEKDATA, pid, addr, 0)
size_t peekdata(int pid, size_t addr);

// ptrace(PTRACE_POKEDATA, pid, addr, value)
int pokedata(int pid, size_t addr, size_t value);

// ptrace(PTRACE_SINGLESTEP, pid, 0, 0)
int singlestep(int pid);

/**
 * @brief Break at syscall
 *
 * @param pid
 * @return int
 * Syscall number, or error -1
 */
int break_syscall(int pid);

// grep search /proc/%d/maps
ssize_t get_addr(int pid, char *search);

void gdb_attach(int pid);

void pwntools_attach(int pid);

// continue to run
int con(int pid);

/**
 * @brief Wait for breakpoints
 *
 * @param pid
 * Excepted pid
 * @return int
 * register->rip
 */
int wai(int pid);

/**
 * Search needle string in SYS_wirte.
 * Note: It will be searched in the line output. 
 *
 * Return: It will call gdb_attach(SIGSTOP) without return.
 **/
int find_output(int pid, char *search);

// Force to write into memory while ignoring the memory property.
int patched(int pid, char *in_buf, unsigned int size, size_t child_addr);

int interrupt(int pid);

int trace_read(int pid, void *out_buf, int size, size_t child_addr);
int trace_write(int pid, void *in_buf, int size, size_t child_addr);
int trace_gets(int pid, char *out_buf, int out_buf_size, size_t child_addr);
int set_libc_path(int pid, char *libc_path);

// Show more information
#ifdef DEBUG
#define DPRINTF printf
#else
#define DPRINTF(...)
#endif

/**
 * The value must be TRUE, or the program will break down.
 * e.g., the value is thing what the program need to do.
 **/
#define CHECK(value)                                            \
    {                                                           \
        if ((value) == 0)                                       \
        {                                                       \
            fprintf(stderr, "%s:%d: %m\n", __FILE__, __LINE__); \
            abort();                                            \
        }                                                       \
    }

#define LOGV(variable)                           \
    {                                            \
        printf("" #variable ": 0x%llx (%llu)\n", \
               (unsigned long long)(variable),   \
               (unsigned long long)(variable));  \
    }

/**
 * Get the syscall parameters
 * 
 *  position: 
 *  0: Syscall number
 *  1: The first parameter
 *  2: The second parameter
 *  ...
 */
size_t get_syscall_arg(struct user_regs_struct *regs, int position)
{
    size_t result = 0;
#ifdef __x86_64__
    switch (position)
    {
    case 0:
        result = regs->orig_rax;
        break;
    case 1:
        result = regs->rdi;
        break;
    case 2:
        result = regs->rsi;
        break;
    case 3:
        result = regs->rdx;
        break;
    case 4:
        result = regs->r10;
        break;
    case 5:
        result = regs->r8;
        break;
    case 6:
        result = regs->r9;
        break;
    default:
        result = -1;
        fprintf(stderr, "[TRACE ERROR] Unknown position (%m)  %s:%d\n", __FILE__, __LINE__);
        break;
    }
#elif __i386__
    switch (position)
    {
    case 0:
        if(regs->eax == -38)
        {
            // Syscall start
            result = regs->orig_eax;
        }
        else
        {
            // Syscall end
            result = regs->orig_eax | 0x80000000;
        }
        break;
    case 1:
        result = regs->ebx;
        break;
    case 2:
        result = regs->ecx;
        break;
    case 3:
        result = regs->edx;
        break;
    case 4:
        result = regs->esi;
        break;
    case 5:
        result = regs->edi;
        break;
    case 6:
        result = regs->ebp;
        break;
    default:
        result = -1;
        fprintf(stderr, "[TRACE ERROR] Unknown position (%m)  %s:%d\n", __FILE__, __LINE__);
        break;
    }
#else
    result = -1;
    error("UNSUPPORTED ARCHITECTURE");
#endif
    return result;
}

size_t get_syscall_rax(struct user_regs_struct *regs)
{
    size_t result = 0;
#ifdef __x86_64__
    result = regs->rax;
#elif __i386__
    result = regs->eax;
#else
    result = -1;
    error("UNSUPPORTED ARCHITECTURE");
#endif
    return result;
}

size_t get_register_ip(struct user_regs_struct *regs)
{
    size_t result = 0;
#ifdef __x86_64__
    result = regs->rip;
#elif __i386__
    result = regs->eip;
#else
    result = -1;
    error("UNSUPPORTED ARCHITECTURE");
#endif
    return result;
}

int set_register_ip(struct user_regs_struct *regs, size_t value)
{
    size_t result = 0;
#ifdef __x86_64__
    result = 0;
    regs->rip = value;
#elif __i386__
    result = 0;
    regs->eip value;
#else
    result = -1;
    error("UNSUPPORTED ARCHITECTURE");
#endif
    return result;
}

int handle_stopped_signal(int pid, int wstatus)
{
    switch (WSTOPSIG(wstatus))
    {
    case SIGINT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGINT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGILL:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGILL  %s:%d\n", pid, __FILE__, __LINE__);
        printf("[TRACE INFO]: Killing %d because of SIGILL  %s:%d\n", pid, __FILE__, __LINE__);
        ptrace(PTRACE_KILL, pid);
        break;
    case SIGABRT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGABRT  %s:%d\n", pid, __FILE__, __LINE__);
        printf("[TRACE INFO]: Killing %d because of SIGABRT  %s:%d\n", pid, __FILE__, __LINE__);
        ptrace(PTRACE_KILL, pid);
        break;
    case SIGFPE:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGFPE  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGSEGV:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGSEGV  %s:%d\n", pid, __FILE__, __LINE__);
        printf("[TRACE INFO]: Killing %d because of SIGSEGV  %s:%d\n", pid, __FILE__, __LINE__);
        ptrace(PTRACE_KILL, pid);
        break;
    case SIGTERM:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGTERM  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGHUP:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGHUP  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGQUIT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGQUIT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTRAP:
        DPRINTF("[TRACE DEBUG]: pid %5d : stopped by signal SIGTRAP  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGKILL:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGKILL  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGPIPE:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGPIPE  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGALRM:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGALRM  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGPOLL:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGPOLL  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGCHLD:
        DPRINTF("[TRACE DEBUG]: pid %5d : stopped by signal SIGCHLD  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGSTKFLT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGSTKFLT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGPWR:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGPWR  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGBUS:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGBUS  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGSYS:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGSYS  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGURG:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGURG  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGSTOP:
        DPRINTF("[TRACE INFO]: pid %5d : stopped by signal SIGSTOP  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTSTP:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGTSTP  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGCONT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGCONT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTTIN:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGTTIN  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTTOU:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGTTOU  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGXFSZ:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGXFSZ  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGXCPU:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGXCPU  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGVTALRM:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGVTALRM  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGPROF:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGPROF  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGUSR1:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGUSR1  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGUSR2:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGUSR2  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGWINCH:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGWINCH  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTRAP | 0x80:
        /**
         * From ptrace(2), setting PTRACE_O_TRACESYSGOOD has the effect
         * of delivering SIGTRAP | 0x80 as the signal number for syscall
         * stops. This allows easily distinguishing syscall stops from
         * genuine SIGTRAP signals.
         **/
        DPRINTF("[TRACE DEBUG]: pid %5d : stopped by signal SIGTRAP|0x80  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    default:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : stopped by unknown signal %d (%#x)  %s:%d\n",
                pid, WSTOPSIG(wstatus), WSTOPSIG(wstatus), __FILE__, __LINE__);
        break;
    }

    return 0;
}

int handle_killed_signal(int pid, int wstatus)
{
    switch (WTERMSIG(wstatus))
    {
    case SIGINT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGINT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGILL:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGILL  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGABRT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGABRT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGFPE:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGFPE  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGSEGV:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGSEGV  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTERM:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTERM  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGHUP:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGHUP  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGQUIT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGQUIT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTRAP:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTRAP  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGKILL:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGKILL  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGPIPE:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGPIPE  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGALRM:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGALRM  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGPOLL:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGPOLL  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGCHLD:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGCHLD  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGSTKFLT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGSTKFLT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGPWR:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGPWR  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGBUS:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGBUS  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGSYS:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGSYS  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGURG:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGURG  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGSTOP:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGSTOP  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTSTP:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTSTP  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGCONT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGCONT  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTTIN:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTTIN  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGTTOU:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTTOU  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGXFSZ:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGXFSZ  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGXCPU:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGXCPU  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGVTALRM:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGVTALRM  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGPROF:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGPROF  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGUSR1:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGUSR1  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGUSR2:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGUSR2  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    case SIGWINCH:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGWINCH  %s:%d\n", pid, __FILE__, __LINE__);
        break;
    default:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal %d (%#x)  %s:%d\n", pid, WTERMSIG(wstatus), WTERMSIG(wstatus), __FILE__, __LINE__);
        break;
    }
    return 0;
}

int getregs(int pid, struct user_regs_struct *regs)
{
    int status, r;

    interrupt(pid);

    for (errno = 0, r = 0; r != -1 && ptrace(PTRACE_GETREGS, pid, 0, regs) == -1 && errno == ESRCH;)
    {
        r = waitpid(pid, &status, __WALL | WNOHANG);
        DPRINTF("[TRACE DEBUG]: pid %5d : PTRACE_GETREGS failed with ESRCH  %s:%d\n", pid, __FILE__, __LINE__);
    }
    if (errno != 0)
    {
        fprintf(stderr, "[TRACE ERROR]: pid %5d : PTRACE_GETREGS failed : %m  %s:%d\n", pid, __FILE__, __LINE__);
        return -1;
    }
    return r;
}

int setregs(int pid, struct user_regs_struct *regs)
{
    int status, r;

    interrupt(pid);

    for (errno = 0, r = 0; r != -1 && ptrace(PTRACE_SETREGS, pid, 0, regs) == -1 && errno == ESRCH;)
    {
        r = waitpid(pid, &status, __WALL | WNOHANG);
        DPRINTF("[TRACE DEBUG]: pid %5d : PTRACE_SETREGS failed with ESRCH  %s:%d\n", pid, __FILE__, __LINE__);
    }
    if (errno != 0)
    {
        fprintf(stderr, "[TRACE ERROR]: pid %5d : PTRACE_SETREGS failed : %m  %s:%d\n", pid, __FILE__, __LINE__);
        return -1;
    }
    return r;
}

size_t peekdata(int pid, size_t addr)
{
    int status, r;
    size_t value;

    interrupt(pid);

    for (errno = 0, r = 0; r != -1 && (value = ptrace(PTRACE_PEEKDATA, pid, addr, 0)) == -1 && errno == ESRCH;)
    {
        r = waitpid(pid, &status, __WALL | WNOHANG);
        DPRINTF("[TRACE DEBUG]: pid %5d : PTRACE_PEEKDATA failed with ESRCH  %s:%d\n", pid, __FILE__, __LINE__);
    }
    if (errno != 0)
    {
        fprintf(stderr, "[TRACE ERROR]: pid %5d : PTRACE_PEEKDATA failed : %m  %s:%d\n", pid, __FILE__, __LINE__);
        return -1;
    }
    return value;
}

int pokedata(int pid, size_t addr, size_t value)
{
    int status, r;

    interrupt(pid);

    for (errno = 0, r = 0; r != -1 && ptrace(PTRACE_POKEDATA, pid, addr, value) == -1 && errno == ESRCH;)
    {
        r = waitpid(pid, &status, __WALL | WNOHANG);
        DPRINTF("[TRACE DEBUG]: pid %5d : PTRACE_POKEDATA failed with ESRCH  %s:%d\n", pid, __FILE__, __LINE__);
    }
    if (errno != 0)
    {
        fprintf(stderr, "[TRACE ERROR]: pid %5d : PTRACE_POKEDATA failed : %m  %s:%d\n", pid, __FILE__, __LINE__);
        return -1;
    }
    return r;
}

int singlestep(int pid)
{
    int status;
    int recv_pid;

    interrupt(pid);

    for(recv_pid = 0, status = 0; recv_pid != -1 && (recv_pid == pid && WIFSTOPPED(status) != 0 && (WSTOPSIG(status) & 0x7f) == SIGTRAP) == 0;)
    {
        if(ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        {
            // Wait 
            CHECK(errno == ESRCH);
        }

        recv_pid = wait(&status);

        if(recv_pid != 0 && recv_pid != -1)
        {
            if (WIFEXITED(status))
            {
                printf("[TRACE INFO]: pid %5d : exited, status=%d  %s:%d\n", recv_pid, WEXITSTATUS(status), __FILE__, __LINE__);
            }
            else if (WIFSIGNALED(status))
            {
                handle_killed_signal(recv_pid, status);
            }
            else if (WIFSTOPPED(status))
            {
                handle_stopped_signal(recv_pid, status);
            }
            else if (WIFCONTINUED(status))
            {
                printf("[TRACE INFO]: pid %5d : continued  %s:%d\n", recv_pid, __FILE__, __LINE__);
            }
        }
    }

    if(recv_pid == -1)
    {
        fprintf(stderr, "[TRACE ERROR]: wait() == -1  (%m)  %s:%d\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    return recv_pid;
}

int interrupt(int pid)
{

    if(ptrace(PTRACE_LISTEN, pid, 0, 0) == 0)
    {
        CHECK(ptrace(PTRACE_INTERRUPT, pid, 0, 0) != -1);
    }
    
    return 0;
}

// ptrace(PTRACE_DETACH, pid, 0, 0)
#define detach(pid)                                      \
    {                                                    \
        CHECK(ptrace(PTRACE_DETACH, (pid), 0, 0) != -1); \
    }

char *syscall_name[440];
int break_syscall(int pid)
{
    struct user_regs_struct regs;
    int status;
    int recv_pid; // Received pid
    size_t syscall_num;
    int i;
    static int count = 0;

    interrupt(pid);

    for(recv_pid = 0, status = 0; recv_pid != -1 && (recv_pid == pid && WIFSTOPPED(status) != 0 && (WSTOPSIG(status) & 0x7f) == SIGTRAP) == 0;)
    {
        if(ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        {
            // Wait 
            CHECK(errno == ESRCH);
        }

        recv_pid = wait(&status);

        if(recv_pid != 0 && recv_pid != -1)
        {
            if (WIFEXITED(status))
            {
                printf("[TRACE INFO]: pid %5d : exited, status=%d  %s:%d\n", recv_pid, WEXITSTATUS(status), __FILE__, __LINE__);
            }
            else if (WIFSIGNALED(status))
            {
                handle_killed_signal(recv_pid, status);
            }
            else if (WIFSTOPPED(status))
            {
                handle_stopped_signal(recv_pid, status);
            }
            else if (WIFCONTINUED(status))
            {
                printf("[TRACE INFO]: pid %5d : continued  %s:%d\n", recv_pid, __FILE__, __LINE__);
            }
        }
    }

    if(recv_pid == -1)
    {
        fprintf(stderr, "[TRACE ERROR]: wait() == -1  (%m)  %s:%d\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    getregs(pid, &regs);
    syscall_num = get_syscall_arg(&regs, 0);

    // Prevent array overflow
    CHECK((sizeof(syscall_name)/sizeof(char*)) > syscall_num);
    DPRINTF("[TRACE DEBUG]: pid %5d : PTRACE_SYSCALL return (%s)  %s:%d\n", pid, syscall_name[syscall_num], __FILE__, __LINE__);
    return syscall_num;
}

int traceme(char **new_args)
{
    int pid, wstatus;
    int syscall_num;

    CHECK((pid = fork()) != -1);

    // Child process
    if (pid == 0)
    {
        CHECK(prctl(PR_SET_PTRACER, getppid()) != -1);
        raise(SIGSTOP);

        DPRINTF("[TRACE DEBUG]: Child pid %d  %s:%d\n", getpid(), __FILE__, __LINE__);
        CHECK(execv(new_args[0], new_args) != -1);
        exit(EXIT_SUCCESS);
    }

    CHECK(ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_EXITKILL) != -1);

    for (syscall_num = break_syscall(pid); syscall_num != SYS_execve; syscall_num = break_syscall(pid))
        ;

    // After execve
    CHECK(singlestep(pid) != -1);

    return pid;
}

int get_line(int fd, char *buf, int size)
{
    int i, ret_val, end;

    for(i = 0, ret_val = 1, end = 0; i < size && ret_val > 0 && end == 0; i++)
    {
        ret_val = read(fd, buf + i, 1);
        if(ret_val == 1 && (buf[i] == '\n' || buf[i] == '\0'))
        {
            end = 1;
        }
    }
    if(i - 1 < size && i - 1 >= 0 && buf[i-1] == '\n')
    {
        buf[i-1] = '\0';
    }

    return i;
}

ssize_t get_addr(int pid, char *search)
{
    char buf[0x1000];
    char path[0x100];
    ssize_t addr;
    int result;
    char *target;
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    CHECK((fd = open(path, O_RDONLY)) != -1);

    for(target = NULL; target == NULL && get_line(fd, buf, sizeof(buf) - 1) > 0;)
    {
        memset(buf, 0, sizeof(buf));
        target = strstr(buf, search);
    }
    close(fd);

    CHECK(target != NULL && buf[0] != '\0');

#ifdef __x86_64__
    sscanf(buf, "%lx", &addr);
#elif __i386__
    sscanf(buf, "%x", &addr);
#endif

    CHECK(addr != -1);

    return addr;
}

int bre(int pid, int option, size_t addr)
{
#define INS 0 // Install addr
#define DEL 1 // Remove addr
#define ALL 2 // Remove all
#define EXI 3 // Is existed
#define SIN 4 // Singlestep
    static size_t address[0x100] = {0};
    static unsigned char reserved[0x100];
    int i;
    size_t value = 0;
    struct user_regs_struct regs;
    // Register->rip
    size_t ip;

    interrupt(pid);

    getregs(pid, &regs);
    ip = get_register_ip(&regs);

    switch (option)
    {
    case INS:
        for (i = 0; i < sizeof(address) / sizeof(size_t) && address[i]; i++)
            ;
        // Find a empty position
        if (i < sizeof(address) / sizeof(size_t))
        {
            address[i] = addr;
            value = peekdata(pid, addr);
            reserved[i] = (char)value;
            value = (value & (~0xff)) | 0xcc; // int3 instruction
            pokedata(pid, addr, value);
            DPRINTF("[TRACE DEBUG]: pid %5d : install breakpoiont %p  %s:%d\n",
                    pid, (char *)addr, __FILE__, __LINE__);
        }
        else
        {
            fprintf(stderr, "FULL  %s:%d: %m\n", __FILE__, __LINE__);
            return -1;
        }
        break;
    case DEL:
        // Find breakpoint
        for (i = 0; i < sizeof(address) / sizeof(size_t) && address[i] != addr; i++)
            ;
        // Remove
        if (i < sizeof(address) / sizeof(size_t) && address[i] == addr && addr != 0)
        {
            if (ip - 1 == addr)
            { // Now it is on a breakpoint
                set_register_ip(&regs, ip - 1);

                // Recover register
                setregs(pid, &regs);
                DPRINTF("[TRACE DEBUG]: pid %5d : remove breakpoiont (%p) and recover register  %s:%d\n",
                        pid, (char *)addr, __FILE__, __LINE__);
            }
            else
            {
                DPRINTF("[TRACE DEBUG]: pid %5d : remove breakpoiont %p  %s:%d\n",
                        pid, (char *)addr, __FILE__, __LINE__);
            }

            value = peekdata(pid, addr);
            value = (value & (~0xff)) | reserved[i]; // Recovery
            pokedata(pid, addr, value);
            address[i] = 0;
            reserved[i] = 0;
        }
        else
        {
            DPRINTF("[TRACE DEBUG]: pid %5d : DEL not existed %p  %s:%d\n",
                    pid, (char *)addr, __FILE__, __LINE__);
            return -1;
        }
        break;
    case ALL:
        for (i = 0; i < sizeof(address) / sizeof(size_t); i++)
        {
            if (address[i])
            {
                if (ip - 1 == address[i])
                { // Now it is on a breakpoint
                    set_register_ip(&regs, ip - 1);

                    // Recover register
                    setregs(pid, &regs);
                    DPRINTF("[TRACE DEBUG]: pid %5d : remove breakpoiont (%p) and recover register  %s:%d\n",
                            pid, (char *)address[i], __FILE__, __LINE__);
                }
                else
                {
                    DPRINTF("[TRACE DEBUG]: pid %5d : remove breakpoiont %p  %s:%d\n",
                            pid, (char *)address[i], __FILE__, __LINE__);
                }

                value = peekdata(pid, address[i]);
                value = (value & (~0xff)) | reserved[i]; // Recovery
                pokedata(pid, address[i], value);
                address[i] = 0;
                reserved[i] = 0;
            }
        }
        break;
    case EXI:
        // Find breakpoint
        for (i = 0; i < sizeof(address) / sizeof(size_t) && address[i] != addr; i++)
            ;
        if (i < sizeof(address) / sizeof(size_t) && address[i] == addr && addr != 0)
        {
            DPRINTF("[TRACE DEBUG]: pid %5d : EXISTED %p  %s:%d\n",
                    pid, (char *)ip, __FILE__, __LINE__);
            return addr;
        }
        else
        {
            DPRINTF("[TRACE DEBUG]: pid %5d : NOT EXISTED %p  %s:%d\n",
                    pid, (char *)ip, __FILE__, __LINE__);
            return 0;
        }
        break;
    case SIN:
        // Find breakpoint
        for (i = 0; i < sizeof(address) / sizeof(size_t) && address[i] != addr; i++)
            ;
        if (i < sizeof(address) / sizeof(size_t) && addr != 0 && address[i] == ip - 1) // Whether now is on the breakpoint
        {
            value = peekdata(pid, address[i]);
            value = (value & (~0xff)) + reserved[i];
            pokedata(pid, address[i], value);

            set_register_ip(&regs, ip - 1);

            setregs(pid, &regs);
            singlestep(pid);
            getregs(pid, &regs);

            value = peekdata(pid, address[i]);
            reserved[i] = (char)value;
            value = (value & (~0xff)) | 0xcc; // int3 instruction
            pokedata(pid, address[i], value);

            ip = get_register_ip(&regs);
            DPRINTF("[TRACE DEBUG]: pid %5d : SIN into %p  %s:%d\n",
                    pid, (char *)ip, __FILE__, __LINE__);
            return ip;
        }
        else
        {
            DPRINTF("[TRACE DEBUG]: pid %5d : NOT SIN at %p  %s:%d\n",
                    pid, (char *)ip, __FILE__, __LINE__);
            return 0;
        }
    default:
        fprintf(stderr, "Unknown option  %s:%d: %m\n", __FILE__, __LINE__);
        break;
    }

    return 0;
}

#define PID_FILE "/tmp/gdb_pid"
void gdb_attach(int pid)
{
    FILE *fp;
    char buf[0x100];
    int result;
    // Received pid
    int recv_pid;
    int wstatus;

    bre(pid, ALL, 0);

    CHECK(kill(pid, SIGSTOP) != -1);
    
    printf("[TRACE INFO]: pid %5d : Detached  %s:%d\n", pid, __FILE__, __LINE__);
    detach(pid);

    CHECK((fp = fopen(PID_FILE, "w")) != NULL);

    result = snprintf(buf, sizeof(buf), "%d", pid);

    fwrite(buf, 1, result, fp);
    fclose(fp);

    for (recv_pid = wait(&wstatus); recv_pid != -1; recv_pid = wait(&wstatus))
    {
        if (WIFEXITED(wstatus))
        {
            printf("[TRACE INFO]: pid %5d : exited, wstatus=%d  %s:%d\n", recv_pid, WEXITSTATUS(wstatus), __FILE__, __LINE__);
        }
        else if (WIFSIGNALED(wstatus))
        {
            handle_killed_signal(recv_pid, wstatus);
        }
        else if (WIFSTOPPED(wstatus))
        {
            handle_stopped_signal(recv_pid, wstatus);
        }
        else if (WIFCONTINUED(wstatus))
        {
            DPRINTF("[TRACE DEBUG]: pid %5d : continued  %s:%d\n", recv_pid, __FILE__, __LINE__);
        }
    }
}

void pwntools_attach(int pid)
{
    FILE *fp;
    char buf[0x100];
    int result;
    // Received pid
    int recv_pid;
    int status;

    bre(pid, ALL, 0);

    interrupt(pid);

    printf("[TRACE INFO]: pid %5d : Detached  %s:%d\n", pid, __FILE__, __LINE__);
    detach(pid);

    CHECK((fp = fopen(PID_FILE, "w")) != NULL);

    result = snprintf(buf, sizeof(buf), "%d", pid);

    fwrite("\0\0\0\0", 4, 1, fp);
    fwrite(buf, 1, result, fp);
    fclose(fp);

    for (recv_pid = wait(&status); recv_pid != -1; recv_pid = wait(&status))
    {
        if (WIFEXITED(status))
        {
            printf("[TRACE INFO]: pid %5d : exited, status=%d  %s:%d\n", recv_pid, WEXITSTATUS(status), __FILE__, __LINE__);
        }
        else if (WIFSIGNALED(status))
        {
            handle_killed_signal(recv_pid, status);
        }
        else if (WIFSTOPPED(status))
        {
            handle_stopped_signal(recv_pid, status);
        }
        else if (WIFCONTINUED(status))
        {
            printf("[TRACE INFO]: pid %5d : continued  %s:%d\n", recv_pid, __FILE__, __LINE__);
        }
    }
    fprintf(stderr, "[TRACE ERROR] recv_pid -1 %m  %s:%d\n", __FILE__, __LINE__);
}

int con(int pid)
{
    size_t value;
    size_t ip;
    struct user_regs_struct regs;

    interrupt(pid);

    getregs(pid, &regs);
    ip = get_register_ip(&regs);

    bre(pid, SIN, ip - 1);

    // Restart until continuing
    for (errno = 0; ptrace(PTRACE_CONT, pid, 0, 0) != -1 && errno != ESRCH;)
    {
        DPRINTF("[TRACE DEBUG]: pid %5d : PTRACE_CONT retry with errno(%d)  %s:%d\n",
                pid, errno, __FILE__, __LINE__);
    }

    return 0;
}

int wai(int pid)
{
    struct user_regs_struct regs = {0};
    size_t ip;
    int status, r;
    // Received pid
    int recv_pid;

    for (ip = 0, recv_pid = pid; recv_pid != -1 && bre(recv_pid, EXI, ip) == 0;)
    {
        con(pid);

        // Wait for SIGTRAP
        for(recv_pid = 0, status = 0; recv_pid != -1 && (recv_pid == pid && WIFSTOPPED(status) != 0 && (WSTOPSIG(status) & 0x7f) == SIGTRAP) == 0;)
        {
            if(ptrace(PTRACE_CONT, pid, 0, 0) == -1)
            {
                // Wait 
                CHECK(errno == ESRCH);
            }

            recv_pid = wait(&status);

            if(recv_pid != 0 && recv_pid != -1)
            {
                if (WIFEXITED(status))
                {
                    printf("[TRACE INFO]: pid %5d : exited, status=%d  %s:%d\n", recv_pid, WEXITSTATUS(status), __FILE__, __LINE__);
                }
                else if (WIFSIGNALED(status))
                {
                    handle_killed_signal(recv_pid, status);
                }
                else if (WIFSTOPPED(status))
                {
                    handle_stopped_signal(recv_pid, status);
                }
                else if (WIFCONTINUED(status))
                {
                    printf("[TRACE INFO]: pid %5d : continued  %s:%d\n", recv_pid, __FILE__, __LINE__);
                }
            }
        }

        if(recv_pid == -1)
        {
            fprintf(stderr, "[TRACE ERROR]: wait() == -1  (%m)  %s:%d\n", __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }

        getregs(recv_pid, &regs);
        ip = get_register_ip(&regs) - 1;
    }

    printf("[TRACE INFO]: pid %5d : Stopped at breakpoint %p  %s:%d\n", recv_pid, (char *)ip, __FILE__, __LINE__);

    return ip;
}

int patched(int pid, char *in_buf, unsigned int size, size_t child_addr)
{
    union
    {
        size_t number;
        char str[sizeof(size_t)];
    } value;
    int i;
    unsigned int patched_counts, patched_bits;
    size_t *patched_ptr;

    patched_counts = size / sizeof(void *);
    patched_bits = size % sizeof(void *);
    patched_ptr = (size_t *)in_buf;

    for (i = 0; i < patched_counts; i++)
    {
        pokedata(pid, child_addr + (i * sizeof(void *)), patched_ptr[i]);
    }

    if (patched_bits == 0)
    {
        return 0;
    }
    else
    {
        value.number = peekdata(pid, child_addr + (patched_counts * sizeof(void *)));
        for (i = 0; i < patched_bits; i++)
        {
            value.str[i] = in_buf[i + patched_counts * sizeof(void *)];
        }
        pokedata(pid, child_addr + (patched_counts * sizeof(void *)), value.number);
    }
    return 0;
}

int handle_write(char *buf, int buf_len, int pi, int pid, size_t arg1, size_t arg2, size_t arg3)
{
    int i;
    size_t value;

    for(i = 0; i < arg3 && pi < buf_len; i++, pi++)
    {
        value = peekdata(pid, arg2 + i) & 0xff;
        buf[pi] = value;
    }

    if(i - 1 >= 0 && pi < buf_len && pi - 1 >= 0 && (buf[pi - 1] == '\0' || buf[pi - 1] == '\n'))
    { // Check the string end
        return -1;
    }
    else
    {
        return pi;
    }
}

int handle_writev(char *buf, int buf_len, int pi, int pid, size_t arg1, size_t arg2, size_t arg3)
{
    struct iovec iov;
    int i, j;
    size_t value;
    int reserved_pi = pi;
    for(i = 0; i < arg3 && pi < buf_len; i++)
    {
        trace_read(pid, &iov, sizeof(iov), arg2 + i * sizeof(iov));
        for(j = 0; j < iov.iov_len && pi < buf_len; j++, pi++)
        {
            value = peekdata(pid, (size_t)iov.iov_base + j) & 0xff;
            buf[pi] = value;
        }
    }
    if(reserved_pi < pi && pi < buf_len && pi - 1 >= 0 && (buf[pi - 1] == '\0' || buf[pi - 1] == '\n'))
    { // Check the string end
        return -1;
    }
    else
    {
        return pi;
    }
    return 0;
}

int find_output(int pid, char *search)
{
    static char *find_output_page = NULL;
    struct user_regs_struct regs;
    int syscall_num;
    size_t arg1, arg2, arg3, regs_rax;
    int pi = 0;
#define FIND_OUTPUT_PAGE_LEN 0x100000

    if (find_output_page == NULL)
    {
        find_output_page = mmap(NULL, FIND_OUTPUT_PAGE_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(find_output_page != MAP_FAILED);
    }

    pi = 0;
    for (memset(find_output_page, 0, FIND_OUTPUT_PAGE_LEN); memmem(find_output_page, FIND_OUTPUT_PAGE_LEN, search, strlen(search)) == NULL;)
    {
        // again
        if(FIND_OUTPUT_PAGE_LEN == pi || pi == -1)
        {
            memset(find_output_page, 0, FIND_OUTPUT_PAGE_LEN);
            pi = 0;
        }

        // regs_rax != -38 : Find the syscall start
        for(syscall_num = -1, regs_rax = 0; (syscall_num != SYS_write && syscall_num != SYS_writev) || regs_rax != -38;)
        {
            syscall_num = break_syscall(pid);
            getregs(pid, &regs);
            regs_rax = get_syscall_rax(&regs);
        }

        switch (syscall_num)
        {
        case SYS_write:
            arg1 = get_syscall_arg(&regs, 1);
            arg2 = get_syscall_arg(&regs, 2);
            arg3 = get_syscall_arg(&regs, 3);
            pi = handle_write(find_output_page, FIND_OUTPUT_PAGE_LEN, pi, pid, arg1, arg2, arg3);
            break;
        case SYS_writev:
            arg1 = get_syscall_arg(&regs, 1);
            arg2 = get_syscall_arg(&regs, 2);
            arg3 = get_syscall_arg(&regs, 3);
            pi = handle_writev(find_output_page, FIND_OUTPUT_PAGE_LEN, pi, pid, arg1, arg2, arg3);
            break;
        case -1:
            fprintf(stderr, "[TRACE ERROR] Unhandled syscall number (%m)  %s:%d\n", __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        default:
            break;
        }
        DPRINTF("[TRACE DEBUG]: pid %5d : find_output(\"%s\")  %s:%d\n", pid, find_output_page, __FILE__, __LINE__);

    }

    gdb_attach(pid);
    return 0;
}

int trace_gets(int pid, char *out_buf, int out_buf_size, size_t child_addr)
{
    int i;
    size_t value;
    for (i = 0, value = -1; i < out_buf_size && value != 0; i++)
    {
        value = peekdata(pid, child_addr + i) & 0xff;
        value = value == '\n' ? 0 : value;
        out_buf[i] = value;
    }

    return i;
}

int trace_read(int pid, void *out_buf, int size, size_t child_addr)
{
    int i;
    char *buf = (char *)out_buf;
    for (i = 0; i < size; i++)
    {
        buf[i] = peekdata(pid, child_addr + i) & 0xff;
    }
    return i;
}

int trace_write(int pid, void *in_buf, int size, size_t child_addr)
{
    return patched(pid, in_buf, size, child_addr);
}

int set_libc_path(int pid, char *libc_path)
{
    struct user_regs_struct regs;
    char buf[0x1000];
    int syscall_num;
    size_t addr;
    size_t regs_rax;

    for (memset(buf, 0, sizeof(buf)); strstr(buf, "libc") == NULL;)
    {
        for(syscall_num = -1; syscall_num != SYS_open && syscall_num != SYS_openat; syscall_num = break_syscall(pid))
            ;

        getregs(pid, &regs);

        switch (syscall_num)
        {
        case SYS_open:
            addr = get_syscall_arg(&regs, 1);
            break;
        case SYS_openat:
            addr = get_syscall_arg(&regs, 2);
            break;
        default:
            fprintf(stderr, "[TRACE ERROR] Unhandled syscall number (%m)  %s%d\n", __FILE__, __LINE__);
            break;
        }

        memset(buf, 0, sizeof(buf));
        trace_gets(pid, buf, sizeof(buf), addr);
        DPRINTF("[TRACE DEBUG]: pid %5d : set_libc_path finds open(\"%s\")  %s:%d\n", pid, buf, __FILE__, __LINE__);
    }

    DPRINTF("[TRACE DEBUG]: pid %5d : set_libc_path changes open(\"%s\") to open(\"%s\")  %s:%d\n", pid, buf, libc_path, __FILE__, __LINE__);
    return patched(pid, libc_path, strlen(libc_path) + 1, addr);
}








#ifdef __x86_64__
char *syscall_name[] = {
    "SYS_read",
    "SYS_write",
    "SYS_open",
    "SYS_close",
    "SYS_stat",
    "SYS_fstat",
    "SYS_lstat",
    "SYS_poll",
    "SYS_lseek",
    "SYS_mmap",
    "SYS_mprotect",
    "SYS_munmap",
    "SYS_brk",
    "SYS_rt_sigaction",
    "SYS_rt_sigprocmask",
    "SYS_rt_sigreturn",
    "SYS_ioctl",
    "SYS_pread64",
    "SYS_pwrite64",
    "SYS_readv",
    "SYS_writev",
    "SYS_access",
    "SYS_pipe",
    "SYS_select",
    "SYS_sched_yield",
    "SYS_mremap",
    "SYS_msync",
    "SYS_mincore",
    "SYS_madvise",
    "SYS_shmget",
    "SYS_shmat",
    "SYS_shmctl",
    "SYS_dup",
    "SYS_dup2",
    "SYS_pause",
    "SYS_nanosleep",
    "SYS_getitimer",
    "SYS_alarm",
    "SYS_setitimer",
    "SYS_getpid",
    "SYS_sendfile",
    "SYS_socket",
    "SYS_connect",
    "SYS_accept",
    "SYS_sendto",
    "SYS_recvfrom",
    "SYS_sendmsg",
    "SYS_recvmsg",
    "SYS_shutdown",
    "SYS_bind",
    "SYS_listen",
    "SYS_getsockname",
    "SYS_getpeername",
    "SYS_socketpair",
    "SYS_setsockopt",
    "SYS_getsockopt",
    "SYS_clone",
    "SYS_fork",
    "SYS_vfork",
    "SYS_execve",
    "SYS_exit",
    "SYS_wait4",
    "SYS_kill",
    "SYS_uname",
    "SYS_semget",
    "SYS_semop",
    "SYS_semctl",
    "SYS_shmdt",
    "SYS_msgget",
    "SYS_msgsnd",
    "SYS_msgrcv",
    "SYS_msgctl",
    "SYS_fcntl",
    "SYS_flock",
    "SYS_fsync",
    "SYS_fdatasync",
    "SYS_truncate",
    "SYS_ftruncate",
    "SYS_getdents",
    "SYS_getcwd",
    "SYS_chdir",
    "SYS_fchdir",
    "SYS_rename",
    "SYS_mkdir",
    "SYS_rmdir",
    "SYS_creat",
    "SYS_link",
    "SYS_unlink",
    "SYS_symlink",
    "SYS_readlink",
    "SYS_chmod",
    "SYS_fchmod",
    "SYS_chown",
    "SYS_fchown",
    "SYS_lchown",
    "SYS_umask",
    "SYS_gettimeofday",
    "SYS_getrlimit",
    "SYS_getrusage",
    "SYS_sysinfo",
    "SYS_times",
    "SYS_ptrace",
    "SYS_getuid",
    "SYS_syslog",
    "SYS_getgid",
    "SYS_setuid",
    "SYS_setgid",
    "SYS_geteuid",
    "SYS_getegid",
    "SYS_setpgid",
    "SYS_getppid",
    "SYS_getpgrp",
    "SYS_setsid",
    "SYS_setreuid",
    "SYS_setregid",
    "SYS_getgroups",
    "SYS_setgroups",
    "SYS_setresuid",
    "SYS_getresuid",
    "SYS_setresgid",
    "SYS_getresgid",
    "SYS_getpgid",
    "SYS_setfsuid",
    "SYS_setfsgid",
    "SYS_getsid",
    "SYS_capget",
    "SYS_capset",
    "SYS_rt_sigpending",
    "SYS_rt_sigtimedwait",
    "SYS_rt_sigqueueinfo",
    "SYS_rt_sigsuspend",
    "SYS_sigaltstack",
    "SYS_utime",
    "SYS_mknod",
    "SYS_uselib",
    "SYS_personality",
    "SYS_ustat",
    "SYS_statfs",
    "SYS_fstatfs",
    "SYS_sysfs",
    "SYS_getpriority",
    "SYS_setpriority",
    "SYS_sched_setparam",
    "SYS_sched_getparam",
    "SYS_sched_setscheduler",
    "SYS_sched_getscheduler",
    "SYS_sched_get_priority_max",
    "SYS_sched_get_priority_min",
    "SYS_sched_rr_get_interval",
    "SYS_mlock",
    "SYS_munlock",
    "SYS_mlockall",
    "SYS_munlockall",
    "SYS_vhangup",
    "SYS_modify_ldt",
    "SYS_pivot_root",
    "SYS__sysctl",
    "SYS_prctl",
    "SYS_arch_prctl",
    "SYS_adjtimex",
    "SYS_setrlimit",
    "SYS_chroot",
    "SYS_sync",
    "SYS_acct",
    "SYS_settimeofday",
    "SYS_mount",
    "SYS_umount2",
    "SYS_swapon",
    "SYS_swapoff",
    "SYS_reboot",
    "SYS_sethostname",
    "SYS_setdomainname",
    "SYS_iopl",
    "SYS_ioperm",
    "SYS_create_module",
    "SYS_init_module",
    "SYS_delete_module",
    "SYS_get_kernel_syms",
    "SYS_query_module",
    "SYS_quotactl",
    "SYS_nfsservctl",
    "SYS_getpmsg",
    "SYS_putpmsg",
    "SYS_afs_syscall",
    "SYS_tuxcall",
    "SYS_security",
    "SYS_gettid",
    "SYS_readahead",
    "SYS_setxattr",
    "SYS_lsetxattr",
    "SYS_fsetxattr",
    "SYS_getxattr",
    "SYS_lgetxattr",
    "SYS_fgetxattr",
    "SYS_listxattr",
    "SYS_llistxattr",
    "SYS_flistxattr",
    "SYS_removexattr",
    "SYS_lremovexattr",
    "SYS_fremovexattr",
    "SYS_tkill",
    "SYS_time",
    "SYS_futex",
    "SYS_sched_setaffinity",
    "SYS_sched_getaffinity",
    "SYS_set_thread_area",
    "SYS_io_setup",
    "SYS_io_destroy",
    "SYS_io_getevents",
    "SYS_io_submit",
    "SYS_io_cancel",
    "SYS_get_thread_area",
    "SYS_lookup_dcookie",
    "SYS_epoll_create",
    "SYS_epoll_ctl_old",
    "SYS_epoll_wait_old",
    "SYS_remap_file_pages",
    "SYS_getdents64",
    "SYS_set_tid_address",
    "SYS_restart_syscall",
    "SYS_semtimedop",
    "SYS_fadvise64",
    "SYS_timer_create",
    "SYS_timer_settime",
    "SYS_timer_gettime",
    "SYS_timer_getoverrun",
    "SYS_timer_delete",
    "SYS_clock_settime",
    "SYS_clock_gettime",
    "SYS_clock_getres",
    "SYS_clock_nanosleep",
    "SYS_exit_group",
    "SYS_epoll_wait",
    "SYS_epoll_ctl",
    "SYS_tgkill",
    "SYS_utimes",
    "SYS_vserver",
    "SYS_mbind",
    "SYS_set_mempolicy",
    "SYS_get_mempolicy",
    "SYS_mq_open",
    "SYS_mq_unlink",
    "SYS_mq_timedsend",
    "SYS_mq_timedreceive",
    "SYS_mq_notify",
    "SYS_mq_getsetattr",
    "SYS_kexec_load",
    "SYS_waitid",
    "SYS_add_key",
    "SYS_request_key",
    "SYS_keyctl",
    "SYS_ioprio_set",
    "SYS_ioprio_get",
    "SYS_inotify_init",
    "SYS_inotify_add_watch",
    "SYS_inotify_rm_watch",
    "SYS_migrate_pages",
    "SYS_openat",
    "SYS_mkdirat",
    "SYS_mknodat",
    "SYS_fchownat",
    "SYS_futimesat",
    "SYS_newfstatat",
    "SYS_unlinkat",
    "SYS_renameat",
    "SYS_linkat",
    "SYS_symlinkat",
    "SYS_readlinkat",
    "SYS_fchmodat",
    "SYS_faccessat",
    "SYS_pselect6",
    "SYS_ppoll",
    "SYS_unshare",
    "SYS_set_robust_list",
    "SYS_get_robust_list",
    "SYS_splice",
    "SYS_tee",
    "SYS_sync_file_range",
    "SYS_vmsplice",
    "SYS_move_pages",
    "SYS_utimensat",
    "SYS_epoll_pwait",
    "SYS_signalfd",
    "SYS_timerfd_create",
    "SYS_eventfd",
    "SYS_fallocate",
    "SYS_timerfd_settime",
    "SYS_timerfd_gettime",
    "SYS_accept4",
    "SYS_signalfd4",
    "SYS_eventfd2",
    "SYS_epoll_create1",
    "SYS_dup3",
    "SYS_pipe2",
    "SYS_inotify_init1",
    "SYS_preadv",
    "SYS_pwritev",
    "SYS_rt_tgsigqueueinfo",
    "SYS_perf_event_open",
    "SYS_recvmmsg",
    "SYS_fanotify_init",
    "SYS_fanotify_mark",
    "SYS_prlimit64",
    "SYS_name_to_handle_at",
    "SYS_open_by_handle_at",
    "SYS_clock_adjtime",
    "SYS_syncfs",
    "SYS_sendmmsg",
    "SYS_setns",
    "SYS_getcpu",
    "SYS_process_vm_readv",
    "SYS_process_vm_writev",
    "SYS_kcmp",
    "SYS_finit_module",
    "SYS_sched_setattr",
    "SYS_sched_getattr",
    "SYS_renameat2",
    "SYS_seccomp",
    "SYS_getrandom",
    "SYS_memfd_create",
    "SYS_kexec_file_load",
    "SYS_bpf",
    "SYS_execveat",
    "SYS_userfaultfd",
    "SYS_membarrier",
    "SYS_mlock2",
    "SYS_copy_file_range",
    "SYS_preadv2",
    "SYS_pwritev2",
    "SYS_pkey_mprotect",
    "SYS_pkey_alloc",
    "SYS_pkey_free",
    "SYS_statx",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "SYS_io_uring_setup",
    "SYS_io_uring_enter",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "SYS_faccessat2",
};
#elif __i386__
char *syscall_name[] = {
    "SYS_restart_syscall",
    "SYS_exit",
    "SYS_fork",
    "SYS_read",
    "SYS_write",
    "SYS_open",
    "SYS_close",
    "SYS_waitpid",
    "SYS_creat",
    "SYS_link",
    "SYS_unlink",
    "SYS_execve",
    "SYS_chdir",
    "SYS_time",
    "SYS_mknod",
    "SYS_chmod",
    "SYS_lchown",
    "SYS_break",
    "SYS_oldstat",
    "SYS_lseek",
    "SYS_getpid",
    "SYS_mount",
    "SYS_umount",
    "SYS_setuid",
    "SYS_getuid",
    "SYS_stime",
    "SYS_ptrace",
    "SYS_alarm",
    "SYS_oldfstat",
    "SYS_pause",
    "SYS_utime",
    "SYS_stty",
    "SYS_gtty",
    "SYS_access",
    "SYS_nice",
    "SYS_ftime",
    "SYS_sync",
    "SYS_kill",
    "SYS_rename",
    "SYS_mkdir",
    "SYS_rmdir",
    "SYS_dup",
    "SYS_pipe",
    "SYS_times",
    "SYS_prof",
    "SYS_brk",
    "SYS_setgid",
    "SYS_getgid",
    "SYS_signal",
    "SYS_geteuid",
    "SYS_getegid",
    "SYS_acct",
    "SYS_umount2",
    "SYS_lock",
    "SYS_ioctl",
    "SYS_fcntl",
    "SYS_mpx",
    "SYS_setpgid",
    "SYS_ulimit",
    "SYS_oldolduname",
    "SYS_umask",
    "SYS_chroot",
    "SYS_ustat",
    "SYS_dup2",
    "SYS_getppid",
    "SYS_getpgrp",
    "SYS_setsid",
    "SYS_sigaction",
    "SYS_sgetmask",
    "SYS_ssetmask",
    "SYS_setreuid",
    "SYS_setregid",
    "SYS_sigsuspend",
    "SYS_sigpending",
    "SYS_sethostname",
    "SYS_setrlimit",
    "SYS_getrlimit",
    "SYS_getrusage",
    "SYS_gettimeofday",
    "SYS_settimeofday",
    "SYS_getgroups",
    "SYS_setgroups",
    "SYS_select",
    "SYS_symlink",
    "SYS_oldlstat",
    "SYS_readlink",
    "SYS_uselib",
    "SYS_swapon",
    "SYS_reboot",
    "SYS_readdir",
    "SYS_mmap",
    "SYS_munmap",
    "SYS_truncate",
    "SYS_ftruncate",
    "SYS_fchmod",
    "SYS_fchown",
    "SYS_getpriority",
    "SYS_setpriority",
    "SYS_profil",
    "SYS_statfs",
    "SYS_fstatfs",
    "SYS_ioperm",
    "SYS_socketcall",
    "SYS_syslog",
    "SYS_setitimer",
    "SYS_getitimer",
    "SYS_stat",
    "SYS_lstat",
    "SYS_fstat",
    "SYS_olduname",
    "SYS_iopl",
    "SYS_vhangup",
    "SYS_idle",
    "SYS_vm86old",
    "SYS_wait4",
    "SYS_swapoff",
    "SYS_sysinfo",
    "SYS_ipc",
    "SYS_fsync",
    "SYS_sigreturn",
    "SYS_clone",
    "SYS_setdomainname",
    "SYS_uname",
    "SYS_modify_ldt",
    "SYS_adjtimex",
    "SYS_mprotect",
    "SYS_sigprocmask",
    "SYS_create_module",
    "SYS_init_module",
    "SYS_delete_module",
    "SYS_get_kernel_syms",
    "SYS_quotactl",
    "SYS_getpgid",
    "SYS_fchdir",
    "SYS_bdflush",
    "SYS_sysfs",
    "SYS_personality",
    "SYS_afs_syscall",
    "SYS_setfsuid",
    "SYS_setfsgid",
    "SYS__llseek",
    "SYS_getdents",
    "SYS__newselect",
    "SYS_flock",
    "SYS_msync",
    "SYS_readv",
    "SYS_writev",
    "SYS_getsid",
    "SYS_fdatasync",
    "SYS__sysctl",
    "SYS_mlock",
    "SYS_munlock",
    "SYS_mlockall",
    "SYS_munlockall",
    "SYS_sched_setparam",
    "SYS_sched_getparam",
    "SYS_sched_setscheduler",
    "SYS_sched_getscheduler",
    "SYS_sched_yield",
    "SYS_sched_get_priority_max",
    "SYS_sched_get_priority_min",
    "SYS_sched_rr_get_interval",
    "SYS_nanosleep",
    "SYS_mremap",
    "SYS_setresuid",
    "SYS_getresuid",
    "SYS_vm86",
    "SYS_query_module",
    "SYS_poll",
    "SYS_nfsservctl",
    "SYS_setresgid",
    "SYS_getresgid",
    "SYS_prctl",
    "SYS_rt_sigreturn",
    "SYS_rt_sigaction",
    "SYS_rt_sigprocmask",
    "SYS_rt_sigpending",
    "SYS_rt_sigtimedwait",
    "SYS_rt_sigqueueinfo",
    "SYS_rt_sigsuspend",
    "SYS_pread64",
    "SYS_pwrite64",
    "SYS_chown",
    "SYS_getcwd",
    "SYS_capget",
    "SYS_capset",
    "SYS_sigaltstack",
    "SYS_sendfile",
    "SYS_getpmsg",
    "SYS_putpmsg",
    "SYS_vfork",
    "SYS_ugetrlimit",
    "SYS_mmap2",
    "SYS_truncate64",
    "SYS_ftruncate64",
    "SYS_stat64",
    "SYS_lstat64",
    "SYS_fstat64",
    "SYS_lchown32",
    "SYS_getuid32",
    "SYS_getgid32",
    "SYS_geteuid32",
    "SYS_getegid32",
    "SYS_setreuid32",
    "SYS_setregid32",
    "SYS_getgroups32",
    "SYS_setgroups32",
    "SYS_fchown32",
    "SYS_setresuid32",
    "SYS_getresuid32",
    "SYS_setresgid32",
    "SYS_getresgid32",
    "SYS_chown32",
    "SYS_setuid32",
    "SYS_setgid32",
    "SYS_setfsuid32",
    "SYS_setfsgid32",
    "SYS_pivot_root",
    "SYS_mincore",
    "SYS_madvise",
    "SYS_getdents64",
    "SYS_fcntl64",
    "not implemented",
    "not implemented",
    "SYS_gettid",
    "SYS_readahead",
    "SYS_setxattr",
    "SYS_lsetxattr",
    "SYS_fsetxattr",
    "SYS_getxattr",
    "SYS_lgetxattr",
    "SYS_fgetxattr",
    "SYS_listxattr",
    "SYS_llistxattr",
    "SYS_flistxattr",
    "SYS_removexattr",
    "SYS_lremovexattr",
    "SYS_fremovexattr",
    "SYS_tkill",
    "SYS_sendfile64",
    "SYS_futex",
    "SYS_sched_setaffinity",
    "SYS_sched_getaffinity",
    "SYS_set_thread_area",
    "SYS_get_thread_area",
    "SYS_io_setup",
    "SYS_io_destroy",
    "SYS_io_getevents",
    "SYS_io_submit",
    "SYS_io_cancel",
    "SYS_fadvise64",
    "not implemented",
    "SYS_exit_group",
    "SYS_lookup_dcookie",
    "SYS_epoll_create",
    "SYS_epoll_ctl",
    "SYS_epoll_wait",
    "SYS_remap_file_pages",
    "SYS_set_tid_address",
    "SYS_timer_create",
    "SYS_timer_settime",
    "SYS_timer_gettime",
    "SYS_timer_getoverrun",
    "SYS_timer_delete",
    "SYS_clock_settime",
    "SYS_clock_gettime",
    "SYS_clock_getres",
    "SYS_clock_nanosleep",
    "SYS_statfs64",
    "SYS_fstatfs64",
    "SYS_tgkill",
    "SYS_utimes",
    "SYS_fadvise64_64",
    "SYS_vserver",
    "SYS_mbind",
    "SYS_get_mempolicy",
    "SYS_set_mempolicy",
    "SYS_mq_open",
    "SYS_mq_unlink",
    "SYS_mq_timedsend",
    "SYS_mq_timedreceive",
    "SYS_mq_notify",
    "SYS_mq_getsetattr",
    "SYS_kexec_load",
    "SYS_waitid",
    "not implemented",
    "SYS_add_key",
    "SYS_request_key",
    "SYS_keyctl",
    "SYS_ioprio_set",
    "SYS_ioprio_get",
    "SYS_inotify_init",
    "SYS_inotify_add_watch",
    "SYS_inotify_rm_watch",
    "SYS_migrate_pages",
    "SYS_openat",
    "SYS_mkdirat",
    "SYS_mknodat",
    "SYS_fchownat",
    "SYS_futimesat",
    "SYS_fstatat64",
    "SYS_unlinkat",
    "SYS_renameat",
    "SYS_linkat",
    "SYS_symlinkat",
    "SYS_readlinkat",
    "SYS_fchmodat",
    "SYS_faccessat",
    "SYS_pselect6",
    "SYS_ppoll",
    "SYS_unshare",
    "SYS_set_robust_list",
    "SYS_get_robust_list",
    "SYS_splice",
    "SYS_sync_file_range",
    "SYS_tee",
    "SYS_vmsplice",
    "SYS_move_pages",
    "SYS_getcpu",
    "SYS_epoll_pwait",
    "SYS_utimensat",
    "SYS_signalfd",
    "SYS_timerfd_create",
    "SYS_eventfd",
    "SYS_fallocate",
    "SYS_timerfd_settime",
    "SYS_timerfd_gettime",
    "SYS_signalfd4",
    "SYS_eventfd2",
    "SYS_epoll_create1",
    "SYS_dup3",
    "SYS_pipe2",
    "SYS_inotify_init1",
    "SYS_preadv",
    "SYS_pwritev",
    "SYS_rt_tgsigqueueinfo",
    "SYS_perf_event_open",
    "SYS_recvmmsg",
    "SYS_fanotify_init",
    "SYS_fanotify_mark",
    "SYS_prlimit64",
    "SYS_name_to_handle_at",
    "SYS_open_by_handle_at",
    "SYS_clock_adjtime",
    "SYS_syncfs",
    "SYS_sendmmsg",
    "SYS_setns",
    "SYS_process_vm_readv",
    "SYS_process_vm_writev",
    "SYS_kcmp",
    "SYS_finit_module",
    "SYS_sched_setattr",
    "SYS_sched_getattr",
    "SYS_renameat2",
    "SYS_seccomp",
    "SYS_getrandom",
    "SYS_memfd_create",
    "SYS_bpf",
    "SYS_execveat",
    "SYS_socket",
    "SYS_socketpair",
    "SYS_bind",
    "SYS_connect",
    "SYS_listen",
    "SYS_accept4",
    "SYS_getsockopt",
    "SYS_setsockopt",
    "SYS_getsockname",
    "SYS_getpeername",
    "SYS_sendto",
    "SYS_sendmsg",
    "SYS_recvfrom",
    "SYS_recvmsg",
    "SYS_shutdown",
    "SYS_userfaultfd",
    "SYS_membarrier",
    "SYS_mlock2",
    "SYS_copy_file_range",
    "SYS_preadv2",
    "SYS_pwritev2",
    "SYS_pkey_mprotect",
    "SYS_pkey_alloc",
    "SYS_pkey_free",
    "SYS_statx",
    "SYS_arch_prctl",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "SYS_clock_gettime64",
    "SYS_clock_settime64",
    "SYS_clock_adjtime64",
    "SYS_clock_getres_time64",
    "SYS_clock_nanosleep_time64",
    "SYS_timer_gettime64",
    "SYS_timer_settime64",
    "SYS_timerfd_gettime64",
    "SYS_timerfd_settime64",
    "SYS_utimensat_time64",
    "SYS_pselect6_time64",
    "SYS_ppoll_time64",
    "not implemented",
    "SYS_io_pgetevents_time64",
    "SYS_recvmmsg_time64",
    "SYS_mq_timedsend_time64",
    "SYS_mq_timedreceive_time64",
    "SYS_semtimedop_time64",
    "SYS_rt_sigtimedwait_time64",
    "SYS_futex_time64",
    "SYS_sched_rr_get_interval_time64",
    "not implemented",
    "SYS_io_uring_setup",
    "SYS_io_uring_enter",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "not implemented",
    "SYS_faccessat2",
};
#endif



#endif