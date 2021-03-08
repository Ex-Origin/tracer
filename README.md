# tracer

A made-to-measure debuger.

### Linux

```c++
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

/*
 * 
 * Set library address at the beginning of the child process. It will fail to call the function after the finished of libc loading.
 * 
 * Require: suspended process.
 * Return: running process.
 * 
 **/
void set_libc_addr(int pid, size_t addr);
// If sig is SIGSTOP, the child process will be blocked.
void gdb_attach(int pid, int sig);

/*
 * 
 * Set heap address at the beginning of the initial malloc.
 * 
 * Require: suspended process.
 * Return: running process.
 * 
 **/
void set_heap_addr(int pid, size_t addr);

/*
 * Monitoring syscall number until there is a required syscall_num, It will run until the required syscall happen.
 * 
 * Argument: If syscall_num is -1, then it will stop at any next syscall.
 * 
 * Note: the process must be suspended, or not it will be failed.
 * 
 * Require: suspended process.
 * Return: suspended process.
 * 
 **/
int break_syscall(int pid, size_t syscall_num);
```

#### count.c

Record the total number of instructions taken by the program.


### Windows

```c++
int traceme(char* cmdline, PROCESS_INFORMATION* out);
void print_regs(CONTEXT* Regs);
size_t get_image_addr(PROCESS_INFORMATION* pi);
void print_hex(unsigned char* addr, int size, int mode);
void getregs(PROCESS_INFORMATION* pi, CONTEXT* Regs);
void setregs(PROCESS_INFORMATION* pi, CONTEXT* Regs);
void wait_for_signal(PROCESS_INFORMATION* pi, int sig);
size_t peekdata(PROCESS_INFORMATION* pi, size_t addr);
void pokedata(PROCESS_INFORMATION* pi, size_t addr, size_t value);
void single_step(PROCESS_INFORMATION* pi);
int install_break_point(PROCESS_INFORMATION* pi, size_t addr);
void detach(PROCESS_INFORMATION* pi);
void continue_(PROCESS_INFORMATION* pi);
int restore_break_point(PROCESS_INFORMATION* pi);
int continue_break_point(PROCESS_INFORMATION* pi);
```

### AARCH64

#### example.c

Show how to use ptrace in aarch64.

