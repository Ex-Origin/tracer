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
ssize_t get_image_addr(int pid);
void detach(int pid);
void continue_(int pid);
void getregs(int pid, struct user_regs_struct *regs);
void setregs(int pid, struct user_regs_struct *regs);
size_t peekdata(int pid, size_t addr);
void pokedata(int pid, size_t addr, size_t vaule);
ssize_t get_addr(int pid, char *search);
void update_tmp_pid(int pid);
```

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
