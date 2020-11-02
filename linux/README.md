
## UPDATE


### 2020-11-02:

1. `set_libc_addr`(int pid, size_t addr): Set library address at the beginning of the child process. It will fail to call the function after the finished of libc loading.
2. `set_heap_addr`(int pid, size_t addr): Set heap address at the beginning of the initial malloc. Same as above.

3. `gdb_attach`(int pid, int sig): Just detach the child process to make it freedom, if `sig` is `SIGSTOP`, then the process will be suspended to wait for gdb attaching.

4. `break_syscall`(int pid, size_t syscall_num): Monitoring syscall number until there is a required `syscall_num`.

