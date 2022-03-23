

## Example

A made-to-measure debuger.

```c++
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
```

### output

The first terminal:

```
$ gdbpwn
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Attaching to process 61261
Reading symbols from /home/ex/tracer/examples/output...
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...
...
 RAX  0xfffffffffffffe00
 RBX  0x5650283a0260 (__libc_csu_init) ◂— endbr64 
 RCX  0x7f51c4bf90a7 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x1
 RDI  0x1
 RSI  0x5650283a100a ◂— 0x7200770020006f /* 'o' */
 R8   0x0
 R9   0x7f51c4d09d50 ◂— endbr64 
 R10  0x7f51c4d25f68 ◂— 0x6ffffff0
 R11  0x246
 R12  0x5650283a0060 (_start) ◂— endbr64 
 R13  0x7ffde5be27a0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffde5be26b0 ◂— 0x0
 RSP  0x7ffde5be26a8 —▸ 0x5650283a01bf (main+118) ◂— mov    edx, 1
 RIP  0x7f51c4bf90a7 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */

```

The second terminal:

```
$ make
...
$ ./output_trace 
hell[TRACE INFO]: pid 61261 : Detached  ../tracer.h:923

```

### uid

```
$ make
...
$ objdump -d -M intel uid
...
0000000000001169 <main>:
    1169:	f3 0f 1e fa          	endbr64 
    116d:	55                   	push   rbp
    116e:	48 89 e5             	mov    rbp,rsp
    1171:	e8 ea fe ff ff       	call   1060 <getuid@plt>
    1176:	89 c6                	mov    esi,eax
    1178:	48 8d 3d 85 0e 00 00 	lea    rdi,[rip+0xe85]        # 2004 <_IO_stdin_used+0x4>
    117f:	b8 00 00 00 00       	mov    eax,0x0
    1184:	e8 e7 fe ff ff       	call   1070 <printf@plt>
    1189:	b8 00 00 00 00       	mov    eax,0x0
    118e:	5d                   	pop    rbp
    118f:	c3                   	ret        
...
$ ./uid
uid: 1000
$ ./uid_trace 
image_addr: 0x55a7ed1ec000 (94179726114816)
[TRACE INFO]: pid 61046 : Stopped at breakpoint 0x55a7ed1ed176  ../tracer.h:1077
uid: 1234
[TRACE INFO]: pid 61046 : exited, status=0  ../tracer.h:1050
[TRACE ERROR]: wait() == -1  (No child processes)  ../tracer.h:1069
```

### lib

The first terminal:

```
$ gdbpwn
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Attaching to process 62645
...
 RAX  0xfffffffffffffe00
 RBX  0xc
 RCX  0x7f5d20e100a7 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0xc
 RDI  0x1
 RSI  0x55faee2772a0 ◂— 'hello world\n'
 R8   0x0
 R9   0x7c
 R10  0x7f5d20eeebe0 —▸ 0x55faee2776a0 ◂— 0x0
 R11  0x246
 R12  0xc
 R13  0x7f5d20eef6a0 (_IO_2_1_stdout_) ◂— 0xfbad2a84
 R14  0x7f5d20eeb4a0 (_IO_file_jumps) ◂— 0x0
 R15  0x7f5d20eea8a0 ◂— 0x0
 RBP  0x55faee2772a0 ◂— 'hello world\n'
 RSP  0x7ffe02c7c3b8 —▸ 0x7f5d20d90ebd (_IO_file_write+45) ◂— test   rax, rax
 RIP  0x7f5d20e100a7 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
...
pwndbg> vmmap
...
    0x55faee277000     0x55faee298000 rw-p    21000 0      [heap]
    0x7f5d20d02000     0x7f5d20d24000 r--p    22000 0      /tmp/libc.so.6
    0x7f5d20d24000     0x7f5d20e9c000 r-xp   178000 22000  /tmp/libc.so.6
    0x7f5d20e9c000     0x7f5d20eea000 r--p    4e000 19a000 /tmp/libc.so.6
    0x7f5d20eea000     0x7f5d20eee000 r--p     4000 1e7000 /tmp/libc.so.6
    0x7f5d20eee000     0x7f5d20ef0000 rw-p     2000 1eb000 /tmp/libc.so.6
```

The second terminal:

```
$ cp /usr/lib/x86_64-linux-gnu/libc.so.6 /tmp/libc.so.6
$ make
...
$ ./lib_trace 
image_addr: 0x55faedb24000 (94536218066944)
[TRACE INFO]: pid 62645 : Detached  ../tracer.h:923


```