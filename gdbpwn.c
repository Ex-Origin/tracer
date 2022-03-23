#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/inotify.h>

#define GDB_PID "/tmp/gdb_pid"

int gdb_pid;

int main()
{
    int status, pid_fd, fd, wd, length, i;
    char *gdb_args[10] = {"/usr/bin/gdb", "-p", NULL, "-q", "-x", "/tmp/gdb_script", NULL};
    char pid_buf[0x100];
    struct inotify_event event[10];

    gdb_pid = -1;

    if (access(GDB_PID, F_OK) != 0)
    {
        pid_fd = open(GDB_PID, O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK, 0666);
        if (pid_fd == -1)
        {
            perror("open");
            exit(EXIT_FAILURE);
        }
        close(pid_fd);
    }

    signal(SIGTTOU, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    fd = inotify_init();
    wd = inotify_add_watch(fd, GDB_PID, IN_MODIFY);

    while (1)
    {
        length = read(fd, &event, sizeof(event));
        pid_fd = open(GDB_PID, O_RDONLY);
        memset(pid_buf, 0, sizeof(pid_buf));
        read(pid_fd, pid_buf, sizeof(pid_buf));
        close(pid_fd);
        if (pid_buf[0] == 0)
        {
            continue;
        }
        gdb_args[2] = pid_buf;

        if (gdb_pid != -1)
        {
            kill(gdb_pid, SIGTERM);
        }
        gdb_pid = fork();

        if (gdb_pid == 0)
        {
            execv(gdb_args[0], gdb_args);
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
