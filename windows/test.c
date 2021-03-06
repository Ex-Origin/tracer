#define _CRT_SECURE_NO_WARNINGS
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <windows.h>
#include "tracer.h"

int main(int argc, char** argv)
{
    long long i, j = 0, len, result;
    char buf[0x100], * command = ".\\add.exe";
    size_t image_addr;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    CONTEXT Regs;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    traceme(command, &pi);

    image_addr = get_image_addr(&pi);
    printf("image_addr: %#p\n", (char*)image_addr);

    install_break_point(&pi, image_addr + 0x1041);
    ResumeThread(pi.hThread);

    printf("dwProcessId: %d\n", pi.dwProcessId);

    while (TRUE)
    {
        wait_for_signal(&pi, SIGTRAP);
        if (restore_break_point(&pi) == 0)
        {
            getregs(&pi, &Regs);
            Regs.XAX = 12;
            setregs(&pi, &Regs);
        }
        continue_(&pi);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}