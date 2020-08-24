/*
 *
 * Author: Ex
 * Time: 2020-08-25
 * Email: 2462148389@qq.com
 *
 **/
#ifndef TRACER_H_
#define TRACER_H_

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>

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

void (*__traceme_hook)();

#define FOR_IDA

#ifdef _WIN64
#define XIP Rip
#define XAX Rax
#define XBX Rbx
#define XCX Rcx
#define XDX Rdx
#define XDI Rdi
#define XSI Rsi
#define XSP Rsp
#elif _WIN32
#define XIP Eip
#define XAX Eax
#define XBX Ebx
#define XCX Ecx
#define XDX Edx
#define XDI Edi
#define XSI Esi
#define XSP Esp
#endif

size_t global_image_base_addr = 0;

#define ERROR_REPORT()                                                                                                                    \
    {                                                                                                                                     \
        fprintf(stderr, "Error has happened at %s:%d (func: %s) , GetLastError() -> %d\n", __FILE__, __LINE__, __func__, GetLastError()); \
    }

#define ASSERT(expression, expected)                 \
    {                                                \
        if (expression != expected)                  \
        {                                            \
            ERROR_REPORT();                          \
            fprintf(stderr, "-> " #expression "\n"); \
            exit(EXIT_FAILURE);                      \
        }                                            \
    }

#define SIGTRAP 5

#define LOGV(variable)                           \
    {                                            \
        printf("" #variable ": 0x%llx (%llu)\n", \
               (unsigned long long)(variable),   \
               (unsigned long long)(variable));  \
    }

void print_regs(CONTEXT* Regs)
{
	printf("rcx: %16llx    rdx: %16llx\n", Regs->XCX, Regs->XDX);
#ifdef _WIN64
	printf("r8 : %16llx    r9 : %16llx\n", Regs->R8, Regs->R9);
#endif
	printf("rax: %16llx    rbx: %16llx\n", Regs->XAX, Regs->XBX);
	printf("rdi: %16llx    rsi: %16llx\n", Regs->XDI, Regs->XSI);
	printf("rdi: %16llx    rsi: %16llx\n", Regs->XDI, Regs->XSI);
#ifndef FOR_IDA
	printf("rsp: %16llx    rip: %16llx\n", Regs->XSP, Regs->XIP);
#else
#ifdef _WIN64
	if ((size_t)(Regs->XIP - global_image_base_addr + 0x140001000) < 0x2000000)
		printf("rsp: %16llx    rip: %16llx (%#llx)\n", Regs->XSP, Regs->XIP, Regs->XIP - global_image_base_addr + 0x140001000);
	else
		printf("rsp: %16llx    rip: %16llx\n", Regs->XSP, Regs->XIP);
#elif _WIN32
	if ((size_t)(Regs->XIP - global_image_base_addr + 0x140001000) < 0x401000)
		printf("rsp: %16llx    rip: %16llx (%#llx)\n", Regs->XSP, Regs->XIP, Regs->XIP - global_image_base_addr + 0x401000);
	else
		printf("rsp: %16llx    rip: %16llx\n", Regs->XSP, Regs->XIP);
#endif
#endif // !FOR_IDA
}

int traceme(char* cmdline, PROCESS_INFORMATION* out)
{
	STARTUPINFO si;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(out, sizeof(PROCESS_INFORMATION));

	ASSERT(CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, DEBUG_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, out), TRUE);
	ASSERT(DebugSetProcessKillOnExit(TRUE) != 0, 1);
	if (__traceme_hook)
	{
		__traceme_hook();
	}

	return 0;
}

size_t get_image_addr(PROCESS_INFORMATION* pi)
{
	unsigned char* addr, * image_addr;
	NTSTATUS(*NtQueryInformationProcessHook)
		(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	PROCESS_BASIC_INFORMATION info;
	size_t result;

	ZeroMemory(&info, sizeof(info));
	*(size_t*)&NtQueryInformationProcessHook = (size_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
	//result = NtQueryInformationProcessHook(hProcess, ProcessBasicInformation, &info, sizeof(info), NULL);
	ASSERT(NtQueryInformationProcessHook(pi->hProcess, ProcessBasicInformation, &info, sizeof(info), NULL), 0);
	addr = (unsigned char*)info.PebBaseAddress;
	ASSERT(ReadProcessMemory(pi->hProcess, addr + (sizeof(PVOID) * 2), &image_addr, sizeof(PVOID), &result) != 0, 1);
	ASSERT(result == sizeof(PVOID), 1);
	global_image_base_addr = (size_t)image_addr;

	return global_image_base_addr;
}

void print_hex(unsigned char* addr, int size, int mode)
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
			temp = *(unsigned long long*)(addr + i);
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

void getregs(PROCESS_INFORMATION* pi, CONTEXT* Regs)
{
	ASSERT(SuspendThread(pi->hThread) >= 0, 1);
	ZeroMemory(Regs, sizeof(CONTEXT));
	Regs->ContextFlags = CONTEXT_FULL;
	ASSERT(GetThreadContext(pi->hThread, Regs) != 0, 1);
	ASSERT(ResumeThread(pi->hThread) >= 0, 1);
}

void setregs(PROCESS_INFORMATION* pi, CONTEXT* Regs)
{
	ASSERT(SuspendThread(pi->hThread) >= 0, 1);
	Regs->ContextFlags = CONTEXT_FULL;
	ASSERT(SetThreadContext(pi->hThread, Regs) != 0, 1);
	ASSERT(ResumeThread(pi->hThread) >= 0, 1);
}

void wait_for_signal(PROCESS_INFORMATION* pi, int sig)
{
	DEBUG_EVENT DebugEv;
	CONTEXT Regs;
	int TrapFlag;
	DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation
	long long result;
	//Regs.

	TrapFlag = FALSE;
	while (TrapFlag == FALSE)
	{
		// Wait for a debugging event to occur. The second parameter indicates
		// that the function does not return until a debugging event occurs.

		WaitForDebugEvent(&DebugEv, INFINITE);

		// Process the debugging event code.
		switch (DebugEv.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			// Process the exception code. When handling
			// exceptions, remember to set the continuation
			// status parameter (dwContinueStatus). This value
			// is used by the ContinueDebugEvent function.

			switch (DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
				printf("EXCEPTION_ACCESS_VIOLATION:    The thread tried to read from or write to a virtual address for which it does not have the appropriate access.\n\n");
				getregs(pi, &Regs);
				print_regs(&Regs);
				exit(EXIT_SUCCESS);
				break;

			case EXCEPTION_BREAKPOINT:
				ASSERT(DebugEv.dwProcessId == pi->dwProcessId, 1);
				ASSERT(DebugEv.dwThreadId == pi->dwThreadId, 1);
				TrapFlag = TRUE;
				break;

			case EXCEPTION_DATATYPE_MISALIGNMENT:
				printf("EXCEPTION_DATATYPE_MISALIGNMENT:    The thread tried to read or write data that is misaligned on hardware that does not provide alignment. "
					"For example, 16-bit values must be aligned on 2-byte boundaries; 32-bit values on 4-byte boundaries, and so on.\n\n");
				getregs(pi, &Regs);
				print_regs(&Regs);
				exit(EXIT_SUCCESS);
				break;

			case EXCEPTION_SINGLE_STEP:
				ASSERT(DebugEv.dwProcessId == pi->dwProcessId, 1);
				ASSERT(DebugEv.dwThreadId == pi->dwThreadId, 1);
				TrapFlag = TRUE;
				break;

			case DBG_CONTROL_C:
				ASSERT(TerminateProcess(pi->hProcess, 2) != 0, 1);
				exit(EXIT_SUCCESS);
				break;

			case EXCEPTION_FLT_INVALID_OPERATION:
				printf("EXCEPTION_FLT_INVALID_OPERATION:    This exception represents any floating-point exception not included in this list.\n\n");
				getregs(pi, &Regs);
				print_regs(&Regs);
				exit(EXIT_SUCCESS);
				break;

			case EXCEPTION_FLT_STACK_CHECK:
				printf("EXCEPTION_FLT_STACK_CHECK:    The stack overflowed or underflowed as the result of a floating-point operation.\n\n");
				getregs(pi, &Regs);
				print_regs(&Regs);
				exit(EXIT_SUCCESS);
				break;

			case EXCEPTION_ILLEGAL_INSTRUCTION:
				printf("EXCEPTION_ILLEGAL_INSTRUCTION:    The thread tried to execute an invalid instruction.\n\n");
				getregs(pi, &Regs);
				print_regs(&Regs);
				exit(EXIT_SUCCESS);
				break;

			case EXCEPTION_IN_PAGE_ERROR:
				printf("EXCEPTION_IN_PAGE_ERROR:    The thread tried to access a page that was not present, and the system was unable to load the page."
					" For example, this exception might occur if a network connection is lost while running a program over the network.\n\n");
				getregs(pi, &Regs);
				print_regs(&Regs);
				exit(EXIT_SUCCESS);
				break;

			case EXCEPTION_STACK_OVERFLOW:
				printf("EXCEPTION_STACK_OVERFLOW:    The thread used up its stack.\n\n");
				getregs(pi, &Regs);
				print_regs(&Regs);
				exit(EXIT_SUCCESS);
				break;

			default:
				printf("Unknow Event!\n\n");
				getregs(pi, &Regs);
				print_regs(&Regs);
				exit(EXIT_FAILURE);
				break;
			}

			break;

		case CREATE_THREAD_DEBUG_EVENT:
			// As needed, examine or change the thread's registers
			// with the GetThreadContext and SetThreadContext functions;
			// and suspend and resume thread execution with the
			// SuspendThread and ResumeThread functions.

#ifdef DEBUG
			printf("Create thread %d.\n\n", DebugEv.u.CreateThread.hThread);
#endif // DEBUG
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			// As needed, examine or change the registers of the
			// process's initial thread with the GetThreadContext and
			// SetThreadContext functions; read from and write to the
			// process's virtual memory with the ReadProcessMemory and
			// WriteProcessMemory functions; and suspend and resume
			// thread execution with the SuspendThread and ResumeThread
			// functions. Be sure to close the handle to the process image
			// file with CloseHandle.

#ifdef DEBUG
			printf("Create process %d.\n\n", DebugEv.u.CreateProcessInfo.hProcess);
#endif
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			// Display the thread's exit code.

#ifdef DEBUG
			printf("Thread %d had exited with ExitCode( %d )!\n\n", DebugEv.dwThreadId, DebugEv.u.ExitThread.dwExitCode);
#endif
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			// Display the process's exit code.

			printf("Process %d had exited with ExitCode( %d )!\n\n", DebugEv.dwProcessId, DebugEv.u.ExitProcess.dwExitCode);
			exit(EXIT_SUCCESS);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			// Read the debugging information included in the newly
			// loaded DLL. Be sure to close the handle to the loaded DLL
			// with CloseHandle.

#ifdef DEBUG
			puts("LOAD_DLL_DEBUG_EVENT\n");
#endif
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			// Display a message that the DLL has been unloaded.

#ifdef DEBUG
			printf("Unload dll: %#llx\n\n", DebugEv.u.UnloadDll.lpBaseOfDll);
#endif
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			// Display the output debugging string.

#ifdef DEBUG
			printf("Receive child process' message: %s\n\n", DebugEv.u.DebugString.lpDebugStringData);
#endif
			break;

		case RIP_EVENT:
			printf("RIP_EVENT, error: %d, type: %d\n\n", DebugEv.u.RipInfo.dwError, DebugEv.u.RipInfo.dwType);
			break;
		}
		if (TrapFlag == FALSE)
		{
			ASSERT(ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, DBG_CONTINUE) != 0, 1);
		}
	}
}

size_t peekdata(PROCESS_INFORMATION* pi, size_t addr)
{
	size_t value, result;
	ASSERT(ReadProcessMemory(pi->hProcess, (PVOID)addr, &value, sizeof(size_t), &result) != 0, 1);
	ASSERT(result == sizeof(size_t), 1);
	return value;
}

void pokedata(PROCESS_INFORMATION* pi, size_t addr, size_t value)
{
	size_t local, result;
	local = value;
	ASSERT(WriteProcessMemory(pi->hProcess, (PVOID)addr, &local, sizeof(size_t), &result) != 0, 1);
	ASSERT(result == sizeof(size_t), 1);
}

void single_step(PROCESS_INFORMATION* pi)
{
	CONTEXT Regs;
	getregs(pi, &Regs);
	Regs.EFlags |= 0x100;
	setregs(pi, &Regs);
}

#define ERROR_RET(arg) arg

typedef struct BreakPoint
{
	size_t addr;
	size_t previous_byte;
} BreakPoint;

BreakPoint global_point[0x100];

char* error_info[] = {
	"success",
	"Can't find BreakPoint",
	"Run out of BreakPoint",
	"Can't find this address",
};

int install_break_point(PROCESS_INFORMATION* pi, size_t addr)
{
	size_t value;
	int index;
	value = peekdata(pi, addr);
	for (index = 0; index < sizeof(global_point) / sizeof(BreakPoint); index++)
	{
		if (global_point[index].addr == 0)
		{
			break;
		}
	}
	if (index == sizeof(global_point) / sizeof(BreakPoint))
	{
		return ERROR_RET(2);
	}
	global_point[index].addr = addr;
	global_point[index].previous_byte = value;
	value = (value & ~(0xff)) | (0xcc);
	pokedata(pi, addr, value);

	return 0;
}

void detach(PROCESS_INFORMATION* pi)
{
	ASSERT(DebugActiveProcessStop(pi->dwProcessId) != 0, 1);
}

void continue_(PROCESS_INFORMATION* pi)
{
	ASSERT(ContinueDebugEvent(pi->dwProcessId, pi->dwThreadId, DBG_EXCEPTION_HANDLED) != 0, 1);
}

int restore_break_point(PROCESS_INFORMATION* pi)
{
	CONTEXT Regs;
	size_t value, xip;
	int index, wstatus;

	getregs(pi, &Regs);
	xip = Regs.XIP - 1;

	for (index = 0; index < sizeof(global_point) / sizeof(BreakPoint); index++)
	{
		if (global_point[index].addr == xip)
		{
			break;
		}
	}
	if (index == sizeof(global_point) / sizeof(BreakPoint))
	{
		return ERROR_RET(1);
	}

	Regs.XIP = xip;
	setregs(pi, &Regs);
	pokedata(pi, xip, global_point[index].previous_byte);

	return 0;
}

int continue_break_point(PROCESS_INFORMATION* pi)
{
	CONTEXT Regs;
	size_t value, xip;
	int index, wstatus;

	getregs(pi, &Regs);
	xip = Regs.XIP - 1;

	for (index = 0; index < sizeof(global_point) / sizeof(BreakPoint); index++)
	{
		if (global_point[index].addr == xip)
		{
			break;
		}
	}
	if (index == sizeof(global_point) / sizeof(BreakPoint))
	{
		return ERROR_RET(1);
	}
	restore_break_point(pi);

	value = global_point[index].previous_byte;
	value = (value & ~(0xff)) | (0xcc);
	pokedata(pi, xip, value);
	continue_(pi);

	return 0;
}

#endif // !TRACER_H_
