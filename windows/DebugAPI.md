## Debugging Functions

**The following functions are used with debugging.**


| Function                       | Description                                                                                          |
| ----                           | ----                                                                                                 |
| CheckRemoteDebuggerPresent     | Determines whether the specified process is being debugged.                                          |
| ContinueDebugEvent             | Enables a debugger to continue a thread that previously reported a debugging event.                  |
| DebugActiveProcess             | Enables a debugger to attach to an active process and debug it.                                      |
| DebugActiveProcessStop         | Stops the debugger from debugging the specified process.                                             |
| DebugBreak                     | Causes a breakpoint exception to occur in the current process.                                       |
| DebugBreakProcess              | Causes a breakpoint exception to occur in the specified process.                                     |
| DebugSetProcessKillOnExit      | Sets the action to be performed when the calling thread exits.                                       |
| FatalExit                      | Transfers execution control to the debugger.                                                         |
| FlushInstructionCache          | Flushes the instruction cache for the specified process.                                             |
| GetThreadContext               | Retrieves the context of the specified thread.                                                       |
| GetThreadSelectorEntry         | Retrieves a descriptor table entry for the specified selector and thread.                            |
| IsDebuggerPresent              | Determines whether the calling process is being debugged by a user-mode debugger.                    |
| OutputDebugString              | Sends a string to the debugger for display.                                                          |
| ReadProcessMemory              | Reads data from an area of memory in a specified process.                                            |
| SetThreadContext               | Sets the context for the specified thread.                                                           |
| WaitForDebugEvent              | Waits for a debugging event to occur in a process being debugged.                                    |
| Wow64GetThreadContext          | Retrieves the context of the specified WOW64 thread.                                                 |
| Wow64GetThreadSelectorEntry    | Retrieves a descriptor table entry for the specified selector and WOW64 thread.                      |
| Wow64SetThreadContext          | Sets the context of the specified WOW64 thread.                                                      |
| WriteProcessMemory             | Writes data to an area of memory in a specified process.                                             |
