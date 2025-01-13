# Native API Calls

Endpoint Detection and Response (EDR) and Anti-Virus (AV) solutions often use API hooking to collect telemetry data when analyzing whether an application's behavior is potentially malicious. One way to bypass such detection mechanisms is to use lower-level API calls that may not be hooked by these security solutions.

In Windows, API calls from user-space are often translated into lower-level system calls via the _NTDLL.dll_ library. These calls are generally undocumented and may change across Windows versions.

## References

- [Windows Native API - Wikipedia](https://en.wikipedia.org/wiki/Windows_Native_API)
- [Windows Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [NtAllocateVirtualMemory Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
- [GetCurrentProcess - Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess)

## Building the Script

We will use the `NtAllocateVirtualMemory` function from the _NTDLL_ library. This function allows for the allocation of memory in a process’s virtual address space.


To start, we import the necessary modules from the `ctypes` library, which allows us to interact with Windows APIs at a low level.

```python
from ctypes import *
from ctypes import wintypes
```

Next, we define the argument types the function expects.

```ruby
NtAllocateVirtualMemory = windll.ntdll.NtAllocateVirtualMemory

NtAllocateVirtualMemory.argtypes = (
    wintypes.HANDLE, POINTER(wintypes.LPVOID),
    wintypes.ULONG, POINTER(wintypes.ULONG),
    wintypes.ULONG, wintypes.ULONG
)

NtAllocateVirtualMemory.restype = wintypes.DWORD
```

- `argtypes`: Defines the expected types for the function's arguments.
- `restype`: Specifies the return type, which in this case is a `DWORD` (error code or success).

<br>

The `NtAllocateVirtualMemory` function requires the following parameters:

1. **ProcessHandle**: A handle to the target process for which the memory allocation is to be performed.
   
2. **BaseAddress**: A pointer to a variable that will receive the base address of the allocated memory region. Setting this to `0` allows the operating system to determine the address.

3. **ZeroBits**: The number of high-order address bits that must be zero in the base address. This parameter is only relevant when the OS determines the base address.

4. **RegionSize**: A pointer to a variable that will receive the actual size of the allocated memory region (in bytes).

5. **AllocationType**: A bitmask that specifies the type of allocation to be performed..

6. **Protect**: A bitmask specifying the protection desired for the committed memory pages.

<br>

We now set the parameters with appropriate values and make the function call.

```python
ProcessHandle = 0xFFFFFFFFFFFFFFFF
BaseAddress = wintypes.LPVOID(0x0)
ZeroBits = wintypes.ULONG(0)
RegionSize = wintypes.ULONG(4096)
AllocationType = 0x00001000 | 0x00002000
Protect = 0x40

ptr = NtAllocateVirtualMemory(
    ProcessHandle,
    byref(BaseAddress),
    ZeroBits,
    byref(RegionSize),
    AllocationType,
    Protect
)
```

The value `0xFFFFFFFFFFFFFFFF` represents a pseudo handle used to refer to the current process, allowing the memory allocation to occur within the calling process's address space. By setting the base address to `0x0`, the operating system is instructed to automatically determine the appropriate base address for the allocated memory region. The value `0` for zero bits means there are no specific high-order address bits that need to be zeroed, allowing the operating system to manage address alignment.

A region size of `4096` bytes (4KB) is specified, and the allocation type `0x00001000 | 0x00002000` combines the flags for both reserving and committing memory. Finally, the value `0x40` sets the memory protection to `PAGE_EXECUTE_READWRITE`, which enables the allocated memory to be read, written to, and executed.


Finally, if the function call is successful, we print the base address of the allocated memory region and wait for 3 minutes to allow inspection.

```python
if ptr == 0:
    print("NtAllocateVirtualMemory: pointer ->", hex(BaseAddress.value))
    time.sleep(180)
```

## Example Output

If the memory allocation is successful, the console will display something like:

```
NtAllocateVirtualMemory: pointer -> 0x[...]
```

In the screenshot, we can see the allocated memory region (`0x1e28bcd0000`) with 4KB of memory and `RWX` (read, write, execute) protection flags.

![ss_process_hacker](https://github.com/user-attachments/assets/5bb73078-5b5a-4d63-94de-55d0e561a228)

