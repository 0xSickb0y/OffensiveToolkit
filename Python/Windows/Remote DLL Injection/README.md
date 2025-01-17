# DLL Injection

DLL injection is a technique that allows execution of code within the address space of another process. This is achieved by allocating memory in the target process, writing the DLL path into that memory, and starting a remote thread to load the DLL using `LoadLibraryA`.

This program demonstrates how to use Python and the `ctypes` library to perform DLL injection.

## References

- [DLL Injection - Wikipedia](https://en.wikipedia.org/wiki/DLL_injection)  
- [OpenProcess Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)  
- [VirtualAllocEx Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)  
- [WriteProcessMemory Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)  
- [GetProcAddress Documentation](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)  
- [CreateRemoteThread Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)  

## Building the Program

#### Import Required Modules
The script imports `ctypes` and its submodules to interact with Windows API functions:

```python
import os
from ctypes import *
from ctypes import wintypes
```

#### Declaration of the Arguments and Return Types  

This section defines the argument and return types for the `OpenProcess` function:

```python
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (
    wintypes.DWORD,  # Access flags
    wintypes.BOOL,   # Inherit handle
    wintypes.DWORD   # Process ID
)
OpenProcess.restype = wintypes.HANDLE  # Handle to the process
```

Similarly, the argument and return types are declared for other functions, such as `VirtualAllocEx`, `WriteProcessMemory`, `GetProcAddress`, and `CreateRemoteThread`. Each declaration specifies the expected parameters and return type to ensure correct behavior when interacting with these Windows API functions.

#### Open a Handle to the Target Process
The script uses the `OpenProcess` function to get a handle for the target process. This requires the process ID (PID), which must be set manually in the script:

```python
pid = 1337  # change this line
dll_path = b"C:\\path\\to\\file.dll"  # change this line

process_handle = OpenProcess(
    PROCESS_ALL_ACCESS,  # Access rights
    False,               # Handle inheritance
    pid                  # Target PID
)
if not process_handle:
    raise WinError()
print("[!] ProcessHandle for PID {} -> {}".format(pid, process_handle))
```

#### Allocate Memory in the Remote Process
The `VirtualAllocEx` function is used to allocate memory in the address space of the target process. This memory will hold the DLL path:

```python
remote_memory = VirtualAllocEx(
    process_handle,
    False,
    len(dll_path) + 1,        # Allocate enough memory to store the DLL path and a null terminator
    MEM_COMMIT | MEM_RESERVE, # Memory allocation options
    PAGE_READWRITE            # Access rights for the allocated memory
)
if not remote_memory:
    raise WinError()
print("[!] Allocated Memory for PID {}, address -> {}".format(pid, hex(remote_memory)))
```

#### Write the DLL Path into the Allocated Memory
The `WriteProcessMemory` function is called to write the DLL path into the memory allocated in the remote process:

```python
write = WriteProcessMemory(
    process_handle,
    remote_memory,     # Remote memory location where the DLL path is written
    dll_path,          # DLL path to be written
    len(dll_path) + 1, # Number of bytes to write
    None
)
if not write:
    raise WinError()
print("[!] Bytes Written from {} -> {}".format(os.path.abspath(dll_path.decode('utf-8')), hex(remote_memory)))
```

#### Get the Address of `LoadLibraryA`
The `GetProcAddress` function retrieves the address of `LoadLibraryA` from the `kernel32` library. This function will be used to load the DLL into the target process:

```python
load_lib = GetProcAddress(
    GetModuleHandleA(b"kernel32.dll"), # A handle to kernel32.dll
    b"LoadLibraryA"                    # Name of the function to be executed
)
if not load_lib:
    raise WinError()
print("[!] LoadLibraryA address -> {}".format(hex(load_lib)))
```

The script targets a Notepad process (PID `200`) and injects the `injection.dll` file. The injected DLL can be verified by inspecting the target process in tools like Process Hacker or by scanning the process memory for the DLL path.

![screenshot](https://github.com/user-attachments/assets/7a423287-e65c-4235-8538-9f0efe92d567)

#### Create a Remote Thread
The `CreateRemoteThread` function creates a thread in the target process that starts executing `LoadLibraryA`, passing the DLL path stored in remote memory as its argument

```python
rthread = CreateRemoteThread(
    process_handle,
    None,          # Default security attributes (no inheritance)
    0,             # Stack size (default)
    load_lib,      # Function address (LoadLibraryA)
    remote_memory, # Address of the DLL path in remote memory
    0,             # Creation flags (default behavior)
    None           # No thread ID needed
)
if not rthread:
    raise WinError()
print("[!] Started remote thread")
```

## Example Output

![demo](https://github.com/user-attachments/assets/55e6bc21-c62f-421f-a7be-5f9726968269)

