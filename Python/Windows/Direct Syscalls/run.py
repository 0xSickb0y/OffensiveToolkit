import time
from ctypes import *
from ctypes import wintypes

SIZE_T = c_size_t
NTSTATUS = wintypes.DWORD
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READ_WRITE = 0x40

### Put your raw shellcode in this file ###
with open("shellcode", "rb") as shellcode:
    buf = create_string_buffer(shellcode.read())

VirtualProtect = windll.kernel32.VirtualProtect

VirtualProtect.argtypes = (
    wintypes.LPVOID,
    SIZE_T,
    wintypes.DWORD,
    wintypes.LPDWORD
)

VirtualProtect.restype = wintypes.INT

lpAddress = addressof(buf)
dwSize = len(buf)
flNewProtect = PAGE_EXECUTE_READ_WRITE
lpflOldProtect = byref(wintypes.DWORD(0))

protect = VirtualProtect( 
    lpAddress,
    dwSize,
    flNewProtect,
    lpflOldProtect
)

syscall_type = CFUNCTYPE(
    NTSTATUS,
    wintypes.HANDLE, POINTER(wintypes.LPVOID),
    wintypes.ULONG, POINTER(wintypes.ULONG),
    wintypes.ULONG, wintypes.ULONG
)

syscall_function = syscall_type(lpAddress)

ProcessHandle = 0xffffffffffffffff
BaseAddress = wintypes.LPVOID(0x0)
ZeroBits = wintypes.ULONG(0)
RegionSize = wintypes.ULONG(1024 * 15)
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

if ptr == 0:
    print("Direct Syscall: pointer ->", hex(BaseAddress.value))
    time.sleep(180)
