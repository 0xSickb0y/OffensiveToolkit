# Built using Windows 10 Enterprise 10.0.19043
# https://github.com/0xSickb0y/OffensiveToolkit/tree/main/Python/Windows/Native%20API

import time
from ctypes import *
from ctypes import wintypes

NtAllocateVirtualMemory = windll.ntdll.NtAllocateVirtualMemory
NtAllocateVirtualMemory.argtypes = (
    wintypes.HANDLE, POINTER(wintypes.LPVOID),
    wintypes.ULONG, POINTER(wintypes.ULONG),
    wintypes.ULONG, wintypes.ULONG
)
NtAllocateVirtualMemory.restype = wintypes.DWORD

ProcessHandle = 0xffffffffffffffff
BaseAddress = wintypes.LPVOID(0x0)
ZeroBits = wintypes.ULONG(0)
RegionSize = wintypes.ULONG(4096)
AllocationType = 0x00001000 | 0x00002000
Protect = 0x40

res = NtAllocateVirtualMemory(
    ProcessHandle,
    byref(BaseAddress),
    ZeroBits,
    byref(RegionSize),
    AllocationType,
    Protect
)

if res == 0:
    print("NtAllocateVirtualMemory: pointer ->", hex(BaseAddress.value))
    time.sleep(180)
