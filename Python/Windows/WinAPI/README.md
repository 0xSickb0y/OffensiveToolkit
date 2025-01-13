# Windows API Calls

The Windows API, informally WinAPI, is the foundational application programming interface (API) that allows a computer program to access the features of the Microsoft Windows operating system in which the program is running.

This [program](https://github.com/0xSickb0y/OffensiveToolkit/blob/main/Python/Windows/WinAPI/run.py) is a simple "troll" that demonstrates basic usage of the Windows API by utilizing MessageBoxA. The program is not harmful in any way.

## References

- [Windows API - Wikipedia](https://en.wikipedia.org/wiki/Windows_API)
- [MessageBoxA Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa)
- [Programming reference for the Win32 API](https://learn.microsoft.com/en-us/windows/win32/api/)

## Building the Script

In this script, we use the `MessageBoxA` function from the `user32.dll` library. This function creates a message box with customizable text, a title, and flags for defining its behavior.

We start by importing the necessary modules from `ctypes` and `ctypes.wintypes` to interact with the Windows API.

```python
import os
import subprocess
from ctypes import *
from ctypes.wintypes import HWND, LPCSTR, UINT
```

Next, we load the `MessageBoxA` function from the `user32.dll` library. The function's argument types and return type are defined as follows:

```python
mboxa = windll.user32.MessageBoxA
mboxa.argtypes = (HWND, LPCSTR, LPCSTR, UINT)
mboxa.restype = UINT
```

- `argtypes`: Specifies the argument types expected by the function:
  - `HWND`: Handle to the owner window (we use `None` here).
  - `LPCSTR`: A pointer to a constant string, used for both the text of the message box and its title.
  - `UINT`: The flags that specify the behavior and appearance of the message box.

- `restype`: Specifies that the function will return a `UINT` (the result of the message box interaction, where `6` indicates the "Yes" button was clicked).

We then declare the arguments for the `MessageBoxA` function:

```python
W_HANDLE = None
LP_TEXT = LPCSTR(b"Are you stupid?")
LP_CAPTION = LPCSTR(b"MessageBoxA")
MB_FLAGS = 0x00000004 | 0x00001000
```

- `W_HANDLE`: The handle to the owner window. In this case, we set it to `None` because the message box is independent of any specific window.
- `LP_TEXT`: The text displayed in the message box.
- `LP_CAPTION`: The title displayed in the message box.
- `MB_FLAGS`: Flags that define the message box's behavior. Here, `0x00000004` sets the message box as modal (blocking interaction with other windows), and `0x00001000` gives it the "Yes/No" buttons.

Finally, we define a function to show the message box and check the result:

```python
def show_messagebox():
    return mboxa(W_HANDLE, LP_TEXT, LP_CAPTION, MB_FLAGS)
```

- This function calls `MessageBoxA` and returns the result (the button clicked by the user).

The script continuously opens new instances of the message box until the user clicks the "Yes" button. If the user clicks "Yes," the function will return `6`, and the script will stop opening new message boxes. 

```python
if __name__ == '__main__':
    while True:
        if show_messagebox() == 6:
            break

        for _ in range(0, 6):
            subprocess.Popen(["python", os.path.abspath(__file__)])
```

- The `while True` loop ensures that the message box reappears until the user clicks "Yes."
- The `subprocess.Popen()` call spawns new instances of the script (up to 6 times) to keep the message boxes appearing.

## Example Output

![output](https://github.com/user-attachments/assets/daca833f-d8ee-4abe-a6ec-596b6130ee24)
