from __future__ import annotations

import os
import sys


def _enable_windows_ansi() -> None:
    """
    Best-effort enabling of ANSI colors on Windows terminals.
    On modern Windows 10/11, this is usually already enabled.
    """
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        h = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE = -11
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(h, ctypes.byref(mode)) == 0:
            return
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(h, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:
        # If it fails, we silently fall back to plain text.
        return


_enable_windows_ansi()


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def supports_color() -> bool:
    # Conservative check: disable colors if output is not a TTY.
    return sys.stdout.isatty()


def color(text: str, *styles: str) -> str:
    if not supports_color() or not styles:
        return text
    return "".join(styles) + text + C.RESET


def hr() -> str:
    return "-" * 48


def clear_screen() -> None:
    if not sys.stdout.isatty():
        return
    os.system("cls" if os.name == "nt" else "clear")


