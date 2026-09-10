"""Cross-platform clipboard access with memory safety and auto-clearing."""

import asyncio
import ctypes
import shutil
import subprocess
import sys
from typing import Optional


class ClipboardError(Exception):
    """Raised when reading from or writing to the system clipboard fails."""


def _get_clipboard_windows() -> str:
    """Reads UTF-16 text from the Windows clipboard using ctypes."""
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    CF_UNICODETEXT = 13

    if not user32.OpenClipboard(0):
        raise ClipboardError("Unable to open Windows clipboard")

    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return ""

        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            return ""

        try:
            return ctypes.c_wchar_p(ptr).value or ""
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _set_clipboard_windows(text: str) -> None:
    """Sets UTF-16 text to the Windows clipboard using ctypes."""
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    encoded = text.encode("utf-16-le") + b"\x00\x00"

    h_global = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
    if not h_global:
        raise ClipboardError("GlobalAlloc failed for clipboard data")

    ptr = kernel32.GlobalLock(h_global)
    if not ptr:
        kernel32.GlobalFree(h_global)
        raise ClipboardError("GlobalLock failed for clipboard data")

    ctypes.memmove(ptr, encoded, len(encoded))
    kernel32.GlobalUnlock(h_global)

    if not user32.OpenClipboard(0):
        kernel32.GlobalFree(h_global)
        raise ClipboardError("Unable to open Windows clipboard")

    try:
        user32.EmptyClipboard()
        user32.SetClipboardData(CF_UNICODETEXT, h_global)
    finally:
        user32.CloseClipboard()


def get_clipboard_text() -> str:
    """Retrieves plain text from the system clipboard."""
    if sys.platform == "win32":
        return _get_clipboard_windows()

    if sys.platform == "darwin":
        proc = subprocess.run(["pbpaste"], capture_output=True, text=True, check=True)
        return proc.stdout

    # Linux / BSD: Check Wayland then X11
    if shutil.which("wl-paste"):
        proc = subprocess.run(["wl-paste", "--no-newline"], capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout

    if shutil.which("xclip"):
        proc = subprocess.run(
            ["xclip", "-selection", "clipboard", "-o"], capture_output=True, text=True
        )
        if proc.returncode == 0:
            return proc.stdout

    if shutil.which("xsel"):
        proc = subprocess.run(["xsel", "--clipboard", "--output"], capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout

    raise ClipboardError(
        "No supported clipboard utility found (requires wl-paste, xclip, or xsel on Linux)"
    )


def set_clipboard_text(text: str) -> None:
    """Copies plain text to the system clipboard."""
    if sys.platform == "win32":
        _set_clipboard_windows(text)
        return

    if sys.platform == "darwin":
        subprocess.run(["pbcopy"], input=text, text=True, check=True)
        return

    # Linux / BSD
    if shutil.which("wl-copy"):
        subprocess.run(["wl-copy"], input=text, text=True, check=True)
        return

    if shutil.which("xclip"):
        subprocess.run(["xclip", "-selection", "clipboard"], input=text, text=True, check=True)
        return

    if shutil.which("xsel"):
        subprocess.run(["xsel", "--clipboard", "--input"], input=text, text=True, check=True)
        return

    raise ClipboardError("No supported clipboard utility found for copy operation")


async def auto_clear_clipboard(
    target_secret: str,
    timeout_seconds: int = 45,
    on_cleared: Optional[callable] = None,
) -> None:
    """Asynchronously clears the system clipboard after timeout if it still contains the secret."""
    await asyncio.sleep(timeout_seconds)
    try:
        current = get_clipboard_text()
        if current == target_secret:
            set_clipboard_text("")
            if on_cleared:
                on_cleared()
    except Exception:
        pass
