"""Memory sanitization helpers for overwriting sensitive buffers."""

import ctypes
from typing import Any, Union


def zero_memory(buffer: Union[bytearray, memoryview, Any]) -> None:
    """Overwrites a mutable buffer with zero bytes in place.

    Works on bytearray, memoryview, or any object supporting the buffer protocol.
    If the object is immutable (e.g. bytes), attempts a best-effort ctypes memory
    scrubbing when possible.
    """
    if buffer is None:
        return

    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
        return

    if isinstance(buffer, memoryview):
        if not buffer.readonly:
            buffer[:] = b"\x00" * len(buffer)
            return

    # Attempt ctypes memset if address and length are accessible
    try:
        raw_len = len(buffer)
        raw_addr = ctypes.c_char.from_buffer(buffer)
        ctypes.memset(ctypes.addressof(raw_addr), 0, raw_len)
    except (TypeError, BufferError, ValueError):
        # Read-only or unaddressable buffer
        pass
