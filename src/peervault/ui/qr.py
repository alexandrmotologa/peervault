"""Terminal QR code generator with Unicode block and ASCII support."""

import io
import sys

import segno


def render_terminal_qr(content: str, out=None, compact: bool = True) -> str:
    """Renders a QR code into terminal block characters string.

    Returns the formatted string.
    """
    qr = segno.make(content, error="m")
    buf = io.StringIO()
    qr.terminal(out=buf, compact=compact)
    return buf.getvalue()


def display_terminal_qr(content: str, compact: bool = True) -> None:
    """Prints a QR code directly to terminal output safely on any platform."""
    rendered = render_terminal_qr(content, compact=compact)
    try:
        # On Windows, stdout buffer handles utf-8 unicode blocks without charmap errors
        if hasattr(sys.stdout, "buffer"):
            sys.stdout.buffer.write(rendered.encode("utf-8"))
            sys.stdout.buffer.flush()
        else:
            print(rendered)
    except Exception:
        # Fallback to ascii representation if terminal cannot render blocks
        try:
            qr = segno.make(content, error="m")
            buf = io.StringIO()
            qr.terminal(out=buf, compact=False)
            print(buf.getvalue())
        except Exception:
            pass
