"""Terminal progress indicators and transfer statistics using Rich."""

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)


def get_console(use_stderr: bool = False) -> Console:
    """Returns a Rich Console configured for either stdout or stderr."""
    return Console(stderr=use_stderr)


def create_transfer_progress(use_stderr: bool = False) -> Progress:
    """Creates a Rich Progress instance configured for file or stream transfers."""
    console = get_console(use_stderr=use_stderr)
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )
