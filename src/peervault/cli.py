"""Command line interface for PeerVault."""

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from peervault import __version__
from peervault.config import DEFAULT_NETWORK_CONFIG
from peervault.p2p.channel import DataChannelStream
from peervault.p2p.connection import create_peer_connection, negotiate_receiver, negotiate_sender
from peervault.signaling.client import SignalingClient
from peervault.signaling.server import run_server
from peervault.signaling.words import generate_code, validate_code
from peervault.transfer.receiver import receive_payload
from peervault.transfer.sender import send_payload
from peervault.ui.progress import create_transfer_progress, get_console
from peervault.ui.qr import display_terminal_qr

app = typer.Typer(
    name="peervault",
    help="Direct peer-to-peer secret sharing and environment sync over WebRTC.",
    add_completion=False,
)


@app.command()
def version() -> None:
    """Show PeerVault version."""
    typer.echo(f"peervault version {__version__}")


@app.command()
def server(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host interface to bind"),
    port: int = typer.Option(8765, "--port", "-p", help="Port to listen on"),
) -> None:
    """Run an in-memory WebSocket signaling relay server."""
    console = Console()
    console.print(
        f"[bold green]Starting PeerVault signaling relay[/bold green] on ws://{host}:{port}"
    )
    console.print("[dim]Rooms are stored in memory and expire after 5 minutes of inactivity.[/dim]")
    try:
        asyncio.run(run_server(host, port))
    except KeyboardInterrupt:
        console.print("\n[yellow]Signaling relay stopped.[/yellow]")


@app.command()
def send(
    path: str = typer.Argument(..., help="Path to file, directory, or '-' for stdin"),
    relay: str = typer.Option(
        DEFAULT_NETWORK_CONFIG.default_relay_url,
        "--relay",
        "-r",
        help="WebSocket signaling relay URL",
    ),
    code: Optional[str] = typer.Option(
        None,
        "--code",
        "-c",
        help="Custom passphrase code (auto-generated if omitted)",
    ),
) -> None:
    """Send a file, folder, or standard input directly to a peer."""
    console = Console()

    if code is None:
        code = generate_code()
    else:
        code = code.strip().lower()
        if not validate_code(code):
            console.print(
                f"[bold red]Error:[/bold red] '{code}' is invalid. "
                "Expected format like '7-copper-falcon'."
            )
            raise typer.Exit(code=1)

    if path != "-" and not Path(path).exists():
        console.print(f"[bold red]Error:[/bold red] Source path '{path}' does not exist.")
        raise typer.Exit(code=1)

    console.print()
    console.print(f"[bold]Passphrase code:[/bold] [bold cyan]{code}[/bold cyan]")
    console.print("[dim]Scan QR code or run 'peervault receive <code-phrase>' on receiver:[/dim]")
    console.print()

    # Display terminal QR code
    display_terminal_qr(f"peervault:{code}")
    console.print()

    async def _send_flow() -> None:
        signaling = SignalingClient(
            relay_url=relay,
            passphrase=code,
            role="sender",
        )
        try:
            with console.status("[cyan]Connecting to signaling relay...[/cyan]"):
                await signaling.connect()
                await signaling.join()

            console.print("[dim]Waiting for receiver to connect...[/dim]")
            await signaling.wait_for_peer()
            console.print("[green]✓[/green] Peer joined! Negotiating direct WebRTC DataChannel...")

            pc = create_peer_connection()
            try:
                channel = await negotiate_sender(pc, signaling)
                transport_key = bytes(signaling.transport_base_key)

                console.print(
                    "[green]✓[/green] Direct P2P open. Performing forward secrecy handshake..."
                )
                stream = DataChannelStream(channel)
                try:
                    await stream.perform_handshake(transport_key)
                    console.print("[green]✓[/green] Encrypted session established (AEAD + X25519).")

                    # Stream transfer with progress bar
                    progress = create_transfer_progress()
                    task_id = progress.add_task("Sending payload...", total=None)

                    def update_progress(current: int, total: int) -> None:
                        if progress.tasks[task_id].total is None and total > 0:
                            progress.update(task_id, total=total)
                        progress.update(task_id, completed=current)

                    with progress:
                        result = await send_payload(
                            source=path,
                            stream=stream,
                            progress_callback=update_progress,
                        )

                    console.print()
                    console.print("[bold green]Transfer complete![/bold green]")
                    console.print(f"  Name:    {result['name']}")
                    console.print(f"  Size:    {result['size']:,} bytes")
                    console.print(f"  SHA-256: [cyan]{result['sha256']}[/cyan]")
                finally:
                    await stream.close()
            finally:
                await pc.close()

        finally:
            await signaling.close()

    try:
        asyncio.run(_send_flow())
    except KeyboardInterrupt:
        console.print("\n[yellow]Transfer cancelled by user.[/yellow]")
        raise typer.Exit(code=130)
    except Exception as err:
        console.print(f"\n[bold red]Transfer failed:[/bold red] {err}")
        raise typer.Exit(code=1)


@app.command()
def receive(
    code: str = typer.Argument(..., help="Passphrase code (e.g. '7-copper-falcon')"),
    destination: Optional[str] = typer.Argument(
        None,
        help="Destination directory, output filename, or '-' for stdout",
    ),
    relay: str = typer.Option(
        DEFAULT_NETWORK_CONFIG.default_relay_url,
        "--relay",
        "-r",
        help="WebSocket signaling relay URL",
    ),
) -> None:
    """Receive a file, folder, or standard output stream from a peer."""
    is_pipe = destination == "-"
    console = get_console(use_stderr=is_pipe)

    # Strip URI prefix if present
    code = code.strip().lower()
    if code.startswith("peervault:"):
        code = code[len("peervault:") :]

    if not validate_code(code):
        console.print(
            f"[bold red]Error:[/bold red] '{code}' is invalid. "
            "Expected format like '7-copper-falcon'."
        )
        raise typer.Exit(code=1)

    async def _receive_flow() -> None:
        signaling = SignalingClient(
            relay_url=relay,
            passphrase=code,
            role="receiver",
        )
        try:
            with console.status("[cyan]Connecting to signaling relay...[/cyan]"):
                await signaling.connect()
                await signaling.join()

            console.print("[dim]Connecting to sender...[/dim]")
            pc = create_peer_connection()
            try:
                channel = await negotiate_receiver(pc, signaling)
                transport_key = bytes(signaling.transport_base_key)

                console.print(
                    "[green]✓[/green] Direct P2P open. Performing forward secrecy handshake..."
                )
                stream = DataChannelStream(channel)
                try:
                    await stream.perform_handshake(transport_key)
                    console.print("[green]✓[/green] Encrypted session established (AEAD + X25519).")

                    progress = create_transfer_progress(use_stderr=is_pipe)
                    task_id = progress.add_task("Receiving payload...", total=None)

                    def update_progress(current: int, total: int) -> None:
                        if progress.tasks[task_id].total is None and total > 0:
                            progress.update(task_id, total=total)
                        progress.update(task_id, completed=current)

                    with progress:
                        result = await receive_payload(
                            dest_path=destination,
                            stream=stream,
                            progress_callback=update_progress,
                        )

                    if not is_pipe:
                        console.print()
                        console.print("[bold green]Transfer complete and verified![/bold green]")
                        console.print(f"  Name:        {result['name']}")
                        console.print(f"  Destination: {result['destination']}")
                        console.print(f"  Size:        {result['size']:,} bytes")
                        console.print(f"  SHA-256:     [cyan]{result['sha256']}[/cyan]")
                        if result.get("extracted_files"):
                            file_count = len(result["extracted_files"])
                            console.print(f"  Extracted:   {file_count} files unpacked")
                finally:
                    await stream.close()
            finally:
                await pc.close()

        finally:
            await signaling.close()

    try:
        asyncio.run(_receive_flow())
    except KeyboardInterrupt:
        console.print("\n[yellow]Transfer cancelled by user.[/yellow]")
        raise typer.Exit(code=130)
    except Exception as err:
        console.print(f"\n[bold red]Transfer failed:[/bold red] {err}")
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
