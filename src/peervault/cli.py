"""Command line interface for PeerVault."""

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

from peervault import __version__
from peervault.config import (
    generate_default_config_toml,
    get_default_config_path,
    load_configuration,
)
from peervault.crypto.sas import compute_sas
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

config_app = typer.Typer(
    name="config",
    help="Manage PeerVault configuration and default settings.",
)
app.add_typer(config_app, name="config")


@app.command()
def version() -> None:
    """Show PeerVault version."""
    typer.echo(f"peervault version {__version__}")


@config_app.command("show")
def config_show() -> None:
    """Display active configuration settings and configuration file path."""
    console = Console()
    path = get_default_config_path()
    cfg = load_configuration()

    status_label = "[green](exists)[/green]" if path.is_file() else "[dim](using defaults)[/dim]"
    console.print(f"[bold]Config File:[/bold] {path} {status_label}")
    console.print()
    console.print(f"  [bold cyan]Relay URL:[/bold cyan]         {cfg.relay_url}")
    console.print(f"  [bold cyan]STUN Servers:[/bold cyan]      {', '.join(cfg.stun_servers)}")
    console.print(f"  [bold cyan]Chunk Size:[/bold cyan]        {cfg.chunk_size:,} bytes")
    console.print(f"  [bold cyan]Auto Accept:[/bold cyan]       {cfg.auto_accept}")
    console.print(f"  [bold cyan]Overwrite:[/bold cyan]         {cfg.overwrite}")
    if cfg.default_output_dir:
        console.print(f"  [bold cyan]Default Output:[/bold cyan]    {cfg.default_output_dir}")


@config_app.command("init")
def config_init(
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite existing configuration file"
    ),
) -> None:
    """Generate a default documented configuration file."""
    console = Console()
    path = get_default_config_path()

    if path.is_file() and not force:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] Configuration file already exists at {path}."
        )
        console.print("Use '--force' to overwrite it.")
        raise typer.Exit(code=1)

    path.parent.mkdir(parents=True, exist_ok=True)
    template = generate_default_config_toml()
    path.write_text(template, encoding="utf-8")
    console.print(f"[bold green]✓ Configuration file created at:[/bold green] {path}")


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
    paths: List[str] = typer.Argument(..., help="Path(s) to file(s), directory, or '-' for stdin"),
    relay: Optional[str] = typer.Option(
        None,
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
    sas: bool = typer.Option(
        True,
        "--sas/--no-sas",
        help="Display visual Short Authentication String for MitM verification",
    ),
) -> None:
    """Send one or more files, folders, or standard input directly to a peer."""
    console = Console()
    app_cfg = load_configuration()
    relay_url = relay or app_cfg.relay_url

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

    # Validate paths if not stdin
    is_pipe = len(paths) == 1 and paths[0] == "-"
    if not is_pipe:
        for p in paths:
            if not Path(p).exists():
                console.print(f"[bold red]Error:[/bold red] Source path '{p}' does not exist.")
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
            relay_url=relay_url,
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

            pc = create_peer_connection(stun_servers=app_cfg.stun_servers)
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

                    # Display SAS verification code
                    if sas and stream.session_key:
                        sas_code = compute_sas(stream.session_key)
                        console.print(
                            f"[bold cyan]Security Code (SAS):[/bold cyan] "
                            f"[bold yellow]{sas_code.display}[/bold yellow]"
                        )
                        console.print(
                            "[dim]Verify that the receiver shows the exact same code.[/dim]"
                        )
                        console.print()

                    # Stream transfer with progress bar
                    progress = create_transfer_progress()
                    task_id = progress.add_task("Sending payload...", total=None)

                    def update_progress(current: int, total: int) -> None:
                        if progress.tasks[task_id].total is None and total > 0:
                            progress.update(task_id, total=total)
                        progress.update(task_id, completed=current)

                    payload_source = paths[0] if len(paths) == 1 else paths
                    with progress:
                        result = await send_payload(
                            source=payload_source,
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
    relay: Optional[str] = typer.Option(
        None,
        "--relay",
        "-r",
        help="WebSocket signaling relay URL",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Accept incoming transfer without interactive prompt",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Overwrite existing files instead of generating a unique name",
    ),
    sas: bool = typer.Option(
        True,
        "--sas/--no-sas",
        help="Display visual Short Authentication String for MitM verification",
    ),
) -> None:
    """Receive a file, folder, batch archive, or standard output stream from a peer."""
    app_cfg = load_configuration()
    relay_url = relay or app_cfg.relay_url
    auto_accept = yes or app_cfg.auto_accept
    allow_overwrite = overwrite or app_cfg.overwrite

    dest_target = destination or app_cfg.default_output_dir
    is_pipe = dest_target == "-"
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

    def interactive_confirm(metadata: dict) -> bool:
        size = metadata.get("size", 0)
        size_str = f"{size:,} bytes"
        if size >= 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        elif size >= 1024:
            size_str = f"{size / 1024:.1f} KB"

        name = metadata.get("name", "unnamed")
        console.print(
            f"\n[bold yellow]Incoming transfer:[/bold yellow] [bold]{name}[/bold] ({size_str})"
        )
        return typer.confirm("Accept file download?", default=True)

    async def _receive_flow() -> None:
        signaling = SignalingClient(
            relay_url=relay_url,
            passphrase=code,
            role="receiver",
        )
        try:
            with console.status("[cyan]Connecting to signaling relay...[/cyan]"):
                await signaling.connect()
                await signaling.join()

            console.print("[dim]Connecting to sender...[/dim]")
            pc = create_peer_connection(stun_servers=app_cfg.stun_servers)
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

                    # Display SAS verification code
                    if sas and stream.session_key and not is_pipe:
                        sas_code = compute_sas(stream.session_key)
                        console.print(
                            f"[bold cyan]Security Code (SAS):[/bold cyan] "
                            f"[bold yellow]{sas_code.display}[/bold yellow]"
                        )
                        console.print(
                            "[dim]Verify that the sender terminal shows the exact same code.[/dim]"
                        )
                        console.print()

                    progress = create_transfer_progress(use_stderr=is_pipe)
                    task_id = progress.add_task("Receiving payload...", total=None)

                    def update_progress(current: int, total: int) -> None:
                        if progress.tasks[task_id].total is None and total > 0:
                            progress.update(task_id, total=total)
                        progress.update(task_id, completed=current)

                    with progress:
                        result = await receive_payload(
                            dest_path=dest_target,
                            stream=stream,
                            progress_callback=update_progress,
                            confirm_callback=interactive_confirm,
                            auto_accept=auto_accept,
                            overwrite=allow_overwrite,
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
