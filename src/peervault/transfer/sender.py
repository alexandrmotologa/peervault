"""Sender transfer coordinator for files, directories, batch items, and piped standard input."""

import hashlib
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from peervault.config import DEFAULT_CRYPTO_CONFIG, CryptoConfig
from peervault.p2p.channel import EOS_FRAME, DataChannelStream
from peervault.transfer.archive import create_batch_archive, create_directory_archive


class TransferError(Exception):
    """Raised when transfer protocol fails."""


class TransferRejectedError(TransferError):
    """Raised when receiver explicitly declines the transfer."""


async def send_payload(
    source: Union[str, List[str], Path, List[Path]],
    stream: DataChannelStream,
    crypto_config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Union[str, int]]:
    """Streams a file, directory, batch items, or stdin across an established DataChannelStream."""
    hasher = hashlib.sha256()

    # Normalize source
    if isinstance(source, (list, tuple)) and len(source) == 1:
        source = source[0]

    # Case 1: Multiple items (batch mode)
    if isinstance(source, (list, tuple)):
        path_list = [Path(p).resolve() for p in source]
        for p in path_list:
            if not p.exists():
                raise FileNotFoundError(f"Source does not exist: {p}")

        mode = "archive"
        name = f"batch_{len(path_list)}_items.tar.gz"
        tar_bytes = create_batch_archive(path_list)
        total_size = len(tar_bytes)
        hasher.update(tar_bytes)
        sha256_hex = hasher.hexdigest()

        def data_generator():
            for i in range(0, total_size, crypto_config.chunk_size):
                yield tar_bytes[i : i + crypto_config.chunk_size]

    # Case 2: Standard input pipe
    elif str(source) == "-":
        mode = "pipe"
        name = "stdin.data"
        raw_data = sys.stdin.buffer.read()
        total_size = len(raw_data)
        hasher.update(raw_data)
        sha256_hex = hasher.hexdigest()

        def data_generator():
            for i in range(0, total_size, crypto_config.chunk_size):
                yield raw_data[i : i + crypto_config.chunk_size]

    # Case 3: Single file or single directory
    else:
        src_path = Path(source).resolve()
        if not src_path.exists():
            raise FileNotFoundError(f"Source does not exist: {source}")

        if src_path.is_dir():
            mode = "archive"
            name = src_path.name + ".tar.gz"
            tar_bytes = create_directory_archive(src_path)
            total_size = len(tar_bytes)
            hasher.update(tar_bytes)
            sha256_hex = hasher.hexdigest()

            def data_generator():
                for i in range(0, total_size, crypto_config.chunk_size):
                    yield tar_bytes[i : i + crypto_config.chunk_size]

        else:
            mode = "file"
            name = src_path.name
            total_size = src_path.stat().st_size

            with open(src_path, "rb") as f:
                while chunk := f.read(128 * 1024):
                    hasher.update(chunk)
            sha256_hex = hasher.hexdigest()

            def data_generator():
                with open(src_path, "rb") as f:
                    while chunk := f.read(crypto_config.chunk_size):
                        yield chunk

    # 1. Send encrypted metadata frame (index 0)
    metadata = {
        "mode": mode,
        "name": name,
        "size": total_size,
        "sha256": sha256_hex,
    }
    meta_json = json.dumps(metadata).encode("utf-8")
    meta_frame = stream.cipher.encrypt_chunk(0, meta_json)
    await stream.send_frame(meta_frame)

    # 2. Await ready acknowledgement from receiver (or resume request)
    ready_frame = await stream.read_frame(timeout=30.0)
    if ready_frame.startswith(b"PV_REJECT"):
        reason = ready_frame.decode("utf-8", errors="replace")
        if ":" in reason:
            reason = reason.split(":", 1)[1]
        raise TransferRejectedError(f"Receiver declined transfer: {reason}")

    start_chunk = 1
    if ready_frame.startswith(b"PV_RESUME:"):
        start_chunk = int(ready_frame.decode("utf-8").split(":")[1])
    elif ready_frame != b"PV_READY":
        raise TransferError(f"Receiver did not send ready ACK, got: {ready_frame!r}")

    # 3. Stream encrypted chunks
    chunk_index = 1
    bytes_sent = 0

    if progress_callback:
        progress_callback(bytes_sent, total_size)

    for chunk in data_generator():
        if chunk_index >= start_chunk:
            chunk_frame = stream.cipher.encrypt_chunk(chunk_index, chunk)
            await stream.send_frame(chunk_frame)
        bytes_sent += len(chunk)
        chunk_index += 1
        if progress_callback:
            progress_callback(bytes_sent, total_size)

    # 4. Send end-of-stream indicator
    await stream.send_frame(EOS_FRAME)

    # 5. Await verification confirmation
    ack_frame = await stream.read_frame(timeout=30.0)
    if ack_frame != b"PV_OK":
        raise TransferError(f"Receiver rejected transfer verification: {ack_frame!r}")

    return {
        "mode": mode,
        "name": name,
        "size": total_size,
        "sha256": sha256_hex,
        "chunks": chunk_index - 1,
    }


async def send_file_update(
    content: bytes,
    name: str,
    stream: DataChannelStream,
    crypto_config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
) -> Dict[str, Union[str, int]]:
    """Sends an incremental live update for an open DataChannelStream."""
    await stream.send_frame(b"PV_UPDATE")

    hasher = hashlib.sha256(content)
    total_size = len(content)
    sha256_hex = hasher.hexdigest()

    metadata = {
        "mode": "file",
        "name": name,
        "size": total_size,
        "sha256": sha256_hex,
    }
    meta_json = json.dumps(metadata).encode("utf-8")
    meta_frame = stream.cipher.encrypt_chunk(0, meta_json)
    await stream.send_frame(meta_frame)

    ready = await stream.read_frame(timeout=30.0)
    if not ready.startswith(b"PV_READY") and not ready.startswith(b"PV_RESUME:"):
        raise TransferError(f"Receiver rejected live update: {ready!r}")

    chunk_index = 1
    for i in range(0, total_size, crypto_config.chunk_size):
        chunk = content[i : i + crypto_config.chunk_size]
        chunk_frame = stream.cipher.encrypt_chunk(chunk_index, chunk)
        await stream.send_frame(chunk_frame)
        chunk_index += 1

    await stream.send_frame(EOS_FRAME)
    ack = await stream.read_frame(timeout=30.0)
    if ack != b"PV_OK":
        raise TransferError(f"Receiver failed to verify live update: {ack!r}")

    return {"name": name, "size": total_size, "sha256": sha256_hex}
