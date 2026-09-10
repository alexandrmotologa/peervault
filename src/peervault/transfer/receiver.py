"""Receiver transfer coordinator for files, directories, and piped standard output."""

import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from peervault.p2p.channel import EOS_FRAME, DataChannelStream
from peervault.transfer.archive import extract_archive_safely


class ChecksumMismatchError(Exception):
    """Raised when transferred payload SHA-256 does not match sender's digest."""


async def receive_payload(
    dest_path: Optional[str],
    stream: DataChannelStream,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Union[str, int, List[str]]]:
    """Receives and verifies an incoming stream from a DataChannelStream."""
    # 1. Read metadata frame (index 0)
    meta_frame = await stream.read_frame(timeout=30.0)
    chunk_index, meta_json = stream.cipher.decrypt_chunk(meta_frame)
    if chunk_index != 0:
        raise ValueError(f"Expected metadata chunk index 0, got {chunk_index}")

    metadata = json.loads(meta_json.decode("utf-8"))
    mode = metadata.get("mode", "file")
    suggested_name = metadata.get("name", "received.data")
    expected_size = metadata.get("size", 0)
    expected_sha256 = metadata.get("sha256", "")

    # 2. Determine destination
    is_pipe = dest_path == "-"
    archive_buffer: Optional[io.BytesIO] = None
    file_handle = None
    final_destination: Optional[Path] = None

    if is_pipe:
        # Pipe directly to stdout
        pass
    elif mode == "archive":
        # Buffer tar.gz in memory for safe extraction
        archive_buffer = io.BytesIO()
        if dest_path:
            final_destination = Path(dest_path).resolve()
        else:
            folder_name = suggested_name.replace(".tar.gz", "")
            final_destination = Path(folder_name).resolve()
    else:
        # Single file
        if dest_path:
            dest_file = Path(dest_path).resolve()
            if dest_file.is_dir():
                dest_file = dest_file / suggested_name
        else:
            dest_file = Path(suggested_name).resolve()

        dest_file.parent.mkdir(parents=True, exist_ok=True)
        final_destination = dest_file
        file_handle = open(dest_file, "wb")

    # 3. Send ready confirmation
    await stream.send_frame(b"PV_READY")

    # 4. Stream receiving loop
    hasher = hashlib.sha256()
    bytes_received = 0
    expected_chunk_index = 1

    if progress_callback:
        progress_callback(bytes_received, expected_size)

    try:
        while True:
            frame = await stream.read_frame(timeout=60.0)
            if frame == EOS_FRAME:
                break

            idx, plaintext = stream.cipher.decrypt_chunk(frame)
            if idx != expected_chunk_index:
                raise ValueError(
                    f"Chunk index sequence gap: expected {expected_chunk_index}, got {idx}"
                )

            hasher.update(plaintext)
            bytes_received += len(plaintext)
            expected_chunk_index += 1

            if is_pipe:
                sys.stdout.buffer.write(plaintext)
                sys.stdout.buffer.flush()
            elif archive_buffer is not None:
                archive_buffer.write(plaintext)
            elif file_handle is not None:
                file_handle.write(plaintext)

            if progress_callback:
                progress_callback(bytes_received, expected_size)

    finally:
        if file_handle is not None:
            file_handle.close()

    # 5. Checksum verification
    computed_sha256 = hasher.hexdigest()
    if expected_sha256 and computed_sha256 != expected_sha256:
        raise ChecksumMismatchError(
            f"Checksum mismatch! Expected: {expected_sha256}, Got: {computed_sha256}"
        )

    # 6. If archive mode, extract safely
    extracted_files: List[str] = []
    if mode == "archive" and archive_buffer is not None and final_destination is not None:
        extracted_files = extract_archive_safely(archive_buffer.getvalue(), final_destination)

    # 7. Send OK verification ACK
    await stream.send_frame(b"PV_OK")

    return {
        "mode": mode,
        "name": suggested_name,
        "destination": str(final_destination) if final_destination else "stdout",
        "size": bytes_received,
        "sha256": computed_sha256,
        "extracted_files": extracted_files,
    }
