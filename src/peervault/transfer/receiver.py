"""Receiver transfer coordinator for files, directories, and piped standard output."""

import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from peervault.config import DEFAULT_CRYPTO_CONFIG, CryptoConfig
from peervault.p2p.channel import EOS_FRAME, DataChannelStream
from peervault.transfer.archive import extract_archive_safely
from peervault.transfer.checkpoint import TransferCheckpoint


class ChecksumMismatchError(Exception):
    """Raised when transferred payload SHA-256 does not match sender's digest."""


class TransferRejectedError(Exception):
    """Raised when the receiver declines the transfer."""


def get_unique_path(target: Path) -> Path:
    """Returns an unused path by appending (1), (2), etc. if the file or directory exists."""
    if not target.exists():
        return target

    parent = target.parent
    if target.is_dir() or target.name.endswith(".tar.gz"):
        base_name = (
            target.name.replace(".tar.gz", "") if target.name.endswith(".tar.gz") else target.name
        )
        suffix = ".tar.gz" if target.name.endswith(".tar.gz") else ""
    else:
        base_name = target.stem
        suffix = target.suffix

    counter = 1
    while True:
        candidate = parent / f"{base_name} ({counter}){suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


async def receive_payload(
    dest_path: Optional[str],
    stream: DataChannelStream,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    confirm_callback: Optional[Callable[[Dict[str, Union[str, int]]], bool]] = None,
    auto_accept: bool = False,
    overwrite: bool = False,
    crypto_config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
) -> Dict[str, Union[str, int, List[str]]]:
    """Receives, previews, resumes, and verifies an incoming stream from a DataChannelStream."""
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

    is_pipe = dest_path == "-"

    # 2. Interactive confirmation prompt
    if confirm_callback and not auto_accept and not is_pipe:
        accepted = confirm_callback(metadata)
        if not accepted:
            await stream.send_frame(b"PV_REJECT:Declined by receiver")
            raise TransferRejectedError("Transfer was declined by user")

    # 3. Determine destination and safe overwrite handling
    archive_buffer: Optional[io.BytesIO] = None
    file_handle = None
    final_destination: Optional[Path] = None
    checkpoint: Optional[TransferCheckpoint] = None

    if is_pipe:
        pass
    elif mode == "archive":
        archive_buffer = io.BytesIO()
        if dest_path:
            final_destination = Path(dest_path).resolve()
        else:
            folder_name = suggested_name.replace(".tar.gz", "")
            final_destination = Path(folder_name).resolve()

        if final_destination.exists() and not overwrite:
            final_destination = get_unique_path(final_destination)
    else:
        if dest_path:
            dest_file = Path(dest_path).resolve()
            if dest_file.is_dir():
                dest_file = dest_file / suggested_name
        else:
            dest_file = Path(suggested_name).resolve()

        if dest_file.exists() and not overwrite:
            dest_file = get_unique_path(dest_file)

        dest_file.parent.mkdir(parents=True, exist_ok=True)
        final_destination = dest_file
        checkpoint = TransferCheckpoint(
            target_file=dest_file,
            expected_sha256=expected_sha256,
            total_size=expected_size,
            chunk_size=crypto_config.chunk_size,
        )

    # 4. Check for resumption opportunity
    hasher = hashlib.sha256()
    bytes_received = 0
    expected_chunk_index = 1

    if checkpoint is not None:
        resume_chunk = checkpoint.get_resume_chunk_index()
        if resume_chunk and resume_chunk > 1:
            # Resuming from part file
            expected_chunk_index = resume_chunk
            bytes_received = (resume_chunk - 1) * crypto_config.chunk_size
            # Pre-hash existing bytes
            with open(checkpoint.part_file, "rb") as pf:
                while chk := pf.read(128 * 1024):
                    hasher.update(chk)
            file_handle = open(checkpoint.part_file, "ab")
            await stream.send_frame(f"PV_RESUME:{resume_chunk}".encode("utf-8"))
        else:
            file_handle = open(checkpoint.part_file, "wb")
            await stream.send_frame(b"PV_READY")
    else:
        await stream.send_frame(b"PV_READY")

    # 5. Stream receiving loop
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
                if checkpoint is not None:
                    checkpoint.record_chunk(idx)

            if progress_callback:
                progress_callback(bytes_received, expected_size)

    finally:
        if file_handle is not None:
            file_handle.close()

    # 6. Checksum verification
    computed_sha256 = hasher.hexdigest()
    if expected_sha256 and computed_sha256 != expected_sha256:
        raise ChecksumMismatchError(
            f"Checksum mismatch! Expected: {expected_sha256}, Got: {computed_sha256}"
        )

    # 7. Promote part file to destination
    if checkpoint is not None:
        final_destination = checkpoint.finalize()

    # 8. Safe extraction for archive mode
    extracted_files: List[str] = []
    if mode == "archive" and archive_buffer is not None and final_destination is not None:
        extracted_files = extract_archive_safely(archive_buffer.getvalue(), final_destination)

    # 9. Send OK verification ACK
    await stream.send_frame(b"PV_OK")

    return {
        "mode": mode,
        "name": suggested_name,
        "destination": str(final_destination) if final_destination else "stdout",
        "size": bytes_received,
        "sha256": computed_sha256,
        "extracted_files": extracted_files,
    }
