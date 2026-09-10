"""In-memory directory tarball generation and Zip-Slip protected safe extraction."""

import io
import os
import tarfile
from pathlib import Path
from typing import List


class PathTraversalError(Exception):
    """Raised when a tar entry attempts to write outside the destination directory."""


def create_directory_archive(source_dir: Path) -> bytes:
    """Recursively packages a directory into an in-memory tar.gz archive."""
    source_path = source_dir.resolve()
    if not source_path.is_dir():
        raise ValueError(f"Source path is not a directory: {source_dir}")

    buffer = io.BytesIO()
    with tarfile.open(mode="w:gz", fileobj=buffer) as tar:
        for root, dirs, files in os.walk(source_path):
            rel_dir = os.path.relpath(root, source_path)
            if rel_dir != ".":
                tar.add(root, arcname=rel_dir, recursive=False)

            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, source_path)
                tar.add(full_path, arcname=rel_path, recursive=False)

    return buffer.getvalue()


def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """Verifies that target_path strictly resolves within base_dir."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_target.is_relative_to(resolved_base)
    except (ValueError, RuntimeError):
        return False


def extract_archive_safely(archive_bytes: bytes, dest_dir: Path) -> List[str]:
    """Safely unpacks a tar.gz archive, defending against Zip-Slip path traversal."""
    dest_path = dest_dir.resolve()
    dest_path.mkdir(parents=True, exist_ok=True)

    extracted_files: List[str] = []
    buffer = io.BytesIO(archive_bytes)

    with tarfile.open(mode="r:gz", fileobj=buffer) as tar:
        members = tar.getmembers()

        # Security pre-check: inspect all entries before extracting any
        for member in members:
            # Block absolute paths or Windows drive letters in member names
            if os.path.isabs(member.name) or (len(member.name) > 1 and member.name[1] == ":"):
                raise PathTraversalError(f"Absolute path in tarball rejected: {member.name}")

            # Verify resolved target is inside destination directory
            candidate_path = dest_path / member.name
            if not is_safe_path(dest_path, candidate_path):
                raise PathTraversalError(f"Path traversal detected for member: {member.name}")

            # Block symlinks or hardlinks pointing outside the destination
            if member.issym() or member.islnk():
                link_target = member.linkname
                if os.path.isabs(link_target):
                    raise PathTraversalError(f"Absolute symlink rejected: {link_target}")
                link_candidate = (candidate_path.parent / link_target).resolve()
                if not is_safe_path(dest_path, link_candidate):
                    raise PathTraversalError(
                        f"Symlink points outside target directory: {member.name} -> {link_target}"
                    )

        # Extract all verified entries
        for member in members:
            target = dest_path / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                target.parent.mkdir(parents=True, exist_ok=True)
                source_file = tar.extractfile(member)
                if source_file is not None:
                    with open(target, "wb") as out_file:
                        while chunk := source_file.read(64 * 1024):
                            out_file.write(chunk)
                    extracted_files.append(member.name)

    return extracted_files
