"""Unit tests for directory archiving and Zip-Slip path traversal protection."""

import io
import tarfile
import tempfile
from pathlib import Path

import pytest

from peervault.transfer.archive import (
    PathTraversalError,
    create_batch_archive,
    create_directory_archive,
    extract_archive_safely,
)


def test_archive_and_safe_extraction_roundtrip():
    with tempfile.TemporaryDirectory() as src_temp, tempfile.TemporaryDirectory() as dst_temp:
        src_path = Path(src_temp)
        dst_path = Path(dst_temp)

        # Create nested file structure
        (src_path / "sub").mkdir()
        (src_path / "sub" / "config.json").write_text('{"app": "peervault"}', encoding="utf-8")
        (src_path / "secret.env").write_text("API_KEY=12345", encoding="utf-8")

        # Archive directory
        tar_bytes = create_directory_archive(src_path)
        assert len(tar_bytes) > 0

        # Extract safely
        extracted = extract_archive_safely(tar_bytes, dst_path)
        assert len(extracted) == 2

        assert (dst_path / "sub" / "config.json").read_text(
            encoding="utf-8"
        ) == '{"app": "peervault"}'
        assert (dst_path / "secret.env").read_text(encoding="utf-8") == "API_KEY=12345"


def test_zip_slip_path_traversal_blocked():
    buf = io.BytesIO()
    with tarfile.open(mode="w:gz", fileobj=buf) as tar:
        # Create malicious entry attempting to escape directory
        data = b"malicious content"
        ti = tarfile.TarInfo(name="../../escaped.txt")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

    malicious_tar = buf.getvalue()

    with tempfile.TemporaryDirectory() as dst_temp:
        dst_path = Path(dst_temp)
        with pytest.raises(PathTraversalError):
            extract_archive_safely(malicious_tar, dst_path)


def test_absolute_path_blocked():
    buf = io.BytesIO()
    with tarfile.open(mode="w:gz", fileobj=buf) as tar:
        data = b"root content"
        ti = tarfile.TarInfo(name="/etc/passwd")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

    malicious_tar = buf.getvalue()

    with tempfile.TemporaryDirectory() as dst_temp:
        dst_path = Path(dst_temp)
        with pytest.raises(PathTraversalError):
            extract_archive_safely(malicious_tar, dst_path)


def test_batch_archive_and_extraction():
    with tempfile.TemporaryDirectory() as src_temp, tempfile.TemporaryDirectory() as dst_temp:
        src_path = Path(src_temp)
        dst_path = Path(dst_temp)

        f1 = src_path / "file1.txt"
        f1.write_text("content 1", encoding="utf-8")
        f2 = src_path / "file2.json"
        f2.write_text('{"key": "value"}', encoding="utf-8")

        sub = src_path / "subdir"
        sub.mkdir()
        (sub / "nested.txt").write_text("nested content", encoding="utf-8")

        tar_bytes = create_batch_archive([f1, f2, sub])
        assert len(tar_bytes) > 0

        extracted = extract_archive_safely(tar_bytes, dst_path)
        assert len(extracted) >= 3
        assert (dst_path / "file1.txt").read_text(encoding="utf-8") == "content 1"
        assert (dst_path / "file2.json").read_text(encoding="utf-8") == '{"key": "value"}'
        assert (dst_path / "subdir" / "nested.txt").read_text(encoding="utf-8") == "nested content"
