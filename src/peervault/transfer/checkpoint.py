"""Transfer checkpoint manager for resumable chunked file transfers."""

import json
from pathlib import Path
from typing import Optional, Set


class TransferCheckpoint:
    """Manages .peervault.part data files and .peervault.meta checkpoint metadata."""

    def __init__(self, target_file: Path, expected_sha256: str, total_size: int, chunk_size: int):
        self.target_file = target_file.resolve()
        self.expected_sha256 = expected_sha256
        self.total_size = total_size
        self.chunk_size = chunk_size

        self.part_file = self.target_file.parent / f"{self.target_file.name}.peervault.part"
        self.meta_file = self.target_file.parent / f"{self.target_file.name}.peervault.meta"
        self.confirmed_chunks: Set[int] = set()

        self._load_meta()

    def _load_meta(self) -> None:
        """Loads checkpoint metadata if valid and matching expected SHA-256."""
        if not self.meta_file.is_file() or not self.part_file.is_file():
            return

        try:
            data = json.loads(self.meta_file.read_text(encoding="utf-8"))
            if (
                data.get("sha256") == self.expected_sha256
                and data.get("total_size") == self.total_size
            ):
                self.confirmed_chunks = set(data.get("confirmed_chunks", []))
        except Exception:
            self.confirmed_chunks.clear()

    def get_resume_chunk_index(self) -> Optional[int]:
        """Calculates the first missing contiguous chunk index, or None if starting fresh."""
        if not self.confirmed_chunks or not self.part_file.is_file():
            return None

        # Check contiguous sequence starting at 1
        contiguous_max = 0
        while (contiguous_max + 1) in self.confirmed_chunks:
            contiguous_max += 1

        if contiguous_max == 0:
            return None

        # Truncate part file to exact byte boundary of contiguous chunks
        expected_bytes = contiguous_max * self.chunk_size
        actual_size = self.part_file.stat().st_size
        if actual_size < expected_bytes:
            contiguous_max = actual_size // self.chunk_size

        return contiguous_max + 1 if contiguous_max > 0 else None

    def record_chunk(self, chunk_index: int) -> None:
        """Records a successfully written chunk index to metadata."""
        self.confirmed_chunks.add(chunk_index)
        # Periodically persist metadata every 10 chunks or when complete
        if len(self.confirmed_chunks) % 10 == 0:
            self.flush_meta()

    def flush_meta(self) -> None:
        """Persists the current chunk confirmation set to disk."""
        data = {
            "sha256": self.expected_sha256,
            "total_size": self.total_size,
            "chunk_size": self.chunk_size,
            "confirmed_chunks": sorted(list(self.confirmed_chunks)),
        }
        self.meta_file.write_text(json.dumps(data), encoding="utf-8")

    def finalize(self) -> Path:
        """Atomically promotes the .part file to final destination and cleans up metadata."""
        if self.meta_file.exists():
            try:
                self.meta_file.unlink()
            except Exception:
                pass

        if self.target_file.exists():
            self.target_file.unlink()

        self.part_file.rename(self.target_file)
        return self.target_file
