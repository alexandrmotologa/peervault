"""File change detection and live watch streaming coordinator."""

import asyncio
import hashlib
from pathlib import Path
from typing import AsyncGenerator, Optional, Tuple


class FileWatcher:
    """Monitors a file for changes using modification timestamps and SHA-256 digests."""

    def __init__(self, target_path: Path, poll_interval: float = 0.5):
        self.target_path = target_path.resolve()
        self.poll_interval = poll_interval
        self._last_mtime: Optional[int] = None
        self._last_sha256: Optional[str] = None

    def _compute_digest(self) -> Tuple[int, str, bytes]:
        """Reads the file and returns (mtime_ns, sha256_hex, content)."""
        stat = self.target_path.stat()
        content = self.target_path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        return stat.st_mtime_ns, digest, content

    async def watch(self) -> AsyncGenerator[Tuple[bytes, str], None]:
        """Yields (new_content, new_sha256) whenever the file content changes."""
        if not self.target_path.is_file():
            raise ValueError(f"Watch target must be a regular file: {self.target_path}")

        self._last_mtime, self._last_sha256, _ = self._compute_digest()

        while True:
            await asyncio.sleep(self.poll_interval)
            try:
                if not self.target_path.exists():
                    continue

                mtime = self.target_path.stat().st_mtime_ns
                if mtime != self._last_mtime:
                    _, current_digest, content = self._compute_digest()
                    if current_digest != self._last_sha256:
                        self._last_mtime = mtime
                        self._last_sha256 = current_digest
                        yield content, current_digest
            except Exception:
                # File might be temporarily locked while saving
                continue
