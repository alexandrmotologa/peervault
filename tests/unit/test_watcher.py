"""Unit tests for FileWatcher change detection."""

import asyncio

import pytest

from peervault.transfer.watcher import FileWatcher


@pytest.mark.asyncio
async def test_file_watcher_detects_modification(tmp_path):
    target = tmp_path / "env.local"
    target.write_text("VERSION=1", encoding="utf-8")

    watcher = FileWatcher(target, poll_interval=0.05)

    async def update_file():
        await asyncio.sleep(0.1)
        target.write_text("VERSION=2", encoding="utf-8")

    async def watch_first():
        async for content, digest in watcher.watch():
            return content, digest

    update_task = asyncio.create_task(update_file())
    watch_task = asyncio.create_task(watch_first())

    content, digest = await watch_task
    await update_task

    assert content == b"VERSION=2"
    assert len(digest) == 64
