"""Unit tests for clipboard operations and auto-clear timer."""

import pytest

from peervault.transfer import clipboard


def test_clipboard_read_write(monkeypatch):
    mock_store = {"content": ""}

    def mock_get():
        return mock_store["content"]

    def mock_set(text: str):
        mock_store["content"] = text

    monkeypatch.setattr(clipboard, "get_clipboard_text", mock_get)
    monkeypatch.setattr(clipboard, "set_clipboard_text", mock_set)

    test_secret = "ghp_superSecretToken123456"
    clipboard.set_clipboard_text(test_secret)
    assert clipboard.get_clipboard_text() == test_secret


@pytest.mark.asyncio
async def test_auto_clear_clipboard(monkeypatch):
    mock_store = {"content": "my-temporary-token"}
    cleared_flag = False

    def mock_get():
        return mock_store["content"]

    def mock_set(text: str):
        mock_store["content"] = text

    def on_cleared():
        nonlocal cleared_flag
        cleared_flag = True

    monkeypatch.setattr(clipboard, "get_clipboard_text", mock_get)
    monkeypatch.setattr(clipboard, "set_clipboard_text", mock_set)

    # Run auto clear with very short timeout
    await clipboard.auto_clear_clipboard(
        target_secret="my-temporary-token",
        timeout_seconds=0.05,
        on_cleared=on_cleared,
    )

    assert mock_store["content"] == ""
    assert cleared_flag is True
