"""Integration test verifying signaling server serves embedded web receiver over HTTP."""

import asyncio
import urllib.request

import pytest

from peervault.signaling.server import SignalingServer


@pytest.mark.asyncio
async def test_server_serves_embedded_web_app():
    server = SignalingServer()
    await server.start("127.0.0.1", 0)
    port = server.port

    try:
        # Request HTTP root
        def fetch_url(url: str):
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status, resp.headers.get("Content-Type"), resp.read().decode("utf-8")

        status, content_type, body = await asyncio.to_thread(fetch_url, f"http://127.0.0.1:{port}/")
        assert status == 200
        assert "text/html" in content_type
        assert "PeerVault" in body
        assert "P2P Web Receiver" in body

        # Request /web path
        status_web, _, body_web = await asyncio.to_thread(fetch_url, f"http://127.0.0.1:{port}/web")
        assert status_web == 200
        assert "PeerVault" in body_web

    finally:
        await server.stop()
