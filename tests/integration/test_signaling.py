"""Integration tests for the WebSocket signaling server and client."""

import socket

import pytest

from peervault.config import CryptoConfig
from peervault.signaling.client import SignalingClient
from peervault.signaling.server import SignalingServer

FAST_CRYPTO = CryptoConfig(
    argon2_time_cost=1,
    argon2_memory_cost=8 * 1024,
    argon2_parallelism=2,
)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_signaling_rendezvous_and_exchange():
    server = SignalingServer()
    await server.start("127.0.0.1", 0)
    relay_url = f"ws://127.0.0.1:{server.port}"

    passphrase = "7-copper-falcon"

    alice = SignalingClient(
        relay_url=relay_url,
        passphrase=passphrase,
        role="sender",
        crypto_config=FAST_CRYPTO,
    )
    bob = SignalingClient(
        relay_url=relay_url,
        passphrase=passphrase,
        role="receiver",
        crypto_config=FAST_CRYPTO,
    )

    try:
        await alice.connect()
        alice_peer_present = await alice.join()
        assert alice_peer_present is False

        await bob.connect()
        bob_peer_present = await bob.join()
        assert bob_peer_present is True

        # Alice should now see that peer joined
        await alice.wait_for_peer(timeout=5.0)

        # Alice sends offer
        await alice.send_signal({"type": "offer", "sdp": "test-offer-sdp"})
        bob_received = await bob.receive_signal(timeout=5.0)
        assert bob_received == {"type": "offer", "sdp": "test-offer-sdp"}

        # Bob sends answer
        await bob.send_signal({"type": "answer", "sdp": "test-answer-sdp"})
        alice_received = await alice.receive_signal(timeout=5.0)
        assert alice_received == {"type": "answer", "sdp": "test-answer-sdp"}

    finally:
        await alice.close()
        await bob.close()
        await server.stop()
