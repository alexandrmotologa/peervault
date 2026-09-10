"""Full stack workflow test: signaling server + WebRTC negotiation + P2P transfer."""

import asyncio
import hashlib
import tempfile
from pathlib import Path

import pytest

from peervault.config import CryptoConfig
from peervault.p2p.channel import DataChannelStream
from peervault.p2p.connection import (
    create_peer_connection,
    negotiate_receiver,
    negotiate_sender,
)
from peervault.signaling.client import SignalingClient
from peervault.signaling.server import SignalingServer
from peervault.transfer.receiver import receive_payload
from peervault.transfer.sender import send_payload

FAST = CryptoConfig(
    argon2_time_cost=1,
    argon2_memory_cost=8 * 1024,
    argon2_parallelism=2,
    chunk_size=16 * 1024,
)


@pytest.mark.asyncio
async def test_full_signaling_and_webrtc_transfer():
    server = SignalingServer()
    await server.start("127.0.0.1", 0)
    relay_url = f"ws://127.0.0.1:{server.port}"
    passphrase = "14-ruby-falcon"

    test_payload = b"SUPER_SECRET_PRODUCTION_DATABASE_PASSWORD_XYZ123\n" * 100
    expected_hash = hashlib.sha256(test_payload).hexdigest()

    sig_sender = SignalingClient(relay_url, passphrase, "sender", crypto_config=FAST)
    sig_receiver = SignalingClient(relay_url, passphrase, "receiver", crypto_config=FAST)

    await sig_sender.connect()
    await sig_sender.join()

    await sig_receiver.connect()
    await sig_receiver.join()

    await sig_sender.wait_for_peer()

    pc_sender = create_peer_connection()
    pc_receiver = create_peer_connection()

    t1 = asyncio.create_task(negotiate_sender(pc_sender, sig_sender))
    t2 = asyncio.create_task(negotiate_receiver(pc_receiver, sig_receiver))
    ch_sender, ch_receiver = await asyncio.gather(t1, t2)

    s_sender = DataChannelStream(ch_sender, crypto_config=FAST)
    s_receiver = DataChannelStream(ch_receiver, crypto_config=FAST)

    h1 = asyncio.create_task(s_sender.perform_handshake(bytes(sig_sender.transport_base_key)))
    h2 = asyncio.create_task(s_receiver.perform_handshake(bytes(sig_receiver.transport_base_key)))
    await asyncio.gather(h1, h2)

    with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dst_dir:
        src_file = Path(src_dir) / ".env.production"
        src_file.write_bytes(test_payload)
        dst_file = Path(dst_dir) / ".env.received"

        tr1 = asyncio.create_task(send_payload(str(src_file), s_sender, crypto_config=FAST))
        tr2 = asyncio.create_task(receive_payload(str(dst_file), s_receiver))
        send_res, recv_res = await asyncio.gather(tr1, tr2)

        assert send_res["sha256"] == expected_hash
        assert recv_res["sha256"] == expected_hash
        assert dst_file.read_bytes() == test_payload

    await s_sender.close()
    await s_receiver.close()
    await pc_sender.close()
    await pc_receiver.close()
    await sig_sender.close()
    await sig_receiver.close()
    await server.stop()
