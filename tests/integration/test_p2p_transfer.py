"""End-to-end integration tests for P2P transfers over loopback WebRTC."""

import asyncio
import hashlib
import os
import tempfile
from pathlib import Path

import pytest
from aiortc import RTCPeerConnection

from peervault.config import CryptoConfig
from peervault.p2p.channel import DataChannelStream
from peervault.transfer.receiver import receive_payload
from peervault.transfer.sender import send_payload

FAST_CRYPTO = CryptoConfig(
    argon2_time_cost=1,
    argon2_memory_cost=8 * 1024,
    argon2_parallelism=2,
    chunk_size=16 * 1024,  # 16 KB chunks for testing
)


async def setup_direct_datachannel_pair():
    """Sets up two directly connected RTCPeerConnections and DataChannelStreams."""
    pc1 = RTCPeerConnection()
    pc2 = RTCPeerConnection()

    channel1 = pc1.createDataChannel("peervault", ordered=True)
    ch2_future: asyncio.Future = asyncio.get_running_loop().create_future()

    @pc2.on("datachannel")
    def on_dc(ch):
        ch2_future.set_result(ch)

    # Perform loopback SDP exchange
    await pc1.setLocalDescription(await pc1.createOffer())
    await pc2.setRemoteDescription(pc1.localDescription)
    await pc2.setLocalDescription(await pc2.createAnswer())
    await pc1.setRemoteDescription(pc2.localDescription)

    channel2 = await ch2_future

    stream1 = DataChannelStream(channel1, crypto_config=FAST_CRYPTO)
    stream2 = DataChannelStream(channel2, crypto_config=FAST_CRYPTO)

    return pc1, pc2, stream1, stream2


@pytest.mark.asyncio
async def test_end_to_end_file_transfer():
    pc1, pc2, stream1, stream2 = await setup_direct_datachannel_pair()
    transport_base_key = b"K" * 32

    # Run in-band ephemeral X25519 handshakes concurrently
    h1, h2 = await asyncio.gather(
        stream1.perform_handshake(transport_base_key),
        stream2.perform_handshake(transport_base_key),
    )
    assert h1 == h2

    # Create a 256 KB test file with random bytes
    test_data = os.urandom(256 * 1024)
    expected_hash = hashlib.sha256(test_data).hexdigest()

    with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dst_dir:
        src_file = Path(src_dir) / "sample_secret.bin"
        src_file.write_bytes(test_data)

        dst_file = Path(dst_dir) / "received.bin"

        # Run sender and receiver concurrently
        send_task = asyncio.create_task(
            send_payload(str(src_file), stream1, crypto_config=FAST_CRYPTO)
        )
        recv_task = asyncio.create_task(receive_payload(str(dst_file), stream2))

        send_res, recv_res = await asyncio.gather(send_task, recv_task)

        assert send_res["sha256"] == expected_hash
        assert recv_res["sha256"] == expected_hash
        assert dst_file.read_bytes() == test_data

    await stream1.close()
    await stream2.close()
    await pc1.close()
    await pc2.close()


@pytest.mark.asyncio
async def test_end_to_end_directory_transfer():
    pc1, pc2, stream1, stream2 = await setup_direct_datachannel_pair()
    transport_base_key = b"D" * 32

    await asyncio.gather(
        stream1.perform_handshake(transport_base_key),
        stream2.perform_handshake(transport_base_key),
    )

    with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dst_dir:
        src_path = Path(src_dir) / "nested_configs"
        src_path.mkdir()
        (src_path / "env.local").write_text("DEBUG=true", encoding="utf-8")
        (src_path / "certs").mkdir()
        (src_path / "certs" / "ca.crt").write_text("CERT_DATA", encoding="utf-8")

        dst_path = Path(dst_dir) / "unpacked_configs"

        send_task = asyncio.create_task(
            send_payload(str(src_path), stream1, crypto_config=FAST_CRYPTO)
        )
        recv_task = asyncio.create_task(receive_payload(str(dst_path), stream2))

        await asyncio.gather(send_task, recv_task)

        assert (dst_path / "env.local").read_text(encoding="utf-8") == "DEBUG=true"
        assert (dst_path / "certs" / "ca.crt").read_text(encoding="utf-8") == "CERT_DATA"

    await stream1.close()
    await stream2.close()
    await pc1.close()
    await pc2.close()
