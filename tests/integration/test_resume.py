"""Integration tests for interrupted and resumed file transfers."""

import asyncio
import hashlib
import json

import pytest
from aiortc import RTCPeerConnection

from peervault.config import CryptoConfig
from peervault.p2p.channel import DataChannelStream
from peervault.transfer.receiver import receive_payload
from peervault.transfer.sender import send_payload


async def setup_direct_datachannel_pair(crypto_config: CryptoConfig):
    pc1 = RTCPeerConnection()
    pc2 = RTCPeerConnection()

    channel1 = pc1.createDataChannel("peervault", ordered=True)
    ch2_future: asyncio.Future = asyncio.get_running_loop().create_future()

    @pc2.on("datachannel")
    def on_dc(ch):
        ch2_future.set_result(ch)

    await pc1.setLocalDescription(await pc1.createOffer())
    await pc2.setRemoteDescription(pc1.localDescription)
    await pc2.setLocalDescription(await pc2.createAnswer())
    await pc1.setRemoteDescription(pc2.localDescription)

    channel2 = await ch2_future

    stream1 = DataChannelStream(channel1, crypto_config=crypto_config)
    stream2 = DataChannelStream(channel2, crypto_config=crypto_config)

    return pc1, pc2, stream1, stream2


@pytest.mark.asyncio
async def test_resumable_transfer_after_simulated_interruption(tmp_path):
    chunk_size = 64 * 1024
    custom_crypto = CryptoConfig(chunk_size=chunk_size)

    pc1, pc2, stream1, stream2 = await setup_direct_datachannel_pair(custom_crypto)
    transport_key = b"R" * 32

    await asyncio.gather(
        stream1.perform_handshake(transport_key),
        stream2.perform_handshake(transport_key),
    )

    # 1. Create a 300 KB test file (approx 5 chunks with 64KB chunk size)
    src_file = tmp_path / "source_big.bin"
    payload = b"Z" * (chunk_size * 4 + 12345)
    src_file.write_bytes(payload)

    dest_file = tmp_path / "dest_big.bin"

    # 2. Simulate existing partial transfer (2 chunks already received in .part file)
    part_file = tmp_path / "dest_big.bin.peervault.part"
    meta_file = tmp_path / "dest_big.bin.peervault.meta"

    full_sha256 = hashlib.sha256(payload).hexdigest()

    # Pre-populate 2 chunks in .part file
    part_file.write_bytes(payload[: chunk_size * 2])
    meta_data = {
        "sha256": full_sha256,
        "total_size": len(payload),
        "chunk_size": chunk_size,
        "confirmed_chunks": [1, 2],
    }
    meta_file.write_text(json.dumps(meta_data), encoding="utf-8")

    # 3. Run sender and receiver concurrently with resume
    send_task = asyncio.create_task(
        send_payload(
            source=str(src_file),
            stream=stream1,
            crypto_config=custom_crypto,
        )
    )
    receive_task = asyncio.create_task(
        receive_payload(
            dest_path=str(dest_file),
            stream=stream2,
            auto_accept=True,
            overwrite=True,
            crypto_config=custom_crypto,
        )
    )

    send_res, recv_res = await asyncio.gather(send_task, receive_task)

    # 4. Verify results
    assert dest_file.is_file()
    assert dest_file.read_bytes() == payload
    assert recv_res["sha256"] == full_sha256
    assert not part_file.exists()
    assert not meta_file.exists()

    await stream1.close()
    await stream2.close()
    await pc1.close()
    await pc2.close()
