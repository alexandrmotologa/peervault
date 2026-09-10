"""Unit tests for local LAN UDP discovery."""

import asyncio
import socket

import pytest

from peervault.discovery.lan import LAN_BEACON_MAGIC


@pytest.mark.asyncio
async def test_lan_discovery_packet_format():
    test_room = "test-room-hash-123"
    test_port = 9999

    import json

    payload = {"room": test_room, "port": test_port}
    encoded = (LAN_BEACON_MAGIC + json.dumps(payload)).encode("utf-8")

    assert encoded.startswith(b"PV_LAN_V1:")
    parsed = json.loads(encoded[len(LAN_BEACON_MAGIC) :].decode("utf-8"))
    assert parsed["room"] == test_room
    assert parsed["port"] == test_port


@pytest.mark.asyncio
async def test_udp_discovery_loopback():
    test_port = 18766
    test_room = "unique-room-xyz"

    sock_receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_receiver.bind(("127.0.0.1", test_port))
    sock_receiver.setblocking(False)

    sock_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    import json

    msg = (LAN_BEACON_MAGIC + json.dumps({"room": test_room, "port": 8765})).encode("utf-8")

    loop = asyncio.get_running_loop()

    async def send_after_delay():
        await asyncio.sleep(0.05)
        sock_sender.sendto(msg, ("127.0.0.1", test_port))

    send_task = asyncio.create_task(send_after_delay())

    data, addr = await loop.sock_recvfrom(sock_receiver, 1024)
    await send_task

    assert data.startswith(b"PV_LAN_V1:")
    parsed = json.loads(data[len(LAN_BEACON_MAGIC) :].decode("utf-8"))
    assert parsed["room"] == test_room
    assert parsed["port"] == 8765

    sock_sender.close()
    sock_receiver.close()
