"""Zero-infrastructure local LAN discovery and direct peer rendezvous over UDP broadcast."""

import asyncio
import json
import logging
import socket
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

LAN_BEACON_MAGIC = "PV_LAN_V1:"
DEFAULT_LAN_PORT = 8766


class LANBeaconBroadcaster:
    """Periodically broadcasts UDP discovery beacons on the local network."""

    def __init__(
        self,
        room_id: str,
        local_port: int,
        broadcast_port: int = DEFAULT_LAN_PORT,
        interval: float = 1.0,
    ):
        self.room_id = room_id
        self.local_port = local_port
        self.broadcast_port = broadcast_port
        self.interval = interval
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Starts the background broadcast task."""
        self._running = True
        self._task = asyncio.create_task(self._run_loop())

    async def _run_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)

        payload = {
            "room": self.room_id,
            "port": self.local_port,
        }
        message = (LAN_BEACON_MAGIC + json.dumps(payload)).encode("utf-8")

        try:
            while self._running:
                try:
                    sock.sendto(message, ("255.255.255.255", self.broadcast_port))
                except Exception as err:
                    logger.debug("LAN beacon broadcast failed: %s", err)
                await asyncio.sleep(self.interval)
        finally:
            sock.close()

    async def stop(self) -> None:
        """Stops the broadcaster."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


async def discover_lan_peer(
    room_id: str,
    timeout: float = 30.0,
    listen_port: int = DEFAULT_LAN_PORT,
) -> Tuple[str, int]:
    """Listens for a local UDP discovery beacon matching room_id.

    Returns the (sender_ip, sender_port) of the discovered peer.
    """
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_BROADCAST"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    sock.bind(("", listen_port))
    sock.setblocking(False)

    try:
        start_time = loop.time()
        while (loop.time() - start_time) < timeout:
            try:
                data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), timeout=1.0)
                text = data.decode("utf-8", errors="ignore")
                if text.startswith(LAN_BEACON_MAGIC):
                    raw_json = text[len(LAN_BEACON_MAGIC) :]
                    info = json.loads(raw_json)
                    if info.get("room") == room_id:
                        sender_ip = addr[0]
                        sender_port = info.get("port")
                        return sender_ip, int(sender_port)
            except asyncio.TimeoutError:
                continue
            except Exception as err:
                logger.debug("Error while reading LAN discovery beacon: %s", err)

        raise TimeoutError(f"No LAN peer discovered for room within {timeout} seconds")
    finally:
        sock.close()
