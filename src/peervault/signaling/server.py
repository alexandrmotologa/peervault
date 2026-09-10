"""Standalone in-memory WebSocket signaling relay for rendezvous and SDP/ICE exchange."""

import asyncio
import json
import logging
import time
from http import HTTPStatus
from pathlib import Path
from typing import Any, Dict, Optional, Set

from websockets.asyncio.server import Server, serve
from websockets.exceptions import ConnectionClosed

from peervault.config import DEFAULT_NETWORK_CONFIG, NetworkConfig
from peervault.signaling.protocol import Action, Status

logger = logging.getLogger(__name__)

WEB_HTML_PATH = Path(__file__).parent.parent / "web" / "index.html"


class SignalingServer:
    """Lightweight in-memory signaling relay with zero persistence."""

    def __init__(self, config: NetworkConfig = DEFAULT_NETWORK_CONFIG):
        self.config = config
        # room_id -> {websocket: {"role": role, "joined_at": float}}
        self.rooms: Dict[str, Dict[Any, Dict[str, Any]]] = {}
        # websocket -> room_id
        self.connection_to_room: Dict[Any, str] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        self._server: Optional[Server] = None

    async def handle_connection(self, websocket: Any) -> None:
        """Handles lifecycle for an incoming client WebSocket connection."""
        try:
            async for raw_message in websocket:
                try:
                    data = json.loads(raw_message)
                except json.JSONDecodeError:
                    await websocket.send(
                        json.dumps({"status": Status.ERROR, "message": "invalid_json"})
                    )
                    continue

                action = data.get("action")
                if action == Action.JOIN:
                    await self._handle_join(websocket, data)
                elif action == Action.SIGNAL:
                    await self._handle_signal(websocket, data)
                elif action == Action.LEAVE:
                    await self._handle_leave(websocket)
                    break
        except ConnectionClosed:
            pass
        finally:
            await self._handle_leave(websocket)

    async def _handle_join(self, websocket: Any, data: Dict[str, Any]) -> None:
        room_id = data.get("room")
        role = data.get("role", "peer")

        if not room_id or not isinstance(room_id, str):
            await websocket.send(json.dumps({"status": Status.ERROR, "message": "missing_room_id"}))
            return

        if room_id not in self.rooms:
            self.rooms[room_id] = {}

        room_peers = self.rooms[room_id]

        if len(room_peers) >= 2 and websocket not in room_peers:
            await websocket.send(json.dumps({"status": Status.ERROR, "message": "room_full"}))
            return

        room_peers[websocket] = {"role": role, "joined_at": time.time()}
        self.connection_to_room[websocket] = room_id

        peer_present = len(room_peers) > 1

        # Acknowledge joining to the current client
        await websocket.send(
            json.dumps(
                {
                    "status": Status.JOINED,
                    "room": room_id,
                    "peer_present": peer_present,
                }
            )
        )

        # Notify the other peer if already waiting in the room
        if peer_present:
            for other_ws in list(room_peers.keys()):
                if other_ws != websocket:
                    try:
                        await other_ws.send(
                            json.dumps(
                                {
                                    "status": Status.PEER_JOINED,
                                    "room": room_id,
                                    "role": role,
                                }
                            )
                        )
                    except ConnectionClosed:
                        pass

    async def _handle_signal(self, websocket: Any, data: Dict[str, Any]) -> None:
        room_id = self.connection_to_room.get(websocket)
        if not room_id or room_id not in self.rooms:
            await websocket.send(json.dumps({"status": Status.ERROR, "message": "not_in_room"}))
            return

        room_peers = self.rooms[room_id]
        forwarded = 0
        for other_ws in list(room_peers.keys()):
            if other_ws != websocket:
                try:
                    await other_ws.send(
                        json.dumps(
                            {
                                "action": Action.SIGNAL,
                                "room": room_id,
                                "ciphertext": data.get("ciphertext"),
                                "nonce": data.get("nonce"),
                            }
                        )
                    )
                    forwarded += 1
                except ConnectionClosed:
                    pass

        if forwarded == 0:
            await websocket.send(json.dumps({"status": Status.ERROR, "message": "no_peer_in_room"}))

    async def _handle_leave(self, websocket: Any) -> None:
        room_id = self.connection_to_room.pop(websocket, None)
        if not room_id or room_id not in self.rooms:
            return

        room_peers = self.rooms[room_id]
        room_peers.pop(websocket, None)

        # Notify remaining peer that peer left
        for other_ws in list(room_peers.keys()):
            try:
                await other_ws.send(json.dumps({"status": Status.PEER_LEFT, "room": room_id}))
            except ConnectionClosed:
                pass

        if not room_peers:
            self.rooms.pop(room_id, None)

    async def _cleanup_loop(self) -> None:
        """Periodically removes abandoned rooms exceeding TTL."""
        while True:
            try:
                await asyncio.sleep(30)
                now = time.time()
                expired_rooms: Set[str] = set()

                for room_id, peers in list(self.rooms.items()):
                    if not peers:
                        expired_rooms.add(room_id)
                        continue
                    oldest = min(p["joined_at"] for p in peers.values())
                    if now - oldest > self.config.room_ttl_seconds:
                        expired_rooms.add(room_id)

                for room_id in expired_rooms:
                    peers = self.rooms.pop(room_id, {})
                    for ws in list(peers.keys()):
                        self.connection_to_room.pop(ws, None)
                        try:
                            await ws.send(
                                json.dumps(
                                    {
                                        "status": Status.ERROR,
                                        "message": "room_expired",
                                    }
                                )
                            )
                            await ws.close()
                        except ConnectionClosed:
                            pass
            except asyncio.CancelledError:
                break
            except Exception as err:
                logger.error("Error in cleanup loop: %s", err)

    @property
    def port(self) -> int:
        """Returns the actual bound TCP port of the running server."""
        if self._server and self._server.server and self._server.server.sockets:
            return self._server.server.sockets[0].getsockname()[1]
        return 0

    def process_http_request(self, connection: Any, request: Any) -> Any:
        """Serves the static WebRTC receiver web page over HTTP on the same port."""
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return None

        if request.path in ("/", "/index.html", "/web", "/web/"):
            if WEB_HTML_PATH.is_file():
                html_text = WEB_HTML_PATH.read_text(encoding="utf-8")
                response = connection.respond(HTTPStatus.OK, html_text)
                try:
                    del response.headers["Content-Type"]
                except Exception:
                    pass
                response.headers["Content-Type"] = "text/html; charset=utf-8"
                return response
        return None

    async def start(self, host: str = "0.0.0.0", port: int = 8765) -> Server:
        """Starts the signaling server and background cleanup task."""
        self._server = await serve(
            self.handle_connection,
            host,
            port,
            process_request=self.process_http_request,
        )
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Signaling relay server running on ws://%s:%d", host, port)
        return self._server

    async def stop(self) -> None:
        """Closes all connections and stops the server."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        for room_peers in list(self.rooms.values()):
            for ws in list(room_peers.keys()):
                try:
                    await ws.close()
                except Exception:
                    pass
        self.rooms.clear()
        self.connection_to_room.clear()

        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                pass


async def run_server(host: str = "0.0.0.0", port: int = 8765) -> None:
    """Convenience function to run signaling server until interrupted."""
    server = SignalingServer()
    await server.start(host, port)
    try:
        await asyncio.Future()  # run forever
    except (asyncio.CancelledError, KeyboardInterrupt):
        await server.stop()
