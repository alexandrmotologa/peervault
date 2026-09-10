"""Client for encrypted rendezvous and signaling via WebSocket relay."""

import asyncio
import json
import logging
from typing import Any, Dict, Optional

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from peervault.config import (
    DEFAULT_CRYPTO_CONFIG,
    DEFAULT_NETWORK_CONFIG,
    CryptoConfig,
    NetworkConfig,
)
from peervault.crypto.cipher import decrypt_signaling_payload, encrypt_signaling_payload
from peervault.crypto.kdf import compute_blind_room_id, derive_master_key, derive_subkeys
from peervault.crypto.memory import zero_memory
from peervault.signaling.protocol import Action, Status

logger = logging.getLogger(__name__)


class SignalingError(Exception):
    """Raised when a signaling protocol error occurs."""


class SignalingClient:
    """Manages encrypted signaling rendezvous through an ephemeral WebSocket relay."""

    def __init__(
        self,
        relay_url: str,
        passphrase: str,
        role: str,
        crypto_config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
        network_config: NetworkConfig = DEFAULT_NETWORK_CONFIG,
    ):
        self.relay_url = relay_url
        self.passphrase = passphrase
        self.role = role
        self.crypto_config = crypto_config
        self.network_config = network_config

        self.room_id = compute_blind_room_id(passphrase, crypto_config)
        master_key = derive_master_key(passphrase, crypto_config)
        self.signaling_key, self.transport_base_key = derive_subkeys(master_key)
        zero_memory(master_key)

        self._ws: Optional[ClientConnection] = None
        self._listener_task: Optional[asyncio.Task] = None
        self._signal_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self._peer_joined_event = asyncio.Event()
        self._peer_left_event = asyncio.Event()
        self._joined_ack = asyncio.Event()
        self._peer_present = False
        self._closed = False

    @property
    def peer_present(self) -> bool:
        return self._peer_present

    async def connect(self) -> None:
        """Connects to the signaling relay server and starts the listener loop."""
        try:
            self._ws = await asyncio.wait_for(
                connect(self.relay_url),
                timeout=self.network_config.connect_timeout_seconds,
            )
        except Exception as err:
            raise SignalingError(
                f"Could not connect to signaling relay at {self.relay_url}: {err}"
            ) from err

        self._listener_task = asyncio.create_task(self._listener_loop())

    async def _listener_loop(self) -> None:
        """Continuously receives messages from the WebSocket relay."""
        if not self._ws:
            return

        try:
            async for raw_message in self._ws:
                try:
                    data = json.loads(raw_message)
                except json.JSONDecodeError:
                    continue

                status = data.get("status")
                action = data.get("action")

                if status == Status.JOINED:
                    self._peer_present = bool(data.get("peer_present", False))
                    if self._peer_present:
                        self._peer_joined_event.set()
                    self._joined_ack.set()

                elif status == Status.PEER_JOINED:
                    self._peer_present = True
                    self._peer_joined_event.set()

                elif status == Status.PEER_LEFT:
                    self._peer_present = False
                    self._peer_left_event.set()

                elif status == Status.ERROR:
                    msg = data.get("message", "unknown_error")
                    logger.warning("Signaling server returned error: %s", msg)

                elif action == Action.SIGNAL:
                    ciphertext = data.get("ciphertext")
                    nonce = data.get("nonce")
                    if ciphertext and nonce:
                        try:
                            decrypted_bytes = decrypt_signaling_payload(
                                self.signaling_key, ciphertext, nonce
                            )
                            signal_payload = json.loads(decrypted_bytes.decode("utf-8"))
                            await self._signal_queue.put(signal_payload)
                        except Exception as err:
                            logger.error("Failed to decrypt incoming signaling payload: %s", err)
        except ConnectionClosed:
            pass
        finally:
            self._closed = True

    async def join(self) -> bool:
        """Registers in the blind room and returns whether the peer is already present."""
        if not self._ws:
            raise SignalingError("Not connected to relay")

        join_msg = {
            "action": Action.JOIN,
            "room": self.room_id,
            "role": self.role,
        }
        await self._ws.send(json.dumps(join_msg))

        try:
            await asyncio.wait_for(self._joined_ack.wait(), timeout=10.0)
        except asyncio.TimeoutError as err:
            raise SignalingError("Timeout waiting for join response from relay") from err

        return self._peer_present

    async def wait_for_peer(self, timeout: float = 300.0) -> None:
        """Blocks until the peer joins the room or timeout expires."""
        if self._peer_present:
            return

        try:
            await asyncio.wait_for(self._peer_joined_event.wait(), timeout=timeout)
        except asyncio.TimeoutError as err:
            raise SignalingError(
                f"Timed out after {timeout} seconds waiting for peer to join room"
            ) from err

    async def send_signal(self, payload: Dict[str, Any]) -> None:
        """Encrypts and transmits a signaling payload to the peer."""
        if not self._ws:
            raise SignalingError("Not connected to relay")

        raw_json = json.dumps(payload).encode("utf-8")
        b64_ct, b64_nonce = encrypt_signaling_payload(self.signaling_key, raw_json)

        msg = {
            "action": Action.SIGNAL,
            "room": self.room_id,
            "ciphertext": b64_ct,
            "nonce": b64_nonce,
        }
        await self._ws.send(json.dumps(msg))

    async def receive_signal(self, timeout: float = 30.0) -> Dict[str, Any]:
        """Awaits and returns the next decrypted signal message from the peer."""
        try:
            return await asyncio.wait_for(self._signal_queue.get(), timeout=timeout)
        except asyncio.TimeoutError as err:
            raise SignalingError("Timed out waiting for peer signal") from err

    async def close(self) -> None:
        """Closes the connection, stops the listener, and scrubs cryptographic keys."""
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass

        if self._ws:
            try:
                await self._ws.send(json.dumps({"action": Action.LEAVE, "room": self.room_id}))
                await self._ws.close()
            except Exception:
                pass

        zero_memory(self.signaling_key)
