"""Binary stream transport, flow control, and in-band forward secrecy over RTCDataChannel."""

import asyncio
import logging
from typing import Optional, Union

from aiortc.rtcdatachannel import RTCDataChannel

from peervault.config import (
    DEFAULT_CRYPTO_CONFIG,
    DEFAULT_NETWORK_CONFIG,
    CryptoConfig,
    NetworkConfig,
)
from peervault.crypto.cipher import ChunkCipher
from peervault.crypto.dh import compute_session_key, generate_ephemeral_keypair
from peervault.crypto.memory import zero_memory

logger = logging.getLogger(__name__)

KEY_HANDSHAKE_PREFIX = b"PV_KEY:"
EOS_FRAME = b"PV_EOS"


class DataChannelStream:
    """Manages high-throughput binary frames, backpressure, and forward secrecy over WebRTC."""

    def __init__(
        self,
        channel: RTCDataChannel,
        crypto_config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
        network_config: NetworkConfig = DEFAULT_NETWORK_CONFIG,
    ):
        self.channel = channel
        self.crypto_config = crypto_config
        self.network_config = network_config

        self._channel_open_event = asyncio.Event()
        if self.channel.readyState == "open":
            self._channel_open_event.set()

        self._incoming_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer_low_event = asyncio.Event()
        self._buffer_low_event.set()
        self._cipher: Optional[ChunkCipher] = None
        self._session_key: Optional[bytearray] = None
        self._closed = False

        self._setup_channel_events()

    def _setup_channel_events(self) -> None:
        self.channel.bufferedAmountLowThreshold = self.network_config.max_buffered_amount // 2

        @self.channel.on("open")
        def on_open() -> None:
            self._channel_open_event.set()

        @self.channel.on("message")
        def on_message(message: Union[str, bytes]) -> None:
            if isinstance(message, str):
                msg_bytes = message.encode("utf-8")
            else:
                msg_bytes = bytes(message)
            self._incoming_queue.put_nowait(msg_bytes)

        @self.channel.on("bufferedamountlow")
        def on_buffered_amount_low() -> None:
            self._buffer_low_event.set()

        @self.channel.on("close")
        def on_close() -> None:
            self._closed = True

    async def wait_until_open(self, timeout: float = 30.0) -> None:
        """Blocks until the underlying DataChannel is open."""
        if self.channel.readyState == "open":
            return
        try:
            await asyncio.wait_for(self._channel_open_event.wait(), timeout=timeout)
        except asyncio.TimeoutError as err:
            raise TimeoutError("DataChannel did not open within timeout") from err

    async def perform_handshake(
        self,
        transport_base_key: Union[bytearray, bytes],
        timeout: float = 15.0,
    ) -> bytearray:
        """Exchanges ephemeral X25519 public keys over the DataChannel and derives session key."""
        await self.wait_until_open(timeout=timeout)
        priv_key, local_pub = generate_ephemeral_keypair()
        self.channel.send(KEY_HANDSHAKE_PREFIX + local_pub)

        # Await peer's public key frame
        while True:
            try:
                frame = await asyncio.wait_for(self._incoming_queue.get(), timeout=timeout)
            except asyncio.TimeoutError as err:
                raise TimeoutError("Timed out waiting for peer ephemeral key exchange") from err

            if frame.startswith(KEY_HANDSHAKE_PREFIX):
                peer_pub = frame[len(KEY_HANDSHAKE_PREFIX) :]
                if len(peer_pub) != 32:
                    raise ValueError(f"Invalid peer public key size: {len(peer_pub)}")
                break

        # Compute session key via HKDF(Salt=transport_base_key, IKM=shared_secret)
        self._session_key = compute_session_key(
            priv_key, peer_pub, transport_base_key, self.crypto_config
        )
        self._cipher = ChunkCipher(self._session_key)
        return self._session_key

    @property
    def cipher(self) -> ChunkCipher:
        if not self._cipher:
            raise RuntimeError("Handshake has not been performed; cipher not available")
        return self._cipher

    async def send_frame(self, frame: bytes) -> None:
        """Sends a raw binary frame, respecting flow control backpressure."""
        if self._closed:
            raise ConnectionResetError("DataChannel is closed")

        # Backpressure check
        if self.channel.bufferedAmount > self.network_config.max_buffered_amount:
            self._buffer_low_event.clear()
            await self._buffer_low_event.wait()

        self.channel.send(frame)
        # Yield control briefly to avoid starving event loop on high-throughput sends
        await asyncio.sleep(0)

    async def read_frame(self, timeout: float = 60.0) -> bytes:
        """Awaits and returns the next binary frame from the peer."""
        try:
            return await asyncio.wait_for(self._incoming_queue.get(), timeout=timeout)
        except asyncio.TimeoutError as err:
            raise TimeoutError("Timed out waiting for data frame from peer") from err

    async def close(self) -> None:
        """Closes the channel and scrubs session cryptographic keys."""
        if not self._closed:
            self._closed = True
            try:
                self.channel.close()
            except Exception:
                pass

        if self._cipher:
            self._cipher.close()
            self._cipher = None

        if self._session_key:
            zero_memory(self._session_key)
            self._session_key = None
