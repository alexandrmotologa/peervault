"""Configuration constants and default settings for PeerVault."""

import os
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class CryptoConfig:
    # Argon2id parameters
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 64 * 1024  # 64 MB in KiB
    argon2_parallelism: int = 4
    argon2_key_length: int = 32  # 256-bit symmetric key

    # Chunk transfer parameters
    chunk_size: int = 64 * 1024  # 64 KB
    nonce_size: int = 24  # 192-bit nonce for XChaCha20
    tag_size: int = 16  # 128-bit Poly1305 tag

    # Salt and domain separators
    domain_salt_kdf: bytes = b"peervault-argon2id-salt-v1"
    domain_signaling: bytes = b"peervault-signaling-room-v1"
    domain_hkdf_info: bytes = b"peervault-datachannel-session-v1"


@dataclass(frozen=True)
class NetworkConfig:
    # STUN servers for WebRTC NAT traversal
    stun_servers: List[str] = field(
        default_factory=lambda: [
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302",
            "stun:stun2.l.google.com:19302",
        ]
    )

    # Ephemeral signaling relay
    default_relay_url: str = os.getenv("PEERVAULT_RELAY", "ws://127.0.0.1:8765")
    room_ttl_seconds: int = 300  # 5 minutes
    connect_timeout_seconds: float = 30.0

    # Flow control and backpressure limits (in bytes)
    max_buffered_amount: int = 1024 * 1024  # 1 MB


DEFAULT_CRYPTO_CONFIG = CryptoConfig()
DEFAULT_NETWORK_CONFIG = NetworkConfig()
