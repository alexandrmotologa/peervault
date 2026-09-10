"""Configuration constants and default settings for PeerVault."""

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


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


@dataclass
class AppConfig:
    """User-configurable application settings."""

    relay_url: str = field(
        default_factory=lambda: os.getenv("PEERVAULT_RELAY", "ws://127.0.0.1:8765")
    )
    stun_servers: List[str] = field(
        default_factory=lambda: [
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302",
            "stun:stun2.l.google.com:19302",
        ]
    )
    chunk_size: int = 64 * 1024
    auto_accept: bool = False
    overwrite: bool = False
    default_output_dir: Optional[str] = None


DEFAULT_CRYPTO_CONFIG = CryptoConfig()
DEFAULT_NETWORK_CONFIG = NetworkConfig()


def get_default_config_path() -> Path:
    """Resolves the standard configuration file path for the current OS."""
    override = os.getenv("PEERVAULT_CONFIG")
    if override:
        return Path(override).expanduser().resolve()

    if sys.platform == "win32":
        base_dir = os.getenv("APPDATA")
        if base_dir:
            return Path(base_dir) / "peervault" / "config.toml"
        return Path.home() / ".config" / "peervault" / "config.toml"

    xdg_config = os.getenv("XDG_CONFIG_HOME")
    if xdg_config:
        return Path(xdg_config) / "peervault" / "config.toml"
    return Path.home() / ".config" / "peervault" / "config.toml"


def generate_default_config_toml() -> str:
    """Returns a fully documented TOML configuration template."""
    return """# PeerVault User Configuration

[network]
# Default WebSocket signaling relay URL
relay_url = "ws://127.0.0.1:8765"

# STUN servers for WebRTC NAT traversal
stun_servers = [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
]

[transfer]
# Transfer chunk size in bytes (default: 65536 = 64 KB)
chunk_size = 65536

# Skip interactive confirmation prompt when receiving files
auto_accept = false

# Overwrite existing files automatically without prompting
overwrite = false

# Optional default download directory (e.g. "~/Downloads")
# default_output_dir = "~/Downloads"
"""


def load_configuration(config_path: Optional[Path] = None) -> AppConfig:
    """Loads settings from config.toml, falling back to default values if not found."""
    target_path = config_path or get_default_config_path()
    cfg = AppConfig()

    if not target_path.is_file():
        return cfg

    try:
        with open(target_path, "rb") as f:
            data = tomllib.load(f)

        network = data.get("network", {})
        if "relay_url" in network and isinstance(network["relay_url"], str):
            cfg.relay_url = network["relay_url"]
        if "stun_servers" in network and isinstance(network["stun_servers"], list):
            cfg.stun_servers = [str(s) for s in network["stun_servers"]]

        transfer = data.get("transfer", {})
        if "chunk_size" in transfer and isinstance(transfer["chunk_size"], int):
            cfg.chunk_size = transfer["chunk_size"]
        if "auto_accept" in transfer and isinstance(transfer["auto_accept"], bool):
            cfg.auto_accept = transfer["auto_accept"]
        if "overwrite" in transfer and isinstance(transfer["overwrite"], bool):
            cfg.overwrite = transfer["overwrite"]
        if "default_output_dir" in transfer and isinstance(transfer["default_output_dir"], str):
            cfg.default_output_dir = transfer["default_output_dir"]

    except Exception:
        # Fall back to defaults on parse errors
        pass

    return cfg
