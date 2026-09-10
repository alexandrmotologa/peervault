"""Key derivation and blind room calculation using Argon2id and HKDF."""

import hashlib
import hmac
from typing import Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from peervault.config import DEFAULT_CRYPTO_CONFIG, CryptoConfig


def normalize_passphrase(passphrase: str) -> str:
    """Normalizes the human code phrase to lower-case, trimmed string."""
    return passphrase.strip().lower()


def compute_blind_room_id(
    passphrase: str,
    config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
) -> str:
    """Computes a blind room identifier for signaling using HMAC-SHA256.

    The signaling relay never receives or learns the actual passphrase.
    """
    normalized = normalize_passphrase(passphrase).encode("utf-8")
    return hmac.new(config.domain_signaling, normalized, hashlib.sha256).hexdigest()


def derive_master_key(
    passphrase: str,
    config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
) -> bytearray:
    """Derives a 256-bit master key from the passphrase using Argon2id.

    Returns a mutable bytearray so the caller can scrub the key from memory.
    """
    normalized = normalize_passphrase(passphrase).encode("utf-8")
    kdf = Argon2id(
        salt=config.domain_salt_kdf,
        length=config.argon2_key_length,
        iterations=config.argon2_time_cost,
        lanes=config.argon2_parallelism,
        memory_cost=config.argon2_memory_cost,
    )
    key_buffer = bytearray(config.argon2_key_length)
    kdf.derive_into(normalized, key_buffer)
    return key_buffer


def derive_subkeys(
    master_key: Union[bytearray, bytes],
) -> Tuple[bytearray, bytearray]:
    """Derives separate signaling and transport keys from the Argon2id master key.

    Returns (signaling_key, transport_base_key).
    """
    signaling_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"peervault-hkdf-signaling-salt",
        info=b"peervault-signaling-key",
    )
    transport_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"peervault-hkdf-transport-salt",
        info=b"peervault-transport-base-key",
    )

    key_bytes = bytes(master_key)
    sig_key = bytearray(signaling_hkdf.derive(key_bytes))
    transport_key = bytearray(transport_hkdf.derive(key_bytes))
    return sig_key, transport_key
