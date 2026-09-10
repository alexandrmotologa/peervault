"""Ephemeral X25519 Diffie-Hellman key exchange for forward secrecy."""

from typing import Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from peervault.config import DEFAULT_CRYPTO_CONFIG, CryptoConfig
from peervault.crypto.memory import zero_memory


def generate_ephemeral_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    """Generates an ephemeral X25519 keypair.

    Returns the private key object and raw 32-byte public key.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def compute_session_key(
    private_key: x25519.X25519PrivateKey,
    peer_public_bytes: bytes,
    transport_base_key: Union[bytearray, bytes],
    config: CryptoConfig = DEFAULT_CRYPTO_CONFIG,
) -> bytearray:
    """Computes the final session key combining ephemeral DH and passphrase key.

    Uses HKDF-SHA256 with the transport base key as salt and ephemeral shared
    secret as input key material.
    """
    if len(peer_public_bytes) != 32:
        raise ValueError(f"Invalid peer public key length: {len(peer_public_bytes)} (expected 32)")

    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = bytearray(private_key.exchange(peer_public_key))

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=config.argon2_key_length,
            salt=bytes(transport_base_key),
            info=config.domain_hkdf_info,
        )
        session_key = bytearray(hkdf.derive(bytes(shared_secret)))
        return session_key
    finally:
        zero_memory(shared_secret)
