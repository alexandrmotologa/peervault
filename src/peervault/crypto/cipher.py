"""Authenticated AEAD chunk encryption and decryption using ChaCha20-Poly1305."""

import base64
import os
import struct
from typing import Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from peervault.crypto.memory import zero_memory

# Wire header format:
# 4 bytes: chunk index (uint32)
# 4 bytes: plaintext length (uint32)
# 12 bytes: nonce (RFC 8439 96-bit nonce)
# Followed by ciphertext (plaintext_length + 16 bytes tag)
HEADER_STRUCT = struct.Struct(">II")
HEADER_SIZE = HEADER_STRUCT.size  # 8 bytes
NONCE_SIZE = 12
MIN_FRAME_SIZE = HEADER_SIZE + NONCE_SIZE + 16  # 36 bytes


class CryptographyError(Exception):
    """Raised when encryption or decryption fails."""


class AuthenticationError(CryptographyError):
    """Raised when ciphertext authentication tag is invalid or tampered."""


class ChunkCipher:
    """Manages chunk-level encryption and decryption for streaming transfers."""

    def __init__(self, key: Union[bytearray, bytes]):
        if len(key) != 32:
            raise ValueError(f"Invalid key length: {len(key)} (expected 32 bytes)")
        self._key = bytearray(key)
        self._aead = ChaCha20Poly1305(bytes(self._key))
        # 4-byte random session salt combined with 8-byte chunk index for nonces
        self._session_salt = os.urandom(4)

    def close(self) -> None:
        """Scrubs key material from memory."""
        zero_memory(self._key)

    def __enter__(self) -> "ChunkCipher":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def encrypt_chunk(self, chunk_index: int, plaintext: bytes) -> bytes:
        """Encrypts a plaintext chunk into a self-contained framed binary message."""
        plain_len = len(plaintext)
        header = HEADER_STRUCT.pack(chunk_index, plain_len)

        # 12-byte nonce: 4-byte random salt + 8-byte chunk index counter
        nonce = self._session_salt + struct.pack(">Q", chunk_index)

        # Associated data protects chunk index and length from tampering
        try:
            ciphertext = self._aead.encrypt(nonce, plaintext, header)
        except Exception as err:
            raise CryptographyError(f"Encryption failed for chunk {chunk_index}: {err}") from err

        return header + nonce + ciphertext

    def decrypt_chunk(self, frame: bytes) -> Tuple[int, bytes]:
        """Decrypts a framed binary message back into chunk index and plaintext."""
        if len(frame) < MIN_FRAME_SIZE:
            raise AuthenticationError(
                f"Frame size {len(frame)} is smaller than minimum required header {MIN_FRAME_SIZE}"
            )

        header = frame[:HEADER_SIZE]
        chunk_index, expected_len = HEADER_STRUCT.unpack(header)

        nonce = frame[HEADER_SIZE : HEADER_SIZE + NONCE_SIZE]
        ciphertext = frame[HEADER_SIZE + NONCE_SIZE :]

        try:
            plaintext = self._aead.decrypt(nonce, ciphertext, header)
        except InvalidTag as err:
            raise AuthenticationError(
                f"Authentication failed for chunk {chunk_index}. Data was tampered."
            ) from err
        except Exception as err:
            raise CryptographyError(f"Decryption failed for chunk {chunk_index}: {err}") from err

        if len(plaintext) != expected_len:
            msg = (
                f"Chunk {chunk_index} length mismatch: "
                f"got {len(plaintext)}, expected {expected_len}"
            )
            raise AuthenticationError(msg)

        return chunk_index, plaintext


def encrypt_signaling_payload(key: Union[bytearray, bytes], payload: bytes) -> Tuple[str, str]:
    """Encrypts arbitrary payload for signaling transport.

    Returns (base64_ciphertext, base64_nonce).
    """
    aead = ChaCha20Poly1305(bytes(key))
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aead.encrypt(nonce, payload, None)
    return base64.b64encode(ciphertext).decode("ascii"), base64.b64encode(nonce).decode("ascii")


def decrypt_signaling_payload(
    key: Union[bytearray, bytes],
    b64_ciphertext: str,
    b64_nonce: str,
) -> bytes:
    """Decrypts arbitrary payload from signaling transport."""
    try:
        ciphertext = base64.b64decode(b64_ciphertext)
        nonce = base64.b64decode(b64_nonce)
        aead = ChaCha20Poly1305(bytes(key))
        return aead.decrypt(nonce, ciphertext, None)
    except InvalidTag as err:
        raise AuthenticationError("Failed to authenticate signaling message.") from err
    except Exception as err:
        raise CryptographyError(f"Failed to decrypt signaling message: {err}") from err
