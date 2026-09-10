"""Unit tests for cryptographic components in PeerVault."""

import pytest

from peervault.config import CryptoConfig
from peervault.crypto.cipher import (
    AuthenticationError,
    ChunkCipher,
    decrypt_signaling_payload,
    encrypt_signaling_payload,
)
from peervault.crypto.dh import compute_session_key, generate_ephemeral_keypair
from peervault.crypto.kdf import (
    compute_blind_room_id,
    derive_master_key,
    derive_subkeys,
    normalize_passphrase,
)
from peervault.crypto.memory import zero_memory

FAST_CONFIG = CryptoConfig(
    argon2_time_cost=1,
    argon2_memory_cost=8 * 1024,
    argon2_parallelism=2,
)


def test_normalize_passphrase():
    assert normalize_passphrase("  7-Copper-Falcon  ") == "7-copper-falcon"


def test_blind_room_id():
    room1 = compute_blind_room_id("7-copper-falcon", FAST_CONFIG)
    room2 = compute_blind_room_id("  7-COPPER-FALCON  ", FAST_CONFIG)
    room3 = compute_blind_room_id("8-copper-falcon", FAST_CONFIG)

    assert len(room1) == 64
    assert room1 == room2
    assert room1 != room3


def test_derive_master_key_and_subkeys():
    master1 = derive_master_key("7-copper-falcon", FAST_CONFIG)
    master2 = derive_master_key("7-copper-falcon", FAST_CONFIG)
    master3 = derive_master_key("different-code", FAST_CONFIG)

    assert master1 == master2
    assert master1 != master3

    sig_key1, transport_key1 = derive_subkeys(master1)
    sig_key2, transport_key2 = derive_subkeys(master2)

    assert sig_key1 == sig_key2
    assert transport_key1 == transport_key2
    assert sig_key1 != transport_key1
    assert len(sig_key1) == 32
    assert len(transport_key1) == 32


def test_chunk_cipher_roundtrip():
    key = b"A" * 32
    with ChunkCipher(key) as cipher:
        data = b"Hello, PeerVault world of encrypted streams!"
        frame = cipher.encrypt_chunk(chunk_index=42, plaintext=data)

        index, decrypted = cipher.decrypt_chunk(frame)
        assert index == 42
        assert decrypted == data


def test_chunk_cipher_tampering_fails():
    key = b"B" * 32
    with ChunkCipher(key) as cipher:
        data = b"Secret payload to protect"
        frame = bytearray(cipher.encrypt_chunk(chunk_index=1, plaintext=data))

        # Tamper with the last byte (authentication tag)
        frame[-1] ^= 0xFF
        with pytest.raises(AuthenticationError):
            cipher.decrypt_chunk(bytes(frame))

        # Tamper with chunk index header
        frame2 = bytearray(cipher.encrypt_chunk(chunk_index=2, plaintext=data))
        frame2[0] ^= 0x01
        with pytest.raises(AuthenticationError):
            cipher.decrypt_chunk(bytes(frame2))


def test_signaling_payload_encryption():
    key = b"C" * 32
    plaintext = b'{"type": "offer", "sdp": "v=0..."}'

    b64_ct, b64_nonce = encrypt_signaling_payload(key, plaintext)
    decrypted = decrypt_signaling_payload(key, b64_ct, b64_nonce)

    assert decrypted == plaintext

    wrong_key = b"D" * 32
    with pytest.raises(AuthenticationError):
        decrypt_signaling_payload(wrong_key, b64_ct, b64_nonce)


def test_ephemeral_dh_and_forward_secrecy():
    transport_base_key = b"T" * 32

    # Alice side
    alice_priv, alice_pub = generate_ephemeral_keypair()

    # Bob side
    bob_priv, bob_pub = generate_ephemeral_keypair()

    # Both compute session key
    alice_session_key = compute_session_key(alice_priv, bob_pub, transport_base_key)
    bob_session_key = compute_session_key(bob_priv, alice_pub, transport_base_key)

    assert alice_session_key == bob_session_key
    assert len(alice_session_key) == 32
    assert alice_session_key != transport_base_key

    # Test invalid public key size
    with pytest.raises(ValueError):
        compute_session_key(alice_priv, b"short", transport_base_key)


def test_memory_zeroing():
    buf = bytearray(b"super_secret_master_key_1234567")
    assert any(b != 0 for b in buf)

    zero_memory(buf)
    assert all(b == 0 for b in buf)
