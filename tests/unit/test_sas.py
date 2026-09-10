"""Unit tests for Short Authentication String (SAS) generation."""

from peervault.crypto.sas import SAS_EMOJIS, compute_sas


def test_compute_sas_deterministic():
    key1 = b"\x01" * 32
    sas1 = compute_sas(key1)
    sas2 = compute_sas(key1)

    assert sas1.emojis == sas2.emojis
    assert sas1.numeric == sas2.numeric
    assert sas1.display == sas2.display
    assert len(sas1.numeric) == 7  # XXX-XXX
    assert "-" in sas1.numeric


def test_compute_sas_changes_with_key():
    key1 = b"\x01" * 32
    key2 = b"\x02" * 32

    sas1 = compute_sas(key1)
    sas2 = compute_sas(key2)

    assert sas1.numeric != sas2.numeric
    assert sas1.emojis != sas2.emojis


def test_compute_sas_emoji_count_and_validity():
    key = b"test-key-material-32-bytes-long!"
    sas = compute_sas(key)
    emojis = sas.emojis.split(" ")

    assert len(emojis) == 4
    for emoji in emojis:
        assert emoji in SAS_EMOJIS
