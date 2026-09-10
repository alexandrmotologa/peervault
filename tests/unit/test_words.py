"""Unit tests for the word passphrase generator."""

import pytest

from peervault.signaling.words import generate_code, parse_code, validate_code


def test_generate_code_format():
    for _ in range(50):
        code = generate_code()
        assert validate_code(code)
        num, adj, noun = parse_code(code)
        assert 1 <= num <= 99
        assert len(adj) > 2
        assert len(noun) > 2


def test_parse_code_valid():
    num, adj, noun = parse_code("42-amber-falcon")
    assert num == 42
    assert adj == "amber"
    assert noun == "falcon"


def test_parse_code_invalid():
    with pytest.raises(ValueError):
        parse_code("invalid-code")

    with pytest.raises(ValueError):
        parse_code("abc-amber-falcon")

    with pytest.raises(ValueError):
        parse_code("42-amber")

    with pytest.raises(ValueError):
        parse_code("42-amber-falcon-extra")


def test_validate_code():
    assert validate_code("7-copper-falcon") is True
    assert validate_code("10-bright-cedar") is True
    assert validate_code("not-a-code") is False
