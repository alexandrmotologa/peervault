"""Unit tests for configuration loading and TOML parsing."""

from peervault.config import (
    generate_default_config_toml,
    get_default_config_path,
    load_configuration,
)


def test_default_config_path_resolution(monkeypatch):
    monkeypatch.setenv("PEERVAULT_CONFIG", "/custom/path/config.toml")
    path = get_default_config_path()
    assert str(path).replace("\\", "/").endswith("/custom/path/config.toml")


def test_load_configuration_defaults_when_no_file(tmp_path):
    missing_file = tmp_path / "non_existent.toml"
    cfg = load_configuration(missing_file)

    assert cfg.relay_url == "ws://127.0.0.1:8765"
    assert cfg.chunk_size == 65536
    assert cfg.auto_accept is False
    assert cfg.overwrite is False
    assert len(cfg.stun_servers) == 3


def test_load_configuration_from_toml(tmp_path):
    config_file = tmp_path / "config.toml"
    config_content = """
[network]
relay_url = "wss://custom-relay.org:9000"
stun_servers = ["stun:custom-stun.org:3478"]

[transfer]
chunk_size = 131072
auto_accept = true
overwrite = true
default_output_dir = "/tmp/downloads"
"""
    config_file.write_text(config_content, encoding="utf-8")

    cfg = load_configuration(config_file)
    assert cfg.relay_url == "wss://custom-relay.org:9000"
    assert cfg.stun_servers == ["stun:custom-stun.org:3478"]
    assert cfg.chunk_size == 131072
    assert cfg.auto_accept is True
    assert cfg.overwrite is True
    assert cfg.default_output_dir == "/tmp/downloads"


def test_generate_default_config_toml():
    template = generate_default_config_toml()
    assert "[network]" in template
    assert "[transfer]" in template
    assert "relay_url" in template
