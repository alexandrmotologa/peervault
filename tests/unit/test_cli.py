"""Tests for CLI options and commands."""

from typer.testing import CliRunner

from peervault import __version__
from peervault.cli import app

runner = CliRunner()


def test_cli_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert f"peervault version {__version__}" in result.stdout


def test_cli_version_flag_long():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"peervault version {__version__}" in result.stdout


def test_cli_version_flag_short():
    result = runner.invoke(app, ["-v"])
    assert result.exit_code == 0
    assert f"peervault version {__version__}" in result.stdout
