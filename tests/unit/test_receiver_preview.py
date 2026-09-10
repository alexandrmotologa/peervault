"""Unit tests for receiver preview, confirmation, and safe overwrite."""

from peervault.transfer.receiver import get_unique_path


def test_get_unique_path_non_existent(tmp_path):
    target = tmp_path / "new_file.txt"
    assert get_unique_path(target) == target


def test_get_unique_path_single_file(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("initial", encoding="utf-8")

    unique1 = get_unique_path(target)
    assert unique1.name == "secret (1).env"

    unique1.write_text("second", encoding="utf-8")
    unique2 = get_unique_path(target)
    assert unique2.name == "secret (2).env"


def test_get_unique_path_directory(tmp_path):
    folder = tmp_path / "my_project"
    folder.mkdir()

    unique_folder = get_unique_path(folder)
    assert unique_folder.name == "my_project (1)"
