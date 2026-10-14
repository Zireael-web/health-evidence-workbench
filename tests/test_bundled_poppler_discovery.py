"""Find an existing trusted dependency; never install or launch it."""
from pathlib import Path
import pytest
from health_analyzer import local_documents as local


def test_existing_path_dependency_is_preserved(monkeypatch):
    monkeypatch.setattr(local.shutil, "which", lambda _: "/selected/pdftoppm")
    assert local._render_executable() == "/selected/pdftoppm"


@pytest.fixture
def bundled(tmp_path, monkeypatch):
    home = tmp_path.resolve()
    binary = home / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/poppler/poppler/bin/pdftoppm"
    binary.parent.mkdir(parents=True, mode=0o700)
    binary.write_bytes(b"synthetic executable fixture, never launched")
    binary.chmod(0o700)
    monkeypatch.setattr(local.shutil, "which", lambda _: None)
    monkeypatch.setattr(local.sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return binary


def test_bundled_dependency_works_without_path(bundled):
    assert local._render_executable() == str(bundled)


def test_writable_dependency_is_not_executed(bundled):
    bundled.chmod(0o777)
    assert local._render_executable() is None


def test_linked_dependency_is_not_executed(bundled):
    other = bundled.with_name("other")
    bundled.rename(other)
    bundled.symlink_to(other)
    assert local._render_executable() is None


def test_missing_dependency_does_not_install_anything(bundled):
    bundled.unlink()
    assert local._render_executable() is None
