"""Synthetic local data only; byte comparison is not medical interpretation."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from health_analyzer import duplicate_search as search
from health_analyzer.file_archive import ArchiveError, load_profiles


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "health-duplicates"


@pytest.fixture
def example(tmp_path):
    base = tmp_path.resolve()
    first = base / "first"
    other = base / "second"
    first.mkdir()
    other.mkdir()
    source = base / "chosen.pdf"
    source.write_bytes(b"synthetic file data\x00")
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [
        {"id": "a", "label": "Профиль один", "root": str(first)},
        {"id": "b", "label": "Perfil dos", "root": str(other)},
    ]}, ensure_ascii=False), encoding="utf-8")
    return source, first, other, config


def test_finds_identical_bytes_only_in_selected_profile(example):
    source, first, other, config = example
    (first / "nested").mkdir()
    (first / "nested" / "different-name.bin").write_bytes(source.read_bytes())
    (first / "same-length.bin").write_bytes(b"X" * len(source.read_bytes()))
    (other / "same.pdf").write_bytes(source.read_bytes())
    result = search.find_duplicates(load_profiles(config), "Профиль один", source)
    assert result["matches"] == ["nested/different-name.bin"]
    assert result["coverage"]["search_complete"] is True
    assert result["coverage"]["matching_files"] == 1
    assert "not_identity_or_role" in result["coverage"]["match_meaning"]


def test_complete_absence_and_incomplete_links_are_distinct(example):
    source, first, _, config = example
    profiles = load_profiles(config)
    result = search.find_duplicates(profiles, "a", source)
    assert result["matches"] == []
    assert result["coverage"]["search_complete"] is True
    (first / "hidden-link").symlink_to(source)
    result = search.find_duplicates(profiles, "a", source)
    assert result["matches"] == []
    assert result["coverage"]["search_complete"] is False
    assert result["coverage"]["skipped_or_unreadable"] == 1


def test_hardlinked_source_rejected_and_archive_hardlink_skipped(example):
    source, first, _, config = example
    alias = source.with_name("extra-link")
    os.link(source, alias)
    with pytest.raises(ArchiveError):
        search.find_duplicates(load_profiles(config), "a", source)
    alias.unlink()
    item = first / "one"
    item.write_bytes(source.read_bytes())
    os.link(item, first / "two")
    result = search.find_duplicates(load_profiles(config), "a", source)
    assert result["matches"] == []
    assert result["coverage"]["search_complete"] is False
    assert result["coverage"]["skipped_or_unreadable"] == 2


def test_unknown_profile_and_oversized_source_fail(example, monkeypatch):
    source, _, _, config = example
    profiles = load_profiles(config)
    with pytest.raises(ArchiveError):
        search.find_duplicates(profiles, "unknown", source)
    monkeypatch.setattr(search, "MAX_SOURCE_BYTES", 1)
    with pytest.raises(ArchiveError):
        search.find_duplicates(profiles, "a", source)


def test_limits_do_not_claim_exhaustive_absence(example, monkeypatch):
    source, first, _, config = example
    (first / "candidate").write_bytes(source.read_bytes())
    monkeypatch.setattr(search, "MAX_HASH_BYTES", len(source.read_bytes()) - 1)
    result = search.find_duplicates(load_profiles(config), "a", source)
    assert result["matches"] == []
    assert result["coverage"]["search_complete"] is False
    assert result["coverage"]["limits_reached"] == ["bytes"]


def test_changed_candidate_discards_stale_matches(example, monkeypatch):
    source, first, _, config = example
    item = first / "candidate"
    item.write_bytes(source.read_bytes())
    real_digest = search._digest
    calls = 0

    def change_after_hash(fd, info, deadline):
        nonlocal calls
        calls += 1
        value = real_digest(fd, info, deadline)
        if calls == 2:
            item.unlink()
            item.write_bytes(b"replacement")
        return value

    monkeypatch.setattr(search, "_digest", change_after_hash)
    result = search.find_duplicates(load_profiles(config), "a", source)
    assert result["matches"] == []
    assert result["coverage"]["search_complete"] is False


def test_moved_source_parent_fails_closed(example, monkeypatch):
    source, first, _, config = example
    selected_dir = source.parent / "selected"
    selected_dir.mkdir()
    selected = selected_dir / "record.pdf"
    selected.write_bytes(source.read_bytes())
    profiles = load_profiles(config)
    original_digest = search._digest
    calls = 0

    def moved_after_source_hash(fd, info, deadline):
        nonlocal calls
        calls += 1
        digest = original_digest(fd, info, deadline)
        if calls == 1:
            selected_dir.rename(selected_dir.with_name("moved"))
            selected_dir.mkdir()
            (selected_dir / selected.name).write_bytes(source.read_bytes())
        return digest

    monkeypatch.setattr(search, "_digest", moved_after_source_hash)
    with pytest.raises(ArchiveError):
        search.find_duplicates(profiles, "a", selected)


def test_cli_includes_no_input_values_on_errors(example):
    source, _, _, config = example
    result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT),
                             "--config", str(config), "--profile", "unknown-sensitive-label",
                             "--source", str(source)], capture_output=True, text=True)
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "duplicate_search_unavailable"
    assert str(config) not in result.stderr
    assert "unknown-sensitive-label" not in result.stderr


def test_cli_synthetic_file_and_unknown_format(example):
    source, first, _, config = example
    (first / "previous.xyz").write_bytes(source.read_bytes())
    result = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT),
                             "--config", str(config), "--profile", "a",
                             "--source", str(source)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["matches"] == ["previous.xyz"]
    assert payload["coverage"]["search_complete"] is True
