"""Synthetic-only tests: no real health records, names, or archives are used."""

import json
import os
from pathlib import Path

import pytest

from health_analyzer.file_archive import ArchiveError, load_profiles, search_text, select_profile


@pytest.fixture
def example(tmp_path: Path):
    base = tmp_path.resolve()
    first, second = base / "first", base / "second"
    first.mkdir()
    second.mkdir()
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [
        {"id": "subject_one", "label": "Пример Один", "root": str(first)},
        {"id": "subject_two", "label": "Пример Два", "root": str(second)},
    ]}, ensure_ascii=False), encoding="utf-8")
    return config, first, second


def test_explicit_unicode_profile_and_isolated_search(example):
    config, first, second = example
    (first / "report.txt").write_text("Синтетический отчёт\nМаркер 123\n", encoding="utf-8")
    (second / "report.txt").write_text("Маркер 456", encoding="utf-8")
    (first / "report.pdf").write_bytes(b"%PDF-synthetic")
    profiles = load_profiles(config)
    assert select_profile(profiles, "пример один").id == "subject_one"
    result = search_text(profiles, "subject_one", "мАрКеР")
    assert result["matches"] == [{"path": "report.txt", "line": 2,
                                  "excerpt": "Маркер 123", "excerpt_truncated": False}]
    assert result["coverage"]["text_files_scanned"] == 1
    assert result["coverage"]["other_files"] == 1
    assert result["coverage"]["source_document_coverage"] == "unknown"
    assert result["coverage"]["text_search_complete"] is True
    assert "456" not in repr(result)


def test_no_default_or_unknown_profile(example):
    profiles = load_profiles(example[0])
    for value in ("", "unknown"):
        with pytest.raises(ArchiveError):
            search_text(profiles, value, "marker")


def test_overlapping_roots_and_ambiguous_aliases_rejected(example):
    config, first, second = example
    original = json.loads(config.read_text())
    configs = [
        [{"id": "a", "label": "A", "root": str(first)},
         {"id": "b", "label": "B", "root": str(first)}],
        [{"id": "a", "label": "Совпадение", "root": str(first)},
         {"id": "b", "label": "совпадение", "root": str(second)}],
        [{"id": "a", "label": "B", "root": str(first)},
         {"id": "b", "label": "Два", "root": str(second)}],
    ]
    nested = first / "nested"
    nested.mkdir()
    configs.append([{"id": "a", "label": "One", "root": str(first)},
                    {"id": "b", "label": "Two", "root": str(nested)}])
    for profiles in configs:
        config.write_text(json.dumps({"profiles": profiles}, ensure_ascii=False))
        with pytest.raises(ArchiveError):
            load_profiles(config)
    config.write_text(json.dumps(original, ensure_ascii=False))


def test_rejects_symlinked_root_and_config(example):
    config, first, second = example
    alias = first.parent / "root-link"
    alias.symlink_to(first, target_is_directory=True)
    value = json.loads(config.read_text())
    value["profiles"][0]["root"] = str(alias)
    config.write_text(json.dumps(value))
    with pytest.raises(ArchiveError):
        load_profiles(config)
    linked_config = first.parent / "link.json"
    linked_config.symlink_to(config)
    with pytest.raises(ArchiveError):
        load_profiles(linked_config)


def test_changed_root_fails_closed(example):
    config, first, _ = example
    profiles = load_profiles(config)
    first.rename(first.with_name("moved"))
    first.mkdir()
    with pytest.raises(ArchiveError):
        search_text(profiles, "subject_one", "marker")


def test_nested_and_incomplete_search_reporting(example):
    config, first, second = example
    folder = first / "nested"
    folder.mkdir()
    (folder / "report.TXT").write_text("marker\nmarker", encoding="utf-8")
    (first / "broken.txt").write_bytes(b"\xff")
    (first / "not-a-txt.txt").symlink_to(second / "other.txt")
    (second / "other.txt").write_text("private marker", encoding="utf-8")
    result = search_text(load_profiles(config), "subject_one", "marker", max_matches=1)
    assert result["matches"][0]["path"] == "nested/report.TXT"
    assert result["coverage"]["total_matches"] == 2
    assert result["coverage"]["results_truncated"] is True
    assert result["coverage"]["text_search_complete"] is False
    assert result["coverage"]["skipped_or_unreadable"] == 2
    assert "private marker" not in repr(result)


def test_file_limits_and_hardlinks_are_visible_as_incomplete(example, monkeypatch):
    from health_analyzer import file_archive

    config, first, _ = example
    (first / "big.txt").write_text("1234567")
    (first / "linked.txt").write_text("x")
    os.link(first / "linked.txt", first / "hardlink.txt")
    monkeypatch.setattr(file_archive, "MAX_TEXT_BYTES", 6)
    result = search_text(load_profiles(config), "subject_one", "1")
    assert result["coverage"]["skipped_or_unreadable"] == 3
    assert result["coverage"]["text_search_complete"] is False
    assert not result["matches"]


def test_limits_and_unsafe_config_rejected(example):
    config, first, _ = example
    profiles = load_profiles(config)
    for query in ("", "x\ny", "x" * 513):
        with pytest.raises(ArchiveError):
            search_text(profiles, "subject_one", query)
    for limit in (0, 101, True):
        with pytest.raises(ArchiveError):
            search_text(profiles, "subject_one", "x", max_matches=limit)
    config.write_text('{"profiles": [], "profiles": []}')
    with pytest.raises(ArchiveError):
        load_profiles(config)


@pytest.mark.parametrize("line,query,expected", [
    ("z" * 5000 + "Строка совпадение" + "z" * 1000, "совпадение", "совпадение"),
    ("ß" * 2000 + "Straße" + "z" * 1000, "strasse", "Straße"),
    ("z" * 5000 + "e\u0301clair" + "z" * 1000, "éclair", "e\u0301clair"),
])
def test_late_unicode_match_returns_source_excerpt(example, line, query, expected):
    config, first, _ = example
    (first / "long.txt").write_text(line, encoding="utf-8")
    match = search_text(load_profiles(config), "subject_one", query)["matches"][0]
    assert expected in match["excerpt"]
    assert match["excerpt"] in line
    assert match["excerpt_truncated"] is True


def test_relocated_subdirectory_discards_results_and_marks_incomplete(example, monkeypatch):
    from health_analyzer import file_archive

    config, first, _ = example
    nested = first / "nested"
    nested.mkdir()
    (nested / "report.txt").write_text("synthetic marker")
    profiles = load_profiles(config)
    nested_id = (nested.stat().st_dev, nested.stat().st_ino)
    original_scandir = file_archive.os.scandir
    moved = False

    def move_during_scan(descriptor):
        nonlocal moved
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) == nested_id and not moved:
            nested.rename(first.parent / "outside-root")
            moved = True
        return original_scandir(descriptor)

    monkeypatch.setattr(file_archive.os, "scandir", move_during_scan)
    result = search_text(profiles, "subject_one", "marker")
    assert moved
    assert result["matches"] == []
    assert result["coverage"]["text_files_scanned"] == 0
    assert result["coverage"]["text_search_complete"] is False


def test_display_names_allow_unicode_joiners(example):
    config, first, second = example
    config.write_text(json.dumps({"profiles": [
        {"id": "a", "label": "Пример \u200d🩺", "root": str(first)}
    ]}, ensure_ascii=False), encoding="utf-8")
    assert select_profile(load_profiles(config), "Пример \u200d🩺").id == "a"


def test_subdirectory_moved_after_scan_discards_all_results(example, monkeypatch):
    from health_analyzer import file_archive

    config, first, _ = example
    nested = first / "nested"
    nested.mkdir()
    deep = nested / "deep"
    deep.mkdir()
    (deep / "report.txt").write_text("synthetic marker")
    profiles = load_profiles(config)
    original_open_dir = file_archive._open_dir
    root_opens = 0

    def move_after_scan(path, ancestry=None):
        nonlocal root_opens
        if path == first:
            root_opens += 1
            if root_opens == 2:
                deep.rename(first.parent / "moved-after-scan")
        return original_open_dir(path, ancestry)

    monkeypatch.setattr(file_archive, "_open_dir", move_after_scan)
    result = search_text(profiles, "subject_one", "marker")
    assert result["matches"] == []
    assert result["coverage"]["text_search_complete"] is False


def test_file_changed_after_read_discards_results(example, monkeypatch):
    from health_analyzer import file_archive

    config, first, _ = example
    report = first / "report.txt"
    report.write_text("synthetic marker")
    profiles = load_profiles(config)
    original_open_dir = file_archive._open_dir
    root_opens = 0

    def change_after_scan(path, ancestry=None):
        nonlocal root_opens
        if path == first:
            root_opens += 1
            if root_opens == 2:
                report.write_text("changed synthetic contents")
        return original_open_dir(path, ancestry)

    monkeypatch.setattr(file_archive, "_open_dir", change_after_scan)
    result = search_text(profiles, "subject_one", "marker")
    assert result["matches"] == []
    assert result["coverage"]["text_search_complete"] is False
