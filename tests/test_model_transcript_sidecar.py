"""Dialogue-text sidecars over fixed artificial PDF/text fixtures only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from health_analyzer.local_intake import (
    IntakeConflictError,
    LocalIntakeError,
    MAX_TRANSCRIPT_BYTES,
    read_model_transcript,
    save_model_transcript,
)


PDF = b"%PDF-1.7\n% fixed fictional sidecar test\n%%EOF\n"
PDF_SHA256 = hashlib.sha256(PDF).hexdigest()


@pytest.fixture
def pdf(tmp_path: Path) -> Path:
    # macOS /var may itself be a symlink; APIs require the direct actual path.
    path = tmp_path.resolve() / "synthetic-report.pdf"
    path.write_bytes(PDF)
    return path


def snapshot(path: Path) -> tuple:
    info = path.stat()
    return info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def test_exact_unicode_whitespace_and_newlines_round_trip_preserves_pdf(pdf: Path) -> None:
    text = " \r\nСинтетика 👩🏽‍🔬 e\u0301\t\x00\n\ntrailing  \r\n"
    before = snapshot(pdf)
    result = save_model_transcript(pdf, text, expected_sha256=PDF_SHA256.upper())

    assert result.path == pdf.with_suffix(".txt")
    assert result.status == "copied"
    assert result.sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert result.path.read_bytes() == text.encode("utf-8")
    assert read_model_transcript(result.path) == text
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o600
    assert result.path.stat().st_nlink == 1
    assert pdf.read_bytes() == PDF and snapshot(pdf) == before
    assert set(pdf.parent.iterdir()) == {pdf, result.path}


def test_identical_retry_preserves_existing_sidecar_and_conflict_changes_nothing(pdf: Path) -> None:
    first = save_model_transcript(pdf, "synthetic text\r\n", expected_sha256=PDF_SHA256)
    first.path.chmod(0o640)
    before = snapshot(first.path)
    repeated = save_model_transcript(pdf, "synthetic text\r\n", expected_sha256=PDF_SHA256)
    assert repeated.status == "already_present" and repeated.sha256 == first.sha256
    assert snapshot(first.path) == before

    with pytest.raises(IntakeConflictError, match="different contents"):
        save_model_transcript(pdf, "different text\n", expected_sha256=PDF_SHA256)
    assert first.path.read_bytes() == b"synthetic text\r\n"
    assert snapshot(first.path) == before
    assert set(pdf.parent.iterdir()) == {pdf, first.path}


@pytest.mark.parametrize("text", ["", "Ж" * (MAX_TRANSCRIPT_BYTES // 2)])
def test_empty_and_exact_utf8_byte_limit_are_saved_in_full(pdf: Path, text: str) -> None:
    saved = save_model_transcript(pdf, text, expected_sha256=PDF_SHA256)
    assert saved.path.read_bytes() == text.encode("utf-8")
    assert read_model_transcript(saved.path) == text


@pytest.mark.parametrize("expected", ["0" * 64, "", "z" * 64, None])
def test_hash_mismatch_or_invalid_hash_prevents_all_writes(pdf: Path, expected, monkeypatch) -> None:
    original_open = os.open

    def forbid_write(path, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT), "Hash failure attempted a write"
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", forbid_write)
    with pytest.raises(LocalIntakeError, match="SHA-256"):
        save_model_transcript(pdf, "synthetic text", expected_sha256=expected)
    assert list(pdf.parent.iterdir()) == [pdf]


def test_invalid_pdf_header_and_oversized_or_invalid_utf8_text_leave_no_sidecar(pdf: Path) -> None:
    with pytest.raises(LocalIntakeError, match="8 MiB"):
        save_model_transcript(pdf, "Ж" * (MAX_TRANSCRIPT_BYTES // 2 + 1), expected_sha256=PDF_SHA256)
    with pytest.raises(LocalIntakeError, match="valid UTF-8"):
        save_model_transcript(pdf, "\ud800", expected_sha256=PDF_SHA256)
    pdf.write_bytes(b"fixed synthetic non-PDF")
    with pytest.raises(LocalIntakeError, match="PDF header"):
        save_model_transcript(pdf, "text", expected_sha256=hashlib.sha256(pdf.read_bytes()).hexdigest())
    assert list(pdf.parent.iterdir()) == [pdf]


@pytest.mark.parametrize("kind", ["pdf", "parent", "sidecar"])
def test_save_rejects_symlink_in_source_parent_or_destination(pdf: Path, kind: str) -> None:
    chosen = pdf
    target = pdf.with_suffix(".txt")
    if kind == "pdf":
        chosen = pdf.parent / "linked.pdf"
        chosen.symlink_to(pdf)
    elif kind == "parent":
        link = pdf.parent / "linked-parent"
        link.symlink_to(pdf.parent, target_is_directory=True)
        chosen = link / pdf.name
    else:
        outside = pdf.parent / "unrelated.txt"
        outside.write_bytes(b"synthetic unrelated text")
        target.symlink_to(outside)
    with pytest.raises(LocalIntakeError):
        save_model_transcript(chosen, "text", expected_sha256=PDF_SHA256)
    assert pdf.read_bytes() == PDF
    if kind == "sidecar":
        assert target.is_symlink() and outside.read_bytes() == b"synthetic unrelated text"
    else:
        assert not target.exists()


@pytest.mark.parametrize("kind", ["invalid_utf8", "oversize", "symlink", "parent_symlink", "directory", "fifo"])
def test_staging_reader_rejects_unsafe_or_invalid_text(pdf: Path, kind: str) -> None:
    path = pdf.with_suffix(".txt")
    if kind == "invalid_utf8":
        path.write_bytes(b"\xff\xfe")
    elif kind == "oversize":
        with path.open("wb") as output:
            output.truncate(MAX_TRANSCRIPT_BYTES + 1)
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        actual = pdf.parent / "actual.txt"
        actual.write_bytes(b"synthetic text")
        if kind == "symlink":
            path.symlink_to(actual)
        else:
            link = pdf.parent / "linked-text-parent"
            link.symlink_to(pdf.parent, target_is_directory=True)
            path = link / actual.name
    with pytest.raises(LocalIntakeError):
        read_model_transcript(path)


def test_oversized_existing_sidecar_is_a_conflict_and_is_left_untouched(pdf: Path) -> None:
    target = pdf.with_suffix(".txt")
    with target.open("wb") as output:
        output.truncate(MAX_TRANSCRIPT_BYTES + 1)
    before = snapshot(target)
    with pytest.raises(IntakeConflictError):
        save_model_transcript(pdf, "text", expected_sha256=PDF_SHA256)
    assert snapshot(target) == before
    assert set(pdf.parent.iterdir()) == {pdf, target}


def test_save_text_cli_publishes_full_dialogue_text_without_native_inspection(pdf: Path, monkeypatch, capsys) -> None:
    from health_analyzer import cli, local_documents

    def forbidden_inspection(*args, **kwargs):
        pytest.fail("Saving dialogue text must not inspect or parse the PDF")

    monkeypatch.setattr(local_documents, "inspect_local_pdf", forbidden_inspection)
    text = " \r\nСинтетический текст\t👩🏽‍🔬\n" + "retained line\r\n" * 25000 + "trailing  \n"
    staging = pdf.parent / "dialogue-transcription.txt"
    staging.write_bytes(text.encode("utf-8"))
    before = snapshot(pdf)

    cli.main(["local-pdf", "save-text", str(pdf), "--text-file", str(staging),
              "--expected-sha256", PDF_SHA256])

    assert pdf.with_suffix(".txt").read_bytes() == text.encode("utf-8")
    assert snapshot(pdf) == before
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "copied" and summary["path"] == str(pdf.with_suffix(".txt"))
    assert summary["method"] == "dialogue_model_supplied_text"
    assert summary["sha256"] == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert "Синтетический" not in json.dumps(summary, ensure_ascii=False)
