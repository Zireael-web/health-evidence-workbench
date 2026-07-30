from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import os
from pathlib import Path
import stat

import pytest

from health_analyzer import local_intake
from health_analyzer.local_intake import (
    IntakeConflictError,
    IntakeResult,
    LocalIntakeError,
    copy_authorized_pdf,
)


PDF = b"%PDF-1.7\n% synthetic test document\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
OTHER_PDF = b"%PDF-1.7\n% different synthetic test document\n%%EOF\n"


@pytest.fixture
def files(tmp_path: Path) -> tuple[Path, Path]:
    # macOS may expose the test temporary directory through a /var symlink.
    # The API intentionally requires the actual path, without symlink parents.
    base = tmp_path.resolve()
    source = base / "synthetic-report.pdf"
    source.write_bytes(PDF)
    archive = base / "explicitly-selected-archive"
    archive.mkdir()
    return source, archive


def test_copy_is_verified_private_immutable_result_and_preserves_source(files) -> None:
    source, archive = files
    original = source.stat()
    result = copy_authorized_pdf(source, archive)

    assert result == IntakeResult(archive / source.name, hashlib.sha256(PDF).hexdigest(), "copied")
    assert result.path.read_bytes() == PDF
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o600
    assert source.read_bytes() == PDF
    assert local_intake._snapshot(source.stat()) == local_intake._snapshot(original)
    assert set(archive.iterdir()) == {result.path}
    assert result.path.stat().st_nlink == 1  # staging link was removed
    with pytest.raises(FrozenInstanceError):
        result.status = "already_present"


def test_repeat_is_idempotent_and_does_not_change_existing_file(files) -> None:
    source, archive = files
    first = copy_authorized_pdf(source, archive)
    first.path.chmod(0o640)
    before = first.path.stat()

    second = copy_authorized_pdf(source, archive)

    assert second.status == "already_present"
    assert second.path == first.path
    assert second.sha256 == first.sha256
    assert local_intake._snapshot(second.path.stat()) == local_intake._snapshot(before)
    assert stat.S_IMODE(second.path.stat().st_mode) == 0o640
    assert set(archive.iterdir()) == {first.path}


def test_expected_sha256_binds_copy_to_inspected_snapshot(files) -> None:
    source, archive = files
    expected = hashlib.sha256(PDF).hexdigest()
    result = copy_authorized_pdf(source, archive, expected_sha256=expected.upper())
    assert result.sha256 == expected
    assert result.status == "copied"


def test_expected_sha256_mismatch_fails_before_any_archive_write(files, monkeypatch) -> None:
    source, archive = files
    expected = hashlib.sha256(PDF).hexdigest()
    source.write_bytes(OTHER_PDF)

    def forbidden_temporary_copy(*args):
        pytest.fail("Unexpected copy after inspected source changed")

    monkeypatch.setattr(local_intake, "_copy_bytes", forbidden_temporary_copy)
    with pytest.raises(LocalIntakeError, match="previously inspected"):
        copy_authorized_pdf(source, archive, expected_sha256=expected)
    assert list(archive.iterdir()) == []


@pytest.mark.parametrize("expected", ["", "f" * 63, "f" * 65, "z" * 64, 3])
def test_invalid_expected_sha256_fails_closed(files, expected) -> None:
    source, archive = files
    with pytest.raises(LocalIntakeError, match="64 hexadecimal"):
        copy_authorized_pdf(source, archive, expected_sha256=expected)
    assert list(archive.iterdir()) == []


def test_source_already_at_destination_is_unchanged(files) -> None:
    source, archive = files
    source_in_archive = archive / source.name
    source_in_archive.write_bytes(PDF)
    before = source_in_archive.stat()

    result = copy_authorized_pdf(source_in_archive, archive)

    assert result.status == "already_present"
    assert local_intake._snapshot(source_in_archive.stat()) == local_intake._snapshot(before)


def test_explicit_nested_destination_uses_only_existing_selected_directory(files) -> None:
    source, archive = files
    (archive / "chosen-folder").mkdir()
    result = copy_authorized_pdf(source, archive, "chosen-folder/chosen-name.pdf")
    assert result.path == archive / "chosen-folder/chosen-name.pdf"
    assert result.path.read_bytes() == PDF


def test_missing_destination_parent_is_not_created(files) -> None:
    source, archive = files
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive, "missing/report.pdf")
    assert list(archive.iterdir()) == []


@pytest.mark.parametrize("destination", ["", ".", "..", "../outside.pdf", "one/../../outside.pdf", "/outside.pdf", "one//report.pdf", "one/./report.pdf", "one/", "..\\outside.pdf", "C:\\outside.pdf", "report\x00.pdf"])
def test_destination_traversal_and_ambiguous_paths_fail_closed(files, destination) -> None:
    source, archive = files
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive, destination)
    assert list(archive.iterdir()) == []


@pytest.mark.parametrize("existing", [OTHER_PDF, b"not a PDF"])
def test_existing_different_file_is_never_overwritten(files, existing) -> None:
    source, archive = files
    target = archive / source.name
    target.write_bytes(existing)
    target.chmod(0o644)
    before = target.stat()

    with pytest.raises(IntakeConflictError):
        copy_authorized_pdf(source, archive)

    assert target.read_bytes() == existing
    assert local_intake._snapshot(target.stat()) == local_intake._snapshot(before)
    assert set(archive.iterdir()) == {target}


@pytest.mark.parametrize("kind", ["source", "source_parent", "archive", "archive_parent", "destination_parent", "destination"])
def test_symlinks_in_any_path_component_are_rejected(files, kind) -> None:
    source, archive = files
    base = source.parent
    destination = None
    if kind == "source":
        link = base / "linked-source.pdf"
        link.symlink_to(source)
        source = link
    elif kind == "source_parent":
        link = base / "linked-source-parent"
        link.symlink_to(base, target_is_directory=True)
        source = link / source.name
    elif kind == "archive":
        link = base / "linked-archive"
        link.symlink_to(archive, target_is_directory=True)
        archive = link
    elif kind == "archive_parent":
        link = base / "linked-archive-parent"
        link.symlink_to(base, target_is_directory=True)
        archive = link / archive.name
    elif kind == "destination_parent":
        (archive / "linked-folder").symlink_to(base, target_is_directory=True)
        destination = "linked-folder/escaped.pdf"
    else:
        (archive / source.name).symlink_to(source)

    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive, destination)
    assert (base / "synthetic-report.pdf").read_bytes() == PDF
    assert not (base / "escaped.pdf").exists()


def test_dangling_destination_symlink_is_not_replaced(files) -> None:
    source, archive = files
    target = archive / source.name
    missing = source.parent / "missing.pdf"
    target.symlink_to(missing)
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive)
    assert target.is_symlink()
    assert not missing.exists()


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_source_must_be_a_regular_file_without_blocking(files, kind) -> None:
    _, archive = files
    source = archive.parent / "nonregular.pdf"
    if kind == "directory":
        source.mkdir()
    else:
        os.mkfifo(source)
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive)
    assert list(archive.iterdir()) == []


@pytest.mark.parametrize("contents", [b"", b"%PDF", b"hello", b" prefix %PDF-1.7"])
def test_missing_pdf_header_is_rejected_before_archive_write(files, contents) -> None:
    source, archive = files
    source.write_bytes(contents)
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive)
    assert list(archive.iterdir()) == []


def test_pdf_size_limit_is_64_mib_and_enforced_before_copy(files, monkeypatch) -> None:
    source, archive = files
    assert local_intake.MAX_PDF_BYTES == 64 * 1024 * 1024
    monkeypatch.setattr(local_intake, "MAX_PDF_BYTES", len(PDF) - 1)
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive)
    assert list(archive.iterdir()) == []


def test_pdf_exactly_at_size_limit_is_allowed(files, monkeypatch) -> None:
    source, archive = files
    monkeypatch.setattr(local_intake, "MAX_PDF_BYTES", len(PDF))
    assert copy_authorized_pdf(source, archive).status == "copied"


@pytest.mark.parametrize("change", ["content", "replace", "symlink"])
def test_source_mutation_or_replacement_during_copy_fails_before_publication(files, monkeypatch, change) -> None:
    source, archive = files
    real_copy = local_intake._copy_bytes

    def changed_copy(source_fd, temporary_fd):
        real_copy(source_fd, temporary_fd)
        if change == "content":
            source.write_bytes(OTHER_PDF)
        elif change == "replace":
            replacement = source.with_name("replacement.pdf")
            replacement.write_bytes(PDF)
            os.replace(replacement, source)
        else:
            source.rename(source.with_name("original.pdf"))
            source.symlink_to(source.with_name("original.pdf"))

    monkeypatch.setattr(local_intake, "_copy_bytes", changed_copy)
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive)
    assert list(archive.iterdir()) == []


def test_destination_parent_substitution_cannot_follow_new_symlink(files, monkeypatch) -> None:
    source, archive = files
    chosen = archive / "chosen"
    chosen.mkdir()
    outside = archive.parent / "outside"
    outside.mkdir()
    real_copy = local_intake._copy_bytes

    def swapped_parent(source_fd, temporary_fd):
        real_copy(source_fd, temporary_fd)
        chosen.rename(archive / "old-chosen")
        chosen.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(local_intake, "_copy_bytes", swapped_parent)
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive, "chosen/report.pdf")
    assert list(outside.iterdir()) == []
    assert list((archive / "old-chosen").iterdir()) == []


def _write_exclusive_at(parent_fd: int, name: str, contents: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
    try:
        assert os.write(fd, contents) == len(contents)
    finally:
        os.close(fd)


@pytest.mark.parametrize("same_contents", [False, True])
def test_competing_creation_is_atomic_and_never_overwritten(files, monkeypatch, same_contents) -> None:
    source, archive = files
    real_link = os.link
    competing = PDF if same_contents else OTHER_PDF

    def race_link(src, dst, **kwargs):
        _write_exclusive_at(kwargs["dst_dir_fd"], dst, competing)
        return real_link(src, dst, **kwargs)

    monkeypatch.setattr(os, "link", race_link)
    if same_contents:
        assert copy_authorized_pdf(source, archive).status == "already_present"
    else:
        with pytest.raises(IntakeConflictError):
            copy_authorized_pdf(source, archive)
    assert (archive / source.name).read_bytes() == competing
    assert set(archive.iterdir()) == {archive / source.name}


def test_competing_symlink_is_not_followed_or_overwritten(files, monkeypatch) -> None:
    source, archive = files
    real_link = os.link
    outside = archive.parent / "outside.pdf"
    outside.write_bytes(OTHER_PDF)

    def race_link(src, dst, **kwargs):
        os.symlink(outside, dst, dir_fd=kwargs["dst_dir_fd"])
        return real_link(src, dst, **kwargs)

    monkeypatch.setattr(os, "link", race_link)
    with pytest.raises(LocalIntakeError):
        copy_authorized_pdf(source, archive)
    assert (archive / source.name).is_symlink()
    assert outside.read_bytes() == OTHER_PDF
    assert set(archive.iterdir()) == {archive / source.name}


def test_destination_bytes_are_verified_after_publication(files, monkeypatch) -> None:
    source, archive = files
    real_link = os.link

    def corrupt_link(src, dst, **kwargs):
        real_link(src, dst, **kwargs)
        fd = os.open(dst, os.O_WRONLY | os.O_TRUNC, dir_fd=kwargs["dst_dir_fd"])
        try:
            os.write(fd, OTHER_PDF)
        finally:
            os.close(fd)

    monkeypatch.setattr(os, "link", corrupt_link)
    with pytest.raises(IntakeConflictError):
        copy_authorized_pdf(source, archive)
    # An archive entry is not silently removed after it has been published.
    assert (archive / source.name).read_bytes() == OTHER_PDF
    assert source.read_bytes() == PDF
    assert set(archive.iterdir()) == {archive / source.name}
