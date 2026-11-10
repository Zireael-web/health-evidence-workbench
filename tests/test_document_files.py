"""Storage tests use only invented byte strings and pytest temporary folders."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

import pytest

from health_analyzer import document_files as storage
from health_analyzer.local_intake import IntakeConflictError, LocalIntakeError


@pytest.fixture
def paths(tmp_path: Path) -> tuple[Path, Path]:
    # macOS may expose /var as a symlink; storage intentionally refuses it.
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    incoming = base / "incoming"
    incoming.mkdir()
    return archive, incoming


@pytest.mark.parametrize("name,data", [
    ("sample.pdf", b"%PDF-1.7\nfictional bytes"),
    ("sample.png", b"\x89PNG\r\n\x1a\nfictional bytes"),
    ("sample.jpeg", b"\xff\xd8\xfffictional bytes"),
    ("sample.odt", b"fictional bytes of another format"),
    ("empty.bin", b""),
])
def test_copy_preserves_selected_bytes_and_permissions(paths, name: str, data: bytes) -> None:
    archive, incoming = paths
    source = incoming / name
    source.write_bytes(data)
    result = storage.copy_authorized_document(source, archive)
    assert result.path == archive / name
    assert result.path.read_bytes() == data
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert result.status == "copied"
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o600
    assert result.path.stat().st_nlink == 1
    assert source.read_bytes() == data


def test_retry_and_conflicts_never_replace_source_or_destination(paths) -> None:
    archive, incoming = paths
    source = incoming / "sample.png"
    source.write_bytes(b"fictional image")
    original = storage.copy_authorized_document(source, archive)
    before = original.path.stat()
    retry = storage.copy_authorized_document(source, archive)
    assert retry.status == "already_present"
    assert retry.warnings == ("existing_document_role_and_source_unverified",)
    assert original.path.stat().st_ino == before.st_ino
    source.write_bytes(b"another fictional image")
    with pytest.raises(IntakeConflictError):
        storage.copy_authorized_document(source, archive)
    assert original.path.read_bytes() == b"fictional image"
    assert sorted(p.name for p in archive.iterdir()) == ["sample.png"]


def test_hash_bound_copy_rejects_mismatch_before_any_write(paths) -> None:
    archive, incoming = paths
    source = incoming / "sample.bin"
    source.write_bytes(b"fictional")
    with pytest.raises(LocalIntakeError, match="SHA-256"):
        storage.copy_authorized_document(source, archive, expected_sha256="0" * 64)
    assert list(archive.iterdir()) == []


def test_text_sidecars_include_full_source_name_and_preserve_bytes(paths) -> None:
    archive, incoming = paths
    for name in ("same.pdf", "same.png"):
        (incoming / name).write_bytes(name.encode())
        copied = storage.copy_authorized_document(incoming / name, archive)
        text = f"\r\nВымышленная расшифровка: {name}\n"
        saved = storage.save_document_transcript(copied.path, text, archive_root=archive,
                                                 expected_sha256=copied.sha256)
        assert saved.path.name == name + ".txt"
        assert saved.path.read_bytes() == text.encode()
        assert stat.S_IMODE(saved.path.stat().st_mode) == 0o600
        retry = storage.save_document_transcript(copied.path, text, archive_root=archive,
                                                  expected_sha256=copied.sha256)
        assert retry.status == "already_present"
        assert "existing_text_role_and_source_unverified" in retry.warnings
        with pytest.raises(IntakeConflictError):
            storage.save_document_transcript(copied.path, "changed", archive_root=archive,
                                             expected_sha256=copied.sha256)
        assert saved.path.read_bytes() == text.encode()
    assert (archive / "same.pdf.txt").exists()
    assert (archive / "same.png.txt").exists()


def test_transcript_must_belong_to_selected_profile_and_match_hash(paths) -> None:
    archive, incoming = paths
    other = incoming / "subject-b"
    other.mkdir()
    original = other / "synthetic.pdf"
    original.write_bytes(b"fictional")
    correct = hashlib.sha256(original.read_bytes()).hexdigest()
    with pytest.raises(LocalIntakeError, match="inside"):
        storage.save_document_transcript(original, "text", archive_root=archive, expected_sha256=correct)
    within = storage.copy_authorized_document(original, archive)
    with pytest.raises(LocalIntakeError, match="SHA-256"):
        storage.save_document_transcript(within.path, "text", archive_root=archive, expected_sha256="0" * 64)
    assert sorted(p.name for p in archive.iterdir()) == ["synthetic.pdf"]


@pytest.mark.parametrize("destination", ["../elsewhere.bin", "/outside.bin", "a/../b", "a//b", "a\\b", ""])
def test_destination_must_stay_within_selected_root(paths, destination: str) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.bin"
    source.write_bytes(b"fictional")
    with pytest.raises(LocalIntakeError):
        storage.copy_authorized_document(source, archive, destination)
    assert list(archive.iterdir()) == []


@pytest.mark.parametrize("where", ["source", "destination", "parent", "root"])
def test_symlinks_are_rejected_without_altering_targets(paths, where: str) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.bin"
    source.write_bytes(b"fictional")
    outside = incoming / "untouched.bin"
    outside.write_bytes(b"unrelated")
    destination = None
    root = archive
    if where == "source":
        source = incoming / "linked.bin"
        source.symlink_to(outside)
    elif where == "destination":
        (archive / source.name).symlink_to(outside)
    elif where == "parent":
        (archive / "linked").symlink_to(incoming, target_is_directory=True)
        destination = "linked/new.bin"
    else:
        root = incoming / "linked-root"
        root.symlink_to(archive, target_is_directory=True)
    with pytest.raises(LocalIntakeError):
        storage.copy_authorized_document(source, root, destination)
    assert outside.read_bytes() == b"unrelated"


def test_transcript_sidecar_symlink_is_not_followed(paths) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.jpg"
    source.write_bytes(b"fictional")
    copied = storage.copy_authorized_document(source, archive)
    outside = incoming / "outside.txt"
    outside.write_text("untouched")
    (archive / "synthetic.jpg.txt").symlink_to(outside)
    with pytest.raises(LocalIntakeError):
        storage.save_document_transcript(copied.path, "different", archive_root=archive,
                                         expected_sha256=copied.sha256)
    assert outside.read_text() == "untouched"


def test_size_limits_and_fifo_fail_without_writes(paths, monkeypatch) -> None:
    archive, incoming = paths
    monkeypatch.setattr(storage, "MAX_DOCUMENT_BYTES", 3)
    oversized = incoming / "large.bin"
    oversized.write_bytes(b"four")
    with pytest.raises(LocalIntakeError, match="size limit"):
        storage.copy_authorized_document(oversized, archive)
    fifo = incoming / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(LocalIntakeError):
        storage.copy_authorized_document(fifo, archive)
    assert list(archive.iterdir()) == []


def test_invalid_or_oversized_transcript_never_replaces_a_source(paths, monkeypatch) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.bin"
    source.write_bytes(b"fictional")
    copied = storage.copy_authorized_document(source, archive)
    monkeypatch.setattr(storage, "MAX_TEXT_BYTES", 3)
    with pytest.raises(LocalIntakeError, match="limit"):
        storage.save_document_transcript(copied.path, "four", archive_root=archive,
                                         expected_sha256=copied.sha256)
    with pytest.raises(LocalIntakeError, match="UTF-8"):
        storage.save_document_transcript(copied.path, "\ud800", archive_root=archive,
                                         expected_sha256=copied.sha256)
    assert copied.path.read_bytes() == b"fictional"
    assert sorted(p.name for p in archive.iterdir()) == ["synthetic.bin"]


def test_reuse_of_broad_permissions_warns_without_changing_them(paths) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.bin"
    source.write_bytes(b"fictional")
    target = storage.copy_authorized_document(source, archive).path
    target.chmod(0o644)
    result = storage.copy_authorized_document(source, archive)
    assert result.status == "already_present"
    assert "existing_permissions_allow_group_or_other_mode_bits" in result.warnings
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    transcript = storage.save_document_transcript(target, "synthetic", archive_root=archive,
                                                  expected_sha256=result.sha256)
    transcript.path.chmod(0o640)
    result2 = storage.save_document_transcript(target, "synthetic", archive_root=archive,
                                                expected_sha256=result.sha256)
    assert set(result2.warnings) == {"existing_permissions_allow_group_or_other_mode_bits",
                                    "source_permissions_allow_group_or_other_mode_bits",
                                    "existing_text_role_and_source_unverified"}
    assert stat.S_IMODE(transcript.path.stat().st_mode) == 0o640


def test_identical_preexisting_sidecar_has_unverified_role(paths) -> None:
    archive, incoming = paths
    pdf = incoming / "exam.pdf"
    pdf.write_bytes(b"fictional pdf")
    copied = storage.copy_authorized_document(pdf, archive)
    other_original = incoming / "exam.pdf.txt"
    other_original.write_bytes(b"synthetic text")
    storage.copy_authorized_document(other_original, archive)
    result = storage.save_document_transcript(copied.path, "synthetic text", archive_root=archive,
                                              expected_sha256=copied.sha256)
    assert result.status == "already_present"
    assert "existing_text_role_and_source_unverified" in result.warnings
    assert result.path.read_bytes() == b"synthetic text"


@pytest.mark.parametrize("kind", ["source", "destination", "saved_document", "sidecar"])
def test_existing_hardlinks_are_rejected(paths, kind: str) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.bin"
    source.write_bytes(b"fictional")
    if kind == "source":
        os.link(source, incoming / "another-name.bin")
    elif kind == "destination":
        # An existing destination with more than one name cannot be safely reused.
        (archive / "synthetic.bin").write_bytes(b"fictional")
        os.link(archive / "synthetic.bin", incoming / "other-profile.bin")
    else:
        copied = storage.copy_authorized_document(source, archive)
        if kind == "saved_document":
            os.link(copied.path, incoming / "other-profile.bin")
        else:
            sidecar = archive / "synthetic.bin.txt"
            sidecar.write_text("text")
            os.link(sidecar, incoming / "other-profile.txt")
    with pytest.raises(LocalIntakeError, match="[Hh]ard ?links?|hard links"):
        if kind in {"source", "destination"}:
            storage.copy_authorized_document(source, archive)
        else:
            storage.save_document_transcript(copied.path, "text", archive_root=archive,
                                              expected_sha256=copied.sha256)
    assert source.read_bytes() == b"fictional"


def test_failure_after_publication_leaves_file_and_retry_reuses_it(paths, monkeypatch) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.bin"
    source.write_bytes(b"fictional")
    real_assert = storage._assert_destination_parent
    checks = 0

    def synthetic_interruption(*args):
        nonlocal checks
        checks += 1
        if checks == 2:
            raise LocalIntakeError("synthetic post-publication interruption")
        return real_assert(*args)

    monkeypatch.setattr(storage, "_assert_destination_parent", synthetic_interruption)
    with pytest.raises(LocalIntakeError, match="post-publication"):
        storage.copy_authorized_document(source, archive)
    target = archive / source.name
    assert target.read_bytes() == b"fictional"
    assert target.stat().st_nlink == 1
    assert sorted(p.name for p in archive.iterdir()) == [source.name]
    monkeypatch.setattr(storage, "_assert_destination_parent", real_assert)
    assert storage.copy_authorized_document(source, archive).status == "already_present"


def test_interrupted_text_write_preserves_published_original_for_retry(paths, monkeypatch) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.bin"
    source.write_bytes(b"fictional")
    copied = storage.copy_authorized_document(source, archive)
    real_write = storage._write_all

    def fail_write(fd: int, data: bytes) -> None:
        raise OSError("synthetic interruption")

    monkeypatch.setattr(storage, "_write_all", fail_write)
    with pytest.raises(LocalIntakeError):
        storage.save_document_transcript(copied.path, "text", archive_root=archive,
                                         expected_sha256=copied.sha256)
    assert copied.path.read_bytes() == b"fictional"
    assert sorted(p.name for p in archive.iterdir()) == ["synthetic.bin"]
    monkeypatch.setattr(storage, "_write_all", real_write)
    result = storage.save_document_transcript(copied.path, "text", archive_root=archive,
                                               expected_sha256=copied.sha256)
    assert result.path.read_text() == "text"


def test_staging_transcript_rejects_hardlink_and_preserves_exact_utf8(paths) -> None:
    _, incoming = paths
    source = incoming / "synthetic.txt"
    source.write_bytes("Вымышленный текст\r\n".encode())
    assert storage.read_supplied_transcript(source) == "Вымышленный текст\r\n"
    os.link(source, incoming / "linked.txt")
    with pytest.raises(LocalIntakeError, match="Hardlinked"):
        storage.read_supplied_transcript(source)


def test_profile_root_identity_is_checked_before_writing(paths) -> None:
    archive, incoming = paths
    source = incoming / "synthetic.bin"
    source.write_bytes(b"fictional")
    real = archive.stat()
    with pytest.raises(LocalIntakeError, match="root changed"):
        storage.copy_authorized_document(source, archive, expected_root_identity=(real.st_dev, real.st_ino + 1))
    assert list(archive.iterdir()) == []
    result = storage.copy_authorized_document(source, archive,
                                               expected_root_identity=(real.st_dev, real.st_ino))
    with pytest.raises(LocalIntakeError, match="root changed"):
        storage.save_document_transcript(result.path, "text", archive_root=archive,
                                          expected_sha256=result.sha256,
                                          expected_root_identity=(real.st_dev, real.st_ino + 1))
    assert sorted(p.name for p in archive.iterdir()) == ["synthetic.bin"]


def test_ensure_folder_nested_reuses_existing_without_chmod(paths) -> None:
    archive, _ = paths
    existing = archive / "existing"
    existing.mkdir(mode=0o755)
    existing.chmod(0o755)
    root_info = archive.stat()
    expected = (root_info.st_dev, root_info.st_ino)
    created = storage.ensure_folder(archive, "existing/новый/глубже", expected_root_identity=expected)
    assert created.status == "created" and created.created_count == 2
    assert created.path == archive / "existing" / "новый" / "глубже"
    assert "existing_folder_permissions_allow_group_or_other_mode_bits" in created.warnings
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755
    assert stat.S_IMODE((existing / "новый").stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE(created.path.stat().st_mode) & 0o077 == 0
    repeated = storage.ensure_folder(archive, "existing/новый/глубже", expected_root_identity=expected)
    assert repeated.status == "already_present" and repeated.created_count == 0
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755


@pytest.mark.parametrize("folder", ["../outside", "/absolute", "one/../two", "a//b", "a\\b", "", "."])
def test_ensure_folder_rejects_traversal(paths, folder: str) -> None:
    archive, _ = paths
    with pytest.raises(LocalIntakeError):
        storage.ensure_folder(archive, folder)
    assert list(archive.iterdir()) == []


@pytest.mark.parametrize("kind", ["symlink", "file"])
def test_ensure_folder_rejects_symlink_or_file_without_modifying_target(paths, kind: str) -> None:
    archive, incoming = paths
    component = archive / "blocked"
    if kind == "symlink":
        component.symlink_to(incoming, target_is_directory=True)
    else:
        component.write_bytes(b"invented")
    with pytest.raises(LocalIntakeError):
        storage.ensure_folder(archive, "blocked/inner")
    assert list(incoming.iterdir()) == []
    if kind == "file":
        assert component.read_bytes() == b"invented"
    else:
        assert component.is_symlink()


def test_ensure_folder_root_mismatch_prevents_all_writes(paths) -> None:
    archive, _ = paths
    root_info = archive.stat()
    with pytest.raises(LocalIntakeError, match="root changed"):
        storage.ensure_folder(archive, "inside", expected_root_identity=(root_info.st_dev, root_info.st_ino + 1))
    assert list(archive.iterdir()) == []


def test_ensure_folder_warns_for_broad_root_without_chmod(paths) -> None:
    archive, _ = paths
    archive.chmod(0o755)
    result = storage.ensure_folder(archive, "created")
    assert "existing_folder_permissions_allow_group_or_other_mode_bits" in result.warnings
    assert stat.S_IMODE(archive.stat().st_mode) == 0o755
    assert stat.S_IMODE(result.path.stat().st_mode) & 0o077 == 0


def test_ensure_folder_interruption_leaves_existing_partial_path_and_retry(paths, monkeypatch) -> None:
    archive, _ = paths
    actual_check = storage._assert_folder_chain

    def interrupt(root, fd, parts, identities):
        if len(parts) == 1:
            raise LocalIntakeError("fictional interruption")
        return actual_check(root, fd, parts, identities)

    monkeypatch.setattr(storage, "_assert_folder_chain", interrupt)
    with pytest.raises(LocalIntakeError, match="interruption"):
        storage.ensure_folder(archive, "one/two")
    assert (archive / "one").is_dir()
    assert not (archive / "one" / "two").exists()
    monkeypatch.setattr(storage, "_assert_folder_chain", actual_check)
    result = storage.ensure_folder(archive, "one/two")
    assert result.status == "created" and result.created_count == 1


def test_ensure_folder_detects_component_replacement(paths, monkeypatch) -> None:
    archive, incoming = paths
    actual_check = storage._assert_folder_chain
    switched = False

    def replace_after_creation(root, fd, parts, identities):
        nonlocal switched
        if len(parts) == 1 and not switched:
            switched = True
            (archive / "one").rename(archive / "moved")
            (archive / "one").symlink_to(incoming, target_is_directory=True)
        return actual_check(root, fd, parts, identities)

    monkeypatch.setattr(storage, "_assert_folder_chain", replace_after_creation)
    with pytest.raises(LocalIntakeError):
        storage.ensure_folder(archive, "one/two")
    assert list(incoming.iterdir()) == []
    assert (archive / "moved").is_dir()


def test_concurrent_move_can_leave_partial_directory_outside_root(paths, monkeypatch) -> None:
    # Explicitly document the same-user POSIX race; this is not an isolation
    # guarantee and no created or moved directory may be silently deleted.
    archive, outside = paths
    (archive / "one").mkdir()
    real_mkdir = os.mkdir

    def move_before_mkdir(path, mode=0o777, *, dir_fd=None):
        if path == "two":
            os.rename(archive / "one", outside / "one")
        return real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {move_before_mkdir})
    monkeypatch.setattr(os, "mkdir", move_before_mkdir)
    with pytest.raises(LocalIntakeError):
        storage.ensure_folder(archive, "one/two")
    assert (outside / "one" / "two").is_dir()


def test_immediate_same_user_replacement_is_not_an_isolation_boundary(paths, monkeypatch) -> None:
    archive, outside = paths
    real_mkdir = os.mkdir

    def replace_after_mkdir(path, mode=0o777, *, dir_fd=None):
        result = real_mkdir(path, mode, dir_fd=dir_fd)
        if path == "created":
            os.rename(archive / "created", outside / "moved")
            real_mkdir("created", mode, dir_fd=dir_fd)
        return result

    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {replace_after_mkdir})
    monkeypatch.setattr(os, "mkdir", replace_after_mkdir)
    result = storage.ensure_folder(archive, "created")
    assert result.status == "created"
    assert "concurrent_folder_moves_are_not_isolated" in result.warnings
    assert (outside / "moved").is_dir()
