"""Copy explicitly selected files and save model-supplied text locally.

This helper neither selects a person nor extracts or interprets a document.
The caller is responsible for selecting the correct existing subject root and
obtaining authorization. Originals and existing sidecars are never overwritten.
Text sidecars use the complete source filename (``report.pdf.txt``), avoiding
collisions between files with the same stem and different extensions. A name
alone does not prove that an existing file is a transcript of its neighbour;
the helper does not create a provenance manifest.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
from typing import BinaryIO

from .local_intake import (
    IntakeConflictError,
    IntakeResult,
    LocalIntakeError,
    _absolute_path,
    _assert_destination_parent,
    _destination_parts,
    _directory,
    _identity,
    _regular_file,
    _relative_directory,
    _snapshot,
)

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024
_CHUNK = 1024 * 1024
_TEMP_NAME = re.compile(r"\.document-intake-[0-9a-f]{32}\.tmp\Z")


class HardlinkReviewRequired(LocalIntakeError):
    """Unexpected hardlinks need manual review; no recovery deletion is attempted."""


@dataclass(frozen=True, slots=True)
class DocumentResult(IntakeResult):
    """Outcome with warnings about reused files, not a provenance certificate."""

    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FolderResult:
    """Outcome of creating explicit folders beneath one selected root."""

    path: Path
    status: str
    created_count: int
    warnings: tuple[str, ...] = ()


def _stable(info: os.stat_result) -> tuple:
    # Inode link count is not included in local_intake's ordinary snapshot.
    return (*_snapshot(info), info.st_nlink)


def _require_unlinked(info: os.stat_result) -> None:
    if info.st_nlink != 1:
        raise HardlinkReviewRequired("Hardlinked files cannot be safely associated with one subject archive.")


def _reuse_warnings(info: os.stat_result, *, transcript: bool) -> tuple[str, ...]:
    warnings = []
    if stat.S_IMODE(info.st_mode) & 0o077:
        warnings.append("existing_permissions_allow_group_or_other_mode_bits")
    if transcript:
        warnings.append("existing_text_role_and_source_unverified")
    else:
        warnings.append("existing_document_role_and_source_unverified")
    return tuple(warnings)


def _root_identity(fd: int, expected: tuple[int, int] | None) -> None:
    if expected is not None and (
        not isinstance(expected, tuple) or len(expected) != 2
        or not all(type(item) is int and item >= 0 for item in expected)
        or _identity(os.fstat(fd)) != expected
    ):
        raise LocalIntakeError("Selected profile root changed before the operation.")


def _assert_folder_chain(root: Path, root_fd: int, parts: tuple[str, ...],
                         identities: tuple[tuple[int, int], ...]) -> None:
    """Reopen every path component without links and verify its bound identity."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with _directory(root) as current_root:
        if _identity(os.fstat(current_root)) != _identity(os.fstat(root_fd)):
            raise LocalIntakeError("Selected archive root changed during folder creation.")
        fd = os.dup(current_root)
        try:
            for part, expected in zip(parts, identities, strict=True):
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                if _identity(os.fstat(fd)) != expected:
                    raise LocalIntakeError("An archive folder changed during creation.")
        finally:
            os.close(fd)


def ensure_folder(archive_root: Path, relative_folder: str, *,
                  expected_root_identity: tuple[int, int] | None = None) -> FolderResult:
    """Ensure a selected root-relative folder exists without following symlinks.

    New components are requested with mode 0700, subject to the process umask.
    Existing folders are reused without chmod. An error can leave earlier created
    directories in place; this operation never deletes, moves or renames them.
    The caller must select the correct person before invoking this function.
    Descriptor-relative operations and repeated inode checks detect many moves,
    but are not an isolation boundary against concurrent moves by a process with
    the same filesystem permissions. A moved parent may receive a new child before
    the mismatch is detected; replacement immediately after mkdir may go unnoticed.
    """
    _require_posix()
    if os.mkdir not in os.supports_dir_fd:
        raise LocalIntakeError("Secure folder creation requires directory-descriptor mkdir.")
    root = _validated_root(archive_root)
    parts = _destination_parts(relative_folder)
    if len(parts) > 64:
        raise LocalIntakeError("Folder path exceeds the maximum depth.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        with ExitStack() as stack:
            root_fd = stack.enter_context(_directory(root))
            _root_identity(root_fd, expected_root_identity)
            parent_fd = root_fd
            identities: list[tuple[int, int]] = []
            created_count = 0
            broad_existing = bool(stat.S_IMODE(os.fstat(root_fd).st_mode) & 0o077)
            for index, part in enumerate(parts):
                _root_identity(root_fd, expected_root_identity)
                _assert_folder_chain(root, root_fd, parts[:index], tuple(identities))
                try:
                    os.mkdir(part, 0o700, dir_fd=parent_fd)
                    created = True
                    created_count += 1
                except FileExistsError:
                    created = False
                named = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISDIR(named.st_mode):
                    raise LocalIntakeError("A path component is not a directory.")
                child_fd = os.open(part, flags, dir_fd=parent_fd)
                stack.callback(os.close, child_fd)
                opened = os.fstat(child_fd)
                named_after = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                if (_identity(named) != _identity(opened)
                        or _identity(named_after) != _identity(opened)
                        or not stat.S_ISDIR(named_after.st_mode)):
                    raise LocalIntakeError("An archive folder changed while being opened.")
                if created:
                    if opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) & 0o077:
                        raise LocalIntakeError("Created folder ownership or permissions are unexpected.")
                    os.fsync(parent_fd)
                elif stat.S_IMODE(opened.st_mode) & 0o077:
                    broad_existing = True
                identities.append(_identity(opened))
                _root_identity(root_fd, expected_root_identity)
                _assert_folder_chain(root, root_fd, parts[:index + 1], tuple(identities))
                parent_fd = child_fd
            warnings = ("concurrent_folder_moves_are_not_isolated",)
            if broad_existing:
                warnings += ("existing_folder_permissions_allow_group_or_other_mode_bits",)
            return FolderResult(root.joinpath(*parts), "created" if created_count else "already_present",
                                created_count, warnings)
    except OSError as exc:
        raise LocalIntakeError("Folder paths must remain within the selected root and contain no symlinks.") from exc


def _require_posix() -> None:
    if os.name != "posix" or not all(
        hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK")
    ):
        raise LocalIntakeError("Secure document storage requires POSIX no-follow filesystem support.")
    if not all(fn in os.supports_dir_fd for fn in (os.open, os.stat, os.link, os.unlink)):
        raise LocalIntakeError("Secure document storage requires directory-descriptor operations.")


def _validated_root(root: Path) -> Path:
    path = Path(root)
    if not path.is_absolute():
        raise LocalIntakeError("Choose an absolute existing subject archive root.")
    path = _absolute_path(path)
    if path == Path(path.anchor):
        raise LocalIntakeError("Select a subject archive directory, not the filesystem root.")
    return path


def _sha256(value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        c not in "0123456789abcdefABCDEF" for c in value
    ):
        raise LocalIntakeError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
    return value.lower()


def _hash_regular(fd: int, limit: int) -> str:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise LocalIntakeError("File must be regular and within the size limit.")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while chunk := os.read(fd, min(_CHUNK, limit + 1 - count)):
        count += len(chunk)
        if count > limit:
            raise LocalIntakeError("File grew beyond the size limit.")
        digest.update(chunk)
    if count != before.st_size or _stable(os.fstat(fd)) != _stable(before):
        raise LocalIntakeError("File changed while its hash was checked.")
    return digest.hexdigest()


def _assert_source(path: Path, fd: int, before: os.stat_result, digest: str) -> None:
    _require_unlinked(before)
    if _stable(os.fstat(fd)) != _stable(before) or _hash_regular(fd, MAX_DOCUMENT_BYTES) != digest:
        raise LocalIntakeError("Source changed during storage.")
    with _directory(path.parent) as parent, _regular_file(parent, path.name) as current:
        if _stable(os.fstat(current)) != _stable(before):
            raise LocalIntakeError("Source path was replaced during storage.")


def _existing(parent: int, name: str, digest: str, limit: int,
              identity: tuple[int, int] | None = None) -> os.stat_result | None:
    try:
        with _regular_file(parent, name) as fd:
            before = os.fstat(fd)
            if identity is not None and _identity(before) != identity:
                raise LocalIntakeError("Published destination was replaced during storage.")
            # Our temporary file has exactly two links until its name is removed.
            if before.st_nlink != (2 if identity is not None else 1):
                raise HardlinkReviewRequired("Destination has an unexpected number of hard links.")
            try:
                actual = _hash_regular(fd, limit)
            except LocalIntakeError as exc:
                raise IntakeConflictError("Existing destination is not an identical bounded file.") from exc
            if actual != digest:
                raise IntakeConflictError("Existing destination has different contents.")
            if _stable(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _stable(before):
                raise LocalIntakeError("Destination changed during verification.")
            return before
    except FileNotFoundError:
        if identity is not None:
            raise LocalIntakeError("Published destination disappeared during storage.") from None
        return None


def _publish(parent: int, name: str, content_writer, digest: str, limit: int,
             before_link, after_link, *, transcript: bool = False) -> tuple[str, tuple[str, ...]]:
    """Write to a private sibling and publish by an exclusive same-dir hard link."""
    temp = f".document-intake-{secrets.token_hex(16)}.tmp"
    temp_fd = os.open(temp, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0o600, dir_fd=parent)
    temp_id = _identity(os.fstat(temp_fd))
    try:
        os.fchmod(temp_fd, 0o600)
        content_writer(temp_fd)
        if _hash_regular(temp_fd, limit) != digest:
            raise LocalIntakeError("Temporary file differs from the selected source.")
        os.fsync(temp_fd)
        before_link()
        if _identity(os.stat(temp, dir_fd=parent, follow_symlinks=False)) != temp_id:
            raise LocalIntakeError("Temporary path was replaced during storage.")
        try:
            os.link(temp, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        except FileExistsError:
            status = "already_present"
            expected_id = None
        else:
            status = "copied"
            expected_id = temp_id
        after_link()
        existing = _existing(parent, name, digest, limit, expected_id)
        if existing is None:
            raise LocalIntakeError("Destination disappeared before storage completed.")
        os.fsync(parent)
        return status, _reuse_warnings(existing, transcript=transcript) if status == "already_present" else ()
    finally:
        os.close(temp_fd)
        try:
            current = os.stat(temp, dir_fd=parent, follow_symlinks=False)
            if _identity(current) == temp_id:
                os.unlink(temp, dir_fd=parent)
        except FileNotFoundError:
            pass


def _write_all(fd: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise LocalIntakeError("Could not write the complete file.")
        remaining = remaining[written:]


def read_supplied_transcript(path: Path) -> str:
    """Read an explicitly selected UTF-8 staging file without following links."""
    _require_posix()
    path = _absolute_path(path)
    if path.suffix.casefold() != ".txt":
        raise LocalIntakeError("Transcript input must be a .txt file.")
    try:
        with _directory(path.parent) as parent, _regular_file(parent, path.name) as fd:
            before = os.fstat(fd)
            _require_unlinked(before)
            digest = _hash_regular(fd, MAX_TEXT_BYTES)
            os.lseek(fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = MAX_TEXT_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(_CHUNK, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (len(content) > MAX_TEXT_BYTES or hashlib.sha256(content).hexdigest() != digest
                    or _stable(before) != _stable(os.fstat(fd)) or _stable(before) != _stable(current)):
                raise LocalIntakeError("Transcript input changed while being read.")
            _assert_destination_parent(path.parent, parent, (), parent)
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalIntakeError("Transcript input must be valid UTF-8.") from exc
    except OSError as exc:
        raise LocalIntakeError("Transcript paths must exist and allow secure access.") from exc


def read_supplied_transcript_stream(stream: BinaryIO) -> str:
    """Read bounded UTF-8 input without creating or deleting a staging file.

    The caller must provide a binary stream and close its writing end after the
    supplied text. The stream and its transport are the caller's responsibility;
    this function does not establish their confidentiality or retain a retry copy.
    """
    chunks: list[bytes] = []
    remaining = MAX_TEXT_BYTES + 1
    try:
        while remaining:
            chunk = stream.read(min(_CHUNK, remaining))
            if not isinstance(chunk, bytes):
                raise LocalIntakeError("Transcript stream must provide UTF-8 bytes.")
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > MAX_TEXT_BYTES:
            raise LocalIntakeError("Transcript exceeds the 8 MiB UTF-8 limit.")
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalIntakeError("Transcript input must be valid UTF-8.") from exc
    except OSError as exc:
        raise LocalIntakeError("Transcript stream could not be read.") from exc


def inspect_pending_publication(archive_root: Path, relative_destination: str, *,
                                expected_sha256: str,
                                expected_root_identity: tuple[int, int] | None = None) -> dict:
    """Read-only inspection of a possible interrupted publication.

    This cannot authenticate who created a temporary name; it never unlinks or
    repairs anything. Even a matching candidate requires human/operator review.
    """
    _require_posix()
    root = _validated_root(archive_root)
    parts = _destination_parts(relative_destination)
    expected = _sha256(expected_sha256)
    try:
        with ExitStack() as stack:
            root_fd = stack.enter_context(_directory(root))
            _root_identity(root_fd, expected_root_identity)
            parent_fd = stack.enter_context(_relative_directory(root_fd, parts[:-1]))
            target_fd = stack.enter_context(_regular_file(parent_fd, parts[-1]))
            before = os.fstat(target_fd)
            if _hash_regular(target_fd, MAX_DOCUMENT_BYTES) != expected:
                raise LocalIntakeError("Destination does not match the supplied expected SHA-256.")
            matches: list[str] = []
            examined = 0
            with os.scandir(parent_fd) as entries:
                for entry in entries:
                    examined += 1
                    if examined > 10000:
                        raise LocalIntakeError("Directory exceeds the safe inspection limit.")
                    if not _TEMP_NAME.fullmatch(entry.name):
                        continue
                    info = os.stat(entry.name, dir_fd=parent_fd, follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode) and _identity(info) == _identity(before):
                        matches.append(entry.name)
            _root_identity(root_fd, expected_root_identity)
            _assert_destination_parent(root, root_fd, parts[:-1], parent_fd)
            current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if _stable(os.fstat(target_fd)) != _stable(before) or _stable(current) != _stable(before):
                raise LocalIntakeError("Destination changed during inspection.")
            possible = (before.st_nlink == 2 and len(matches) == 1 and before.st_uid == os.getuid()
                        and stat.S_IMODE(before.st_mode) == 0o600)
            return {"status": "possible_interrupted_publication" if possible else "manual_review_required",
                    "candidate_name": matches[0] if possible else None,
                    "content_matches_expected_hash": True,
                    "origin_of_candidate": "unverified",
                    "automatic_changes": False}
    except OSError as exc:
        raise LocalIntakeError("Cannot safely inspect the selected local destination.") from exc


def copy_authorized_document(source: Path, archive_root: Path,
                             relative_destination: str | None = None, *,
                             expected_sha256: str | None = None,
                             expected_root_identity: tuple[int, int] | None = None) -> DocumentResult:
    """Copy selected bytes to a caller-selected subject root, with no parsing.

    The destination parent must already exist. Existing byte-identical files are
    reused; conflicts are not overwritten. A successful copy is mode 0600.
    The limit bounds bytes and does not certify file format or file safety.
    """
    _require_posix()
    source = _absolute_path(source)
    root = _validated_root(archive_root)
    parts = _destination_parts(source.name if relative_destination is None else relative_destination)
    requested_hash = _sha256(expected_sha256) if expected_sha256 is not None else None
    try:
        with ExitStack() as stack:
            source_parent = stack.enter_context(_directory(source.parent))
            source_fd = stack.enter_context(_regular_file(source_parent, source.name))
            before = os.fstat(source_fd)
            _require_unlinked(before)
            digest = _hash_regular(source_fd, MAX_DOCUMENT_BYTES)
            if requested_hash is not None and digest != requested_hash:
                raise LocalIntakeError("Source does not match the previously inspected SHA-256.")
            root_fd = stack.enter_context(_directory(root))
            _root_identity(root_fd, expected_root_identity)
            parent_fd = stack.enter_context(_relative_directory(root_fd, parts[:-1]))

            def check() -> None:
                _assert_source(source, source_fd, before, digest)
                _root_identity(root_fd, expected_root_identity)
                _assert_destination_parent(root, root_fd, parts[:-1], parent_fd)

            if _existing(parent_fd, parts[-1], digest, MAX_DOCUMENT_BYTES):
                check()
                existing = _existing(parent_fd, parts[-1], digest, MAX_DOCUMENT_BYTES)
                if existing is None:
                    raise LocalIntakeError("Existing destination disappeared during storage.")
                return DocumentResult(root.joinpath(*parts), digest, "already_present",
                                      _reuse_warnings(existing, transcript=False))

            def copy(fd: int) -> None:
                os.lseek(source_fd, 0, os.SEEK_SET)
                count = 0
                while chunk := os.read(source_fd, min(_CHUNK, MAX_DOCUMENT_BYTES + 1 - count)):
                    count += len(chunk)
                    if count > MAX_DOCUMENT_BYTES:
                        raise LocalIntakeError("Source grew beyond the size limit.")
                    _write_all(fd, chunk)

            status, warnings = _publish(parent_fd, parts[-1], copy, digest, MAX_DOCUMENT_BYTES, check, check)
            return DocumentResult(root.joinpath(*parts), digest, status, warnings)
    except OSError as exc:
        raise LocalIntakeError("Document paths must exist, contain no symlinks, and allow secure storage.") from exc


def save_document_transcript(document: Path, text: str, *, archive_root: Path,
                             expected_sha256: str,
                             expected_root_identity: tuple[int, int] | None = None) -> DocumentResult:
    """Save supplied UTF-8 text next to a hash-checked saved source document.

    Text is not generated or validated here; completeness and accuracy remain
    unverified. The original and any existing different text remain unchanged.
    Existing identical bytes are reused without proving their provenance.
    """
    _require_posix()
    root = _validated_root(archive_root)
    path = _absolute_path(document)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise LocalIntakeError("Document must be inside the selected subject archive.") from exc
    parts = _destination_parts(relative.as_posix())
    if not isinstance(text, str):
        raise LocalIntakeError("Transcript must be a UTF-8 string.")
    try:
        content = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LocalIntakeError("Transcript must be valid UTF-8.") from exc
    if len(content) > MAX_TEXT_BYTES:
        raise LocalIntakeError("Transcript exceeds the 8 MiB UTF-8 limit.")
    expected = _sha256(expected_sha256)
    digest = hashlib.sha256(content).hexdigest()
    target = parts[-1] + ".txt"
    try:
        with ExitStack() as stack:
            root_fd = stack.enter_context(_directory(root))
            _root_identity(root_fd, expected_root_identity)
            parent_fd = stack.enter_context(_relative_directory(root_fd, parts[:-1]))
            source_fd = stack.enter_context(_regular_file(parent_fd, parts[-1]))
            before = os.fstat(source_fd)
            _require_unlinked(before)
            if _hash_regular(source_fd, MAX_DOCUMENT_BYTES) != expected:
                raise LocalIntakeError("Document does not match the previously inspected SHA-256.")

            def check() -> None:
                _assert_source(path, source_fd, before, expected)
                _root_identity(root_fd, expected_root_identity)
                _assert_destination_parent(root, root_fd, parts[:-1], parent_fd)

            source_warning = (("source_permissions_allow_group_or_other_mode_bits",)
                              if stat.S_IMODE(before.st_mode) & 0o077 else ())
            if _existing(parent_fd, target, digest, MAX_TEXT_BYTES):
                check()
                existing = _existing(parent_fd, target, digest, MAX_TEXT_BYTES)
                if existing is None:
                    raise LocalIntakeError("Existing transcript disappeared during storage.")
                return DocumentResult(path.with_name(target), digest, "already_present",
                                      source_warning + _reuse_warnings(existing, transcript=True))
            status, warnings = _publish(parent_fd, target, lambda fd: _write_all(fd, content), digest,
                                        MAX_TEXT_BYTES, check, check, transcript=True)
            return DocumentResult(path.with_name(target), digest, status, source_warning + warnings)
    except OSError as exc:
        raise LocalIntakeError("Transcript paths must exist, contain no symlinks, and allow secure storage.") from exc
