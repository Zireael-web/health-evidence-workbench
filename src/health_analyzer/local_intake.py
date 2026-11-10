"""Copy one explicitly authorized PDF into one explicitly selected archive.

This local-only helper has no vault, keyring, MCP, or network dependencies. The
caller must obtain authorization for the source and select the exact subject
root; neither identity nor authorization is inferred here. Existing archive
entries are never replaced, renamed, chmodded, or removed. Destination parent
directories must already exist.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import stat
from typing import Iterator, Literal


MAX_PDF_BYTES = 64 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024


class LocalIntakeError(ValueError):
    """The requested intake failed validation or an integrity check."""


class IntakeConflictError(LocalIntakeError):
    """An existing destination has different content and was left untouched."""


@dataclass(frozen=True, slots=True)
class IntakeResult:
    path: Path
    sha256: str
    status: Literal["copied", "already_present"]


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _snapshot(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _absolute_path(path: Path) -> Path:
    path = Path(path)
    if ".." in path.parts or "\x00" in os.fspath(path):
        raise LocalIntakeError("Source and archive paths must not contain traversal or NUL.")
    # Do not resolve symlinks: every original component must pass O_NOFOLLOW.
    return path if path.is_absolute() else Path.cwd() / path


def _destination_parts(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise LocalIntakeError("Destination must be a nonempty relative path.")
    parts = tuple(value.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise LocalIntakeError("Destination must be strictly within the selected archive.")
    return parts


@contextmanager
def _directory(path: Path) -> Iterator[int]:
    """Open an absolute directory without following any symlink component."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _relative_directory(root_fd: int, parts: tuple[str, ...]) -> Iterator[int]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _regular_file(parent_fd: int, name: str) -> Iterator[int]:
    # O_NONBLOCK also prevents a hostile FIFO from hanging before fstat.
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        dir_fd=parent_fd,
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise LocalIntakeError("Source and destination must be regular, non-symlink files.")
        yield fd
    finally:
        os.close(fd)


def _hash_pdf(fd: int) -> str:
    initial = os.fstat(fd)
    if not stat.S_ISREG(initial.st_mode) or not 5 <= initial.st_size <= MAX_PDF_BYTES:
        raise LocalIntakeError("PDF must be a regular file between 5 bytes and 64 MiB.")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while chunk := os.read(fd, min(_CHUNK_BYTES, MAX_PDF_BYTES + 1 - count)):
        if count == 0 and not chunk.startswith(b"%PDF-"):
            raise LocalIntakeError("Source does not begin with a PDF header.")
        count += len(chunk)
        if count > MAX_PDF_BYTES:
            raise LocalIntakeError("PDF exceeds the 64 MiB limit.")
        digest.update(chunk)
    if count != initial.st_size or _snapshot(os.fstat(fd)) != _snapshot(initial):
        raise LocalIntakeError("File changed while its hash was being checked.")
    return digest.hexdigest()


def _assert_source(
    source: Path, source_fd: int, original: os.stat_result, expected_hash: str
) -> None:
    if _snapshot(os.fstat(source_fd)) != _snapshot(original):
        raise LocalIntakeError("Source changed during intake.")
    if _hash_pdf(source_fd) != expected_hash:
        raise LocalIntakeError("Source contents changed during intake.")
    with _directory(source.parent) as parent_fd:
        with _regular_file(parent_fd, source.name) as current_fd:
            if _snapshot(os.fstat(current_fd)) != _snapshot(original):
                raise LocalIntakeError("Source path was replaced during intake.")


def _assert_destination_parent(
    root: Path, root_fd: int, parent_parts: tuple[str, ...], parent_fd: int
) -> None:
    with _directory(root) as current_root:
        if _identity(os.fstat(current_root)) != _identity(os.fstat(root_fd)):
            raise LocalIntakeError("Selected archive root changed during intake.")
        with _relative_directory(current_root, parent_parts) as current_parent:
            if _identity(os.fstat(current_parent)) != _identity(os.fstat(parent_fd)):
                raise LocalIntakeError("Destination parent changed during intake.")


def _existing_destination(
    parent_fd: int,
    name: str,
    expected_hash: str,
    expected_identity: tuple[int, int] | None = None,
) -> bool:
    try:
        with _regular_file(parent_fd, name) as fd:
            initial = os.fstat(fd)
            if expected_identity is not None and _identity(initial) != expected_identity:
                raise LocalIntakeError("Published destination was replaced during intake.")
            try:
                actual_hash = _hash_pdf(fd)
            except LocalIntakeError as exc:
                raise IntakeConflictError("Existing destination is not an identical PDF.") from exc
            if actual_hash != expected_hash:
                raise IntakeConflictError("Existing destination has different contents.")
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if _snapshot(current) != _snapshot(initial):
                raise LocalIntakeError("Destination changed during verification.")
        return True
    except FileNotFoundError:
        if expected_identity is not None:
            raise LocalIntakeError("Published destination disappeared during intake.") from None
        return False


def _copy_bytes(source_fd: int, temporary_fd: int) -> None:
    os.lseek(source_fd, 0, os.SEEK_SET)
    count = 0
    while chunk := os.read(source_fd, min(_CHUNK_BYTES, MAX_PDF_BYTES + 1 - count)):
        count += len(chunk)
        if count > MAX_PDF_BYTES:
            raise LocalIntakeError("Source grew beyond the 64 MiB limit during intake.")
        pending = memoryview(chunk)
        while pending:
            written = os.write(temporary_fd, pending)
            if written == 0:
                raise LocalIntakeError("Could not write the complete temporary PDF.")
            pending = pending[written:]


def copy_authorized_pdf(
    source: Path,
    archive_root: Path,
    relative_destination: str | None = None,
    *,
    expected_sha256: str | None = None,
) -> IntakeResult:
    """Copy an authorized PDF without overwriting any existing archive entry.

    ``archive_root`` is the exact, existing subject root selected by the caller.
    The destination defaults to the source filename. Every parent must already
    exist and be a non-symlink directory. The 64 MiB/header checks bound and
    identify the input; they are not a full PDF parse or a safety certification.

    A successful copy has mode 0600 and is published atomically with an
    exclusive hard link. Existing byte-identical files are returned unchanged.
    Conflicts, symlinks, path substitution, and source mutation fail closed.
    If supplied, ``expected_sha256`` binds intake to a previously inspected
    source snapshot and is checked before any temporary or final archive write.
    This requires POSIX no-follow and directory-descriptor operations.
    """
    if os.name != "posix" or not all(
        hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")
    ):
        raise LocalIntakeError("Secure local intake requires POSIX no-follow filesystem support.")
    source = _absolute_path(source)
    root = _absolute_path(archive_root)
    if root == Path(root.anchor):
        raise LocalIntakeError("Select a subject archive directory, not the filesystem root.")
    parts = _destination_parts(source.name if relative_destination is None else relative_destination)
    destination = root.joinpath(*parts)
    if expected_sha256 is not None:
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in expected_sha256)
        ):
            raise LocalIntakeError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
        expected_sha256 = expected_sha256.lower()
    try:
        with ExitStack() as stack:
            source_parent = stack.enter_context(_directory(source.parent))
            source_fd = stack.enter_context(_regular_file(source_parent, source.name))
            original = os.fstat(source_fd)
            expected_hash = _hash_pdf(source_fd)
            if expected_sha256 is not None and expected_hash != expected_sha256:
                raise LocalIntakeError("Source does not match the previously inspected SHA-256.")
            if _snapshot(os.fstat(source_fd)) != _snapshot(original):
                raise LocalIntakeError("Source changed before intake.")
            root_fd = stack.enter_context(_directory(root))
            parent_fd = stack.enter_context(_relative_directory(root_fd, parts[:-1]))

            if _existing_destination(parent_fd, parts[-1], expected_hash):
                _assert_source(source, source_fd, original, expected_hash)
                _assert_destination_parent(root, root_fd, parts[:-1], parent_fd)
                if not _existing_destination(parent_fd, parts[-1], expected_hash):
                    raise LocalIntakeError("Existing destination disappeared during intake.")
                return IntakeResult(destination, expected_hash, "already_present")

            temporary_name = f".authorized-intake-{secrets.token_hex(16)}.tmp"
            temporary_fd = os.open(
                temporary_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=parent_fd,
            )
            temporary_identity = _identity(os.fstat(temporary_fd))
            try:
                os.fchmod(temporary_fd, 0o600)
                _copy_bytes(source_fd, temporary_fd)
                if _hash_pdf(temporary_fd) != expected_hash:
                    raise LocalIntakeError("Copied PDF does not match the authorized source.")
                os.fsync(temporary_fd)
                _assert_source(source, source_fd, original, expected_hash)
                _assert_destination_parent(root, root_fd, parts[:-1], parent_fd)
                if _identity(os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)) != temporary_identity:
                    raise LocalIntakeError("Temporary PDF path was replaced during intake.")
                try:
                    os.link(
                        temporary_name,
                        parts[-1],
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    status: Literal["copied", "already_present"] = "already_present"
                    if not _existing_destination(parent_fd, parts[-1], expected_hash):
                        raise LocalIntakeError("Concurrent destination disappeared during intake.")
                else:
                    status = "copied"
                    _existing_destination(parent_fd, parts[-1], expected_hash, temporary_identity)
                _assert_source(source, source_fd, original, expected_hash)
                _assert_destination_parent(root, root_fd, parts[:-1], parent_fd)
                if not _existing_destination(
                    parent_fd,
                    parts[-1],
                    expected_hash,
                    temporary_identity if status == "copied" else None,
                ):
                    raise LocalIntakeError("Destination disappeared before intake completed.")
                return IntakeResult(destination, expected_hash, status)
            finally:
                os.close(temporary_fd)
                # Only the temporary name created by this invocation is removed.
                # A published destination is never unlinked, including on errors.
                try:
                    current = os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
                    if _identity(current) == temporary_identity:
                        os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
    except OSError as exc:
        raise LocalIntakeError(
            "Local PDF intake failed: paths must exist, contain no symlinks, and allow secure copying."
        ) from exc


def _read_transcript_bytes(
    parent_fd: int, name: str, expected_identity: tuple[int, int] | None = None,
) -> bytes:
    with _regular_file(parent_fd, name) as fd:
        before = os.fstat(fd)
        if expected_identity is not None and _identity(before) != expected_identity:
            raise LocalIntakeError("Transcript path was replaced during access.")
        if before.st_size > MAX_TRANSCRIPT_BYTES:
            raise LocalIntakeError("Transcript exceeds the 8 MiB UTF-8 limit.")
        content = bytearray()
        while chunk := os.read(fd, min(_CHUNK_BYTES, MAX_TRANSCRIPT_BYTES + 1 - len(content))):
            content.extend(chunk)
            if len(content) > MAX_TRANSCRIPT_BYTES:
                raise LocalIntakeError("Transcript exceeds the 8 MiB UTF-8 limit.")
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (len(content) != before.st_size
                or _snapshot(os.fstat(fd)) != _snapshot(before)
                or _snapshot(named) != _snapshot(before)):
            raise LocalIntakeError("Transcript changed during access.")
        return bytes(content)


def _existing_transcript(
    parent_fd: int, name: str, content: bytes,
    expected_identity: tuple[int, int] | None = None,
) -> bool:
    try:
        try:
            saved = _read_transcript_bytes(parent_fd, name, expected_identity)
        except LocalIntakeError as exc:
            raise IntakeConflictError("Existing transcript is not an identical bounded text file.") from exc
        if saved != content:
            raise IntakeConflictError("Existing transcript has different contents.")
        return True
    except FileNotFoundError:
        if expected_identity is not None:
            raise LocalIntakeError("Published transcript disappeared during intake.") from None
        return False


def save_model_transcript(pdf: Path, text: str, *, expected_sha256: str) -> IntakeResult:
    """Save dialogue-supplied text beside its hash-checked PDF, without recognition.

    The same-stem ``.txt`` contains the exact supplied UTF-8 bytes, up to 8 MiB.
    Existing identical text is reused unchanged; different text is never replaced.
    This does not establish transcription accuracy or source-page coverage.
    """
    if not isinstance(text, str):
        raise LocalIntakeError("Model transcript must be a UTF-8 string.")
    try:
        content = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LocalIntakeError("Model transcript must be valid UTF-8.") from exc
    if len(content) > MAX_TRANSCRIPT_BYTES:
        raise LocalIntakeError("Transcript exceeds the 8 MiB UTF-8 limit.")
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in expected_sha256)):
        raise LocalIntakeError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
    expected_sha256 = expected_sha256.lower()
    pdf = _absolute_path(pdf)
    if pdf.suffix.casefold() != ".pdf":
        raise LocalIntakeError("Select the preserved PDF with a .pdf filename.")
    destination = pdf.with_suffix(".txt")
    text_hash = hashlib.sha256(content).hexdigest()
    try:
        with _directory(pdf.parent) as parent_fd, _regular_file(parent_fd, pdf.name) as source_fd:
            original = os.fstat(source_fd)
            if _hash_pdf(source_fd) != expected_sha256:
                raise LocalIntakeError("PDF does not match the previously inspected SHA-256.")
            _assert_source(pdf, source_fd, original, expected_sha256)
            if _existing_transcript(parent_fd, destination.name, content):
                _assert_destination_parent(pdf.parent, parent_fd, (), parent_fd)
                _assert_source(pdf, source_fd, original, expected_sha256)
                if not _existing_transcript(parent_fd, destination.name, content):
                    raise LocalIntakeError("Existing transcript disappeared during intake.")
                return IntakeResult(destination, text_hash, "already_present")

            temporary_name = f".model-transcript-{secrets.token_hex(16)}.tmp"
            temporary_fd = os.open(
                temporary_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=parent_fd,
            )
            temporary_identity = _identity(os.fstat(temporary_fd))
            try:
                os.fchmod(temporary_fd, 0o600)
                pending = memoryview(content)
                while pending:
                    written = os.write(temporary_fd, pending)
                    if written == 0:
                        raise LocalIntakeError("Could not write the complete model transcript.")
                    pending = pending[written:]
                os.fsync(temporary_fd)
                if _read_transcript_bytes(parent_fd, temporary_name, temporary_identity) != content:
                    raise LocalIntakeError("Temporary transcript differs from the supplied text.")
                _assert_source(pdf, source_fd, original, expected_sha256)
                _assert_destination_parent(pdf.parent, parent_fd, (), parent_fd)
                try:
                    os.link(temporary_name, destination.name, src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd, follow_symlinks=False)
                except FileExistsError:
                    status: Literal["copied", "already_present"] = "already_present"
                else:
                    status = "copied"
                _assert_source(pdf, source_fd, original, expected_sha256)
                _assert_destination_parent(pdf.parent, parent_fd, (), parent_fd)
                if not _existing_transcript(parent_fd, destination.name, content,
                                            temporary_identity if status == "copied" else None):
                    raise LocalIntakeError("Transcript disappeared before intake completed.")
                os.fsync(parent_fd)
                return IntakeResult(destination, text_hash, status)
            finally:
                os.close(temporary_fd)
                try:
                    current = os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
                    if _identity(current) == temporary_identity:
                        os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
    except OSError as exc:
        raise LocalIntakeError("Transcript paths must exist, contain no symlinks, and allow secure access.") from exc


def read_model_transcript(path: Path) -> str:
    """Read the complete bounded UTF-8 staging TXT without following symlinks."""
    path = _absolute_path(path)
    if path.suffix.casefold() != ".txt":
        raise LocalIntakeError("Model transcript input must be a .txt file.")
    try:
        with _directory(path.parent) as parent_fd:
            content = _read_transcript_bytes(parent_fd, path.name)
            _assert_destination_parent(path.parent, parent_fd, (), parent_fd)
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalIntakeError("Model transcript input must be valid UTF-8.") from exc
    except OSError as exc:
        raise LocalIntakeError("Transcript paths must exist, contain no symlinks, and allow secure access.") from exc
