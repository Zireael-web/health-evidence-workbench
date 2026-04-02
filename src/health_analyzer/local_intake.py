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
