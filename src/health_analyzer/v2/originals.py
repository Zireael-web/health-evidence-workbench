"""Private, immutable original bytes for newly imported v2 document versions.

The import service owns this API. Its returned manifest must be stored in the
subject-scoped SignedStore and retrieved with its signed document version;
an opaque reference supplied by a model is not provenance. This module never
accepts snapshot paths and never opens, changes, or deletes an archive source.

Filesystem publication precedes the SQLite commit. A database rollback can
therefore leave an unreferenced, verified blob. Retain it for safe idempotent
reuse; do not automatically delete, repair, or migrate originals. An interrupted
publication can also leave a private staging file. Staging files are never read
as originals and automatic garbage collection is deliberately absent.

Descriptor traversal prevents symlink redirection; mode restrictions prevent
accidental writes. A process with the same OS identity can still tamper with
private files. Every read verifies the signed size and hash and fails closed.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import threading
from typing import Iterator
from uuid import uuid4

from .common import V2Error, require
from .contracts import identifier


MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MANIFEST_SCHEMA = "health-analyzer.original/1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MANIFEST_FIELDS = {"schema_version", "subject_id", "source_sha256", "size",
                   "mime", "source_mode", "snapshot_ref"}


class OriginalsStore:
    """Content-addressed bytes, physically separated by subject scope.

    Directory descriptors are reopened from the filesystem root for every
    operation. The base directory's inode is pinned at construction, so replacing
    or renaming the configured base does not silently select another store.
    The deployment must provision the base's parent. Ancestors are opened
    read-only; only the base and its descendants may be created by this store.
    Existing private directories and files must already have restrictive modes;
    unsafe or corrupt existing objects are never overwritten or repaired.
    """

    def __init__(self, base: Path, *, readonly: bool = False):
        require(type(readonly) is bool, "INVALID_ORIGINAL", "Originals read mode must be boolean")
        self.readonly = readonly
        require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
                and os.open in os.supports_dir_fd and os.link in os.supports_dir_fd
                and os.stat in os.supports_dir_fd and os.unlink in os.supports_dir_fd,
                "ORIGINALS_PLATFORM_UNSUPPORTED", "Safe descriptor paths are unavailable")
        try:
            self.base = Path(base).absolute()
        except (TypeError, ValueError, OSError) as exc:
            raise V2Error("UNSAFE_ORIGINAL_PATH", "Invalid originals base path") from exc
        require(self.base != Path(self.base.anchor)
                and all(part not in {".", ".."} and "\x00" not in part
                        for part in self.base.parts),
                "UNSAFE_ORIGINAL_PATH", "Originals base must be a direct absolute path")
        self._lock = threading.RLock()
        self._base_identity: tuple[int, int] | None = None
        with self._base_directory(create=not readonly) as (fd, _):
            self._base_identity = self._inode(os.fstat(fd))

    @staticmethod
    def _inode(metadata: os.stat_result) -> tuple[int, int]:
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _identity(metadata: os.stat_result) -> tuple:
        return (metadata.st_dev, metadata.st_ino, metadata.st_size,
                metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_mode,
                metadata.st_uid)

    @staticmethod
    def _private(metadata: os.stat_result, *, directory: bool) -> None:
        regular = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
        require(regular and metadata.st_uid == os.getuid()
                and stat.S_IMODE(metadata.st_mode) in ({0o700} if directory else {0o400, 0o600}),
                "ORIGINAL_INTEGRITY_FAILURE", "Originals object has an unsafe type, owner, or mode")

    @staticmethod
    def _scope(subject_id: str) -> str:
        identifier(subject_id, "subject_id")
        return hashlib.sha256(subject_id.encode("utf-8")).hexdigest()

    @classmethod
    def snapshot_ref(cls, subject_id: str, sha256: str) -> str:
        """An opaque identity, never a pathname or a bearer authorization."""
        scope = cls._scope(subject_id)
        cls._validate_hash(sha256)
        return f"originals-v1:{scope}:{sha256}"

    @staticmethod
    def _validate_hash(sha256: str) -> None:
        require(isinstance(sha256, str) and bool(SHA256_RE.fullmatch(sha256)),
                "INVALID_ORIGINAL", "Original SHA-256 must be lowercase hex")

    @staticmethod
    def _validate_size(size: int) -> None:
        require(isinstance(size, int) and not isinstance(size, bool)
                and 0 <= size <= MAX_ORIGINAL_BYTES,
                "INVALID_ORIGINAL", "Original size must be bounded to 64 MiB")

    @staticmethod
    def _validate_mime(mime: str) -> None:
        require(isinstance(mime, str) and bool(re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*", mime))
            and len(mime) <= 100, "INVALID_ORIGINAL", "A bounded MIME type is required")

    @staticmethod
    def _open_directory(parent: int, name: str, *, create: bool) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            # Do not issue a write request for an existing directory. macOS
            # private Seatbelt allows descriptor traversal of literal ancestor
            # paths without granting directory creation or synchronization there.
            fd = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass  # A concurrent creator won; no chmod or repair.
            else:
                os.fsync(parent)
            fd = os.open(name, flags, dir_fd=parent)
        require(stat.S_ISDIR(os.fstat(fd).st_mode), "UNSAFE_ORIGINAL_PATH",
                "Originals path is not a directory")
        return fd

    @staticmethod
    def _verify_chain(chain: list[tuple[int, str, int]]) -> None:
        for parent, name, child in chain:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(named.st_mode)
                    and OriginalsStore._inode(named) == OriginalsStore._inode(os.fstat(child)),
                    "UNSAFE_ORIGINAL_PATH", "Originals directory changed during access")

    @contextmanager
    def _base_directory(self, *, create: bool = False) -> Iterator[tuple[int, list]]:
        descriptors: list[int] = []
        chain: list[tuple[int, str, int]] = []
        try:
            descriptors.append(os.open(self.base.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            for index, part in enumerate(self.base.parts[1:], start=1):
                parent = descriptors[-1]
                child = self._open_directory(parent, part,
                    create=create and index == len(self.base.parts) - 1)
                descriptors.append(child)
                chain.append((parent, part, child))
            base_fd = descriptors[-1]
            metadata = os.fstat(base_fd)
            self._private(metadata, directory=True)
            require(self._base_identity is None or self._inode(metadata) == self._base_identity,
                    "UNSAFE_ORIGINAL_PATH", "Originals base was replaced")
            self._verify_chain(chain)
            yield base_fd, chain
            self._private(os.fstat(base_fd), directory=True)
            self._verify_chain(chain)
        except OSError as exc:
            code = "ORIGINAL_UNAVAILABLE" if exc.errno == errno.ENOENT else "UNSAFE_ORIGINAL_PATH"
            raise V2Error(code, "Originals store path is missing or unsafe") from exc
        finally:
            for fd in reversed(descriptors):
                os.close(fd)

    @contextmanager
    def _blob_directory(self, subject_id: str, sha256: str, *, create: bool = False) -> Iterator[int]:
        scope = self._scope(subject_id)
        self._validate_hash(sha256)
        with self._lock, self._base_directory() as (base_fd, chain):
            # A directory flock adds no mutable lock file and releases on crash.
            # Shared reads cannot see the transient two-link publication stage.
            fcntl.flock(base_fd, fcntl.LOCK_EX if create else fcntl.LOCK_SH)
            descriptors: list[int] = []
            try:
                parent = base_fd
                for part in (scope, sha256[:2]):
                    child = self._open_directory(parent, part, create=create)
                    descriptors.append(child)
                    self._private(os.fstat(child), directory=True)
                    chain.append((parent, part, child))
                    parent = child
                self._verify_chain(chain)
                yield parent
                for fd in descriptors:
                    self._private(os.fstat(fd), directory=True)
                self._verify_chain(chain)
            except OSError as exc:
                code = "ORIGINAL_UNAVAILABLE" if exc.errno == errno.ENOENT else "UNSAFE_ORIGINAL_PATH"
                raise V2Error(code, "Original subject directory is missing or unsafe") from exc
            finally:
                # _base_directory verifies only its own live descriptors.
                del chain[len(self.base.parts) - 1:]
                for fd in reversed(descriptors):
                    os.close(fd)
                fcntl.flock(base_fd, fcntl.LOCK_UN)

    @classmethod
    def _read_blob(cls, directory_fd: int, sha256: str, expected_size: int) -> bytes:
        fd = None
        try:
            fd = os.open(sha256, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            before = os.fstat(fd)
            cls._private(before, directory=False)
            require(before.st_size == expected_size, "ORIGINAL_INTEGRITY_FAILURE", "Original size differs")
            content = bytearray()
            while len(content) <= expected_size:
                block = os.read(fd, min(1024 * 1024, expected_size + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
            after = os.fstat(fd)
            named = os.stat(sha256, dir_fd=directory_fd, follow_symlinks=False)
            require(cls._identity(before) == cls._identity(after)
                    and cls._inode(named) == cls._inode(after) and stat.S_ISREG(named.st_mode)
                    and len(content) == expected_size
                    and hmac.compare_digest(hashlib.sha256(content).hexdigest(), sha256),
                    "ORIGINAL_INTEGRITY_FAILURE", "Original bytes or path no longer match their identity")
            return bytes(content)
        except OSError as exc:
            code = "ORIGINAL_UNAVAILABLE" if exc.errno == errno.ENOENT else "ORIGINAL_INTEGRITY_FAILURE"
            raise V2Error(code, "Original bytes are missing or unsafe") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def preserve(self, subject_id: str, content: bytes, mime: str) -> dict:
        """Durably publish bytes once, or verify and reuse an existing blob."""
        require(not self.readonly, "ORIGINALS_READ_ONLY", "Read-only originals cannot publish bytes")
        self._scope(subject_id)
        require(isinstance(content, bytes), "INVALID_ORIGINAL", "Original content must be bytes")
        self._validate_size(len(content))
        self._validate_mime(mime)
        sha256 = hashlib.sha256(content).hexdigest()
        with self._blob_directory(subject_id, sha256, create=True) as directory_fd:
            try:
                self._read_blob(directory_fd, sha256, len(content))
            except V2Error as exc:
                if exc.code != "ORIGINAL_UNAVAILABLE":
                    raise
                self._publish(directory_fd, sha256, content)
            self._read_blob(directory_fd, sha256, len(content))
        return {"schema_version": MANIFEST_SCHEMA, "subject_id": subject_id,
                "source_sha256": sha256, "size": len(content), "mime": mime,
                "source_mode": "immutable_snapshot",
                "snapshot_ref": self.snapshot_ref(subject_id, sha256)}

    @classmethod
    def _publish(cls, directory_fd: int, sha256: str, content: bytes) -> None:
        temporary = ".staging-" + uuid4().hex
        fd = None
        created_identity = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            created_identity = cls._inode(os.fstat(fd))
            remaining = memoryview(content)
            while remaining:
                written = os.write(fd, remaining)
                require(written > 0, "ORIGINAL_PUBLICATION_FAILED", "Original write made no progress")
                remaining = remaining[written:]
            os.fchmod(fd, 0o400)
            os.fsync(fd)
            named = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
            require(stat.S_ISREG(named.st_mode) and cls._inode(named) == created_identity,
                    "ORIGINAL_INTEGRITY_FAILURE", "Original staging path changed")
            try:
                # link is atomic and exclusive; unlike rename it cannot replace.
                os.link(temporary, sha256, src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd, follow_symlinks=False)
            except FileExistsError:
                # Another publisher may have won; no overwrite or repair.
                cls._read_blob(directory_fd, sha256, len(content))
            else:
                published = os.stat(sha256, dir_fd=directory_fd, follow_symlinks=False)
                require(stat.S_ISREG(published.st_mode) and cls._inode(published) == created_identity,
                        "ORIGINAL_INTEGRITY_FAILURE", "Original publication path changed")
            os.fsync(directory_fd)
        except OSError as exc:
            raise V2Error("ORIGINAL_PUBLICATION_FAILED", "Original publication did not complete") from exc
        finally:
            if fd is not None:
                os.close(fd)
            if created_identity is not None:
                try:
                    named = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISREG(named.st_mode) and cls._inode(named) == created_identity:
                        os.unlink(temporary, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    raise V2Error("ORIGINAL_PUBLICATION_FAILED", "Original staging cleanup did not complete") from exc

    def read(self, subject_id: str, sha256: str, expected_size: int) -> bytes:
        """Internal bounded read; callers obtain identity from signed provenance."""
        self._validate_size(expected_size)
        with self._blob_directory(subject_id, sha256) as directory_fd:
            return self._read_blob(directory_fd, sha256, expected_size)

    def read_manifest(self, subject_id: str, manifest: dict, version: dict | None = None) -> bytes:
        """Validate scoped manifest/version metadata before reading exact bytes.

        Passing a dictionary does not authenticate it. The import integration
        must load both objects from its signed, subject-scoped store first.
        """
        self._scope(subject_id)
        require(isinstance(manifest, dict) and set(manifest) == MANIFEST_FIELDS
                and manifest.get("schema_version") == MANIFEST_SCHEMA
                and manifest.get("source_mode") == "immutable_snapshot",
                "INVALID_ORIGINAL_MANIFEST", "Invalid immutable-original manifest")
        require(manifest.get("subject_id") == subject_id, "WRONG_SUBJECT", "Original manifest is outside subject scope")
        sha256 = manifest.get("source_sha256")
        self._validate_hash(sha256)
        self._validate_size(manifest.get("size"))
        self._validate_mime(manifest.get("mime"))
        require(manifest.get("snapshot_ref") == self.snapshot_ref(subject_id, sha256),
                "INVALID_ORIGINAL_MANIFEST", "Original reference does not match its scoped identity")
        if version is not None:
            require(isinstance(version, dict) and version.get("subject_id") == subject_id,
                    "WRONG_SUBJECT", "Document version is outside subject scope")
            self._validate_size(version.get("size"))
            require(all(version.get(key) == manifest[key] for key in ("source_sha256", "size", "mime")),
                    "ORIGINAL_VERSION_MISMATCH", "Original manifest does not match the document version")
        return self.read(subject_id, sha256, manifest["size"])

    def verified_path(self, subject_id: str, manifest: dict, version: dict | None = None) -> Path:
        """A private local-viewer path derived only from verified provenance.

        The path is never accepted as input or stored as the source identity.
        Verification applies at this call; a later viewer open cannot inherit
        the descriptor guarantee. Recheck bytes for subsequent extraction or
        review commits, and keep this path out of public/synthesis surfaces.
        """
        self.read_manifest(subject_id, manifest, version)
        sha256 = manifest["source_sha256"]
        return self.base / self._scope(subject_id) / sha256[:2] / sha256

    def availability(self, subject_id: str, sha256: str, expected_size: int) -> dict:
        """A byte verification status; never hides malformed caller identities."""
        self._scope(subject_id)
        self._validate_hash(sha256)
        self._validate_size(expected_size)
        try:
            self.read(subject_id, sha256, expected_size)
        except V2Error as exc:
            if exc.code not in {"ORIGINAL_UNAVAILABLE", "ORIGINAL_INTEGRITY_FAILURE", "UNSAFE_ORIGINAL_PATH"}:
                raise
            return {"status": "unavailable" if exc.code == "ORIGINAL_UNAVAILABLE" else "integrity_failure",
                    "available": False, "error_code": exc.code}
        return {"status": "available", "available": True}
