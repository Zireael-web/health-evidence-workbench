"""SQLite sidecar index for immutable private source documents."""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import mimetypes
import os
from pathlib import Path
import sqlite3
import stat

from .identity import SubjectPseudonymizer
from .manifest import SubjectManifest
from .models import (
    AllowedRoot,
    CrossSubjectDocumentError,
    LocationHint,
    ProvenanceLocator,
    SourceChangedDuringReadError,
    SourceDocument,
    SourceOutsideVaultError,
    UnknownSubjectError,
    VerificationResult,
)


MAX_VAULT_FILE_BYTES = 64 * 1024 * 1024
MAX_VAULT_TREE_FILES = 20_000
MAX_VAULT_TREE_BYTES = 4 * 1024 * 1024 * 1024
MAX_SNAPSHOT_PAGE_SIZE = 500
MAX_SNAPSHOT_CURSOR_CHARS = 1_024
VAULT_SCHEMA_VERSION = 3


@dataclass(frozen=True, slots=True)
class VaultDocumentState:
    """Durable presence state for one path-addressed logical document."""

    document_id: str
    subject_id: str
    root_id: str
    relative_path: str
    current_source_id: str
    presence_state: str
    created_at: str
    updated_at: str
    tombstoned_at: str | None


@dataclass(frozen=True, slots=True)
class VaultSnapshot:
    """Metadata for one completely published, immutable root snapshot."""

    snapshot_id: str
    subject_id: str
    root_id: str
    relative_directory: str
    suffixes: tuple[str, ...] | None
    created_at: str
    published_at: str
    source_count: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class VaultSnapshotPage:
    """A bounded page whose cursor is cryptographically bound to its snapshot."""

    snapshot: VaultSnapshot
    documents: tuple[SourceDocument, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class _PreparedSource:
    root: AllowedRoot
    resolved: Path
    relative_path: str
    state: os.stat_result
    sha256: str
    media_type: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_root_file(
    root: Path,
    relative_path: str,
    *,
    maximum_bytes: int = MAX_VAULT_FILE_BYTES,
) -> tuple[os.stat_result, str]:
    """Hash one source through a no-follow descriptor walk."""

    relative = Path(relative_path)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SourceOutsideVaultError("source path is unsafe")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_only = getattr(os, "O_DIRECTORY", 0)
    opened: list[int] = []
    try:
        current = os.open(
            root,
            os.O_RDONLY | directory_only | no_follow | close_on_exec,
        )
        opened.append(current)
        for part in relative.parts[:-1]:
            current = os.open(
                part,
                os.O_RDONLY | directory_only | no_follow | close_on_exec,
                dir_fd=current,
            )
            opened.append(current)
        source = os.open(
            relative.parts[-1],
            os.O_RDONLY | no_follow | close_on_exec,
            dir_fd=current,
        )
        opened.append(source)
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode):
            raise SourceOutsideVaultError("source is not a regular file")
        if before.st_nlink != 1:
            raise SourceOutsideVaultError("multiply linked sources are not accepted")
        if before.st_size > maximum_bytes:
            raise SourceOutsideVaultError("source exceeds the per-file indexing limit")

        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise SourceOutsideVaultError("source exceeds the per-file indexing limit")
        after = os.fstat(source)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or total != after.st_size:
            raise SourceChangedDuringReadError("source changed while it was being hashed")
        return before, digest.hexdigest()
    except OSError as error:
        raise SourceOutsideVaultError("source is unavailable or unsafe") from error
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


class VaultIndex:
    """A patient-scoped metadata index; source roots are never written.

    The SQLite database must live outside every allowlisted source root.  Every
    document read/query API requires a subject ID, preventing accidental
    unscoped reads across patient vaults.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        roots: Mapping[str, str | Path],
        pseudonymizer: SubjectPseudonymizer,
    ) -> None:
        if not roots:
            raise ValueError("at least one allowlisted root is required")
        self.roots = {
            root_id: AllowedRoot(root_id, Path(path))
            for root_id, path in roots.items()
        }
        self.pseudonymizer = pseudonymizer

        if str(database_path) == ":memory:":
            self.database_path: Path | None = None
            sqlite_target = ":memory:"
        else:
            requested_database_path = Path(database_path).expanduser()
            if requested_database_path.is_symlink():
                raise ValueError("vault database must not be a symbolic link")
            self.database_path = requested_database_path.resolve()
            if any(
                self._is_relative_to(self.database_path, root.path)
                for root in self.roots.values()
            ):
                raise ValueError("vault database must be outside read-only source roots")
            if self.database_path.exists():
                database_state = self.database_path.lstat()
                if (
                    not stat.S_ISREG(database_state.st_mode)
                    or database_state.st_nlink != 1
                ):
                    raise ValueError(
                        "vault database must be a singly linked regular file"
                    )
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            sqlite_target = str(self.database_path)

        self._connection = sqlite3.connect(sqlite_target)
        try:
            self._require_safe_database_link()
        except Exception:
            self._connection.close()
            raise
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        try:
            self._create_schema()
        except Exception:
            self._connection.close()
            raise

    @staticmethod
    def _is_relative_to(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
        except ValueError:
            return False
        return True

    def _require_safe_database_link(self) -> None:
        if self.database_path is None:
            return
        try:
            database_state = self.database_path.lstat()
        except OSError as error:
            raise ValueError("vault database is unavailable") from error
        if (
            not stat.S_ISREG(database_state.st_mode)
            or database_state.st_nlink != 1
        ):
            raise ValueError(
                "vault database must remain a singly linked regular file"
            )

    def _create_schema(self) -> None:
        schema_version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if schema_version > VAULT_SCHEMA_VERSION:
            raise RuntimeError(
                "vault schema version "
                f"{schema_version} is newer than supported version {VAULT_SCHEMA_VERSION}"
            )

        document_columns = self._table_columns("documents")
        if document_columns and "document_id" not in document_columns:
            self._migrate_v1_schema()
        else:
            with self._connection:
                self._create_v2_tables()

        document_columns = self._table_columns("documents")
        if "presence_state" not in document_columns:
            self._migrate_v2_schema()
        else:
            with self._connection:
                self._create_v3_tables()
                self._require_foreign_key_integrity()
                self._connection.execute(
                    f"PRAGMA user_version = {VAULT_SCHEMA_VERSION}"
                )

    def _table_columns(self, table_name: str) -> set[str]:
        # All callers use fixed internal table names; interpolation avoids a
        # misleading impression that SQLite accepts table identifiers as bind
        # parameters.
        return {
            row["name"]
            for row in self._connection.execute(
                f"PRAGMA table_info({table_name})"
            ).fetchall()
        }

    def _require_foreign_key_integrity(self) -> None:
        if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise sqlite3.IntegrityError(
                "vault schema contains invalid foreign-key references"
            )

    def _create_v2_tables(self) -> None:
        """Create the normalized logical-document/content-version schema."""

        statements = (
            """
            CREATE TABLE IF NOT EXISTS subjects (
                subject_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS documents (
                document_id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
                absolute_path TEXT NOT NULL UNIQUE,
                root_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                current_source_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(subject_id, root_id, relative_path),
                FOREIGN KEY(document_id, current_source_id)
                    REFERENCES document_versions(document_id, source_id)
                    DEFERRABLE INITIALLY DEFERRED
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS document_versions (
                source_id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
                version_number INTEGER NOT NULL CHECK(version_number >= 1),
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                media_type TEXT NOT NULL,
                indexed_at TEXT NOT NULL,
                UNIQUE(document_id, version_number),
                UNIQUE(document_id, sha256),
                UNIQUE(document_id, source_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS provenance_locators (
                locator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL REFERENCES document_versions(source_id) ON DELETE CASCADE,
                page INTEGER,
                bbox_x0 REAL,
                bbox_y0 REAL,
                bbox_x1 REAL,
                bbox_y1 REAL,
                line_start INTEGER,
                line_end INTEGER,
                char_start INTEGER,
                char_end INTEGER
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS documents_subject_idx
                ON documents(subject_id, root_id, relative_path)
            """,
            """
            CREATE INDEX IF NOT EXISTS document_versions_document_idx
                ON document_versions(document_id, version_number)
            """,
            """
            CREATE INDEX IF NOT EXISTS provenance_source_idx
                ON provenance_locators(source_id)
            """,
        )
        for statement in statements:
            self._connection.execute(statement)

    def _create_v3_tables(self) -> None:
        """Create snapshot storage and enforce published-snapshot immutability."""

        statements = (
            """
            CREATE TABLE IF NOT EXISTS vault_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
                root_id TEXT NOT NULL,
                relative_directory TEXT NOT NULL,
                suffixes_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                published_at TEXT,
                source_count INTEGER NOT NULL CHECK(source_count >= 0),
                total_bytes INTEGER NOT NULL CHECK(total_bytes >= 0)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS vault_snapshot_entries (
                snapshot_id TEXT NOT NULL
                    REFERENCES vault_snapshots(snapshot_id) ON DELETE RESTRICT,
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                source_id TEXT NOT NULL REFERENCES document_versions(source_id),
                PRIMARY KEY(snapshot_id, ordinal),
                UNIQUE(snapshot_id, source_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS vault_snapshot_locators (
                snapshot_id TEXT NOT NULL,
                entry_ordinal INTEGER NOT NULL,
                locator_ordinal INTEGER NOT NULL CHECK(locator_ordinal >= 0),
                page INTEGER,
                bbox_x0 REAL,
                bbox_y0 REAL,
                bbox_x1 REAL,
                bbox_y1 REAL,
                line_start INTEGER,
                line_end INTEGER,
                char_start INTEGER,
                char_end INTEGER,
                PRIMARY KEY(snapshot_id, entry_ordinal, locator_ordinal),
                FOREIGN KEY(snapshot_id, entry_ordinal)
                    REFERENCES vault_snapshot_entries(snapshot_id, ordinal)
                    ON DELETE RESTRICT
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS vault_snapshots_subject_root_idx
                ON vault_snapshots(subject_id, root_id, created_at, snapshot_id)
            """,
            """
            CREATE TRIGGER IF NOT EXISTS snapshot_published_insert_guard
            BEFORE INSERT ON vault_snapshots
            WHEN NEW.published_at IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'vault snapshots must be staged before publication');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS documents_presence_insert_guard
            BEFORE INSERT ON documents
            WHEN NEW.presence_state NOT IN ('present', 'tombstoned')
                 OR (NEW.presence_state = 'present' AND NEW.tombstoned_at IS NOT NULL)
                 OR (NEW.presence_state = 'tombstoned' AND NEW.tombstoned_at IS NULL)
            BEGIN
                SELECT RAISE(ABORT, 'invalid document presence state');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS documents_presence_update_guard
            BEFORE UPDATE OF presence_state, tombstoned_at ON documents
            WHEN NEW.presence_state NOT IN ('present', 'tombstoned')
                 OR (NEW.presence_state = 'present' AND NEW.tombstoned_at IS NOT NULL)
                 OR (NEW.presence_state = 'tombstoned' AND NEW.tombstoned_at IS NULL)
            BEGIN
                SELECT RAISE(ABORT, 'invalid document presence state');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS published_snapshot_update_guard
            BEFORE UPDATE ON vault_snapshots
            WHEN OLD.published_at IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'published vault snapshots are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS published_snapshot_delete_guard
            BEFORE DELETE ON vault_snapshots
            WHEN OLD.published_at IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'published vault snapshots are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS published_snapshot_entry_insert_guard
            BEFORE INSERT ON vault_snapshot_entries
            WHEN (SELECT published_at FROM vault_snapshots
                  WHERE snapshot_id = NEW.snapshot_id) IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'published vault snapshot entries are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS snapshot_entry_binding_guard
            BEFORE INSERT ON vault_snapshot_entries
            WHEN NOT EXISTS (
                SELECT 1
                FROM vault_snapshots AS s
                JOIN document_versions AS v ON v.source_id = NEW.source_id
                JOIN documents AS d ON d.document_id = v.document_id
                WHERE s.snapshot_id = NEW.snapshot_id
                      AND d.subject_id = s.subject_id
                      AND d.root_id = s.root_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'vault snapshot entry binding mismatch');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS published_snapshot_entry_update_guard
            BEFORE UPDATE ON vault_snapshot_entries
            WHEN (SELECT published_at FROM vault_snapshots
                  WHERE snapshot_id = OLD.snapshot_id) IS NOT NULL
                 OR (SELECT published_at FROM vault_snapshots
                     WHERE snapshot_id = NEW.snapshot_id) IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'published vault snapshot entries are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS published_snapshot_entry_delete_guard
            BEFORE DELETE ON vault_snapshot_entries
            WHEN (SELECT published_at FROM vault_snapshots
                  WHERE snapshot_id = OLD.snapshot_id) IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'published vault snapshot entries are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS published_snapshot_locator_insert_guard
            BEFORE INSERT ON vault_snapshot_locators
            WHEN (SELECT published_at FROM vault_snapshots
                  WHERE snapshot_id = NEW.snapshot_id) IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'published vault snapshot locators are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS published_snapshot_locator_update_guard
            BEFORE UPDATE ON vault_snapshot_locators
            WHEN (SELECT published_at FROM vault_snapshots
                  WHERE snapshot_id = OLD.snapshot_id) IS NOT NULL
                 OR (SELECT published_at FROM vault_snapshots
                     WHERE snapshot_id = NEW.snapshot_id) IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'published vault snapshot locators are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS published_snapshot_locator_delete_guard
            BEFORE DELETE ON vault_snapshot_locators
            WHEN (SELECT published_at FROM vault_snapshots
                  WHERE snapshot_id = OLD.snapshot_id) IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'published vault snapshot locators are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS snapshot_publication_completeness_guard
            BEFORE UPDATE OF published_at ON vault_snapshots
            WHEN OLD.published_at IS NULL AND NEW.published_at IS NOT NULL
                 AND (
                     (SELECT COUNT(*) FROM vault_snapshot_entries
                      WHERE snapshot_id = NEW.snapshot_id) != NEW.source_count
                     OR (
                         NEW.source_count > 0
                         AND (
                             (SELECT MIN(ordinal) FROM vault_snapshot_entries
                              WHERE snapshot_id = NEW.snapshot_id) != 0
                             OR (SELECT MAX(ordinal) FROM vault_snapshot_entries
                                 WHERE snapshot_id = NEW.snapshot_id)
                                != NEW.source_count - 1
                         )
                     )
                     OR COALESCE(
                         (SELECT SUM(v.size_bytes)
                          FROM vault_snapshot_entries AS e
                          JOIN document_versions AS v ON v.source_id = e.source_id
                          WHERE e.snapshot_id = NEW.snapshot_id),
                         0
                     ) != NEW.total_bytes
                 )
            BEGIN
                SELECT RAISE(ABORT, 'vault snapshot publication is incomplete');
            END
            """,
        )
        for statement in statements:
            self._connection.execute(statement)

    def _migrate_v2_schema(self) -> None:
        """Add durable presence and immutable snapshots to every v2 document."""

        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                ALTER TABLE documents
                ADD COLUMN presence_state TEXT NOT NULL DEFAULT 'present'
                    CHECK(presence_state IN ('present', 'tombstoned'))
                """
            )
            self._connection.execute(
                "ALTER TABLE documents ADD COLUMN tombstoned_at TEXT"
            )
            self._create_v3_tables()
            self._require_foreign_key_integrity()
            self._connection.execute(f"PRAGMA user_version = {VAULT_SCHEMA_VERSION}")
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    @staticmethod
    def _logical_document_id(subject_id: str, root_id: str, relative_path: str) -> str:
        material = "\0".join((subject_id, root_id, relative_path))
        return "doc_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

    def _migrate_v1_schema(self) -> None:
        """Migrate the original one-row-per-path schema without losing data.

        Version 1 used a content-derived ``source_id`` as the primary key while
        also making the logical path unique. Re-indexing changed bytes at the
        same path therefore attempted to insert a new primary key and collided
        with the path constraint. The migration makes the path-addressed
        document stable and preserves the old row as content version 1.
        """

        locator_columns = self._table_columns("provenance_locators")
        self._connection.commit()
        self._connection.execute("PRAGMA foreign_keys = OFF")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            if locator_columns:
                self._connection.execute(
                    "ALTER TABLE provenance_locators RENAME TO provenance_locators_v1"
                )
            self._connection.execute("ALTER TABLE documents RENAME TO documents_v1")
            # Renamed tables retain their indexes, including their names.
            self._connection.execute("DROP INDEX IF EXISTS documents_subject_idx")
            self._connection.execute("DROP INDEX IF EXISTS provenance_source_idx")
            self._create_v2_tables()

            rows = self._connection.execute(
                """
                SELECT source_id, subject_id, absolute_path, root_id, relative_path,
                       sha256, size_bytes, mtime_ns, media_type, indexed_at
                FROM documents_v1
                ORDER BY subject_id, root_id, relative_path, source_id
                """
            ).fetchall()
            for row in rows:
                document_id = self._logical_document_id(
                    row["subject_id"], row["root_id"], row["relative_path"]
                )
                self._connection.execute(
                    """
                    INSERT INTO documents(
                        document_id, subject_id, absolute_path, root_id, relative_path,
                        current_source_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        document_id,
                        row["subject_id"],
                        row["absolute_path"],
                        row["root_id"],
                        row["relative_path"],
                        row["source_id"],
                        row["indexed_at"],
                        row["indexed_at"],
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO document_versions(
                        source_id, document_id, version_number, sha256, size_bytes,
                        mtime_ns, media_type, indexed_at
                    ) VALUES (?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["source_id"],
                        document_id,
                        row["sha256"],
                        row["size_bytes"],
                        row["mtime_ns"],
                        row["media_type"],
                        row["indexed_at"],
                    ),
                )

            if locator_columns:
                self._connection.execute(
                    """
                    INSERT INTO provenance_locators(
                        locator_id, source_id, page, bbox_x0, bbox_y0, bbox_x1,
                        bbox_y1, line_start, line_end, char_start, char_end
                    )
                    SELECT locator_id, source_id, page, bbox_x0, bbox_y0, bbox_x1,
                           bbox_y1, line_start, line_end, char_start, char_end
                    FROM provenance_locators_v1
                    ORDER BY locator_id
                    """
                )
                self._connection.execute("DROP TABLE provenance_locators_v1")
            self._connection.execute("DROP TABLE documents_v1")
            self._require_foreign_key_integrity()
            self._connection.execute("PRAGMA user_version = 2")
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            self._connection.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "VaultIndex":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def register_subject(self, local_patient_key: str) -> str:
        subject_id = self.pseudonymizer.subject_id(local_patient_key)
        self._require_safe_database_link()
        self._connection.execute(
            "INSERT OR IGNORE INTO subjects(subject_id, created_at) VALUES (?, ?)",
            (subject_id, _utc_now()),
        )
        self._connection.commit()
        return subject_id

    def _require_subject(self, subject_id: str) -> None:
        row = self._connection.execute(
            "SELECT 1 FROM subjects WHERE subject_id = ?",
            (subject_id,),
        ).fetchone()
        if row is None:
            raise UnknownSubjectError(subject_id)

    def _resolve_source(self, source_path: str | Path) -> tuple[AllowedRoot, Path, str]:
        requested = Path(source_path).expanduser()
        if requested.is_symlink():
            raise SourceOutsideVaultError("symbolic-link sources are not accepted")
        try:
            resolved = requested.resolve(strict=True)
        except FileNotFoundError as error:
            raise SourceOutsideVaultError("source does not exist") from None
        if not resolved.is_file():
            raise SourceOutsideVaultError("source is not a regular file")

        matches = [
            root for root in self.roots.values()
            if self._is_relative_to(resolved, root.path)
        ]
        if len(matches) != 1:
            raise SourceOutsideVaultError(
                "source must resolve under exactly one allowlisted root"
            )
        root = matches[0]
        return root, resolved, resolved.relative_to(root.path).as_posix()

    def _prepare_source(
        self,
        subject_id: str,
        source_path: str | Path,
    ) -> _PreparedSource:
        root, resolved, relative_path = self._resolve_source(source_path)
        owner = self._connection.execute(
            "SELECT subject_id FROM documents WHERE absolute_path = ?",
            (str(resolved),),
        ).fetchone()
        if owner is not None and owner["subject_id"] != subject_id:
            raise CrossSubjectDocumentError(
                f"source path is already assigned to {owner['subject_id']}"
            )
        state, digest = _hash_root_file(root.path, relative_path)
        return _PreparedSource(
            root=root,
            resolved=resolved,
            relative_path=relative_path,
            state=state,
            sha256=digest,
            media_type=(
                mimetypes.guess_type(resolved.name)[0]
                or "application/octet-stream"
            ),
        )

    def _upsert_prepared(
        self,
        subject_id: str,
        prepared: _PreparedSource,
        *,
        indexed_at: str,
        locations: tuple[LocationHint, ...] = (),
        replace_locations: bool,
    ) -> str:
        """Upsert one already hashed source inside the caller's transaction."""

        owner = self._connection.execute(
            "SELECT subject_id FROM documents WHERE absolute_path = ?",
            (str(prepared.resolved),),
        ).fetchone()
        if owner is not None and owner["subject_id"] != subject_id:
            raise CrossSubjectDocumentError(
                f"source path is already assigned to {owner['subject_id']}"
            )

        document_id = self._logical_document_id(
            subject_id,
            prepared.root.root_id,
            prepared.relative_path,
        )
        id_material = "\0".join(
            (
                subject_id,
                prepared.root.root_id,
                prepared.relative_path,
                prepared.sha256,
            )
        )
        source_id = (
            "src_"
            + hashlib.sha256(id_material.encode("utf-8")).hexdigest()[:32]
        )
        logical = self._connection.execute(
            """
            SELECT document_id, current_source_id, presence_state
            FROM documents
            WHERE subject_id = ? AND root_id = ? AND relative_path = ?
            """,
            (subject_id, prepared.root.root_id, prepared.relative_path),
        ).fetchone()
        known_version = self._connection.execute(
            """
            SELECT source_id, document_id, sha256
            FROM document_versions
            WHERE source_id = ?
            """,
            (source_id,),
        ).fetchone()

        if logical is None:
            if known_version is not None:
                raise sqlite3.IntegrityError("content-version identifier collision")
            self._connection.execute(
                """
                INSERT INTO documents(
                    document_id, subject_id, absolute_path, root_id, relative_path,
                    current_source_id, created_at, updated_at, presence_state,
                    tombstoned_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'present', NULL)
                """,
                (
                    document_id,
                    subject_id,
                    str(prepared.resolved),
                    prepared.root.root_id,
                    prepared.relative_path,
                    source_id,
                    indexed_at,
                    indexed_at,
                ),
            )
            self._connection.execute(
                """
                INSERT INTO document_versions(
                    source_id, document_id, version_number, sha256, size_bytes,
                    mtime_ns, media_type, indexed_at
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    source_id,
                    document_id,
                    prepared.sha256,
                    prepared.state.st_size,
                    prepared.state.st_mtime_ns,
                    prepared.media_type,
                    indexed_at,
                ),
            )
        else:
            if logical["document_id"] != document_id:
                raise sqlite3.IntegrityError("logical document identity mismatch")
            current = self._connection.execute(
                """
                SELECT source_id, sha256
                FROM document_versions
                WHERE source_id = ? AND document_id = ?
                """,
                (logical["current_source_id"], document_id),
            ).fetchone()
            if current is None:
                raise sqlite3.IntegrityError("current document version is missing")

            if current["sha256"] == prepared.sha256:
                if current["source_id"] != source_id:
                    raise sqlite3.IntegrityError(
                        "content-version identifier does not match current bytes"
                    )
            else:
                if known_version is None:
                    next_version = self._connection.execute(
                        """
                        SELECT COALESCE(MAX(version_number), 0) + 1
                        FROM document_versions
                        WHERE document_id = ?
                        """,
                        (document_id,),
                    ).fetchone()[0]
                    self._connection.execute(
                        """
                        INSERT INTO document_versions(
                            source_id, document_id, version_number, sha256,
                            size_bytes, mtime_ns, media_type, indexed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            source_id,
                            document_id,
                            next_version,
                            prepared.sha256,
                            prepared.state.st_size,
                            prepared.state.st_mtime_ns,
                            prepared.media_type,
                            indexed_at,
                        ),
                    )
                elif (
                    known_version["document_id"] != document_id
                    or known_version["sha256"] != prepared.sha256
                ):
                    raise sqlite3.IntegrityError("content-version identifier collision")

            if (
                logical["current_source_id"] != source_id
                or logical["presence_state"] != "present"
            ):
                self._connection.execute(
                    """
                    UPDATE documents
                    SET current_source_id = ?, absolute_path = ?, updated_at = ?,
                        presence_state = 'present', tombstoned_at = NULL
                    WHERE document_id = ?
                    """,
                    (source_id, str(prepared.resolved), indexed_at, document_id),
                )

        if replace_locations:
            self._connection.execute(
                "DELETE FROM provenance_locators WHERE source_id = ?",
                (source_id,),
            )
            for hint in locations:
                bbox = hint.bbox or (None, None, None, None)
                self._connection.execute(
                    """
                    INSERT INTO provenance_locators(
                        source_id, page, bbox_x0, bbox_y0, bbox_x1, bbox_y1,
                        line_start, line_end, char_start, char_end
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_id,
                        hint.page,
                        *bbox,
                        hint.line_start,
                        hint.line_end,
                        hint.char_start,
                        hint.char_end,
                    ),
                )
        return source_id

    def import_file(
        self,
        subject_id: str,
        source_path: str | Path,
        *,
        locations: Iterable[LocationHint] = (),
    ) -> SourceDocument:
        """Index one source, reviving its logical path if it was tombstoned."""

        self._require_subject(subject_id)
        prepared = self._prepare_source(subject_id, source_path)
        hints = tuple(locations)
        self._require_safe_database_link()
        try:
            with self._connection:
                source_id = self._upsert_prepared(
                    subject_id,
                    prepared,
                    indexed_at=_utc_now(),
                    locations=hints,
                    replace_locations=True,
                )
                self._validate_prepared_source(prepared)
        except sqlite3.IntegrityError:
            owner = self._connection.execute(
                "SELECT subject_id FROM documents WHERE absolute_path = ?",
                (str(prepared.resolved),),
            ).fetchone()
            if owner is not None and owner["subject_id"] != subject_id:
                raise CrossSubjectDocumentError(
                    "source is assigned to another subject"
                ) from None
            raise
        return self.get_document(subject_id, source_id)

    @staticmethod
    def _canonical_suffixes(
        suffixes: Iterable[str] | None,
    ) -> tuple[str, ...] | None:
        if suffixes is None:
            return None
        canonical: set[str] = set()
        for suffix in suffixes:
            if not isinstance(suffix, str) or "\0" in suffix:
                raise ValueError("suffixes must contain text without NUL")
            canonical.add(suffix.casefold())
        return tuple(sorted(canonical))

    def _enumerate_tree(
        self,
        root: AllowedRoot,
        relative_directory: str,
        suffixes: tuple[str, ...] | None,
    ) -> tuple[str, tuple[tuple[Path, os.stat_result], ...]]:
        try:
            base = (root.path / relative_directory).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise SourceOutsideVaultError("source directory is unavailable") from error
        if not self._is_relative_to(base, root.path) or not base.is_dir():
            raise SourceOutsideVaultError(relative_directory)
        scope_path = base.relative_to(root.path)
        scope = "." if not scope_path.parts else scope_path.as_posix()
        allowed_suffixes = None if suffixes is None else set(suffixes)
        entries: list[tuple[Path, os.stat_result]] = []
        total_bytes = 0
        try:
            for path in base.rglob("*"):
                try:
                    state = path.lstat()
                except OSError as error:
                    raise SourceOutsideVaultError(
                        "source tree changed during enumeration"
                    ) from error
                if stat.S_ISLNK(state.st_mode) or stat.S_ISDIR(state.st_mode):
                    continue
                if not stat.S_ISREG(state.st_mode):
                    continue
                if (
                    allowed_suffixes is not None
                    and path.suffix.casefold() not in allowed_suffixes
                ):
                    continue
                if state.st_nlink != 1 or state.st_size > MAX_VAULT_FILE_BYTES:
                    raise SourceOutsideVaultError(
                        "source tree contains an unsafe file"
                    )
                entries.append((path, state))
                total_bytes += state.st_size
                if len(entries) > MAX_VAULT_TREE_FILES:
                    raise SourceOutsideVaultError(
                        "source tree exceeds the file-count indexing limit"
                    )
                if total_bytes > MAX_VAULT_TREE_BYTES:
                    raise SourceOutsideVaultError(
                        "source tree exceeds the total-byte indexing limit"
                    )
        except OSError as error:
            raise SourceOutsideVaultError(
                "source tree changed during enumeration"
            ) from error
        entries.sort(key=lambda item: item[0].relative_to(root.path).as_posix())
        return scope, tuple(entries)

    @staticmethod
    def _stat_identity(state: os.stat_result) -> tuple[int, ...]:
        return (
            state.st_dev,
            state.st_ino,
            state.st_nlink,
            state.st_size,
            state.st_mtime_ns,
            state.st_ctime_ns,
        )

    def _validate_prepared_source(self, prepared: _PreparedSource) -> None:
        """Re-read one prepared source and reject stale metadata before commit."""

        current_state, current_digest = _hash_root_file(
            prepared.root.path,
            prepared.relative_path,
        )
        if (
            self._stat_identity(current_state) != self._stat_identity(prepared.state)
            or current_digest != prepared.sha256
        ):
            raise SourceChangedDuringReadError(
                "source changed before indexed metadata was committed"
            )

    def _validate_prepared_tree(
        self,
        root: AllowedRoot,
        relative_directory: str,
        suffixes: tuple[str, ...] | None,
        prepared: tuple[_PreparedSource, ...],
    ) -> None:
        """Reject publication when the enumerated tree changed before commit."""

        _, current = self._enumerate_tree(root, relative_directory, suffixes)
        expected_paths = tuple(item.relative_path for item in prepared)
        current_paths = tuple(
            path.relative_to(root.path).as_posix() for path, _ in current
        )
        if current_paths != expected_paths:
            raise SourceChangedDuringReadError(
                "source tree changed before snapshot publication"
            )
        states = {
            path.relative_to(root.path).as_posix(): state for path, state in current
        }
        if any(
            self._stat_identity(states[item.relative_path])
            != self._stat_identity(item.state)
            for item in prepared
        ):
            raise SourceChangedDuringReadError(
                "source tree changed before snapshot publication"
            )

    @staticmethod
    def _path_is_in_scope(relative_path: str, scope: str) -> bool:
        return scope == "." or relative_path.startswith(scope + "/")

    @staticmethod
    def _path_matches_suffixes(
        relative_path: str,
        suffixes: tuple[str, ...] | None,
    ) -> bool:
        return suffixes is None or Path(relative_path).suffix.casefold() in suffixes

    def _tombstone_missing(
        self,
        subject_id: str,
        root_id: str,
        *,
        scope: str,
        suffixes: tuple[str, ...] | None,
        present_paths: frozenset[str],
        tombstoned_at: str,
    ) -> None:
        rows = self._connection.execute(
            """
            SELECT document_id, relative_path
            FROM documents
            WHERE subject_id = ? AND root_id = ? AND presence_state = 'present'
            ORDER BY relative_path, document_id
            """,
            (subject_id, root_id),
        ).fetchall()
        missing_ids = tuple(
            row["document_id"]
            for row in rows
            if self._path_is_in_scope(row["relative_path"], scope)
            and self._path_matches_suffixes(row["relative_path"], suffixes)
            and row["relative_path"] not in present_paths
        )
        self._connection.executemany(
            """
            UPDATE documents
            SET presence_state = 'tombstoned', tombstoned_at = ?, updated_at = ?
            WHERE document_id = ?
            """,
            ((tombstoned_at, tombstoned_at, document_id) for document_id in missing_ids),
        )

    @staticmethod
    def _snapshot_identifier(
        subject_id: str,
        root_id: str,
        scope: str,
        suffixes: tuple[str, ...] | None,
        entries: tuple[tuple[str, str], ...],
        locator_sets: tuple[tuple[tuple[int | float | None, ...], ...], ...],
    ) -> str:
        payload = {
            "schema": "health-analyzer/vault-snapshot/v2",
            "subject_id": subject_id,
            "root_id": root_id,
            "relative_directory": scope,
            "suffixes": None if suffixes is None else list(suffixes),
            "entries": [
                {
                    "relative_path": relative_path,
                    "source_id": source_id,
                    "locators": [list(locator) for locator in locators],
                }
                for (relative_path, source_id), locators in zip(
                    entries, locator_sets, strict=True
                )
            ],
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return "vsnap_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _publish_snapshot(
        self,
        subject_id: str,
        root_id: str,
        *,
        scope: str,
        suffixes: tuple[str, ...] | None,
        entries: tuple[tuple[str, str], ...],
        created_at: str,
        total_bytes: int,
    ) -> str:
        source_ids = tuple(source_id for _, source_id in entries)
        locator_sets = tuple(
            tuple(
                (
                    row["page"],
                    row["bbox_x0"],
                    row["bbox_y0"],
                    row["bbox_x1"],
                    row["bbox_y1"],
                    row["line_start"],
                    row["line_end"],
                    row["char_start"],
                    row["char_end"],
                )
                for row in self._connection.execute(
                    """
                    SELECT page, bbox_x0, bbox_y0, bbox_x1, bbox_y1,
                           line_start, line_end, char_start, char_end
                    FROM provenance_locators
                    WHERE source_id = ?
                    ORDER BY locator_id
                    """,
                    (source_id,),
                ).fetchall()
            )
            for source_id in source_ids
        )
        snapshot_id = self._snapshot_identifier(
            subject_id, root_id, scope, suffixes, entries, locator_sets
        )
        existing = self._connection.execute(
            """
            SELECT subject_id, root_id, relative_directory, suffixes_json,
                   published_at, source_count, total_bytes
            FROM vault_snapshots WHERE snapshot_id = ?
            """,
            (snapshot_id,),
        ).fetchone()
        suffixes_json = json.dumps(
            None if suffixes is None else list(suffixes),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        if existing is not None:
            persisted_ids = tuple(
                row["source_id"]
                for row in self._connection.execute(
                    """
                    SELECT source_id FROM vault_snapshot_entries
                    WHERE snapshot_id = ? ORDER BY ordinal
                    """,
                    (snapshot_id,),
                ).fetchall()
            )
            persisted_locators = tuple(
                (
                    row["entry_ordinal"],
                    row["locator_ordinal"],
                    row["page"],
                    row["bbox_x0"],
                    row["bbox_y0"],
                    row["bbox_x1"],
                    row["bbox_y1"],
                    row["line_start"],
                    row["line_end"],
                    row["char_start"],
                    row["char_end"],
                )
                for row in self._connection.execute(
                    """
                    SELECT entry_ordinal, locator_ordinal, page,
                           bbox_x0, bbox_y0, bbox_x1, bbox_y1,
                           line_start, line_end, char_start, char_end
                    FROM vault_snapshot_locators
                    WHERE snapshot_id = ?
                    ORDER BY entry_ordinal, locator_ordinal
                    """,
                    (snapshot_id,),
                ).fetchall()
            )
            expected_locators = tuple(
                (entry_ordinal, locator_ordinal, *locator)
                for entry_ordinal, locators in enumerate(locator_sets)
                for locator_ordinal, locator in enumerate(locators)
            )
            if (
                existing["published_at"] is None
                or existing["subject_id"] != subject_id
                or existing["root_id"] != root_id
                or existing["relative_directory"] != scope
                or existing["suffixes_json"] != suffixes_json
                or existing["source_count"] != len(entries)
                or existing["total_bytes"] != total_bytes
                or persisted_ids != source_ids
                or persisted_locators != expected_locators
            ):
                raise sqlite3.IntegrityError("vault snapshot identifier collision")
            return snapshot_id

        self._connection.execute(
            """
            INSERT INTO vault_snapshots(
                snapshot_id, subject_id, root_id, relative_directory,
                suffixes_json, created_at, published_at, source_count, total_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                snapshot_id,
                subject_id,
                root_id,
                scope,
                suffixes_json,
                created_at,
                len(entries),
                total_bytes,
            ),
        )
        self._connection.executemany(
            """
            INSERT INTO vault_snapshot_entries(snapshot_id, ordinal, source_id)
            VALUES (?, ?, ?)
            """,
            (
                (snapshot_id, ordinal, source_id)
                for ordinal, source_id in enumerate(source_ids)
            ),
        )
        for entry_ordinal, locators in enumerate(locator_sets):
            self._connection.executemany(
                """
                INSERT INTO vault_snapshot_locators(
                    snapshot_id, entry_ordinal, locator_ordinal, page,
                    bbox_x0, bbox_y0, bbox_x1, bbox_y1, line_start, line_end,
                    char_start, char_end
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        snapshot_id,
                        entry_ordinal,
                        locator_ordinal,
                        *locator,
                    )
                    for locator_ordinal, locator in enumerate(locators)
                ),
            )
        self._connection.execute(
            """
            UPDATE vault_snapshots SET published_at = ?
            WHERE snapshot_id = ? AND published_at IS NULL
            """,
            (created_at, snapshot_id),
        )
        return snapshot_id

    def sync_tree(
        self,
        subject_id: str,
        root_id: str,
        *,
        relative_directory: str = ".",
        suffixes: Iterable[str] | None = None,
    ) -> VaultSnapshot:
        """Atomically reconcile one tree and publish its immutable snapshot.

        Hashing and stability checks complete before any document, tombstone, or
        snapshot row becomes visible. Source roots are only opened read-only.
        """

        self._require_subject(subject_id)
        root = self.roots[root_id]
        canonical_suffixes = self._canonical_suffixes(suffixes)
        scope, enumerated = self._enumerate_tree(
            root, relative_directory, canonical_suffixes
        )
        prepared = tuple(
            self._prepare_source(subject_id, path) for path, _ in enumerated
        )
        if any(item.root.root_id != root_id for item in prepared):
            raise SourceOutsideVaultError("source resolved outside the selected root")
        indexed_at = _utc_now()
        self._require_safe_database_link()

        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._validate_prepared_tree(
                root, relative_directory, canonical_suffixes, prepared
            )
            source_ids = tuple(
                self._upsert_prepared(
                    subject_id,
                    item,
                    indexed_at=indexed_at,
                    replace_locations=False,
                )
                for item in prepared
            )
            present_paths = frozenset(item.relative_path for item in prepared)
            self._tombstone_missing(
                subject_id,
                root_id,
                scope=scope,
                suffixes=canonical_suffixes,
                present_paths=present_paths,
                tombstoned_at=indexed_at,
            )
            entries = tuple(
                (item.relative_path, source_id)
                for item, source_id in zip(prepared, source_ids, strict=True)
            )
            snapshot_id = self._publish_snapshot(
                subject_id,
                root_id,
                scope=scope,
                suffixes=canonical_suffixes,
                entries=entries,
                created_at=indexed_at,
                total_bytes=sum(item.state.st_size for item in prepared),
            )
            self._validate_prepared_tree(
                root, relative_directory, canonical_suffixes, prepared
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        return self.get_snapshot(subject_id, snapshot_id)

    def import_tree(
        self,
        subject_id: str,
        root_id: str,
        *,
        relative_directory: str = ".",
        suffixes: Iterable[str] | None = None,
    ) -> tuple[SourceDocument, ...]:
        """Reconcile a tree and return the exact published snapshot contents."""

        snapshot = self.sync_tree(
            subject_id,
            root_id,
            relative_directory=relative_directory,
            suffixes=suffixes,
        )
        return self._snapshot_documents(subject_id, snapshot.snapshot_id)

    def _locators_for(self, source_id: str, sha256: str) -> tuple[ProvenanceLocator, ...]:
        rows = self._connection.execute(
            """
            SELECT page, bbox_x0, bbox_y0, bbox_x1, bbox_y1,
                   line_start, line_end, char_start, char_end
            FROM provenance_locators
            WHERE source_id = ?
            ORDER BY locator_id
            """,
            (source_id,),
        ).fetchall()
        locators: list[ProvenanceLocator] = []
        for row in rows:
            bbox_values = (row["bbox_x0"], row["bbox_y0"], row["bbox_x1"], row["bbox_y1"])
            bbox = None if all(value is None for value in bbox_values) else bbox_values
            locators.append(
                ProvenanceLocator(
                    source_id=source_id,
                    sha256=sha256,
                    page=row["page"],
                    bbox=bbox,
                    line_start=row["line_start"],
                    line_end=row["line_end"],
                    char_start=row["char_start"],
                    char_end=row["char_end"],
                )
            )
        return tuple(locators)

    def _snapshot_locators_for(
        self,
        snapshot_id: str,
        entry_ordinal: int,
        source_id: str,
        sha256: str,
    ) -> tuple[ProvenanceLocator, ...]:
        rows = self._connection.execute(
            """
            SELECT page, bbox_x0, bbox_y0, bbox_x1, bbox_y1,
                   line_start, line_end, char_start, char_end
            FROM vault_snapshot_locators
            WHERE snapshot_id = ? AND entry_ordinal = ?
            ORDER BY locator_ordinal
            """,
            (snapshot_id, entry_ordinal),
        ).fetchall()
        locators: list[ProvenanceLocator] = []
        for row in rows:
            bbox_values = (
                row["bbox_x0"],
                row["bbox_y0"],
                row["bbox_x1"],
                row["bbox_y1"],
            )
            bbox = None if all(value is None for value in bbox_values) else bbox_values
            locators.append(
                ProvenanceLocator(
                    source_id=source_id,
                    sha256=sha256,
                    page=row["page"],
                    bbox=bbox,
                    line_start=row["line_start"],
                    line_end=row["line_end"],
                    char_start=row["char_start"],
                    char_end=row["char_end"],
                )
            )
        return tuple(locators)

    def _row_to_document(
        self,
        row: sqlite3.Row,
        *,
        provenance: tuple[ProvenanceLocator, ...] | None = None,
    ) -> SourceDocument:
        return SourceDocument(
            source_id=row["source_id"],
            subject_id=row["subject_id"],
            root_id=row["root_id"],
            relative_path=row["relative_path"],
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            mtime_ns=row["mtime_ns"],
            media_type=row["media_type"],
            indexed_at=row["indexed_at"],
            provenance=(
                self._locators_for(row["source_id"], row["sha256"])
                if provenance is None
                else provenance
            ),
        )

    def get_document(self, subject_id: str, source_id: str) -> SourceDocument:
        self._require_subject(subject_id)
        row = self._connection.execute(
            """
            SELECT v.source_id, d.subject_id, d.root_id, d.relative_path,
                   v.sha256, v.size_bytes, v.mtime_ns, v.media_type, v.indexed_at
            FROM document_versions AS v
            JOIN documents AS d ON d.document_id = v.document_id
            WHERE d.subject_id = ? AND v.source_id = ?
            """,
            (subject_id, source_id),
        ).fetchone()
        if row is None:
            raise KeyError(source_id)
        return self._row_to_document(row)

    def list_document_versions(
        self,
        subject_id: str,
        source_id: str,
    ) -> tuple[SourceDocument, ...]:
        """Return every retained content version for a source's logical path.

        ``source_id`` may identify either the current version or an older one.
        The existing ``list_documents`` API intentionally remains a current
        manifest view so callers do not process superseded bytes twice.
        """

        self._require_subject(subject_id)
        row = self._connection.execute(
            """
            SELECT v.document_id
            FROM document_versions AS v
            JOIN documents AS d ON d.document_id = v.document_id
            WHERE d.subject_id = ? AND v.source_id = ?
            """,
            (subject_id, source_id),
        ).fetchone()
        if row is None:
            raise KeyError(source_id)
        rows = self._connection.execute(
            """
            SELECT v.source_id, d.subject_id, d.root_id, d.relative_path,
                   v.sha256, v.size_bytes, v.mtime_ns, v.media_type, v.indexed_at
            FROM document_versions AS v
            JOIN documents AS d ON d.document_id = v.document_id
            WHERE v.document_id = ?
            ORDER BY v.version_number
            """,
            (row["document_id"],),
        ).fetchall()
        return tuple(self._row_to_document(item) for item in rows)

    @staticmethod
    def _row_to_document_state(row: sqlite3.Row) -> VaultDocumentState:
        return VaultDocumentState(
            document_id=row["document_id"],
            subject_id=row["subject_id"],
            root_id=row["root_id"],
            relative_path=row["relative_path"],
            current_source_id=row["current_source_id"],
            presence_state=row["presence_state"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            tombstoned_at=row["tombstoned_at"],
        )

    def get_document_state(
        self,
        subject_id: str,
        source_id: str,
    ) -> VaultDocumentState:
        """Return presence state for the logical document owning a version."""

        self._require_subject(subject_id)
        row = self._connection.execute(
            """
            SELECT d.document_id, d.subject_id, d.root_id, d.relative_path,
                   d.current_source_id, d.presence_state, d.created_at,
                   d.updated_at, d.tombstoned_at
            FROM documents AS d
            JOIN document_versions AS v ON v.document_id = d.document_id
            WHERE d.subject_id = ? AND v.source_id = ?
            """,
            (subject_id, source_id),
        ).fetchone()
        if row is None:
            raise KeyError(source_id)
        return self._row_to_document_state(row)

    def list_document_states(
        self,
        subject_id: str,
        *,
        root_id: str | None = None,
        presence_state: str | None = None,
    ) -> tuple[VaultDocumentState, ...]:
        """List present and/or tombstoned logical paths for one subject."""

        self._require_subject(subject_id)
        if presence_state not in {None, "present", "tombstoned"}:
            raise ValueError("presence_state must be present, tombstoned, or None")
        conditions = ["subject_id = ?"]
        parameters: list[object] = [subject_id]
        if root_id is not None:
            conditions.append("root_id = ?")
            parameters.append(root_id)
        if presence_state is not None:
            conditions.append("presence_state = ?")
            parameters.append(presence_state)
        rows = self._connection.execute(
            """
            SELECT document_id, subject_id, root_id, relative_path,
                   current_source_id, presence_state, created_at, updated_at,
                   tombstoned_at
            FROM documents
            WHERE """
            + " AND ".join(conditions)
            + " ORDER BY root_id, relative_path, document_id",
            tuple(parameters),
        ).fetchall()
        return tuple(self._row_to_document_state(row) for row in rows)

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> VaultSnapshot:
        try:
            suffixes_value = json.loads(row["suffixes_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise sqlite3.IntegrityError(
                "vault snapshot suffix metadata is invalid"
            ) from error
        if suffixes_value is not None and (
            not isinstance(suffixes_value, list)
            or any(not isinstance(value, str) for value in suffixes_value)
        ):
            raise sqlite3.IntegrityError("vault snapshot suffix metadata is invalid")
        if row["published_at"] is None:
            raise sqlite3.IntegrityError("vault snapshot is not completely published")
        return VaultSnapshot(
            snapshot_id=row["snapshot_id"],
            subject_id=row["subject_id"],
            root_id=row["root_id"],
            relative_directory=row["relative_directory"],
            suffixes=(
                None if suffixes_value is None else tuple(suffixes_value)
            ),
            created_at=row["created_at"],
            published_at=row["published_at"],
            source_count=row["source_count"],
            total_bytes=row["total_bytes"],
        )

    def get_snapshot(self, subject_id: str, snapshot_id: str) -> VaultSnapshot:
        """Load metadata for one fully published subject-bound snapshot."""

        self._require_subject(subject_id)
        row = self._connection.execute(
            """
            SELECT snapshot_id, subject_id, root_id, relative_directory,
                   suffixes_json, created_at, published_at, source_count,
                   total_bytes
            FROM vault_snapshots
            WHERE subject_id = ? AND snapshot_id = ? AND published_at IS NOT NULL
            """,
            (subject_id, snapshot_id),
        ).fetchone()
        if row is None:
            raise KeyError(snapshot_id)
        return self._row_to_snapshot(row)

    def list_snapshots(
        self,
        subject_id: str,
        *,
        root_id: str | None = None,
    ) -> tuple[VaultSnapshot, ...]:
        """List only completely published snapshots for one subject."""

        self._require_subject(subject_id)
        if root_id is None:
            rows = self._connection.execute(
                """
                SELECT snapshot_id, subject_id, root_id, relative_directory,
                       suffixes_json, created_at, published_at, source_count,
                       total_bytes
                FROM vault_snapshots
                WHERE subject_id = ? AND published_at IS NOT NULL
                ORDER BY created_at, snapshot_id
                """,
                (subject_id,),
            ).fetchall()
        else:
            rows = self._connection.execute(
                """
                SELECT snapshot_id, subject_id, root_id, relative_directory,
                       suffixes_json, created_at, published_at, source_count,
                       total_bytes
                FROM vault_snapshots
                WHERE subject_id = ? AND root_id = ?
                      AND published_at IS NOT NULL
                ORDER BY created_at, snapshot_id
                """,
                (subject_id, root_id),
            ).fetchall()
        return tuple(self._row_to_snapshot(row) for row in rows)

    def _snapshot_documents(
        self,
        subject_id: str,
        snapshot_id: str,
    ) -> tuple[SourceDocument, ...]:
        self.get_snapshot(subject_id, snapshot_id)
        rows = self._connection.execute(
            """
            SELECT e.ordinal AS snapshot_ordinal,
                   v.source_id, d.subject_id, d.root_id, d.relative_path,
                   v.sha256, v.size_bytes, v.mtime_ns, v.media_type, v.indexed_at
            FROM vault_snapshot_entries AS e
            JOIN document_versions AS v ON v.source_id = e.source_id
            JOIN documents AS d ON d.document_id = v.document_id
            WHERE e.snapshot_id = ?
            ORDER BY e.ordinal
            """,
            (snapshot_id,),
        ).fetchall()
        return tuple(
            self._row_to_document(
                row,
                provenance=self._snapshot_locators_for(
                    snapshot_id,
                    row["snapshot_ordinal"],
                    row["source_id"],
                    row["sha256"],
                ),
            )
            for row in rows
        )

    def _encode_snapshot_cursor(
        self,
        subject_id: str,
        snapshot_id: str,
        offset: int,
    ) -> str:
        body = json.dumps(
            {
                "schema": "health-analyzer/vault-snapshot-cursor/v1",
                "subject_id": subject_id,
                "snapshot_id": snapshot_id,
                "offset": offset,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = hmac.new(
            self.pseudonymizer.secret,
            b"health-analyzer/vault-snapshot-cursor/v1\0" + body,
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(body + signature).decode("ascii").rstrip("=")

    def _decode_snapshot_cursor(
        self,
        cursor: str,
        *,
        subject_id: str,
        snapshot_id: str,
    ) -> int:
        if not isinstance(cursor, str) or not cursor:
            raise ValueError("snapshot cursor must be non-empty text")
        if len(cursor) > MAX_SNAPSHOT_CURSOR_CHARS:
            raise ValueError("snapshot cursor exceeds the size limit")
        try:
            padding = "=" * (-len(cursor) % 4)
            decoded = base64.b64decode(
                cursor + padding,
                altchars=b"-_",
                validate=True,
            )
            if len(decoded) <= hashlib.sha256().digest_size:
                raise ValueError
            body = decoded[:-hashlib.sha256().digest_size]
            signature = decoded[-hashlib.sha256().digest_size :]
            expected = hmac.new(
                self.pseudonymizer.secret,
                b"health-analyzer/vault-snapshot-cursor/v1\0" + body,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            payload = json.loads(body)
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            raise ValueError("snapshot cursor is invalid") from error
        if (
            not isinstance(payload, dict)
            or payload.get("schema")
            != "health-analyzer/vault-snapshot-cursor/v1"
            or payload.get("subject_id") != subject_id
            or payload.get("snapshot_id") != snapshot_id
            or not isinstance(payload.get("offset"), int)
            or isinstance(payload.get("offset"), bool)
            or payload["offset"] < 0
        ):
            raise ValueError("snapshot cursor does not match the requested snapshot")
        return payload["offset"]

    def load_snapshot_page(
        self,
        subject_id: str,
        snapshot_id: str,
        *,
        cursor: str | None = None,
        limit: int = 100,
    ) -> VaultSnapshotPage:
        """Read an immutable snapshot page, never a page of the live tree."""

        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > MAX_SNAPSHOT_PAGE_SIZE
        ):
            raise ValueError(
                f"limit must be between 1 and {MAX_SNAPSHOT_PAGE_SIZE}"
            )
        snapshot = self.get_snapshot(subject_id, snapshot_id)
        offset = (
            0
            if cursor is None
            else self._decode_snapshot_cursor(
                cursor,
                subject_id=subject_id,
                snapshot_id=snapshot_id,
            )
        )
        if offset > snapshot.source_count:
            raise ValueError("snapshot cursor offset is outside the snapshot")
        rows = self._connection.execute(
            """
            SELECT e.ordinal AS snapshot_ordinal,
                   v.source_id, d.subject_id, d.root_id, d.relative_path,
                   v.sha256, v.size_bytes, v.mtime_ns, v.media_type, v.indexed_at
            FROM vault_snapshot_entries AS e
            JOIN document_versions AS v ON v.source_id = e.source_id
            JOIN documents AS d ON d.document_id = v.document_id
            WHERE e.snapshot_id = ? AND e.ordinal >= ?
            ORDER BY e.ordinal
            LIMIT ?
            """,
            (snapshot_id, offset, limit + 1),
        ).fetchall()
        page_rows = rows[:limit]
        documents = tuple(
            self._row_to_document(
                row,
                provenance=self._snapshot_locators_for(
                    snapshot_id,
                    row["snapshot_ordinal"],
                    row["source_id"],
                    row["sha256"],
                ),
            )
            for row in page_rows
        )
        next_cursor = None
        if len(rows) > limit:
            next_cursor = self._encode_snapshot_cursor(
                subject_id,
                snapshot_id,
                offset + len(documents),
            )
        return VaultSnapshotPage(snapshot, documents, next_cursor)

    def list_documents(self, subject_id: str) -> tuple[SourceDocument, ...]:
        self._require_subject(subject_id)
        rows = self._connection.execute(
            """
            SELECT v.source_id, d.subject_id, d.root_id, d.relative_path,
                   v.sha256, v.size_bytes, v.mtime_ns, v.media_type, v.indexed_at
            FROM documents AS d
            JOIN document_versions AS v ON v.source_id = d.current_source_id
            WHERE d.subject_id = ? AND d.presence_state = 'present'
            ORDER BY d.root_id, d.relative_path, v.source_id
            """,
            (subject_id,),
        ).fetchall()
        return tuple(self._row_to_document(row) for row in rows)

    def manifest(self, subject_id: str) -> SubjectManifest:
        return SubjectManifest(subject_id, self.list_documents(subject_id))

    def verify_manifest(self, subject_id: str) -> tuple[VerificationResult, ...]:
        results: list[VerificationResult] = []
        for document in self.list_documents(subject_id):
            root = self.roots.get(document.root_id)
            if root is None:
                results.append(
                    VerificationResult(
                        document.source_id,
                        "unavailable_root",
                        document.sha256,
                        detail=document.root_id,
                    )
                )
                continue
            path = root.path / document.relative_path
            try:
                resolved_root, resolved_path, resolved_relative = self._resolve_source(path)
            except SourceOutsideVaultError:
                results.append(
                    VerificationResult(
                        document.source_id,
                        "unsafe_or_missing",
                        document.sha256,
                    )
                )
                continue
            if (
                resolved_root.root_id != document.root_id
                or resolved_relative != document.relative_path
            ):
                results.append(
                    VerificationResult(
                        document.source_id,
                        "path_changed",
                        document.sha256,
                    )
                )
                continue
            try:
                _, actual = _hash_root_file(resolved_root.path, resolved_relative)
            except (SourceOutsideVaultError, SourceChangedDuringReadError):
                results.append(
                    VerificationResult(
                        document.source_id,
                        "unsafe_or_missing",
                        document.sha256,
                    )
                )
                continue
            results.append(
                VerificationResult(
                    document.source_id,
                    "ok" if actual == document.sha256 else "modified",
                    document.sha256,
                    actual_sha256=actual,
                )
            )
        return tuple(results)
