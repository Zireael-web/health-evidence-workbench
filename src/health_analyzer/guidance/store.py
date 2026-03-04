"""SQLite persistence for immutable guideline versions and recommendations."""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from typing import Self

from .models import (
    GuidanceStatus,
    GuidelineDocument,
    GuidelineRecommendation,
    RecommendationDirection,
    SourceProvenance,
    VersionRelation,
    VersionRelationType,
)

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS guideline_documents (
    document_id TEXT PRIMARY KEY,
    series_id TEXT NOT NULL,
    title TEXT NOT NULL,
    issuer TEXT NOT NULL,
    version TEXT NOT NULL,
    jurisdictions_json TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    published_on TEXT,
    effective_until TEXT,
    withdrawn_on TEXT,
    declared_status TEXT NOT NULL,
    status_changed_on TEXT,
    last_checked_at TEXT,
    document_type TEXT NOT NULL,
    language TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    source_locator TEXT,
    publisher_document_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_guideline_documents_series
    ON guideline_documents(series_id, effective_from);

CREATE TABLE IF NOT EXISTS version_relations (
    source_document_id TEXT NOT NULL,
    target_document_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    affected_keys_json TEXT NOT NULL,
    provenance_note TEXT,
    PRIMARY KEY (source_document_id, target_document_id, relation_type),
    FOREIGN KEY (source_document_id) REFERENCES guideline_documents(document_id),
    FOREIGN KEY (target_document_id) REFERENCES guideline_documents(document_id)
);

CREATE INDEX IF NOT EXISTS idx_version_relations_target
    ON version_relations(target_document_id, effective_from);

CREATE TABLE IF NOT EXISTS guideline_recommendations (
    recommendation_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    recommendation_key TEXT NOT NULL,
    decision_key TEXT NOT NULL,
    population_key TEXT NOT NULL,
    verbatim_text TEXT NOT NULL,
    native_grade_system TEXT NOT NULL,
    native_grade TEXT NOT NULL,
    native_strength TEXT,
    native_certainty TEXT,
    direction TEXT NOT NULL,
    position_key TEXT,
    applies_from TEXT,
    applies_until TEXT,
    jurisdictions_json TEXT NOT NULL,
    topic TEXT,
    metadata_json TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    source_locator TEXT,
    publisher_document_id TEXT,
    FOREIGN KEY (document_id) REFERENCES guideline_documents(document_id)
);

CREATE INDEX IF NOT EXISTS idx_guideline_recommendations_document
    ON guideline_recommendations(document_id, recommendation_key);

CREATE INDEX IF NOT EXISTS idx_guideline_recommendations_decision
    ON guideline_recommendations(decision_key, population_key);

CREATE TABLE IF NOT EXISTS guidance_integrity (
    record_kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    payload_hmac TEXT NOT NULL,
    PRIMARY KEY (record_kind, record_id)
);

CREATE TABLE IF NOT EXISTS guidance_manifest (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    record_count INTEGER NOT NULL CHECK(record_count >= 0),
    manifest_hmac TEXT NOT NULL
);
"""

_DOCUMENT_COLUMNS = (
    "document_id", "series_id", "title", "issuer", "version",
    "jurisdictions_json", "effective_from", "published_on",
    "effective_until", "withdrawn_on", "declared_status",
    "status_changed_on", "last_checked_at", "document_type", "language",
    "metadata_json", "canonical_url", "retrieved_at", "content_sha256",
    "source_locator", "publisher_document_id",
)
_RELATION_COLUMNS = (
    "source_document_id", "target_document_id", "relation_type",
    "effective_from", "affected_keys_json", "provenance_note",
)
_RECOMMENDATION_COLUMNS = (
    "recommendation_id", "document_id", "recommendation_key",
    "decision_key", "population_key", "verbatim_text",
    "native_grade_system", "native_grade", "native_strength",
    "native_certainty", "direction", "position_key", "applies_from",
    "applies_until", "jurisdictions_json", "topic", "metadata_json",
    "canonical_url", "retrieved_at", "content_sha256", "source_locator",
    "publisher_document_id",
)


def _read_integrity_key(descriptor: int) -> bytes:
    state = os.fstat(descriptor)
    if not stat.S_ISREG(state.st_mode) or state.st_nlink != 1 or state.st_size != 32:
        raise ValueError("guidance integrity key must be a singly linked 32-byte file")
    os.lseek(descriptor, 0, os.SEEK_SET)
    key = os.read(descriptor, 33)
    if len(key) != 32:
        raise ValueError("guidance integrity key is incomplete")
    return key


def _load_or_create_integrity_key(database: str, *, readonly: bool) -> bytes:
    if database == ":memory:":
        if readonly:
            raise ValueError("read-only in-memory guidance storage is unsupported")
        return secrets.token_bytes(32)
    path = Path(f"{database}.integrity-v1.key")
    if path.parent.is_symlink():
        raise ValueError("guidance integrity-key parent must not be a symbolic link")
    if not readonly:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
    if not path.parent.is_dir() or path.is_symlink():
        raise ValueError("guidance integrity key path is unavailable or unsafe")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    created = False
    if readonly:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    else:
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                0o400,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        state = os.fstat(descriptor)
        if not stat.S_ISREG(state.st_mode) or state.st_nlink != 1:
            raise ValueError("guidance integrity key must be a singly linked regular file")
        if state.st_size == 0 and created:
            key = secrets.token_bytes(32)
            if os.write(descriptor, key) != len(key):
                raise OSError("guidance integrity key write was incomplete")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            return key
        return _read_integrity_key(descriptor)
    finally:
        os.close(descriptor)


def _relation_record_id(values: tuple[object, ...]) -> str:
    material = json.dumps(
        list(values[:3]), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _date(value: str | None) -> date | None:
    return date.fromisoformat(value) if value else None


def _datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _provenance_from_row(row: sqlite3.Row) -> SourceProvenance:
    return SourceProvenance(
        canonical_url=row["canonical_url"],
        retrieved_at=datetime.fromisoformat(row["retrieved_at"]),
        content_sha256=row["content_sha256"],
        locator=row["source_locator"],
        publisher_document_id=row["publisher_document_id"],
    )


class SQLiteGuidanceStore:
    """Small stdlib-only store with immutable insert semantics."""

    def __init__(
        self,
        database: str | Path = ":memory:",
        *,
        readonly: bool = False,
        integrity_key: bytes | None = None,
    ) -> None:
        self.database = str(database)
        self.readonly = readonly
        self._transaction_depth = 0
        self._savepoint_counter = 0
        self._outer_transaction_immediate = False
        if integrity_key is None:
            self._integrity_key = _load_or_create_integrity_key(
                self.database,
                readonly=readonly,
            )
        else:
            self._integrity_key = bytes(integrity_key)
            if len(self._integrity_key) != 32:
                raise ValueError("guidance integrity key must contain exactly 32 bytes")
        if readonly:
            if self.database == ":memory:":
                raise ValueError("read-only guidance store requires a database file")
            path = Path(self.database)
            if not path.is_file() or path.is_symlink():
                raise ValueError("read-only guidance database is unavailable or unsafe")
            self._connection = sqlite3.connect(
                f"{path.absolute().as_uri()}?mode=ro",
                uri=True,
            )
            self._connection.execute("PRAGMA query_only = ON")
        else:
            self._connection = sqlite3.connect(self.database)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA trusted_schema = OFF")
        if not readonly:
            self._connection.executescript(SCHEMA)
            integrity_count = self._connection.execute(
                "SELECT COUNT(*) FROM guidance_integrity"
            ).fetchone()[0]
            manifest_count = self._connection.execute(
                "SELECT COUNT(*) FROM guidance_manifest"
            ).fetchone()[0]
            if manifest_count == 0 and integrity_count == 0:
                with self.transaction():
                    self._write_manifest()
            elif manifest_count != 1:
                raise ValueError("guidance registry manifest is unavailable")
            else:
                self._verify_manifest()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[None]:
        """Run one atomic write scope, nesting callers with savepoints.

        The outermost scope owns the SQLite transaction. Nested public store
        operations use savepoints so a fixture import can compose the existing
        immutable insert methods without letting any inner method commit the
        batch prematurely. ``immediate`` acquires the writer lock before a
        read-then-write invariant such as version-graph cycle detection.
        """

        outermost = self._transaction_depth == 0
        savepoint: str | None = None
        if outermost:
            self._connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            self._outer_transaction_immediate = immediate
        else:
            if immediate and not self._outer_transaction_immediate:
                raise RuntimeError(
                    "an immediate nested write requires an immediate outer transaction"
                )
            self._savepoint_counter += 1
            savepoint = f"guidance_write_{self._savepoint_counter}"
            self._connection.execute(f"SAVEPOINT {savepoint}")
        self._transaction_depth += 1
        try:
            yield
        except Exception:
            if savepoint is None:
                self._connection.rollback()
            else:
                self._connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        else:
            if savepoint is None:
                self._connection.commit()
            else:
                self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        finally:
            self._transaction_depth -= 1
            if outermost:
                self._outer_transaction_immediate = False

    def add_document(self, document: GuidelineDocument) -> None:
        values = (
            document.document_id,
            document.series_id,
            document.title,
            document.issuer,
            document.version,
            json.dumps(document.jurisdictions),
            document.effective_from.isoformat(),
            document.published_on.isoformat() if document.published_on else None,
            document.effective_until.isoformat()
            if document.effective_until
            else None,
            document.withdrawn_on.isoformat() if document.withdrawn_on else None,
            document.declared_status.value,
            document.status_changed_on.isoformat()
            if document.status_changed_on
            else None,
            document.last_checked_at.isoformat()
            if document.last_checked_at
            else None,
            document.document_type,
            document.language,
            json.dumps(document.metadata, sort_keys=True),
            document.provenance.canonical_url,
            document.provenance.retrieved_at.isoformat(),
            document.provenance.content_sha256,
            document.provenance.locator,
            document.provenance.publisher_document_id,
        )
        with self.transaction():
            self._connection.execute(
                """
            INSERT INTO guideline_documents (
                document_id, series_id, title, issuer, version,
                jurisdictions_json, effective_from, published_on,
                effective_until, withdrawn_on, declared_status,
                status_changed_on, last_checked_at, document_type, language,
                metadata_json, canonical_url, retrieved_at, content_sha256,
                source_locator, publisher_document_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            self._write_integrity(
                "document",
                document.document_id,
                _DOCUMENT_COLUMNS,
                values,
            )
            self._write_manifest()

    def add_relation(self, relation: VersionRelation) -> None:
        values = (
            relation.source_document_id,
            relation.target_document_id,
            relation.relation_type.value,
            relation.effective_from.isoformat(),
            json.dumps(relation.affected_recommendation_keys),
            relation.provenance_note,
        )
        with self.transaction(immediate=True):
            # Cycle detection and insertion must share the same writer lock.
            # Otherwise two connections can both validate stale acyclic
            # snapshots and then commit opposing edges.
            self._assert_acyclic(relation)
            self._assert_relation_lifecycle(relation)
            self._connection.execute(
                """
            INSERT INTO version_relations (
                source_document_id, target_document_id, relation_type,
                effective_from, affected_keys_json, provenance_note
            ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            self._write_integrity(
                "relation",
                _relation_record_id(values),
                _RELATION_COLUMNS,
                values,
            )
            self._write_manifest()

    def add_recommendation(self, recommendation: GuidelineRecommendation) -> None:
        values = (
            recommendation.recommendation_id,
            recommendation.document_id,
            recommendation.recommendation_key,
            recommendation.decision_key,
            recommendation.population_key,
            recommendation.verbatim_text,
            recommendation.native_grade_system,
            recommendation.native_grade,
            recommendation.native_strength,
            recommendation.native_certainty,
            recommendation.direction.value,
            recommendation.position_key,
            recommendation.applies_from.isoformat()
            if recommendation.applies_from
            else None,
            recommendation.applies_until.isoformat()
            if recommendation.applies_until
            else None,
            json.dumps(recommendation.jurisdictions),
            recommendation.topic,
            json.dumps(recommendation.metadata, sort_keys=True),
            recommendation.provenance.canonical_url,
            recommendation.provenance.retrieved_at.isoformat(),
            recommendation.provenance.content_sha256,
            recommendation.provenance.locator,
            recommendation.provenance.publisher_document_id,
        )
        with self.transaction():
            self._connection.execute(
                """
            INSERT INTO guideline_recommendations (
                recommendation_id, document_id, recommendation_key,
                decision_key, population_key, verbatim_text,
                native_grade_system, native_grade, native_strength,
                native_certainty, direction, position_key, applies_from,
                applies_until, jurisdictions_json, topic, metadata_json,
                canonical_url, retrieved_at, content_sha256, source_locator,
                publisher_document_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            self._write_integrity(
                "recommendation",
                recommendation.recommendation_id,
                _RECOMMENDATION_COLUMNS,
                values,
            )
            self._write_manifest()

    def _canonical_integrity_payload(
        self,
        record_kind: str,
        record_id: str,
        columns: tuple[str, ...],
        values: tuple[object, ...],
    ) -> bytes:
        return json.dumps(
            {
                "schema": "health-analyzer-guidance-integrity-v1",
                "record_kind": record_kind,
                "record_id": record_id,
                "fields": [[name, value] for name, value in zip(columns, values)],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _integrity_digest(
        self,
        record_kind: str,
        record_id: str,
        columns: tuple[str, ...],
        values: tuple[object, ...],
    ) -> str:
        return hmac.new(
            self._integrity_key,
            self._canonical_integrity_payload(
                record_kind,
                record_id,
                columns,
                values,
            ),
            hashlib.sha256,
        ).hexdigest()

    def _write_integrity(
        self,
        record_kind: str,
        record_id: str,
        columns: tuple[str, ...],
        values: tuple[object, ...],
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO guidance_integrity (record_kind, record_id, payload_hmac)
            VALUES (?, ?, ?)
            """,
            (
                record_kind,
                record_id,
                self._integrity_digest(record_kind, record_id, columns, values),
            ),
        )

    def _integrity_rows(self) -> tuple[tuple[str, str, str], ...]:
        rows = self._connection.execute(
            """
            SELECT record_kind, record_id, payload_hmac
            FROM guidance_integrity
            ORDER BY record_kind, record_id
            LIMIT 20001
            """
        ).fetchall()
        if len(rows) > 20_000:
            raise ValueError("guidance registry exceeds the manifest record limit")
        resolved = tuple(
            (str(row["record_kind"]), str(row["record_id"]), str(row["payload_hmac"]))
            for row in rows
        )
        if any(
            kind not in {"document", "relation", "recommendation"}
            or not record_id
            or len(record_id) > 512
            or len(payload_hmac) != 64
            for kind, record_id, payload_hmac in resolved
        ):
            raise ValueError("guidance registry integrity rows are malformed")
        return resolved

    def _manifest_digest(self, rows: tuple[tuple[str, str, str], ...]) -> str:
        return hmac.new(
            self._integrity_key,
            json.dumps(
                {
                    "schema": "health-analyzer-guidance-manifest-v1",
                    "records": [list(row) for row in rows],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _write_manifest(self) -> None:
        rows = self._integrity_rows()
        self._connection.execute(
            """
            INSERT INTO guidance_manifest(singleton, record_count, manifest_hmac)
            VALUES (1, ?, ?)
            ON CONFLICT(singleton) DO UPDATE SET
                record_count = excluded.record_count,
                manifest_hmac = excluded.manifest_hmac
            """,
            (len(rows), self._manifest_digest(rows)),
        )

    def _actual_record_keys(self) -> set[tuple[str, str]]:
        keys = {
            ("document", str(row[0]))
            for row in self._connection.execute(
                "SELECT document_id FROM guideline_documents LIMIT 20001"
            ).fetchall()
        }
        keys.update(
            ("recommendation", str(row[0]))
            for row in self._connection.execute(
                "SELECT recommendation_id FROM guideline_recommendations LIMIT 20001"
            ).fetchall()
        )
        relation_rows = self._connection.execute(
            """
            SELECT source_document_id, target_document_id, relation_type,
                   effective_from, affected_keys_json, provenance_note
            FROM version_relations
            LIMIT 20001
            """
        ).fetchall()
        keys.update(
            (
                "relation",
                _relation_record_id(tuple(row[column] for column in _RELATION_COLUMNS)),
            )
            for row in relation_rows
        )
        if len(keys) > 20_000:
            raise ValueError("guidance registry exceeds the manifest record limit")
        return keys

    def _verify_manifest(self) -> None:
        try:
            manifest = self._connection.execute(
                "SELECT record_count, manifest_hmac FROM guidance_manifest WHERE singleton = 1"
            ).fetchone()
            rows = self._integrity_rows()
            actual_keys = self._actual_record_keys()
        except sqlite3.DatabaseError as error:
            raise ValueError("guidance registry manifest is unavailable") from error
        integrity_keys = {(kind, record_id) for kind, record_id, _ in rows}
        if (
            manifest is None
            or manifest["record_count"] != len(rows)
            or actual_keys != integrity_keys
            or not hmac.compare_digest(
                str(manifest["manifest_hmac"]),
                self._manifest_digest(rows),
            )
        ):
            raise ValueError("guidance registry manifest verification failed")

    def _verify_integrity(
        self,
        row: sqlite3.Row,
        *,
        record_kind: str,
        record_id: str,
        columns: tuple[str, ...],
    ) -> None:
        try:
            integrity = self._connection.execute(
                """
                SELECT payload_hmac FROM guidance_integrity
                WHERE record_kind = ? AND record_id = ?
                """,
                (record_kind, record_id),
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise ValueError("guidance integrity metadata is unavailable") from error
        if integrity is None:
            raise ValueError("guidance record has no integrity receipt")
        values = tuple(row[name] for name in columns)
        expected = self._integrity_digest(
            record_kind,
            record_id,
            columns,
            values,
        )
        if not hmac.compare_digest(str(integrity["payload_hmac"]), expected):
            raise ValueError("guidance record integrity verification failed")

    def get_document(self, document_id: str) -> GuidelineDocument | None:
        self._verify_manifest()
        row = self._connection.execute(
            "SELECT * FROM guideline_documents WHERE document_id = ?",
            (document_id,),
        ).fetchone()
        if row is None:
            return None
        self._verify_integrity(
            row,
            record_kind="document",
            record_id=str(row["document_id"]),
            columns=_DOCUMENT_COLUMNS,
        )
        return self._document_from_row(row)

    def list_documents(self) -> tuple[GuidelineDocument, ...]:
        self._verify_manifest()
        rows = self._connection.execute(
            "SELECT * FROM guideline_documents ORDER BY effective_from, document_id"
        ).fetchall()
        for row in rows:
            self._verify_integrity(
                row,
                record_kind="document",
                record_id=str(row["document_id"]),
                columns=_DOCUMENT_COLUMNS,
            )
        return tuple(self._document_from_row(row) for row in rows)

    def get_recommendation(
        self, recommendation_id: str
    ) -> GuidelineRecommendation | None:
        self._verify_manifest()
        row = self._connection.execute(
            "SELECT * FROM guideline_recommendations WHERE recommendation_id = ?",
            (recommendation_id,),
        ).fetchone()
        if row is None:
            return None
        self._verify_integrity(
            row,
            record_kind="recommendation",
            record_id=str(row["recommendation_id"]),
            columns=_RECOMMENDATION_COLUMNS,
        )
        return self._recommendation_from_row(row)

    def list_recommendations(
        self, document_id: str | None = None
    ) -> tuple[GuidelineRecommendation, ...]:
        self._verify_manifest()
        if document_id is None:
            rows = self._connection.execute(
                """SELECT * FROM guideline_recommendations
                   ORDER BY document_id, recommendation_key, recommendation_id"""
            ).fetchall()
        else:
            rows = self._connection.execute(
                """SELECT * FROM guideline_recommendations
                   WHERE document_id = ?
                   ORDER BY recommendation_key, recommendation_id""",
                (document_id,),
            ).fetchall()
        for row in rows:
            self._verify_integrity(
                row,
                record_kind="recommendation",
                record_id=str(row["recommendation_id"]),
                columns=_RECOMMENDATION_COLUMNS,
            )
        return tuple(self._recommendation_from_row(row) for row in rows)

    def list_relations(self) -> tuple[VersionRelation, ...]:
        self._verify_manifest()
        rows = self._connection.execute(
            """SELECT * FROM version_relations
               ORDER BY effective_from, source_document_id, target_document_id"""
        ).fetchall()
        for row in rows:
            values = tuple(row[name] for name in _RELATION_COLUMNS)
            self._verify_integrity(
                row,
                record_kind="relation",
                record_id=_relation_record_id(values),
                columns=_RELATION_COLUMNS,
            )
        return tuple(
            VersionRelation(
                source_document_id=row["source_document_id"],
                target_document_id=row["target_document_id"],
                relation_type=VersionRelationType(row["relation_type"]),
                effective_from=date.fromisoformat(row["effective_from"]),
                affected_recommendation_keys=tuple(
                    json.loads(row["affected_keys_json"])
                ),
                provenance_note=row["provenance_note"],
            )
            for row in rows
        )

    def _assert_acyclic(self, relation: VersionRelation) -> None:
        if self.get_document(relation.source_document_id) is None:
            raise KeyError(f"unknown source document: {relation.source_document_id}")
        if self.get_document(relation.target_document_id) is None:
            raise KeyError(f"unknown target document: {relation.target_document_id}")

        adjacency: dict[str, set[str]] = {}
        for existing in self.list_relations():
            adjacency.setdefault(existing.source_document_id, set()).add(
                existing.target_document_id
            )
        adjacency.setdefault(relation.source_document_id, set()).add(
            relation.target_document_id
        )

        stack = [relation.target_document_id]
        visited: set[str] = set()
        while stack:
            current = stack.pop()
            if current == relation.source_document_id:
                raise ValueError("version relation would create a cycle")
            if current in visited:
                continue
            visited.add(current)
            stack.extend(adjacency.get(current, ()))

    def _assert_relation_lifecycle(self, relation: VersionRelation) -> None:
        """Validate the documented newer-to-older edge and activation date."""

        source = self.get_document(relation.source_document_id)
        target = self.get_document(relation.target_document_id)
        if source is None or target is None:
            # _assert_acyclic emits the public, identifier-specific error first.
            raise KeyError("version relation references an unknown document")
        if source.series_id != target.series_id:
            raise ValueError("version relations require documents in the same series")
        if source.effective_from < target.effective_from:
            raise ValueError(
                "version relation source must not predate its target document"
            )
        if relation.effective_from < source.effective_from:
            raise ValueError(
                "version relation cannot take effect before its source document"
            )
        if (
            source.effective_until is not None
            and relation.effective_from > source.effective_until
        ):
            raise ValueError(
                "version relation must take effect while its source document is active"
            )
        if (
            source.withdrawn_on is not None
            and relation.effective_from >= source.withdrawn_on
        ):
            raise ValueError(
                "version relation must take effect before its source is withdrawn"
            )
        if (
            source.status_changed_on is not None
            and source.declared_status
            in {GuidanceStatus.SUPERSEDED, GuidanceStatus.WITHDRAWN}
            and relation.effective_from >= source.status_changed_on
        ):
            raise ValueError(
                "version relation must take effect before its source becomes non-current"
            )

    @staticmethod
    def _document_from_row(row: sqlite3.Row) -> GuidelineDocument:
        return GuidelineDocument(
            document_id=row["document_id"],
            series_id=row["series_id"],
            title=row["title"],
            issuer=row["issuer"],
            version=row["version"],
            jurisdictions=tuple(json.loads(row["jurisdictions_json"])),
            effective_from=date.fromisoformat(row["effective_from"]),
            published_on=_date(row["published_on"]),
            effective_until=_date(row["effective_until"]),
            withdrawn_on=_date(row["withdrawn_on"]),
            declared_status=GuidanceStatus(row["declared_status"]),
            status_changed_on=_date(row["status_changed_on"]),
            last_checked_at=_datetime(row["last_checked_at"]),
            document_type=row["document_type"],
            language=row["language"],
            metadata=json.loads(row["metadata_json"]),
            provenance=_provenance_from_row(row),
        )

    @staticmethod
    def _recommendation_from_row(row: sqlite3.Row) -> GuidelineRecommendation:
        return GuidelineRecommendation(
            recommendation_id=row["recommendation_id"],
            document_id=row["document_id"],
            recommendation_key=row["recommendation_key"],
            decision_key=row["decision_key"],
            population_key=row["population_key"],
            verbatim_text=row["verbatim_text"],
            native_grade_system=row["native_grade_system"],
            native_grade=row["native_grade"],
            native_strength=row["native_strength"],
            native_certainty=row["native_certainty"],
            direction=RecommendationDirection(row["direction"]),
            position_key=row["position_key"],
            applies_from=_date(row["applies_from"]),
            applies_until=_date(row["applies_until"]),
            jurisdictions=tuple(json.loads(row["jurisdictions_json"])),
            topic=row["topic"],
            metadata=json.loads(row["metadata_json"]),
            provenance=_provenance_from_row(row),
        )
