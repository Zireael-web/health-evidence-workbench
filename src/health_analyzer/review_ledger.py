"""Private, source-bound review receipts for extracted candidates.

The ledger closes the MCP boundary that previously accepted caller-supplied
``verification=verified`` JSON.  It proves that a reviewed record came from a
candidate registered by the local ingestion pipeline and preserves the exact
source value and provenance used to create it.

``reviewer_id`` is an audit attribution label, not authentication.  Proving
human presence or identity requires a separate trusted UI or OS-identity
integration; this SQLite ledger deliberately does not claim to provide that.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any

from .contracts import StatementKind, VerificationStatus, utc_now
from .ingest.models import Candidate, CandidateKind, content_hash, deterministic_id
from .ingest.security import InstructionDetector


_SUBJECT_ID = re.compile(r"subj_[a-f0-9]{16,64}\Z")
MAX_RECEIPTS_PER_CASE_PACKET = 100
MAX_REVIEW_BATCH_JSON_BYTES = 8 * 1024 * 1024
MAX_DOCUMENT_REVIEW_CANDIDATES = 1_000
MAX_ARCHIVE_REVIEW_CANDIDATES = 20_000
MAX_ARCHIVE_INGESTION_SUMMARY_BYTES = 64 * 1024
MAX_PRIVATE_LEDGER_PAGE_SIZE = 100
REVIEW_LEDGER_SCHEMA_VERSION = 4
_EXTRACTION_METADATA_COLUMNS = frozenset(
    {"confidence", "extraction_status", "instruction_findings_json", "limitations_json"}
)


class UnknownReviewCandidateError(ValueError):
    """Raised when review is requested for a candidate not registered by ingestion."""


class UnknownReviewReceiptError(ValueError):
    """Raised when packet construction references a receipt absent from the ledger."""


class UnknownReviewBatchError(ValueError):
    """Raised when a batch identifier is absent from the private ledger."""


class ReviewLedgerIntegrityError(RuntimeError):
    """Raised when immutable candidate or receipt bindings do not validate."""


class StaleReviewBatchError(ReviewLedgerIntegrityError):
    """Raised when a prepared artifact snapshot no longer matches the ledger."""


class _ReviewLedgerConnection(sqlite3.Connection):
    """Verification memoization confined to one database transaction."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.application_outcomes: dict[str, dict[str, Any]] = {}
        self.verified_effect_batches: set[str] = set()
        self.receipt_commit_links: dict[str, dict[str, dict[str, Any]]] = {}
        self.verified_memberships: set[tuple[str, str, str]] = set()
        self.snapshot_materials: dict[str, dict[str, Any]] = {}


@dataclass(frozen=True, slots=True)
class ReviewedRecordReceipt:
    receipt_id: str
    record_id: str
    record_type: str
    subject_id: str
    candidate_id: str
    candidate_sha256: str
    artifact_sha256: str
    provenance: tuple[dict[str, Any], ...]
    source_value: str
    reviewer_id: str
    review_note: str | None
    reviewed_at: str
    record_json: str

    @property
    def record(self) -> dict[str, Any]:
        return json.loads(self.record_json)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("record_json")
        payload["record"] = self.record
        return payload


@dataclass(frozen=True, slots=True)
class ReviewedRecordBatch:
    root_scope: str
    subject_id: str
    verified_at: str
    records: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class UserNoteReceipt:
    receipt_id: str
    record_id: str
    subject_id: str
    root_scope: str
    recorder_id: str
    recorded_at: str
    record_json: str

    @property
    def record(self) -> dict[str, Any]:
        return json.loads(self.record_json)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("record_json")
        payload["record"] = self.record
        return payload


@dataclass(frozen=True, slots=True)
class ArchiveIngestionReceipt:
    root_scope: str
    subject_id: str
    source_id: str
    artifact_sha256: str
    processing_profile_sha256: str
    media_type: str
    processed_at: str
    summary_json: str

    @property
    def summary(self) -> dict[str, Any]:
        return json.loads(self.summary_json)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("summary_json")
        payload["summary"] = self.summary
        return payload


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_text(value: str, *, name: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    if "\0" in value:
        raise ValueError(f"{name} must not contain NUL")
    return value.strip()


def _require_exact_text(value: str, *, name: str, maximum: int) -> str:
    """Validate operator-confirmed text without normalizing the signed value."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    if "\0" in value:
        raise ValueError(f"{name} must not contain NUL")
    return value


def _execute_transactional_script(
    connection: sqlite3.Connection,
    script: str,
) -> None:
    """Execute internal DDL without ``executescript`` implicitly committing."""

    pending = ""
    for character in script:
        pending += character
        if character == ";" and sqlite3.complete_statement(pending):
            connection.execute(pending)
            pending = ""
    if pending.strip():
        raise RuntimeError("review-ledger schema script is incomplete")


class PrivateReviewLedger:
    """Source-bound HMAC review receipts in a private SQLite database.

    The schema intentionally has no source-path or source-byte column.  It
    stores extracted source text because exact-value comparison is the review
    contract, plus hashes and locators needed to bind that text to an artifact.
    SQLite itself remains mutable; verification rejects rows that no longer
    match the keyed receipt binding.
    """

    def __init__(self, database_path: str | Path, *, integrity_key: bytes) -> None:
        self.database_path = Path(database_path)
        self._integrity_key = bytes(integrity_key)
        if len(self._integrity_key) < 32:
            raise ValueError("review-ledger integrity key must contain at least 32 bytes")
        self._instruction_detector = InstructionDetector()
        self._prepare_private_database()
        self._initialize()

    def _mac(self, value: Any) -> str:
        return hmac.new(
            self._integrity_key,
            _canonical_json(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _prepare_private_database(self) -> None:
        parent = self.database_path.parent
        if parent.is_symlink():
            raise ValueError("review-ledger parent must not be a symbolic link")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("review-ledger parent must be a private directory")
        parent.chmod(0o700)

        if self.database_path.is_symlink():
            raise ValueError("review-ledger database must not be a symbolic link")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.database_path, flags, 0o600)
        try:
            file_state = os.fstat(descriptor)
            if not stat.S_ISREG(file_state.st_mode):
                raise ValueError("review-ledger database must be a regular file")
            if file_state.st_nlink != 1:
                raise ValueError("review-ledger database must not be multiply linked")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def _connect(self) -> sqlite3.Connection:
        parent_state = self.database_path.parent.lstat()
        database_state = self.database_path.lstat()
        if (
            stat.S_ISLNK(parent_state.st_mode)
            or not stat.S_ISDIR(parent_state.st_mode)
            or stat.S_ISLNK(database_state.st_mode)
            or not stat.S_ISREG(database_state.st_mode)
            or database_state.st_nlink != 1
        ):
            raise ValueError("review-ledger path is no longer a private regular file")
        connection = sqlite3.connect(
            self.database_path, timeout=5.0, factory=_ReviewLedgerConnection
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA busy_timeout = 5000")
        except BaseException:
            connection.close()
            raise
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if schema_version > REVIEW_LEDGER_SCHEMA_VERSION:
                raise ReviewLedgerIntegrityError(
                    "review-ledger schema version "
                    f"{schema_version} is newer than supported version "
                    f"{REVIEW_LEDGER_SCHEMA_VERSION}"
                )
            if schema_version < 0:
                raise ReviewLedgerIntegrityError(
                    f"review-ledger schema version {schema_version} is unsupported"
                )
            if schema_version == REVIEW_LEDGER_SCHEMA_VERSION:
                connection.commit()
            else:
                _execute_transactional_script(
                    connection,
                    """

                    CREATE TABLE IF NOT EXISTS extraction_candidate (
                    root_scope TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    candidate_kind TEXT NOT NULL CHECK(candidate_kind IN ('field', 'statement')),
                    field_name TEXT,
                    raw_value TEXT NOT NULL,
                    confidence REAL,
                    extraction_status TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    instruction_findings_json TEXT NOT NULL,
                    limitations_json TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    candidate_binding_hmac TEXT NOT NULL,
                    PRIMARY KEY(root_scope, candidate_id)
                );

                CREATE TABLE IF NOT EXISTS reviewed_extraction (
                    receipt_id TEXT PRIMARY KEY,
                    root_scope TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    source_value TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    record_type TEXT NOT NULL CHECK(record_type IN ('observation', 'statement')),
                    record_id TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    review_note TEXT,
                    reviewed_at TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL UNIQUE,
                    review_action TEXT CHECK(review_action IN ('accept', 'edit')),
                    corrected_field_name TEXT,
                    corrected_value TEXT,
                    batch_id TEXT,
                    source_id TEXT,
                    processing_profile_sha256 TEXT,
                    FOREIGN KEY(root_scope, candidate_id)
                        REFERENCES extraction_candidate(root_scope, candidate_id)
                );

                CREATE INDEX IF NOT EXISTS reviewed_extraction_subject_idx
                    ON reviewed_extraction(root_scope, subject_id, reviewed_at);
                CREATE INDEX IF NOT EXISTS reviewed_extraction_candidate_idx
                    ON reviewed_extraction(root_scope, candidate_id, reviewed_at);

                CREATE TABLE IF NOT EXISTS reviewed_user_note (
                    receipt_id TEXT PRIMARY KEY,
                    root_scope TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    record_id TEXT NOT NULL UNIQUE,
                    note_text TEXT NOT NULL,
                    recorder_id TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL UNIQUE
                );

                CREATE INDEX IF NOT EXISTS reviewed_user_note_subject_idx
                    ON reviewed_user_note(root_scope, subject_id, recorded_at);

                CREATE TABLE IF NOT EXISTS archive_ingestion (
                    root_scope TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    processing_profile_sha256 TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    processed_at TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    binding_hmac TEXT NOT NULL,
                    PRIMARY KEY(root_scope, source_id, processing_profile_sha256)
                );

                CREATE INDEX IF NOT EXISTS archive_ingestion_subject_idx
                    ON archive_ingestion(root_scope, subject_id, processed_at);

                CREATE TABLE IF NOT EXISTS candidate_source_version (
                    root_scope TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_order INTEGER NOT NULL CHECK(source_order >= 0),
                    candidate_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    binding_hmac TEXT NOT NULL,
                    PRIMARY KEY(root_scope, source_id, candidate_id),
                    UNIQUE(root_scope, source_id, source_order),
                    FOREIGN KEY(root_scope, candidate_id)
                        REFERENCES extraction_candidate(root_scope, candidate_id)
                );

                CREATE INDEX IF NOT EXISTS candidate_source_version_subject_idx
                    ON candidate_source_version(
                        root_scope, subject_id, source_id, source_order
                    );

                CREATE TABLE IF NOT EXISTS candidate_source_profile_version (
                    root_scope TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    processing_profile_sha256 TEXT NOT NULL,
                    source_order INTEGER NOT NULL CHECK(source_order >= 0),
                    candidate_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    binding_hmac TEXT NOT NULL,
                    PRIMARY KEY(
                        root_scope, source_id, processing_profile_sha256,
                        candidate_id
                    ),
                    UNIQUE(
                        root_scope, source_id, processing_profile_sha256,
                        source_order
                    ),
                    FOREIGN KEY(root_scope, candidate_id)
                        REFERENCES extraction_candidate(root_scope, candidate_id)
                );

                CREATE INDEX IF NOT EXISTS candidate_source_profile_subject_idx
                    ON candidate_source_profile_version(
                        root_scope, subject_id, source_id,
                        processing_profile_sha256, source_order
                    );

                CREATE TABLE IF NOT EXISTS review_batch_snapshot (
                    batch_id TEXT PRIMARY KEY,
                    root_scope TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    source_id TEXT,
                    processing_profile_sha256 TEXT,
                    artifact_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    prepared_at TEXT NOT NULL,
                    candidate_count INTEGER NOT NULL CHECK(candidate_count > 0),
                    candidates_json TEXT NOT NULL,
                    archive_ingestion_json TEXT,
                    snapshot_sha256 TEXT NOT NULL,
                    binding_hmac TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS review_batch_snapshot_scope_idx
                    ON review_batch_snapshot(
                        root_scope, subject_id, source_id, artifact_sha256, prepared_at
                    );

                CREATE TABLE IF NOT EXISTS review_batch_application (
                    batch_id TEXT PRIMARY KEY,
                    reviewer_id TEXT NOT NULL,
                    default_action TEXT NOT NULL
                        CHECK(default_action IN ('accept_all', 'no_default')),
                    request_json TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    applied_at TEXT NOT NULL,
                    outcome_json TEXT NOT NULL,
                    binding_hmac TEXT NOT NULL,
                    FOREIGN KEY(batch_id) REFERENCES review_batch_snapshot(batch_id)
                );

                CREATE TABLE IF NOT EXISTS candidate_review_action (
                    action_id TEXT PRIMARY KEY,
                    root_scope TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('accept', 'edit', 'reject')),
                    original_field_name TEXT,
                    original_source_value TEXT NOT NULL,
                    corrected_field_name TEXT,
                    corrected_value TEXT,
                    reviewer_id TEXT NOT NULL,
                    review_note TEXT,
                    reviewed_at TEXT NOT NULL,
                    receipt_id TEXT,
                    source_id TEXT,
                    processing_profile_sha256 TEXT,
                    binding_hmac TEXT NOT NULL,
                    UNIQUE(batch_id, candidate_id),
                    FOREIGN KEY(root_scope, candidate_id)
                        REFERENCES extraction_candidate(root_scope, candidate_id),
                    FOREIGN KEY(batch_id) REFERENCES review_batch_snapshot(batch_id),
                    FOREIGN KEY(receipt_id) REFERENCES reviewed_extraction(receipt_id)
                );

                CREATE INDEX IF NOT EXISTS candidate_review_action_candidate_idx
                    ON candidate_review_action(root_scope, candidate_id, reviewed_at);
                    """,
                )
                candidate_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(extraction_candidate)"
                    ).fetchall()
                }
                if "subject_id" not in candidate_columns:
                    # Legacy rows cannot be assigned safely. Re-ingestion will
                    # fail closed on a NULL/different immutable binding instead of
                    # guessing which patient owned them.
                    connection.execute(
                        "ALTER TABLE extraction_candidate ADD COLUMN subject_id TEXT"
                    )
                for column_name in (
                    "instruction_findings_json",
                    "limitations_json",
                    "candidate_binding_hmac",
                ):
                    if column_name not in candidate_columns:
                        # Rows created before candidate-level HMAC binding remain
                        # unusable until an exact source re-ingestion re-registers
                        # and signs them. Never guess missing security metadata.
                        connection.execute(
                            "ALTER TABLE extraction_candidate "
                            f"ADD COLUMN {column_name} TEXT"
                        )
                reviewed_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(reviewed_extraction)"
                    ).fetchall()
                }
                for column_name, declaration in (
                    (
                        "review_action",
                        "TEXT CHECK(review_action IN ('accept', 'edit'))",
                    ),
                    ("corrected_field_name", "TEXT"),
                    ("corrected_value", "TEXT"),
                    ("batch_id", "TEXT"),
                    ("source_id", "TEXT"),
                    ("processing_profile_sha256", "TEXT"),
                ):
                    if column_name not in reviewed_columns:
                        connection.execute(
                            "ALTER TABLE reviewed_extraction "
                            f"ADD COLUMN {column_name} {declaration}"
                        )
                snapshot_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(review_batch_snapshot)"
                    ).fetchall()
                }
                if "processing_profile_sha256" not in snapshot_columns:
                    connection.execute(
                        "ALTER TABLE review_batch_snapshot "
                        "ADD COLUMN processing_profile_sha256 TEXT"
                    )
                if "archive_ingestion_json" not in snapshot_columns:
                    connection.execute(
                        "ALTER TABLE review_batch_snapshot "
                        "ADD COLUMN archive_ingestion_json TEXT"
                    )
                profile_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(candidate_source_profile_version)"
                    )
                }
                if "extraction_metadata_json" not in profile_columns:
                    connection.execute(
                        "ALTER TABLE candidate_source_profile_version "
                        "ADD COLUMN extraction_metadata_json TEXT"
                    )
                action_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(candidate_review_action)"
                    ).fetchall()
                }
                for column_name in ("source_id", "processing_profile_sha256"):
                    if column_name not in action_columns:
                        connection.execute(
                            "ALTER TABLE candidate_review_action "
                            f"ADD COLUMN {column_name} TEXT"
                        )
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                        reviewed_extraction_occurrence_idx
                    ON reviewed_extraction(
                        root_scope, subject_id, source_id,
                        processing_profile_sha256, candidate_id
                    )
                    WHERE source_id IS NOT NULL
                      AND processing_profile_sha256 IS NOT NULL
                    """
                )
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                        candidate_review_action_occurrence_idx
                    ON candidate_review_action(
                        root_scope, subject_id, source_id,
                        processing_profile_sha256, candidate_id
                    )
                    WHERE source_id IS NOT NULL
                      AND processing_profile_sha256 IS NOT NULL
                    """
                )
                connection.execute(
                    f"PRAGMA user_version = {REVIEW_LEDGER_SCHEMA_VERSION}"
                )
                connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        self.database_path.chmod(0o600)
        self.database_path.parent.chmod(0o700)

    @staticmethod
    def _candidate_registration(
        root_scope: str,
        subject_id: str,
        artifact_sha256: str,
        candidate: Candidate,
    ) -> dict[str, Any]:
        provenance = tuple(asdict(item) for item in candidate.provenance)
        if any(item["artifact_sha256"] != artifact_sha256 for item in provenance):
            raise ReviewLedgerIntegrityError(
                "candidate provenance does not match the ingested artifact hash"
            )
        artifact_ids = {item["artifact_id"] for item in provenance}
        if len(artifact_ids) != 1:
            raise ReviewLedgerIntegrityError("candidate spans multiple artifacts")
        if artifact_ids != {deterministic_id("art", artifact_sha256)}:
            raise ReviewLedgerIntegrityError("candidate artifact ID is not content-addressed")
        if len(provenance) != 1:
            raise ReviewLedgerIntegrityError(
                "generic review candidates must have exactly one source locator"
            )
        locator = provenance[0]
        expected_candidate_sha256 = content_hash(
            {
                "kind": candidate.kind.value,
                "raw_value": candidate.raw_value,
                "field_name": candidate.field_name,
                "provenance": {
                    "block_id": locator["block_id"],
                    "line_start": locator["line_start"],
                    "line_end": locator["line_end"],
                    "row_index": locator["row_index"],
                    "column_index": locator["column_index"],
                },
            }
        )
        if not hmac.compare_digest(candidate.candidate_sha256, expected_candidate_sha256):
            raise ReviewLedgerIntegrityError("candidate content hash is invalid")
        return {
            "root_scope": root_scope,
            "subject_id": subject_id,
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.candidate_sha256,
            "artifact_id": next(iter(artifact_ids)),
            "artifact_sha256": artifact_sha256,
            "candidate_kind": candidate.kind.value,
            "field_name": candidate.field_name,
            "raw_value": candidate.raw_value,
            "confidence": (
                0.0 if candidate.confidence == 0 else candidate.confidence
            ),
            "extraction_status": candidate.verification.value,
            "provenance_json": _canonical_json(provenance),
            "instruction_findings_json": _canonical_json(
                tuple(asdict(item) for item in candidate.instruction_findings)
            ),
            "limitations_json": _canonical_json(candidate.limitations),
        }

    @staticmethod
    def _candidate_binding_material(
        registration: dict[str, Any],
        *,
        registered_at: str,
    ) -> dict[str, Any]:
        return {
            "schema": "private-review-candidate-v1",
            "root_scope": registration["root_scope"],
            "subject_id": registration["subject_id"],
            "candidate_id": registration["candidate_id"],
            "candidate_sha256": registration["candidate_sha256"],
            "artifact_id": registration["artifact_id"],
            "artifact_sha256": registration["artifact_sha256"],
            "candidate_kind": registration["candidate_kind"],
            "field_name": registration["field_name"],
            "raw_value": registration["raw_value"],
            "confidence": registration["confidence"],
            "extraction_status": registration["extraction_status"],
            "provenance": json.loads(registration["provenance_json"]),
            "instruction_findings": json.loads(
                registration["instruction_findings_json"]
            ),
            "limitations": json.loads(registration["limitations_json"]),
            "registered_at": registered_at,
        }

    @staticmethod
    def _candidate_registration_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "root_scope": row["root_scope"],
            "subject_id": row["subject_id"],
            "candidate_id": row["candidate_id"],
            "candidate_sha256": row["candidate_sha256"],
            "artifact_id": row["artifact_id"],
            "artifact_sha256": row["artifact_sha256"],
            "candidate_kind": row["candidate_kind"],
            "field_name": row["field_name"],
            "raw_value": row["raw_value"],
            "confidence": row["confidence"],
            "extraction_status": row["extraction_status"],
            "provenance_json": row["provenance_json"],
            "instruction_findings_json": row["instruction_findings_json"],
            "limitations_json": row["limitations_json"],
        }

    def _verify_candidate_row(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            registration = self._candidate_registration_from_row(row)
            binding = row["candidate_binding_hmac"]
            if not isinstance(binding, str) or not binding:
                raise ValueError("missing candidate binding")
            expected = self._mac(
                self._candidate_binding_material(
                    registration,
                    registered_at=row["registered_at"],
                )
            )
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ReviewLedgerIntegrityError(
                "candidate binding is missing or invalid; re-ingest the source"
            ) from None
        if not hmac.compare_digest(expected, binding):
            raise ReviewLedgerIntegrityError(
                "candidate binding is missing or invalid; re-ingest the source"
            )
        return registration

    @staticmethod
    def _source_association_material(
        *,
        root_scope: str,
        subject_id: str,
        source_id: str,
        source_order: int,
        candidate_id: str,
        candidate_sha256: str,
        artifact_sha256: str,
        registered_at: str,
    ) -> dict[str, Any]:
        return {
            "schema": "private-candidate-source-version-v1",
            "root_scope": root_scope,
            "subject_id": subject_id,
            "source_id": source_id,
            "source_order": source_order,
            "candidate_id": candidate_id,
            "candidate_sha256": candidate_sha256,
            "artifact_sha256": artifact_sha256,
            "registered_at": registered_at,
        }

    def _verify_source_association_row(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            material = self._source_association_material(
                root_scope=row["root_scope"],
                subject_id=row["subject_id"],
                source_id=row["source_id"],
                source_order=row["source_order"],
                candidate_id=row["candidate_id"],
                candidate_sha256=row["candidate_sha256"],
                artifact_sha256=row["artifact_sha256"],
                registered_at=row["registered_at"],
            )
            expected = self._mac(material)
            binding = row["binding_hmac"]
        except (IndexError, KeyError, TypeError, ValueError):
            raise ReviewLedgerIntegrityError(
                "candidate source-version binding is missing or invalid"
            ) from None
        if not isinstance(binding, str) or not hmac.compare_digest(expected, binding):
            raise ReviewLedgerIntegrityError(
                "candidate source-version binding is missing or invalid"
            )
        return material

    @staticmethod
    def _source_profile_association_material(
        *,
        root_scope: str,
        subject_id: str,
        source_id: str,
        processing_profile_sha256: str,
        source_order: int,
        candidate_id: str,
        candidate_sha256: str,
        artifact_sha256: str,
        registered_at: str,
        extraction_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        material = {
            "schema": (
                "private-candidate-source-profile-version-v2"
                if extraction_metadata is not None
                else "private-candidate-source-profile-version-v1"
            ),
            "root_scope": root_scope,
            "subject_id": subject_id,
            "source_id": source_id,
            "processing_profile_sha256": processing_profile_sha256,
            "source_order": source_order,
            "candidate_id": candidate_id,
            "candidate_sha256": candidate_sha256,
            "artifact_sha256": artifact_sha256,
            "registered_at": registered_at,
        }
        if extraction_metadata is not None:
            material["extraction_metadata"] = extraction_metadata
        return material

    @staticmethod
    def _candidate_extraction_metadata(registration: dict[str, Any]) -> dict[str, Any]:
        return {
            key: registration[key] for key in _EXTRACTION_METADATA_COLUMNS
        }

    def _verify_source_profile_association_row(
        self,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        try:
            material = self._source_profile_association_material(
                root_scope=row["root_scope"],
                subject_id=row["subject_id"],
                source_id=row["source_id"],
                processing_profile_sha256=row["processing_profile_sha256"],
                source_order=row["source_order"],
                candidate_id=row["candidate_id"],
                candidate_sha256=row["candidate_sha256"],
                artifact_sha256=row["artifact_sha256"],
                registered_at=row["registered_at"],
                extraction_metadata=(
                    json.loads(row["extraction_metadata_json"])
                    if row["extraction_metadata_json"] is not None
                    else None
                ),
            )
            metadata = material.get("extraction_metadata")
            if metadata is not None and (
                not isinstance(metadata, dict)
                or set(metadata) != _EXTRACTION_METADATA_COLUMNS
            ):
                raise ValueError("invalid profile extraction metadata")
            expected = self._mac(material)
            binding = row["binding_hmac"]
        except (IndexError, KeyError, TypeError, ValueError):
            raise ReviewLedgerIntegrityError(
                "candidate source-profile binding is missing or invalid"
            ) from None
        if not isinstance(binding, str) or not hmac.compare_digest(expected, binding):
            raise ReviewLedgerIntegrityError(
                "candidate source-profile binding is missing or invalid"
            )
        return material

    def register_candidates(
        self,
        *,
        root_scope: str,
        subject_id: str,
        artifact_sha256: str,
        candidates: tuple[Candidate, ...],
        source_id: str | None = None,
        source_order: tuple[str, ...] | list[str] | None = None,
        processing_profile_sha256: str | None = None,
    ) -> tuple[str, ...]:
        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")
        if len(artifact_sha256) != 64:
            raise ValueError("artifact_sha256 must be a SHA-256 hex digest")
        source: str | None = None
        if source_id is not None:
            source = _require_text(source_id, name="source_id", maximum=128)
        elif source_order is not None:
            raise ValueError("source_order requires source_id")
        profile: str | None = None
        if processing_profile_sha256 is not None:
            if source is None:
                raise ValueError("processing_profile_sha256 requires source_id")
            profile = _require_text(
                processing_profile_sha256,
                name="processing_profile_sha256",
                maximum=64,
            )
            if not re.fullmatch(r"[a-f0-9]{64}", profile):
                raise ValueError(
                    "processing_profile_sha256 must be a lowercase SHA-256 value"
                )
        registrations = tuple(
            self._candidate_registration(scope, subject, artifact_sha256, candidate)
            for candidate in candidates
        )
        registration_by_id = {
            registration["candidate_id"]: registration
            for registration in registrations
        }
        if len(registration_by_id) != len(registrations):
            raise ReviewLedgerIntegrityError(
                "candidate registration contains duplicate candidate IDs"
            )
        if source_order is None:
            ordered_candidate_ids = tuple(registration_by_id)
        else:
            if not isinstance(source_order, (tuple, list)):
                raise ValueError("source_order must be an array of candidate IDs")
            ordered_candidate_ids = tuple(
                _require_text(item, name="source_order candidate_id", maximum=128)
                for item in source_order
            )
            if (
                len(ordered_candidate_ids) != len(registrations)
                or len(set(ordered_candidate_ids)) != len(ordered_candidate_ids)
                or set(ordered_candidate_ids) != set(registration_by_id)
            ):
                raise ValueError(
                    "source_order must contain every registered candidate ID exactly once"
                )
        registered_at = utc_now()
        stable_columns = (
            "subject_id",
            "candidate_sha256",
            "artifact_id",
            "artifact_sha256",
            "candidate_kind",
            "field_name",
            "raw_value",
            "confidence",
            "extraction_status",
            "provenance_json",
            "instruction_findings_json",
            "limitations_json",
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if source is not None and profile is not None:
                ingestion_row = connection.execute(
                    "SELECT * FROM archive_ingestion WHERE root_scope = ? "
                    "AND source_id = ? AND processing_profile_sha256 = ?",
                    (scope, source, profile),
                ).fetchone()
                if ingestion_row is not None:
                    ingestion = self._verify_archive_ingestion_row(ingestion_row)
                    expected_count = ingestion.summary.get("candidate_count")
                    if (
                        ingestion.subject_id != subject
                        or ingestion.artifact_sha256 != artifact_sha256
                        or type(expected_count) is not int
                        or expected_count != len(registrations)
                    ):
                        raise ReviewLedgerIntegrityError(
                            "candidate registration resolves to different immutable "
                            "archive ingestion candidate count or scope"
                        )
            baseline_by_id: dict[str, dict[str, Any]] = {}
            for registration in registrations:
                existing = connection.execute(
                    """
                    SELECT *
                    FROM extraction_candidate
                    WHERE root_scope = ? AND candidate_id = ?
                    """,
                    (scope, registration["candidate_id"]),
                ).fetchone()
                if existing is not None:
                    legacy_binding = existing["candidate_binding_hmac"]
                    if legacy_binding is not None:
                        baseline_by_id[registration["candidate_id"]] = (
                            self._verify_candidate_row(existing)
                        )
                    legacy_columns_match = all(
                        existing[column] == registration[column]
                        for column in stable_columns
                        if existing[column] is not None
                        and not (
                            profile is not None
                            and legacy_binding is not None
                            and column in _EXTRACTION_METADATA_COLUMNS
                        )
                    )
                    if not legacy_columns_match:
                        raise ReviewLedgerIntegrityError(
                            "registered candidate ID resolves to different immutable content"
                        )
                    if legacy_binding is None:
                        baseline_by_id[registration["candidate_id"]] = registration
                        # Exact re-ingestion is the migration authority for an
                        # unsigned legacy row. Refresh the timestamp and sign all
                        # immutable fields, including newly retained findings.
                        refreshed_at = utc_now()
                        candidate_binding = self._mac(
                            self._candidate_binding_material(
                                registration,
                                registered_at=refreshed_at,
                            )
                        )
                        connection.execute(
                            """
                            UPDATE extraction_candidate
                            SET subject_id = ?, candidate_sha256 = ?, artifact_id = ?,
                                artifact_sha256 = ?, candidate_kind = ?, field_name = ?,
                                raw_value = ?, confidence = ?, extraction_status = ?,
                                provenance_json = ?, instruction_findings_json = ?,
                                limitations_json = ?, registered_at = ?,
                                candidate_binding_hmac = ?
                            WHERE root_scope = ? AND candidate_id = ?
                            """,
                            (
                                subject,
                                registration["candidate_sha256"],
                                registration["artifact_id"],
                                registration["artifact_sha256"],
                                registration["candidate_kind"],
                                registration["field_name"],
                                registration["raw_value"],
                                registration["confidence"],
                                registration["extraction_status"],
                                registration["provenance_json"],
                                registration["instruction_findings_json"],
                                registration["limitations_json"],
                                refreshed_at,
                                candidate_binding,
                                scope,
                                registration["candidate_id"],
                            ),
                        )
                    continue
                baseline_by_id[registration["candidate_id"]] = registration
                candidate_binding = self._mac(
                    self._candidate_binding_material(
                        registration,
                        registered_at=registered_at,
                    )
                )
                connection.execute(
                    """
                    INSERT INTO extraction_candidate(
                        root_scope, subject_id, candidate_id, candidate_sha256, artifact_id,
                        artifact_sha256, candidate_kind, field_name, raw_value,
                        confidence, extraction_status, provenance_json,
                        instruction_findings_json, limitations_json, registered_at,
                        candidate_binding_hmac
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scope,
                        subject,
                        registration["candidate_id"],
                        registration["candidate_sha256"],
                        registration["artifact_id"],
                        registration["artifact_sha256"],
                        registration["candidate_kind"],
                        registration["field_name"],
                        registration["raw_value"],
                        registration["confidence"],
                        registration["extraction_status"],
                        registration["provenance_json"],
                        registration["instruction_findings_json"],
                        registration["limitations_json"],
                        registered_at,
                        candidate_binding,
                    ),
                )
            if source is not None:
                stable_keys = (
                    "root_scope",
                    "subject_id",
                    "source_id",
                    "source_order",
                    "candidate_id",
                    "candidate_sha256",
                    "artifact_sha256",
                )
                if profile is not None:
                    existing_associations = connection.execute(
                        """
                        SELECT * FROM candidate_source_profile_version
                        WHERE root_scope = ? AND source_id = ?
                          AND processing_profile_sha256 = ?
                        ORDER BY source_order
                        """,
                        (scope, source, profile),
                    ).fetchall()
                    desired_materials = tuple(
                        self._source_profile_association_material(
                            root_scope=scope,
                            subject_id=subject,
                            source_id=source,
                            processing_profile_sha256=profile,
                            source_order=ordinal,
                            candidate_id=candidate_key,
                            candidate_sha256=registration_by_id[candidate_key][
                                "candidate_sha256"
                            ],
                            artifact_sha256=artifact_sha256,
                            registered_at=registered_at,
                            extraction_metadata=self._candidate_extraction_metadata(
                                registration_by_id[candidate_key]
                            ),
                        )
                        for ordinal, candidate_key in enumerate(ordered_candidate_ids)
                    )
                    if existing_associations:
                        existing_materials = tuple(
                            self._verify_source_profile_association_row(row)
                            for row in existing_associations
                        )
                        if len(existing_materials) != len(desired_materials) or any(
                            any(existing[key] != desired[key] for key in stable_keys)
                            or existing["processing_profile_sha256"]
                            != desired["processing_profile_sha256"]
                            or existing.get(
                                "extraction_metadata",
                                self._candidate_extraction_metadata(
                                    baseline_by_id[existing["candidate_id"]]
                                ),
                            ) != desired["extraction_metadata"]
                            for existing, desired in zip(
                                existing_materials, desired_materials, strict=True
                            )
                        ):
                            raise ReviewLedgerIntegrityError(
                                "source/profile resolves to a different immutable "
                                "candidate sequence"
                            )
                    else:
                        for material in desired_materials:
                            connection.execute(
                                """
                                INSERT INTO candidate_source_profile_version(
                                    root_scope, subject_id, source_id,
                                    processing_profile_sha256, source_order,
                                    candidate_id, candidate_sha256, artifact_sha256,
                                    registered_at, binding_hmac, extraction_metadata_json
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    material["root_scope"],
                                    material["subject_id"],
                                    material["source_id"],
                                    material["processing_profile_sha256"],
                                    material["source_order"],
                                    material["candidate_id"],
                                    material["candidate_sha256"],
                                    material["artifact_sha256"],
                                    material["registered_at"],
                                    self._mac(material),
                                    _canonical_json(material["extraction_metadata"]),
                                ),
                            )
                else:
                    profile_bound = connection.execute(
                        """
                        SELECT 1 FROM candidate_source_profile_version
                        WHERE root_scope = ? AND source_id = ? LIMIT 1
                        """,
                        (scope, source),
                    ).fetchone()
                    if profile_bound is not None:
                        raise ValueError(
                            "processing_profile_sha256 is required for this source_id"
                        )
                    existing_associations = connection.execute(
                        """
                        SELECT * FROM candidate_source_version
                        WHERE root_scope = ? AND source_id = ?
                        ORDER BY source_order
                        """,
                        (scope, source),
                    ).fetchall()
                    desired_materials = tuple(
                        self._source_association_material(
                            root_scope=scope,
                            subject_id=subject,
                            source_id=source,
                            source_order=ordinal,
                            candidate_id=candidate_key,
                            candidate_sha256=registration_by_id[candidate_key][
                                "candidate_sha256"
                            ],
                            artifact_sha256=artifact_sha256,
                            registered_at=registered_at,
                        )
                        for ordinal, candidate_key in enumerate(ordered_candidate_ids)
                    )
                    if existing_associations:
                        existing_materials = tuple(
                            self._verify_source_association_row(row)
                            for row in existing_associations
                        )
                        if len(existing_materials) != len(desired_materials) or any(
                            any(existing[key] != desired[key] for key in stable_keys)
                            for existing, desired in zip(
                                existing_materials, desired_materials, strict=True
                            )
                        ):
                            raise ReviewLedgerIntegrityError(
                                "source_id resolves to a different immutable "
                                "candidate sequence"
                            )
                    else:
                        for material in desired_materials:
                            connection.execute(
                                """
                                INSERT INTO candidate_source_version(
                                    root_scope, subject_id, source_id, source_order,
                                    candidate_id, candidate_sha256, artifact_sha256,
                                    registered_at, binding_hmac
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    material["root_scope"],
                                    material["subject_id"],
                                    material["source_id"],
                                    material["source_order"],
                                    material["candidate_id"],
                                    material["candidate_sha256"],
                                    material["artifact_sha256"],
                                    material["registered_at"],
                                    self._mac(material),
                                ),
                            )
        return tuple(item["candidate_id"] for item in registrations)

    @staticmethod
    def _archive_ingestion_material(
        *,
        root_scope: str,
        subject_id: str,
        source_id: str,
        artifact_sha256: str,
        processing_profile_sha256: str,
        media_type: str,
        processed_at: str,
        summary: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "schema": "private-archive-ingestion-v1",
            "root_scope": root_scope,
            "subject_id": subject_id,
            "source_id": source_id,
            "artifact_sha256": artifact_sha256,
            "processing_profile_sha256": processing_profile_sha256,
            "media_type": media_type,
            "processed_at": processed_at,
            "summary": summary,
        }

    def _verify_archive_ingestion_row(
        self,
        row: sqlite3.Row,
    ) -> ArchiveIngestionReceipt:
        try:
            summary = json.loads(row["summary_json"])
            material = self._archive_ingestion_material(
                root_scope=row["root_scope"],
                subject_id=row["subject_id"],
                source_id=row["source_id"],
                artifact_sha256=row["artifact_sha256"],
                processing_profile_sha256=row["processing_profile_sha256"],
                media_type=row["media_type"],
                processed_at=row["processed_at"],
                summary=summary,
            )
            expected = self._mac(material)
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ReviewLedgerIntegrityError(
                "archive ingestion binding is missing or invalid; reprocess the source"
            ) from None
        binding = row["binding_hmac"]
        if (
            not isinstance(summary, dict)
            or not isinstance(binding, str)
            or not hmac.compare_digest(expected, binding)
        ):
            raise ReviewLedgerIntegrityError(
                "archive ingestion binding is missing or invalid; reprocess the source"
            )
        return ArchiveIngestionReceipt(
            root_scope=row["root_scope"],
            subject_id=row["subject_id"],
            source_id=row["source_id"],
            artifact_sha256=row["artifact_sha256"],
            processing_profile_sha256=row["processing_profile_sha256"],
            media_type=row["media_type"],
            processed_at=row["processed_at"],
            summary_json=row["summary_json"],
        )

    def archive_ingestion_for(
        self,
        *,
        root_scope: str,
        subject_id: str,
        source_id: str,
        artifact_sha256: str,
        processing_profile_sha256: str,
    ) -> ArchiveIngestionReceipt | None:
        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        source = _require_text(source_id, name="source_id", maximum=128)
        artifact_hash = _require_text(
            artifact_sha256,
            name="artifact_sha256",
            maximum=64,
        )
        profile_hash = _require_text(
            processing_profile_sha256,
            name="processing_profile_sha256",
            maximum=64,
        )
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")
        if not re.fullmatch(r"[a-f0-9]{64}", artifact_hash) or not re.fullmatch(
            r"[a-f0-9]{64}", profile_hash
        ):
            raise ValueError("archive ingestion hashes must be lowercase SHA-256 values")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM archive_ingestion
                WHERE root_scope = ? AND source_id = ?
                  AND processing_profile_sha256 = ?
                """,
                (scope, source, profile_hash),
            ).fetchone()
        if row is None:
            return None
        receipt = self._verify_archive_ingestion_row(row)
        if (
            receipt.subject_id != subject
            or receipt.artifact_sha256 != artifact_hash
        ):
            raise ReviewLedgerIntegrityError(
                "archive ingestion record does not match the selected source"
            )
        return receipt

    def record_archive_ingestion(
        self,
        *,
        root_scope: str,
        subject_id: str,
        source_id: str,
        artifact_sha256: str,
        processing_profile_sha256: str,
        media_type: str,
        summary: dict[str, Any],
    ) -> ArchiveIngestionReceipt:
        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        source = _require_text(source_id, name="source_id", maximum=128)
        artifact_hash = _require_text(
            artifact_sha256,
            name="artifact_sha256",
            maximum=64,
        )
        profile_hash = _require_text(
            processing_profile_sha256,
            name="processing_profile_sha256",
            maximum=64,
        )
        media = _require_text(media_type, name="media_type", maximum=256)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")
        if not re.fullmatch(r"[a-f0-9]{64}", artifact_hash) or not re.fullmatch(
            r"[a-f0-9]{64}", profile_hash
        ):
            raise ValueError("archive ingestion hashes must be lowercase SHA-256 values")
        if not isinstance(summary, dict):
            raise ValueError("archive ingestion summary must be an object")
        summary_json = _canonical_json(summary)
        if len(summary_json.encode("utf-8")) > MAX_ARCHIVE_INGESTION_SUMMARY_BYTES:
            raise ValueError("archive ingestion summary exceeds the byte limit")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            associations = connection.execute(
                "SELECT * FROM candidate_source_profile_version WHERE root_scope = ? "
                "AND source_id = ? AND processing_profile_sha256 = ? ORDER BY source_order",
                (scope, source, profile_hash),
            ).fetchall()
            if associations:
                expected_count = summary.get("candidate_count")
                if (
                    type(expected_count) is not int
                    or expected_count != len(associations)
                    or [row["source_order"] for row in associations]
                    != list(range(len(associations)))
                ):
                    raise ReviewLedgerIntegrityError(
                        "archive ingestion conflicts with the immutable candidate membership"
                    )
                for row in associations:
                    association = self._verify_source_profile_association_row(row)
                    if (
                        association["subject_id"] != subject
                        or association["artifact_sha256"] != artifact_hash
                    ):
                        raise ReviewLedgerIntegrityError(
                            "archive ingestion does not match its candidate membership"
                        )
            existing = connection.execute(
                """
                SELECT * FROM archive_ingestion
                WHERE root_scope = ? AND source_id = ?
                  AND processing_profile_sha256 = ?
                """,
                (scope, source, profile_hash),
            ).fetchone()
            if existing is not None:
                existing_receipt = self._verify_archive_ingestion_row(existing)
                if (
                    existing_receipt.subject_id != subject
                    or existing_receipt.artifact_sha256 != artifact_hash
                    or existing_receipt.media_type != media
                    or existing_receipt.summary_json != summary_json
                ):
                    raise ReviewLedgerIntegrityError(
                        "archive ingestion source/profile is already bound to "
                        "different immutable content"
                    )
                return existing_receipt
            processed_at = utc_now()
            material = self._archive_ingestion_material(
                root_scope=scope,
                subject_id=subject,
                source_id=source,
                artifact_sha256=artifact_hash,
                processing_profile_sha256=profile_hash,
                media_type=media,
                processed_at=processed_at,
                summary=summary,
            )
            binding = self._mac(material)
            connection.execute(
                """
                INSERT INTO archive_ingestion(
                    root_scope, subject_id, source_id, artifact_sha256,
                    processing_profile_sha256, media_type, processed_at,
                    summary_json, binding_hmac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope,
                    subject,
                    source,
                    artifact_hash,
                    profile_hash,
                    media,
                    processed_at,
                    summary_json,
                    binding,
                ),
            )
        return ArchiveIngestionReceipt(
            root_scope=scope,
            subject_id=subject,
            source_id=source,
            artifact_sha256=artifact_hash,
            processing_profile_sha256=profile_hash,
            media_type=media,
            processed_at=processed_at,
            summary_json=summary_json,
        )

    def candidate_page(
        self,
        *,
        root_scope: str,
        subject_id: str,
        after_candidate_id: str | None = None,
        limit: int = 50,
        review_status: str = "unreviewed",
    ) -> dict[str, Any]:
        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")
        if not isinstance(limit, int) or isinstance(limit, bool) or not (
            1 <= limit <= MAX_PRIVATE_LEDGER_PAGE_SIZE
        ):
            raise ValueError(
                f"limit must be between 1 and {MAX_PRIVATE_LEDGER_PAGE_SIZE}"
            )
        if review_status not in {"unreviewed", "reviewed", "all"}:
            raise ValueError("review_status must be unreviewed, reviewed, or all")
        cursor = ""
        if after_candidate_id is not None:
            cursor = _require_text(
                after_candidate_id,
                name="after_candidate_id",
                maximum=128,
            )
        with self._connect() as connection:
            connection.execute("BEGIN")
            all_candidate_rows = connection.execute(
                """
                SELECT * FROM extraction_candidate
                WHERE root_scope = ? AND subject_id = ?
                ORDER BY candidate_id
                """,
                (scope, subject),
            ).fetchall()
            candidate_registrations = {
                row["candidate_id"]: self._verify_candidate_row(row)
                for row in all_candidate_rows
            }
            receipt_rows = connection.execute(
                """
                SELECT r.*,
                       c.candidate_sha256 AS registered_candidate_sha256,
                       c.artifact_sha256 AS registered_artifact_sha256,
                       c.provenance_json AS registered_provenance_json,
                       c.raw_value AS registered_raw_value,
                       c.subject_id AS registered_subject_id,
                       c.field_name AS field_name
                FROM reviewed_extraction r
                JOIN extraction_candidate c
                  ON c.root_scope = r.root_scope
                 AND c.candidate_id = r.candidate_id
                WHERE r.root_scope = ? AND r.subject_id = ?
                ORDER BY r.receipt_id
                """,
                (scope, subject),
            ).fetchall()
            receipt_ids_by_candidate: dict[str, list[str]] = {}
            legacy_receipt_candidates: set[str] = set()
            for receipt_row in receipt_rows:
                self._verify_receipt_row(receipt_row, connection=connection)
                receipt_ids_by_candidate.setdefault(
                    receipt_row["candidate_id"], []
                ).append(receipt_row["receipt_id"])
                if (
                    receipt_row["source_id"] is None
                    and receipt_row["processing_profile_sha256"] is None
                ):
                    legacy_receipt_candidates.add(receipt_row["candidate_id"])
            action_rows = connection.execute(
                """
                SELECT * FROM candidate_review_action
                WHERE root_scope = ? AND subject_id = ?
                ORDER BY reviewed_at, action_id
                """,
                (scope, subject),
            ).fetchall()
            actions_by_candidate: dict[str, list[dict[str, Any]]] = {}
            for action_row in action_rows:
                action = self._verify_batch_action_row(action_row)
                actions_by_candidate.setdefault(action["candidate_id"], []).append(
                    action
                )

            profile_associations_by_candidate: dict[
                str, list[dict[str, Any]]
            ] = {}
            profile_association_rows = connection.execute(
                """
                SELECT * FROM candidate_source_profile_version
                WHERE root_scope = ? AND subject_id = ?
                ORDER BY candidate_id, source_id,
                         processing_profile_sha256, source_order
                """,
                (scope, subject),
            ).fetchall()
            for association_row in profile_association_rows:
                association = self._verify_source_profile_association_row(
                    association_row
                )
                registration = candidate_registrations.get(
                    association["candidate_id"]
                )
                if registration is None or any(
                    (
                        registration["candidate_sha256"]
                        != association["candidate_sha256"],
                        registration["artifact_sha256"]
                        != association["artifact_sha256"],
                        registration["subject_id"] != association["subject_id"],
                    )
                ):
                    raise ReviewLedgerIntegrityError(
                        "candidate source-profile association does not match "
                        "its immutable candidate"
                    )
                profile_associations_by_candidate.setdefault(
                    association["candidate_id"], []
                ).append(association)
            associations_by_profile: dict[tuple[str, str], list[sqlite3.Row]] = {}
            for row in profile_association_rows:
                associations_by_profile.setdefault(
                    (row["source_id"], row["processing_profile_sha256"]), []
                ).append(row)
            ingestion_rows = connection.execute(
                "SELECT * FROM archive_ingestion WHERE root_scope = ? AND subject_id = ?",
                (scope, subject),
            ).fetchall()
            for row in ingestion_rows:
                self._verify_profile_membership_count(
                    connection,
                    root_scope=scope,
                    subject_id=subject,
                    source_id=row["source_id"],
                    processing_profile_sha256=row["processing_profile_sha256"],
                    artifact_sha256=row["artifact_sha256"],
                    association_rows=sorted(
                        associations_by_profile.get(
                            (row["source_id"], row["processing_profile_sha256"]), []
                        ),
                        key=lambda item: item["source_order"],
                    ),
                )

            legacy_associations_by_candidate: dict[
                str, list[dict[str, Any]]
            ] = {}
            legacy_association_rows = connection.execute(
                """
                SELECT * FROM candidate_source_version
                WHERE root_scope = ? AND subject_id = ?
                ORDER BY candidate_id, source_id, source_order
                """,
                (scope, subject),
            ).fetchall()
            for association_row in legacy_association_rows:
                association = self._verify_source_association_row(association_row)
                registration = candidate_registrations.get(
                    association["candidate_id"]
                )
                if registration is None or any(
                    (
                        registration["candidate_sha256"]
                        != association["candidate_sha256"],
                        registration["artifact_sha256"]
                        != association["artifact_sha256"],
                        registration["subject_id"] != association["subject_id"],
                    )
                ):
                    raise ReviewLedgerIntegrityError(
                        "candidate source-version association does not match "
                        "its immutable candidate"
                    )
                legacy_associations_by_candidate.setdefault(
                    association["candidate_id"], []
                ).append(association)

            def occurrence_payload(
                candidate_row: sqlite3.Row,
                *,
                source_id: str | None,
                processing_profile_sha256: str | None,
                source_order: int | None,
                extraction_metadata: dict[str, Any] | None = None,
            ) -> dict[str, Any]:
                state = self._candidate_review_state(
                    connection,
                    candidate_row,
                    source_id=(
                        source_id
                        if processing_profile_sha256 is not None
                        else None
                    ),
                    processing_profile_sha256=processing_profile_sha256,
                )
                status = state["status"]
                action = (
                    None
                    if status == "unreviewed"
                    else ("accept" if status == "accepted" else status)
                )
                receipt_ids = state.get("receipt_ids")
                if receipt_ids is None:
                    receipt_id = state.get("receipt_id")
                    receipt_ids = [] if receipt_id is None else [receipt_id]
                return {
                    "source_id": source_id,
                    "processing_profile_sha256": processing_profile_sha256,
                    "artifact_sha256": candidate_row["artifact_sha256"],
                    "source_order": source_order,
                    "status": status,
                    "action": action,
                    "action_id": state.get("action_id"),
                    "batch_id": state.get("batch_id"),
                    "receipt_id": state.get("receipt_id"),
                    "receipt_ids": receipt_ids,
                    "extraction_metadata": (
                        extraction_metadata
                        if extraction_metadata is not None
                        else self._candidate_extraction_metadata(
                            candidate_registrations[candidate_row["candidate_id"]]
                        )
                    ),
                }

            filtered_entries: list[
                tuple[sqlite3.Row, list[dict[str, Any]], str, str | None]
            ] = []
            for row in all_candidate_rows:
                candidate_id = row["candidate_id"]
                if candidate_id <= cursor:
                    continue
                occurrences = [
                    occurrence_payload(
                        row,
                        source_id=association["source_id"],
                        processing_profile_sha256=association[
                            "processing_profile_sha256"
                        ],
                        source_order=association["source_order"],
                        extraction_metadata=association.get("extraction_metadata"),
                    )
                    for association in profile_associations_by_candidate.get(
                        candidate_id, []
                    )
                ]
                occurrences.extend(
                    occurrence_payload(
                        row,
                        source_id=association["source_id"],
                        processing_profile_sha256=None,
                        source_order=association["source_order"],
                    )
                    for association in legacy_associations_by_candidate.get(
                        candidate_id, []
                    )
                )
                legacy_actions = [
                    action
                    for action in actions_by_candidate.get(candidate_id, [])
                    if action.get("source_id") is None
                    and action.get("processing_profile_sha256") is None
                ]
                if not occurrences or (
                    profile_associations_by_candidate.get(candidate_id)
                    and not legacy_associations_by_candidate.get(candidate_id)
                    and (
                        legacy_actions
                        or candidate_id in legacy_receipt_candidates
                    )
                ):
                    occurrences.append(
                        occurrence_payload(
                            row,
                            source_id=None,
                            processing_profile_sha256=None,
                            source_order=None,
                        )
                    )
                has_unreviewed = any(
                    item["status"] == "unreviewed" for item in occurrences
                )
                has_reviewed = any(
                    item["status"] != "unreviewed" for item in occurrences
                )
                if review_status == "unreviewed" and not has_unreviewed:
                    continue
                if review_status == "reviewed" and not has_reviewed:
                    continue
                overall_state = (
                    "mixed"
                    if has_unreviewed and has_reviewed
                    else ("reviewed" if has_reviewed else "unreviewed")
                )
                occurrence_actions = {
                    item["action"]
                    for item in occurrences
                    if item["action"] is not None
                }
                review_action = (
                    None
                    if not occurrence_actions
                    else (
                        next(iter(occurrence_actions))
                        if len(occurrence_actions) == 1 and not has_unreviewed
                        else "mixed"
                    )
                )
                filtered_entries.append(
                    (row, occurrences, overall_state, review_action)
                )
                if len(filtered_entries) == limit + 1:
                    break
            page_entries = filtered_entries[:limit]
            candidates: list[dict[str, Any]] = []
            for row, occurrences, overall_state, review_action in page_entries:
                registration = candidate_registrations[row["candidate_id"]]
                candidates.append(
                    {
                        "candidate_id": registration["candidate_id"],
                        "artifact_id": registration["artifact_id"],
                        "artifact_sha256": registration["artifact_sha256"],
                        "kind": registration["candidate_kind"],
                        "field_name": registration["field_name"],
                        "raw_value": registration["raw_value"],
                        "confidence": registration["confidence"],
                        "extraction_status": registration["extraction_status"],
                        "provenance": json.loads(registration["provenance_json"]),
                        "instruction_findings": json.loads(
                            registration["instruction_findings_json"]
                        ),
                        "limitations": json.loads(
                            registration["limitations_json"]
                        ),
                        "registered_at": row["registered_at"],
                        "review_receipt_ids": receipt_ids_by_candidate.get(
                            row["candidate_id"], []
                        ),
                        "review_state": overall_state,
                        "review_action": review_action,
                        "review_occurrences": occurrences,
                    }
                )
        return {
            "root_id": scope,
            "subject_id": subject,
            "review_status": review_status,
            "candidates": candidates,
            "next_after_candidate_id": (
                page_entries[-1][0]["candidate_id"]
                if len(filtered_entries) > limit
                else None
            ),
        }

    def occurrence_review_summary(
        self,
        *,
        root_scope: str,
        subject_id: str,
        source_id: str,
        processing_profile_sha256: str,
        artifact_sha256: str,
    ) -> dict[str, Any]:
        """Return current review counts for one exact source/profile occurrence.

        ``reviewed_candidates`` and ``rejected_candidates`` are disjoint;
        together they are the completed review count.  The method verifies the
        source/profile association and its archive-ingestion receipt before
        reporting state.
        """

        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")
        source = _require_text(source_id, name="source_id", maximum=128)
        profile = _require_text(
            processing_profile_sha256,
            name="processing_profile_sha256",
            maximum=64,
        )
        if not re.fullmatch(r"[a-f0-9]{64}", profile):
            raise ValueError(
                "processing_profile_sha256 must be a lowercase SHA-256 value"
            )
        artifact_hash = _require_text(
            artifact_sha256, name="artifact_sha256", maximum=64
        )
        if not re.fullmatch(r"[a-f0-9]{64}", artifact_hash):
            raise ValueError("artifact_sha256 must be a lowercase SHA-256 value")

        with self._connect() as connection:
            connection.execute("BEGIN")
            self._profile_archive_ingestion_snapshot(
                connection,
                root_scope=scope,
                subject_id=subject,
                source_id=source,
                processing_profile_sha256=profile,
                artifact_sha256=artifact_hash,
            )
            candidates = self._document_candidate_snapshot(
                connection,
                root_scope=scope,
                subject_id=subject,
                source_id=source,
                processing_profile_sha256=profile,
                artifact_sha256=artifact_hash,
                candidate_limit=MAX_ARCHIVE_REVIEW_CANDIDATES,
            )
        statuses = [item["review_state"]["status"] for item in candidates]
        unreviewed_count = statuses.count("unreviewed")
        rejected_count = statuses.count("reject")
        reviewed_count = sum(
            status in {"accept", "accepted", "edit"} for status in statuses
        )
        if unreviewed_count + reviewed_count + rejected_count != len(statuses):
            raise ReviewLedgerIntegrityError(
                "candidate occurrence has an unsupported review state"
            )
        return {
            "root_id": scope,
            "subject_id": subject,
            "source_id": source,
            "processing_profile_sha256": profile,
            "artifact_sha256": artifact_hash,
            "total_candidates": len(statuses),
            "unreviewed_candidates": unreviewed_count,
            "reviewed_candidates": reviewed_count,
            "rejected_candidates": rejected_count,
            "completed_candidates": reviewed_count + rejected_count,
            "needs_review": unreviewed_count > 0,
        }

    @staticmethod
    def _candidate_source_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        provenance = item["provenance"][0]

        def located(value: Any) -> tuple[int, Any]:
            return (1, 0) if value is None else (0, value)

        return (
            located(provenance.get("page")),
            located(provenance.get("line_start")),
            located(provenance.get("row_index")),
            located(provenance.get("column_index")),
            provenance.get("block_id") or "",
            item["candidate_id"],
        )

    @staticmethod
    def _batch_action_material_from_row(row: sqlite3.Row) -> dict[str, Any]:
        source_id = row["source_id"]
        profile = row["processing_profile_sha256"]
        if (source_id is None) != (profile is None):
            raise ValueError("occurrence action has incomplete source/profile scope")
        material = {
            "schema": (
                "private-candidate-review-action-v2"
                if profile is not None
                else "private-candidate-review-action-v1"
            ),
            "action_id": row["action_id"],
            "root_scope": row["root_scope"],
            "subject_id": row["subject_id"],
            "artifact_sha256": row["artifact_sha256"],
            "candidate_id": row["candidate_id"],
            "candidate_sha256": row["candidate_sha256"],
            "batch_id": row["batch_id"],
            "action": row["action"],
            "original_field_name": row["original_field_name"],
            "original_source_value": row["original_source_value"],
            "corrected_field_name": row["corrected_field_name"],
            "corrected_value": row["corrected_value"],
            "reviewer_id": row["reviewer_id"],
            "review_note": row["review_note"],
            "reviewed_at": row["reviewed_at"],
            "receipt_id": row["receipt_id"],
        }
        if profile is not None:
            material["source_id"] = source_id
            material["processing_profile_sha256"] = profile
        return material

    def _verify_batch_action_row(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            material = self._batch_action_material_from_row(row)
            expected = self._mac(material)
            binding = row["binding_hmac"]
        except (IndexError, KeyError, TypeError, ValueError):
            raise ReviewLedgerIntegrityError(
                "batch review action binding is missing or invalid"
            ) from None
        if not isinstance(binding, str) or not hmac.compare_digest(expected, binding):
            raise ReviewLedgerIntegrityError(
                "batch review action binding is missing or invalid"
            )
        action = material["action"]
        if action == "accept":
            valid_shape = (
                material["receipt_id"] is not None
                and material["corrected_field_name"] is None
                and material["corrected_value"] is None
            )
        elif action == "edit":
            valid_shape = (
                material["receipt_id"] is not None
                and isinstance(material["corrected_value"], str)
                and bool(material["corrected_value"].strip())
            )
        elif action == "reject":
            valid_shape = (
                material["receipt_id"] is None
                and material["corrected_field_name"] is None
                and material["corrected_value"] is None
                and isinstance(material["review_note"], str)
                and bool(material["review_note"].strip())
            )
        else:
            valid_shape = False
        if not valid_shape:
            raise ReviewLedgerIntegrityError("batch review action shape is invalid")
        return material

    def _candidate_review_state(
        self,
        connection: sqlite3.Connection,
        candidate_row: sqlite3.Row,
        *,
        source_id: str | None,
        processing_profile_sha256: str | None,
    ) -> dict[str, Any]:
        if processing_profile_sha256 is not None:
            application_rows = connection.execute(
                """
                SELECT a.batch_id
                FROM review_batch_application a
                JOIN review_batch_snapshot s ON s.batch_id = a.batch_id
                WHERE s.root_scope = ? AND s.subject_id = ?
                  AND s.source_id = ? AND s.processing_profile_sha256 = ?
                  AND s.artifact_sha256 = ?
                """,
                (
                    candidate_row["root_scope"],
                    candidate_row["subject_id"],
                    source_id,
                    processing_profile_sha256,
                    candidate_row["artifact_sha256"],
                ),
            ).fetchall()
        else:
            application_rows = connection.execute(
                """
                SELECT a.batch_id
                FROM review_batch_application a
                JOIN review_batch_snapshot s ON s.batch_id = a.batch_id
                WHERE s.root_scope = ? AND s.subject_id = ?
                  AND s.processing_profile_sha256 IS NULL
                  AND s.artifact_sha256 = ?
                """,
                (
                    candidate_row["root_scope"],
                    candidate_row["subject_id"],
                    candidate_row["artifact_sha256"],
                ),
            ).fetchall()
        for application_row in application_rows:
            if (
                isinstance(connection, _ReviewLedgerConnection)
                and application_row["batch_id"] in connection.verified_effect_batches
            ):
                continue
            application_row = connection.execute(
                "SELECT * FROM review_batch_application WHERE batch_id = ?",
                (application_row["batch_id"],),
            ).fetchone()
            if application_row is None:
                raise ReviewLedgerIntegrityError("review batch application is missing")
            snapshot_row = connection.execute(
                "SELECT * FROM review_batch_snapshot WHERE batch_id = ?",
                (application_row["batch_id"],),
            ).fetchone()
            if snapshot_row is None:
                raise ReviewLedgerIntegrityError(
                    "review batch application snapshot is missing"
                )
            self._verify_review_batch_snapshot_row(snapshot_row)
            outcome = self._application_outcome(connection, application_row)
            actions = outcome.get("actions")
            if isinstance(actions, list) and any(
                isinstance(action, dict)
                and action.get("candidate_id") == candidate_row["candidate_id"]
                for action in actions
            ):
                self._verify_applied_batch_effects(
                    connection,
                    batch_id=application_row["batch_id"],
                    outcome=outcome,
                )
        if processing_profile_sha256 is not None:
            action_rows = connection.execute(
                """
                SELECT * FROM candidate_review_action
                WHERE root_scope = ? AND candidate_id = ?
                  AND source_id = ? AND processing_profile_sha256 = ?
                ORDER BY reviewed_at, action_id
                """,
                (
                    candidate_row["root_scope"],
                    candidate_row["candidate_id"],
                    source_id,
                    processing_profile_sha256,
                ),
            ).fetchall()
        else:
            action_rows = connection.execute(
                """
                SELECT * FROM candidate_review_action
                WHERE root_scope = ? AND candidate_id = ?
                  AND source_id IS NULL
                  AND processing_profile_sha256 IS NULL
                ORDER BY reviewed_at, action_id
                """,
                (candidate_row["root_scope"], candidate_row["candidate_id"]),
            ).fetchall()
        action_materials = tuple(
            self._verify_batch_action_row(row) for row in action_rows
        )
        for action in action_materials:
            if (
                isinstance(connection, _ReviewLedgerConnection)
                and action["batch_id"] in connection.verified_effect_batches
            ):
                continue
            application_row = connection.execute(
                "SELECT * FROM review_batch_application WHERE batch_id = ?",
                (action["batch_id"],),
            ).fetchone()
            if application_row is None:
                raise ReviewLedgerIntegrityError(
                    "batch review action application is missing"
                )
            outcome = self._application_outcome(connection, application_row)
            self._verify_applied_batch_effects(
                connection, batch_id=action["batch_id"], outcome=outcome
            )
        receipt_query = """
            SELECT r.*,
                   c.candidate_sha256 AS registered_candidate_sha256,
                   c.artifact_sha256 AS registered_artifact_sha256,
                   c.provenance_json AS registered_provenance_json,
                   c.raw_value AS registered_raw_value,
                   c.subject_id AS registered_subject_id,
                   c.field_name AS field_name
            FROM reviewed_extraction r
            JOIN extraction_candidate c
              ON c.root_scope = r.root_scope
             AND c.candidate_id = r.candidate_id
            WHERE r.root_scope = ? AND r.candidate_id = ?
        """
        receipt_params: tuple[Any, ...] = (
            candidate_row["root_scope"],
            candidate_row["candidate_id"],
        )
        if processing_profile_sha256 is not None:
            receipt_query += (
                " AND r.source_id = ? AND r.processing_profile_sha256 = ?"
            )
            receipt_params += (source_id, processing_profile_sha256)
        else:
            receipt_query += (
                " AND r.source_id IS NULL "
                "AND r.processing_profile_sha256 IS NULL"
            )
        receipt_query += " ORDER BY r.reviewed_at, r.receipt_id"
        receipt_rows = connection.execute(receipt_query, receipt_params).fetchall()
        for receipt_row in receipt_rows:
            self._verify_receipt_row(receipt_row, connection=connection)

        if action_materials:
            if len(action_materials) != 1:
                raise ReviewLedgerIntegrityError(
                    "candidate has multiple immutable batch review actions"
                )
            action = action_materials[0]
            if (
                action["subject_id"] != candidate_row["subject_id"]
                or action["artifact_sha256"] != candidate_row["artifact_sha256"]
                or action["candidate_sha256"] != candidate_row["candidate_sha256"]
                or action["original_field_name"] != candidate_row["field_name"]
                or action["original_source_value"] != candidate_row["raw_value"]
                or action.get("source_id") != (
                    source_id if processing_profile_sha256 is not None else None
                )
                or action.get("processing_profile_sha256")
                != processing_profile_sha256
            ):
                raise ReviewLedgerIntegrityError(
                    "batch review action does not match its immutable candidate"
                )
            receipt_ids = tuple(row["receipt_id"] for row in receipt_rows)
            if action["action"] == "reject":
                if receipt_ids:
                    raise ReviewLedgerIntegrityError(
                        "rejected candidate unexpectedly has a verified record"
                    )
            elif receipt_ids != (action["receipt_id"],):
                raise ReviewLedgerIntegrityError(
                    "batch review action does not match its verified receipt"
                )
            return {
                "status": action["action"],
                "action_id": action["action_id"],
                "batch_id": action["batch_id"],
                "receipt_id": action["receipt_id"],
            }

        if receipt_rows:
            return {
                "status": "accepted",
                "action_id": None,
                "batch_id": None,
                "receipt_ids": [row["receipt_id"] for row in receipt_rows],
            }
        return {
            "status": "unreviewed",
            "action_id": None,
            "batch_id": None,
            "receipt_id": None,
        }

    def _snapshot_candidate(
        self,
        connection: sqlite3.Connection,
        candidate_row: sqlite3.Row,
        *,
        source_order: int | None,
        source_id: str | None,
        processing_profile_sha256: str | None,
        extraction_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        registration = self._verify_candidate_row(candidate_row)
        if extraction_metadata is not None:
            registration = {**registration, **extraction_metadata}
        return {
            "candidate_id": registration["candidate_id"],
            "candidate_sha256": registration["candidate_sha256"],
            "artifact_id": registration["artifact_id"],
            "artifact_sha256": registration["artifact_sha256"],
            "source_order": source_order,
            "kind": registration["candidate_kind"],
            "field_name": registration["field_name"],
            "raw_value": registration["raw_value"],
            "confidence": registration["confidence"],
            "extraction_status": registration["extraction_status"],
            "provenance": json.loads(registration["provenance_json"]),
            "instruction_findings": json.loads(
                registration["instruction_findings_json"]
            ),
            "limitations": json.loads(registration["limitations_json"]),
            "registered_at": candidate_row["registered_at"],
            "review_state": self._candidate_review_state(
                connection,
                candidate_row,
                source_id=source_id,
                processing_profile_sha256=processing_profile_sha256,
            ),
        }

    def _document_candidate_snapshot(
        self,
        connection: sqlite3.Connection,
        *,
        root_scope: str,
        subject_id: str,
        source_id: str | None,
        processing_profile_sha256: str | None,
        artifact_sha256: str,
        candidate_limit: int | None = None,
    ) -> list[dict[str, Any]]:
        if candidate_limit is None:
            candidate_limit = MAX_DOCUMENT_REVIEW_CANDIDATES
        if source_id is not None:
            if processing_profile_sha256 is not None:
                association_rows = connection.execute(
                    """
                    SELECT * FROM candidate_source_profile_version
                    WHERE root_scope = ? AND source_id = ?
                      AND processing_profile_sha256 = ?
                    ORDER BY source_order
                    LIMIT ?
                    """,
                    (
                        root_scope,
                        source_id,
                        processing_profile_sha256,
                        candidate_limit + 1,
                    ),
                ).fetchall()
                association_verifier = self._verify_source_profile_association_row
            else:
                profile_bound = connection.execute(
                    """
                    SELECT 1 FROM candidate_source_profile_version
                    WHERE root_scope = ? AND source_id = ? LIMIT 1
                    """,
                    (root_scope, source_id),
                ).fetchone()
                if profile_bound is not None:
                    raise ValueError(
                        "processing_profile_sha256 is required for this source_id"
                    )
                association_rows = connection.execute(
                    """
                    SELECT * FROM candidate_source_version
                    WHERE root_scope = ? AND source_id = ?
                    ORDER BY source_order
                    LIMIT ?
                    """,
                    (root_scope, source_id, candidate_limit + 1),
                ).fetchall()
                association_verifier = self._verify_source_association_row
            if len(association_rows) > candidate_limit:
                raise ValueError(
                    "document candidate count exceeds the batch review hard cap"
                )
            if processing_profile_sha256 is not None:
                self._verify_profile_membership_count(
                    connection,
                    root_scope=root_scope,
                    subject_id=subject_id,
                    source_id=source_id,
                    processing_profile_sha256=processing_profile_sha256,
                    artifact_sha256=artifact_sha256,
                    association_rows=association_rows,
                )
            if not association_rows and processing_profile_sha256 is None:
                raise UnknownReviewCandidateError(
                    "source/profile has no registered candidates in the selected "
                    "private root"
                )
            output: list[dict[str, Any]] = []
            for association_row in association_rows:
                association = association_verifier(association_row)
                if (
                    association["subject_id"] != subject_id
                    or association["artifact_sha256"] != artifact_sha256
                    or association.get("processing_profile_sha256")
                    != processing_profile_sha256
                ):
                    raise ValueError(
                        "source/profile does not match the selected subject and artifact"
                    )
                candidate_row = connection.execute(
                    """
                    SELECT * FROM extraction_candidate
                    WHERE root_scope = ? AND candidate_id = ?
                    """,
                    (root_scope, association["candidate_id"]),
                ).fetchone()
                if candidate_row is None:
                    raise StaleReviewBatchError(
                        "source-version candidate registration is missing"
                    )
                if (
                    candidate_row["subject_id"] != subject_id
                    or candidate_row["artifact_sha256"] != artifact_sha256
                    or candidate_row["candidate_sha256"]
                    != association["candidate_sha256"]
                ):
                    raise ReviewLedgerIntegrityError(
                        "source-version association does not match its candidate"
                    )
                output.append(
                    self._snapshot_candidate(
                        connection,
                        candidate_row,
                        source_order=association["source_order"],
                        source_id=(
                            source_id
                            if processing_profile_sha256 is not None
                            else None
                        ),
                        processing_profile_sha256=processing_profile_sha256,
                        extraction_metadata=association.get("extraction_metadata"),
                    )
                )
            return output

        if processing_profile_sha256 is not None:
            raise ValueError("processing_profile_sha256 requires source_id")

        bound_source = connection.execute(
            """
            SELECT source_id FROM (
                SELECT root_scope, subject_id, artifact_sha256, source_id
                FROM candidate_source_version
                UNION ALL
                SELECT root_scope, subject_id, artifact_sha256, source_id
                FROM candidate_source_profile_version
                UNION ALL
                SELECT root_scope, subject_id, artifact_sha256, source_id
                FROM archive_ingestion
            )
            WHERE root_scope = ? AND subject_id = ? AND artifact_sha256 = ?
            LIMIT 1
            """,
            (root_scope, subject_id, artifact_sha256),
        ).fetchone()
        if bound_source is not None:
            raise ValueError(
                "source_id is required for source-version-bound candidates"
            )
        candidate_rows = connection.execute(
            """
            SELECT * FROM extraction_candidate
            WHERE root_scope = ? AND subject_id = ? AND artifact_sha256 = ?
            LIMIT ?
            """,
            (
                root_scope,
                subject_id,
                artifact_sha256,
                candidate_limit + 1,
            ),
        ).fetchall()
        if not candidate_rows:
            raise UnknownReviewCandidateError(
                "artifact has no registered candidates for the selected subject"
            )
        if len(candidate_rows) > candidate_limit:
            raise ValueError("document candidate count exceeds the batch review hard cap")
        output = [
            self._snapshot_candidate(
                connection,
                row,
                source_order=None,
                source_id=None,
                processing_profile_sha256=None,
            )
            for row in candidate_rows
        ]
        output.sort(key=self._candidate_source_sort_key)
        return output

    def _verify_profile_membership_count(
        self,
        connection: sqlite3.Connection,
        *,
        root_scope: str,
        subject_id: str,
        source_id: str,
        processing_profile_sha256: str,
        artifact_sha256: str,
        association_rows: list[sqlite3.Row],
    ) -> None:
        row = connection.execute(
            "SELECT * FROM archive_ingestion WHERE root_scope = ? "
            "AND source_id = ? AND processing_profile_sha256 = ?",
            (root_scope, source_id, processing_profile_sha256),
        ).fetchone()
        if row is None and not association_rows:
            raise UnknownReviewCandidateError(
                "source/profile has no registered candidates in the selected private root"
            )
        ingestion = self._profile_archive_ingestion_snapshot(
            connection,
            root_scope=root_scope,
            subject_id=subject_id,
            source_id=source_id,
            processing_profile_sha256=processing_profile_sha256,
            artifact_sha256=artifact_sha256,
        )
        expected_count = ingestion["summary"].get("candidate_count")
        if (
            type(expected_count) is not int
            or expected_count < 0
            or expected_count != len(association_rows)
            or [item["source_order"] for item in association_rows]
            != list(range(expected_count))
        ):
            raise ReviewLedgerIntegrityError(
                "source-profile candidate membership is incomplete or invalid"
            )
        for association_row in association_rows:
            association = self._verify_source_profile_association_row(association_row)
            if (
                association["subject_id"] != subject_id
                or association["artifact_sha256"] != artifact_sha256
            ):
                raise ReviewLedgerIntegrityError(
                    "source-profile candidate membership does not match its ingestion"
                )
        if isinstance(connection, _ReviewLedgerConnection):
            connection.verified_memberships.add(
                (root_scope, source_id, processing_profile_sha256)
            )

    def _profile_archive_ingestion_snapshot(
        self,
        connection: sqlite3.Connection,
        *,
        root_scope: str,
        subject_id: str,
        source_id: str,
        processing_profile_sha256: str,
        artifact_sha256: str,
    ) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT * FROM archive_ingestion
            WHERE root_scope = ? AND source_id = ?
              AND processing_profile_sha256 = ?
            """,
            (root_scope, source_id, processing_profile_sha256),
        ).fetchone()
        if row is None:
            raise ReviewLedgerIntegrityError(
                "profile-bound review requires a verified archive ingestion receipt"
            )
        receipt = self._verify_archive_ingestion_row(row)
        if (
            receipt.subject_id != subject_id
            or receipt.artifact_sha256 != artifact_sha256
        ):
            raise ReviewLedgerIntegrityError(
                "archive ingestion receipt does not match the review occurrence"
            )
        return receipt.to_dict()

    @staticmethod
    def _review_batch_snapshot_material(
        *,
        root_scope: str,
        subject_id: str,
        source_id: str | None,
        processing_profile_sha256: str | None,
        archive_ingestion: dict[str, Any] | None,
        artifact_id: str,
        artifact_sha256: str,
        prepared_at: str,
        candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if processing_profile_sha256 is not None and (
            source_id is None or not isinstance(archive_ingestion, dict)
        ):
            raise ValueError(
                "profile-bound snapshot requires source and archive ingestion receipt"
            )
        material = {
            "schema": (
                "private-document-review-snapshot-v2"
                if processing_profile_sha256 is not None
                else "private-document-review-snapshot-v1"
            ),
            "root_scope": root_scope,
            "subject_id": subject_id,
            "source_id": source_id,
            "artifact_id": artifact_id,
            "artifact_sha256": artifact_sha256,
            "prepared_at": prepared_at,
            "candidate_count": len(candidates),
            "candidates": candidates,
        }
        if processing_profile_sha256 is not None:
            material["processing_profile_sha256"] = processing_profile_sha256
            material["archive_ingestion"] = archive_ingestion
        return material

    def _verify_review_batch_snapshot_row(
        self,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        try:
            candidates = json.loads(row["candidates_json"])
            if not isinstance(candidates, list):
                raise ValueError("candidates must be an array")
            if not (1 <= len(candidates) <= MAX_DOCUMENT_REVIEW_CANDIDATES):
                raise ValueError("candidate count outside hard cap")
            if len(row["candidates_json"].encode("utf-8")) > (
                MAX_REVIEW_BATCH_JSON_BYTES
            ):
                raise ValueError("candidate snapshot exceeds byte limit")
            if row["processing_profile_sha256"] is not None:
                archive_ingestion = json.loads(row["archive_ingestion_json"])
                if not isinstance(archive_ingestion, dict):
                    raise ValueError("archive ingestion snapshot must be an object")
            else:
                if row["archive_ingestion_json"] is not None:
                    raise ValueError(
                        "legacy snapshot has unexpected archive ingestion material"
                    )
                archive_ingestion = None
            material = self._review_batch_snapshot_material(
                root_scope=row["root_scope"],
                subject_id=row["subject_id"],
                source_id=row["source_id"],
                processing_profile_sha256=row["processing_profile_sha256"],
                archive_ingestion=archive_ingestion,
                artifact_id=row["artifact_id"],
                artifact_sha256=row["artifact_sha256"],
                prepared_at=row["prepared_at"],
                candidates=candidates,
            )
            snapshot_sha256 = _json_sha256(material)
            binding_version = (
                "v2" if row["processing_profile_sha256"] is not None else "v1"
            )
            expected_batch_id = "rbatch_" + self._mac(
                {
                    "schema": f"private-document-review-batch-id-{binding_version}",
                    "snapshot_sha256": snapshot_sha256,
                    "prepared_at": row["prepared_at"],
                }
            )[:32]
            expected_binding = self._mac(
                {
                    "schema": (
                        "private-document-review-snapshot-binding-"
                        f"{binding_version}"
                    ),
                    "batch_id": expected_batch_id,
                    "snapshot_sha256": snapshot_sha256,
                    "snapshot": material,
                }
            )
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ReviewLedgerIntegrityError(
                "review batch snapshot binding is missing or invalid"
            ) from None
        if (
            row["candidate_count"] != len(candidates)
            or not hmac.compare_digest(snapshot_sha256, row["snapshot_sha256"])
            or not hmac.compare_digest(expected_batch_id, row["batch_id"])
            or not hmac.compare_digest(expected_binding, row["binding_hmac"])
        ):
            raise ReviewLedgerIntegrityError(
                "review batch snapshot binding is missing or invalid"
            )
        return material

    def _batch_snapshot(
        self, connection: sqlite3.Connection, batch_id: str
    ) -> dict[str, Any]:
        if isinstance(connection, _ReviewLedgerConnection):
            cached = connection.snapshot_materials.get(batch_id)
            if cached is not None:
                return cached
        row = connection.execute(
            "SELECT * FROM review_batch_snapshot WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if row is None:
            raise ReviewLedgerIntegrityError("review receipt batch snapshot is missing")
        snapshot = self._verify_review_batch_snapshot_row(row)
        if isinstance(connection, _ReviewLedgerConnection):
            connection.snapshot_materials[batch_id] = snapshot
        return snapshot

    def prepare_review_batch(
        self,
        *,
        root_scope: str,
        subject_id: str,
        artifact_sha256: str,
        source_id: str | None = None,
        processing_profile_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Freeze one complete, ordered source-version candidate snapshot."""

        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")
        artifact_hash = _require_text(
            artifact_sha256, name="artifact_sha256", maximum=64
        )
        if not re.fullmatch(r"[a-f0-9]{64}", artifact_hash):
            raise ValueError("artifact_sha256 must be a lowercase SHA-256 value")
        source = (
            _require_text(source_id, name="source_id", maximum=128)
            if source_id is not None
            else None
        )
        profile: str | None = None
        if processing_profile_sha256 is not None:
            if source is None:
                raise ValueError("processing_profile_sha256 requires source_id")
            profile = _require_text(
                processing_profile_sha256,
                name="processing_profile_sha256",
                maximum=64,
            )
            if not re.fullmatch(r"[a-f0-9]{64}", profile):
                raise ValueError(
                    "processing_profile_sha256 must be a lowercase SHA-256 value"
                )
        artifact_id = deterministic_id("art", artifact_hash)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            candidates = self._document_candidate_snapshot(
                connection,
                root_scope=scope,
                subject_id=subject,
                source_id=source,
                processing_profile_sha256=profile,
                artifact_sha256=artifact_hash,
            )
            if not any(
                item["review_state"]["status"] == "unreviewed"
                for item in candidates
            ):
                raise ValueError("document has no unreviewed candidates")
            archive_ingestion = (
                self._profile_archive_ingestion_snapshot(
                    connection,
                    root_scope=scope,
                    subject_id=subject,
                    source_id=source,
                    processing_profile_sha256=profile,
                    artifact_sha256=artifact_hash,
                )
                if source is not None and profile is not None
                else None
            )
            prepared_at = utc_now()
            material = self._review_batch_snapshot_material(
                root_scope=scope,
                subject_id=subject,
                source_id=source,
                processing_profile_sha256=profile,
                archive_ingestion=archive_ingestion,
                artifact_id=artifact_id,
                artifact_sha256=artifact_hash,
                prepared_at=prepared_at,
                candidates=candidates,
            )
            candidates_json = _canonical_json(candidates)
            if len(candidates_json.encode("utf-8")) > MAX_REVIEW_BATCH_JSON_BYTES:
                raise ValueError("review batch snapshot exceeds the byte limit")
            snapshot_sha256 = _json_sha256(material)
            binding_version = "v2" if profile is not None else "v1"
            batch_id = "rbatch_" + self._mac(
                {
                    "schema": f"private-document-review-batch-id-{binding_version}",
                    "snapshot_sha256": snapshot_sha256,
                    "prepared_at": prepared_at,
                }
            )[:32]
            binding = self._mac(
                {
                    "schema": (
                        "private-document-review-snapshot-binding-"
                        f"{binding_version}"
                    ),
                    "batch_id": batch_id,
                    "snapshot_sha256": snapshot_sha256,
                    "snapshot": material,
                }
            )
            connection.execute(
                """
                INSERT INTO review_batch_snapshot(
                    batch_id, root_scope, subject_id, source_id,
                    processing_profile_sha256, artifact_id, artifact_sha256,
                    prepared_at, candidate_count,
                    candidates_json, archive_ingestion_json,
                    snapshot_sha256, binding_hmac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    batch_id,
                    scope,
                    subject,
                    source,
                    profile,
                    artifact_id,
                    artifact_hash,
                    prepared_at,
                    len(candidates),
                    candidates_json,
                    (
                        _canonical_json(archive_ingestion)
                        if archive_ingestion is not None
                        else None
                    ),
                    snapshot_sha256,
                    binding,
                ),
            )
        return {
            "batch_id": batch_id,
            "snapshot_sha256": snapshot_sha256,
            "root_id": scope,
            "subject_id": subject,
            "source_id": source,
            "processing_profile_sha256": profile,
            "archive_ingestion": archive_ingestion,
            "artifact_id": artifact_id,
            "artifact_sha256": artifact_hash,
            "prepared_at": prepared_at,
            "candidate_count": len(candidates),
            "actionable_candidate_count": sum(
                item["review_state"]["status"] == "unreviewed"
                for item in candidates
            ),
            "candidates": candidates,
        }

    def _normalize_batch_decisions(
        self,
        *,
        candidates: list[dict[str, Any]],
        archive_ingestion: dict[str, Any] | None,
        default_action: str,
        decisions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if default_action not in {"accept_all", "no_default"}:
            raise ValueError("default_action must be accept_all or no_default")
        if not isinstance(decisions, list):
            raise ValueError("decisions must be an array")
        if len(decisions) > MAX_DOCUMENT_REVIEW_CANDIDATES:
            raise ValueError("decision count exceeds the batch review hard cap")

        by_id = {item["candidate_id"]: item for item in candidates}
        if len(by_id) != len(candidates):
            raise ReviewLedgerIntegrityError(
                "review batch snapshot contains duplicate candidate IDs"
            )
        actionable = {
            candidate_id: item
            for candidate_id, item in by_id.items()
            if item["review_state"]["status"] == "unreviewed"
        }
        explicit: dict[str, dict[str, Any]] = {}
        if archive_ingestion is None:
            safe_document_for_implicit_accept = True
        else:
            summary = archive_ingestion.get("summary")
            safe_document_for_implicit_accept = (
                isinstance(summary, dict)
                and summary.get("complete") is True
                and type(summary.get("failure_count")) is int
                and summary.get("failure_count") == 0
                and isinstance(summary.get("failure_codes", []), (list, tuple))
                and not summary.get("failure_codes", [])
                and isinstance(summary.get("limitations", []), (list, tuple))
                and not summary.get("limitations", [])
                and summary.get("ocr_required") is False
            )
        for raw_decision in decisions:
            if not isinstance(raw_decision, dict):
                raise ValueError("each batch decision must be an object")
            candidate_id = _require_text(
                raw_decision.get("candidate_id"),
                name="decision candidate_id",
                maximum=128,
            )
            if candidate_id in explicit:
                raise ValueError("batch decisions contain duplicate candidate IDs")
            candidate = by_id.get(candidate_id)
            if candidate is None:
                raise UnknownReviewCandidateError(
                    "batch decision references a candidate absent from the frozen snapshot"
                )
            if candidate_id not in actionable:
                raise StaleReviewBatchError(
                    "batch decision references an already-reviewed snapshot candidate"
                )
            action = raw_decision.get("action")
            if action not in {"accept", "edit", "reject"}:
                raise ValueError("decision action must be accept, edit, or reject")
            allowed_keys = {"candidate_id", "action", "note"}
            if action == "edit":
                allowed_keys.update(
                    {
                        "corrected_field_name",
                        "corrected_raw_value",
                        "corrected_source_statement",
                    }
                )
            unknown_keys = set(raw_decision) - allowed_keys
            if unknown_keys:
                raise ValueError(
                    "batch decision contains unsupported fields: "
                    + ", ".join(sorted(unknown_keys))
                )
            note = raw_decision.get("note")
            if note is not None:
                note = _require_exact_text(note, name="decision note", maximum=4096)
            if action == "reject" and note is None:
                raise ValueError("reject decisions require an audit note")
            if action == "edit" and note is None:
                raise ValueError("edit decisions require an audit note")

            corrected_field_name: str | None = None
            corrected_value: str | None = None
            if action == "edit":
                if candidate["instruction_findings"]:
                    raise ReviewLedgerIntegrityError(
                        "instruction-like candidate cannot be promoted by batch review"
                    )
                if candidate["kind"] == CandidateKind.FIELD.value:
                    if "corrected_source_statement" in raw_decision:
                        raise ValueError(
                            "field edit does not accept corrected_source_statement"
                        )
                    corrected_field_name = _require_exact_text(
                        raw_decision.get("corrected_field_name"),
                        name="corrected_field_name",
                        maximum=512,
                    )
                    corrected_value = _require_exact_text(
                        raw_decision.get("corrected_raw_value"),
                        name="corrected_raw_value",
                        maximum=65_536,
                    )
                    if (
                        corrected_field_name == candidate["field_name"]
                        and corrected_value == candidate["raw_value"]
                    ):
                        raise ValueError(
                            "edit must change the exact field name or source value"
                        )
                    corrected_texts = (
                        corrected_field_name,
                        corrected_value,
                        f"{corrected_field_name}: {corrected_value}",
                        f"{corrected_field_name} {corrected_value}",
                    )
                else:
                    if (
                        "corrected_field_name" in raw_decision
                        or "corrected_raw_value" in raw_decision
                    ):
                        raise ValueError(
                            "statement edit accepts corrected_source_statement only"
                        )
                    corrected_value = _require_exact_text(
                        raw_decision.get("corrected_source_statement"),
                        name="corrected_source_statement",
                        maximum=65_536,
                    )
                    if corrected_value == candidate["raw_value"]:
                        raise ValueError("edit must change the exact source statement")
                    corrected_texts = (corrected_value,)
                if any(
                    self._instruction_detector.scan(text)
                    for text in corrected_texts
                ):
                    raise ReviewLedgerIntegrityError(
                        "instruction-like corrected text cannot be promoted by "
                        "batch review"
                    )
            elif any(
                key in raw_decision
                for key in (
                    "corrected_field_name",
                    "corrected_raw_value",
                    "corrected_source_statement",
                )
            ):
                raise ValueError("only edit decisions accept corrected values")

            if action == "accept" and candidate["instruction_findings"]:
                raise ReviewLedgerIntegrityError(
                    "instruction-like candidate cannot be promoted by batch review"
                )
            explicit[candidate_id] = {
                "candidate_id": candidate_id,
                "action": action,
                "corrected_field_name": corrected_field_name,
                "corrected_value": corrected_value,
                "note": note,
                "explicit": True,
            }

        normalized: list[dict[str, Any]] = []
        for candidate in candidates:
            candidate_id = candidate["candidate_id"]
            if candidate_id not in actionable:
                continue
            decision = explicit.get(candidate_id)
            if decision is None:
                if default_action == "no_default":
                    raise ValueError(
                        "no_default requires an explicit decision for every "
                        "unreviewed snapshot candidate"
                    )
                safe_for_implicit_accept = (
                    safe_document_for_implicit_accept
                    and candidate["extraction_status"]
                    == VerificationStatus.EXTRACTED.value
                    and not candidate["instruction_findings"]
                    and not candidate["limitations"]
                )
                if not safe_for_implicit_accept:
                    raise ValueError(
                        "accept_all requires an explicit decision for candidates "
                        "with review status, instruction findings, or mapping limitations"
                    )
                decision = {
                    "candidate_id": candidate_id,
                    "action": "accept",
                    "corrected_field_name": None,
                    "corrected_value": None,
                    "note": None,
                    "explicit": False,
                }
            normalized.append(decision)
        if not normalized:
            raise StaleReviewBatchError("review batch has no unreviewed candidates")
        return normalized

    @staticmethod
    def _batch_record_material(
        *,
        root_scope: str,
        subject_id: str,
        candidate: dict[str, Any],
        batch_id: str,
        source_id: str | None,
        processing_profile_sha256: str | None,
        decision: dict[str, Any],
        reviewer_id: str,
        reviewed_at: str,
    ) -> dict[str, Any]:
        record_type = (
            "observation"
            if candidate["kind"] == CandidateKind.FIELD.value
            else "statement"
        )
        material = {
            "schema": (
                "private-review-record-v4"
                if processing_profile_sha256 is not None
                else "private-review-record-v3"
            ),
            "root_scope": root_scope,
            "subject_id": subject_id,
            "candidate_id": candidate["candidate_id"],
            "candidate_sha256": candidate["candidate_sha256"],
            "artifact_sha256": candidate["artifact_sha256"],
            "provenance": candidate["provenance"],
            "original_field_name": candidate["field_name"],
            "source_value": candidate["raw_value"],
            "review_action": decision["action"],
            "corrected_field_name": decision["corrected_field_name"],
            "corrected_value": decision["corrected_value"],
            "record_type": record_type,
            "batch_id": batch_id,
            "reviewer_id": reviewer_id,
            "review_note": decision["note"],
            "reviewed_at": reviewed_at,
        }
        if processing_profile_sha256 is not None:
            material["source_id"] = source_id
            material["processing_profile_sha256"] = processing_profile_sha256
        return material

    def _insert_batch_verified_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        root_scope: str,
        subject_id: str,
        candidate: dict[str, Any],
        batch_id: str,
        source_id: str | None,
        processing_profile_sha256: str | None,
        decision: dict[str, Any],
        reviewer_id: str,
        reviewed_at: str,
    ) -> dict[str, Any]:
        material = self._batch_record_material(
            root_scope=root_scope,
            subject_id=subject_id,
            candidate=candidate,
            batch_id=batch_id,
            source_id=source_id,
            processing_profile_sha256=processing_profile_sha256,
            decision=decision,
            reviewer_id=reviewer_id,
            reviewed_at=reviewed_at,
        )
        record_type = material["record_type"]
        record_prefix = "obs" if record_type == "observation" else "stmt"
        record_id = f"{record_prefix}_{self._mac({'record': material})[:32]}"
        effective_value = (
            candidate["raw_value"]
            if decision["action"] == "accept"
            else decision["corrected_value"]
        )
        packet_provenance = self._packet_provenance(
            tuple(candidate["provenance"]),
            source_id=(
                source_id if processing_profile_sha256 is not None else None
            ),
        )
        if record_type == "observation":
            effective_field_name = (
                candidate["field_name"]
                if decision["action"] == "accept"
                else decision["corrected_field_name"]
            )
            record_payload = {
                "observation_id": record_id,
                "subject_id": subject_id,
                "display": effective_field_name,
                "raw_value": effective_value,
                "provenance": packet_provenance,
                "verification": VerificationStatus.VERIFIED.value,
            }
        else:
            record_payload = {
                "statement_id": record_id,
                "subject_id": subject_id,
                "kind": StatementKind.SOURCE_FACT.value,
                "text": effective_value,
                "provenance": packet_provenance,
                "verification": VerificationStatus.VERIFIED.value,
            }
        record_json = _canonical_json(
            {"record_type": record_type, "payload": record_payload}
        )
        receipt_version = "v4" if processing_profile_sha256 is not None else "v3"
        binding_sha256 = self._mac(
            {
                "schema": f"private-review-receipt-binding-{receipt_version}",
                "material": material,
                "record_json": record_json,
            }
        )
        receipt_id = "rcpt_" + self._mac(
            {
                "schema": f"private-review-receipt-id-{receipt_version}",
                "binding_hmac": binding_sha256,
            }
        )[:32]
        connection.execute(
            """
            INSERT INTO reviewed_extraction(
                receipt_id, root_scope, candidate_id, candidate_sha256,
                artifact_sha256, provenance_json, source_value, subject_id,
                record_type, record_id, record_json, reviewer_id, review_note,
                reviewed_at, binding_sha256, review_action,
                corrected_field_name, corrected_value, batch_id, source_id,
                processing_profile_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt_id,
                root_scope,
                candidate["candidate_id"],
                candidate["candidate_sha256"],
                candidate["artifact_sha256"],
                _canonical_json(candidate["provenance"]),
                candidate["raw_value"],
                subject_id,
                record_type,
                record_id,
                record_json,
                reviewer_id,
                decision["note"],
                reviewed_at,
                binding_sha256,
                decision["action"],
                decision["corrected_field_name"],
                decision["corrected_value"],
                batch_id,
                source_id if processing_profile_sha256 is not None else None,
                processing_profile_sha256,
            ),
        )
        return {
            "receipt_id": receipt_id,
            "record_id": record_id,
            "record": json.loads(record_json),
        }

    @staticmethod
    def _review_batch_application_material(
        *,
        batch_id: str,
        reviewer_id: str,
        default_action: str,
        request_json: str,
        request_sha256: str,
        applied_at: str,
        outcome_json: str,
    ) -> dict[str, Any]:
        return {
            "schema": "private-document-review-application-v1",
            "batch_id": batch_id,
            "reviewer_id": reviewer_id,
            "default_action": default_action,
            "request": json.loads(request_json),
            "request_sha256": request_sha256,
            "applied_at": applied_at,
            "outcome": json.loads(outcome_json),
        }

    def _verify_review_batch_application_row(
        self,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        try:
            request = json.loads(row["request_json"])
            outcome = json.loads(row["outcome_json"])
            if not isinstance(request, dict) or not isinstance(outcome, dict):
                raise ValueError("application payloads must be objects")
            request_sha256 = _json_sha256(request)
            material = self._review_batch_application_material(
                batch_id=row["batch_id"],
                reviewer_id=row["reviewer_id"],
                default_action=row["default_action"],
                request_json=row["request_json"],
                request_sha256=row["request_sha256"],
                applied_at=row["applied_at"],
                outcome_json=row["outcome_json"],
            )
            expected = self._mac(material)
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ReviewLedgerIntegrityError(
                "review batch application binding is missing or invalid"
            ) from None
        if (
            not hmac.compare_digest(request_sha256, row["request_sha256"])
            or not hmac.compare_digest(expected, row["binding_hmac"])
        ):
            raise ReviewLedgerIntegrityError(
                "review batch application binding is missing or invalid"
            )
        return outcome

    def _application_outcome(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> dict[str, Any]:
        if isinstance(connection, _ReviewLedgerConnection):
            cached = connection.application_outcomes.get(row["batch_id"])
            if cached is not None:
                return cached
        outcome = self._verify_review_batch_application_row(row)
        if isinstance(connection, _ReviewLedgerConnection):
            connection.application_outcomes[row["batch_id"]] = outcome
        return outcome

    def _verify_applied_batch_effects(
        self,
        connection: sqlite3.Connection,
        *,
        batch_id: str,
        outcome: dict[str, Any],
    ) -> None:
        if (
            isinstance(connection, _ReviewLedgerConnection)
            and batch_id in connection.verified_effect_batches
        ):
            return
        snapshot_row = connection.execute(
            "SELECT * FROM review_batch_snapshot WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if snapshot_row is None:
            raise ReviewLedgerIntegrityError(
                "review batch application snapshot is missing"
            )
        snapshot = self._verify_review_batch_snapshot_row(snapshot_row)
        snapshot_candidates = snapshot.get("candidates")
        if not isinstance(snapshot_candidates, list):
            raise ReviewLedgerIntegrityError(
                "review batch application snapshot candidates are invalid"
            )
        candidates_by_id = {
            item.get("candidate_id"): item
            for item in snapshot_candidates
            if isinstance(item, dict)
        }
        if len(candidates_by_id) != len(snapshot_candidates):
            raise ReviewLedgerIntegrityError(
                "review batch application snapshot candidates are invalid"
            )
        snapshot_profile = snapshot.get("processing_profile_sha256")
        if snapshot_profile is not None:
            current_ingestion = self._profile_archive_ingestion_snapshot(
                connection,
                root_scope=snapshot["root_scope"],
                subject_id=snapshot["subject_id"],
                source_id=snapshot["source_id"],
                processing_profile_sha256=snapshot_profile,
                artifact_sha256=snapshot["artifact_sha256"],
            )
            if _canonical_json(current_ingestion) != _canonical_json(
                snapshot.get("archive_ingestion")
            ):
                raise ReviewLedgerIntegrityError(
                    "review batch application archive ingestion is stale"
                )
        action_rows = connection.execute(
            """
            SELECT * FROM candidate_review_action
            WHERE batch_id = ? ORDER BY rowid
            """,
            (batch_id,),
        ).fetchall()
        outcome_actions = outcome.get("actions")
        if not isinstance(outcome_actions, list) or len(action_rows) != len(
            outcome_actions
        ):
            raise ReviewLedgerIntegrityError(
                "review batch application effects are incomplete"
            )
        rows_by_action_id = {
            row["action_id"]: (row, self._verify_batch_action_row(row))
            for row in action_rows
        }
        if len(rows_by_action_id) != len(action_rows):
            raise ReviewLedgerIntegrityError(
                "review batch application contains duplicate action IDs"
            )
        for output in outcome_actions:
            if not isinstance(output, dict):
                raise ReviewLedgerIntegrityError(
                    "review batch application outcome is invalid"
                )
            found = rows_by_action_id.get(output.get("action_id"))
            if found is None:
                raise ReviewLedgerIntegrityError(
                    "review batch application action is missing"
                )
            _, action = found
            candidate = candidates_by_id.get(action["candidate_id"])
            if candidate is None or any(
                (
                    action["root_scope"] != snapshot["root_scope"],
                    action["subject_id"] != snapshot["subject_id"],
                    action["artifact_sha256"] != snapshot["artifact_sha256"],
                    action["candidate_sha256"]
                    != candidate.get("candidate_sha256"),
                    action["original_field_name"] != candidate.get("field_name"),
                    action["original_source_value"] != candidate.get("raw_value"),
                    action.get("source_id")
                    != (snapshot["source_id"] if snapshot_profile is not None else None),
                    action.get("processing_profile_sha256") != snapshot_profile,
                )
            ):
                raise ReviewLedgerIntegrityError(
                    "review batch application action does not match its snapshot"
                )
            if snapshot["source_id"] is not None:
                if snapshot_profile is not None:
                    association_row = connection.execute(
                        """
                        SELECT * FROM candidate_source_profile_version
                        WHERE root_scope = ? AND subject_id = ?
                          AND source_id = ? AND processing_profile_sha256 = ?
                          AND candidate_id = ?
                        """,
                        (
                            snapshot["root_scope"],
                            snapshot["subject_id"],
                            snapshot["source_id"],
                            snapshot_profile,
                            action["candidate_id"],
                        ),
                    ).fetchone()
                    association = (
                        self._verify_source_profile_association_row(
                            association_row
                        )
                        if association_row is not None
                        else None
                    )
                else:
                    association_row = connection.execute(
                        """
                        SELECT * FROM candidate_source_version
                        WHERE root_scope = ? AND subject_id = ?
                          AND source_id = ? AND candidate_id = ?
                        """,
                        (
                            snapshot["root_scope"],
                            snapshot["subject_id"],
                            snapshot["source_id"],
                            action["candidate_id"],
                        ),
                    ).fetchone()
                    association = (
                        self._verify_source_association_row(association_row)
                        if association_row is not None
                        else None
                    )
                if association is None or any(
                    (
                        association["candidate_sha256"]
                        != candidate.get("candidate_sha256"),
                        association["artifact_sha256"]
                        != snapshot["artifact_sha256"],
                    )
                ):
                    raise ReviewLedgerIntegrityError(
                        "review batch application source association is missing "
                        "or invalid"
                    )
            if (
                output.get("candidate_id") != action["candidate_id"]
                or output.get("action") != action["action"]
                or output.get("receipt_id") != action["receipt_id"]
            ):
                raise ReviewLedgerIntegrityError(
                    "review batch application outcome does not match its action"
                )
            if action["receipt_id"] is None:
                if output.get("record_id") is not None or output.get("record") is not None:
                    raise ReviewLedgerIntegrityError(
                        "rejected batch action exposes a verified record"
                    )
                continue
            receipt_row = connection.execute(
                """
                SELECT r.*,
                       c.candidate_sha256 AS registered_candidate_sha256,
                       c.artifact_sha256 AS registered_artifact_sha256,
                       c.provenance_json AS registered_provenance_json,
                       c.raw_value AS registered_raw_value,
                       c.subject_id AS registered_subject_id,
                       c.field_name AS field_name
                FROM reviewed_extraction r
                JOIN extraction_candidate c
                  ON c.root_scope = r.root_scope
                 AND c.candidate_id = r.candidate_id
                WHERE r.receipt_id = ?
                """,
                (action["receipt_id"],),
            ).fetchone()
            if receipt_row is None:
                raise ReviewLedgerIntegrityError(
                    "review batch verified receipt is missing"
                )
            record = self._verify_receipt_row(
                receipt_row, connection=connection
            )
            if (
                output.get("record_id") != receipt_row["record_id"]
                or output.get("record") != record
            ):
                raise ReviewLedgerIntegrityError(
                    "review batch outcome does not match its verified record"
                )
        if isinstance(connection, _ReviewLedgerConnection):
            connection.verified_effect_batches.add(batch_id)

    def apply_review_batch(
        self,
        *,
        root_scope: str,
        subject_id: str,
        artifact_sha256: str,
        batch_id: str,
        reviewer_id: str,
        default_action: str,
        decisions: list[dict[str, Any]],
        source_id: str | None = None,
        processing_profile_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Atomically apply every decision in a frozen document snapshot."""

        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")
        artifact_hash = _require_text(
            artifact_sha256, name="artifact_sha256", maximum=64
        )
        if not re.fullmatch(r"[a-f0-9]{64}", artifact_hash):
            raise ValueError("artifact_sha256 must be a lowercase SHA-256 value")
        batch_key = _require_text(batch_id, name="batch_id", maximum=128)
        reviewer = _require_text(reviewer_id, name="reviewer_id", maximum=256)
        source = (
            _require_text(source_id, name="source_id", maximum=128)
            if source_id is not None
            else None
        )
        profile: str | None = None
        if processing_profile_sha256 is not None:
            if source is None:
                raise ValueError("processing_profile_sha256 requires source_id")
            profile = _require_text(
                processing_profile_sha256,
                name="processing_profile_sha256",
                maximum=64,
            )
            if not re.fullmatch(r"[a-f0-9]{64}", profile):
                raise ValueError(
                    "processing_profile_sha256 must be a lowercase SHA-256 value"
                )

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            snapshot_row = connection.execute(
                "SELECT * FROM review_batch_snapshot WHERE batch_id = ?",
                (batch_key,),
            ).fetchone()
            if snapshot_row is None:
                raise UnknownReviewBatchError(
                    "review batch is not present in the private ledger"
                )
            snapshot = self._verify_review_batch_snapshot_row(snapshot_row)
            if (
                snapshot["root_scope"] != scope
                or snapshot["subject_id"] != subject
                or snapshot["source_id"] != source
                or snapshot.get("processing_profile_sha256") != profile
                or snapshot["artifact_sha256"] != artifact_hash
            ):
                raise ValueError(
                    "review batch does not match the selected root, subject, and source"
                )
            normalized_decisions = self._normalize_batch_decisions(
                candidates=snapshot["candidates"],
                archive_ingestion=snapshot.get("archive_ingestion"),
                default_action=default_action,
                decisions=decisions,
            )
            request = {
                "schema": (
                    "private-document-review-request-v2"
                    if profile is not None
                    else "private-document-review-request-v1"
                ),
                "batch_id": batch_key,
                "snapshot_sha256": snapshot_row["snapshot_sha256"],
                "root_scope": scope,
                "subject_id": subject,
                "source_id": source,
                "artifact_sha256": artifact_hash,
                "reviewer_id": reviewer,
                "default_action": default_action,
                "decisions": normalized_decisions,
            }
            if profile is not None:
                request["processing_profile_sha256"] = profile
                request["archive_ingestion"] = snapshot["archive_ingestion"]
            request_json = _canonical_json(request)
            if len(request_json.encode("utf-8")) > MAX_REVIEW_BATCH_JSON_BYTES:
                raise ValueError("review batch request exceeds the byte limit")
            request_sha256 = _json_sha256(request)

            existing_application = connection.execute(
                "SELECT * FROM review_batch_application WHERE batch_id = ?",
                (batch_key,),
            ).fetchone()
            if existing_application is not None:
                outcome = self._verify_review_batch_application_row(
                    existing_application
                )
                if not hmac.compare_digest(
                    request_sha256, existing_application["request_sha256"]
                ) or request_json != existing_application["request_json"]:
                    raise ReviewLedgerIntegrityError(
                        "review batch was already applied with a different request"
                    )
                self._verify_applied_batch_effects(
                    connection, batch_id=batch_key, outcome=outcome
                )
                return outcome

            try:
                current_candidates = self._document_candidate_snapshot(
                    connection,
                    root_scope=scope,
                    subject_id=subject,
                    source_id=source,
                    processing_profile_sha256=profile,
                    artifact_sha256=artifact_hash,
                )
            except UnknownReviewCandidateError:
                raise StaleReviewBatchError(
                    "review batch source candidates are no longer present"
                ) from None
            if _canonical_json(current_candidates) != _canonical_json(
                snapshot["candidates"]
            ):
                raise StaleReviewBatchError(
                    "review batch is stale because candidate content or review state changed"
                )
            if profile is not None:
                current_ingestion = self._profile_archive_ingestion_snapshot(
                    connection,
                    root_scope=scope,
                    subject_id=subject,
                    source_id=source,
                    processing_profile_sha256=profile,
                    artifact_sha256=artifact_hash,
                )
                if _canonical_json(current_ingestion) != _canonical_json(
                    snapshot["archive_ingestion"]
                ):
                    raise StaleReviewBatchError(
                        "review batch archive ingestion receipt changed"
                    )

            candidates_by_id = {
                item["candidate_id"]: item for item in current_candidates
            }
            applied_at = utc_now()
            action_outputs: list[dict[str, Any]] = []
            for decision in normalized_decisions:
                candidate = candidates_by_id[decision["candidate_id"]]
                action_seed = {
                    "schema": (
                        "private-candidate-review-action-id-v2"
                        if profile is not None
                        else "private-candidate-review-action-id-v1"
                    ),
                    "batch_id": batch_key,
                    "request_sha256": request_sha256,
                    "candidate_id": candidate["candidate_id"],
                    "action": decision["action"],
                    "reviewed_at": applied_at,
                }
                if profile is not None:
                    action_seed["source_id"] = source
                    action_seed["processing_profile_sha256"] = profile
                action_id = "ract_" + self._mac(action_seed)[:32]
                receipt: dict[str, Any] | None = None
                if decision["action"] in {"accept", "edit"}:
                    receipt = self._insert_batch_verified_receipt(
                        connection,
                        root_scope=scope,
                        subject_id=subject,
                        candidate=candidate,
                        batch_id=batch_key,
                        source_id=source,
                        processing_profile_sha256=profile,
                        decision=decision,
                        reviewer_id=reviewer,
                        reviewed_at=applied_at,
                    )
                action_material = {
                    "schema": (
                        "private-candidate-review-action-v2"
                        if profile is not None
                        else "private-candidate-review-action-v1"
                    ),
                    "action_id": action_id,
                    "root_scope": scope,
                    "subject_id": subject,
                    "artifact_sha256": artifact_hash,
                    "candidate_id": candidate["candidate_id"],
                    "candidate_sha256": candidate["candidate_sha256"],
                    "batch_id": batch_key,
                    "action": decision["action"],
                    "original_field_name": candidate["field_name"],
                    "original_source_value": candidate["raw_value"],
                    "corrected_field_name": decision["corrected_field_name"],
                    "corrected_value": decision["corrected_value"],
                    "reviewer_id": reviewer,
                    "review_note": decision["note"],
                    "reviewed_at": applied_at,
                    "receipt_id": receipt["receipt_id"] if receipt else None,
                }
                if profile is not None:
                    action_material["source_id"] = source
                    action_material["processing_profile_sha256"] = profile
                connection.execute(
                    """
                    INSERT INTO candidate_review_action(
                        action_id, root_scope, subject_id, artifact_sha256,
                        candidate_id, candidate_sha256, batch_id, action,
                        original_field_name, original_source_value,
                        corrected_field_name, corrected_value, reviewer_id,
                        review_note, reviewed_at, receipt_id, source_id,
                        processing_profile_sha256, binding_hmac
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        scope,
                        subject,
                        artifact_hash,
                        candidate["candidate_id"],
                        candidate["candidate_sha256"],
                        batch_key,
                        decision["action"],
                        candidate["field_name"],
                        candidate["raw_value"],
                        decision["corrected_field_name"],
                        decision["corrected_value"],
                        reviewer,
                        decision["note"],
                        applied_at,
                        receipt["receipt_id"] if receipt else None,
                        source if profile is not None else None,
                        profile,
                        self._mac(action_material),
                    ),
                )
                action_outputs.append(
                    {
                        "candidate_id": candidate["candidate_id"],
                        "action_id": action_id,
                        "action": decision["action"],
                        "receipt_id": receipt["receipt_id"] if receipt else None,
                        "record_id": receipt["record_id"] if receipt else None,
                        "record": receipt["record"] if receipt else None,
                    }
                )

            outcome = {
                "batch_id": batch_key,
                "snapshot_sha256": snapshot_row["snapshot_sha256"],
                "root_id": scope,
                "subject_id": subject,
                "source_id": source,
                "processing_profile_sha256": profile,
                "artifact_id": snapshot["artifact_id"],
                "artifact_sha256": artifact_hash,
                "reviewer_id": reviewer,
                "default_action": default_action,
                "applied_at": applied_at,
                "actions": action_outputs,
            }
            outcome_json = _canonical_json(outcome)
            if len(outcome_json.encode("utf-8")) > MAX_REVIEW_BATCH_JSON_BYTES:
                raise ValueError("review batch outcome exceeds the byte limit")
            application_material = self._review_batch_application_material(
                batch_id=batch_key,
                reviewer_id=reviewer,
                default_action=default_action,
                request_json=request_json,
                request_sha256=request_sha256,
                applied_at=applied_at,
                outcome_json=outcome_json,
            )
            connection.execute(
                """
                INSERT INTO review_batch_application(
                    batch_id, reviewer_id, default_action, request_json,
                    request_sha256, applied_at, outcome_json, binding_hmac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    batch_key,
                    reviewer,
                    default_action,
                    request_json,
                    request_sha256,
                    applied_at,
                    outcome_json,
                    self._mac(application_material),
                ),
            )
        return outcome

    def verified_record_page(
        self,
        *,
        root_scope: str,
        subject_id: str,
        cursor: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")
        if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0:
            raise ValueError("cursor must be a non-negative integer")
        if not isinstance(limit, int) or isinstance(limit, bool) or not (
            1 <= limit <= MAX_PRIVATE_LEDGER_PAGE_SIZE
        ):
            raise ValueError(
                f"limit must be between 1 and {MAX_PRIVATE_LEDGER_PAGE_SIZE}"
            )
        entries: list[dict[str, Any]] = []
        with self._connect() as connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                """
                SELECT r.*,
                       c.candidate_sha256 AS registered_candidate_sha256,
                       c.artifact_sha256 AS registered_artifact_sha256,
                       c.provenance_json AS registered_provenance_json,
                       c.raw_value AS registered_raw_value,
                       c.subject_id AS registered_subject_id,
                       c.field_name AS field_name
                FROM reviewed_extraction r
                JOIN extraction_candidate c
                  ON c.root_scope = r.root_scope
                 AND c.candidate_id = r.candidate_id
                WHERE r.root_scope = ? AND r.subject_id = ?
                """,
                (scope, subject),
            ).fetchall()
            for row in rows:
                candidate_row = connection.execute(
                    """
                    SELECT * FROM extraction_candidate
                    WHERE root_scope = ? AND candidate_id = ?
                    """,
                    (scope, row["candidate_id"]),
                ).fetchone()
                if candidate_row is None:
                    raise ReviewLedgerIntegrityError(
                        "review receipt candidate binding is missing"
                    )
                self._verify_candidate_row(candidate_row)
                entries.append(
                    {
                        "receipt_id": row["receipt_id"],
                        "record_id": row["record_id"],
                        "record_type": row["record_type"],
                        "recorded_at": row["reviewed_at"],
                        "actor_id": row["reviewer_id"],
                        "record": self._verify_receipt_row(
                            row, connection=connection
                        ),
                    }
                )
            note_rows = connection.execute(
                """
                SELECT * FROM reviewed_user_note
                WHERE root_scope = ? AND subject_id = ?
                """,
                (scope, subject),
            ).fetchall()
            for row in note_rows:
                record = self._verify_user_note_row(row)
                entries.append(
                    {
                        "receipt_id": row["receipt_id"],
                        "record_id": row["record_id"],
                        "record_type": "user_note",
                        "recorded_at": row["recorded_at"],
                        "actor_id": row["recorder_id"],
                        "record": record,
                    }
                )
        entries.sort(key=lambda item: (item["recorded_at"], item["receipt_id"]))
        page = entries[cursor : cursor + limit]
        next_cursor = cursor + len(page)
        return {
            "root_id": scope,
            "subject_id": subject,
            "total_records": len(entries),
            "records": page,
            "next_cursor": next_cursor if next_cursor < len(entries) else None,
        }

    @staticmethod
    def _packet_provenance(
        provenance: tuple[dict[str, Any], ...],
        *,
        source_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return [
            {
                "source_id": source_id or item["artifact_id"],
                "sha256": item["artifact_sha256"],
                "page": item.get("page"),
                "bbox": item.get("bbox"),
                "line_start": item.get("line_start"),
                "line_end": item.get("line_end"),
            }
            for item in provenance
        ]

    @staticmethod
    def _binding_material(
        *,
        root_scope: str,
        candidate_id: str,
        candidate_sha256: str,
        artifact_sha256: str,
        provenance: tuple[dict[str, Any], ...],
        source_value: str,
        field_name: str | None,
        subject_id: str,
        record_type: str,
        reviewer_id: str,
        review_note: str | None,
        reviewed_at: str,
    ) -> dict[str, Any]:
        return {
            "schema": "private-review-record-v2",
            "root_scope": root_scope,
            "candidate_id": candidate_id,
            "candidate_sha256": candidate_sha256,
            "artifact_sha256": artifact_sha256,
            "provenance": provenance,
            "source_value": source_value,
            "field_name": field_name,
            "subject_id": subject_id,
            "record_type": record_type,
            "reviewer_id": reviewer_id,
            "review_note": review_note,
            "reviewed_at": reviewed_at,
        }

    def review_candidate(
        self,
        *,
        root_scope: str,
        candidate_id: str,
        reviewer_id: str,
        confirmed_field_name: str | None = None,
        confirmed_raw_value: str | None = None,
        confirmed_source_statement: str | None = None,
        note: str | None = None,
    ) -> ReviewedRecordReceipt:
        scope = _require_text(root_scope, name="root_scope", maximum=64)
        candidate_key = _require_text(candidate_id, name="candidate_id", maximum=128)
        reviewer = _require_text(reviewer_id, name="reviewer_id", maximum=256)
        if note is not None:
            if not isinstance(note, str) or len(note) > 4096 or "\0" in note:
                raise ValueError("note must be a string of at most 4096 characters without NUL")

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            candidate = connection.execute(
                """
                SELECT *
                FROM extraction_candidate
                WHERE root_scope = ? AND candidate_id = ?
                """,
                (scope, candidate_key),
            ).fetchone()
            if candidate is None:
                raise UnknownReviewCandidateError(
                    "candidate is not registered by ingestion in the selected private root"
                )
            registration = self._verify_candidate_row(candidate)
            occurrence_binding = connection.execute(
                """
                SELECT 1 FROM candidate_source_version
                WHERE root_scope = ? AND candidate_id = ?
                UNION ALL
                SELECT 1 FROM candidate_source_profile_version
                WHERE root_scope = ? AND candidate_id = ?
                UNION ALL
                SELECT 1 FROM archive_ingestion
                WHERE root_scope = ? AND subject_id = ? AND artifact_sha256 = ?
                LIMIT 1
                """,
                (
                    scope, candidate_key, scope, candidate_key,
                    scope, candidate["subject_id"], candidate["artifact_sha256"],
                ),
            ).fetchone()
            if occurrence_binding is not None:
                raise ReviewLedgerIntegrityError(
                    "source-bound candidates must be reviewed with the batch tool"
                )
            prior_legacy_receipt = connection.execute(
                """
                SELECT receipt_id FROM reviewed_extraction
                WHERE root_scope = ? AND candidate_id = ?
                  AND source_id IS NULL
                  AND processing_profile_sha256 IS NULL
                LIMIT 1
                """,
                (scope, candidate_key),
            ).fetchone()
            if prior_legacy_receipt is not None:
                raise ReviewLedgerIntegrityError(
                    "candidate already has an immutable review receipt"
                )
            prior_batch_action = connection.execute(
                """
                SELECT * FROM candidate_review_action
                WHERE root_scope = ? AND candidate_id = ?
                ORDER BY reviewed_at, action_id
                LIMIT 1
                """,
                (scope, candidate_key),
            ).fetchone()
            if prior_batch_action is not None:
                self._verify_batch_action_row(prior_batch_action)
                raise ReviewLedgerIntegrityError(
                    "candidate already has an immutable batch review action"
                )

            subject = candidate["subject_id"]
            if not isinstance(subject, str) or not _SUBJECT_ID.fullmatch(subject):
                raise ReviewLedgerIntegrityError(
                    "candidate has no valid server-derived subject binding; re-ingest it"
                )
            instruction_findings = json.loads(
                registration["instruction_findings_json"]
            )
            if instruction_findings:
                raise ReviewLedgerIntegrityError(
                    "candidate contains instruction-like untrusted source text and cannot "
                    "be promoted to a verified clinical record"
                )

            source_value = candidate["raw_value"]
            if candidate["candidate_kind"] == CandidateKind.FIELD.value:
                if confirmed_source_statement is not None:
                    raise ValueError("field review accepts confirmed_raw_value only")
                if confirmed_raw_value is None or confirmed_raw_value != source_value:
                    raise ValueError("confirmed_raw_value must exactly match the registered candidate")
                if (
                    confirmed_field_name is None
                    or confirmed_field_name != candidate["field_name"]
                ):
                    raise ValueError(
                        "confirmed_field_name must exactly match the registered candidate"
                    )
                record_type = "observation"
            else:
                if confirmed_raw_value is not None:
                    raise ValueError(
                        "statement review accepts confirmed_source_statement only"
                    )
                if confirmed_field_name is not None:
                    raise ValueError("statement review does not accept confirmed_field_name")
                if (
                    confirmed_source_statement is None
                    or confirmed_source_statement != source_value
                ):
                    raise ValueError(
                        "confirmed_source_statement must exactly match the registered candidate"
                    )
                record_type = "statement"

            provenance = tuple(json.loads(candidate["provenance_json"]))
            reviewed_at = utc_now()
            material = self._binding_material(
                root_scope=scope,
                candidate_id=candidate_key,
                candidate_sha256=candidate["candidate_sha256"],
                artifact_sha256=candidate["artifact_sha256"],
                provenance=provenance,
                source_value=source_value,
                field_name=candidate["field_name"],
                subject_id=subject,
                record_type=record_type,
                reviewer_id=reviewer,
                review_note=note,
                reviewed_at=reviewed_at,
            )
            record_prefix = "obs" if record_type == "observation" else "stmt"
            record_id = f"{record_prefix}_{self._mac({'record': material})[:32]}"
            packet_provenance = self._packet_provenance(provenance)
            if record_type == "observation":
                record_payload = {
                    "observation_id": record_id,
                    "subject_id": subject,
                    "display": candidate["field_name"],
                    "raw_value": source_value,
                    "provenance": packet_provenance,
                    "verification": VerificationStatus.VERIFIED.value,
                }
            else:
                record_payload = {
                    "statement_id": record_id,
                    "subject_id": subject,
                    "kind": StatementKind.SOURCE_FACT.value,
                    "text": source_value,
                    "provenance": packet_provenance,
                    "verification": VerificationStatus.VERIFIED.value,
                }
            record_json = _canonical_json(
                {"record_type": record_type, "payload": record_payload}
            )
            binding_sha256 = self._mac(
                {
                    "schema": "private-review-receipt-binding-v2",
                    "material": material,
                    "record_json": record_json,
                }
            )
            receipt_id = "rcpt_" + self._mac(
                {
                    "schema": "private-review-receipt-id-v2",
                    "binding_hmac": binding_sha256,
                }
            )[:32]
            connection.execute(
                """
                INSERT INTO reviewed_extraction(
                    receipt_id, root_scope, candidate_id, candidate_sha256,
                    artifact_sha256, provenance_json, source_value, subject_id,
                    record_type, record_id, record_json, reviewer_id, review_note,
                    reviewed_at, binding_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    scope,
                    candidate_key,
                    candidate["candidate_sha256"],
                    candidate["artifact_sha256"],
                    candidate["provenance_json"],
                    source_value,
                    subject,
                    record_type,
                    record_id,
                    record_json,
                    reviewer,
                    note,
                    reviewed_at,
                    binding_sha256,
                ),
            )

        return ReviewedRecordReceipt(
            receipt_id=receipt_id,
            record_id=record_id,
            record_type=record_type,
            subject_id=subject,
            candidate_id=candidate_key,
            candidate_sha256=candidate["candidate_sha256"],
            artifact_sha256=candidate["artifact_sha256"],
            provenance=provenance,
            source_value=source_value,
            reviewer_id=reviewer,
            review_note=note,
            reviewed_at=reviewed_at,
            record_json=record_json,
        )

    def record_user_note(
        self,
        *,
        root_scope: str,
        subject_id: str,
        text: str,
        recorder_id: str,
    ) -> UserNoteReceipt:
        """Create a typed receipt for an explicitly confirmed user statement."""

        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        note_text = _require_text(text, name="text", maximum=8_000)
        recorder = _require_text(recorder_id, name="recorder_id", maximum=256)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")

        recorded_at = utc_now()
        material = {
            "schema": "private-user-note-v1",
            "root_scope": scope,
            "subject_id": subject,
            "text": note_text,
            "recorder_id": recorder,
            "recorded_at": recorded_at,
        }
        record_id = f"stmt_{self._mac({'user_note': material})[:32]}"
        content_binding = self._mac(
            {"schema": "private-user-note-content-v1", "material": material}
        )
        record_payload = {
            "statement_id": record_id,
            "subject_id": subject,
            "kind": StatementKind.USER_NOTE.value,
            "text": note_text,
            "provenance": [
                {
                    "source_id": f"user_note:{record_id}",
                    "sha256": content_binding,
                }
            ],
            "verification": VerificationStatus.VERIFIED.value,
        }
        record_json = _canonical_json(
            {"record_type": "statement", "payload": record_payload}
        )
        binding_sha256 = self._mac(
            {
                "schema": "private-user-note-receipt-binding-v1",
                "material": material,
                "record_json": record_json,
            }
        )
        receipt_id = "note_rcpt_" + self._mac(
            {
                "schema": "private-user-note-receipt-id-v1",
                "binding_hmac": binding_sha256,
            }
        )[:32]
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO reviewed_user_note(
                    receipt_id, root_scope, subject_id, record_id, note_text,
                    recorder_id, recorded_at, record_json, binding_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    scope,
                    subject,
                    record_id,
                    note_text,
                    recorder,
                    recorded_at,
                    record_json,
                    binding_sha256,
                ),
            )
        return UserNoteReceipt(
            receipt_id=receipt_id,
            record_id=record_id,
            subject_id=subject,
            root_scope=scope,
            recorder_id=recorder,
            recorded_at=recorded_at,
            record_json=record_json,
        )

    def user_note_for_receipt(
        self,
        receipt_id: str,
        *,
        root_scope: str,
        subject_id: str,
    ) -> UserNoteReceipt:
        """Load one integrity-verified user note bound to the expected subject.

        This deliberately does not fall back to extraction receipts.  Callers
        that require a ``USER_NOTE`` must not be able to reinterpret a reviewed
        source statement merely because both record types share the CasePacket
        receipt loader.
        """

        receipt_key = _require_text(receipt_id, name="receipt_id", maximum=128)
        scope = _require_text(root_scope, name="root_scope", maximum=64)
        subject = _require_text(subject_id, name="subject_id", maximum=69)
        if not _SUBJECT_ID.fullmatch(subject):
            raise ValueError("subject_id must be a keyed pseudonymous subj_ identifier")

        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM reviewed_user_note WHERE receipt_id = ?",
                (receipt_key,),
            ).fetchone()
        if row is None:
            raise UnknownReviewReceiptError(
                f"user-note receipt is not present in the private ledger: {receipt_key}"
            )

        self._verify_user_note_row(row)
        if row["root_scope"] != scope or row["subject_id"] != subject:
            raise ValueError("user-note receipt does not match the selected private root")
        return UserNoteReceipt(
            receipt_id=row["receipt_id"],
            record_id=row["record_id"],
            subject_id=row["subject_id"],
            root_scope=row["root_scope"],
            recorder_id=row["recorder_id"],
            recorded_at=row["recorded_at"],
            record_json=row["record_json"],
        )

    def _verify_user_note_row(self, row: sqlite3.Row) -> dict[str, Any]:
        material = {
            "schema": "private-user-note-v1",
            "root_scope": row["root_scope"],
            "subject_id": row["subject_id"],
            "text": row["note_text"],
            "recorder_id": row["recorder_id"],
            "recorded_at": row["recorded_at"],
        }
        expected_record_id = f"stmt_{self._mac({'user_note': material})[:32]}"
        content_binding = self._mac(
            {"schema": "private-user-note-content-v1", "material": material}
        )
        expected_record_json = _canonical_json(
            {
                "record_type": "statement",
                "payload": {
                    "statement_id": expected_record_id,
                    "subject_id": row["subject_id"],
                    "kind": StatementKind.USER_NOTE.value,
                    "text": row["note_text"],
                    "provenance": [
                        {
                            "source_id": f"user_note:{expected_record_id}",
                            "sha256": content_binding,
                        }
                    ],
                    "verification": VerificationStatus.VERIFIED.value,
                },
            }
        )
        expected_binding = self._mac(
            {
                "schema": "private-user-note-receipt-binding-v1",
                "material": material,
                "record_json": expected_record_json,
            }
        )
        expected_receipt_id = "note_rcpt_" + self._mac(
            {
                "schema": "private-user-note-receipt-id-v1",
                "binding_hmac": expected_binding,
            }
        )[:32]
        if (
            not hmac.compare_digest(expected_record_id, row["record_id"])
            or not hmac.compare_digest(expected_binding, row["binding_sha256"])
            or not hmac.compare_digest(expected_receipt_id, row["receipt_id"])
            or row["record_json"] != expected_record_json
        ):
            raise ReviewLedgerIntegrityError("user-note receipt binding is invalid")
        return json.loads(expected_record_json)

    def _verify_batch_receipt_links(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> None:
        """Verify the signed commit and action without recursively loading receipts."""

        action_rows = connection.execute(
            "SELECT * FROM candidate_review_action WHERE receipt_id = ?",
            (row["receipt_id"],),
        ).fetchall()
        if len(action_rows) != 1:
            raise ReviewLedgerIntegrityError("review receipt batch action is missing or ambiguous")
        action = self._verify_batch_action_row(action_rows[0])
        comparisons = {
            "root_scope": "root_scope",
            "subject_id": "subject_id",
            "candidate_id": "candidate_id",
            "candidate_sha256": "candidate_sha256",
            "artifact_sha256": "artifact_sha256",
            "batch_id": "batch_id",
            "action": "review_action",
            "original_field_name": "field_name",
            "original_source_value": "source_value",
            "corrected_field_name": "corrected_field_name",
            "corrected_value": "corrected_value",
            "reviewer_id": "reviewer_id",
            "review_note": "review_note",
            "reviewed_at": "reviewed_at",
            "source_id": "source_id",
            "processing_profile_sha256": "processing_profile_sha256",
        }
        if any(action.get(key) != row[column] for key, column in comparisons.items()):
            raise ReviewLedgerIntegrityError("review receipt does not match its batch action")
        expected = {
            "candidate_id": row["candidate_id"],
            "action_id": action["action_id"],
            "action": row["review_action"],
            "receipt_id": row["receipt_id"],
            "record_id": row["record_id"],
            "record": json.loads(row["record_json"]),
        }
        if isinstance(connection, _ReviewLedgerConnection):
            cached = connection.receipt_commit_links.get(row["batch_id"])
            if cached is not None:
                if cached.get(action["action_id"]) != expected:
                    raise ReviewLedgerIntegrityError(
                        "review receipt does not match its batch application"
                    )
                return
        application_row = connection.execute(
            "SELECT * FROM review_batch_application WHERE batch_id = ?",
            (row["batch_id"],),
        ).fetchone()
        if application_row is None:
            raise ReviewLedgerIntegrityError("review receipt batch application is missing")
        outcome = self._application_outcome(connection, application_row)
        outputs = outcome.get("actions")
        committed_actions = connection.execute(
            "SELECT * FROM candidate_review_action WHERE batch_id = ?",
            (row["batch_id"],),
        ).fetchall()
        if (
            not isinstance(outputs, list)
            or len(outputs) != len(committed_actions)
            or any(not isinstance(item, dict) for item in outputs)
            or {item.get("action_id") for item in outputs}
            != {item["action_id"] for item in committed_actions}
        ):
            raise ReviewLedgerIntegrityError("review batch application effects are incomplete")
        for committed_action in committed_actions:
            self._verify_batch_action_row(committed_action)
        matching = [item for item in outputs if item.get("action_id") == action["action_id"]]
        if matching != [expected]:
            raise ReviewLedgerIntegrityError("review receipt does not match its batch application")
        snapshot = self._batch_snapshot(connection, row["batch_id"])
        if (
            snapshot["root_scope"] != row["root_scope"]
            or snapshot["subject_id"] != row["subject_id"]
            or snapshot["artifact_sha256"] != row["artifact_sha256"]
            or snapshot.get("processing_profile_sha256")
            != row["processing_profile_sha256"]
            or not any(
                item["candidate_id"] == row["candidate_id"]
                and item["candidate_sha256"] == row["candidate_sha256"]
                for item in snapshot["candidates"]
            )
        ):
            raise ReviewLedgerIntegrityError("review receipt does not match its batch snapshot")
        if isinstance(connection, _ReviewLedgerConnection):
            connection.receipt_commit_links[row["batch_id"]] = {
                item["action_id"]: item for item in outputs
            }

    def _verify_receipt_occurrence_membership(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> None:
        membership_key = (row["root_scope"], row["source_id"], row["processing_profile_sha256"])
        if not isinstance(connection, _ReviewLedgerConnection) or membership_key not in connection.verified_memberships:
            association_rows = connection.execute(
                "SELECT * FROM candidate_source_profile_version "
                "WHERE root_scope = ? AND source_id = ? AND processing_profile_sha256 = ? "
                "ORDER BY source_order LIMIT ?",
                (*membership_key, MAX_ARCHIVE_REVIEW_CANDIDATES + 1),
            ).fetchall()
            if len(association_rows) > MAX_ARCHIVE_REVIEW_CANDIDATES:
                raise ReviewLedgerIntegrityError("source-profile membership exceeds the hard cap")
            self._verify_profile_membership_count(
                connection,
                root_scope=row["root_scope"],
                subject_id=row["subject_id"],
                source_id=row["source_id"],
                processing_profile_sha256=row["processing_profile_sha256"],
                artifact_sha256=row["artifact_sha256"],
                association_rows=association_rows,
            )
        association_row = connection.execute(
            """
            SELECT * FROM candidate_source_profile_version
            WHERE root_scope = ? AND subject_id = ? AND source_id = ?
              AND processing_profile_sha256 = ? AND candidate_id = ?
            """,
            (
                row["root_scope"],
                row["subject_id"],
                row["source_id"],
                row["processing_profile_sha256"],
                row["candidate_id"],
            ),
        ).fetchone()
        if association_row is None:
            raise ReviewLedgerIntegrityError(
                "review receipt source-profile association is missing"
            )
        association = self._verify_source_profile_association_row(association_row)
        if (
            association["candidate_sha256"] != row["candidate_sha256"]
            or association["artifact_sha256"] != row["artifact_sha256"]
        ):
            raise ReviewLedgerIntegrityError(
                "review receipt does not match its source-profile association"
            )
        snapshot = self._batch_snapshot(connection, row["batch_id"])
        if (
            snapshot["root_scope"] != row["root_scope"]
            or snapshot["subject_id"] != row["subject_id"]
            or snapshot["source_id"] != row["source_id"]
            or snapshot.get("processing_profile_sha256")
            != row["processing_profile_sha256"]
            or snapshot["artifact_sha256"] != row["artifact_sha256"]
        ):
            raise ReviewLedgerIntegrityError(
                "review receipt does not match its batch occurrence"
            )
        current_ingestion = self._profile_archive_ingestion_snapshot(
            connection,
            root_scope=row["root_scope"],
            subject_id=row["subject_id"],
            source_id=row["source_id"],
            processing_profile_sha256=row["processing_profile_sha256"],
            artifact_sha256=row["artifact_sha256"],
        )
        if _canonical_json(current_ingestion) != _canonical_json(
            snapshot["archive_ingestion"]
        ):
            raise ReviewLedgerIntegrityError(
                "review receipt archive ingestion binding is invalid"
            )

    def _verify_receipt_row(
        self,
        row: sqlite3.Row,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        provenance = tuple(json.loads(row["provenance_json"]))
        review_action = row["review_action"]
        if review_action is not None:
            source_id = row["source_id"]
            profile = row["processing_profile_sha256"]
            if (source_id is None) != (profile is None):
                raise ReviewLedgerIntegrityError(
                    "review receipt has incomplete occurrence scope"
                )
            if review_action not in {"accept", "edit"}:
                raise ReviewLedgerIntegrityError(
                    "review receipt contains an invalid batch action"
                )
            if review_action == "accept":
                if (
                    row["corrected_field_name"] is not None
                    or row["corrected_value"] is not None
                ):
                    raise ReviewLedgerIntegrityError(
                        "accepted review receipt contains unexpected corrections"
                    )
                effective_field_name = row["field_name"]
                effective_value = row["source_value"]
            else:
                if (
                    not isinstance(row["corrected_value"], str)
                    or not row["corrected_value"].strip()
                ):
                    raise ReviewLedgerIntegrityError(
                        "edited review receipt has no corrected exact value"
                    )
                effective_field_name = row["corrected_field_name"]
                effective_value = row["corrected_value"]
                if row["record_type"] == "observation" and (
                    not isinstance(effective_field_name, str)
                    or not effective_field_name.strip()
                ):
                    raise ReviewLedgerIntegrityError(
                        "edited observation has no corrected field name"
                    )
                if row["record_type"] == "statement" and (
                    effective_field_name is not None
                ):
                    raise ReviewLedgerIntegrityError(
                        "edited statement contains a corrected field name"
                    )
            material = {
                "schema": (
                    "private-review-record-v4"
                    if profile is not None
                    else "private-review-record-v3"
                ),
                "root_scope": row["root_scope"],
                "subject_id": row["subject_id"],
                "candidate_id": row["candidate_id"],
                "candidate_sha256": row["candidate_sha256"],
                "artifact_sha256": row["artifact_sha256"],
                "provenance": list(provenance),
                "original_field_name": row["field_name"],
                "source_value": row["source_value"],
                "review_action": review_action,
                "corrected_field_name": row["corrected_field_name"],
                "corrected_value": row["corrected_value"],
                "record_type": row["record_type"],
                "batch_id": row["batch_id"],
                "reviewer_id": row["reviewer_id"],
                "review_note": row["review_note"],
                "reviewed_at": row["reviewed_at"],
            }
            if profile is not None:
                material["source_id"] = source_id
                material["processing_profile_sha256"] = profile
            prefix = "obs" if row["record_type"] == "observation" else "stmt"
            expected_record_id = f"{prefix}_{self._mac({'record': material})[:32]}"
            packet_provenance = self._packet_provenance(
                provenance,
                source_id=source_id if profile is not None else None,
            )
            if row["record_type"] == "observation":
                expected_payload = {
                    "observation_id": expected_record_id,
                    "subject_id": row["subject_id"],
                    "display": effective_field_name,
                    "raw_value": effective_value,
                    "provenance": packet_provenance,
                    "verification": VerificationStatus.VERIFIED.value,
                }
            else:
                expected_payload = {
                    "statement_id": expected_record_id,
                    "subject_id": row["subject_id"],
                    "kind": StatementKind.SOURCE_FACT.value,
                    "text": effective_value,
                    "provenance": packet_provenance,
                    "verification": VerificationStatus.VERIFIED.value,
                }
            expected_record_json = _canonical_json(
                {"record_type": row["record_type"], "payload": expected_payload}
            )
            receipt_version = "v4" if profile is not None else "v3"
            binding_sha256 = self._mac(
                {
                    "schema": f"private-review-receipt-binding-{receipt_version}",
                    "material": material,
                    "record_json": expected_record_json,
                }
            )
            expected_receipt_id = "rcpt_" + self._mac(
                {
                    "schema": f"private-review-receipt-id-{receipt_version}",
                    "binding_hmac": binding_sha256,
                }
            )[:32]
            if (
                not isinstance(row["batch_id"], str)
                or not row["batch_id"].startswith("rbatch_")
                or not hmac.compare_digest(binding_sha256, row["binding_sha256"])
                or not hmac.compare_digest(expected_receipt_id, row["receipt_id"])
                or not hmac.compare_digest(expected_record_id, row["record_id"])
                or not hmac.compare_digest(
                    row["candidate_sha256"], row["registered_candidate_sha256"]
                )
                or not hmac.compare_digest(
                    row["artifact_sha256"], row["registered_artifact_sha256"]
                )
                or row["provenance_json"] != row["registered_provenance_json"]
                or row["source_value"] != row["registered_raw_value"]
                or row["subject_id"] != row["registered_subject_id"]
                or row["record_json"] != expected_record_json
            ):
                raise ReviewLedgerIntegrityError(
                    "review receipt source binding is invalid"
                )
            if connection is None:
                with self._connect() as membership_connection:
                    self._verify_batch_receipt_links(membership_connection, row)
                    if profile is not None:
                        self._verify_receipt_occurrence_membership(
                            membership_connection, row
                        )
            else:
                self._verify_batch_receipt_links(connection, row)
                if profile is not None:
                    self._verify_receipt_occurrence_membership(connection, row)
            return json.loads(expected_record_json)

        material = self._binding_material(
            root_scope=row["root_scope"],
            candidate_id=row["candidate_id"],
            candidate_sha256=row["candidate_sha256"],
            artifact_sha256=row["artifact_sha256"],
            provenance=provenance,
            source_value=row["source_value"],
            field_name=row["field_name"],
            subject_id=row["subject_id"],
            record_type=row["record_type"],
            reviewer_id=row["reviewer_id"],
            review_note=row["review_note"],
            reviewed_at=row["reviewed_at"],
        )
        prefix = "obs" if row["record_type"] == "observation" else "stmt"
        expected_record_id = f"{prefix}_{self._mac({'record': material})[:32]}"
        packet_provenance = self._packet_provenance(provenance)
        if row["record_type"] == "observation":
            expected_payload = {
                "observation_id": expected_record_id,
                "subject_id": row["subject_id"],
                "display": row["field_name"],
                "raw_value": row["source_value"],
                "provenance": packet_provenance,
                "verification": VerificationStatus.VERIFIED.value,
            }
        else:
            expected_payload = {
                "statement_id": expected_record_id,
                "subject_id": row["subject_id"],
                "kind": StatementKind.SOURCE_FACT.value,
                "text": row["source_value"],
                "provenance": packet_provenance,
                "verification": VerificationStatus.VERIFIED.value,
            }
        expected_record_json = _canonical_json(
            {"record_type": row["record_type"], "payload": expected_payload}
        )
        binding_sha256 = self._mac(
            {
                "schema": "private-review-receipt-binding-v2",
                "material": material,
                "record_json": expected_record_json,
            }
        )
        expected_receipt_id = "rcpt_" + self._mac(
            {
                "schema": "private-review-receipt-id-v2",
                "binding_hmac": binding_sha256,
            }
        )[:32]
        if (
            not hmac.compare_digest(binding_sha256, row["binding_sha256"])
            or not hmac.compare_digest(expected_receipt_id, row["receipt_id"])
            or not hmac.compare_digest(expected_record_id, row["record_id"])
            or not hmac.compare_digest(
                row["candidate_sha256"], row["registered_candidate_sha256"]
            )
            or not hmac.compare_digest(
                row["artifact_sha256"], row["registered_artifact_sha256"]
            )
            or row["provenance_json"] != row["registered_provenance_json"]
            or row["source_value"] != row["registered_raw_value"]
            or row["subject_id"] != row["registered_subject_id"]
            or row["record_json"] != expected_record_json
        ):
            raise ReviewLedgerIntegrityError("review receipt source binding is invalid")

        return json.loads(expected_record_json)

    def records_for_receipts(self, receipt_ids: list[str]) -> ReviewedRecordBatch:
        if not isinstance(receipt_ids, list) or not receipt_ids:
            raise ValueError("receipt_ids must be a non-empty array")
        if len(receipt_ids) > MAX_RECEIPTS_PER_CASE_PACKET:
            raise ValueError(
                f"receipt_ids must contain at most {MAX_RECEIPTS_PER_CASE_PACKET} entries"
            )
        if len(set(receipt_ids)) != len(receipt_ids):
            raise ValueError("receipt_ids must not contain duplicates")
        for receipt_id in receipt_ids:
            _require_text(receipt_id, name="receipt_id", maximum=128)

        entries: list[
            tuple[str, str, tuple[str, ...], str, dict[str, Any]]
        ] = []
        with self._connect() as connection:
            connection.execute("BEGIN")
            for receipt_id in receipt_ids:
                row = connection.execute(
                    """
                    SELECT r.*,
                           c.candidate_sha256 AS registered_candidate_sha256,
                           c.artifact_sha256 AS registered_artifact_sha256,
                           c.provenance_json AS registered_provenance_json,
                           c.raw_value AS registered_raw_value,
                           c.subject_id AS registered_subject_id,
                           c.field_name AS field_name
                    FROM reviewed_extraction r
                    JOIN extraction_candidate c
                      ON c.root_scope = r.root_scope
                     AND c.candidate_id = r.candidate_id
                    WHERE r.receipt_id = ?
                    """,
                    (receipt_id,),
                ).fetchone()
                if row is not None:
                    candidate_row = connection.execute(
                        """
                        SELECT * FROM extraction_candidate
                        WHERE root_scope = ? AND candidate_id = ?
                        """,
                        (row["root_scope"], row["candidate_id"]),
                    ).fetchone()
                    if candidate_row is None:
                        raise ReviewLedgerIntegrityError(
                            "review receipt candidate binding is missing"
                        )
                    self._verify_candidate_row(candidate_row)
                    entries.append(
                        (
                            row["root_scope"],
                            row["subject_id"],
                            (
                                "candidate",
                                row["source_id"] or "",
                                row["processing_profile_sha256"] or "",
                                row["candidate_id"],
                            ),
                            row["reviewed_at"],
                            self._verify_receipt_row(row, connection=connection),
                        )
                    )
                    continue
                note_row = connection.execute(
                    "SELECT * FROM reviewed_user_note WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone()
                if note_row is None:
                    raise UnknownReviewReceiptError(
                        f"review receipt is not present in the private ledger: {receipt_id}"
                    )
                entries.append(
                    (
                        note_row["root_scope"],
                        note_row["subject_id"],
                        ("user_note", note_row["record_id"]),
                        note_row["recorded_at"],
                        self._verify_user_note_row(note_row),
                    )
                )

        encoded_records = _canonical_json([entry[4] for entry in entries]).encode("utf-8")
        if len(encoded_records) > MAX_REVIEW_BATCH_JSON_BYTES:
            raise ValueError("reviewed record batch exceeds the CasePacket byte limit")

        scopes = {entry[0] for entry in entries}
        subjects = {entry[1] for entry in entries}
        sources = {entry[2] for entry in entries}
        if len(scopes) != 1:
            raise ValueError("receipt_ids span multiple private roots")
        if len(subjects) != 1:
            raise ValueError("receipt_ids span multiple subjects")
        if len(sources) != len(entries):
            raise ValueError("receipt_ids contain multiple reviews of the same candidate")
        return ReviewedRecordBatch(
            root_scope=next(iter(scopes)),
            subject_id=next(iter(subjects)),
            verified_at=max(entry[3] for entry in entries),
            records=tuple(entry[4] for entry in entries),
        )
