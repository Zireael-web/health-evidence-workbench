"""Tamper-evident receipts for server-retrieved public evidence metadata.

The ledger is the persistence boundary between network retrieval and later
evidence-packet construction.  Network-facing code registers the exact
``EvidenceQuery`` and ordered ``EvidenceItem`` tuple once.  Downstream callers
receive an opaque receipt and can load only the server-side snapshot bound to
that receipt; they never submit replacement evidence items at load time.

Canonical SHA-256 hashes make snapshots reproducible.  A keyed HMAC additionally
detects database edits where an attacker also recomputes the public hashes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Any

from ..contracts import (
    EvidenceItem,
    RiskEnvelope,
    evidence_item_snapshot_sha256,
    utc_now,
)
from ..privacy import PrivacyGate
from ..serialization import risk_envelope_from
from .query import EvidenceQuery, retrieval_execution_descriptor


__all__ = [
    "DuplicateRetrievalReceiptError",
    "evidence_item_snapshot_sha256",
    "RetrievalLedger",
    "RetrievalLedgerIntegrityError",
    "RetrievalReceipt",
    "RetrievalSource",
    "RetrievedEvidence",
    "UnknownRetrievalReceiptError",
]


_HEX_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_RECEIPT_ID = re.compile(r"retr_[a-f0-9]{32}\Z")
_NONCE = re.compile(r"[a-f0-9]{32}\Z")
_CANONICAL_DOI = re.compile(r"10\.[0-9]{4,9}/[^\s?#]{1,480}\Z", re.ASCII)
_MAX_QUERY_JSON_BYTES = 64 * 1024
_MAX_EXECUTION_JSON_BYTES = 64 * 1024
_MAX_ITEM_JSON_BYTES = 256 * 1024
_MAX_TOTAL_ITEM_JSON_BYTES = 8 * 1024 * 1024
_MAX_ITEMS_PER_RETRIEVAL = 100
_MAX_RECEIPTS_PER_LOAD = 100


class RetrievalSource(StrEnum):
    PUBMED = "pubmed"
    CROSSREF = "crossref"


class UnknownRetrievalReceiptError(ValueError):
    """Raised when a requested retrieval receipt is absent."""


class DuplicateRetrievalReceiptError(ValueError):
    """Raised when one load request repeats a receipt identifier."""


class RetrievalLedgerIntegrityError(RuntimeError):
    """Raised when persisted retrieval data no longer matches its binding."""


@dataclass(frozen=True, slots=True)
class RetrievalReceipt:
    """Opaque handle plus non-sensitive canonical snapshot hashes."""

    receipt_id: str
    source: str
    query_id: str
    query_sha256: str
    execution_sha256: str
    results_sha256: str
    item_sha256s: tuple[str, ...]
    item_count: int
    registered_at: str
    risk_envelope: RiskEnvelope


@dataclass(frozen=True, slots=True)
class RetrievedEvidence:
    """Exact query and ordered items loaded from one verified receipt."""

    receipt: RetrievalReceipt
    query: EvidenceQuery
    execution: dict[str, Any]
    items: tuple[EvidenceItem, ...]


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _query_from_json(value: str) -> EvidenceQuery:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise TypeError("query JSON must be an object")
    for key in ("outcomes", "source_types", "jurisdictions"):
        raw = payload.get(key, ())
        if not isinstance(raw, list):
            raise TypeError(f"query field {key} must be an array")
        payload[key] = tuple(raw)
    if "risk_envelope" in payload:
        payload["risk_envelope"] = risk_envelope_from(payload["risk_envelope"])
    return EvidenceQuery(**payload)


def _item_from_json(value: str) -> EvidenceItem:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise TypeError("evidence-item JSON must be an object")
    for key in ("limitations", "supersedes"):
        raw = payload.get(key, ())
        if not isinstance(raw, list):
            raise TypeError(f"evidence-item field {key} must be an array")
        payload[key] = tuple(raw)
    identifiers = payload.get("identifiers", {})
    if not isinstance(identifiers, dict):
        raise TypeError("evidence-item identifiers must be an object")
    payload["identifiers"] = dict(identifiers)
    return EvidenceItem(**payload)


def _execution_from_json(value: str) -> dict[str, Any]:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise TypeError("execution JSON must be an object")
    return payload


def _validated_execution(
    source: RetrievalSource,
    query: EvidenceQuery,
    execution: dict[str, Any] | None,
    *,
    items: tuple[EvidenceItem, ...] = (),
) -> dict[str, Any]:
    if source is RetrievalSource.PUBMED:
        if execution is None:
            summary_ids = tuple(
                item.evidence_id.removeprefix("pmid:") for item in items
            )
            resolved = retrieval_execution_descriptor(
                source.value,
                query,
                pubmed_summary_ids=summary_ids,
            )
        else:
            resolved = execution
            try:
                summary_ids = tuple(resolved["requests"][1]["ordered_ids"])
            except (KeyError, IndexError, TypeError):
                raise ValueError("PubMed execution descriptor is missing summary IDs") from None
        expected = retrieval_execution_descriptor(
            source.value,
            query,
            pubmed_summary_ids=summary_ids,
        )
        item_pmids = {
            item.evidence_id.removeprefix("pmid:") for item in items
        }
        if not item_pmids.issubset(set(summary_ids)):
            raise ValueError("PubMed items are not bound to the executed summary request")
    else:
        expected = retrieval_execution_descriptor(source.value, query)
        resolved = expected if execution is None else execution
    if not isinstance(resolved, dict) or resolved != expected:
        raise ValueError(
            "execution descriptor must exactly match the credential-free server request"
        )
    encoded = _canonical_json(resolved).encode("utf-8")
    if len(encoded) > _MAX_EXECUTION_JSON_BYTES:
        raise ValueError("execution descriptor exceeds the canonical size limit")
    return json.loads(encoded.decode("utf-8"))


def _source(value: str | RetrievalSource) -> RetrievalSource:
    try:
        return RetrievalSource(value)
    except (TypeError, ValueError):
        raise ValueError("source must be 'pubmed' or 'crossref'") from None


def _validate_item_for_source(source: RetrievalSource, item: EvidenceItem) -> None:
    if not isinstance(item, EvidenceItem):
        raise TypeError("items must contain EvidenceItem instances")
    if not isinstance(item.evidence_id, str) or not item.evidence_id:
        raise ValueError("retrieved evidence item requires a string evidence_id")
    if not isinstance(item.url, str):
        raise ValueError("retrieved evidence item requires a string URL")
    if (
        not isinstance(item.content_hash, str)
        or not _HEX_SHA256.fullmatch(item.content_hash)
    ):
        raise ValueError("retrieved evidence item requires a lowercase SHA-256 content_hash")
    if not isinstance(item.identifiers, dict) or len(item.identifiers) > 50:
        raise ValueError("evidence identifiers must be a bounded object")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in item.identifiers.items()
    ):
        raise ValueError("evidence identifiers must contain string keys and values")
    PrivacyGate().assert_public_payload(asdict(item))

    if source is RetrievalSource.PUBMED:
        if not item.evidence_id.startswith("pmid:"):
            raise ValueError("PubMed results require a pmid: evidence identifier")
        pmid = item.evidence_id.removeprefix("pmid:")
        if not re.fullmatch(r"[1-9][0-9]{0,15}", pmid):
            raise ValueError("PubMed result contains an invalid PMID")
        if item.identifiers.get("pmid") != pmid:
            raise ValueError("PubMed result identifier does not match its PMID")
        if item.url != f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/":
            raise ValueError("PubMed result URL does not match its PMID")
        return

    if not item.evidence_id.startswith("doi:"):
        raise ValueError("Crossref results require a doi: evidence identifier")
    doi = item.evidence_id.removeprefix("doi:")
    if doi != doi.casefold() or _CANONICAL_DOI.fullmatch(doi) is None:
        raise ValueError("Crossref result contains an invalid canonical DOI")
    if item.identifiers.get("doi", "").casefold() != doi:
        raise ValueError("Crossref result identifier does not match its DOI")
    if item.url != f"https://doi.org/{doi}":
        raise ValueError("Crossref result URL does not match its DOI")


class RetrievalLedger:
    """Persistent, source-bound retrieval receipts backed by private-mode SQLite."""

    def __init__(self, database_path: str | Path, *, integrity_key: bytes) -> None:
        self.database_path = Path(database_path)
        self._integrity_key = bytes(integrity_key)
        if len(self._integrity_key) < 32:
            raise ValueError("retrieval-ledger integrity key must contain at least 32 bytes")
        if str(self.database_path) == ":memory:":
            raise ValueError("retrieval ledger requires a persistent filesystem database")
        self._prepare_database()
        self._initialize()

    def _mac(self, value: Any) -> str:
        return hmac.new(
            self._integrity_key,
            _canonical_json(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _prepare_database(self) -> None:
        parent = self.database_path.parent
        if parent.is_symlink():
            raise ValueError("retrieval-ledger parent must not be a symbolic link")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("retrieval-ledger parent must be a private directory")
        parent.chmod(0o700)

        if self.database_path.is_symlink():
            raise ValueError("retrieval-ledger database must not be a symbolic link")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.database_path, flags, 0o600)
        try:
            file_state = os.fstat(descriptor)
            if not stat.S_ISREG(file_state.st_mode):
                raise ValueError("retrieval-ledger database must be a regular file")
            if file_state.st_nlink != 1:
                raise ValueError("retrieval-ledger database must not be multiply linked")
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
            raise ValueError("retrieval-ledger path is no longer a private regular file")
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS retrieval_run (
                    receipt_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL CHECK(source IN ('pubmed', 'crossref')),
                    query_id TEXT NOT NULL,
                    query_sha256 TEXT NOT NULL,
                    query_json TEXT NOT NULL,
                    results_sha256 TEXT NOT NULL,
                    item_count INTEGER NOT NULL CHECK(item_count >= 0),
                    registered_at TEXT NOT NULL,
                    nonce TEXT NOT NULL UNIQUE,
                    binding_hmac TEXT NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS retrieval_item (
                    receipt_id TEXT NOT NULL REFERENCES retrieval_run(receipt_id),
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                    evidence_id TEXT NOT NULL,
                    item_sha256 TEXT NOT NULL,
                    item_json TEXT NOT NULL,
                    PRIMARY KEY(receipt_id, ordinal),
                    UNIQUE(receipt_id, evidence_id)
                );

                CREATE TABLE IF NOT EXISTS retrieval_execution (
                    receipt_id TEXT PRIMARY KEY REFERENCES retrieval_run(receipt_id),
                    execution_sha256 TEXT NOT NULL,
                    execution_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS retrieval_run_query_idx
                    ON retrieval_run(source, query_id, registered_at);
                """
            )
        self.database_path.chmod(0o600)
        self.database_path.parent.chmod(0o700)

    @staticmethod
    def _results_sha256(
        source: RetrievalSource,
        query_sha256: str,
        item_rows: tuple[dict[str, Any], ...],
    ) -> str:
        return _sha256_text(
            _canonical_json(
                {
                    "schema": "retrieval-results-v1",
                    "source": source.value,
                    "query_sha256": query_sha256,
                    "items": [
                        {
                            "ordinal": item["ordinal"],
                            "evidence_id": item["evidence_id"],
                            "item_sha256": item["item_sha256"],
                        }
                        for item in item_rows
                    ],
                }
            )
        )

    @staticmethod
    def _binding_material(
        *,
        source: RetrievalSource,
        query_id: str,
        query_sha256: str,
        results_sha256: str,
        execution_sha256: str,
        item_count: int,
        registered_at: str,
        nonce: str,
    ) -> dict[str, Any]:
        return {
            "schema": "retrieval-ledger-binding-v2",
            "source": source.value,
            "query_id": query_id,
            "query_sha256": query_sha256,
            "execution_sha256": execution_sha256,
            "results_sha256": results_sha256,
            "item_count": item_count,
            "registered_at": registered_at,
            "nonce": nonce,
        }

    def register(
        self,
        source: str | RetrievalSource,
        query: EvidenceQuery,
        items: tuple[EvidenceItem, ...],
        *,
        execution: dict[str, Any] | None = None,
    ) -> RetrievalReceipt:
        """Persist one exact server retrieval and return its opaque receipt."""

        resolved_source = _source(source)
        if not isinstance(query, EvidenceQuery):
            raise TypeError("query must be an EvidenceQuery")
        if not isinstance(items, tuple):
            raise TypeError("items must be a tuple of EvidenceItem instances")
        query.validate()
        if len(items) > query.max_results:
            raise ValueError("retrieval returned more items than the query requested")

        if any(not isinstance(item, EvidenceItem) for item in items):
            raise TypeError("items must contain EvidenceItem instances")
        for item in items:
            _validate_item_for_source(resolved_source, item)
        evidence_ids = [item.evidence_id for item in items]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("retrieval results must not contain duplicate evidence identifiers")

        query_json = _canonical_json(asdict(query))
        if len(query_json.encode("utf-8")) > _MAX_QUERY_JSON_BYTES:
            raise ValueError("retrieval query exceeds the canonical size limit")
        query_sha256 = _sha256_text(query_json)
        resolved_execution = _validated_execution(
            resolved_source,
            query,
            execution,
            items=items,
        )
        execution_json = _canonical_json(resolved_execution)
        execution_sha256 = _sha256_text(execution_json)

        item_rows: list[dict[str, Any]] = []
        total_item_bytes = 0
        for ordinal, item in enumerate(items):
            item_json = _canonical_json(asdict(item))
            item_size = len(item_json.encode("utf-8"))
            if item_size > _MAX_ITEM_JSON_BYTES:
                raise ValueError("retrieval item exceeds the canonical size limit")
            total_item_bytes += item_size
            if total_item_bytes > _MAX_TOTAL_ITEM_JSON_BYTES:
                raise ValueError("retrieval results exceed the cumulative size limit")
            item_rows.append(
                {
                    "ordinal": ordinal,
                    "evidence_id": item.evidence_id,
                    "item_sha256": _sha256_text(item_json),
                    "item_json": item_json,
                }
            )
        frozen_item_rows = tuple(item_rows)
        results_sha256 = self._results_sha256(
            resolved_source,
            query_sha256,
            frozen_item_rows,
        )
        registered_at = utc_now()
        nonce = secrets.token_hex(16)
        material = self._binding_material(
            source=resolved_source,
            query_id=query.query_id,
            query_sha256=query_sha256,
            execution_sha256=execution_sha256,
            results_sha256=results_sha256,
            item_count=len(items),
            registered_at=registered_at,
            nonce=nonce,
        )
        binding_hmac = self._mac(material)
        receipt_id = "retr_" + self._mac(
            {
                "schema": "retrieval-ledger-receipt-id-v1",
                "binding_hmac": binding_hmac,
            }
        )[:32]

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO retrieval_run(
                        receipt_id, source, query_id, query_sha256, query_json,
                        results_sha256, item_count, registered_at, nonce, binding_hmac
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt_id,
                        resolved_source.value,
                        query.query_id,
                        query_sha256,
                        query_json,
                        results_sha256,
                        len(items),
                        registered_at,
                        nonce,
                        binding_hmac,
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO retrieval_item(
                        receipt_id, ordinal, evidence_id, item_sha256, item_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            receipt_id,
                            item["ordinal"],
                            item["evidence_id"],
                            item["item_sha256"],
                            item["item_json"],
                        )
                        for item in frozen_item_rows
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO retrieval_execution(
                        receipt_id, execution_sha256, execution_json
                    ) VALUES (?, ?, ?)
                    """,
                    (receipt_id, execution_sha256, execution_json),
                )
        except sqlite3.IntegrityError as error:
            raise RetrievalLedgerIntegrityError(
                "retrieval receipt could not be persisted without a collision"
            ) from error
        self.database_path.chmod(0o600)

        return RetrievalReceipt(
            receipt_id=receipt_id,
            source=resolved_source.value,
            query_id=query.query_id,
            query_sha256=query_sha256,
            execution_sha256=execution_sha256,
            results_sha256=results_sha256,
            item_sha256s=tuple(item["item_sha256"] for item in frozen_item_rows),
            item_count=len(items),
            registered_at=registered_at,
            risk_envelope=query.risk_envelope,
        )

    def _load_verified(self, receipt_id: str) -> RetrievedEvidence:
        with self._connect() as connection:
            run = connection.execute(
                "SELECT * FROM retrieval_run WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if run is None:
                raise UnknownRetrievalReceiptError(
                    f"retrieval receipt is not present in the ledger: {receipt_id}"
                )
            rows = connection.execute(
                """
                SELECT ordinal, evidence_id, item_sha256, item_json
                FROM retrieval_item
                WHERE receipt_id = ?
                ORDER BY ordinal
                LIMIT ?
                """,
                (receipt_id, _MAX_ITEMS_PER_RETRIEVAL + 1),
            ).fetchall()
            execution_row = connection.execute(
                """
                SELECT execution_sha256, execution_json
                FROM retrieval_execution WHERE receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()

        try:
            resolved_source = _source(run["source"])
            if not _NONCE.fullmatch(run["nonce"]):
                raise ValueError("invalid nonce")
            if (
                not isinstance(run["query_json"], str)
                or not isinstance(run["item_count"], int)
                or not 0 <= run["item_count"] <= _MAX_ITEMS_PER_RETRIEVAL
                or len(rows) > _MAX_ITEMS_PER_RETRIEVAL
                or len(run["query_json"].encode("utf-8")) > _MAX_QUERY_JSON_BYTES
            ):
                raise ValueError("stored retrieval exceeds structural limits")
            query = _query_from_json(run["query_json"])
            canonical_query_json = _canonical_json(asdict(query))
            query_sha256 = _sha256_text(canonical_query_json)
            if execution_row is None or not isinstance(execution_row["execution_json"], str):
                raise ValueError("retrieval execution descriptor is missing")
            if (
                len(execution_row["execution_json"].encode("utf-8"))
                > _MAX_EXECUTION_JSON_BYTES
            ):
                raise ValueError("retrieval execution descriptor exceeds its size limit")
            execution = _execution_from_json(execution_row["execution_json"])
            canonical_execution_json = _canonical_json(execution)
            execution_sha256 = _sha256_text(canonical_execution_json)
            if (
                execution_row["execution_json"] != canonical_execution_json
                or execution_row["execution_sha256"] != execution_sha256
            ):
                raise ValueError("retrieval execution binding mismatch")

            item_rows: list[dict[str, Any]] = []
            loaded_items: list[EvidenceItem] = []
            total_item_bytes = 0
            for expected_ordinal, row in enumerate(rows):
                if row["ordinal"] != expected_ordinal:
                    raise ValueError("non-contiguous item ordinals")
                if (
                    not isinstance(row["item_json"], str)
                    or len(row["item_json"].encode("utf-8")) > _MAX_ITEM_JSON_BYTES
                ):
                    raise ValueError("item size limit exceeded")
                item = _item_from_json(row["item_json"])
                _validate_item_for_source(resolved_source, item)
                canonical_item_json = _canonical_json(asdict(item))
                item_size = len(canonical_item_json.encode("utf-8"))
                total_item_bytes += item_size
                if (
                    item_size > _MAX_ITEM_JSON_BYTES
                    or total_item_bytes > _MAX_TOTAL_ITEM_JSON_BYTES
                ):
                    raise ValueError("item size limit exceeded")
                item_sha256 = _sha256_text(canonical_item_json)
                if (
                    row["item_json"] != canonical_item_json
                    or row["item_sha256"] != item_sha256
                    or row["evidence_id"] != item.evidence_id
                ):
                    raise ValueError("item canonical binding mismatch")
                item_rows.append(
                    {
                        "ordinal": expected_ordinal,
                        "evidence_id": item.evidence_id,
                        "item_sha256": item_sha256,
                        "item_json": canonical_item_json,
                    }
                )
                loaded_items.append(item)

            execution = _validated_execution(
                resolved_source,
                query,
                execution,
                items=tuple(loaded_items),
            )
            canonical_execution_json = _canonical_json(execution)
            execution_sha256 = _sha256_text(canonical_execution_json)

            frozen_item_rows = tuple(item_rows)
            results_sha256 = self._results_sha256(
                resolved_source,
                query_sha256,
                frozen_item_rows,
            )
            material = self._binding_material(
                source=resolved_source,
                query_id=query.query_id,
                query_sha256=query_sha256,
                execution_sha256=execution_sha256,
                results_sha256=results_sha256,
                item_count=len(loaded_items),
                registered_at=run["registered_at"],
                nonce=run["nonce"],
            )
            binding_hmac = self._mac(material)
            expected_receipt_id = "retr_" + self._mac(
                {
                    "schema": "retrieval-ledger-receipt-id-v1",
                    "binding_hmac": binding_hmac,
                }
            )[:32]
            if (
                run["query_json"] != canonical_query_json
                or run["query_id"] != query.query_id
                or run["query_sha256"] != query_sha256
                or run["results_sha256"] != results_sha256
                or run["item_count"] != len(loaded_items)
                or not hmac.compare_digest(run["binding_hmac"], binding_hmac)
                or not hmac.compare_digest(expected_receipt_id, run["receipt_id"])
                or not hmac.compare_digest(receipt_id, run["receipt_id"])
            ):
                raise ValueError("retrieval binding mismatch")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RetrievalLedgerIntegrityError(
                "retrieval receipt canonical binding is invalid"
            ) from error

        receipt = RetrievalReceipt(
            receipt_id=run["receipt_id"],
            source=resolved_source.value,
            query_id=query.query_id,
            query_sha256=query_sha256,
            execution_sha256=execution_sha256,
            results_sha256=results_sha256,
            item_sha256s=tuple(item["item_sha256"] for item in frozen_item_rows),
            item_count=len(loaded_items),
            registered_at=run["registered_at"],
            risk_envelope=query.risk_envelope,
        )
        return RetrievedEvidence(receipt, query, execution, tuple(loaded_items))

    def load_receipt(self, receipt_id: str) -> RetrievedEvidence:
        """Load and verify one exact server-side retrieval snapshot."""

        return self.load_receipts([receipt_id])[0]

    def load_receipts(self, receipt_ids: list[str]) -> tuple[RetrievedEvidence, ...]:
        """Load verified snapshots in request order, rejecting unknown/duplicate IDs."""

        if not isinstance(receipt_ids, list) or not receipt_ids:
            raise ValueError("receipt_ids must be a non-empty list")
        if len(receipt_ids) > _MAX_RECEIPTS_PER_LOAD:
            raise ValueError("receipt_ids exceeds the batch limit")
        if any(not isinstance(receipt_id, str) for receipt_id in receipt_ids):
            raise ValueError("receipt_id must be an opaque retr_ identifier")
        if len(set(receipt_ids)) != len(receipt_ids):
            raise DuplicateRetrievalReceiptError(
                "receipt_ids must not contain duplicate retrieval receipts"
            )
        for receipt_id in receipt_ids:
            if not _RECEIPT_ID.fullmatch(receipt_id):
                raise ValueError("receipt_id must be an opaque retr_ identifier")
        return tuple(self._load_verified(receipt_id) for receipt_id in receipt_ids)
