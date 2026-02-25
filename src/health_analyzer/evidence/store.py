"""Versioned SQLite evidence metadata store with optional FTS5 search."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from ..contracts import (
    EvidenceItem,
    EvidencePacket,
    ReviewedEvidenceClaim,
    SearchLogEntry,
    utc_now,
)
from ..privacy import PrivacyGate
from .query import EvidenceQuery, EvidenceSourcePolicy


MAX_EVIDENCE_PACKET_JSON_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_ITEMS = 100
MAX_EVIDENCE_SEARCH_RUNS = 100
MAX_REVIEWED_EVIDENCE_CLAIMS = 100


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


class EvidenceStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fts_enabled = False
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_snapshot (
                    snapshot_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    published_at TEXT,
                    retrieved_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE (evidence_id, content_hash)
                );
                CREATE INDEX IF NOT EXISTS evidence_snapshot_evidence_id
                    ON evidence_snapshot(evidence_id, retrieved_at DESC);
                CREATE TABLE IF NOT EXISTS search_run (
                    run_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    query_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    query_json TEXT NOT NULL,
                    result_ids_json TEXT NOT NULL
                );
                """
            )
            search_run_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(search_run)").fetchall()
            }
            if "source" not in search_run_columns:
                connection.execute(
                    """ALTER TABLE search_run ADD COLUMN source TEXT NOT NULL
                       DEFAULT 'legacy_unknown'"""
                )
            try:
                connection.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(snapshot_id, title)"
                )
                self._fts_enabled = True
            except sqlite3.OperationalError:
                self._fts_enabled = False

    def store(
        self,
        query: EvidenceQuery,
        items: tuple[EvidenceItem, ...],
        *,
        source: str = "manual_snapshot",
        search_log: tuple[SearchLogEntry, ...] | None = None,
        reviewed_claims: tuple[ReviewedEvidenceClaim, ...] = (),
        limitations: tuple[str, ...] = (),
        retrieved_at: str | None = None,
    ) -> EvidencePacket:
        if not isinstance(query, EvidenceQuery):
            raise TypeError("query must be an EvidenceQuery")
        if not isinstance(items, tuple) or any(
            not isinstance(item, EvidenceItem) for item in items
        ):
            raise TypeError("items must be a tuple of EvidenceItem instances")
        if not isinstance(reviewed_claims, tuple) or any(
            not isinstance(claim, ReviewedEvidenceClaim) for claim in reviewed_claims
        ):
            raise TypeError(
                "reviewed_claims must be a tuple of ReviewedEvidenceClaim instances"
            )
        if not isinstance(limitations, tuple) or any(
            not isinstance(limitation, str) for limitation in limitations
        ):
            raise TypeError("limitations must be a tuple of strings")
        if len(items) > MAX_EVIDENCE_ITEMS:
            raise ValueError("evidence items exceed the packet item limit")
        if len(reviewed_claims) > MAX_REVIEWED_EVIDENCE_CLAIMS:
            raise ValueError("reviewed claims exceed the packet item limit")
        query.validate()
        if not isinstance(source, str) or not source.strip():
            raise ValueError("evidence source is required")
        policy = EvidenceSourcePolicy()
        started_at = utc_now()
        if search_log is None:
            run_id = "run_" + hashlib.sha256(
                f"{query.query_id}|{source}|{started_at}".encode("utf-8")
            ).hexdigest()[:20]
            resolved_search_log = (
                SearchLogEntry(
                    run_id=run_id,
                    source=source,
                    query_id=query.query_id,
                    executed_at=started_at,
                    query=asdict(query),
                    result_ids=tuple(item.evidence_id for item in items),
                ),
            )
        else:
            if not isinstance(search_log, tuple) or any(
                not isinstance(entry, SearchLogEntry) for entry in search_log
            ):
                raise TypeError("search_log must be a tuple of SearchLogEntry instances")
            if not search_log:
                raise ValueError("search_log must contain at least one issued retrieval")
            resolved_search_log = search_log
            expected_query = asdict(query)
            expected_risk = asdict(query.risk_envelope)
            for entry in resolved_search_log:
                if (
                    not isinstance(entry.query, dict)
                    or not isinstance(entry.result_ids, tuple)
                    or any(not isinstance(result_id, str) for result_id in entry.result_ids)
                    or len(set(entry.result_ids)) != len(entry.result_ids)
                    or not all(
                        isinstance(value, str) and value.strip()
                        for value in (
                            entry.run_id,
                            entry.source,
                            entry.query_id,
                            entry.executed_at,
                        )
                    )
                ):
                    raise ValueError("search log entry is malformed")
                logged_query = entry.query.get("structured_query", entry.query)
                if (
                    not isinstance(logged_query, dict)
                    or logged_query.get("question") != query.question
                    or logged_query.get("risk_envelope") != expected_risk
                ):
                    raise ValueError(
                        "search log question and risk envelope must match the evidence query"
                    )
                if "structured_query" in entry.query:
                    if set(logged_query) != set(expected_query):
                        raise ValueError(
                            "search log structured_query fields are invalid"
                        )
                    logged_query_id = "query_" + hashlib.sha256(
                        json.dumps(
                            logged_query,
                            ensure_ascii=False,
                            sort_keys=True,
                        ).encode("utf-8")
                    ).hexdigest()[:20]
                    if entry.query_id != logged_query_id:
                        raise ValueError(
                            "search log query_id does not match its structured query"
                        )
                elif entry.query_id != query.query_id:
                    raise ValueError("search log query_id must match the evidence query")
            run_ids = [entry.run_id for entry in resolved_search_log]
            if len(run_ids) != len(set(run_ids)):
                raise ValueError("search log run IDs must be unique")
            logged_result_ids = {
                result_id
                for entry in resolved_search_log
                for result_id in entry.result_ids
            }
            item_ids = {item.evidence_id for item in items}
            if item_ids != logged_result_ids:
                raise ValueError("search log result IDs must exactly match stored evidence items")
        if len(resolved_search_log) > MAX_EVIDENCE_SEARCH_RUNS:
            raise ValueError("search log exceeds the packet run limit")

        packet_material = {
            "schema_version": "1.3",
            "question": query.question,
            "items": [asdict(item) for item in items],
            "reviewed_claims": [asdict(claim) for claim in reviewed_claims],
            "search_log": [asdict(entry) for entry in resolved_search_log],
            "limitations": limitations,
            "risk_envelope": asdict(query.risk_envelope),
        }
        packet_json = _canonical_json(packet_material)
        if len(packet_json.encode("utf-8")) > MAX_EVIDENCE_PACKET_JSON_BYTES:
            raise ValueError("evidence packet exceeds the canonical size limit")
        privacy_search_log = [
            {
                "source": entry.source,
                "query_id": entry.query_id,
                "query": entry.query.get("structured_query", entry.query),
                "result_ids": entry.result_ids,
            }
            for entry in resolved_search_log
        ]
        PrivacyGate().assert_public_payload(
            {
                "query": asdict(query),
                "items": [asdict(item) for item in items],
                "reviewed_claims": [asdict(claim) for claim in reviewed_claims],
                "search_log": privacy_search_log,
                "limitations": limitations,
            }
        )
        packet_id = "evidence_" + hashlib.sha256(packet_json.encode("utf-8")).hexdigest()[:24]
        packet = EvidencePacket(
            packet_id=packet_id,
            question=query.question,
            items=items,
            reviewed_claims=reviewed_claims,
            retrieved_at=retrieved_at or started_at,
            search_log=resolved_search_log,
            limitations=limitations,
            risk_envelope=query.risk_envelope,
        )
        for item in items:
            policy.assert_allowed(item.url)

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for item in items:
                payload = asdict(item)
                content_hash = item.content_hash or hashlib.sha256(
                    _canonical_json(payload).encode("utf-8")
                ).hexdigest()
                if re.fullmatch(r"[a-f0-9]{64}", content_hash) is None:
                    raise ValueError(
                        "evidence item content_hash must be a lowercase SHA-256 digest"
                    )
                snapshot_id = "snapshot_" + hashlib.sha256(
                    f"{item.evidence_id}|{content_hash}".encode("utf-8")
                ).hexdigest()[:24]
                payload_json = _canonical_json(payload)
                existing = connection.execute(
                    """SELECT snapshot_id, payload_json FROM evidence_snapshot
                       WHERE snapshot_id = ? OR (evidence_id = ? AND content_hash = ?)""",
                    (snapshot_id, item.evidence_id, content_hash),
                ).fetchone()
                inserted = existing is None
                if existing is not None:
                    try:
                        existing_payload = json.loads(existing["payload_json"])
                    except (TypeError, json.JSONDecodeError):
                        raise ValueError("stored evidence snapshot is malformed") from None
                    comparison_payload = dict(payload)
                    if not isinstance(existing_payload, dict):
                        raise ValueError("stored evidence snapshot is malformed")
                    existing_payload.pop("retrieved_at", None)
                    comparison_payload.pop("retrieved_at", None)
                    if (
                        existing["snapshot_id"] != snapshot_id
                        or _canonical_json(existing_payload)
                        != _canonical_json(comparison_payload)
                    ):
                        raise ValueError(
                            "evidence snapshot identity collides with different metadata"
                        )
                else:
                    connection.execute(
                        """INSERT INTO evidence_snapshot
                        (snapshot_id, evidence_id, title, source_type, url, published_at,
                         retrieved_at, content_hash, payload_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            snapshot_id,
                            item.evidence_id,
                            item.title,
                            item.source_type,
                            item.url,
                            item.published_at,
                            item.retrieved_at,
                            content_hash,
                            payload_json,
                        ),
                    )
                if self._fts_enabled and inserted:
                    connection.execute(
                        "INSERT INTO evidence_fts (snapshot_id, title) VALUES (?, ?)",
                        (snapshot_id, item.title),
                    )
            for entry in resolved_search_log:
                query_json = _canonical_json(entry.query)
                result_ids_json = _canonical_json(entry.result_ids)
                values = (
                    entry.source,
                    entry.query_id,
                    entry.executed_at,
                    query_json,
                    result_ids_json,
                )
                existing = connection.execute(
                    """SELECT source, query_id, started_at, query_json, result_ids_json
                       FROM search_run WHERE run_id = ?""",
                    (entry.run_id,),
                ).fetchone()
                if existing is not None:
                    try:
                        stored_query = json.loads(existing["query_json"])
                        stored_result_ids = json.loads(existing["result_ids_json"])
                    except (TypeError, json.JSONDecodeError):
                        raise ValueError("stored search run is malformed") from None
                    if (
                        existing["source"] != entry.source
                        or existing["query_id"] != entry.query_id
                        or existing["started_at"] != entry.executed_at
                        or _canonical_json(stored_query) != query_json
                        or _canonical_json(stored_result_ids) != result_ids_json
                    ):
                        raise ValueError(
                            "search run identity collides with different metadata"
                        )
                else:
                    connection.execute(
                        """INSERT INTO search_run
                        (run_id, source, query_id, started_at, query_json, result_ids_json)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                        (entry.run_id, *values),
                    )
        return packet

    def latest(self, evidence_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload_json FROM evidence_snapshot WHERE evidence_id = ?
                ORDER BY retrieved_at DESC LIMIT 1""",
                (evidence_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def search_titles(self, text: str, *, limit: int = 20) -> list[dict[str, object]]:
        if not text.strip():
            return []
        with self._connect() as connection:
            if self._fts_enabled:
                tokens = re.findall(r"\w+", text, flags=re.UNICODE)
                if not tokens:
                    return []
                fts_query = " AND ".join(f'"{token}"' for token in tokens)
                try:
                    rows = connection.execute(
                        """SELECT s.payload_json FROM evidence_fts f
                        JOIN evidence_snapshot s ON s.snapshot_id = f.snapshot_id
                        WHERE evidence_fts MATCH ? LIMIT ?""",
                        (fts_query, limit),
                    ).fetchall()
                except sqlite3.OperationalError:
                    rows = connection.execute(
                        "SELECT payload_json FROM evidence_snapshot WHERE title LIKE ? LIMIT ?",
                        (f"%{text}%", limit),
                    ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT payload_json FROM evidence_snapshot WHERE title LIKE ? LIMIT ?",
                    (f"%{text}%", limit),
                ).fetchall()
        return [json.loads(row[0]) for row in rows]
