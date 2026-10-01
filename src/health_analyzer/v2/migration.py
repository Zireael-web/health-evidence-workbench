"""Bounded, owned synthetic migration exercise; not a real legacy adapter.

The only accepted physical schema is written by SyntheticLegacyFixture. No CLI,
MCP, production record service or default path exposes this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
from typing import Iterable

from .common import SignedStore, V2Error, canonical, digest, require, utc_now
from .exercise_scope import require_owned_synthetic_path, verify_synthetic_exercise

LEGACY_SCHEMA = "health-analyzer.synthetic-legacy/1"
MAPPING_VERSION = "synthetic-preservation/1"
MAX_RECORDS = 10_000
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_BATCH_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
CONTEXT_RULE = "legacy-context/1"
DISPOSITIONS = frozenset({"trusted_projected", "preserved_only", "quarantined"})
SCHEMAS = {
    "legacy_records": "health-analyzer.synthetic-legacy-record/1",
    "legacy_payload_chunk": "health-analyzer.synthetic-legacy-chunk/1",
    "legacy_mapping": "health-analyzer.synthetic-legacy-mapping/1",
    "migration_disposition": "health-analyzer.synthetic-migration-disposition/1",
    "quarantine": "health-analyzer.synthetic-migration-quarantine/1",
    "legacy_projection": "health-analyzer.synthetic-legacy-projection/1",
    "migration_reconciliation_group": "health-analyzer.synthetic-migration-group/1",
    "migration_run": "health-analyzer.synthetic-migration-run/1",
}


def _key_id(key: bytes) -> str:
    require(isinstance(key, bytes) and len(key) >= 32, "SYNTHETIC_KEY", "Explicit test key must contain at least 32 bytes")
    return "test_sha256_" + hashlib.sha256(key).hexdigest()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mac(key: bytes, metadata: dict, raw: bytes = b"") -> str:
    # This is exclusively the fixture schema's HMAC contract, not a legacy MAC.
    header = canonical(metadata)
    return hmac.new(key, b"ha-synthetic-legacy/1\0" + len(header).to_bytes(8, "big") + header + raw, hashlib.sha256).hexdigest()


def _valid_mac(value: object, expected: str) -> bool:
    return isinstance(value, str) and hmac.compare_digest(value.encode("utf-8"), expected.encode("ascii"))


def _text(value: object, label: str, maximum: int = 256) -> str:
    require(isinstance(value, str) and 0 < len(value) <= maximum and "\x00" not in value,
            "SYNTHETIC_STRUCTURE", f"Invalid synthetic {label}")
    return value


def _json(raw: bytes) -> object:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def _sealed_path(root: Path, path: str | Path) -> Path:
    result = require_owned_synthetic_path(root, path, must_exist=True)
    require(result.is_file(), "SYNTHETIC_SOURCE", "Source must be an owned regular fixture file")
    for suffix in ("-wal", "-shm", "-journal"):
        candidate = require_owned_synthetic_path(root, str(result) + suffix)
        require(not candidate.exists(), "SYNTHETIC_NOT_SEALED", "Fixture must be sealed without WAL, SHM or journal sidecars")
    require(result.stat().st_size <= MAX_SOURCE_BYTES, "MIGRATION_BYTE_LIMIT", "Sealed fixture file exceeds byte cap")
    fd = os.open(result, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        header = os.read(fd, 100)
    finally:
        os.close(fd)
    require(header[:16] == b"SQLite format 3\x00" and len(header) == 100,
            "SYNTHETIC_FOREIGN_SCHEMA", "Source is not a sealed SQLite fixture")
    require(header[18:20] == b"\x01\x01", "SYNTHETIC_NOT_SEALED",
            "Fixture must use rollback-journal format, never a live or WAL-header database")
    return result


def _file_hash(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        require(info.st_nlink == 1 and info.st_size <= MAX_SOURCE_BYTES,
                "SYNTHETIC_SOURCE", "Fixture file identity or byte cap changed")
        sha = hashlib.sha256()
        total = 0
        while raw := os.read(fd, 1024 * 1024):
            total += len(raw)
            require(total <= MAX_SOURCE_BYTES, "MIGRATION_BYTE_LIMIT", "Source exceeds byte cap")
            sha.update(raw)
        after = os.fstat(fd)
        require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
                "SYNTHETIC_SOURCE_CHANGED", "Sealed source changed during hashing")
        return sha.hexdigest()
    finally:
        os.close(fd)


@dataclass(frozen=True)
class LegacyOrigin:
    identity: dict
    scope_bytes: bytes
    raw_payload: bytes
    signature: str
    key_id: str
    subject_id: str | None
    integrity_reasons: tuple[str, ...]

    @property
    def origin_id(self) -> str:
        return "legacy_origin_" + digest(self.identity)

    @property
    def raw_sha256(self) -> str:
        return _sha(self.raw_payload)

    @property
    def parsed_payload(self) -> dict | None:
        try:
            result = _json(self.raw_payload)
            return result if isinstance(result, dict) else None
        except (ValueError, UnicodeError, TypeError):
            return None


@dataclass(frozen=True)
class SourceSnapshot:
    exercise_id: str
    source_path: Path
    metadata: dict
    sealed_file_sha256: str
    records: tuple[LegacyOrigin, ...]
    salvage: bool
    identity_bytes: bytes
    identity_signature: str
    _test_key: bytes = field(repr=False, compare=False)


class SyntheticLegacyFixture:
    """Factory for an explicitly artificial schema and supplied test keys."""

    @staticmethod
    def create(root: str | Path, path: str | Path, records: Iterable[dict], test_key: bytes,
               *, snapshot_id: str = "synthetic-snapshot-1", store_id: str = "synthetic-store-1") -> Path:
        marker = verify_synthetic_exercise(root)
        target = require_owned_synthetic_path(root, path)
        require(not target.exists() and target.parent.is_dir(), "SYNTHETIC_FIXTURE_EXISTS", "Fixture destination must be new in an existing owned directory")
        key_id = _key_id(test_key)
        metadata = {"schema_version": LEGACY_SCHEMA, "fixture_factory": "SyntheticLegacyFixture/1",
                    "exercise_id": marker["exercise_id"], "snapshot_id": _text(snapshot_id, "snapshot ID"),
                    "store_id": _text(store_id, "store ID"), "key_id": key_id, "sealed": True}
        prepared = []
        total = 0
        origins = set()
        for record in records:
            require(len(prepared) < MAX_RECORDS, "MIGRATION_COUNT_LIMIT", "Fixture count cap exceeded")
            require(isinstance(record, dict), "SYNTHETIC_STRUCTURE", "Fixture row must be an object")
            scope = record.get("scope")
            require(isinstance(scope, dict), "SYNTHETIC_STRUCTURE", "Fixture scope must be an explicit object")
            _text(scope.get("subject_id"), "subject ID", 128)
            scope_raw = canonical(scope)
            require(len(scope_raw) <= 65536, "MIGRATION_BYTE_LIMIT", "Scope exceeds byte cap")
            kind = _text(record.get("kind"), "kind", 80)
            legacy_id = _text(record.get("legacy_id"), "legacy ID")
            payload = record.get("payload")
            raw = payload if isinstance(payload, bytes) else canonical(payload)
            require(len(raw) <= MAX_PAYLOAD_BYTES, "MIGRATION_PAYLOAD_LIMIT", "Raw fixture payload exceeds 2 MiB")
            total += len(raw) + len(scope_raw)
            require(total <= MAX_BATCH_BYTES, "MIGRATION_BYTE_LIMIT", "Fixture batch bytes exceed cap")
            identity = {"snapshot_id": snapshot_id, "store_id": store_id, "kind": kind,
                        "scope": scope, "legacy_id": legacy_id}
            require(digest(identity) not in origins, "MIGRATION_DUPLICATE_ORIGIN", "Fixture origin is duplicated")
            origins.add(digest(identity))
            binding = {"schema_version": LEGACY_SCHEMA, **identity, "scope_bytes_sha256": _sha(scope_raw), "key_id": key_id}
            prepared.append((kind, sqlite3.Binary(scope_raw), legacy_id, sqlite3.Binary(raw), key_id, _mac(test_key, binding, raw)))
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        db = sqlite3.connect(target)
        try:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("CREATE TABLE synthetic_identity (metadata BLOB NOT NULL, signature TEXT NOT NULL)")
            db.execute("CREATE TABLE synthetic_records (kind TEXT NOT NULL, scope BLOB NOT NULL, legacy_id TEXT NOT NULL, payload BLOB NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL)")
            db.execute("INSERT INTO synthetic_identity VALUES (?, ?)", (sqlite3.Binary(canonical(metadata)), _mac(test_key, metadata)))
            db.executemany("INSERT INTO synthetic_records VALUES (?, ?, ?, ?, ?, ?)", prepared)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
        _sealed_path(Path(root).absolute(), target)
        return target


class SyntheticLegacyAdapter:
    """Read only a sealed owned fixture; never an ordinary/live legacy store."""

    def __init__(self, root: str | Path, source_path: str | Path, test_key: bytes):
        self.root = Path(root).absolute()
        self.source_path = require_owned_synthetic_path(self.root, source_path, must_exist=True)
        self.test_key = test_key
        _key_id(test_key)

    def read(self, *, salvage: bool = False) -> SourceSnapshot:
        require(type(salvage) is bool, "SYNTHETIC_STRUCTURE", "Salvage must be explicit boolean")
        marker = verify_synthetic_exercise(self.root)
        path = _sealed_path(self.root, self.source_path)
        before = _file_hash(path)
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            require(tables == {"synthetic_identity", "synthetic_records"}, "SYNTHETIC_FOREIGN_SCHEMA", "Only the factory's synthetic physical schema is supported")
            expected = {"synthetic_identity": [("metadata", "BLOB"), ("signature", "TEXT")],
                        "synthetic_records": [("kind", "TEXT"), ("scope", "BLOB"), ("legacy_id", "TEXT"), ("payload", "BLOB"), ("key_id", "TEXT"), ("signature", "TEXT")]}
            for table, columns in expected.items():
                actual = [(r[1], r[2]) for r in db.execute(f"PRAGMA table_info({table})")]
                require(actual == columns, "SYNTHETIC_FOREIGN_SCHEMA", "Synthetic table contract differs")
            identities = db.execute("SELECT metadata,signature FROM synthetic_identity LIMIT 2").fetchall()
            require(len(identities) == 1 and isinstance(identities[0][0], bytes) and len(identities[0][0]) <= 65536,
                    "SYNTHETIC_IDENTITY", "Exactly one bounded factory identity is required")
            metadata = _json(identities[0][0])
            require(isinstance(metadata, dict) and metadata.get("fixture_factory") == "SyntheticLegacyFixture/1"
                    and metadata.get("exercise_id") == marker["exercise_id"] and metadata.get("sealed") is True,
                    "SYNTHETIC_IDENTITY", "Fixture identity does not bind this owned exercise")
            snapshot_id = _text(metadata.get("snapshot_id"), "snapshot ID")
            store_id = _text(metadata.get("store_id"), "store ID")
            identity_reasons = []
            if metadata.get("schema_version") != LEGACY_SCHEMA:
                identity_reasons.append("unknown_schema")
            if metadata.get("key_id") != _key_id(self.test_key):
                identity_reasons.append("key_mismatch")
            if not _valid_mac(identities[0][1], _mac(self.test_key, metadata)):
                identity_reasons.append("fixture_identity_hmac_failure")
            count, payload_bytes, scope_bytes, biggest, biggest_scope = db.execute("SELECT count(*),coalesce(sum(length(payload)),0),coalesce(sum(length(scope)),0),coalesce(max(length(payload)),0),coalesce(max(length(scope)),0) FROM synthetic_records").fetchone()
            require(count <= MAX_RECORDS, "MIGRATION_COUNT_LIMIT", "Source count cap exceeded; no partial batch")
            require(biggest <= MAX_PAYLOAD_BYTES, "MIGRATION_PAYLOAD_LIMIT", "Source raw payload cap exceeded")
            require(biggest_scope <= 65536 and payload_bytes + scope_bytes <= MAX_BATCH_BYTES,
                    "MIGRATION_BYTE_LIMIT", "Source batch bytes exceed cap; no partial batch")
            captured = []
            seen = set()
            for kind, scope_raw, legacy_id, raw, key_id, signature in db.execute("SELECT kind,scope,legacy_id,payload,key_id,signature FROM synthetic_records ORDER BY rowid"):
                _text(kind, "kind", 80); _text(legacy_id, "legacy ID")
                require(isinstance(raw, bytes) and isinstance(scope_raw, bytes) and isinstance(key_id, str)
                        and isinstance(signature, str) and len(key_id) <= 256 and len(signature) <= 256,
                        "SYNTHETIC_STRUCTURE", "Synthetic row physical values differ from bounded contract")
                reasons = list(identity_reasons)
                subject = None
                try:
                    scope = _json(scope_raw)
                    require(isinstance(scope, dict), "SYNTHETIC_STRUCTURE", "Scope must be an object")
                    subject = _text(scope.get("subject_id"), "subject ID", 128)
                except (ValueError, UnicodeError, TypeError):
                    scope = {"unparsed_scope_bytes_b64": _b64(scope_raw)}
                    reasons.append("invalid_scope")
                identity = {"snapshot_id": snapshot_id, "store_id": store_id, "kind": kind, "scope": scope, "legacy_id": legacy_id}
                origin_id = digest(identity)
                require(origin_id not in seen, "MIGRATION_DUPLICATE_ORIGIN", "Source repeats an origin; no silent collapse")
                seen.add(origin_id)
                binding = {"schema_version": metadata.get("schema_version"), **identity, "scope_bytes_sha256": _sha(scope_raw), "key_id": key_id}
                if key_id != _key_id(self.test_key):
                    reasons.append("key_mismatch")
                if not _valid_mac(signature, _mac(self.test_key, binding, raw)):
                    reasons.append("record_hmac_failure")
                try:
                    payload = _json(raw)
                    require(isinstance(payload, dict), "SYNTHETIC_STRUCTURE", "Payload must be an object")
                    if "subject_id" in payload and payload["subject_id"] != subject:
                        reasons.append("subject_binding_mismatch")
                except (ValueError, UnicodeError, TypeError):
                    reasons.append("unparseable_payload")
                reasons = tuple(dict.fromkeys(reasons))
                require(not reasons or salvage, "SYNTHETIC_INTEGRITY", "Source integrity/structure failure; explicit salvage required")
                captured.append(LegacyOrigin(identity, scope_raw, raw, signature, key_id, subject, reasons))
            db.execute("COMMIT")
        except sqlite3.DatabaseError as exc:
            raise V2Error("SYNTHETIC_FOREIGN_SCHEMA", "Not a readable sealed synthetic fixture") from exc
        finally:
            db.close()
        _sealed_path(self.root, path)
        require(before == _file_hash(path), "SYNTHETIC_SOURCE_CHANGED", "Sealed source bytes changed during read")
        return SourceSnapshot(marker["exercise_id"], path, metadata, before, tuple(captured), salvage, identities[0][0], identities[0][1], self.test_key)


class OriginRegistry:
    """Immutable origin registry on a new owned v2 private domain store."""

    def __init__(self, root: str | Path, target_path: str | Path, target_test_key: bytes):
        self.root = Path(root).absolute()
        self.marker = verify_synthetic_exercise(self.root)
        self.path = require_owned_synthetic_path(self.root, target_path)
        require(self.path.parent.is_dir(), "SYNTHETIC_SCOPE_PATH", "Registry parent must already exist")
        _key_id(target_test_key)
        for suffix in ("-wal", "-shm", "-journal"):
            require_owned_synthetic_path(self.root, str(self.path) + suffix)
        self.store = SignedStore(self.path, target_test_key, "private-data")

    def close(self) -> None:
        self.store.close()

    def _fresh(self, snapshot: SourceSnapshot) -> SourceSnapshot:
        require(isinstance(snapshot, SourceSnapshot) and snapshot.exercise_id == self.marker["exercise_id"],
                "SYNTHETIC_IDENTITY", "Snapshot belongs to another exercise")
        require(require_owned_synthetic_path(self.root, snapshot.source_path, must_exist=True) != self.path,
                "SYNTHETIC_SCOPE_PATH", "Source and target must differ")
        fresh = SyntheticLegacyAdapter(self.root, snapshot.source_path, snapshot._test_key).read(salvage=snapshot.salvage)
        require(fresh == snapshot, "SYNTHETIC_SOURCE_CHANGED", "Snapshot changed or caller altered its representation")
        return fresh

    def _put(self, kind: str, object_id: str, payload: dict, subject: str | None = None) -> dict:
        return self.store.put(kind, object_id, {"schema_version": SCHEMAS[kind], **payload}, subject)

    def _maybe(self, kind: str, object_id: str, subject: str | None = None) -> dict | None:
        try:
            return self.store.get(kind, object_id, subject)
        except V2Error as exc:
            if exc.code == "NOT_FOUND":
                return None
            raise

    def _all(self, kind: str) -> list[dict]:
        # Own registry only. Decode every row through SignedStore's MAC check;
        # scope enumeration is necessary to detect projections with orphan scopes.
        count, total = self.store._db.execute("SELECT count(*),coalesce(sum(length(payload)),0) FROM v2_objects").fetchone()
        require(count <= 100_000 and total <= 256 * 1024 * 1024, "MIGRATION_REGISTRY_LIMIT", "Registry inventory cap exceeded")
        ids = self.store._db.execute("SELECT object_id,subject_id FROM v2_objects WHERE kind=? ORDER BY object_id", (kind,)).fetchall()
        result = []
        id_field = {"legacy_records": "origin_id", "legacy_mapping": "origin_id",
                    "migration_disposition": "origin_id", "quarantine": "origin_id",
                    "legacy_payload_chunk": "chunk_id", "legacy_projection": "projection_id",
                    "migration_reconciliation_group": "group_id", "migration_run": "run_id"}[kind]
        for object_id, subject in ids:
            payload = self.store.get(kind, object_id, subject)
            require(payload.get("schema_version") == SCHEMAS[kind] and payload.get(id_field) == object_id,
                    "MIGRATION_OBJECT_IDENTITY", "Registry object identity/schema differs")
            require((kind == "legacy_projection" and subject == payload.get("subject_id")) or
                    (kind != "legacy_projection" and subject is None),
                    "MIGRATION_CROSS_SUBJECT", "Registry envelope scope differs")
            result.append(payload)
        return result

    def payload_bytes(self, origin_id: str) -> bytes:
        record = self.store.get("legacy_records", origin_id)
        raw = bytearray()
        for index, chunk_id in enumerate(record["raw_chunk_ids"]):
            chunk = self.store.get("legacy_payload_chunk", chunk_id)
            require(chunk["origin_id"] == origin_id and chunk["index"] == index,
                    "MIGRATION_ORPHAN", "Raw chunk binding differs")
            try:
                value = base64.b64decode(chunk["raw_bytes_b64"], validate=True)
            except (ValueError, TypeError) as exc:
                raise V2Error("MIGRATION_INTEGRITY", "Raw chunk encoding differs") from exc
            require(_sha(value) == chunk["raw_sha256"], "MIGRATION_INTEGRITY", "Raw chunk hash differs")
            raw.extend(value)
            require(len(raw) <= MAX_PAYLOAD_BYTES, "MIGRATION_PAYLOAD_LIMIT", "Captured origin payload exceeds cap")
        require(len(raw) == record["raw_payload_length"] and _sha(bytes(raw)) == record["raw_payload_sha256"],
                "MIGRATION_INTEGRITY", "Captured exact payload hash/length differs")
        return bytes(raw)

    def _projection(self, record: LegacyOrigin, rules: tuple[str, ...]) -> dict | None:
        payload = record.parsed_payload
        if CONTEXT_RULE not in rules or payload is None or record.integrity_reasons:
            return None
        kind = record.identity["kind"]
        if kind == "user_note" and isinstance(payload.get("text"), str):
            projected_kind = "user_note"
        elif kind == "calculation" and isinstance(payload.get("formula"), str) and "value" in payload:
            projected_kind = "calculated"
        else:
            return None
        return {"origin_id": record.origin_id, "subject_id": record.subject_id,
                "record_kind": projected_kind, "legacy_payload": payload,
                "legacy_status": payload.get("status"), "legacy_assurance": payload.get("assurance"),
                "validation": "integrity_and_rule_structure_only", "confirmation_assurance": "none",
                "human_validated": False, "medical_validated": False, "measurement": False,
                "mapping_rule": CONTEXT_RULE}

    def import_snapshot(self, snapshot: SourceSnapshot, *, projection_rules: Iterable[str] = ()) -> dict:
        snapshot = self._fresh(snapshot)
        requested = []
        for rule in projection_rules:
            require(rule == CONTEXT_RULE and len(requested) < 2, "MIGRATION_RULE", "Unknown or excessive synthetic projection rules")
            requested.append(rule)
        rules = tuple(sorted(set(requested)))
        run_id = "migration_run_" + digest({"source_hash": snapshot.sealed_file_sha256,
                                           "exercise_id": snapshot.exercise_id, "rules": rules,
                                           "mapping_version": MAPPING_VERSION, "salvage": snapshot.salvage})
        audit_time = utc_now()
        with self.store.transaction():
            self._all("legacy_records")
            for record in snapshot.records:
                origin_id = record.origin_id
                capture_binding = {"origin": record.identity, "legacy_schema": snapshot.metadata["schema_version"],
                                   "scope_bytes_b64": _b64(record.scope_bytes), "legacy_signature": record.signature,
                                   "legacy_key_id": record.key_id, "raw_payload_sha256": record.raw_sha256,
                                   "raw_payload_length": len(record.raw_payload),
                                   "integrity_reasons": list(record.integrity_reasons)}
                existing = self._maybe("legacy_records", origin_id)
                if existing is not None:
                    require(existing["capture_binding"] == capture_binding and self.payload_bytes(origin_id) == record.raw_payload,
                            "MIGRATION_ORIGIN_CONFLICT", "Same origin has conflicting exact payload or binding")
                    continue
                chunks = []
                for index, offset in enumerate(range(0, len(record.raw_payload), CHUNK_BYTES)):
                    raw = record.raw_payload[offset:offset + CHUNK_BYTES]
                    chunk_id = "legacy_chunk_" + digest({"origin_id": origin_id, "index": index, "hash": _sha(raw)})
                    self._put("legacy_payload_chunk", chunk_id, {"chunk_id": chunk_id, "origin_id": origin_id,
                              "index": index, "raw_bytes_b64": _b64(raw), "raw_sha256": _sha(raw)})
                    chunks.append(chunk_id)
                self._put("legacy_records", origin_id, {"origin_id": origin_id, **capture_binding,
                          "capture_binding": capture_binding, "subject_id": record.subject_id,
                          "raw_chunk_ids": chunks, "migration_audit_at": audit_time})
                projection = self._projection(record, rules)
                projection_ids = []
                if projection:
                    projection_id = "legacy_projection_" + digest({"origin_id": origin_id, "rule": CONTEXT_RULE})
                    self._put("legacy_projection", projection_id, {"projection_id": projection_id, **projection,
                              "migration_audit_at": audit_time}, record.subject_id)
                    projection_ids.append(projection_id)
                disposition = "quarantined" if record.integrity_reasons else ("trusted_projected" if projection else "preserved_only")
                self._put("legacy_mapping", origin_id, {"origin_id": origin_id, "subject_id": record.subject_id,
                          "projection_ids": projection_ids, "mapping_version": MAPPING_VERSION,
                          "mapping_rule": CONTEXT_RULE if projection else None, "migration_audit_at": audit_time})
                self._put("migration_disposition", origin_id, {"origin_id": origin_id, "disposition": disposition,
                          "subject_id": record.subject_id, "migration_audit_at": audit_time})
                if record.integrity_reasons:
                    self._put("quarantine", origin_id, {"origin_id": origin_id, "reasons": list(record.integrity_reasons),
                              "payload_reference": origin_id, "migration_audit_at": audit_time})
            report = self._reconcile(snapshot)
            group_ids = []
            for group in report["groups"]:
                group_id = "migration_group_" + digest({"run_id": run_id, "group": group})
                self._put("migration_reconciliation_group", group_id, {"group_id": group_id, "run_id": run_id, **group})
                group_ids.append(group_id)
            old_run = self._maybe("migration_run", run_id)
            if old_run is None:
                self._put("migration_run", run_id, {"run_id": run_id, "stage": "synthetic_reconciled",
                          "source_snapshot": snapshot.metadata, "source_identity_bytes_b64": _b64(snapshot.identity_bytes),
                          "source_identity_signature": snapshot.identity_signature, "source_sha256": snapshot.sealed_file_sha256,
                          "source_hash_scope": "sealed_sqlite_main_file_bytes_no_sidecars",
                          "source_origin_ids": sorted(record.origin_id for record in snapshot.records),
                          "target_schema": SignedStore.MARKER, "mapping_version": MAPPING_VERSION,
                          "projection_rules": list(rules), "salvage": snapshot.salvage,
                          "counts": report["counts"], "partition_sha256": report["partition_sha256"],
                          "group_ids": group_ids, "migration_audit_at": audit_time})
            self._verify_run(snapshot, report, run_id)
            self._all("legacy_records")
        # Only acknowledged after the encompassing SQLite commit.
        return {"run_id": run_id, **report}

    def reconcile(self, snapshot: SourceSnapshot, *, run_id: str | None = None) -> dict:
        snapshot = self._fresh(snapshot)
        with self.store.transaction(readonly=True):
            report = self._reconcile(snapshot)
            if run_id is not None:
                self._verify_run(snapshot, report, run_id)
            return report

    def _verify_run(self, snapshot: SourceSnapshot, report: dict, run_id: str) -> None:
        run = self.store.get("migration_run", run_id)
        rules = run.get("projection_rules")
        require(isinstance(rules, list) and len(rules) <= 1 and
                all(rule == CONTEXT_RULE for rule in rules),
                "MIGRATION_RECONCILIATION", "Run projection rules differ from fixed synthetic contracts")
        expected_id = "migration_run_" + digest({"source_hash": snapshot.sealed_file_sha256,
                                                 "exercise_id": snapshot.exercise_id, "rules": tuple(rules),
                                                 "mapping_version": MAPPING_VERSION, "salvage": snapshot.salvage})
        require(run_id == expected_id, "MIGRATION_RECONCILIATION", "Run ID does not bind source, exercise, rules and mapping version")
        expected_groups = {}
        for group in report["groups"]:
            group_id = "migration_group_" + digest({"run_id": run_id, "group": group})
            expected_groups[group_id] = {"schema_version": SCHEMAS["migration_reconciliation_group"],
                                         "group_id": group_id, "run_id": run_id, **group}
        persisted_groups = {group["group_id"]: group for group in self._all("migration_reconciliation_group")
                            if group.get("run_id") == run_id}
        require(persisted_groups == expected_groups, "MIGRATION_RECONCILIATION",
                "Persisted run groups do not match recomputed exact counts, statuses and payload hashes")
        audit_time = run.get("migration_audit_at")
        require(isinstance(audit_time, str) and 0 < len(audit_time) <= 64,
                "MIGRATION_RECONCILIATION", "Run must retain its separate bounded migration audit timestamp")
        expected_run = {"schema_version": SCHEMAS["migration_run"], "run_id": run_id,
                        "stage": "synthetic_reconciled", "source_snapshot": snapshot.metadata,
                        "source_identity_bytes_b64": _b64(snapshot.identity_bytes),
                        "source_identity_signature": snapshot.identity_signature,
                        "source_sha256": snapshot.sealed_file_sha256,
                        "source_hash_scope": "sealed_sqlite_main_file_bytes_no_sidecars",
                        "source_origin_ids": sorted(record.origin_id for record in snapshot.records),
                        "target_schema": SignedStore.MARKER, "mapping_version": MAPPING_VERSION,
                        "projection_rules": rules, "salvage": snapshot.salvage,
                        "counts": report["counts"], "partition_sha256": report["partition_sha256"],
                        "group_ids": list(expected_groups), "migration_audit_at": audit_time}
        require(run == expected_run, "MIGRATION_RECONCILIATION",
                "Run metadata, source identity, references, counts or partition differ from recomputed source")

    def _reconcile(self, snapshot: SourceSnapshot) -> dict:
        all_records = {record["origin_id"]: record for record in self._all("legacy_records")}
        all_mappings = {row["origin_id"]: row for row in self._all("legacy_mapping")}
        all_dispositions = {row["origin_id"]: row for row in self._all("migration_disposition")}
        quarantine = {row["origin_id"]: row for row in self._all("quarantine")}
        require(set(all_records) == set(all_mappings) == set(all_dispositions),
                "MIGRATION_PARTITION", "Captured/mapping/disposition origin sets differ")
        require(set(quarantine) == {key for key, row in all_dispositions.items() if row["disposition"] == "quarantined"},
                "MIGRATION_PARTITION", "Quarantine references differ from quarantined origins")
        projections = {row["projection_id"]: row for row in self._all("legacy_projection")}
        linked = []
        for origin_id, mapping in all_mappings.items():
            record = all_records[origin_id]
            disposition = all_dispositions[origin_id]
            require(disposition["disposition"] in DISPOSITIONS,
                    "MIGRATION_PARTITION", "Disposition is not one disjoint supported status")
            require(disposition["subject_id"] == record["subject_id"] and mapping["subject_id"] == record["subject_id"],
                    "MIGRATION_CROSS_SUBJECT", "Disposition/mapping subject differs")
            edges = mapping["projection_ids"]
            require(isinstance(edges, list) and len(edges) <= 1 and len(edges) == len(set(edges)) and
                    bool(edges) == (disposition["disposition"] == "trusted_projected"),
                    "MIGRATION_PARTITION", "Fixed context rule supports exactly zero or one projection per origin")
            require(mapping.get("mapping_version") == MAPPING_VERSION and
                    mapping.get("mapping_rule") == (CONTEXT_RULE if edges else None),
                    "MIGRATION_RECONCILIATION", "Mapping version/rule does not match fixed synthetic contract")
            for edge in edges:
                require(edge == "legacy_projection_" + digest({"origin_id": origin_id, "rule": CONTEXT_RULE}),
                        "MIGRATION_RECONCILIATION", "Projection ID differs from fixed origin/rule binding")
                require(edge in projections, "MIGRATION_ORPHAN", "Projection edge does not resolve")
                projection = projections[edge]
                require(projection["origin_id"] == origin_id and projection["subject_id"] == record["subject_id"],
                        "MIGRATION_CROSS_SUBJECT", "Projection origin or subject differs")
                expected_kind = {"user_note": "user_note", "calculation": "calculated"}.get(record["origin"]["kind"])
                require(expected_kind is not None and projection["record_kind"] == expected_kind and
                        projection["confirmation_assurance"] == "none" and projection["measurement"] is False and
                        projection["human_validated"] is False and projection["medical_validated"] is False,
                        "MIGRATION_STATUS_UPGRADE", "Synthetic projection upgraded legacy assurance or kind")
                linked.append(edge)
            if origin_id in quarantine:
                require(quarantine[origin_id]["payload_reference"] == origin_id and
                        quarantine[origin_id]["reasons"] == record["integrity_reasons"],
                        "MIGRATION_PARTITION", "Quarantine must reference exact captured origin and reason")
        require(set(linked) == set(projections) and len(linked) == len(set(linked)),
                "MIGRATION_ORPHAN", "Projection is orphaned or linked more than once")
        source = {record.origin_id: record for record in snapshot.records}
        captured = {key for key, row in all_records.items() if row["origin"]["snapshot_id"] == snapshot.metadata["snapshot_id"]
                    and row["origin"]["store_id"] == snapshot.metadata["store_id"]}
        require(set(source) == captured, "MIGRATION_RECONCILIATION", "Exact source and captured origin sets differ")
        partition = {status: set() for status in DISPOSITIONS}
        grouped = {}
        for origin_id, original in source.items():
            record = all_records[origin_id]
            expected_binding = {"origin": original.identity, "legacy_schema": snapshot.metadata["schema_version"],
                                "scope_bytes_b64": _b64(original.scope_bytes), "legacy_signature": original.signature,
                                "legacy_key_id": original.key_id, "raw_payload_sha256": original.raw_sha256,
                                "raw_payload_length": len(original.raw_payload),
                                "integrity_reasons": list(original.integrity_reasons)}
            require(record["capture_binding"] == expected_binding and
                    all(record[key] == value for key, value in expected_binding.items()) and
                    record["subject_id"] == original.subject_id and self.payload_bytes(origin_id) == original.raw_payload,
                    "MIGRATION_RECONCILIATION", "Exact source bytes or legacy identity binding differs")
            disposition = all_dispositions[origin_id]["disposition"]
            require((disposition == "quarantined") == bool(original.integrity_reasons),
                    "MIGRATION_STATUS_UPGRADE", "Failed integrity cannot receive a trusted disposition")
            partition[disposition].add(origin_id)
            payload = original.parsed_payload
            for edge in all_mappings[origin_id]["projection_ids"]:
                projection = projections[edge]
                require(payload is not None and projection["legacy_payload"] == payload and
                        projection["legacy_status"] == payload.get("status") and
                        projection["legacy_assurance"] == payload.get("assurance") and
                        projection["mapping_rule"] == CONTEXT_RULE and
                        projection["validation"] == "integrity_and_rule_structure_only",
                        "MIGRATION_STATUS_UPGRADE", "Projection differs from exact legacy payload or rule scope")
            status = {"present": payload is not None and "status" in payload,
                      "value": payload.get("status") if payload is not None else None}
            dims = {"subject_id": original.subject_id, "store_id": original.identity["store_id"],
                    "kind": original.identity["kind"], "legacy_status": status}
            group = grouped.setdefault(digest(dims), {**dims, "source": [], "captured": [], "dispositions": {s: [] for s in sorted(DISPOSITIONS)}})
            item = {"origin_id": origin_id, "raw_payload_sha256": original.raw_sha256}
            group["source"].append(item); group["captured"].append(item); group["dispositions"][disposition].append(item)
        require(set().union(*partition.values()) == set(source) and sum(map(len, partition.values())) == len(source),
                "MIGRATION_PARTITION", "Dispositions do not form an exact disjoint complete partition")
        groups = []
        for group in grouped.values():
            source_items = sorted(group.pop("source"), key=lambda x: x["origin_id"])
            captured_items = sorted(group.pop("captured"), key=lambda x: x["origin_id"])
            statuses = group.pop("dispositions")
            groups.append({**group, "source_count": len(source_items), "captured_count": len(captured_items),
                           "source_origin_payload_sha256": digest(source_items), "captured_origin_payload_sha256": digest(captured_items),
                           "dispositions": {s: {"count": len(items), "origin_payload_sha256": digest(sorted(items, key=lambda x: x["origin_id"]))} for s, items in statuses.items()}})
        groups.sort(key=digest)
        return {"scope": "synthetic_only", "counts": {"source": len(source), "captured": len(captured),
                **{status: len(partition[status]) for status in sorted(DISPOSITIONS)}},
                "partition_sha256": digest({status: sorted(ids) for status, ids in partition.items()}),
                "groups": groups, "unexplained_losses": 0, "unexplained_duplicates": 0,
                "orphan_links": 0, "cross_subject_links": 0,
                "validation": "integrity_structure_and_exact_byte_reconciliation_only"}

    def export_inventory(self) -> dict:
        with self.store.transaction(readonly=True):
            objects = {kind: self._all(kind) for kind in SCHEMAS}
            return {"scope": "synthetic_only", "exercise_id": self.marker["exercise_id"],
                    "object_counts": {kind: len(rows) for kind, rows in objects.items()},
                    "object_payload_sha256": {kind: digest(rows) for kind, rows in objects.items()}}


def create_synthetic_legacy_fixture(root: str | Path, path: str | Path, records: Iterable[dict], test_key: bytes, **metadata) -> Path:
    return SyntheticLegacyFixture.create(root, path, records, test_key, **metadata)
