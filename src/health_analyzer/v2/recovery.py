"""Bounded, plaintext recovery exercises for *owned synthetic* v2 stores.

No default paths, deployment configuration, legacy database, key discovery,
archive extraction, CLI or MCP entry point. This is not an encrypted production
recovery bundle or credential escrow. Caller-supplied test keys remain outside
the bundle. A same-user process can defeat a marker or a quiescence assertion;
the exercise is an accidental-path boundary, not OS isolation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Mapping, Sequence

from .common import SignedStore, V2Error, canonical, digest, new_id, require, utc_now
from .contracts import SCHEMA_VERSION, iso_timestamp, lab_observation
from .exercise_scope import require_owned_synthetic_path, verify_synthetic_exercise

RECOVERY_SCHEMA = "health-analyzer.synthetic-recovery/1"
RECOVERY_CODE = "synthetic-recovery/1"
MANIFEST = "manifest.json"
MAX_STORES = 8
MAX_OBJECTS = 10000
MAX_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
ORIGINALS_LIMIT = "not_included; original-source availability is not validated"
KEY_CUSTODY = "explicit test keys supplied outside bundle; fingerprints only"
PLAINTEXT_LIMIT = "plaintext synthetic exercise; not encrypted real recovery or credential escrow"
MANIFEST_FIELDS = {"schema_version", "code_version", "store_marker", "records_schema", "exercise_id",
                   "source_generation", "bundle_id", "created_at", "stores", "source_files",
                   "synthetic_quiesced", "consistency", "cross_store_atomic_transaction",
                   "originals", "key_custody", "limitation", "manifest_hmacs"}

PRIVATE_KINDS = {
    "subject", "document", "document_version", "file_occurrence", "extraction_run",
    "extraction_selection", "panel", "observation_draft", "observation_revision",
    "review_snapshot", "review_event", "correction_event", "document_relation",
    "source_availability", "context_event", "case_selection", "idempotency",
    "original_manifest", "import_issue", "import_issue_event",
    "private_calculation", "private_answer_draft", "private_answer_review",
    "document_transcript", "document_transcript_chunk",
}
PUBLIC_KINDS = {
    "search_plan", "search_page", "search_run", "search_operation",
    "scientific_source", "scientific_source_snapshot", "source_access",
    "source_capture", "finding", "dossier", "answer_draft", "review_report",
}
ORIGIN_SCHEMAS = {
    "legacy_records": "health-analyzer.synthetic-legacy-record/1",
    "legacy_payload_chunk": "health-analyzer.synthetic-legacy-chunk/1",
    "legacy_mapping": "health-analyzer.synthetic-legacy-mapping/1",
    "migration_disposition": "health-analyzer.synthetic-migration-disposition/1",
    "quarantine": "health-analyzer.synthetic-migration-quarantine/1",
    "legacy_projection": "health-analyzer.synthetic-legacy-projection/1",
    "migration_reconciliation_group": "health-analyzer.synthetic-migration-group/1",
    "migration_run": "health-analyzer.synthetic-migration-run/1",
}
ORIGIN_IDENTITIES = {"legacy_records": "origin_id", "legacy_mapping": "origin_id",
                     "migration_disposition": "origin_id", "quarantine": "origin_id",
                     "legacy_payload_chunk": "chunk_id", "legacy_projection": "projection_id",
                     "migration_reconciliation_group": "group_id", "migration_run": "run_id"}
EVENT_KINDS = {"review_event", "correction_event", "context_event", "idempotency",
               "import_issue_event", "extraction_selection", "migration_run"}
PRIVATE_SCHEMAS = {"subject", "document", "document_version", "extraction_run", "extraction_selection",
                   "observation_draft", "observation_revision", "review_snapshot", "review_event",
                   "context_event", "case_selection", "private_calculation", "private_answer_draft",
                   "private_answer_review", "document_transcript", "document_transcript_chunk"}
PRIVATE_ARTIFACT_SCHEMAS = {
    "case_selection": "health-analyzer.case-selection/2.0",
    "private_calculation": "health-analyzer.private-calculation/2.0",
    "private_answer_draft": "health-analyzer.private-answer-draft/2.0",
    "private_answer_review": "health-analyzer.private-answer-review/2.0",
    "document_transcript": "health-analyzer.document-transcript/1",
    "document_transcript_chunk": "health-analyzer.document-transcript-chunk/1",
}
PRIVATE_IDENTITIES = {"subject": "subject_id", "document": "document_id", "document_version": "version_id",
                      "file_occurrence": "occurrence_id", "extraction_run": "run_id",
                      "extraction_selection": "selection_token", "panel": "panel_id",
                      "observation_draft": "draft_id", "observation_revision": "revision_id",
                      "review_snapshot": "snapshot_id", "review_event": "review_event_id",
                      "correction_event": "correction_event_id", "document_relation": "relation_id",
                      "source_availability": "availability_id", "context_event": "context_event_id",
                      "case_selection": "selection_id", "import_issue": "issue_id", "import_issue_event": "event_id",
                      "private_calculation": "calculation_id", "private_answer_draft": "draft_id",
                      "private_answer_review": "review_id", "document_transcript": "transcript_id",
                      "document_transcript_chunk": "chunk_id"}
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class TestKey:
    """Explicit, in-memory exercise key; never pass its material in argv/logs."""
    __test__ = False
    key_id: str
    material: bytes = field(repr=False)

    def __post_init__(self) -> None:
        require(isinstance(self.key_id, str) and self.key_id.startswith("test_")
                and bool(_NAME.fullmatch(self.key_id)), "RECOVERY_TEST_KEY_REQUIRED",
                "A deliberately named test key is required")
        require(isinstance(self.material, bytes) and len(self.material) >= 32,
                "RECOVERY_TEST_KEY_REQUIRED", "Explicit test key material must be at least 32 bytes")

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.material).hexdigest()


@dataclass(frozen=True)
class SyntheticStore:
    name: str
    path: str | Path
    domain: str
    key_id: str


def _mac(key: TestKey, value: object) -> str:
    return hmac.new(key.material, canonical(value), hashlib.sha256).hexdigest()


class SyntheticRecovery:
    def __init__(self, exercise_root: str | Path, *, test_keys: Mapping[str, TestKey],
                 max_objects: int = MAX_OBJECTS, max_total_bytes: int = MAX_BYTES):
        self.root = Path(exercise_root).absolute()
        self.marker = verify_synthetic_exercise(self.root)
        require(isinstance(test_keys, Mapping) and 0 < len(test_keys) <= MAX_STORES
                and all(isinstance(v, TestKey) and k == v.key_id for k, v in test_keys.items()),
                "RECOVERY_TEST_KEY_REQUIRED", "Pass explicit TestKey objects keyed by their IDs")
        require(type(max_objects) is int and 0 < max_objects <= MAX_OBJECTS
                and type(max_total_bytes) is int and 0 < max_total_bytes <= MAX_BYTES,
                "RECOVERY_LIMIT", "Recovery limits must be positive and within hard caps")
        self.keys = dict(test_keys)
        self.max_objects, self.max_total_bytes = max_objects, max_total_bytes

    def _path(self, path: str | Path, *, exists: bool = False, directory: bool = False) -> Path:
        candidate = require_owned_synthetic_path(self.root, path, must_exist=exists)
        for part in [candidate, *candidate.parents]:
            if part == self.root:
                break
            if not part.exists():
                continue
            info = part.lstat()
            is_dir = stat.S_ISDIR(info.st_mode)
            require(info.st_uid == os.geteuid() and
                    (is_dir or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)) and
                    stat.S_IMODE(info.st_mode) in ({0o700} if is_dir else {0o400, 0o600}),
                    "SYNTHETIC_SCOPE_PATH", "Synthetic inputs must be owned private directories or regular files")
        if exists:
            require(candidate.is_dir() if directory else candidate.is_file(),
                    "SYNTHETIC_SCOPE_PATH", "Synthetic input has the wrong type")
        return candidate

    def _stores(self, stores: Sequence[SyntheticStore], quiesced: bool) -> list[SyntheticStore]:
        require(isinstance(stores, (list, tuple)) and 0 < len(stores) <= MAX_STORES,
                "RECOVERY_LIMIT", "A bounded explicit store list is required")
        require(type(quiesced) is bool and (len(stores) == 1 or quiesced),
                "RECOVERY_QUIESCE_REQUIRED", "Multiple stores require explicit own-synthetic writer quiescence")
        names, paths, result = set(), set(), []
        # Validate every source and sidecar before opening any database.
        for spec in stores:
            require(isinstance(spec, SyntheticStore) and isinstance(spec.name, str)
                    and bool(_NAME.fullmatch(spec.name)) and spec.name not in names,
                    "RECOVERY_STORE_SPEC", "Store names must be distinct bounded identifiers")
            require(spec.domain in {"private-data", "public-research"} and spec.key_id in self.keys,
                    "RECOVERY_STORE_SPEC", "Explicit domain and test key binding are required")
            path = self._path(spec.path, exists=True)
            require(path not in paths, "RECOVERY_STORE_SPEC", "A database cannot be listed twice")
            for suffix in ("-wal", "-shm", "-journal"):
                self._path(Path(str(path) + suffix))
            names.add(spec.name); paths.add(path)
            result.append(SyntheticStore(spec.name, path, spec.domain, spec.key_id))
        return result

    def _bytes(self, path: Path) -> bytes:
        self._path(path, exists=True)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and info.st_size <= self.max_total_bytes,
                    "RECOVERY_LIMIT", "Synthetic file is unsafe or exceeds the whole-exercise byte cap")
            chunks, size = [], 0
            while chunk := os.read(fd, 1024 * 1024):
                size += len(chunk)
                require(size <= self.max_total_bytes, "RECOVERY_LIMIT", "Synthetic file exceeds byte cap")
                chunks.append(chunk)
            after = os.fstat(fd)
            require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "RECOVERY_SOURCE_CHANGED", "Synthetic file changed during hashing")
            require((path.stat().st_dev, path.stat().st_ino) == (info.st_dev, info.st_ino),
                    "RECOVERY_SOURCE_CHANGED", "Synthetic input was replaced during hashing")
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _source_files(self, specs: list[SyntheticStore]) -> dict:
        files, total = {}, 0
        for spec in specs:
            for suffix in ("", "-wal", "-journal"):
                path = self._path(Path(str(spec.path) + suffix))
                if path.exists():
                    raw = self._bytes(path); total += len(raw)
                    require(total <= self.max_total_bytes, "RECOVERY_LIMIT", "Whole source set exceeds byte cap")
                    files[f"{spec.name}{suffix}"] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                else:
                    files[f"{spec.name}{suffix}"] = None
        return files

    @staticmethod
    def _schema(db: sqlite3.Connection) -> None:
        expected = {
            ("table", "v2_identity"): "CREATE TABLE v2_identity (marker TEXT NOT NULL, domain TEXT NOT NULL, mac TEXT NOT NULL)",
            ("table", "v2_objects"): "CREATE TABLE v2_objects ( kind TEXT NOT NULL, object_id TEXT NOT NULL, subject_id TEXT, payload TEXT NOT NULL, mac TEXT NOT NULL, PRIMARY KEY (kind, object_id))",
            ("index", "v2_scope"): "CREATE INDEX v2_scope ON v2_objects(kind, subject_id)",
            ("index", "sqlite_autoindex_v2_objects_1"): None,
        }
        actual = {(r[0], r[1]): r[2] for r in db.execute("SELECT type,name,sql FROM sqlite_master")}
        normalize = lambda sql: None if sql is None else re.sub(r"\s+", " ", sql).strip()
        require({k: normalize(v) for k, v in actual.items()} ==
                {k: normalize(v) for k, v in expected.items()},
                "RECOVERY_INCOMPATIBLE", "Only the exact supported v2 schema can be recovered")

    def _inventory(self, db: sqlite3.Connection, spec: SyntheticStore) -> tuple[dict, list[dict]]:
        self._schema(db)
        key = self.keys[spec.key_id]
        identities = db.execute("SELECT marker,domain,mac FROM v2_identity").fetchall()
        require(len(identities) == 1, "RECOVERY_INTEGRITY", "Invalid v2 identity inventory")
        marker, domain, mac = identities[0]
        require(marker == SignedStore.MARKER and domain == spec.domain,
                "RECOVERY_DOMAIN", "Snapshot marker or domain does not match its binding")
        require(isinstance(mac, str) and hmac.compare_digest(mac, _mac(key, {"marker": marker, "domain": domain})),
                "RECOVERY_INTEGRITY", "Test key or signed identity does not match")
        rows = db.execute("SELECT rowid,kind,object_id,subject_id,payload,mac FROM v2_objects ORDER BY rowid LIMIT ?",
                          (self.max_objects + 1,)).fetchall()
        require(len(rows) <= self.max_objects, "RECOVERY_LIMIT", "Object cap exceeded; no partial inventory")
        objects, inventory, counts, payload_bytes = [], [], {}, 0
        for rowid, kind, object_id, subject_id, raw, mac in rows:
            SignedStore._validate_identity(kind, object_id, subject_id)
            require(isinstance(raw, str) and len(raw.encode()) <= SignedStore.MAX_OBJECT_BYTES,
                    "RECOVERY_INTEGRITY", "Invalid stored payload size")
            payload_bytes += len(raw.encode())
            require(payload_bytes <= self.max_total_bytes, "RECOVERY_LIMIT", "Whole payload set exceeds byte cap")
            try:
                payload = json.loads(raw)
            except (ValueError, TypeError) as exc:
                raise V2Error("RECOVERY_INTEGRITY", "Stored object is not valid JSON") from exc
            require(isinstance(payload, dict) and canonical(payload).decode() == raw,
                    "RECOVERY_INTEGRITY", "Stored payload must be canonical v2 JSON")
            envelope = {"domain": domain, "kind": kind, "object_id": object_id,
                        "subject_id": subject_id, "payload": payload}
            require(isinstance(mac, str) and hmac.compare_digest(mac, _mac(key, envelope)),
                    "RECOVERY_INTEGRITY", "Every immutable object must pass HMAC verification")
            allowed = PRIVATE_KINDS | set(ORIGIN_SCHEMAS) if domain == "private-data" else PUBLIC_KINDS
            require(kind in allowed, "RECOVERY_INCOMPATIBLE", "Unknown object kind requires code/schema review")
            if kind in PRIVATE_SCHEMAS:
                require("schema_version" in payload, "RECOVERY_INCOMPATIBLE", "Typed object needs its explicit supported schema")
            if kind in PRIVATE_IDENTITIES:
                require(payload.get(PRIVATE_IDENTITIES[kind]) == object_id,
                        "RECOVERY_OBJECT_SCHEMA", "Payload identity differs from immutable object identity")
            if kind in ORIGIN_SCHEMAS:
                version = ORIGIN_SCHEMAS[kind]
                require(payload.get("schema_version") == version
                        and payload.get(ORIGIN_IDENTITIES[kind]) == object_id,
                        "RECOVERY_INCOMPATIBLE", "Unknown synthetic origin schema")
            elif "schema_version" in payload:
                versions = ({PRIVATE_ARTIFACT_SCHEMAS[kind]} if kind in PRIVATE_ARTIFACT_SCHEMAS
                            else {SCHEMA_VERSION} if domain == "private-data" else {"2.0"})
                require(payload["schema_version"] in versions,
                        "RECOVERY_INCOMPATIBLE", "Unknown object schema requires code/schema review")
            if domain == "public-research":
                require(subject_id is None and payload.get("subject_id") is None,
                        "RECOVERY_SCOPE", "Public objects cannot carry private subject scopes")
            elif kind in set(ORIGIN_SCHEMAS) - {"legacy_projection"}:
                require(subject_id is None, "RECOVERY_SCOPE", "Origin registry objects are unscoped")
            else:
                require(isinstance(subject_id, str) and payload.get("subject_id") == subject_id,
                        "RECOVERY_SCOPE", "Private payload and envelope subject scopes must match")
            for timefield in ("recorded_at", "created_at", "imported_at", "completed_at", "reviewed_at", "migration_audit_at"):
                if timefield in payload:
                    iso_timestamp(payload[timefield], timefield)
            obj = {"rowid": rowid, **envelope, "mac": mac}
            objects.append(obj)
            inventory.append({"rowid": rowid, "kind": kind, "object_id": object_id,
                              "subject_id": subject_id, "envelope_sha256": digest(envelope), "mac": mac})
            counts[kind] = counts.get(kind, 0) + 1
        self._links(objects, domain)
        latest = {kind: next((item for item in reversed(inventory) if item["kind"] == kind), None)
                  for kind in sorted(EVENT_KINDS) if kind in counts}
        return {"object_count": len(objects), "payload_bytes": payload_bytes, "counts": counts,
                "committed_watermark": {"kind": "immutable_object_rowid", "value": inventory[-1]["rowid"] if inventory else 0,
                                        "limitation": "object insertion order; not a SQLite LSN or cross-store commit ID"},
                "latest_events": latest, "objects": inventory, "inventory_sha256": digest(inventory)}, objects

    @staticmethod
    def _links(objects: list[dict], domain: str) -> None:
        lookup = {(o["kind"], o["object_id"], o["subject_id"]): o["payload"] for o in objects}
        def linked(kinds, object_id, subject):
            kinds = [kinds] if isinstance(kinds, str) else kinds
            matches = [lookup[(kind, object_id, subject)] for kind in kinds if (kind, object_id, subject) in lookup]
            require(len(matches) == 1, "RECOVERY_LINK", "An immutable reference is missing, ambiguous or outside scope")
            return matches[0]
        if domain == "public-research":
            rootlinks = {"plan_id": "search_plan", "source_id": "scientific_source",
                         "access_id": "source_access", "capture_id": "source_capture"}
            for obj in objects:
                p = obj["payload"]
                for fieldname, kind in rootlinks.items():
                    if p.get(fieldname) is not None and obj["kind"] != kind:
                        linked(kind, p[fieldname], None)
            return
        for obj in objects:
            p, kind, subject = obj["payload"], obj["kind"], obj["subject_id"]
            if kind in ORIGIN_SCHEMAS:
                continue  # OriginRegistry owns its richer typed reconciliation contract.
            linked("subject", subject, subject)
            if p.get("document_id") is not None:
                linked("document", p["document_id"], subject)
            version = None
            for name in ("version_id", "source_version_id", "target_version_id"):
                if p.get(name) is not None:
                    version = linked("document_version", p[name], subject)
            for name in ("run_id", "extraction_run_id"):
                if p.get(name) is not None:
                    linked("extraction_run", p[name], subject)
            if kind in {"observation_draft", "observation_revision"}:
                require(version is not None and p.get("source_sha256") == version["source_sha256"],
                        "RECOVERY_LINK", "Typed row source hash must match its source version")
                row = lab_observation(p.get("row"), version["version_id"], version["source_sha256"],
                                      correction=kind == "observation_revision")
                require(row == p["row"], "RECOVERY_OBJECT_SCHEMA", "Typed row must preserve its validated contract")
            if kind == "observation_revision":
                linked("observation_draft", p["draft_id"], subject)
                linked(["review_event", "correction_event"], p["review_event_id"], subject)
                if p.get("supersedes_revision_id"):
                    old = linked("observation_revision", p["supersedes_revision_id"], subject)
                    require(old["observation_id"] == p["observation_id"], "RECOVERY_LINK", "Revision chain identity differs")
            for fieldname, refkind in (("draft_ids", "observation_draft"), ("displayed_draft_ids", "observation_draft"),
                                      ("revision_ids", "observation_revision")):
                for object_id in p.get(fieldname, []):
                    linked(refkind, object_id, subject)
            if kind == "review_snapshot":
                for row in p["rows"]:
                    require(row == linked("observation_draft", row["draft_id"], subject),
                            "RECOVERY_LINK", "Frozen preview differs from its immutable draft")
                require(digest({k: v for k, v in p.items() if k != "snapshot_sha256"}) == p["snapshot_sha256"],
                        "RECOVERY_INTEGRITY", "Frozen preview hash differs")
            elif kind == "review_event":
                linked("review_snapshot", p["snapshot_id"], subject)
                require(digest(p["decisions"]) == p["decisions_sha256"], "RECOVERY_INTEGRITY", "Decision hash differs")
            elif kind == "correction_event":
                linked("observation_revision", p["previous_revision_id"], subject)
                linked("observation_revision", p["revision_id"], subject)
            elif kind == "original_manifest":
                manifest = p["manifest"]
                require(version is not None and manifest.get("schema_version") == "health-analyzer.original/1"
                        and manifest.get("subject_id") == subject
                        and all(manifest.get(f) == version.get(f) for f in ("source_sha256", "size", "mime")),
                        "RECOVERY_LINK", "Signed original manifest differs from its source version")
            elif kind == "case_selection":
                # Historical frozen selections remain recoverable after a
                # correction. Validate their immutable graph, never their
                # present-day projection or physical-source availability.
                from .private_cases import validate_case_snapshot
                validate_case_snapshot(p, lambda k, i, s: linked(k, i, s))
            elif kind == "private_calculation":
                from .private_calculations import validate_calculation_receipt
                validate_calculation_receipt(p, lambda k, i, s: linked(k, i, s))
            elif kind == "private_answer_review":
                from .private_answers import validate_private_answer_artifacts
                draft = linked("private_answer_draft", p["draft_id"], subject)
                validate_private_answer_artifacts(draft, p, lambda k, i, s: linked(k, i, s))
            elif kind == "private_answer_draft":
                reports = [o["payload"] for o in objects if o["kind"] == "private_answer_review"
                           and o["subject_id"] == subject and o["payload"].get("draft_id") == p["draft_id"]]
                require(len(reports) == 1, "RECOVERY_LINK", "Private answer draft needs one atomic review report")
            elif kind == "import_issue_event":
                linked("import_issue", p["issue_id"], subject)
            elif kind == "document_transcript":
                from .document_io import validate_document_transcript_links
                chunks = [linked("document_transcript_chunk", chunk_id, subject)
                          for page in p["pages"] for chunk_id in page["chunk_ids"]]
                require(version is not None, "RECOVERY_LINK", "Transcript source version is missing")
                validate_document_transcript_links(p, version, chunks)
            elif kind == "document_transcript_chunk":
                from .document_io import validate_document_transcript_chunk
                validate_document_transcript_chunk(p, object_id=obj["object_id"], subject_id=subject)
                header = linked("document_transcript", p["transcript_id"], subject)
                require(sum(chunk_id == p["chunk_id"] for page in header["pages"]
                            for chunk_id in page["chunk_ids"]) == 1,
                        "RECOVERY_LINK", "Transcript chunk is not in its exact header inventory")
            elif kind == "idempotency":
                result = p.get("result", {})
                if result.get("review_event_id"):
                    linked("review_event", result["review_event_id"], subject)
                for rid in result.get("revision_ids", []):
                    linked("observation_revision", rid, subject)
                if result.get("revision"):
                    revision = result["revision"]
                    require(revision == linked("observation_revision", revision["revision_id"], subject),
                            "RECOVERY_LINK", "Retry result differs from its immutable revision")
                if result.get("calculation_id"):
                    from .private_calculations import validate_calculation_idempotency
                    validate_calculation_idempotency(p, lambda k, i, s: linked(k, i, s))
                if result.get("kind") == "private_answer_review":
                    from .private_answers import validate_private_answer_idempotency
                    validate_private_answer_idempotency(p, lambda k, i, s: linked(k, i, s))
                if p.get("operation") == "prepare_attachment":
                    from .attachments import validate_attachment_idempotency
                    validate_attachment_idempotency(p, lambda k, i, s: linked(k, i, s))
                if result.get("transcript_id") is not None:
                    from .document_io import _request_metadata, validate_document_transcript_links
                    header = linked("document_transcript", result["transcript_id"], subject)
                    version = linked("document_version", header["version_id"], subject)
                    chunks = [linked("document_transcript_chunk", chunk_id, subject)
                              for page in header["pages"] for chunk_id in page["chunk_ids"]]
                    validate_document_transcript_links(header, version, chunks)
                    fields = ("transcript_id", "subject_id", "version_id", "source_sha256", "method",
                              "model", "page_count", "text_bytes", "source_extent", "review_status", "human_verified")
                    require(result == {field: header[field] for field in fields}
                            and p.get("request_sha256") == digest(_request_metadata(header)),
                            "RECOVERY_LINK", "Transcript retry differs from its exact saved text")

    def _read(self, spec: SyntheticStore, destination: Path | None = None) -> tuple[dict, list[dict]]:
        self._path(spec.path, exists=True)
        for suffix in ("-wal", "-shm", "-journal"):
            self._path(Path(str(spec.path) + suffix))
        header = self._bytes(Path(spec.path))[:100]
        if len(header) >= 20 and header[:16] == b"SQLite format 3\x00" and header[18:20] == b"\x02\x02":
            # Even mode=ro can create an empty WAL/SHM when a dormant WAL-mode
            # source has no sidecars. Reject before connecting; never chmod,
            # checkpoint or switch that source's journal mode here.
            require(Path(str(spec.path) + "-wal").is_file()
                    and Path(str(spec.path) + "-shm").is_file(),
                    "RECOVERY_DORMANT_WAL", "WAL-mode source needs existing owned WAL/SHM; own fixture writer may explicitly seal it")
        try:
            # A normal read-only SQLite connection sees acknowledged WAL commits.
            # No source PRAGMA, checkpoint, immutable flag or write transaction.
            db = sqlite3.connect(Path(spec.path).as_uri() + "?mode=ro", uri=True, isolation_level=None)
            try:
                db.execute("BEGIN")
                inventory, objects = self._inventory(db, spec)
                if destination is not None:
                    self._path(destination)
                    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    os.close(fd)
                    out = sqlite3.connect(destination, isolation_level=None)
                    try:
                        db.backup(out)
                        # Only our fresh destination is converted to a sealed main file.
                        out.execute("PRAGMA journal_mode=DELETE")
                        checked, _ = self._inventory(out, spec)
                        require(checked == inventory, "RECOVERY_INTEGRITY", "Backup inventory differs from its read snapshot")
                    finally:
                        out.close()
                    self._fsync_file(destination)
                db.execute("COMMIT")
                return inventory, objects
            finally:
                db.close()
        except sqlite3.DatabaseError as exc:
            raise V2Error("RECOVERY_FOREIGN_OR_CORRUPT", "Not a readable supported signed v2 store") from exc
        except (KeyError, TypeError, AttributeError) as exc:
            raise V2Error("RECOVERY_OBJECT_SCHEMA", "Stored object does not match its supported contract") from exc

    @staticmethod
    def _fsync_file(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(fd)
        finally: os.close(fd)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try: os.fsync(fd)
        finally: os.close(fd)

    def _new_directory(self, destination: str | Path) -> Path:
        path = self._path(destination)
        require(not path.exists(), "RECOVERY_DESTINATION_EXISTS", "Destination must be new; no existing bundle or store is replaced")
        if path.parent == self.root:
            verify_synthetic_exercise(self.root)
        else:
            self._path(path.parent, exists=True, directory=True)
        return path

    def _temporary(self, parent: Path) -> Path:
        path = self._path(parent / (".recovery-" + new_id("build")))
        path.mkdir(mode=0o700)
        return path

    def _budget(self, inventories: list[dict]) -> None:
        require(sum(i["object_count"] for i in inventories) <= self.max_objects
                and sum(i["payload_bytes"] for i in inventories) <= self.max_total_bytes,
                "RECOVERY_LIMIT", "Whole-batch cap exceeded; no partial success")

    def _write_json(self, path: Path, data: dict) -> None:
        raw = canonical(data)
        require(len(raw) <= min(MAX_MANIFEST_BYTES, self.max_total_bytes), "RECOVERY_LIMIT", "Manifest cap exceeded")
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())

    def _publish(self, build: Path, destination: Path, publication: str) -> None:
        # mkdir reserves a new name without replacing even an empty existing dir.
        # A directory is valid only after its final fsynced publication manifest.
        # A crash leaves a rejected incomplete directory, never a successful bundle.
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise V2Error("RECOVERY_DESTINATION_EXISTS", "Destination appeared; no overwrite") from exc
        for item in sorted(build.iterdir()):
            if item.name != publication:
                os.rename(item, destination / item.name)
        self._fsync_directory(destination)
        os.rename(build / publication, destination / publication)
        self._fsync_directory(destination)
        self._fsync_directory(destination.parent)
        build.rmdir()  # Our own now-empty build directory only.

    def create_backup(self, destination: str | Path, stores: Sequence[SyntheticStore], *,
                      source_generation: str, synthetic_quiesced: bool = False) -> dict:
        dest = self._new_directory(destination)
        specs = self._stores(stores, synthetic_quiesced)
        require(isinstance(source_generation, str) and bool(_NAME.fullmatch(source_generation)),
                "RECOVERY_GENERATION", "An explicit bounded synthetic generation is required")
        require(not any(dest == Path(s.path) or dest in Path(s.path).parents for s in specs),
                "RECOVERY_STORE_SPEC", "Bundle destination cannot contain its sources")
        before = self._source_files(specs)
        build = self._temporary(dest.parent)
        entries, inventories, size = [], [], 0
        for spec in specs:
            snapshot = build / f"{spec.name}.sqlite3"
            inventory, _ = self._read(spec, snapshot)
            raw = self._bytes(snapshot); size += len(raw)
            require(size <= self.max_total_bytes, "RECOVERY_LIMIT", "Whole snapshot set exceeds byte cap")
            entries.append({"name": spec.name, "domain": spec.domain, "key_id": spec.key_id,
                            "key_fingerprint": self.keys[spec.key_id].fingerprint,
                            "snapshot": snapshot.name, "size": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(), "inventory": inventory})
            inventories.append(inventory)
        self._budget(inventories)
        after = self._source_files(specs)
        require(before == after, "RECOVERY_SOURCE_CHANGED", "Source main/WAL/journal bytes changed; bundle is not published")
        body = {"schema_version": RECOVERY_SCHEMA, "code_version": RECOVERY_CODE,
                "store_marker": SignedStore.MARKER, "records_schema": SCHEMA_VERSION,
                "exercise_id": self.marker["exercise_id"], "source_generation": source_generation,
                "bundle_id": new_id("synthetic_backup"), "created_at": utc_now(), "stores": entries,
                "source_files": before, "synthetic_quiesced": synthetic_quiesced,
                "consistency": "per-store read snapshots; explicit synthetic quiesce" if len(specs) > 1 else "one SQLite read snapshot",
                "cross_store_atomic_transaction": False,
                "originals": ORIGINALS_LIMIT, "key_custody": KEY_CUSTODY, "limitation": PLAINTEXT_LIMIT}
        manifest = {**body, "manifest_hmacs": {key_id: _mac(self.keys[key_id], body)
                                               for key_id in sorted({s.key_id for s in specs})}}
        require(size + len(canonical(manifest)) <= self.max_total_bytes,
                "RECOVERY_LIMIT", "Snapshots plus manifest exceed the whole-bundle byte cap")
        self._write_json(build / MANIFEST, manifest)
        self._publish(build, dest, MANIFEST)
        return self.verify_bundle(dest, expected_generation=source_generation)

    def _verified(self, bundle: str | Path, expected_generation: str | None = None) -> tuple[dict, list[tuple[SyntheticStore, dict, list[dict]]]]:
        path = self._path(bundle, exists=True, directory=True)
        manifest_path = self._path(path / MANIFEST, exists=True)
        raw = self._bytes(manifest_path)
        require(len(raw) <= MAX_MANIFEST_BYTES, "RECOVERY_LIMIT", "Manifest exceeds hard cap")
        try: manifest = json.loads(raw)
        except ValueError as exc: raise V2Error("RECOVERY_MANIFEST", "Invalid recovery manifest") from exc
        require(isinstance(manifest, dict) and canonical(manifest) == raw,
                "RECOVERY_MANIFEST", "Recovery manifest must be canonical JSON")
        require(set(manifest) == MANIFEST_FIELDS, "RECOVERY_MANIFEST", "Manifest fields must match the complete supported contract")
        require(manifest.get("schema_version") == RECOVERY_SCHEMA and manifest.get("code_version") == RECOVERY_CODE
                and manifest.get("records_schema") == SCHEMA_VERSION and manifest.get("store_marker") == SignedStore.MARKER,
                "RECOVERY_INCOMPATIBLE", "Unknown recovery code/schema version; keep current data read-only")
        require(manifest.get("exercise_id") == self.marker["exercise_id"],
                "RECOVERY_SCOPE", "Bundle belongs to another exercise")
        require(isinstance(manifest.get("source_generation"), str) and bool(_NAME.fullmatch(manifest["source_generation"]))
                and isinstance(manifest.get("bundle_id"), str) and manifest["bundle_id"].startswith("synthetic_backup_")
                and manifest.get("cross_store_atomic_transaction") is False
                and manifest.get("originals") == ORIGINALS_LIMIT and manifest.get("key_custody") == KEY_CUSTODY
                and manifest.get("limitation") == PLAINTEXT_LIMIT,
                "RECOVERY_MANIFEST", "Generation, identity or exercise limitations differ from the supported contract")
        iso_timestamp(manifest["created_at"], "manifest created_at")
        require(expected_generation is None or manifest.get("source_generation") == expected_generation,
                "RECOVERY_GENERATION", "Bundle generation differs from explicit expectation")
        entries = manifest.get("stores")
        require(isinstance(entries, list) and 0 < len(entries) <= MAX_STORES,
                "RECOVERY_MANIFEST", "Bundle must enumerate all stores")
        specs, filenames, total = [], {MANIFEST}, len(raw)
        for entry in entries:
            require(isinstance(entry, dict) and isinstance(entry.get("name"), str)
                    and bool(_NAME.fullmatch(entry["name"])) and entry.get("snapshot") == entry["name"] + ".sqlite3",
                    "RECOVERY_MANIFEST", "Only fixed direct snapshot filenames are accepted")
            require(set(entry) == {"name", "domain", "key_id", "key_fingerprint", "snapshot", "size", "sha256", "inventory"},
                    "RECOVERY_MANIFEST", "Snapshot entry must use the complete supported contract")
            require(entry.get("key_id") in self.keys and entry.get("key_fingerprint") == self.keys[entry["key_id"]].fingerprint,
                    "RECOVERY_TEST_KEY_REQUIRED", "Explicit test key custody or fingerprint does not match")
            snapshot = self._path(path / entry["snapshot"], exists=True)
            filenames.add(snapshot.name)
            specs.append(SyntheticStore(entry["name"], snapshot, entry.get("domain"), entry["key_id"]))
        specs = self._stores(specs, manifest.get("synthetic_quiesced"))
        require({p.name for p in path.iterdir()} == filenames and len(filenames) == len(entries) + 1,
                "RECOVERY_MANIFEST", "Unexpected, duplicate or partial bundle files")
        require(isinstance(manifest["source_files"], dict)
                and set(manifest["source_files"]) == {s.name + suffix for s in specs for suffix in ("", "-wal", "-journal")}
                and all(v is None or (isinstance(v, dict) and set(v) == {"size", "sha256"}
                                     and type(v["size"]) is int and 0 <= v["size"] <= self.max_total_bytes
                                     and isinstance(v["sha256"], str) and bool(_HASH.fullmatch(v["sha256"])))
                        for v in manifest["source_files"].values()),
                "RECOVERY_MANIFEST", "Source-byte evidence must enumerate every bound main/WAL/journal")
        body = {k: v for k, v in manifest.items() if k != "manifest_hmacs"}
        expected_macs = {key_id: _mac(self.keys[key_id], body) for key_id in sorted({s.key_id for s in specs})}
        require(isinstance(manifest.get("manifest_hmacs"), dict) and set(manifest["manifest_hmacs"]) == set(expected_macs)
                and all(isinstance(manifest["manifest_hmacs"][k], str)
                        and hmac.compare_digest(manifest["manifest_hmacs"][k], v) for k, v in expected_macs.items()),
                "RECOVERY_INTEGRITY", "Complete manifest authentication failed")
        verified = []
        for entry, spec in zip(entries, specs):
            snapshot_raw = self._bytes(Path(spec.path)); total += len(snapshot_raw)
            require(total <= self.max_total_bytes, "RECOVERY_LIMIT", "Whole bundle exceeds byte cap")
            require(entry.get("size") == len(snapshot_raw) and entry.get("sha256") == hashlib.sha256(snapshot_raw).hexdigest(),
                    "RECOVERY_INTEGRITY", "Snapshot bytes differ from the authenticated manifest")
            inventory, objects = self._read(spec)
            require(inventory == entry.get("inventory"), "RECOVERY_INTEGRITY", "Object counts, hashes, scopes or committed watermark differ")
            verified.append((spec, inventory, objects))
        self._budget([i for _, i, _ in verified])
        return manifest, verified

    def verify_bundle(self, bundle: str | Path, *, expected_generation: str | None = None) -> dict:
        return self._verified(bundle, expected_generation)[0]

    def _restore_verified(self, manifest: dict, verified: list[tuple[SyntheticStore, dict, list[dict]]],
                          destination: Path, *, mode: str, extra: dict | None = None) -> dict:
        build = self._temporary(destination.parent)
        output = []
        for spec, inventory, _ in verified:
            target = build / f"{spec.name}.sqlite3"
            checked, _ = self._read(spec, target)
            require(checked == inventory, "RECOVERY_INTEGRITY", "Restored objects differ; no target is published")
            output.append({"name": spec.name, "path": str(destination / target.name), "domain": spec.domain,
                           "inventory_sha256": inventory["inventory_sha256"],
                           "object_count": inventory["object_count"], "committed_watermark": inventory["committed_watermark"]})
        report = {"schema_version": RECOVERY_SCHEMA, "mode": mode, "bundle_id": manifest["bundle_id"],
                  "source_generation": manifest["source_generation"], "stores": output,
                  "originals": manifest["originals"], "key_custody": manifest["key_custody"],
                  "limitation": manifest["limitation"], **(extra or {})}
        self._write_json(build / "recovery-report.json", report)
        self._publish(build, destination, "recovery-report.json")
        return report

    def restore_bundle(self, bundle: str | Path, new_staging: str | Path) -> dict:
        destination = self._new_directory(new_staging)
        manifest, verified = self._verified(bundle)
        return self._restore_verified(manifest, verified, destination, mode="new_empty_synthetic_staging")

    def read_recovery_view(self, stores: Sequence[SyntheticStore], *, synthetic_quiesced: bool = False) -> dict:
        specs = self._stores(stores, synthetic_quiesced)
        before = self._source_files(specs)
        results = []
        for spec in specs:
            inventory, objects = self._read(spec)
            results.append({"name": spec.name, "domain": spec.domain, "inventory": inventory, "objects": objects})
        self._budget([r["inventory"] for r in results])
        require(before == self._source_files(specs), "RECOVERY_SOURCE_CHANGED", "Source changed during recovery view")
        return {"mode": "read_only_verified_recovery_view", "stores": results,
                "originals": ORIGINALS_LIMIT}

    def reconstruct_rollback(self, base_bundle: str | Path, current_stores: Sequence[SyntheticStore],
                             new_staging: str | Path, *, source_generation: str,
                             synthetic_quiesced: bool = False) -> dict:
        """Prove the old base is an exact insertion prefix, retain every new object.

        The union equals the fully verified current snapshots after this proof.
        Reconstructing those snapshots keeps exact payloads, MACs, row order,
        timestamps, source links, decisions and idempotent response objects.
        Never overlay an old backup or reverse-import to a legacy writer.
        """
        destination = self._new_directory(new_staging)
        base, old = self._verified(base_bundle)
        specs = self._stores(current_stores, synthetic_quiesced)
        require({(s.name, s.domain, s.key_id) for s in specs} == {(s.name, s.domain, s.key_id) for s, _, _ in old},
                "RECOVERY_SCOPE", "Rollback must account for every base store with the same domain/key binding")
        current_bundle = self._path(destination.parent / new_id("rollback_snapshot"))
        current = self.create_backup(current_bundle, specs, source_generation=source_generation,
                                     synthetic_quiesced=synthetic_quiesced)
        _, verified = self._verified(current_bundle)
        old_by_name = {s.name: (inventory, objects) for s, inventory, objects in old}
        retained = {}
        for spec, inventory, objects in verified:
            base_inventory, base_objects = old_by_name[spec.name]
            now_by_id = {(o["kind"], o["object_id"]): o for o in objects}
            for obj in base_objects:
                counterpart = now_by_id.get((obj["kind"], obj["object_id"]))
                require(counterpart is not None, "RECOVERY_BASE_MISSING", "A base immutable object was deleted; no rollback is published")
                require(counterpart == obj, "RECOVERY_IMMUTABLE_CONFLICT", "Same immutable ID differs from the old base")
            require(inventory["objects"][:base_inventory["object_count"]] == base_inventory["objects"],
                    "RECOVERY_BASE_PREFIX", "Base must be an exact current insertion prefix; no history is excused")
            retained[spec.name] = {"base_objects": base_inventory["object_count"],
                                   "retained_post_cutover_objects": inventory["object_count"] - base_inventory["object_count"],
                                   "current_inventory_sha256": inventory["inventory_sha256"]}
        return self._restore_verified(current, verified, destination,
                                      mode="read_only_rollback_reconstruction",
                                      extra={"base_bundle_id": base["bundle_id"], "retained": retained,
                                             "compatibility": "current supported v2 schema only; unknown code/schema fails closed",
                                             "acknowledged_commits": "all current verified immutable objects retained, including exact retry results"})
