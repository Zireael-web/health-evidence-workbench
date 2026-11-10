"""Shared v2 primitives. Integrity is not medical or human authentication."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from typing import Iterator
from datetime import datetime, timezone
from uuid import uuid4


class V2Error(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message}


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise V2Error(code, message)


def canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise V2Error("INVALID_PAYLOAD", "Payload must be finite JSON data") from exc


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def new_id(prefix: str) -> str:
    require(bool(re.fullmatch(r"[a-z][a-z0-9_]{0,40}", prefix)),
            "INVALID_ID", "Invalid ID prefix")
    return f"{prefix}_{uuid4().hex}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SignedStore:
    """Immutable, scoped objects in a newly provisioned v2 SQLite store.

    Does not initialize an existing foreign DB, load legacy keys, or migrate.
    HMAC binds identity, subject, payload and domain. Missing objects/history
    deletion must additionally be detected through inventories/backups.
    """

    MAX_OBJECT_BYTES = 2 * 1024 * 1024
    MAX_LIST = 10000
    MARKER = "health-analyzer-v2/1"

    def __init__(self, path: str | Path, key: bytes, domain: str, readonly: bool = False):
        require(domain in {"private-data", "public-research"},
                "INVALID_DOMAIN", "Unknown v2 store domain")
        require(isinstance(key, bytes) and len(key) >= 32,
                "INVALID_KEY", "A domain key of at least 32 bytes is required")
        require(type(readonly) is bool, "INVALID_MODE", "Readonly must be boolean")
        self.path = Path(path).absolute()
        self.domain = domain
        self.readonly = readonly
        self._key = key
        self._lock = threading.RLock()
        self._depth = 0
        self._closed = False
        require(not self.path.is_symlink(), "UNSAFE_PATH", "Store path is a symlink")
        require(not any(p.is_symlink() for p in self.path.parents),
                "UNSAFE_PATH", "Store parent is a symlink; use its resolved path")
        existed = self.path.exists()
        require(existed or not readonly, "STORE_READ_ONLY", "Readonly stores must already exist")
        if not existed:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError as exc:
                raise V2Error("STORE_CONFLICT", "Store appeared during initialization") from exc
            os.close(fd)
        require(self.path.is_file(), "UNSAFE_PATH", "Store is not a regular file")
        try:
            if existed:
                # SQLite mode=rw may recover a hot journal before the first
                # SELECT. Reject foreign databases without even that write.
                # Only the fixed identity is read this way; v2 initializes it
                # in the main DB before WAL is enabled. Live objects always
                # use normal SQLite/WAL semantics below.
                preflight = sqlite3.connect(self.path.as_uri() + "?mode=ro&immutable=1", uri=True)
                try:
                    preflight.row_factory = sqlite3.Row
                    self._verify_identity(preflight)
                finally:
                    preflight.close()
            self._db = sqlite3.connect(self.path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True,
                                       isolation_level=None, check_same_thread=False,
                                       timeout=10)
            self._db.row_factory = sqlite3.Row
            if existed:
                self._verify_identity()
            else:
                self._initialize()
            if readonly:
                # Normal read-only SQLite keeps committed WAL rows visible.
                # immutable=1 is used only for the fixed identity preflight,
                # never for the object connection or latest WAL state.
                self._db.execute("PRAGMA query_only=ON")
            else:
                self._db.execute("PRAGMA journal_mode=WAL")
                self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA foreign_keys=ON")
        except V2Error:
            if hasattr(self, "_db"):
                self._db.close()
            raise
        except sqlite3.DatabaseError as exc:
            if hasattr(self, "_db"):
                self._db.close()
            raise V2Error("FOREIGN_OR_CORRUPT_STORE", "Not a readable v2 store") from exc

    def _mac(self, envelope: dict) -> str:
        return hmac.new(self._key, canonical(envelope), hashlib.sha256).hexdigest()

    def _initialize(self) -> None:
        identity = {"marker": self.MARKER, "domain": self.domain}
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("CREATE TABLE v2_identity (marker TEXT NOT NULL, domain TEXT NOT NULL, mac TEXT NOT NULL)")
            self._db.execute("INSERT INTO v2_identity VALUES (?, ?, ?)",
                             (self.MARKER, self.domain, self._mac(identity)))
            self._db.execute("""CREATE TABLE v2_objects (
                kind TEXT NOT NULL, object_id TEXT NOT NULL,
                subject_id TEXT, payload TEXT NOT NULL, mac TEXT NOT NULL,
                PRIMARY KEY (kind, object_id))""")
            self._db.execute("CREATE INDEX v2_scope ON v2_objects(kind, subject_id)")
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def _verify_identity(self, connection: sqlite3.Connection | None = None) -> None:
        try:
            database = connection if connection is not None else self._db
            rows = database.execute("SELECT marker, domain, mac FROM v2_identity").fetchall()
        except sqlite3.DatabaseError as exc:
            raise V2Error("FOREIGN_STORE", "Existing DB has no v2 marker; migration is not permitted") from exc
        require(len(rows) == 1, "INTEGRITY_FAILURE", "Invalid v2 store identity")
        row = rows[0]
        require(row["marker"] == self.MARKER and row["domain"] == self.domain,
                "WRONG_DOMAIN", "Store marker or domain does not match")
        require(hmac.compare_digest(row["mac"], self._mac({"marker": row["marker"], "domain": row["domain"]})),
                "INTEGRITY_FAILURE", "Store key or identity verification failed")

    @contextmanager
    def transaction(self, *, readonly: bool = False) -> Iterator[None]:
        with self._lock:
            require(not self._closed, "STORE_CLOSED", "Store is closed")
            depth = self._depth
            name = f"v2_tx_{depth}"
            begin = "BEGIN" if self.readonly or readonly else "BEGIN IMMEDIATE"
            self._db.execute(begin if depth == 0 else f"SAVEPOINT {name}")
            self._depth += 1
            try:
                # The identity read establishes the same SQLite snapshot as
                # every subsequent object read in this transaction.
                self._verify_identity()
                yield
                self._db.execute("COMMIT" if depth == 0 else f"RELEASE {name}")
            except BaseException:
                self._db.execute("ROLLBACK" if depth == 0 else f"ROLLBACK TO {name}")
                if depth:
                    self._db.execute(f"RELEASE {name}")
                raise
            finally:
                self._depth -= 1

    @staticmethod
    def _validate_identity(kind: str, object_id: str, subject_id: str | None) -> None:
        require(isinstance(kind, str) and bool(re.fullmatch(r"[a-z][a-z0-9_-]{0,80}", kind)),
                "INVALID_KIND", "Invalid object kind")
        require(isinstance(object_id, str) and 0 < len(object_id) <= 256 and "\x00" not in object_id,
                "INVALID_ID", "Invalid object ID")
        require(subject_id is None or (isinstance(subject_id, str) and 0 < len(subject_id) <= 128),
                "INVALID_SUBJECT", "Invalid subject ID")

    def put(self, kind: str, object_id: str, payload: dict,
            subject_id: str | None = None) -> dict:
        require(not self.readonly, "STORE_READ_ONLY", "Readonly stores cannot write objects")
        self._validate_identity(kind, object_id, subject_id)
        require(isinstance(payload, dict), "INVALID_PAYLOAD", "Object payload must be a JSON object")
        require(self.domain != "public-research" or subject_id is None,
                "PRIVATE_PUBLIC_BOUNDARY", "Public store cannot have a private subject scope")
        encoded = canonical(payload)
        require(len(encoded) <= self.MAX_OBJECT_BYTES, "PAYLOAD_LIMIT", "Object exceeds v2 size limit")
        envelope = {"domain": self.domain, "kind": kind, "object_id": object_id,
                    "subject_id": subject_id, "payload": payload}
        with self.transaction():
            existing = self._db.execute("SELECT * FROM v2_objects WHERE kind=? AND object_id=?",
                                        (kind, object_id)).fetchone()
            if existing is not None:
                old = self._decode(existing)
                require(existing["subject_id"] == subject_id, "WRONG_SUBJECT", "Object scope differs")
                require(canonical(old) == encoded, "IMMUTABLE_CONFLICT", "An immutable object cannot be overwritten")
                return old
            self._db.execute("INSERT INTO v2_objects VALUES (?, ?, ?, ?, ?)",
                             (kind, object_id, subject_id, encoded.decode(), self._mac(envelope)))
        return json.loads(encoded)

    def _decode(self, row: sqlite3.Row) -> dict:
        try:
            require(len(row["payload"].encode("utf-8")) <= self.MAX_OBJECT_BYTES,
                    "INTEGRITY_FAILURE", "Stored payload exceeds size limit")
            payload = json.loads(row["payload"])
        except (ValueError, TypeError) as exc:
            raise V2Error("INTEGRITY_FAILURE", "Stored object cannot be decoded") from exc
        envelope = {"domain": self.domain, "kind": row["kind"], "object_id": row["object_id"],
                    "subject_id": row["subject_id"], "payload": payload}
        require(hmac.compare_digest(row["mac"], self._mac(envelope)),
                "INTEGRITY_FAILURE", "Stored object MAC verification failed")
        return payload

    def get(self, kind: str, object_id: str, subject_id: str | None = None) -> dict:
        self._validate_identity(kind, object_id, subject_id)
        with self._lock:
            require(not self._closed, "STORE_CLOSED", "Store is closed")
            self._verify_identity()
            row = self._db.execute("SELECT * FROM v2_objects WHERE kind=? AND object_id=?",
                                   (kind, object_id)).fetchone()
            require(row is not None, "NOT_FOUND", "Object was not found")
            require(row["subject_id"] == subject_id, "WRONG_SUBJECT", "Object is outside requested scope")
            return self._decode(row)

    def list(self, kind: str, subject_id: str | None = None) -> list[dict]:
        self._validate_identity(kind, "list", subject_id)
        with self._lock:
            require(not self._closed, "STORE_CLOSED", "Store is closed")
            self._verify_identity()
            rows = self._db.execute("SELECT * FROM v2_objects WHERE kind=? AND subject_id IS ? ORDER BY rowid LIMIT ?",
                                    (kind, subject_id, self.MAX_LIST + 1)).fetchall()
            require(len(rows) <= self.MAX_LIST, "QUERY_LIMIT", "Use a narrower query; no partial list returned")
            return [self._decode(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True
