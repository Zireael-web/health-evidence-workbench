"""Opaque, server-issued packet handoffs between isolated MCP zones."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Literal

from .contracts import CasePacket, EvidencePacket, RiskEnvelope
from .packets import validate_case_packet
from .serialization import case_packet_from, evidence_packet_from


PacketKind = Literal["case", "evidence"]
Packet = CasePacket | EvidencePacket
MAX_HANDOFF_PACKET_BYTES = 8 * 1024 * 1024
_PACKET_IDS = {
    "case": re.compile(r"case_[a-f0-9]{20,64}\Z"),
    "evidence": re.compile(r"evidence_[a-f0-9]{20,64}\Z"),
}


class UnknownHandoffPacketError(ValueError):
    """Raised when synthesis references a packet not issued by a zone server."""


class HandoffIntegrityError(RuntimeError):
    """Raised when a stored packet no longer matches its canonical binding."""


def _canonical_json(
    packet: Packet,
    *,
    legacy_evidence_without_risk_envelope: bool = False,
) -> str:
    material = asdict(packet)
    if legacy_evidence_without_risk_envelope:
        if (
            not isinstance(packet, EvidencePacket)
            or packet.schema_version != "1.2"
            or packet.risk_envelope != RiskEnvelope()
        ):
            raise ValueError(
                "only legacy unspecified evidence may omit risk_envelope"
            )
        material.pop("risk_envelope")
    return json.dumps(
        material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


class PacketHandoffStore:
    """Append-only packet registry with read-only synthesis access.

    Filesystem policy, not SQLite itself, is the trust boundary: only the
    issuing MCP zone receives write access, while synthesis receives read-only
    access and the Codex agent shell is denied the handoff directory.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        kind: PacketKind,
        writable: bool,
        integrity_key: bytes,
    ) -> None:
        self.path = Path(path)
        self.kind = kind
        self.writable = writable
        self._integrity_key = bytes(integrity_key)
        if len(self._integrity_key) < 32:
            raise ValueError("handoff integrity key must contain at least 32 bytes")
        self._prepare_path()
        if writable:
            self._initialize()

    def _prepare_path(self) -> None:
        parent = self.path.parent
        if parent.is_symlink():
            raise ValueError("handoff parent must not be a symbolic link")
        if self.writable:
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            parent.chmod(0o700)
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, 0o600)
            try:
                state = os.fstat(descriptor)
                if not stat.S_ISREG(state.st_mode) or state.st_nlink != 1:
                    raise ValueError("handoff database must be a singly linked regular file")
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        elif not self.path.exists():
            raise UnknownHandoffPacketError("handoff store has not been initialized")

        parent_state = parent.lstat()
        file_state = self.path.lstat()
        if (
            stat.S_ISLNK(parent_state.st_mode)
            or not stat.S_ISDIR(parent_state.st_mode)
            or stat.S_ISLNK(file_state.st_mode)
            or not stat.S_ISREG(file_state.st_mode)
            or file_state.st_nlink != 1
        ):
            raise ValueError("handoff path is unsafe")

    def _connect(self) -> sqlite3.Connection:
        self._prepare_path()
        if self.writable:
            connection = sqlite3.connect(self.path, timeout=5.0)
        else:
            connection = sqlite3.connect(
                self.path.absolute().as_uri() + "?mode=ro",
                uri=True,
                timeout=5.0,
            )
            connection.execute("PRAGMA query_only = ON")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS packet_handoff (
                    packet_id TEXT PRIMARY KEY,
                    packet_kind TEXT NOT NULL CHECK(packet_kind IN ('case', 'evidence')),
                    payload_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    binding_hmac TEXT,
                    issued_at TEXT NOT NULL
                )
                """
            )
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(packet_handoff)")
            }
            if "binding_hmac" not in columns:
                connection.execute(
                    "ALTER TABLE packet_handoff ADD COLUMN binding_hmac TEXT"
                )

    def _binding_hmac(self, packet_id: str, payload_sha256: str) -> str:
        material = json.dumps(
            {
                "schema": "packet-handoff-binding-v2",
                "packet_kind": self.kind,
                "packet_id": packet_id,
                "payload_sha256": payload_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hmac.new(
            self._integrity_key,
            material.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def put(self, packet: Packet) -> str:
        if not self.writable:
            raise PermissionError("handoff store is read-only")
        expected_type = CasePacket if self.kind == "case" else EvidencePacket
        if not isinstance(packet, expected_type):
            raise TypeError(f"{self.kind} handoff received the wrong packet type")
        if isinstance(packet, EvidencePacket) and not packet.risk_envelope.is_explicit:
            raise ValueError("new evidence handoff records require an explicit risk envelope")
        if not _PACKET_IDS[self.kind].fullmatch(packet.packet_id):
            raise ValueError(f"{self.kind} packet_id is not canonical")
        payload_json = _canonical_json(packet)
        if len(payload_json.encode("utf-8")) > MAX_HANDOFF_PACKET_BYTES:
            raise ValueError("handoff packet exceeds the 8 MiB canonical size limit")
        if isinstance(packet, CasePacket):
            validate_case_packet(packet)
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        binding_hmac = self._binding_hmac(packet.packet_id, payload_sha256)
        with self._connect() as connection:
            # Serialize the idempotent read-before-insert decision. Without an
            # immediate transaction, two issuers can both observe no row and
            # one fails with a primary-key IntegrityError instead of verifying
            # and returning the identical issued packet.
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT packet_kind, payload_sha256, payload_json, binding_hmac
                FROM packet_handoff WHERE packet_id = ?""",
                (packet.packet_id,),
            ).fetchone()
            if existing is not None:
                payload_matches = (
                    existing["packet_kind"] == self.kind
                    and existing["payload_sha256"] == payload_sha256
                    and existing["payload_json"] == payload_json
                )
                if payload_matches and existing["binding_hmac"] is None:
                    connection.execute(
                        """UPDATE packet_handoff SET binding_hmac = ?
                        WHERE packet_id = ? AND binding_hmac IS NULL""",
                        (binding_hmac, packet.packet_id),
                    )
                    return packet.packet_id
                if (
                    not payload_matches
                    or not isinstance(existing["binding_hmac"], str)
                    or not hmac.compare_digest(existing["binding_hmac"], binding_hmac)
                ):
                    raise HandoffIntegrityError(
                        "packet ID is already bound to different handoff content"
                    )
                return packet.packet_id
            connection.execute(
                """
                INSERT INTO packet_handoff(
                    packet_id, packet_kind, payload_sha256, payload_json, binding_hmac, issued_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    packet.packet_id,
                    self.kind,
                    payload_sha256,
                    payload_json,
                    binding_hmac,
                    packet.created_at if isinstance(packet, CasePacket) else packet.retrieved_at,
                ),
            )
        return packet.packet_id

    def get(self, packet_id: str) -> Packet:
        if not isinstance(packet_id, str) or not _PACKET_IDS[self.kind].fullmatch(packet_id):
            raise ValueError(f"{self.kind} packet_id is not canonical")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT packet_kind, payload_sha256, payload_json, binding_hmac
                FROM packet_handoff WHERE packet_id = ?
                """,
                (packet_id,),
            ).fetchone()
        if row is None:
            raise UnknownHandoffPacketError(
                f"packet was not issued into the {self.kind} handoff store"
            )
        if len(row["payload_json"].encode("utf-8")) > MAX_HANDOFF_PACKET_BYTES:
            raise HandoffIntegrityError("handoff packet exceeds the canonical size limit")
        actual_hash = hashlib.sha256(row["payload_json"].encode("utf-8")).hexdigest()
        expected_hmac = self._binding_hmac(packet_id, actual_hash)
        if (
            row["packet_kind"] != self.kind
            or actual_hash != row["payload_sha256"]
            or not isinstance(row["binding_hmac"], str)
            or not hmac.compare_digest(row["binding_hmac"], expected_hmac)
        ):
            raise HandoffIntegrityError("handoff packet binding is invalid")
        try:
            raw = json.loads(row["payload_json"])
            if not isinstance(raw, dict):
                raise ValueError("handoff packet payload must be an object")
            legacy_evidence_without_risk_envelope = (
                self.kind == "evidence" and "risk_envelope" not in raw
            )
            if legacy_evidence_without_risk_envelope and raw.get("schema_version") != "1.2":
                raise ValueError(
                    "only EvidencePacket 1.2 may omit risk_envelope"
                )
            packet = (
                case_packet_from(raw)
                if self.kind == "case"
                else evidence_packet_from(raw)
            )
            if isinstance(packet, CasePacket):
                validate_case_packet(packet)
            elif (
                not legacy_evidence_without_risk_envelope
                and not packet.risk_envelope.is_explicit
            ):
                raise ValueError(
                    "stored evidence with a risk_envelope must declare an explicit intent"
                )
        except (KeyError, TypeError, ValueError) as error:
            raise HandoffIntegrityError(
                "handoff packet canonical payload is invalid"
            ) from error
        try:
            canonical_payload = _canonical_json(
                packet,
                legacy_evidence_without_risk_envelope=(
                    legacy_evidence_without_risk_envelope
                ),
            )
        except ValueError as error:
            raise HandoffIntegrityError(
                "handoff packet canonical payload is invalid"
            ) from error
        if packet.packet_id != packet_id or canonical_payload != row["payload_json"]:
            raise HandoffIntegrityError("handoff packet canonical payload is invalid")
        return packet
