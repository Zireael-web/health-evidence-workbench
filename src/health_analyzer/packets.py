"""Build minimal deterministic packets after human extraction review."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime
import hashlib
import json
import re
from typing import Any

from .contracts import (
    CasePacket,
    Observation,
    ProvenanceLocator,
    Statement,
    StatementKind,
    VerificationStatus,
    utc_now,
)
from .privacy import PrivacyGate, PrivacyViolation
from .serialization import observation_from, statement_from


_SUBJECT_ID = re.compile(r"subj_[a-f0-9]{16,64}\Z")
_CASE_PACKET_ID = re.compile(r"case_[a-f0-9]{20,64}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
MAX_CASE_PACKET_RECORDS = 100
MAX_CASE_PACKET_BYTES = 8 * 1024 * 1024


def case_packet_content_id(packet: CasePacket) -> str:
    """Derive the opaque ID from every canonical packet field except the ID."""

    if not isinstance(packet, CasePacket):
        raise TypeError("packet must be a CasePacket")
    material = asdict(packet)
    material.pop("packet_id")
    encoded = json.dumps(
        material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "case_" + hashlib.sha256(encoded).hexdigest()[:24]


def _require_packet_text(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise ValueError(f"{name} must be non-empty text without NUL")
    return value


def _validate_record_provenance(
    provenance: object,
    *,
    record_name: str,
) -> tuple[ProvenanceLocator, ...]:
    if not isinstance(provenance, tuple) or not provenance:
        raise ValueError(f"{record_name} requires provenance")
    for locator in provenance:
        if not isinstance(locator, ProvenanceLocator):
            raise ValueError(f"{record_name} provenance is malformed")
        # Reconstruct from the public representation so objects created through
        # unsafe low-level means cannot bypass the locator invariants.
        ProvenanceLocator(**locator.to_dict())
    return provenance


def validate_case_packet(packet: CasePacket) -> None:
    """Validate the complete trust-boundary CasePacket without mutating it."""

    if not isinstance(packet, CasePacket):
        raise TypeError("packet must be a CasePacket")
    if not isinstance(packet.packet_id, str) or not _CASE_PACKET_ID.fullmatch(
        packet.packet_id
    ):
        raise ValueError("CasePacket packet_id is not canonical")
    if not isinstance(packet.subject_id, str) or not _SUBJECT_ID.fullmatch(
        packet.subject_id
    ):
        raise ValueError("CasePacket requires a keyed pseudonymous subject_id")
    if packet.schema_version != "1.0":
        raise ValueError("CasePacket schema_version must be 1.0")
    _validated_created_at(packet.created_at)
    for name in ("source_hashes", "observations", "statements", "limitations"):
        if not isinstance(getattr(packet, name), tuple):
            raise ValueError(f"CasePacket {name} must be an immutable tuple")

    record_count = len(packet.observations) + len(packet.statements)
    if record_count < 1:
        raise ValueError("CasePacket requires at least one verified record")
    if record_count > MAX_CASE_PACKET_RECORDS:
        raise ValueError(
            f"CasePacket accepts at most {MAX_CASE_PACKET_RECORDS} records"
        )

    record_ids: list[str] = []
    observation_ids: list[str] = []
    statement_ids: list[str] = []
    provenance_hashes: set[str] = set()
    for observation in packet.observations:
        if not isinstance(observation, Observation):
            raise ValueError("CasePacket observations are malformed")
        observation_id = _require_packet_text(
            observation.observation_id,
            name="observation_id",
        )
        record_ids.append(observation_id)
        observation_ids.append(observation_id)
        if observation.subject_id != packet.subject_id:
            raise ValueError("CasePacket observation belongs to a different subject")
        _require_packet_text(observation.display, name="observation display")
        _require_packet_text(observation.raw_value, name="observation raw_value")
        _assert_minimized_record_text(
            "observation",
            {
                "display": observation.display,
                "raw_value": observation.raw_value,
            },
        )
        if observation.verification is not VerificationStatus.VERIFIED:
            raise ValueError("CasePacket observations must be verified")
        provenance = _validate_record_provenance(
            observation.provenance,
            record_name="verified observation",
        )
        provenance_hashes.update(locator.sha256 for locator in provenance)

    for statement in packet.statements:
        if not isinstance(statement, Statement):
            raise ValueError("CasePacket statements are malformed")
        statement_id = _require_packet_text(
            statement.statement_id,
            name="statement_id",
        )
        record_ids.append(statement_id)
        statement_ids.append(statement_id)
        if statement.subject_id not in (None, packet.subject_id):
            raise ValueError("CasePacket statement belongs to a different subject")
        _require_packet_text(statement.text, name="statement text")
        _assert_minimized_record_text("statement", {"text": statement.text})
        if not isinstance(statement.kind, StatementKind):
            raise ValueError("CasePacket statement kind is invalid")
        if statement.verification is not VerificationStatus.VERIFIED:
            raise ValueError("CasePacket statements must be verified")
        provenance = _validate_record_provenance(
            statement.provenance,
            record_name="verified statement",
        )
        provenance_hashes.update(locator.sha256 for locator in provenance)

    if len(set(record_ids)) != len(record_ids):
        raise ValueError("CasePacket record identifiers must be unique")
    if observation_ids != sorted(observation_ids) or statement_ids != sorted(
        statement_ids
    ):
        raise ValueError("CasePacket records must use canonical identifier order")
    if len(set(packet.source_hashes)) != len(packet.source_hashes) or any(
        not isinstance(value, str) or _SHA256.fullmatch(value) is None
        for value in packet.source_hashes
    ):
        raise ValueError("CasePacket source_hashes must be unique SHA-256 digests")
    if packet.source_hashes != tuple(sorted(packet.source_hashes)):
        raise ValueError("CasePacket source_hashes must use canonical order")
    if set(packet.source_hashes) != provenance_hashes:
        raise ValueError(
            "CasePacket source_hashes must exactly cover record provenance"
        )
    for limitation in packet.limitations:
        _require_packet_text(limitation, name="CasePacket limitation")
        try:
            PrivacyGate().assert_minimized_case_text(limitation)
        except PrivacyViolation as error:
            raise ValueError(
                "CasePacket limitation contains data that must be minimized: "
                f"{error}"
            ) from None

    canonical_bytes = json.dumps(
        asdict(packet),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(canonical_bytes) > MAX_CASE_PACKET_BYTES:
        raise ValueError("CasePacket exceeds the canonical byte limit")
    if packet.packet_id != case_packet_content_id(packet):
        raise ValueError("CasePacket packet_id is not derived from canonical content")


def _validated_created_at(value: str | None) -> str:
    resolved = value or utc_now()
    if not isinstance(resolved, str) or not resolved.strip() or "\0" in resolved:
        raise ValueError("CasePacket created_at must be an ISO 8601 date-time")
    try:
        parsed = datetime.fromisoformat(resolved.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("CasePacket created_at must be an ISO 8601 date-time") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("CasePacket created_at must include a timezone")
    return resolved


def _assert_bounded_packet_input(value: object) -> None:
    stack = [value]
    visited = 0
    text_bytes = 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 20_000:
            raise ValueError("CasePacket input exceeds the structural limit")
        if isinstance(current, str):
            text_bytes += len(current.encode("utf-8"))
            if text_bytes > MAX_CASE_PACKET_BYTES:
                raise ValueError("CasePacket input exceeds the byte limit")
        elif isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend(current)


def _assert_minimized_record_text(record_type: str, payload: dict[str, Any]) -> None:
    if record_type == "observation":
        values = (f"{payload.get('display', '')}: {payload.get('raw_value', '')}",)
    else:
        values = (str(payload.get("text", "")),)
    gate = PrivacyGate()
    for value in values:
        try:
            gate.assert_minimized_case_text(value)
        except PrivacyViolation as error:
            raise ValueError(
                "CasePacket record contains data that must be minimized in the private zone: "
                f"{error}"
            ) from None


def build_case_packet(
    *,
    subject_id: str,
    records: list[dict[str, Any]],
    limitations: list[str] | None = None,
    created_at: str | None = None,
) -> CasePacket:
    if not _SUBJECT_ID.fullmatch(subject_id):
        raise ValueError("CasePacket requires a keyed pseudonymous subj_ identifier")
    if not isinstance(records, list) or not records:
        raise ValueError("CasePacket requires a non-empty record array")
    if len(records) > MAX_CASE_PACKET_RECORDS:
        raise ValueError(f"CasePacket accepts at most {MAX_CASE_PACKET_RECORDS} records")
    if limitations is not None and not isinstance(limitations, list):
        raise ValueError("CasePacket limitations must be an array")
    if any(
        not isinstance(item, str) or not item.strip() or "\0" in item
        for item in (limitations or [])
    ):
        raise ValueError("CasePacket limitations must contain non-empty text")
    _assert_bounded_packet_input({"records": records, "limitations": limitations or []})
    observations = []
    statements: list[Statement] = []
    source_hashes: set[str] = set()
    for record in records:
        record_type = record.get("record_type")
        payload = dict(record.get("payload") or {})
        _assert_minimized_record_text(str(record_type), payload)
        if record_type == "observation":
            observation = observation_from(payload)
            if observation.subject_id != subject_id:
                raise ValueError("observation belongs to a different subject")
            if observation.verification is not VerificationStatus.VERIFIED:
                raise ValueError("CasePacket may only contain human-verified observations")
            if not observation.provenance:
                raise ValueError("verified observation requires provenance")
            observations.append(observation)
            source_hashes.update(locator.sha256 for locator in observation.provenance)
        elif record_type == "statement":
            statement = statement_from(payload)
            if statement.subject_id not in (None, subject_id):
                raise ValueError("statement belongs to a different subject")
            if statement.verification is not VerificationStatus.VERIFIED:
                raise ValueError("CasePacket may only contain human-verified statements")
            if not statement.provenance:
                raise ValueError("verified statement requires provenance")
            statements.append(statement)
            source_hashes.update(locator.sha256 for locator in statement.provenance)
        else:
            raise ValueError(f"unsupported extraction record type: {record_type}")
    observations.sort(key=lambda item: item.observation_id)
    statements.sort(key=lambda item: item.statement_id)
    record_ids = [item.observation_id for item in observations]
    record_ids.extend(item.statement_id for item in statements)
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("CasePacket record identifiers must be unique")
    provisional = CasePacket(
        packet_id="case_" + "0" * 24,
        subject_id=subject_id,
        created_at=_validated_created_at(created_at),
        source_hashes=tuple(sorted(source_hashes)),
        observations=tuple(observations),
        statements=tuple(statements),
        limitations=tuple(limitations or ()),
    )
    packet = replace(provisional, packet_id=case_packet_content_id(provisional))
    if len(
        json.dumps(
            asdict(packet),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ) > MAX_CASE_PACKET_BYTES:
        raise ValueError("CasePacket exceeds the canonical byte limit")
    validate_case_packet(packet)
    return packet
