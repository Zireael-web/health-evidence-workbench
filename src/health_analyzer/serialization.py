"""Strict JSON-to-contract decoding used at MCP/CLI boundaries."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .contracts import (
    AnswerBundle,
    CasePacket,
    Claim,
    EvidenceItem,
    EvidencePacket,
    ReviewedEvidenceClaim,
    Observation,
    ProvenanceLocator,
    ReferenceInterval,
    RiskEnvelope,
    RiskIntent,
    SearchLogEntry,
    Statement,
    StatementKind,
    VerificationStatus,
)


def _tuple(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ValueError("expected an array")
    return tuple(value)


def _strict_object(
    value: Any,
    *,
    name: str,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    if missing:
        raise ValueError(f"{name} is missing required fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"{name} contains unsupported fields: {', '.join(sorted(extra))}")
    return dict(value)


def _string(value: Any, *, name: str, nonempty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if nonempty and not value.strip():
        raise ValueError(f"{name} must not be empty")
    return value


def _optional_string(value: Any, *, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name=name, nonempty=True)


def _string_tuple(value: Any, *, name: str, nonempty: bool = False) -> tuple[str, ...]:
    items = _tuple(value)
    if nonempty and not items:
        raise ValueError(f"{name} must not be empty")
    resolved = tuple(_string(item, name=f"{name} item", nonempty=True) for item in items)
    return resolved


def _datetime_string(value: Any, *, name: str) -> str:
    text = _string(value, name=name, nonempty=True)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{name} must be an ISO 8601 date-time") from None
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return text


def provenance_from(data: dict[str, Any]) -> ProvenanceLocator:
    payload = dict(data)
    if payload.get("bbox") is not None:
        payload["bbox"] = tuple(payload["bbox"])
    return ProvenanceLocator(**payload)


def reference_interval_from(data: dict[str, Any]) -> ReferenceInterval:
    return ReferenceInterval(**data)


def observation_from(data: dict[str, Any]) -> Observation:
    payload = dict(data)
    payload["reference_intervals"] = tuple(
        reference_interval_from(item) for item in _tuple(payload.get("reference_intervals"))
    )
    payload["provenance"] = tuple(provenance_from(item) for item in _tuple(payload.get("provenance")))
    payload["notes"] = _tuple(payload.get("notes"))
    if "verification" in payload:
        payload["verification"] = VerificationStatus(payload["verification"])
    return Observation(**payload)


def statement_from(data: dict[str, Any]) -> Statement:
    payload = dict(data)
    payload["kind"] = StatementKind(payload["kind"])
    payload["support_ids"] = _tuple(payload.get("support_ids"))
    payload["provenance"] = tuple(provenance_from(item) for item in _tuple(payload.get("provenance")))
    if "verification" in payload:
        payload["verification"] = VerificationStatus(payload["verification"])
    return Statement(**payload)


def case_packet_from(data: dict[str, Any]) -> CasePacket:
    payload = dict(data)
    payload["source_hashes"] = _tuple(payload.get("source_hashes"))
    payload["observations"] = tuple(
        observation_from(item) for item in _tuple(payload.get("observations"))
    )
    payload["statements"] = tuple(statement_from(item) for item in _tuple(payload.get("statements")))
    payload["limitations"] = _tuple(payload.get("limitations"))
    return CasePacket(**payload)


def evidence_item_from(data: dict[str, Any]) -> EvidenceItem:
    payload = dict(data)
    payload["limitations"] = _tuple(payload.get("limitations"))
    payload["supersedes"] = _tuple(payload.get("supersedes"))
    payload["identifiers"] = dict(payload.get("identifiers") or {})
    return EvidenceItem(**payload)


def reviewed_evidence_claim_from(data: dict[str, Any]) -> ReviewedEvidenceClaim:
    payload = dict(data)
    payload["statement_kind"] = StatementKind(payload["statement_kind"])
    payload["provenance"] = provenance_from(payload["provenance"])
    payload["limitations"] = _tuple(payload.get("limitations"))
    if "verification" in payload:
        payload["verification"] = VerificationStatus(payload["verification"])
    return ReviewedEvidenceClaim(**payload)


def search_log_entry_from(data: dict[str, Any]) -> SearchLogEntry:
    payload = dict(data)
    payload["query"] = dict(payload.get("query") or {})
    payload["result_ids"] = _tuple(payload.get("result_ids"))
    return SearchLogEntry(**payload)


def risk_envelope_from(data: dict[str, Any]) -> RiskEnvelope:
    payload = _strict_object(
        data,
        name="RiskEnvelope",
        required=frozenset({"intent", "clinician_confirmation_required"}),
    )
    try:
        payload["intent"] = RiskIntent(payload["intent"])
    except (TypeError, ValueError):
        raise ValueError("RiskEnvelope.intent is unsupported") from None
    if type(payload["clinician_confirmation_required"]) is not bool:
        raise ValueError(
            "RiskEnvelope.clinician_confirmation_required must be a boolean"
        )
    return RiskEnvelope(**payload)


def evidence_packet_from(data: dict[str, Any]) -> EvidencePacket:
    payload = dict(data)
    schema_version = payload.get("schema_version")
    if schema_version == "1.3" and "risk_envelope" not in payload:
        raise ValueError("EvidencePacket 1.3 is missing required risk_envelope")
    payload["items"] = tuple(evidence_item_from(item) for item in _tuple(payload.get("items")))
    payload["reviewed_claims"] = tuple(
        reviewed_evidence_claim_from(item)
        for item in _tuple(payload.get("reviewed_claims"))
    )
    payload["search_log"] = tuple(
        search_log_entry_from(item) for item in _tuple(payload.get("search_log"))
    )
    payload["limitations"] = _tuple(payload.get("limitations"))
    if "risk_envelope" in payload:
        payload["risk_envelope"] = risk_envelope_from(payload["risk_envelope"])
    return EvidencePacket(**payload)


def claim_from(data: dict[str, Any]) -> Claim:
    payload = _strict_object(
        data,
        name="Claim",
        required=frozenset(
            {
                "claim_id",
                "text",
                "kind",
                "support_ids",
                "certainty",
                "conflicts_with",
                "caveats",
                "status",
            }
        ),
    )
    payload["claim_id"] = _string(payload["claim_id"], name="Claim.claim_id", nonempty=True)
    payload["text"] = _string(payload["text"], name="Claim.text", nonempty=True)
    try:
        payload["kind"] = StatementKind(payload["kind"])
    except (TypeError, ValueError):
        raise ValueError("Claim.kind is unsupported") from None
    payload["support_ids"] = _string_tuple(
        payload["support_ids"], name="Claim.support_ids", nonempty=True
    )
    if len(set(payload["support_ids"])) != len(payload["support_ids"]):
        raise ValueError("Claim.support_ids must contain unique identifiers")
    payload["certainty"] = _string(payload["certainty"], name="Claim.certainty")
    if payload["certainty"] not in {"low", "moderate", "high", "not_applicable"}:
        raise ValueError("Claim.certainty is unsupported")
    payload["conflicts_with"] = _string_tuple(
        payload["conflicts_with"], name="Claim.conflicts_with"
    )
    payload["caveats"] = _string_tuple(payload["caveats"], name="Claim.caveats")
    try:
        payload["status"] = VerificationStatus(payload["status"])
    except (TypeError, ValueError):
        raise ValueError("Claim.status is unsupported") from None
    return Claim(**payload)


def answer_bundle_from(data: dict[str, Any]) -> AnswerBundle:
    payload = _strict_object(
        data,
        name="AnswerBundle",
        required=frozenset(
            {
                "bundle_id",
                "question",
                "claims",
                "created_at",
                "review_required",
                "limitations",
                "schema_version",
            }
        ),
        optional=frozenset(
            {"case_packet_id", "evidence_packet_id", "risk_envelope"}
        ),
    )
    payload["bundle_id"] = _string(
        payload["bundle_id"], name="AnswerBundle.bundle_id", nonempty=True
    )
    payload["question"] = _string(
        payload["question"], name="AnswerBundle.question", nonempty=True
    )
    raw_claims = _tuple(payload["claims"])
    if not raw_claims:
        raise ValueError("AnswerBundle.claims must not be empty")
    payload["claims"] = tuple(claim_from(item) for item in raw_claims)
    payload["case_packet_id"] = _optional_string(
        payload.get("case_packet_id"), name="AnswerBundle.case_packet_id"
    )
    payload["evidence_packet_id"] = _optional_string(
        payload.get("evidence_packet_id"), name="AnswerBundle.evidence_packet_id"
    )
    payload["created_at"] = _datetime_string(
        payload["created_at"], name="AnswerBundle.created_at"
    )
    if type(payload["review_required"]) is not bool:
        raise ValueError("AnswerBundle.review_required must be a boolean")
    payload["limitations"] = _string_tuple(
        payload["limitations"], name="AnswerBundle.limitations"
    )
    if "risk_envelope" in payload:
        payload["risk_envelope"] = risk_envelope_from(payload["risk_envelope"])
    if payload["schema_version"] not in {"1.0", "1.1"}:
        raise ValueError("AnswerBundle.schema_version must be '1.0' or '1.1'")
    if payload["schema_version"] == "1.1" and "risk_envelope" not in data:
        raise ValueError("AnswerBundle 1.1 is missing required risk_envelope")
    return AnswerBundle(**payload)
