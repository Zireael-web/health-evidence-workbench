"""Stable contracts crossing trust-zone boundaries.

The contracts deliberately keep source statements, user notes, calculations,
external evidence, and model inferences distinct.  Mixing those categories is
the fastest route to an authoritative-looking but unverifiable medical answer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum, StrEnum
from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any

from .vault.models import ProvenanceLocator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_observed_at(
    value: str | None,
    *,
    name: str = "observed_at",
) -> str | None:
    """Accept exact dates or timezone-aware ISO 8601 date-times only."""

    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise ValueError(f"{name} must be ISO 8601 text without NUL or null")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            date.fromisoformat(value)
        except ValueError:
            raise ValueError(f"{name} must be a valid ISO 8601 date") from None
        return value
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            f"{name} must be an ISO 8601 date or date-time"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} date-times must include a timezone")
    return value


class TrustZone(StrEnum):
    PRIVATE_INGEST = "private_ingest"
    PUBLIC_RESEARCH = "public_research"
    SOURCE_REVIEW = "source_review"
    OFFLINE_SYNTHESIS = "offline_synthesis"
    AUDIT = "audit"
    REVIEW_EXPORT = "review_export"


class StatementKind(StrEnum):
    SOURCE_FACT = "source_fact"
    USER_NOTE = "user_note"
    CALCULATED = "calculated"
    EXTERNAL_EVIDENCE = "external_evidence"
    INFERENCE = "inference"
    GUIDELINE_RECOMMENDATION = "guideline_recommendation"


class VerificationStatus(StrEnum):
    EXTRACTED = "extracted"
    NEEDS_REVIEW = "needs_review"
    VERIFIED = "verified"
    REJECTED = "rejected"


class RiskIntent(StrEnum):
    """Declared answer intent carried unchanged across public and synthesis artifacts.

    This is a caller-supplied safety contract.  It deliberately does not try to
    infer clinical intent from prose.
    """

    LEGACY_UNSPECIFIED = "legacy_unspecified"
    EDUCATION = "education"
    PERSONAL_CONTEXT = "personal_context"
    CLINICAL_ACTION = "clinical_action"
    URGENT_ASSESSMENT = "urgent_assessment"


@dataclass(frozen=True, slots=True)
class RiskEnvelope:
    """Declared risk intent; confirmation-required is not confirmation obtained."""

    intent: RiskIntent = RiskIntent.LEGACY_UNSPECIFIED
    clinician_confirmation_required: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.intent, RiskIntent):
            raise ValueError("RiskEnvelope.intent is unsupported")
        if type(self.clinician_confirmation_required) is not bool:
            raise ValueError(
                "RiskEnvelope.clinician_confirmation_required must be a boolean"
            )
        required = self.intent is RiskIntent.CLINICAL_ACTION
        if self.clinician_confirmation_required is not required:
            raise ValueError(
                "clinician_confirmation_required must be true only for "
                "clinical_action"
            )

    @property
    def is_explicit(self) -> bool:
        return self.intent is not RiskIntent.LEGACY_UNSPECIFIED


@dataclass(frozen=True, slots=True)
class ReferenceInterval:
    low: str | None = None
    high: str | None = None
    unit: str | None = None
    comparator: str | None = None
    label: str = "laboratory_reference"
    population: str | None = None


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    subject_id: str
    display: str
    raw_value: str
    original_unit: str | None = None
    code_system: str | None = None
    code: str | None = None
    normalized_value: str | None = None
    ucum_unit: str | None = None
    comparator: str | None = None
    specimen: str | None = None
    method: str | None = None
    device: str | None = None
    observed_at: str | None = None
    reference_intervals: tuple[ReferenceInterval, ...] = ()
    provenance: tuple[ProvenanceLocator, ...] = ()
    verification: VerificationStatus = VerificationStatus.EXTRACTED
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reference_intervals", tuple(self.reference_intervals))
        object.__setattr__(self, "provenance", tuple(self.provenance))
        object.__setattr__(self, "notes", tuple(self.notes))
        validate_observed_at(self.observed_at)


@dataclass(frozen=True, slots=True)
class Statement:
    statement_id: str
    kind: StatementKind
    text: str
    subject_id: str | None = None
    support_ids: tuple[str, ...] = ()
    provenance: tuple[ProvenanceLocator, ...] = ()
    verification: VerificationStatus = VerificationStatus.EXTRACTED
    certainty: str | None = None


@dataclass(frozen=True, slots=True)
class CasePacket:
    packet_id: str
    subject_id: str
    created_at: str = field(default_factory=utc_now)
    source_hashes: tuple[str, ...] = ()
    observations: tuple[Observation, ...] = ()
    statements: tuple[Statement, ...] = ()
    limitations: tuple[str, ...] = ()
    schema_version: str = "1.0"


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    evidence_id: str
    title: str
    source_type: str
    url: str
    published_at: str | None = None
    retrieved_at: str = field(default_factory=utc_now)
    organization: str | None = None
    jurisdiction: str | None = None
    identifiers: dict[str, str] = field(default_factory=dict)
    study_design: str | None = None
    population: str | None = None
    effect: str | None = None
    limitations: tuple[str, ...] = ()
    source_grade: str | None = None
    raw_grade: str | None = None
    supersedes: tuple[str, ...] = ()
    content_hash: str | None = None


def evidence_item_snapshot_sha256(item: EvidenceItem) -> str:
    """Hash source metadata while excluding the local retrieval timestamp."""

    if not isinstance(item, EvidenceItem):
        raise TypeError("item must be an EvidenceItem")
    material = asdict(item)
    material.pop("retrieved_at", None)
    return hashlib.sha256(
        json.dumps(
            material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ReviewedEvidenceClaim:
    """One explicitly reviewed source-level claim bound to a public source record.

    ``reviewer_id`` is attribution only. It may label a human or an independent
    agent pass and authenticates neither; ``VERIFIED`` means the persisted claim
    exactly matched the reviewed candidate, not that it is clinically true.
    """

    claim_id: str
    question: str
    source_kind: str
    source_evidence_id: str
    source_snapshot_sha256: str
    statement_kind: StatementKind
    claim_type: str
    text: str
    provenance: ProvenanceLocator
    review_receipt_id: str
    reviewed_at: str
    reviewer_id: str
    verification: VerificationStatus = VerificationStatus.VERIFIED
    population: str | None = None
    outcome: str | None = None
    effect: str | None = None
    native_grade_system: str | None = None
    native_grade: str | None = None
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not self.claim_id.strip()
            or not self.question.strip()
            or not self.source_evidence_id.strip()
            or not self.text.strip()
        ):
            raise ValueError("reviewed evidence claim ID, question, and text are required")
        if re.fullmatch(r"evclaim_[a-f0-9]{32}", self.claim_id) is None:
            raise ValueError("reviewed evidence claim_id must be an opaque evclaim_ ID")
        if self.source_kind not in {"retrieval_item", "guideline_recommendation"}:
            raise ValueError("reviewed evidence source_kind is unsupported")
        if self.claim_type not in {"finding", "effect", "harm", "recommendation"}:
            raise ValueError("reviewed evidence claim_type is unsupported")
        expected_kind = (
            StatementKind.GUIDELINE_RECOMMENDATION
            if self.claim_type == "recommendation"
            else StatementKind.EXTERNAL_EVIDENCE
        )
        if self.statement_kind is not expected_kind:
            raise ValueError("reviewed evidence claim type and statement kind do not match")
        if self.source_kind == "guideline_recommendation" and (
            self.statement_kind is not StatementKind.GUIDELINE_RECOMMENDATION
        ):
            raise ValueError("guideline source requires guideline_recommendation kind")
        if self.source_kind == "retrieval_item" and self.claim_type == "recommendation":
            raise ValueError("retrieval metadata cannot produce a guideline recommendation")
        if self.claim_type == "effect" and not (self.effect or "").strip():
            raise ValueError("reviewed effect claims require an exact effect field")
        if self.source_kind == "guideline_recommendation" and (
            not (self.native_grade_system or "").strip()
            or not (self.native_grade or "").strip()
        ):
            raise ValueError("reviewed guideline recommendations require native grade fields")
        if self.verification is not VerificationStatus.VERIFIED:
            raise ValueError("reviewed evidence claims must be verified")
        if re.fullmatch(r"[a-f0-9]{64}", self.source_snapshot_sha256) is None:
            raise ValueError("source_snapshot_sha256 must be a lowercase SHA-256 digest")
        if self.provenance.source_id != self.source_evidence_id:
            raise ValueError("reviewed evidence provenance source must match source_evidence_id")
        if re.fullmatch(r"[a-f0-9]{64}", self.provenance.sha256) is None:
            raise ValueError("reviewed evidence provenance requires a lowercase SHA-256 digest")
        if not self.provenance.excerpt or not self.provenance.locator:
            raise ValueError("reviewed evidence provenance requires locator and exact excerpt")
        if (
            re.fullmatch(r"eclaim_rcpt_[a-f0-9]{32}", self.review_receipt_id)
            is None
            or not self.reviewer_id.strip()
        ):
            raise ValueError("review receipt and reviewer attribution are required")
        try:
            reviewed_at = datetime.fromisoformat(
                self.reviewed_at.replace("Z", "+00:00")
            )
        except (AttributeError, ValueError):
            raise ValueError("reviewed_at must be an ISO 8601 date-time") from None
        if reviewed_at.tzinfo is None:
            raise ValueError("reviewed_at must include a timezone")


@dataclass(frozen=True, slots=True)
class SearchLogEntry:
    run_id: str
    source: str
    query_id: str
    executed_at: str
    query: dict[str, Any]
    result_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidencePacket:
    packet_id: str
    question: str
    items: tuple[EvidenceItem, ...]
    reviewed_claims: tuple[ReviewedEvidenceClaim, ...] = ()
    retrieved_at: str = field(default_factory=utc_now)
    search_log: tuple[SearchLogEntry, ...] = ()
    limitations: tuple[str, ...] = ()
    risk_envelope: RiskEnvelope = field(default_factory=RiskEnvelope)
    schema_version: str = "1.3"

    def __post_init__(self) -> None:
        if self.schema_version not in {"1.2", "1.3"}:
            raise ValueError("EvidencePacket schema_version must be 1.2 or 1.3")
        if not self.question.strip():
            raise ValueError("EvidencePacket question is required")
        if not self.search_log:
            raise ValueError("EvidencePacket requires a reproducible search log")
        if not isinstance(self.risk_envelope, RiskEnvelope):
            raise ValueError("EvidencePacket risk_envelope is required")
        if self.schema_version == "1.3" and not self.risk_envelope.is_explicit:
            raise ValueError("EvidencePacket 1.3 requires an explicit risk envelope")
        if self.schema_version == "1.2" and self.risk_envelope.is_explicit:
            raise ValueError("EvidencePacket 1.2 risk must remain legacy unspecified")
        item_ids = {item.evidence_id for item in self.items}
        item_source_types = {item.evidence_id: item.source_type for item in self.items}
        item_by_id = {item.evidence_id: item for item in self.items}
        if len(item_ids) != len(self.items):
            raise ValueError("EvidencePacket evidence IDs must be unique")
        claim_ids = {claim.claim_id for claim in self.reviewed_claims}
        if len(claim_ids) != len(self.reviewed_claims):
            raise ValueError("EvidencePacket reviewed claim IDs must be unique")
        if item_ids.intersection(claim_ids):
            raise ValueError("EvidencePacket item and reviewed claim IDs must be disjoint")
        for claim in self.reviewed_claims:
            if claim.source_evidence_id not in item_ids:
                raise ValueError("reviewed claim source is absent from EvidencePacket items")
            source_item = item_by_id[claim.source_evidence_id]
            if claim.source_snapshot_sha256 != evidence_item_snapshot_sha256(
                source_item
            ):
                raise ValueError(
                    "reviewed claim source snapshot does not match its EvidenceItem"
                )
            if (
                claim.source_kind == "guideline_recommendation"
                and item_source_types[claim.source_evidence_id] != "clinical_guideline"
            ):
                raise ValueError("guideline reviewed claim requires a clinical_guideline item")
            if claim.source_kind == "guideline_recommendation" and (
                source_item.content_hash is None
                or claim.provenance.sha256 != source_item.content_hash
            ):
                raise ValueError(
                    "guideline claim provenance must match its EvidenceItem content hash"
                )
            if claim.question != self.question:
                raise ValueError("reviewed claim question does not match EvidencePacket")


@dataclass(frozen=True, slots=True)
class Claim:
    claim_id: str
    text: str
    kind: StatementKind
    support_ids: tuple[str, ...]
    certainty: str
    conflicts_with: tuple[str, ...] = ()
    caveats: tuple[str, ...] = ()
    status: VerificationStatus = VerificationStatus.EXTRACTED


@dataclass(frozen=True, slots=True)
class AnswerBundle:
    bundle_id: str
    question: str
    claims: tuple[Claim, ...]
    case_packet_id: str | None = None
    evidence_packet_id: str | None = None
    created_at: str = field(default_factory=utc_now)
    review_required: bool = True
    limitations: tuple[str, ...] = ()
    risk_envelope: RiskEnvelope = field(default_factory=RiskEnvelope)
    schema_version: str = "1.1"

    def __post_init__(self) -> None:
        if self.schema_version not in {"1.0", "1.1"}:
            raise ValueError("AnswerBundle schema_version must be 1.0 or 1.1")
        if not isinstance(self.risk_envelope, RiskEnvelope):
            raise ValueError("AnswerBundle risk_envelope is required")
        if self.schema_version == "1.1" and not self.risk_envelope.is_explicit:
            raise ValueError("AnswerBundle 1.1 requires an explicit risk envelope")
        if self.schema_version == "1.0" and self.risk_envelope.is_explicit:
            raise ValueError("AnswerBundle 1.0 risk must remain legacy unspecified")


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def to_dict(value: Any) -> dict[str, Any]:
    """Convert a contract dataclass to JSON-compatible primitives."""

    return _json_value(asdict(value))
