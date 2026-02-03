"""Offline decision drafts over issued packets and strictly typed answer claims.

This module performs no I/O. Its caller must load packets through the verified
handoff stores; validation here does not establish issuance. Assigning a claim
to an option field is a draft editorial mapping, not a semantic or clinical
review. No option can become an approved treatment through this API.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
import hashlib
import json
import re
from typing import Any

from ..claims.ledger import AuditReport, audit_answer
from ..contracts import (
    AnswerBundle,
    CasePacket,
    Claim,
    EvidenceItem,
    EvidencePacket,
    Observation,
    ReviewedEvidenceClaim,
    RiskEnvelope,
    RiskIntent,
    Statement,
    to_dict,
)
from ..privacy import PrivacyGate
from ..serialization import answer_bundle_from, evidence_packet_from
from .validation import validated_case_snapshot


MAX_DECISION_OPTIONS = 10
MAX_DECISION_REFERENCES = 100
MAX_DECISION_CLAIMS = 100
_REFERENCE_FIELDS = (
    "benefit_claim_ids",
    "harm_claim_ids",
    "dose_claim_ids",
    "duration_claim_ids",
    "monitoring_claim_ids",
    "alternative_claim_ids",
    "applicability_claim_ids",
    "uncertainty_claim_ids",
)
_OPTION_FIELDS = frozenset(("option_id", "label_claim_id", *_REFERENCE_FIELDS))
_DRAFT_AUDIT_CODES = frozenset(
    ("unverified_output_claim", "clinician_confirmation_not_obtained")
)
_LIMITATIONS = (
    "This card is a draft for review; no option is selected or clinically approved.",
    "Structural traceability does not establish semantic support, applicability, "
    "citation truth, or clinical safety. Option-field assignments also need review.",
    "Missing information describes the supplied minimal packets and draft only; "
    "it does not establish a clinical absence or a complete, current history.",
)


class DecisionContext(StrEnum):
    ALLERGIES = "allergies"
    MEDICATIONS = "medications"
    SUPPLEMENTS = "supplements"
    CONDITIONS = "conditions"
    SYMPTOMS = "symptoms"
    GOALS = "goals"
    MEASUREMENTS = "measurements"
    PREVIOUS_TREATMENTS = "previous_treatments"
    PREFERENCES = "preferences"


def _text(value: object, *, name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\0" in value
    ):
        raise ValueError(f"{name} must be non-empty text of at most {maximum} characters without NUL")
    return value


def _array(value: object, *, name: str, maximum: int) -> tuple[Any, ...]:
    if not isinstance(value, (tuple, list)):
        raise ValueError(f"{name} must be an array")
    if len(value) > maximum:
        raise ValueError(f"{name} accepts at most {maximum} entries")
    return tuple(value)


def _references(value: object, *, name: str) -> tuple[str, ...]:
    references = tuple(
        _text(item, name=name, maximum=128)
        for item in _array(value, name=name, maximum=MAX_DECISION_REFERENCES)
    )
    if len(set(references)) != len(references):
        raise ValueError(f"{name} must contain unique claim identifiers")
    return references


@dataclass(frozen=True, slots=True)
class DecisionOptionDraft:
    """Only exact answer-claim references; medical text is never accepted here."""

    option_id: str
    label_claim_id: str | None = None
    benefit_claim_ids: tuple[str, ...] = ()
    harm_claim_ids: tuple[str, ...] = ()
    dose_claim_ids: tuple[str, ...] = ()
    duration_claim_ids: tuple[str, ...] = ()
    monitoring_claim_ids: tuple[str, ...] = ()
    alternative_claim_ids: tuple[str, ...] = ()
    applicability_claim_ids: tuple[str, ...] = ()
    uncertainty_claim_ids: tuple[str, ...] = ()
    status: str = field(default="draft", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.option_id, str) or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.option_id
        ) is None:
            raise ValueError("option_id must be a neutral identifier of at most 64 characters")
        if self.label_claim_id is not None:
            _text(self.label_claim_id, name="label_claim_id", maximum=128)
        for name in _REFERENCE_FIELDS:
            object.__setattr__(self, name, _references(getattr(self, name), name=name))
        if len(_option_references(self)) > MAX_DECISION_REFERENCES:
            raise ValueError("an option accepts at most 100 claim references")


def _option_references(option: DecisionOptionDraft) -> tuple[str, ...]:
    return (
        ((option.label_claim_id,) if option.label_claim_id is not None else ())
        + tuple(reference for name in _REFERENCE_FIELDS for reference in getattr(option, name))
    )


def decision_option_drafts_from(value: object) -> tuple[DecisionOptionDraft, ...]:
    """Reject unknown fields, prose, duplicate IDs, and caps without truncation."""

    result: list[DecisionOptionDraft] = []
    for item in _array(value, name="options", maximum=MAX_DECISION_OPTIONS):
        if not isinstance(item, dict) or not all(isinstance(key, str) for key in item):
            raise ValueError("each decision option must be an object")
        if "option_id" not in item:
            raise ValueError("decision option is missing option_id")
        if set(item) - _OPTION_FIELDS:
            raise ValueError("decision option contains unsupported fields")
        result.append(DecisionOptionDraft(**item))
    return _validate_options(tuple(result))


def _validate_options(value: object) -> tuple[DecisionOptionDraft, ...]:
    options = _array(value, name="options", maximum=MAX_DECISION_OPTIONS)
    if not all(isinstance(option, DecisionOptionDraft) for option in options):
        raise ValueError("options must contain DecisionOptionDraft values")
    # Reconstruct immutable values to enforce the direct Python API too.
    options = tuple(
        DecisionOptionDraft(**{name: getattr(option, name) for name in _OPTION_FIELDS})
        for option in options
    )
    if len({option.option_id for option in options}) != len(options):
        raise ValueError("options must have unique option_id values")
    if sum(len(_option_references(option)) for option in options) > MAX_DECISION_REFERENCES:
        raise ValueError("decision card accepts at most 100 claim references")
    return options


def decision_contexts_from(value: object) -> tuple[DecisionContext, ...]:
    contexts: list[DecisionContext] = []
    for item in _array(value, name="required_context", maximum=len(DecisionContext)):
        try:
            contexts.append(DecisionContext(item))
        except (ValueError, TypeError):
            raise ValueError("required_context contains an unsupported category") from None
    if len(set(contexts)) != len(contexts):
        raise ValueError("required_context categories must be unique")
    return tuple(contexts)


@dataclass(frozen=True, slots=True)
class DecisionContextGap:
    category: DecisionContext
    status: str = field(default="not_assessed", init=False)
    message: str = field(
        default="This required context has not been assessed by the structural card builder; "
        "review the supplied case records for completeness, relevance, and recency.",
        init=False,
    )


@dataclass(frozen=True, slots=True)
class DecisionCard:
    card_id: str
    question: str
    case_packet_id: str | None
    evidence_packet_id: str | None
    answer_bundle_id: str | None
    risk_envelope: RiskEnvelope
    status: str
    options: tuple[DecisionOptionDraft, ...]
    claims: tuple[Claim, ...]
    case_observations: tuple[Observation, ...]
    case_statements: tuple[Statement, ...]
    reviewed_evidence_claims: tuple[ReviewedEvidenceClaim, ...]
    evidence_items: tuple[EvidenceItem, ...]
    missing_context: tuple[DecisionContextGap, ...]
    research_gaps: tuple[str, ...]
    limitations: tuple[str, ...]
    audit: AuditReport | None
    card_type: str = field(default="decision", init=False)
    schema_version: str = field(default="1.0", init=False)
    review_required: bool = field(default=True, init=False)
    clinical_approval_obtained: bool = field(default=False, init=False)


def build_decision_card(
    *,
    question: str,
    risk_envelope: RiskEnvelope,
    case_packet: CasePacket | None = None,
    evidence_packet: EvidencePacket | None = None,
    answer_bundle: AnswerBundle | None = None,
    options: tuple[DecisionOptionDraft, ...] = (),
    required_context: tuple[DecisionContext, ...] = (),
) -> DecisionCard:
    """Build a bounded, traceable draft; clinical-action output stays blocked.

    ``question`` is a planning question, not a substantive medical statement.
    Use ``answer_bundle=None`` when research or synthesis has not yet happened;
    an empty or malformed AnswerBundle is never accepted as a shortcut.
    Required context remains unassessed, even if related case records exist.
    """

    _text(question, name="question", maximum=4_000)
    if not isinstance(risk_envelope, RiskEnvelope) or not risk_envelope.is_explicit:
        raise ValueError("decision card requires an explicit risk envelope")
    risk_envelope = RiskEnvelope(
        intent=risk_envelope.intent,
        clinician_confirmation_required=risk_envelope.clinician_confirmation_required,
    )
    resolved_options = _validate_options(options)
    contexts = decision_contexts_from(required_context)
    if case_packet is not None:
        case_packet = validated_case_snapshot(case_packet)
    if evidence_packet is not None:
        if not isinstance(evidence_packet, EvidencePacket):
            raise ValueError("evidence_packet must be an EvidencePacket")
        if any(len(values) > 100 for values in (
            evidence_packet.items, evidence_packet.reviewed_claims, evidence_packet.search_log
        )):
            raise ValueError("decision evidence accepts at most 100 items, reviewed claims, and search runs")
        evidence_packet = evidence_packet_from(to_dict(evidence_packet))
        if evidence_packet.question != question:
            raise ValueError("decision question does not match EvidencePacket")
        if evidence_packet.risk_envelope != risk_envelope:
            raise ValueError("decision risk envelope does not match EvidencePacket")
    if answer_bundle is not None:
        if not isinstance(answer_bundle, AnswerBundle):
            raise ValueError("answer_bundle must be an AnswerBundle")
        if len(answer_bundle.claims) > MAX_DECISION_CLAIMS:
            raise ValueError("decision answer accepts at most 100 claims")
        answer_bundle = answer_bundle_from(to_dict(answer_bundle))
        for claim in answer_bundle.claims:
            _text(claim.text, name="Claim.text", maximum=8_000)
        if answer_bundle.question != question:
            raise ValueError("decision question does not match AnswerBundle")
        if answer_bundle.risk_envelope != risk_envelope:
            raise ValueError("decision risk envelope does not match AnswerBundle")

    gate = PrivacyGate()
    gate.assert_bounded_payload({
        "question": question,
        "case_packet": to_dict(case_packet) if case_packet is not None else None,
        "evidence_packet": to_dict(evidence_packet) if evidence_packet is not None else None,
        "answer_bundle": to_dict(answer_bundle) if answer_bundle is not None else None,
        "options": [to_dict(option) for option in resolved_options],
    })
    report: AuditReport | None = None
    claims = answer_bundle.claims if answer_bundle is not None else ()
    if answer_bundle is not None:
        report = audit_answer(
            answer_bundle, case_packet=case_packet, evidence_packet=evidence_packet
        )
        failures = sorted({
            issue.code for issue in report.issues
            if issue.severity == "error" and issue.code not in _DRAFT_AUDIT_CODES
        })
        if failures:
            raise ValueError("decision answer failed audit: " + ", ".join(failures))
    claim_ids = {claim.claim_id for claim in claims}
    mapped_ids = {reference for option in resolved_options for reference in _option_references(option)}
    if mapped_ids - claim_ids:
        raise ValueError("decision options reference claims absent from AnswerBundle")

    support_ids = {support for claim in claims for support in claim.support_ids}
    observations = tuple(
        observation for observation in (case_packet.observations if case_packet else ())
        if observation.observation_id in support_ids
    )
    statements = tuple(
        statement for statement in (case_packet.statements if case_packet else ())
        if statement.statement_id in support_ids
    )
    reviewed_claims = tuple(
        claim for claim in (evidence_packet.reviewed_claims if evidence_packet else ())
        if claim.claim_id in support_ids
    )
    source_ids = {claim.source_evidence_id for claim in reviewed_claims}
    evidence_items = tuple(
        item for item in (evidence_packet.items if evidence_packet else ())
        if item.evidence_id in source_ids
    )
    gaps: list[str] = []
    if answer_bundle is None:
        gaps.append("An AnswerBundle draft has not been supplied.")
    if not evidence_packet or not evidence_packet.reviewed_claims:
        gaps.append("Source-reviewed evidence claims have not been supplied.")
    if not resolved_options:
        gaps.append("Decision options have not been mapped to answer claims.")
    elif not mapped_ids:
        gaps.append("The draft options do not yet reference any answer claims.")
    if not case_packet and risk_envelope.intent in {
        RiskIntent.PERSONAL_CONTEXT, RiskIntent.CLINICAL_ACTION, RiskIntent.URGENT_ASSESSMENT
    }:
        gaps.append("A verified CasePacket has not been supplied for personal context.")
    reviewed_ids = {claim.claim_id for claim in reviewed_claims}
    mapped_public_support = any(
        claim.claim_id in mapped_ids and bool(set(claim.support_ids) & reviewed_ids)
        for claim in claims
    )
    if resolved_options and not mapped_public_support:
        gaps.append("No option claim is linked to source-reviewed public evidence.")
    status = "research_needed" if gaps else "draft"
    if risk_envelope.intent is RiskIntent.CLINICAL_ACTION:
        status = "blocked_clinician_confirmation"
    limitations = tuple(dict.fromkeys((
        *_LIMITATIONS,
        *(case_packet.limitations if case_packet else ()),
        *(evidence_packet.limitations if evidence_packet else ()),
        *(answer_bundle.limitations if answer_bundle else ()),
    )))
    card = DecisionCard(
        card_id="",
        question=question,
        case_packet_id=case_packet.packet_id if case_packet else None,
        evidence_packet_id=evidence_packet.packet_id if evidence_packet else None,
        answer_bundle_id=answer_bundle.bundle_id if answer_bundle else None,
        risk_envelope=risk_envelope,
        status=status,
        options=resolved_options,
        claims=claims,
        case_observations=observations,
        case_statements=statements,
        reviewed_evidence_claims=reviewed_claims,
        evidence_items=evidence_items,
        missing_context=tuple(DecisionContextGap(category) for category in contexts),
        research_gaps=tuple(gaps),
        limitations=limitations,
        audit=report,
    )
    identity = to_dict(card)
    identity.pop("card_id")
    if identity["audit"] is not None:
        identity["audit"].pop("audited_at")
    digest = hashlib.sha256(json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")).hexdigest()
    card = replace(card, card_id="decision_" + digest[:24])
    gate.assert_bounded_payload(to_dict(card))
    return card
