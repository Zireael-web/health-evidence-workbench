"""Deterministic routing across public, private, and offline trust zones."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .contracts import RiskEnvelope, TrustZone


class QuestionClass(StrEnum):
    GENERAL_SCIENCE = "general_science"
    GUIDELINE = "guideline"
    SOURCE_REVIEW = "source_review"
    DOCUMENT_INGEST = "document_ingest"
    PERSONAL_INTERPRETATION = "personal_interpretation"
    ANSWER_AUDIT = "answer_audit"


class RouteSubstage(StrEnum):
    PRIVATE_INGEST = "private_ingest"
    DEIDENTIFICATION_HANDOFF = "deidentification_handoff"
    METADATA_DISCOVERY = "metadata_discovery"
    SOURCE_REVIEW = "source_review"
    CLAIM_ISSUANCE = "claim_issuance"
    OFFLINE_SYNTHESIS = "offline_synthesis"
    COMPLETE_BUNDLE_AUDIT = "complete_bundle_audit"
    PUBLIC_AUDIT = "public_audit"
    REVIEW_EXPORT = "review_export"


SUBSTAGE_CONTRACTS: dict[RouteSubstage, tuple[TrustZone, str | None]] = {
    RouteSubstage.PRIVATE_INGEST: (
        TrustZone.PRIVATE_INGEST,
        "ingest-health-document",
    ),
    RouteSubstage.DEIDENTIFICATION_HANDOFF: (
        TrustZone.OFFLINE_SYNTHESIS,
        "route-science-question",
    ),
    RouteSubstage.METADATA_DISCOVERY: (
        TrustZone.PUBLIC_RESEARCH,
        "retrieve-scientific-evidence",
    ),
    RouteSubstage.SOURCE_REVIEW: (
        TrustZone.SOURCE_REVIEW,
        "inspect-public-source",
    ),
    RouteSubstage.CLAIM_ISSUANCE: (
        TrustZone.PUBLIC_RESEARCH,
        "retrieve-scientific-evidence",
    ),
    RouteSubstage.OFFLINE_SYNTHESIS: (
        TrustZone.OFFLINE_SYNTHESIS,
        "synthesize-personal-context",
    ),
    RouteSubstage.COMPLETE_BUNDLE_AUDIT: (
        TrustZone.OFFLINE_SYNTHESIS,
        "audit-medical-answer",
    ),
    RouteSubstage.PUBLIC_AUDIT: (
        TrustZone.AUDIT,
        "audit-medical-answer",
    ),
    RouteSubstage.REVIEW_EXPORT: (TrustZone.REVIEW_EXPORT, None),
}


@dataclass(frozen=True, slots=True)
class RouteStage:
    order: int
    zone: TrustZone
    substage: RouteSubstage
    action: str
    next_skill: str | None
    network_allowed: bool
    private_vault_allowed: bool
    fresh_task_required: bool = False


@dataclass(frozen=True, slots=True)
class RoutePlan:
    question_class: QuestionClass
    stages: tuple[RouteStage, ...]
    risk_envelope: RiskEnvelope
    invariant: str = (
        "No process may have private-vault and public-network access simultaneously."
    )


def route_question(
    *,
    question_class: QuestionClass | str,
    has_private_context: bool,
    needs_external_evidence: bool,
    risk_envelope: RiskEnvelope,
) -> RoutePlan:
    kind = QuestionClass(question_class)
    if (
        not isinstance(risk_envelope, RiskEnvelope)
        or not risk_envelope.is_explicit
    ):
        raise ValueError("route requires an explicit risk envelope")
    stages: list[RouteStage] = []

    def append_stage(
        *,
        zone: TrustZone,
        substage: RouteSubstage,
        action: str,
        next_skill: str | None,
        network_allowed: bool,
        private_vault_allowed: bool,
        fresh_task_required: bool = False,
    ) -> None:
        stages.append(
            RouteStage(
                order=len(stages) + 1,
                zone=zone,
                substage=substage,
                action=action,
                next_skill=next_skill,
                network_allowed=network_allowed,
                private_vault_allowed=private_vault_allowed,
                fresh_task_required=fresh_task_required,
            )
        )

    private_stage_required = (
        kind is QuestionClass.DOCUMENT_INGEST or has_private_context
    )
    external_evidence_required = needs_external_evidence or kind in {
        QuestionClass.GENERAL_SCIENCE,
        QuestionClass.GUIDELINE,
    }

    if private_stage_required:
        append_stage(
            zone=TrustZone.PRIVATE_INGEST,
            substage=RouteSubstage.PRIVATE_INGEST,
            action="extract and verify a minimal CasePacket",
            next_skill="ingest-health-document",
            network_allowed=False,
            private_vault_allowed=True,
        )

    public_access_required = (
        external_evidence_required or kind is QuestionClass.SOURCE_REVIEW
    )
    if private_stage_required and public_access_required:
        append_stage(
            zone=TrustZone.OFFLINE_SYNTHESIS,
            substage=RouteSubstage.DEIDENTIFICATION_HANDOFF,
            action=(
                "derive and manually verify the minimum deidentified public "
                "question before opening a fresh public task"
            ),
            next_skill="route-science-question",
            network_allowed=False,
            private_vault_allowed=False,
        )

    if kind is QuestionClass.SOURCE_REVIEW:
        append_stage(
            zone=TrustZone.SOURCE_REVIEW,
            substage=RouteSubstage.SOURCE_REVIEW,
            action=(
                "inspect official or primary source content in a fresh "
                "deidentified task"
            ),
            next_skill="inspect-public-source",
            network_allowed=True,
            private_vault_allowed=False,
            fresh_task_required=True,
        )
    elif external_evidence_required:
        append_stage(
            zone=TrustZone.PUBLIC_RESEARCH,
            substage=RouteSubstage.METADATA_DISCOVERY,
            action="retrieve deidentified bibliographic metadata and receipts",
            next_skill="retrieve-scientific-evidence",
            network_allowed=True,
            private_vault_allowed=False,
        )
        append_stage(
            zone=TrustZone.SOURCE_REVIEW,
            substage=RouteSubstage.SOURCE_REVIEW,
            action=(
                "inspect official or primary source content in a fresh "
                "deidentified task"
            ),
            next_skill="inspect-public-source",
            network_allowed=True,
            private_vault_allowed=False,
            fresh_task_required=True,
        )
        append_stage(
            zone=TrustZone.PUBLIC_RESEARCH,
            substage=RouteSubstage.CLAIM_ISSUANCE,
            action=(
                "register and exactly confirm source claims before issuing "
                "an EvidencePacket"
            ),
            next_skill="retrieve-scientific-evidence",
            network_allowed=True,
            private_vault_allowed=False,
        )

    needs_offline_synthesis = (
        private_stage_required
        and (
            external_evidence_required
            or kind is QuestionClass.PERSONAL_INTERPRETATION
        )
    )
    if needs_offline_synthesis:
        append_stage(
            zone=TrustZone.OFFLINE_SYNTHESIS,
            substage=RouteSubstage.OFFLINE_SYNTHESIS,
            action="join verified packets and build a claim ledger",
            next_skill="synthesize-personal-context",
            network_allowed=False,
            private_vault_allowed=False,
        )

    if kind is QuestionClass.ANSWER_AUDIT:
        if has_private_context:
            append_stage(
                zone=TrustZone.OFFLINE_SYNTHESIS,
                substage=RouteSubstage.COMPLETE_BUNDLE_AUDIT,
                action=(
                    "audit a complete bundle against issued case and evidence "
                    "packets"
                ),
                next_skill="audit-medical-answer",
                network_allowed=False,
                private_vault_allowed=False,
            )
        else:
            append_stage(
                zone=TrustZone.AUDIT,
                substage=RouteSubstage.PUBLIC_AUDIT,
                action="audit public claims against an issued EvidencePacket",
                next_skill="audit-medical-answer",
                network_allowed=False,
                private_vault_allowed=False,
            )

    if kind is QuestionClass.ANSWER_AUDIT or has_private_context:
        append_stage(
            zone=TrustZone.REVIEW_EXPORT,
            substage=RouteSubstage.REVIEW_EXPORT,
            action="perform explicit operator review before export",
            next_skill=None,
            network_allowed=False,
            private_vault_allowed=False,
        )

    if not stages:
        append_stage(
            zone=TrustZone.OFFLINE_SYNTHESIS,
            substage=RouteSubstage.OFFLINE_SYNTHESIS,
            action="answer from already supplied public evidence",
            next_skill="synthesize-personal-context",
            network_allowed=False,
            private_vault_allowed=False,
        )
    plan = RoutePlan(
        question_class=kind,
        stages=tuple(stages),
        risk_envelope=risk_envelope,
    )
    validate_route(plan)
    return plan


def validate_route(plan: RoutePlan) -> None:
    if (
        not isinstance(plan.risk_envelope, RiskEnvelope)
        or not plan.risk_envelope.is_explicit
    ):
        raise ValueError("route requires an explicit risk envelope")
    expected_capabilities = {
        TrustZone.PRIVATE_INGEST: (False, True),
        TrustZone.PUBLIC_RESEARCH: (True, False),
        TrustZone.SOURCE_REVIEW: (True, False),
        TrustZone.OFFLINE_SYNTHESIS: (False, False),
        TrustZone.AUDIT: (False, False),
        TrustZone.REVIEW_EXPORT: (False, False),
    }
    for expected_order, stage in enumerate(plan.stages, start=1):
        if stage.order != expected_order:
            raise ValueError("route stage order is not contiguous")
        expected_zone, expected_skill = SUBSTAGE_CONTRACTS[stage.substage]
        if stage.zone is not expected_zone or stage.next_skill != expected_skill:
            raise ValueError(
                "route substage does not match its required trust zone and skill"
            )
        if stage.network_allowed and stage.private_vault_allowed:
            raise ValueError(
                "a route stage cannot combine network and private-vault access"
            )
        expected = expected_capabilities[stage.zone]
        actual = (stage.network_allowed, stage.private_vault_allowed)
        if actual != expected:
            raise ValueError("route stage capabilities do not match its trust zone")
        if stage.zone is TrustZone.SOURCE_REVIEW:
            if not stage.fresh_task_required:
                raise ValueError("source review requires a fresh deidentified task")
            if stage.next_skill != "inspect-public-source":
                raise ValueError("source review requires inspect-public-source")
        elif stage.fresh_task_required:
            raise ValueError("fresh_task_required is reserved for source review")

    claim_issuance_positions = [
        index
        for index, stage in enumerate(plan.stages)
        if stage.substage is RouteSubstage.CLAIM_ISSUANCE
    ]
    for index in claim_issuance_positions:
        if not any(
            stage.substage is RouteSubstage.SOURCE_REVIEW
            for stage in plan.stages[:index]
        ):
            raise ValueError("claim issuance requires a preceding source-review stage")

    private_positions = [
        index
        for index, stage in enumerate(plan.stages)
        if stage.zone is TrustZone.PRIVATE_INGEST
    ]
    public_positions = [
        index
        for index, stage in enumerate(plan.stages)
        if stage.zone in {TrustZone.PUBLIC_RESEARCH, TrustZone.SOURCE_REVIEW}
    ]
    if private_positions and public_positions:
        last_private = max(private_positions)
        first_public = min(public_positions)
        if first_public < last_private or not any(
            stage.substage is RouteSubstage.DEIDENTIFICATION_HANDOFF
            for stage in plan.stages[last_private + 1 : first_public]
        ):
            raise ValueError(
                "private-to-public routing requires a deidentification handoff"
            )

    if any(stage.zone is TrustZone.AUDIT for stage in plan.stages) and any(
        stage.zone is TrustZone.PRIVATE_INGEST for stage in plan.stages
    ):
        raise ValueError("the public audit zone cannot follow private ingestion")

    review_positions = [
        index
        for index, stage in enumerate(plan.stages)
        if stage.zone is TrustZone.REVIEW_EXPORT
    ]
    if review_positions and review_positions != [len(plan.stages) - 1]:
        raise ValueError("review_export must be the final route stage")
