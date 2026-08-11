import pytest

from health_analyzer.contracts import RiskEnvelope, RiskIntent, TrustZone
from health_analyzer.routing import (
    QuestionClass,
    RoutePlan,
    RouteStage,
    RouteSubstage,
    route_question,
    validate_route,
)


EDUCATION_RISK = RiskEnvelope(intent=RiskIntent.EDUCATION)


def test_personal_research_uses_physically_separate_stages() -> None:
    plan = route_question(
        question_class=QuestionClass.PERSONAL_INTERPRETATION,
        has_private_context=True,
        needs_external_evidence=True,
        risk_envelope=EDUCATION_RISK,
    )
    validate_route(plan)
    assert [stage.zone for stage in plan.stages] == [
        TrustZone.PRIVATE_INGEST,
        TrustZone.OFFLINE_SYNTHESIS,
        TrustZone.PUBLIC_RESEARCH,
        TrustZone.SOURCE_REVIEW,
        TrustZone.PUBLIC_RESEARCH,
        TrustZone.OFFLINE_SYNTHESIS,
        TrustZone.REVIEW_EXPORT,
    ]
    assert [stage.substage for stage in plan.stages] == [
        RouteSubstage.PRIVATE_INGEST,
        RouteSubstage.DEIDENTIFICATION_HANDOFF,
        RouteSubstage.METADATA_DISCOVERY,
        RouteSubstage.SOURCE_REVIEW,
        RouteSubstage.CLAIM_ISSUANCE,
        RouteSubstage.OFFLINE_SYNTHESIS,
        RouteSubstage.REVIEW_EXPORT,
    ]
    source_review = plan.stages[3]
    assert source_review.next_skill == "inspect-public-source"
    assert source_review.fresh_task_required is True
    assert not any(
        stage.network_allowed and stage.private_vault_allowed
        for stage in plan.stages
    )
    assert plan.risk_envelope == EDUCATION_RISK


def test_route_rejects_legacy_unspecified_risk() -> None:
    with pytest.raises(ValueError, match="explicit risk envelope"):
        route_question(
            question_class=QuestionClass.GENERAL_SCIENCE,
            has_private_context=False,
            needs_external_evidence=True,
            risk_envelope=RiskEnvelope(),
        )


def test_source_review_is_an_explicit_fresh_public_stage() -> None:
    plan = route_question(
        question_class=QuestionClass.SOURCE_REVIEW,
        has_private_context=False,
        needs_external_evidence=False,
        risk_envelope=EDUCATION_RISK,
    )

    assert len(plan.stages) == 1
    assert plan.stages[0].zone is TrustZone.SOURCE_REVIEW
    assert plan.stages[0].substage is RouteSubstage.SOURCE_REVIEW
    assert plan.stages[0].next_skill == "inspect-public-source"
    assert plan.stages[0].fresh_task_required is True


def test_private_source_review_requires_offline_deidentification_handoff() -> None:
    plan = route_question(
        question_class=QuestionClass.SOURCE_REVIEW,
        has_private_context=True,
        needs_external_evidence=False,
        risk_envelope=EDUCATION_RISK,
    )

    assert [stage.substage for stage in plan.stages] == [
        RouteSubstage.PRIVATE_INGEST,
        RouteSubstage.DEIDENTIFICATION_HANDOFF,
        RouteSubstage.SOURCE_REVIEW,
        RouteSubstage.REVIEW_EXPORT,
    ]
    assert plan.stages[2].fresh_task_required is True


def test_public_answer_audit_uses_the_runtime_audit_zone() -> None:
    plan = route_question(
        question_class=QuestionClass.ANSWER_AUDIT,
        has_private_context=False,
        needs_external_evidence=False,
        risk_envelope=EDUCATION_RISK,
    )

    assert [stage.zone for stage in plan.stages] == [
        TrustZone.AUDIT,
        TrustZone.REVIEW_EXPORT,
    ]
    assert plan.stages[0].substage is RouteSubstage.PUBLIC_AUDIT
    assert plan.stages[0].next_skill == "audit-medical-answer"


def test_private_answer_audit_stays_offline() -> None:
    plan = route_question(
        question_class=QuestionClass.ANSWER_AUDIT,
        has_private_context=True,
        needs_external_evidence=False,
        risk_envelope=EDUCATION_RISK,
    )

    assert TrustZone.AUDIT not in {stage.zone for stage in plan.stages}
    assert RouteSubstage.COMPLETE_BUNDLE_AUDIT in {
        stage.substage for stage in plan.stages
    }
    assert not any(stage.network_allowed for stage in plan.stages)


def test_claim_issuance_cannot_precede_source_review() -> None:
    invalid = RoutePlan(
        question_class=QuestionClass.GENERAL_SCIENCE,
        risk_envelope=EDUCATION_RISK,
        stages=(
            RouteStage(
                order=1,
                zone=TrustZone.PUBLIC_RESEARCH,
                substage=RouteSubstage.CLAIM_ISSUANCE,
                action="issue claim",
                next_skill="retrieve-scientific-evidence",
                network_allowed=True,
                private_vault_allowed=False,
            ),
        ),
    )

    with pytest.raises(ValueError, match="preceding source-review"):
        validate_route(invalid)


@pytest.mark.parametrize(
    ("zone", "next_skill"),
    [
        (TrustZone.OFFLINE_SYNTHESIS, "retrieve-scientific-evidence"),
        (TrustZone.PUBLIC_RESEARCH, "inspect-public-source"),
    ],
)
def test_substage_requires_its_declared_zone_and_skill(
    zone: TrustZone,
    next_skill: str,
) -> None:
    invalid = RoutePlan(
        question_class=QuestionClass.GENERAL_SCIENCE,
        risk_envelope=EDUCATION_RISK,
        stages=(
            RouteStage(
                order=1,
                zone=zone,
                substage=RouteSubstage.METADATA_DISCOVERY,
                action="search",
                next_skill=next_skill,
                network_allowed=zone is TrustZone.PUBLIC_RESEARCH,
                private_vault_allowed=False,
            ),
        ),
    )

    with pytest.raises(ValueError, match="required trust zone and skill"):
        validate_route(invalid)


def test_private_to_public_route_requires_deidentification_handoff() -> None:
    invalid = RoutePlan(
        question_class=QuestionClass.GENERAL_SCIENCE,
        risk_envelope=EDUCATION_RISK,
        stages=(
            RouteStage(
                order=1,
                zone=TrustZone.PRIVATE_INGEST,
                substage=RouteSubstage.PRIVATE_INGEST,
                action="ingest",
                next_skill="ingest-health-document",
                network_allowed=False,
                private_vault_allowed=True,
            ),
            RouteStage(
                order=2,
                zone=TrustZone.PUBLIC_RESEARCH,
                substage=RouteSubstage.METADATA_DISCOVERY,
                action="search",
                next_skill="retrieve-scientific-evidence",
                network_allowed=True,
                private_vault_allowed=False,
            ),
        ),
    )

    with pytest.raises(ValueError, match="deidentification handoff"):
        validate_route(invalid)
