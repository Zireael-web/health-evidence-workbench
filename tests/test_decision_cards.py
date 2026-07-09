"""Synthetic, offline decision-card contract and traceability checks."""

from dataclasses import replace

import pytest

from health_analyzer.cards.decision import (
    DecisionContext,
    DecisionOptionDraft,
    build_decision_card,
    decision_contexts_from,
    decision_option_drafts_from,
)
from health_analyzer.contracts import (
    AnswerBundle,
    Claim,
    EvidenceItem,
    EvidencePacket,
    ProvenanceLocator,
    ReviewedEvidenceClaim,
    RiskEnvelope,
    RiskIntent,
    SearchLogEntry,
    StatementKind,
    VerificationStatus,
    evidence_item_snapshot_sha256,
    to_dict,
)
from health_analyzer.packets import build_case_packet


QUESTION = "Compare synthetic options for a synthetic outcome"
RISK = RiskEnvelope(intent=RiskIntent.PERSONAL_CONTEXT)
PUBLIC_SUPPORT = "evclaim_" + "b" * 32


def _inputs(*, risk=RISK, status=VerificationStatus.NEEDS_REVIEW):
    subject_id = "subj_" + "1" * 32
    case = build_case_packet(
        subject_id=subject_id,
        created_at="2026-08-07T09:30:00+05:00",
        records=[{
            "record_type": "observation",
            "payload": {
                "observation_id": "obs-synthetic",
                "subject_id": subject_id,
                "display": "Synthetic marker",
                "raw_value": "10",
                "original_unit": "synthetic units",
                "verification": "verified",
                "provenance": [{
                    "source_id": "source-synthetic",
                    "sha256": "a" * 64,
                    "page": 1,
                }],
            },
        }],
        limitations=["Synthetic case limitation"],
    )
    item = EvidenceItem(
        evidence_id="synthetic-evidence",
        title="Synthetic trial",
        source_type="randomized_trial",
        url="https://example.org/synthetic",
        limitations=("Synthetic source limitation",),
    )
    evidence = EvidencePacket(
        packet_id="evidence_" + "1" * 24,
        question=QUESTION,
        items=(item,),
        reviewed_claims=(ReviewedEvidenceClaim(
            claim_id=PUBLIC_SUPPORT,
            question=QUESTION,
            source_kind="retrieval_item",
            source_evidence_id=item.evidence_id,
            source_snapshot_sha256=evidence_item_snapshot_sha256(item),
            statement_kind=StatementKind.EXTERNAL_EVIDENCE,
            claim_type="effect",
            text="Synthetic reviewed effect text",
            effect="Synthetic between-group effect",
            population="Synthetic study population",
            provenance=ProvenanceLocator(
                source_id=item.evidence_id,
                sha256="b" * 64,
                locator="Synthetic results section",
                excerpt="Synthetic exact source excerpt",
            ),
            review_receipt_id="eclaim_rcpt_" + "c" * 32,
            reviewed_at="2026-08-07T10:00:00+00:00",
            reviewer_id="synthetic-reviewer",
            limitations=("Synthetic claim limitation",),
        ),),
        search_log=(SearchLogEntry(
            run_id="synthetic-run",
            source="synthetic",
            query_id="synthetic-query",
            executed_at="2026-08-07T10:00:00+00:00",
            query={"question": QUESTION},
            result_ids=(item.evidence_id,),
        ),),
        risk_envelope=risk,
        limitations=("Synthetic evidence limitation",),
    )
    answer = AnswerBundle(
        bundle_id="synthetic-answer",
        question=QUESTION,
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=risk,
        claims=(Claim(
            claim_id="synthetic-inference",
            text="Synthetic application requiring review",
            kind=StatementKind.INFERENCE,
            support_ids=("obs-synthetic", PUBLIC_SUPPORT),
            certainty="low",
            caveats=("Synthetic inference caveat",),
            status=status,
        ),),
        limitations=("Synthetic answer limitation",),
    )
    options = (DecisionOptionDraft(
        option_id="option-1",
        label_claim_id="synthetic-inference",
        benefit_claim_ids=("synthetic-inference",),
    ),)
    return {
        "question": QUESTION,
        "risk_envelope": risk,
        "case_packet": case,
        "evidence_packet": evidence,
        "answer_bundle": answer,
        "options": options,
    }


def test_supported_option_preserves_exact_claims_and_support_provenance():
    inputs = _inputs()
    card = build_decision_card(**inputs)
    assert card.status == "draft"
    assert card.claims == inputs["answer_bundle"].claims
    assert card.case_observations == inputs["case_packet"].observations
    assert card.reviewed_evidence_claims == inputs["evidence_packet"].reviewed_claims
    assert card.evidence_items == inputs["evidence_packet"].items
    assert card.case_statements == ()
    assert card.audit.structural_traceability_passed is True
    assert card.audit.passed is False
    assert card.review_required is True
    assert card.clinical_approval_obtained is False
    assert card.options[0].status == "draft"
    assert "Synthetic case limitation" in card.limitations
    assert "Synthetic answer limitation" in card.limitations
    assert to_dict(card)["claims"][0]["kind"] == "inference"


def test_passing_audit_does_not_approve_or_select_any_option():
    card = build_decision_card(**_inputs(status=VerificationStatus.VERIFIED))
    assert card.audit.passed is True
    assert card.status == "draft"
    assert card.clinical_approval_obtained is False
    assert card.review_required is True
    assert "preferred_option_id" not in to_dict(card)
    assert all(option.status == "draft" for option in card.options)


def test_clinical_action_stays_blocked_with_structurally_valid_verified_claims():
    risk = RiskEnvelope(
        intent=RiskIntent.CLINICAL_ACTION,
        clinician_confirmation_required=True,
    )
    card = build_decision_card(**_inputs(risk=risk, status=VerificationStatus.VERIFIED))
    assert card.status == "blocked_clinician_confirmation"
    assert card.risk_envelope == risk
    assert card.audit.structural_traceability_passed is True
    assert card.audit.passed is False
    assert {issue.code for issue in card.audit.issues} == {"clinician_confirmation_not_obtained"}
    assert card.clinical_approval_obtained is False


def test_clinical_action_planning_placeholder_is_also_blocked():
    card = build_decision_card(
        question=QUESTION,
        risk_envelope=RiskEnvelope(
            intent=RiskIntent.CLINICAL_ACTION,
            clinician_confirmation_required=True,
        ),
    )
    assert card.status == "blocked_clinician_confirmation"
    assert card.audit is None
    assert card.research_gaps


def test_empty_planning_input_requests_research_without_conclusions():
    card = build_decision_card(question=QUESTION, risk_envelope=RISK)
    assert card.status == "research_needed"
    assert card.claims == card.options == card.reviewed_evidence_claims == ()
    assert card.audit is None
    assert card.research_gaps
    assert card.answer_bundle_id is None


def test_metadata_only_evidence_without_answer_stays_research_needed():
    inputs = _inputs()
    inputs["evidence_packet"] = replace(inputs["evidence_packet"], reviewed_claims=())
    inputs["answer_bundle"] = None
    inputs["options"] = ()
    card = build_decision_card(**inputs)
    assert card.status == "research_needed"
    assert card.claims == ()
    assert card.evidence_items == ()
    assert any("Source-reviewed evidence" in gap for gap in card.research_gaps)


def test_required_context_never_implies_absence_or_clinical_clearance():
    card = build_decision_card(
        **_inputs(),
        required_context=(DecisionContext.MEDICATIONS, DecisionContext.ALLERGIES),
    )
    assert [gap.category for gap in card.missing_context] == ["medications", "allergies"]
    assert all(gap.status == "not_assessed" for gap in card.missing_context)
    assert card.clinical_approval_obtained is False


@pytest.mark.parametrize("change,expected", [
    ({"support_ids": ("synthetic-evidence",)}, "metadata_only_support"),
    ({"support_ids": ("missing-support",)}, "unknown_support"),
    ({"support_ids": ("obs-synthetic",)}, "missing_inference_support"),
    ({"kind": StatementKind.SOURCE_FACT}, "mixed_support_requires_inference"),
    ({"status": VerificationStatus.REJECTED}, "rejected_claim"),
    ({"conflicts_with": ("missing-claim",)}, "invalid_conflict_reference"),
])
def test_invalid_answer_claims_fail_closed_even_when_options_omit_them(change, expected):
    inputs = _inputs()
    answer = inputs["answer_bundle"]
    inputs["answer_bundle"] = replace(answer, claims=(replace(answer.claims[0], **change),))
    inputs["options"] = ()
    with pytest.raises(ValueError, match=expected):
        build_decision_card(**inputs)


@pytest.mark.parametrize("field,value,expected", [
    ("case_packet_id", None, "case_packet_mismatch"),
    ("evidence_packet_id", None, "evidence_packet_mismatch"),
    ("review_required", False, "review_not_required"),
    ("claims", (), "claims must not be empty"),
    ("created_at", "invalid", "ISO 8601"),
])
def test_answer_bundle_boundary_remains_strict(field, value, expected):
    inputs = _inputs()
    inputs["answer_bundle"] = replace(inputs["answer_bundle"], **{field: value})
    with pytest.raises(ValueError, match=expected):
        build_decision_card(**inputs)


def test_option_refs_require_exact_answer_claim_ids_not_support_ids():
    inputs = _inputs()
    inputs["options"] = (DecisionOptionDraft(option_id="option-1", benefit_claim_ids=(PUBLIC_SUPPORT,)),)
    with pytest.raises(ValueError, match="absent from AnswerBundle"):
        build_decision_card(**inputs)


def test_alternatives_remain_claim_mappings_in_drafts():
    inputs = _inputs(status=VerificationStatus.VERIFIED)
    inputs["options"] = (DecisionOptionDraft(
        option_id="option-1",
        alternative_claim_ids=("synthetic-inference",),
    ),)
    card = build_decision_card(**inputs)
    assert card.options[0].alternative_claim_ids == ("synthetic-inference",)
    assert card.options[0].status == "draft"
    assert card.clinical_approval_obtained is False


def test_guideline_native_grade_and_exact_source_locator_survive_card_projection():
    inputs = _inputs(status=VerificationStatus.VERIFIED)
    evidence = inputs["evidence_packet"]
    item = replace(
        evidence.items[0],
        source_type="clinical_guideline",
        content_hash="d" * 64,
        source_grade="Synthetic original source grade",
    )
    reviewed = replace(
        evidence.reviewed_claims[0],
        source_kind="guideline_recommendation",
        statement_kind=StatementKind.GUIDELINE_RECOMMENDATION,
        claim_type="recommendation",
        source_snapshot_sha256=evidence_item_snapshot_sha256(item),
        native_grade_system="Synthetic native grading system",
        native_grade="Synthetic native grade",
        provenance=replace(evidence.reviewed_claims[0].provenance, sha256=item.content_hash),
    )
    inputs["evidence_packet"] = replace(evidence, items=(item,), reviewed_claims=(reviewed,))
    card = build_decision_card(**inputs)
    assert card.reviewed_evidence_claims == (reviewed,)
    assert card.reviewed_evidence_claims[0].native_grade == "Synthetic native grade"
    assert card.reviewed_evidence_claims[0].provenance.locator == "Synthetic results section"
    assert card.evidence_items[0].source_grade == "Synthetic original source grade"
    assert card.status == "draft"


def test_case_backed_claim_kind_cannot_be_relabelled_to_pass_audit():
    inputs = _inputs()
    answer = inputs["answer_bundle"]
    inputs["answer_bundle"] = replace(answer, claims=(replace(
        answer.claims[0],
        kind=StatementKind.USER_NOTE,
        support_ids=("obs-synthetic",),
    ),))
    with pytest.raises(ValueError, match="case_support_kind_mismatch"):
        build_decision_card(**inputs)


def _with_case_statement(inputs, *, kind, use_statement):
    original_case = inputs["case_packet"]
    case = build_case_packet(
        subject_id=original_case.subject_id,
        created_at=original_case.created_at,
        records=[
            {"record_type": "observation", "payload": to_dict(original_case.observations[0])},
            {"record_type": "statement", "payload": {
                "statement_id": "statement-synthetic",
                "subject_id": original_case.subject_id,
                "kind": kind.value,
                "text": "Synthetic case statement",
                "support_ids": ["synthetic-upstream"],
                "verification": "verified",
                "provenance": [{
                    "source_id": "source-synthetic",
                    "sha256": "a" * 64,
                    "page": 1,
                }],
            }},
        ],
    )
    answer = inputs["answer_bundle"]
    claim = answer.claims[0]
    if use_statement:
        claim = replace(claim, support_ids=("statement-synthetic", PUBLIC_SUPPORT))
    return {
        **inputs,
        "case_packet": case,
        "answer_bundle": replace(answer, case_packet_id=case.packet_id, claims=(claim,)),
    }


@pytest.mark.parametrize("kind", [
    StatementKind.EXTERNAL_EVIDENCE,
    StatementKind.GUIDELINE_RECOMMENDATION,
    StatementKind.INFERENCE,
])
@pytest.mark.parametrize("use_statement", [True, False])
def test_non_case_statement_kinds_fail_closed_even_when_unused(kind, use_statement):
    inputs = _with_case_statement(
        _inputs(status=VerificationStatus.VERIFIED),
        kind=kind,
        use_statement=use_statement,
    )
    with pytest.raises(ValueError, match="only exact-kind case records"):
        build_decision_card(**inputs)


@pytest.mark.parametrize("kind", [
    StatementKind.SOURCE_FACT, StatementKind.USER_NOTE, StatementKind.CALCULATED,
])
def test_valid_case_statement_kinds_remain_distinct_in_inference_support(kind):
    inputs = _with_case_statement(
        _inputs(status=VerificationStatus.VERIFIED), kind=kind, use_statement=True
    )
    card = build_decision_card(**inputs)
    assert card.status == "draft"
    assert card.audit.passed is True
    assert card.case_statements[0].kind is kind
    assert card.case_statements == inputs["case_packet"].statements


def test_case_projection_detaches_nested_mutable_statement_references():
    inputs = _with_case_statement(
        _inputs(), kind=StatementKind.USER_NOTE, use_statement=True
    )
    case = inputs["case_packet"]
    original_statement = case.statements[0]
    mutable_support = list(original_statement.support_ids)
    inputs["case_packet"] = replace(case, statements=(
        replace(original_statement, support_ids=mutable_support),
    ))
    card = build_decision_card(**inputs)
    mutable_support.append("later-caller-mutation")
    assert card.case_statements[0].support_ids == ("synthetic-upstream",)
    assert card.case_statements[0] is not inputs["case_packet"].statements[0]


def test_unverified_or_tampered_case_packet_fails_closed():
    inputs = _inputs()
    case = inputs["case_packet"]
    inputs["case_packet"] = replace(case, observations=(
        replace(case.observations[0], verification=VerificationStatus.EXTRACTED),
    ))
    with pytest.raises(ValueError, match="must be verified"):
        build_decision_card(**inputs)
    inputs["case_packet"] = replace(case, observations=(
        replace(case.observations[0], raw_value="11"),
    ))
    with pytest.raises(ValueError, match="canonical content"):
        build_decision_card(**inputs)


@pytest.mark.parametrize("changed", ["question", "risk_envelope"])
def test_planning_question_and_risk_must_exactly_match_packet_and_answer(changed):
    inputs = _inputs()
    inputs[changed] = "Different synthetic question" if changed == "question" else RiskEnvelope(intent=RiskIntent.EDUCATION)
    with pytest.raises(ValueError, match="does not match EvidencePacket"):
        build_decision_card(**inputs)
    inputs = _inputs()
    inputs["answer_bundle"] = replace(
        inputs["answer_bundle"],
        **{changed: "Different synthetic question" if changed == "question" else RiskEnvelope(intent=RiskIntent.EDUCATION)},
    )
    with pytest.raises(ValueError, match="does not match AnswerBundle"):
        build_decision_card(**inputs)


def test_missing_mapping_and_public_support_are_explicit_research_gaps():
    inputs = _inputs()
    inputs["options"] = ()
    assert build_decision_card(**inputs).status == "research_needed"
    inputs["options"] = (DecisionOptionDraft(option_id="option-1"),)
    card = build_decision_card(**inputs)
    assert card.status == "research_needed"
    assert any("do not yet reference" in gap for gap in card.research_gaps)


@pytest.mark.parametrize("option", [
    {"option_id": "option-1", "benefit": "Unsupported text"},
    {"option_id": "option-1", "label": "Unsupported label"},
    {"option_id": "option-1", "status": "approved"},
    {"option_id": "option-1", "benefit_claim_ids": "claim-1"},
    {"option_id": "option-1", "benefit_claim_ids": ["claim-1", "claim-1"]},
    {"option_id": "option-1", "label_claim_id": ""},
    {"option_id": "../unsafe"},
    {"label_claim_id": "claim-1"},
])
def test_option_parser_rejects_prose_invalid_fields_and_malformed_references(option):
    with pytest.raises(ValueError):
        decision_option_drafts_from([option])


def test_option_parser_freezes_lists_and_rejects_global_caps_without_truncation():
    source = [{"option_id": "option-1", "benefit_claim_ids": ["claim-1"]}]
    parsed = decision_option_drafts_from(source)
    source[0]["benefit_claim_ids"].append("claim-2")
    assert parsed[0].benefit_claim_ids == ("claim-1",)
    with pytest.raises(ValueError, match="at most 10"):
        decision_option_drafts_from([{"option_id": f"option-{index}"} for index in range(11)])
    with pytest.raises(ValueError, match="unique option_id"):
        decision_option_drafts_from([{"option_id": "option-1"}, {"option_id": "option-1"}])
    refs = [f"claim-{index}" for index in range(51)]
    with pytest.raises(ValueError, match="at most 100"):
        decision_option_drafts_from([
            {"option_id": "option-1", "benefit_claim_ids": refs},
            {"option_id": "option-2", "harm_claim_ids": refs},
        ])


@pytest.mark.parametrize("value", ["medications", ["unsupported"], ["allergies", "allergies"], [{"medications": "none"}]])
def test_context_parser_never_accepts_freeform_or_duplicate_context(value):
    with pytest.raises(ValueError):
        decision_contexts_from(value)


def test_direct_api_bounds_are_fail_closed():
    with pytest.raises(ValueError, match="explicit risk"):
        build_decision_card(question=QUESTION, risk_envelope=RiskEnvelope())
    for question in ("", "x" * 4001, "question\0"):
        with pytest.raises(ValueError, match="question"):
            build_decision_card(question=question, risk_envelope=RISK)
    inputs = _inputs()
    inputs["options"] = tuple(DecisionOptionDraft(option_id=f"option-{index}") for index in range(11))
    with pytest.raises(ValueError, match="at most 10"):
        build_decision_card(**inputs)
    inputs = _inputs()
    answer = inputs["answer_bundle"]
    inputs["answer_bundle"] = replace(answer, claims=tuple(
        replace(answer.claims[0], claim_id=f"claim-{index}") for index in range(101)
    ))
    with pytest.raises(ValueError, match="at most 100"):
        build_decision_card(**inputs)


def test_card_identity_is_stable_but_binds_option_mapping_and_required_context():
    inputs = _inputs()
    first = build_decision_card(**inputs)
    assert first.card_id == build_decision_card(**inputs).card_id
    second = build_decision_card(**inputs, required_context=(DecisionContext.MEDICATIONS,))
    inputs["options"] = (replace(inputs["options"][0], harm_claim_ids=("synthetic-inference",)),)
    third = build_decision_card(**inputs)
    assert len({first.card_id, second.card_id, third.card_id}) == 3
