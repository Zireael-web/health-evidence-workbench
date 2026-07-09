from dataclasses import replace

import pytest

from health_analyzer.claims import ClaimLedger, audit_answer
from health_analyzer.contracts import (
    AnswerBundle,
    CasePacket,
    Claim,
    EvidenceItem,
    EvidencePacket,
    Observation,
    ProvenanceLocator,
    ReviewedEvidenceClaim,
    RiskEnvelope,
    RiskIntent,
    SearchLogEntry,
    Statement,
    StatementKind,
    VerificationStatus,
    evidence_item_snapshot_sha256,
)
from health_analyzer.serialization import answer_bundle_from


PERSONAL_CONTEXT_RISK = RiskEnvelope(intent=RiskIntent.PERSONAL_CONTEXT)


def packets() -> tuple[CasePacket, EvidencePacket]:
    case = CasePacket(
        packet_id="case-1",
        subject_id="subj-test",
        observations=(
            Observation(
                observation_id="obs-1",
                subject_id="subj-test",
                display="Synthetic marker",
                raw_value="10",
                verification=VerificationStatus.VERIFIED,
            ),
        ),
    )
    evidence_item = EvidenceItem(
        evidence_id="pmid:1",
        title="Synthetic trial",
        source_type="randomized_trial",
        url="https://pubmed.ncbi.nlm.nih.gov/1/",
    )
    evidence = EvidencePacket(
        packet_id="evp-1",
        question="Synthetic question",
        items=(evidence_item,),
        reviewed_claims=(
            ReviewedEvidenceClaim(
                claim_id="evclaim_" + "b" * 32,
                question="Synthetic question",
                source_kind="retrieval_item",
                source_evidence_id="pmid:1",
                source_snapshot_sha256=evidence_item_snapshot_sha256(evidence_item),
                statement_kind=StatementKind.EXTERNAL_EVIDENCE,
                claim_type="finding",
                text="Synthetic reviewed finding",
                provenance=ProvenanceLocator(
                    source_id="pmid:1",
                    sha256="b" * 64,
                    locator="Results section",
                    excerpt="Synthetic reviewed source excerpt",
                ),
                review_receipt_id="eclaim_rcpt_" + "c" * 32,
                reviewed_at="2026-01-01T00:00:00+00:00",
                reviewer_id="reviewer-test",
            ),
        ),
        search_log=(
            SearchLogEntry(
                run_id="run_" + "1" * 20,
                source="synthetic",
                query_id="query-1",
                executed_at="2026-01-01T00:00:00+00:00",
                query={"question": "Synthetic question"},
                result_ids=("pmid:1",),
            ),
        ),
        risk_envelope=PERSONAL_CONTEXT_RISK,
    )
    return case, evidence


def test_evidence_packet_rejects_review_claim_bound_to_another_snapshot() -> None:
    _, evidence = packets()
    with pytest.raises(ValueError, match="source snapshot"):
        EvidencePacket(
            packet_id="evidence_" + "0" * 20,
            question=evidence.question,
            items=evidence.items,
            reviewed_claims=(
                replace(
                    evidence.reviewed_claims[0],
                    source_snapshot_sha256="0" * 64,
                ),
            ),
            search_log=evidence.search_log,
            risk_envelope=evidence.risk_envelope,
        )


def test_audit_rejects_inference_without_case_and_evidence_support() -> None:
    case, evidence = packets()
    bundle = AnswerBundle(
        bundle_id="answer-1",
        question=evidence.question,
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-1",
                text="Personal inference",
                kind=StatementKind.INFERENCE,
                support_ids=("obs-1",),
                certainty="high",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )
    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)
    assert not report.passed
    assert report.structural_traceability_passed is False
    assert {issue.code for issue in report.issues} == {"missing_inference_support"}


def test_valid_answer_is_persisted_with_audit(tmp_path) -> None:
    case, evidence = packets()
    bundle = AnswerBundle(
        bundle_id="answer-2",
        question=evidence.question,
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-2",
                text="Moderate personal inference",
                kind=StatementKind.INFERENCE,
                support_ids=("obs-1", "evclaim_" + "b" * 32),
                certainty="moderate",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )
    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)
    assert report.passed
    assert report.structural_traceability_passed is True
    ledger = ClaimLedger(tmp_path / "claims.sqlite3")
    ledger.append(bundle, report)
    assert ledger.latest_audit(bundle.bundle_id)["passed"] is True
    assert (
        ledger.latest_audit(bundle.bundle_id)["structural_traceability_passed"]
        is True
    )


def _supported_bundle(case: CasePacket, evidence: EvidencePacket) -> AnswerBundle:
    return AnswerBundle(
        bundle_id="answer-bound-content",
        question=evidence.question,
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(Claim(
            claim_id="claim-bound-content", text="Synthetic inference",
            kind=StatementKind.INFERENCE,
            support_ids=(case.observations[0].observation_id,
                         evidence.reviewed_claims[0].claim_id),
            certainty="moderate", status=VerificationStatus.VERIFIED,
        ),),
    )


def test_audit_cannot_use_one_colliding_id_as_both_case_and_evidence() -> None:
    case, evidence = packets()
    colliding = evidence.reviewed_claims[0].claim_id
    case = replace(case, observations=(replace(case.observations[0], observation_id=colliding),))
    bundle = _supported_bundle(case, evidence)
    bundle = replace(bundle, claims=(replace(bundle.claims[0], support_ids=(colliding,)),))
    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)
    assert not report.structural_traceability_passed
    assert "ambiguous_support_id" in {issue.code for issue in report.issues}


def test_audit_rejects_cross_subject_support_in_direct_python_api() -> None:
    case, evidence = packets()
    case = replace(case, observations=(replace(case.observations[0], subject_id="another-subject"),))
    report = audit_answer(_supported_bundle(case, evidence), case_packet=case, evidence_packet=evidence)
    assert not report.structural_traceability_passed
    assert "case_subject_mismatch" in {issue.code for issue in report.issues}


@pytest.mark.parametrize("change,code", [
    ({"claim_id": ""}, "invalid_claim_id"),
    ({"kind": "unsupported"}, "invalid_claim_kind"),
])
def test_audit_rejects_invalid_direct_claim_contract(change, code) -> None:
    case, evidence = packets()
    bundle = _supported_bundle(case, evidence)
    bundle = replace(bundle, claims=(replace(bundle.claims[0], **change),))
    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)
    assert not report.structural_traceability_passed
    assert code in {issue.code for issue in report.issues}


def test_claim_ledger_rejects_changed_content_with_same_bundle_id(tmp_path) -> None:
    case, evidence = packets()
    bundle = _supported_bundle(case, evidence)
    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)
    assert report.passed
    changed = replace(bundle, claims=(replace(bundle.claims[0], text="A different conclusion"),))
    ledger = ClaimLedger(tmp_path / "claims.sqlite3")
    with pytest.raises(ValueError, match="exact answer bundle content"):
        ledger.append(changed, report)
    assert ledger.latest_audit(bundle.bundle_id) is None
    ledger.append(bundle, report)
    assert ledger.latest_audit(bundle.bundle_id)["bundle_sha256"] == report.bundle_sha256


@pytest.mark.parametrize(
    "status",
    (VerificationStatus.EXTRACTED, VerificationStatus.NEEDS_REVIEW),
)
def test_structurally_traceable_unverified_output_cannot_pass_final_audit(
    status: VerificationStatus,
) -> None:
    case, evidence = packets()
    bundle = AnswerBundle(
        bundle_id=f"answer-unverified-output-{status.value}",
        question=evidence.question,
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id=f"claim-unverified-output-{status.value}",
                text="Structurally traceable inference awaiting output review",
                kind=StatementKind.INFERENCE,
                support_ids=("obs-1", "evclaim_" + "b" * 32),
                certainty="moderate",
                status=status,
            ),
        ),
    )

    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)

    assert report.passed is False
    assert report.structural_traceability_passed is True
    assert {issue.code for issue in report.issues} == {
        "unverified_output_claim"
    }


def test_audit_requires_same_risk_envelope_across_evidence_and_answer() -> None:
    case, evidence = packets()
    evidence = replace(
        evidence,
        risk_envelope=RiskEnvelope(intent=RiskIntent.PERSONAL_CONTEXT),
    )
    bundle = AnswerBundle(
        bundle_id="answer-risk-mismatch",
        question=evidence.question,
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=RiskEnvelope(
            intent=RiskIntent.CLINICAL_ACTION,
            clinician_confirmation_required=True,
        ),
        claims=(
            Claim(
                claim_id="claim-risk-mismatch",
                text="Synthetic personal action draft",
                kind=StatementKind.INFERENCE,
                support_ids=("obs-1", "evclaim_" + "b" * 32),
                certainty="moderate",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)

    assert report.passed is False
    assert report.structural_traceability_passed is False
    assert {issue.code for issue in report.issues} == {
        "risk_envelope_mismatch",
        "clinician_confirmation_not_obtained",
    }


def test_matching_clinical_action_risk_envelope_can_pass_structural_audit() -> None:
    case, evidence = packets()
    clinical_action = RiskEnvelope(
        intent=RiskIntent.CLINICAL_ACTION,
        clinician_confirmation_required=True,
    )
    evidence = replace(evidence, risk_envelope=clinical_action)
    bundle = AnswerBundle(
        bundle_id="answer-clinical-action",
        question=evidence.question,
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=clinical_action,
        claims=(
            Claim(
                claim_id="claim-clinical-action",
                text="Synthetic personal action draft",
                kind=StatementKind.INFERENCE,
                support_ids=("obs-1", "evclaim_" + "b" * 32),
                certainty="moderate",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)

    assert report.passed is False
    assert report.structural_traceability_passed is True
    assert {issue.code for issue in report.issues} == {
        "clinician_confirmation_not_obtained"
    }


def test_caller_authored_legacy_answer_without_risk_cannot_pass_audit() -> None:
    case, _ = packets()
    bundle = AnswerBundle(
        bundle_id="answer-legacy-risk-unspecified",
        question="Synthetic question",
        case_packet_id=case.packet_id,
        schema_version="1.0",
        claims=(
            Claim(
                claim_id="claim-legacy-risk-unspecified",
                text="Synthetic source fact",
                kind=StatementKind.SOURCE_FACT,
                support_ids=("obs-1",),
                certainty="not_applicable",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, case_packet=case)

    assert report.passed is False
    assert report.structural_traceability_passed is False
    assert {issue.code for issue in report.issues} == {
        "answer_risk_unspecified",
        "unsupported_schema",
    }


def test_audit_rejects_cross_question_evidence_replay() -> None:
    _, evidence = packets()
    bundle = AnswerBundle(
        bundle_id="answer-cross-question",
        question="Does an unrelated intervention cure an unrelated condition?",
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-cross-question",
                text="Unrelated substantive claim",
                kind=StatementKind.EXTERNAL_EVIDENCE,
                support_ids=(evidence.reviewed_claims[0].claim_id,),
                certainty="high",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, evidence_packet=evidence)

    assert report.passed is False
    assert "evidence_question_mismatch" in {
        issue.code for issue in report.issues
    }


@pytest.mark.parametrize(
    "claim_kind",
    tuple(kind for kind in StatementKind if kind is not StatementKind.INFERENCE),
)
def test_non_inference_claim_cannot_mix_case_and_evidence_support(
    claim_kind: StatementKind,
) -> None:
    case, evidence = packets()
    bundle = AnswerBundle(
        bundle_id=f"answer-mixed-{claim_kind.value}",
        question=evidence.question,
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id=f"claim-mixed-{claim_kind.value}",
                text="A claim mixing personal and population-level support",
                kind=claim_kind,
                support_ids=("obs-1", evidence.reviewed_claims[0].claim_id),
                certainty="moderate",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)

    assert report.passed is False
    assert "mixed_support_requires_inference" in {
        issue.code for issue in report.issues
    }


def test_bibliographic_metadata_cannot_support_a_substantive_claim() -> None:
    _, evidence = packets()
    bundle = AnswerBundle(
        bundle_id="answer-metadata-only",
        question="Synthetic question",
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-metadata-only",
                text="Unsupported efficacy statement",
                kind=StatementKind.EXTERNAL_EVIDENCE,
                support_ids=("pmid:1",),
                certainty="moderate",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, evidence_packet=evidence)

    assert report.passed is False
    assert "metadata_only_support" in {issue.code for issue in report.issues}


def test_unverified_case_value_cannot_support_personal_claim() -> None:
    case, evidence = packets()
    unverified = CasePacket(
        packet_id="case-unverified",
        subject_id=case.subject_id,
        observations=(
            Observation(
                observation_id="obs-unverified",
                subject_id=case.subject_id,
                display="Synthetic marker",
                raw_value="10",
            ),
        ),
    )
    bundle = AnswerBundle(
        bundle_id="answer-unverified",
        question="Synthetic question",
        case_packet_id=unverified.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-unverified",
                text="Synthetic personal claim",
                kind=StatementKind.SOURCE_FACT,
                support_ids=("obs-unverified",),
                certainty="not_applicable",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )
    report = audit_answer(bundle, case_packet=unverified)
    assert "unverified_case_support" in {issue.code for issue in report.issues}


def test_answer_bundle_decoder_rejects_schema_invalid_contract_values() -> None:
    raw_bundle = {
        "bundle_id": "answer-invalid-contract",
        "question": "Synthetic question",
        "case_packet_id": None,
        "evidence_packet_id": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "review_required": "not-a-boolean",
        "limitations": [],
        "schema_version": "9.9",
        "claims": [
            {
                "claim_id": "claim-invalid-contract",
                "text": "Synthetic claim",
                "kind": "external_evidence",
                "support_ids": ["pmid:1"],
                "certainty": "moderate",
                "conflicts_with": [],
                "caveats": [7],
                "status": "extracted",
            }
        ],
    }

    with pytest.raises(ValueError):
        answer_bundle_from(raw_bundle)


def test_audit_requires_symmetric_packet_id_binding() -> None:
    case, evidence = packets()
    bundle = AnswerBundle(
        bundle_id="answer-missing-packet-bindings",
        question="Synthetic question",
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-missing-packet-bindings",
                text="Synthetic personal inference",
                kind=StatementKind.INFERENCE,
                support_ids=("obs-1", "evclaim_" + "b" * 32),
                certainty="moderate",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)

    assert report.passed is False
    assert {issue.code for issue in report.issues} == {
        "case_packet_mismatch",
        "evidence_packet_mismatch",
    }


def test_audit_does_not_launder_user_note_into_source_fact() -> None:
    case = CasePacket(
        packet_id="case-note",
        subject_id="subj-test",
        statements=(
            Statement(
                statement_id="note-1",
                kind=StatementKind.USER_NOTE,
                text="Synthetic user report",
                subject_id="subj-test",
                verification=VerificationStatus.VERIFIED,
            ),
        ),
    )
    bundle = AnswerBundle(
        bundle_id="answer-note-laundering",
        question="Synthetic question",
        case_packet_id=case.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-note-laundering",
                text="Presented as a source fact",
                kind=StatementKind.SOURCE_FACT,
                support_ids=("note-1",),
                certainty="not_applicable",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, case_packet=case)

    assert report.passed is False
    assert "case_support_kind_mismatch" in {issue.code for issue in report.issues}


def test_audit_requires_guideline_source_for_guideline_recommendation() -> None:
    _, evidence = packets()
    bundle = AnswerBundle(
        bundle_id="answer-guideline-laundering",
        question="Synthetic question",
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-guideline-laundering",
                text="Presented as a guideline recommendation",
                kind=StatementKind.GUIDELINE_RECOMMENDATION,
                support_ids=("evclaim_" + "b" * 32,),
                certainty="moderate",
                status=VerificationStatus.VERIFIED,
            ),
        ),
    )

    report = audit_answer(bundle, evidence_packet=evidence)

    assert report.passed is False
    assert "missing_guideline_support" in {issue.code for issue in report.issues}


def test_audit_rejects_rejected_claim_even_with_valid_support() -> None:
    case, evidence = packets()
    bundle = AnswerBundle(
        bundle_id="answer-rejected-claim",
        question="Synthetic question",
        case_packet_id=case.packet_id,
        evidence_packet_id=evidence.packet_id,
        risk_envelope=PERSONAL_CONTEXT_RISK,
        claims=(
            Claim(
                claim_id="claim-rejected",
                text="Rejected inference",
                kind=StatementKind.INFERENCE,
                support_ids=("obs-1", "evclaim_" + "b" * 32),
                certainty="low",
                status=VerificationStatus.REJECTED,
            ),
        ),
    )

    report = audit_answer(bundle, case_packet=case, evidence_packet=evidence)

    assert report.passed is False
    assert "rejected_claim" in {issue.code for issue in report.issues}
