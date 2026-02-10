"""Deterministic fictional cards for UI/testing; never reads a patient archive."""

from ..contracts import (
    AnswerBundle, Claim, EvidenceItem, EvidencePacket, ProvenanceLocator,
    ReviewedEvidenceClaim, RiskEnvelope, RiskIntent, SearchLogEntry,
    StatementKind, VerificationStatus, evidence_item_snapshot_sha256, to_dict,
)
from ..packets import build_case_packet
from .decision import DecisionContext, DecisionOptionDraft, build_decision_card
from .patient import build_patient_card


DEMO_NOTICE = "ДЕМОНСТРАЦИЯ: все записи, исследования и варианты вымышлены. Не медицинская рекомендация."
_TIMESTAMP = "2026-09-14T00:00:00+00:00"


def demo_packets():
    """Test-only-looking content is generated here, not issued as real evidence."""
    subject = "subj_" + "0" * 32
    provenance = {"source_id": "synthetic-source", "sha256": "a" * 64, "page": 1}
    case = build_case_packet(
        subject_id=subject, created_at=_TIMESTAMP, limitations=[DEMO_NOTICE],
        records=[
            {"record_type": "observation", "payload": {
                "observation_id": "demo-observation", "subject_id": subject,
                "display": "Вымышленный показатель", "raw_value": "12,4",
                "original_unit": "условных единиц", "observed_at": "2026-08-01",
                "reference_intervals": [{"low": "10", "high": "20", "unit": "условных единиц"}],
                "provenance": [provenance], "verification": "verified",
                "notes": ["Диапазон вымышленный, медицинская интерпретация отсутствует."],
            }},
            {"record_type": "statement", "payload": {
                "statement_id": "demo-goal", "subject_id": subject, "kind": "user_note",
                "text": "Хочу сравнить два вымышленных варианта по пользе и рискам.",
                "provenance": [provenance], "verification": "verified",
            }},
        ],
    )
    question = "Как сравнить вымышленные варианты A и B?"
    risk = RiskEnvelope(intent=RiskIntent.CLINICAL_ACTION, clinician_confirmation_required=True)
    item = EvidenceItem(
        evidence_id="synthetic-study", title="Вымышленный источник для проверки интерфейса",
        source_type="journal_article", url="https://example.invalid/synthetic-study",
        retrieved_at=_TIMESTAMP, study_design="Synthetic demonstration",
        population="Вымышленная популяция", limitations=(DEMO_NOTICE,),
    )
    source_texts = (
        "Вымышленный вариант A: в учебном примере сообщён эффект, но применимость не проверена.",
        "Вымышленный вариант B: в учебном примере данные о пользе и рисках ограничены.",
    )
    reviewed = tuple(ReviewedEvidenceClaim(
        claim_id="evclaim_" + str(index) * 32, question=question,
        source_kind="retrieval_item", source_evidence_id=item.evidence_id,
        source_snapshot_sha256=evidence_item_snapshot_sha256(item),
        statement_kind=StatementKind.EXTERNAL_EVIDENCE, claim_type="finding", text=text,
        provenance=ProvenanceLocator(source_id=item.evidence_id, sha256="b" * 64,
                                     locator=f"Synthetic section {index}", excerpt=text),
        review_receipt_id="eclaim_rcpt_" + str(index) * 32,
        reviewed_at=_TIMESTAMP, reviewer_id="synthetic-reviewer", limitations=(DEMO_NOTICE,),
    ) for index, text in enumerate(source_texts, start=1))
    evidence = EvidencePacket(
        packet_id="evidence_" + "0" * 24, question=question, items=(item,),
        reviewed_claims=reviewed, retrieved_at=_TIMESTAMP, risk_envelope=risk,
        limitations=(DEMO_NOTICE,),
        search_log=(SearchLogEntry(run_id="synthetic-run", source="synthetic",
            query_id="synthetic-query", executed_at=_TIMESTAMP,
            query={"question": question}, result_ids=(item.evidence_id,)),),
    )
    return case, evidence


def demo_card(card_type: str = "patient") -> dict:
    case, evidence = demo_packets()
    if card_type == "patient":
        return to_dict(build_patient_card(case, context_bindings={"goals": ["demo-goal"]}))
    if card_type != "decision":
        raise ValueError("card_type must be patient or decision")
    claims = tuple(Claim(
        claim_id=f"demo-claim-{index}", text=claim.text,
        kind=StatementKind.EXTERNAL_EVIDENCE, support_ids=(claim.claim_id,),
        certainty="low", status=VerificationStatus.NEEDS_REVIEW, caveats=(DEMO_NOTICE,),
    ) for index, claim in enumerate(evidence.reviewed_claims, start=1))
    bundle = AnswerBundle(
        bundle_id="synthetic-answer", question=evidence.question, claims=claims,
        case_packet_id=case.packet_id, evidence_packet_id=evidence.packet_id,
        created_at=_TIMESTAMP, risk_envelope=evidence.risk_envelope,
        limitations=(DEMO_NOTICE,),
    )
    card = to_dict(build_decision_card(
        question=evidence.question, risk_envelope=evidence.risk_envelope,
        case_packet=case, evidence_packet=evidence, answer_bundle=bundle,
        options=(
            DecisionOptionDraft(option_id="option-a", label_claim_id="demo-claim-1",
                                benefit_claim_ids=("demo-claim-1",)),
            DecisionOptionDraft(option_id="option-b", label_claim_id="demo-claim-2",
                                uncertainty_claim_ids=("demo-claim-2",)),
        ),
        required_context=(DecisionContext.ALLERGIES, DecisionContext.MEDICATIONS,
                          DecisionContext.GOALS, DecisionContext.PREVIOUS_TREATMENTS),
    ))
    # Only this fictional preview uses a fixed audit time. Real audit reports
    # retain their actual timestamp; the card identity excludes audited_at.
    card["audit"]["audited_at"] = _TIMESTAMP
    return card
