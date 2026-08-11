import json
from pathlib import Path

import jsonschema
import pytest

from health_analyzer.contracts import (
    AnswerBundle,
    Claim,
    EvidenceItem,
    EvidencePacket,
    RiskEnvelope,
    RiskIntent,
    SearchLogEntry,
    StatementKind,
    VerificationStatus,
    to_dict,
)
from health_analyzer.serialization import answer_bundle_from, evidence_packet_from


ROOT = Path(__file__).parents[1]


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text())


def _evidence(*, risk_envelope: RiskEnvelope | None = None) -> EvidencePacket:
    kwargs = {
        "risk_envelope": risk_envelope
        or RiskEnvelope(intent=RiskIntent.EDUCATION)
    }
    return EvidencePacket(
        packet_id="evidence_" + "a" * 20,
        question="Synthetic question",
        items=(
            EvidenceItem(
                evidence_id="pmid:1",
                title="Synthetic evidence",
                source_type="journal_article",
                url="https://pubmed.ncbi.nlm.nih.gov/1/",
            ),
        ),
        search_log=(
            SearchLogEntry(
                run_id="run_" + "b" * 20,
                source="synthetic",
                query_id="query-risk-contract",
                executed_at="2026-01-01T00:00:00+00:00",
                query={"question": "Synthetic question"},
                result_ids=("pmid:1",),
            ),
        ),
        **kwargs,
    )


def _answer(*, risk_envelope: RiskEnvelope | None = None) -> AnswerBundle:
    kwargs = {
        "risk_envelope": risk_envelope
        or RiskEnvelope(intent=RiskIntent.EDUCATION)
    }
    return AnswerBundle(
        bundle_id="answer-risk-contract",
        question="Synthetic question",
        claims=(
            Claim(
                claim_id="claim-risk-contract",
                text="Synthetic reviewed output claim",
                kind=StatementKind.EXTERNAL_EVIDENCE,
                support_ids=("evclaim_" + "c" * 32,),
                certainty="moderate",
                status=VerificationStatus.VERIFIED,
            ),
        ),
        **kwargs,
    )


@pytest.mark.parametrize(
    "intent",
    tuple(intent for intent in RiskIntent if intent is not RiskIntent.LEGACY_UNSPECIFIED),
)
def test_risk_envelope_supports_each_declared_intent(intent: RiskIntent) -> None:
    envelope = RiskEnvelope(
        intent=intent,
        clinician_confirmation_required=intent is RiskIntent.CLINICAL_ACTION,
    )

    assert envelope.intent is intent


def test_clinical_action_requires_explicit_clinician_confirmation() -> None:
    with pytest.raises(ValueError, match="true only for clinical_action"):
        RiskEnvelope(intent=RiskIntent.CLINICAL_ACTION)


def test_new_risk_envelope_round_trips_through_contract_decoders() -> None:
    envelope = RiskEnvelope(
        intent=RiskIntent.CLINICAL_ACTION,
        clinician_confirmation_required=True,
    )

    evidence = evidence_packet_from(to_dict(_evidence(risk_envelope=envelope)))
    answer = answer_bundle_from(to_dict(_answer(risk_envelope=envelope)))

    assert evidence.risk_envelope == envelope
    assert answer.risk_envelope == envelope


def test_legacy_payloads_without_risk_envelope_are_unspecified() -> None:
    legacy_evidence = to_dict(_evidence())
    legacy_answer = to_dict(_answer())
    legacy_evidence["schema_version"] = "1.2"
    legacy_answer["schema_version"] = "1.0"
    legacy_evidence.pop("risk_envelope")
    legacy_answer.pop("risk_envelope")

    evidence = evidence_packet_from(legacy_evidence)
    answer = answer_bundle_from(legacy_answer)

    assert evidence.risk_envelope == RiskEnvelope()
    assert answer.risk_envelope == RiskEnvelope()
    assert evidence.risk_envelope.intent is RiskIntent.LEGACY_UNSPECIFIED
    assert answer.risk_envelope.intent is RiskIntent.LEGACY_UNSPECIFIED


def test_current_contract_decoders_reject_missing_risk_envelope() -> None:
    evidence = to_dict(_evidence())
    answer = to_dict(_answer())
    evidence.pop("risk_envelope")
    answer.pop("risk_envelope")

    with pytest.raises(ValueError, match="1.3.*risk_envelope"):
        evidence_packet_from(evidence)
    with pytest.raises(ValueError, match="1.1.*risk_envelope"):
        answer_bundle_from(answer)


@pytest.mark.parametrize(
    "schema_name,payload",
    (
        ("evidence-packet.schema.json", to_dict(_evidence())),
        ("answer-bundle.schema.json", to_dict(_answer())),
    ),
)
def test_published_schemas_require_explicit_risk_envelope(
    schema_name: str,
    payload: dict,
) -> None:
    payload.pop("risk_envelope")

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, _schema(schema_name))


@pytest.mark.parametrize(
    "schema_name,payload",
    (
        ("evidence-packet.schema.json", to_dict(_evidence())),
        ("answer-bundle.schema.json", to_dict(_answer())),
    ),
)
def test_published_schemas_reject_confirmation_flag_for_nonclinical_intent(
    schema_name: str,
    payload: dict,
) -> None:
    payload["risk_envelope"] = {
        "intent": "education",
        "clinician_confirmation_required": True,
    }

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, _schema(schema_name))


@pytest.mark.parametrize(
    "schema_name,payload",
    (
        ("evidence-packet.schema.json", to_dict(_evidence())),
        ("answer-bundle.schema.json", to_dict(_answer())),
    ),
)
def test_published_schemas_reject_unconfirmed_clinical_action(
    schema_name: str,
    payload: dict,
) -> None:
    payload["risk_envelope"] = {
        "intent": "clinical_action",
        "clinician_confirmation_required": False,
    }

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, _schema(schema_name))
