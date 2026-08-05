from dataclasses import replace

import pytest

from health_analyzer.cards.patient import build_patient_card
from health_analyzer.contracts import StatementKind, VerificationStatus, to_dict
from health_analyzer.packets import build_case_packet, case_packet_content_id


def synthetic_case():
    provenance = {"source_id": "synthetic-card-source", "sha256": "a" * 64, "page": 2}
    subject = "subj_" + "1" * 32
    return build_case_packet(
        subject_id=subject,
        created_at="2026-09-14T00:00:00+00:00",
        limitations=["Synthetic packet: not medical information."],
        records=[
            {"record_type": "observation", "payload": {
                "observation_id": "obs-synthetic", "subject_id": subject,
                "display": "Synthetic marker", "raw_value": "< 2,5",
                "original_unit": "µmol/L", "comparator": "<",
                "normalized_value": "2.5", "ucum_unit": "umol/L",
                "observed_at": "2026-08-01", "method": "Synthetic method",
                "reference_intervals": [{"low": "1", "high": "3", "unit": "µmol/L"}],
                "notes": ["Synthetic measurement limitation"],
                "verification": "verified", "provenance": [provenance],
            }},
            *({"record_type": "statement", "payload": {
                "statement_id": f"stmt-{kind}", "subject_id": subject,
                "kind": kind, "text": "Synthetic record", "verification": "verified",
                "provenance": [provenance],
                "support_ids": ["obs-synthetic"] if kind == "calculated" else [],
            }} for kind in ("source_fact", "user_note", "calculated")),
        ],
    )


def test_patient_card_is_deterministic_lossless_and_packet_scoped():
    packet = synthetic_case()
    card = build_patient_card(packet)
    assert card == build_patient_card(packet)
    assert card.case_packet_id == packet.packet_id
    assert card.observations == packet.observations
    assert card.statements == packet.statements
    assert card.observations[0].observed_at != card.packet_created_at
    assert card.record_count == 4
    assert card.source_count == 1
    assert card.scope == "selected_case_packet"
    assert card.archive_completeness == "unknown"
    assert card.review_required is True
    assert set(s.kind for s in card.statements) == {
        StatementKind.SOURCE_FACT, StatementKind.USER_NOTE, StatementKind.CALCULATED,
    }
    assert all(context.status == "unknown" for context in card.contexts)
    assert packet.limitations[0] in card.limitations
    payload = to_dict(card)
    assert payload["observations"][0]["raw_value"] == "< 2,5"
    assert payload["observations"][0]["original_unit"] == "µmol/L"
    assert payload["observations"][0]["provenance"][0]["page"] == 2


def test_context_binding_never_asserts_absence_or_clinical_readiness():
    card = build_patient_card(synthetic_case(), context_bindings={
        "allergies": ["stmt-user_note"], "goals": [],
    })
    contexts = {item.category: item for item in card.contexts}
    assert contexts["allergies"].status == "records_available_in_packet"
    assert contexts["goals"].status == "unknown"


@pytest.mark.parametrize("bindings", [
    [], {"other": []}, {"allergies": "none"}, {"allergies": ["missing"]},
    {"allergies": ["stmt-user_note", "stmt-user_note"]},
    {"allergies": [None]}, {"allergies": [True]}, {"allergies": None},
])
def test_patient_context_rejects_malformed_or_unbound_data(bindings):
    with pytest.raises(ValueError):
        build_patient_card(synthetic_case(), context_bindings=bindings)


def test_patient_card_rejects_unverified_and_content_tampered_packets():
    packet = synthetic_case()
    with pytest.raises(ValueError, match="content"):
        build_patient_card(replace(packet, limitations=("Tampered",)))
    bad = replace(packet, observations=(replace(
        packet.observations[0], verification=VerificationStatus.EXTRACTED,
    ),))
    with pytest.raises(ValueError, match="verified"):
        build_patient_card(replace(bad, packet_id=case_packet_content_id(bad)))


def test_patient_card_does_not_relabel_inference_as_source_fact():
    packet = synthetic_case()
    bad = replace(packet, statements=(replace(packet.statements[0], kind=StatementKind.INFERENCE),))
    bad = replace(bad, packet_id=case_packet_content_id(bad))
    with pytest.raises(ValueError, match="exact-kind"):
        build_patient_card(bad)


def test_patient_context_hard_cap_never_returns_partial_card():
    with pytest.raises(ValueError, match="at most 100"):
        build_patient_card(synthetic_case(), context_bindings={"medications": ["obs-synthetic"] * 101})


def test_patient_source_count_is_origins_not_unique_file_hashes():
    packet = synthetic_case()
    changed_source = replace(packet.statements[0].provenance[0], source_id="second-synthetic-origin")
    packet = replace(packet, statements=(
        replace(packet.statements[0], provenance=(changed_source,)), *packet.statements[1:],
    ))
    packet = replace(packet, packet_id=case_packet_content_id(packet))
    assert len(packet.source_hashes) == 1
    assert build_patient_card(packet).source_count == 2


def test_patient_never_fills_unknown_observation_date_with_packet_timestamp():
    packet = synthetic_case()
    packet = replace(packet, observations=(replace(packet.observations[0], observed_at=None),))
    packet = replace(packet, packet_id=case_packet_content_id(packet))
    assert build_patient_card(packet).observations[0].observed_at is None
