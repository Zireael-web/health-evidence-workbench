"""Synthetic cases that are ingestible but unsafe to coerce for display."""

from dataclasses import replace

import pytest

from health_analyzer.cards.decision import build_decision_card
from health_analyzer.cards.patient import build_patient_card
from health_analyzer.cards.validation import validated_case_snapshot
from health_analyzer.contracts import RiskEnvelope, RiskIntent, StatementKind, to_dict
from health_analyzer.packets import build_case_packet, validate_case_packet


_UNSET = object()
_OBSERVATION_OPTIONAL_FIELDS = (
    "original_unit", "code_system", "code", "normalized_value", "ucum_unit",
    "comparator", "specimen", "method", "device",
)
_INTERVAL_FIELDS = ("low", "high", "unit", "comparator", "population", "label")


def _case(*, observation=None, interval=None, notes=_UNSET, statement=None):
    subject = "subj_" + "3" * 32
    provenance = {
        "source_id": "source-synthetic-card-validation", "sha256": "d" * 64, "page": 1,
    }
    interval_payload = {
        "low": "-0.50", "high": "3,0", "unit": "µmol/L", "comparator": "<=",
        "population": "Synthetic population", "label": "Synthetic reference",
        **(interval or {}),
    }
    observation_payload = {
        "observation_id": "observation-synthetic", "subject_id": subject,
        "display": "Synthetic marker", "raw_value": "< 2,5", "original_unit": "µmol/L",
        "code_system": "Synthetic code system", "code": "Synthetic code",
        "normalized_value": "2.5", "ucum_unit": "umol/L", "comparator": "<",
        "specimen": "Synthetic specimen", "method": "Synthetic method",
        "device": "Synthetic device", "observed_at": "2026-08-07",
        "reference_intervals": [interval_payload],
        "notes": ["Synthetic source note"] if notes is _UNSET else notes,
        "provenance": [provenance], "verification": "verified",
        **(observation or {}),
    }
    statement_payload = {
        "statement_id": "statement-synthetic", "subject_id": subject,
        "kind": "calculated", "text": "Synthetic calculated text",
        "support_ids": ["observation-synthetic"], "certainty": "Synthetic original certainty",
        "provenance": [provenance], "verification": "verified", **(statement or {}),
    }
    return build_case_packet(
        subject_id=subject,
        created_at="2026-09-14T00:00:00+00:00",
        records=[
            {"record_type": "observation", "payload": observation_payload},
            {"record_type": "statement", "payload": statement_payload},
        ],
    )


def _decision(case):
    return build_decision_card(
        question="Synthetic planning question",
        risk_envelope=RiskEnvelope(intent=RiskIntent.PERSONAL_CONTEXT),
        case_packet=case,
    )


_BUILDERS = (validated_case_snapshot, build_patient_card, _decision)


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize("field", _OBSERVATION_OPTIONAL_FIELDS)
@pytest.mark.parametrize("value", [True, False, 7])
def test_ingestible_observation_scalar_mismatch_rejected_by_both_cards(builder, field, value):
    case = _case(observation={field: value})
    # Reproduce the real upstream gap: this is normally built and canonical.
    validate_case_packet(case)
    with pytest.raises(ValueError, match=f"Observation.{field}"):
        builder(case)


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize("field", _INTERVAL_FIELDS)
@pytest.mark.parametrize("value", [True, False, 7])
def test_ingestible_reference_interval_scalar_mismatch_rejected(builder, field, value):
    case = _case(interval={field: value})
    validate_case_packet(case)
    with pytest.raises(ValueError, match=f"ReferenceInterval.{field}"):
        builder(case)


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize("notes", [[True], [3], ["Synthetic note", False], [True, 3]])
def test_ingestible_nontext_source_notes_are_never_formatted_as_yes_no(builder, notes):
    case = _case(notes=notes)
    validate_case_packet(case)
    with pytest.raises(ValueError, match="Observation.notes"):
        builder(case)


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize("value", [True, 7, ["Synthetic certainty"]])
def test_ingestible_nontext_statement_certainty_is_rejected(builder, value):
    case = _case(statement={"certainty": value})
    validate_case_packet(case)
    with pytest.raises(ValueError, match="Statement.certainty"):
        builder(case)


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize("value", [[True], [7], ["observation-synthetic", False], [""]])
def test_ingestible_invalid_statement_support_ids_are_rejected(builder, value):
    case = _case(statement={"support_ids": value})
    validate_case_packet(case)
    with pytest.raises(ValueError, match="Statement.support_ids"):
        builder(case)


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize("kind", [
    StatementKind.EXTERNAL_EVIDENCE,
    StatementKind.GUIDELINE_RECOMMENDATION,
    StatementKind.INFERENCE,
])
def test_shared_snapshot_rejects_non_case_kinds_even_for_planning_without_answer(builder, kind):
    case = _case(statement={"kind": kind.value})
    validate_case_packet(case)
    with pytest.raises(ValueError, match="exact-kind"):
        builder(case)


@pytest.mark.parametrize("kind", [
    StatementKind.SOURCE_FACT, StatementKind.USER_NOTE, StatementKind.CALCULATED,
])
def test_snapshot_is_detached_lossless_and_preserves_valid_statement_kind(kind):
    case = _case(statement={"kind": kind.value})
    snapshot = validated_case_snapshot(case)
    assert to_dict(snapshot) == to_dict(case)
    assert snapshot is not case
    assert snapshot.observations[0] is not case.observations[0]
    assert snapshot.observations[0].reference_intervals[0] is not case.observations[0].reference_intervals[0]
    assert snapshot.statements[0].kind is kind
    assert snapshot.observations[0].raw_value == "< 2,5"
    assert snapshot.observations[0].reference_intervals[0].low == "-0.50"


def test_snapshot_preserves_unknown_optional_text_and_verbatim_empty_strings():
    case = _case(
        observation={field: None for field in _OBSERVATION_OPTIONAL_FIELDS},
        interval={field: None for field in _INTERVAL_FIELDS if field != "label"},
        notes=["", "  "],
        statement={"certainty": None},
    )
    snapshot = validated_case_snapshot(case)
    assert to_dict(snapshot) == to_dict(case)
    assert snapshot.observations[0].original_unit is None
    assert snapshot.observations[0].notes == ("", "  ")
    assert snapshot.statements[0].certainty is None


@pytest.mark.parametrize("builder", _BUILDERS)
def test_reference_interval_label_is_required_text_not_null(builder):
    case = _case(interval={"label": None})
    validate_case_packet(case)
    with pytest.raises(ValueError, match="ReferenceInterval.label"):
        builder(case)


def test_snapshot_rejects_nul_in_previously_unchecked_optional_text():
    case = _case(observation={"original_unit": "synthetic\0unit"})
    validate_case_packet(case)
    with pytest.raises(ValueError, match="Observation.original_unit"):
        validated_case_snapshot(case)


def test_snapshot_detaches_caller_owned_mutable_statement_references():
    case = _case()
    support_ids = list(case.statements[0].support_ids)
    case = replace(case, statements=(replace(case.statements[0], support_ids=support_ids),))
    snapshot = validated_case_snapshot(case)
    support_ids.append("subsequent-caller-change")
    assert snapshot.statements[0].support_ids == ("observation-synthetic",)


def test_snapshot_does_not_repair_tampered_canonical_packet():
    case = _case()
    changed = replace(case, observations=(replace(case.observations[0], raw_value="11"),))
    with pytest.raises(ValueError, match="canonical content"):
        validated_case_snapshot(changed)
