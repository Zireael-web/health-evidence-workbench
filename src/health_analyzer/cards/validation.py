"""Strict, lossless case snapshots shared by offline card builders."""

from __future__ import annotations

from ..contracts import CasePacket, ReferenceInterval, StatementKind, to_dict
from ..packets import validate_case_packet
from ..privacy import PrivacyGate
from ..serialization import case_packet_from


_OBSERVATION_OPTIONAL_TEXT = (
    "original_unit", "code_system", "code", "normalized_value", "ucum_unit",
    "comparator", "specimen", "method", "device", "observed_at",
)
_INTERVAL_OPTIONAL_TEXT = ("low", "high", "unit", "comparator", "population")
_CASE_KINDS = frozenset((
    StatementKind.SOURCE_FACT, StatementKind.USER_NOTE, StatementKind.CALCULATED,
))


def _string(value: object, *, name: str, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or "\0" in value:
        suffix = " or null" if optional else ""
        raise ValueError(f"{name} must be a string without NUL{suffix}")


def _validate_card_fields(case: CasePacket) -> None:
    """Refuse booleans/numbers before renderers can format them as source text."""

    for observation in case.observations:
        for name in _OBSERVATION_OPTIONAL_TEXT:
            _string(getattr(observation, name), name=f"Observation.{name}", optional=True)
        if not isinstance(observation.notes, tuple):
            raise ValueError("Observation.notes must be a tuple of strings")
        for note in observation.notes:
            _string(note, name="Observation.notes item")
        if not isinstance(observation.reference_intervals, tuple):
            raise ValueError("Observation.reference_intervals must be a tuple")
        for interval in observation.reference_intervals:
            if not isinstance(interval, ReferenceInterval):
                raise ValueError("Observation.reference_intervals must contain ReferenceInterval values")
            for name in _INTERVAL_OPTIONAL_TEXT:
                _string(getattr(interval, name), name=f"ReferenceInterval.{name}", optional=True)
            _string(interval.label, name="ReferenceInterval.label")
    for statement in case.statements:
        if statement.kind not in _CASE_KINDS:
            raise ValueError("Cards accept only exact-kind case records")
        _string(statement.text, name="Statement.text")
        _string(statement.certainty, name="Statement.certainty", optional=True)
        # An SDK caller may supply a list inside a frozen Statement. Validate
        # its values first; the snapshot roundtrip below detaches/freezes it.
        if not isinstance(statement.support_ids, (tuple, list)):
            raise ValueError("Statement.support_ids must be an array of strings")
        for support_id in statement.support_ids:
            _string(support_id, name="Statement.support_ids item")
            if not support_id.strip():
                raise ValueError("Statement.support_ids must contain non-empty identifiers")


def validated_case_snapshot(case: CasePacket) -> CasePacket:
    """Return a bounded, detached, strictly typed snapshot without coercion.

    The caller still establishes issuance through a verified handoff loader.
    No units, values, comparators, notes, or source evidence grades are inferred,
    normalized, or repaired here. Malformed fields fail the whole card.
    """

    validate_case_packet(case)
    _validate_card_fields(case)
    gate = PrivacyGate()
    payload = to_dict(case)
    gate.assert_bounded_payload(payload)
    snapshot = case_packet_from(payload)
    validate_case_packet(snapshot)
    _validate_card_fields(snapshot)
    gate.assert_bounded_payload(to_dict(snapshot))
    return snapshot
