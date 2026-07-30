from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from health_analyzer.lab import (
    IntervalRelation,
    LoincAxes,
    LoincCatalogEntry,
    LoincMapper,
    LoincMapping,
    MappingStatus,
    Threshold,
    ThresholdKind,
    laboratory_reference_relation,
    parse_numeric,
    partition_thresholds,
)


def _entry() -> LoincCatalogEntry:
    return LoincCatalogEntry(
        code="2345-7",
        display="Glucose [Mass/volume] in Serum or Plasma",
        version="synthetic-pinned-version",
        axes=LoincAxes(
            component="Glucose",
            property="Mass concentration",
            time="Point in time",
            system="Serum or plasma",
            scale="Quantitative",
        ),
        aliases=("Глюкоза", "Glucose"),
    )


def _mapper() -> LoincMapper:
    return LoincMapper((_entry(),))


def test_loinc_is_candidate_until_all_axes_are_explicitly_verified() -> None:
    mapper = _mapper()
    candidate = mapper.propose("Глюкоза")[0]
    assert candidate.status is MappingStatus.CANDIDATE

    with pytest.raises(ValueError, match="axes not verified"):
        mapper.confirm(candidate, verified_axes={"component", "system"}, reviewer_id="reviewer-1")

    confirmed = mapper.confirm(
        candidate,
        verified_axes={"component", "property", "time", "system", "scale"},
        reviewer_id="reviewer-1",
    )
    assert confirmed.status is MappingStatus.CONFIRMED
    assert confirmed.confirmed_by == "reviewer-1"


def test_loinc_rejects_duplicate_codes_and_candidates_not_bound_to_snapshot() -> None:
    entry = _entry()
    with pytest.raises(ValueError, match="codes must be unique"):
        LoincMapper((entry, replace(entry, display="Conflicting display")))

    mapper = LoincMapper((entry,))
    candidate = mapper.propose("Глюкоза")[0]
    for forged in (
        replace(candidate, display="Wrong display"),
        replace(candidate, matched_alias="Unregistered alias"),
        replace(candidate, entry_sha256="0" * 64),
    ):
        with pytest.raises(ValueError, match="pinned catalog"):
            mapper.confirm(
                forged,
                verified_axes={"component", "property", "time", "system", "scale"},
                reviewer_id="reviewer-1",
            )

    changed_axes = replace(entry.axes, system="Whole blood")
    foreign_candidate = LoincMapper((replace(entry, axes=changed_axes),)).propose(
        "Глюкоза"
    )[0]
    assert isinstance(foreign_candidate, LoincMapping)
    with pytest.raises(ValueError, match="pinned catalog"):
        mapper.confirm(
            foreign_candidate,
            verified_axes={"component", "property", "time", "system", "scale"},
            reviewer_id="reviewer-1",
        )


def test_threshold_kinds_remain_separate() -> None:
    thresholds = (
        Threshold(
            "lab-ri",
            ThresholdKind.LAB_REFERENCE_INTERVAL,
            "source-report",
            "mg/dL",
            low=Decimal("0.5"),
            high=Decimal("1.2"),
        ),
        Threshold(
            "decision",
            ThresholdKind.CLINICAL_DECISION_THRESHOLD,
            "guideline-v1",
            "mg/dL",
            high=Decimal("1.0"),
        ),
        Threshold(
            "target",
            ThresholdKind.TREATMENT_TARGET,
            "guideline-v1",
            "mg/dL",
            high=Decimal("0.9"),
        ),
        Threshold(
            "critical",
            ThresholdKind.CRITICAL_THRESHOLD,
            "local-policy-v1",
            "mg/dL",
            high=Decimal("2.0"),
        ),
    )
    partitioned = partition_thresholds(thresholds)

    assert all(len(partitioned[kind]) == 1 for kind in ThresholdKind)
    assert laboratory_reference_relation(parse_numeric("1,1"), thresholds, unit="mg/dL") is IntervalRelation.WITHIN
    assert laboratory_reference_relation(parse_numeric("1,3"), thresholds, unit="mg/dL") is IntervalRelation.ABOVE
    assert laboratory_reference_relation(parse_numeric("<0,7"), thresholds, unit="mg/dL") is IntervalRelation.INDETERMINATE


@pytest.mark.parametrize(
    "overrides",
    (
        {"threshold_id": ""},
        {"source_id": ""},
        {"unit": ""},
        {"kind": "laboratory_reference_interval"},
        {"low": Decimal("NaN")},
        {"low": Decimal("Infinity")},
        {"low": Decimal("1e1001")},
        {"low": Decimal("9" * 129)},
        {"low": 0},
        {"low_inclusive": 1},
        {
            "low": Decimal("1"),
            "high": Decimal("1"),
            "high_inclusive": False,
        },
    ),
)
def test_threshold_rejects_untyped_non_finite_or_empty_bounds(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "threshold_id": "threshold-1",
        "kind": ThresholdKind.LAB_REFERENCE_INTERVAL,
        "source_id": "source-report",
        "unit": "mg/dL",
        "low": Decimal("0"),
        "high": Decimal("2"),
    }
    values.update(overrides)

    with pytest.raises(ValueError):
        Threshold(**values)  # type: ignore[arg-type]
