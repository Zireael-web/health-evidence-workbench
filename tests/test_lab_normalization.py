from __future__ import annotations

from decimal import Decimal

import pytest

from health_analyzer.lab import (
    IntervalRelation,
    LabNormalizer,
    LabObservationInput,
    LoincAxes,
    LoincCatalogEntry,
    LoincMapper,
    MappingStatus,
    Threshold,
    ThresholdKind,
)
from health_analyzer.vault import ProvenanceLocator


def test_lab_normalizer_keeps_lossless_source_and_provenance() -> None:
    digest = "a" * 64
    provenance = ProvenanceLocator(
        source_id="src_synthetic",
        sha256=digest,
        page=2,
        bbox=(12.0, 30.0, 420.0, 52.0),
        line_start=18,
        line_end=18,
    )
    mapper = LoincMapper(
        (
            LoincCatalogEntry(
                "718-7",
                "Hemoglobin [Mass/volume] in Blood",
                "synthetic-pinned-version",
                LoincAxes(
                    "Hemoglobin",
                    "Mass concentration",
                    "Point in time",
                    "Blood",
                    "Quantitative",
                ),
                ("Гемоглобин",),
            ),
        )
    )
    source_interval = Threshold(
        "ri-1",
        ThresholdKind.LAB_REFERENCE_INTERVAL,
        "src_synthetic",
        "g/dL",
        low=Decimal("13.2"),
        high=Decimal("17.3"),
    )
    item = LabObservationInput(
        subject_id="subj_synthetic",
        display="Гемоглобин",
        raw_value="15,9",
        original_unit="г/дл",
        provenance=(provenance,),
        specimen="whole blood",
        method="automated analyzer",
        observed_at="2026-08-07T09:30:00+05:00",
        thresholds=(source_interval,),
    )

    result = LabNormalizer(loinc=mapper).normalize(item, target_ucum="g/L")

    assert result.quantity.raw_value == "15,9"
    assert result.quantity.original_unit == "г/дл"
    assert result.quantity.normalized_value == Decimal("159.0")
    assert result.loinc_mappings[0].status is MappingStatus.CANDIDATE
    assert result.laboratory_reference_relation is IntervalRelation.WITHIN
    assert result.provenance == (provenance,)
    assert result.observed_at == "2026-08-07T09:30:00+05:00"
    assert result.observed_at_raw == "2026-08-07T09:30:00+05:00"


def test_observation_identity_includes_full_provenance_and_clinical_chronology() -> None:
    first_locator = ProvenanceLocator(
        source_id="src_synthetic",
        sha256="a" * 64,
        page=1,
        line_start=10,
        line_end=10,
    )
    second_locator = ProvenanceLocator(
        source_id="src_synthetic",
        sha256="a" * 64,
        page=2,
        line_start=10,
        line_end=10,
    )
    common = {
        "subject_id": "subj_synthetic",
        "display": "Glucose",
        "raw_value": "5.4",
        "original_unit": "mmol/L",
    }
    first = LabObservationInput(
        **common,
        observed_at="2026-01-01T09:00:00+05:00",
        provenance=(first_locator,),
    )
    different_page = LabObservationInput(
        **common,
        observed_at="2026-01-01T09:00:00+05:00",
        provenance=(second_locator,),
    )
    different_time = LabObservationInput(
        **common,
        observed_at="2026-08-01T09:00:00+05:00",
        provenance=(first_locator,),
    )
    normalizer = LabNormalizer()

    first_result = normalizer.normalize(first)
    same_source_different_target = normalizer.normalize(first, target_ucum="mmol/L")
    page_result = normalizer.normalize(different_page)
    time_result = normalizer.normalize(different_time)

    assert first_result.observation_id == same_source_different_target.observation_id
    assert first_result.observation_id != page_result.observation_id
    assert first_result.observation_id != time_result.observation_id


def test_lab_time_keeps_raw_source_text_separate_from_validated_chronology() -> None:
    provenance = ProvenanceLocator(
        source_id="src_synthetic",
        sha256="a" * 64,
        page=1,
    )
    item = LabObservationInput(
        subject_id="subj_synthetic",
        display="Glucose",
        raw_value="5.4",
        original_unit="mmol/L",
        provenance=(provenance,),
        observed_at="2026-08-07",
        observed_at_raw="07.08.2026 (source date, time not reported)",
    )

    result = LabNormalizer().normalize(item)

    assert result.observed_at == "2026-08-07"
    assert result.observed_at_raw == "07.08.2026 (source date, time not reported)"


@pytest.mark.parametrize(
    "observed_at",
    (
        "yesterday",
        "2026-08-07T09:30:00",
        "2026-02-30",
    ),
)
def test_lab_time_rejects_ambiguous_or_naive_chronology(observed_at: str) -> None:
    provenance = ProvenanceLocator(
        source_id="src_synthetic",
        sha256="a" * 64,
    )

    with pytest.raises(ValueError, match="observed_at"):
        LabObservationInput(
            subject_id="subj_synthetic",
            display="Glucose",
            raw_value="5.4",
            original_unit="mmol/L",
            provenance=(provenance,),
            observed_at=observed_at,
        )
