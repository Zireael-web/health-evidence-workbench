"""Composable laboratory normalization facade."""

from __future__ import annotations

import hashlib
import json

from .models import LabObservationInput, NormalizedLabObservation
from .parsing import parse_numeric
from .terminology import LoincMapper
from .thresholds import laboratory_reference_relation
from .units import CuratedUnitRegistry


class LabNormalizer:
    def __init__(
        self,
        *,
        units: CuratedUnitRegistry | None = None,
        loinc: LoincMapper | None = None,
    ) -> None:
        self.units = units or CuratedUnitRegistry()
        self.loinc = loinc or LoincMapper()

    def normalize(
        self,
        item: LabObservationInput,
        *,
        target_ucum: str | None = None,
    ) -> NormalizedLabObservation:
        parsed = parse_numeric(item.raw_value)
        quantity = self.units.normalize(
            parsed,
            item.original_unit,
            target_ucum=target_ucum,
        )
        source_ucum = self.units.resolve(item.original_unit).ucum_code
        id_material = json.dumps(
            {
                "schema": "lab-observation-source-identity-v2",
                "subject_id": item.subject_id,
                "display": item.display,
                "raw_value": item.raw_value,
                "original_unit": item.original_unit,
                "specimen": item.specimen,
                "method": item.method,
                "observed_at": item.observed_at,
                "observed_at_raw": item.observed_at_raw,
                "provenance": [locator.to_dict() for locator in item.provenance],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        observation_id = (
            "obs_" + hashlib.sha256(id_material.encode("utf-8")).hexdigest()[:32]
        )
        return NormalizedLabObservation(
            observation_id=observation_id,
            subject_id=item.subject_id,
            display=item.display,
            quantity=quantity,
            specimen=item.specimen,
            method=item.method,
            observed_at=item.observed_at,
            observed_at_raw=item.observed_at_raw,
            loinc_mappings=self.loinc.propose(item.display),
            thresholds=item.thresholds,
            laboratory_reference_relation=laboratory_reference_relation(
                parsed,
                item.thresholds,
                unit=source_ucum,
            ),
            provenance=item.provenance,
        )
