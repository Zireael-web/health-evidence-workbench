"""Lossless normalized laboratory observation models."""

from __future__ import annotations

from dataclasses import dataclass
import json

from health_analyzer.contracts import validate_observed_at
from health_analyzer.vault import ProvenanceLocator

from .terminology import LoincMapping
from .thresholds import IntervalRelation, Threshold
from .units import NormalizedQuantity


@dataclass(frozen=True, slots=True)
class LabObservationInput:
    subject_id: str
    display: str
    raw_value: str
    original_unit: str
    provenance: tuple[ProvenanceLocator, ...]
    specimen: str | None = None
    method: str | None = None
    observed_at: str | None = None
    observed_at_raw: str | None = None
    thresholds: tuple[Threshold, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "provenance", tuple(self.provenance))
        object.__setattr__(self, "thresholds", tuple(self.thresholds))
        if not self.provenance:
            raise ValueError("at least one provenance locator is required")
        for name in ("subject_id", "display", "raw_value", "original_unit"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or "\0" in value:
                raise ValueError(f"{name} must be non-empty text without NUL")
        for name in ("specimen", "method", "observed_at_raw"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str) or not value.strip() or "\0" in value
            ):
                raise ValueError(f"{name} must be non-empty text without NUL or null")
        validate_observed_at(self.observed_at)
        if self.observed_at is not None and self.observed_at_raw is None:
            object.__setattr__(self, "observed_at_raw", self.observed_at)
        provenance_keys = {
            json.dumps(
                locator.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
            )
            for locator in self.provenance
        }
        if len(provenance_keys) != len(self.provenance):
            raise ValueError("provenance locators must be unique")


@dataclass(frozen=True, slots=True)
class NormalizedLabObservation:
    observation_id: str
    subject_id: str
    display: str
    quantity: NormalizedQuantity
    specimen: str | None
    method: str | None
    observed_at: str | None
    observed_at_raw: str | None
    loinc_mappings: tuple[LoincMapping, ...]
    thresholds: tuple[Threshold, ...]
    laboratory_reference_relation: IntervalRelation
    provenance: tuple[ProvenanceLocator, ...]
