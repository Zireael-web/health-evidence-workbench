"""Typed thresholds that cannot be silently collapsed into a reference range."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from .parsing import ParsedNumeric, is_bounded_decimal


class ThresholdKind(StrEnum):
    LAB_REFERENCE_INTERVAL = "laboratory_reference_interval"
    CLINICAL_DECISION_THRESHOLD = "clinical_decision_threshold"
    TREATMENT_TARGET = "treatment_target"
    CRITICAL_THRESHOLD = "critical_threshold"


class IntervalRelation(StrEnum):
    BELOW = "below"
    WITHIN = "within"
    ABOVE = "above"
    INDETERMINATE = "indeterminate"
    NOT_AVAILABLE = "not_available"


@dataclass(frozen=True, slots=True)
class Threshold:
    threshold_id: str
    kind: ThresholdKind
    source_id: str
    unit: str
    low: Decimal | None = None
    high: Decimal | None = None
    low_inclusive: bool = True
    high_inclusive: bool = True
    population: str | None = None
    method: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        for name in ("threshold_id", "source_id", "unit"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or not value.strip()
                or "\0" in value
            ):
                raise ValueError(f"{name} must be non-empty text without NUL")
        if not isinstance(self.kind, ThresholdKind):
            raise ValueError("kind must be a ThresholdKind")
        for name in ("low", "high"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, Decimal) or not is_bounded_decimal(value)
            ):
                raise ValueError(f"{name} must be a finite bounded Decimal or null")
        for name in ("low_inclusive", "high_inclusive"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be boolean")
        for name in ("population", "method", "version"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str)
                or not value.strip()
                or "\0" in value
            ):
                raise ValueError(f"{name} must be non-empty text or null")
        if self.low is None and self.high is None:
            raise ValueError("threshold needs at least one bound")
        if self.low is not None and self.high is not None and self.low > self.high:
            raise ValueError("threshold low must not exceed high")
        if (
            self.low is not None
            and self.high is not None
            and self.low == self.high
            and not (self.low_inclusive and self.high_inclusive)
        ):
            raise ValueError("equal threshold bounds must both be inclusive")


def relation_to_interval(value: ParsedNumeric, interval: Threshold) -> IntervalRelation:
    """Describe relation to one interval without assigning clinical meaning."""

    if value.comparator is not None:
        return IntervalRelation.INDETERMINATE
    if interval.low is not None:
        below = (
            value.value < interval.low
            if interval.low_inclusive
            else value.value <= interval.low
        )
        if below:
            return IntervalRelation.BELOW
    if interval.high is not None:
        above = value.value > interval.high if interval.high_inclusive else value.value >= interval.high
        if above:
            return IntervalRelation.ABOVE
    return IntervalRelation.WITHIN


def laboratory_reference_relation(
    value: ParsedNumeric,
    thresholds: tuple[Threshold, ...],
    *,
    unit: str,
) -> IntervalRelation:
    """Evaluate only the lab's own reference interval.

    Decision limits, targets, and critical policies are deliberately ignored.
    """

    matches = tuple(
        threshold
        for threshold in thresholds
        if threshold.kind is ThresholdKind.LAB_REFERENCE_INTERVAL
        and threshold.unit == unit
    )
    if not matches:
        return IntervalRelation.NOT_AVAILABLE
    if len(matches) != 1:
        return IntervalRelation.INDETERMINATE
    return relation_to_interval(value, matches[0])


def partition_thresholds(
    thresholds: tuple[Threshold, ...],
) -> dict[ThresholdKind, tuple[Threshold, ...]]:
    return {
        kind: tuple(item for item in thresholds if item.kind is kind)
        for kind in ThresholdKind
    }
