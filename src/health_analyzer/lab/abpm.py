"""Versioned adequacy checks for ambulatory blood-pressure monitoring."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from datetime import time
import hashlib
import json

from health_analyzer.contracts import StatementKind
from health_analyzer.vault import ProvenanceLocator

from .parsing import is_bounded_decimal


class AdequacyStatus(StrEnum):
    ADEQUATE = "adequate"
    LIMITED = "limited"
    INSUFFICIENT = "insufficient"
    UNKNOWN = "unknown"


class DippingClassification(StrEnum):
    REVERSE_DIPPER = "reverse_dipper"
    NON_DIPPER = "non_dipper"
    DIPPER = "dipper"
    EXTREME_DIPPER = "extreme_dipper"
    INSUFFICIENT_DATA = "insufficient_data"


_DEFAULT_RULE_ID = "esh-abpm-completeness-local-profile-v1"
_DEFAULT_RULE_SOURCE_URL = "https://pubmed.ncbi.nlm.nih.gov/33710173/"
_DEFAULT_RULE_APPLICABILITY = "adult_ambulatory_blood_pressure_monitoring"
_DEFAULT_RULE_PARAMETERS: dict[str, object] = {
    "source_url": _DEFAULT_RULE_SOURCE_URL,
    "applicability": _DEFAULT_RULE_APPLICABILITY,
    "min_valid_percent": Decimal("70"),
    "min_valid_awake": 20,
    "min_valid_asleep": 7,
    "min_duration_hours": Decimal("20"),
    "non_dipper_lower_percent": Decimal("0"),
    "dipper_lower_percent": Decimal("10"),
    "extreme_dipper_lower_percent": Decimal("20"),
}


@dataclass(frozen=True, slots=True)
class SourceAssertion:
    text: str
    kind: StatementKind
    provenance: tuple[ProvenanceLocator, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("source assertion text is required")
        if self.kind not in (StatementKind.SOURCE_FACT, StatementKind.USER_NOTE):
            raise ValueError("ABPM source assertions must be source facts or user notes")
        if not self.provenance:
            raise ValueError("source assertion requires provenance")


@dataclass(frozen=True, slots=True)
class MonitorRemovalEvent:
    local_time: str
    assertion: SourceAssertion
    approximate: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.approximate, bool):
            raise ValueError("approximate must be boolean")
        _parse_clock(self.local_time)

    def parsed_time(self) -> time:
        return _parse_clock(self.local_time)


@dataclass(frozen=True, slots=True)
class ABPMSummary:
    attempts: int | None
    valid_total: int | None
    valid_awake: int | None
    valid_asleep: int | None
    duration_hours: Decimal | None
    awake_mean_systolic: Decimal | None = None
    asleep_mean_systolic: Decimal | None = None
    sleep_start: str | None = None
    sleep_end: str | None = None
    source_conclusion: SourceAssertion | None = None
    removal_event: MonitorRemovalEvent | None = None

    def __post_init__(self) -> None:
        counts = {
            "attempts": self.attempts,
            "valid_total": self.valid_total,
            "valid_awake": self.valid_awake,
            "valid_asleep": self.valid_asleep,
        }
        for name, value in counts.items():
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ValueError(f"{name} must be a non-negative integer or null")
        if (
            self.attempts is not None
            and self.valid_total is not None
            and self.valid_total > self.attempts
        ):
            raise ValueError("valid_total cannot exceed attempts")
        if self.valid_total is not None:
            for name in ("valid_awake", "valid_asleep"):
                value = counts[name]
                if value is not None and value > self.valid_total:
                    raise ValueError(f"{name} cannot exceed valid_total")
            if (
                self.valid_awake is not None
                and self.valid_asleep is not None
                and self.valid_awake + self.valid_asleep > self.valid_total
            ):
                raise ValueError("valid_awake plus valid_asleep cannot exceed valid_total")

        for name in (
            "duration_hours",
            "awake_mean_systolic",
            "asleep_mean_systolic",
        ):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, Decimal)
                or not is_bounded_decimal(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a finite positive Decimal or null")
        if (self.awake_mean_systolic is None) != (
            self.asleep_mean_systolic is None
        ):
            raise ValueError("awake and asleep mean systolic values must be supplied together")
        if (self.sleep_start is None) != (self.sleep_end is None):
            raise ValueError("sleep_start and sleep_end must be supplied together")
        if self.sleep_start is not None and self.sleep_end is not None:
            start = _parse_clock(self.sleep_start)
            end = _parse_clock(self.sleep_end)
            if start == end:
                raise ValueError("sleep_start and sleep_end must define a non-zero interval")


@dataclass(frozen=True, slots=True)
class ABPMAdequacyRule:
    rule_id: str = _DEFAULT_RULE_ID
    source_url: str = _DEFAULT_RULE_SOURCE_URL
    applicability: str = _DEFAULT_RULE_APPLICABILITY
    min_valid_percent: Decimal = Decimal("70")
    min_valid_awake: int = 20
    min_valid_asleep: int = 7
    min_duration_hours: Decimal = Decimal("20")
    non_dipper_lower_percent: Decimal = Decimal("0")
    dipper_lower_percent: Decimal = Decimal("10")
    extreme_dipper_lower_percent: Decimal = Decimal("20")

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id.strip():
            raise ValueError("rule_id is required")
        if (
            not isinstance(self.source_url, str)
            or not self.source_url.startswith("https://")
            or "\0" in self.source_url
        ):
            raise ValueError("source_url must be a non-empty HTTPS URL")
        if (
            not isinstance(self.applicability, str)
            or not self.applicability.strip()
            or "\0" in self.applicability
        ):
            raise ValueError("applicability is required")
        for name in ("min_valid_awake", "min_valid_asleep"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        decimal_fields = (
            "min_valid_percent",
            "min_duration_hours",
            "non_dipper_lower_percent",
            "dipper_lower_percent",
            "extreme_dipper_lower_percent",
        )
        for name in decimal_fields:
            value = getattr(self, name)
            if not isinstance(value, Decimal) or not is_bounded_decimal(value):
                raise ValueError(f"{name} must be a finite bounded Decimal")
        if not (Decimal("0") < self.min_valid_percent <= Decimal("100")):
            raise ValueError("min_valid_percent must be in (0, 100]")
        if self.min_duration_hours <= 0:
            raise ValueError("min_duration_hours must be positive")
        if not (
            self.non_dipper_lower_percent
            < self.dipper_lower_percent
            < self.extreme_dipper_lower_percent
        ):
            raise ValueError("dipping thresholds must be strictly increasing")
        if self.rule_id == _DEFAULT_RULE_ID and any(
            getattr(self, name) != expected
            for name, expected in _DEFAULT_RULE_PARAMETERS.items()
        ):
            raise ValueError(
                "custom ABPM rule parameters require a distinct custom rule_id"
            )

    def snapshot(self) -> dict[str, object]:
        return {
            "schema": "abpm-adequacy-rule-v1",
            "rule_id": self.rule_id,
            "source_url": self.source_url,
            "applicability": self.applicability,
            "min_valid_percent": str(self.min_valid_percent),
            "min_valid_awake": self.min_valid_awake,
            "min_valid_asleep": self.min_valid_asleep,
            "min_duration_hours": str(self.min_duration_hours),
            "non_dipper_lower_percent": str(self.non_dipper_lower_percent),
            "dipper_lower_percent": str(self.dipper_lower_percent),
            "extreme_dipper_lower_percent": str(
                self.extreme_dipper_lower_percent
            ),
        }

    @property
    def rule_sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(
                self.snapshot(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ABPMAssessment:
    rule_id: str
    rule_sha256: str
    rule_source_url: str
    rule_applicability: str
    overall_adequacy: AdequacyStatus
    awake_adequacy: AdequacyStatus
    asleep_adequacy: AdequacyStatus
    valid_percent: Decimal | None
    own_dipping_classification: DippingClassification
    calculated_dipping_percent: Decimal | None
    source_conclusion: SourceAssertion | None
    removal_event: MonitorRemovalEvent | None
    limitations: tuple[str, ...]


def _parse_clock(value: str) -> time:
    if not isinstance(value, str) or len(value) != 5 or value[2] != ":":
        raise ValueError("clock values must use HH:MM")
    hour_text, minute_text = value.split(":", maxsplit=1)
    if not hour_text.isdigit() or not minute_text.isdigit():
        raise ValueError("clock values must use HH:MM")
    return time(hour=int(hour_text), minute=int(minute_text))


def _within_clock_period(candidate: time, start: time, end: time) -> bool:
    if start <= end:
        return start <= candidate <= end
    return candidate >= start or candidate <= end


def assess_abpm(
    summary: ABPMSummary,
    *,
    rule: ABPMAdequacyRule | None = None,
) -> ABPMAssessment:
    rule = rule or ABPMAdequacyRule()
    limitations: list[str] = []

    if summary.attempts is None or summary.valid_total is None or summary.attempts <= 0:
        valid_percent = None
        limitations.append("Valid-measurement percentage is unknown.")
    else:
        valid_percent = Decimal(summary.valid_total) * Decimal("100") / Decimal(summary.attempts)
        if valid_percent < rule.min_valid_percent:
            limitations.append(
                f"Only {valid_percent:.1f}% of attempted measurements were valid; "
                f"the configured minimum is {rule.min_valid_percent}%."
            )

    if summary.valid_awake is None:
        awake = AdequacyStatus.UNKNOWN
        limitations.append("Awake measurement count is unknown.")
    elif summary.valid_awake < rule.min_valid_awake:
        awake = AdequacyStatus.INSUFFICIENT
        limitations.append(
            f"Only {summary.valid_awake} awake measurements; "
            f"the configured minimum is {rule.min_valid_awake}."
        )
    else:
        awake = AdequacyStatus.ADEQUATE

    if summary.valid_asleep is None:
        asleep = AdequacyStatus.UNKNOWN
        limitations.append("Asleep measurement count is unknown.")
    elif summary.valid_asleep < rule.min_valid_asleep:
        asleep = AdequacyStatus.INSUFFICIENT
        limitations.append(
            f"Only {summary.valid_asleep} asleep measurements; "
            f"the configured minimum is {rule.min_valid_asleep}."
        )
    else:
        asleep = AdequacyStatus.ADEQUATE

    removal_compromises_sleep = summary.removal_event is not None
    if summary.removal_event is not None:
        removal_during_sleep = False
        if summary.sleep_start is not None and summary.sleep_end is not None:
            removal_during_sleep = _within_clock_period(
                summary.removal_event.parsed_time(),
                _parse_clock(summary.sleep_start),
                _parse_clock(summary.sleep_end),
            )
        asleep = AdequacyStatus.INSUFFICIENT
        if removal_during_sleep:
            limitations.append(
                "The monitor was removed during the declared sleep interval; "
                "the remaining night was not observed."
            )
        else:
            limitations.append(
                "A monitor-removal event is recorded, but dated reattachment and "
                "continuous nighttime coverage are not proven; nighttime adequacy "
                "and dipping are therefore not inferred."
            )

    if summary.duration_hours is None:
        duration_ok = False
        limitations.append("Recording duration is unknown.")
    else:
        duration_ok = summary.duration_hours >= rule.min_duration_hours
        if not duration_ok:
            limitations.append(
                f"Recording duration {summary.duration_hours} h is shorter than "
                f"the configured minimum {rule.min_duration_hours} h."
            )

    percentage_ok = valid_percent is not None and valid_percent >= rule.min_valid_percent
    if percentage_ok and duration_ok and awake is AdequacyStatus.ADEQUATE and asleep is AdequacyStatus.ADEQUATE:
        overall = AdequacyStatus.ADEQUATE
    elif (
        (valid_percent is not None and not percentage_ok)
        or (summary.duration_hours is not None and not duration_ok)
        or awake is AdequacyStatus.INSUFFICIENT
        or asleep is AdequacyStatus.INSUFFICIENT
    ):
        overall = AdequacyStatus.INSUFFICIENT
    elif (
        valid_percent is None
        or awake is AdequacyStatus.UNKNOWN
        or asleep is AdequacyStatus.UNKNOWN
    ):
        overall = AdequacyStatus.UNKNOWN
    else:
        overall = AdequacyStatus.INSUFFICIENT

    dipping_percent: Decimal | None = None
    if (
        awake is AdequacyStatus.ADEQUATE
        and asleep is AdequacyStatus.ADEQUATE
        and not removal_compromises_sleep
        and summary.awake_mean_systolic is not None
        and summary.asleep_mean_systolic is not None
        and summary.awake_mean_systolic != 0
    ):
        dipping_percent = (
            (summary.awake_mean_systolic - summary.asleep_mean_systolic)
            / summary.awake_mean_systolic
            * Decimal("100")
        )
        if dipping_percent < rule.non_dipper_lower_percent:
            own_classification = DippingClassification.REVERSE_DIPPER
        elif dipping_percent < rule.dipper_lower_percent:
            own_classification = DippingClassification.NON_DIPPER
        elif dipping_percent <= rule.extreme_dipper_lower_percent:
            own_classification = DippingClassification.DIPPER
        else:
            own_classification = DippingClassification.EXTREME_DIPPER
    else:
        own_classification = DippingClassification.INSUFFICIENT_DATA
        limitations.append("Independent dipping classification was not calculated.")

    return ABPMAssessment(
        rule_id=rule.rule_id,
        rule_sha256=rule.rule_sha256,
        rule_source_url=rule.source_url,
        rule_applicability=rule.applicability,
        overall_adequacy=overall,
        awake_adequacy=awake,
        asleep_adequacy=asleep,
        valid_percent=valid_percent,
        own_dipping_classification=own_classification,
        calculated_dipping_percent=dipping_percent,
        source_conclusion=summary.source_conclusion,
        removal_event=summary.removal_event,
        limitations=tuple(dict.fromkeys(limitations)),
    )
