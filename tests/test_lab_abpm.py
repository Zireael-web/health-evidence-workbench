from __future__ import annotations

from decimal import Decimal

import pytest

from health_analyzer.contracts import StatementKind
from health_analyzer.lab import (
    ABPMAdequacyRule,
    ABPMSummary,
    AdequacyStatus,
    DippingClassification,
    MonitorRemovalEvent,
    SourceAssertion,
    assess_abpm,
)
from health_analyzer.vault import ProvenanceLocator


def _provenance(line: int) -> tuple[ProvenanceLocator, ...]:
    return (
        ProvenanceLocator(
            source_id="src_synthetic_abpm",
            sha256="b" * 64,
            page=1,
            line_start=line,
            line_end=line,
        ),
    )


def test_two_night_readings_and_removal_block_dipping_classification() -> None:
    source_conclusion = SourceAssertion(
        text="Source report classification: non-dipper",
        kind=StatementKind.SOURCE_FACT,
        provenance=_provenance(9),
    )
    removal_note = SourceAssertion(
        text="Monitor removed at approximately 04:30",
        kind=StatementKind.USER_NOTE,
        provenance=_provenance(10),
    )
    summary = ABPMSummary(
        attempts=97,
        valid_total=59,
        valid_awake=57,
        valid_asleep=2,
        duration_hours=Decimal("15.03"),
        awake_mean_systolic=Decimal("120"),
        asleep_mean_systolic=Decimal("109"),
        sleep_start="04:00",
        sleep_end="09:50",
        source_conclusion=source_conclusion,
        removal_event=MonitorRemovalEvent("04:30", removal_note, approximate=True),
    )

    result = assess_abpm(summary)

    assert result.source_conclusion == source_conclusion
    assert result.removal_event == summary.removal_event
    assert result.awake_adequacy is AdequacyStatus.ADEQUATE
    assert result.asleep_adequacy is AdequacyStatus.INSUFFICIENT
    assert result.overall_adequacy is AdequacyStatus.INSUFFICIENT
    assert result.own_dipping_classification is DippingClassification.INSUFFICIENT_DATA
    assert result.calculated_dipping_percent is None
    assert result.valid_percent is not None and result.valid_percent < Decimal("70")
    assert any("removed during" in limitation for limitation in result.limitations)
    assert any("2 asleep" in limitation for limitation in result.limitations)


@pytest.mark.parametrize(
    "overrides",
    (
        {"attempts": 10, "valid_total": 20},
        {"valid_total": 20, "valid_awake": 21},
        {"valid_total": 20, "valid_awake": 15, "valid_asleep": 6},
        {"attempts": True},
        {"duration_hours": Decimal("NaN")},
        {"duration_hours": Decimal("1e1001")},
        {"duration_hours": Decimal("9" * 129)},
        {"awake_mean_systolic": Decimal("120"), "asleep_mean_systolic": None},
    ),
)
def test_abpm_summary_rejects_impossible_or_non_finite_values(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "attempts": 30,
        "valid_total": 25,
        "valid_awake": 18,
        "valid_asleep": 7,
        "duration_hours": Decimal("24"),
        "awake_mean_systolic": Decimal("120"),
        "asleep_mean_systolic": Decimal("105"),
    }
    values.update(overrides)

    with pytest.raises(ValueError):
        ABPMSummary(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("sleep_start", "sleep_end"),
    (("05:00", "09:00"), (None, None)),
)
def test_any_unresolved_monitor_removal_blocks_night_adequacy_and_dipping(
    sleep_start: str | None,
    sleep_end: str | None,
) -> None:
    removal_note = SourceAssertion(
        text="Monitor removed at approximately 04:30 and not reattached",
        kind=StatementKind.USER_NOTE,
        provenance=_provenance(10),
    )
    summary = ABPMSummary(
        attempts=35,
        valid_total=30,
        valid_awake=23,
        valid_asleep=7,
        duration_hours=Decimal("24"),
        awake_mean_systolic=Decimal("120"),
        asleep_mean_systolic=Decimal("105"),
        sleep_start=sleep_start,
        sleep_end=sleep_end,
        removal_event=MonitorRemovalEvent("04:30", removal_note, approximate=True),
    )

    result = assess_abpm(summary)

    assert result.asleep_adequacy is AdequacyStatus.INSUFFICIENT
    assert result.overall_adequacy is AdequacyStatus.INSUFFICIENT
    assert result.own_dipping_classification is DippingClassification.INSUFFICIENT_DATA
    assert result.calculated_dipping_percent is None
    assert any("coverage" in limitation for limitation in result.limitations)


def test_abpm_rule_identity_binds_parameters_source_and_applicability() -> None:
    with pytest.raises(ValueError, match="distinct custom rule_id"):
        ABPMAdequacyRule(min_valid_awake=1)

    default_rule = ABPMAdequacyRule()
    custom_rule = ABPMAdequacyRule(
        rule_id="synthetic-abpm-profile-v2",
        source_url="https://example.invalid/synthetic-abpm-profile-v2",
        applicability="synthetic_validation_only",
        min_valid_awake=1,
    )
    summary = ABPMSummary(
        attempts=10,
        valid_total=10,
        valid_awake=1,
        valid_asleep=9,
        duration_hours=Decimal("24"),
    )

    default_assessment = assess_abpm(summary, rule=default_rule)
    custom_assessment = assess_abpm(summary, rule=custom_rule)

    assert default_assessment.awake_adequacy is AdequacyStatus.INSUFFICIENT
    assert custom_assessment.awake_adequacy is AdequacyStatus.ADEQUATE
    assert default_assessment.rule_sha256 != custom_assessment.rule_sha256
    assert custom_assessment.rule_id == custom_rule.rule_id
    assert custom_assessment.rule_sha256 == custom_rule.rule_sha256
    assert custom_assessment.rule_source_url == custom_rule.source_url
    assert custom_assessment.rule_applicability == custom_rule.applicability
