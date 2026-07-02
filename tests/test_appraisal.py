import pytest

from health_analyzer.evidence import (
    AppraisalDomain,
    DomainJudgment,
    EvidenceAppraisal,
    GradeCrosswalk,
)


def test_appraisal_preserves_native_framework_and_locators() -> None:
    appraisal = EvidenceAppraisal(
        appraisal_id="app-1",
        evidence_id="pmid:1",
        framework="RoB 2",
        framework_version="2019",
        domains=(
            AppraisalDomain(
                domain="randomization process",
                judgment=DomainJudgment.LOW,
                rationale="Allocation sequence and concealment were described.",
                support_locators=("pmid:1#methods-randomization",),
            ),
        ),
        overall_judgment=DomainJudgment.LOW,
        assessor="human-reviewer",
        assessed_at="2026-08-07T10:00:00+05:00",
    )
    assert appraisal.framework == "RoB 2"


def test_crosswalk_requires_an_explicit_external_mapping_source() -> None:
    with pytest.raises(ValueError):
        GradeCrosswalk(
            source_framework="GRADE",
            source_value="moderate",
            target_framework="USPSTF",
            target_value="B",
            rationale="",
            mapping_source="",
        )
