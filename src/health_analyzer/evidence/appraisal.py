"""Explicit, framework-scoped critical appraisal records.

No universal score is calculated. RoB 2, ROBINS-I, AMSTAR 2, AGREE II, and
GRADE answer different questions; any crosswalk must be stored as a separate,
auditable mapping rather than overwriting native judgments.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum


class DomainJudgment(StrEnum):
    LOW = "low"
    SOME_CONCERNS = "some_concerns"
    HIGH = "high"
    CRITICALLY_LOW = "critically_low"
    UNCLEAR = "unclear"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class AppraisalDomain:
    domain: str
    judgment: DomainJudgment
    rationale: str
    support_locators: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.domain.strip() or not self.rationale.strip():
            raise ValueError("appraisal domain and rationale are required")
        if not self.support_locators:
            raise ValueError("appraisal judgment requires source locators")


@dataclass(frozen=True, slots=True)
class EvidenceAppraisal:
    appraisal_id: str
    evidence_id: str
    framework: str
    framework_version: str
    domains: tuple[AppraisalDomain, ...]
    overall_judgment: DomainJudgment
    assessor: str
    assessed_at: str
    applicability_notes: tuple[str, ...] = ()
    funding_and_conflicts: str | None = None

    def __post_init__(self) -> None:
        if not self.framework or not self.framework_version:
            raise ValueError("native appraisal framework and version are required")
        if not self.domains:
            raise ValueError("at least one appraisal domain is required")
        names = [domain.domain.casefold() for domain in self.domains]
        if len(names) != len(set(names)):
            raise ValueError("appraisal domains must be unique")
        parsed = datetime.fromisoformat(self.assessed_at)
        if parsed.tzinfo is None:
            raise ValueError("assessed_at must include a timezone")


@dataclass(frozen=True, slots=True)
class GradeCrosswalk:
    source_framework: str
    source_value: str
    target_framework: str
    target_value: str
    rationale: str
    mapping_source: str

    def __post_init__(self) -> None:
        if self.source_framework == self.target_framework:
            raise ValueError("crosswalk is unnecessary within the same framework")
        if not self.rationale or not self.mapping_source:
            raise ValueError("crosswalk requires rationale and a mapping source")


def new_assessment_time() -> str:
    return datetime.now(timezone.utc).isoformat()
