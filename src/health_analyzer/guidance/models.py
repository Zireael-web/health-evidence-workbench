"""Domain models for a temporal, jurisdiction-aware guidance registry.

The registry intentionally stores a publisher's wording and grading system
verbatim.  Normalized fields are useful for filtering and conflict detection,
but must never replace the source representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from urllib.parse import urlsplit

GLOBAL_JURISDICTION = "GLOBAL"


class GuidanceStatus(StrEnum):
    CURRENT = "current"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"
    NOT_YET_EFFECTIVE = "not_yet_effective"


class VersionRelationType(StrEnum):
    SUPERSEDES = "supersedes"
    AMENDS = "amends"
    FOCUSED_UPDATE = "focused_update"


class RecommendationDirection(StrEnum):
    FOR = "for"
    AGAINST = "against"
    CONDITIONAL = "conditional"
    UNCERTAIN = "uncertain"


class ConflictKind(StrEnum):
    DIRECTION = "direction"
    POSITION = "position"


@dataclass(frozen=True, slots=True)
class SourceProvenance:
    """Immutable locator for a source document or recommendation."""

    canonical_url: str
    retrieved_at: datetime
    content_sha256: str
    locator: str | None = None
    publisher_document_id: str | None = None

    def __post_init__(self) -> None:
        parsed = urlsplit(self.canonical_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
        ):
            raise ValueError("canonical_url must be canonical HTTPS without credentials")
        if self.retrieved_at.tzinfo is None:
            raise ValueError("retrieved_at must be timezone-aware")
        if len(self.content_sha256) != 64:
            raise ValueError("content_sha256 must be a 64-character SHA-256 hex digest")
        try:
            int(self.content_sha256, 16)
        except ValueError as exc:
            raise ValueError("content_sha256 must be hexadecimal") from exc


@dataclass(frozen=True, slots=True)
class GuidelineDocument:
    """One immutable publication/version in a guideline series."""

    document_id: str
    series_id: str
    title: str
    issuer: str
    version: str
    jurisdictions: tuple[str, ...]
    effective_from: date
    provenance: SourceProvenance
    published_on: date | None = None
    effective_until: date | None = None
    withdrawn_on: date | None = None
    declared_status: GuidanceStatus = GuidanceStatus.CURRENT
    status_changed_on: date | None = None
    last_checked_at: datetime | None = None
    document_type: str = "clinical_guideline"
    language: str = "en"
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.declared_status, GuidanceStatus):
            raise ValueError("declared_status must be a GuidanceStatus")
        if self.declared_status is GuidanceStatus.NOT_YET_EFFECTIVE:
            raise ValueError(
                "not_yet_effective is computed from effective_from and cannot "
                "be stored as declared_status"
            )
        if not self.document_id or not self.series_id:
            raise ValueError("document_id and series_id are required")
        if not self.jurisdictions:
            raise ValueError("at least one jurisdiction is required")
        if self.effective_until and self.effective_until < self.effective_from:
            raise ValueError("effective_until cannot precede effective_from")
        if self.withdrawn_on and self.withdrawn_on < self.effective_from:
            raise ValueError("withdrawn_on cannot precede effective_from")
        if self.status_changed_on and self.status_changed_on < self.effective_from:
            raise ValueError("status_changed_on cannot precede effective_from")
        if (
            self.declared_status
            in {GuidanceStatus.SUPERSEDED, GuidanceStatus.WITHDRAWN}
            and self.status_changed_on is None
        ):
            raise ValueError(
                "a non-current declared_status requires status_changed_on"
            )
        if (
            self.declared_status is GuidanceStatus.CURRENT
            and self.status_changed_on is not None
        ):
            raise ValueError(
                "status_changed_on is inconsistent with declared_status=current"
            )
        if (
            self.declared_status is GuidanceStatus.WITHDRAWN
            and self.withdrawn_on is not None
            and self.status_changed_on != self.withdrawn_on
        ):
            raise ValueError(
                "withdrawn_on and status_changed_on must agree for withdrawn guidance"
            )
        if self.last_checked_at and self.last_checked_at.tzinfo is None:
            raise ValueError("last_checked_at must be timezone-aware")

    def applies_to(self, jurisdiction: str) -> bool:
        return (
            jurisdiction in self.jurisdictions
            or GLOBAL_JURISDICTION in self.jurisdictions
        )


@dataclass(frozen=True, slots=True)
class VersionRelation:
    """A directed edge from a newer document to an older document."""

    source_document_id: str
    target_document_id: str
    relation_type: VersionRelationType
    effective_from: date
    affected_recommendation_keys: tuple[str, ...] = ()
    provenance_note: str | None = None

    def __post_init__(self) -> None:
        if not self.source_document_id or not self.target_document_id:
            raise ValueError("version relation document identifiers are required")
        if self.source_document_id == self.target_document_id:
            raise ValueError("a document cannot version itself")
        if (
            self.relation_type is VersionRelationType.SUPERSEDES
            and self.affected_recommendation_keys
        ):
            raise ValueError(
                "supersedes replaces a full document and cannot list affected keys"
            )
        if (
            self.relation_type
            in {VersionRelationType.AMENDS, VersionRelationType.FOCUSED_UPDATE}
            and not self.affected_recommendation_keys
        ):
            raise ValueError(
                "partial version relations require affected recommendation keys"
            )
        if len(set(self.affected_recommendation_keys)) != len(
            self.affected_recommendation_keys
        ):
            raise ValueError("affected recommendation keys must be unique")


@dataclass(frozen=True, slots=True)
class GuidelineRecommendation:
    """One recommendation with untouched source wording and grade fields."""

    recommendation_id: str
    document_id: str
    recommendation_key: str
    decision_key: str
    population_key: str
    verbatim_text: str
    native_grade_system: str
    native_grade: str
    provenance: SourceProvenance
    direction: RecommendationDirection = RecommendationDirection.UNCERTAIN
    position_key: str | None = None
    native_strength: str | None = None
    native_certainty: str | None = None
    applies_from: date | None = None
    applies_until: date | None = None
    jurisdictions: tuple[str, ...] = ()
    topic: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        required = (
            self.recommendation_id,
            self.document_id,
            self.recommendation_key,
            self.decision_key,
            self.population_key,
            self.native_grade_system,
        )
        if not all(required):
            raise ValueError(
                "recommendation identifiers and native grade system are required"
            )
        if (
            self.applies_from
            and self.applies_until
            and self.applies_until < self.applies_from
        ):
            raise ValueError("applies_until cannot precede applies_from")

    def applies_to(self, jurisdiction: str, document: GuidelineDocument) -> bool:
        jurisdictions = self.jurisdictions or document.jurisdictions
        return jurisdiction in jurisdictions or GLOBAL_JURISDICTION in jurisdictions


@dataclass(frozen=True, slots=True)
class GuidelineFreshness:
    document_id: str
    status: GuidanceStatus
    checked_at: datetime
    age_days: int
    is_stale: bool
    reason: str


@dataclass(frozen=True, slots=True)
class RecommendationConflict:
    conflict_key: str
    kind: ConflictKind
    recommendation_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True, slots=True)
class EffectiveGuidanceBundle:
    as_of: date
    jurisdiction: str
    documents: tuple[GuidelineDocument, ...]
    recommendations: tuple[GuidelineRecommendation, ...]
    conflicts: tuple[RecommendationConflict, ...]
    freshness: tuple[GuidelineFreshness, ...]
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
