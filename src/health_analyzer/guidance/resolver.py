"""Resolution of effective guidance for a date and jurisdiction."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date

from .models import (
    ConflictKind,
    EffectiveGuidanceBundle,
    GuidanceStatus,
    GuidelineDocument,
    GuidelineFreshness,
    GuidelineRecommendation,
    RecommendationConflict,
    RecommendationDirection,
    VersionRelation,
    VersionRelationType,
)
from .store import SQLiteGuidanceStore


class GuidanceResolver:
    def __init__(self, store: SQLiteGuidanceStore) -> None:
        self.store = store

    def resolve(
        self,
        *,
        as_of: date,
        jurisdiction: str,
        stale_after_days: int = 90,
        topics: tuple[str, ...] = (),
        issuers: tuple[str, ...] = (),
    ) -> EffectiveGuidanceBundle:
        """Build the effective recommendation view at a point in time.

        Exact jurisdiction matches and ``GLOBAL`` documents are eligible. Full
        supersession removes the old lineage; amendments and focused updates
        overlay only recommendation keys in the same series.
        """

        if type(stale_after_days) is not int or stale_after_days < 0:
            raise ValueError("stale_after_days must be a non-negative integer")

        documents = tuple(
            document
            for document in self.store.list_documents()
            if document.applies_to(jurisdiction)
            and (not issuers or document.issuer in issuers)
        )
        relations = self.store.list_relations()
        statuses = self._statuses(
            documents=documents,
            relations=relations,
            as_of=as_of,
            jurisdiction=jurisdiction,
        )
        current_documents = tuple(
            document
            for document in documents
            if statuses[document.document_id] is GuidanceStatus.CURRENT
        )
        current_ids = {document.document_id for document in current_documents}
        documents_by_id = {
            document.document_id: document for document in current_documents
        }
        all_documents_by_id = {
            document.document_id: document for document in documents
        }

        all_recommendations = self.store.list_recommendations()
        recommendations = tuple(
            recommendation
            for recommendation in all_recommendations
            if recommendation.document_id in current_ids
            and recommendation.applies_to(
                jurisdiction, documents_by_id[recommendation.document_id]
            )
            and self._recommendation_effective(recommendation, as_of)
            and (not topics or recommendation.topic in topics)
        )
        effective_recommendations = self._apply_partial_updates(
            recommendations=recommendations,
            all_recommendations=all_recommendations,
            documents_by_id=documents_by_id,
            all_documents_by_id=all_documents_by_id,
            relations=relations,
            as_of=as_of,
            jurisdiction=jurisdiction,
        )
        conflicts = self.detect_conflicts(effective_recommendations)
        freshness = tuple(
            self._freshness(
                document,
                status=statuses[document.document_id],
                as_of=as_of,
                stale_after_days=stale_after_days,
            )
            for document in documents
            if document.effective_from <= as_of
        )

        # Keep base documents that are still clinically current even when all
        # of their recommendation keys are overlaid by partial updates. The
        # base remains part of the effective provenance bundle.
        relevant_document_ids = {
            recommendation.document_id for recommendation in recommendations
        }
        bundle_documents = tuple(
            sorted(
                (
                    document
                    for document in current_documents
                    if document.document_id in relevant_document_ids
                ),
                key=lambda item: (item.effective_from, item.document_id),
            )
        )
        return EffectiveGuidanceBundle(
            as_of=as_of,
            jurisdiction=jurisdiction,
            documents=bundle_documents,
            recommendations=effective_recommendations,
            conflicts=conflicts,
            freshness=freshness,
        )

    def status(
        self,
        document_id: str,
        *,
        as_of: date,
        jurisdiction: str,
    ) -> GuidanceStatus:
        document = self.store.get_document(document_id)
        if document is None:
            raise KeyError(document_id)
        if not document.applies_to(jurisdiction):
            raise ValueError(
                f"document {document_id!r} does not apply to {jurisdiction!r}"
            )
        statuses = self._statuses(
            documents=tuple(
                item
                for item in self.store.list_documents()
                if item.applies_to(jurisdiction)
            ),
            relations=self.store.list_relations(),
            as_of=as_of,
            jurisdiction=jurisdiction,
        )
        return statuses[document_id]

    def freshness(
        self,
        document_id: str,
        *,
        as_of: date,
        jurisdiction: str,
        stale_after_days: int = 90,
    ) -> GuidelineFreshness:
        document = self.store.get_document(document_id)
        if document is None:
            raise KeyError(document_id)
        status = self.status(document_id, as_of=as_of, jurisdiction=jurisdiction)
        return self._freshness(
            document,
            status=status,
            as_of=as_of,
            stale_after_days=stale_after_days,
        )

    @staticmethod
    def detect_conflicts(
        recommendations: tuple[GuidelineRecommendation, ...],
    ) -> tuple[RecommendationConflict, ...]:
        groups: dict[tuple[str, str], list[GuidelineRecommendation]] = defaultdict(list)
        for recommendation in recommendations:
            groups[(recommendation.decision_key, recommendation.population_key)].append(
                recommendation
            )

        conflicts: list[RecommendationConflict] = []
        for (decision_key, population_key), group in sorted(groups.items()):
            if len(group) < 2:
                continue
            recommendation_ids = tuple(sorted(item.recommendation_id for item in group))
            directions = {item.direction for item in group}
            positive = {
                RecommendationDirection.FOR,
                RecommendationDirection.CONDITIONAL,
            }
            if RecommendationDirection.AGAINST in directions and directions & positive:
                conflicts.append(
                    RecommendationConflict(
                        conflict_key=f"{decision_key}:{population_key}:direction",
                        kind=ConflictKind.DIRECTION,
                        recommendation_ids=recommendation_ids,
                        description=(
                            "Applicable recommendations point in opposing "
                            "directions; retain each source position."
                        ),
                    )
                )

            positions = {
                item.position_key for item in group if item.position_key is not None
            }
            if len(positions) > 1:
                conflicts.append(
                    RecommendationConflict(
                        conflict_key=f"{decision_key}:{population_key}:position",
                        kind=ConflictKind.POSITION,
                        recommendation_ids=recommendation_ids,
                        description=(
                            "Applicable recommendations use different actionable "
                            "positions or thresholds."
                        ),
                    )
                )
        return tuple(conflicts)

    def _statuses(
        self,
        *,
        documents: tuple[GuidelineDocument, ...],
        relations: tuple[VersionRelation, ...],
        as_of: date,
        jurisdiction: str,
    ) -> dict[str, GuidanceStatus]:
        documents_by_id = {document.document_id: document for document in documents}
        statuses = {
            document.document_id: self._declared_status(document, as_of)
            for document in documents
        }

        active_relations = tuple(
            relation
            for relation in relations
            if relation.effective_from <= as_of
            and relation.source_document_id in documents_by_id
            and relation.target_document_id in documents_by_id
        )
        superseded_ids = {
            relation.target_document_id
            for relation in active_relations
            if relation.relation_type is VersionRelationType.SUPERSEDES
            # Supersession is a historical transition, not a live dependency
            # on the successor remaining current. A later withdrawal/expiry of
            # the successor creates a gap; it must not silently resurrect the
            # retired baseline without an explicit reinstatement event.
            and documents_by_id[relation.source_document_id].effective_from <= as_of
        }

        # Full replacement also retires partial overlays and older ancestors
        # connected to the replaced baseline. This prevents a stale focused
        # update from surviving after a new complete guideline is effective.
        changed = True
        while changed:
            changed = False
            for relation in active_relations:
                if (
                    relation.source_document_id in superseded_ids
                    and relation.target_document_id not in superseded_ids
                ):
                    superseded_ids.add(relation.target_document_id)
                    changed = True
                if (
                    relation.target_document_id in superseded_ids
                    and relation.relation_type
                    in {
                        VersionRelationType.AMENDS,
                        VersionRelationType.FOCUSED_UPDATE,
                    }
                    and relation.source_document_id not in superseded_ids
                ):
                    superseded_ids.add(relation.source_document_id)
                    changed = True

        for document_id in superseded_ids:
            if statuses.get(document_id) is GuidanceStatus.CURRENT:
                statuses[document_id] = GuidanceStatus.SUPERSEDED
        return statuses

    @staticmethod
    def _declared_status(document: GuidelineDocument, as_of: date) -> GuidanceStatus:
        if as_of < document.effective_from:
            return GuidanceStatus.NOT_YET_EFFECTIVE
        if document.withdrawn_on and as_of >= document.withdrawn_on:
            return GuidanceStatus.WITHDRAWN
        if document.effective_until and as_of > document.effective_until:
            return GuidanceStatus.SUPERSEDED
        if (
            document.status_changed_on
            and as_of >= document.status_changed_on
            and document.declared_status
            in {GuidanceStatus.SUPERSEDED, GuidanceStatus.WITHDRAWN}
        ):
            return document.declared_status
        return GuidanceStatus.CURRENT

    @staticmethod
    def _recommendation_effective(
        recommendation: GuidelineRecommendation, as_of: date
    ) -> bool:
        if recommendation.applies_from and as_of < recommendation.applies_from:
            return False
        return not (
            recommendation.applies_until and as_of > recommendation.applies_until
        )

    @staticmethod
    def _apply_partial_updates(
        *,
        recommendations: tuple[GuidelineRecommendation, ...],
        all_recommendations: tuple[GuidelineRecommendation, ...],
        documents_by_id: dict[str, GuidelineDocument],
        all_documents_by_id: dict[str, GuidelineDocument],
        relations: tuple[VersionRelation, ...],
        as_of: date,
        jurisdiction: str,
    ) -> tuple[GuidelineRecommendation, ...]:
        grouped: dict[tuple[str, str], list[GuidelineRecommendation]] = defaultdict(
            list
        )
        for recommendation in recommendations:
            document = documents_by_id[recommendation.document_id]
            grouped[(document.series_id, recommendation.recommendation_key)].append(
                recommendation
            )

        shadowed: set[tuple[str, str]] = set()
        for relation in relations:
            if relation.effective_from > as_of:
                continue
            if relation.relation_type not in {
                VersionRelationType.AMENDS,
                VersionRelationType.FOCUSED_UPDATE,
            }:
                continue
            source = all_documents_by_id.get(relation.source_document_id)
            target = all_documents_by_id.get(relation.target_document_id)
            if source is None or target is None or source.series_id != target.series_id:
                continue
            if source.effective_from > as_of:
                continue
            for recommendation_key in relation.affected_recommendation_keys:
                source_replaces_key = any(
                    recommendation.document_id == source.document_id
                    and recommendation.recommendation_key == recommendation_key
                    and recommendation.applies_to(jurisdiction, source)
                    and GuidanceResolver._recommendation_was_effective(
                        recommendation,
                        source=source,
                        start=relation.effective_from,
                        end=as_of,
                    )
                    for recommendation in all_recommendations
                )
                if source_replaces_key:
                    # Partial relations are replacement overlays, not deletion
                    # tombstones. Once a source-backed replacement takes effect,
                    # its historical shadow remains even if the source is later
                    # withdrawn; an empty update cannot erase the target key.
                    shadowed.add((relation.target_document_id, recommendation_key))

        effective: list[GuidelineRecommendation] = []
        for candidates in grouped.values():
            effective.extend(
                candidate
                for candidate in candidates
                if (
                    candidate.document_id,
                    candidate.recommendation_key,
                )
                not in shadowed
            )
        return tuple(
            sorted(
                effective,
                key=lambda item: (
                    item.decision_key,
                    item.population_key,
                    item.recommendation_id,
                ),
            )
        )

    @staticmethod
    def _recommendation_was_effective(
        recommendation: GuidelineRecommendation,
        *,
        source: GuidelineDocument,
        start: date,
        end: date,
    ) -> bool:
        """Return whether a replacement existed at any instant in the interval."""

        activation = max(
            start,
            source.effective_from,
            recommendation.applies_from or start,
        )
        if activation > end:
            return False
        if recommendation.applies_until and activation > recommendation.applies_until:
            return False
        if source.effective_until and activation > source.effective_until:
            return False
        if source.withdrawn_on and activation >= source.withdrawn_on:
            return False
        if (
            source.status_changed_on
            and source.declared_status
            in {GuidanceStatus.SUPERSEDED, GuidanceStatus.WITHDRAWN}
            and activation >= source.status_changed_on
        ):
            return False
        return True

    @staticmethod
    def _freshness(
        document: GuidelineDocument,
        *,
        status: GuidanceStatus,
        as_of: date,
        stale_after_days: int,
    ) -> GuidelineFreshness:
        if type(stale_after_days) is not int or stale_after_days < 0:
            raise ValueError("stale_after_days must be a non-negative integer")
        checked_at = document.last_checked_at or document.provenance.retrieved_at
        checked_date = checked_at.astimezone(UTC).date()
        if checked_date > as_of:
            age_days = 0
            is_stale = True
            reason = (
                f"{status.value}; last_checked_at is after as_of and cannot "
                "establish point-in-time freshness"
            )
        else:
            age_days = (as_of - checked_date).days
            is_stale = age_days > stale_after_days
            reason = f"{status.value}; last checked {age_days} day(s) before as_of"
        return GuidelineFreshness(
            document_id=document.document_id,
            status=status,
            checked_at=checked_at,
            age_days=age_days,
            is_stale=is_stale,
            reason=reason,
        )
