"""Public API for the clinical guidance registry."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Self
from urllib.parse import urldefrag, urlsplit

from health_analyzer.privacy import PrivacyGate

from .models import (
    EffectiveGuidanceBundle,
    GuidanceStatus,
    GuidelineDocument,
    GuidelineFreshness,
    GuidelineRecommendation,
    RecommendationDirection,
    SourceProvenance,
    VersionRelation,
    VersionRelationType,
)
from .resolver import GuidanceResolver
from .source_catalog import (
    GuidanceRiskLevel,
    GuidanceSourceCatalog,
    GuidanceSourcePortal,
)
from .store import SQLiteGuidanceStore

MAX_GUIDANCE_SOURCE_BYTES = 128 * 1024 * 1024
MAX_GUIDANCE_FIXTURE_BYTES = 8 * 1024 * 1024
_AUDITED_RISKS = frozenset(
    {GuidanceRiskLevel.PERSONAL_CONTEXT, GuidanceRiskLevel.CLINICAL_ACTION}
)
_REVIEWED_IMPORT_CAPABILITY = object()
_SOURCE_REVIEW_METADATA_FIELDS = frozenset(
    {
        "source_review_status",
        "source_review_catalog_id",
        "source_review_reviewer_id",
        "source_review_risk_level",
        "source_review_recheck_days",
        "source_review_valid_until",
    }
)


def _sha256_regular_file(path: Path) -> str:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not no_follow:
        raise RuntimeError("this platform cannot enforce no-follow source reads")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        raise ValueError("guidance source snapshot is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_GUIDANCE_SOURCE_BYTES:
            raise ValueError("guidance source snapshot must be a bounded regular file")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ValueError("guidance source snapshot changed while being hashed")
    return digest.hexdigest()


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in guidance snapshot: {key}")
        result[key] = value
    return result


def _read_fixture_payload(path: Path) -> dict[str, Any]:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not no_follow:
        raise RuntimeError("this platform cannot enforce no-follow fixture reads")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        raise ValueError("guidance snapshot is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= MAX_GUIDANCE_FIXTURE_BYTES
        ):
            raise ValueError("guidance snapshot must be a bounded regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_GUIDANCE_FIXTURE_BYTES + 1)
            after = os.fstat(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or len(raw) != after.st_size:
        raise ValueError("guidance snapshot changed while being read")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("guidance snapshot is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("guidance snapshot must be an object")
    return payload


def _parse_provenance(raw: dict[str, Any]) -> SourceProvenance:
    return SourceProvenance(
        canonical_url=raw["canonical_url"],
        retrieved_at=datetime.fromisoformat(raw["retrieved_at"]),
        content_sha256=raw["content_sha256"],
        locator=raw.get("locator"),
        publisher_document_id=raw.get("publisher_document_id"),
    )


def _optional_date(value: str | None) -> date | None:
    return date.fromisoformat(value) if value else None


_TYPED_METADATA_KEYS = frozenset(
    {
        "canonical_url",
        "content_hash",
        "content_sha256",
        "doi",
        "document_id",
        "effective_from",
        "effective_until",
        "isbn",
        "issn",
        "last_checked_at",
        "nct_id",
        "pmid",
        "published_at",
        "published_on",
        "publisher_document_id",
        "retrieved_at",
        "sha256",
        "source_document_sha256",
        "status_changed_on",
        "version",
        "withdrawn_on",
    }
)


def _metadata_semantic_payload(metadata: object) -> object:
    """Treat untyped metadata values as prose, except named typed fields."""

    if not isinstance(metadata, dict):
        return metadata
    return {
        str(key): value
        for key, value in metadata.items()
        if str(key).strip().casefold().replace("-", "_")
        not in _TYPED_METADATA_KEYS
    }


def _fixture_source_locator(raw: dict[str, Any]) -> object:
    provenance = raw.get("provenance")
    if isinstance(provenance, dict):
        return provenance.get("locator")
    return provenance


def _document_semantic_payload(document: GuidelineDocument) -> dict[str, Any]:
    """Project only free text; identifiers, dates, URLs and hashes stay typed."""

    return {
        "title": document.title,
        "issuer": document.issuer,
        "source_locator": document.provenance.locator,
        "metadata": _metadata_semantic_payload(document.metadata),
    }


def _relation_semantic_payload(relation: VersionRelation) -> dict[str, Any]:
    return {"provenance_note": relation.provenance_note}


def _recommendation_semantic_payload(
    recommendation: GuidelineRecommendation,
) -> dict[str, Any]:
    return {
        "verbatim_text": recommendation.verbatim_text,
        "native_grade_system": recommendation.native_grade_system,
        "native_grade": recommendation.native_grade,
        "native_strength": recommendation.native_strength,
        "native_certainty": recommendation.native_certainty,
        "source_locator": recommendation.provenance.locator,
        "metadata": _metadata_semantic_payload(recommendation.metadata),
    }


def _fixture_semantic_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Preflight all fixture prose before the first registry write."""

    return {
        "documents": [
            {
                "title": raw.get("title"),
                "issuer": raw.get("issuer"),
                "source_locator": _fixture_source_locator(raw),
                "metadata": _metadata_semantic_payload(raw.get("metadata", {})),
            }
            for raw in payload.get("documents", [])
            if isinstance(raw, dict)
        ],
        "relations": [
            {"provenance_note": raw.get("provenance_note")}
            for raw in payload.get("relations", [])
            if isinstance(raw, dict)
        ],
        "recommendations": [
            {
                "verbatim_text": raw.get("verbatim_text"),
                "native_grade_system": raw.get("native_grade_system"),
                "native_grade": raw.get("native_grade"),
                "native_strength": raw.get("native_strength"),
                "native_certainty": raw.get("native_certainty"),
                "source_locator": _fixture_source_locator(raw),
                "metadata": _metadata_semantic_payload(raw.get("metadata", {})),
            }
            for raw in payload.get("recommendations", [])
            if isinstance(raw, dict)
        ],
    }


def _resolved_semantic_payload(result: EffectiveGuidanceBundle) -> dict[str, Any]:
    """Recheck persisted prose so legacy registries fail closed on output."""

    return {
        "documents": [
            _document_semantic_payload(document) for document in result.documents
        ],
        "recommendations": [
            _recommendation_semantic_payload(recommendation)
            for recommendation in result.recommendations
        ],
    }


def validate_audited_document(
    document: GuidelineDocument,
    *,
    catalog: GuidanceSourceCatalog,
    now: datetime,
) -> tuple[GuidanceRiskLevel, GuidanceSourcePortal, datetime, int]:
    """Revalidate one audited document against the current packaged catalog."""

    if now.tzinfo is None:
        raise ValueError("audited guidance validation clock must be timezone-aware")
    metadata = document.metadata
    if metadata.get("source_review_status") != "audited_snapshot":
        raise ValueError("guidance document is not an audited source snapshot")
    catalog_source_id = metadata.get("source_review_catalog_id")
    if not isinstance(catalog_source_id, str):
        raise ValueError("guidance source-review catalog binding is missing")
    source = catalog.require_source_url(
        source_id=catalog_source_id,
        canonical_url=document.provenance.canonical_url,
    )
    if document.issuer != source.issuer:
        raise ValueError("guidance issuer does not match current source catalog")
    if not set(document.jurisdictions).issubset(source.jurisdictions):
        raise ValueError("guidance jurisdictions exceed current source catalog scope")
    reviewer_id = metadata.get("source_review_reviewer_id")
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        raise ValueError("guidance source-review reviewer attribution is missing")
    try:
        reviewed_risk = GuidanceRiskLevel(metadata["source_review_risk_level"])
        valid_until = datetime.fromisoformat(metadata["source_review_valid_until"])
        recheck_days = int(metadata["source_review_recheck_days"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("guidance source-review metadata is incomplete") from None
    if reviewed_risk not in _AUDITED_RISKS:
        raise ValueError("guidance source-review risk binding is invalid")
    if valid_until.tzinfo is None:
        raise ValueError("source_review_valid_until must be timezone-aware")
    if document.last_checked_at is None:
        raise ValueError("audited guidance requires last_checked_at")
    if document.last_checked_at > now + timedelta(minutes=5):
        raise ValueError("guidance source review cannot be in the future")
    if recheck_days != source.review_interval_days:
        raise ValueError(
            "guidance source-review cadence does not match the current source catalog"
        )
    expected_valid_until = document.last_checked_at + timedelta(
        days=source.review_interval_days
    )
    if valid_until != expected_valid_until:
        raise ValueError(
            "guidance source-review validity does not match checked-at and cadence"
        )
    if valid_until < now:
        raise ValueError(
            "audited guidance source review is stale; recheck the official source"
        )
    return reviewed_risk, source, valid_until, recheck_days


class GuidanceRegistry:
    """Facade combining persistence, fixture import, and effective resolution."""

    def __init__(self, database: str | Path = ":memory:", *, readonly: bool = False) -> None:
        self._store = SQLiteGuidanceStore(database, readonly=readonly)
        self._resolver = GuidanceResolver(self._store)
        self._privacy_gate = PrivacyGate()

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def add_document(
        self,
        document: GuidelineDocument,
        *,
        _source_review_capability: object | None = None,
    ) -> None:
        if (
            _SOURCE_REVIEW_METADATA_FIELDS.intersection(document.metadata)
            and _source_review_capability is not _REVIEWED_IMPORT_CAPABILITY
        ):
            raise ValueError(
                "reserved source-review metadata may only be issued by "
                "load_reviewed_fixture"
            )
        self._privacy_gate.assert_public_payload({"guideline_document": asdict(document)})
        self._privacy_gate.assert_public_semantic_payload(
            _document_semantic_payload(document)
        )
        self._store.add_document(document)

    def add_relation(self, relation: VersionRelation) -> None:
        self._privacy_gate.assert_public_payload({"guideline_relation": asdict(relation)})
        self._privacy_gate.assert_public_semantic_payload(
            _relation_semantic_payload(relation)
        )
        self._store.add_relation(relation)

    def add_recommendation(self, recommendation: GuidelineRecommendation) -> None:
        self._privacy_gate.assert_public_payload(
            {"guideline_recommendation": asdict(recommendation)}
        )
        self._privacy_gate.assert_public_semantic_payload(
            _recommendation_semantic_payload(recommendation)
        )
        document = self._store.get_document(recommendation.document_id)
        if document is None:
            raise ValueError("guideline recommendation requires a parent document")
        if (
            urldefrag(recommendation.provenance.canonical_url).url
            != urldefrag(document.provenance.canonical_url).url
            or recommendation.provenance.content_sha256
            != document.provenance.content_sha256
            or recommendation.provenance.retrieved_at
            != document.provenance.retrieved_at
        ):
            raise ValueError(
                "guideline recommendation provenance must match its parent document snapshot"
            )
        self._store.add_recommendation(recommendation)

    def get_document(self, document_id: str) -> GuidelineDocument | None:
        """Return one immutable document without exposing the writable store."""

        return self._store.get_document(document_id)

    def get_recommendation(
        self, recommendation_id: str
    ) -> GuidelineRecommendation | None:
        """Return one immutable recommendation without exposing the writable store."""

        return self._store.get_recommendation(recommendation_id)

    def resolve(
        self,
        *,
        as_of: date,
        jurisdiction: str,
        stale_after_days: int = 90,
        topics: tuple[str, ...] = (),
        issuers: tuple[str, ...] = (),
    ) -> EffectiveGuidanceBundle:
        result = self._resolver.resolve(
            as_of=as_of,
            jurisdiction=jurisdiction,
            stale_after_days=stale_after_days,
            topics=topics,
            issuers=issuers,
        )
        checked_now = datetime.now(UTC)
        catalog = GuidanceSourceCatalog.load()
        for document in result.documents:
            if document.metadata.get("source_review_status") != "audited_snapshot":
                continue
            validate_audited_document(
                document,
                catalog=catalog,
                now=checked_now,
            )
        self._privacy_gate.assert_public_payload({"effective_guidance": asdict(result)})
        self._privacy_gate.assert_public_semantic_payload(
            _resolved_semantic_payload(result)
        )
        return result

    def status(
        self, document_id: str, *, as_of: date, jurisdiction: str
    ) -> GuidanceStatus:
        return self._resolver.status(document_id, as_of=as_of, jurisdiction=jurisdiction)

    def freshness(
        self,
        document_id: str,
        *,
        as_of: date,
        jurisdiction: str,
        stale_after_days: int = 90,
    ) -> GuidelineFreshness:
        return self._resolver.freshness(
            document_id,
            as_of=as_of,
            jurisdiction=jurisdiction,
            stale_after_days=stale_after_days,
        )

    def load_fixture(self, path: str | Path) -> None:
        """Load test-only synthetic guidance from ``example.invalid``."""

        payload = _read_fixture_payload(Path(path))
        documents = payload.get("documents")
        if not isinstance(documents, list) or not documents:
            raise ValueError("synthetic guidance fixture requires documents")
        if any(
            urlsplit(str(raw.get("provenance", {}).get("canonical_url", ""))).hostname
            != "example.invalid"
            for raw in documents
            if isinstance(raw, dict)
        ):
            raise ValueError(
                "load_fixture is restricted to example.invalid synthetic data; "
                "use load_reviewed_fixture for real guidance"
            )
        self._load_payload(payload)

    def load_reviewed_fixture(
        self,
        path: str | Path,
        *,
        source_files: dict[str, str | Path],
        source_ids: dict[str, str],
        reviewer_id: str,
        risk_level: GuidanceRiskLevel | str,
        now: datetime | None = None,
    ) -> None:
        """Load a current audited snapshot bound to exact local source bytes."""

        normalized_reviewer = reviewer_id.strip()
        if not normalized_reviewer or len(normalized_reviewer.encode("utf-8")) > 256:
            raise ValueError("reviewer_id is required and must not exceed 256 bytes")
        try:
            normalized_risk = GuidanceRiskLevel(risk_level)
        except (TypeError, ValueError):
            raise ValueError("risk_level is unsupported") from None
        if normalized_risk not in _AUDITED_RISKS:
            raise ValueError(
                "registry import requires personal_context or clinical_action risk"
            )
        payload = _read_fixture_payload(Path(path))
        documents = payload.get("documents")
        if not isinstance(documents, list) or not documents:
            raise ValueError("reviewed guidance snapshot requires documents")
        document_ids = {
            raw.get("document_id") for raw in documents if isinstance(raw, dict)
        }
        if None in document_ids or "" in document_ids:
            raise ValueError("every guidance document requires document_id")
        if set(source_files) != document_ids or set(source_ids) != document_ids:
            raise ValueError(
                "source_files and source_ids must exactly cover guidance documents"
            )

        resolved_catalog = GuidanceSourceCatalog.load()
        checked_now = now or datetime.now(UTC)
        if checked_now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        for raw in documents:
            document_id = raw["document_id"]
            provenance = raw.get("provenance")
            if not isinstance(provenance, dict):
                raise ValueError("guidance document provenance is required")
            source = resolved_catalog.require_source_url(
                source_id=source_ids[document_id],
                canonical_url=provenance.get("canonical_url", ""),
            )
            if raw.get("issuer") != source.issuer:
                raise ValueError(
                    f"guidance issuer does not match catalog source for {document_id}"
                )
            raw_jurisdictions = raw.get("jurisdictions")
            if not isinstance(raw_jurisdictions, list) or any(
                not isinstance(value, str) for value in raw_jurisdictions
            ):
                raise ValueError("reviewed guidance jurisdictions must be strings")
            if not set(raw_jurisdictions).issubset(source.jurisdictions):
                raise ValueError(
                    f"guidance jurisdictions exceed catalog source scope for {document_id}"
                )
            expected_hash = provenance.get("content_sha256")
            actual_hash = _sha256_regular_file(Path(source_files[document_id]))
            if actual_hash != expected_hash:
                raise ValueError(
                    f"source bytes do not match content_sha256 for {document_id}"
                )
            try:
                retrieved_at = datetime.fromisoformat(provenance["retrieved_at"])
            except (KeyError, TypeError, ValueError):
                raise ValueError(
                    "reviewed guidance provenance requires retrieved_at"
                ) from None
            if retrieved_at.tzinfo is None:
                raise ValueError("provenance retrieved_at must be timezone-aware")
            if retrieved_at > checked_now + timedelta(minutes=5):
                raise ValueError("provenance retrieved_at cannot be in the future")
            last_checked_raw = raw.get("last_checked_at")
            if not isinstance(last_checked_raw, str):
                raise ValueError("reviewed guidance requires last_checked_at")
            last_checked = datetime.fromisoformat(last_checked_raw)
            if last_checked.tzinfo is None:
                raise ValueError("last_checked_at must be timezone-aware")
            if last_checked > checked_now + timedelta(minutes=5):
                raise ValueError("last_checked_at cannot be in the future")
            if retrieved_at > last_checked + timedelta(minutes=5):
                raise ValueError(
                    "provenance retrieved_at cannot be after last_checked_at"
                )
            valid_until = last_checked + timedelta(days=source.review_interval_days)
            if checked_now > valid_until:
                raise ValueError(
                    f"source review is stale for {document_id}; recheck official source"
                )
            metadata = dict(raw.get("metadata", {}))
            if _SOURCE_REVIEW_METADATA_FIELDS.intersection(metadata):
                raise ValueError("guidance metadata uses reserved source-review fields")
            metadata.update(
                {
                    "source_review_status": "audited_snapshot",
                    "source_review_catalog_id": source.source_id,
                    "source_review_reviewer_id": normalized_reviewer,
                    "source_review_risk_level": normalized_risk.value,
                    "source_review_recheck_days": str(source.review_interval_days),
                    "source_review_valid_until": valid_until.isoformat(),
                }
            )
            raw["metadata"] = metadata

        document_by_id = {
            raw["document_id"]: raw for raw in documents if isinstance(raw, dict)
        }
        for raw in payload.get("recommendations", []):
            if not isinstance(raw, dict):
                raise ValueError("guidance recommendation must be an object")
            provenance = raw.get("provenance")
            if not isinstance(provenance, dict):
                raise ValueError("guidance recommendation provenance is required")
            parent = document_by_id.get(raw.get("document_id"))
            if parent is None:
                raise ValueError(
                    "reviewed recommendation requires a reviewed parent document"
                )
            recommendation_jurisdictions = raw.get("jurisdictions", [])
            if not isinstance(recommendation_jurisdictions, list) or any(
                not isinstance(value, str) for value in recommendation_jurisdictions
            ):
                raise ValueError(
                    "reviewed recommendation jurisdictions must be strings"
                )
            if recommendation_jurisdictions and not set(
                recommendation_jurisdictions
            ).issubset(parent["jurisdictions"]):
                raise ValueError(
                    "recommendation jurisdictions exceed parent document scope"
                )
            try:
                retrieved_at = datetime.fromisoformat(provenance["retrieved_at"])
            except (KeyError, TypeError, ValueError):
                raise ValueError(
                    "reviewed recommendation provenance requires retrieved_at"
                ) from None
            if retrieved_at.tzinfo is None:
                raise ValueError(
                    "recommendation provenance retrieved_at must be timezone-aware"
                )
            if retrieved_at > checked_now + timedelta(minutes=5):
                raise ValueError(
                    "recommendation provenance retrieved_at cannot be in the future"
                )
        self._load_payload(payload, reviewed=True)

    def _load_payload(self, payload: dict[str, Any], *, reviewed: bool = False) -> None:
        self._privacy_gate.assert_public_payload({"guidance_fixture": payload})
        if set(payload) != {"documents", "relations", "recommendations"}:
            raise ValueError("guidance snapshot fields are invalid")
        if any(not isinstance(payload[field], list) for field in payload):
            raise ValueError("guidance snapshot collections must be arrays")
        self._privacy_gate.assert_public_semantic_payload(
            _fixture_semantic_payload(payload)
        )
        # One fixture is one registry snapshot mutation. The outer immediate
        # transaction prevents intermediate document/relation/recommendation
        # states from becoming visible and composes the immutable insert APIs
        # through their nested savepoints.
        with self._store.transaction(immediate=True):
            for raw in payload.get("documents", []):
                self.add_document(
                    GuidelineDocument(
                        document_id=raw["document_id"],
                        series_id=raw["series_id"],
                        title=raw["title"],
                        issuer=raw["issuer"],
                        version=raw["version"],
                        jurisdictions=tuple(raw["jurisdictions"]),
                        effective_from=date.fromisoformat(raw["effective_from"]),
                        provenance=_parse_provenance(raw["provenance"]),
                        published_on=_optional_date(raw.get("published_on")),
                        effective_until=_optional_date(raw.get("effective_until")),
                        withdrawn_on=_optional_date(raw.get("withdrawn_on")),
                        declared_status=GuidanceStatus(
                            raw.get(
                                "declared_status",
                                GuidanceStatus.CURRENT.value,
                            )
                        ),
                        status_changed_on=_optional_date(
                            raw.get("status_changed_on")
                        ),
                        last_checked_at=datetime.fromisoformat(
                            raw["last_checked_at"]
                        )
                        if raw.get("last_checked_at")
                        else None,
                        document_type=raw.get(
                            "document_type",
                            "clinical_guideline",
                        ),
                        language=raw.get("language", "en"),
                        metadata=dict(raw.get("metadata", {})),
                    ),
                    _source_review_capability=(
                        _REVIEWED_IMPORT_CAPABILITY if reviewed else None
                    ),
                )
            for raw in payload.get("relations", []):
                self.add_relation(
                    VersionRelation(
                        source_document_id=raw["source_document_id"],
                        target_document_id=raw["target_document_id"],
                        relation_type=VersionRelationType(raw["relation_type"]),
                        effective_from=date.fromisoformat(raw["effective_from"]),
                        affected_recommendation_keys=tuple(
                            raw.get("affected_recommendation_keys", [])
                        ),
                        provenance_note=raw.get("provenance_note"),
                    )
                )
            for raw in payload.get("recommendations", []):
                self.add_recommendation(
                    GuidelineRecommendation(
                        recommendation_id=raw["recommendation_id"],
                        document_id=raw["document_id"],
                        recommendation_key=raw["recommendation_key"],
                        decision_key=raw["decision_key"],
                        population_key=raw["population_key"],
                        verbatim_text=raw["verbatim_text"],
                        native_grade_system=raw["native_grade_system"],
                        native_grade=raw["native_grade"],
                        provenance=_parse_provenance(raw["provenance"]),
                        direction=RecommendationDirection(
                            raw.get(
                                "direction",
                                RecommendationDirection.UNCERTAIN.value,
                            )
                        ),
                        position_key=raw.get("position_key"),
                        native_strength=raw.get("native_strength"),
                        native_certainty=raw.get("native_certainty"),
                        applies_from=_optional_date(raw.get("applies_from")),
                        applies_until=_optional_date(raw.get("applies_until")),
                        jurisdictions=tuple(raw.get("jurisdictions", [])),
                        topic=raw.get("topic"),
                        metadata=dict(raw.get("metadata", {})),
                    )
                )
