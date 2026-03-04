"""Validated catalog and deterministic plan for on-demand guidance discovery.

The catalog contains source portals, not clinical recommendations.  It narrows
live research to known official issuers while the guidance registry remains a
versioned cache of only the documents and recommendations actually inspected.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DEFAULT_GUIDANCE_SOURCE_CATALOG = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "guidance-source-catalog.json"
)
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_CATALOG_SOURCES = 100
MAX_DISCOVERY_SOURCES = 30
MAX_DISCOVERY_DOMAINS = 12
MAX_DISCOVERY_JURISDICTIONS = 12
MAX_GUIDANCE_QUESTION_CHARS = 4_000

_SOURCE_ID = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
_TAXONOMY_KEY = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
_JURISDICTION = re.compile(r"[A-Z][A-Z0-9-]{0,15}\Z")
_HOST = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_DOMAIN_ALIASES: dict[str, tuple[str, ...]] = {
    "beauty": ("cosmetics", "dermatology"),
    "health": ("general-health",),
    "labs": ("laboratory-medicine",),
    "sports": ("sport",),
}
_JURISDICTION_ALIASES = {"USA": "US"}


class GuidanceRiskLevel(StrEnum):
    INFORMATION = "information"
    PERSONAL_CONTEXT = "personal_context"
    CLINICAL_ACTION = "clinical_action"


class SourceAccessMode(StrEnum):
    OPEN_HTML = "open_html"
    OPEN_PDF = "open_pdf"
    MIXED = "mixed"
    REGISTRATION = "registration"
    PAYWALLED = "paywalled"


def _nonempty(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    if "\0" in value:
        raise ValueError(f"{name} must not contain NUL")
    return value.strip()


def _sorted_unique(
    values: tuple[str, ...],
    *,
    name: str,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str, ...]:
    if not values:
        raise ValueError(f"{name} must not be empty")
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{name} must be sorted and unique")
    if pattern is not None and any(pattern.fullmatch(value) is None for value in values):
        raise ValueError(f"{name} contains an invalid value")
    return values


@dataclass(frozen=True, slots=True)
class GuidanceSourcePortal:
    source_id: str
    issuer: str
    authority_tier: str
    index_url: str
    canonical_hosts: tuple[str, ...]
    domains: tuple[str, ...]
    jurisdictions: tuple[str, ...]
    document_kinds: tuple[str, ...]
    status_signals: tuple[str, ...]
    languages: tuple[str, ...]
    access_mode: SourceAccessMode
    browser_fallback: bool
    review_interval_days: int
    priority: int

    def __post_init__(self) -> None:
        if _SOURCE_ID.fullmatch(self.source_id) is None:
            raise ValueError("source_id is invalid")
        _nonempty(self.issuer, name="issuer")
        if _TAXONOMY_KEY.fullmatch(self.authority_tier) is None:
            raise ValueError("authority_tier is invalid")
        _sorted_unique(
            self.canonical_hosts,
            name="canonical_hosts",
            pattern=_HOST,
        )
        _sorted_unique(self.domains, name="domains", pattern=_TAXONOMY_KEY)
        _sorted_unique(
            self.jurisdictions,
            name="jurisdictions",
            pattern=_JURISDICTION,
        )
        _sorted_unique(
            self.document_kinds,
            name="document_kinds",
            pattern=_TAXONOMY_KEY,
        )
        _sorted_unique(
            self.status_signals,
            name="status_signals",
            pattern=_TAXONOMY_KEY,
        )
        _sorted_unique(self.languages, name="languages", pattern=_TAXONOMY_KEY)
        if not isinstance(self.access_mode, SourceAccessMode):
            raise ValueError("access_mode is invalid")
        if not isinstance(self.browser_fallback, bool):
            raise ValueError("browser_fallback must be boolean")
        if type(self.review_interval_days) is not int or not (
            1 <= self.review_interval_days <= 365
        ):
            raise ValueError("review_interval_days must be between 1 and 365")
        if type(self.priority) is not int or not 1 <= self.priority <= 100:
            raise ValueError("priority must be between 1 and 100")
        if len(self.issuer) > 256:
            raise ValueError("issuer must not exceed 256 characters")

        parsed = urlsplit(self.index_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.fragment
            or parsed.hostname.casefold() not in self.canonical_hosts
        ):
            raise ValueError("index_url must be canonical HTTPS on an allowlisted host")

    def matches(
        self,
        *,
        domains: frozenset[str],
        jurisdictions: frozenset[str],
    ) -> bool:
        domain_match = "all" in self.domains or bool(domains.intersection(self.domains))
        jurisdiction_match = "GLOBAL" in self.jurisdictions or bool(
            jurisdictions.intersection(self.jurisdictions)
        )
        return domain_match and jurisdiction_match


@dataclass(frozen=True, slots=True)
class GuidanceDiscoveryPlan:
    question: str
    domains: tuple[str, ...]
    unmapped_domains: tuple[str, ...]
    jurisdictions: tuple[str, ...]
    unmapped_jurisdictions: tuple[str, ...]
    uncovered_scopes: tuple[str, ...]
    risk_level: GuidanceRiskLevel
    sources: tuple[GuidanceSourcePortal, ...]
    source_review_passes: int
    requires_registry_snapshot: bool
    requires_clinician_confirmation: bool
    recheck_after_days: int
    required_checks: tuple[str, ...]
    browser_policy: str
    cache_policy: str


class GuidanceSourceCatalog:
    def __init__(self, sources: tuple[GuidanceSourcePortal, ...]) -> None:
        if not sources:
            raise ValueError("guidance source catalog must not be empty")
        if tuple(sorted(sources, key=lambda item: item.source_id)) != sources:
            raise ValueError("guidance sources must be sorted by source_id")
        identifiers = [source.source_id for source in sources]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("guidance source IDs must be unique")
        self.sources = sources
        self._by_id = {source.source_id: source for source in sources}
        self.domains = frozenset(
            domain
            for source in sources
            for domain in source.domains
        )
        self.jurisdictions = frozenset(
            jurisdiction
            for source in sources
            for jurisdiction in source.jurisdictions
            if jurisdiction != "GLOBAL"
        )

    def require_source_url(
        self,
        *,
        source_id: str,
        canonical_url: str,
    ) -> GuidanceSourcePortal:
        """Bind an inspected document URL to one explicit catalog issuer."""

        source = self._by_id.get(source_id)
        if source is None:
            raise ValueError(f"unknown guidance source_id: {source_id}")
        parsed = urlsplit(canonical_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.fragment
            or parsed.hostname.casefold() not in source.canonical_hosts
        ):
            raise ValueError(
                "guidance document URL must use an allowlisted canonical host "
                f"for {source_id}"
            )
        return source

    @classmethod
    def load(
        cls,
        path: str | Path = DEFAULT_GUIDANCE_SOURCE_CATALOG,
    ) -> GuidanceSourceCatalog:
        payload = _read_catalog(Path(path))
        if set(payload) != {"schema_version", "sources"}:
            raise ValueError("guidance source catalog fields are invalid")
        if payload["schema_version"] != "1.0":
            raise ValueError("guidance source catalog schema is unsupported")
        raw_sources = payload["sources"]
        if not isinstance(raw_sources, list):
            raise ValueError("guidance source catalog sources must be an array")
        if not 1 <= len(raw_sources) <= MAX_CATALOG_SOURCES:
            raise ValueError(
                f"guidance source catalog must contain 1 to {MAX_CATALOG_SOURCES} sources"
            )
        return cls(tuple(_parse_source(raw) for raw in raw_sources))

    def plan(
        self,
        *,
        question: str,
        domains: tuple[str, ...],
        jurisdictions: tuple[str, ...] = ("GLOBAL",),
        risk_level: GuidanceRiskLevel = GuidanceRiskLevel.INFORMATION,
        max_sources: int = 12,
    ) -> GuidanceDiscoveryPlan:
        normalized_question = _nonempty(question, name="question")
        if len(normalized_question) > MAX_GUIDANCE_QUESTION_CHARS:
            raise ValueError(
                f"question must not exceed {MAX_GUIDANCE_QUESTION_CHARS} characters"
            )
        requested_domains = _sorted_unique(
            domains,
            name="domains",
            pattern=_TAXONOMY_KEY,
        )
        if len(requested_domains) > MAX_DISCOVERY_DOMAINS:
            raise ValueError(
                f"domains must contain at most {MAX_DISCOVERY_DOMAINS} values"
            )
        normalized_domains = tuple(
            sorted(
                {
                    canonical
                    for requested in requested_domains
                    for canonical in _DOMAIN_ALIASES.get(requested, (requested,))
                }
            )
        )
        unmapped_domains = tuple(
            sorted(set(normalized_domains).difference(self.domains))
        )
        requested_jurisdictions = _sorted_unique(
            jurisdictions,
            name="jurisdictions",
            pattern=_JURISDICTION,
        )
        normalized_jurisdictions = tuple(
            sorted(
                {
                    _JURISDICTION_ALIASES.get(value, value)
                    for value in requested_jurisdictions
                }
            )
        )
        if len(normalized_jurisdictions) > MAX_DISCOVERY_JURISDICTIONS:
            raise ValueError(
                "jurisdictions must contain at most "
                f"{MAX_DISCOVERY_JURISDICTIONS} values"
            )
        unmapped_jurisdictions = tuple(
            sorted(
                jurisdiction
                for jurisdiction in normalized_jurisdictions
                if jurisdiction != "GLOBAL" and jurisdiction not in self.jurisdictions
            )
        )
        try:
            normalized_risk = GuidanceRiskLevel(risk_level)
        except (TypeError, ValueError):
            raise ValueError("risk_level is unsupported") from None
        if type(max_sources) is not int or not 1 <= max_sources <= MAX_DISCOVERY_SOURCES:
            raise ValueError(
                f"max_sources must be between 1 and {MAX_DISCOVERY_SOURCES}"
            )

        candidates = [
            source
            for source in self.sources
            if source.matches(
                domains=frozenset(normalized_domains),
                jurisdictions=frozenset(normalized_jurisdictions),
            )
        ]
        candidates.sort(key=lambda item: (item.priority, item.source_id))
        if not candidates:
            raise ValueError("no official guidance source matches the requested scope")

        # Broad portals are useful discovery fallbacks, but cannot silently replace
        # a profile issuer.  Reserve one explicit-domain source for every mapped
        # domain before filling remaining slots by global priority.
        mapped_domains = {
            domain for domain in normalized_domains if domain not in unmapped_domains
        }
        specific_jurisdictions = {
            jurisdiction
            for jurisdiction in normalized_jurisdictions
            if jurisdiction != "GLOBAL"
        }
        uncovered_scopes = tuple(
            sorted(
                f"{domain}@{jurisdiction}"
                for domain in mapped_domains
                for jurisdiction in specific_jurisdictions
                if not any(
                    domain in source.domains
                    and jurisdiction in source.jurisdictions
                    for source in candidates
                )
            )
        )
        coverable_scopes = {
            (domain, jurisdiction)
            for domain in mapped_domains
            for jurisdiction in specific_jurisdictions
            if f"{domain}@{jurisdiction}" not in uncovered_scopes
        }
        coverable_domains = {
            domain
            for domain in mapped_domains
            if any(domain in source.domains for source in candidates)
        }
        uncovered_domain_scopes = tuple(
            sorted(
                f"{domain}@{'-'.join(normalized_jurisdictions)}"
                for domain in mapped_domains.difference(coverable_domains)
            )
        )
        uncovered_scopes = tuple(
            sorted(set(uncovered_scopes).union(uncovered_domain_scopes))
        )
        uncovered_domains_for_selection = set(coverable_domains)
        uncovered_scope_pairs = set(coverable_scopes)
        required_items: list[GuidanceSourcePortal] = []
        while uncovered_domains_for_selection or uncovered_scope_pairs:
            covering = [
                (
                    len(uncovered_domains_for_selection.intersection(source.domains))
                    + sum(
                        domain in source.domains
                        and jurisdiction in source.jurisdictions
                        for domain, jurisdiction in uncovered_scope_pairs
                    ),
                    source,
                )
                for source in candidates
            ]
            score, source = min(
                covering,
                key=lambda item: (-item[0], item[1].priority, item[1].source_id),
            )
            if score == 0:
                break
            required_items.append(source)
            uncovered_domains_for_selection.difference_update(source.domains)
            uncovered_scope_pairs = {
                (domain, jurisdiction)
                for domain, jurisdiction in uncovered_scope_pairs
                if not (
                    domain in source.domains
                    and jurisdiction in source.jurisdictions
                )
            }

        required = tuple(dict.fromkeys(required_items))
        if len(required) > max_sources:
            raise ValueError(
                "max_sources is too small to cover every mapped domain and jurisdiction"
            )
        selected_ids = {source.source_id for source in required}
        for source in candidates:
            if len(selected_ids) >= max_sources:
                break
            if source.source_id not in selected_ids:
                selected_ids.add(source.source_id)
        selected = tuple(
            source for source in candidates if source.source_id in selected_ids
        )

        audited = normalized_risk is not GuidanceRiskLevel.INFORMATION
        return GuidanceDiscoveryPlan(
            question=normalized_question,
            domains=normalized_domains,
            unmapped_domains=unmapped_domains,
            jurisdictions=normalized_jurisdictions,
            unmapped_jurisdictions=unmapped_jurisdictions,
            uncovered_scopes=uncovered_scopes,
            risk_level=normalized_risk,
            sources=selected,
            source_review_passes=2 if audited else 1,
            requires_registry_snapshot=audited,
            requires_clinician_confirmation=(
                normalized_risk is GuidanceRiskLevel.CLINICAL_ACTION
            ),
            recheck_after_days=min(source.review_interval_days for source in selected),
            required_checks=(
                *((
                    "identify and verify a canonical specialist issuer for each unmapped domain",
                ) if unmapped_domains else ()),
                *((
                    "identify and verify the competent national authority for each unmapped jurisdiction",
                ) if unmapped_jurisdictions else ()),
                *((
                    "identify and verify a profile authority for each uncovered domain-jurisdiction scope",
                ) if uncovered_scopes else ()),
                "canonical issuer and stable document identifier",
                "publication, update, and effective dates",
                "draft, current, withdrawn, superseded, amendment, and correction status",
                "jurisdiction, population, intervention, comparator, outcomes, and harms",
                "verbatim recommendation, exact locator, and native grading system",
                "content hash when a registry snapshot is required",
            ),
            browser_policy=(
                "Use direct official HTTPS pages first. Use Chrome only when an official "
                "page requires JavaScript or an existing login; never place private case "
                "data or direct identifiers in browser queries."
            ),
            cache_policy=(
                "Do not mirror the portal. Cache only source-reviewed documents and "
                "recommendations used by the answer; recheck status before reuse and "
                "preserve version relations plus the exact source hash."
            ),
        )


def _read_catalog(path: Path) -> dict[str, Any]:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not no_follow:
        raise RuntimeError("this platform cannot enforce no-follow catalog reads")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        raise ValueError("guidance source catalog is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_CATALOG_BYTES:
            raise ValueError("guidance source catalog must be a bounded regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_CATALOG_BYTES + 1)
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
        raise ValueError("guidance source catalog changed while being read")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("guidance source catalog is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("guidance source catalog must be an object")
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in guidance catalog: {key}")
        result[key] = value
    return result


def _string_tuple(raw: Any, *, name: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or any(not isinstance(value, str) for value in raw):
        raise ValueError(f"{name} must be an array of strings")
    return tuple(raw)


def _parse_source(raw: Any) -> GuidanceSourcePortal:
    if not isinstance(raw, dict):
        raise ValueError("guidance source entry must be an object")
    expected = {
        "access_mode",
        "authority_tier",
        "browser_fallback",
        "canonical_hosts",
        "document_kinds",
        "domains",
        "index_url",
        "issuer",
        "jurisdictions",
        "languages",
        "priority",
        "review_interval_days",
        "source_id",
        "status_signals",
    }
    if set(raw) != expected:
        raise ValueError("guidance source entry fields are invalid")
    try:
        access_mode = SourceAccessMode(raw["access_mode"])
    except (TypeError, ValueError):
        raise ValueError("guidance source access_mode is unsupported") from None
    return GuidanceSourcePortal(
        source_id=raw["source_id"],
        issuer=raw["issuer"],
        authority_tier=raw["authority_tier"],
        index_url=raw["index_url"],
        canonical_hosts=_string_tuple(raw["canonical_hosts"], name="canonical_hosts"),
        domains=_string_tuple(raw["domains"], name="domains"),
        jurisdictions=_string_tuple(raw["jurisdictions"], name="jurisdictions"),
        document_kinds=_string_tuple(raw["document_kinds"], name="document_kinds"),
        status_signals=_string_tuple(raw["status_signals"], name="status_signals"),
        languages=_string_tuple(raw["languages"], name="languages"),
        access_mode=access_mode,
        browser_fallback=raw["browser_fallback"],
        review_interval_days=raw["review_interval_days"],
        priority=raw["priority"],
    )


__all__ = [
    "DEFAULT_GUIDANCE_SOURCE_CATALOG",
    "GuidanceDiscoveryPlan",
    "GuidanceRiskLevel",
    "GuidanceSourceCatalog",
    "GuidanceSourcePortal",
    "SourceAccessMode",
]
