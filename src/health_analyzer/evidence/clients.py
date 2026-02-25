"""Small public metadata clients for PubMed and Crossref.

Only deidentified, privacy-gated queries reach these clients.  The clients
return metadata and stable identifiers; they do not scrape paywalled full text.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..contracts import EvidenceItem
from .query import (
    CROSSREF_WORKS_ENDPOINT,
    PUBMED_ESEARCH_ENDPOINT,
    EvidenceQuery,
    EvidenceSourcePolicy,
    rank_evidence,
    retrieval_execution_descriptor,
)


OpenUrl = Callable[[Request, float], Any]
MAX_PUBLIC_METADATA_BYTES = 5 * 1024 * 1024
_CANONICAL_DOI = re.compile(r"10\.[0-9]{4,9}/[^\s?#]{1,480}\Z", re.ASCII)


class RemoteEvidenceError(RuntimeError):
    """A sanitized public metadata endpoint failure."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("duplicate JSON key")
        payload[key] = value
    return payload


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), parsed.port


class _SameOriginRedirectHandler(HTTPRedirectHandler):
    """Keep query strings and API credentials on the original metadata host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        target = urljoin(req.full_url, newurl)
        try:
            EvidenceSourcePolicy().assert_allowed(target)
        except ValueError:
            raise HTTPError(req.full_url, code, "redirect target denied", headers, fp) from None
        if _origin(req.full_url) != _origin(target):
            raise HTTPError(req.full_url, code, "cross-origin redirect denied", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, target)


_PUBLIC_OPENER = build_opener(_SameOriginRedirectHandler())


def _default_open(request: Request, timeout: float) -> Any:
    return _PUBLIC_OPENER.open(request, timeout=timeout)


def _read_json(opener: OpenUrl, url: str, *, timeout: float, user_agent: str) -> dict[str, Any]:
    EvidenceSourcePolicy().assert_allowed(url)
    request = Request(url, headers={"User-Agent": user_agent, "Accept": "application/json"})
    try:
        response = opener(request, timeout)
    except HTTPError as error:
        raise RemoteEvidenceError(
            f"public metadata endpoint {request.host} returned HTTP {error.code}"
        ) from None
    except URLError:
        raise RemoteEvidenceError(
            f"public metadata endpoint {request.host} is unavailable"
        ) from None
    try:
        payload = response.read(MAX_PUBLIC_METADATA_BYTES + 1)
    except (OSError, TimeoutError, ValueError):
        raise RemoteEvidenceError(
            f"public metadata endpoint {request.host} is unavailable"
        ) from None
    finally:
        close = getattr(response, "close", None)
        if close:
            close()
    if not isinstance(payload, bytes):
        raise RemoteEvidenceError(
            f"public metadata endpoint {request.host} returned an invalid response"
        )
    if len(payload) > MAX_PUBLIC_METADATA_BYTES:
        raise RemoteEvidenceError(
            f"public metadata endpoint {request.host} exceeded the response size limit"
        )
    try:
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise RemoteEvidenceError(
            f"public metadata endpoint {request.host} returned an invalid JSON response"
        ) from None
    if not isinstance(parsed, dict):
        raise RemoteEvidenceError(
            f"public metadata endpoint {request.host} returned an invalid JSON response"
        )
    return parsed


def _content_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class PubMedClient:
    base_url = PUBMED_ESEARCH_ENDPOINT.rsplit("/", 1)[0]

    def __init__(
        self,
        *,
        email: str,
        api_key: str | None = None,
        opener: OpenUrl = _default_open,
        sleeper: Callable[[float], None] = time.sleep,
        timeout: float = 20.0,
    ):
        if "@" not in email:
            raise ValueError("NCBI requests require a valid operator email")
        self.email = email
        self.api_key = api_key
        self.opener = opener
        self.sleeper = sleeper
        self.timeout = timeout
        self.last_summary_ids: tuple[str, ...] | None = None
        self.last_summary_query_id: str | None = None

    def search(self, query: EvidenceQuery) -> tuple[EvidenceItem, ...]:
        query.validate()
        planned_execution = retrieval_execution_descriptor(
            "pubmed",
            query,
            pubmed_summary_ids=(),
        )
        common = {
            "db": "pubmed",
            "retmode": "json",
            "tool": "health_analyzer",
            "email": self.email,
        }
        if self.api_key:
            common["api_key"] = self.api_key
        search_url = f"{self.base_url}/esearch.fcgi?" + urlencode(
            {**common, **planned_execution["requests"][0]["parameters"]}
        )
        search_payload = _read_json(
            self.opener,
            search_url,
            timeout=self.timeout,
            user_agent=f"health-analyzer/0.1 ({self.email})",
        )
        search_result = search_payload.get("esearchresult")
        if not isinstance(search_result, dict):
            raise RemoteEvidenceError("PubMed returned an invalid search result")
        ids = search_result.get("idlist", [])
        if (
            not isinstance(ids, list)
            or len(ids) > query.max_results
            or any(
                not isinstance(pmid, str)
                or re.fullmatch(r"[1-9][0-9]{0,15}", pmid) is None
                for pmid in ids
            )
            or len(set(ids)) != len(ids)
        ):
            raise RemoteEvidenceError("PubMed returned an invalid bounded identifier list")
        self.last_summary_ids = tuple(ids)
        self.last_summary_query_id = query.query_id
        if not ids:
            return ()
        if not self.api_key:
            self.sleeper(0.35)
        summary_url = f"{self.base_url}/esummary.fcgi?" + urlencode(
            {**common, "id": ",".join(ids), "version": "2.0"}
        )
        payload = _read_json(
            self.opener,
            summary_url,
            timeout=self.timeout,
            user_agent=f"health-analyzer/0.1 ({self.email})",
        )
        result = payload.get("result")
        if not isinstance(result, dict):
            raise RemoteEvidenceError("PubMed returned an invalid summary result")
        items: list[EvidenceItem] = []
        for pmid in ids:
            record = result.get(str(pmid))
            if not isinstance(record, dict):
                continue
            article_ids = record.get("articleids", [])
            pubtype_values = record.get("pubtype", [])
            title_value = record.get("title")
            published_value = record.get("pubdate")
            source_value = record.get("source")
            if (
                not isinstance(article_ids, list)
                or any(not isinstance(article_id, dict) for article_id in article_ids)
                or not isinstance(pubtype_values, list)
                or any(not isinstance(value, str) for value in pubtype_values)
                or title_value is not None
                and not isinstance(title_value, str)
                or published_value is not None
                and not isinstance(published_value, str)
                or source_value is not None
                and not isinstance(source_value, str)
            ):
                raise RemoteEvidenceError("PubMed returned an invalid summary record")
            identifiers = {"pmid": str(pmid)}
            for article_id in article_ids:
                identifier_type = article_id.get("idtype")
                identifier_value = article_id.get("value")
                if identifier_type and identifier_value:
                    if not isinstance(identifier_type, str) or not isinstance(
                        identifier_value, str
                    ):
                        raise RemoteEvidenceError(
                            "PubMed returned an invalid summary record"
                        )
                    identifiers[identifier_type] = identifier_value
            pubtypes = {value.casefold() for value in pubtype_values}
            if "meta-analysis" in pubtypes:
                source_type = "meta_analysis"
            elif "systematic review" in pubtypes:
                source_type = "systematic_review"
            elif "randomized controlled trial" in pubtypes:
                source_type = "randomized_trial"
            elif "practice guideline" in pubtypes or "guideline" in pubtypes:
                source_type = "clinical_guideline"
            else:
                source_type = "journal_article"
            items.append(
                EvidenceItem(
                    evidence_id=f"pmid:{pmid}",
                    title=title_value or f"PubMed {pmid}",
                    source_type=source_type,
                    url=f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/",
                    published_at=published_value or None,
                    organization=source_value or None,
                    identifiers=identifiers,
                    content_hash=_content_hash(record),
                )
            )
        return rank_evidence(items)

    def execution_descriptor(
        self,
        query: EvidenceQuery,
        *,
        summary_ids: tuple[str, ...] | None = None,
    ) -> dict[str, object]:
        resolved_ids = self.last_summary_ids if summary_ids is None else summary_ids
        if resolved_ids is None:
            raise RuntimeError("PubMed execution descriptor is available only after search")
        if summary_ids is None and self.last_summary_query_id != query.query_id:
            raise RuntimeError("PubMed execution descriptor does not match the last search")
        return retrieval_execution_descriptor(
            "pubmed",
            query,
            pubmed_summary_ids=resolved_ids,
        )


class CrossrefClient:
    base_url = CROSSREF_WORKS_ENDPOINT

    def __init__(
        self,
        *,
        email: str | None = None,
        opener: OpenUrl = _default_open,
        timeout: float = 20.0,
    ):
        self.email = email
        self.opener = opener
        self.timeout = timeout

    def search(self, query: EvidenceQuery) -> tuple[EvidenceItem, ...]:
        query.validate()
        execution = self.execution_descriptor(query)
        params = dict(execution["parameters"])
        if self.email:
            params["mailto"] = self.email
        url = self.base_url + "?" + urlencode(params)
        payload = _read_json(
            self.opener,
            url,
            timeout=self.timeout,
            user_agent=f"health-analyzer/0.1 ({self.email or 'public'})",
        )
        message = payload.get("message")
        if not isinstance(message, dict):
            raise RemoteEvidenceError("Crossref returned an invalid works result")
        records = message.get("items")
        if not isinstance(records, list) or len(records) > query.max_results:
            raise RemoteEvidenceError("Crossref returned an invalid bounded works list")
        items: list[EvidenceItem] = []
        seen_dois: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                raise RemoteEvidenceError("Crossref returned an invalid works record")
            raw_doi = record.get("DOI")
            if raw_doi is None:
                continue
            if not isinstance(raw_doi, str):
                raise RemoteEvidenceError("Crossref returned an invalid DOI")
            doi = raw_doi.casefold()
            if _CANONICAL_DOI.fullmatch(doi) is None or doi in seen_dois:
                raise RemoteEvidenceError("Crossref returned an invalid canonical DOI")
            seen_dois.add(doi)
            titles = record.get("title") or []
            if not isinstance(titles, list) or any(
                not isinstance(title, str) for title in titles
            ):
                raise RemoteEvidenceError("Crossref returned an invalid title")
            title = titles[0] if titles else doi
            published_record = record.get("published")
            if published_record is None:
                published_record = record.get("issued")
            if published_record is None:
                published_record = {}
            if not isinstance(published_record, dict):
                raise RemoteEvidenceError("Crossref returned an invalid publication date")
            date_parts = published_record.get("date-parts", [[]])
            if (
                not isinstance(date_parts, list)
                or not date_parts
                or not isinstance(date_parts[0], list)
                or len(date_parts[0]) > 3
                or any(
                    not isinstance(part, int) or isinstance(part, bool)
                    for part in date_parts[0]
                )
            ):
                raise RemoteEvidenceError("Crossref returned an invalid publication date")
            published = "-".join(str(part) for part in date_parts[0]) or None
            record_type = record.get("type")
            publisher = record.get("publisher")
            if record_type is not None and not isinstance(record_type, str):
                raise RemoteEvidenceError("Crossref returned an invalid work type")
            if publisher is not None and not isinstance(publisher, str):
                raise RemoteEvidenceError("Crossref returned an invalid publisher")
            source_type = {
                "journal-article": "journal_article",
                "proceedings-article": "conference_article",
                "book-chapter": "book_chapter",
            }.get(record_type, record_type or "metadata_record")
            items.append(
                EvidenceItem(
                    evidence_id=f"doi:{doi}",
                    title=title,
                    source_type=source_type,
                    url=f"https://doi.org/{doi}",
                    published_at=published,
                    organization=publisher or None,
                    identifiers={"doi": doi},
                    content_hash=_content_hash(record),
                )
            )
        return rank_evidence(items)

    def execution_descriptor(self, query: EvidenceQuery) -> dict[str, object]:
        return retrieval_execution_descriptor("crossref", query)
