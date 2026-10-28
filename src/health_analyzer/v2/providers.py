"""Official PubMed E-utilities only; stdlib, bounded HTTPS, no URL fetch tool."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from typing import Protocol
from urllib.parse import urlencode
import xml.etree.ElementTree as ET

from .common import V2Error, require, utc_now
from .research import public_request_guard

NCBI_HOST = "eutils.ncbi.nlm.nih.gov"
NCBI_PATH = "/entrez/eutils/"
MAX_HTTP_BYTES = 1024 * 1024
MAX_ABSTRACT_BYTES = 64 * 1024
_RATE_LOCK = threading.Lock()
_LAST_REQUEST = 0.0


@dataclass(frozen=True)
class HTTPResponse:
    body: bytes
    content_type: str
    requested_url: str
    received_at: str


@dataclass(frozen=True)
class FetchedAbstract:
    pmid: str
    xml_bytes: bytes
    abstract_text: str
    sections: tuple[dict, ...]
    requested_url: str
    fetched_at: str
    doi: str | None = None
    publication_notices: tuple[dict, ...] = ()


class PublicTransport(Protocol):
    def request(self, endpoint: str, parameters: dict[str, str]) -> HTTPResponse: ...


def _pmid(value: str) -> str:
    require(isinstance(value, str) and bool(re.fullmatch(r"[1-9][0-9]{0,11}", value)), "invalid_pmid", "Expected one numeric PMID")
    return value


class _PublicNCBIConnection(http.client.HTTPSConnection):
    """Resolve once, reject private addresses, and TLS-verify the fixed hostname."""

    def connect(self) -> None:
        require(self.host == NCBI_HOST and self.port == 443 and self._tunnel_host is None,
                "provider_endpoint_denied", "Only the official NCBI HTTPS endpoint is allowed")
        started = time.monotonic()
        addresses = socket.getaddrinfo(NCBI_HOST, 443, type=socket.SOCK_STREAM)
        require(bool(addresses) and len(addresses) <= 16, "provider_dns_invalid", "Unexpected NCBI DNS result")
        require(all(ipaddress.ip_address(a[4][0].split("%", 1)[0]).is_global for a in addresses),
                "provider_dns_denied", "NCBI DNS returned a non-public address")
        last_error = None
        for family, kind, protocol, _, address in addresses:
            remaining = self.timeout - (time.monotonic() - started)
            require(remaining > 0, "provider_connection_timeout", "NCBI connection deadline expired")
            raw_socket = socket.socket(family, kind, protocol)
            raw_socket.settimeout(remaining)
            try:
                raw_socket.connect(address)
                remaining = self.timeout - (time.monotonic() - started)
                require(remaining > 0, "provider_connection_timeout", "NCBI TLS deadline expired")
                raw_socket.settimeout(remaining)
                self.sock = self._context.wrap_socket(raw_socket, server_hostname=NCBI_HOST)
                self.sock.settimeout(self.timeout)
                return
            except V2Error:
                raw_socket.close()
                raise
            except OSError as exc:
                raw_socket.close()
                last_error = exc
        raise V2Error("provider_connection_failed", "Could not establish verified NCBI HTTPS") from last_error


class NCBITransport:
    """Fixed endpoint/parameters, no proxy, redirects, API keys or implicit email.

    The process-wide request interval is one second. Retries are limited to two
    for transient status/connection errors. DNS addresses are pinned per socket;
    redirects are rejected rather than followed to a different host.
    """

    ENDPOINT_FIELDS = {
        "esearch.fcgi": {"db", "term", "retstart", "retmax", "sort", "retmode"},
        "esummary.fcgi": {"db", "id", "retmode", "version"},
        "efetch.fcgi": {"db", "id", "retmode"},
    }

    def __init__(self, *, timeout: float = 10.0, retries: int = 2):
        require(isinstance(timeout, (int, float)) and 1 <= timeout <= 15 and type(retries) is int and 0 <= retries <= 2,
                "provider_configuration_invalid", "Invalid NCBI timeout/retry limits")
        self.timeout, self.retries = timeout, retries

    @staticmethod
    def _pace() -> None:
        global _LAST_REQUEST
        with _RATE_LOCK:
            wait = 1.0 - (time.monotonic() - _LAST_REQUEST)
            if wait > 0:
                time.sleep(wait)
            _LAST_REQUEST = time.monotonic()

    def request(self, endpoint: str, parameters: dict[str, str]) -> HTTPResponse:
        require(endpoint in self.ENDPOINT_FIELDS and isinstance(parameters, dict) and set(parameters) <= self.ENDPOINT_FIELDS[endpoint],
                "provider_endpoint_denied", "Unsupported NCBI endpoint or parameter")
        require(parameters.get("db") == "pubmed" and all(isinstance(v, str) and len(v) <= 4000 for v in parameters.values()),
                "provider_request_invalid", "Only bounded public PubMed parameters are allowed")
        public_request_guard(parameters)
        parameters = {**parameters, "tool": "health-analyzer-v2"}
        path = NCBI_PATH + endpoint + "?" + urlencode(parameters)
        require(len(path) <= 16384, "provider_request_limit", "Encoded NCBI request exceeds the URL bound")
        requested_url = "https://" + NCBI_HOST + path
        for attempt in range(self.retries + 1):
            self._pace()
            connection = _PublicNCBIConnection(NCBI_HOST, timeout=self.timeout, context=ssl.create_default_context())
            def abort() -> None:
                active_socket = connection.sock
                if active_socket is not None:
                    try:
                        active_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                connection.close()
            timer = threading.Timer(self.timeout, abort)
            timer.daemon = True
            timer.start()
            retry_delay = None
            try:
                connection.request("GET", path, headers={"Accept": "application/json, application/xml, text/xml", "User-Agent": "HealthAnalyzer/2.0 (public research)", "Accept-Encoding": "identity"})
                response = connection.getresponse()
                require(not 300 <= response.status < 400, "provider_redirect_denied", "NCBI redirects are not followed")
                if response.status == 429 and attempt == self.retries:
                    raise V2Error("provider_rate_limited", "NCBI rate limit requires a later request")
                if response.status in {429, 500, 502, 503, 504} and attempt < self.retries:
                    value = response.getheader("Retry-After", "")
                    if not value:
                        retry_delay = attempt + 1
                    elif value.isdigit():
                        retry_delay = max(1, int(value))
                    else:
                        try:
                            requested = parsedate_to_datetime(value)
                            require(requested.tzinfo is not None, "provider_rate_limited", "Invalid NCBI Retry-After date; retry later")
                            retry_delay = max(1, (requested - datetime.now(timezone.utc)).total_seconds())
                        except (ValueError, TypeError, OverflowError) as exc:
                            raise V2Error("provider_rate_limited", "Invalid NCBI Retry-After; retry later") from exc
                    require(retry_delay <= 5, "provider_rate_limited", "NCBI requested a wait beyond the automatic retry budget; retry later")
                else:
                    require(response.status == 200, "provider_http_error", f"NCBI returned HTTP {response.status}")
                    length = response.getheader("Content-Length")
                    require(length is None or (length.isdigit() and int(length) <= MAX_HTTP_BYTES), "provider_response_limit", "NCBI response exceeds 1 MiB")
                    body = response.read(MAX_HTTP_BYTES + 1)
                    require(len(body) <= MAX_HTTP_BYTES, "provider_response_limit", "NCBI response exceeds 1 MiB")
                    content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower()
                    require(content_type in {"application/json", "application/xml", "text/xml"}, "provider_content_type", "Unexpected NCBI response type")
                    return HTTPResponse(body, content_type, requested_url, utc_now())
            except V2Error:
                raise
            except (OSError, http.client.HTTPException) as exc:
                if attempt == self.retries:
                    raise V2Error("provider_network_error", "NCBI HTTPS request failed within its retry limit") from exc
                retry_delay = attempt + 1
            finally:
                timer.cancel()
                connection.close()
            if retry_delay is not None:
                time.sleep(retry_delay)
        raise V2Error("provider_network_error", "NCBI request did not complete")


def _json(response: HTTPResponse) -> dict:
    require(response.content_type == "application/json" and len(response.body) <= MAX_HTTP_BYTES, "provider_response_invalid", "Expected bounded JSON")
    try:
        payload = json.loads(response.body)
    except (ValueError, UnicodeError) as exc:
        raise V2Error("provider_response_invalid", "Invalid NCBI JSON") from exc
    require(isinstance(payload, dict) and "error" not in payload, "provider_api_error", "NCBI returned an API error")
    return payload


class PubMedProvider:
    name = "pubmed-eutilities-v2"

    def __init__(self, transport: PublicTransport | None = None):
        self.transport = transport if transport is not None else NCBITransport()

    def search(self, *, query: str, offset: int, page_size: int, sort: str) -> dict:
        require(isinstance(query, str) and 0 < len(query) <= 4000, "provider_request_invalid", "Invalid public query")
        public_request_guard({"query": query})
        require(type(offset) is int and type(page_size) is int and 0 <= offset and 1 <= page_size <= 50 and offset + page_size <= 10000,
                "provider_request_invalid", "PubMed page must be within its first 10,000 records")
        require(sort in {"relevance", "publication_date"}, "provider_request_invalid", "Unsupported PubMed sort")
        search_reply = self.transport.request("esearch.fcgi", {"db": "pubmed", "term": query, "retstart": str(offset), "retmax": str(page_size),
                                                               "sort": "relevance" if sort == "relevance" else "pub_date", "retmode": "json"})
        result = _json(search_reply).get("esearchresult")
        require(isinstance(result, dict) and "ERROR" not in result, "provider_response_invalid", "Missing ESearch result")
        ids = result.get("idlist")
        require(isinstance(ids, list) and len(ids) <= page_size and len(set(ids)) == len(ids), "provider_response_invalid", "Invalid ESearch PMID page")
        ids = [_pmid(pmid) for pmid in ids]
        count = result.get("count")
        require(isinstance(count, str) and count.isdigit(), "provider_response_invalid", "Invalid PubMed total count")
        total = int(count)
        require(offset + len(ids) <= total and (bool(ids) or offset >= total), "provider_response_invalid", "Inconsistent PubMed total/page")
        warnings = result.get("warninglist", {})
        errors = result.get("errorlist", {})
        require(isinstance(warnings, dict) and isinstance(errors, dict), "provider_response_invalid", "Invalid ESearch notices")
        require(not any(errors.values()), "provider_query_error", "NCBI rejected a query field or phrase; revise the explicit query")
        notices = []
        for group in (warnings, errors):
            for key, value in group.items():
                require(isinstance(key, str) and isinstance(value, list) and all(isinstance(v, str) and len(v) <= 4000 for v in value), "provider_response_invalid", "Invalid ESearch notice")
                notices.extend(f"{key}: {v}" for v in value)
        require(len(notices) <= 100, "provider_response_limit", "Too many ESearch notices")
        items = []
        summary_digest = None
        if ids:
            summary_reply = self.transport.request("esummary.fcgi", {"db": "pubmed", "id": ",".join(ids), "retmode": "json", "version": "2.0"})
            summary = _json(summary_reply).get("result")
            summary_ids = summary.get("uids") if isinstance(summary, dict) else None
            require(isinstance(summary_ids, list) and len(summary_ids) == len(ids) and set(summary_ids) == set(ids), "provider_response_invalid", "ESummary identifiers do not match the executed page")
            for pmid in ids:
                metadata = summary.get(pmid)
                require(isinstance(metadata, dict) and str(metadata.get("uid")) == pmid and isinstance(metadata.get("title"), str), "provider_response_invalid", "Invalid PubMed summary")
                article_ids = metadata.get("articleids", [])
                require(isinstance(article_ids, list) and all(isinstance(item, dict) for item in article_ids), "provider_response_invalid", "Invalid article identifiers")
                dois = [item.get("value") for item in article_ids if item.get("idtype") == "doi"]
                pubtypes = metadata.get("pubtype", [])
                require(isinstance(pubtypes, list) and all(isinstance(t, str) for t in pubtypes), "provider_response_invalid", "Invalid publication types")
                items.append({"pmid": pmid, "doi": dois[0] if dois else None, "title": metadata["title"], "url": f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/",
                              "publication_date": metadata.get("pubdate") or None, "design": "; ".join(pubtypes) or "unknown", "classification_basis": "PubMed publication type metadata; not quality or design adjudication"})
            summary_digest = hashlib.sha256(summary_reply.body).hexdigest()
        translation = result.get("querytranslation", query)
        require(isinstance(translation, str) and len(translation) <= 16000, "provider_response_invalid", "Invalid query translation")
        return {"items": items, "total": total, "cursor_exhausted": offset + len(ids) >= total,
                "provider_receipt": {"query_translation": translation, "notices": notices, "search_response_sha256": hashlib.sha256(search_reply.body).hexdigest(),
                                     "summary_response_sha256": summary_digest, "retrieved_at": search_reply.received_at, "metadata_only": True, "pubmed_retrieval_ceiling": 10000}}

    def fetch_abstract(self, pmid: str) -> FetchedAbstract:
        pmid = _pmid(pmid)
        response = self.transport.request("efetch.fcgi", {"db": "pubmed", "id": pmid, "retmode": "xml"})
        require(response.content_type in {"application/xml", "text/xml"} and len(response.body) <= MAX_HTTP_BYTES, "provider_response_invalid", "Expected bounded PubMed XML")
        require(not re.search(br"<!ENTITY|<!DOCTYPE[^>]*\[", response.body, re.I), "provider_xml_denied", "XML entity declarations/internal DTD subsets are not allowed")
        try:
            tree = ET.fromstring(response.body)
        except ET.ParseError as exc:
            raise V2Error("provider_response_invalid", "Invalid PubMed XML") from exc
        require(tree.tag == "PubmedArticleSet" and len(list(tree.iter())) <= 20000, "provider_response_invalid", "Unexpected or oversized PubMed XML tree")
        records = list(tree)
        require(len(records) == 1 and records[0].tag in {"PubmedArticle", "PubmedBookArticle"}, "provider_identity_mismatch", "EFetch must return exactly the requested public record")
        identity = records[0].find("./MedlineCitation/PMID") if records[0].tag == "PubmedArticle" else records[0].find("./BookDocument/PMID")
        require(identity is not None and identity.text == pmid, "provider_identity_mismatch", "Fetched PMID differs from the requested source")
        base = "./MedlineCitation/Article/Abstract/AbstractText" if records[0].tag == "PubmedArticle" else "./BookDocument/Abstract/AbstractText"
        sections = []
        for index, node in enumerate(records[0].findall(base), start=1):
            text = "".join(node.itertext()).strip()
            if not text:
                continue
            label = node.get("Label") or node.get("NlmCategory") or None
            require(label is None or len(label) <= 1000, "provider_response_limit", "Abstract label exceeds its bound")
            sections.append({"label": label, "text": text, "locator": f"PMID {pmid}, AbstractText[{index}]"})
        require(len(sections) <= 100, "provider_response_limit", "Too many abstract sections")
        abstract = "\n\n".join((f"{s['label']}: " if s["label"] else "") + s["text"] for s in sections)
        require(len(abstract.encode()) <= MAX_ABSTRACT_BYTES, "provider_response_limit", "Abstract exceeds 64 KiB")
        doi_path = "./PubmedData/ArticleIdList/ArticleId[@IdType='doi']" if records[0].tag == "PubmedArticle" else "./PubmedBookData/ArticleIdList/ArticleId[@IdType='doi']"
        doi_nodes = records[0].findall(doi_path)
        doi = doi_nodes[0].text.lower().strip() if doi_nodes and doi_nodes[0].text else None
        notices = []
        notice_path = "./MedlineCitation/CommentsCorrectionsList/CommentsCorrections" if records[0].tag == "PubmedArticle" else "./BookDocument/CommentsCorrectionsList/CommentsCorrections"
        for item in records[0].findall(notice_path):
            relation = item.get("RefType")
            node = item.find("PMID")
            linked_pmid = _pmid(node.text) if node is not None and node.text else None
            node = item.find("RefSource")
            reference = "".join(node.itertext()).strip() if node is not None else None
            require(isinstance(relation, str) and 0 < len(relation) <= 100 and (reference is None or len(reference) <= 4000),
                    "provider_response_invalid", "Invalid PubMed correction/comment notice")
            notices.append({"ref_type": relation, "pmid": linked_pmid, "ref_source": reference,
                            "url": f"https://pubmed.ncbi.nlm.nih.gov/{linked_pmid}/" if linked_pmid else None, "content_review_status": "not_reviewed"})
        require(len(notices) <= 100, "provider_response_limit", "Too many linked publication notices")
        return FetchedAbstract(pmid, response.body, abstract, tuple(sections), response.requested_url, response.received_at, doi, tuple(notices))
