"""Bounded public evidence records; no implicit network or article verification.

The provider boundary is injected by the deployment, never selected by an MCP
argument.  The default service deliberately cannot execute a live search.
"""
from __future__ import annotations

import base64
from datetime import date
import hashlib
import ipaddress
import re
from typing import Any, Protocol
from urllib.parse import urlsplit

from .common import SignedStore, V2Error, canonical, digest, new_id, require, utc_now

QUESTION_TYPES = {"intervention", "harms", "diagnosis", "prognosis", "etiology", "prevalence", "mechanism", "guideline_comparison"}
INTENTS = {"education", "research", "personal_interpretation", "clinical_action"}
DEPTHS = {"quick", "focused", "broad"}
EXTENTS = {"metadata", "abstract", "selected_sections", "complete_text", "unknown"}
FINDING_KINDS = {"benefit", "harm", "null", "mechanism", "recommendation", "certainty"}


class SearchProvider(Protocol):
    """An explicitly installed public-only metadata adapter, not a model tool."""

    name: str

    def search(self, *, query: str, offset: int, page_size: int, sort: str) -> dict: ...


def _object(value: Any, allowed: set[str], *, required: set[str] = frozenset()) -> dict:
    require(isinstance(value, dict), "invalid_input", "Expected a JSON object")
    require(set(value) <= allowed, "unknown_field", f"Unsupported fields: {sorted(set(value) - allowed)}")
    require(required <= set(value), "missing_field", f"Missing fields: {sorted(required - set(value))}")
    return value


def _text(value: Any, name: str, limit: int = 4000, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    require(isinstance(value, str) and bool(value.strip()) and len(value) <= limit, "invalid_input", f"Invalid {name}")
    return value.strip()


def public_request_guard(value: dict) -> None:
    """Defense in depth only: this does not identify every personal identifier."""
    text = canonical(value).decode("utf-8")
    forbidden = r"(?:/Users/|/home/|file://|[A-Za-z]:\\\\|case(?:packet|_id)|subject_id|medical_record_id|patient_id|date_of_birth|birth_date|\bDOB\b|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})"
    require(not re.search(forbidden, text, re.I), "private_payload_rejected", "Public research input contains a private field or identifier")
    private_id = r"\b(?:observation|revision|document|version|snapshot|context|case)_[a-f0-9]{32,64}\b"
    require(not re.search(private_id, text, re.I), "private_payload_rejected", "Public research input contains a private v2 record identifier")
    require(not re.search(r"(?:\+\d[\d ()-]{8,}\d)", text), "private_payload_rejected", "Contact-like input is not allowed in public research")


def _public_url(value: Any) -> str:
    url = _text(value, "public URL", 2048)
    try:
        parts = urlsplit(url)
        host = parts.hostname
        require(parts.scheme in {"https", "http"} and bool(host) and not parts.username and not parts.password,
                "invalid_public_url", "Expected a public HTTP(S) URL without credentials")
        require(host not in {"localhost", "localhost.localdomain"} and not host.endswith((".local", ".localhost", ".internal")),
                "invalid_public_url", "Local hostnames are not public sources")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        require(address is None or address.is_global, "invalid_public_url", "Non-public IP addresses are not allowed")
        require(address is not None or not re.fullmatch(r"[0-9.]+|0x[0-9a-f]+", host, re.I),
                "invalid_public_url", "Ambiguous numeric hostnames are not public sources")
        # Validate malformed ports even though this module never fetches URLs.
        _ = parts.port
    except (ValueError, TypeError) as exc:
        raise V2Error("invalid_public_url", "Malformed public URL") from exc
    return url


class ScientificResearchService:
    def __init__(self, store: SignedStore, provider: SearchProvider | None = None):
        require(store.domain == "public-research", "wrong_domain", "Scientific evidence requires the public-research store")
        self.store = store
        self.provider = provider

    def create_plan(self, request: dict) -> dict:
        allowed = {"question", "intent", "question_type", "depth", "population", "intervention", "exposure", "comparator", "outcome", "jurisdiction", "as_of", "constraints", "strategies", "budget"}
        _object(request, allowed, required={"question"})
        public_request_guard(request)
        question = _text(request["question"], "question")
        intent, depth = request.get("intent", "education"), request.get("depth", "focused")
        question_type = request.get("question_type", "intervention")
        require(intent in INTENTS and depth in DEPTHS and question_type in QUESTION_TYPES, "invalid_input", "Unknown research intent, depth or question type")
        cleaned = {"question": question, "intent": intent, "depth": depth, "question_type": question_type}
        for field in ("population", "intervention", "exposure", "comparator", "outcome", "jurisdiction"):
            cleaned[field] = _text(request.get(field), field, 1000, optional=True)
        as_of = request.get("as_of")
        if as_of is not None:
            try:
                require(isinstance(as_of, str) and date.fromisoformat(as_of).isoformat() == as_of, "invalid_input", "as_of must be an ISO date")
            except ValueError as exc:
                raise V2Error("invalid_input", "as_of must be an ISO date") from exc
        cleaned["as_of"] = as_of
        constraints = request.get("constraints", [])
        require(isinstance(constraints, list) and len(constraints) <= 20, "invalid_input", "At most 20 constraints are allowed")
        cleaned["constraints"] = [_text(item, "constraint", 1000) for item in constraints]
        defaults = {"quick": (100, 2), "focused": (250, 5), "broad": (500, 10)}[depth]
        budget = request.get("budget", {})
        _object(budget, {"page_size", "max_records", "max_pages"})
        limits = {"page_size": budget.get("page_size", 50), "max_records": budget.get("max_records", defaults[0]), "max_pages": budget.get("max_pages", defaults[1])}
        for field, maximum in (("page_size", 50), ("max_records", 2000), ("max_pages", 40)):
            require(type(limits[field]) is int and 1 <= limits[field] <= maximum, "invalid_budget", f"{field} must be within 1..{maximum}")
        strategies = request.get("strategies")
        if strategies is None:
            concepts = [cleaned[k] for k in ("population", "intervention", "exposure") if cleaned[k]]
            query = " AND ".join(f'"{term.replace(chr(34), chr(32))}"' for term in concepts) if concepts else question
            strategies = [{"query": query, "sort": "relevance", "reason": "Initial explicit concepts; no mandatory comparator/outcome or design filter"}]
        require(isinstance(strategies, list) and 1 <= len(strategies) <= 10, "invalid_input", "One to ten explicit strategies are required")
        checked = []
        for strategy in strategies:
            _object(strategy, {"query", "sort", "reason", "filters"}, required={"query", "reason"})
            sort = strategy.get("sort", "relevance")
            require(sort in {"relevance", "publication_date"}, "invalid_input", "Unknown sort")
            filters = strategy.get("filters", [])
            require(isinstance(filters, list) and len(filters) <= 20, "invalid_input", "Invalid explicit filters")
            checked.append({"query": _text(strategy["query"], "query"), "sort": sort, "reason": _text(strategy["reason"], "reason", 1000),
                            "filters": [{"requested": _text(f, "filter", 200), "status": "filter_not_applied", "reason": "No filter adapter is installed; include explicit syntax in query and screen returned metadata"} for f in filters]})
        plan = {"schema_version": "2.0", "plan_id": new_id("plan"), "created_at": utc_now(), "request": cleaned, "strategies": checked, "budget": limits,
                "stop_rule": "provider_exhausted_or_budget_or_error", "provider": getattr(self.provider, "name", None), "privacy_assurance": "schema_and_heuristic_guard_not_anonymity_proof"}
        self.store.put("search_plan", plan["plan_id"], plan)
        return plan

    def execute_search(self, plan_id: str, idempotency_key: str = "") -> dict:
        plan = self.store.get("search_plan", plan_id)
        require(self.provider is not None, "provider_unavailable", "No public metadata provider is configured; no search executed")
        require(getattr(self.provider, "name", None) == plan["provider"], "provider_changed", "Create a new plan for the configured provider")
        if idempotency_key:
            _text(idempotency_key, "idempotency_key", 200)
            receipt_id = "search_op_" + digest({"plan": plan_id, "key": idempotency_key})
            for existing in self.store.list("search_operation"):
                if existing["operation_id"] == receipt_id:
                    return self.store.get("search_run", existing["run_id"])
        run_id = new_id("run")
        pages, sources, source_snapshots, states = [], {}, {}, []
        remaining, page_budget = plan["budget"]["max_records"], plan["budget"]["max_pages"]
        for index, strategy in enumerate(plan["strategies"]):
            offset, total, exhausted, reason = 0, None, False, "not_searched"
            page_ids = []
            while remaining > 0 and page_budget > 0:
                size = min(plan["budget"]["page_size"], remaining)
                try:
                    reply = self.provider.search(query=strategy["query"], offset=offset, page_size=size, sort=strategy["sort"])
                    _object(reply, {"items", "total", "cursor_exhausted", "provider_receipt"}, required={"items", "total", "cursor_exhausted"})
                    require(isinstance(reply["items"], list) and len(reply["items"]) <= size, "provider_invalid_page", "Provider exceeded the requested page size")
                    require(type(reply["total"]) is int and reply["total"] >= 0 and type(reply["cursor_exhausted"]) is bool, "provider_invalid_page", "Invalid provider count/exhaustion")
                    require(len(reply["items"]) > 0 or reply["cursor_exhausted"], "provider_invalid_page", "Empty page must be exhausted")
                    end = offset + len(reply["items"])
                    require(reply["total"] >= end and (not reply["cursor_exhausted"] or reply["total"] == end),
                            "provider_invalid_page", "Provider exhaustion/counts are inconsistent")
                    checked_sources = [self._validate_source(item) for item in reply["items"]]
                    receipt = reply.get("provider_receipt")
                    if receipt is not None:
                        require(isinstance(receipt, dict) and len(canonical(receipt)) <= 64000, "provider_invalid_page", "Provider receipt must be bounded metadata")
                        public_request_guard(receipt)
                except Exception as exc:
                    reason = "provider_error"
                    # Error code only: provider exception messages may include credentials.
                    error = exc.code if isinstance(exc, V2Error) else "provider_error"
                    states.append({"strategy_index": index, "query": strategy["query"], "sort": strategy["sort"], "total": total, "page_ids": page_ids,
                                   "returned_count": offset, "exhausted": False, "stop_reason": reason, "error_code": error})
                    break
                page = {"schema_version": "2.0", "page_id": new_id("page"), "run_id": run_id, "plan_id": plan_id, "provider": self.provider.name,
                        "executed_at": utc_now(), "strategy_index": index, "query": strategy["query"], "sort": strategy["sort"], "offset": offset,
                        "requested_page_size": size, "returned_count": len(checked_sources), "total": reply["total"], "cursor_exhausted": reply["cursor_exhausted"],
                        "source_ids": [s["source_id"] for s in checked_sources]}
                page["source_snapshot_ids"] = ["source_snapshot_" + digest(s) for s in checked_sources]
                if receipt is not None:
                    page["provider_receipt"] = receipt
                pages.append(page)
                page_ids.append(page["page_id"])
                for source in checked_sources:
                    sources.setdefault(source["source_id"], source)
                    source_snapshots.setdefault(digest(source), source)
                offset += len(checked_sources)
                remaining -= len(checked_sources)
                page_budget -= 1
                total = reply["total"]
                exhausted = reply["cursor_exhausted"]
                if exhausted:
                    reason = "provider_exhausted"
                    break
                reason = "budget_reached"
            else:
                reason = "budget_reached" if page_ids else "not_searched"
            if not states or states[-1]["strategy_index"] != index:
                states.append({"strategy_index": index, "query": strategy["query"], "sort": strategy["sort"], "total": total, "page_ids": page_ids,
                               "returned_count": offset, "exhausted": exhausted, "stop_reason": reason})
        complete = all(state["exhausted"] for state in states)
        run = {"schema_version": "2.0", "run_id": run_id, "plan_id": plan_id, "completed_at": utc_now(), "provider": self.provider.name,
               "page_ids": [p["page_id"] for p in pages], "source_ids": list(sources), "strategies": states,
               "returned_count": sum(p["returned_count"] for p in pages), "unique_source_count": len(sources),
               "coverage": "planned_queries_exhausted" if complete else "coverage_limited", "not_systematic_review": True}
        run["source_snapshot_ids"] = ["source_snapshot_" + digest(s) for s in sources.values()]
        run["source_summaries"] = [self._source_summary({"snapshot_id": "source_snapshot_" + digest(s), **s}) for s in list(sources.values())[:50]]
        run["summaries_total"] = len(sources)
        run["summaries_truncated"] = len(sources) > 50
        with self.store.transaction():
            for source in source_snapshots.values():
                self._store_source(source)
            for page in pages:
                self.store.put("search_page", page["page_id"], page)
            self.store.put("search_run", run_id, run)
            if idempotency_key:
                self.store.put("search_operation", receipt_id, {"operation_id": receipt_id, "plan_id": plan_id, "run_id": run_id})
        return run

    @staticmethod
    def _source_summary(source: dict) -> dict:
        return {key: source.get(key) for key in ("source_id", "snapshot_id", "pmid", "doi", "title", "url", "publication_date", "design", "classification_basis")}

    def get_search_results(self, run_id: str, offset: int = 0, limit: int = 50) -> dict:
        require(type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 50, "invalid_input", "Search results use a nonnegative offset and limit 1..50")
        run = self.store.get("search_run", run_id)
        snapshot_ids = run.get("source_snapshot_ids")
        require(isinstance(snapshot_ids, list) and len(snapshot_ids) == len(run["source_ids"]), "search_results_unavailable", "This old run has no captured bibliographic result mapping; execute a new search")
        selected = snapshot_ids[offset:offset + limit]
        sources = [self.store.get("scientific_source_snapshot", sid) for sid in selected]
        require(all(source["source_id"] in run["source_ids"] for source in sources), "invalid_search_lineage", "Source snapshot does not belong to the search run")
        return {"run_id": run_id, "offset": offset, "limit": limit, "total": len(snapshot_ids), "sources": [self._source_summary(source) for source in sources],
                "next_offset": offset + len(selected) if offset + len(selected) < len(snapshot_ids) else None,
                "order_basis": "first_returned_search_order_deduplicated", "coverage": run["coverage"]}

    def _validate_source(self, source: dict) -> dict:
        allowed = {"doi", "pmid", "url", "title", "publication_date", "update_date", "effective_date", "issuer", "jurisdiction", "status", "design", "classification_basis", "aliases"}
        _object(source, allowed, required={"title", "url"})
        clean = {field: _text(source.get(field), field, 2000, optional=True) for field in allowed - {"aliases"}}
        clean["url"] = _public_url(source["url"])
        public_request_guard(source)
        clean["title"] = _text(source["title"], "title", 2000)
        if clean["doi"]:
            clean["doi"] = clean["doi"].removeprefix("https://doi.org/").lower()
            require(bool(re.fullmatch(r"10\.\d{4,9}/\S+", clean["doi"])), "invalid_source", "Invalid DOI")
        if clean["pmid"]:
            require(clean["pmid"].isdigit(), "invalid_source", "Invalid PMID")
        aliases = source.get("aliases", [])
        require(isinstance(aliases, list) and len(aliases) <= 20, "invalid_source", "At most 20 aliases are allowed")
        clean["aliases"] = [_text(alias, "alias", 2000) for alias in aliases]
        clean["design"] = clean["design"] or "unknown"
        clean["classification_basis"] = clean["classification_basis"] or "not_classified"
        identity = {"doi": clean["doi"]} if clean["doi"] else ({"pmid": clean["pmid"]} if clean["pmid"] else {"url": clean["url"]})
        return {"schema_version": "2.0", "source_id": "source_" + digest(identity), **clean}

    def _store_source(self, source: dict) -> dict:
        # Bibliographic snapshots can change while scientific identity stays stable.
        snapshot_id = "source_snapshot_" + digest(source)
        self.store.put("scientific_source_snapshot", snapshot_id, {"snapshot_id": snapshot_id, **source})
        identity = {"source_id": source["source_id"], "identity": {k: source[k] for k in ("doi", "pmid", "url") if source[k]}}
        # Alias changes do not rewrite immutable identity records.
        try:
            current = self.store.get("scientific_source", source["source_id"])
        except V2Error as exc:
            if exc.code not in {"NOT_FOUND", "not_found", "object_not_found"}:
                raise
        else:
            return {**source, "snapshot_id": snapshot_id, "identity": current["identity"]}
        self.store.put("scientific_source", source["source_id"], identity)
        return {**source, "snapshot_id": snapshot_id}

    def register_source(self, source: dict) -> dict:
        checked = self._validate_source(source)
        with self.store.transaction():
            return self._store_source(checked)

    def record_source_access(self, source_id: str, access: dict) -> dict:
        self.store.get("scientific_source", source_id)
        allowed = {"checked_url", "availability", "text_extent", "inspected_scope", "locators", "source_version", "accessed_at", "limitations"}
        _object(access, allowed, required={"checked_url", "availability", "text_extent", "inspected_scope"})
        public_request_guard(access)
        require(access["availability"] in {"available", "unavailable", "error", "unknown"} and access["text_extent"] in EXTENTS, "invalid_access", "Unknown access status or extent")
        locators = access.get("locators", [])
        limitations = access.get("limitations", [])
        require(isinstance(locators, list) and len(locators) <= 100 and isinstance(limitations, list) and len(limitations) <= 50, "invalid_access", "Invalid access locators/limitations")
        record = {"schema_version": "2.0", "access_id": new_id("access"), "source_id": source_id, "recorded_at": utc_now(),
                  "accessed_at": _text(access.get("accessed_at"), "accessed_at", 100, optional=True), "checked_url": _public_url(access["checked_url"]),
                  "availability": access["availability"], "text_extent": access["text_extent"], "inspected_scope": _text(access["inspected_scope"], "inspected_scope", 4000),
                  "locators": [_text(item, "locator", 2000) for item in locators], "limitations": [_text(item, "limitation", 2000) for item in limitations],
                  "source_version": _text(access.get("source_version"), "source_version", 1000, optional=True), "attestation": "model_reported", "source_document_sha256": None, "hash_scope": None,
                  "retrieval_assurance": "The backend did not fetch or verify source bytes"}
        self.store.put("source_access", record["access_id"], record)
        return record

    def fetch_source_abstract(self, source_id: str) -> dict:
        """Fetch only a known PMID through the trusted configured provider.

        Stored byte hashes describe the PubMed XML record and rendered abstract,
        never publisher full text. Fetching is not a claim that a model read it.
        """
        from .providers import FetchedAbstract, MAX_ABSTRACT_BYTES, MAX_HTTP_BYTES

        source = self.store.get("scientific_source", source_id)
        require(self.provider is not None and callable(getattr(self.provider, "fetch_abstract", None)),
                "provider_unavailable", "The configured provider cannot fetch PubMed abstracts")
        pmid = source["identity"].get("pmid")
        if pmid is None:
            snapshots = [s for s in self.store.list("scientific_source_snapshot") if s["source_id"] == source_id and s.get("pmid")]
            pmid = snapshots[-1]["pmid"] if snapshots else None
        require(isinstance(pmid, str) and bool(re.fullmatch(r"[1-9][0-9]{0,11}", pmid)), "source_pmid_unavailable", "The registered source has no valid PMID")
        fetched = self.provider.fetch_abstract(pmid)
        require(isinstance(fetched, FetchedAbstract) and fetched.pmid == pmid, "provider_identity_mismatch", "Trusted provider returned another source")
        require(source["identity"].get("doi") is None or source["identity"]["doi"] == fetched.doi,
                "provider_identity_mismatch", "Fetched PubMed DOI differs from the registered scientific identity")
        require(isinstance(fetched.xml_bytes, bytes) and len(fetched.xml_bytes) <= MAX_HTTP_BYTES and
                isinstance(fetched.abstract_text, str) and len(fetched.abstract_text.encode()) <= MAX_ABSTRACT_BYTES,
                "provider_response_limit", "Source capture exceeded its byte bounds")
        public_request_guard({"abstract": fetched.abstract_text, "sections": fetched.sections, "publication_notices": fetched.publication_notices})
        xml_hash = hashlib.sha256(fetched.xml_bytes).hexdigest()
        abstract_hash = hashlib.sha256(fetched.abstract_text.encode()).hexdigest()
        capture_id = "capture_" + digest({"source_id": source_id, "xml_hash": xml_hash, "abstract_hash": abstract_hash,
                                         "projection": "pubmed_abstract_v1_notices_v1", "sections": fetched.sections,
                                         "publication_notices": fetched.publication_notices})
        capture = {"schema_version": "2.0", "capture_id": capture_id, "source_id": source_id, "pmid": pmid,
                   "source_document_sha256": xml_hash, "hash_scope": "pubmed_efetch_xml_record", "bytes_base64": base64.b64encode(fetched.xml_bytes).decode("ascii"),
                   "abstract_text": fetched.abstract_text, "abstract_sha256": abstract_hash, "abstract_hash_scope": "utf8_rendered_pubmed_abstract_v1", "sections": list(fetched.sections),
                   "publication_notices": list(fetched.publication_notices),
                   "retrieval_extent": "abstract" if fetched.abstract_text else "metadata", "full_text_retrieved": False}
        access = {"schema_version": "2.0", "access_id": new_id("access"), "source_id": source_id, "capture_id": capture_id, "recorded_at": utc_now(),
                  "accessed_at": fetched.fetched_at, "checked_url": _public_url(fetched.requested_url), "availability": "available" if fetched.abstract_text else "unavailable",
                  "text_extent": "abstract" if fetched.abstract_text else "metadata", "retrieval_extent": capture["retrieval_extent"], "inspected_scope": "Backend retrieval only; no model or human inspection attested",
                  "inspection_attestation": "not_reported", "locators": [section["locator"] for section in fetched.sections], "source_version": f"PMID {pmid}",
                  "attestation": "backend_fetched", "source_document_sha256": xml_hash, "hash_scope": capture["hash_scope"], "abstract_sha256": abstract_hash,
                  "publication_notices": list(fetched.publication_notices),
                  "limitations": ["PubMed abstract/record only; publisher full text was not fetched", "Retrieval and excerpt matching do not prove semantic entailment, applicability or safety"],
                  "retrieval_assurance": "Configured fixed-endpoint PubMed provider returned the saved XML bytes"}
        with self.store.transaction():
            self.store.put("source_capture", capture_id, capture)
            self.store.put("source_access", access["access_id"], access)
        return {"source_id": source_id, "access": access, "capture_id": capture_id, "abstract_text": fetched.abstract_text, "sections": list(fetched.sections), "publication_notices": list(fetched.publication_notices),
                "source_document_sha256": xml_hash, "hash_scope": capture["hash_scope"], "abstract_sha256": abstract_hash, "full_text_retrieved": False}

    def record_finding(self, finding: dict) -> dict:
        allowed = {"source_id", "access_id", "population", "design", "intervention", "comparator", "outcome", "time_horizon", "kind", "statement", "excerpt", "locator", "effect", "limitations", "review_status", "native_grade", "native_strength"}
        _object(finding, allowed, required={"source_id", "access_id", "kind", "statement", "excerpt", "locator"})
        public_request_guard(finding)
        source = self.store.get("scientific_source", finding["source_id"])
        access = self.store.get("source_access", finding["access_id"])
        require(access["source_id"] == source["source_id"], "source_mismatch", "Access record belongs to another source")
        require(access["availability"] == "available" and access["text_extent"] in {"abstract", "selected_sections", "complete_text"}, "source_text_not_inspected", "Metadata/unknown access does not support substantive findings")
        status = finding.get("review_status", "extracted")
        require(status in {"extracted", "source_rechecked"}, "invalid_review_status", "This API cannot issue human_checked findings")
        require(finding["kind"] in FINDING_KINDS, "invalid_finding", "Unknown finding kind")
        record = {"schema_version": "2.0", "finding_id": new_id("finding"), "recorded_at": utc_now(), "source_id": source["source_id"], "access_id": access["access_id"],
                  "kind": finding["kind"], "review_status": status, "review_assurance": "model_attested_not_authenticated_human_or_semantic_verification", "source_text_extent": access["text_extent"]}
        for field in ("statement", "excerpt", "locator"):
            record[field] = _text(finding[field], field, 12000 if field == "excerpt" else 4000)
        if access["attestation"] == "backend_fetched":
            capture = self.store.get("source_capture", access["capture_id"])
            require(capture["source_id"] == source["source_id"] and record["excerpt"] in capture["abstract_text"],
                    "excerpt_not_in_capture", "The excerpt is not present in the fetched abstract")
            require(record["locator"] in access["locators"], "locator_not_in_capture", "Choose an actual fetched abstract section locator")
            section = next((section for section in capture["sections"] if section["locator"] == record["locator"]), None)
            require(section is not None and record["excerpt"] in section["text"], "excerpt_locator_mismatch", "The excerpt is not in the selected fetched abstract section")
            record["capture_id"] = capture["capture_id"]
            record["excerpt_match_assurance"] = "literal_match_not_semantic_entailment"
        for field in ("population", "design", "intervention", "comparator", "outcome", "time_horizon", "native_grade", "native_strength"):
            record[field] = _text(finding.get(field), field, 2000, optional=True)
        effect = finding.get("effect")
        if effect is not None:
            _object(effect, {"measure", "value_raw", "ci_raw", "denominator_raw", "unit_raw"}, required={"measure", "value_raw"})
            record["effect"] = {key: _text(val, f"effect.{key}", 1000, optional=True) for key, val in effect.items()}
        else:
            record["effect"] = None
        limits = finding.get("limitations", [])
        require(isinstance(limits, list) and len(limits) <= 50, "invalid_finding", "Invalid limitations")
        record["limitations"] = [_text(item, "limitation", 2000) for item in limits]
        self.store.put("finding", record["finding_id"], record)
        return record

    def build_dossier(self, run_ids: list[str], finding_ids: list[str] | None = None) -> dict:
        require(isinstance(run_ids, list) and len(run_ids) <= 40 and len(set(run_ids)) == len(run_ids), "invalid_input", "At most 40 unique run IDs are allowed")
        runs = [self.store.get("search_run", _text(run_id, "run ID", 200)) for run_id in run_ids]
        sources = set().union(*(set(run["source_ids"]) for run in runs))
        if finding_ids is None:
            findings = [f for f in self.store.list("finding") if f["source_id"] in sources]
        else:
            require(isinstance(finding_ids, list) and len(finding_ids) <= 500 and len(set(finding_ids)) == len(finding_ids), "invalid_input", "At most 500 unique findings are allowed")
            findings = [self.store.get("finding", _text(fid, "finding ID", 200)) for fid in finding_ids]
            if runs:
                require(all(f["source_id"] in sources for f in findings), "finding_not_in_search", "A selected finding was not returned by these executed runs")
        for run in runs:
            # The report derives receipts from backend objects, not a caller log.
            pages = [self.store.get("search_page", pid) for pid in run["page_ids"]]
            require(all(p["run_id"] == run["run_id"] for p in pages), "invalid_search_lineage", "Page/run lineage mismatch")
        dossier = {"schema_version": "2.0", "dossier_id": new_id("dossier"), "created_at": utc_now(), "run_ids": run_ids,
                   "page_ids": [pid for run in runs for pid in run["page_ids"]], "finding_ids": [f["finding_id"] for f in findings],
                   "source_ids": sorted(sources | {f["source_id"] for f in findings}), "search_coverage": "not_searched" if not runs else ("planned_queries_exhausted" if all(r["coverage"] == "planned_queries_exhausted" for r in runs) else "coverage_limited"),
                   "executed_strategies": [state for run in runs for state in run["strategies"]], "not_systematic_review": True,
                   "limitations": ["Search exhaustion describes the explicit plans only", "Model access/source recheck remain attestations; backend captures, when present, are PubMed abstracts rather than publisher full text"]}
        self.store.put("dossier", dossier["dossier_id"], dossier)
        return dossier
