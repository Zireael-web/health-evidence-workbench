"""Search contracts and deterministic source/ranking policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import calendar
from datetime import date
import hashlib
import json
from urllib.parse import urlparse

from ..contracts import EvidenceItem, RiskEnvelope
from ..privacy import PrivacyGate, PrivacyViolation


PUBMED_ESEARCH_ENDPOINT = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
PUBMED_ESUMMARY_ENDPOINT = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"
CROSSREF_WORKS_ENDPOINT = "https://api.crossref.org/works"
# This string is part of the HMAC-verified retrieval execution protocol. Do not
# couple it to the package release: changing it requires an explicit receipt
# migration or a bounded historical-version verifier.
RETRIEVAL_CLIENT_VERSION = "health-analyzer/0.2.0"


@dataclass(frozen=True, slots=True)
class EvidenceQuery:
    question: str
    risk_envelope: RiskEnvelope
    question_type: str = "intervention"
    population: str = ""
    intervention: str = ""
    exposure: str = ""
    comparison: str = ""
    outcomes: tuple[str, ...] = ()
    index_test: str = ""
    reference_standard: str = ""
    target_condition: str = ""
    context: str = ""
    source_types: tuple[str, ...] = ()
    jurisdictions: tuple[str, ...] = ()
    date_from: str | None = None
    date_to: str | None = None
    max_results: int = 10

    @property
    def query_id(self) -> str:
        payload = json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)
        return "query_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]

    def validate(self) -> None:
        if (
            not isinstance(self.risk_envelope, RiskEnvelope)
            or not self.risk_envelope.is_explicit
        ):
            raise ValueError("EvidenceQuery requires an explicit risk envelope")
        PrivacyGate().assert_public_query(self.public_text())
        allowed_question_types = {
            "intervention",
            "diagnosis",
            "prognosis",
            "etiology",
            "harms",
            "prevalence",
            "mechanism",
        }
        if self.question_type not in allowed_question_types:
            raise ValueError(
                "question_type must be one of: " + ", ".join(sorted(allowed_question_types))
            )
        if not 1 <= self.max_results <= 100:
            raise ValueError("max_results must be between 1 and 100")
        parsed_from = date.fromisoformat(self.date_from) if self.date_from else None
        parsed_to = date.fromisoformat(self.date_to) if self.date_to else None
        if parsed_from and parsed_from.day != 1:
            raise ValueError("date_from must be the first day of a publication month")
        if parsed_to and parsed_to.day != calendar.monthrange(
            parsed_to.year, parsed_to.month
        )[1]:
            raise ValueError("date_to must be the last day of a publication month")
        if bool(self.date_from) != bool(self.date_to):
            raise ValueError("date_from and date_to must be provided together")
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("date_from must not be after date_to")

    def public_text(self) -> str:
        parts = [
            self.question,
            self.population,
            self.intervention,
            self.exposure,
            self.comparison,
            *self.outcomes,
            self.index_test,
            self.reference_standard,
            self.target_condition,
            self.context,
        ]
        return " ".join(part.strip() for part in parts if part.strip())

    @property
    def framework(self) -> str:
        return {
            "intervention": "PICOTS",
            "diagnosis": "PIRD",
            "prognosis": "PICOTS-prognosis",
            "etiology": "PECO",
            "harms": "PECO",
            "prevalence": "CoCoPop",
            "mechanism": "conceptual",
        }[self.question_type]

    @property
    def effective_source_types(self) -> tuple[str, ...]:
        if self.source_types:
            return self.source_types
        return {
            "intervention": ("clinical_guideline", "systematic_review", "randomized_trial"),
            "diagnosis": ("clinical_guideline", "systematic_review", "diagnostic_accuracy"),
            "prognosis": ("clinical_guideline", "systematic_review", "cohort"),
            "etiology": ("systematic_review", "cohort", "case_control"),
            "harms": ("clinical_guideline", "systematic_review", "randomized_trial", "cohort"),
            "prevalence": ("systematic_review", "cross_sectional"),
            "mechanism": ("systematic_review", "primary_study"),
        }[self.question_type]

    def pubmed_term(self) -> str:
        self.validate()
        concepts: list[str] = []
        if self.population:
            concepts.append(f"({self.population})")
        if self.intervention:
            concepts.append(f"({self.intervention})")
        if self.exposure:
            concepts.append(f"({self.exposure})")
        if self.comparison:
            concepts.append(f"({self.comparison})")
        if self.outcomes:
            concepts.append("(" + " OR ".join(self.outcomes) + ")")
        if self.index_test:
            concepts.append(f"({self.index_test})")
        if self.reference_standard:
            concepts.append(f"({self.reference_standard})")
        if self.target_condition:
            concepts.append(f"({self.target_condition})")
        if self.context:
            concepts.append(f"({self.context})")
        publication_types = {
            "clinical_guideline": '(guideline[Publication Type] OR practice guideline[Publication Type])',
            "systematic_review": '"systematic review"[Publication Type]',
            "meta_analysis": '"meta-analysis"[Publication Type]',
            "randomized_trial": '"randomized controlled trial"[Publication Type]',
        }
        filters = [
            publication_types[source_type]
            for source_type in self.effective_source_types
            if source_type in publication_types
        ]
        if filters:
            concepts.append("(" + " OR ".join(filters) + ")")
        if not concepts:
            concepts.append(f"({self.question})")
        if self.date_from and self.date_to:
            concepts.append(
                f'("{self.date_from}"[Date - Publication] : '
                f'"{self.date_to}"[Date - Publication])'
            )
        return " AND ".join(concepts)


class EvidenceSourcePolicy:
    """Allowlist of authoritative metadata and guidance endpoints."""

    allowed_hosts: tuple[str, ...] = (
        "ncbi.nlm.nih.gov",
        "pubmed.ncbi.nlm.nih.gov",
        "eutils.ncbi.nlm.nih.gov",
        "api.crossref.org",
        "doi.org",
        "who.int",
        "nice.org.uk",
        "cdc.gov",
        "fda.gov",
        "ema.europa.eu",
        "cochranelibrary.com",
        "escardio.org",
        "acc.org",
        "heart.org",
    )

    def assert_allowed(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("evidence source URL must use HTTPS")
        host = parsed.hostname.casefold()
        if not any(host == allowed or host.endswith("." + allowed) for allowed in self.allowed_hosts):
            raise ValueError(f"evidence source host is not allowlisted: {host}")


def retrieval_execution_descriptor(
    source: str,
    query: EvidenceQuery,
    *,
    pubmed_summary_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    """Return the credential-free, exact semantic request executed by a client."""

    query.validate()
    if source == "pubmed":
        summary_ids = tuple(pubmed_summary_ids or ())
        if len(summary_ids) > query.max_results:
            raise ValueError("PubMed summary ID count exceeds max_results")
        if len(set(summary_ids)) != len(summary_ids) or any(
            not isinstance(pmid, str) or not pmid.isascii() or not pmid.isdigit()
            or pmid.startswith("0")
            for pmid in summary_ids
        ):
            raise ValueError("PubMed summary IDs must be unique canonical PMIDs")
        parameters: dict[str, object] = {
            "db": "pubmed",
            "retmode": "json",
            "tool": "health_analyzer",
            "term": query.pubmed_term(),
            "retmax": query.max_results,
            "sort": "pub date",
        }
        return {
            "schema": "retrieval-execution-v2",
            "source": "pubmed",
            "database": "pubmed",
            "requests": [
                {
                    "step": "esearch",
                    "endpoint": PUBMED_ESEARCH_ENDPOINT,
                    "method": "GET",
                    "parameters": parameters,
                },
                {
                    "step": "esummary",
                    "endpoint": PUBMED_ESUMMARY_ENDPOINT,
                    "method": "GET",
                    "executed": bool(summary_ids),
                    "ordered_ids": list(summary_ids),
                    "parameters": {
                        "db": "pubmed",
                        "retmode": "json",
                        "tool": "health_analyzer",
                        "id": ",".join(summary_ids),
                        "version": "2.0",
                    },
                },
            ],
            "credential_parameters_omitted": ["email", "api_key"],
            "client": RETRIEVAL_CLIENT_VERSION,
        }
    if source == "crossref":
        parameters = {
            "query.bibliographic": query.public_text(),
            "rows": query.max_results,
            "select": "DOI,title,type,published,issued,publisher,URL",
        }
        filters: list[str] = []
        if query.date_from:
            filters.append(f"from-pub-date:{query.date_from}")
        if query.date_to:
            filters.append(f"until-pub-date:{query.date_to}")
        if filters:
            parameters["filter"] = ",".join(filters)
        return {
            "schema": "retrieval-execution-v1",
            "source": "crossref",
            "database": "crossref-works",
            "endpoint": CROSSREF_WORKS_ENDPOINT,
            "method": "GET",
            "parameters": parameters,
            "credential_parameters_omitted": ["mailto"],
            "client": RETRIEVAL_CLIENT_VERSION,
        }
    raise ValueError("source must be 'pubmed' or 'crossref'")


def plan_evidence_search(query: EvidenceQuery) -> dict[str, object]:
    query.validate()
    return {
        "query_id": query.query_id,
        "question": query.question,
        "risk_envelope": asdict(query.risk_envelope),
        "question_type": query.question_type,
        "framework": query.framework,
        "structured_question": {
            "population": query.population,
            "intervention": query.intervention,
            "exposure": query.exposure,
            "comparison": query.comparison,
            "outcomes": list(query.outcomes),
            "index_test": query.index_test,
            "reference_standard": query.reference_standard,
            "target_condition": query.target_condition,
            "context": query.context,
        },
        "source_types": list(query.effective_source_types),
        "jurisdictions": list(query.jurisdictions),
        "date_range": {"from": query.date_from, "to": query.date_to},
        "queries": {
            "pubmed": query.pubmed_term(),
            "crossref": query.public_text(),
        },
        "privacy_checked": True,
        "limitations": [
            "Source type filters are retrieval aids, not critical appraisal.",
            "Crossref may not expose enough metadata to enforce study-design filters; screen records explicitly.",
        ],
    }


_SOURCE_TYPE_WEIGHT = {
    "clinical_guideline": 100,
    "systematic_review": 90,
    "meta_analysis": 90,
    "randomized_trial": 80,
    "cohort": 65,
    "diagnostic_accuracy": 65,
    "case_control": 55,
    "cross_sectional": 45,
    "narrative_review": 35,
    "journal_article": 30,
}


def rank_evidence(items: tuple[EvidenceItem, ...] | list[EvidenceItem]) -> tuple[EvidenceItem, ...]:
    """Rank by evidence design, publication recency, then stable identifier."""

    def publication_year(item: EvidenceItem) -> int:
        try:
            return int((item.published_at or "0000")[:4])
        except ValueError:
            return 0

    return tuple(
        sorted(
            items,
            key=lambda item: (
                -_SOURCE_TYPE_WEIGHT.get(item.source_type, 0),
                -publication_year(item),
                item.evidence_id,
            ),
        )
    )


def ensure_public_query_text(text: str) -> None:
    try:
        PrivacyGate().assert_public_query(text)
    except PrivacyViolation:
        raise
