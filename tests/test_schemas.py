import json
from pathlib import Path

import jsonschema

from health_analyzer.contracts import (
    AnswerBundle,
    CasePacket,
    Claim,
    EvidenceItem,
    EvidencePacket,
    ProvenanceLocator,
    ReviewedEvidenceClaim,
    RiskEnvelope,
    RiskIntent,
    SearchLogEntry,
    StatementKind,
    evidence_item_snapshot_sha256,
    to_dict,
)


ROOT = Path(__file__).parents[1]
EDUCATION_RISK = RiskEnvelope(intent=RiskIntent.EDUCATION)


def schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text())


def test_minimal_packets_validate_against_published_schemas() -> None:
    case = CasePacket(packet_id="case_" + "a" * 20, subject_id="subj_" + "b" * 16)
    evidence = EvidencePacket(
        packet_id="evidence_" + "c" * 20,
        question="Synthetic question",
        risk_envelope=EDUCATION_RISK,
        items=(
            EvidenceItem(
                evidence_id="pmid:1",
                title="Synthetic evidence",
                source_type="journal_article",
                url="https://pubmed.ncbi.nlm.nih.gov/1/",
            ),
        ),
        search_log=(
            SearchLogEntry(
                run_id="run_" + "d" * 20,
                source="synthetic",
                query_id="query-schema",
                executed_at="2026-01-01T00:00:00+00:00",
                query={"question": "Synthetic question"},
                result_ids=("pmid:1",),
            ),
        ),
    )
    answer = AnswerBundle(
        bundle_id="answer-1",
        question="Synthetic question",
        risk_envelope=EDUCATION_RISK,
        claims=(
            Claim(
                claim_id="claim-1",
                text="Synthetic claim",
                kind=StatementKind.EXTERNAL_EVIDENCE,
                support_ids=("pmid:1",),
                certainty="low",
            ),
        ),
    )
    jsonschema.validate(to_dict(case), schema("case-packet.schema.json"))
    jsonschema.validate(to_dict(evidence), schema("evidence-packet.schema.json"))
    jsonschema.validate(to_dict(answer), schema("answer-bundle.schema.json"))


def test_reviewed_evidence_claim_validates_against_packet_schema_v1_2() -> None:
    evidence_item = EvidenceItem(
        evidence_id="pmid:42",
        title="Synthetic trial",
        source_type="randomized_trial",
        url="https://pubmed.ncbi.nlm.nih.gov/42/",
    )
    evidence = EvidencePacket(
        packet_id="evidence_" + "a" * 20,
        question="Synthetic reviewed question",
        risk_envelope=EDUCATION_RISK,
        items=(evidence_item,),
        reviewed_claims=(
            ReviewedEvidenceClaim(
                claim_id="evclaim_" + "b" * 32,
                question="Synthetic reviewed question",
                source_kind="retrieval_item",
                source_evidence_id="pmid:42",
                source_snapshot_sha256=evidence_item_snapshot_sha256(evidence_item),
                statement_kind=StatementKind.EXTERNAL_EVIDENCE,
                claim_type="effect",
                text="The synthetic intervention changed the outcome.",
                provenance=ProvenanceLocator(
                    source_id="pmid:42",
                    sha256="d" * 64,
                    locator="page 4, Results",
                    page=4,
                    excerpt="The adjusted difference was 4 units.",
                ),
                review_receipt_id="eclaim_rcpt_" + "e" * 32,
                reviewed_at="2026-01-01T00:00:00+00:00",
                reviewer_id="operator-1",
                effect="adjusted difference 4 units",
            ),
        ),
        search_log=(
            SearchLogEntry(
                run_id="run_" + "f" * 20,
                source="pubmed",
                query_id="query-reviewed-schema",
                executed_at="2026-01-01T00:00:00+00:00",
                query={"question": "Synthetic reviewed question"},
                result_ids=("pmid:42",),
            ),
        ),
    )

    jsonschema.validate(to_dict(evidence), schema("evidence-packet.schema.json"))


def test_guidance_source_catalog_validates_against_published_schema() -> None:
    from health_analyzer.guidance import DEFAULT_GUIDANCE_SOURCE_CATALOG

    catalog = json.loads(DEFAULT_GUIDANCE_SOURCE_CATALOG.read_text())

    jsonschema.validate(catalog, schema("guidance-source-catalog.schema.json"))
