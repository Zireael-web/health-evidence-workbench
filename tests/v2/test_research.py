from __future__ import annotations

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.research import ScientificResearchService


@pytest.fixture
def store(tmp_path):
    db = SignedStore(tmp_path / "public-v2.sqlite3", b"s" * 32, "public-research")
    yield db
    db.close()


def source(index=1, **extra):
    return {"pmid": str(index), "title": f"Synthetic study {index}", "url": f"https://pubmed.ncbi.nlm.nih.gov/{index}/", **extra}


class FakeProvider:
    name = "synthetic-metadata"

    def __init__(self, items):
        self.items, self.calls = items, []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        start, size = kwargs["offset"], kwargs["page_size"]
        return {"items": self.items[start:start + size], "total": len(self.items), "cursor_exhausted": start + size >= len(self.items)}


def finding(service, item=None, extent="abstract", **extra):
    registered = service.register_source(item or source())
    access = service.record_source_access(registered["source_id"], {"checked_url": registered["url"], "availability": "available", "text_extent": extent,
                                                                 "inspected_scope": "Synthetic abstract", "locators": ["Abstract, Results"]})
    return service.record_finding({"source_id": registered["source_id"], "access_id": access["access_id"], "kind": "null", "statement": "The synthetic outcome did not differ.",
                                   "excerpt": "No difference in the synthetic outcome.", "locator": "Abstract, Results", **extra})


def test_plan_avoids_mandatory_outcome_comparator_and_primary_exclusions(store):
    service = ScientificResearchService(store)
    plan = service.create_plan({"question": "Synthetic etiology question", "question_type": "etiology", "population": "synthetic population", "exposure": "synthetic exposure",
                                "outcome": "synthetic outcome", "comparator": "unexposed"})
    query = plan["strategies"][0]["query"]
    assert query == '"synthetic population" AND "synthetic exposure"'
    assert "outcome" not in query and "[pt]" not in query
    assert plan["budget"]["page_size"] == 50
    with pytest.raises(V2Error, match="No public metadata provider") as exc:
        service.execute_search(plan["plan_id"])
    assert exc.value.code == "provider_unavailable"
    assert store.list("search_run") == []


def test_executed_pages_persist_actual_counts_cap_and_idempotency(store):
    provider = FakeProvider([source(i) for i in range(1, 108)])
    service = ScientificResearchService(store, provider)
    plan = service.create_plan({"question": "Synthetic harms", "question_type": "harms", "budget": {"max_records": 100, "max_pages": 2}})
    run = service.execute_search(plan["plan_id"], "operation-1")
    assert run["returned_count"] == 100 and run["unique_source_count"] == 100
    assert run["coverage"] == "coverage_limited"
    pages = [store.get("search_page", pid) for pid in run["page_ids"]]
    assert [p["offset"] for p in pages] == [0, 50]
    assert all(p["total"] == 107 for p in pages)
    assert run["strategies"][0]["stop_reason"] == "budget_reached"
    assert service.execute_search(plan["plan_id"], "operation-1") == run
    assert len(provider.calls) == 2
    assert service.build_dossier([run["run_id"]])["search_coverage"] == "coverage_limited"


def test_empty_exhausted_search_is_distinct_from_no_execution(store):
    service = ScientificResearchService(store, FakeProvider([]))
    run = service.execute_search(service.create_plan({"question": "Synthetic empty search"})["plan_id"])
    assert run["returned_count"] == 0 and len(run["page_ids"]) == 1
    assert run["coverage"] == "planned_queries_exhausted"
    assert service.build_dossier([])["search_coverage"] == "not_searched"


def test_search_rejects_fabricated_page_receipts_and_filters_are_visible(store):
    service = ScientificResearchService(store)
    with pytest.raises(V2Error) as exc:
        service.create_plan({"question": "Synthetic query", "returned_count": 100})
    assert exc.value.code == "unknown_field"
    plan = service.create_plan({"question": "Synthetic query", "strategies": [{"query": "synthetic", "reason": "diagnostic design screening", "filters": ["diagnostic accuracy"]}]})
    assert plan["strategies"][0]["filters"][0]["status"] == "filter_not_applied"
    with pytest.raises(V2Error):
        service.build_dossier(["run_never_executed"])


def test_dedup_keeps_source_snapshots_and_returned_count(store):
    original = source(1, doi="10.1234/synthetic")
    newer = source(2, doi="10.1234/SYNTHETIC", title="Synthetic corrected title")
    service = ScientificResearchService(store, FakeProvider([original, newer]))
    run = service.execute_search(service.create_plan({"question": "Synthetic duplicate"})["plan_id"])
    assert run["returned_count"] == 2 and run["unique_source_count"] == 1
    assert len(store.list("scientific_source_snapshot")) == 2
    registered = service.register_source(newer)
    assert len(store.list("scientific_source")) == 1
    assert len(store.list("scientific_source_snapshot")) == 2
    assert registered["source_id"] == run["source_ids"][0]


def test_provider_failures_are_limited_not_empty_success(store):
    class BrokenProvider:
        name = "broken"

        def search(self, **kwargs):
            raise RuntimeError("SECRET should not be persisted")

    service = ScientificResearchService(store, BrokenProvider())
    run = service.execute_search(service.create_plan({"question": "Synthetic error"})["plan_id"])
    assert run["coverage"] == "coverage_limited" and run["page_ids"] == []
    assert run["strategies"][0]["error_code"] == "provider_error"
    assert "SECRET" not in str(run)


def test_oversized_provider_page_is_not_partially_stored(store):
    class InvalidProvider:
        name = "invalid"

        def search(self, **kwargs):
            return {"items": [source(i) for i in range(51)], "total": 51, "cursor_exhausted": True}

    service = ScientificResearchService(store, InvalidProvider())
    run = service.execute_search(service.create_plan({"question": "Synthetic malformed page"})["plan_id"])
    assert run["returned_count"] == 0
    assert store.list("scientific_source") == [] and store.list("search_page") == []
    assert run["strategies"][0]["error_code"] == "provider_invalid_page"


@pytest.mark.parametrize("payload", [{"question": "/Users/synthetic/private/report.pdf"}, {"question": "Synthetic", "subject_id": "person-1"}, {"question": "email person@example.org"}])
def test_private_input_rejected(store, payload):
    with pytest.raises(V2Error):
        ScientificResearchService(store).create_plan(payload)
    assert store.list("search_plan") == []


@pytest.mark.parametrize("extra", [{"title": "/Users/synthetic/private/report.pdf"}, {"aliases": ["person@example.org"]}])
def test_source_metadata_private_content_rejected_before_persistence(store, extra):
    service = ScientificResearchService(store)
    with pytest.raises(V2Error) as exc:
        service.register_source(source(**extra))
    assert exc.value.code == "private_payload_rejected"
    assert store.list("scientific_source") == []
    assert store.list("scientific_source_snapshot") == []


def test_private_opaque_ids_rejected_but_public_identifiers_remain_valid(store):
    service = ScientificResearchService(store)
    with pytest.raises(V2Error) as exc:
        service.register_source(source(aliases=["observation_" + "b" * 64]))
    assert exc.value.code == "private_payload_rejected"
    assert store.list("scientific_source") == []
    public = service.register_source(source(doi="10.1234/synthetic", issuer="Synthetic Author Society"))
    assert public["pmid"] == "1" and public["doi"] == "10.1234/synthetic"


@pytest.mark.parametrize("url", ["file:///private/report.pdf", "http://localhost/report", "https://127.0.0.1/report", "https://10.0.0.1/report", "https://127.1/report", "https://2130706433/report", "https://user:password@example.org/"])
def test_nonpublic_urls_rejected(store, url):
    with pytest.raises(V2Error) as exc:
        ScientificResearchService(store).register_source(source(url=url))
    assert exc.value.code == "invalid_public_url"


def test_source_access_cannot_fake_backend_hash_or_human_review(store):
    service = ScientificResearchService(store)
    item = service.register_source(source())
    access = {"checked_url": item["url"], "availability": "available", "text_extent": "complete_text", "inspected_scope": "Synthetic Results section only"}
    with pytest.raises(V2Error):
        service.record_source_access(item["source_id"], {**access, "attestation": "backend_fetched", "source_document_sha256": "a" * 64})
    saved = service.record_source_access(item["source_id"], access)
    assert saved["attestation"] == "model_reported" and saved["source_document_sha256"] is None
    with pytest.raises(V2Error) as exc:
        finding(service, review_status="human_checked")
    assert exc.value.code == "invalid_review_status"


def test_metadata_cannot_support_effect_and_access_belongs_to_source(store):
    service = ScientificResearchService(store)
    with pytest.raises(V2Error) as exc:
        finding(service, extent="metadata")
    assert exc.value.code == "source_text_not_inspected"
    a, b = service.register_source(source(1)), service.register_source(source(2))
    access = service.record_source_access(a["source_id"], {"checked_url": a["url"], "availability": "available", "text_extent": "abstract", "inspected_scope": "Abstract"})
    with pytest.raises(V2Error) as exc:
        service.record_finding({"source_id": b["source_id"], "access_id": access["access_id"], "kind": "harm", "statement": "Synthetic", "excerpt": "Synthetic", "locator": "Abstract"})
    assert exc.value.code == "source_mismatch"


def test_dossier_screening_bound_to_executed_pages(store):
    service = ScientificResearchService(store, FakeProvider([source(1)]))
    run = service.execute_search(service.create_plan({"question": "Synthetic search"})["plan_id"])
    in_scope = finding(service, source(1))
    outside = finding(service, source(2))
    dossier = service.build_dossier([run["run_id"]], [in_scope["finding_id"]])
    assert dossier["finding_ids"] == [in_scope["finding_id"]]
    with pytest.raises(V2Error) as exc:
        service.build_dossier([run["run_id"]], [outside["finding_id"]])
    assert exc.value.code == "finding_not_in_search"
