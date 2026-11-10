from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
from urllib.parse import urlencode

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.providers import HTTPResponse, NCBITransport, PubMedProvider, _PublicNCBIConnection
from health_analyzer.v2.research import ScientificResearchService


XML = b'''<?xml version="1.0"?>
<!DOCTYPE PubmedArticleSet PUBLIC "-//NLM//DTD PubMedArticle//EN" "https://dtd.nlm.nih.gov/ncbi/pubmed/out/pubmed_250101.dtd">
<PubmedArticleSet><PubmedArticle><MedlineCitation><PMID>42</PMID><Article><Abstract>
<AbstractText Label="RESULTS">The synthetic outcome changed by <i>four</i> units.</AbstractText>
<AbstractText Label="CONCLUSIONS">Applicability is uncertain.</AbstractText>
</Abstract></Article></MedlineCitation><PubmedData><ArticleIdList><ArticleId IdType="doi">10.1234/synthetic</ArticleId></ArticleIdList></PubmedData></PubmedArticle></PubmedArticleSet>'''


class FakeTransport:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def request(self, endpoint, parameters):
        self.calls.append((endpoint, parameters))
        expected, payload, content_type = self.replies.pop(0)
        assert expected == endpoint
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return HTTPResponse(body, content_type, "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/" + endpoint + "?" + urlencode(parameters), "2026-10-13T01:00:00Z")


def replies(ids=None, total="3", *, xml=XML):
    ids = ids or ["42", "43"]
    search = {"esearchresult": {"count": total, "idlist": ids, "querytranslation": "synthetic[All Fields]", "warninglist": {"outputmessages": ["Synthetic notice"]}}}
    summary = {"result": {"uids": ids, **{pmid: {"uid": pmid, "title": "Synthetic trial", "pubdate": "2026 Jan", "pubtype": ["Randomized Controlled Trial"],
                                                          "articleids": [{"idtype": "doi", "value": f"10.1234/{'synthetic' if pmid == '42' else pmid}"}]} for pmid in ids}}}
    return [("esearch.fcgi", search, "application/json"), ("esummary.fcgi", summary, "application/json"), ("efetch.fcgi", xml, "text/xml")]


@pytest.fixture
def store(tmp_path):
    db = SignedStore(tmp_path / "public-live-tests.sqlite3", b"p" * 32, "public-research")
    yield db
    db.close()


def test_public_metadata_page_uses_real_pagination_sort_and_logs_translation(store):
    transport = FakeTransport(replies())
    service = ScientificResearchService(store, PubMedProvider(transport))
    plan = service.create_plan({"question": "Synthetic public research", "budget": {"page_size": 2, "max_records": 2, "max_pages": 1},
                                "strategies": [{"query": "synthetic", "sort": "publication_date", "reason": "Synthetic explicit strategy"}]})
    run = service.execute_search(plan["plan_id"])
    assert run["coverage"] == "coverage_limited" and run["returned_count"] == 2
    endpoint, request = transport.calls[0]
    assert endpoint == "esearch.fcgi" and request["retstart"] == "0" and request["retmax"] == "2" and request["sort"] == "pub_date"
    assert request["term"] == "synthetic" and "[pt]" not in request["term"]
    page = store.get("search_page", run["page_ids"][0])
    assert page["provider_receipt"]["query_translation"] == "synthetic[All Fields]"
    assert page["provider_receipt"]["metadata_only"] is True
    assert page["provider_receipt"]["notices"] == ["outputmessages: Synthetic notice"]
    assert store.list("source_access") == []
    assert [s["pmid"] for s in run["source_summaries"]] == ["42", "43"]
    results = service.get_search_results(run["run_id"], offset=1, limit=1)
    assert results["sources"][0]["pmid"] == "43" and results["next_offset"] is None


def test_second_page_and_empty_exhaustion_are_provider_derived():
    transport = FakeTransport(replies(["42"], "3")[:2])
    page = PubMedProvider(transport).search(query="synthetic", offset=2, page_size=1, sort="relevance")
    assert transport.calls[0][1]["retstart"] == "2" and page["cursor_exhausted"] is True
    transport = FakeTransport([("esearch.fcgi", {"esearchresult": {"count": "0", "idlist": []}}, "application/json")])
    empty = PubMedProvider(transport).search(query="synthetic empty", offset=0, page_size=50, sort="relevance")
    assert empty["items"] == [] and empty["cursor_exhausted"] and len(transport.calls) == 1


def test_abstract_capture_has_actual_bytes_digest_and_distinct_inspection(store):
    transport = FakeTransport(replies(["42"], "1"))
    service = ScientificResearchService(store, PubMedProvider(transport))
    run = service.execute_search(service.create_plan({"question": "Synthetic public search"})["plan_id"])
    source_id = run["source_ids"][0]
    fetched = service.fetch_source_abstract(source_id)
    assert fetched["abstract_text"] == "RESULTS: The synthetic outcome changed by four units.\n\nCONCLUSIONS: Applicability is uncertain."
    assert fetched["source_document_sha256"] == hashlib.sha256(XML).hexdigest()
    assert fetched["abstract_sha256"] == hashlib.sha256(fetched["abstract_text"].encode()).hexdigest()
    assert fetched["hash_scope"] == "pubmed_efetch_xml_record" and fetched["full_text_retrieved"] is False
    access = fetched["access"]
    assert access["attestation"] == "backend_fetched" and access["inspection_attestation"] == "not_reported"
    capture = store.get("source_capture", fetched["capture_id"])
    assert base64.b64decode(capture["bytes_base64"]) == XML
    finding = service.record_finding({"source_id": source_id, "access_id": access["access_id"], "kind": "mechanism", "statement": "Synthetic summary of four-unit change",
                                      "excerpt": "The synthetic outcome changed by four units.", "locator": fetched["sections"][0]["locator"]})
    assert finding["excerpt_match_assurance"] == "literal_match_not_semantic_entailment"
    assert finding["review_status"] == "extracted"
    assert service.build_dossier([run["run_id"]], [finding["finding_id"]])["finding_ids"] == [finding["finding_id"]]


def test_backend_capture_cannot_support_invented_excerpt_or_locator(store):
    service = ScientificResearchService(store, PubMedProvider(FakeTransport([("efetch.fcgi", XML, "text/xml")])))
    source = service.register_source({"pmid": "42", "doi": "10.1234/synthetic", "title": "Synthetic", "url": "https://pubmed.ncbi.nlm.nih.gov/42/"})
    fetched = service.fetch_source_abstract(source["source_id"])
    payload = {"source_id": source["source_id"], "access_id": fetched["access"]["access_id"], "kind": "benefit", "statement": "Synthetic effect",
               "excerpt": "An invented sentence is not present.", "locator": fetched["sections"][0]["locator"]}
    with pytest.raises(V2Error) as exc:
        service.record_finding(payload)
    assert exc.value.code == "excerpt_not_in_capture"
    payload.update(excerpt="Applicability is uncertain.", locator="An invented full-text page")
    with pytest.raises(V2Error) as exc:
        service.record_finding(payload)
    assert exc.value.code == "locator_not_in_capture"
    payload["locator"] = fetched["sections"][0]["locator"]
    with pytest.raises(V2Error) as exc:
        service.record_finding(payload)
    assert exc.value.code == "excerpt_locator_mismatch"
    assert store.list("finding") == []


def test_fetch_doi_and_pmid_identity_mismatch_fail_before_capture(store):
    service = ScientificResearchService(store, PubMedProvider(FakeTransport([("efetch.fcgi", XML, "text/xml")])))
    source = service.register_source({"pmid": "42", "doi": "10.1234/wrong", "title": "Synthetic", "url": "https://pubmed.ncbi.nlm.nih.gov/42/"})
    with pytest.raises(V2Error) as exc:
        service.fetch_source_abstract(source["source_id"])
    assert exc.value.code == "provider_identity_mismatch"
    assert store.list("source_access") == [] and store.list("source_capture") == []
    mismatched = XML.replace(b"<PMID>42</PMID>", b"<PMID>99</PMID>")
    with pytest.raises(V2Error) as exc:
        PubMedProvider(FakeTransport([("efetch.fcgi", mismatched, "text/xml")])).fetch_abstract("42")
    assert exc.value.code == "provider_identity_mismatch"


def test_missing_abstract_is_honest_unavailable_not_fulltext(store):
    xml = b"<PubmedArticleSet><PubmedArticle><MedlineCitation><PMID>42</PMID><Article/></MedlineCitation></PubmedArticle></PubmedArticleSet>"
    service = ScientificResearchService(store, PubMedProvider(FakeTransport([("efetch.fcgi", xml, "text/xml")])))
    source = service.register_source({"pmid": "42", "title": "Synthetic", "url": "https://pubmed.ncbi.nlm.nih.gov/42/"})
    fetched = service.fetch_source_abstract(source["source_id"])
    assert fetched["abstract_text"] == "" and fetched["access"]["availability"] == "unavailable"
    assert fetched["access"]["text_extent"] == "metadata" and fetched["full_text_retrieved"] is False
    with pytest.raises(V2Error) as exc:
        service.record_finding({"source_id": source["source_id"], "access_id": fetched["access"]["access_id"], "kind": "null", "statement": "Synthetic", "excerpt": "Synthetic", "locator": "Abstract"})
    assert exc.value.code == "source_text_not_inspected"


def test_cited_reference_doi_is_not_the_fetched_article_identity():
    ownless = XML.replace(b'<ArticleIdList><ArticleId IdType="doi">10.1234/synthetic</ArticleId></ArticleIdList>',
                          b'<ReferenceList><Reference><ArticleIdList><ArticleId IdType="doi">10.1234/cited</ArticleId></ArticleIdList></Reference></ReferenceList>')
    fetched = PubMedProvider(FakeTransport([("efetch.fcgi", ownless, "text/xml")])).fetch_abstract("42")
    assert fetched.doi is None


def test_correction_comment_notices_are_exposed_as_unreviewed_discovery(store):
    extra = b'<CommentsCorrectionsList><CommentsCorrections RefType="ErratumIn"><RefSource>Synthetic correction 2025</RefSource><PMID>40034739</PMID></CommentsCorrections><CommentsCorrections RefType="CommentIn"><RefSource>Synthetic comment 2026</RefSource><PMID>42039906</PMID></CommentsCorrections></CommentsCorrectionsList>'
    xml = XML.replace(b"</MedlineCitation>", extra + b"</MedlineCitation>")
    service = ScientificResearchService(store, PubMedProvider(FakeTransport([("efetch.fcgi", xml, "text/xml")])))
    source = service.register_source({"pmid": "42", "title": "Synthetic", "url": "https://pubmed.ncbi.nlm.nih.gov/42/"})
    fetched = service.fetch_source_abstract(source["source_id"])
    notices = fetched["publication_notices"]
    assert [n["ref_type"] for n in notices] == ["ErratumIn", "CommentIn"]
    assert all(n["content_review_status"] == "not_reviewed" for n in notices)
    assert fetched["access"]["publication_notices"] == notices
    assert store.get("source_capture", fetched["capture_id"])["publication_notices"] == notices


def test_certainty_finding_preserves_native_grade_without_claiming_benefit(store):
    xml = XML.replace(b"The synthetic outcome changed by <i>four</i> units.", b"Evidence certainty for the synthetic outcome was low.")
    service = ScientificResearchService(store, PubMedProvider(FakeTransport([("efetch.fcgi", xml, "text/xml")])))
    source = service.register_source({"pmid": "42", "title": "Synthetic", "url": "https://pubmed.ncbi.nlm.nih.gov/42/"})
    fetched = service.fetch_source_abstract(source["source_id"])
    finding = service.record_finding({"source_id": source["source_id"], "access_id": fetched["access"]["access_id"], "kind": "certainty", "native_grade": "low",
                                      "statement": "Authors rated synthetic outcome evidence low", "excerpt": "Evidence certainty for the synthetic outcome was low.", "locator": fetched["sections"][0]["locator"]})
    assert finding["kind"] == "certainty" and finding["native_grade"] == "low" and finding["effect"] is None


def test_capture_idempotence_preserves_old_projection_without_rewriting(store):
    import health_analyzer.v2.research as research_module
    provider = PubMedProvider(FakeTransport([("efetch.fcgi", XML, "text/xml"), ("efetch.fcgi", XML, "text/xml")]))
    service = ScientificResearchService(store, provider)
    source = service.register_source({"pmid": "42", "title": "Synthetic", "url": "https://pubmed.ncbi.nlm.nih.gov/42/"})
    xml_hash = hashlib.sha256(XML).hexdigest()
    old_id = "capture_" + research_module.digest({"source_id": source["source_id"], "xml_hash": xml_hash})
    store.put("source_capture", old_id, {"capture_id": old_id, "legacy_projection": "synthetic prior v2 capture"})
    first = service.fetch_source_abstract(source["source_id"])
    second = service.fetch_source_abstract(source["source_id"])
    assert first["capture_id"] == second["capture_id"] and first["capture_id"] != old_id
    assert len(store.list("source_capture")) == 2
    assert store.get("source_capture", old_id)["legacy_projection"] == "synthetic prior v2 capture"


@pytest.mark.parametrize("xml", [b"<bad>", XML.replace(b"<PubmedArticleSet>", b'<!DOCTYPE a [<!ENTITY evil "x">]><PubmedArticleSet>')])
def test_malformed_and_entity_xml_fail_closed(xml):
    with pytest.raises(V2Error):
        PubMedProvider(FakeTransport([("efetch.fcgi", xml, "text/xml")])).fetch_abstract("42")


def test_metadata_errors_and_mismatched_summaries_fail_closed():
    bad = [("esearch.fcgi", {"error": "rate limit"}, "application/json")]
    with pytest.raises(V2Error) as exc:
        PubMedProvider(FakeTransport(bad)).search(query="synthetic", offset=0, page_size=2, sort="relevance")
    assert exc.value.code == "provider_api_error"
    values = replies()
    values[1][1]["result"]["uids"] = ["99"]
    with pytest.raises(V2Error) as exc:
        PubMedProvider(FakeTransport(values)).search(query="synthetic", offset=0, page_size=2, sort="relevance")
    assert exc.value.code == "provider_response_invalid"


def test_invalid_pubmed_field_is_not_an_exhausted_empty_search(store):
    payload = {"esearchresult": {"count": "0", "idlist": [], "errorlist": {"fieldnotfound": ["unknownfield"]}}}
    provider = PubMedProvider(FakeTransport([("esearch.fcgi", payload, "application/json")]))
    service = ScientificResearchService(store, provider)
    run = service.execute_search(service.create_plan({"question": "Synthetic explicit field error"})["plan_id"])
    assert run["coverage"] == "coverage_limited" and run["page_ids"] == []
    assert run["strategies"][0]["error_code"] == "provider_query_error"


def test_private_query_and_arbitrary_url_never_reach_transport():
    transport = FakeTransport([])
    provider = PubMedProvider(transport)
    with pytest.raises(V2Error):
        provider.search(query="/Users/synthetic/private/report.pdf", offset=0, page_size=2, sort="relevance")
    with pytest.raises(V2Error):
        provider.fetch_abstract("https://127.0.0.1/report")
    with pytest.raises(V2Error):
        provider.search(query="synthetic", offset=9999, page_size=2, sort="relevance")
    assert transport.calls == []
    with pytest.raises(V2Error) as exc:
        NCBITransport().request("https://127.0.0.1/", {"db": "pubmed"})
    assert exc.value.code == "provider_endpoint_denied"


def test_dns_private_address_is_rejected_before_connect(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    connection = _PublicNCBIConnection("eutils.ncbi.nlm.nih.gov", timeout=1, context=ssl.create_default_context())
    with pytest.raises(V2Error) as exc:
        connection.connect()
    assert exc.value.code == "provider_dns_denied" and connection.sock is None


def test_redirect_and_response_byte_cap_are_enforced(monkeypatch):
    import health_analyzer.v2.providers as module

    class Reply:
        def __init__(self, status, length): self.status, self.length = status, length
        def getheader(self, name, default=None): return self.length if name == "Content-Length" else default
        def read(self, size): pytest.fail("Body should not be read after denied status/length")

    class Connection:
        reply = Reply(302, None)
        sock = None
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): pass
        def getresponse(self): return self.reply
        def close(self): pass

    monkeypatch.setattr(module, "_PublicNCBIConnection", Connection)
    monkeypatch.setattr(NCBITransport, "_pace", staticmethod(lambda: None))
    with pytest.raises(V2Error) as exc:
        NCBITransport(retries=0).request("esearch.fcgi", {"db": "pubmed", "term": "synthetic", "retmode": "json"})
    assert exc.value.code == "provider_redirect_denied"
    Connection.reply = Reply(200, str(1024 * 1024 + 1))
    with pytest.raises(V2Error) as exc:
        NCBITransport(retries=0).request("esearch.fcgi", {"db": "pubmed", "term": "synthetic", "retmode": "json"})
    assert exc.value.code == "provider_response_limit"


def test_process_rate_limit_spaces_requests_one_second(monkeypatch):
    import health_analyzer.v2.providers as module
    clock, pauses = [10.0], []
    def sleep(amount):
        pauses.append(amount)
        clock[0] += amount
    monkeypatch.setattr(module, "_LAST_REQUEST", 0.0)
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module.time, "sleep", sleep)
    NCBITransport._pace(); NCBITransport._pace(); NCBITransport._pace()
    assert pauses == [1.0, 1.0]


@pytest.mark.parametrize("retry_after", ["120", "invalid date", "Wed, 31 Dec 2099 23:59:59 GMT"])
def test_long_or_invalid_retry_after_stops_without_early_retry(monkeypatch, retry_after):
    import health_analyzer.v2.providers as module
    calls = []
    class Reply:
        status = 429
        def getheader(self, name, default=None): return retry_after if name == "Retry-After" else default
    class Connection:
        sock = None
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): calls.append("request")
        def getresponse(self): return Reply()
        def close(self): pass
    monkeypatch.setattr(module, "_PublicNCBIConnection", Connection)
    monkeypatch.setattr(NCBITransport, "_pace", staticmethod(lambda: None))
    with pytest.raises(V2Error) as exc:
        NCBITransport().request("esearch.fcgi", {"db": "pubmed", "term": "synthetic", "retmode": "json"})
    assert exc.value.code == "provider_rate_limited" and calls == ["request"]


def test_result_pagination_remains_bound_to_executed_snapshot_after_metadata_update(store):
    provider = PubMedProvider(FakeTransport(replies(["42"], "1")[:2]))
    service = ScientificResearchService(store, provider)
    run = service.execute_search(service.create_plan({"question": "Synthetic known source"})["plan_id"])
    original = run["source_summaries"][0]
    service.register_source({"pmid": "42", "doi": "10.1234/synthetic", "title": "Later synthetic metadata", "url": "https://pubmed.ncbi.nlm.nih.gov/42/"})
    restored = service.get_search_results(run["run_id"])
    assert restored["sources"][0] == original
    with pytest.raises(V2Error):
        service.get_search_results(run["run_id"], limit=51)
