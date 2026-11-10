from __future__ import annotations

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.research import ScientificResearchService
from health_analyzer.v2.review import TypedReviewService


@pytest.fixture
def services(tmp_path):
    store = SignedStore(tmp_path / "review-public-v2.sqlite3", b"r" * 32, "public-research")
    research = ScientificResearchService(store)
    src = research.register_source({"title": "Synthetic study", "pmid": "42", "url": "https://pubmed.ncbi.nlm.nih.gov/42/"})
    access = research.record_source_access(src["source_id"], {"checked_url": src["url"], "availability": "available", "text_extent": "abstract", "inspected_scope": "Abstract, Results"})
    finding = research.record_finding({"source_id": src["source_id"], "access_id": access["access_id"], "kind": "null", "statement": "No synthetic difference", "excerpt": "No synthetic difference", "locator": "Abstract, Results"})
    yield research, TypedReviewService(store, research), finding
    store.close()


def draft(finding, **extra):
    return {"intent": "education", "depth": "quick", "claims": [{"claim_id": "c1", "type": "source_finding", "text": "No synthetic difference", "support_ids": [finding["finding_id"]]}], **extra}


def checks(names, coverage=None):
    return [{"check": name, "status": "ok", "coverage": coverage or ["c1"], "reason": "Synthetic reviewer compared the available abstract and draft", "severity": "none"} for name in names]


def test_structure_alone_does_not_make_medical_answer_ready(services):
    research, reviewer, finding = services
    report = reviewer.review_draft(draft(finding))
    assert report["checks"][0]["status"] == "ok"
    assert report["release_state"] == "needs_revision" and report["medical_validation"] == "not_provided"
    assert next(c for c in report["checks"] if c["check"] == "source_alignment")["status"] == "not_checked"
    assert research.store.get("review_report", report["review_id"]) == report


def test_model_review_is_attributed_not_backend_semantic_proof(services):
    _, reviewer, finding = services
    report = reviewer.review_draft(draft(finding), checks(["source_alignment", "citation_identity_and_status", "reasoning", "privacy"]))
    assert report["release_state"] == "ready_with_limits"
    assert all(c["assurance"] == "model_reported" for c in report["checks"] if c["check"] in {"source_alignment", "reasoning", "privacy"})
    assert report["claim_readiness"][0]["semantic_alignment"] == "not_checked_by_backend"


def test_unrelated_claim_is_structurally_resolvable_but_not_semantically_verified(services):
    _, reviewer, finding = services
    value = draft(finding)
    value["claims"][0]["text"] = "Unrelated synthetic disease treatment is effective"
    report = reviewer.review_draft(value)
    assert report["checks"][0]["status"] == "ok"
    assert report["release_state"] == "needs_revision"
    assert report["medical_validation"] == "not_provided"


def test_bibliographic_id_cannot_replace_finding(services):
    research, reviewer, finding = services
    value = draft(finding)
    value["claims"][0]["support_ids"] = [finding["source_id"]]
    report = reviewer.review_draft(value, checks(["source_alignment", "citation_identity_and_status", "reasoning", "privacy"]))
    assert report["checks"][0]["status"] == "issue" and report["release_state"] == "needs_revision"


def test_personal_or_material_numeric_requires_independent_review(services):
    _, reviewer, finding = services
    value = draft(finding)
    value["claims"][0].update(material=True, quantitative=True)
    model_checks = checks(["source_alignment", "citation_identity_and_status", "reasoning", "privacy", "numeric"])
    report = reviewer.review_draft(value, model_checks)
    assert report["independent_required"] and report["release_state"] == "needs_revision"
    report = reviewer.review_draft(value, model_checks, "independent_agent")
    assert report["release_state"] == "ready_with_limits"
    assert "not_authenticated_human" in report["mode_assurance"]


def test_clinical_action_preserves_intent_and_requires_safety_context(services):
    _, reviewer, finding = services
    value = draft(finding, intent="clinical_action")
    model_checks = checks(["source_alignment", "citation_identity_and_status", "reasoning", "privacy", "applicability", "safety_context"])
    no_context = reviewer.review_draft(value, model_checks, "independent_agent")
    assert no_context["release_state"] == "needs_revision" and no_context["intent"] == "clinical_action"
    value["safety_context"] = [{"field": "relevant contraindications", "status": "unknown", "impact": "Only general options for discussion can be offered"}]
    report = reviewer.review_draft(value, model_checks, "independent_agent")
    assert report["release_state"] == "draft_for_discussion" and report["intent"] == "clinical_action"


def test_model_cannot_override_structural_check_or_fake_human(services):
    _, reviewer, finding = services
    with pytest.raises(V2Error) as exc:
        reviewer.review_draft(draft(finding), checks(["structural"]))
    assert exc.value.code == "invalid_review"
    with pytest.raises(V2Error):
        reviewer.review_draft(draft(finding), review_mode="clinician_confirmed")


def test_not_applicable_does_not_satisfy_required_check(services):
    _, reviewer, finding = services
    model_checks = checks(["source_alignment", "citation_identity_and_status", "reasoning", "privacy"])
    model_checks[0].update(status="not_applicable", reason="Skipped source alignment")
    assert reviewer.review_draft(draft(finding), model_checks)["release_state"] == "needs_revision"


def test_coverage_and_issue_details_are_checked(services):
    _, reviewer, finding = services
    with pytest.raises(V2Error):
        reviewer.review_draft(draft(finding), checks(["reasoning"], ["not-a-claim"]))
    model_checks = checks(["source_alignment", "citation_identity_and_status", "reasoning", "privacy"])
    model_checks[0].update(status="issue", severity="high", issues=[{"claim_id": "c1", "reason": "Unrelated claim", "correction": "Remove the unsupported claim"}])
    assert reviewer.review_draft(draft(finding), model_checks)["release_state"] == "needs_revision"


def test_public_adapter_does_not_accept_private_case_facts(services):
    _, reviewer, finding = services
    value = draft(finding)
    value["claims"][0].update(type="case_fact")
    with pytest.raises(V2Error) as exc:
        reviewer.review_draft(value)
    assert exc.value.code == "private_review_unavailable"
    with pytest.raises(V2Error):
        reviewer.review_draft({**draft(finding), "case_selection": {"subject_id": "private-1"}})


def test_urgent_redirect_does_not_wait_for_research_and_does_not_validate_instructions():
    reviewer = TypedReviewService()
    report = reviewer.review_draft({"intent": "education", "urgent": True, "claims": [{"claim_id": "u1", "type": "option_for_discussion", "text": "Urgent branch requested", "support_ids": []}]})
    assert report["release_state"] == "urgent_redirect" and report["medical_validation"] == "not_provided"


def test_review_dossier_cannot_include_outside_support(services):
    research, reviewer, finding = services
    dossier = research.build_dossier([], [])
    report = reviewer.review_draft(draft(finding, dossier_id=dossier["dossier_id"]))
    assert report["checks"][0]["status"] == "issue"


@pytest.mark.parametrize("private_text", ["/Users/synthetic/private/report.pdf", "person@example.org"])
def test_model_review_annotations_private_payload_rejected_before_persistence(services, private_text):
    research, reviewer, finding = services
    model_checks = checks(["source_alignment", "citation_identity_and_status", "reasoning", "privacy"])
    model_checks[0]["reason"] = private_text
    with pytest.raises(V2Error) as exc:
        reviewer.review_draft(draft(finding), model_checks)
    assert exc.value.code == "private_payload_rejected"
    assert research.store.list("answer_draft") == []
    assert research.store.list("review_report") == []


def test_review_issue_locator_private_payload_rejected_before_persistence(services):
    research, reviewer, finding = services
    model_checks = [{"check": "source_alignment", "status": "issue", "coverage": ["c1"], "reason": "Synthetic source disagreement",
                     "issues": [{"claim_id": "c1", "reason": "See source", "locator": "/Users/synthetic/private/report.pdf"}]}]
    with pytest.raises(V2Error) as exc:
        reviewer.review_draft(draft(finding), model_checks)
    assert exc.value.code == "private_payload_rejected"
    assert research.store.list("answer_draft") == []
    assert research.store.list("review_report") == []


def test_private_revision_support_id_rejected_before_public_persistence(services):
    research, reviewer, finding = services
    value = draft(finding)
    value["claims"][0]["support_ids"] = ["revision_" + "a" * 32]
    with pytest.raises(V2Error) as exc:
        reviewer.review_draft(value)
    assert exc.value.code == "private_payload_rejected"
    assert research.store.list("answer_draft") == []
    assert research.store.list("review_report") == []
