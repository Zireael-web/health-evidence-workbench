"""A16 fake-only private answer tests; all user decisions are SIMULATED.

Every test provisions a fresh temporary private store. No archive, deployment
configuration, public store, model, network or real human decision is used.
"""
import copy

import pytest

from health_analyzer.v2.common import SignedStore, V2Error, canonical, digest
from health_analyzer.v2.private_answers import (
    PrivateAnswerService, validate_private_answer_artifacts,
    validate_private_answer_draft, validate_private_answer_idempotency,
)
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.research import public_request_guard
from test_records import make_row, coverage

SUBJECT = "FAKE_A16_ANSWER_SUBJECT"
OTHER = "FAKE_A16_ANSWER_OTHER"


@pytest.fixture
def services(tmp_path):
    store = SignedStore(tmp_path / "FAKE_A16_ANSWER.sqlite3", b"FAKE_A16_ANSWER_KEY_ONLY_" * 2, "private-data")
    records = RecordsService(store)
    records.register_subject(SUBJECT, "FAKE A16 answer subject")
    records.register_subject(OTHER, "FAKE A16 other subject")
    yield records, PrivateAnswerService(records)
    store.close()


def simulated_attestation(snapshot_id, snapshot_sha256):
    return {"snapshot_id": snapshot_id, "snapshot_sha256": snapshot_sha256,
            "decision_excerpt": "SIMULATED user decision: confirm this FAKE fixture only",
            "attested_by": "FAKE_TEST_ORCHESTRATOR", "origin": "user_message",
            "message_ref": None, "conversation_ref": None, "ref_availability": "not_provided_by_host"}


def save(records, char="a", value="5.4", day="2026-01-01", *, result=None, attested=True):
    version = records.register_document(SUBJECT, char * 64, "text/csv", 100)
    row = make_row(version, value, day)
    row["analyte_raw"] = "FAKE A16 analyte"
    row["field_anchors"]["analyte_raw"]["excerpt"] = row["analyte_raw"]
    if result is not None:
        row["result"] = result
        row["field_anchors"]["result"]["excerpt"] = result["raw"]
    records.submit_extraction(SUBJECT, version["version_id"], [row], coverage(1))
    preview = records.prepare_review(SUBJECT, version["version_id"])
    decisions = [{"draft_id": item["draft_id"], "action": "confirm", "reason": "SIMULATED FAKE confirmation"} for item in preview["rows"]]
    ack = records.commit_review(SUBJECT, preview["snapshot_id"], preview["snapshot_sha256"], decisions,
                                simulated_attestation(preview["snapshot_id"], preview["snapshot_sha256"]) if attested else None)
    return version, records.store.get("observation_revision", ack["revision_ids"][0], SUBJECT)


def case(records, revisions=(), notes=(), **kwargs):
    return records.select_case_context(SUBJECT, {"revision_ids": [r["revision_id"] for r in revisions],
                                               "context_event_ids": [n["context_event_id"] for n in notes]}, **kwargs)


def fact(revision, *, field="result", expected=None, claim_id="FAKE_CLAIM"):
    return {"claim_id": claim_id, "type": "source_fact", "text": "FAKE prose; no medical conclusion",
            "support_id": revision["revision_id"], "assertion": {"field": field,
            "expected_value": copy.deepcopy(revision["row"][field] if expected is None else expected)}}


def prepare(service, selection, claims, key="FAKE_ANSWER_KEY"):
    return service.prepare_private_answer(SUBJECT, selection["selection_id"], selection["selection_sha256"],
                                          {"claims": claims}, key)


def assert_no_answers(records):
    assert records.store.list("private_answer_draft", SUBJECT) == []
    assert records.store.list("private_answer_review", SUBJECT) == []
    assert not [ack for ack in records.store.list("idempotency", SUBJECT)
                if ack.get("result", {}).get("kind") == "private_answer_review"]


def test_selected_fact_preserves_full_result_and_has_no_release_authority(services):
    records, service = services
    _, revision = save(records)
    selected = case(records, [revision])
    report = prepare(service, selected, [fact(revision)])
    assert report["release_state"] == "needs_revision"
    assert all(report[key] == "not_provided" for key in ("semantic_validation", "medical_validation", "human_validation"))
    assert report["claim_readiness"][0]["assertion"]["expected_value"] == revision["row"]["result"]
    assert report["claim_readiness"][0]["semantic_alignment"] == "not_checked_by_backend"
    fetched = service.get_private_answer_review(SUBJECT, report["review_id"])
    assert fetched["report"] == report and fetched["freshness"]["state"] == "current"
    validate_private_answer_artifacts(fetched["draft"], report, records.store.get)
    with pytest.raises(V2Error) as exc:
        service.get_private_answer_review(OTHER, report["review_id"])
    assert exc.value.code == "WRONG_SUBJECT"
    for private_id in (report["review_id"], report["draft_id"], selected["selection_id"]):
        with pytest.raises(V2Error) as exc:
            public_request_guard({"support_id": private_id})
        assert exc.value.code == "private_payload_rejected"


def test_claim_prose_does_not_receive_backend_semantic_assurance(services):
    records, service = services
    _, revision = save(records)
    claim = fact(revision)
    claim["text"] = "Unrelated FAKE treatment conclusion unsupported by this numeric result"
    report = prepare(service, case(records, [revision]), [claim])
    assert report["checks"][0]["status"] == "ok"
    assert report["release_state"] == "needs_revision"
    assert report["checks"][1]["status"] == "not_checked"


@pytest.mark.parametrize("bad_value", ["0.01", {"kind": "numeric_exact", "raw": "0.01", "decimal": "0.01"},
    {"kind": "numeric_censored", "raw": "<0.01", "decimal": "0.01", "operator": "<", "assurance": "verified"}])
def test_censor_cannot_be_reduced_or_kind_changed(services, bad_value):
    records, service = services
    _, revision = save(records, result={"kind": "numeric_censored", "raw": "<0.01", "decimal": "0.01", "operator": "<"})
    with pytest.raises(V2Error) as exc:
        prepare(service, case(records, [revision]), [fact(revision, expected=bad_value)])
    assert exc.value.code == "private_assertion_mismatch"
    assert_no_answers(records)


def test_note_kind_and_exact_fields_are_independent_of_laboratory_kind(services):
    records, service = services
    _, revision = save(records, result={"kind": "qualitative", "raw": "FAKE NEGATIVE", "value": "negative"})
    note = records.record_context_event(SUBJECT, {"kind": "user_note", "event_type": "FAKE_SYMPTOM",
                                                "text": "FAKE subjective note", "fields": {"severity": "unknown"}})
    selected = case(records, [revision], [note])
    claim = {"claim_id": "FAKE_NOTE", "type": "user_note", "text": "Unchecked FAKE note prose",
             "support_id": note["context_event_id"], "assertion": {"field": "fields", "expected_value": note["fields"]}}
    report = prepare(service, selected, [claim])
    assert report["claim_readiness"][0]["field_origin"] == "user_note"
    assert report["claim_readiness"][0]["clinical_truth"] == "not_provided"
    changed = copy.deepcopy(claim)
    changed["assertion"] = {"field": "text", "expected_value": "Different FAKE note"}
    with pytest.raises(V2Error) as exc:
        prepare(service, selected, [changed], "FAKE_MISMATCH")
    assert exc.value.code == "private_assertion_mismatch"
    source_claim = fact(revision)
    source_claim["support_id"] = note["context_event_id"]
    with pytest.raises(V2Error) as exc:
        prepare(service, selected, [source_claim], "FAKE_KIND_SWAP")
    assert exc.value.code == "private_support_kind_mismatch"


def test_unreviewed_source_statement_cannot_be_a_user_note(services):
    records, service = services
    version, revision = save(records)
    event = records.record_context_event(SUBJECT, {"kind": "source_statement", "event_type": "FAKE_STATEMENT",
        "text": "FAKE source statement", "source_version_id": version["version_id"],
        "field_anchors": {"text": {"version_id": version["version_id"], "source_sha256": version["source_sha256"],
            "field": "text", "locator": {"kind": "csv_cell", "row": 3, "column": 1}, "excerpt": "FAKE source statement"}}})
    claim = {"claim_id": "FAKE_BAD_NOTE", "type": "user_note", "text": "FAKE note claim",
             "support_id": event["context_event_id"], "assertion": {"field": "text", "expected_value": event["text"]}}
    with pytest.raises(V2Error):
        prepare(service, case(records, [revision], [event]), [claim])
    assert_no_answers(records)


def test_unselected_and_untrusted_revisions_are_hard_failures(services):
    records, service = services
    _, trusted = save(records)
    _, other = save(records, "b", "5.6", "2026-02-01")
    _, model_only = save(records, "c", "5.8", "2026-03-01", attested=False)
    selected = case(records, [trusted])
    for revision in (other, model_only):
        with pytest.raises(V2Error) as exc:
            prepare(service, selected, [fact(revision)], "FAKE_" + revision["revision_id"])
        assert exc.value.code == "private_support_kind_mismatch"
    assert_no_answers(records)


def test_review_corrected_value_remains_a_correction(services):
    records, service = services
    _, old = save(records)
    response = records.correct_observation(SUBJECT, old["observation_id"],
        {"result": {"kind": "numeric_exact", "raw": "5.6", "decimal": "5.6"}}, "SIMULATED FAKE reading correction",
        simulated_attestation(old["revision_id"], digest(old)))
    corrected = response["revision"]
    report = prepare(service, case(records, [corrected]), [fact(corrected)])
    state = report["claim_readiness"][0]
    assert state["field_origin"] == "review_corrected"
    assert state["literal_printed_proof"] == "not_provided"


def test_exact_retry_survives_correction_and_getter_separates_current_freshness(services):
    records, service = services
    _, old = save(records)
    selected = case(records, [old])
    claims = [fact(old)]
    report = prepare(service, selected, claims)
    records.correct_observation(SUBJECT, old["observation_id"],
        {"result": {"kind": "numeric_exact", "raw": "5.6", "decimal": "5.6"}}, "SIMULATED FAKE correction",
        simulated_attestation(old["revision_id"], digest(old)))
    assert prepare(service, selected, claims) == report
    fetched = service.get_private_answer_review(SUBJECT, report["review_id"])
    assert fetched["report"] == report
    assert fetched["freshness"]["state"] == "stale"
    assert report["preparation_freshness"]["state"] == "current"
    with pytest.raises(V2Error):
        prepare(service, selected, claims, "FAKE_NEW_STALE_KEY")
    changed = copy.deepcopy(claims)
    changed[0]["text"] = "Changed FAKE prose"
    with pytest.raises(V2Error) as exc:
        prepare(service, selected, changed)
    assert exc.value.code == "idempotency_conflict"
    assert len(records.store.list("private_answer_review", SUBJECT)) == 1


def test_historical_selection_cannot_prepare_a_new_answer(services):
    records, service = services
    _, revision = save(records)
    selected = case(records, [revision], recorded_as_of=revision["recorded_at"])
    with pytest.raises(V2Error) as exc:
        prepare(service, selected, [fact(revision)])
    assert exc.value.code == "case_not_current"
    assert_no_answers(records)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(reported_checks=[]), lambda d: d.update(clinician_confirmed=True),
    lambda d: d.update(release_state="ready"), lambda d: d["claims"][0].update(assurance="human"),
    lambda d: d["claims"][0]["assertion"].update(formula="FAKE"),
    lambda d: d["claims"][0].update(type=["source_fact"]),
    lambda d: d["claims"][0]["assertion"].update(field=["result"]),
    lambda d: d["claims"].append(copy.deepcopy(d["claims"][0])),
])
def test_strict_nested_contract_rejects_authority_and_wrong_types(services, mutate):
    records, service = services
    _, revision = save(records)
    selected = case(records, [revision])
    draft = {"claims": [fact(revision)]}
    mutate(draft)
    with pytest.raises(V2Error):
        service.prepare_private_answer(SUBJECT, selected["selection_id"], selected["selection_sha256"], draft, "FAKE_BAD_INPUT")
    assert_no_answers(records)


def test_private_report_forgery_is_rejected_even_with_rehashed_body(services):
    records, service = services
    _, revision = save(records)
    report = prepare(service, case(records, [revision]), [fact(revision)])
    draft = service.get_private_answer_review(SUBJECT, report["review_id"])["draft"]
    for field, value in (("release_state", "ready"), ("medical_validation", "provided"),
                         ("claim_readiness", [{"claim_id": "FAKE_CLAIM", "type": "source_fact", "semantic_alignment": "ok"}]),
                         ("preparation_freshness", {**report["preparation_freshness"], "source_bytes_checked": True})):
        forged = copy.deepcopy(report)
        forged[field] = value
        forged["report_sha256"] = digest({k: v for k, v in forged.items() if k != "report_sha256"})
        with pytest.raises(V2Error):
            validate_private_answer_artifacts(draft, forged, records.store.get)
    ack = next(x for x in records.store.list("idempotency", SUBJECT) if x.get("result", {}).get("kind") == "private_answer_review")
    validate_private_answer_idempotency(ack, records.store.get)
    ack["request_sha256"] = "f" * 64
    with pytest.raises(V2Error):
        validate_private_answer_idempotency(ack, records.store.get)


def test_getter_rejects_other_valid_report_body_under_requested_envelope(services):
    records, service = services
    _, revision = save(records)
    selected = case(records, [revision])
    first = prepare(service, selected, [fact(revision)], "FAKE_REPORT_A")
    other = prepare(service, selected, [fact(revision)], "FAKE_REPORT_B")
    # SIMULATED valid-MAC relocation in this test's newly owned FAKE store.
    # Every report B graph object is legitimate, so graph validity alone
    # cannot establish that a request for report A retrieved report A.
    envelope = {"domain": "private-data", "kind": "private_answer_review", "object_id": first["review_id"],
                "subject_id": SUBJECT, "payload": other}
    with records.store.transaction():
        records.store._db.execute("UPDATE v2_objects SET payload=?,mac=? WHERE kind=? AND object_id=?",
            (canonical(other).decode("utf-8"), records.store._mac(envelope), "private_answer_review", first["review_id"]))
    with pytest.raises(V2Error) as exc:
        service.get_private_answer_review(SUBJECT, first["review_id"])
    assert exc.value.code == "private_answer_scope_mismatch"
    assert service.get_private_answer_review(SUBJECT, other["review_id"])["report"] == other


def test_no_partial_artifacts_after_failed_second_claim(services):
    records, service = services
    _, revision = save(records)
    bad = fact(revision, expected="wrong FAKE typed value", claim_id="FAKE_BAD")
    with pytest.raises(V2Error):
        prepare(service, case(records, [revision]), [fact(revision), bad])
    assert_no_answers(records)


def test_failed_atomic_write_rolls_back_draft_and_review(services, monkeypatch):
    records, service = services
    _, revision = save(records)
    selected = case(records, [revision])
    original = records.store.put
    def fail_ack(kind, *args, **kwargs):
        if kind == "idempotency":
            raise V2Error("FAKE_SIMULATED_ACK_FAILURE", "SIMULATED fresh test store failure")
        return original(kind, *args, **kwargs)
    monkeypatch.setattr(records.store, "put", fail_ack)
    with pytest.raises(V2Error) as exc:
        prepare(service, selected, [fact(revision)])
    assert exc.value.code == "FAKE_SIMULATED_ACK_FAILURE"
    assert_no_answers(records)


def test_claim_list_and_payload_limits_are_fail_closed():
    with pytest.raises(V2Error):
        validate_private_answer_draft({"claims": []})
    with pytest.raises(V2Error):
        validate_private_answer_draft({"claims": [{}] * 101})
    nested = "FAKE_DEEP"
    for _ in range(30):
        nested = {"FAKE_NESTED": nested}
    with pytest.raises(V2Error) as exc:
        validate_private_answer_draft({"claims": [{"claim_id": "FAKE_DEEP", "type": "user_note", "text": "FAKE",
            "support_id": "context_FAKE", "assertion": {"field": "fields", "expected_value": nested}}]})
    assert exc.value.code == "private_answer_limit"


def test_json_boolean_does_not_equal_a_number_in_note_assertion(services):
    records, service = services
    note = records.record_context_event(SUBJECT, {"kind": "user_note", "event_type": "FAKE_BOOLEAN",
                                                "text": "FAKE boolean note", "fields": {"value": True}})
    claim = {"claim_id": "FAKE_BOOLEAN", "type": "user_note", "text": "FAKE",
             "support_id": note["context_event_id"], "assertion": {"field": "fields", "expected_value": {"value": 1}}}
    with pytest.raises(V2Error) as exc:
        prepare(service, case(records, notes=[note]), [claim])
    assert exc.value.code == "private_assertion_mismatch"
    assert_no_answers(records)


def test_calculated_claim_requires_exact_backend_receipt_same_case_and_metric(services):
    from health_analyzer.v2.private_calculations import PrivateCalculationService
    records, service = services
    _, first = save(records, "a", "0.1")
    _, last = save(records, "b", "0.3", "2026-02-01")
    selected = case(records, [first, last])
    calculator = PrivateCalculationService(records)
    receipt = calculator.create_private_calculation(SUBJECT, selected["selection_id"], selected["selection_sha256"],
        [first["revision_id"], last["revision_id"]], "delta", "FAKE_CALCULATION_KEY")["receipt"]
    claim = {"claim_id": "FAKE_CALCULATED", "type": "calculated", "text": "FAKE backend delta prose",
             "support_id": receipt["calculation_id"], "assertion": {"receipt_sha256": receipt["calculation_sha256"], "metric": "delta"}}
    report = prepare(service, selected, [claim])
    assert report["claim_readiness"][0]["numeric_result"]["decimal"] == "0.2"
    assert report["release_state"] == "needs_revision"
    for assertion in ({"receipt_sha256": "f" * 64, "metric": "delta"},
                      {"receipt_sha256": receipt["calculation_sha256"], "metric": "percent_change"},
                      {"receipt_sha256": receipt["calculation_sha256"], "metric": "delta", "denominator": "0.1"}):
        changed = {**claim, "assertion": assertion}
        with pytest.raises(V2Error):
            prepare(service, selected, [changed], "FAKE_BAD_" + digest(assertion))
    other_selection = case(records, [first, last])
    with pytest.raises(V2Error) as exc:
        prepare(service, other_selection, [claim], "FAKE_DIFFERENT_CASE")
    assert exc.value.code == "private_calculation_scope_mismatch"
