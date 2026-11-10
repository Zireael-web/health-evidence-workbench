"""Bounded independent engineering regressions; every record is fictional.

Fresh owned stores only. Attributions are explicitly FAKE and simulated, with
no actual human, archive, deployed database, public request, model, or oracle.
"""
import copy

import pytest

from health_analyzer.v2.common import SignedStore, V2Error, canonical, digest
from health_analyzer.v2.private_answers import (
    PrivateAnswerService, validate_private_answer_artifacts,
    validate_private_answer_idempotency,
)
from health_analyzer.v2.private_calculations import (
    PrivateCalculationService, validate_calculation_receipt,
    validate_calculation_request,
)
from health_analyzer.v2.private_cases import resolve_case, validate_case_snapshot
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.recovery import SyntheticRecovery, SyntheticStore, TestKey
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.research import public_request_guard


SUBJECT = "FAKE_A16_INDEPENDENT_SUBJECT"
OTHER = "FAKE_A16_INDEPENDENT_OTHER"
KEY = TestKey("test_a16_independent", b"FAKE INDEPENDENT OWNED TEST MATERIAL " * 2)


def fake_attestation(identifier, sha):
    return {"snapshot_id": identifier, "snapshot_sha256": sha,
            "decision_excerpt": "FAKE SIMULATED user confirms fictional engineering rows; no actual human",
            "attested_by": "FAKE_INDEPENDENT_ORCHESTRATOR", "origin": "user_message",
            "message_ref": None, "conversation_ref": None,
            "ref_availability": "not_provided_by_host"}


def fake_row(version, value, date, row_number):
    row = {"analyte_raw": "FAKE independent analyte", "analyte_key": "fake_independent_analyte",
           "mapping_status": "confirmed", "result": {"kind": "numeric_exact", "raw": value, "decimal": value},
           "unit_raw": "fake-unit", "clinical_time": {"raw": date, "role": "collected", "precision": "date", "value": date},
           "reference_intervals": [], "specimen": "fake-fluid", "method": "fake-assay",
           "missing_reasons": {"reference_intervals": "not_reported"}, "field_anchors": {}}
    for column, field in enumerate(("analyte_raw", "result", "unit_raw", "clinical_time", "reference_intervals", "specimen", "method"), 1):
        excerpt = value if field == "result" else date if field == "clinical_time" else "FAKE no interval" if field == "reference_intervals" else row[field]
        row["field_anchors"][field] = {"version_id": version["version_id"], "source_sha256": version["source_sha256"],
            "field": field, "locator": {"kind": "csv_cell", "row": row_number, "column": column}, "excerpt": excerpt}
    return row


@pytest.fixture
def owned(tmp_path):
    root = tmp_path / "FAKE_INDEPENDENT_OWNED"
    create_synthetic_exercise(root)
    store = SignedStore(root / "FAKE_PRIVATE.sqlite3", KEY.material, "private-data")
    records = RecordsService(store)
    records.register_subject(SUBJECT, "FAKE fictional independent engineering subject")
    records.register_subject(OTHER, "FAKE other fictional subject")
    yield root, records
    store.close()


def seed(records, values=("2", "3"), marker="initial"):
    version = records.register_document(SUBJECT, digest({"FAKE source": marker}), "text/csv", 200)
    rows = [fake_row(version, value, f"2026-01-{index + 1:02d}", index + 2) for index, value in enumerate(values)]
    run_ack = records.submit_extraction(SUBJECT, version["version_id"], rows,
        {"status": "complete", "expected_count": len(rows), "expected_count_basis": "source_count",
         "processed_pages": [], "unprocessed_pages": [], "errors": []})
    run = records.store.get("extraction_run", run_ack["run_id"], SUBJECT)
    snapshot = records.prepare_review(SUBJECT, version["version_id"])
    ack = records.commit_review(SUBJECT, snapshot["snapshot_id"], snapshot["snapshot_sha256"],
        [{"draft_id": row["draft_id"], "action": "confirm"} for row in snapshot["rows"]],
        fake_attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"]))
    revisions = [records.store.get("observation_revision", rid, SUBJECT) for rid in ack["revision_ids"]]
    selection = records.select_case_context(SUBJECT, {"revision_ids": ack["revision_ids"]})
    assert validate_case_snapshot(selection, records.store.get)["selection"] == selection
    return version, run, revisions, selection


def rehash(case):
    case["selection_sha256"] = digest({key: value for key, value in case.items() if key != "selection_sha256"})
    return case


def overlaid(records, kind, object_id, replacement):
    def lookup(request_kind, request_id, subject):
        if (request_kind, request_id) == (kind, object_id):
            return copy.deepcopy(replacement)
        return records.store.get(request_kind, request_id, subject)
    return lookup


def rewrite_owned_valid_mac(records, kind, object_id, replacement):
    envelope = {"domain": "private-data", "kind": kind, "object_id": object_id,
                "subject_id": SUBJECT, "payload": replacement}
    records.store._db.execute("UPDATE v2_objects SET payload=?,mac=? WHERE kind=? AND object_id=?",
        (canonical(replacement).decode(), records.store._mac(envelope), kind, object_id))


def claim(revision, kind="source_fact", field="result"):
    return {"claim_id": "FAKE_CLAIM", "type": kind, "text": "FAKE unchecked prose",
            "support_id": revision["revision_id"],
            "assertion": {"field": field, "expected_value": copy.deepcopy(revision["row"][field])}}


def test_case_exact_scope_body_order_and_source_projection(owned):
    _, records = owned
    _, _, _, selected = seed(records)
    for field, value in (("schema_version", "unsupported"), ("clinician_confirmed", True)):
        changed = rehash(dict(copy.deepcopy(selected), **{field: value}))
        with pytest.raises(V2Error):
            validate_case_snapshot(changed, records.store.get)
    changed = copy.deepcopy(selected)
    changed["observations"].reverse()
    with pytest.raises(V2Error):
        validate_case_snapshot(rehash(changed), records.store.get)
    with pytest.raises(V2Error):
        resolve_case(records, OTHER, selected["selection_id"], selected["selection_sha256"])
    with pytest.raises(V2Error):
        resolve_case(records, SUBJECT, selected["selection_id"], "0" * 64)


def test_readers_are_readonly_and_context_is_selected_only(owned, monkeypatch):
    _, records = owned
    _, _, revisions, _ = seed(records)
    note = records.record_context_event(SUBJECT, {"kind": "user_note", "event_type": "fake_note", "text": "FAKE selected note"})
    records.record_context_event(SUBJECT, {"kind": "user_note", "event_type": "fake_note", "text": "FAKE secret unselected note"})
    seed(records, ("8",), marker="FAKE unrelated source")
    selected = records.select_case_context(SUBJECT, {"revision_ids": [r["revision_id"] for r in revisions],
                                                    "context_event_ids": [note["context_event_id"]]})
    calculations = PrivateCalculationService(records)
    calculated = calculations.create_private_calculation(SUBJECT, selected["selection_id"], selected["selection_sha256"],
        [r["revision_id"] for r in revisions], "delta", "FAKE readonly calculation")["receipt"]
    answers = PrivateAnswerService(records, calculations)
    report = answers.prepare_private_answer(SUBJECT, selected["selection_id"], selected["selection_sha256"],
        {"claims": [claim(revisions[0])]}, "FAKE readonly answer")
    changes = records.store._db.total_changes
    def deny(*args, **kwargs):
        raise AssertionError("Getters must not write or check physical sources")
    monkeypatch.setattr(records.store, "put", deny)
    monkeypatch.setattr(records, "record_source_availability", deny)
    records.source_checker = deny
    context = records.get_case_selection(SUBJECT, selected["selection_id"], selected["selection_sha256"])["context"]
    assert len(context["observations"]) == 2 and context["context_events"] == [note]
    assert len(context["coverage"]) == 1
    assert "FAKE secret unselected note" not in canonical(context).decode()
    assert calculations.get_private_calculation(SUBJECT, calculated["calculation_id"])["receipt"] == calculated
    assert answers.get_private_answer_review(SUBJECT, report["review_id"])["report"] == report
    assert records.store._db.total_changes == changes


def test_case_rejects_extraction_sha_substitution_and_recovery_refuses_valid_mac(owned):
    root, records = owned
    _, run, _, selected = seed(records)
    assert validate_case_snapshot(selected, overlaid(records, "extraction_run", run["run_id"], run))["selection"] == selected
    changed = dict(copy.deepcopy(run), source_sha256="0" * 64)
    with pytest.raises(V2Error):
        validate_case_snapshot(selected, overlaid(records, "extraction_run", run["run_id"], changed))
    rewrite_owned_valid_mac(records, "extraction_run", run["run_id"], changed)
    recovery = SyntheticRecovery(root, test_keys={KEY.key_id: KEY})
    with pytest.raises(V2Error):
        recovery.read_recovery_view([SyntheticStore("private", records.store.path, "private-data", KEY.key_id)])


def test_review_event_must_bind_every_confirmed_decision_and_exact_revision_order(owned):
    _, records = owned
    _, _, revisions, selected = seed(records)
    event = records.store.get("review_event", revisions[0]["review_event_id"], SUBJECT)
    mutations = []
    changed = copy.deepcopy(event); changed["revision_ids"].reverse(); mutations.append(("reversed revision mapping", changed))
    changed = copy.deepcopy(event); changed["revision_ids"].append(changed["revision_ids"][0]); mutations.append(("duplicate revision mapping", changed))
    changed = copy.deepcopy(event); changed["decisions"][0]["patch"] = {"result": {"kind": "numeric_exact", "raw": "99", "decimal": "99"}}
    changed["decisions_sha256"] = digest(changed["decisions"]); mutations.append(("confirm contains unauthorized patch", changed))
    accepted = []
    for label, changed in mutations:
        try:
            validate_case_snapshot(selected, overlaid(records, "review_event", event["review_event_id"], changed))
        except V2Error:
            pass
        else:
            accepted.append(label)
    assert accepted == [], f"Malformed confirmation objects accepted: {accepted}"


def test_later_review_validates_superseded_correction_ancestry(owned):
    root, records = owned
    version, _, revisions, _ = seed(records, ("2",))
    original = revisions[0]
    corrected = records.correct_observation(SUBJECT, original["observation_id"],
        {"result": {"kind": "numeric_exact", "raw": "2.5", "decimal": "2.5"}},
        "FAKE SIMULATED correction", fake_attestation(original["revision_id"], digest(original)))["revision"]
    snapshot = records.prepare_review(SUBJECT, version["version_id"])
    reviewed = records.commit_review(SUBJECT, snapshot["snapshot_id"], snapshot["snapshot_sha256"],
        [{"draft_id": snapshot["rows"][0]["draft_id"], "action": "confirm"}],
        fake_attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"]))
    selected = records.select_case_context(SUBJECT, {"revision_ids": reviewed["revision_ids"]})
    assert validate_case_snapshot(selected, records.store.get)["selection"] == selected
    bad = dict(copy.deepcopy(corrected), confirmation_assurance="authenticated_human")
    with pytest.raises(V2Error):
        validate_case_snapshot(selected, overlaid(records, "observation_revision", corrected["revision_id"], bad))
    rewrite_owned_valid_mac(records, "observation_revision", corrected["revision_id"], bad)
    recovery = SyntheticRecovery(root, test_keys={KEY.key_id: KEY})
    with pytest.raises(V2Error):
        recovery.read_recovery_view([SyntheticStore("private", records.store.path, "private-data", KEY.key_id)])


def test_correction_preserves_snapshot_patch_and_exact_previous_evidence(owned):
    _, records = owned
    _, _, revisions, _ = seed(records, ("2",))
    previous = revisions[0]
    corrected = records.correct_observation(SUBJECT, previous["observation_id"],
        {"result": {"kind": "numeric_exact", "raw": "2.5", "decimal": "2.5"}},
        "FAKE SIMULATED correction", fake_attestation(previous["revision_id"], digest(previous)))["revision"]
    selected = records.select_case_context(SUBJECT, {"revision_ids": [corrected["revision_id"]]})
    verified = validate_case_snapshot(selected, records.store.get)
    binding = verified["revision_bindings"][corrected["revision_id"]]["confirmation_binding"]
    assert binding["kind"] == "correction_event" and binding["previous_revision_sha256"] == digest(previous)
    assert binding["previous_confirmation_binding"]["kind"] == "review_event"
    event = records.store.get("correction_event", corrected["review_event_id"], SUBJECT)
    for field in ("patch", "confirmation_evidence"):
        bad = copy.deepcopy(event)
        if field == "patch":
            bad[field]["result"] = {"kind": "numeric_exact", "raw": "9", "decimal": "9"}
        else:
            bad[field]["snapshot_sha256"] = "0" * 64
        with pytest.raises(V2Error):
            validate_case_snapshot(selected, overlaid(records, "correction_event", event["correction_event_id"], bad))


def test_case_metadata_and_selector_are_typed_after_rehash(owned):
    root, records = owned
    _, _, _, selected = seed(records)
    mutations = []
    bad = copy.deepcopy(selected); bad["selector"]["clinician_confirmed"] = True; mutations.append(("unknown selector assurance", bad))
    bad = copy.deepcopy(selected); bad["coverage"][0]["reviewed"] = True; mutations.append(("boolean coverage count", bad))
    bad = copy.deepcopy(selected); bad["observations"][0]["source_availability"]["status"] = "authenticated_source"; mutations.append(("unknown availability assurance", bad))
    accepted = []
    for label, bad in mutations:
        try:
            validate_case_snapshot(rehash(bad), records.store.get)
        except V2Error:
            pass
        else:
            accepted.append(label)
    assert accepted == [], f"Malformed frozen metadata accepted: {accepted}"
    rewrite_owned_valid_mac(records, "case_selection", selected["selection_id"], bad)
    recovery = SyntheticRecovery(root, test_keys={KEY.key_id: KEY})
    with pytest.raises(V2Error):
        recovery.read_recovery_view([SyntheticStore("private", records.store.path, "private-data", KEY.key_id)])


def test_answer_exact_kind_whole_value_metadata_and_dlp(owned):
    _, records = owned
    _, _, revisions, selected = seed(records)
    answers = PrivateAnswerService(records)
    bad = claim(revisions[0]); bad["assertion"]["expected_value"]["decimal"] = "2.00"
    with pytest.raises(V2Error):
        answers.prepare_private_answer(SUBJECT, selected["selection_id"], selected["selection_sha256"], {"claims": [bad]}, "FAKE mismatch")
    bad = claim(revisions[0], kind="user_note", field="analyte_raw")
    with pytest.raises(V2Error):
        answers.prepare_private_answer(SUBJECT, selected["selection_id"], selected["selection_sha256"], {"claims": [bad]}, "FAKE kind swap")
    bad = claim(revisions[0]); bad["support_id"] = "evidence_FAKE_metadata_only"
    with pytest.raises(V2Error):
        answers.prepare_private_answer(SUBJECT, selected["selection_id"], selected["selection_sha256"], {"claims": [bad]}, "FAKE metadata")
    report = answers.prepare_private_answer(SUBJECT, selected["selection_id"], selected["selection_sha256"],
        {"intent": "clinical_action", "claims": [claim(revisions[0])]}, "FAKE needs review")
    assert report["release_state"] == "needs_revision"
    assert all(report[field] == "not_provided" for field in ("semantic_validation", "medical_validation", "human_validation"))
    for identifier in (report["draft_id"], report["review_id"], selected["selection_id"]):
        assert identifier.startswith("case_")
        with pytest.raises(V2Error):
            public_request_guard({"support_id": identifier})
    other_report = answers.prepare_private_answer(SUBJECT, selected["selection_id"], selected["selection_sha256"],
        {"claims": [claim(revisions[0])]}, "FAKE second valid report")
    rewrite_owned_valid_mac(records, "private_answer_review", report["review_id"], other_report)
    with pytest.raises(V2Error):
        answers.get_private_answer_review(SUBJECT, report["review_id"])


def test_calculation_uses_production_decimal_outputs_and_refuses_free_formula(owned):
    _, records = owned
    _, _, revisions, selected = seed(records, ("0." + "0" * 125 + "1", "9" * 128))
    ids = [r["revision_id"] for r in revisions]
    comparison = records.compare_observations(SUBJECT, ids, "strict")
    receipt = PrivateCalculationService(records).create_private_calculation(SUBJECT, selected["selection_id"],
        selected["selection_sha256"], ids, "percent_change", "FAKE exponent percent")["receipt"]
    assert "E" in receipt["numeric_result"]["decimal"]
    assert receipt["numeric_result"] == {"metric": "percent_change", **comparison["arithmetic"]["percent_change"]}
    assert receipt["comparison_snapshot"] == comparison
    assert [item["revision"] for item in receipt["input_manifest"]] == revisions
    assert all(item["revision"]["source_sha256"] and item["revision"]["source_version_id"]
               and item["revision"]["draft_id"] and item["revision"]["extraction_run_id"] for item in receipt["input_manifest"])
    request = {"subject_id": SUBJECT, "selection_id": selected["selection_id"], "selection_sha256": selected["selection_sha256"],
               "revision_ids": ids, "metric": "delta", "idempotency_key": "FAKE formula", "formula": "last/baseline"}
    with pytest.raises(V2Error):
        validate_calculation_request(request)
    with pytest.raises(V2Error):
        public_request_guard({"support_id": receipt["calculation_id"]})


def test_old_receipts_ack_and_get_freshness_survive_correction_without_new_claim(owned):
    _, records = owned
    _, _, revisions, selected = seed(records)
    ids = [r["revision_id"] for r in revisions]
    calculations = PrivateCalculationService(records)
    calc_args = (SUBJECT, selected["selection_id"], selected["selection_sha256"], ids, "delta", "FAKE immutable calculation")
    receipt = calculations.create_private_calculation(*calc_args)["receipt"]
    answers = PrivateAnswerService(records, calculations)
    draft = {"claims": [{"claim_id": "FAKE_CALCULATED", "type": "calculated", "text": "FAKE unchecked numeric prose",
        "support_id": receipt["calculation_id"], "assertion": {"receipt_sha256": receipt["calculation_sha256"], "metric": "delta"}}]}
    answer_args = (SUBJECT, selected["selection_id"], selected["selection_sha256"], draft, "FAKE immutable answer")
    report = answers.prepare_private_answer(*answer_args)
    frozen = records.store.get("private_answer_draft", report["draft_id"], SUBJECT)
    original = revisions[0]
    records.correct_observation(SUBJECT, original["observation_id"],
        {"result": {"kind": "numeric_exact", "raw": "2.5", "decimal": "2.5"}},
        "FAKE SIMULATED correction", fake_attestation(original["revision_id"], digest(original)))
    assert validate_calculation_receipt(receipt, records.store.get) == receipt
    validate_private_answer_artifacts(frozen, report, records.store.get)
    for ack in records.store.list("idempotency", SUBJECT):
        if ack["result"].get("kind") == "private_answer_review":
            validate_private_answer_idempotency(ack, records.store.get)
    assert answers.prepare_private_answer(*answer_args) == report
    assert calculations.create_private_calculation(*calc_args)["receipt"] == receipt
    fetched = answers.get_private_answer_review(SUBJECT, report["review_id"])
    assert fetched["report"]["preparation_freshness"]["state"] == "current"
    assert fetched["freshness"]["state"] == "stale"
    with pytest.raises(V2Error):
        answers.prepare_private_answer(*answer_args[:-1], "FAKE new stale answer")
    with pytest.raises(V2Error):
        calculations.create_private_calculation(*calc_args[:-1], "FAKE new stale calculation")
    current = records.select_case_context(SUBJECT)
    historical = records.select_case_context(SUBJECT, recorded_as_of=current["recorded_at"])
    assert records.get_case_selection(SUBJECT, historical["selection_id"], historical["selection_sha256"])["freshness"]["state"] == "historical"
    with pytest.raises(V2Error):
        resolve_case(records, SUBJECT, historical["selection_id"], historical["selection_sha256"])
