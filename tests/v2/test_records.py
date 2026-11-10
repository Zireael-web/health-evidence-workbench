"""Synthetic record acceptance, scope and transactional boundary regressions."""
import copy
from decimal import Decimal
import pytest

from health_analyzer.v2.common import SignedStore, V2Error, digest
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.contracts import lab_observation, result, clinical_time


def make_anchor(version, field, excerpt, *, row=2, column=1):
    return {"version_id": version["version_id"], "source_sha256": version["source_sha256"], "field": field, "locator": {"kind": "csv_cell", "row": row, "column": column}, "excerpt": excerpt}


def make_row(version, value="5.4", day="2026-01-01", *, row_number=2, known_context=True):
    data = {"analyte_raw": "Synthetic analyte", "analyte_key": "synthetic_analyte", "mapping_status": "confirmed", "result": {"kind": "numeric_exact", "raw": value, "decimal": value}, "unit_raw": "mmol/L", "clinical_time": {"raw": day, "role": "collected", "precision": "date", "value": day}, "reference_intervals": [{"kind": "laboratory_reference", "raw": "3.9–5.5", "low": "3.9", "high": "5.5", "low_inclusive": True, "high_inclusive": True, "unit_raw": "mmol/L"}], "specimen": "serum" if known_context else None, "method": "assay-A" if known_context else None, "missing_reasons": {} if known_context else {"specimen": "not_reported", "method": "not_reported"}, "field_anchors": {}}
    for column, field in enumerate(("analyte_raw", "result", "unit_raw", "clinical_time", "reference_intervals", "specimen", "method"), start=1):
        if field in {"specimen", "method"} and not known_context:
            data["field_anchors"][field] = None
            continue
        excerpt = value if field == "result" else day if field == "clinical_time" else "3.9–5.5" if field == "reference_intervals" else data[field]
        data["field_anchors"][field] = make_anchor(version, field, excerpt, row=row_number, column=column)
    return data


def coverage(count=None):
    return {"status": "complete", "expected_count": count, "expected_count_basis": "source_count" if count is not None else "unknown", "processed_pages": [], "unprocessed_pages": [], "errors": []}


def attest(snapshot):
    return {"snapshot_id": snapshot["snapshot_id"], "snapshot_sha256": snapshot["snapshot_sha256"], "decision_excerpt": "Confirm the shown rows", "attested_by": "conversation-orchestrator", "origin": "user_message", "message_ref": None, "conversation_ref": None, "ref_availability": "not_provided_by_host"}


@pytest.fixture
def records(tmp_path):
    store = SignedStore(tmp_path / "v2.sqlite3", b"p" * 32, "private-data")
    service = RecordsService(store)
    service.register_subject("subject_demo", "Synthetic profile")
    service.register_subject("subject_other", "Other synthetic profile")
    yield service
    store.close()


def document(records, hashchar="a", document_id=None, occurrence=None):
    return records.register_document("subject_demo", hashchar * 64, "text/csv", 100, occurrence, document_id)


def extracted(records, rows=1):
    version = document(records)
    run = records.submit_extraction("subject_demo", version["version_id"], [make_row(version, row_number=n+2) for n in range(rows)], coverage(rows))
    return version, run


def commit(records, snapshot, *, attested=True, key=""):
    decisions = [{"draft_id": row["draft_id"], "action": "confirm"} for row in snapshot["rows"]]
    return records.commit_review("subject_demo", snapshot["snapshot_id"], snapshot["snapshot_sha256"], decisions, attest(snapshot) if attested else None, key)


def test_typed_scalar_preserves_censor_and_rejects_combined_or_float():
    assert result({"kind": "numeric_censored", "raw": "<0,01", "operator": "<", "decimal": "0.01"})["operator"] == "<"
    assert result({"kind": "no_result", "raw": "", "reason": "not_reported"})["raw"] == ""
    for invalid in ({"kind": "numeric_exact", "raw": "5.4", "decimal": 5.4}, {"kind": "numeric_exact", "raw": "5.4 mmol/L 3.9–5.5", "decimal": "5.4"}, {"kind": "numeric_exact", "raw": "5.4", "decimal": "54"}, {"kind": "numeric_censored", "raw": "<0.01", "operator": ">", "decimal": "0.01"}):
        with pytest.raises(V2Error):
            result(invalid)


def test_date_roles_precision_and_order_not_guessed():
    assert clinical_time({"raw": "2026-01", "role": "reported", "precision": "month", "value": "2026-01"})["precision"] == "month"
    for invalid in ({"role": "unknown", "precision": "unknown", "value": "2026-01-01"}, {"raw": "2026-01", "role": "collected", "precision": "month", "value": "2026-01-01"}, {"role": "collected", "precision": "interval", "start": "2026-02-01", "end": "2026-01-01", "start_inclusive": True, "end_inclusive": True}):
        with pytest.raises(V2Error):
            clinical_time(invalid)


def test_field_provenance_and_subject_anchors(records):
    version = document(records)
    row = make_row(version)
    bad = copy.deepcopy(row)
    bad["field_anchors"]["result"]["version_id"] = "version_other"
    with pytest.raises(V2Error, match="registered source version"):
        records.submit_extraction("subject_demo", version["version_id"], [bad], coverage(1))
    bad = copy.deepcopy(row)
    del bad["field_anchors"]["unit_raw"]
    with pytest.raises(V2Error, match="source anchor"):
        records.submit_extraction("subject_demo", version["version_id"], [bad], coverage(1))
    with pytest.raises(V2Error, match="outside requested scope"):
        records.prepare_review("subject_other", version["version_id"])
    assert records.store.list("extraction_run", "subject_demo") == []


def test_caller_cannot_assign_confirmed_or_operator_assurance(records):
    version = document(records)
    bad = make_row(version)
    bad["review_status"] = "user_confirmed"
    with pytest.raises(V2Error):
        records.submit_extraction("subject_demo", version["version_id"], [bad], coverage(1))
    run = records.submit_extraction("subject_demo", version["version_id"], [make_row(version)], coverage(1))
    preview = records.prepare_review("subject_demo", version["version_id"])
    evidence = attest(preview)
    evidence["confirmation_assurance"] = "local_operator_confirmed"
    with pytest.raises(V2Error, match="caller assurance"):
        records.commit_review("subject_demo", preview["snapshot_id"], preview["snapshot_sha256"], [{"draft_id": run["draft_ids"][0], "action": "confirm"}], evidence)
    with pytest.raises(V2Error, match="operator"):
        records.commit_review("subject_demo", preview["snapshot_id"], preview["snapshot_sha256"], [{"draft_id": run["draft_ids"][0], "action": "confirm"}], operation_context="operator")
    assert records.store.list("observation_revision", "subject_demo") == []


def test_confirmation_without_evidence_remains_model_checked(records):
    version, _ = extracted(records)
    preview = records.prepare_review("subject_demo", version["version_id"])
    receipt = commit(records, preview, attested=False)
    assert receipt["confirmation_assurance"] == "none"
    history = records.query_history("subject_demo")
    assert not history["current"]
    assert history["contextual"][0]["review_status"] == "model_checked"
    case = records.select_case_context("subject_demo")
    assert case["observations"] == []


def test_group_review_idempotence_and_exact_payload_conflict(records):
    version, _ = extracted(records, 3)
    preview = records.prepare_review("subject_demo", version["version_id"])
    first = commit(records, preview, key="review-1")
    assert commit(records, preview, key="review-1") == first
    assert len(records.store.list("observation_revision", "subject_demo")) == 3
    decisions = [{"draft_id": row["draft_id"], "action": "reject"} for row in preview["rows"]]
    with pytest.raises(V2Error, match="another request"):
        records.commit_review("subject_demo", preview["snapshot_id"], preview["snapshot_sha256"], decisions, attest(preview), "review-1")
    assert len(records.store.list("review_event", "subject_demo")) == 1
    assert first["coverage"]["reviewed"] == 3


def test_partial_invalid_decision_is_atomic_and_unshown_rows_rejected(records):
    version, run = extracted(records, 2)
    preview = records.prepare_review("subject_demo", version["version_id"], limit=1)
    decisions = [{"draft_id": run["draft_ids"][0], "action": "confirm"}, {"draft_id": run["draft_ids"][1], "action": "confirm"}]
    with pytest.raises(V2Error, match="shown row"):
        records.commit_review("subject_demo", preview["snapshot_id"], preview["snapshot_sha256"], decisions, attest(preview))
    assert records.store.list("observation_revision", "subject_demo") == []
    assert records.store.list("review_event", "subject_demo") == []


def test_two_frozen_previews_stale_after_first_commit(records):
    version, _ = extracted(records)
    first = records.prepare_review("subject_demo", version["version_id"])
    second = records.prepare_review("subject_demo", version["version_id"])
    commit(records, first)
    with pytest.raises(V2Error, match="reviewed after"):
        commit(records, second)
    assert len(records.store.list("observation_revision", "subject_demo")) == 1


def test_source_changes_and_new_extraction_block_commit(records):
    version, _ = extracted(records)
    preview = records.prepare_review("subject_demo", version["version_id"])
    records.source_checker = lambda version: False
    with pytest.raises(V2Error, match="Source bytes changed"):
        commit(records, preview)
    assert not records.store.list("observation_revision", "subject_demo")
    records.source_checker = None
    records.submit_extraction("subject_demo", version["version_id"], [make_row(version, "5.5")], coverage(1))
    with pytest.raises(V2Error, match="new extraction"):
        commit(records, preview)


def test_125_rows_reviewed_in_pages_not_per_document_limit(records):
    version, _ = extracted(records, 125)
    preview = records.prepare_review("subject_demo", version["version_id"], limit=100)
    assert len(preview["rows"]) == 100
    receipt = commit(records, preview)
    assert receipt["coverage"]["unreviewed"] == 25
    second = records.prepare_review("subject_demo", version["version_id"], offset=100)
    assert len(second["rows"]) == 25
    assert commit(records, second)["coverage"]["reviewed"] == 125
    assert len(records.query_history("subject_demo")["current"]) == 125


def test_correction_retains_raw_source_anchor_and_immutable_previous(records):
    version, _ = extracted(records)
    preview = records.prepare_review("subject_demo", version["version_id"])
    commit(records, preview)
    previous = records.store.list("observation_revision", "subject_demo")[0]
    evidence = {**attest(preview), "snapshot_id": previous["revision_id"], "snapshot_sha256": digest(previous)}
    correction = records.correct_observation("subject_demo", previous["observation_id"], {"result": {"kind": "numeric_exact", "raw": "5.6", "decimal": "5.6"}}, "Correct misread result", evidence, "correction-1")
    assert records.store.get("observation_revision", previous["revision_id"], "subject_demo") == previous
    revised = correction["revision"]
    assert revised["supersedes_revision_id"] == previous["revision_id"]
    assert revised["row"]["field_anchors"]["result"]["excerpt"] == "5.4"
    assert revised["row"]["field_status"]["result"] == "review_corrected"
    history = records.query_history("subject_demo")
    assert history["current"][0]["revision_id"] == revised["revision_id"]
    assert history["historical"][0]["revision_id"] == previous["revision_id"]
    assert records.correct_observation("subject_demo", previous["observation_id"], {"result": {"kind": "numeric_exact", "raw": "5.6", "decimal": "5.6"}}, "Correct misread result", evidence, "correction-1") == correction


def test_correction_can_add_unknown_field_without_fabricated_source(records):
    version = document(records)
    records.submit_extraction("subject_demo", version["version_id"], [make_row(version, known_context=False)], coverage(1))
    preview = records.prepare_review("subject_demo", version["version_id"])
    commit(records, preview)
    previous = records.store.list("observation_revision", "subject_demo")[0]
    evidence = {**attest(preview), "snapshot_id": previous["revision_id"], "snapshot_sha256": digest(previous)}
    updated = records.correct_observation("subject_demo", previous["observation_id"], {"method": "assay-B", "missing_reasons": {"specimen": "not_reported"}}, "User provided assay context", evidence)["revision"]
    assert updated["row"]["field_anchors"]["method"] is None
    assert updated["row"]["field_status"]["method"] == "review_corrected"


def test_same_bytes_reimport_keeps_one_version_and_one_point(records):
    occurrence = {"root_id": "synthetic", "relative_path": "first.csv", "source_mode": "synthetic"}
    version = document(records, occurrence=occurrence)
    records.submit_extraction("subject_demo", version["version_id"], [make_row(version)], coverage(1))
    preview = records.prepare_review("subject_demo", version["version_id"])
    commit(records, preview)
    second = document(records, occurrence={**occurrence, "relative_path": "renamed.csv"})
    assert second["version_id"] == version["version_id"]
    assert second["deduplicated"] is True
    repeated = records.submit_extraction("subject_demo", version["version_id"], [make_row(version)], coverage(1))
    assert repeated["deduplicated"] is True
    assert len(records.store.list("file_occurrence", "subject_demo")) == 2
    assert len(records.query_history("subject_demo")["current"]) == 1
