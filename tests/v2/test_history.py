"""Temporal history, explicit relations and bounded honest comparison."""
import copy
from datetime import datetime, timezone, timedelta
import pytest

from health_analyzer.v2.common import SignedStore, V2Error, digest
from health_analyzer.v2.records import RecordsService
from test_records import make_row, make_anchor, coverage, attest, commit, document, records


def save(records, hashchar, value, day="2026-01-01", *, document_id=None, occurrence=None, row_change=None, attested=True):
    version = document(records, hashchar, document_id, occurrence)
    row = make_row(version, value, day)
    if row_change:
        row_change(row, version)
    records.submit_extraction("subject_demo", version["version_id"], [row], coverage(1))
    preview = records.prepare_review("subject_demo", version["version_id"])
    receipt = commit(records, preview, attested=attested)
    return version, records.store.get("observation_revision", receipt["revision_ids"][0], "subject_demo")


def relation_evidence(version):
    return {"snapshot_id": version["version_id"], "snapshot_sha256": digest({k: v for k, v in version.items() if k != "deduplicated"}), "decision_excerpt": "Confirmed corrected report supersedes previous report", "attested_by": "conversation-orchestrator", "origin": "user_message", "message_ref": None, "conversation_ref": None, "ref_availability": "not_provided_by_host"}


def test_recorded_as_of_is_not_clinical_date(records):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    _, revision = save(records, "a", "5.4", "1999-01-01")
    assert records.query_history("subject_demo", recorded_as_of=cutoff)["current"] == []
    clinical = records.query_history("subject_demo", clinical_interval={"start": "1999-01-01", "end": "1999-12-31"})
    assert clinical["current"][0]["revision_id"] == revision["revision_id"]
    assert not records.query_history("subject_demo", clinical_interval={"start": "2000-01-01", "end": "2000-12-31"})["current"]


def test_as_of_reconstructs_old_revision_after_correction(records):
    _, old = save(records, "a", "5.4")
    cutoff = old["recorded_at"]
    evidence = {"snapshot_id": old["revision_id"], "snapshot_sha256": digest(old), "decision_excerpt": "Correct to 5.6", "attested_by": "orchestrator", "origin": "user_message", "ref_availability": "not_provided_by_host", "message_ref": None}
    records.correct_observation("subject_demo", old["observation_id"], {"result": {"kind": "numeric_exact", "raw": "5.6", "decimal": "5.6"}}, "Correct reading", evidence)
    history = records.query_history("subject_demo", recorded_as_of=cutoff)
    assert history["current"][0]["revision_id"] == old["revision_id"]
    assert history["historical"] == []


def test_source_loss_does_not_remove_confirmed_history(records):
    version, revision = save(records, "a", "5.4")
    records.record_source_availability("subject_demo", version["version_id"], False)
    history = records.query_history("subject_demo")
    assert history["current"][0]["revision_id"] == revision["revision_id"]
    assert history["current"][0]["source_availability"]["status"] == "unavailable"
    preview = records.prepare_review("subject_demo", version["version_id"])
    with pytest.raises(V2Error, match="unavailable source"):
        commit(records, preview)


def test_new_unreviewed_version_does_not_deactivate_old(records):
    first, old = save(records, "a", "5.4")
    second = document(records, "b", first["document_id"])
    records.submit_extraction("subject_demo", second["version_id"], [make_row(second, "5.6")], coverage(1))
    assert [r["revision_id"] for r in records.query_history("subject_demo")["current"]] == [old["revision_id"]]


def test_unresolved_same_path_conflict_blocks_joint_arithmetic(records):
    occurrence = {"root_id": "synthetic", "relative_path": "report.csv", "source_mode": "synthetic"}
    first, old = save(records, "a", "5.4", occurrence=occurrence)
    second, new = save(records, "b", "5.6", occurrence=occurrence)
    history = records.query_history("subject_demo")
    assert len(history["current"]) == 2
    assert history["conflicts"][0]["reason"] == "unresolved_source_version_relation"
    compared = records.compare_observations("subject_demo", [old["revision_id"], new["revision_id"]])
    assert compared["comparison_status"] == "contextual_only"
    assert compared["arithmetic"]["status"] == "not_computable"
    records.set_document_relation("subject_demo", second["version_id"], "supersedes", first["version_id"], "Corrected laboratory report", relation_evidence(second))
    after = records.query_history("subject_demo")
    assert after["current"][0]["revision_id"] == new["revision_id"]
    assert after["historical"][0]["history_status"] == "supersedes"
    assert not after["conflicts"]


def test_unattested_relation_does_not_cancel_record(records):
    first, old = save(records, "a", "5.4")
    second, new = save(records, "b", "5.6")
    records.set_document_relation("subject_demo", second["version_id"], "supersedes", first["version_id"], "Model thinks corrected")
    assert len(records.query_history("subject_demo")["current"]) == 2


def test_confirmed_relation_needs_confirmed_replacing_observation(records):
    first, old = save(records, "a", "5.4")
    second = document(records, "b")
    records.set_document_relation("subject_demo", second["version_id"], "supersedes", first["version_id"], "Corrected report, still pending rows", relation_evidence(second))
    assert records.query_history("subject_demo")["current"][0]["revision_id"] == old["revision_id"]


def test_relation_cycles_rejected(records):
    first, _ = save(records, "a", "5.4")
    second, _ = save(records, "b", "5.6")
    records.set_document_relation("subject_demo", second["version_id"], "supersedes", first["version_id"], "Corrected report", relation_evidence(second))
    with pytest.raises(V2Error, match="cycle"):
        records.set_document_relation("subject_demo", first["version_id"], "supersedes", second["version_id"], "Conflicting correction", relation_evidence(first))


def test_exact_decimal_comparison_and_zero_baseline(records):
    _, first = save(records, "a", "0.1", "2026-01-01")
    _, second = save(records, "b", "0.3", "2026-02-01")
    comparison = records.compare_observations("subject_demo", [first["revision_id"], second["revision_id"]])
    assert comparison["comparison_status"] == "comparable"
    assert comparison["arithmetic"]["delta"] == "0.2"
    assert comparison["arithmetic"]["percent_change"]["decimal"] == "200"
    _, zero = save(records, "c", "0", "2025-12-01")
    comparison = records.compare_observations("subject_demo", [zero["revision_id"], first["revision_id"]])
    assert comparison["arithmetic"]["percent_change"] == {"status": "not_computable", "reason": "zero_baseline"}


def test_unknown_method_and_report_only_time_contextual(records):
    _, first = save(records, "a", "5.4")
    def modify(row, version):
        row["method"] = None
        row["field_anchors"]["method"] = None
        row["missing_reasons"]["method"] = "not_reported"
        row["clinical_time"]["role"] = "reported"
    _, second = save(records, "b", "5.6", "2026-02-01", row_change=modify)
    comparison = records.compare_observations("subject_demo", [first["revision_id"], second["revision_id"]])
    assert comparison["arithmetic"]["status"] == "not_computable"
    assert "method_unknown" in comparison["contextual_only"][0]["reasons"]
    assert "clinical_time_not_exact_collection_or_performance" in comparison["contextual_only"][0]["reasons"]


def test_censored_and_qualitative_never_imputed_numeric(records):
    _, first = save(records, "a", "5.4")
    def censor(row, version):
        row["result"] = {"kind": "numeric_censored", "raw": "<0.01", "decimal": "0.01", "operator": "<"}
        row["field_anchors"]["result"]["excerpt"] = "<0.01"
    _, second = save(records, "b", "0.01", "2026-02-01", row_change=censor)
    compared = records.compare_observations("subject_demo", [first["revision_id"], second["revision_id"]])
    assert compared["arithmetic"]["reason"] == "censored_values_are_bounds_not_exact_numbers"
    assert compared["included"][1]["row"]["result"]["operator"] == "<"


def test_unit_conversion_is_explicitly_unsupported(records):
    _, first = save(records, "a", "5.4")
    def units(row, version):
        row["unit_raw"] = "mg/dL"
        row["field_anchors"]["unit_raw"]["excerpt"] = "mg/dL"
    _, second = save(records, "b", "97.2", "2026-02-01", row_change=units)
    compared = records.compare_observations("subject_demo", [first["revision_id"], second["revision_id"]])
    assert compared["arithmetic"]["status"] == "not_computable"
    assert "unit_conversion_rule_not_supported" in compared["excluded_with_reasons"][0]["reasons"]


def test_model_only_correction_does_not_hide_confirmed_record(records):
    _, old = save(records, "a", "5.4")
    records.correct_observation("subject_demo", old["observation_id"], {"result": {"kind": "numeric_exact", "raw": "5.6", "decimal": "5.6"}}, "Model proposes changed reading")
    history = records.query_history("subject_demo")
    assert history["current"][0]["revision_id"] == old["revision_id"]
    assert history["contextual"][0]["row"]["result"]["raw"] == "5.6"


def test_context_notes_remain_notes_and_case_selection_is_minimal(records):
    _, revision = save(records, "a", "5.4")
    note = records.record_context_event("subject_demo", {"kind": "user_note", "event_type": "symptom", "text": "Synthetic subjective note"})
    assert note["effective_time"]["precision"] == "unknown"
    assert note["fact_status"] == "user_note"
    case = records.select_case_context("subject_demo", {"revision_ids": [revision["revision_id"]]})
    assert case["context_events"] == []
    chosen = records.select_case_context("subject_demo", {"context_event_ids": [note["context_event_id"]]})
    assert chosen["context_events"][0]["fact_status"] == "user_note"
    with pytest.raises(V2Error, match="document fact"):
        records.record_context_event("subject_demo", {"kind": "user_note", "event_type": "symptom", "text": "Note", "source_version_id": "version_fake"})


def test_exports_are_scoped_preserve_lineage_and_escape_formula(records):
    def injected_name(row, version):
        row["analyte_raw"] = "=synthetic formula"
        row["field_anchors"]["analyte_raw"]["excerpt"] = row["analyte_raw"]
    _, revision = save(records, "a", "5.4", row_change=injected_name)
    exported = records.export_history("subject_demo")
    assert exported["objects"]["observation_revision"][0]["revision_id"] == revision["revision_id"]
    assert exported["objects"]["review_snapshot"][0]["rows"][0]["row"]["field_anchors"]
    assert "'=synthetic formula" in records.export_history("subject_demo", "csv")["csv"]
    assert not records.export_history("subject_other")["objects"]["observation_revision"]


def test_supersession_does_not_cancel_other_collection_date(records):
    first = document(records, "a")
    rows = [make_row(first, "5.4", "2026-01-01", row_number=2), make_row(first, "5.8", "2026-01-02", row_number=3)]
    records.submit_extraction("subject_demo", first["version_id"], rows, coverage(2))
    preview = records.prepare_review("subject_demo", first["version_id"])
    old_ids = commit(records, preview)["revision_ids"]
    second, revised = save(records, "b", "5.6", "2026-01-01")
    records.set_document_relation("subject_demo", second["version_id"], "supersedes", first["version_id"], "Only first collection corrected", relation_evidence(second))
    history = records.query_history("subject_demo")
    assert {r["revision_id"] for r in history["current"]} == {old_ids[1], revised["revision_id"]}
    assert history["historical"][0]["revision_id"] == old_ids[0]


def test_ambiguous_two_collections_are_not_collapsed_by_relation(records):
    first = document(records, "a")
    rows = [make_row(first, "5.4", row_number=2), make_row(first, "5.8", row_number=3)]
    records.submit_extraction("subject_demo", first["version_id"], rows, coverage(2))
    preview = records.prepare_review("subject_demo", first["version_id"])
    old_ids = commit(records, preview)["revision_ids"]
    second, revised = save(records, "b", "5.6", document_id=first["document_id"])
    records.set_document_relation("subject_demo", second["version_id"], "supersedes", first["version_id"], "Mapping is still ambiguous", relation_evidence(second))
    history = records.query_history("subject_demo")
    assert len(history["current"]) == 3
    assert len(history["conflicts"][0]["revision_ids"]) == 3
    comparison = records.compare_observations("subject_demo", old_ids + [revised["revision_id"]])
    assert comparison["arithmetic"]["status"] == "not_computable"


def test_raw_date_spelling_does_not_hide_source_version_conflict(records):
    first, old = save(records, "a", "5.4")
    def spelling(row, version):
        row["clinical_time"]["raw"] = "01 January 2026"
        row["field_anchors"]["clinical_time"]["excerpt"] = "01 January 2026"
    _, revised = save(records, "b", "5.6", document_id=first["document_id"], row_change=spelling)
    assert records.query_history("subject_demo")["conflicts"]
    assert records.compare_observations("subject_demo", [old["revision_id"], revised["revision_id"]])["arithmetic"]["status"] == "not_computable"


def test_month_only_history_not_made_into_exact_measurement_date(records):
    def month(row, version):
        row["clinical_time"] = {"raw": "2026-01", "role": "collected", "precision": "month", "value": "2026-01"}
        row["field_anchors"]["clinical_time"]["excerpt"] = "2026-01"
    _, first = save(records, "a", "5.4", row_change=month)
    history = records.query_history("subject_demo", clinical_interval={"start": "2026-01-20", "end": "2026-01-25"})
    assert history["current"][0]["row"]["clinical_time"]["value"] == "2026-01"
    assert history["current"][0]["strict_time_eligible"] is False
    assert records.compare_observations("subject_demo", [first["revision_id"]])["comparison_status"] == "contextual_only"


def test_different_result_scales_not_marked_comparable(records):
    _, first = save(records, "a", "5.4")
    def qualitative(row, version):
        row["result"] = {"kind": "qualitative", "raw": "Detected", "value": "positive"}
        row["field_anchors"]["result"]["excerpt"] = "Detected"
    _, second = save(records, "b", "5.6", "2026-02-01", row_change=qualitative)
    comparison = records.compare_observations("subject_demo", [first["revision_id"], second["revision_id"]])
    assert "different_result_scale" in comparison["excluded_with_reasons"][0]["reasons"]
    assert comparison["arithmetic"]["status"] == "not_computable"


def test_history_confirmation_context_binds_stored_revision_exactly(records):
    _, old = save(records, "a", "5.4")
    item = records.query_history("subject_demo")["current"][0]
    context = item["confirmation_context"]
    assert context == {"snapshot_id": old["revision_id"], "snapshot_sha256": digest(old)}
    evidence = {**context, "decision_excerpt": "Correct shown result to 5.6", "attested_by": "orchestrator", "origin": "user_message", "message_ref": None, "ref_availability": "not_provided_by_host"}
    new = records.correct_observation("subject_demo", old["observation_id"], {"result": {"kind": "numeric_exact", "raw": "5.6", "decimal": "5.6"}}, "Correct shown result", evidence)
    assert new["revision"]["confirmation_assurance"] == "conversation_attested"


def test_literal_unknown_method_is_not_promoted_by_confirmation(records):
    _, first = save(records, "a", "5.4")
    def unknown(row, version):
        row["method"] = "Unknown"
        row["field_status"] = {"method": "unknown"}
        row["field_anchors"]["method"]["excerpt"] = "Unknown"
    _, second = save(records, "b", "5.6", "2026-02-01", row_change=unknown)
    comparison = records.compare_observations("subject_demo", [first["revision_id"], second["revision_id"]])
    assert "method_unknown" in comparison["contextual_only"][0]["reasons"]
    assert comparison["arithmetic"]["status"] == "not_computable"


def test_aware_datetimes_ordered_by_utc_not_printed_offset_strings(records):
    def instant(value):
        def apply(row, version):
            row["clinical_time"] = {"raw": value, "role": "collected", "precision": "datetime", "value": value}
            row["field_anchors"]["clinical_time"]["excerpt"] = value
        return apply
    # Printed 10:00 appears later, but +10 means midnight UTC; 09:00Z is later.
    _, earlier = save(records, "a", "10", row_change=instant("2026-01-01T10:00:00+10:00"))
    _, later = save(records, "b", "20", row_change=instant("2026-01-01T09:00:00Z"))
    comparison = records.compare_observations("subject_demo", [later["revision_id"], earlier["revision_id"]])
    assert comparison["clinical_order"]["status"] == "established"
    assert comparison["included"][0]["revision_id"] == earlier["revision_id"]
    assert comparison["included"][0]["row"]["clinical_time"]["value"] == "2026-01-01T10:00:00+10:00"
    assert comparison["arithmetic"]["baseline_revision_id"] == earlier["revision_id"]
    assert comparison["arithmetic"]["delta"] == "10"
    assert comparison["arithmetic"]["percent_change"]["decimal"] == "100"


def test_same_day_dates_retain_two_draws_without_fabricated_order(records):
    _, first = save(records, "a", "10", "2026-01-01")
    _, second = save(records, "b", "20", "2026-01-01")
    for ids in ([first["revision_id"], second["revision_id"]], [second["revision_id"], first["revision_id"]]):
        comparison = records.compare_observations("subject_demo", ids)
        assert comparison["comparison_status"] == "comparable"
        assert len(comparison["included"]) == 2
        assert comparison["clinical_order"]["status"] == "ambiguous"
        assert comparison["arithmetic"]["status"] == "not_computable"
        assert comparison["arithmetic"]["reason"] == "clinical_order_ambiguous"
        assert "baseline_revision_id" not in comparison["arithmetic"]


@pytest.mark.parametrize("time", [
    {"raw": "2026-01-01T12:00:00", "role": "collected", "precision": "datetime", "value": "2026-01-01T12:00:00"},
    {"raw": "2026-01-02T12:00:00Z", "role": "collected", "precision": "datetime", "value": "2026-01-02T12:00:00Z"},
])
def test_date_datetime_overlap_or_mixed_zone_does_not_invent_order(records, time):
    _, first = save(records, "a", "10", "2026-01-01")
    def apply(row, version):
        row["clinical_time"] = time
        row["field_anchors"]["clinical_time"]["excerpt"] = time["raw"]
    _, second = save(records, "b", "20", row_change=apply)
    comparison = records.compare_observations("subject_demo", [first["revision_id"], second["revision_id"]])
    assert len(comparison["included"]) == 2
    assert comparison["arithmetic"]["reason"] == "clinical_order_ambiguous"


def test_actual_restored_source_live_check_overrides_cached_unavailable(tmp_path):
    import hashlib
    from types import SimpleNamespace
    from health_analyzer.v2.ingest import ImportService, extract_table
    archive = tmp_path / "synthetic_archive"
    archive.mkdir()
    source = archive / "report.csv"
    original = b"analyte;result;unit;collected;specimen;method\nSynthetic;5.4;u;2026-01-01;serum;assay-A\n"
    source.write_bytes(original)
    store = SignedStore(tmp_path / "new_state.sqlite3", b"p" * 32, "private-data")
    records = RecordsService(store)
    imports = ImportService(SimpleNamespace(archive_roots={"demo": {"path": archive, "subject_id": "subject_demo"}}), records)
    try:
        # Simulate an existing v2 version from before original preservation.
        # Ordinary service opening must not retroactively migrate that data.
        records.register_subject("subject_demo", "Synthetic old v2")
        version = records.register_document("subject_demo", hashlib.sha256(original).hexdigest(),
            "text/csv", len(original), occurrence={"root_id": "demo", "relative_path": "report.csv"})
        version_id = version["version_id"]
        rows = extract_table(original.decode(), version)
        records.submit_extraction("subject_demo", version_id, rows, coverage(len(rows)))
        source.unlink()
        refreshed = imports.refresh_source_status("subject_demo", [version_id])
        assert refreshed["sources"][0]["checked_status"] == "unavailable"
        source.write_bytes(original)
        preview = records.prepare_review("subject_demo", version_id)
        # No second refresh is required; commit itself checks actual bytes.
        receipt = commit(records, preview)
        assert receipt["confirmation_assurance"] == "conversation_attested"
        history = records.query_history("subject_demo")
        assert len(history["current"]) == 1
        assert history["current"][0]["source_availability"]["status"] == "available"
        events = records.store.list("source_availability", "subject_demo")
        assert [event["available"] for event in events][-2:] == [False, True]
    finally:
        store.close()
