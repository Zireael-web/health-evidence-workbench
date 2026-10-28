"""Independent adversarial accounting tests; no extraction, model or network.

The fabricated scorer inputs below deliberately use the frozen fictional
oracle. They test the score accountant, never qualify as recognition outputs
or evidence for any model-quality claim.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.records import RecordsService


STAGE = Path(__file__).resolve().parents[2]
FIXTURES = STAGE / "work/fixtures"
FREEZE = "7fc3d63ad41686114fc43b974d94e077b72b763199217c821c72986e123e1b10"


@pytest.fixture
def scorer():
    spec = importlib.util.spec_from_file_location(
        "independent_chain_accountant", STAGE / "tests/v2/test_production_chain_transport.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def inputs():
    if not all((FIXTURES / name).is_file() for name in ("expected_rows.json", "scoring_policy.json")):
        pytest.skip("These accountant checks require the explicitly generated frozen artificial fixture pack")
    labels = json.loads((FIXTURES / "expected_rows.json").read_text())["rows"]
    source_ids = sorted({row["source_id"] for row in labels})
    documents = {source: {"version_id": "synthetic_version_" + source,
                          "saved_original": {"source_sha256": "a" * 64}}
                 for source in source_ids}
    snapshots = {source: {"rows": []} for source in source_ids}
    return labels, documents, snapshots


def proposal(expected, document, draft_id):
    row = copy.deepcopy(expected)
    row["missing_reasons"] = {}
    if row["unit_raw"] is None:
        row["missing_reasons"]["unit_raw"] = "not_reported"
    if row["clinical_time"]["value"] is None:
        row["missing_reasons"]["clinical_time"] = "not_reported"
    row["field_anchors"] = {}
    for field in ("analyte_raw", "result", "unit_raw", "reference_intervals",
                  "clinical_time", "specimen", "method"):
        region = row["field_regions"].get(field) or row["metadata_regions"].get(field)
        if region:
            row["field_anchors"][field] = {
                "version_id": document["version_id"],
                "source_sha256": document["saved_original"]["source_sha256"],
                "locator": {"page": expected["page"], "region": copy.deepcopy(region)},
            }
    return {"draft_id": draft_id, "row": row}


def test_no_recognition_rows_retains_every_applicable_frozen_denominator(scorer, inputs):
    labels, documents, snapshots = inputs
    report = scorer.raw_score(documents, snapshots)
    observations = [row for row in labels if row["purpose"] == "subject_observation"]
    assert len(report["records"]) == len(observations) == report["subject_row_denominator"] == 28
    for field, count in report["field_counts"].items():
        key = field.split(".")[-1]
        applicable = sum(key in row["result"] for row in observations) if field in {
            "result.decimal", "result.operator"} else len(observations)
        assert count["applicable"] == applicable
        assert count["incorrect"] == applicable
        assert count["correct"] == 0
    assert len(report["control_proposals"]) == 4
    assert not any(row["proposed"] for row in report["control_proposals"])


def test_duplicate_control_proposals_cannot_be_reported_as_absent(scorer, inputs):
    labels, documents, snapshots = inputs
    control = next(row for row in labels if row["purpose"] == "control_exclusion")
    source = control["source_id"]
    snapshots[source]["rows"] = [proposal(control, documents[source], "fake-control-a"),
                                 proposal(control, documents[source], "fake-control-b")]
    report = scorer.raw_score(documents, snapshots)
    scored = next(row for row in report["control_proposals"] if row["expected_row_id"] == control["row_id"])
    assert scored["proposed"] is True
    assert scored["duplicate_or_ambiguous_matches"] == 2
    assert {row["draft"]["draft_id"] for row in report["unmatched_proposals"]} == {
        "fake-control-a", "fake-control-b"}


def test_report_date_imputation_stays_an_error_and_scoring_never_repairs_input(scorer, inputs):
    labels, documents, snapshots = inputs
    unknown = next(row for row in labels if row["purpose"] == "subject_observation"
                   and row["clinical_time"]["value"] is None)
    source = unknown["source_id"]
    fake = proposal(unknown, documents[source], "fake-imputed-date")
    fake["row"]["clinical_time"] = {**unknown["reported_time"], "role": "collected"}
    snapshots[source]["rows"] = [fake]
    before = copy.deepcopy(snapshots)
    frozen_bytes = (FIXTURES / "expected_rows.json").read_bytes()
    report = scorer.raw_score(documents, snapshots)
    row = next(row for row in report["records"] if row["expected_row_id"] == unknown["row_id"])
    assert row["fields"]["clinical_time"] == "incorrect"
    assert row["actual"]["clinical_time"]["value"] == unknown["reported_time"]["value"]
    assert snapshots == before
    assert (FIXTURES / "expected_rows.json").read_bytes() == frozen_bytes
    assert report["fixture_freeze_sha256"] == FREEZE
    assert report["scored_before_review"] is True
    assert report["golden_used_for_repairs"] is False


@pytest.mark.parametrize("wrong_kind,wrong_result", [
    ("numeric_exact", {"kind": "numeric_exact", "raw": "0.05", "decimal": "0.05"}),
    ("no_result", {"kind": "numeric_exact", "raw": "0", "decimal": "0"}),
])
def test_censor_and_no_result_cannot_gain_credit_from_numeric_substitution(
        scorer, inputs, wrong_kind, wrong_result):
    labels, documents, snapshots = inputs
    wanted = "numeric_censored" if wrong_kind == "numeric_exact" else "no_result"
    expected = next(row for row in labels if row["purpose"] == "subject_observation"
                    and row["result"]["kind"] == wanted)
    source = expected["source_id"]
    fake = proposal(expected, documents[source], "fake-substituted-number")
    fake["row"]["result"] = wrong_result
    snapshots[source]["rows"] = [fake]
    report = scorer.raw_score(documents, snapshots)
    row = next(row for row in report["records"] if row["expected_row_id"] == expected["row_id"])
    assert row["fields"]["result.kind"] == "incorrect"
    assert row["fields"]["result.raw"] == "incorrect"
    if wanted == "numeric_censored":
        assert row["fields"]["result.operator"] == "incorrect"


@pytest.fixture
def records(tmp_path):
    store = SignedStore(tmp_path / "independent-fictional.sqlite3", os.urandom(32), "private-data")
    service = RecordsService(store)
    service.register_subject("synthetic_independent", "SYNTHETIC fictional review tests")
    yield service
    store.close()


def fictional_pair(records, *, attested=True, variant=None):
    """Direct synthetic records exercise read logic; this is no import receipt."""
    spec = importlib.util.spec_from_file_location("independent_row_helper", STAGE / "tests/v2/test_records.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    subject = "synthetic_independent"
    version = records.register_document(subject, "b" * 64, "text/csv", 100)
    rows = [helper.make_row(version, "5.4", "2040-01-01", row_number=2),
            helper.make_row(version, "5.6", "2040-02-01", row_number=3)]
    for row in rows:
        row["field_status"] = {field: "proposed" for field in (
            "analyte_raw", "result", "unit_raw", "clinical_time", "reference_intervals", "specimen", "method")}
    if variant == "reported":
        rows[1]["clinical_time"]["role"] = "reported"
    elif variant == "month":
        rows[1]["clinical_time"] = {"raw": "2040-02", "role": "collected", "precision": "month", "value": "2040-02"}
    elif variant == "unknown":
        rows[1]["clinical_time"] = {"raw": None, "role": "unknown", "precision": "unknown", "value": None}
        rows[1]["field_anchors"]["clinical_time"] = None
        rows[1]["missing_reasons"]["clinical_time"] = "not_reported"
    elif variant == "missing_method":
        rows[1]["missing_reasons"]["method"] = "not_reported"
    elif variant == "mapping_proposed":
        rows[1]["mapping_status"] = "proposed"
    elif variant == "ambiguous":
        rows[1]["field_status"]["method"] = "ambiguous"
    records.submit_extraction(subject, version["version_id"], rows, helper.coverage(2))
    preview = records.prepare_review(subject, version["version_id"])
    decisions = [{"draft_id": row["draft_id"], "action": "confirm"} for row in preview["rows"]]
    simulated = {
        "snapshot_id": preview["snapshot_id"], "snapshot_sha256": preview["snapshot_sha256"],
        "decision_excerpt": "SYNTHETIC SIMULATED whole-row acceptance; real human confirmations zero",
        "attested_by": "fictional_test_orchestrator", "origin": "user_message",
        "message_ref": None, "conversation_ref": None, "ref_availability": "not_provided_by_host"}
    receipt = records.commit_review(subject, preview["snapshot_id"], preview["snapshot_sha256"],
                                    decisions, simulated if attested else None)
    return subject, receipt["revision_ids"]


def test_trusted_whole_row_acceptance_reads_known_proposals_without_rewriting_source(records):
    subject, revision_ids = fictional_pair(records)
    before = [records.store.get("observation_revision", rid, subject) for rid in revision_ids]
    compared = records.compare_observations(subject, revision_ids)
    assert compared["comparison_status"] == "comparable"
    assert compared["arithmetic"]["delta"] == "0.2"
    current = records.query_history(subject)["current"]
    assert len(current) == 2 and all(row["strict_time_eligible"] for row in current)
    assert [records.store.get("observation_revision", rid, subject) for rid in revision_ids] == before
    assert all(row["row"]["field_status"]["clinical_time"] == "proposed" for row in before)


def test_model_only_acceptance_does_not_upgrade_proposed_fields_or_private_case(records):
    subject, revision_ids = fictional_pair(records, attested=False)
    history = records.query_history(subject)
    assert history["current"] == [] and len(history["contextual"]) == 2
    assert not any(row["strict_time_eligible"] for row in history["contextual"])
    compared = records.compare_observations(subject, revision_ids)
    assert compared["arithmetic"]["status"] == "not_computable"
    assert all("not_user_confirmed" in row["reasons"] for row in compared["contextual_only"])
    assert records.select_case_context(subject)["observations"] == []


@pytest.mark.parametrize("variant,reason", [
    ("reported", "clinical_time_not_exact_collection_or_performance"),
    ("month", "clinical_time_not_exact_collection_or_performance"),
    ("unknown", "clinical_time_not_exact_collection_or_performance"),
    ("missing_method", "method_unknown"),
    ("mapping_proposed", "analyte_identity_not_confirmed"),
])
def test_trusted_whole_row_does_not_guess_unknown_time_context_or_mapping(records, variant, reason):
    subject, revision_ids = fictional_pair(records, variant=variant)
    compared = records.compare_observations(subject, revision_ids)
    assert compared["arithmetic"]["status"] == "not_computable"
    assert compared["comparison_status"] != "comparable"
    assert reason in next(row for row in compared["contextual_only"] if row["revision_id"] == revision_ids[1])["reasons"]
    if variant in {"reported", "month", "unknown"}:
        current = records.query_history(subject)["current"]
        assert next(row for row in current if row["revision_id"] == revision_ids[1])["strict_time_eligible"] is False


def test_simulated_whole_row_attestation_cannot_confirm_an_ambiguous_field(records):
    with pytest.raises(V2Error) as caught:
        fictional_pair(records, variant="ambiguous")
    assert caught.value.code == "unresolved_field"
    assert records.store.list("observation_revision", "synthetic_independent") == []
    assert records.store.list("review_event", "synthetic_independent") == []
