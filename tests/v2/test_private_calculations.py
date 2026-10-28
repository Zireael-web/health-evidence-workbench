"""Wholly fictional, newly owned A16 calculation graph regressions."""
import copy

import pytest

from health_analyzer.v2.common import SignedStore, V2Error, digest
from health_analyzer.v2.private_calculations import (
    PrivateCalculationService, validate_calculation_idempotency, validate_calculation_receipt,
    validate_calculation_request,
)
from health_analyzer.v2.records import RecordsService


SUBJECT = "a16_calculation_owned_fictional_subject"


def _attestation(snapshot_id, snapshot_sha256):
    return {"snapshot_id": snapshot_id, "snapshot_sha256": snapshot_sha256,
            "decision_excerpt": "Confirm these wholly fictional A16 calculation test rows",
            "attested_by": "a16-owned-fictional-test-orchestrator", "origin": "user_message",
            "message_ref": None, "conversation_ref": None,
            "ref_availability": "not_provided_by_host"}


def _row(version, value, day, number, *, result_override=None, method="fictional-assay-A", unit="fictional-units/L"):
    result = result_override or {"kind": "numeric_exact", "raw": value, "decimal": value}
    row = {"analyte_raw": "A16 wholly fictional analyte",
           "analyte_key": "a16_owned_fictional_analyte", "mapping_status": "confirmed",
           "result": result, "unit_raw": unit,
           "clinical_time": {"raw": day, "role": "collected", "precision": "date", "value": day},
           "reference_intervals": [], "specimen": "fictional-serum", "method": method,
           "missing_reasons": {"reference_intervals": "not_reported"}
           | ({} if method is not None else {"method": "not_reported"}),
           "field_anchors": {}}
    excerpts = {"analyte_raw": row["analyte_raw"], "result": result["raw"], "unit_raw": unit,
                "clinical_time": day, "reference_intervals": "No fictional interval supplied",
                "specimen": row["specimen"], "method": method}
    for column, (field, excerpt) in enumerate(excerpts.items(), 1):
        row["field_anchors"][field] = None if excerpt is None else {
            "version_id": version["version_id"], "source_sha256": version["source_sha256"],
            "field": field, "locator": {"kind": "csv_cell", "row": number, "column": column},
            "excerpt": excerpt}
    return row


def _make_pair(records, values=("2", "3"), *, result_override=None, method="fictional-assay-A",
               unit="fictional-units/L", same_day=False):
    version = records.register_document(SUBJECT, digest({"fictional": "a16-owned-calculation-source"}),
                                        "text/csv", 400)
    rows = [_row(version, values[0], "2025-01-01", 2),
            _row(version, values[1], "2025-01-01" if same_day else "2025-01-02", 3,
                 result_override=result_override, method=method, unit=unit)]
    records.submit_extraction(SUBJECT, version["version_id"], rows,
                              {"status": "complete", "expected_count": 2, "expected_count_basis": "source_count",
                               "processed_pages": [], "unprocessed_pages": [], "errors": []})
    snapshot = records.prepare_review(SUBJECT, version["version_id"])
    committed = records.commit_review(SUBJECT, snapshot["snapshot_id"], snapshot["snapshot_sha256"],
                                     [{"draft_id": row["draft_id"], "action": "confirm"} for row in snapshot["rows"]],
                                     _attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"]))
    case = records.select_case_context(SUBJECT, {"revision_ids": committed["revision_ids"]})
    return case, committed["revision_ids"]


@pytest.fixture
def records(tmp_path):
    store = SignedStore(tmp_path / "a16-owned-fictional-calculations.sqlite3",
                        b"a16-owned-fictional-calculation-key-material", "private-data")
    records = RecordsService(store)
    records.register_subject(SUBJECT, "Wholly fictional A16 calculation test subject")
    yield records
    store.close()


def _create(service, case, ids, metric="delta", key="a16-owned-fictional-calc-retry"):
    return service.create_private_calculation(SUBJECT, case["selection_id"], case["selection_sha256"], ids, metric, key)


def _reseal(receipt):
    receipt["calculation_sha256"] = digest({key: value for key, value in receipt.items() if key != "calculation_sha256"})
    return receipt


def test_receipt_copies_actual_comparator_and_strict_pair(records, monkeypatch):
    case, ids = _make_pair(records)
    comparator = records.compare_observations
    calls = []
    def observed(*args, **kwargs):
        calls.append((args, kwargs, records.store._depth))
        return comparator(*args, **kwargs)
    monkeypatch.setattr(records, "compare_observations", observed)
    service = PrivateCalculationService(records)
    result = _create(service, case, list(reversed(ids)))
    receipt = result["receipt"]
    assert calls == [((SUBJECT, list(reversed(ids)), "strict"), {}, 1)]
    assert receipt["comparison_snapshot"] == comparator(SUBJECT, list(reversed(ids)), "strict")
    assert receipt["numeric_result"] == {"metric": "delta", "decimal": "1", "unit_raw": "fictional-units/L"}
    assert receipt["arithmetic_policy"]["baseline_revision_id"] == ids[0]
    assert receipt["arithmetic_policy"]["last_revision_id"] == ids[1]
    assert receipt["operation"]["revision_ids"] == list(reversed(ids))
    assert [item["revision_id"] for item in receipt["input_manifest"]] == list(reversed(ids))
    assert all(item["revision"] == records.store.get("observation_revision", item["revision_id"], SUBJECT)
               for item in receipt["input_manifest"])
    assert receipt["calculation_id"].startswith("case_") and len(receipt["calculation_id"]) == 37
    assert validate_calculation_receipt(receipt, records.store.get) == receipt
    assert service.get_private_calculation(SUBJECT, receipt["calculation_id"])["receipt"] == receipt


def test_percent_preserves_production_decimal_denominator_and_policy(records):
    case, ids = _make_pair(records, ("3", "4"))
    receipt = _create(PrivateCalculationService(records), case, ids, "percent_change")["receipt"]
    arithmetic = records.compare_observations(SUBJECT, ids, "strict")["arithmetic"]
    assert receipt["numeric_result"] == {"metric": "percent_change", **arithmetic["percent_change"]}
    assert receipt["arithmetic_policy"]["formula"] == arithmetic["formula"]
    assert receipt["arithmetic_policy"]["rounding_policy"] == arithmetic["rounding_policy"]
    assert receipt["arithmetic_policy"]["time_interval"] == arithmetic["time_interval"]


def test_zero_delta_allowed_zero_percent_baseline_refused_atomically(records):
    case, ids = _make_pair(records, ("0", "0"))
    service = PrivateCalculationService(records)
    receipt = _create(service, case, ids)["receipt"]
    assert receipt["numeric_result"]["decimal"] == "0"
    count = len(records.store.list("idempotency", SUBJECT))
    with pytest.raises(V2Error) as error:
        _create(service, case, ids, "percent_change", "a16-owned-zero-percent")
    assert error.value.code == "calculation_zero_baseline"
    assert records.store.list("private_calculation", SUBJECT) == [receipt]
    assert len(records.store.list("idempotency", SUBJECT)) == count


def test_bounded_inputs_allow_long_and_exponent_production_outputs(records):
    case, ids = _make_pair(records, ("0." + "0" * 125 + "1", "9" * 128))
    service = PrivateCalculationService(records)
    delta = _create(service, case, ids, key="a16-owned-long-delta")["receipt"]
    percent = _create(service, case, ids, "percent_change", "a16-owned-exponent-percent")["receipt"]
    assert len(delta["numeric_result"]["decimal"]) > 128
    assert "E" in percent["numeric_result"]["decimal"]
    for receipt in (delta, percent):
        assert validate_calculation_receipt(receipt, records.store.get) == receipt


@pytest.mark.parametrize("override", [
    {"kind": "numeric_censored", "raw": "<3", "operator": "<", "decimal": "3"},
    {"kind": "qualitative", "raw": "Positive", "value": "positive"},
    {"kind": "semiquantitative", "raw": "++", "value": "++"},
    {"kind": "no_result", "raw": "Cancelled", "reason": "cancelled"},
])
def test_unsupported_result_kinds_do_not_create_receipts(records, override):
    case, ids = _make_pair(records, result_override=override)
    with pytest.raises(V2Error):
        _create(PrivateCalculationService(records), case, ids)
    assert records.store.list("private_calculation", SUBJECT) == []


@pytest.mark.parametrize("kwargs", [{"method": None}, {"method": "fictional-assay-B"},
                                    {"unit": "fictional-other-units/L"}, {"same_day": True}])
def test_unknown_mismatched_context_and_ambiguous_time_refused(records, kwargs):
    case, ids = _make_pair(records, **kwargs)
    with pytest.raises(V2Error):
        _create(PrivateCalculationService(records), case, ids)
    assert records.store.list("private_calculation", SUBJECT) == []


@pytest.mark.parametrize("extra", ["formula", "value", "unit", "rounding", "confirmation_assurance", "assurance", "unknown"])
def test_unknown_caller_fields_rejected_by_strict_request_and_api(records, extra):
    case, ids = _make_pair(records)
    request = {"subject_id": SUBJECT, "selection_id": case["selection_id"],
               "selection_sha256": case["selection_sha256"], "revision_ids": ids,
               "metric": "delta", "idempotency_key": "a16-owned-unknown-field", extra: "caller-data"}
    with pytest.raises(V2Error):
        validate_calculation_request(request)
    with pytest.raises(TypeError):
        PrivateCalculationService(records).create_private_calculation(**request)
    assert records.store.list("private_calculation", SUBJECT) == []


@pytest.mark.parametrize("ids,metric", [([], "delta"), (["revision_a"], "delta"),
                                        (["revision_a", "revision_a"], "delta"),
                                        (["revision_a", "revision_b"], "ratio"),
                                        (["revision_a", "revision_b", "revision_c"], "delta")])
def test_only_two_explicit_distinct_ids_and_supported_metric(records, ids, metric):
    case, _ = _make_pair(records)
    with pytest.raises(V2Error):
        _create(PrivateCalculationService(records), case, ids, metric)


def test_nonselected_input_and_wrong_selection_hash_refused(records):
    case, ids = _make_pair(records)
    narrow = records.select_case_context(SUBJECT, {"revision_ids": [ids[0]]})
    with pytest.raises(V2Error):
        _create(PrivateCalculationService(records), narrow, ids)
    bad = dict(case, selection_sha256="0" * 64)
    with pytest.raises(V2Error):
        _create(PrivateCalculationService(records), bad, ids)
    assert records.store.list("private_calculation", SUBJECT) == []


def test_exact_retry_same_receipt_and_conflicting_request_refused(records, monkeypatch):
    case, ids = _make_pair(records)
    service = PrivateCalculationService(records)
    real_put = records.store.put
    written = []
    def capture(kind, object_id, *args, **kwargs):
        written.append((kind, object_id))
        return real_put(kind, object_id, *args, **kwargs)
    monkeypatch.setattr(records.store, "put", capture)
    first = _create(service, case, ids)
    assert _create(service, case, ids) == first
    assert len(records.store.list("private_calculation", SUBJECT)) == 1
    with pytest.raises(V2Error) as error:
        _create(service, case, ids, "percent_change")
    assert error.value.code == "idempotency_conflict"
    assert all(object_id.startswith("case_") for kind, object_id in written)
    acknowledgement = records.store.list("idempotency", SUBJECT)[0]
    assert validate_calculation_idempotency(acknowledgement, records.store.get) == acknowledgement


def test_acknowledgement_hash_and_unknown_result_fields_rejected(records):
    case, ids = _make_pair(records)
    _create(PrivateCalculationService(records), case, ids)
    acknowledgement = records.store.list("idempotency", SUBJECT)[0]
    wrong_hash = copy.deepcopy(acknowledgement)
    wrong_hash["request_sha256"] = "0" * 64
    with pytest.raises(V2Error):
        validate_calculation_idempotency(wrong_hash, records.store.get)
    extra = copy.deepcopy(acknowledgement)
    extra["result"]["numeric_value"] = "123"
    with pytest.raises(V2Error):
        validate_calculation_idempotency(extra, records.store.get)


def test_partial_failure_rolls_back_receipt_and_idempotence(records, monkeypatch):
    case, ids = _make_pair(records)
    real_put = records.store.put
    def fail_after_receipt(kind, *args, **kwargs):
        value = real_put(kind, *args, **kwargs)
        if kind == "idempotency":
            raise RuntimeError("A16 owned fictional injected post-idempotency-write failure")
        return value
    monkeypatch.setattr(records.store, "put", fail_after_receipt)
    with pytest.raises(RuntimeError):
        _create(PrivateCalculationService(records), case, ids)
    assert records.store.list("private_calculation", SUBJECT) == []
    assert records.store.list("idempotency", SUBJECT) == []


def test_old_receipt_remains_valid_after_correction_new_create_stale_retry_live_freshness(records, monkeypatch):
    case, ids = _make_pair(records)
    service = PrivateCalculationService(records)
    first = _create(service, case, ids)
    previous = records.store.get("observation_revision", ids[0], SUBJECT)
    records.correct_observation(SUBJECT, previous["observation_id"],
                                {"result": {"kind": "numeric_exact", "raw": "20", "decimal": "20"}},
                                "Wholly fictional A16 correction",
                                _attestation(previous["revision_id"], digest(previous)))
    assert validate_calculation_receipt(first["receipt"], records.store.get) == first["receipt"]
    def no_live_recompute(*args, **kwargs):
        raise AssertionError("Saved receipt must never recompute against the current projection")
    monkeypatch.setattr(records, "compare_observations", no_live_recompute)
    retry = _create(service, case, ids)
    assert retry["receipt"] == first["receipt"]
    assert retry["freshness"]["state"] == "stale"
    assert service.get_private_calculation(SUBJECT, first["receipt"]["calculation_id"]) == retry
    with pytest.raises(V2Error):
        _create(service, case, ids, key="a16-owned-stale-new-calculation")


def test_source_unavailability_and_unrelated_coverage_do_not_rewrite_or_stale_selected_operands(records):
    case, ids = _make_pair(records)
    service = PrivateCalculationService(records)
    first = _create(service, case, ids)
    version = records.store.get("observation_revision", ids[0], SUBJECT)["source_version_id"]
    records.record_source_availability(SUBJECT, version, False)
    unrelated = records.register_document(SUBJECT, digest({"fictional": "a16-owned-unrelated-coverage"}), "text/csv", 400)
    records.submit_extraction(SUBJECT, unrelated["version_id"], [_row(unrelated, "8", "2024-01-01", 2)],
                              {"status": "complete", "expected_count": 1, "expected_count_basis": "source_count",
                               "processed_pages": [], "unprocessed_pages": [], "errors": []})
    second = _create(service, case, ids, key="a16-owned-after-metadata-change")
    assert first["receipt"]["numeric_result"] == second["receipt"]["numeric_result"]
    assert first["receipt"]["comparison_snapshot"]["coverage"] != second["receipt"]["comparison_snapshot"]["coverage"]
    assert second["receipt"]["comparison_snapshot"]["included"][0]["source_availability"]["status"] == "unavailable"
    assert validate_calculation_receipt(first["receipt"], records.store.get) == first["receipt"]


@pytest.mark.parametrize("mutation", ["value", "arithmetic", "kind_swap", "endpoint", "hash", "unknown", "operation"])
def test_tampered_or_resealed_receipt_rejected_against_original_graph(records, mutation):
    case, ids = _make_pair(records)
    receipt = copy.deepcopy(_create(PrivateCalculationService(records), case, ids)["receipt"])
    if mutation == "value":
        receipt["numeric_result"]["decimal"] = "999"
    elif mutation == "arithmetic":
        receipt["comparison_snapshot"]["arithmetic"]["delta"] = "999"
    elif mutation == "kind_swap":
        receipt["input_manifest"][0]["revision"]["row"]["result"] = {"kind": "qualitative", "raw": "Positive"}
    elif mutation == "endpoint":
        receipt["arithmetic_policy"]["baseline_revision_id"] = ids[1]
    elif mutation == "hash":
        receipt["calculation_sha256"] = "0" * 64
    elif mutation == "unknown":
        receipt["assurance"] = "operator_confirmed"
    else:
        receipt["operation"]["formula"] = "caller expression"
    if mutation != "hash":
        _reseal(receipt)
    with pytest.raises(V2Error):
        validate_calculation_receipt(receipt, records.store.get)


def test_validator_rejects_case_kind_swap_and_cross_subject_lookup(records):
    case, ids = _make_pair(records)
    receipt = _create(PrivateCalculationService(records), case, ids)["receipt"]
    def swapped(kind, object_id, subject_id):
        if kind == "case_selection":
            return receipt
        return records.store.get(kind, object_id, subject_id)
    with pytest.raises(V2Error):
        validate_calculation_receipt(receipt, swapped)
    other = "a16_calculation_owned_other_fictional_subject"
    records.register_subject(other, "Wholly fictional other A16 calculation subject")
    with pytest.raises(V2Error):
        PrivateCalculationService(records).get_private_calculation(other, receipt["calculation_id"])


def test_recorded_as_of_case_cannot_create_calculation(records):
    case, ids = _make_pair(records)
    historical = records.select_case_context(SUBJECT, {"revision_ids": ids}, recorded_as_of=case["recorded_at"])
    with pytest.raises(V2Error):
        _create(PrivateCalculationService(records), historical, ids)
    assert records.store.list("private_calculation", SUBJECT) == []


@pytest.mark.parametrize("field", ["source_availability", "coverage"])
def test_unknown_fields_in_informational_metadata_are_rejected(records, field):
    case, ids = _make_pair(records)
    receipt = copy.deepcopy(_create(PrivateCalculationService(records), case, ids)["receipt"])
    snapshot = receipt["comparison_snapshot"]
    target = snapshot["included"][0]["source_availability"] if field == "source_availability" else snapshot["coverage"][0]
    target["caller_assurance"] = "operator_confirmed"
    _reseal(receipt)
    with pytest.raises(V2Error):
        validate_calculation_receipt(receipt, records.store.get)
