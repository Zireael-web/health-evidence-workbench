"""Frozen A06/A09 artificial gates, through service, subprocess CLI and stdio MCP.

Every attestation below is SIMULATED. The service's conversation_attested value
is exercised as a contract branch, never described as real human confirmation.
No clinical reports, production keys, private databases or network are used.
"""
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from health_analyzer.v2.common import SignedStore, V2Error, canonical, digest
from health_analyzer.v2.contracts import ROW_FIELDS
from health_analyzer.v2.records import RecordsService


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = Path(__file__).resolve().parent / "fixtures/synthetic-chain-corrections-matrix.json"
MATRIX_SHA256 = "7af20091ac767b7ed152ec2668f371bfbbb2f621fed00a1fab65d783d2b5ff99"
MATRIX = json.loads(MATRIX_PATH.read_text())
SUBJECT = "synthetic_chain_subject"
OTHER = "synthetic_chain_other"
BASE_MAPPING = {
    "analyte_key": "synthetic_analyte", "mapping_status": "confirmed",
    "measurement_property": "synthetic_substance_concentration",
    "subtype": "synthetic_subtype_A", "unit_code": "SYNTHETIC-unit-proposal",
}


def evidence(name, payload):
    """Opt-in artificial request/response evidence; never serialize a key."""
    directory = os.environ.get("SYNTHETIC_CHAIN_EVIDENCE_DIR")
    if directory:
        destination = Path(directory).resolve()
        assert destination == (ROOT / "work/corrections/evidence").resolve()
        destination.mkdir(exist_ok=True)
        (destination / (name + ".json")).write_text(json.dumps({
            "scope": "SYNTHETIC ONLY", "matrix_sha256": MATRIX_SHA256,
            "human_confirmation": False, **payload,
        }, ensure_ascii=False, indent=2) + "\n")


def simulated_attestation(object_id, object_sha256):
    return {
        "snapshot_id": object_id, "snapshot_sha256": object_sha256,
        "decision_excerpt": "SYNTHETIC SIMULATED acceptance for automated contract test; no human decision",
        "attested_by": "SYNTHETIC test adapter; not a human",
        "origin": "user_message", "message_ref": None, "conversation_ref": None,
        "ref_availability": "not_provided_by_host",
    }


def shown_attestation(snapshot):
    return simulated_attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"])


def revision_attestation(revision):
    context = revision.get("confirmation_context")
    return simulated_attestation(context["snapshot_id"], context["snapshot_sha256"]) if context else simulated_attestation(revision["revision_id"], digest(revision))


def immutable_revision(revision):
    """Remove documented query-only projection fields before exact readback."""
    return {key: value for key, value in revision.items() if key not in {
        "source_availability", "strict_time_eligible", "confirmation_context",
        "history_status", "replacement",
    }}


def artificial_row(version, value="5.4", day="2026-01-01", row_number=2,
                   reference="3.9-5.5", low="3.9", high="5.5"):
    row = {
        **BASE_MAPPING, "analyte_raw": "SYNTHETIC analyte", "loinc": None,
        "result": {"kind": "numeric_exact", "raw": value, "decimal": value},
        "unit_raw": "mmol/L",
        "clinical_time": {"raw": day, "role": "collected", "precision": "date", "value": day},
        "reference_intervals": [{"kind": "laboratory_reference", "raw": reference,
                                 "low": low, "high": high, "low_inclusive": True,
                                 "high_inclusive": True, "unit_raw": "mmol/L"}],
        "specimen": "SYNTHETIC serum", "method": "SYNTHETIC assay-A",
        "device": "SYNTHETIC analyzer-A", "lab_flag_raw": "SYNTHETIC N",
        "missing_reasons": {}, "field_anchors": {},
    }
    for column, field in enumerate(("analyte_raw", "result", "unit_raw", "clinical_time",
                                     "reference_intervals", "specimen", "method", "device",
                                     "lab_flag_raw"), 1):
        excerpt = value if field == "result" else day if field == "clinical_time" else reference if field == "reference_intervals" else row[field]
        row["field_anchors"][field] = {
            "version_id": version["version_id"], "source_sha256": version["source_sha256"],
            "field": field, "locator": {"kind": "csv_cell", "row": row_number, "column": column},
            "excerpt": excerpt,
        }
    return row


def coverage(count):
    return {"status": "complete", "expected_count": count,
            "expected_count_basis": "source_count", "processed_pages": [],
            "unprocessed_pages": [], "errors": []}


@pytest.fixture
def service(tmp_path):
    # This key is artificial, generated in process and never argv/env/output.
    store = SignedStore(tmp_path / "synthetic.sqlite3", os.urandom(32), "private-data")
    records = RecordsService(store)
    records.register_subject(SUBJECT, "SYNTHETIC test subject; no real identity")
    records.register_subject(OTHER, "SYNTHETIC separate test subject")
    yield records
    store.close()


def save_service(records, index=0, count=1, value="5.4", day="2026-01-01", reference="3.9-5.5", low="3.9", high="5.5"):
    source = f"SYNTHETIC source {index}".encode()
    version = records.register_document(SUBJECT, hashlib.sha256(source).hexdigest(), "text/csv", len(source))
    rows = [artificial_row(version, value, day, n+2, reference, low, high) for n in range(count)]
    run = records.submit_extraction(SUBJECT, version["version_id"], rows, coverage(count))
    preview = records.prepare_review(SUBJECT, version["version_id"])
    decisions = [{"draft_id": row["draft_id"], "action": "confirm"} for row in preview["rows"]]
    receipt = records.commit_review(SUBJECT, preview["snapshot_id"], preview["snapshot_sha256"], decisions, shown_attestation(preview))
    revisions = [records.store.get("observation_revision", r, SUBJECT) for r in receipt["revision_ids"]]
    return version, run, preview, revisions


def inventory(store):
    # Byte-exact signed envelope witness, including immutable old payload/mac.
    return [tuple(row) for row in store._db.execute("SELECT kind, object_id, subject_id, payload, mac FROM v2_objects ORDER BY kind, object_id")]


def old_envelope(store, revision_id):
    return tuple(store._db.execute("SELECT payload, mac FROM v2_objects WHERE kind='observation_revision' AND object_id=?", (revision_id,)).fetchone())


def test_frozen_matrix_covers_entire_actual_correction_allowlist():
    assert hashlib.sha256(MATRIX_PATH.read_bytes()).hexdigest() == MATRIX_SHA256
    allowed = ROW_FIELDS - {"field_anchors", "panel_key", "extraction_method", "field_status"}
    assert set(MATRIX["allowed_fields"]) == allowed
    assert set().union(*(set(case["patch"]) for case in MATRIX["corrections"])) == allowed
    assert "notes" not in ROW_FIELDS
    assert MATRIX["frozen_before_runtime_calls"] is True


@pytest.mark.parametrize("case", MATRIX["corrections"], ids=lambda c: c["id"])
def test_service_every_typed_correction_preserves_old_row_and_source_anchors(service, case):
    _, _, _, saved = save_service(service)
    previous = saved[0]
    before = old_envelope(service.store, previous["revision_id"])
    patch = copy.deepcopy(case["patch"])
    request = {"subject_id": SUBJECT, "observation_id": previous["observation_id"],
               "patch": patch, "reason": "SYNTHETIC automated correction test",
               "conversation_attestation": revision_attestation(previous),
               "idempotency_key": "synthetic_" + case["id"]}
    result = service.correct_observation(**request)
    revision = result["revision"]
    assert old_envelope(service.store, previous["revision_id"]) == before
    assert service.store.get("observation_revision", previous["revision_id"], SUBJECT) == previous
    assert revision["row"]["field_anchors"] == previous["row"]["field_anchors"]
    assert revision["source_sha256"] == previous["source_sha256"]
    assert revision["supersedes_revision_id"] == previous["revision_id"]
    for field, value in patch.items():
        assert revision["row"][field] == value
        if field != "missing_reasons":
            assert revision["row"]["field_status"][field] == "review_corrected"
    state = inventory(service.store)
    assert service.correct_observation(**request) == result
    assert inventory(service.store) == state
    history = service.query_history(SUBJECT)
    assert [r["revision_id"] for r in history["current"]] == [revision["revision_id"]]
    assert [r["revision_id"] for r in history["historical"]] == [previous["revision_id"]]
    evidence("service-correction-" + case["id"], {
        "transport": "RecordsService in process", "request": request, "result": result,
        "old_signed_envelope_unchanged": True, "all_source_anchors_unchanged": True,
        "idempotent_replay_writes": 0,
    })


@pytest.mark.parametrize("case", MATRIX["forbidden_corrections"] + MATRIX["invalid_corrections"], ids=lambda c: c["id"])
def test_service_invalid_or_forbidden_corrections_are_atomic(service, case):
    _, _, _, saved = save_service(service)
    previous = saved[0]
    before = inventory(service.store)
    request = {"subject_id": SUBJECT, "observation_id": previous["observation_id"],
               "patch": copy.deepcopy(case["patch"]), "reason": "SYNTHETIC forbidden correction",
               "conversation_attestation": revision_attestation(previous), "idempotency_key": "synthetic_reject"}
    with pytest.raises(V2Error) as caught:
        service.correct_observation(**request)
    assert caught.value.code == case.get("code", "invalid_patch")
    assert inventory(service.store) == before
    evidence("service-rejected-" + case["id"], {"transport": "RecordsService in process",
             "request": request, "result": {"error": caught.value.to_dict()}, "signed_inventory_unchanged": True})


def test_service_different_laboratory_references_stay_with_their_own_result(service):
    _, _, _, a = save_service(service, 0, value="5.4", day="2026-01-01")
    _, _, _, b = save_service(service, 1, value="5.6", day="2026-02-01", reference="4.2-6.2", low="4.2", high="6.2")
    request = {"subject_id": SUBJECT, "revision_ids": [b[0]["revision_id"], a[0]["revision_id"]]}
    comparison = service.compare_observations(**request)
    assert comparison["comparison_status"] == "comparable"
    assert comparison["arithmetic"]["delta"] == "0.2"
    pairs = [(r["row"]["result"]["raw"], r["row"]["reference_intervals"][0]["raw"]) for r in comparison["included"]]
    assert pairs == [("5.4", "3.9-5.5"), ("5.6", "4.2-6.2")]
    evidence("service-comparison-own-references", {"transport": "RecordsService in process", "request": request, "result": comparison})


@pytest.mark.parametrize("case", MATRIX["comparison_cases"], ids=lambda c: c["id"])
def test_service_mismatches_unknowns_and_conversion_guess_never_become_numeric_trend(service, case):
    _, _, _, a = save_service(service, 0)
    _, _, _, b = save_service(service, 1, value="5.6", day="2026-02-01")
    changed = service.correct_observation(SUBJECT, b[0]["observation_id"], case["patch"],
                  "SYNTHETIC comparison adversarial correction", revision_attestation(b[0]))["revision"]
    request = {"subject_id": SUBJECT, "revision_ids": [a[0]["revision_id"], changed["revision_id"]]}
    result = service.compare_observations(**request)
    assert result["arithmetic"]["status"] == "not_computable"
    assert result["comparison_status"] != "comparable"
    assert case["reason"] in next(r for r in result[case["bucket"]] if r["revision_id"] == changed["revision_id"])["reasons"]
    evidence("service-comparison-" + case["id"], {"transport": "RecordsService in process", "request": request, "result": result})


def test_service_censored_bound_preserved_and_notes_have_separate_context_kind(service):
    _, _, _, a = save_service(service, 0)
    _, _, _, b = save_service(service, 1, value="5.6", day="2026-02-01")
    bound = {"result": {"kind": "numeric_censored", "raw": "<0.01", "decimal": "0.01", "operator": "<"}}
    changed = service.correct_observation(SUBJECT, b[0]["observation_id"], bound, "SYNTHETIC bound", revision_attestation(b[0]))["revision"]
    comparison = service.compare_observations(SUBJECT, [a[0]["revision_id"], changed["revision_id"]])
    assert comparison["arithmetic"]["reason"] == "censored_values_are_bounds_not_exact_numbers"
    assert comparison["included"][1]["row"]["result"] == bound["result"]
    before = service.store.list("observation_revision", SUBJECT)
    note = service.record_context_event(SUBJECT, {"kind": "user_note", "event_type": "synthetic_note", "text": "SYNTHETIC subjective note"})
    assert note["fact_status"] == "user_note"
    assert service.store.list("observation_revision", SUBJECT) == before
    evidence("service-bounds-and-notes", {"transport": "RecordsService in process", "comparison": comparison, "separate_note": note})


def test_service_scope_staleness_and_partial_invalid_transactions(service):
    version, run, preview, saved = save_service(service, count=2)
    fresh = service.prepare_review(SUBJECT, version["version_id"])
    failures = []
    def rejected(name, callable_, code):
        before = inventory(service.store)
        with pytest.raises(V2Error) as caught:
            callable_()
        assert caught.value.code == code
        assert inventory(service.store) == before
        failures.append({"gate": name, "error": caught.value.to_dict(), "signed_inventory_unchanged": True})
    good = {"draft_id": run["draft_ids"][0], "action": "confirm"}
    rejected("wrong_subject", lambda: service.commit_review(OTHER, fresh["snapshot_id"], fresh["snapshot_sha256"], [good], shown_attestation(fresh)), "WRONG_SUBJECT")
    rejected("partial_invalid", lambda: service.commit_review(SUBJECT, fresh["snapshot_id"], fresh["snapshot_sha256"], [good, {"draft_id": run["draft_ids"][1], "action": "correct_and_confirm", "patch": {"result": {"kind": "numeric_exact", "raw": "6", "decimal": "60"}}, "reason": "SYNTHETIC invalid second row"}], shown_attestation(fresh), "synthetic_atomic"), "invalid_result")
    narrow = service.prepare_review(SUBJECT, version["version_id"], limit=1)
    rejected("unshown", lambda: service.commit_review(SUBJECT, narrow["snapshot_id"], narrow["snapshot_sha256"], [good, {"draft_id": run["draft_ids"][1], "action": "confirm"}], shown_attestation(narrow)), "unshown_row")
    rejected("stale_review", lambda: service.commit_review(SUBJECT, preview["snapshot_id"], preview["snapshot_sha256"], [good], shown_attestation(preview)), "stale_review")
    previous = saved[0]
    rejected("wrong_subject_correction", lambda: service.correct_observation(OTHER, previous["observation_id"], {"method": "SYNTHETIC assay-B"}, "SYNTHETIC scope", revision_attestation(previous)), "not_found")
    patch = {"result": {"kind": "numeric_exact", "raw": "5.8", "decimal": "5.8"}}
    corrected = service.correct_observation(SUBJECT, previous["observation_id"], patch, "SYNTHETIC revision", revision_attestation(previous), "synthetic_corrected")
    rejected("stale_correction", lambda: service.correct_observation(SUBJECT, previous["observation_id"], {"method": "SYNTHETIC assay-B"}, "SYNTHETIC stale", revision_attestation(previous)), "confirmation_scope_mismatch")
    rejected("idempotency_conflict", lambda: service.correct_observation(SUBJECT, previous["observation_id"], {"method": "SYNTHETIC assay-B"}, "SYNTHETIC stale", revision_attestation(previous), "synthetic_corrected"), "idempotency_conflict")
    service.source_checker = lambda version: False
    rejected("source_changed", lambda: service.correct_observation(SUBJECT, previous["observation_id"], {"method": "SYNTHETIC assay-B"}, "SYNTHETIC source changed", revision_attestation(corrected["revision"])), "stale_source")
    evidence("service-transaction-gates", {"transport": "RecordsService in process", "failures": failures})


def create_transport_configuration(tmp_path):
    from health_analyzer.v2.configuration import initialize
    archive = tmp_path / "synthetic-inputs"
    archive.mkdir()
    header = "analyte,result,unit,collected,reference,specimen,method,flag\n"
    body = "".join("SYNTHETIC analyte,5.4,mmol/L,2026-01-01,3.9-5.5,SYNTHETIC serum,SYNTHETIC assay-A,SYNTHETIC N\n" for _ in MATRIX["corrections"])
    (archive / "matrix.csv").write_text(header + body)
    (archive / "comparison.csv").write_text(header +
        "SYNTHETIC analyte,5.4,mmol/L,2026-01-01,3.9-5.5,SYNTHETIC serum,SYNTHETIC assay-A,SYNTHETIC N\n" +
        "SYNTHETIC analyte,5.6,mmol/L,2026-02-01,4.2-6.2,SYNTHETIC serum,SYNTHETIC assay-A,SYNTHETIC N\n")
    # Fresh explicit artificial config. Bootstrap handles key descriptors; test
    # never reads a key file, sets a key environment variable or passes raw argv.
    return initialize(tmp_path / "synthetic-config.json", tmp_path / "synthetic-data", isolation="host",
                      deployment_id="synthetic_chain_corrections",
                      archive_roots={"synthetic": {"path": str(archive), "subject_id": SUBJECT}})


async def exercise_actual_transport(invoke, name):
    trace = []
    async def call(tool, arguments, *, fails=False):
        result = await invoke(tool, arguments)
        trace.append({"tool": tool, "request": copy.deepcopy(arguments), "result": copy.deepcopy(result)})
        assert ("error" in result) == fails, (tool, result)
        return result
    await call("register_subject", {"subject_id": OTHER, "label": "SYNTHETIC other scope"})
    imported = await call("prepare_import", {"subject_id": SUBJECT, "input_refs": [{"root_id": "synthetic", "relative_path": f} for f in ("matrix.csv", "comparison.csv")]})
    matrix_version, comparison_version = [v["version_id"] for v in imported["documents"]]
    assert imported["confirmed"] is False
    preview = await call("prepare_review", {"subject_id": SUBJECT, "version_id": matrix_version, "limit": 100})
    assert len(preview["rows"]) == len(MATRIX["corrections"])
    def commit_args(snapshot, decisions=None, full_typed_context=False):
        def typed_patch(shown):
            patch = {**BASE_MAPPING, "device": None}
            if full_typed_context:
                # CSV proposals alone remain contextual. Exercise explicit
                # synthetic typed corrections, without a native acceptance claim.
                patch.update({field: shown["row"][field] for field in (
                    "unit_raw", "clinical_time", "specimen", "method")})
            return patch
        return {"subject_id": SUBJECT, "snapshot_id": snapshot["snapshot_id"], "snapshot_sha256": snapshot["snapshot_sha256"],
                "decisions": decisions if decisions is not None else [{"draft_id": r["draft_id"], "action": "correct_and_confirm", "patch": typed_patch(r),
                            "reason": "SYNTHETIC mapping proposal for contract branch"} for r in snapshot["rows"]],
                "conversation_attestation": shown_attestation(snapshot)}
    initial = await call("commit_review", commit_args(preview))
    history = await call("query_history", {"subject_id": SUBJECT})
    original = {r["observation_id"]: r for r in history["current"]}
    assert len(original) == len(MATRIX["corrections"])
    for case, shown in zip(MATRIX["corrections"], preview["rows"]):
        previous = original[shown["observation_id"]]
        request = {"subject_id": SUBJECT, "observation_id": previous["observation_id"], "patch": case["patch"],
                   "reason": "SYNTHETIC actual transport correction " + case["id"],
                   "conversation_attestation": revision_attestation(previous), "idempotency_key": "synthetic_" + case["id"]}
        result = await call("correct_observation", request)
        revised = result["revision"]
        assert revised["row"]["field_anchors"] == previous["row"]["field_anchors"]
        assert revised["source_sha256"] == previous["source_sha256"]
        assert revised["supersedes_revision_id"] == previous["revision_id"]
        for field, value in case["patch"].items():
            assert revised["row"][field] == value
        if case["id"] == "result_exact":
            assert await call("correct_observation", request) == result
    after = await call("query_history", {"subject_id": SUBJECT})
    historical = {r["observation_id"]: r for r in after["historical"]}
    assert {key: immutable_revision(row) for key, row in historical.items()} == {
        key: immutable_revision(row) for key, row in original.items()}
    before_failed = canonical(after)
    previous = next(iter(original.values()))
    current = next(r for r in after["current"] if r["observation_id"] == previous["observation_id"])
    for case in MATRIX["forbidden_corrections"] + MATRIX["invalid_corrections"]:
        await call("correct_observation", {"subject_id": SUBJECT, "observation_id": current["observation_id"],
                   "patch": case["patch"], "reason": "SYNTHETIC rejection " + case["id"],
                   "conversation_attestation": revision_attestation(current)}, fails=True)
    await call("correct_observation", {"subject_id": OTHER, "observation_id": current["observation_id"], "patch": {"method": "SYNTHETIC B"}, "reason": "SYNTHETIC wrong subject", "conversation_attestation": revision_attestation(current)}, fails=True)
    await call("correct_observation", {"subject_id": SUBJECT, "observation_id": current["observation_id"], "patch": {"method": "SYNTHETIC B"}, "reason": "SYNTHETIC stale attestation", "conversation_attestation": revision_attestation(previous)}, fails=True)
    await call("commit_review", commit_args(preview), fails=True)
    assert canonical(await call("query_history", {"subject_id": SUBJECT})) == before_failed
    compared_preview = await call("prepare_review", {"subject_id": SUBJECT, "version_id": comparison_version})
    await call("commit_review", {**commit_args(compared_preview), "subject_id": OTHER}, fails=True)
    narrow = await call("prepare_review", {"subject_id": SUBJECT, "version_id": comparison_version, "limit": 1})
    await call("commit_review", commit_args(narrow, [{"draft_id": r["draft_id"], "action": "confirm"} for r in compared_preview["rows"]]), fails=True)
    invalid_batch = [{"draft_id": compared_preview["rows"][0]["draft_id"], "action": "confirm"},
                     {"draft_id": compared_preview["rows"][1]["draft_id"], "action": "correct_and_confirm", "patch": {"result": {"kind": "numeric_exact", "raw": "6", "decimal": "60"}}, "reason": "SYNTHETIC invalid second row"}]
    await call("commit_review", commit_args(compared_preview, invalid_batch), fails=True)
    assert canonical(await call("query_history", {"subject_id": SUBJECT})) == before_failed
    receipt = await call("commit_review", commit_args(compared_preview, full_typed_context=True))
    comparison = await call("compare_observations", {"subject_id": SUBJECT, "revision_ids": receipt["revision_ids"]})
    assert comparison["comparison_status"] == "comparable"
    assert comparison["arithmetic"]["delta"] == "0.2"
    assert [(i["row"]["result"]["raw"], i["row"]["reference_intervals"][0]["raw"]) for i in comparison["included"]] == [("5.4", "3.9-5.5"), ("5.6", "4.2-6.2")]
    # Adversarial comparison through actual transport, correcting only the
    # second point, then restoring it before the next frozen matrix case.
    b = next(r for r in (await call("query_history", {"subject_id": SUBJECT}))["current"] if r["revision_id"] == receipt["revision_ids"][1])
    baseline_row = copy.deepcopy(b["row"])
    for case in MATRIX["comparison_cases"]:
        changed = (await call("correct_observation", {"subject_id": SUBJECT, "observation_id": b["observation_id"], "patch": case["patch"], "reason": "SYNTHETIC mismatch " + case["id"], "conversation_attestation": revision_attestation(b)}))["revision"]
        rejected_comparison = await call("compare_observations", {"subject_id": SUBJECT, "revision_ids": [receipt["revision_ids"][0], changed["revision_id"]]})
        assert rejected_comparison["arithmetic"]["status"] == "not_computable"
        assert case["reason"] in next(r for r in rejected_comparison[case["bucket"]] if r["revision_id"] == changed["revision_id"])["reasons"]
        reset = {field: baseline_row[field] for field in case["patch"]}
        b = (await call("correct_observation", {"subject_id": SUBJECT, "observation_id": b["observation_id"], "patch": reset, "reason": "SYNTHETIC restore fixture between matrix cases", "conversation_attestation": revision_attestation(changed)}))["revision"]
    evidence(name, {"transport": name, "actual_calls": len(trace), "trace": trace,
                   "correction_cases": len(MATRIX["corrections"]), "comparison_cases": len(MATRIX["comparison_cases"]),
                   "original_revisions_readback_exact": True, "all_source_anchors_unchanged": True,
                   "failed_gate_history_unchanged": True, "scope_limit": "Artificial CSV typed import only; no native PDF/image acceptance claim; host mode logical isolation"})


def test_actual_subprocess_cli_exercises_frozen_corrections_and_comparison_gates(tmp_path):
    config = create_transport_configuration(tmp_path)
    request_file = tmp_path / "synthetic-arguments.json"
    async def invoke(tool, arguments):
        request_file.write_text(json.dumps(arguments))
        command = [sys.executable, "-I", "-B", str(ROOT / "scripts/ha-v2"), "--config", str(config.path),
                   "call", "--zone", "private-data", "--tool", tool, "--arguments-file", str(request_file)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            error = json.loads(result.stderr)
            assert "error" in error, result.stderr
            return error
        return json.loads(result.stdout)
    asyncio.run(exercise_actual_transport(invoke, "actual-cli"))


def test_actual_stdio_mcp_exercises_frozen_corrections_and_comparison_gates(tmp_path):
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    config = create_transport_configuration(tmp_path)
    async def exercise():
        params = StdioServerParameters(command=sys.executable,
            args=["-I", "-B", str(ROOT / "scripts/ha-v2"), "--config", str(config.path),
                  "serve", "--zone", "private-data", "--transport", "stdio"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert "private-data" in initialized.server_info.name
                names = {tool.name for tool in (await session.list_tools()).tools}
                assert "correct_observation" in names and "compare_observations" in names
                assert "plan_search" not in names
                async def invoke(tool, arguments):
                    result = await session.call_tool(tool, arguments)
                    blocks = [block.text for block in result.content if hasattr(block, "text")]
                    if result.is_error:
                        return {"error": {"message": "\n".join(blocks), "transport": "actual stdio MCP"}}
                    if result.structured_content is not None:
                        return result.structured_content
                    return json.loads("\n".join(blocks))
                await exercise_actual_transport(invoke, "actual-stdio-mcp")
    asyncio.run(exercise())
