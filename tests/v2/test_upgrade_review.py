"""Independent synthetic workflow checks for the v2 ingest upgrade.

Injected page extractors below exercise integration and coverage only. They do
not establish that native image/PDF OCR has recognized a real document.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.configuration import initialize
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.runtime import open_services


CSV_OLD = b"analyte;result;unit;collected\nSynthetic A;1;u;2026-01-02\n"
CSV_NEW = CSV_OLD.replace(b";1;", b";9;")
PNG_SYNTHETIC = b"\x89PNG\r\n\x1a\nsynthetic integration input only"
PDF_SYNTHETIC = b"%PDF-1.4\nsynthetic integration input only"


@contextmanager
def system(tmp_path, *, pdf_extractor=None, image_extractor=None):
    roots = {}
    for subject in ("demo", "other"):
        root = tmp_path / (subject + "-archive")
        root.mkdir()
        roots[subject] = {"path": root, "subject_id": subject}
    store = SignedStore(tmp_path / "synthetic-data" / "private.sqlite3", b"s" * 32, "private-data")
    records = RecordsService(store)
    for subject in roots:
        records.register_subject(subject, "Synthetic " + subject)
    imports = ImportService(SimpleNamespace(archive_roots=roots), records,
                            pdf_extractor=pdf_extractor, image_extractor=image_extractor)
    try:
        yield roots, records, imports
    finally:
        store.close()


def ref(subject="demo", name="report.csv"):
    return [{"root_id": subject, "relative_path": name}]


def assert_error(code, operation):
    with pytest.raises(V2Error) as error:
        operation()
    assert error.value.code == code


def attestation(snapshot):
    return {"snapshot_id": snapshot["snapshot_id"], "snapshot_sha256": snapshot["snapshot_sha256"],
            "decision_excerpt": "Accept these synthetic rows", "origin": "user_message",
            "attested_by": "synthetic_review", "ref_availability": "not_provided_by_host", "message_ref": None}


def decide(records, snapshot, action="confirm", key=""):
    return records.commit_review("demo", snapshot["snapshot_id"], snapshot["snapshot_sha256"],
                                 [{"draft_id": x["draft_id"], "action": action} for x in snapshot["rows"]],
                                 attestation(snapshot), key)


def page(rows, *, source="pdf_text", number=1, confidence=None):
    """Synthetic rectangular source cells with an independently assigned grid."""
    xs = (20, 350, 450, 550)
    headers = ("Analyte", "Result", "Unit", "Reference")
    blocks = []
    for row_number, cells in enumerate([headers, *rows]):
        for column, text in enumerate(cells):
            if not text:
                continue
            block = {"text": text, "x": xs[column], "y": 40 + 40 * row_number,
                     "width": 210 if column == 0 else min(80, max(7, len(text) * 7)), "height": 16}
            if confidence is not None:
                block["confidence"] = confidence
            blocks.append(block)
    return {"page": number, "text": "\n".join(" ".join(cells) for cells in [headers, *rows]),
            "width": 700, "height": 500, "source": source, "blocks": blocks}


def test_saved_source_versions_keep_exact_bytes_after_replace_rename_delete(tmp_path):
    with system(tmp_path) as (roots, records, imports):
        path = roots["demo"]["path"] / "report.csv"
        path.write_bytes(CSV_OLD)
        old = imports.prepare_import("demo", ref())["documents"][0]
        snapshot = records.prepare_review("demo", old["version_id"])
        path.write_bytes(CSV_NEW)
        new = imports.prepare_import("demo", ref())["documents"][0]
        path.rename(path.with_name("renamed.csv"))
        path.with_name("renamed.csv").unlink()
        assert old["version_id"] != new["version_id"]
        for document, expected in ((old, CSV_OLD), (new, CSV_NEW)):
            source = imports.get_source_version("demo", document["version_id"])
            assert source["saved_status"] == "available"
            assert Path(source["verified_saved_source_path"]).read_bytes() == expected
            assert source["archive_sources"][0]["status"] == "SOURCE_UNAVAILABLE"
        decide(records, snapshot, key="old_snapshot_after_archive_delete")
        history = records.query_history("demo")
        assert history["current"][0]["row"]["result"]["decimal"] == "1"
        assert history["current"][0]["source_sha256"] == old["source_sha256"]


def test_same_bytes_two_profiles_have_separate_originals_and_reject_cross_scope(tmp_path):
    with system(tmp_path) as (roots, records, imports):
        documents = {}
        sources = {}
        for subject in roots:
            (roots[subject]["path"] / "report.csv").write_bytes(CSV_OLD)
            documents[subject] = imports.prepare_import(subject, ref(subject))["documents"][0]
            sources[subject] = imports.get_source_version(subject, documents[subject]["version_id"])
        assert documents["demo"]["source_sha256"] == documents["other"]["source_sha256"]
        assert documents["demo"]["version_id"] != documents["other"]["version_id"]
        a, b = (Path(sources[subject]["verified_saved_source_path"]) for subject in ("demo", "other"))
        assert a != b and a.stat().st_ino != b.stat().st_ino
        assert_error("WRONG_SUBJECT", lambda: imports.get_source_version("other", documents["demo"]["version_id"]))
        assert_error("WRONG_SUBJECT", lambda: imports.prepare_import("other", ref("demo")))
        assert records.query_history("other")["current"] == []


def test_tampered_snapshot_never_falls_back_to_intact_archive_or_repairs_itself(tmp_path):
    with system(tmp_path) as (roots, records, imports):
        archive = roots["demo"]["path"] / "report.csv"
        archive.write_bytes(CSV_OLD)
        doc = imports.prepare_import("demo", ref())["documents"][0]
        snapshot = records.prepare_review("demo", doc["version_id"])
        saved = Path(imports.get_source_version("demo", doc["version_id"])["verified_saved_source_path"])
        saved.chmod(0o600)
        saved.write_bytes(b"x" * len(CSV_OLD))
        saved.chmod(0o400)
        assert_error("ORIGINAL_INTEGRITY_FAILURE", lambda: decide(records, snapshot))
        assert_error("ORIGINAL_INTEGRITY_FAILURE", lambda: imports.prepare_import("demo", ref()))
        source = imports.get_source_version("demo", doc["version_id"])
        assert source["saved_status"] == "ORIGINAL_INTEGRITY_FAILURE"
        assert source["verified_saved_source_path"] is None
        assert source["archive_sources"][0]["status"] == "same_bytes"
        refreshed = imports.refresh_source_status("demo", [doc["version_id"]])["sources"][0]
        assert refreshed["checked_status"] == "integrity_failure"
        assert records.store.list("observation_revision", "demo") == []
        assert archive.read_bytes() == CSV_OLD
        assert saved.read_bytes() == b"x" * len(CSV_OLD)


def test_repeat_import_preserves_confirmed_revision_and_unresolved_csv_text(tmp_path):
    with system(tmp_path) as (roots, records, imports):
        (roots["demo"]["path"] / "report.csv").write_bytes(
            b"analyte;result;unit\nSynthetic A;5;u\nSynthetic B;borderline?;u\n")
        doc = imports.prepare_import("demo", ref())["documents"][0]
        snapshot = records.prepare_review("demo", doc["version_id"])
        unresolved = next(x for x in snapshot["rows"] if x["row"]["result"]["kind"] == "text_unparsed")
        assert unresolved["row"]["result"]["raw"] == "borderline?"
        assert_error("unresolved_result", lambda: decide(records, snapshot))
        good = next(x for x in snapshot["rows"] if x != unresolved)
        decisions = [{"draft_id": good["draft_id"], "action": "confirm"},
                     {"draft_id": unresolved["draft_id"], "action": "defer"}]
        result = records.commit_review("demo", snapshot["snapshot_id"], snapshot["snapshot_sha256"],
                                       decisions, attestation(snapshot), "mixed_review")
        repeat = imports.prepare_import("demo", ref())["documents"][0]
        assert repeat["recognition_reused"] is True
        assert repeat["run_id"] == doc["run_id"] and repeat["draft_ids"] == doc["draft_ids"]
        assert len(records.store.list("observation_revision", "demo")) == len(result["revision_ids"]) == 1
        displayed = records.prepare_review("demo", doc["version_id"])
        assert any(x["row"]["result"]["raw"] == "borderline?" for x in displayed["rows"])


def test_forced_recognition_returning_prior_output_selects_that_latest_result(tmp_path):
    recognition = {"value": "5"}

    def extractor(content):
        return [page([("Synthetic A", recognition["value"], "u", "0–10")], source="vision_ocr")], []

    with system(tmp_path, image_extractor=extractor) as (roots, records, imports):
        (roots["demo"]["path"] / "scan.png").write_bytes(PNG_SYNTHETIC)
        first = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        recognition["value"] = "6"
        second = imports.prepare_import("demo", ref(name="scan.png"), force_reextract=True)["documents"][0]
        assert first["run_id"] != second["run_id"]
        recognition["value"] = "5"
        latest = imports.prepare_import("demo", ref(name="scan.png"), force_reextract=True)["documents"][0]
        displayed = records.prepare_review("demo", first["version_id"])
        assert displayed["run_id"] == latest["run_id"]
        assert displayed["rows"][0]["row"]["result"]["decimal"] == "5"
        assert len(records.store.list("extraction_run", "demo")) == 2
        assert records.store.list("observation_revision", "demo") == []


def test_quarantine_events_retain_source_block_stale_updates_and_never_accept(tmp_path):
    extracted_page = page([("Synthetic A", "5", "u", "0–10"),
                           ("Synthetic B", "borderline?", "u", "0–10")], source="vision_ocr")
    with system(tmp_path, image_extractor=lambda content: ([extracted_page], ["synthetic page adapter"])) as (roots, records, imports):
        (roots["demo"]["path"] / "scan.png").write_bytes(PNG_SYNTHETIC)
        doc = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        listed = imports.issues.list("demo", doc["version_id"])
        assert listed["total"] == 1 and len(doc["draft_ids"]) == 1
        issue = listed["issues"][0]
        assert issue["status"] == "pending" and "borderline?" in issue["source"]["raw_text"]
        assert "UNSUPPORTED_RESULT_TEXT" in issue["source"]["reason_codes"]
        assert records.query_history("demo")["current"] == []
        repeat = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        assert repeat["issue_ids"] == doc["issue_ids"]
        event = imports.issues.resolve("demo", issue["issue_id"], "defer", "Need source clarification", idempotency_key="defer_once")
        replay = imports.issues.resolve("demo", issue["issue_id"], "defer", "Need source clarification", idempotency_key="defer_once")
        assert replay == event and event["confirmed"] is False
        assert_error("STALE_IMPORT_ISSUE", lambda: imports.issues.resolve("demo", issue["issue_id"], "discard", "Stale view"))
        assert_error("WRONG_SUBJECT", lambda: imports.issues.resolve("other", issue["issue_id"], "discard", "Wrong profile"))
        latest = imports.issues.list("demo", doc["version_id"])["issues"][0]
        assert latest["status"] == "deferred" and latest["source"] == issue["source"]
        assert records.store.list("observation_revision", "demo") == []


def test_issue_proposal_requires_fresh_run_and_separate_frozen_review(tmp_path):
    extracted_page = page([("Synthetic A", "5", "u", "0–10"),
                           ("Synthetic B", "borderline?", "u", "0–10")], source="vision_ocr")
    with system(tmp_path, image_extractor=lambda content: ([extracted_page], [])) as (roots, records, imports):
        (roots["demo"]["path"] / "scan.png").write_bytes(PNG_SYNTHETIC)
        doc = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        before = records.prepare_review("demo", doc["version_id"])
        issue = imports.issues.list("demo", doc["version_id"])["issues"][0]
        proposed = copy.deepcopy(before["rows"][0]["row"])
        cells = {cell["role"]: cell for cell in issue["source"]["raw_cells"]}
        proposed["analyte_raw"] = "Synthetic B"
        proposed["result"] = {"kind": "qualitative", "raw": "borderline?", "value": "borderline"}
        for field in ("analyte_raw", "result", "unit_raw", "reference_intervals"):
            proposed["field_anchors"][field] = cells[field]["anchors"]
        assert_error("STALE_IMPORT_ISSUE", lambda: imports.issues.resolve(
            "demo", issue["issue_id"], "propose", "Synthetic typed clarification", proposed, expected_run_id="stale_run",
            expected_selection_token=issue["current_selection_token"]))
        event = imports.issues.resolve("demo", issue["issue_id"], "propose", "Synthetic typed clarification",
                                      proposed, expected_run_id=issue["current_run_id"],
                                      expected_selection_token=issue["current_selection_token"])
        assert event["confirmed"] is False and event["requires_frozen_review"] is True
        assert records.store.list("observation_revision", "demo") == []
        assert_error("stale_extraction", lambda: decide(records, before))
        after = records.prepare_review("demo", doc["version_id"])
        assert len(after["rows"]) == 2
        decide(records, after, key="separate_frozen_review")
        assert len(records.store.list("observation_revision", "demo")) == 2
        latest = imports.issues.list("demo", doc["version_id"])["issues"][0]
        assert latest["status"] == "proposed" and latest["source"] == issue["source"]


def test_healthy_row_from_another_cell_cannot_resolve_unrelated_issue(tmp_path):
    extracted_page = page([("Synthetic A", "5", "u", "0–10"),
                           ("Synthetic B", "borderline?", "u", "0–10")], source="vision_ocr")
    with system(tmp_path, image_extractor=lambda content: ([extracted_page], [])) as (roots, records, imports):
        (roots["demo"]["path"] / "scan.png").write_bytes(PNG_SYNTHETIC)
        doc = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        snapshot = records.prepare_review("demo", doc["version_id"])
        issue = imports.issues.list("demo", doc["version_id"])["issues"][0]
        healthy_row = copy.deepcopy(snapshot["rows"][0]["row"])
        assert healthy_row["analyte_raw"] == "Synthetic A"
        assert "Synthetic B" in issue["source"]["raw_text"]
        before_runs = records.store.list("extraction_run", "demo")
        with pytest.raises(V2Error) as error:
            imports.issues.resolve("demo", issue["issue_id"], "propose", "Wrong source cell",
                                   healthy_row, expected_run_id=issue["current_run_id"],
                                   expected_selection_token=issue["current_selection_token"])
        assert "SCOPE" in error.value.code or "ANCHOR" in error.value.code
        assert imports.issues.list("demo", doc["version_id"])["issues"][0]["status"] == "pending"
        assert records.store.list("import_issue_event", "demo") == []
        assert records.store.list("extraction_run", "demo") == before_runs
        assert records.store.list("observation_revision", "demo") == []


def test_low_confidence_draft_stays_visible_but_cannot_confirm(tmp_path):
    extracted_page = page([("Synthetic A", "5", "u", "0–10")], source="vision_ocr", confidence=.4)
    with system(tmp_path, image_extractor=lambda content: ([extracted_page], [])) as (roots, records, imports):
        (roots["demo"]["path"] / "scan.png").write_bytes(PNG_SYNTHETIC)
        doc = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        snapshot = records.prepare_review("demo", doc["version_id"])
        assert len(snapshot["rows"]) == 1
        assert_error("unresolved_field", lambda: decide(records, snapshot))
        assert imports.issues.list("demo", doc["version_id"])["total"] == 1
        decide(records, snapshot, "defer", "low_confidence_defer")
        assert records.store.list("observation_revision", "demo") == []
        assert records.prepare_review("demo", doc["version_id"])["rows"][0]["row"]["result"]["decimal"] == "5"


def test_equivalent_single_anchor_list_replaces_one_issue_row_without_duplicate(tmp_path):
    extracted_page = page([("Synthetic A", "5", "u", "0–10")], source="vision_ocr", confidence=.4)
    with system(tmp_path, image_extractor=lambda content: ([extracted_page], [])) as (roots, records, imports):
        (roots["demo"]["path"] / "scan.png").write_bytes(PNG_SYNTHETIC)
        doc = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        before = records.prepare_review("demo", doc["version_id"])
        issue = imports.issues.list("demo", doc["version_id"])["issues"][0]
        proposed = copy.deepcopy(issue["source"]["proposed_row"])
        proposed["field_status"] = {field: "proposed" for field in proposed["field_anchors"]}
        proposed["field_anchors"]["result"] = [proposed["field_anchors"]["result"]]
        imports.issues.resolve("demo", issue["issue_id"], "propose", "Checked synthetic source cell",
                               proposed, expected_run_id=issue["current_run_id"],
                               expected_selection_token=issue["current_selection_token"])
        after = records.prepare_review("demo", doc["version_id"])
        assert len(after["rows"]) == 1
        assert after["rows"][0]["observation_id"] == before["rows"][0]["observation_id"]


def test_issue_and_frozen_preview_stay_stale_after_extraction_returns_to_same_run(tmp_path):
    recognition = {"value": "5"}

    def extractor(content):
        return [page([("Synthetic A", recognition["value"], "u", "0–10")],
                     source="vision_ocr", confidence=.4)], []

    with system(tmp_path, image_extractor=extractor) as (roots, records, imports):
        (roots["demo"]["path"] / "scan.png").write_bytes(PNG_SYNTHETIC)
        doc = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        old_snapshot = records.prepare_review("demo", doc["version_id"])
        old_issue = imports.issues.list("demo", doc["version_id"])["issues"][0]
        proposed = copy.deepcopy(old_issue["source"]["proposed_row"])
        proposed["field_status"] = {field: "proposed" for field in proposed["field_anchors"]}
        recognition["value"] = "6"
        imports.prepare_import("demo", ref(name="scan.png"), force_reextract=True)
        recognition["value"] = "5"
        latest = imports.prepare_import("demo", ref(name="scan.png"), force_reextract=True)["documents"][0]
        refreshed = next(issue for issue in imports.issues.list("demo", doc["version_id"])["issues"]
                         if issue["issue_id"] == old_issue["issue_id"])
        assert latest["run_id"] == old_issue["current_run_id"] == refreshed["current_run_id"]
        assert refreshed["current_selection_token"] != old_issue["current_selection_token"]
        assert_error("STALE_IMPORT_ISSUE", lambda: imports.issues.resolve(
            "demo", old_issue["issue_id"], "propose", "Synthetic source clarification", proposed,
            expected_run_id=old_issue["current_run_id"],
            expected_selection_token=old_issue["current_selection_token"]))
        assert_error("stale_extraction", lambda: decide(records, old_snapshot, "defer"))
        assert records.store.list("import_issue_event", "demo") == []
        assert records.store.list("review_event", "demo") == []
        event = imports.issues.resolve(
            "demo", refreshed["issue_id"], "propose", "Synthetic source clarification", proposed,
            expected_run_id=refreshed["current_run_id"],
            expected_selection_token=refreshed["current_selection_token"])
        assert event["confirmed"] is False
        assert records.store.list("observation_revision", "demo") == []
        assert len(records.prepare_review("demo", doc["version_id"])["rows"]) == 1


@pytest.mark.parametrize("quality_issue", ["orientation_ambiguous", "exif_mirroring_not_corrected"])
def test_native_ocr_page_uncertainty_remains_visible_in_persisted_import(tmp_path, quality_issue):
    extracted_page = page([("Synthetic A", "5", "u", "0–10")], source="vision_ocr", confidence=.98)
    extracted_page["metadata"] = {"issues": [quality_issue], "readable": True, "confidence": .98}
    with system(tmp_path, image_extractor=lambda content: ([extracted_page], [])) as (roots, records, imports):
        (roots["demo"]["path"] / "scan.png").write_bytes(PNG_SYNTHETIC)
        doc = imports.prepare_import("demo", ref(name="scan.png"))["documents"][0]
        coverage = records.prepare_review("demo", doc["version_id"])["coverage"]
        assert coverage["status"] != "complete"
        issues = imports.issues.list("demo", doc["version_id"])["issues"]
        assert any(quality_issue.upper() in code for issue in issues for code in issue["source"]["reason_codes"])
        assert_error("unresolved_field", lambda: decide(records, records.prepare_review("demo", doc["version_id"])))
        assert records.query_history("demo")["current"] == []


def test_layout_coverage_merge_preserves_unreadable_native_pdf_pages(tmp_path):
    readable = page([("Synthetic A", "5", "u", "0–10")])
    unreadable = {"page": 2, "text": "", "source": "pdf_text", "blocks": [], "width": 700, "height": 500}
    with system(tmp_path, pdf_extractor=lambda content: ([readable, unreadable], ["synthetic page adapter"])) as (roots, records, imports):
        (roots["demo"]["path"] / "report.pdf").write_bytes(PDF_SYNTHETIC)
        doc = imports.prepare_import("demo", ref(name="report.pdf"))["documents"][0]
        coverage = records.prepare_review("demo", doc["version_id"])["coverage"]
        assert coverage["known_extracted_rows"] == 1
        assert coverage["status"] != "complete"
        assert coverage["processed_pages"] == [1]
        assert coverage["unprocessed_pages"] == [2]
        assert coverage["expected_count"] is None


def test_source_and_issue_operations_only_exist_on_private_runtime(tmp_path):
    archive = tmp_path / "synthetic-archive"
    archive.mkdir()
    (archive / "report.csv").write_bytes(CSV_OLD)
    config = initialize(tmp_path / "config.json", tmp_path / "synthetic-v2", isolation="host",
                        archive_roots={"demo": {"path": str(archive), "subject_id": "demo"}})
    private = open_services(config, "private-data", config.key_path("private-data").read_bytes())
    public = open_services(config, "public-research", config.key_path("public-research").read_bytes())
    try:
        doc = private.call("prepare_import", {"subject_id": "demo", "input_refs": ref()})["documents"][0]
        source = private.call("get_source_version", {"subject_id": "demo", "version_id": doc["version_id"]})
        assert Path(source["verified_saved_source_path"]).read_bytes() == CSV_OLD
        for name in ("get_source_version", "list_import_issues", "resolve_import_issue", "prepare_import"):
            assert name in private.tools and name not in public.tools
            assert_error("tool_unavailable", lambda: public.call(name, {"subject_id": "demo", "version_id": doc["version_id"]}))
        assert public.store.list("original_manifest") == []
        assert public.store.list("import_issue") == []
    finally:
        private.close()
        public.close()
