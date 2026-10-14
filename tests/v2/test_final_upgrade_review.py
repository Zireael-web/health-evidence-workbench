"""Synthetic final integration review; never real reports or deployment state."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import SignedStore, V2Error, digest
from health_analyzer.v2.ingest import ImportService, extract_table
from health_analyzer.v2.records import RecordsService


@contextmanager
def system(tmp_path, text, kind, *, injected_page=None):
    root = tmp_path / "synthetic-archive"
    root.mkdir()
    store = SignedStore(tmp_path / "synthetic-data" / "private.sqlite3", b"f" * 32, "private-data")
    records = RecordsService(store)
    page = injected_page or {"page": 1, "text": text, "blocks": [], "width": 1000, "height": 1000, "source": "pdf_text"}
    imports = ImportService(SimpleNamespace(archive_roots={"demo": {"path": root, "subject_id": "demo"}}),
                            records, pdf_extractor=lambda _: ([page], ["synthetic page injection only"]))
    name = "synthetic." + kind
    (root / name).write_bytes(b"%PDF-1.4\nsynthetic extractor input" if kind == "pdf" else text.encode())
    try:
        doc = imports.prepare_import("demo", [{"root_id": "demo", "relative_path": name}])["documents"][0]
        yield records, imports, doc
    finally:
        store.close()


def source_text(imports, version_id):
    issues = imports.issues.list("demo", version_id, limit=100)["issues"]
    return issues, "\n".join(issue["source"]["raw_text"] + "\n" +
                           "\n".join(cell["text"] for cell in issue["source"]["raw_cells"])
                           for issue in issues)


@pytest.mark.parametrize("kind", ["csv", "txt", "pdf"])
def test_delimited_extra_cells_are_visible_issues_with_partial_coverage(tmp_path, kind):
    text = "analyte;result;unit;collected;previous result;comment\nSynthetic A;5;u;2026-01-02;17;synthetic caveat XYZ\n"
    with system(tmp_path, text, kind) as (records, imports, doc):
        issues, preserved = source_text(imports, doc["version_id"])
        assert issues, "Extra source columns must not disappear through the delimited-table fast path"
        assert "17" in preserved and "synthetic caveat XYZ" in preserved
        coverage = records._latest_run("demo", doc["version_id"])["coverage"]
        assert coverage["status"] == "partial" and coverage["expected_count"] is None
        assert records.query_history("demo")["current"] == []


@pytest.mark.parametrize("kind", ["csv", "txt", "pdf"])
def test_delimited_blank_result_is_quarantined_without_no_result_inference(tmp_path, kind):
    text = "analyte;result;unit;collected\nSynthetic missing result;;u;2026-01-02\n"
    with system(tmp_path, text, kind) as (records, imports, doc):
        assert doc["draft_ids"] == [], "A blank source cell is uncertainty, not an explicit no-result conclusion"
        issues, preserved = source_text(imports, doc["version_id"])
        assert issues and "Synthetic missing result" in preserved
        assert any("MISSING_RESULT" in issue["source"]["reason_codes"] for issue in issues)
        assert records.query_history("demo")["current"] == []


@pytest.mark.parametrize("kind", ["csv", "txt"])
@pytest.mark.parametrize("header", ["unknown;unmapped", "analyte;result;result"])
def test_unresolved_delimited_header_keeps_all_source_text_in_queue(tmp_path, kind, header):
    text = header + "\nSynthetic unresolved;17" + (";29" if "result" in header else "") + "\n"
    with system(tmp_path, text, kind) as (records, imports, doc):
        assert doc["draft_ids"] == []
        issues, preserved = source_text(imports, doc["version_id"])
        assert issues and header in preserved and "Synthetic unresolved;17" in preserved
        if "result" in header:
            assert "29" in preserved
        assert records.query_history("demo")["current"] == []


@pytest.mark.parametrize("kind", ["csv", "txt", "pdf"])
def test_invalid_delimited_source_row_does_not_erase_other_valid_rows(tmp_path, kind):
    text = "analyte;result;unit;collected\nSynthetic valid;5;u;2026-01-02\n;7;u;2026-01-02\n"
    with system(tmp_path, text, kind) as (records, imports, doc):
        drafts = [records.store.get("observation_draft", item, "demo") for item in doc["draft_ids"]]
        assert len(drafts) == 1 and drafts[0]["row"]["analyte_raw"] == "Synthetic valid"
        issues, preserved = source_text(imports, doc["version_id"])
        assert issues and "7" in preserved
        assert records._latest_run("demo", doc["version_id"])["coverage"]["status"] == "partial"


@pytest.mark.parametrize("kind", ["csv", "txt", "pdf"])
def test_delimited_oversized_unicode_comment_conserves_exact_physical_source(tmp_path, kind):
    row = 'Synthetic quoted;5;u;2026-01-02;"first line\n' + "Ω" * 9000 + '"\n'
    text = "analyte;result;unit;collected;comment\n" + row
    with system(tmp_path, text, kind) as (records, imports, doc):
        issues = imports.issues.list("demo", doc["version_id"], limit=100)["issues"]
        assert len(doc["draft_ids"]) == 1
        assert issues and all("SOURCE_SPAN_FRAGMENT" in issue["source"]["reason_codes"] for issue in issues)
        assert "".join(issue["source"]["raw_text"] for issue in issues) == row
        links = [issue["source"]["alternatives"][0] for issue in issues]
        assert len({link["group_id"] for link in links}) == 1
        assert [link["index"] for link in links] == list(range(1, len(links) + 1))
        assert records.query_history("demo")["current"] == []


def test_fragmented_oversized_row_cannot_be_resolved_by_another_result_cell(tmp_path):
    blocks = [{"text": "Collected: 2026-01-02", "x": 20, "y": 10, "width": 200, "height": 16}]
    cells = [("Analyte", "Result", "Unit", "Reference"),
             ("Synthetic healthy", "5", "u", "0 - 10"),
             ("Synthetic oversized " + "X" * 9000, "7", "u", "0 - 10")]
    for number, row in enumerate(cells):
        for column, cell in enumerate(row):
            blocks.append({"text": cell, "x": (20, 350, 450, 550)[column],
                           "y": 40 + 40 * number,
                           "width": 210 if column == 0 else min(80, max(7, len(cell) * 7)), "height": 16})
    page = {"page": 1, "text": "\n".join(block["text"] for block in blocks), "blocks": blocks,
            "width": 700, "height": 500, "source": "pdf_text"}
    with system(tmp_path, page["text"], "pdf", injected_page=page) as (records, imports, doc):
        snapshot = records.prepare_review("demo", doc["version_id"])
        assert len(snapshot["rows"]) == 1
        issue = imports.issues.list("demo", doc["version_id"])["issues"][0]
        assert "SOURCE_SPAN_FRAGMENT" in issue["source"]["reason_codes"]
        with pytest.raises(V2Error) as error:
            imports.issues.resolve("demo", issue["issue_id"], "propose", "synthetic unrelated result",
                                   row=snapshot["rows"][0]["row"],
                                   expected_run_id=issue["current_run_id"],
                                   expected_selection_token=issue["current_selection_token"])
        assert error.value.code in {"ISSUE_ANCHOR_SCOPE_MISMATCH", "ISSUE_SCOPE_REQUIRES_VISUAL_BATCH"}
        assert imports.issues.list("demo", doc["version_id"])["issues"][0]["status"] == "pending"


def test_source_correction_rechecks_saved_original_integrity(tmp_path):
    text = "analyte;result;unit;collected\nSynthetic correctable;5;u;2026-01-02\n"
    with system(tmp_path, text, "csv") as (records, imports, doc):
        snapshot = records.prepare_review("demo", doc["version_id"])

        def attestation(snapshot_id, snapshot_sha256):
            return {"snapshot_id": snapshot_id, "snapshot_sha256": snapshot_sha256,
                    "decision_excerpt": "synthetic explicit correction confirmation", "origin": "user_message",
                    "attested_by": "synthetic_final_review", "ref_availability": "not_provided_by_host", "message_ref": None}

        commit = records.commit_review("demo", snapshot["snapshot_id"], snapshot["snapshot_sha256"],
                                       [{"draft_id": snapshot["rows"][0]["draft_id"], "action": "confirm"}],
                                       attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"]))
        previous = records.store.get("observation_revision", commit["revision_ids"][0], "demo")
        saved = Path(imports.get_source_version("demo", doc["version_id"])["verified_saved_source_path"])
        saved.chmod(0o600)
        saved.write_bytes(b"x" * len(text.encode()))
        saved.chmod(0o400)
        with pytest.raises(V2Error) as error:
            records.correct_observation("demo", previous["observation_id"],
                                        {"result": {"kind": "numeric_exact", "raw": "6", "decimal": "6"}},
                                        "synthetic correction after tampering",
                                        attestation(previous["revision_id"], digest(previous)))
        assert error.value.code == "ORIGINAL_INTEGRITY_FAILURE"
        assert len(records.store.list("observation_revision", "demo")) == 1


@pytest.mark.parametrize("blank", ["", "   "])
def test_visual_blank_no_result_cannot_enter_confirmed_history(tmp_path, blank):
    text = "analyte;result;unit;collected\nSynthetic visual blank;" + blank + ";u;2026-01-02\n"
    with system(tmp_path, text, "csv") as (records, imports, doc):
        version = records._version("demo", doc["version_id"])
        row = extract_table(text.replace(";" + blank + ";u;", ";cancelled;u;"), version)[0]
        # Construct the earlier compatible payload directly; conservative
        # intake now correctly refuses to fabricate it from a blank cell.
        row["result"] = {"kind": "no_result", "raw": blank, "reason": "not_reported"}
        row["field_anchors"]["result"]["excerpt"] = text.splitlines()[1]
        assert row["result"]["kind"] == "no_result"
        imports.submit_visual("demo", doc["version_id"], [row],
                              {"status": "partial", "expected_count": None, "expected_count_basis": "unknown",
                               "method": "manual_transcription"})
        snapshot = records.prepare_review("demo", doc["version_id"])
        evidence = {"snapshot_id": snapshot["snapshot_id"], "snapshot_sha256": snapshot["snapshot_sha256"],
                    "decision_excerpt": "synthetic confirmation of blank visual proposal", "origin": "user_message",
                    "attested_by": "synthetic_final_review", "ref_availability": "not_provided_by_host", "message_ref": None}
        with pytest.raises(V2Error) as error:
            records.commit_review("demo", snapshot["snapshot_id"], snapshot["snapshot_sha256"],
                                  [{"draft_id": snapshot["rows"][0]["draft_id"], "action": "confirm"}], evidence)
        assert error.value.code == "unresolved_result"
        assert records.query_history("demo")["current"] == []


@pytest.mark.parametrize("kind", ["csv", "txt", "pdf"])
def test_explicit_cancelled_source_remains_confirmable_no_result(tmp_path, kind):
    text = "analyte;result;unit;collected\nSynthetic explicit cancellation;cancelled;u;2026-01-02\n"
    with system(tmp_path, text, kind) as (records, imports, doc):
        snapshot = records.prepare_review("demo", doc["version_id"])
        assert len(snapshot["rows"]) == 1
        result = snapshot["rows"][0]["row"]["result"]
        assert result == {"kind": "no_result", "raw": "cancelled", "reason": "cancelled"}
        assert records.query_history("demo")["current"] == []
        evidence = {"snapshot_id": snapshot["snapshot_id"], "snapshot_sha256": snapshot["snapshot_sha256"],
                    "decision_excerpt": "synthetic confirmation of explicit source cancellation", "origin": "user_message",
                    "attested_by": "synthetic_final_review", "ref_availability": "not_provided_by_host", "message_ref": None}
        records.commit_review("demo", snapshot["snapshot_id"], snapshot["snapshot_sha256"],
                              [{"draft_id": snapshot["rows"][0]["draft_id"], "action": "confirm"}], evidence)
        history = records.query_history("demo")
        assert len(history["current"]) == 1 and history["current"][0]["row"]["result"] == result


@pytest.mark.parametrize("kind", ["csv", "txt", "pdf"])
def test_populated_unlabelled_delimited_cell_preserves_neighbor_and_quarantines(tmp_path, kind):
    text = "analyte;result;unit;collected;\nSynthetic valid;5;u;2026-01-02;unlabelled synthetic caveat\n"
    with system(tmp_path, text, kind) as (records, imports, doc):
        assert len(doc["draft_ids"]) == 1
        issues, preserved = source_text(imports, doc["version_id"])
        assert issues and "unlabelled synthetic caveat" in preserved
        assert records._latest_run("demo", doc["version_id"])["coverage"]["status"] == "partial"
