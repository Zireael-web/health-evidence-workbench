"""Fictional classic table geometries for the packaged-chain layout regression."""
import copy

import pytest

from health_analyzer.v2.contracts import extraction_coverage, lab_observation
from health_analyzer.v2.import_issues import validate_issue
from health_analyzer.v2.layout import propose_lab_rows


VERSION = {"version_id": "ver_chain_layout", "source_sha256": "c" * 64}


def parallel_tables():
    """Two independently headed panels; values are fixed before extraction."""
    blocks = []

    def cell(text, x, y, width=65):
        if text:
            blocks.append({"text": text, "x": x, "y": y, "width": width, "height": 10})

    cell("Collected: 2040-01-03", 20, 10, 145)
    for left, panel, sample, method, collected in [
        (20, "Panel A", "Fictional serum", "Technique A", "2040-01-04"),
        (340, "Panel B", "Fictional urine", "Technique B", "2040-01-05"),
    ]:
        cell(panel, left, 40, 100)
        cell("Collected: " + collected, left, 55, 145)
        cell("Материал: " + sample, left, 70, 155)
        cell("Method: " + method, left, 85, 145)
        for x, label in zip([left, left + 100, left + 165, left + 220],
                            ["Test", "Result", "Units", "Reference"]):
            cell(label, x, 110, 55)
    for y, left_values, right_values in [
        (135, ["Marker A", "2,1", "g/L", "1–3"], ["Marker C", "not", "", "negative"]),
        (175, ["Marker B", "<0,2", "mg/L", "<0,5"], ["Marker D", "++", "", "negative"]),
    ]:
        for left, values in [(20, left_values), (340, right_values)]:
            for x, value in zip([left, left + 100, left + 165, left + 220], values):
                cell(value, x, y, 85 if x == left else 55)
    # A right-only wrapped result must never become a new row in the left table.
    cell("detected", 440, 147, 55)
    return {"page": 1, "text": "", "blocks": blocks, "width": 650, "height": 230,
            "source": "pdf_text", "metadata": {}}


def valid(output):
    for row in output["rows"]:
        assert lab_observation(row, **VERSION) == row
        assert row["mapping_status"] == "unmapped"
        assert set(row["field_status"].values()) <= {"proposed", "ambiguous"}
    for issue in output["issues"]:
        assert validate_issue(issue, VERSION) == issue
    extraction_coverage(output["coverage"], len(output["rows"]))


def test_same_y_classic_tables_keep_rows_and_independent_metadata_anchors():
    output = propose_lab_rows([parallel_tables()], VERSION)
    valid(output)
    assert [(r["analyte_raw"], r["result"]["raw"]) for r in output["rows"]] == [
        ("Marker A", "2,1"), ("Marker B", "<0,2"),
        ("Marker C", "not detected"), ("Marker D", "++")]
    for row in output["rows"]:
        right = row["analyte_raw"] in {"Marker C", "Marker D"}
        assert row["clinical_time"]["value"] == ("2040-01-05" if right else "2040-01-04")
        assert row["specimen"] == ("Fictional urine" if right else "Fictional serum")
        assert row["method"] == ("Technique B" if right else "Technique A")
        for field in ("analyte_raw", "result", "specimen", "method", "clinical_time"):
            anchor = row["field_anchors"][field]
            assert anchor["locator"]["kind"] == "pdf"
            x0, _, x1, _ = anchor["locator"]["region"]
            assert x0 >= 340 / 650 if right else x1 < 340 / 650
            assert anchor["inherited"] is (field in {"specimen", "method", "clinical_time"})
    assert output["coverage"]["expected_count"] == 4
    assert output["coverage"]["unprocessed_pages"] == []


def test_parallel_panel_without_own_date_does_not_borrow_the_other_panel_date():
    page = parallel_tables()
    page["blocks"] = [b for b in page["blocks"]
                      if not (b["y"] == 55 and b["x"] == 340) and b["y"] != 10]
    output = propose_lab_rows([page], VERSION)
    valid(output)
    assert len(output["rows"]) == 4
    assert [r["clinical_time"]["value"] for r in output["rows"]] == ["2040-01-04", "2040-01-04", None, None]
    assert all("clinical_time" not in r["field_anchors"] for r in output["rows"][2:])


def test_explicit_common_document_date_can_cover_both_parallel_panels():
    page = parallel_tables()
    page["blocks"] = [b for b in page["blocks"] if b["y"] != 55]
    output = propose_lab_rows([page], VERSION)
    valid(output)
    assert len(output["rows"]) == 4
    assert {r["clinical_time"]["value"] for r in output["rows"]} == {"2040-01-03"}
    assert {r["field_anchors"]["clinical_time"]["excerpt"] for r in output["rows"]} == {"Collected: 2040-01-03"}


def test_duplicate_result_inside_one_table_is_still_rejected():
    page = parallel_tables()
    page["blocks"] = [b for b in page["blocks"] if b["x"] < 340]
    page["blocks"].append({"text": "Result", "x": 300, "y": 110, "width": 35, "height": 10})
    page["blocks"].append({"text": "9", "x": 300, "y": 135, "width": 10, "height": 10})
    output = propose_lab_rows([page], VERSION)
    valid(output)
    assert output["rows"] == []
    assert all("AMBIGUOUS_COLUMNS" in issue["reason_codes"] for issue in output["issues"])


def test_invalid_material_result_is_not_a_specimen_metadata_label():
    page = parallel_tables()
    page["blocks"] = [b for b in page["blocks"] if b["x"] < 340 and
                      not (b["y"] == 135 and b["x"] == 120)]
    page["blocks"].append({"text": "материал непригоден", "x": 120, "y": 147,
                           "width": 130, "height": 10})
    output = propose_lab_rows([page], VERSION)
    valid(output)
    assert len(output["rows"]) == 2
    assert output["rows"][0]["result"] == {
        "kind": "no_result", "raw": "материал непригоден", "reason": "invalid_specimen"}


def test_parallel_rows_still_share_the_document_candidate_cap(monkeypatch):
    monkeypatch.setattr("health_analyzer.v2.layout.MAX_ROWS", 3)
    from health_analyzer.v2.common import V2Error
    with pytest.raises(V2Error, match="1000 whole source-row candidates"):
        propose_lab_rows([copy.deepcopy(parallel_tables())], VERSION)
