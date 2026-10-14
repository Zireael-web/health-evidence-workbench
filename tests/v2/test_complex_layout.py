"""Entirely synthetic matrix geometries and source text; no private reports."""
import copy
import re

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.contracts import extraction_coverage, lab_observation
from health_analyzer.v2.import_issues import validate_issue
from health_analyzer.v2.layout import propose_lab_rows
from health_analyzer.v2.records import RecordsService, result_locator


VERSION = {"version_id": "ver_synthetic_matrix", "source_sha256": "b" * 64}


def matrix(headers, rows, *, date_label="Date", y=20, x=10, source="vision_ocr", confidence=.98):
    blocks = []
    for row_number, values in enumerate([[date_label, *headers], *rows]):
        for column, value in enumerate(values):
            if value:
                blocks.append({"text": value, "x": x + column * 140, "y": y + row_number * 35,
                               "width": 110, "height": 20, "confidence": confidence})
    return {"page": 1, "text": "", "blocks": blocks, "width": 1800, "height": 900,
            "source": source, "metadata": {}}


def assert_valid(output):
    for row in output["rows"]:
        assert lab_observation(row, **VERSION) == row
        assert row["mapping_status"] == "unmapped"
        assert set(row["field_status"].values()) <= {"proposed", "ambiguous"}
    for issue in output["issues"]:
        assert validate_issue(issue, VERSION) == issue
    extraction_coverage(output["coverage"], len(output["rows"]))
    assert len({repr(result_locator(row)) for row in output["rows"]}) == len(output["rows"])


def test_explicit_transposed_dates_keep_actual_cell_header_and_date_anchors():
    page = matrix(["Synthetic A (mmol/L)", "Synthetic B (ng/mL)"],
                  [["11.10.2026", "5,1", "<0,10"], ["12.10.2026", "5,2", "0,20"]])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 4
    a = output["rows"][0]
    assert a["analyte_raw"] == "Synthetic A"
    assert a["unit_raw"] == "mmol/L"
    assert a["clinical_time"]["value"] == "2026-10-11"
    assert a["clinical_time"]["role"] == "unknown"
    assert a["field_status"]["clinical_time"] == "ambiguous"
    assert a["field_anchors"]["analyte_raw"]["inherited"] is True
    assert a["field_anchors"]["unit_raw"]["inherited"] is True
    assert a["field_anchors"]["clinical_time"]["inherited"] is False
    assert a["field_anchors"]["result"]["excerpt"] == "5,1"
    assert output["rows"][1]["result"]["operator"] == "<"
    assert output["coverage"]["expected_count"] == 4


def test_blank_corner_matrix_with_multiline_header_units_and_sparse_blanks():
    page = matrix(["Synthetic A\n(mmol/L)", "Synthetic B\n(ng/mL)", "Synthetic C"],
                  [["11.10.2026", "1", "", "negative"]], date_label="")
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [(r["analyte_raw"], r["unit_raw"]) for r in output["rows"]] == [
        ("Synthetic A", "mmol/L"), ("Synthetic C", None)]
    missing = next(issue for issue in output["issues"] if "MISSING_RESULT" in issue["reason_codes"])
    assert next(c for c in missing["raw_cells"] if c["role"] == "analyte_raw")["text"] == "Synthetic B"
    assert missing["proposed_row"] is None
    assert output["coverage"]["unprocessed_pages"] == [1]


def test_explicit_unit_row_and_reference_row_apply_to_only_their_column():
    page = matrix(["Synthetic A", "Synthetic B"], [["Units", "mmol/L", "ng/mL"],
                  ["Reference range", "0–4", "<10"], ["11.10.2026", "2", "3"]], date_label="Collected")
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 2
    a, b = output["rows"]
    assert a["clinical_time"]["role"] == "collected"
    assert a["unit_raw"] == "mmol/L" and b["unit_raw"] == "ng/mL"
    assert a["reference_intervals"][0]["high"] == "4"
    assert b["reference_intervals"][0]["high"] == "10"
    assert a["field_anchors"]["reference_intervals"]["inherited"] is True
    assert output["issues"] == []


def test_units_under_numeric_cell_are_direct_and_result_remains_actual_numeric_cell():
    page = matrix(["Synthetic A", "Synthetic B"], [["11.10.2026", "2\n(mmol/L)", "3\n(ng/mL)"]], date_label="")
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 2
    for row, unit in zip(output["rows"], ["mmol/L", "ng/mL"]):
        assert row["unit_raw"] == unit
        assert row["field_anchors"]["unit_raw"]["inherited"] is False
        assert row["field_anchors"]["result"]["excerpt"].endswith(f"\n({unit})")


def test_wrapped_analyte_header_stays_one_header_without_duplicate_matrix():
    page = matrix(["Synthetic antibody\nto antigen (IgG)", "Synthetic B"],
                  [["11.10.2026", "not detected", "++"]], date_label="")
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [r["analyte_raw"] for r in output["rows"]] == ["Synthetic antibody to antigen (IgG)", "Synthetic B"]
    assert [r["result"]["kind"] for r in output["rows"]] == ["qualitative", "semiquantitative"]


def test_multiple_stacked_sparse_sections_never_inherit_headers_or_units():
    page = matrix(["Synthetic A\n(mmol/L)", "Synthetic B"], [["11.10.2026", "2", "3"]], date_label="", y=20)
    continuation = matrix(["", "Synthetic C"], [["12.10.2026", "", "negative"]], date_label="", y=160)
    one = matrix(["Synthetic D"], [["13.10.2026", "<4 (ng/mL)"]], date_label="", y=260)
    page["blocks"].extend(continuation["blocks"] + one["blocks"])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [r["analyte_raw"] for r in output["rows"]] == ["Synthetic A", "Synthetic B", "Synthetic C", "Synthetic D"]
    assert output["rows"][2]["unit_raw"] is None
    assert output["rows"][2]["clinical_time"]["value"] == "2026-10-12"
    assert output["rows"][3]["unit_raw"] == "ng/mL"


def test_two_explicit_matrices_side_by_side_keep_their_dates():
    page = matrix(["Synthetic A"], [["11.10.2026", "2"]], x=10)
    right = matrix(["Synthetic B"], [["12.10.2026", "3"]], x=600)
    page["blocks"].extend(right["blocks"])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 2
    assert [r["clinical_time"]["value"] for r in output["rows"]] == ["2026-10-11", "2026-10-12"]


@pytest.mark.parametrize("raw", ["11.10.26", "11.10", "31.02.2026", "03/04/26"])
def test_uncertain_or_invalid_year_is_not_filled_from_page_metadata(raw):
    page = matrix(["Synthetic A"], [[raw, "2"]])
    page["blocks"].insert(0, {"text": "Collected: 2026-10-13", "x": 10, "y": 1, "width": 200, "height": 10})
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert output["rows"][0]["clinical_time"] == {"raw": raw, "role": "unknown", "precision": "unknown", "value": None}
    assert output["rows"][0]["missing_reasons"]["clinical_time"] == "ambiguous"


def test_undated_matrix_result_is_ambiguous_and_never_reuses_previous_date():
    page = matrix(["Synthetic A"], [["11.10.2026", "2"], ["", "3"]])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 2
    row = output["rows"][1]
    assert row["clinical_time"]["raw"] is None
    assert row["field_status"]["clinical_time"] == "ambiguous"
    assert row["missing_reasons"]["clinical_time"] == "ambiguous"
    assert "clinical_time" not in row["field_anchors"]
    assert "MISSING_MATRIX_DATE" in output["issues"][1]["reason_codes"]


@pytest.mark.parametrize("rows", [
    [["Units", "mg/L"], ["11.10.2026", "2"]],
    [["11.10.2026", "2\n(mg/L)"]],
    [["11.10.2026", "2 mg/L"]],
])
def test_header_unit_conflicts_remain_issues_with_full_source(rows):
    page = matrix(["Synthetic A (mmol/L)"], rows)
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert output["rows"] == []
    assert any({"CONFLICTING_MATRIX_UNITS", "CONFLICTING_UNIT_CELLS"}.intersection(i["reason_codes"]) for i in output["issues"])
    assert "mmol/L" in "\n".join(i["raw_text"] for i in output["issues"])
    assert "mg/L" in "\n".join(i["raw_text"] for i in output["issues"])


def test_prose_after_data_and_prose_in_reference_row_never_become_reference_values():
    page = matrix(["Synthetic A"], [["Reference range", "see physician for follow-up"],
                  ["11.10.2026", "2"], ["Comment: synthetic prose", "arbitrary medical prose"]])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 1
    assert output["rows"][0]["reference_intervals"] == []
    assert any("REFERENCE_MATRIX_TEXT_PRESERVED" in i["reason_codes"] for i in output["issues"])
    assert any("NON_DATA_MATRIX_ROW_PRESERVED" in i["reason_codes"] for i in output["issues"])
    assert "arbitrary medical prose" in "\n".join(i["raw_text"] for i in output["issues"])


def test_rotated_matrix_anchors_use_original_raster():
    page = matrix(["Synthetic A"], [["11.10.2026", "2"]], date_label="")
    page["metadata"].update(readable_width=1800, readable_height=900, orientation_degrees=270)
    page["width"], page["height"] = 900, 1800
    for block in page["blocks"]:
        readable = {key: block[key] for key in ("x", "y", "width", "height")}
        block["readable_box"] = readable
        block.update(x=900-readable["y"]-readable["height"], y=readable["x"],
                     width=readable["height"], height=readable["width"])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    box = next(b for b in page["blocks"] if b["text"] == "2")
    assert output["rows"][0]["field_anchors"]["result"]["locator"]["region"] == pytest.approx(
        [box["x"]/900, box["y"]/1800, (box["x"]+box["width"])/900, (box["y"]+box["height"])/1800])


def test_native_matrix_literal_character_cells_are_distinct_and_can_be_submitted(tmp_path):
    text = "Date\t\tSynthetic A (mmol/L)    Synthetic B\n11.10.2026\t2\t\t\tnegative\n"
    page = {"page": 1, "text": text, "blocks": [], "source": "pdf_text"}
    output = propose_lab_rows([page], VERSION)
    assert_valid(output)
    assert len(output["rows"]) == 2
    source_line = text.splitlines()[1]
    for row in output["rows"]:
        anchor = row["field_anchors"]["result"]
        match = re.fullmatch(r"2;chars=(\d+):(\d+)", anchor["locator"]["line"])
        assert match
        assert source_line[int(match[1]):int(match[2])] == anchor["excerpt"]
        assert anchor["excerpt"] == row["result"]["raw"]
    store = SignedStore(tmp_path / "synthetic.sqlite3", b"s"*32, "private-data")
    try:
        records = RecordsService(store)
        records.register_subject("demo", "Synthetic profile")
        version = records.register_document("demo", "b"*64, "application/pdf", 123)
        submitted = propose_lab_rows([page], version)
        run = records.submit_extraction("demo", version["version_id"], submitted["rows"], submitted["coverage"])
        assert len(run["draft_ids"]) == 2
    finally:
        store.close()


def test_shared_ocr_row_box_cannot_fabricate_distinct_result_anchors():
    page = matrix(["Synthetic A", "Synthetic B"], [])
    page["blocks"].append({"text": "11.10.2026    2    3", "x": 10, "y": 55, "width": 300, "height": 20})
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert output["rows"] == []
    assert any("MATRIX_RESULT_CELL_NOT_SEPARATED" in i["reason_codes"] for i in output["issues"])


def test_matrix_document_row_cap_counts_every_populated_and_blank_intersection(monkeypatch):
    page = matrix(["Synthetic A", "Synthetic B", "Synthetic C"], [["11.10.2026", "1", "", "negative"]])
    monkeypatch.setattr("health_analyzer.v2.layout.MAX_ROWS", 2)
    with pytest.raises(V2Error) as error:
        propose_lab_rows([page], VERSION, locator_kind="image")
    assert error.value.code == "ROW_LIMIT"


def test_matrix_low_confidence_retains_source_glyphs_and_stays_ambiguous():
    page = matrix(["Синтетический А"], [["11.10.2026", "≤0,12"]], date_label="", confidence=.2)
    original = copy.deepcopy(page)
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert page == original
    row = output["rows"][0]
    assert row["result"]["raw"] == "≤0,12"
    assert row["analyte_raw"] == "Синтетический А"
    assert set(row["field_status"].values()) == {"ambiguous"}


def test_unstructured_prose_is_not_a_lab_matrix():
    page = {"page": 1, "text": "Synthetic explanatory prose\nA B C", "blocks": [], "source": "pdf_text"}
    output = propose_lab_rows([page], VERSION)
    assert_valid(output)
    assert output["rows"] == []
    assert output["issues"][0]["reason_codes"] == ["TABLE_HEADER_UNRECOGNIZED"]


def test_known_explicit_seconds_and_superscript_units_keep_original_glyphs():
    page = matrix(["Synthetic A\n(с)", "Synthetic B\n(10⁹/л)"],
                  [["11.10.2026", "1", "2"]], date_label="")
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [r["unit_raw"] for r in output["rows"]] == ["с", "10⁹/л"]
    assert all(row.get("unit_code") is None for row in output["rows"])


def test_percent_attached_to_header_is_explicit_unit_and_source_is_untouched():
    page = matrix(["Synthetic A%", "Synthetic B %"], [["11.10.2026", "1,2", "3.4"]], date_label="")
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [(r["analyte_raw"], r["unit_raw"], r["result"]["raw"]) for r in output["rows"]] == [
        ("Synthetic A", "%", "1,2"), ("Synthetic B", "%", "3.4")]
    assert output["rows"][0]["field_anchors"]["analyte_raw"]["excerpt"] == "Synthetic A%"


def test_classic_section_and_matrix_section_have_independent_date_metadata():
    page = matrix(["Synthetic A"], [["11.10.2026", "1"]], y=20)
    for row_index, values in enumerate([
        ["Test", "Result", "Units", "Reference range"],
        ["Synthetic B", "2", "mmol/L", "0–4"],
    ]):
        for column, value in enumerate(values):
            page["blocks"].append({"text": value, "x": 10 + column*250, "y": 170 + row_index*35,
                                   "width": 150, "height": 20})
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [r["analyte_raw"] for r in output["rows"]] == ["Synthetic A", "Synthetic B"]
    assert output["rows"][0]["clinical_time"]["value"] == "2026-10-11"
    assert output["rows"][1]["clinical_time"]["raw"] is None
    assert "clinical_time" not in output["rows"][1]["field_anchors"]


def test_matrix_missing_result_stays_absent_while_explicit_no_result_is_a_draft():
    page = matrix(["Synthetic A", "Synthetic B"], [["11.10.2026", "", "not performed"]])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 1
    assert output["rows"][0]["result"] == {"kind": "no_result", "raw": "not performed", "reason": "not_performed"}
    missing = next(i for i in output["issues"] if "MISSING_RESULT" in i["reason_codes"])
    assert next(c for c in missing["raw_cells"] if c["role"] == "result")["text"] == ""


def test_source_caps_fail_closed_before_any_complex_output(monkeypatch):
    page = matrix(["Synthetic A", "Synthetic B"], [["11.10.2026", "1", "2"]])
    monkeypatch.setattr("health_analyzer.v2.layout.MAX_ISSUES", 1)
    with pytest.raises(V2Error) as error:
        propose_lab_rows([page], VERSION, locator_kind="image")
    assert error.value.code == "ISSUE_LIMIT"
    monkeypatch.setattr("health_analyzer.v2.layout.MAX_TEXT", 10)
    with pytest.raises(V2Error) as error:
        propose_lab_rows([page], VERSION, locator_kind="image")
    assert error.value.code == "LAYOUT_INPUT_LIMIT"


def test_complex_oversized_source_header_has_complete_fragments_without_partial_value():
    header = "Synthetic " + "header detail " * 650
    page = matrix([header], [["11.10.2026", "1"]])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert output["rows"] == []
    fragments = output["issues"]
    assert len(fragments) > 1
    assert all("SOURCE_SPAN_FRAGMENT" in i["reason_codes"] for i in fragments)
    assert header in "".join(i["raw_text"] for i in fragments)
    assert all("SOURCE_FIELD_LIMIT" in i["reason_codes"] for i in fragments)


def _classic_sections(*sections, prefix=()):
    def fixed(values):
        return "".join(str(value).ljust(width) for value, width in zip(values, [36, 20, 16, 28])).rstrip()
    lines = list(prefix)
    for metadata, name in sections:
        lines.extend(metadata)
        lines.extend([fixed(["Test", "Result", "Units", "Reference range"]),
                      fixed([name, "1", "g/L", "0–4"])])
    return {"page": 1, "text": "\n".join(lines), "blocks": [], "source": "pdf_text"}


def test_independent_classic_metadata_is_context_and_not_a_missing_result_row():
    page = _classic_sections(([], "Synthetic A"), (["Reported: 12.10.2026"], "Synthetic B"),
                             prefix=["Collected: 11.10.2026", "Method: Synthetic first", "Specimen: Synthetic first sample"])
    output = propose_lab_rows([page], VERSION)
    assert_valid(output)
    assert len(output["rows"]) == 2
    first, second = output["rows"]
    assert first["method"] == "Synthetic first"
    assert second["method"] is None and second["specimen"] is None
    assert second["clinical_time"]["role"] == "reported"
    assert second["clinical_time"]["value"] == "2026-10-12"
    assert output["coverage"]["expected_count"] == 2
    assert output["coverage"]["unprocessed_pages"] == []
    assert [i["reason_codes"] for i in output["issues"]] == [["SOURCE_METADATA_CONTEXT"]]
    assert output["issues"][0]["raw_cells"][0]["role"] == "source_metadata"
    assert output["issues"][0]["raw_text"] == "Reported: 12.10.2026\n"


def test_shared_document_date_can_cover_repeated_headers_but_method_specimen_do_not():
    page = _classic_sections(([], "Synthetic A"), ([], "Synthetic B"),
                             prefix=["Collected: 11.10.2026", "Method: Synthetic first", "Specimen: Synthetic first sample"])
    output = propose_lab_rows([page], VERSION)
    assert_valid(output)
    assert [r["clinical_time"]["value"] for r in output["rows"]] == ["2026-10-11", "2026-10-11"]
    assert output["rows"][1]["method"] is None and output["rows"][1]["specimen"] is None


def test_explicit_later_method_without_time_blocks_first_document_time_reuse():
    page = _classic_sections(([], "Synthetic A"), (["Method: Synthetic second"], "Synthetic B"),
                             prefix=["Collected: 11.10.2026", "Method: Synthetic first"])
    output = propose_lab_rows([page], VERSION)
    assert_valid(output)
    second = output["rows"][1]
    assert second["method"] == "Synthetic second"
    assert second["clinical_time"]["raw"] is None
    assert "clinical_time" not in second["field_anchors"]


def test_third_independent_section_without_metadata_does_not_borrow_either_earlier_date():
    page = _classic_sections(([], "Synthetic A"), (["Reported: 12.10.2026"], "Synthetic B"),
                             ([], "Synthetic C"), prefix=["Collected: 11.10.2026", "Method: Synthetic first"])
    output = propose_lab_rows([page], VERSION)
    assert_valid(output)
    assert [r["clinical_time"]["value"] for r in output["rows"]] == ["2026-10-11", "2026-10-12", None]
    assert output["rows"][2]["method"] is None


def test_unknown_prose_between_metadata_and_next_header_is_not_crossed():
    page = _classic_sections(([], "Synthetic A"), (["Reported: 12.10.2026", "Unrecognized synthetic panel context"], "Synthetic B"),
                             prefix=["Collected: 11.10.2026"])
    output = propose_lab_rows([page], VERSION)
    assert_valid(output)
    second = next(r for r in output["rows"] if r["analyte_raw"] == "Synthetic B")
    assert second["clinical_time"]["raw"] is None
    assert any("SOURCE_METADATA_CONTEXT" in i["reason_codes"] for i in output["issues"])


def test_classic_analyte_comma_then_literal_percent_wrap_retains_complete_name():
    page = {"page": 1, "source": "pdf_text", "blocks": [], "text":
            "Test                                Result              Units           Reference range\n"
            "Marker H,                           2                   %               0–4\n"
            "%\n"
            "Synthetic B                         3                   g/L             0–4\n"}
    output = propose_lab_rows([page], VERSION)
    assert_valid(output)
    assert [r["analyte_raw"] for r in output["rows"]] == ["Marker H, %", "Synthetic B"]
    assert output["rows"][0]["unit_raw"] == "%"
    assert output["rows"][0]["result"]["raw"] == "2"
    assert len(output["rows"][0]["field_anchors"]["analyte_raw"]) == 2


def _dense_bands(*, count=9, date_text="01.01.2040", unknown_unit=False):
    blocks = []
    for column in range(count):
        x = 100 + column*80
        blocks.extend([
            {"text": f"Marker {chr(65+column)}", "x": x, "y": 100, "width": 75, "height": 14, "confidence": .5},
            {"text": f"{column+1},2", "x": x, "y": 142+(column%2)*2, "width": 24, "height": 14, "confidence": .5},
            {"text": "(J)" if unknown_unit else "(g/L)", "x": x-2, "y": 168, "width": 40, "height": 14, "confidence": .5},
        ])
    if date_text:
        blocks.append({"text": date_text, "x": 12, "y": 154, "width": 72, "height": 12, "confidence": .5})
    return {"page": 1, "text": "", "blocks": blocks, "width": 1000, "height": 600, "source": "vision_ocr"}


def test_dense_nearly_touching_headers_and_offset_date_keep_nine_explicit_intersections():
    page = _dense_bands()
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 9
    assert [r["analyte_raw"] for r in output["rows"]] == [f"Marker {chr(65+i)}" for i in range(9)]
    assert [r["result"]["raw"] for r in output["rows"]] == [f"{i+1},2" for i in range(9)]
    for row in output["rows"]:
        assert row["unit_raw"] == "g/L"
        assert row["clinical_time"]["role"] == "unknown"
        assert row["clinical_time"]["raw"] == "01.01.2040"
        assert row["field_status"]["clinical_time"] == "ambiguous"
        result_box = next(b for b in page["blocks"] if b["text"] == row["result"]["raw"])
        assert row["field_anchors"]["result"]["locator"]["region"] == pytest.approx([
            result_box["x"]/1000, result_box["y"]/600,
            (result_box["x"]+result_box["width"])/1000, (result_box["y"]+result_box["height"])/600])
        assert row["field_anchors"]["clinical_time"]["locator"]["region"] == pytest.approx([.012,154/600,.084,166/600])
    assert "AMBIGUOUS_COLUMNS" not in output["coverage"]["errors"]
    assert "MISSING_MATRIX_DATE" not in output["coverage"]["errors"]


def test_unknown_parenthesized_unit_subcells_keep_numeric_source_and_ambiguous_raw_unit():
    page = _dense_bands(count=3, unknown_unit=True)
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 3
    assert [r["result"]["raw"] for r in output["rows"]] == ["1,2", "2,2", "3,2"]
    assert all(r["unit_raw"] == "J" and r["field_status"]["unit_raw"] == "ambiguous" for r in output["rows"])
    assert all(r.get("unit_code") is None for r in output["rows"])
    assert all(r["field_anchors"]["unit_raw"]["excerpt"] == "(J)" for r in output["rows"])


def test_offset_date_with_short_year_stays_unknown_without_a_guessed_century():
    output = propose_lab_rows([_dense_bands(count=3, date_text="01.01.40")], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 3
    assert all(r["clinical_time"] == {"raw": "01.01.40", "role": "unknown", "precision": "unknown", "value": None}
               for r in output["rows"])


def test_competing_date_bands_cannot_select_one_for_dense_values():
    page = _dense_bands(count=3)
    page["blocks"].append({"text": "02.01.2040", "x": 12, "y": 171, "width": 72, "height": 12, "confidence": .5})
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert output["rows"] == []
    raw = "\n".join(i["raw_text"] for i in output["issues"])
    assert "01.01.2040" in raw and "02.01.2040" in raw


def test_tall_date_box_does_not_bridge_independent_numeric_rows():
    page = _dense_bands(count=3)
    date = next(b for b in page["blocks"] if b["text"] == "01.01.2040")
    date.update(y=140, height=70)
    for column in range(3):
        page["blocks"].append({"text": f"{column+6}.3", "x": 100+column*80, "y": 198, "width": 24, "height": 14, "confidence": .5})
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert output["rows"] == []


def test_new_undated_header_panel_cannot_reuse_previous_matrix_analytes():
    page = _dense_bands(count=3)
    for column in range(3):
        page["blocks"].extend([
            {"text": f"Later marker {chr(65+column)}", "x": 100+column*80, "y": 235, "width": 75, "height": 14, "confidence": .5},
            {"text": f"{column+6}.3", "x": 100+column*80, "y": 270, "width": 24, "height": 14, "confidence": .5},
        ])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert len(output["rows"]) == 3
    assert all(r["result"]["raw"] in {"1,2", "2,2", "3,2"} for r in output["rows"])
    assert "MATRIX_SECTION_BOUNDARY_UNCERTAIN" in output["coverage"]["errors"]


def test_separate_dense_panels_keep_their_own_header_and_date_cells():
    page = _dense_bands(count=3)
    second = _dense_bands(count=3, date_text="02.01.2040")
    for box in second["blocks"]:
        box["y"] += 150
        if box["text"].startswith("Marker "):
            box["text"] = "Later " + box["text"]
    page["blocks"].extend(second["blocks"])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [r["analyte_raw"] for r in output["rows"]] == ["Marker A", "Marker B", "Marker C", "Later Marker A", "Later Marker B", "Later Marker C"]
    assert [r["clinical_time"]["raw"] for r in output["rows"]] == ["01.01.2040"]*3 + ["02.01.2040"]*3


def test_repeated_dense_unknown_unit_subcells_never_become_later_analyte_headers():
    page = _dense_bands(count=3, unknown_unit=True)
    for column in range(3):
        page["blocks"].extend([
            {"text": f"{column+6}.3", "x": 100+column*80, "y": 242+(column%2)*2, "width": 24, "height": 14, "confidence": .5},
            {"text": "(J)", "x": 98+column*80, "y": 268, "width": 40, "height": 14, "confidence": .5},
        ])
    page["blocks"].append({"text": "02.01.2040", "x": 12, "y": 254, "width": 72, "height": 12, "confidence": .5})
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [r["analyte_raw"] for r in output["rows"]] == ["Marker A", "Marker B", "Marker C"]*2
    assert [r["result"]["raw"] for r in output["rows"]] == ["1,2", "2,2", "3,2", "6.3", "7.3", "8.3"]
    assert [r["clinical_time"]["raw"] for r in output["rows"]] == ["01.01.2040"]*3 + ["02.01.2040"]*3
    for index, row in enumerate(output["rows"]):
        assert row["unit_raw"] == "J"
        assert row["field_status"]["unit_raw"] == "ambiguous"
        assert row["field_anchors"]["unit_raw"]["excerpt"] == "(J)"
        assert row["field_anchors"]["unit_raw"]["inherited"] is False
        assert row["field_anchors"]["unit_raw"]["locator"]["region"][1] == pytest.approx((168 if index < 3 else 268)/600)


def test_unknown_parenthesized_analyte_header_without_value_context_is_not_a_unit():
    page = matrix(["(J)", "Marker B"], [["01.01.2040", "2", "3"]])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert_valid(output)
    assert [r["analyte_raw"] for r in output["rows"]] == ["(J)", "Marker B"]
    assert output["rows"][0]["unit_raw"] is None
