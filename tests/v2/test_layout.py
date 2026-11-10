"""Synthetic layouts only: no report content or personal information."""
import copy

import pytest

from health_analyzer.v2.common import SignedStore, V2Error, canonical
from health_analyzer.v2.contracts import extraction_coverage, lab_observation
from health_analyzer.v2.import_issues import ImportIssueService, validate_issue
from health_analyzer.v2.layout import propose_lab_rows
from health_analyzer.v2.records import RecordsService


VERSION = {"version_id": "ver_synthetic", "source_sha256": "a" * 64}


def fixed(*rows, metadata="", page=1, header=None):
    def line(cells):
        widths = [36, 20, 16, 28, 24]
        return "".join(str(cell).ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()
    header = header or ["Исследование", "Результат", "Единицы", "Референсные значения"]
    return {"page": page, "text": (metadata + "\n" if metadata else "") + line(header) + "\n" +
            "\n".join(line(row) for row in rows), "blocks": [], "source": "pdf_text"}


def geometry(rows, *, source="vision_ocr", confidence=.98, metadata=None, headers=None):
    blocks = []
    columns = [12, 270, 395, 500, 700]
    headers = headers or ["Test", "Result", "Units", "Reference range"]
    for row_index, row in enumerate([headers, *rows]):
        for column, token in enumerate(row):
            if token:
                blocks.append({"text": token, "x": columns[column], "y": 40 + row_index * 18,
                               "width": min(180, max(18, len(token) * 6)), "height": 11,
                               "confidence": confidence if source == "vision_ocr" else None})
    return {"page": 1, "text": "", "blocks": blocks, "width": 900, "height": 600,
            "source": source, "metadata": metadata or {}}


def validate(output):
    for row in output["rows"]:
        assert lab_observation(row, **VERSION) == row
        assert row["mapping_status"] == "unmapped"
        assert set(row["field_status"].values()) <= {"proposed", "ambiguous"}
    extraction_coverage(output["coverage"], len(output["rows"]))


def test_russian_fixed_columns_are_whole_rows_with_collection_datetime():
    page = fixed(["Глюкоза", "5,1", "ммоль/л", "3,5–6,0"],
                 ["Ферритин", "<0,10", "нг/мл", ">=20"],
                 metadata="Дата взятия образца: 11.10.2026 08:45\nДата печати: 12.10.2026 12:01")
    output = propose_lab_rows([page], VERSION)
    validate(output)
    assert len(output["rows"]) == 2
    a, b = output["rows"]
    assert a["result"] == {"kind": "numeric_exact", "raw": "5,1", "decimal": "5.1"}
    assert a["clinical_time"]["role"] == "collected"
    assert a["clinical_time"]["value"] == "2026-10-11T08:45"
    assert "timezone" not in a["clinical_time"]
    assert b["result"]["operator"] == "<"
    assert b["reference_intervals"][0]["low"] == "20"
    assert b["reference_intervals"][0]["low_inclusive"] is True
    assert a["field_anchors"]["clinical_time"]["inherited"] is True
    assert a["field_anchors"]["result"]["locator"]["line"] == 4
    assert output["coverage"]["expected_count"] == 2


def test_geometry_ocr_qualitative_flags_and_units_are_proposals():
    output = propose_lab_rows([geometry([
        ["Synthetic A", "7.2 ↑", "mmol/L", "3.0–6.0"],
        ["Synthetic B", "not detected", "", "negative"],
        ["Synthetic C", "++", "", "negative"],
    ])], VERSION, locator_kind="image")
    validate(output)
    assert [row["result"]["kind"] for row in output["rows"]] == ["numeric_exact", "qualitative", "semiquantitative"]
    a = output["rows"][0]
    assert a["result"]["raw"] == "7.2"
    assert a["lab_flag_raw"] == "↑"
    assert a["extraction_method"] == "local_ocr"
    anchor = a["field_anchors"]["result"]
    assert anchor["locator"]["kind"] == "image"
    assert anchor["excerpt"] == "7.2 ↑"
    assert anchor["locator"]["region"][0] == pytest.approx(270 / 900)


def test_multiline_analyte_before_result_and_reference_continuation():
    page = fixed(["Антитела к синтетическому", "", "", ""],
                 ["антигену (IgG)", "не обнаружено", "", "Отрицательно"],
                 ["", "", "", "при значении менее 1"],
                 ["Synthetic D", "2,3", "ед/л", "0–4"])
    output = propose_lab_rows([page], VERSION)
    validate(output)
    assert len(output["rows"]) == 2
    assert output["rows"][0]["analyte_raw"] == "Антитела к синтетическому антигену (IgG)"
    assert output["rows"][0]["reference_intervals"][0]["raw"] == "Отрицательно при значении менее 1"
    assert len(output["rows"][0]["field_anchors"]["analyte_raw"]) == 2


def test_split_qualitative_cell_forms_one_whole_row_with_wrap_issue():
    page = fixed(["Synthetic A", "не", "", "отрицательно"],
                 ["", "обнаружено", "", ""],
                 ["Synthetic B", "1", "ед/л", "0–4"])
    output = propose_lab_rows([page], VERSION)
    validate(output)
    assert len(output["rows"]) == 2
    assert output["rows"][0]["result"]["raw"] == "не обнаружено"
    assert output["issues"][0]["reason_codes"] == ["MULTILINE_ROW_PROPOSED"]


def test_named_blank_result_cannot_be_swallowed_as_analyte_continuation():
    page = fixed(["Synthetic A", "1", "ед/л", "0–4"],
                 ["Synthetic Missing", "", "", ""],
                 ["Synthetic B", "2", "ед/л", "0–4"])
    output = propose_lab_rows([page], VERSION)
    validate(output)
    assert [row["analyte_raw"] for row in output["rows"]] == ["Synthetic A", "Synthetic B"]
    assert len(output["issues"]) == 1
    assert output["issues"][0]["raw_cells"][0]["text"] == "Synthetic Missing"
    assert output["issues"][0]["reason_codes"] == ["MISSING_RESULT"]


def test_row_comment_keeps_the_source_without_polluting_analyte():
    page = fixed(["Synthetic A", "5,1", "ммоль/л", "3–6"],
                 ["Комментарий: повторить при необходимости"],
                 ["Synthetic B", "2", "ед/л", "0–4"])
    output = propose_lab_rows([page], VERSION)
    validate(output)
    assert [row["analyte_raw"] for row in output["rows"]] == ["Synthetic A", "Synthetic B"]
    issue = output["issues"][0]
    assert issue["reason_codes"] == ["ROW_COMMENT_CONTINUATION"]
    assert issue["raw_cells"][-1]["role"] == "comment"
    assert "повторить" in issue["raw_cells"][-1]["text"]
    assert issue["proposed_row"] == output["rows"][0]


def test_prior_results_remain_separate_with_unknown_time_role():
    page = fixed(["Synthetic A", "7,0", "ммоль/л", "3–6", "4,0"],
                 header=["Исследование", "Результат", "Единицы", "Референсные значения", "01.08.2026"])
    output = propose_lab_rows([page], VERSION)
    validate(output)
    assert len(output["rows"]) == 1
    assert output["rows"][0]["result"]["decimal"] == "7.0"
    issue = output["issues"][0]
    assert issue["reason_codes"] == ["PRIOR_RESULT_COLUMN_SEPARATED"]
    prior = issue["alternatives"][0]
    assert prior["result"]["decimal"] == "4.0"
    assert prior["clinical_time"] == {"raw": "01.08.2026", "role": "unknown", "precision": "date", "value": "2026-08-01"}
    assert "unit_raw" not in prior
    assert "reference_intervals" not in prior
    assert issue["raw_cells"][-1]["column"] == 4


@pytest.mark.parametrize("date_text", ["03/04/26", "31.02.2026", "осень 2026"])
def test_unknown_collection_dates_preserve_raw_with_ambiguity(date_text):
    output = propose_lab_rows([fixed(["Synthetic A", "1", "ед/л", "0–4"],
                                    metadata="Дата забора: " + date_text)], VERSION)
    validate(output)
    row = output["rows"][0]
    assert row["clinical_time"] == {"raw": date_text, "role": "collected", "precision": "unknown", "value": None}
    assert row["field_status"]["clinical_time"] == "ambiguous"
    assert output["issues"][0]["reason_codes"] == ["UNKNOWN_CLINICAL_TIME"]


def test_dates_are_page_local_and_reported_role_is_not_collected():
    a = fixed(["Synthetic A", "1", "ед/л", "0–4"], metadata="Report date: 2026-10-11", page=1)
    b = fixed(["Synthetic B", "2", "ед/л", "0–4"], page=2)
    output = propose_lab_rows([a, b], VERSION)
    validate(output)
    assert output["rows"][0]["clinical_time"]["role"] == "reported"
    assert output["rows"][1]["clinical_time"]["precision"] == "unknown"
    assert output["rows"][1]["clinical_time"]["raw"] is None
    assert "clinical_time" not in output["rows"][1]["field_anchors"]


@pytest.mark.parametrize("metadata", ["Дата рождения: 01.01.1900", "Date of birth: 1900-01-01"])
def test_birth_date_is_not_reused_as_clinical_timestamp(metadata):
    output = propose_lab_rows([fixed(["Synthetic A", "1", "ед/л", "0–4"], metadata=metadata)], VERSION)
    assert output["rows"][0]["clinical_time"]["raw"] is None
    assert "clinical_time" not in output["rows"][0]["field_anchors"]


def test_conflicting_collected_dates_cannot_choose_one_silently():
    output = propose_lab_rows([fixed(["Synthetic A", "1", "ед/л", "0–4"],
                                    metadata="Collected: 2026-10-11\nCollected: 2026-10-12")], VERSION)
    row = output["rows"][0]
    assert row["clinical_time"]["precision"] == "unknown"
    assert row["clinical_time"]["raw"] == "2026-10-11 | 2026-10-12"
    assert "UNKNOWN_CLINICAL_TIME" in output["issues"][0]["reason_codes"]


@pytest.mark.parametrize("raw", ["", "5 7", "1.2E3", "see source details", "5 mmol/L 3–6"])
def test_unsupported_or_missing_result_is_visible_issue_never_no_result(raw):
    output = propose_lab_rows([fixed(["Synthetic A", raw, "ед/л", "0–4"])], VERSION)
    validate(output)
    assert output["rows"] == []
    issue = output["issues"][0]
    assert issue["proposed_row"] is None
    assert issue["raw_cells"][0]["text"] == "Synthetic A"
    assert issue["reason_codes"]
    assert output["coverage"]["unprocessed_pages"] == [1]


def test_arbitrary_numeric_suffix_is_not_guessed_as_unit():
    output = propose_lab_rows([fixed(["Synthetic A", "5 positive", "", "0–4"])], VERSION)
    assert output["rows"] == []
    assert "AMBIGUOUS_RESULT_SUFFIX" in output["issues"][0]["reason_codes"]


def test_explicit_no_result_token_is_distinct_from_absent_cell():
    output = propose_lab_rows([fixed(["Synthetic A", "не выполнено", "", ""])], VERSION)
    validate(output)
    assert output["rows"][0]["result"] == {"kind": "no_result", "raw": "не выполнено", "reason": "not_performed"}


def test_inline_unit_split_has_real_cell_provenance_and_conflict_is_issue():
    output = propose_lab_rows([fixed(["Synthetic A", "5.1 mmol/L", "", "3–6"])], VERSION)
    validate(output)
    row = output["rows"][0]
    assert row["result"]["raw"] == "5.1"
    assert row["unit_raw"] == "mmol/L"
    assert row["field_anchors"]["unit_raw"]["excerpt"] == "5.1 mmol/L"
    conflict = propose_lab_rows([fixed(["Synthetic A", "5.1 mmol/L", "mg/L", "3–6"])], VERSION)
    assert conflict["rows"] == []
    assert "CONFLICTING_UNIT_CELLS" in conflict["issues"][0]["reason_codes"]


def test_low_ocr_confidence_is_explicit_and_never_confirmation():
    output = propose_lab_rows([geometry([["Synthetic A", "5.1", "mmol/L", "3–6"]], confidence=.4)], VERSION)
    validate(output)
    assert output["issues"][0]["reason_codes"] == ["LOW_OCR_CONFIDENCE"]
    assert set(output["rows"][0]["field_status"].values()) == {"ambiguous"}
    assert "confirmed" not in output["rows"][0]


def test_rotated_ocr_groups_readable_boxes_but_anchors_original_boxes():
    page = geometry([["Synthetic A", "5.1", "mmol/L", "3–6"]])
    page["metadata"].update(orientation_degrees=90, readable_width=900, readable_height=600)
    page["width"], page["height"] = 600, 900
    for box in page["blocks"]:
        readable = {key: box[key] for key in ("x", "y", "width", "height")}
        box["readable_box"] = readable
        box.update(x=readable["y"], y=900 - readable["x"] - readable["width"],
                   width=readable["height"], height=readable["width"])
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    validate(output)
    assert output["rows"][0]["result"]["decimal"] == "5.1"
    result_box = next(box for box in page["blocks"] if box["text"] == "5.1")
    region = output["rows"][0]["field_anchors"]["result"]["locator"]["region"]
    assert region == pytest.approx([result_box["x"] / 600, result_box["y"] / 900,
                                   (result_box["x"] + result_box["width"]) / 600,
                                   (result_box["y"] + result_box["height"]) / 900])


def test_word_blocks_join_headers_without_joining_columns():
    page = geometry([["Synthetic A", "5.1", "mmol/L", "3–6"]])
    header = next(box for box in page["blocks"] if box["text"] == "Reference range")
    page["blocks"].remove(header)
    a = dict(header, text="Reference", width=54)
    b = dict(header, text="range", x=560, width=30)
    page["blocks"].extend([a, b])
    output = propose_lab_rows([page], VERSION)
    assert output["rows"][0]["reference_intervals"][0]["high"] == "6"


def test_duplicate_result_columns_and_unknown_headers_are_not_silent():
    duplicate = fixed(["Synthetic A", "5.1", "4.1", "3–6"], header=["Test", "Result", "Result", "Reference range"])
    output = propose_lab_rows([duplicate], VERSION)
    assert output["rows"] == []
    assert "AMBIGUOUS_COLUMNS" in output["issues"][0]["reason_codes"]
    plain = {"page": 1, "text": "Synthetic unsupported table\nA B C", "source": "pdf_text", "blocks": []}
    output = propose_lab_rows([plain], VERSION)
    assert "A B C" in output["issues"][0]["raw_text"]
    assert output["issues"][0]["reason_codes"] == ["TABLE_HEADER_UNRECOGNIZED"]


def test_large_limits_and_malformed_geometry_fail_closed(monkeypatch):
    page = geometry([["Synthetic A", "1", "mmol/L", "3–6"]])
    bad = copy.deepcopy(page)
    bad["blocks"][0]["width"] = float("nan")
    with pytest.raises(V2Error) as error:
        propose_lab_rows([bad], VERSION)
    assert error.value.code == "INVALID_LAYOUT"
    monkeypatch.setattr("health_analyzer.v2.layout.MAX_ROWS", 1)
    with pytest.raises(V2Error) as error:
        propose_lab_rows([fixed(["Synthetic A", "1", "u", "0–4"], ["Synthetic B", "2", "u", "0–4"])], VERSION)
    assert error.value.code == "ROW_LIMIT"


def test_unknown_page_55_lines_keeps_full_source_with_coarse_truthful_range():
    text = "\n".join(f"Unsupported synthetic source line {index:02d}: context {index}" for index in range(55)) + "\n"
    unknown = {"page": 1, "text": text, "blocks": [], "source": "pdf_text"}
    output = propose_lab_rows([unknown, fixed(["Synthetic A", "1", "u", "0–4"], page=2)], VERSION)
    validate(output)
    assert len(output["rows"]) == 1
    assert output["coverage"]["status"] == "partial"
    assert output["coverage"]["expected_count"] is None
    assert output["coverage"]["processed_pages"] == [2]
    assert output["coverage"]["unprocessed_pages"] == [1]
    issue = output["issues"][0]
    assert validate_issue(issue, VERSION) == issue
    assert issue["raw_text"] == text
    anchors = issue["raw_cells"][0]["anchors"]
    assert len(anchors) == 1
    assert anchors[0]["locator"] == {"kind": "pdf", "page": 1, "line": "1-55"}
    assert all(line in anchors[0]["excerpt"] for line in text.splitlines())


def test_55_comment_lines_do_not_discard_or_duplicate_valid_lab_rows():
    comments = [[f"Комментарий: synthetic complete statement {index:02d}"] for index in range(55)]
    page = fixed(["Synthetic A", "1", "u", "0–4"], *comments, ["Synthetic B", "2", "u", "0–4"])
    output = propose_lab_rows([page], VERSION)
    validate(output)
    assert [row["analyte_raw"] for row in output["rows"]] == ["Synthetic A", "Synthetic B"]
    assert output["coverage"]["expected_count"] == 2
    assert output["coverage"]["status"] == "partial"
    issue = output["issues"][0]
    validate_issue(issue, VERSION)
    cell = next(cell for cell in issue["raw_cells"] if cell["role"] == "comment")
    assert len(cell["anchors"]) == 1
    assert cell["anchors"][0]["locator"]["line"] == "3-57"
    assert all(comment[0] in issue["raw_text"] for comment in comments)
    assert issue["proposed_row"] == output["rows"][0]


def test_long_unknown_page_partitions_into_complete_ordered_bounded_fragments(tmp_path):
    text = "\n".join(f"Unmapped synthetic line {index:02d}: " + "синтетический контекст " * 12 for index in range(60)) + "\n"
    unknown = {"page": 1, "text": text, "blocks": [], "source": "pdf_text"}
    valid = fixed(["Synthetic A", "1", "u", "0–4"], page=2)
    with_store = SignedStore(tmp_path / "synthetic.sqlite3", b"s" * 32, "private-data")
    try:
        records = RecordsService(with_store)
        records.register_subject("demo", "Synthetic profile")
        version = records.register_document("demo", "a" * 64, "application/pdf", 123)
        output = propose_lab_rows([unknown, valid], version)
        assert len(output["rows"]) == 1
        fragments = output["issues"]
        assert len(fragments) > 1
        assert "".join(fragment["raw_text"] for fragment in fragments) == text
        links = [fragment["alternatives"][0] for fragment in fragments]
        assert len({link["group_id"] for link in links}) == 1
        for index, (fragment, link) in enumerate(zip(fragments, links), 1):
            assert validate_issue(fragment, version) == fragment
            assert "TABLE_HEADER_UNRECOGNIZED" in fragment["reason_codes"]
            assert "SOURCE_SPAN_FRAGMENT" in fragment["reason_codes"]
            assert link["index"] == index and link["count"] == len(fragments)
            assert link["previous_index"] == (index - 1 if index > 1 else None)
            assert link["next_index"] == (index + 1 if index < len(fragments) else None)
            assert len(fragment["raw_text"]) <= 8000 and len(canonical(fragment)) <= 64 * 1024
            assert text[link["start_character"]:link["end_character"]] == fragment["raw_text"]
        run = records.submit_extraction("demo", version["version_id"], output["rows"], output["coverage"])
        registered = ImportIssueService(records).register("demo", version["version_id"], run["run_id"], fragments)
        assert len(registered) == len(fragments)
        review = records.prepare_review("demo", version["version_id"])
        assert len(review["rows"]) == 1 and review["rows"][0]["row"]["analyte_raw"] == "Synthetic A"
        assert review["coverage"]["status"] == "partial" and review["coverage"]["expected_count"] is None
    finally:
        with_store.close()


def test_long_row_comment_fragments_keep_complete_source_and_related_row():
    comments = [[f"Комментарий: synthetic statement {index:02d} " + "detail " * 70] for index in range(55)]
    page = fixed(["Synthetic A", "1", "u", "0–4"], *comments)
    output = propose_lab_rows([page], VERSION)
    assert len(output["rows"]) == 1
    fragments = output["issues"]
    assert len(fragments) > 1
    expected = "".join(page["text"].splitlines(keepends=True)[1:])
    assert "".join(fragment["raw_text"] for fragment in fragments) == expected
    for fragment in fragments:
        validate_issue(fragment, VERSION)
        assert fragment["proposed_row"] is None
        assert fragment["alternatives"][0]["related_result_locators"] == [{"kind": "pdf", "page": 1, "line": 2}]
    assert output["coverage"]["status"] == "partial"


def test_single_oversized_source_cell_is_quarantined_without_truncating_other_rows():
    page = fixed(["Synthetic A", "1", "u", "0–4"], ["Synthetic B", "2", "u", "s" * 12000])
    output = propose_lab_rows([page], VERSION)
    assert [row["analyte_raw"] for row in output["rows"]] == ["Synthetic A"]
    expected = page["text"].splitlines(keepends=True)[2]
    assert "".join(fragment["raw_text"] for fragment in output["issues"]) == expected
    assert all("SOURCE_FIELD_LIMIT" in fragment["reason_codes"] for fragment in output["issues"])
    for fragment in output["issues"]:
        validate_issue(fragment, VERSION)
        assert fragment["raw_cells"][0]["anchors"][0]["locator"]["line"] == 3
    assert output["coverage"]["status"] == "partial" and output["coverage"]["expected_count"] is None


def test_empty_unreadable_page_has_no_none_or_fabricated_anchors():
    output = propose_lab_rows([{"page": 1, "text": "", "blocks": [], "source": "pdf_text"}], VERSION)
    issue = output["issues"][0]
    assert issue["raw_text"] == "" and issue["raw_cells"] == []
    validate_issue(issue, VERSION)


def test_fragment_issue_and_document_text_caps_remain_fail_closed(monkeypatch):
    long_page = {"page": 1, "text": "Unmapped " + "x" * 10000, "blocks": [], "source": "pdf_text"}
    monkeypatch.setattr("health_analyzer.v2.layout.MAX_ISSUES", 2)
    with pytest.raises(V2Error) as error:
        propose_lab_rows([long_page, fixed(["Synthetic A", "1", "u", "0–4"], page=2)], VERSION)
    assert error.value.code == "ISSUE_LIMIT"
    monkeypatch.setattr("health_analyzer.v2.layout.MAX_TEXT", 100)
    with pytest.raises(V2Error) as error:
        propose_lab_rows([long_page], VERSION)
    assert error.value.code == "LAYOUT_INPUT_LIMIT"
