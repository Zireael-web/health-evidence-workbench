"""Synthetic collapsed PDF text; no original report values or identifiers."""
from health_analyzer.v2.layout import propose_lab_rows

VERSION = {"version_id": "ver_synthetic", "source_sha256": "a" * 64}


def page(unit, reference="", continuation=""):
    def line(values):
        return "".join(str(v).ljust(w) for v, w in zip(values, (36, 20, 24, 45))).rstrip()
    text = line(["Test", "Result", "Units", "Reference range"]) + "\n" + line(["Synthetic A", "4.2", unit, reference])
    if continuation:
        text += "\n" + line(["", "", "", continuation])
    return {"page": 1, "source": "pdf_text", "text": text, "blocks": []}


def test_collapsed_unit_range_cannot_be_confirmed_as_certain_unit_or_missing_reference():
    output = propose_lab_rows([page("mmol/L 1–8")], VERSION)
    row = output["rows"][0]
    assert row["unit_raw"] == "mmol/L 1–8"  # exact candidate stays available
    assert row["field_status"]["unit_raw"] == "ambiguous"
    assert row["field_status"]["reference_intervals"] == "ambiguous"
    assert row["missing_reasons"]["reference_intervals"] == "ambiguous"
    assert any("UNIT_CELL_AMBIGUOUS" in i["reason_codes"] for i in output["issues"])
    assert output["coverage"]["status"] == "partial"


def test_device_narrative_continuation_remains_uncertain_source_not_certain_reference():
    output = propose_lab_rows([page("mmol/L", "1–8", "Device: synthetic analyzer")], VERSION)
    row = output["rows"][0]
    assert row["field_status"]["reference_intervals"] == "ambiguous"
    assert "synthetic analyzer" in row["reference_intervals"][0]["raw"]
    assert any("REFERENCE_CELL_AMBIGUOUS" in i["reason_codes"] for i in output["issues"])


def test_clean_scalar_reference_and_unit_remain_separate_proposals():
    output = propose_lab_rows([page("mmol/L", "1–8")], VERSION)
    row = output["rows"][0]
    assert row["unit_raw"] == "mmol/L"
    assert row["field_status"]["unit_raw"] == "proposed"
    assert row["field_status"]["reference_intervals"] == "proposed"
    assert row["reference_intervals"][0]["low"] == "1"


def test_generic_technology_prose_cannot_hide_in_a_reference_range():
    output = propose_lab_rows([page("mmol/L", "1–8", "Synthetic optical platform employed")], VERSION)
    row = output["rows"][0]
    assert row["field_status"]["reference_intervals"] == "ambiguous"
    assert "optical platform" in row["reference_intervals"][0]["raw"]


def test_close_distinct_ocr_headers_do_not_merge_result_and_unit():
    blocks = []
    columns = [(70, 200), (650, 185), (911, 100), (1100, 240)]
    for index, cells in enumerate([("Analyte", "Result", "Unit", "Reference"),
                                   ("Synthetic A", "5", "g/L", "0–10")]):
        for (x, width), value in zip(columns, cells):
            blocks.append({"text": value, "x": x, "y": 30 + index * 100,
                           "width": width, "height": 54, "confidence": .98})
    output = propose_lab_rows([{"page": 1, "source": "vision_ocr", "text": "", "blocks": blocks,
                               "width": 1600, "height": 900}], VERSION, locator_kind="image")
    assert len(output["rows"]) == 1
    assert output["rows"][0]["result"]["decimal"] == "5"
    assert output["rows"][0]["unit_raw"] == "g/L"
    assert output["coverage"]["status"] == "complete"
