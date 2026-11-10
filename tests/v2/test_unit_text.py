from health_analyzer.v2.unit_text import inspect_unit


def test_raw_is_preserved_for_exact_typography_and_micro_aliases():
    for raw in ("мкмоль / л", "µmol/L", "μmol/L", "umol/L"):
        value = inspect_unit(raw)
        assert value["raw"] == raw and value["unit_code"] == "umol/L"
        assert value["status"] == "known"


def test_competing_prefixes_and_confused_liter_are_never_silently_corrected():
    value = inspect_unit("mg/L", [{"text": "µg/L", "confidence": .99}])
    assert value["raw"] == "mg/L" and value["status"] == "ambiguous"
    assert value["unit_code"] is None
    confused = inspect_unit("mmol/1")
    assert confused["raw"] == "mmol/1" and confused["status"] == "ambiguous"
    assert confused["alternatives"][0]["unit_code"] == "mmol/L"


def test_superscript_notation_is_explicit_not_an_inferred_exponent():
    assert inspect_unit("10⁹/л")["unit_code"] == "10*9/L"
    assert inspect_unit("10^9/л")["unit_code"] == "10*9/L"
    assert inspect_unit("109/л")["unit_code"] is None
    assert inspect_unit("1019/л")["unit_code"] is None


def test_prefix_case_is_significant_and_prose_is_not_a_unit():
    assert inspect_unit("Ммоль/л")["unit_code"] is None
    assert inspect_unit("Mmol/L")["unit_code"] is None
    assert inspect_unit("ммОЛЬ/л")["unit_code"] == "mmol/L"
    assert inspect_unit("ммоль/л 1–8")["unit_code"] is None
    assert inspect_unit(None)["status"] == "missing"


def test_late_conflicting_candidate_is_not_hidden_by_a_display_limit():
    candidates = [{"text": " " * i + "mg/L"} for i in range(1, 15)] + [{"text": "µg/L"}]
    value = inspect_unit("mg/L", candidates)
    assert value["raw"] == "mg/L" and value["unit_code"] is None
    assert value["status"] == "ambiguous" and len(value["alternatives"]) == 15
    assert value["alternatives"][-1]["text"] == "µg/L"
