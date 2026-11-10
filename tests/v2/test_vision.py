"""Pure historical OCR protocol validation; no recognition or native builds."""
from copy import deepcopy
import json

import pytest

from health_analyzer.v2.common import V2Error
from health_analyzer.v2 import vision


def response():
    return {"protocol": vision.PROTOCOL, "ok": True, "pages": [{
        "page": 1, "text": "Synthetic 148", "width": 100, "height": 200,
        "source": "vision_ocr", "blocks": [{"text": "148", "x": 10.0, "y": 20.0,
            "width": 30.0, "height": 10.0, "confidence": 0.9,
            "readable_box": {"x": 10.0, "y": 20.0, "width": 30.0, "height": 10.0},
            "geometry_estimated": False}],
        "metadata": {"orientation_degrees": 0, "confidence": 0.9,
            "readable": True, "issues": [], "readable_width": 100,
            "readable_height": 200, "exif_orientation": 1,
            "coordinate_space": "original_raster_pixels_top_left",
            "orientation_trials": [{"degrees": d, "confidence": 0.9 if d == 0 else 0.1,
                "score": 10.0 if d == 0 else 1.0, "characters": 13 if d == 0 else 2}
                for d in (0, 90, 180, 270)]}}]}


def encoded(value):
    return json.dumps(value, allow_nan=True).encode("utf-8")



@pytest.mark.parametrize("mutate", [
    lambda value: value["pages"][0]["blocks"][0].update(x=float("nan")),
    lambda value: value["pages"][0]["blocks"][0].update(width=1000),
    lambda value: value["pages"][0]["blocks"][0]["readable_box"].update(x=20),
    lambda value: value["pages"][0]["metadata"].update(orientation_trials=[]),
    lambda value: value["pages"][0]["metadata"].update(confidence=1.1),
    lambda value: value["pages"][0].update(page=2),
    lambda value: value.update(pages=[]),
])
def test_rejects_forged_or_unbounded_geometry_and_metadata(mutate):
    value = response()
    mutate(value)
    with pytest.raises(V2Error):
        vision._decode_response(encoded(value), maximum=1)


@pytest.mark.parametrize("rotation,expected", [
    (0, {"x": 0.1, "y": 0.2, "width": 0.3, "height": 0.1}),
    (90, {"x": 0.2, "y": 0.6, "width": 0.1, "height": 0.3}),
    (180, {"x": 0.6, "y": 0.7, "width": 0.3, "height": 0.1}),
    (270, {"x": 0.7, "y": 0.1, "width": 0.1, "height": 0.3}),
])
def test_original_box_inverse_orientation(rotation, expected):
    actual = vision.transform_normalized_box({"x": 0.1, "y": 0.2, "width": 0.3, "height": 0.1}, rotation)
    assert actual == pytest.approx(expected)


def test_unreadable_page_is_not_fabricated_as_read_text():
    value = response()
    page = value["pages"][0]
    page.update(text="", blocks=[])
    page["metadata"].update(confidence=0.0, readable=False, issues=["no_text_recognized"])
    pages = vision._decode_response(encoded(value), maximum=1)
    assert pages[0]["text"] == "" and pages[0]["metadata"]["quality"] == "unreadable"


def test_page_cap_discards_entire_result():
    value = response()
    second = deepcopy(value["pages"][0])
    second["page"] = 2
    value["pages"].append(second)
    with pytest.raises(V2Error) as error:
        vision._decode_response(encoded(value), maximum=1)
    assert error.value.code == "VISION_PROTOCOL_ERROR"


def test_worker_error_is_sanitized():
    with pytest.raises(V2Error) as error:
        vision._decode_response(encoded({"protocol": vision.PROTOCOL, "ok": False,
                                        "code": "VISION_PDF_PAGE_LIMIT"}), maximum=50)
    assert error.value.code == "VISION_PDF_PAGE_LIMIT"
    assert "page" not in error.value.message.lower()


def _with_candidates():
    value = response()
    value["pages"][0]["metadata"]["recognition"] = {
        "revision": 3, "supported_languages": ["en-US", "ru-RU"],
        "recognition_languages": ["ru-RU", "en-US"], "automatic_language_detection": False,
        "language_correction": False, "custom_words_count": 45, "crop_passes": 1, "crop_pixels": 1000,
    }
    block = value["pages"][0]["blocks"][0]
    block["text"] = "1019/л"
    block["candidates"] = [{"text": "1019/л", "confidence": block["confidence"], "origin": "first_pass"},
                           {"text": "10^9/л", "confidence": 1.0, "origin": "pixel_crop"}]
    return value


def test_bounded_candidates_preserve_raw_and_legacy_protocol():
    original = _with_candidates()
    pages = vision._decode_response(encoded(original), maximum=1)
    assert pages[0]["blocks"][0]["text"] == "1019/л"
    assert pages[0]["blocks"][0]["candidates"] == original["pages"][0]["blocks"][0]["candidates"]
    assert vision._decode_response(encoded(response()), maximum=1)[0]["blocks"][0]["text"] == "148"


@pytest.mark.parametrize("mutate", [
    lambda p: p["blocks"][0]["candidates"][0].update(text="10^9/л"),
    lambda p: p["blocks"][0]["candidates"][0].update(confidence=0.1),
    lambda p: p["blocks"][0]["candidates"][0].update(origin="pixel_crop"),
    lambda p: p["blocks"][0]["candidates"].append({"text": "1019/л", "confidence": 0.5, "origin": "first_pass"}),
    lambda p: p["blocks"][0]["candidates"].extend([{"text": s, "confidence": 0.5, "origin": "first_pass"} for s in ("A", "B")]),
    lambda p: p["blocks"][0]["candidates"][1].update(confidence=float("nan")),
    lambda p: p["blocks"][0]["candidates"][1].update(origin=[]),
    lambda p: p["blocks"][0]["candidates"][1].update(source_path="synthetic-path"),
    lambda p: p["metadata"]["recognition"].update(recognition_languages=["en-US", "ru-RU"]),
    lambda p: p["metadata"]["recognition"].update(supported_languages=["ru-RU", "ru-RU"]),
    lambda p: p["metadata"]["recognition"].update(language_correction=True),
    lambda p: p["metadata"]["recognition"].update(crop_passes=65),
    lambda p: p["metadata"]["recognition"].update(crop_pixels=vision.MAX_CROP_PIXELS+1),
    lambda p: p["metadata"]["recognition"].update(crop_passes=0, crop_pixels=0),
    lambda p: p["metadata"].pop("recognition"),
])
def test_candidate_and_runtime_metadata_protocol_is_strict(mutate):
    value = _with_candidates()
    mutate(value["pages"][0])
    with pytest.raises(V2Error):
        vision._decode_response(encoded(value), maximum=1)


def test_total_crop_budget_overflow_discards_all_pages():
    value = _with_candidates()
    page = value["pages"][0]
    page["metadata"]["recognition"].update(crop_passes=64, crop_pixels=vision.MAX_CROP_PIXELS)
    second = deepcopy(page)
    second["page"] = 2
    value["pages"].append(second)
    with pytest.raises(V2Error) as error:
        vision._decode_response(encoded(value), maximum=50)
    assert error.value.code == "VISION_OUTPUT_LIMIT"
