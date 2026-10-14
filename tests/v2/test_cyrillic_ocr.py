"""Historical Cyrillic OCR payloads remain unchanged by pure validation."""
import json

import pytest

from health_analyzer.v2 import vision


@pytest.mark.parametrize("raw,alternative", [
    ("1019/л", "10^9/л"), ("10⁹/л", "10^9/л"), ("µg/L", "μg/L"),
    ("ммоль/л", "mmol/L"), ("2,50", "2.50"),
])
def test_historical_source_tokens_and_candidates_are_preserved(raw, alternative):
    value = {"protocol": vision.PROTOCOL, "ok": True, "pages": [{
        "page": 1, "text": "СИНТЕТИЧЕСКИЙ " + raw, "width": 100, "height": 100,
        "source": "vision_ocr", "blocks": [{"text": raw, "x": 10, "y": 20,
            "width": 30, "height": 10, "confidence": 0.9,
            "readable_box": {"x": 10, "y": 20, "width": 30, "height": 10},
            "geometry_estimated": False,
            "candidates": [{"text": raw, "confidence": 0.9, "origin": "first_pass"},
                           {"text": alternative, "confidence": 1.0, "origin": "pixel_crop"}]}],
        "metadata": {"orientation_degrees": 0, "confidence": 0.9,
            "readable": True, "issues": [], "readable_width": 100,
            "readable_height": 100, "exif_orientation": 1,
            "coordinate_space": "original_raster_pixels_top_left",
            "orientation_trials": [{"degrees": d, "confidence": 0.9 if d == 0 else 0.1,
                "score": 10.0 if d == 0 else 1.0, "characters": 13 if d == 0 else 2}
                for d in (0, 90, 180, 270)],
            "recognition": {"revision": 3, "supported_languages": ["en-US", "ru-RU"],
                "recognition_languages": ["ru-RU", "en-US"], "automatic_language_detection": False,
                "language_correction": False, "custom_words_count": 45, "crop_passes": 1, "crop_pixels": 1000}}}]}
    encoded = json.dumps(value, ensure_ascii=False).encode()
    decoded = vision._decode_response(encoded, maximum=1)[0]
    assert decoded["text"] == "СИНТЕТИЧЕСКИЙ " + raw
    assert decoded["blocks"][0]["text"] == raw
    assert decoded["blocks"][0]["candidates"] == value["pages"][0]["blocks"][0]["candidates"]
    assert json.dumps(value, ensure_ascii=False).encode() == encoded
