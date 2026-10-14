"""Pure validation for historical OCR payloads; local OCR is disabled.

Existing stored text, candidates and geometry remain readable without changing
or re-running recognition. The old launch and preparation entrypoints fail
before touching paths, creating scratch files, building or starting a process.
New visual transcriptions are supplied by the ChatGPT/Codex conversation.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import re

from .common import V2Error, require

PROTOCOL = "health-analyzer-vision/1"
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_BLOCKS = 30000
MAX_PDF_PAGES = 50
MAX_DIMENSION = 12000
MAX_PIXELS = 40_000_000
MAX_CANDIDATES = 3
MAX_CROP_PASSES_PER_PAGE = 64
MAX_TOTAL_CROP_PASSES = 256
MAX_CROP_PIXELS = 16_000_000
IMAGE_TIMEOUT_SECONDS = 45.0
PDF_TIMEOUT_SECONDS = 175.0
_CODE = re.compile(r"VISION_[A-Z0-9_]{1,100}\Z")


def _local_ocr_disabled() -> None:
    raise V2Error("LOCAL_OCR_DISABLED",
                  "Local OCR is disabled; use ChatGPT/Codex visual transcription")


def _bounded_run(command: tuple[str, ...], request: bytes, *, timeout: float,
                 max_output: int = MAX_OUTPUT_BYTES) -> bytes:
    """Compatibility entrypoint; never starts a process."""
    _local_ocr_disabled()


def _compile_trusted(command: tuple[str, ...], *, timeout: float = 90.0) -> None:
    """Compatibility entrypoint; never invokes a compiler or command."""
    _local_ocr_disabled()


def prepare_native_helper(scratch_dir: str | Path) -> Path:
    """Compatibility entrypoint; never creates or inspects native scratch."""
    _local_ocr_disabled()


def _validate_ancestry(path: Path) -> None:
    _local_ocr_disabled()


def _protected_directory(path: Path) -> None:
    _local_ocr_disabled()


def _validate_helper(helper: Path) -> None:
    _local_ocr_disabled()


def _command(helper_path: str | Path) -> tuple[str, ...]:
    _local_ocr_disabled()


def _extract(content: bytes, *, kind: str, helper_path: str | Path) -> tuple[list[dict], list[str]]:
    _local_ocr_disabled()


def extract_image(content: bytes, *, helper_path: str | Path) -> tuple[list[dict], list[str]]:
    """Compatibility entrypoint; never decodes or recognizes image bytes."""
    _local_ocr_disabled()


def extract_pdf_ocr(content: bytes, *, helper_path: str | Path) -> tuple[list[dict], list[str]]:
    """Compatibility entrypoint; never rasterizes or recognizes PDF bytes."""
    _local_ocr_disabled()


def transform_normalized_box(box: dict, rotation: int) -> dict[str, float]:
    """Inverse clockwise readable rotation, normalized top-left coordinates."""
    require(rotation in (0, 90, 180, 270), "VISION_PROTOCOL_ERROR", "Invalid orientation")
    x, y, width, height = (float(box[k]) for k in ("x", "y", "width", "height"))
    if rotation == 90:
        return {"x": y, "y": 1 - x - width, "width": height, "height": width}
    if rotation == 180:
        return {"x": 1 - x - width, "y": 1 - y - height, "width": width, "height": height}
    if rotation == 270:
        return {"x": 1 - y - height, "y": x, "width": height, "height": width}
    return {"x": x, "y": y, "width": width, "height": height}


def _finite_number(value: object) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _box(value: object, width: int, height: int) -> None:
    require(isinstance(value, dict) and all(key in value for key in ("x", "y", "width", "height")),
            "VISION_PROTOCOL_ERROR", "Invalid OCR geometry")
    require(all(_finite_number(value[key]) for key in ("x", "y", "width", "height")),
            "VISION_PROTOCOL_ERROR", "Non-finite OCR geometry")
    require(0 <= value["x"] <= width and 0 <= value["y"] <= height and
            0 <= value["width"] <= width and 0 <= value["height"] <= height and
            value["x"] + value["width"] <= width + 1e-6 and
            value["y"] + value["height"] <= height + 1e-6,
            "VISION_PROTOCOL_ERROR", "OCR geometry exceeds the source raster")


def _decode_response(content: bytes, *, maximum: int) -> list[dict]:
    require(type(content) is bytes and 0 < len(content) <= MAX_OUTPUT_BYTES,
            "VISION_OUTPUT_LIMIT", "OCR output exceeds its bound")
    try:
        response = json.loads(content)
    except (UnicodeError, ValueError) as exc:
        raise V2Error("VISION_PROTOCOL_ERROR", "OCR returned invalid JSON") from exc
    require(isinstance(response, dict) and response.get("protocol") == PROTOCOL and
            type(response.get("ok")) is bool, "VISION_PROTOCOL_ERROR", "OCR returned an invalid protocol")
    if not response["ok"]:
        require(set(response) == {"protocol", "ok", "code"} and isinstance(response["code"], str)
                and bool(_CODE.fullmatch(response["code"])), "VISION_PROTOCOL_ERROR", "Invalid OCR error")
        raise V2Error(response["code"], "Mandatory isolated OCR worker reported a failure")
    require(set(response) == {"protocol", "ok", "pages"} and isinstance(response["pages"], list)
            and 0 < len(response["pages"]) <= maximum, "VISION_PROTOCOL_ERROR", "Invalid OCR page count")
    total_text = 0
    total_blocks = 0
    total_crop_passes = 0
    total_crop_pixels = 0
    for number, page in enumerate(response["pages"], 1):
        require(isinstance(page, dict) and set(page) == {"page", "text", "blocks", "width", "height", "source", "metadata"}
                and type(page["page"]) is int and page["page"] == number and page["source"] == "vision_ocr",
                "VISION_PROTOCOL_ERROR", "Invalid OCR page")
        width, height = page["width"], page["height"]
        require(type(width) is int and type(height) is int and 0 < width <= MAX_DIMENSION and
                0 < height <= MAX_DIMENSION and width * height <= MAX_PIXELS,
                "VISION_PROTOCOL_ERROR", "Invalid OCR raster dimensions")
        require(isinstance(page["text"], str) and isinstance(page["blocks"], list),
                "VISION_PROTOCOL_ERROR", "Invalid OCR text/blocks")
        try:
            total_text += len(page["text"].encode("utf-8"))
        except UnicodeError as exc:
            raise V2Error("VISION_PROTOCOL_ERROR", "Invalid OCR text encoding") from exc
        total_blocks += len(page["blocks"])
        require(total_text <= MAX_TEXT_BYTES and total_blocks <= MAX_BLOCKS,
                "VISION_OUTPUT_LIMIT", "OCR text/block count exceeds its bound")
        metadata = page["metadata"]
        expected = {"orientation_degrees", "confidence", "readable", "issues", "readable_width", "readable_height",
                    "exif_orientation", "coordinate_space", "orientation_trials"}
        require(isinstance(metadata, dict) and expected <= set(metadata) <= expected | {"recognition"},
                "VISION_PROTOCOL_ERROR", "Invalid OCR quality metadata")
        if "recognition" in metadata:
            recognition = metadata["recognition"]
            require(isinstance(recognition, dict) and set(recognition) == {
                "revision", "supported_languages", "recognition_languages", "automatic_language_detection",
                "language_correction", "custom_words_count", "crop_passes", "crop_pixels"},
                "VISION_PROTOCOL_ERROR", "Invalid OCR recognition metadata")
            require(type(recognition["revision"]) is int and 1 <= recognition["revision"] <= 16 and
                    recognition["automatic_language_detection"] is False and recognition["language_correction"] is False and
                    type(recognition["custom_words_count"]) is int and 0 < recognition["custom_words_count"] <= 256,
                    "VISION_PROTOCOL_ERROR", "Invalid OCR recognition configuration")
            for key in ("supported_languages", "recognition_languages"):
                languages = recognition[key]
                require(isinstance(languages, list) and 0 < len(languages) <= 64 and
                        all(type(language) is str and bool(re.fullmatch(r"[a-z]{2,3}-[A-Za-z]{2,4}", language)) for language in languages) and
                        len(set(languages)) == len(languages), "VISION_PROTOCOL_ERROR", "Invalid OCR languages")
            require(set(recognition["recognition_languages"]) <= set(recognition["supported_languages"]) and
                    recognition["recognition_languages"] == [language for language in ("ru-RU", "en-US")
                                                              if language in recognition["supported_languages"]],
                    "VISION_PROTOCOL_ERROR", "OCR languages do not match supported Russian-first configuration")
            require(type(recognition["crop_passes"]) is int and 0 <= recognition["crop_passes"] <= MAX_CROP_PASSES_PER_PAGE and
                    type(recognition["crop_pixels"]) is int and 0 <= recognition["crop_pixels"] <= MAX_CROP_PIXELS and
                    (recognition["crop_passes"] == 0) == (recognition["crop_pixels"] == 0),
                    "VISION_PROTOCOL_ERROR", "Invalid OCR crop budget")
            total_crop_passes += recognition["crop_passes"]
            total_crop_pixels += recognition["crop_pixels"]
            require(total_crop_passes <= MAX_TOTAL_CROP_PASSES and total_crop_pixels <= MAX_CROP_PIXELS,
                    "VISION_OUTPUT_LIMIT", "OCR crop budget exceeds its bound")
        rotation = metadata["orientation_degrees"]
        require(type(rotation) is int and rotation in (0, 90, 180, 270) and
                _finite_number(metadata["confidence"]) and 0 <= metadata["confidence"] <= 1 and
                type(metadata["readable"]) is bool and type(metadata["exif_orientation"]) is int and
                1 <= metadata["exif_orientation"] <= 8 and
                metadata["coordinate_space"] == "original_raster_pixels_top_left",
                "VISION_PROTOCOL_ERROR", "Invalid OCR quality/orientation")
        rw, rh = ((width, height) if rotation % 180 == 0 else (height, width))
        require(type(metadata["readable_width"]) is int and type(metadata["readable_height"]) is int and
                (metadata["readable_width"], metadata["readable_height"]) == (rw, rh),
                "VISION_PROTOCOL_ERROR", "Invalid readable raster dimensions")
        require(isinstance(metadata["issues"], list) and len(metadata["issues"]) <= 10 and
                all(type(issue) is str and bool(re.fullmatch(r"[a-z_]{1,100}", issue)) for issue in metadata["issues"]),
                "VISION_PROTOCOL_ERROR", "Invalid OCR quality issues")
        trials = metadata["orientation_trials"]
        require(isinstance(trials, list) and len(trials) == 4, "VISION_PROTOCOL_ERROR", "Missing orientation trials")
        for trial, degree in zip(trials, (0, 90, 180, 270)):
            require(isinstance(trial, dict) and set(trial) == {"degrees", "confidence", "score", "characters"} and
                    type(trial["degrees"]) is int and trial["degrees"] == degree and
                    _finite_number(trial["confidence"]) and 0 <= trial["confidence"] <= 1 and
                    _finite_number(trial["score"]) and 0 <= trial["score"] <= MAX_TEXT_BYTES and
                    type(trial["characters"]) is int and 0 <= trial["characters"] <= MAX_TEXT_BYTES,
                    "VISION_PROTOCOL_ERROR", "Invalid orientation trial")
        for block in page["blocks"]:
            block_keys = {"text", "x", "y", "width", "height", "confidence", "readable_box", "geometry_estimated"}
            require(isinstance(block, dict) and block_keys <= set(block) <= block_keys | {"candidates"} and isinstance(block["text"], str) and
                    0 < len(block["text"]) <= 16384 and _finite_number(block["confidence"]) and
                    0 <= block["confidence"] <= 1 and type(block["geometry_estimated"]) is bool,
                    "VISION_PROTOCOL_ERROR", "Invalid OCR block")
            if "candidates" in block:
                candidates = block["candidates"]
                require(isinstance(candidates, list) and 0 < len(candidates) <= MAX_CANDIDATES,
                        "VISION_PROTOCOL_ERROR", "Invalid OCR candidate count")
                texts = set()
                for index, candidate in enumerate(candidates):
                    require(isinstance(candidate, dict) and set(candidate) == {"text", "confidence", "origin"} and
                            isinstance(candidate["text"], str) and 0 < len(candidate["text"]) <= 16384 and
                            candidate["text"] not in texts and _finite_number(candidate["confidence"]) and
                            0 <= candidate["confidence"] <= 1 and type(candidate["origin"]) is str and
                            candidate["origin"] in {"first_pass", "pixel_crop"},
                            "VISION_PROTOCOL_ERROR", "Invalid OCR candidate")
                    if index == 0:
                        require(candidate["text"] == block["text"] and candidate["confidence"] == block["confidence"] and
                                candidate["origin"] == "first_pass", "VISION_PROTOCOL_ERROR", "First OCR candidate must preserve raw text")
                    if candidate["origin"] == "pixel_crop":
                        require("recognition" in metadata and metadata["recognition"]["crop_passes"] > 0,
                                "VISION_PROTOCOL_ERROR", "Pixel candidate requires bounded crop metadata")
                    try:
                        total_text += len(candidate["text"].encode("utf-8"))
                    except UnicodeError as exc:
                        raise V2Error("VISION_PROTOCOL_ERROR", "Invalid OCR candidate encoding") from exc
                    require(total_text <= MAX_TEXT_BYTES, "VISION_OUTPUT_LIMIT", "OCR candidate text exceeds its bound")
                    texts.add(candidate["text"])
            _box(block, width, height)
            require(isinstance(block["readable_box"], dict) and set(block["readable_box"]) == {"x", "y", "width", "height"},
                    "VISION_PROTOCOL_ERROR", "Invalid readable OCR geometry")
            _box(block["readable_box"], rw, rh)
            normalized = {k: block["readable_box"][k] / (rw if k in {"x", "width"} else rh)
                          for k in ("x", "y", "width", "height")}
            original = transform_normalized_box(normalized, rotation)
            require(all(abs(block[k] - original[k] * (width if k in {"x", "width"} else height)) <= 1e-4
                        for k in original), "VISION_PROTOCOL_ERROR", "OCR orientation geometry mismatch")
        metadata["quality"] = ("unreadable" if not metadata["readable"] else
                               "low_confidence" if metadata["confidence"] < 0.65 else "readable")
    return response["pages"]
