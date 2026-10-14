"""Offline word geometry from a fixed local Poppler binary, always sandboxed."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import stat
import sys

from .common import V2Error, require

PROTOCOL = "health-analyzer-pdf-geometry/1"
MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 32 * 1024 * 1024
MAX_TEXT = 8 * 1024 * 1024
MAX_PAGES = 500
MAX_WORDS = 50000


def local_binary() -> Path | None:
    """Trusted bootstrap discovery only, never a source/caller command field."""
    if sys.platform != "darwin":
        return None
    candidate = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/poppler/poppler/bin/pdftotext"
    if not candidate.is_file() or candidate.is_symlink():
        return None
    for path in (candidate, *candidate.parents):
        info = path.lstat()
        if path.is_symlink() or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
            return None
    return candidate.resolve()


def extract_pdf_geometry(content: bytes) -> tuple[list[dict], list[str]] | None:
    binary = local_binary()
    if binary is None:
        return None
    require(type(content) is bytes and 0 < len(content) <= MAX_INPUT and content[:1024].lstrip().startswith(b"%PDF-"),
            "PDF_GEOMETRY_INPUT_LIMIT", "Geometry input requires bounded PDF bytes")
    sandbox = Path("/usr/bin/sandbox-exec")
    require(sandbox.is_file(), "PDF_GEOMETRY_SANDBOX_UNAVAILABLE", "Mandatory geometry sandbox unavailable")
    profile = Path(__file__).with_name("native") / "pdf-geometry.sb"
    params = {"CODE_ROOT": Path(__file__).resolve().parents[2], "PYTHON_ROOT": Path(sys.prefix).resolve(),
              "BASE_PYTHON_ROOT": Path(sys.base_prefix).resolve(), "PYTHON_EXEC": Path(sys.executable).resolve(),
              "GEOMETRY_EXEC": binary, "GEOMETRY_LIBS": binary.parent.parent / "lib",
              "GEOMETRY_SHARE": binary.parent.parent / "share"}
    command = [str(sandbox), "-f", str(profile)]
    for key, value in params.items():
        command += ["-D", f"{key}={value}"]
    command += [sys.executable, "-I", "-B", str(Path(__file__).with_name("pdf_geometry_worker.py")), str(binary)]
    from health_analyzer.ingest.pypdf_subprocess import _run_bounded_process
    from health_analyzer.ingest.registry import ExtractorFailure
    try:
        raw = _run_bounded_process(tuple(command), content, timeout_seconds=30,
                                   max_output_bytes=MAX_OUTPUT, max_stderr_bytes=64 * 1024)
    except ExtractorFailure as exc:
        raise V2Error("PDF_GEOMETRY_PROCESS_FAILED", "Mandatory isolated PDF geometry worker failed") from exc
    pages = decode_geometry(raw)
    return pages, ["Native PDF word boxes extracted locally in a mandatory no-network sandbox; PDF text layer is not a visual verification",
                   "Word geometry uses the PDF crop viewport; source text and clinical fields remain unreviewed proposals",
                   "Darwin has no hard address-space bound; byte, page, word, text, CPU, wall-time and output bounds apply"]


def decode_geometry(raw: bytes) -> list[dict]:
    require(0 < len(raw) <= MAX_OUTPUT, "PDF_GEOMETRY_OUTPUT_LIMIT", "Geometry response exceeds bounds")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise V2Error("PDF_GEOMETRY_PROTOCOL_ERROR", "Invalid geometry response") from exc
    require(isinstance(value, dict) and value.get("protocol") == PROTOCOL and type(value.get("ok")) is bool,
            "PDF_GEOMETRY_PROTOCOL_ERROR", "Invalid geometry protocol")
    if not value["ok"]:
        code = value.get("code")
        require(set(value) == {"protocol", "ok", "code"} and isinstance(code, str) and
                code.startswith("PDF_GEOMETRY_") and code.replace("_", "").isalnum(),
                "PDF_GEOMETRY_PROTOCOL_ERROR", "Invalid geometry failure")
        raise V2Error(code, "Isolated PDF geometry worker rejected the document")
    require(set(value) == {"protocol", "ok", "pages"} and isinstance(value["pages"], list) and
            0 < len(value["pages"]) <= MAX_PAGES, "PDF_GEOMETRY_PROTOCOL_ERROR", "Invalid geometry pages")
    total_words = total_text = total_block_text = 0
    for number, page in enumerate(value["pages"], 1):
        require(isinstance(page, dict) and set(page) == {"page", "text", "blocks", "width", "height", "source", "metadata"}
                and page["page"] == number and type(page["page"]) is int and page["source"] == "pdf_text",
                "PDF_GEOMETRY_PROTOCOL_ERROR", "Invalid geometry page")
        w, h = page["width"], page["height"]
        require(all(type(n) in (int, float) and math.isfinite(n) and 0 < n <= 100000 for n in (w, h)) and
                isinstance(page["text"], str) and isinstance(page["blocks"], list),
                "PDF_GEOMETRY_PROTOCOL_ERROR", "Invalid geometry dimensions/text")
        require(page["metadata"] == {"provider": "poppler_bbox", "coordinate_space": "pdf_crop_viewport", "source_layer": "pdf_text"},
                "PDF_GEOMETRY_PROTOCOL_ERROR", "Unexpected geometry metadata")
        total_words += len(page["blocks"])
        total_text += len(page["text"].encode("utf-8"))
        require(total_words <= MAX_WORDS and total_text <= MAX_TEXT, "PDF_GEOMETRY_OUTPUT_LIMIT", "Geometry text/words exceed bounds")
        for block in page["blocks"]:
            require(isinstance(block, dict) and set(block) == {"text", "x", "y", "width", "height", "confidence", "geometry_estimated"}
                    and isinstance(block["text"], str) and 0 < len(block["text"]) <= 8000 and
                    block["confidence"] is None and block["geometry_estimated"] is False,
                    "PDF_GEOMETRY_PROTOCOL_ERROR", "Invalid PDF word")
            total_block_text += len(block["text"].encode("utf-8"))
            require(total_block_text <= MAX_TEXT, "PDF_GEOMETRY_OUTPUT_LIMIT", "PDF word text exceeds document bound")
            x, y, bw, bh = (block[k] for k in ("x", "y", "width", "height"))
            require(all(type(n) in (int, float) and math.isfinite(n) for n in (x, y, bw, bh)) and
                    x >= 0 and y >= 0 and bw > 0 and bh > 0 and x + bw <= w + 1e-6 and y + bh <= h + 1e-6,
                    "PDF_GEOMETRY_PROTOCOL_ERROR", "PDF word outside crop viewport")
    return value["pages"]
