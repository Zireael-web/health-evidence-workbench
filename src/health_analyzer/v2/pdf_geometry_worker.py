"""Untrusted PDF/Poppler XML decoding only within the mandatory source sandbox."""
from pathlib import Path
import json
import math
import os
import resource
import re
import signal
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from health_analyzer.v2.pdf_geometry import PROTOCOL, MAX_INPUT, MAX_OUTPUT, MAX_TEXT, MAX_PAGES, MAX_WORDS
from health_analyzer.v2.common import V2Error, require
from health_analyzer.ingest.pypdf_subprocess import _run_bounded_process
from health_analyzer.ingest.registry import ExtractorFailure


def supervise_decoder(command: tuple[str, ...], content: bytes) -> bytes:
    """Keep Poppler in this decoder's owned group, including cancellation.

    The shared legacy supervisor always creates a new session. This fixed
    single-threaded worker adapts its process-local launch method for the one
    nested decoder only; host/global supervisors are never patched.
    """
    import health_analyzer.ingest.pypdf_subprocess as supervisor
    original_launch = supervisor.subprocess.Popen
    original_kill = supervisor._kill_process_group
    def launch(*args, **kwargs):
        kwargs["start_new_session"] = False
        return original_launch(*args, **kwargs)
    def kill_child(process):
        try:
            process.kill()
        except ProcessLookupError:
            pass
    supervisor.subprocess.Popen = launch
    supervisor._kill_process_group = kill_child
    try:
        return supervisor._run_bounded_process(command, content, timeout_seconds=23,
            max_output_bytes=MAX_OUTPUT, max_stderr_bytes=64*1024)
    except ExtractorFailure:
        # An inner failure must not leave nested decoder descendants running.
        # The source worker was launched as its own session/group leader.
        if os.getpgrp() == os.getpid():
            os.killpg(os.getpgrp(), signal.SIGKILL)
        raise
    finally:
        supervisor.subprocess.Popen = original_launch
        supervisor._kill_process_group = original_kill


def parse_bbox(xml: bytes) -> list[dict]:
    require(len(xml) <= MAX_OUTPUT, "PDF_GEOMETRY_OUTPUT_LIMIT", "Geometry XML exceeds bounds")
    # Poppler's fixed XHTML doctype never needs an external DTD. Reject entity
    # declarations explicitly; XML parsing remains inside the decoder sandbox.
    without_doctype = re.sub(rb'<!DOCTYPE\s+html\s+PUBLIC\s+"-//W3C//DTD XHTML 1.0 Transitional//EN"\s+"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"\s*>', b"", xml, count=1, flags=re.I)
    require(b"<!ENTITY" not in xml.upper() and b"<!DOCTYPE" not in without_doctype.upper(),
        "PDF_GEOMETRY_XML_UNSUPPORTED", "Unexpected XML declaration")
    try:
        tree = ET.fromstring(without_doctype)
    except ET.ParseError as exc:
        raise V2Error("PDF_GEOMETRY_XML_INVALID", "Invalid bounded geometry XML") from exc
    pages = []
    words_count = text_count = 0
    for element in tree.iter():
        if element.tag.rsplit("}", 1)[-1] != "page":
            continue
        require(len(pages) < MAX_PAGES, "PDF_GEOMETRY_PAGE_LIMIT", "PDF has more than 500 pages")
        width, height = float(element.get("width", "nan")), float(element.get("height", "nan"))
        require(all(math.isfinite(n) and 0 < n <= 100000 for n in (width, height)), "PDF_GEOMETRY_DIMENSION_LIMIT", "Invalid PDF viewport")
        blocks, lines = [], []
        for line in element.iter():
            if line.tag.rsplit("}", 1)[-1] != "line":
                continue
            tokens = []
            for word in line:
                if word.tag.rsplit("}", 1)[-1] != "word":
                    continue
                text = "".join(word.itertext())
                if not text:
                    continue
                words_count += 1
                text_count += len(text.encode("utf-8"))
                require(words_count <= MAX_WORDS and text_count <= MAX_TEXT and len(text) <= 8000,
                        "PDF_GEOMETRY_TEXT_LIMIT", "PDF word/text limits exceeded")
                x0, y0, x1, y1 = (float(word.get(k, "nan")) for k in ("xMin", "yMin", "xMax", "yMax"))
                require(all(math.isfinite(n) for n in (x0, y0, x1, y1)) and
                        0 <= x0 < x1 <= width + 1e-6 and 0 <= y0 < y1 <= height + 1e-6,
                        "PDF_GEOMETRY_OUTSIDE_VIEWPORT", "PDF text outside crop viewport requires explicit inspection")
                blocks.append({"text": text, "x": x0, "y": y0, "width": x1-x0, "height": y1-y0,
                               "confidence": None, "geometry_estimated": False})
                tokens.append(text)
            if tokens:
                lines.append(" ".join(tokens))
        pages.append({"page": len(pages)+1, "text": "\n".join(lines), "blocks": blocks,
            "width": width, "height": height, "source": "pdf_text",
            "metadata": {"provider": "poppler_bbox", "coordinate_space": "pdf_crop_viewport", "source_layer": "pdf_text"}})
    require(bool(pages), "PDF_GEOMETRY_EMPTY_DOCUMENT", "No bounded PDF pages returned")
    return pages


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (25, 25))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    try:
        content = sys.stdin.buffer.read(MAX_INPUT + 1)
        require(0 < len(content) <= MAX_INPUT and content[:1024].lstrip().startswith(b"%PDF-"),
                "PDF_GEOMETRY_INPUT_LIMIT", "Invalid bounded PDF input")
        require(len(sys.argv) == 2, "PDF_GEOMETRY_LAUNCH_INVALID", "Fixed trusted binary required")
        raw = supervise_decoder((sys.argv[1], "-bbox-layout", "-cropbox", "-enc", "UTF-8", "-remove-hyphens", "none", "-", "-"), content)
        value = {"protocol": PROTOCOL, "ok": True, "pages": parse_bbox(raw)}
    except V2Error as exc:
        value = {"protocol": PROTOCOL, "ok": False, "code": exc.code}
    except ExtractorFailure:
        value = {"protocol": PROTOCOL, "ok": False, "code": "PDF_GEOMETRY_DECODER_FAILED"}
    except (ValueError, OSError, MemoryError):
        value = {"protocol": PROTOCOL, "ok": False, "code": "PDF_GEOMETRY_INVALID"}
    output = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if len(output) > MAX_OUTPUT:
        output = json.dumps({"protocol": PROTOCOL, "ok": False, "code": "PDF_GEOMETRY_OUTPUT_LIMIT"}).encode()
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
