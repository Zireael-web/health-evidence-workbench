"""Independent review regressions; every source and subprocess is synthetic."""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import signal
import sys
import time

import pytest

from health_analyzer.ingest.pypdf_subprocess import _run_bounded_process
from health_analyzer.ingest.registry import ExtractorFailure
from health_analyzer.v2.common import V2Error
from health_analyzer.v2.layout import propose_lab_rows
from health_analyzer.v2.ocr_review import annotate_ocr_rows
from health_analyzer.v2.pdf_geometry import PROTOCOL, decode_geometry
from health_analyzer.v2.pdf_geometry_worker import parse_bbox
from health_analyzer.v2.unit_text import inspect_unit


VERSION = {"version_id": "ver_synthetic_independent_review", "source_sha256": "d" * 64}


def _fixed_line(cells):
    return "".join(str(cell).ljust(width) for cell, width in zip(cells, [36, 20, 16, 28])).rstrip()


def test_new_classic_section_metadata_does_not_inherit_first_section_date_or_method():
    header = _fixed_line(["Test", "Result", "Units", "Reference range"])
    text = "\n".join([
        "Collected: 11.10.2026", "Method: Synthetic first section", header,
        _fixed_line(["Synthetic A", "1", "g/L", "0-4"]),
        "Reported: 12.10.2026", header,
        _fixed_line(["Synthetic B", "2", "ng/L", "0-4"]),
    ])
    output = propose_lab_rows([{"page": 1, "text": text, "blocks": [], "source": "pdf_text"}], VERSION)
    first, second = output["rows"]
    assert first["clinical_time"]["value"] == "2026-10-11"
    assert second["clinical_time"] == {
        "raw": "12.10.2026", "role": "reported", "precision": "date", "value": "2026-10-12",
    }
    assert second["method"] is None
    assert second["field_anchors"]["clinical_time"]["locator"]["line"] == 5


def test_geometry_decoder_child_stops_when_outer_worker_times_out(tmp_path):
    """Exercise actual nested transport with a fake decoder; no PDF is parsed.

    The fake child writes only a synthetic heartbeat and is always terminated
    in finally. This verifies process cleanup, not the native Seatbelt gate.
    """
    pid_file = tmp_path / "synthetic-child.pid"
    heartbeat_file = tmp_path / "synthetic-heartbeat.txt"
    child_code = (
        "import time\nfrom pathlib import Path\n"
        f"p=Path({str(heartbeat_file)!r})\n"
        "for i in range(300):\n p.write_text(str(i))\n time.sleep(.03)\n"
    )
    source_root = str(Path(__file__).resolve().parents[2] / "src")
    worker_code = f"""
import sys, subprocess
from pathlib import Path
sys.path.insert(0, {source_root!r})
from health_analyzer.v2 import pdf_geometry_worker
import health_analyzer.ingest.pypdf_subprocess as supervisor
from health_analyzer.ingest.pypdf_subprocess import _run_bounded_process
original_popen = subprocess.Popen
def tracked_popen(*args, **kwargs):
    process = original_popen(*args, **kwargs)
    Path({str(pid_file)!r}).write_text(str(process.pid))
    return process
subprocess.Popen = tracked_popen
def synthetic_decoder(command, request, **limits):
    return _run_bounded_process((sys.executable, '-B', '-c', {child_code!r}), request, **limits)
pdf_geometry_worker._run_bounded_process = synthetic_decoder
supervisor._run_bounded_process = synthetic_decoder
sys.argv = ['synthetic-worker', 'fixed-synthetic-decoder']
pdf_geometry_worker.main()
"""
    child_pid = None
    try:
        with pytest.raises(ExtractorFailure) as error:
            _run_bounded_process((sys.executable, "-B", "-c", worker_code), b"%PDF-1.4 synthetic",
                                 timeout_seconds=.7, max_output_bytes=1024, max_stderr_bytes=1024)
        assert error.value.code == "pdf_worker_timeout"
        assert pid_file.exists(), "Synthetic decoder must start before the timeout"
        child_pid = int(pid_file.read_text())
        assert heartbeat_file.exists()
        time.sleep(.12)
        stopped_value = heartbeat_file.read_text()
        time.sleep(.2)
        assert heartbeat_file.read_text() == stopped_value, "Outer worker timeout left its decoder child running"
    finally:
        if child_pid is None and pid_file.exists():
            child_pid = int(pid_file.read_text())
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize("raw", ["Mmol/L", "MG/L", "Ммоль/л", "мКмоль/л", "109/л", "10⁻³/л"])
def test_prefix_case_and_missing_exponent_are_not_silently_repaired(raw):
    value = inspect_unit(raw)
    assert value["raw"] == raw
    assert value["unit_code"] is None


def test_pdf_decoder_keeps_original_word_boxes_and_rejects_nonfinite_dimension():
    xml = b'<doc><page width="600" height="800"><line><word xMin="1" yMin="2" xMax="8" yMax="9">4,20</word></line></page></doc>'
    pages = parse_bbox(xml)
    decoded = decode_geometry(json.dumps({"protocol": PROTOCOL, "ok": True, "pages": pages}).encode())
    assert decoded[0]["blocks"][0] == {
        "text": "4,20", "x": 1.0, "y": 2.0, "width": 7.0, "height": 7.0,
        "confidence": None, "geometry_estimated": False,
    }
    with pytest.raises(V2Error):
        parse_bbox(xml.replace(b'width="600"', b'width="inf"'))


def test_geometry_page_cap_rejects_entire_document(monkeypatch):
    monkeypatch.setattr("health_analyzer.v2.pdf_geometry_worker.MAX_PAGES", 1)
    page = b'<page width="600" height="800"><line><word xMin="1" yMin="2" xMax="8" yMax="9">1</word></line></page>'
    with pytest.raises(V2Error) as error:
        parse_bbox(b"<doc>" + page + page + b"</doc>")
    assert error.value.code == "PDF_GEOMETRY_PAGE_LIMIT"


def test_bridge_native_word_cap_is_document_wide_not_reset_per_page(monkeypatch):
    from health_analyzer.v2 import pdf_bridge
    xml = b'<doc><page width="600" height="800"><line><word xMin="1" yMin="2" xMax="8" yMax="9">1</word></line></page></doc>'
    first = parse_bbox(xml)[0]
    second = json.loads(json.dumps(first))
    second["page"] = 2
    monkeypatch.setattr("health_analyzer.v2.pdf_geometry.MAX_WORDS", 1)
    with pdf_bridge.PdfBridgeBootstrap(lambda content: ([first, second], [])) as bridge:
        connection = pdf_bridge._PdfRuntimeClient(*(os.dup(fd) for fd in bridge.client_fds))
        try:
            with pytest.raises(V2Error) as error:
                connection.extract(b"%PDF-1.4 synthetic")
            assert error.value.code == "PDF_BRIDGE_PROTOCOL_ERROR"
        finally:
            connection.close()


def test_geometry_decoder_counts_word_text_even_when_page_text_omits_it(monkeypatch):
    xml = b'<doc><page width="600" height="800"><line><word xMin="1" yMin="2" xMax="8" yMax="9">1234</word></line></page></doc>'
    pages = parse_bbox(xml)
    pages[0]["text"] = ""
    monkeypatch.setattr("health_analyzer.v2.pdf_geometry.MAX_TEXT", 3)
    with pytest.raises(V2Error) as error:
        decode_geometry(json.dumps({"protocol": PROTOCOL, "ok": True, "pages": pages}).encode())
    assert error.value.code == "PDF_GEOMETRY_OUTPUT_LIMIT"


def test_bridge_rejects_duplicate_geometry_page_ids():
    from health_analyzer.v2 import pdf_bridge
    xml = b'<doc><page width="600" height="800"><line><word xMin="1" yMin="2" xMax="8" yMax="9">1</word></line></page></doc>'
    page = parse_bbox(xml)[0]
    with pdf_bridge.PdfBridgeBootstrap(lambda content: ([page, page], [])) as bridge:
        connection = pdf_bridge._PdfRuntimeClient(*(os.dup(fd) for fd in bridge.client_fds))
        try:
            with pytest.raises(V2Error) as error:
                connection.extract(b"%PDF-1.4 synthetic")
            assert error.value.code == "PDF_BRIDGE_PROTOCOL_ERROR"
        finally:
            connection.close()


def test_bridge_ocr_candidate_text_cap_is_document_wide(monkeypatch):
    from health_analyzer.v2 import pdf_bridge
    metadata = {"orientation_degrees": 0, "confidence": .99, "readable": True, "issues": [],
                "readable_width": 100, "readable_height": 100, "exif_orientation": 1,
                "coordinate_space": "original_raster_pixels_top_left",
                "orientation_trials": [{"degrees": d, "confidence": .99, "score": 1, "characters": 1}
                                       for d in (0, 90, 180, 270)]}
    box = {"x": 1, "y": 2, "width": 7, "height": 7}
    block = {"text": "u", **box, "confidence": .99, "readable_box": box, "geometry_estimated": False,
             "candidates": [{"text": "u", "confidence": .99, "origin": "first_pass"},
                            {"text": "ng/mL", "confidence": .98, "origin": "first_pass"}]}
    first = {"page": 1, "text": "u", "blocks": [block], "width": 100, "height": 100,
             "source": "vision_ocr", "metadata": metadata}
    second = json.loads(json.dumps(first))
    second["page"] = 2
    monkeypatch.setattr("health_analyzer.v2.vision.MAX_TEXT_BYTES", 10)
    with pdf_bridge.PdfBridgeBootstrap(lambda content: ([first, second], [])) as bridge:
        connection = pdf_bridge._PdfRuntimeClient(*(os.dup(fd) for fd in bridge.client_fds))
        try:
            with pytest.raises(V2Error) as error:
                connection.extract(b"%PDF-1.4 synthetic")
            assert error.value.code == "PDF_BRIDGE_PROTOCOL_ERROR"
        finally:
            connection.close()


def _unit_candidate_page(primary, competing):
    blocks = [{"text": "Collected: 11.10.2026", "x": 10, "y": 1, "width": 220, "height": 12}]
    for index, cells in enumerate([
        ["Test", "Result", "Units", "Reference range"],
        ["Synthetic A", "4,20", primary, "0-8"],
    ]):
        for column, value in enumerate(cells):
            block = {"text": value, "x": [10, 230, 350, 470][column], "y": 40 + index*40,
                     "width": 130 if column in {0, 3} else 80, "height": 20, "confidence": .99}
            if index == 1 and column == 2:
                block["candidates"] = [
                    {"text": primary, "confidence": .99, "origin": "first_pass"},
                    {"text": competing, "confidence": .98, "origin": "first_pass"},
                ]
            blocks.append(block)
    return {"page": 1, "text": "", "blocks": blocks, "width": 700, "height": 200,
            "source": "vision_ocr", "metadata": {}}


def test_ocr_unit_prefix_conflict_retains_source_numeric_and_unit_glyphs():
    page = _unit_candidate_page("mg/L", "µg/L")
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    row = output["rows"][0]
    source_anchor = json.loads(json.dumps(row["field_anchors"]["unit_raw"]))
    issues = annotate_ocr_rows([row], [page])
    assert row["result"] == {"kind": "numeric_exact", "raw": "4,20", "decimal": "4.20"}
    assert row["unit_raw"] == "mg/L" and row["unit_code"] is None
    assert row["field_anchors"]["unit_raw"] == source_anchor
    assert row["field_status"]["unit_raw"] == "ambiguous"
    assert "OCR_UNIT_CANDIDATES_CONFLICT" in issues[0]["reason_codes"]


def test_equivalent_micro_glyph_candidate_remains_an_explicit_proposed_code():
    page = _unit_candidate_page("μg/L", "µg/L")
    row = propose_lab_rows([page], VERSION, locator_kind="image")["rows"][0]
    issues = annotate_ocr_rows([row], [page])
    assert row["unit_raw"] == "μg/L"
    assert row["unit_code"] == "ug/L"
    assert row["field_status"]["unit_code"] == "proposed"
    assert row["field_anchors"]["unit_raw"]["excerpt"] == "μg/L"
    assert issues[0]["reason_codes"] == ["OCR_UNIT_EQUIVALENT_NOTATION_ALTERNATIVES"]


def test_ocr_unit_candidates_do_not_leak_to_adjacent_source_row():
    page = _unit_candidate_page("mg/L", "µg/L")
    for column, value in enumerate(["Synthetic B", "5.10", "ng/L", "0-8"]):
        page["blocks"].append({"text": value, "x": [10, 230, 350, 470][column], "y": 120,
                               "width": 130 if column in {0, 3} else 80, "height": 20, "confidence": .99})
    first, second = propose_lab_rows([page], VERSION, locator_kind="image")["rows"]
    issues = annotate_ocr_rows([first, second], [page])
    assert first["field_status"]["unit_raw"] == "ambiguous"
    assert second["unit_raw"] == "ng/L" and second["field_status"]["unit_raw"] == "proposed"
    assert second["result"]["raw"] == "5.10"
    assert all(issue["proposed_row"]["analyte_raw"] == "Synthetic A" for issue in issues)


def test_ocr_hypothesis_partitions_keep_all_raw_text_and_result_source_association():
    from health_analyzer.v2.import_issues import validate_issue
    page = _unit_candidate_page("mg/L", "µg/L")
    source_unit = next(block for block in page["blocks"] if block["text"] == "mg/L")
    source_unit.pop("candidates")
    expected = {f"synthetic-reading-{index}" for index in range(20)}
    for index, candidate_text in enumerate(sorted(expected)):
        page["blocks"].append({"text": "mg/L", "x": 350, "y": 110 + index*12,
                               "width": 80, "height": 10, "confidence": .99,
                               "candidates": [{"text": "mg/L", "confidence": .99, "origin": "first_pass"},
                                              {"text": candidate_text, "confidence": .98, "origin": "first_pass"}]})
    page["height"] = 500
    row = propose_lab_rows([page], VERSION, locator_kind="image")["rows"][0]
    raw_unit = row["unit_raw"]
    result_anchor = json.loads(json.dumps(row["field_anchors"]["result"]))
    issues = annotate_ocr_rows([row], [page])
    assert len(issues) == 2 and [len(issue["alternatives"]) for issue in issues] == [16, 4]
    assert {a["text"] for issue in issues for a in issue["alternatives"]} == expected
    assert row["unit_raw"] == raw_unit and row["field_anchors"]["result"] == result_anchor
    for issue in issues:
        validate_issue(issue, VERSION)
        assert issue["proposed_row"]["field_anchors"]["result"] == result_anchor
        assert next(cell for cell in issue["raw_cells"] if cell["role"] == "unit_raw")["text"] == raw_unit
        assert next(cell for cell in issue["raw_cells"] if cell["role"] == "result")["anchors"] == [result_anchor]
        assert all(alternative["source_anchors"] for alternative in issue["alternatives"])


def test_ocr_unit_conflict_requires_correction_and_preserves_anchor_and_idempotency(tmp_path):
    from health_analyzer.v2.common import SignedStore
    from health_analyzer.v2.records import RecordsService
    store = SignedStore(tmp_path / "synthetic-review.sqlite3", b"q"*32, "private-data")
    try:
        records = RecordsService(store)
        records.register_subject("demo", "Synthetic profile")
        version = records.register_document("demo", "d"*64, "image/png", 123)
        page = _unit_candidate_page("mg/L", "µg/L")
        output = propose_lab_rows([page], version, locator_kind="image")
        annotate_ocr_rows(output["rows"], [page])
        records.submit_extraction("demo", version["version_id"], output["rows"], output["coverage"])
        preview = records.prepare_review("demo", version["version_id"])
        draft = preview["rows"][0]
        with pytest.raises(V2Error) as error:
            records.commit_review("demo", preview["snapshot_id"], preview["snapshot_sha256"],
                                  [{"draft_id": draft["draft_id"], "action": "confirm"}])
        assert error.value.code == "unresolved_field"
        assert records.query_history("demo")["current"] == []
        evidence = {"snapshot_id": preview["snapshot_id"], "snapshot_sha256": preview["snapshot_sha256"],
                    "decision_excerpt": "Synthetic explicit unit correction confirmation", "origin": "user_message",
                    "attested_by": "synthetic_review", "ref_availability": "not_provided_by_host", "message_ref": None}
        decisions = [{"draft_id": draft["draft_id"], "action": "correct_and_confirm",
                      "patch": {"unit_raw": "µg/L"}, "reason": "Synthetic unit source review"}]
        first = records.commit_review("demo", preview["snapshot_id"], preview["snapshot_sha256"], decisions,
                                      evidence, idempotency_key="synthetic-unit-correction")
        repeated = records.commit_review("demo", preview["snapshot_id"], preview["snapshot_sha256"], decisions,
                                         evidence, idempotency_key="synthetic-unit-correction")
        assert repeated == first
        revision = store.get("observation_revision", first["revision_ids"][0], "demo")
        assert revision["row"]["unit_raw"] == "µg/L"
        assert revision["row"]["field_anchors"]["unit_raw"]["excerpt"] == "mg/L"
        assert len(store.list("observation_revision", "demo")) == 1
    finally:
        store.close()


@pytest.mark.parametrize("untyped", [False, True])
def test_oversized_ocr_hypothesis_issue_rolls_back_entire_import_batch(tmp_path, untyped):
    from types import SimpleNamespace
    from health_analyzer.v2.common import SignedStore
    from health_analyzer.v2.ingest import ImportService
    from health_analyzer.v2.records import RecordsService
    archive = tmp_path / "synthetic-archive"
    archive.mkdir()
    first = b"\x89PNG\r\n\x1a\nsynthetic first"
    second = b"\x89PNG\r\n\x1a\nsynthetic second"
    (archive / "first.png").write_bytes(first)
    (archive / "second.png").write_bytes(second)
    good_page = _unit_candidate_page("mg/L", "mg/L")
    next(block for block in good_page["blocks"] if block["text"] == "mg/L").pop("candidates")
    bad_page = _unit_candidate_page("mg/L", "Ω"*16384)
    if untyped:
        block = {"text": "Synthetic untyped source", "x": 12, "y": 24, "width": 160, "height": 18, "confidence": .99,
                 "candidates": [{"text": "Synthetic untyped source", "confidence": .99, "origin": "first_pass"},
                                {"text": "Ω"*16384, "confidence": .98, "origin": "first_pass"},
                                {"text": "Ψ"*16384, "confidence": .97, "origin": "first_pass"}]}
        bad_page = {"page": 1, "text": block["text"], "blocks": [block], "width": 700, "height": 200,
                    "source": "vision_ocr", "metadata": {}}
    store = SignedStore(tmp_path / "synthetic-state" / "review.sqlite3", b"j"*32, "private-data")
    try:
        records = RecordsService(store)
        config = SimpleNamespace(archive_roots={"demo": {"path": archive, "subject_id": "demo"}})
        imports = ImportService(config, records,
            image_extractor=lambda content: ([good_page if content == first else bad_page], ["Synthetic injected OCR only"]))
        with pytest.raises(V2Error) as error:
            imports.prepare_import("demo", [{"root_id": "demo", "relative_path": "first.png"},
                                            {"root_id": "demo", "relative_path": "second.png"}])
        assert error.value.code == "ISSUE_LIMIT"
        for kind in ("document_version", "extraction_run", "observation_draft", "import_issue"):
            assert store.list(kind, "demo") == [], "A hard OCR issue cap cannot persist the earlier valid batch item"
        assert (archive / "first.png").read_bytes() == first
        assert (archive / "second.png").read_bytes() == second
    finally:
        store.close()


def test_actual_geometry_profile_denies_network_and_other_file_access(tmp_path):
    from health_analyzer.v2 import pdf_geometry
    if os.environ.get("HEALTH_ANALYZER_RUN_NATIVE_GEOMETRY") != "1" or pdf_geometry.local_binary() is None:
        pytest.skip("opt-in actual bundled offline geometry sandbox deny canary")
    forbidden = tmp_path / "synthetic-protected-canary.txt"
    forbidden.write_text("Synthetic protected canary")
    forbidden_write = tmp_path / "synthetic-forbidden-write.txt"
    probe = f"""
import errno, json, os, socket
def denied(fn):
    try:
        fn()
    except OSError as exc:
        return exc.errno in (errno.EPERM, errno.EACCES)
    return False
def read_other_file():
    with open({str(forbidden)!r}, 'rb') as stream:
        stream.read(1)
def write_other_file():
    with open({str(forbidden_write)!r}, 'wb') as stream:
        stream.write(b'x')
def create_local_network_endpoint():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', 0))
    finally:
        sock.close()
print(json.dumps({{'file_read_denied': denied(read_other_file),
                  'file_write_denied': denied(write_other_file),
                  'network_denied': denied(create_local_network_endpoint)}}))
"""
    binary = pdf_geometry.local_binary()
    params = {"CODE_ROOT": Path(pdf_geometry.__file__).resolve().parents[2],
              "PYTHON_ROOT": Path(sys.prefix).resolve(), "BASE_PYTHON_ROOT": Path(sys.base_prefix).resolve(),
              "PYTHON_EXEC": Path(sys.executable).resolve(), "GEOMETRY_EXEC": binary,
              "GEOMETRY_LIBS": binary.parent.parent / "lib", "GEOMETRY_SHARE": binary.parent.parent / "share"}
    command = ["/usr/bin/sandbox-exec", "-f", str(Path(pdf_geometry.__file__).with_name("native") / "pdf-geometry.sb")]
    for key, value in params.items():
        command.extend(["-D", f"{key}={value}"])
    command.extend([sys.executable, "-I", "-B", "-c", probe])
    raw = _run_bounded_process(tuple(command), b"synthetic canary", timeout_seconds=3,
                               max_output_bytes=1024, max_stderr_bytes=1024)
    assert json.loads(raw) == {"file_read_denied": True, "file_write_denied": True, "network_denied": True}
    assert not forbidden_write.exists()


@pytest.mark.parametrize("name,suffix,wrapped", [
    ("Synthetic Marker H,", "%", True),
    ("Synthetic Marker H,", "‰", True),
    ("Synthetic Marker H", "%", False),
    ("Synthetic Marker H,", "% extra", False),
    ("Synthetic Marker H,", "Synthetic Missing", False),
])
def test_literal_percent_wrap_requires_trailing_comma_and_single_visible_symbol(name, suffix, wrapped):
    page = {"page": 1, "source": "pdf_text", "blocks": [], "text": "\n".join([
        _fixed_line(["Test", "Result", "Units", "Reference range"]),
        _fixed_line([name, "2,00", "%", "0-4"]), suffix,
        _fixed_line(["Synthetic B", "3", "g/L", "0-4"]),
    ])}
    output = propose_lab_rows([page], VERSION)
    first, second = output["rows"]
    assert first["analyte_raw"] == name + (" " + suffix if wrapped else "")
    assert second["analyte_raw"] == "Synthetic B"
    assert first["unit_raw"] == "%"
    assert first["result"] == {"kind": "numeric_exact", "raw": "2,00", "decimal": "2.00"}
    anchors = first["field_anchors"]["analyte_raw"]
    if wrapped:
        assert [anchor["locator"]["line"] for anchor in anchors] == [2, 3]
        assert [anchor["excerpt"] for anchor in anchors] == [name, suffix]
    else:
        assert anchors["locator"]["line"] == 2
        assert any("MISSING_RESULT" in issue["reason_codes"] for issue in output["issues"])


@contextmanager
def _synthetic_ocr_import(tmp_path, page):
    from types import SimpleNamespace
    from health_analyzer.v2.common import SignedStore
    from health_analyzer.v2.ingest import ImportService
    from health_analyzer.v2.records import RecordsService
    archive = tmp_path / "synthetic-ocr-archive"
    archive.mkdir()
    (archive / "source.png").write_bytes(b"\x89PNG\r\n\x1a\nsynthetic injected OCR source")
    store = SignedStore(tmp_path / "synthetic-ocr-state" / "review.sqlite3", b"u"*32, "private-data")
    try:
        records = RecordsService(store)
        config = SimpleNamespace(archive_roots={"demo": {"path": archive, "subject_id": "demo"}})
        imports = ImportService(config, records, image_extractor=lambda content: ([page], ["Synthetic injected OCR only"]))
        document = imports.prepare_import("demo", [{"root_id": "demo", "relative_path": "source.png"}])["documents"][0]
        yield records, imports, document
    finally:
        store.close()


@pytest.mark.parametrize("unresolved", ["missing_result", "unknown_header"])
def test_untyped_ocr_block_readings_and_receipt_survive_import_with_actual_source_box(tmp_path, unresolved):
    if unresolved == "missing_result":
        page = _unit_candidate_page("mg/L", "µg/L")
        page["blocks"] = [block for block in page["blocks"] if block["text"] != "4,20"]
        block = next(block for block in page["blocks"] if block["text"] == "mg/L")
    else:
        block = {"text": "Synthetic OCR source", "x": 12, "y": 24, "width": 160, "height": 18, "confidence": .99,
                 "candidates": [{"text": "Synthetic OCR source", "confidence": .99, "origin": "first_pass"},
                                {"text": "5ynthetic OCR source", "confidence": .98, "origin": "first_pass"}]}
        page = {"page": 1, "text": block["text"], "blocks": [block], "width": 700, "height": 200,
                "source": "vision_ocr", "metadata": {}}
    receipt = {"revision": 3, "supported_languages": ["ru-RU", "en-US"], "recognition_languages": ["ru-RU", "en-US"],
               "automatic_language_detection": False, "language_correction": False, "custom_words_count": 48,
               "crop_passes": 0, "crop_pixels": 0}
    page["metadata"]["recognition"] = receipt
    with _synthetic_ocr_import(tmp_path, page) as (records, imports, document):
        assert document["draft_ids"] == []
        issues = imports.issues.list("demo", document["version_id"], limit=100)["issues"]
        source = next(issue["source"] for issue in issues if "UNMAPPED_OCR_CANDIDATES" in issue["source"]["reason_codes"])
        assert source["proposed_row"] is None and source["raw_text"] == block["text"]
        saved = [alternative for alternative in source["alternatives"] if alternative["kind"] == "source_ocr_candidate"]
        assert [{key: item[key] for key in ("text", "confidence", "origin")} for item in saved] == block["candidates"]
        assert next(item for item in source["alternatives"] if item["kind"] == "ocr_recognition_receipt") == {
            "kind": "ocr_recognition_receipt", **receipt,
        }
        anchor = source["raw_cells"][0]["anchors"][0]
        version = records._version("demo", document["version_id"])
        assert anchor["version_id"] == version["version_id"] and anchor["source_sha256"] == version["source_sha256"]
        assert anchor["excerpt"] == block["text"] and anchor["inherited"] is False
        assert anchor["locator"]["kind"] == "image" and anchor["locator"]["page"] == 1
        assert anchor["locator"]["region"] == pytest.approx([
            block["x"]/page["width"], block["y"]/page["height"],
            (block["x"]+block["width"])/page["width"], (block["y"]+block["height"])/page["height"],
        ])
        assert all(item["source_anchors"] == [anchor] for item in saved)
        assert records.query_history("demo")["current"] == []


@pytest.mark.parametrize("field", ["reference_intervals", "lab_flag_raw"])
def test_additional_typed_ocr_field_readings_are_preserved_and_block_confirmation(tmp_path, field):
    page = _unit_candidate_page("mg/L", "mg/L")
    next(block for block in page["blocks"] if block["text"] == "mg/L").pop("candidates")
    if field == "reference_intervals":
        block = next(block for block in page["blocks"] if block["text"] == "0-8")
        competing = "0-4"
    else:
        page["blocks"].append({"text": "Flag", "x": 620, "y": 40, "width": 70, "height": 20, "confidence": .99})
        block = {"text": "H", "x": 620, "y": 80, "width": 30, "height": 20, "confidence": .99}
        page["blocks"].append(block)
        competing = "L"
    block["candidates"] = [{"text": block["text"], "confidence": .99, "origin": "first_pass"},
                           {"text": competing, "confidence": .98, "origin": "first_pass"}]
    with _synthetic_ocr_import(tmp_path, page) as (records, imports, document):
        preview = records.prepare_review("demo", document["version_id"])
        draft = preview["rows"][0]
        row = draft["row"]
        assert row["field_status"][field] == "ambiguous"
        assert row["result"] == {"kind": "numeric_exact", "raw": "4,20", "decimal": "4.20"}
        if field == "reference_intervals":
            assert row[field][0]["raw"] == "0-8" and row[field][0]["high"] == "8"
        else:
            assert row[field] == "H"
        issues = imports.issues.list("demo", document["version_id"], limit=100)["issues"]
        readings = [item for issue in issues for item in issue["source"]["alternatives"]
                    if item.get("kind") == "source_ocr_candidate" and item.get("field") == field]
        assert [item["text"] for item in readings] == [competing]
        assert readings[0]["observed_source_text"] == block["text"]
        assert readings[0]["source_anchors"] == [row["field_anchors"][field]]
        with pytest.raises(V2Error) as error:
            records.commit_review("demo", preview["snapshot_id"], preview["snapshot_sha256"],
                                  [{"draft_id": draft["draft_id"], "action": "confirm"}])
        assert error.value.code == "unresolved_field"


def test_date_band_join_does_not_move_sparse_right_aligned_value_to_next_column():
    page = {"page": 1, "text": "", "source": "vision_ocr", "width": 1000, "height": 300, "blocks": [
        {"text": "Date", "x": 10, "y": 20, "width": 100, "height": 20},
        {"text": "Synthetic A", "x": 150, "y": 20, "width": 100, "height": 20},
        {"text": "Synthetic B", "x": 300, "y": 20, "width": 100, "height": 20},
        {"text": "2", "x": 280, "y": 80, "width": 8, "height": 20},
        {"text": "11.10.2026", "x": 10, "y": 100, "width": 110, "height": 20},
    ]}
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert [(row["analyte_raw"], row["result"]["raw"]) for row in output["rows"]] == [("Synthetic A", "2")]
    row = output["rows"][0]
    assert row["clinical_time"]["raw"] == "11.10.2026"
    assert row["field_anchors"]["result"]["excerpt"] == "2"
    assert row["field_anchors"]["result"]["locator"]["region"] == pytest.approx([.28, 80/300, .288, 100/300])
    assert row["field_anchors"]["clinical_time"]["locator"]["region"] == pytest.approx([.01, 100/300, .12, 120/300])
    assert any("MISSING_RESULT" in issue["reason_codes"] for issue in output["issues"])


def _review_dense_source():
    blocks = []
    for index in range(3):
        x = 150 + index*160
        blocks.extend([
            {"text": f"Synthetic Marker {chr(65+index)}", "x": x, "y": 20, "width": 155, "height": 18},
            {"text": f"{index+1},2", "x": x, "y": 80, "width": 24, "height": 18},
            {"text": "(g/L)", "x": x-2, "y": 118, "width": 40, "height": 18},
        ])
    blocks.append({"text": "11.10.2026", "x": 12, "y": 98, "width": 120, "height": 16})
    return {"page": 1, "text": "", "source": "vision_ocr", "width": 850, "height": 250, "blocks": blocks}


def test_dense_fallback_never_invents_an_absent_middle_analyte_header():
    page = _review_dense_source()
    page["blocks"] = [block for block in page["blocks"] if block["text"] != "Synthetic Marker B"]
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert output["rows"] == []
    assert "2,2" in "\n".join(issue["raw_text"] for issue in output["issues"])


def test_dense_fallback_does_not_promote_shared_source_box_to_distinct_numeric_cells():
    page = _review_dense_source()
    page["blocks"] = [block for block in page["blocks"] if block["text"] not in {"1,2", "2,2", "3,2"}]
    text = "1,2    2,2    3,2"
    page["blocks"].append({"text": text, "x": 150, "y": 80, "width": 400, "height": 18})
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert output["rows"] == []
    assert text in "\n".join(issue["raw_text"] for issue in output["issues"])


@pytest.mark.parametrize("competing", ["dates", "same_column_results"])
def test_date_band_ambiguity_cannot_assign_a_date_to_nearby_undated_results(competing):
    blocks = [
        {"text": "Date", "x": 10, "y": 20, "width": 100, "height": 20},
        {"text": "Synthetic A", "x": 150, "y": 20, "width": 100, "height": 20},
        {"text": "Synthetic B", "x": 300, "y": 20, "width": 100, "height": 20},
        {"text": "2", "x": 150, "y": 80, "width": 8, "height": 20},
        {"text": "11.10.2026", "x": 10, "y": 100, "width": 110, "height": 20},
    ]
    blocks.append({"text": "12.10.2026", "x": 10, "y": 120, "width": 110, "height": 20} if competing == "dates" else
                  {"text": "3", "x": 150, "y": 120, "width": 8, "height": 20})
    page = {"page": 1, "text": "", "source": "vision_ocr", "width": 1000, "height": 300, "blocks": blocks}
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert output["rows"]
    assert all(row["clinical_time"]["raw"] is None and "clinical_time" not in row["field_anchors"] for row in output["rows"])
    assert all(row["missing_reasons"]["clinical_time"] == "ambiguous" for row in output["rows"])
    assert "11.10.2026" in "\n".join(issue["raw_text"] for issue in output["issues"])


def test_joining_result_bands_with_different_glyph_heights_keeps_original_column_membership():
    page = {"page": 1, "text": "", "source": "vision_ocr", "width": 1000, "height": 300, "blocks": [
        {"text": "Date", "x": 10, "y": 20, "width": 100, "height": 20},
        {"text": "Synthetic A", "x": 150, "y": 20, "width": 100, "height": 20},
        {"text": "Synthetic B", "x": 300, "y": 20, "width": 100, "height": 20},
        {"text": "Synthetic C", "x": 450, "y": 20, "width": 100, "height": 20},
        {"text": "2", "x": 280, "y": 80, "width": 8, "height": 20},
        {"text": "11.10.2026", "x": 10, "y": 105, "width": 110, "height": 20},
        {"text": "3", "x": 450, "y": 125, "width": 8, "height": 30},
    ]}
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert [(row["analyte_raw"], row["result"]["raw"]) for row in output["rows"]] == [
        ("Synthetic A", "2"), ("Synthetic C", "3"),
    ]
    for row, expected in zip(output["rows"], [[.28, 80/300, .288, 100/300], [.45, 125/300, .458, 155/300]]):
        assert row["field_anchors"]["result"]["locator"]["region"] == pytest.approx(expected)
        assert row["clinical_time"]["raw"] in {None, "11.10.2026"}


def test_unknown_unit_subcells_cannot_become_a_new_dense_analyte_header():
    page = _review_dense_source()
    for block in page["blocks"]:
        if block["text"] == "(g/L)":
            block["text"] = "(J)"
    for index in range(3):
        x = 150 + index*160
        page["blocks"].extend([
            {"text": f"{index+6},3", "x": x, "y": 180, "width": 24, "height": 18},
            {"text": "(J)", "x": x-2, "y": 218, "width": 40, "height": 18},
        ])
    page["blocks"].append({"text": "12.10.2026", "x": 12, "y": 198, "width": 120, "height": 16})
    output = propose_lab_rows([page], VERSION, locator_kind="image")
    assert [row["analyte_raw"] for row in output["rows"]] == ["Synthetic Marker A", "Synthetic Marker B", "Synthetic Marker C"]*2
    assert [row["result"]["raw"] for row in output["rows"]] == ["1,2", "2,2", "3,2", "6,3", "7,3", "8,3"]
    assert [row["clinical_time"]["raw"] for row in output["rows"]] == ["11.10.2026"]*3 + ["12.10.2026"]*3
    assert all(row["unit_raw"] == "J" and row["field_status"]["unit_raw"] == "ambiguous" for row in output["rows"])
    assert all(row["field_anchors"]["unit_raw"]["excerpt"] == "(J)" for row in output["rows"])
