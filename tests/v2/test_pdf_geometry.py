import json
import os
from pathlib import Path
import sys

import pytest

from health_analyzer.v2.common import V2Error
from health_analyzer.v2.pdf_geometry import PROTOCOL, decode_geometry, extract_pdf_geometry, local_binary
from health_analyzer.v2.pdf_geometry_worker import parse_bbox
from health_analyzer.v2 import pdf_geometry


XML = b'<html><body><doc><page width="600" height="800"><flow><block><line><word xMin="10" yMin="20" xMax="35" yMax="30">Unit</word><word xMin="40" yMin="20" xMax="80" yMax="30">g/L</word></line></block></flow></page></doc></body></html>'


def test_native_word_boxes_are_precise_and_layer_not_visual_verification():
    pages = parse_bbox(XML)
    decoded = decode_geometry(json.dumps({"protocol": PROTOCOL, "ok": True, "pages": pages}).encode())
    assert decoded[0]["text"] == "Unit g/L"
    assert decoded[0]["blocks"][1]["x"] == 40
    assert decoded[0]["blocks"][1]["geometry_estimated"] is False
    assert decoded[0]["metadata"]["source_layer"] == "pdf_text"


@pytest.mark.parametrize("xml", [XML.replace(b'xMax="35"', b'xMax="900"'), XML.replace(b'xMin="10"', b'xMin="nan"'), b'<!DOCTYPE x [<!ENTITY bad "x">]>'+XML])
def test_invalid_bbox_and_entities_fail_closed(xml):
    with pytest.raises(V2Error):
        parse_bbox(xml)


def synthetic_pdf():
    content = b'BT /F1 12 Tf 30 700 Td (Analyte) Tj 200 0 Td (Result) Tj 100 0 Td (Unit) Tj 100 0 Td (Reference) Tj ET\nBT /F1 12 Tf 30 670 Td (Synthetic A) Tj 200 0 Td (4.2) Tj 100 0 Td (g/L) Tj 100 0 Td (1-8) Tj ET\n'
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Count 1 /Kids [3 0 R] >>',
       b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 800] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
       b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>', b'<< /Length '+str(len(content)).encode()+b' >>\nstream\n'+content+b'endstream']
    data=bytearray(b'%PDF-1.4\n'); offsets=[0]
    for i, value in enumerate(objects,1):
        offsets.append(len(data)); data.extend(str(i).encode()+b' 0 obj\n'+value+b'\nendobj\n')
    xref=len(data); data.extend(b'xref\n0 6\n0000000000 65535 f \n')
    for offset in offsets[1:]: data.extend(f'{offset:010d} 00000 n \n'.encode())
    data.extend(b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n'+str(xref).encode()+b'\n%%EOF\n')
    return bytes(data)


def test_actual_sandboxed_word_geometry_and_table_cells():
    if os.environ.get("HEALTH_ANALYZER_RUN_NATIVE_GEOMETRY") != "1" or local_binary() is None:
        pytest.skip("opt-in actual bundled offline PDF geometry")
    pages, limits = extract_pdf_geometry(synthetic_pdf())
    from health_analyzer.v2.layout import propose_lab_rows
    output = propose_lab_rows(pages, {"version_id":"ver_synthetic","source_sha256":"a"*64})
    assert len(output["rows"]) == 1
    row = output["rows"][0]
    assert row["result"]["decimal"] == "4.2" and row["unit_raw"] == "g/L"
    assert row["reference_intervals"][0]["low"] == "1"
    assert "region" in row["field_anchors"]["result"]["locator"]
    assert "text layer" in limits[0]


def test_actual_geometry_profile_denies_synthetic_archive_key_writes_and_network(tmp_path):
    """Exercise the real narrower profile with fixed synthetic canaries only."""
    if sys.platform != "darwin" or os.environ.get("HEALTH_ANALYZER_RUN_NATIVE_GEOMETRY") != "1":
        pytest.skip("opt-in actual mandatory offline geometry sandbox")
    binary = local_binary()
    if binary is None:
        pytest.skip("trusted bundled Poppler is unavailable")
    archive = tmp_path / "synthetic-archive"
    archive.mkdir()
    source = archive / "synthetic-report.pdf"
    source.write_bytes(b"Synthetic protected archive marker; never a real report")
    state = tmp_path / "synthetic-state"
    state.mkdir()
    key = state / "synthetic-private-data.key"
    key.write_bytes(b"Synthetic protected key marker; never a real key")
    write_target = archive / "synthetic-forbidden-write.txt"
    original_source, original_key = source.read_bytes(), key.read_bytes()
    params = {
        "CODE_ROOT": Path(pdf_geometry.__file__).resolve().parents[2],
        "PYTHON_ROOT": Path(sys.prefix).resolve(), "BASE_PYTHON_ROOT": Path(sys.base_prefix).resolve(),
        "PYTHON_EXEC": Path(sys.executable).resolve(), "GEOMETRY_EXEC": binary,
        "GEOMETRY_LIBS": binary.parent.parent / "lib", "GEOMETRY_SHARE": binary.parent.parent / "share",
    }
    command = ["/usr/bin/sandbox-exec", "-f",
               str(Path(pdf_geometry.__file__).with_name("native") / "pdf-geometry.sb")]
    for name, path in params.items():
        command.extend(["-D", f"{name}={path}"])
    probe = r'''
import errno, json, socket, sys
def denied(operation):
    try:
        operation()
    except OSError as exc:
        return exc.errno in (errno.EPERM, errno.EACCES)
    return False
def read(path):
    with open(path, "rb") as stream:
        stream.read()
def write(path):
    with open(path, "wb") as stream:
        stream.write(b"synthetic forbidden write")
def network():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(.5)
        connection.connect(("127.0.0.1", 9))
sys.stdout.write(json.dumps({
    "archive_read_blocked": denied(lambda: read(sys.argv[1])),
    "key_read_blocked": denied(lambda: read(sys.argv[2])),
    "archive_write_blocked": denied(lambda: write(sys.argv[1])),
    "key_write_blocked": denied(lambda: write(sys.argv[2])),
    "new_file_write_blocked": denied(lambda: write(sys.argv[3])),
    "network_blocked": denied(network),
}))
'''
    command.extend([sys.executable, "-I", "-B", "-c", probe, str(source), str(key), str(write_target)])
    from health_analyzer.ingest.pypdf_subprocess import _run_bounded_process
    result = _run_bounded_process(tuple(command), b"", timeout_seconds=15,
                                  max_output_bytes=1024, max_stderr_bytes=4096)
    assert json.loads(result) == {
        "archive_read_blocked": True, "key_read_blocked": True,
        "archive_write_blocked": True, "key_write_blocked": True,
        "new_file_write_blocked": True, "network_blocked": True,
    }
    assert source.read_bytes() == original_source and key.read_bytes() == original_key
    assert not write_target.exists()
