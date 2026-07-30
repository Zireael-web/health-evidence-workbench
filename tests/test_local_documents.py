from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import sys
import struct
import zlib

import pytest

from health_analyzer import local_documents as local
from health_analyzer.ingest.models import BlockDraft, BlockKind
from health_analyzer.ingest.registry import ExtractorFailure


@pytest.fixture
def fake_pdf(tmp_path: Path) -> Path:
    source = tmp_path / "synthetic.pdf"
    source.write_bytes(b"%PDF-1.4\nsynthetic test bytes\n%%EOF\n")
    return source


def _mock_extraction(monkeypatch: pytest.MonkeyPatch, *, count: int = 1, blocks=None, failure=None):
    monkeypatch.setattr(local, "_pdf_page_count", lambda content, **kwargs: count)

    def extract(provider, content):
        if failure is not None:
            raise failure
        return blocks if blocks is not None else (
            BlockDraft(kind=BlockKind.TEXT, text="Synthetic text", page=1, line_start=1, line_end=1),
        )

    monkeypatch.setattr(local.PypdfTextProvider, "extract_pdf", extract)


def _synthetic_pdf(texts: list[str | None]) -> bytes:
    pypdf = pytest.importorskip("pypdf")
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    writer = pypdf.PdfWriter()
    for text in texts:
        page = writer.add_blank_page(width=612, height=792)
        if text is None:
            continue
        font = DictionaryObject({
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        })
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})
        })
        stream = DecodedStreamObject()
        stream.set_data(f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii"))
        page[NameObject("/Contents")] = writer._add_object(stream)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_local_inspection_preserves_text_hash_and_page_provenance(fake_pdf, monkeypatch):
    _mock_extraction(monkeypatch)
    before = fake_pdf.read_bytes()
    result = local.inspect_local_pdf(fake_pdf)
    assert fake_pdf.read_bytes() == before
    assert result["sha256"] == sha256(before).hexdigest()
    assert result["byte_size"] == len(before)
    assert result["page_count"] == 1
    assert result["extraction_complete"] is True
    assert result["review_status"] == "needs_review"
    page = result["pages"][0]
    assert page["text"] == "Synthetic text"
    assert page["review_status"] == "needs_review"
    assert page["provenance"]["page"] == 1
    assert page["provenance"]["source_sha256"] == result["sha256"]
    assert page["provenance"]["source_path"] == str(fake_pdf)
    assert json.loads(json.dumps(result)) == result


def test_missing_trailing_pages_are_explicit(fake_pdf, monkeypatch):
    _mock_extraction(monkeypatch, count=3)
    result = local.inspect_local_pdf(fake_pdf)
    assert result["page_count"] == 3
    assert result["extraction_complete"] is False
    assert [p["page"] for p in result["pages"]] == [1, 2, 3]
    assert [p["text"] for p in result["pages"]] == ["Synthetic text", None, None]
    assert result["pages"][2]["extraction_status"] == "needs_visual_review"


@pytest.mark.parametrize("failure_code", ["pdf_ocr_required", "pdf_text_extraction_failed"])
def test_all_pages_without_native_text_have_exact_count(fake_pdf, monkeypatch, failure_code):
    _mock_extraction(monkeypatch, count=2, failure=ExtractorFailure(failure_code, "synthetic"))
    result = local.inspect_local_pdf(fake_pdf)
    assert result["page_count"] == len(result["pages"]) == 2
    assert result["failures"] == [failure_code]
    assert all(p["text"] is None for p in result["pages"])
    assert result["extraction_complete"] is False


@pytest.mark.parametrize("failure_code", ["pdf_page_limit_exceeded", "pdf_total_text_limit_exceeded", "pdf_worker_timeout", "pdf_worker_sandbox_unavailable"])
def test_extractor_hard_failures_never_return_partial_results(fake_pdf, monkeypatch, failure_code):
    _mock_extraction(monkeypatch, failure=ExtractorFailure(failure_code, "synthetic", recoverable=False))
    with pytest.raises(local.LocalDocumentError) as raised:
        local.inspect_local_pdf(fake_pdf)
    assert raised.value.code == failure_code


def test_rejects_symlink_without_following_it(fake_pdf, tmp_path):
    link = tmp_path / "link.pdf"
    link.symlink_to(fake_pdf)
    with pytest.raises(local.LocalDocumentError, match="regular non-symlink"):
        local.inspect_local_pdf(link)


def test_rejects_symlink_ancestor(fake_pdf, tmp_path, monkeypatch):
    link = tmp_path / "ancestor"
    link.symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(local, "_pdf_page_count", lambda *args, **kwargs: pytest.fail("must not parse through an ancestor symlink"))
    with pytest.raises(local.LocalDocumentError) as raised:
        local.inspect_local_pdf(link / fake_pdf.name)
    assert raised.value.code == "pdf_source_unavailable"


def test_rejects_traversal_before_normalization(fake_pdf):
    with pytest.raises(local.LocalDocumentError) as raised:
        local.inspect_local_pdf(fake_pdf.parent / "unused" / ".." / fake_pdf.name)
    assert raised.value.code == "pdf_source_path_invalid"


@pytest.mark.parametrize("name,content,code", [
    ("wrong.txt", b"%PDF-1.4\n%%EOF\n", "pdf_extension_mismatch"),
    ("wrong.pdf", b"not a pdf", "pdf_signature_mismatch"),
    ("wrong.pdf", b"%PDF-1.4\ntruncated", "pdf_signature_mismatch"),
])
def test_rejects_extension_or_header_mismatch(tmp_path, name, content, code):
    path = tmp_path / name
    path.write_bytes(content)
    with pytest.raises(local.LocalDocumentError) as raised:
        local.inspect_local_pdf(path)
    assert raised.value.code == code


def test_rejects_directory_and_fifo_without_blocking(tmp_path):
    directory = tmp_path / "directory.pdf"
    directory.mkdir()
    fifo = tmp_path / "fifo.pdf"
    os.mkfifo(fifo)
    for source in (directory, fifo):
        with pytest.raises(local.LocalDocumentError) as raised:
            local.inspect_local_pdf(source)
        assert raised.value.code == "pdf_not_regular_file"


def test_input_hard_cap_is_applied_before_parse(fake_pdf, monkeypatch):
    monkeypatch.setattr(local, "MAX_LOCAL_PDF_BYTES", 8)
    monkeypatch.setattr(local, "_pdf_page_count", lambda _: pytest.fail("must not parse oversized file"))
    with pytest.raises(local.LocalDocumentError) as raised:
        local.inspect_local_pdf(fake_pdf)
    assert raised.value.code == "pdf_input_size_limit_exceeded"


@pytest.mark.parametrize("change", ["content", "replace", "symlink", "delete"])
def test_source_change_after_parse_discards_result(fake_pdf, monkeypatch, change):
    _mock_extraction(monkeypatch)

    def changed_count(content, **kwargs):
        if change == "content":
            fake_pdf.write_bytes(content.replace(b"synthetic", b"different"))
        elif change == "replace":
            replacement = fake_pdf.with_name("replacement.pdf")
            replacement.write_bytes(content)
            os.replace(replacement, fake_pdf)
        elif change == "symlink":
            target = fake_pdf.with_name("target.pdf")
            target.write_bytes(content)
            fake_pdf.unlink()
            fake_pdf.symlink_to(target)
        else:
            fake_pdf.unlink()
        return 1

    monkeypatch.setattr(local, "_pdf_page_count", changed_count)
    with pytest.raises(local.LocalDocumentError) as raised:
        local.inspect_local_pdf(fake_pdf)
    assert raised.value.code == "pdf_source_changed"


def test_source_change_during_read_is_rejected(fake_pdf, monkeypatch):
    original_read = os.read
    changed = False

    def mutate_during_read(fd, size):
        nonlocal changed
        data = original_read(fd, size)
        if not changed:
            changed = True
            fake_pdf.write_bytes(b"%PDF-1.4\nchanged source\n%%EOF\n")
        return data

    monkeypatch.setattr(local.os, "read", mutate_during_read)
    with pytest.raises(local.LocalDocumentError) as raised:
        local.inspect_local_pdf(fake_pdf)
    assert raised.value.code == "pdf_source_changed"


def test_duplicate_page_provenance_is_rejected(fake_pdf, monkeypatch):
    block = BlockDraft(kind=BlockKind.TEXT, text="Synthetic", page=1)
    _mock_extraction(monkeypatch, blocks=(block, block))
    with pytest.raises(local.LocalDocumentError) as raised:
        local.inspect_local_pdf(fake_pdf)
    assert raised.value.code == "pdf_page_provenance_invalid"


def test_metadata_command_preserves_mandatory_sandbox_prefix(monkeypatch):
    existing = ("sandbox-exec", "-f", "pdf-parser.sb", "python", "-I", "-B", "-X", "utf8", "-m", "health_analyzer.ingest.pypdf_worker")
    monkeypatch.setattr(local, "_pdf_worker_command", lambda: existing)
    command = local._metadata_worker_command()
    assert command[:-2] == existing[:-1]
    assert command[-2:] == ("health_analyzer.local_documents", "--pdf-metadata-worker")


@pytest.mark.parametrize("payload", [
    {},
    {"protocol": local._METADATA_PROTOCOL, "page_count": True},
    {"protocol": local._METADATA_PROTOCOL, "page_count": 501},
    {"protocol": local._METADATA_PROTOCOL, "page_count": 0},
    {"protocol": local._METADATA_PROTOCOL, "page_count": 1, "extra": "unsafe"},
    {"protocol": local._METADATA_PROTOCOL, "error": "untrusted arbitrary error"},
])
def test_metadata_protocol_is_fail_closed(monkeypatch, payload):
    monkeypatch.setattr(local, "_metadata_worker_command", lambda **kwargs: ("fake",))
    monkeypatch.setattr(local, "_run_bounded_process", lambda *args, **kwargs: json.dumps(payload).encode())
    with pytest.raises(local.LocalDocumentError) as raised:
        local._pdf_page_count(b"synthetic")
    assert raised.value.code == "pdf_metadata_response_invalid"


@pytest.mark.parametrize("texts", [["Synthetic native text"], ["Synthetic native text", None], [None, None]])
def test_real_synthetic_pdf_runs_through_production_workers(tmp_path, texts):
    source = tmp_path / "synthetic.pdf"
    source.write_bytes(_synthetic_pdf(texts))
    original = source.read_bytes()
    result = local.inspect_local_pdf(source, isolation="host")
    assert result["page_count"] == len(texts)
    assert [p["text"] for p in result["pages"]] == texts
    assert result["extraction_complete"] is all(text is not None for text in texts)
    assert source.read_bytes() == original
    assert result["isolation"]["mode"] == "host"
    assert result["isolation"]["nested_seatbelt"] is False
    assert result["isolation"]["os_no_network_guarantee"] is False
    if texts[0] is not None:
        assert "resource-bounded child process" in " ".join(result["pages"][0]["limitations"])


def _tiny_png(width=1, height=1):
    def chunk(kind, data):
        return len(data).to_bytes(4, "big") + kind + data + zlib.crc32(kind + data).to_bytes(4, "big")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b"")


def _mock_render(monkeypatch, *, count=2):
    monkeypatch.setattr(local, "_pdf_page_count", lambda content, **kwargs: count)
    monkeypatch.setattr(local.shutil, "which", lambda name: "/synthetic/pdftoppm")
    calls = []
    def render(command, content, **kwargs):
        calls.append((command, content, kwargs))
        return _tiny_png()
    monkeypatch.setattr(local, "_run_bounded_process", render)
    return calls


def test_render_is_exclusive_complete_and_passes_only_stdin(fake_pdf, tmp_path, monkeypatch):
    calls = _mock_render(monkeypatch)
    output = tmp_path / "renders"
    output.mkdir()
    first = local.render_local_pdf(fake_pdf, output, isolation="host")
    second = local.render_local_pdf(fake_pdf, output, isolation="host")
    assert first["render_directory"] != second["render_directory"]
    assert first["page_count"] == len(first["pages"]) == 2
    assert first["isolation"]["os_no_network_guarantee"] is False
    assert all(Path(page["path"]).read_bytes() == _tiny_png() for page in first["pages"])
    assert all(page["review_status"] == "needs_review" for page in first["pages"])
    assert all(command[-1] == "-" and str(fake_pdf) not in command for command, _, _ in calls)
    assert all(content == fake_pdf.read_bytes() for _, content, _ in calls)
    assert all(kwargs["timeout_seconds"] <= 20 and kwargs["max_output_bytes"] <= local.MAX_RENDER_PAGE_BYTES for _, _, kwargs in calls)
    assert json.loads(json.dumps(first)) == first


def test_render_nested_never_silently_falls_back(fake_pdf, tmp_path, monkeypatch):
    monkeypatch.setattr(local, "_pdf_page_count", lambda *args, **kwargs: pytest.fail("must not parse"))
    with pytest.raises(local.LocalDocumentError) as raised:
        local.render_local_pdf(fake_pdf, tmp_path)
    assert raised.value.code == "pdf_render_sandbox_unavailable"


@pytest.mark.parametrize("dpi", [0, 35, 201, True, 100.5])
def test_render_rejects_unbounded_dpi(fake_pdf, tmp_path, dpi):
    with pytest.raises(ValueError):
        local.render_local_pdf(fake_pdf, tmp_path, dpi=dpi, isolation="host")


def test_render_page_limit_prevents_any_output(fake_pdf, tmp_path, monkeypatch):
    _mock_render(monkeypatch, count=local.MAX_RENDER_PAGES + 1)
    output = tmp_path / "renders"
    output.mkdir()
    with pytest.raises(local.LocalDocumentError) as raised:
        local.render_local_pdf(fake_pdf, output, isolation="host")
    assert raised.value.code == "pdf_render_page_limit_exceeded"
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("failure", ["process", "total_bytes", "invalid_png", "source_change", "pixels"])
def test_render_failure_removes_only_own_partial_directory(fake_pdf, tmp_path, monkeypatch, failure):
    _mock_render(monkeypatch)
    output = tmp_path / "renders"
    output.mkdir()
    unrelated = output / "keep.txt"
    unrelated.write_text("synthetic user file")
    calls = 0
    def render(command, content, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _tiny_png()
        if failure == "process":
            raise ExtractorFailure("pdf_worker_timeout", "synthetic timeout")
        if failure == "invalid_png":
            return b"not png"
        if failure == "pixels":
            return _tiny_png(local.MAX_RENDER_DIMENSION + 1)
        if failure == "source_change":
            fake_pdf.write_bytes(content + b"changed")
        return _tiny_png()
    monkeypatch.setattr(local, "_run_bounded_process", render)
    if failure == "total_bytes":
        monkeypatch.setattr(local, "MAX_RENDER_TOTAL_BYTES", len(_tiny_png()) + 1)
    with pytest.raises(local.LocalDocumentError):
        local.render_local_pdf(fake_pdf, output, isolation="host")
    assert list(output.iterdir()) == [unrelated]
    assert unrelated.read_text() == "synthetic user file"


def test_real_synthetic_pdf_renders_all_pages(tmp_path):
    if local.shutil.which("pdftoppm") is None:
        pytest.skip("optional local Poppler is not installed")
    source = tmp_path / "synthetic.pdf"
    source.write_bytes(_synthetic_pdf(["Synthetic render", None]))
    output = tmp_path / "renders"
    output.mkdir()
    result = local.render_local_pdf(source, output, dpi=72, isolation="host")
    assert result["page_count"] == len(result["pages"]) == 2
    assert all(0 < page["width"] <= 2500 and 0 < page["height"] <= 2500 for page in result["pages"])
    assert all(Path(page["path"]).read_bytes().startswith(b"\x89PNG") for page in result["pages"])
