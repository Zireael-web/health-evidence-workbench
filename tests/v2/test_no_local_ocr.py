"""Synthetic offline checks for disabled local OCR and preserved source intake."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from health_analyzer.ingest import BlockDraft, BlockKind, DocumentArtifact, OCRProviderExtractor
from health_analyzer.ingest.registry import ExtractorFailure
from health_analyzer.v2 import ingest, pdf_bridge, pdf_geometry, vision
from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.records import RecordsService


class UnreadablePath:
    def __fspath__(self):
        raise AssertionError("Disabled OCR must not inspect a helper or scratch path")


@pytest.mark.parametrize("entrypoint", [
    lambda path: vision.prepare_native_helper(path),
    lambda path: vision._compile_trusted(("synthetic-command",)),
    lambda path: vision._bounded_run(("synthetic-command",), b"synthetic", timeout=1),
    lambda path: vision._validate_ancestry(path),
    lambda path: vision._protected_directory(path),
    lambda path: vision._validate_helper(path),
    lambda path: vision._command(path),
    lambda path: vision._extract(b"synthetic", kind="image", helper_path=path),
    lambda path: vision.extract_image(b"\x89PNG\r\n\x1a\nsynthetic", helper_path=path),
    lambda path: vision.extract_pdf_ocr(b"%PDF-1.4\nsynthetic", helper_path=path),
])
def test_old_execution_entrypoints_fail_before_any_side_effect(entrypoint, monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("Disabled OCR must not write files or start a process")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)
    for name in ("mkdir", "write_bytes", "write_text", "chmod", "open"):
        monkeypatch.setattr(Path, name, forbidden)
    with pytest.raises(V2Error) as error:
        entrypoint(UnreadablePath())
    assert error.value.code == "LOCAL_OCR_DISABLED"
    assert list(tmp_path.iterdir()) == []


def test_legacy_ocr_adapter_never_calls_a_provider():
    class Provider:
        provider_id, version = "synthetic", "1"

        def recognize(self, *args):
            raise AssertionError("Disabled OCR must not call a provider")

    with pytest.raises(ExtractorFailure) as error:
        OCRProviderExtractor(Provider()).extract(DocumentArtifact.from_bytes(b"synthetic", media_type="image/png"))
    assert error.value.code == "LOCAL_OCR_DISABLED"
    assert error.value.recoverable is False


def page(number, text):
    return {"page": number, "text": text, "blocks": [] if not text else [{
        "text": text, "x": 0, "y": 0, "width": 10, "height": 10,
        "confidence": None, "geometry_estimated": False}],
        "width": 100, "height": 100, "source": "pdf_text",
        "metadata": {"provider": "poppler_bbox", "coordinate_space": "pdf_crop_viewport", "source_layer": "pdf_text"}}


def disable_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Native intake must not invoke local OCR")

    for name in ("prepare_native_helper", "extract_image", "extract_pdf_ocr", "_bounded_run", "_compile_trusted"):
        monkeypatch.setattr(vision, name, forbidden)


@pytest.mark.parametrize("texts", [["", ""], ["native original", ""], ["native original", "second page"]])
def test_native_dispatch_preserves_all_geometry_pages_without_ocr(monkeypatch, texts):
    disable_execution(monkeypatch)
    originals = [page(number, text) for number, text in enumerate(texts, 1)]
    before = deepcopy(originals)
    monkeypatch.setattr(pdf_geometry, "extract_pdf_geometry", lambda content: (originals, ["synthetic native layer"]))
    blocks, limitations = ingest.extract_document_native(b"%PDF-1.4\nsynthetic")
    assert [block["page"] for block in blocks] == [1, 2]
    assert [block["text"] for block in blocks] == texts
    assert all(block["document_incomplete"] is ("" in texts) for block in blocks)
    assert originals == before
    assert (any("visual transcription" in item for item in limitations)) is ("" in texts)


def test_missing_native_text_returns_visual_requirement_without_ocr(monkeypatch):
    disable_execution(monkeypatch)
    monkeypatch.setattr(pdf_geometry, "extract_pdf_geometry", lambda content: None)
    monkeypatch.setattr(ingest, "_extract_pdf_text", lambda content: ([], ["No native PDF text"]))
    assert ingest.extract_document_native(b"%PDF-1.4\nsynthetic")[0] == []


def test_partial_native_worker_result_is_preserved_without_ocr(monkeypatch):
    disable_execution(monkeypatch)
    native = BlockDraft(BlockKind.TEXT, text="unmodified native text", page=3, document_incomplete=True)
    monkeypatch.setattr(pdf_geometry, "extract_pdf_geometry", lambda content: None)
    monkeypatch.setattr(ingest, "_extract_pdf_text", lambda content: ([native], ["synthetic native layer"]))
    blocks, _ = ingest.extract_document_native(b"%PDF-1.4\nsynthetic")
    assert blocks == [native]


@pytest.mark.parametrize("extension,content", [
    ("png", b"\x89PNG\r\n\x1a\nsynthetic image"),
    ("jpg", b"\xff\xd8\xffsynthetic image"),
])
def test_image_intake_is_pending_page_one_and_preserves_exact_original(tmp_path, monkeypatch, extension, content):
    disable_execution(monkeypatch)
    root = tmp_path / "synthetic-archive"
    root.mkdir()
    name = "synthetic." + extension
    (root / name).write_bytes(content)
    store = SignedStore(tmp_path / "synthetic-state/private.sqlite3", b"s" * 32, "private-data")
    records = RecordsService(store)
    config = SimpleNamespace(archive_roots={"synthetic": {"path": root, "subject_id": "synthetic"}})
    imports = ingest.ImportService(config, records)
    try:
        document = imports.prepare_import("synthetic", [{"root_id": "synthetic", "relative_path": name}])["documents"][0]
        coverage = store.get("extraction_run", document["run_id"], "synthetic")["coverage"]
        assert coverage["status"] == "visual_required"
        assert coverage["processed_pages"] == []
        assert coverage["unprocessed_pages"] == [1]
        assert coverage["errors"] == []
        assert coverage["method"] == "source_index"
        assert document["draft_ids"] == []
        source = imports.get_source_version("synthetic", document["version_id"])
        assert Path(source["verified_saved_source_path"]).read_bytes() == content
        assert document["source_sha256"] == hashlib.sha256(content).hexdigest()
        repeated = imports.prepare_import("synthetic", [{"root_id": "synthetic", "relative_path": name}])["documents"][0]
        assert repeated["run_id"] == document["run_id"]
        assert repeated["recognition_reused"] is True
        assert records.query_history("synthetic")["current"] == []
    finally:
        store.close()


def test_blank_native_geometry_page_remains_pending_in_import_coverage(tmp_path, monkeypatch):
    disable_execution(monkeypatch)
    monkeypatch.setattr(pdf_geometry, "extract_pdf_geometry", lambda content: ([
        page(1, "analyte;result;unit\nSynthetic;5;u\n"), page(2, "")], ["synthetic native layer"]))
    root = tmp_path / "synthetic-archive"
    root.mkdir()
    (root / "synthetic.pdf").write_bytes(b"%PDF-1.4\nsynthetic")
    store = SignedStore(tmp_path / "synthetic-state/private.sqlite3", b"s" * 32, "private-data")
    records = RecordsService(store)
    imports = ingest.ImportService(SimpleNamespace(archive_roots={
        "synthetic": {"path": root, "subject_id": "synthetic"}}), records)
    try:
        document = imports.prepare_import("synthetic", [{"root_id": "synthetic", "relative_path": "synthetic.pdf"}])["documents"][0]
        coverage = store.get("extraction_run", document["run_id"], "synthetic")["coverage"]
        assert len(document["draft_ids"]) == 1
        assert coverage["status"] == "partial"
        assert coverage["processed_pages"] == [1]
        assert coverage["unprocessed_pages"] == [2]
        assert imports.issues.list("synthetic", document["version_id"])["issues"][0]["source"]["page"] == 2
    finally:
        store.close()


def test_production_bridge_dispatches_images_without_scratch_or_ocr(monkeypatch):
    disable_execution(monkeypatch)
    with pdf_bridge.PdfBridgeBootstrap() as bridge:
        connection = pdf_bridge._PdfRuntimeClient(*(os.dup(fd) for fd in bridge.client_fds))
        try:
            blocks, limitations = connection.extract(b"\x89PNG\r\n\x1a\nsynthetic")
            assert blocks == []
            assert any("visual transcription" in item for item in limitations)
        finally:
            connection.close()
