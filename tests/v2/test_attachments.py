"""Owned synthetic attachment intake; no archive, network, OCR or native tools."""
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from health_analyzer.v2.attachments import AttachmentService, validate_attachment_idempotency
from health_analyzer.v2.common import SignedStore, V2Error, digest
from health_analyzer.v2.document_io import DocumentIOService
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.records import RecordsService


@pytest.fixture
def intake(tmp_path):
    config = SimpleNamespace(archive_roots={}, isolation="host", data_root=tmp_path)
    store = SignedStore(tmp_path / "private" / "private.sqlite3", b"a" * 32, "private-data")
    records = RecordsService(store)
    forbidden = lambda _content: pytest.fail("Native parser/OCR must not run in synthetic attachment tests")
    imports = ImportService(config, records, pdf_extractor=forbidden,
                            image_extractor=lambda _content: ([], ["Synthetic image requires visual transcription"]))
    documents = DocumentIOService(config, records, imports)
    service = AttachmentService(config, records, imports, documents)
    yield service
    store.close()


def source(tmp_path, name="report.csv", content=b"analyte;result;unit\nSynthetic A;1;u\n"):
    path = tmp_path / name
    path.write_bytes(content)
    return path


def test_selected_csv_preserves_original_and_full_text_without_archive_binding(intake, tmp_path):
    path = source(tmp_path)
    original, original_mode = path.read_bytes(), path.stat().st_mode
    result = intake.prepare_attachment("demo", str(path), "selected-file")
    assert result["preparation_id"].startswith("case_")
    assert result["confirmed"] is False and result["verification"] == "unverified"
    assert len(result["draft_ids"]) == 1 and result["issue_ids"] == []
    assert intake.records.query_history("demo")["current"] == []
    assert intake.store.list("file_occurrence", "demo") == []
    assert intake.config.archive_roots == {}
    assert path.read_bytes() == original and path.stat().st_mode == original_mode
    assert Path(result["source_view"]["verified_saved_source_path"]).read_bytes() == original
    assert Path(result["source_view"]["verified_view_path"]).read_bytes() == original
    assert result["native_transcripts"][0]["method"] == "native_text"
    saved = intake.documents.get_document_text("demo", result["native_transcripts"][0]["transcript_id"])
    assert saved["pages"] == [{"page": 1, "text": original.decode()}]
    assert saved["human_verified"] is False and saved["review_status"] == "unverified"
    path.unlink()
    assert intake.imports.check_current_source(intake.records._version("demo", result["version_id"]))


def test_same_bytes_different_selected_path_reuses_run_without_reextract(intake, tmp_path, monkeypatch):
    first = source(tmp_path)
    original = intake.prepare_attachment("demo", str(first))
    second = source(tmp_path, "renamed.csv", first.read_bytes())
    monkeypatch.setattr(intake.imports, "_extract", lambda *_args: pytest.fail("Same bytes were extracted again"))
    repeat = intake.prepare_attachment("demo", str(second))
    assert repeat["recognition_reused"] is True
    assert repeat["version_id"] == original["version_id"]
    assert repeat["run_id"] == original["run_id"]
    assert repeat["native_transcripts"] == original["native_transcripts"]
    assert len(intake.store.list("extraction_run", "demo")) == 1


def test_exact_retry_returns_original_ack_even_after_paths_vanish(intake, tmp_path, monkeypatch):
    path = source(tmp_path)
    result = intake.prepare_attachment("demo", str(path), "retry")
    path.unlink()
    monkeypatch.setattr("health_analyzer.v2.attachments.read_source", lambda *_args: pytest.fail("Retry reread selected file"))
    monkeypatch.setattr(intake.imports.originals, "read_manifest", lambda *_args: pytest.fail("Retry reread original"))
    monkeypatch.setattr(intake.documents, "prepare_document_view", lambda *_args: pytest.fail("Retry prepared another view"))
    assert intake.prepare_attachment("demo", str(path), "retry") == result
    with pytest.raises(V2Error, match="another request") as error:
        intake.prepare_attachment("demo", str(tmp_path / "different.csv"), "retry")
    assert error.value.code == "idempotency_conflict"
    assert len(intake.store.list("idempotency", "demo")) == 1


@pytest.mark.parametrize("name,content,mime", [
    ("image.png", b"\x89PNG\r\n\x1a\nsynthetic", "image/png"),
    ("image.jpeg", b"\xff\xd8\xffsynthetic", "image/jpeg"),
])
def test_selected_image_keeps_visual_pending_and_has_usable_source_view(intake, tmp_path, name, content, mime):
    result = intake.prepare_attachment("demo", str(source(tmp_path, name, content)))
    assert result["mime"] == mime
    assert result["draft_ids"] == [] and result["native_transcripts"] == []
    assert result["coverage"]["status"] == "visual_required"
    assert result["coverage"]["unprocessed_pages"] == [1]
    view = Path(result["source_view"]["verified_view_path"])
    assert view.suffix in {".png", ".jpg", ".jpeg"} and view.read_bytes() == content
    assert intake.store.list("observation_revision", "demo") == []


def test_full_native_pdf_text_survives_preview_budget_and_preserves_blank_pages(intake, tmp_path, monkeypatch):
    content = b"%PDF-1.4\nsynthetic only"
    long_text = "Synthetic report line\n" * 15000
    coverage = {"status": "visual_required", "expected_count": None, "expected_count_basis": "unknown",
                "processed_pages": [1], "unprocessed_pages": [2], "errors": ["NO_NATIVE_TEXT"],
                "method": "native_table", "model": None, "provider": "v2", "extractor_version": "1"}
    monkeypatch.setattr(intake.imports, "_extract", lambda *_args: (
        [], coverage, [{"page": 1, "text": long_text}], ["Synthetic native page extraction"], []))
    result = intake.prepare_attachment("demo", str(source(tmp_path, "report.pdf", content)))
    ref = result["native_transcripts"][0]
    assert ref["method"] == "native_pdf_text" and ref["text_bytes"] > 256 * 1024
    saved = intake.documents.get_document_text("demo", ref["transcript_id"])
    assert saved["pages"] == [{"page": 1, "text": long_text}, {"page": 2, "text": ""}]
    assert "native_text" not in result  # ACK contains references, never a clipped text preview.


def test_parser_failure_rolls_back_all_database_registration(intake, tmp_path, monkeypatch):
    path = source(tmp_path)
    def fail(*_args):
        raise V2Error("SYNTHETIC_FAILURE", "Synthetic parser failure")
    monkeypatch.setattr(intake.imports, "_extract", fail)
    with pytest.raises(V2Error):
        intake.prepare_attachment("demo", str(path), "failure")
    for kind in ("subject", "document", "document_version", "original_manifest", "extraction_run",
                 "observation_draft", "document_transcript", "document_transcript_chunk", "idempotency"):
        assert intake.store.list(kind, "demo") == []
    assert path.read_bytes() == b"analyte;result;unit\nSynthetic A;1;u\n"


def test_late_native_storage_failure_rolls_back_drafts_and_issues(intake, tmp_path, monkeypatch):
    path = source(tmp_path)
    def fail(*_args, **_kwargs):
        raise V2Error("DOCUMENT_TEXT_LIMIT", "Synthetic transcript overflow")
    monkeypatch.setattr(intake.documents, "_save_native_document_text", fail)
    with pytest.raises(V2Error) as error:
        intake.prepare_attachment("demo", str(path), "failure")
    assert error.value.code == "DOCUMENT_TEXT_LIMIT"
    for kind in ("subject", "document", "document_version", "original_manifest", "extraction_run",
                 "observation_draft", "panel", "import_issue", "idempotency"):
        assert intake.store.list(kind, "demo") == []


@pytest.mark.parametrize("value", ["report.csv", "https://example.invalid/report.pdf", "file:///tmp/report.csv",
                                   "/tmp/../report.csv", "/tmp/./report.csv", "/tmp//report.csv", "//host/report.csv"])
def test_requires_one_direct_absolute_local_path(intake, value):
    with pytest.raises(V2Error):
        intake.prepare_attachment("demo", value)
    assert intake.store.list("subject", "demo") == []


def test_symlink_source_and_ancestor_rejected_without_registration(intake, tmp_path):
    path = source(tmp_path)
    linked = tmp_path / "linked.csv"
    linked.symlink_to(path)
    directory = tmp_path / "linked-directory"
    directory.symlink_to(tmp_path, target_is_directory=True)
    for candidate in (linked, directory / path.name):
        with pytest.raises(V2Error) as error:
            intake.prepare_attachment("demo", str(candidate))
        assert error.value.code == "SOURCE_UNAVAILABLE"
    assert intake.store.list("document_version", "demo") == []


@pytest.mark.parametrize("name,content", [("bad.png", b"not png"), ("bad.pdf", b"not pdf"),
                                         ("bad.jpg", b"not jpeg"), ("empty.txt", b""),
                                         ("binary.csv", b"analyte;result\n\x00;1\n"),
                                         ("other.docx", b"unsupported")])
def test_bad_mime_empty_binary_and_unsupported_are_atomic(intake, tmp_path, name, content):
    with pytest.raises(V2Error):
        intake.prepare_attachment("demo", str(source(tmp_path, name, content)), "invalid")
    assert intake.store.list("document_version", "demo") == []
    assert intake.store.list("idempotency", "demo") == []


def test_live_denial_remains_denied_in_enforced_mode(intake, tmp_path, monkeypatch):
    intake.config.isolation = "macos_enforced"
    path = source(tmp_path)
    def denied(*_args):
        raise V2Error("SOURCE_UNAVAILABLE", "Synthetic live permission denial")
    monkeypatch.setattr("health_analyzer.v2.attachments.read_source", denied)
    with pytest.raises(V2Error) as error:
        intake.prepare_attachment("demo", str(path))
    assert error.value.code == "SOURCE_UNAVAILABLE"
    assert intake.config.isolation == "macos_enforced" and intake.config.archive_roots == {}
    assert intake.store.list("document_version", "demo") == []


def test_recovery_validator_is_pure_and_rejects_forged_source_or_confirmation(intake, tmp_path, monkeypatch):
    result = intake.prepare_attachment("demo", str(source(tmp_path)), "recovery")
    payload = intake.store.list("idempotency", "demo")[0]
    monkeypatch.setattr("health_analyzer.v2.attachments.read_source", lambda *_args: pytest.fail("Pure validator read a source"))
    validate_attachment_idempotency(payload, intake.store.get)
    for key, value in (("source_sha256", "f" * 64), ("confirmed", True), ("run_id", "missing_run")):
        forged = copy.deepcopy(payload)
        forged["result"][key] = value
        forged["result"]["preparation_sha256"] = digest({field: item for field, item in forged["result"].items()
                                                         if field != "preparation_sha256"})
        with pytest.raises(V2Error):
            validate_attachment_idempotency(forged, intake.store.get)
    assert result["source_sha256"] == hashlib.sha256(source(tmp_path).read_bytes()).hexdigest()
