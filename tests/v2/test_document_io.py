"""Synthetic owned fixtures only; mocked render tests are not a Poppler gate."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.document_io import (
    DocumentIOService, MAX_TEXT_BYTES, validate_document_transcript,
    validate_document_transcript_chunk, validate_document_transcript_links, validate_document_text_ack,
)
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.records import RecordsService


PDF = b"%PDF-1.4\n% synthetic non-rendered fixture\n%%EOF\n"


@pytest.fixture
def fixture(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    store = SignedStore(private / "private.sqlite3", b"synthetic-test-key-material-only!" * 2, "private-data")
    records = RecordsService(store)
    records.register_subject("synthetic_subject", "Synthetic subject")
    config = SimpleNamespace(data_root=tmp_path, isolation="host", archive_roots={})
    imports = ImportService(config, records)
    documents = DocumentIOService(config, records, imports)

    def register(content=PDF, mime="application/pdf", subject="synthetic_subject"):
        if subject != "synthetic_subject":
            records.register_subject(subject, "Synthetic alternate subject")
        version = records.register_document(subject, hashlib.sha256(content).hexdigest(), mime, len(content))
        saved = imports.originals.preserve(subject, content, mime)
        store.put("original_manifest", imports._manifest_id(version),
                  {"subject_id": subject, "version_id": version["version_id"], "manifest": saved}, subject)
        return version

    version = register()
    yield SimpleNamespace(store=store, records=records, imports=imports, documents=documents,
                          config=config, version=version, register=register, root=tmp_path)
    store.close()


def save(fixture, pages=None, **kwargs):
    return fixture.documents.save_document_text(
        "synthetic_subject", fixture.version["version_id"], fixture.version["source_sha256"],
        pages or [{"page": 1, "text": "Synthetic exact text\r\n"}],
        kwargs.pop("method", "model_vision"), **kwargs)


def assert_code(code, function):
    with pytest.raises(V2Error) as failure:
        function()
    assert failure.value.code == code


def inventory(fixture):
    return {kind: fixture.store.list(kind, "synthetic_subject")
            for kind in ("document_transcript", "document_transcript_chunk", "idempotency")}


def test_exact_text_blank_pages_null_model_and_lossless_pagination(fixture):
    pages = [{"page": 1, "text": " \r\nСинтетика 👩🏽‍🔬\t\x00e\u0301\n"},
             {"page": 2, "text": ""}, {"page": 3, "text": "third\n\n "}]
    ack = save(fixture, pages, idempotency_key="synthetic-retry")
    assert ack["transcript_id"].startswith("case_")
    assert ack["model"] is None
    assert ack["human_verified"] is False
    assert ack["source_extent"] == ack["review_status"] == "unverified"
    retrieved = []
    offset = 0
    while offset is not None:
        result = fixture.documents.get_document_text("synthetic_subject", ack["transcript_id"], offset, 1)
        retrieved.extend(result["pages"])
        offset = result["next_offset"]
    assert retrieved == pages
    assert fixture.documents.get_document_text("synthetic_subject", ack["transcript_id"], limit=500)["pages"] == pages
    assert save(fixture, pages, idempotency_key="synthetic-retry") == ack
    assert len(fixture.store.list("document_transcript", "synthetic_subject")) == 1


def test_large_page_survives_store_object_limit_and_utf8_boundaries(fixture):
    text = ("🚀Ж\x00\n" * 320000) + "trailing\r\n "
    assert 2 * 1024 * 1024 < len(text.encode()) < MAX_TEXT_BYTES
    ack = save(fixture, [{"page": 1, "text": text}])
    assert fixture.documents.get_document_text("synthetic_subject", ack["transcript_id"])["pages"] == [{"page": 1, "text": text}]
    chunks = fixture.store.list("document_transcript_chunk", "synthetic_subject")
    assert len(chunks) > 1
    assert all(chunk["chunk_id"].startswith("case_") for chunk in chunks)


def test_exact_8_mib_limit_is_stored_without_truncation(fixture):
    text = "x" * MAX_TEXT_BYTES
    ack = save(fixture, [{"page": 1, "text": text}])
    result = fixture.documents.get_document_text("synthetic_subject", ack["transcript_id"], limit=500)
    assert result["text_bytes"] == MAX_TEXT_BYTES
    assert result["pages"][0]["text"] == text


@pytest.mark.parametrize("pages,code", [
    ([], "DOCUMENT_TEXT_LIMIT"),
    ([{"page": 1, "text": "x"}] * 501, "DOCUMENT_TEXT_LIMIT"),
    ([{"page": 1, "text": "x" * (MAX_TEXT_BYTES + 1)}], "DOCUMENT_TEXT_LIMIT"),
    ([{"page": 2, "text": "x"}], "INVALID_DOCUMENT_TEXT"),
    ([{"page": True, "text": "x"}], "INVALID_DOCUMENT_TEXT"),
    ([{"page": 1, "text": "x", "human_verified": True}], "INVALID_DOCUMENT_TEXT"),
    ([{"page": 1, "text": None}], "INVALID_DOCUMENT_TEXT"),
    ([{"page": 1, "text": "\ud800"}], "INVALID_DOCUMENT_TEXT"),
])
def test_invalid_input_or_overflow_writes_nothing(fixture, pages, code):
    before = inventory(fixture)
    assert_code(code, lambda: fixture.documents.save_document_text(
        "synthetic_subject", fixture.version["version_id"], fixture.version["source_sha256"], pages,
        "model_vision", idempotency_key="must-not-write"))
    assert inventory(fixture) == before


@pytest.mark.parametrize("method,model", [("native_pdf_text", None), ("OCR", None),
                                         ([], None), ("manual_transcription", "invented-model"),
                                         ("model_vision", ""), ("model_vision", "x" * 201)])
def test_public_method_and_model_provenance_are_honest(fixture, method, model):
    assert_code("INVALID_DOCUMENT_TEXT", lambda: save(fixture, method=method, model=model))
    assert inventory(fixture) == {"document_transcript": [], "document_transcript_chunk": [], "idempotency": []}


def test_new_versions_preserved_and_idempotency_conflict_fails(fixture):
    old = save(fixture, idempotency_key="one-operation")
    assert_code("idempotency_conflict", lambda: save(fixture, [{"page": 1, "text": "changed"}], idempotency_key="one-operation"))
    newer = save(fixture, [{"page": 1, "text": "corrected proposal"}])
    assert newer["transcript_id"] != old["transcript_id"]
    assert len(fixture.store.list("document_transcript", "synthetic_subject")) == 2
    assert fixture.documents.get_document_text("synthetic_subject", old["transcript_id"])["pages"][0]["text"].endswith("\r\n")


def test_source_scope_hash_and_checker_required_for_new_transcript(fixture):
    version = fixture.version
    fixture.records.register_subject("other_subject", "Synthetic other")
    assert_code("WRONG_SUBJECT", lambda: fixture.documents.save_document_text(
        "other_subject", version["version_id"], version["source_sha256"], [{"page": 1, "text": "x"}], "model_vision"))
    assert_code("SOURCE_CHANGED", lambda: fixture.documents.save_document_text(
        "synthetic_subject", version["version_id"], "f" * 64, [{"page": 1, "text": "x"}], "model_vision"))
    fixture.records.source_checker = None
    assert_code("SOURCE_CHECKER_REQUIRED", lambda: save(fixture))
    fixture.records.source_checker = lambda version: False
    assert_code("SOURCE_CHANGED", lambda: save(fixture))
    assert inventory(fixture) == {"document_transcript": [], "document_transcript_chunk": [], "idempotency": []}


def test_history_and_exact_ack_remain_readable_after_saved_source_loss(fixture):
    ack = save(fixture, idempotency_key="durable-ack")
    view = fixture.documents.get_document_view("synthetic_subject", fixture.version["version_id"])
    os.unlink(view["verified_saved_source_path"])
    assert save(fixture, idempotency_key="durable-ack") == ack
    assert fixture.documents.get_document_text("synthetic_subject", ack["transcript_id"])["pages"][0]["text"] == "Synthetic exact text\r\n"
    assert_code("ORIGINAL_UNAVAILABLE", lambda: save(fixture, [{"page": 1, "text": "new proposal"}]))
    assert_code("ORIGINAL_UNAVAILABLE", lambda: fixture.documents.get_document_view("synthetic_subject", fixture.version["version_id"]))


def test_internal_native_helper_preserves_blank_inventory_and_plain_text_method(fixture):
    ack = fixture.documents._save_native_document_text("synthetic_subject", fixture.version["version_id"],
            fixture.version["source_sha256"], [{"page": 1, "text": "native"}, {"page": 2, "text": ""}])
    assert ack["method"] == "native_pdf_text"
    other = fixture.register(b"plain\ntext\r\n", "text/plain")
    ack = fixture.documents._save_native_document_text("synthetic_subject", other["version_id"],
            other["source_sha256"], [{"page": 1, "text": "plain\ntext\r\n"}], method="native_text")
    assert ack["method"] == "native_text"


def test_atomic_failure_rolls_back_chunks_header_and_ack(fixture, monkeypatch):
    original = fixture.store.put

    def broken(kind, *args, **kwargs):
        if kind == "document_transcript":
            raise V2Error("SYNTHETIC_FAILURE", "Synthetic publication failure")
        return original(kind, *args, **kwargs)

    monkeypatch.setattr(fixture.store, "put", broken)
    assert_code("SYNTHETIC_FAILURE", lambda: save(fixture, idempotency_key="atomic"))
    assert inventory(fixture) == {"document_transcript": [], "document_transcript_chunk": [], "idempotency": []}


def test_pure_recovery_validators_bind_kind_schema_hash_scope_and_links(fixture):
    ack = save(fixture)
    header = fixture.store.get("document_transcript", ack["transcript_id"], "synthetic_subject")
    chunks = fixture.store.list("document_transcript_chunk", "synthetic_subject")
    assert validate_document_transcript(header, object_id=ack["transcript_id"], subject_id="synthetic_subject") == header
    assert validate_document_transcript_chunk(chunks[0], object_id=chunks[0]["chunk_id"]) == chunks[0]
    assert validate_document_text_ack(ack, header) == ack
    assert_code("INVALID_DOCUMENT_TEXT", lambda: validate_document_text_ack({**ack, "human_verified": True}, header))
    assert validate_document_transcript_links(header, fixture.version, chunks) == [{"page": 1, "text": "Synthetic exact text\r\n"}]
    assert_code("INVALID_DOCUMENT_TEXT", lambda: validate_document_transcript(chunks[0]))
    assert_code("INVALID_DOCUMENT_TEXT", lambda: validate_document_transcript_chunk(header))
    assert_code("WRONG_SUBJECT", lambda: validate_document_transcript(header, subject_id="other"))
    assert_code("INVALID_DOCUMENT_TEXT", lambda: validate_document_transcript_links(header, fixture.version, []))
    assert_code("INVALID_DOCUMENT_TEXT", lambda: validate_document_transcript_links(header, {**fixture.version, "source_sha256": "a" * 64}, chunks))
    changed = copy.deepcopy(chunks)
    changed[0]["text"] = "tampered"
    assert_code("INVALID_DOCUMENT_TEXT", lambda: validate_document_transcript_links(header, fixture.version, changed))
    for key, value in (("human_verified", True), ("source_extent", "all_pages_verified"),
                       ("extra", True), ("request_sha256", "f" * 64)):
        assert_code("INVALID_DOCUMENT_TEXT", lambda key=key, value=value: validate_document_transcript({**header, key: value}))


def test_missing_chunk_does_not_get_healed_by_retry(fixture):
    ack = save(fixture)
    chunk = fixture.store.list("document_transcript_chunk", "synthetic_subject")[0]
    fixture.store._db.execute("DELETE FROM v2_objects WHERE kind=? AND object_id=?",
                             ("document_transcript_chunk", chunk["chunk_id"]))
    assert_code("NOT_FOUND", lambda: save(fixture))
    assert fixture.store.list("document_transcript_chunk", "synthetic_subject") == []


def test_getter_rejects_scope_pagination_and_keeps_full_pages(fixture):
    ack = save(fixture)
    assert_code("WRONG_SUBJECT", lambda: fixture.documents.get_document_text("other_subject", ack["transcript_id"]))
    for offset, limit in ((-1, 1), (True, 1), (0, 0), (0, 501)):
        assert_code("INVALID_PAGINATION", lambda: fixture.documents.get_document_text("synthetic_subject", ack["transcript_id"], offset, limit))


def test_list_attempts_is_paginated_scoped_metadata_and_needs_no_source(fixture):
    first = save(fixture)
    second = save(fixture, [{"page": 1, "text": "second"}])
    view = fixture.documents.get_document_view("synthetic_subject", fixture.version["version_id"])
    os.unlink(view["verified_saved_source_path"])
    page = fixture.documents.list_document_texts("synthetic_subject", fixture.version["version_id"], limit=1)
    assert page["total"] == 2 and page["next_offset"] == 1
    assert page["transcripts"][0]["transcript_id"] == first["transcript_id"]
    assert "pages" not in page["transcripts"][0]
    following = fixture.documents.list_document_texts("synthetic_subject", fixture.version["version_id"], offset=1)
    assert following["transcripts"][0]["transcript_id"] == second["transcript_id"]
    assert following["next_offset"] is None


def test_get_view_is_readonly_prepare_copy_has_extension_and_never_overwrites(fixture):
    source = fixture.imports.originals.verified_path("synthetic_subject", fixture.imports._saved_manifest(fixture.version), fixture.version)
    before = source.stat()
    view = fixture.documents.get_document_view("synthetic_subject", fixture.version["version_id"])
    assert view["verified_view_path"] is None
    assert not (fixture.root / "private" / "document-views").exists()
    prepared = fixture.documents.prepare_document_view("synthetic_subject", fixture.version["version_id"])
    path = Path(prepared["verified_view_path"])
    assert path.suffix == ".pdf" and path.read_bytes() == PDF
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    inode = path.stat().st_ino
    assert fixture.documents.prepare_document_view("synthetic_subject", fixture.version["version_id"])["verified_view_path"] == str(path)
    assert path.stat().st_ino == inode
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (source.stat().st_ino, source.stat().st_mtime_ns, source.stat().st_ctime_ns)
    os.chmod(path, 0o600)
    path.write_bytes(b"tampered")
    assert_code("VIEW_INTEGRITY_FAILURE", lambda: fixture.documents.prepare_document_view("synthetic_subject", fixture.version["version_id"]))
    assert path.read_bytes() == b"tampered"


@pytest.mark.parametrize("which", ["directory", "view"])
def test_view_symlink_scope_is_rejected(fixture, which):
    outside = fixture.root / "outside"
    outside.mkdir()
    if which == "directory":
        (fixture.root / "private" / "document-views").symlink_to(outside, target_is_directory=True)
    else:
        path = fixture.documents._view_path(fixture.version)
        path.parent.mkdir(mode=0o700)
        outside_file = outside / "never-overwrite.pdf"
        outside_file.write_bytes(b"outside")
        path.symlink_to(outside_file)
    with pytest.raises(V2Error):
        fixture.documents.prepare_document_view("synthetic_subject", fixture.version["version_id"])
    assert not list(outside.glob(".staging-*"))


def test_enforced_runtime_returns_saved_view_limitation_without_renderer_or_writes(fixture, monkeypatch):
    fixture.config.isolation = "macos_enforced"
    monkeypatch.setattr("health_analyzer.local_documents.render_local_pdf", lambda *args, **kwargs: pytest.fail("must not render"))
    result = fixture.documents.render_document_pages("synthetic_subject", fixture.version["version_id"])
    assert result["render_status"] == "explicit_local_render_required"
    assert Path(result["verified_saved_source_path"]).read_bytes() == PDF
    assert not (fixture.root / "private" / "document-previews").exists()
    assert not (fixture.root / "private" / "document-views").exists()
    prepared = fixture.documents.prepare_document_view("synthetic_subject", fixture.version["version_id"])
    assert Path(prepared["verified_view_path"]).suffix == ".pdf"


def synthetic_renderer(path, output, *, dpi, isolation):
    assert Path(path).read_bytes() == PDF and Path(path).suffix == ".pdf"
    assert isolation == "host"
    directory = Path(output) / "local-pdf-render-synthetic"
    directory.mkdir(mode=0o700)
    pages = []
    for page in (1, 2):
        content = b"synthetic-image-page-" + str(page).encode()
        image = directory / f"page-{page:04d}.png"
        image.write_bytes(content)
        pages.append({"page": page, "path": str(image), "sha256": hashlib.sha256(content).hexdigest(),
                      "byte_size": len(content), "width": 1, "height": 1})
    return {"sha256": hashlib.sha256(PDF).hexdigest(), "render_directory": str(directory),
            "page_count": 2, "pages": pages, "total_bytes": sum(page["byte_size"] for page in pages),
            "dpi_requested": dpi, "isolation": {"mode": "host", "os_no_network_guarantee": False}}


def test_render_mock_saves_complete_page_and_sha_manifest_in_owned_root(fixture, monkeypatch):
    monkeypatch.setattr("health_analyzer.local_documents.render_local_pdf", synthetic_renderer)
    first = fixture.documents.render_document_pages("synthetic_subject", fixture.version["version_id"])
    second = fixture.documents.render_document_pages("synthetic_subject", fixture.version["version_id"])
    assert first["manifest_path"] != second["manifest_path"]
    manifest = Path(first["manifest_path"])
    assert manifest.is_relative_to(fixture.root / "private" / "document-previews")
    assert json.loads(manifest.read_bytes()) == first
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o400
    assert [page["page"] for page in first["render"]["pages"]] == [1, 2]
    assert first["render"]["isolation"]["os_no_network_guarantee"] is False


def test_render_incomplete_inventory_fails_and_removes_only_own_render(fixture, monkeypatch):
    def incomplete(*args, **kwargs):
        result = synthetic_renderer(*args, **kwargs)
        result["pages"].pop()
        return result
    monkeypatch.setattr("health_analyzer.local_documents.render_local_pdf", incomplete)
    assert_code("INVALID_PREVIEW", lambda: fixture.documents.render_document_pages("synthetic_subject", fixture.version["version_id"]))
    assert list((fixture.root / "private" / "document-previews").iterdir()) == []
    assert Path(fixture.documents.get_document_view("synthetic_subject", fixture.version["version_id"])["verified_view_path"]).read_bytes() == PDF


def test_preview_root_symlink_rejected_without_outside_write(fixture, monkeypatch):
    outside = fixture.root / "outside-render"
    outside.mkdir()
    (fixture.root / "private" / "document-previews").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr("health_analyzer.local_documents.render_local_pdf", lambda *a, **k: pytest.fail("unsafe root"))
    assert_code("UNSAFE_PREVIEW_PATH", lambda: fixture.documents.render_document_pages("synthetic_subject", fixture.version["version_id"]))
    assert list(outside.iterdir()) == []
