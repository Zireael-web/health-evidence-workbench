"""Independent engineering scenarios over fresh artificial documents only."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace
import urllib.request

import pytest

from health_analyzer.v2 import ingest, pdf_geometry, vision
from health_analyzer.v2.attachments import AttachmentService
from health_analyzer.v2.common import SignedStore, V2Error, digest
from health_analyzer.v2.configuration import DeploymentConfig
from health_analyzer.v2.document_io import DocumentIOService
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.recovery import SyntheticRecovery
from health_analyzer.v2.runtime import open_services


@pytest.fixture
def env(tmp_path, monkeypatch):
    def no_external_execution(*args, **kwargs):
        pytest.fail("This document scenario must not start OCR, a model, a process, or a network request")

    monkeypatch.setattr(subprocess, "Popen", no_external_execution)
    monkeypatch.setattr(socket, "create_connection", no_external_execution)
    monkeypatch.setattr(urllib.request, "urlopen", no_external_execution)
    data = tmp_path / "synthetic-data"
    data.mkdir(mode=0o700)
    config = DeploymentConfig(tmp_path / "synthetic-config.json", "independent_synthetic", data, "host", {})
    store = SignedStore(config.store_path("private-data"), b"independent-synthetic-only-key!!!" * 2, "private-data")
    records = RecordsService(store)
    imports = ingest.ImportService(config, records)
    documents = DocumentIOService(config, records, imports)
    attachments = AttachmentService(config, records, imports, documents)
    yield SimpleNamespace(config=config, store=store, records=records, imports=imports,
                          documents=documents, attachments=attachments, root=tmp_path)
    store.close()


def selected(env, name="selected.csv", content=b"analyte;result;unit\nSynthetic;1;u\n"):
    path = env.root / name
    path.write_bytes(content)
    return path


def attach(env, path=None, key=""):
    return env.attachments.prepare_attachment("synthetic_a", str(path or selected(env)), key)


def text(env, ack):
    return env.documents.get_document_text("synthetic_a", ack["transcript_id"])


def objects(env):
    return [{"kind": kind, "object_id": object_id, "subject_id": subject, "payload": json.loads(payload)}
            for kind, object_id, subject, payload in env.store._db.execute(
                "SELECT kind,object_id,subject_id,payload FROM v2_objects ORDER BY rowid")]


def inventory(env):
    return env.store._db.execute("SELECT kind,object_id,payload FROM v2_objects ORDER BY rowid").fetchall()


def test_direct_file_intake_yields_exact_original_text_view_and_unconfirmed_rows(env):
    source = selected(env, content="analyte;result;unit\r\nСинтетический;1,25;мкмоль/л\r\n".encode())
    before = source.read_bytes(), source.stat().st_mode, source.stat().st_mtime_ns
    result = attach(env, source, "new-selection")
    assert (source.read_bytes(), source.stat().st_mode, source.stat().st_mtime_ns) == before
    assert Path(result["source_view"]["verified_saved_source_path"]).read_bytes() == before[0]
    view = Path(result["source_view"]["verified_view_path"])
    assert view.suffix == ".csv" and view.read_bytes() == before[0]
    assert text(env, result["native_transcripts"][0])["pages"] == [{"page": 1, "text": before[0].decode()}]
    assert result["source_sha256"] == hashlib.sha256(before[0]).hexdigest()
    assert result["confirmed"] is False and result["verification"] == "unverified"
    assert len(result["draft_ids"]) == 1
    assert env.records.query_history("synthetic_a")["current"] == []
    assert env.config.archive_roots == {} and env.store.list("file_occurrence", "synthetic_a") == []


def test_dialogue_text_above_preview_budget_is_lossless_and_does_not_upgrade_trust(env):
    env.imports.pdf_extractor = lambda _: ([], ["Synthetic PDF requires dialogue transcription"])
    result = attach(env, selected(env, "selected.pdf", b"%PDF-1.4\nsynthetic"))
    exact = " \r\n" + ("Ж🚀e\u0301\t\x00\n" * 40000) + "trailing  \r\n"
    pages = [{"page": 1, "text": exact}, {"page": 2, "text": ""}, {"page": 3, "text": "end\n"}]
    assert len(exact.encode()) > 256 * 1024
    saved = env.documents.save_document_text("synthetic_a", result["version_id"], result["source_sha256"],
                                            pages, "model_vision", model=None, idempotency_key="dialogue")
    full = text(env, saved)
    assert full["pages"] == pages
    assert full["text_bytes"] == sum(len(page["text"].encode()) for page in pages)
    assert len(env.store.list("document_transcript_chunk", "synthetic_a")) > 1
    assert full["model"] is None and full["human_verified"] is False
    assert full["review_status"] == full["source_extent"] == "unverified"
    assert env.records.query_history("synthetic_a")["current"] == []


def test_archive_native_text_is_saved_before_preview_clipping_and_keeps_blank_page(env):
    archive = env.root / "synthetic-archive"
    archive.mkdir(mode=0o700)
    (archive / "native.pdf").write_bytes(b"%PDF-1.4\nsynthetic only")
    env.config.archive_roots["synthetic"] = {"path": archive, "subject_id": "synthetic_a"}
    # Synthetic native text with valid rows exercises the real import path,
    # including row parsing and response clipping, without a PDF decoder.
    exact = "analyte;result\n" + "".join(f"{'Ж' * 225}{index};1\n" for index in range(600))
    assert len(exact.encode()) > 256 * 1024
    env.imports.pdf_extractor = lambda _: ([
        {"page": 1, "text": exact, "document_incomplete": True},
        {"page": 2, "text": "", "document_incomplete": True}], ["Synthetic native text"])
    result = env.imports.prepare_import("synthetic_a", [{"root_id": "synthetic", "relative_path": "native.pdf"}])["documents"][0]
    assert result["native_preview_truncated"] is True
    assert sum(len(section["text"].encode()) for section in result["native_text"]) <= 256 * 1024
    saved = text(env, result["document_texts"][0])
    assert saved["pages"] == [{"page": 1, "text": exact}, {"page": 2, "text": ""}]
    assert saved["method"] == "native_pdf_text" and saved["human_verified"] is False
    run = env.store.get("extraction_run", result["run_id"], "synthetic_a")
    assert run["coverage"]["unprocessed_pages"] == [2]
    assert run["coverage"]["status"] == "partial"


def test_prior_document_history_and_exact_retry_survive_all_source_copies_disappearing(env):
    source = selected(env)
    old = attach(env, source, "old-selection")
    old_text = text(env, old["native_transcripts"][0])
    source.write_bytes(b"analyte;result;unit\nSynthetic;2;u\n")
    newer = attach(env, source, "new-selection")
    assert newer["version_id"] != old["version_id"]
    assert text(env, old["native_transcripts"][0]) == old_text
    source.unlink()
    Path(old["source_view"]["verified_saved_source_path"]).unlink()
    Path(old["source_view"]["verified_view_path"]).unlink()
    assert attach(env, source, "old-selection") == old
    assert text(env, old["native_transcripts"][0]) == old_text
    assert env.documents.list_document_texts("synthetic_a", old["version_id"])["total"] == 1
    with pytest.raises(V2Error):
        env.documents.get_document_view("synthetic_a", old["version_id"])
    assert env.records.query_history("synthetic_a")["current"] == []


def test_wrong_subject_hash_and_symlink_fail_without_new_state(env):
    result = attach(env)
    env.records.register_subject("synthetic_b", "Artificial alternate")
    before = inventory(env)
    for subject, source_hash in (("synthetic_b", result["source_sha256"]), ("synthetic_a", "f" * 64)):
        with pytest.raises(V2Error):
            env.documents.save_document_text(subject, result["version_id"], source_hash,
                                              [{"page": 1, "text": "proposal"}], "manual_transcription")
    with pytest.raises(V2Error):
        env.documents.get_document_text("synthetic_b", result["native_transcripts"][0]["transcript_id"])
    linked = env.root / "linked.csv"
    linked.symlink_to(env.root / "selected.csv")
    directory = env.root / "linked-parent"
    directory.symlink_to(env.root, target_is_directory=True)
    for path in (linked, directory / "selected.csv"):
        with pytest.raises(V2Error):
            env.attachments.prepare_attachment("synthetic_a", str(path), "forbidden")
    assert inventory(env) == before


def test_local_ocr_is_disabled_directly_and_never_used_as_image_or_pdf_fallback(env, monkeypatch):
    for call in (lambda: vision.prepare_native_helper(env.root / "must-not-exist"),
                 lambda: vision.extract_image(b"synthetic", helper_path=env.root / "helper"),
                 lambda: vision.extract_pdf_ocr(b"synthetic", helper_path=env.root / "helper")):
        with pytest.raises(V2Error) as failure:
            call()
        assert failure.value.code == "LOCAL_OCR_DISABLED"
    image = attach(env, selected(env, "selected.jpg", b"\xff\xd8\xffsynthetic"))
    assert image["coverage"]["status"] == "visual_required"
    assert image["coverage"]["unprocessed_pages"] == [1]
    monkeypatch.setattr(pdf_geometry, "extract_pdf_geometry", lambda _: None)
    monkeypatch.setattr(ingest, "_extract_pdf_text", lambda _: ([], ["No native text"]))
    pdf = attach(env, selected(env, "selected.pdf", b"%PDF-1.4\nsynthetic"))
    assert pdf["coverage"]["status"] == "visual_required" and pdf["native_transcripts"] == []
    assert not (env.root / "must-not-exist").exists()


def test_private_runtime_is_the_only_tool_surface_and_callers_cannot_claim_native_or_verified(env):
    private = open_services(env.config, "private-data", b"independent-synthetic-only-key!!!" * 2)
    public = open_services(env.config, "public-research", b"independent-public-test-key-only!" * 2)
    try:
        result = private.call("prepare_attachment", {"subject_id": "synthetic_a", "source_path": str(selected(env))})
        arguments = {"subject_id": "synthetic_a", "version_id": result["version_id"],
                     "source_sha256": result["source_sha256"], "pages": [{"page": 1, "text": "proposal"}],
                     "method": "native_pdf_text"}
        with pytest.raises(V2Error) as failure:
            private.call("save_document_text", arguments)
        assert failure.value.code == "INVALID_DOCUMENT_TEXT"
        arguments.update(method="model_vision", human_verified=True)
        with pytest.raises(V2Error) as failure:
            private.call("save_document_text", arguments)
        assert failure.value.code == "arguments_invalid"
        for name in ("prepare_attachment", "save_document_text", "get_document_text", "get_document_view", "render_document_pages"):
            with pytest.raises(V2Error) as failure:
                public.call(name, {})
            assert failure.value.code == "tool_unavailable"
        assert "_save_native_document_text" not in private.tools
    finally:
        public.close()
        private.close()
    readonly = open_services(env.config, "private-data", b"independent-synthetic-only-key!!!" * 2, readonly=True)
    try:
        assert {"get_document_text", "list_document_texts", "get_document_view"} <= set(readonly.tools)
        assert not {"prepare_attachment", "save_document_text", "prepare_document_view", "render_document_pages"} & set(readonly.tools)
    finally:
        readonly.close()


def test_pure_recovery_validates_full_graph_after_source_loss_and_rejects_semantic_forgery(env, monkeypatch):
    source = selected(env)
    result = attach(env, source, "recover-attachment")
    env.documents.save_document_text("synthetic_a", result["version_id"], result["source_sha256"],
                                     [{"page": 1, "text": "Unverified dialogue Ж🚀"}], "model_vision", idempotency_key="recover-text")
    graph = objects(env)
    source.unlink()
    Path(result["source_view"]["verified_saved_source_path"]).unlink()
    Path(result["source_view"]["verified_view_path"]).unlink()
    monkeypatch.setattr(ingest, "read_source", lambda *_: pytest.fail("Pure recovery reopened a source"))
    monkeypatch.setattr(Path, "read_bytes", lambda *_: pytest.fail("Pure recovery read a source file"))
    SyntheticRecovery._links(graph, "private-data")
    # Rehash a modified chunk correctly while retaining the original header's
    # page digest. Aggregate source linkage must still reject the graph.
    forged = copy.deepcopy(graph)
    chunk = next(item for item in forged if item["kind"] == "document_transcript_chunk")
    old_id = chunk["object_id"]
    payload = chunk["payload"]
    payload["text"] = "Forged text"
    payload["text_bytes"] = len(payload["text"].encode())
    payload["text_sha256"] = hashlib.sha256(payload["text"].encode()).hexdigest()
    payload["chunk_id"] = "case_" + digest({key: value for key, value in payload.items() if key != "chunk_id"})
    chunk["object_id"] = payload["chunk_id"]
    for item in forged:
        if item["kind"] == "document_transcript":
            for page in item["payload"]["pages"]:
                page["chunk_ids"] = [payload["chunk_id"] if value == old_id else value for value in page["chunk_ids"]]
    with pytest.raises(V2Error):
        SyntheticRecovery._links(forged, "private-data")
    for field, value in (("human_verified", True), ("source_extent", "verified"), ("review_status", "verified")):
        forged = copy.deepcopy(graph)
        next(item for item in forged if item["kind"] == "document_transcript")["payload"][field] = value
        with pytest.raises(V2Error):
            SyntheticRecovery._links(forged, "private-data")
    missing = [item for item in graph if item["kind"] != "document_transcript_chunk"]
    with pytest.raises(V2Error):
        SyntheticRecovery._links(missing, "private-data")
