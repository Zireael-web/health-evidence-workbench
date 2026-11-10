"""Document transport/recovery proof over explicit, owned fictional inputs.

The actual native-parser/Poppler proof is opt-in with HA_DOCUMENT_IO_PROOF set
to a fresh nonexistent exercise directory. Default tests never launch parsers.
Manual transcript fixtures are simulated text, with no model or human review.
"""
from __future__ import annotations

import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from health_analyzer.v2 import cli
from health_analyzer.v2.common import SignedStore, V2Error, canonical
from health_analyzer.v2.document_io import DocumentIOService
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.recovery import SyntheticRecovery, SyntheticStore, TestKey
from test_a16_transport_recovery import ActualTransport, ActualMCP, save, state_hashes


SUBJECT = "fictional_document_transport"
CORE_FILES = ("ingest.py", "attachments.py", "document_io.py", "runtime.py", "cli.py", "recovery.py")


def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _code_hashes():
    directory = cli.code_root() / "src/health_analyzer/v2"
    return {name: _sha((directory / name).read_bytes()) for name in CORE_FILES} | {
        name: _sha((directory.parent / name).read_bytes())
        for name in ("local_documents.py", "local_document_entry.py")}


def _fictional_pdf():
    pypdf = pytest.importorskip("pypdf")
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject
    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"):
        DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
    stream = DecodedStreamObject()
    stream.set_data(b"BT /F1 12 Tf 72 720 Td (FICTIONAL DOCUMENT TRANSPORT - native ASCII text) Tj ET")
    page[NameObject("/Contents")] = writer._add_object(stream)
    writer.add_blank_page(width=612, height=792)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def _long_pages(suffix=""):
    text = ("SIMULATED MANUAL TRANSCRIPTION - fictional text only\r\n" * 47000) + suffix
    return [{"page": 1, "text": text}, {"page": 2, "text": ""}]


def _long_table_text():
    return "analyte;result\n" + "".join(f"Fictional {number} {'x' * 500};1\n" for number in range(600))


@pytest.mark.parametrize("domain,tool,large", [
    ("private-data", "save_document_text", True),
    ("public-research", "save_document_text", False),
    ("private-data", "prepare_attachment", False),
    ("private-data", "submit_visual_transcription", False),
    ("public-research", "record_finding", False),
])
def test_cli_large_input_limit_is_scoped_to_private_full_transcript(tmp_path, domain, tool, large):
    path = tmp_path / "fictional-arguments.json"
    payload = {"pages": _long_pages()}
    encoded = canonical(payload)
    assert 2 * 1024 * 1024 < len(encoded) < 16 * 1024 * 1024
    path.write_bytes(encoded)
    limit = cli._request_limit(domain, tool)
    assert limit == (16 if large else 2) * 1024 * 1024
    if large:
        assert cli._input_json(path, limit=limit) == payload
    else:
        with pytest.raises(V2Error):
            cli._input_json(path, limit=limit)


def test_recovery_reconstructs_complete_transcript_graph_without_original_access(tmp_path):
    root = tmp_path / "fictional-document-recovery"
    create_synthetic_exercise(root)
    key = TestKey("test_fictional_document_key", b"fictional-local-test-key-only!" * 2)
    store = SignedStore(root / "private.sqlite3", key.material, "private-data")
    records = RecordsService(store)
    records.register_subject(SUBJECT, "Fictional document profile")
    content = b"%PDF-1.4\nfictional bytes; not parsed\n%%EOF\n"
    version = records.register_document(SUBJECT, _sha(content), "application/pdf", len(content))
    config = SimpleNamespace(data_root=root, isolation="host", archive_roots={})
    imports = ImportService(config, records)
    manifest = imports.originals.preserve(SUBJECT, content, "application/pdf")
    store.put("original_manifest", imports._manifest_id(version),
              {"subject_id": SUBJECT, "version_id": version["version_id"], "manifest": manifest}, SUBJECT)
    documents = DocumentIOService(config, records, imports)
    pages = _long_pages()
    ack = documents.save_document_text(SUBJECT, version["version_id"], version["source_sha256"],
                                      pages, "manual_transcription", idempotency_key="fictional-recovery")
    store._db.execute("PRAGMA journal_mode=DELETE")
    store.close()
    recovery = SyntheticRecovery(root, test_keys={key.key_id: key})
    spec = SyntheticStore("private", root / "private.sqlite3", "private-data", key.key_id)
    backup = root / "bundle"
    recovery.create_backup(backup, [spec], source_generation="fictional_document_graph")
    restored = recovery.restore_bundle(backup, root / "restored")
    reader = SignedStore(restored["stores"][0]["path"], key.material, "private-data", readonly=True)
    try:
        restored_records = RecordsService(reader)
        restored_imports = ImportService(config, restored_records)
        def no_source(_version):
            pytest.fail("Transcript history attempted original-source access")
        restored_records.source_checker = no_source
        restored_documents = DocumentIOService(config, restored_records, restored_imports)
        assert restored_documents.get_document_text(SUBJECT, ack["transcript_id"])["pages"] == pages
        assert len(reader.list("document_transcript_chunk", SUBJECT)) > 1
    finally:
        reader.close()


def test_configured_text_import_retains_full_native_text_beyond_preview(tmp_path):
    archive = tmp_path / "fictional-configured-inputs"
    archive.mkdir(mode=0o700)
    text = _long_table_text()
    assert len(text.encode()) > 256 * 1024
    path = archive / "fictional-long.txt"
    path.write_text(text)
    store = SignedStore(tmp_path / "private" / "private.sqlite3", b"fictional-test-key" * 3, "private-data")
    records = RecordsService(store)
    config = SimpleNamespace(data_root=tmp_path, isolation="host",
                             archive_roots={"fictional": {"path": archive, "subject_id": SUBJECT}})
    imports = ImportService(config, records)
    try:
        imported = imports.prepare_import(SUBJECT, [{"root_id": "fictional", "relative_path": path.name}])
        doc = imported["documents"][0]
        assert len(doc["draft_ids"]) == 600
        assert len(doc["document_texts"]) == 1
        documents = DocumentIOService(config, records, imports)
        assert documents.get_document_text(SUBJECT, doc["document_texts"][0]["transcript_id"])["pages"] == [
            {"page": 1, "text": text}]
        assert path.read_text() == text
        assert records.query_history(SUBJECT)["current"] == []
    finally:
        store.close()


@pytest.mark.skipif(not os.environ.get("HA_DOCUMENT_IO_PROOF"), reason="Explicit opt-in real local PDF/PNG proof")
def test_actual_document_cli_mcp_full_text_view_render_and_recovery():
    pytest.importorskip("mcp")
    root = Path(os.environ["HA_DOCUMENT_IO_PROOF"]).absolute()
    create_synthetic_exercise(root)
    code_before = _code_hashes()
    inputs = root / "fictional-inputs"
    inputs.mkdir(mode=0o700)
    path = inputs / "fictional-two-page.pdf"
    path.write_bytes(_fictional_pdf())
    path.chmod(0o600)
    source_before = _sha(path.read_bytes())
    transport = ActualTransport(root)
    transport.run(["init", "--data-root", str(root / "state"), "--isolation", "host",
                   "--deployment-id", "fictional_document_proof"])
    configuration_before = transport.config.read_bytes()
    try:
        attachment = transport.call("prepare_attachment", {"subject_id": SUBJECT,
            "source_path": str(path), "idempotency_key": "fictional-attachment"})
    except AssertionError as failure:
        save(root / "receipts" / "blocker.json", {"stage": "actual_mandatory_native_pdf_intake",
             "failure": str(failure), "fallback_attempted": False, "simulation_only": True,
             "source_code_sha256": code_before})
        raise
    assert attachment["confirmed"] is False
    assert attachment["coverage"]["status"] != "complete"
    assert len(attachment["native_transcripts"]) == 1
    native = attachment["native_transcripts"][0]
    assert native["method"] == "native_pdf_text" and native["page_count"] == 2
    assert native["human_verified"] is False
    version = {"subject_id": SUBJECT, "version_id": attachment["version_id"]}
    source = transport.call("get_source_version", version)
    assert source["archive_sources"] == [] and source["saved_status"] == "available"
    original = Path(source["verified_saved_source_path"])
    assert _sha(original.read_bytes()) == source_before
    long_txt = inputs / "fictional-long-native.txt"
    long_txt.write_text(_long_table_text())
    long_txt_before = long_txt.read_bytes()
    txt_attachment = transport.call("prepare_attachment", {"subject_id": SUBJECT,
        "source_path": str(long_txt), "idempotency_key": "fictional-long-native-text"})
    txt_ref = txt_attachment["native_transcripts"][0]
    assert txt_ref["method"] == "native_text" and txt_ref["text_bytes"] > 256 * 1024
    txt_full = transport.call("get_document_text", {"subject_id": SUBJECT, "transcript_id": txt_ref["transcript_id"]})
    assert txt_full["pages"] == [{"page": 1, "text": long_txt_before.decode()}]
    pages = _long_pages()
    long_request = {**version, "source_sha256": source_before, "pages": pages,
                    "method": "manual_transcription", "idempotency_key": "fictional-long-cli"}
    assert 2 * 1024 * 1024 < len(canonical(long_request)) < cli.MAX_DOCUMENT_REQUEST_BYTES
    cli_ack = transport.call("save_document_text", long_request)
    mcp = ActualMCP(transport, "fictional-documents")
    try:
        names = {item["name"] for item in mcp.request("tools/list", {})["tools"]}
        private_tools = {"prepare_attachment", "save_document_text", "get_document_text", "list_document_texts",
                         "prepare_document_view", "get_document_view", "render_document_pages"}
        assert private_tools <= names
        native_full = mcp.call("get_document_text", {"subject_id": SUBJECT, "transcript_id": native["transcript_id"]})
        assert "FICTIONAL DOCUMENT TRANSPORT" in native_full["pages"][0]["text"]
        assert native_full["pages"][1] == {"page": 2, "text": ""}
        old = mcp.call("get_document_text", {"subject_id": SUBJECT, "transcript_id": cli_ack["transcript_id"]})
        assert old["pages"] == pages
        assert mcp.call("save_document_text", long_request) == cli_ack
        newer_pages = _long_pages("NEW SIMULATED MANUAL VERSION\n")
        mcp_request = {**long_request, "pages": newer_pages, "idempotency_key": "fictional-long-mcp"}
        mcp_ack = mcp.call("save_document_text", mcp_request)
        assert mcp_ack["transcript_id"] != cli_ack["transcript_id"]
        assert mcp.call("save_document_text", mcp_request) == mcp_ack
        view = mcp.call("prepare_document_view", version)
        pdf_view = Path(view["verified_view_path"])
        assert pdf_view.suffix == ".pdf" and _sha(pdf_view.read_bytes()) == source_before
        assert mcp.call("get_document_view", version)["verified_view_path"] == str(pdf_view)
        try:
            rendered = mcp.call("render_document_pages", {**version, "dpi": 72})
        except AssertionError as failure:
            save(root / "receipts" / "blocker.json", {"stage": "actual_pdf_to_png_render",
                 "failure": str(failure), "fallback_attempted": False, "simulation_only": True,
                 "source_code_sha256": code_before})
            raise
        assert rendered["render_status"] == "rendered"
        render = rendered["render"]
        assert render["sha256"] == source_before and render["page_count"] == 2
        assert [page["page"] for page in render["pages"]] == [1, 2]
        png_hashes = []
        for page in render["pages"]:
            png = Path(page["path"]).read_bytes()
            assert png.startswith(b"\x89PNG\r\n\x1a\n")
            assert len(png) == page["byte_size"] and _sha(png) == page["sha256"]
            png_hashes.append(page["sha256"])
        assert png_hashes[0] != png_hashes[1]
    finally:
        mcp.close()
    assert mcp.process.returncode == 0
    for ack, expected in ((cli_ack, pages), (mcp_ack, newer_pages)):
        read = transport.call("get_document_text", {"subject_id": SUBJECT, "transcript_id": ack["transcript_id"]})
        assert read["pages"] == expected
        assert read["human_verified"] is False and read["review_status"] == "unverified"
    assert transport.call("save_document_text", long_request) == cli_ack
    assert transport.call("save_document_text", mcp_request) == mcp_ack
    discovered = transport.call("list_document_texts", version)
    assert {item["transcript_id"] for item in discovered["transcripts"]} == {
        native["transcript_id"], cli_ack["transcript_id"], mcp_ack["transcript_id"]}
    assert transport.call("get_document_view", version)["verified_view_path"] == str(pdf_view)
    transport.call("save_document_text", long_request, zone="public-research", expected=2)
    for tool, arguments in (
        ("prepare_attachment", {"subject_id": SUBJECT, "source_path": str(path)}),
        ("get_document_text", {"subject_id": SUBJECT, "transcript_id": cli_ack["transcript_id"]}),
        ("list_document_texts", version), ("get_document_view", version),
        ("prepare_document_view", version), ("render_document_pages", version),
    ):
        transport.call(tool, arguments, zone="public-research", expected=2)
    transport.call("review_answer", {"draft": {"intent": "educational", "claims": [
        {"claim_id": "fictional_private_id_canary", "type": "source_finding", "text": "Fictional canary",
         "support_ids": [cli_ack["transcript_id"]]}]}}, zone="public-research", expected=2)
    config = cli.load_config(transport.config)
    assert config.archive_roots == {} and config.isolation == "host"
    public = SignedStore(config.store_path("public-research"), config.key_path("public-research").read_bytes(),
                         "public-research", readonly=True)
    try:
        assert public._db.execute("SELECT COUNT(*) FROM v2_objects").fetchone()[0] == 0
    finally:
        public.close()
    key = TestKey("test_fictional_document_generated", config.key_path("private-data").read_bytes())
    private_path = config.store_path("private-data")
    writer = SignedStore(private_path, key.material, "private-data")
    assert writer.list("observation_revision", SUBJECT) == []
    assert writer.list("file_occurrence", SUBJECT) == []
    writer._db.execute("PRAGMA journal_mode=DELETE")
    writer.close()
    recovery = SyntheticRecovery(root, test_keys={key.key_id: key})
    spec = SyntheticStore("private", private_path, "private-data", key.key_id)
    before_backup = state_hashes(private_path)
    backup = root / "recovery-bundle"
    manifest = recovery.create_backup(backup, [spec], source_generation="fictional_document_transport")
    assert state_hashes(private_path) == before_backup
    restored = recovery.restore_bundle(backup, root / "recovered")
    restored_store = SignedStore(restored["stores"][0]["path"], key.material, "private-data", readonly=True)
    try:
        records = RecordsService(restored_store)
        imports = ImportService(config, records)
        documents = DocumentIOService(config, records, imports)
        assert documents.get_document_text(SUBJECT, cli_ack["transcript_id"])["pages"] == pages
        assert documents.get_document_text(SUBJECT, mcp_ack["transcript_id"])["pages"] == newer_pages
    finally:
        restored_store.close()
    assert "not_included" in manifest["originals"]
    assert path.read_bytes() == original.read_bytes() == pdf_view.read_bytes()
    assert _sha(path.read_bytes()) == source_before
    assert long_txt.read_bytes() == long_txt_before
    assert transport.config.read_bytes() == configuration_before
    assert _code_hashes() == code_before, "Core implementation changed during this retained proof"
    save(root / "receipts" / "summary.json", {
        "simulation_only": True, "actual_cli": True, "actual_stdio_mcp": True,
        "actual_native_pdf_text": True, "actual_pdf_to_png_render": True, "render_page_count": 2,
        "source_pdf_sha256": source_before, "viewer_pdf_sha256": _sha(pdf_view.read_bytes()),
        "render_png_sha256": png_hashes, "render_manifest_path": rendered["manifest_path"],
        "native_text_pages_sha256": _sha(canonical(native_full["pages"])),
        "native_txt_sha256": _sha(long_txt_before), "native_txt_bytes": len(long_txt_before),
        "cli_transcript_pages_sha256": _sha(canonical(pages)),
        "mcp_transcript_pages_sha256": _sha(canonical(newer_pages)),
        "transcript_text_bytes": cli_ack["text_bytes"], "cli_json_request_bytes": len(canonical(long_request)),
        "full_text_lossless_across_cli_mcp": True, "old_transcript_retained": True,
        "public_new_private_operations_denied": True, "public_private_text_id_denied": True,
        "public_persisted_object_count": 0, "recovery_complete_transcript_graph": True,
        "source_unchanged": True, "configuration_unchanged": True, "archive_bindings_created": False,
        "mcp_graceful_exit_returncode": mcp.process.returncode, "ocr_used": False,
        "isolation": "host_logical_only; native PDF geometry retains mandatory nested sandbox",
        "benchmark": "0/72", "source_code_sha256": code_before,
    })
