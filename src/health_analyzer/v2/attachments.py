"""Explicit user-selected local files into the existing private review path.

This entry point creates no archive binding and never changes a source. Native
text is retained separately from typed row proposals. Images remain pending
visual transcription in the conversation; intake cannot confirm observations.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import re
from typing import Callable

from .common import SignedStore, V2Error, canonical, digest, new_id, require, utc_now
from .contracts import identifier, iso_timestamp
from .ingest import _text, read_source


ATTACHMENT_SCHEMA = "health-analyzer.attachment-preparation/1"
OPERATION = "prepare_attachment"
MIMES = {".csv": "text/csv", ".txt": "text/plain", ".pdf": "application/pdf",
         ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
RESULT_FIELDS = {"schema_version", "kind", "preparation_id", "subject_id", "request",
                 "request_sha256", "document_id", "version_id", "source_sha256", "mime", "size",
                 "run_id", "draft_ids", "panel_ids", "issue_ids", "coverage", "saved_original",
                 "source_view", "native_transcripts", "recognition_reused", "confirmed", "verification",
                 "prepared_at", "limitations", "preparation_sha256"}
TRANSCRIPT_REF_FIELDS = {"transcript_id", "subject_id", "version_id", "source_sha256",
                         "method", "model", "page_count", "text_bytes", "source_extent",
                         "review_status", "human_verified"}
Lookup = Callable[[str, str, str], dict]


def _selected_path(value: object) -> Path:
    """Validate syntax only; retry validation must not touch a vanished source."""
    require(isinstance(value, str) and 0 < len(value) <= 4096
            and "\x00" not in value and "\\" not in value,
            "INVALID_SOURCE_REF", "Select one bounded absolute local file path")
    path = Path(value)
    require(path.is_absolute() and value.startswith("/") and not value.startswith("//")
            and value == str(path) and path.name not in {"", ".", ".."}
            and all(part not in {".", ".."} for part in value.split("/")[1:]),
            "UNSAFE_PATH", "Select one direct absolute local file path")
    return path


def _request(subject_id: str, source_path: str) -> dict:
    identifier(subject_id, "subject_id")
    _selected_path(source_path)
    return {"subject_id": subject_id, "source_path": source_path}


def _mime(path: Path, content: bytes) -> str:
    require(bool(content), "EMPTY_SOURCE", "Source is empty")
    mime = MIMES.get(path.suffix.casefold())
    require(mime is not None, "UNSUPPORTED_SOURCE", "Supported inputs are CSV, TXT, PDF, PNG and JPEG")
    if mime == "application/pdf":
        require(content[:1024].lstrip().startswith(b"%PDF-"), "SOURCE_TYPE_MISMATCH", "PDF extension does not match bytes")
    if mime == "image/png":
        require(content.startswith(b"\x89PNG\r\n\x1a\n"), "SOURCE_TYPE_MISMATCH", "PNG signature missing")
    if mime == "image/jpeg":
        require(content.startswith(b"\xff\xd8\xff"), "SOURCE_TYPE_MISMATCH", "JPEG signature missing")
    return mime


def _native_pages(content: bytes, mime: str, sections: list[dict], coverage: dict) -> list[dict]:
    if mime in {"text/csv", "text/plain"}:
        # Successful typed table parsing omits raw_text. The original UTF-8
        # text is still retained in full, including its header and whitespace.
        return [{"page": 1, "text": _text(content)}]
    if mime.startswith("image/"):
        return []
    page_numbers = set(coverage["processed_pages"]) | set(coverage["unprocessed_pages"])
    mapped: dict[int, str] = {}
    for section in sections:
        page, text = section.get("page"), section.get("text")
        require(type(page) is int and 1 <= page <= 500 and isinstance(text, str),
                "INVALID_DOCUMENT_TEXT", "Native PDF text needs bounded source page numbers")
        require(page not in mapped, "INVALID_DOCUMENT_TEXT", "Native PDF page was returned more than once")
        mapped[page] = text
        page_numbers.add(page)
    if not page_numbers:
        return []  # No invented page count for an unavailable PDF text layer.
    require(all(type(page) is int and 1 <= page <= 500 for page in page_numbers)
            and page_numbers == set(range(1, max(page_numbers) + 1)),
            "INVALID_DOCUMENT_TEXT", "Native PDF page inventory has a gap")
    return [{"page": page, "text": mapped.get(page, "")} for page in sorted(page_numbers)]


def _transcript_ref(header: dict) -> dict:
    return {key: header[key] for key in TRANSCRIPT_REF_FIELDS}


def validate_attachment_preparation(value: dict, lookup: Lookup) -> None:
    """Pure ACK validation for recovery; never reopens the selected local path."""
    require(isinstance(value, dict) and set(value) == RESULT_FIELDS
            and value.get("schema_version") == ATTACHMENT_SCHEMA
            and value.get("kind") == "attachment_preparation",
            "INVALID_ATTACHMENT_ACK", "Invalid attachment acknowledgement schema")
    subject = identifier(value["subject_id"], "subject_id")
    require(isinstance(value["preparation_id"], str)
            and bool(re.fullmatch(r"case_[0-9a-f]{32,64}", value["preparation_id"])),
            "INVALID_ATTACHMENT_ACK", "Attachment acknowledgements require private case IDs")
    request = value["request"]
    require(isinstance(request, dict) and set(request) == {"subject_id", "source_path"}
            and request["subject_id"] == subject,
            "INVALID_ATTACHMENT_ACK", "Attachment request scope differs")
    _request(request["subject_id"], request["source_path"])
    require(value["request_sha256"] == digest(request)
            and value["preparation_sha256"] == digest({key: item for key, item in value.items()
                                                       if key != "preparation_sha256"}),
            "INVALID_ATTACHMENT_ACK", "Attachment request or acknowledgement hash differs")
    iso_timestamp(value["prepared_at"], "prepared_at")
    require(type(value["recognition_reused"]) is bool and value["confirmed"] is False
            and value["verification"] == "unverified"
            and isinstance(value["limitations"], list)
            and all(isinstance(item, str) and len(item) <= 4000 for item in value["limitations"]),
            "INVALID_ATTACHMENT_ACK", "Attachment intake cannot confirm or verify source proposals")
    version = lookup("document_version", value["version_id"], subject)
    require(all(value[key] == version.get(key) for key in
                ("subject_id", "document_id", "version_id", "source_sha256", "mime", "size")),
            "INVALID_ATTACHMENT_ACK", "Attachment version metadata differs")
    document = lookup("document", value["document_id"], subject)
    require(document.get("subject_id") == subject and document.get("document_id") == value["document_id"],
            "INVALID_ATTACHMENT_ACK", "Attachment document link differs")
    run = lookup("extraction_run", value["run_id"], subject)
    require(all(run.get(key) == value[key] for key in
                ("subject_id", "version_id", "source_sha256", "run_id", "draft_ids", "panel_ids", "coverage")),
            "INVALID_ATTACHMENT_ACK", "Attachment extraction metadata differs")
    for key, kind, field in (("draft_ids", "observation_draft", "extraction_run_id"),
                             ("panel_ids", "panel", "run_id"), ("issue_ids", "import_issue", "run_id")):
        require(isinstance(value[key], list) and all(isinstance(item, str) for item in value[key])
                and len(set(value[key])) == len(value[key]),
                "INVALID_ATTACHMENT_ACK", "Attachment references must be distinct lists")
        for object_id in value[key]:
            linked = lookup(kind, object_id, subject)
            require(linked.get(field) == value["run_id"] and linked.get("subject_id") == subject,
                    "INVALID_ATTACHMENT_ACK", "Attachment reference belongs to another run")
    manifest = lookup("original_manifest", "original_" + digest({"subject_id": subject,
                        "version_id": value["version_id"]}), subject)
    require(manifest.get("version_id") == value["version_id"]
            and canonical(manifest.get("manifest")) == canonical(value["saved_original"]),
            "INVALID_ATTACHMENT_ACK", "Attachment saved-original manifest differs")
    original = value["saved_original"]
    require(isinstance(original, dict) and original.get("schema_version") == "health-analyzer.original/1"
            and original.get("source_mode") == "immutable_snapshot"
            and all(original.get(key) == version.get(key) for key in ("subject_id", "source_sha256", "mime", "size")),
            "INVALID_ATTACHMENT_ACK", "Attachment original does not match the registered bytes")
    view = value["source_view"]
    require(isinstance(view, dict) and all(view.get(key) == version.get(key) for key in
                ("subject_id", "version_id", "source_sha256", "mime", "size"))
            and view.get("source_mode") == "immutable_snapshot"
            and view.get("human_verified") is False and view.get("review_status") == "unverified",
            "INVALID_ATTACHMENT_ACK", "Attachment view cannot confer human verification")
    _selected_path(view.get("verified_saved_source_path"))
    if view.get("verified_view_path") is not None:
        _selected_path(view["verified_view_path"])
    require(isinstance(value["native_transcripts"], list), "INVALID_ATTACHMENT_ACK", "Transcript references must be a list")
    seen = set()
    from .document_io import validate_document_transcript_links
    for ref in value["native_transcripts"]:
        require(isinstance(ref, dict) and set(ref) == TRANSCRIPT_REF_FIELDS
                and ref.get("method") in {"native_pdf_text", "native_text"}
                and ref.get("transcript_id") not in seen,
                "INVALID_ATTACHMENT_ACK", "Attachment native transcript reference differs")
        seen.add(ref["transcript_id"])
        header = lookup("document_transcript", ref["transcript_id"], subject)
        require(canonical(_transcript_ref(header)) == canonical(ref),
                "INVALID_ATTACHMENT_ACK", "Attachment transcript metadata differs")
        chunks = [lookup("document_transcript_chunk", chunk_id, subject)
                  for page in header["pages"] for chunk_id in page["chunk_ids"]]
        validate_document_transcript_links(header, version, chunks)


def validate_attachment_idempotency(payload: dict, lookup: Lookup) -> None:
    """Validate the exact historical private ACK without current file access."""
    require(isinstance(payload, dict) and set(payload) == {"subject_id", "operation", "request_sha256", "result", "recorded_at"}
            and payload.get("operation") == OPERATION,
            "INVALID_ATTACHMENT_ACK", "Invalid attachment retry acknowledgement")
    validate_attachment_preparation(payload["result"], lookup)
    result = payload["result"]
    require(payload["subject_id"] == result["subject_id"]
            and payload["request_sha256"] == result["request_sha256"]
            and payload["recorded_at"] == result["prepared_at"],
            "INVALID_ATTACHMENT_ACK", "Attachment retry scope, request, or time differs")


class AttachmentService:
    def __init__(self, config, records, imports, documents):
        require(isinstance(records.store, SignedStore) and records.store.domain == "private-data"
                and imports.records.store is records.store and documents.records.store is records.store,
                "wrong_domain", "Attachment intake requires one private-data store")
        self.config, self.records, self.imports, self.documents = config, records, imports, documents
        self.store = records.store

    def prepare_attachment(self, subject_id: str, source_path: str, idempotency_key: str = "") -> dict:
        request = _request(subject_id, source_path)
        require(isinstance(idempotency_key, str) and len(idempotency_key) <= 200,
                "invalid_idempotency_key", "Idempotency key must be a bounded string")
        ack_id = ("case_" + digest({"subject_id": subject_id, "operation": OPERATION, "key": idempotency_key})
                  if idempotency_key else None)
        with self.store.transaction():
            if ack_id is not None:
                try:
                    prior = self.store.get("idempotency", ack_id, subject_id)
                except V2Error as exc:
                    if exc.code != "NOT_FOUND":
                        raise
                else:
                    require(prior.get("request_sha256") == digest(request), "idempotency_conflict", "Idempotency key was used for another request")
                    validate_attachment_idempotency(prior, self.store.get)
                    return copy.deepcopy(prior["result"])
            path = _selected_path(source_path)
            # Reuse descriptor traversal from the filesystem anchor so every
            # ancestor is O_NOFOLLOW, including parents outside archive roots.
            # Host and enforced modes both remain under their live permissions.
            content = read_source(Path(path.anchor), path.relative_to(path.anchor).as_posix())
            mime = _mime(path, content)
            try:
                self.records._subject(subject_id)
            except V2Error as exc:
                if exc.code != "NOT_FOUND":
                    raise
                self.records.register_subject(subject_id, subject_id)
            registered = self.records.register_document(subject_id, hashlib.sha256(content).hexdigest(),
                                                         mime, len(content), occurrence=None)
            version = self.records._version(subject_id, registered["version_id"])
            manifest = self.imports.originals.preserve(subject_id, content, mime)
            self.store.put("original_manifest", self.imports._manifest_id(version),
                           {"subject_id": subject_id, "version_id": version["version_id"], "manifest": manifest}, subject_id)
            prior_run = None
            if registered["deduplicated"]:
                try:
                    prior_run = self.records._latest_run(subject_id, version["version_id"])
                except V2Error as exc:
                    if exc.code != "no_extraction":
                        raise
            if prior_run is None:
                rows, coverage, raw_text, limitations, issues = self.imports._extract(content, mime, version)
                extraction = self.records.submit_extraction(subject_id, version["version_id"], rows, coverage)
                issue_ids = self.imports.issues.register(subject_id, version["version_id"], extraction["run_id"], issues)
                native_pages = _native_pages(content, mime, raw_text, coverage)
                if native_pages:
                    self.documents._save_native_document_text(subject_id, version["version_id"], version["source_sha256"], native_pages,
                                                              method="native_text" if mime.startswith("text/") else "native_pdf_text")
                run = self.store.get("extraction_run", extraction["run_id"], subject_id)
            else:
                run = prior_run
                issue_ids = [issue["issue_id"] for issue in self.store.list("import_issue", subject_id)
                             if issue["run_id"] == run["run_id"]]
                limitations = ["Existing scoped extraction reused; no new extraction or model verification performed"]
            native_refs = [_transcript_ref(header) for header in self.store.list("document_transcript", subject_id)
                           if header["version_id"] == version["version_id"]
                           and header["method"] in {"native_pdf_text", "native_text"}]
            if prior_run is not None and not native_refs:
                if mime.startswith("text/"):
                    # This explicit selection supplies the complete current
                    # bytes without repeating the prior typed-row extraction.
                    native_refs = [self.documents._save_native_document_text(
                        subject_id, version["version_id"], version["source_sha256"],
                        [{"page": 1, "text": _text(content)}], method="native_text")]
                elif mime == "application/pdf":
                    limitations.append("Reused historical extraction has no stored full native transcript; preserved original remains available for visual reading")
            view = self.documents.prepare_document_view(subject_id, version["version_id"])
            now = utc_now()
            result = {"schema_version": ATTACHMENT_SCHEMA, "kind": "attachment_preparation",
                      "preparation_id": new_id("case"), "subject_id": subject_id,
                      "request": request, "request_sha256": digest(request),
                      **{key: version[key] for key in ("document_id", "version_id", "source_sha256", "mime", "size")},
                      **{key: run[key] for key in ("run_id", "draft_ids", "panel_ids", "coverage")},
                      "issue_ids": issue_ids, "saved_original": manifest, "source_view": view,
                      "native_transcripts": native_refs, "recognition_reused": prior_run is not None,
                      "confirmed": False, "verification": "unverified", "prepared_at": now,
                      "limitations": [*limitations, "Native text and typed rows are unverified source proposals; visual/model transcription is submitted separately"]}
            result["preparation_sha256"] = digest(result)
            validate_attachment_preparation(result, self.store.get)
            if ack_id is not None:
                payload = {"subject_id": subject_id, "operation": OPERATION, "request_sha256": digest(request),
                           "result": result, "recorded_at": now}
                validate_attachment_idempotency(payload, self.store.get)
                self.store.put("idempotency", ack_id, payload, subject_id)
            return copy.deepcopy(result)
