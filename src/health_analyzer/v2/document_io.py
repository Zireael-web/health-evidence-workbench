"""Bounded complete transcripts and local views of immutable saved originals.

Text is untrusted input. A verified source hash establishes byte identity only;
neither the transcript nor a page-count claim establishes human verification.
Large transcripts use immutable chunks in the existing private SignedStore.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
from uuid import uuid4

from .common import V2Error, canonical, digest, require, utc_now
from .contracts import identifier, iso_timestamp, SHA256_RE


TRANSCRIPT_SCHEMA = "health-analyzer.document-transcript/1"
CHUNK_SCHEMA = "health-analyzer.document-transcript-chunk/1"
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_TEXT_PAGES = 500
CHUNK_TEXT_BYTES = 256 * 1024
MAX_CHUNKS = MAX_TEXT_BYTES // CHUNK_TEXT_BYTES + MAX_TEXT_PAGES
PUBLIC_METHODS = {"model_vision", "manual_transcription"}
NATIVE_METHODS = {"native_pdf_text", "native_text"}
METHODS = PUBLIC_METHODS | NATIVE_METHODS
TRANSCRIPT_FIELDS = {"schema_version", "transcript_id", "subject_id", "version_id",
                     "source_sha256", "method", "model", "page_count", "text_bytes",
                     "pages", "request_sha256", "source_extent", "review_status",
                     "human_verified", "recorded_at"}
CHUNK_FIELDS = {"schema_version", "chunk_id", "transcript_id", "subject_id", "version_id",
                "source_sha256", "page", "index", "text", "text_sha256", "text_bytes"}
PAGE_FIELDS = {"page", "text_sha256", "text_bytes", "chunk_ids"}
ACK_FIELDS = {"transcript_id", "subject_id", "version_id", "source_sha256", "method", "model",
              "page_count", "text_bytes", "source_extent", "review_status", "human_verified"}


def _bytes(value: object) -> bytes:
    require(isinstance(value, str), "INVALID_DOCUMENT_TEXT", "Page text must be a string")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise V2Error("INVALID_DOCUMENT_TEXT", "Page text must be valid UTF-8") from exc


def _hash(value: object) -> None:
    require(isinstance(value, str) and bool(SHA256_RE.fullmatch(value)),
            "INVALID_DOCUMENT_TEXT", "A lowercase SHA-256 is required")


def _count(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _identity(value: object) -> None:
    require(isinstance(value, str) and bool(re.fullmatch(r"case_[0-9a-f]{64}", value)),
            "INVALID_DOCUMENT_TEXT", "Invalid content-addressed transcript identity")


def _request_metadata(payload: dict) -> dict:
    return {key: payload[key] for key in ("subject_id", "version_id", "source_sha256", "method", "model")} | {
        "pages": [{key: page[key] for key in ("page", "text_sha256", "text_bytes")}
                  for page in payload["pages"]]}


def validate_document_transcript(payload: dict, *, object_id: str | None = None,
                                 subject_id: str | None = None) -> dict:
    """Pure exact-schema validation for runtime reads and recovery inventories."""
    require(isinstance(payload, dict) and set(payload) == TRANSCRIPT_FIELDS
            and payload.get("schema_version") == TRANSCRIPT_SCHEMA,
            "INVALID_DOCUMENT_TEXT", "Invalid document transcript schema")
    identifier(payload["subject_id"], "subject_id")
    identifier(payload["version_id"], "version_id")
    _identity(payload["transcript_id"])
    _hash(payload["source_sha256"])
    require(subject_id is None or payload["subject_id"] == subject_id,
            "WRONG_SUBJECT", "Transcript is outside requested subject scope")
    require(object_id is None or payload["transcript_id"] == object_id,
            "INVALID_DOCUMENT_TEXT", "Transcript object identity differs")
    require(isinstance(payload["method"], str) and payload["method"] in METHODS,
            "INVALID_DOCUMENT_TEXT", "Unknown transcript method")
    model = payload["model"]
    require(model is None or (isinstance(model, str) and 0 < len(model) <= 200),
            "INVALID_DOCUMENT_TEXT", "Model must be null or a bounded supplied name")
    require(payload["method"] == "model_vision" or model is None,
            "INVALID_DOCUMENT_TEXT", "Only model vision may name a model")
    require(payload["source_extent"] == "unverified"
            and payload["review_status"] == "unverified" and payload["human_verified"] is False,
            "INVALID_DOCUMENT_TEXT", "Transcript storage cannot confer source or human verification")
    require(_count(payload["page_count"], 1, MAX_TEXT_PAGES)
            and isinstance(payload["pages"], list) and len(payload["pages"]) == payload["page_count"]
            and _count(payload["text_bytes"], 0, MAX_TEXT_BYTES),
            "DOCUMENT_TEXT_LIMIT", "Transcript exceeds its page or byte bound")
    total, all_chunks = 0, []
    for number, page in enumerate(payload["pages"], 1):
        require(isinstance(page, dict) and set(page) == PAGE_FIELDS and type(page["page"]) is int
                and page["page"] == number and _count(page["text_bytes"], 0, MAX_TEXT_BYTES),
                "INVALID_DOCUMENT_TEXT", "Transcript pages must retain a contiguous complete provided inventory")
        _hash(page["text_sha256"])
        require(isinstance(page["chunk_ids"], list)
                and len(page["chunk_ids"]) <= MAX_CHUNKS
                and bool(page["chunk_ids"]) == bool(page["text_bytes"]),
                "INVALID_DOCUMENT_TEXT", "Invalid page chunk inventory")
        for chunk_id in page["chunk_ids"]:
            _identity(chunk_id)
        if page["text_bytes"] == 0:
            require(page["text_sha256"] == hashlib.sha256(b"").hexdigest(),
                    "INVALID_DOCUMENT_TEXT", "Blank page hash differs")
        total += page["text_bytes"]
        all_chunks.extend(page["chunk_ids"])
    require(total == payload["text_bytes"] and total <= MAX_TEXT_BYTES
            and len(all_chunks) <= MAX_CHUNKS and len(set(all_chunks)) == len(all_chunks),
            "INVALID_DOCUMENT_TEXT", "Transcript byte or chunk inventory differs")
    expected = digest(_request_metadata(payload))
    require(payload["request_sha256"] == expected and payload["transcript_id"] == "case_" + expected,
            "INVALID_DOCUMENT_TEXT", "Transcript content identity differs")
    iso_timestamp(payload["recorded_at"], "recorded_at")
    return copy.deepcopy(payload)


def validate_document_transcript_chunk(payload: dict, *, object_id: str | None = None,
                                       subject_id: str | None = None) -> dict:
    """Pure exact-kind chunk validation; linkage is validated separately."""
    require(isinstance(payload, dict) and set(payload) == CHUNK_FIELDS
            and payload.get("schema_version") == CHUNK_SCHEMA,
            "INVALID_DOCUMENT_TEXT", "Invalid document transcript chunk schema")
    identifier(payload["subject_id"], "subject_id")
    identifier(payload["version_id"], "version_id")
    _identity(payload["transcript_id"])
    _identity(payload["chunk_id"])
    _hash(payload["source_sha256"])
    require(subject_id is None or payload["subject_id"] == subject_id,
            "WRONG_SUBJECT", "Text chunk is outside requested scope")
    require(object_id is None or payload["chunk_id"] == object_id,
            "INVALID_DOCUMENT_TEXT", "Text chunk object identity differs")
    content = _bytes(payload["text"])
    require(_count(payload["page"], 1, MAX_TEXT_PAGES)
            and _count(payload["index"], 0, MAX_CHUNKS)
            and _count(payload["text_bytes"], 1, CHUNK_TEXT_BYTES)
            and len(content) == payload["text_bytes"]
            and payload["text_sha256"] == hashlib.sha256(content).hexdigest(),
            "INVALID_DOCUMENT_TEXT", "Text chunk hash, size, or position differs")
    core = {key: value for key, value in payload.items() if key != "chunk_id"}
    require(payload["chunk_id"] == "case_" + digest(core),
            "INVALID_DOCUMENT_TEXT", "Text chunk content identity differs")
    return copy.deepcopy(payload)


def validate_document_transcript_links(payload: dict, version: dict, chunks: list[dict]) -> list[dict]:
    """Validate exact scoped source/chunk links and reconstruct every page losslessly.

    Recovery must resolve version as kind document_version and each chunk as kind
    document_transcript_chunk. This pure helper performs no filesystem reads.
    """
    header = validate_document_transcript(payload)
    require(isinstance(version, dict) and all(version.get(key) == header[key]
            for key in ("subject_id", "version_id", "source_sha256")),
            "INVALID_DOCUMENT_TEXT", "Transcript does not link to its exact source version")
    require(isinstance(chunks, list) and len(chunks) <= MAX_CHUNKS,
            "INVALID_DOCUMENT_TEXT", "Invalid transcript chunk set")
    resolved = {}
    for item in chunks:
        chunk = validate_document_transcript_chunk(item, subject_id=header["subject_id"])
        require(all(chunk[key] == header[key] for key in ("subject_id", "version_id", "source_sha256", "transcript_id"))
                and chunk["chunk_id"] not in resolved,
                "INVALID_DOCUMENT_TEXT", "Duplicate, foreign, or mislinked transcript chunk")
        resolved[chunk["chunk_id"]] = chunk
    expected = {value for page in header["pages"] for value in page["chunk_ids"]}
    require(set(resolved) == expected, "INVALID_DOCUMENT_TEXT", "Transcript chunk inventory is incomplete or has extras")
    pages = []
    for page in header["pages"]:
        selected = [resolved[value] for value in page["chunk_ids"]]
        require(all(chunk["page"] == page["page"] and chunk["index"] == index
                    for index, chunk in enumerate(selected)),
                "INVALID_DOCUMENT_TEXT", "Transcript page chunk order differs")
        full_text = "".join(chunk["text"] for chunk in selected)
        encoded = _bytes(full_text)
        require(len(encoded) == page["text_bytes"]
                and hashlib.sha256(encoded).hexdigest() == page["text_sha256"],
                "INVALID_DOCUMENT_TEXT", "Full page transcript hash differs")
        pages.append({"page": page["page"], "text": full_text})
    return pages


def validate_document_text_ack(payload: dict, transcript: dict) -> dict:
    """Pure validation of the existing idempotency store's exact result link."""
    header = validate_document_transcript(transcript)
    require(isinstance(payload, dict) and set(payload) == ACK_FIELDS
            and canonical(payload) == canonical({key: header[key] for key in ACK_FIELDS}),
            "INVALID_DOCUMENT_TEXT", "Transcript acknowledgement differs from its immutable header")
    return copy.deepcopy(payload)


def _split_text(value: str):
    """Split at UTF-8 boundaries without trimming or normalizing any text."""
    content = _bytes(value)
    offset = 0
    while offset < len(content):
        end = min(offset + CHUNK_TEXT_BYTES, len(content))
        while end < len(content) and content[end] & 0xC0 == 0x80:
            end -= 1
        yield content[offset:end].decode("utf-8")
        offset = end


class DocumentIOService:
    def __init__(self, config, records, imports):
        require(records.store.domain == "private-data", "wrong_domain", "Document intake requires private data")
        self.config, self.records, self.imports = config, records, imports

    def _version(self, subject_id: str, version_id: str, source_sha256: str | None = None) -> dict:
        version = self.records._version(subject_id, version_id)
        if source_sha256 is not None:
            _hash(source_sha256)
            require(version["source_sha256"] == source_sha256, "SOURCE_CHANGED", "Source hash differs from selected version")
        require(callable(self.records.source_checker), "SOURCE_CHECKER_REQUIRED", "A current private source checker is required")
        require(self.records.source_checker(version) is not False, "SOURCE_CHANGED", "Source is unavailable or changed")
        return version

    def save_document_text(self, subject_id: str, version_id: str, source_sha256: str,
                           pages: list[dict], method: str, model: str | None = None,
                           idempotency_key: str = "") -> dict:
        require(isinstance(method, str) and method in PUBLIC_METHODS,
                "INVALID_DOCUMENT_TEXT", "Public intake accepts model vision or manual transcription")
        return self._save_document_text(subject_id, version_id, source_sha256, pages, method, model, idempotency_key)

    def _save_native_document_text(self, subject_id: str, version_id: str, source_sha256: str,
                                  pages: list[dict], idempotency_key: str = "", *,
                                  method: str = "native_pdf_text") -> dict:
        """Import-owned native text entry; never expose it as a caller-selected method."""
        require(isinstance(method, str) and method in NATIVE_METHODS,
                "INVALID_DOCUMENT_TEXT", "Internal native intake requires an honest native method")
        return self._save_document_text(subject_id, version_id, source_sha256, pages,
                                        method, None, idempotency_key)

    def _save_document_text(self, subject_id, version_id, source_sha256, pages, method, model, idempotency_key):
        require(isinstance(pages, list) and 1 <= len(pages) <= MAX_TEXT_PAGES,
                "DOCUMENT_TEXT_LIMIT", "Provide 1–500 pages; overflow is refused without partial storage")
        normalized, inventory, total = [], [], 0
        for number, page in enumerate(pages, 1):
            require(isinstance(page, dict) and set(page) == {"page", "text"}
                    and type(page["page"]) is int and page["page"] == number,
                    "INVALID_DOCUMENT_TEXT", "Provide every supplied page in contiguous original order")
            content = _bytes(page["text"])
            total += len(content)
            require(total <= MAX_TEXT_BYTES, "DOCUMENT_TEXT_LIMIT", "Transcript exceeds 8 MiB; no partial storage")
            normalized.append({"page": number, "text": page["text"]})
            inventory.append({"page": number, "text_sha256": hashlib.sha256(content).hexdigest(), "text_bytes": len(content)})
        request = {"subject_id": subject_id, "version_id": version_id, "source_sha256": source_sha256,
                   "method": method, "model": model, "pages": inventory}
        request_hash = digest(request)
        transcript_id = "case_" + request_hash
        chunks = []
        stored_pages = []
        for page, metadata in zip(normalized, inventory):
            chunk_ids = []
            for index, value in enumerate(_split_text(page["text"])):
                encoded = _bytes(value)
                core = {"schema_version": CHUNK_SCHEMA, "transcript_id": transcript_id,
                        "subject_id": subject_id, "version_id": version_id, "source_sha256": source_sha256,
                        "page": page["page"], "index": index, "text": value,
                        "text_sha256": hashlib.sha256(encoded).hexdigest(), "text_bytes": len(encoded)}
                chunk = {**core, "chunk_id": "case_" + digest(core)}
                validate_document_transcript_chunk(chunk)
                chunks.append(chunk)
                chunk_ids.append(chunk["chunk_id"])
            stored_pages.append({**metadata, "chunk_ids": chunk_ids})
        header = {"schema_version": TRANSCRIPT_SCHEMA, "transcript_id": transcript_id,
                  "subject_id": subject_id, "version_id": version_id, "source_sha256": source_sha256,
                  "method": method, "model": model, "pages": stored_pages, "page_count": len(pages),
                  "text_bytes": total, "request_sha256": request_hash, "source_extent": "unverified",
                  "review_status": "unverified", "human_verified": False, "recorded_at": utc_now()}
        validate_document_transcript(header)
        require(all(len(canonical(value)) <= self.records.store.MAX_OBJECT_BYTES for value in [header, *chunks]),
                "DOCUMENT_TEXT_LIMIT", "Transcript object exceeds store bounds; no partial storage")
        with self.records.store.transaction():
            version = self.records._version(subject_id, version_id)
            require(version["source_sha256"] == source_sha256,
                    "SOURCE_CHANGED", "Source hash differs from selected version")
            validate_document_transcript_links(header, version, chunks)
            idem_id, previous = self.records._idempotency(subject_id, "save_document_text", idempotency_key, request)
            if previous is not None:
                require(previous.get("transcript_id") == transcript_id,
                        "INVALID_DOCUMENT_TEXT", "Saved idempotency acknowledgement differs")
                saved, _ = self._read(subject_id, transcript_id)
                validate_document_text_ack(previous, saved)
                return previous
            try:
                existing = self.records.store.get("document_transcript", transcript_id, subject_id)
            except V2Error as exc:
                if exc.code != "NOT_FOUND":
                    raise
                existing = None
            if existing is not None:
                self._read(subject_id, transcript_id)
            if existing is None:
                self._version(subject_id, version_id, source_sha256)
                for chunk in chunks:
                    self.records.store.put("document_transcript_chunk", chunk["chunk_id"], chunk, subject_id)
                self.records.store.put("document_transcript", transcript_id, header, subject_id)
            result = {key: header[key] for key in ACK_FIELDS}
            self.records._put_idempotency(subject_id, idem_id, request, result)
            return result

    def _read(self, subject_id: str, transcript_id: str) -> tuple[dict, list[dict]]:
        _identity(transcript_id)
        header = self.records.store.get("document_transcript", transcript_id, subject_id)
        validate_document_transcript(header, object_id=transcript_id, subject_id=subject_id)
        version = self.records._version(subject_id, header["version_id"])
        chunks = [self.records.store.get("document_transcript_chunk", chunk_id, subject_id)
                  for page in header["pages"] for chunk_id in page["chunk_ids"]]
        pages = validate_document_transcript_links(header, version, chunks)
        return header, pages

    def get_document_text(self, subject_id: str, transcript_id: str,
                          offset: int = 0, limit: int = 25) -> dict:
        require(_count(offset, 0, MAX_TEXT_PAGES) and _count(limit, 1, MAX_TEXT_PAGES),
                "INVALID_PAGINATION", "Use a bounded page offset and 1–500 whole pages")
        with self.records.store.transaction(readonly=True):
            header, pages = self._read(subject_id, transcript_id)
            selected = pages[offset:offset + limit]
            return {**header, "pages": selected, "offset": offset, "returned_pages": len(selected),
                    "next_offset": offset + len(selected) if offset + len(selected) < len(pages) else None,
                    "returned_text_bytes": sum(len(_bytes(page["text"])) for page in selected)}

    def list_document_texts(self, subject_id: str, version_id: str,
                            offset: int = 0, limit: int = 25) -> dict:
        """Discover immutable transcript attempts without reading source files."""
        require(_count(offset, 0, self.records.store.MAX_LIST)
                and _count(limit, 1, MAX_TEXT_PAGES),
                "INVALID_PAGINATION", "Use a bounded transcript offset and 1–500 attempts")
        with self.records.store.transaction(readonly=True):
            version = self.records._version(subject_id, version_id)
            headers = []
            for payload in self.records.store.list("document_transcript", subject_id):
                header = validate_document_transcript(payload, subject_id=subject_id)
                if header["version_id"] != version_id:
                    continue
                require(header["source_sha256"] == version["source_sha256"],
                        "INVALID_DOCUMENT_TEXT", "Transcript source version hash differs")
                headers.append({key: header[key] for key in TRANSCRIPT_FIELDS - {"pages"}})
            selected = headers[offset:offset + limit]
            return {"subject_id": subject_id, "version_id": version_id, "transcripts": selected,
                    "total": len(headers), "offset": offset,
                    "next_offset": offset + len(selected) if offset + len(selected) < len(headers) else None}

    def get_document_view(self, subject_id: str, version_id: str) -> dict:
        """Return a freshly verified saved original for a native private viewer."""
        version = self._version(subject_id, version_id)
        manifest = self.imports._saved_manifest(version)
        require(manifest is not None, "SAVED_ORIGINAL_REQUIRED", "This version has no preserved original for viewing")
        path = self.imports.originals.verified_path(subject_id, manifest, version)
        view_path = self._existing_view(version)
        return {"subject_id": subject_id, "version_id": version_id, "source_sha256": version["source_sha256"],
                "mime": version["mime"], "size": version["size"], "verified_saved_source_path": str(path),
                "verified_view_path": str(view_path) if view_path is not None else None,
                "source_mode": "immutable_snapshot", "view_status": "saved_original_available",
                "review_status": "unverified", "human_verified": False,
                "limitation": "Path was verified at this call; later viewer access must not be treated as a review receipt."}

    def _view_path(self, version: dict) -> Path:
        extensions = {"application/pdf": ".pdf", "image/png": ".png", "image/jpeg": ".jpg",
                      "text/plain": ".txt", "text/csv": ".csv", "text/tab-separated-values": ".tsv"}
        extension = extensions.get(version["mime"], ".bin")
        name = "view_" + digest({key: version[key] for key in ("subject_id", "source_sha256")}) + extension
        return self.config.data_root / "private" / "document-views" / name

    def _existing_view(self, version: dict) -> Path | None:
        path = self._view_path(version)
        with _owned_directory(path.parent, create=False) as directory:
            if directory is None:
                return None
            try:
                _read_owned_file(directory, path.name, version["size"], version["source_sha256"])
            except FileNotFoundError:
                return None
        return path

    def prepare_document_view(self, subject_id: str, version_id: str) -> dict:
        """Publish an exact protected copy with a viewer-compatible extension."""
        require(not self.records.store.readonly, "STORE_READ_ONLY", "Read-only runtimes cannot prepare a view copy")
        version = self._version(subject_id, version_id)
        manifest = self.imports._saved_manifest(version)
        require(manifest is not None, "SAVED_ORIGINAL_REQUIRED", "Viewing requires a preserved original")
        content = self.imports.originals.read_manifest(subject_id, manifest, version)
        path = self._view_path(version)
        with _owned_directory(path.parent, create=True, exclusive=True) as directory:
            try:
                _read_owned_file(directory, path.name, version["size"], version["source_sha256"])
            except FileNotFoundError:
                staging = ".staging-" + uuid4().hex
                try:
                    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=directory)
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(content)
                        output.flush()
                        os.fsync(output.fileno())
                        os.fchmod(output.fileno(), 0o400)
                    os.link(staging, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                finally:
                    try:
                        os.unlink(staging, dir_fd=directory)
                    except FileNotFoundError:
                        pass
                os.fsync(directory)
                _read_owned_file(directory, path.name, version["size"], version["source_sha256"])
            self._version(subject_id, version_id, version["source_sha256"])
        return self.get_document_view(subject_id, version_id)

    def render_document_pages(self, subject_id: str, version_id: str, dpi: int = 120) -> dict:
        view = self.get_document_view(subject_id, version_id)
        require(view["mime"] == "application/pdf", "PDF_REQUIRED", "Page rendering accepts a saved PDF original")
        require(_count(dpi, 36, 200), "INVALID_RENDER_DPI", "Render DPI must be between 36 and 200")
        if self.config.isolation != "host":
            return {**view, "render_status": "explicit_local_render_required", "pages": [],
                    "limitation": "This private runtime cannot launch the local PDF renderer. Open the verified saved original in the native viewer or use an explicitly authorized host local workflow."}
        require(not self.records.store.readonly, "STORE_READ_ONLY", "Read-only runtimes cannot save page previews")
        view = self.prepare_document_view(subject_id, version_id)
        from health_analyzer.local_documents import render_local_pdf, LocalDocumentError
        root = self.config.data_root / "private" / "document-previews"
        with _owned_directory(root, create=True, exclusive=True) as directory:
            name = "preview-" + uuid4().hex
            os.mkdir(name, mode=0o700, dir_fd=directory)
            container = root / name
            try:
                rendered = render_local_pdf(view["verified_view_path"], container, dpi=dpi, isolation="host")
                _validate_render_result(rendered, container, view["source_sha256"])
                self._version(subject_id, version_id, view["source_sha256"])
                result = {**view, "render_status": "rendered", "render": rendered,
                          "manifest_path": str(container / "manifest.json")}
                _exclusive_write(container / "manifest.json", canonical(result))
                return result
            except LocalDocumentError as exc:
                shutil.rmtree(name, dir_fd=directory)
                raise V2Error(exc.code, str(exc)) from exc
            except BaseException:
                shutil.rmtree(name, dir_fd=directory)
                raise


@contextmanager
def _owned_directory(path: Path, *, create: bool, exclusive: bool = False):
    """Create only the preview leaf; reject symlinks and unsafe private parents."""
    require(path.is_absolute() and ".." not in path.parts, "UNSAFE_PREVIEW_PATH", "Preview root must be a direct absolute path")
    descriptors = []
    chain = []
    try:
        descriptors.append(os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for index, name in enumerate(path.parts[1:], 1):
            parent = descriptors[-1]
            if create and index == len(path.parts) - 1:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent)
                except FileExistsError:
                    pass
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                if not create and index == len(path.parts) - 1:
                    yield None
                    return
                raise
            descriptors.append(child)
            chain.append((parent, name, child))
            if index >= len(path.parts) - 2:
                info = os.fstat(child)
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                        "UNSAFE_PREVIEW_PATH", "Private preview directories require owned mode 0700")
        _verify_directory_chain(chain)
        fcntl.flock(descriptors[-1], fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield descriptors[-1]
        _verify_directory_chain(chain)
    except OSError as exc:
        raise V2Error("UNSAFE_PREVIEW_PATH", "Preview root is missing or unsafe") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _verify_directory_chain(chain) -> None:
    for parent, name, child in chain:
        named, opened = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(child)
        require(stat.S_ISDIR(named.st_mode) and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino),
                "UNSAFE_PREVIEW_PATH", "Private view path changed during access")


def _read_owned_file(directory: int, name: str, expected_size: int, source_sha256: str) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) == 0o400 and before.st_nlink == 1
                and before.st_size == expected_size, "VIEW_INTEGRITY_FAILURE", "Saved view metadata differs")
        content = source.read(expected_size + 1)
        after = os.fstat(source.fileno())
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino)
                and len(content) == expected_size and hashlib.sha256(content).hexdigest() == source_sha256,
                "VIEW_INTEGRITY_FAILURE", "Saved view bytes changed or differ from the original")
    return content


def _exclusive_write(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o400)


def _validate_render_result(result: dict, container: Path, source_sha256: str) -> None:
    """Check renderer inventory before publishing a reusable local manifest."""
    from health_analyzer.local_documents import MAX_RENDER_PAGES, MAX_RENDER_PAGE_BYTES, MAX_RENDER_TOTAL_BYTES
    require(isinstance(result, dict) and result.get("sha256") == source_sha256
            and _count(result.get("page_count"), 1, MAX_RENDER_PAGES)
            and isinstance(result.get("pages"), list) and len(result["pages"]) == result["page_count"],
            "INVALID_PREVIEW", "Renderer source or complete page inventory differs")
    render_dir = Path(result.get("render_directory", ""))
    require(render_dir.parent == container and render_dir.is_dir() and not render_dir.is_symlink(),
            "INVALID_PREVIEW", "Renderer output escaped the owned preview directory")
    total = 0
    names = set()
    for number, page in enumerate(result["pages"], 1):
        require(isinstance(page, dict) and type(page.get("page")) is int and page.get("page") == number,
                "INVALID_PREVIEW", "Renderer page order differs")
        path = Path(page.get("path", ""))
        require(path.parent == render_dir and path.name == f"page-{number:04d}.png"
                and not path.is_symlink(), "INVALID_PREVIEW", "Renderer page path is outside its inventory")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_nlink == 1 and 0 < info.st_size <= MAX_RENDER_PAGE_BYTES,
                    "INVALID_PREVIEW", "Renderer page is not a bounded owned file")
            content = source.read(MAX_RENDER_PAGE_BYTES + 1)
        total += len(content)
        require(len(content) == page.get("byte_size") and hashlib.sha256(content).hexdigest() == page.get("sha256")
                and total <= MAX_RENDER_TOTAL_BYTES, "INVALID_PREVIEW", "Renderer page hash or byte budget differs")
        names.add(path.name)
    require(result.get("total_bytes") == total and {path.name for path in render_dir.iterdir()} == names,
            "INVALID_PREVIEW", "Renderer output inventory has missing or extra pages")
