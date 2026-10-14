"""Bounded v2 intake into whole-row review. Never reads legacy state.

Native extraction is conservative. Visual transcriptions share the same review
path and are explicitly model proposals, not verified facts.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import date, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from .common import V2Error, digest, require

MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_IMPORT_FILES = 100
MAX_IMPORT_BYTES = 128 * 1024 * 1024
MAX_EXTRACTED_ROWS = 1000
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_PREVIEW_BYTES = 256 * 1024
NUMBER = r"[+-]?(?:\d+(?:[.,]\d+)?|[.,]\d+)"
RESULT_RE = re.compile(rf"^\s*(<=|>=|<|>|≤|≥)?\s*({NUMBER})\s*$")
REFERENCE_RE = re.compile(rf"^\s*({NUMBER})\s*[-–—]\s*({NUMBER})\s*$")

ALIASES = {
    "analyte_raw": {"analyte", "analyte_raw", "test", "name", "показатель", "анализ", "наименование"},
    "result": {"result", "value", "результат", "значение"},
    "unit_raw": {"unit", "units", "unit_raw", "единица", "единицы", "ед. изм.", "единицы измерения"},
    "reference_intervals": {"reference", "ref", "range", "reference_interval", "референс", "референсы", "норма", "референсные значения"},
    "clinical_time": {"date", "clinical_date", "collected", "performed", "reported", "дата", "дата забора", "дата исследования", "дата отчета", "дата отчёта"},
    "specimen": {"specimen", "биоматериал", "образец"},
    "method": {"method", "метод"},
    "lab_flag_raw": {"flag", "флаг"},
}


def read_source(root: Path, relative_path: str) -> bytes:
    """Traverse approved directory descriptors without following symlinks."""
    require(isinstance(relative_path, str) and 0 < len(relative_path) <= 4096,
            "INVALID_SOURCE_REF", "A bounded relative source path is required")
    parts = relative_path.split("/")
    require(not Path(relative_path).is_absolute() and all(p not in {"", ".", ".."} for p in parts)
            and "\x00" not in relative_path and "\\" not in relative_path,
            "UNSAFE_PATH", "Source must stay inside its approved root")
    root = Path(root)
    require(not root.is_symlink(), "UNSAFE_PATH", "Archive root must not be a symlink")
    root = root.resolve(strict=True)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(root, directory_flags))
        for part in parts[:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        fd = os.open(parts[-1], file_flags, dir_fd=descriptors[-1])
        descriptors.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), "UNSAFE_PATH", "Source is not a regular file")
        require(before.st_size <= MAX_SOURCE_BYTES, "INPUT_LIMIT", "Source exceeds 64 MiB")
        chunks = bytearray()
        while len(chunks) <= MAX_SOURCE_BYTES:
            block = os.read(fd, min(1024 * 1024, MAX_SOURCE_BYTES + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        require(len(chunks) <= MAX_SOURCE_BYTES, "INPUT_LIMIT", "Source exceeds 64 MiB")
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(before) == identity(after) and len(chunks) == after.st_size,
                "SOURCE_CHANGED", "Source changed during bounded reading")
        return bytes(chunks)
    except OSError as exc:
        raise V2Error("SOURCE_UNAVAILABLE", "Source is inaccessible or its path is unsafe") from exc
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def parse_result(raw: str) -> dict:
    match = RESULT_RE.fullmatch(raw)
    if match:
        operator, number = match.groups()
        if operator:
            return {"kind": "numeric_censored", "raw": raw, "operator": operator,
                    "decimal": number.replace(",", ".")}
        return {"kind": "numeric_exact", "raw": raw, "decimal": number.replace(",", ".")}
    stripped = raw.strip()
    folded = stripped.casefold()
    if not stripped:
        return {"kind": "no_result", "raw": raw, "reason": "not_reported"}
    if folded in {"не обнаружено", "обнаружено", "положительный", "отрицательный", "positive", "negative", "detected", "not detected"}:
        return {"kind": "qualitative", "raw": raw, "value": stripped}
    if re.fullmatch(r"\+{1,4}|\d+:\d+", stripped):
        return {"kind": "semiquantitative", "raw": raw, "value": stripped}
    if folded in {"материал непригоден", "invalid specimen"}:
        return {"kind": "no_result", "raw": raw, "reason": "invalid_specimen"}
    if folded in {"отменён", "отменен", "cancelled"}:
        return {"kind": "no_result", "raw": raw, "reason": "cancelled"}
    return {"kind": "text_unparsed", "raw": raw}


def parse_clinical_time(raw: str | None, column_name: str | None = None) -> dict:
    folded = (column_name or "").casefold()
    role = {"collected": "collected", "дата забора": "collected", "performed": "performed",
            "дата исследования": "performed", "reported": "reported",
            "дата отчета": "reported", "дата отчёта": "reported"}.get(folded, "unknown")
    result = {"raw": raw or None, "role": role, "precision": "unknown", "value": None}
    if not raw:
        return result
    token = raw.strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", token):
            date.fromisoformat(token)
            result.update(precision="date", value=token)
        elif re.fullmatch(r"\d{2}\.\d{2}\.\d{4}", token):
            day, month, year = token.split(".")
            value = f"{year}-{month}-{day}"
            date.fromisoformat(value)
            result.update(precision="date", value=value)
        elif "T" in token:
            datetime.fromisoformat(token.replace("Z", "+00:00"))
            result.update(precision="datetime", value=token)
        elif re.fullmatch(r"\d{4}-\d{2}", token):
            date.fromisoformat(token + "-01")
            result.update(precision="month", value=token)
        elif re.fullmatch(r"\d{4}", token):
            date.fromisoformat(token + "-01-01")
            result.update(precision="year", value=token)
    except ValueError:
        pass
    return result


def parse_reference(raw: str | None, unit: str | None) -> list[dict]:
    if not raw:
        return []
    result = {"kind": "laboratory_reference", "raw": raw, "unit_raw": unit}
    match = REFERENCE_RE.fullmatch(raw)
    if match:
        result.update(low=match[1].replace(",", "."), high=match[2].replace(",", "."),
                      low_inclusive=True, high_inclusive=True)
    else:
        result["text"] = raw
    return [result]


def _text(content: bytes) -> str:
    require(len(content) <= MAX_TEXT_BYTES, "TEXT_LIMIT", "Native text exceeds 16 MiB")
    try:
        result = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise V2Error("TEXT_ENCODING_UNSUPPORTED", "Use UTF-8 input; encoding was not guessed") from exc
    require("\x00" not in result, "TEXT_ENCODING_UNSUPPORTED", "Native text contains binary bytes")
    return result


def _field_columns(header: list[str]) -> dict[str, int]:
    folded = [h.strip().casefold() for h in header]
    mapping = {}
    for field, names in ALIASES.items():
        columns = [i for i, h in enumerate(folded) if h in names]
        require(len(columns) <= 1, "AMBIGUOUS_COLUMNS", "Multiple columns map to the same field")
        if columns:
            mapping[field] = columns[0]
    require("analyte_raw" in mapping and "result" in mapping,
            "TABLE_MAPPING_REQUIRED", "Table needs explicitly named analyte and result columns")
    return mapping


def extract_table(text: str, version: dict, *, delimiter: str | None = None,
                  locator_kind: str = "csv", page: int | None = None) -> list[dict]:
    # Retained pure helper for synthetic/service callers. Transport intake uses
    # the issue-aware pair directly and never drops unresolved source material.
    from .delimited import extract_delimited
    rows, issues = extract_delimited(text, version, delimiter=delimiter,
                                    locator_kind=locator_kind, page=page)
    require(not issues, "TABLE_REVIEW_REQUIRED", "Use issue-aware intake for unresolved source rows")
    return rows



def extract_pdf(content: bytes) -> tuple[list, list[str]]:
    """Extract an existing PDF text layer; visual reading is handled in dialogue."""
    from .pdf_bridge import extract_via_bridge_if_configured
    bridged = extract_via_bridge_if_configured(content)
    if bridged is not None:
        return bridged
    return extract_document_native(content)


def _extract_pdf_text(content: bytes) -> tuple[list, list[str]]:
    """Run the fixed resource-bounded worker; never launch from a sandbox child."""
    from health_analyzer.ingest.pypdf_provider import PypdfExtractionLimits
    from health_analyzer.ingest.pypdf_subprocess import (
        PypdfSubprocessLimits, WORKER_PROTOCOL, _run_bounded_process, _decode_response,
    )
    from health_analyzer.ingest.registry import ExtractorFailure
    document = PypdfExtractionLimits()
    limits = PypdfSubprocessLimits()
    command = [sys.executable, "-I", "-B", str(Path(__file__).with_name("pdf_worker.py"))]
    if sys.platform == "darwin":
        require(Path("/usr/bin/sandbox-exec").is_file(), "PDF_SANDBOX_UNAVAILABLE", "Mandatory PDF sandbox is unavailable")
        variables = {"CODE_ROOT": Path(__file__).resolve().parents[2],
                     "PYTHON_ROOT": Path(sys.prefix).resolve(),
                     "BASE_PYTHON_ROOT": Path(sys.base_prefix).resolve(),
                     "PYTHON_EXEC": Path(sys.executable).resolve()}
        prefix = ["/usr/bin/sandbox-exec", "-f", str(Path(__file__).with_name("pdf-parser.sb"))]
        for key, value in variables.items():
            prefix += ["-D", f"{key}={value}"]
        command = prefix + command
    header = {"protocol": WORKER_PROTOCOL, "input_length": len(content),
              "document_limits": asdict(document), "resource_limits": {
                  key: getattr(limits, key) for key in ("cpu_seconds", "max_address_space_bytes", "max_open_files", "max_processes", "max_output_bytes")},
              "password": {"kind": "none", "base64": ""}}
    request = json.dumps(header, separators=(",", ":")).encode("ascii") + b"\n" + content
    try:
        response = _run_bounded_process(tuple(command), request,
                   timeout_seconds=limits.timeout_seconds, max_output_bytes=limits.max_output_bytes,
                   max_stderr_bytes=limits.max_stderr_bytes)
        failure, blocks, _memory_limit = _decode_response(response, max_pages=document.max_pages)
        if failure == "pdf_ocr_required":
            return [], ["No native PDF text; page count/coverage unknown; visual transcription required"]
        require(failure is None, str(failure or "PDF_EXTRACTION_FAILED"), "PDF worker reported a bounded extraction failure")
    except ExtractorFailure as exc:
        code = getattr(exc, "code", "PDF_EXTRACTION_FAILED")
        raise V2Error(str(code), "Bounded PDF extraction is unavailable or failed") from exc
    limitations = ["Native PDF text only; no OCR or model validation"]
    if not _memory_limit:
        limitations.append("Hard address-space limit unavailable/advisory; input, decoder, CPU, time and output bounds remain enforced")
    if sys.platform != "darwin":
        limitations.append("Worker resource bounds applied without a dedicated OS sandbox")
    return list(blocks), limitations


def extract_document_native(content: bytes) -> tuple[list, list[str]]:
    """Extract native PDF text only, retaining blank-page inventory.

    Image and scanned-page transcription belongs to ChatGPT/Codex in the
    conversation. This dispatcher never builds or invokes a local OCR engine.
    """
    if content[:1024].lstrip().startswith(b"%PDF-"):
        from .pdf_geometry import extract_pdf_geometry
        geometry = extract_pdf_geometry(content)
        blocks, limitations = geometry if geometry is not None else _extract_pdf_text(content)
        if geometry is not None:
            # Keep every page, including blank text layers, so missing text is
            # represented as pending source review rather than silently omitted.
            incomplete = any(not page["text"].strip() for page in blocks)
            blocks = [{**page, "document_incomplete": incomplete} for page in blocks]
        if not blocks or any((page.get("document_incomplete", False) if isinstance(page, dict)
                              else getattr(page, "document_incomplete", False)) for page in blocks):
            limitations = [*limitations, "Pages without native text require ChatGPT/Codex visual transcription; local OCR is disabled"]
        return blocks, limitations
    require(content.startswith(b"\x89PNG\r\n\x1a\n") or content.startswith(b"\xff\xd8\xff"),
            "SOURCE_TYPE_MISMATCH", "Document bridge accepts only PDF, PNG or JPEG bytes")
    return [], ["Image requires ChatGPT/Codex visual transcription; local OCR is disabled"]


def extract_image(content: bytes) -> tuple[list, list[str]]:
    from .pdf_bridge import extract_via_bridge_if_configured
    bridged = extract_via_bridge_if_configured(content)
    return bridged if bridged is not None else extract_document_native(content)


class ImportService:
    def __init__(self, config, records, *, pdf_extractor=None, image_extractor=None, originals=None):
        self.config = config
        self.records = records
        self.pdf_extractor = pdf_extractor or extract_pdf
        self.image_extractor = image_extractor or extract_image
        from .import_issues import ImportIssueService
        self._originals = originals
        self.issues = ImportIssueService(records)
        self.records.source_checker = self.check_current_source

    @property
    def originals(self):
        # Opening a records runtime must not backfill historical documents or
        # create original-copy namespaces before an explicit intake/read.
        if self._originals is None:
            from .originals import OriginalsStore
            self._originals = OriginalsStore(self.records.store.path.parent / "originals",
                                            readonly=getattr(self.records.store, "readonly", False))
        return self._originals

    @staticmethod
    def _manifest_id(version: dict) -> str:
        return "original_" + digest({"subject_id": version["subject_id"], "version_id": version["version_id"]})

    def _saved_manifest(self, version: dict) -> dict | None:
        try:
            payload = self.records.store.get("original_manifest", self._manifest_id(version), version["subject_id"])
        except V2Error as exc:
            if exc.code == "NOT_FOUND":
                return None
            raise
        require(payload["version_id"] == version["version_id"], "ORIGINAL_INTEGRITY_FAILURE", "Saved source version differs")
        return payload["manifest"]

    def get_source_version(self, subject_id: str, version_id: str) -> dict:
        version = self.records._version(subject_id, version_id)
        manifest = self._saved_manifest(version)
        result = {"subject_id": subject_id, "version_id": version_id, "source_sha256": version["source_sha256"],
                  "mime": version["mime"], "size": version["size"], "archive_sources": self._archive_status(version),
                  "saved_original": manifest, "source_mode": "immutable_snapshot" if manifest else "archive",
                  "verified_saved_source_path": None}
        if manifest is not None:
            try:
                result["verified_saved_source_path"] = str(self.originals.verified_path(subject_id, manifest, version))
                result["saved_status"] = "available"
            except V2Error as exc:
                result["saved_status"] = exc.code
        else:
            result["saved_status"] = "not_preserved_by_this_version"
        return result

    def _archive_status(self, version: dict) -> list[dict]:
        statuses = []
        for occurrence in self.records.store.list("file_occurrence", version["subject_id"]):
            if occurrence["version_id"] != version["version_id"]:
                continue
            ref = {"root_id": occurrence["root_id"], "relative_path": occurrence["relative_path"]}
            try:
                _, root, relative = self._binding(version["subject_id"], ref)
                current = read_source(root, relative)
                status = "same_bytes" if hashlib.sha256(current).hexdigest() == version["source_sha256"] else "source_changed"
            except V2Error as exc:
                status = exc.code
            statuses.append({"source_ref": ref, "status": status})
        return statuses

    def _binding(self, subject_id: str, ref: dict) -> tuple[str, Path, str]:
        require(isinstance(ref, dict) and set(ref) == {"root_id", "relative_path"},
                "INVALID_SOURCE_REF", "Use an approved root ID and relative path")
        root_id = ref["root_id"]
        require(isinstance(root_id, str) and root_id in self.config.archive_roots,
                "UNKNOWN_ROOT", "Archive root is not configured")
        binding = self.config.archive_roots[root_id]
        require(binding["subject_id"] == subject_id, "WRONG_SUBJECT", "Archive is bound to another subject")
        return root_id, Path(binding["path"]), ref["relative_path"]

    def check_current_source(self, version: dict) -> bool:
        manifest = self._saved_manifest(version)
        if manifest is not None:
            # Frozen review concerns this immutable byte version, even after a
            # current archive occurrence is renamed or replaced. Never heal a
            # corrupted snapshot by silently substituting live archive bytes.
            self.originals.read_manifest(version["subject_id"], manifest, version)
            return True
        occurrences = [o for o in self.records.store.list("file_occurrence", version["subject_id"])
                       if o["version_id"] == version["version_id"]]
        if not occurrences:
            raise V2Error("SOURCE_UNAVAILABLE", "This source has no registered file occurrence")
        changed = False
        for occurrence in occurrences:
            try:
                _, root, relative = self._binding(version["subject_id"],
                    {"root_id": occurrence["root_id"], "relative_path": occurrence["relative_path"]})
                content = read_source(root, relative)
            except V2Error:
                continue
            if hashlib.sha256(content).hexdigest() == version["source_sha256"]:
                return True
            changed = True
        raise V2Error("SOURCE_CHANGED" if changed else "SOURCE_UNAVAILABLE", "Source no longer matches the displayed version")

    def prepare_import(self, subject_id: str, input_refs: list[dict], force_reextract: bool = False) -> dict:
        require(isinstance(input_refs, list) and 1 <= len(input_refs) <= MAX_IMPORT_FILES,
                "INPUT_LIMIT", "Import accepts 1 to 100 explicit files")
        require(type(force_reextract) is bool, "INVALID_ARGUMENT", "Re-extraction choice must be boolean")
        # Read all inputs before committing any registration; hard errors roll back all.
        inputs = []
        total_bytes = 0
        for ref in input_refs:
            root_id, root, relative = self._binding(subject_id, ref)
            content = read_source(root, relative)
            total_bytes += len(content)
            require(total_bytes <= MAX_IMPORT_BYTES, "INPUT_LIMIT", "Import batch exceeds 128 MiB; split it explicitly")
            require(bool(content), "EMPTY_SOURCE", "Source is empty")
            suffix = Path(relative).suffix.casefold()
            mime = {".csv": "text/csv", ".txt": "text/plain", ".pdf": "application/pdf",
                    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}.get(suffix)
            require(mime is not None, "UNSUPPORTED_SOURCE", "Supported inputs are CSV, TXT, PDF, PNG and JPEG")
            if suffix == ".pdf":
                require(content[:1024].lstrip().startswith(b"%PDF-"), "SOURCE_TYPE_MISMATCH", "PDF extension does not match bytes")
            if mime == "image/png":
                require(content.startswith(b"\x89PNG\r\n\x1a\n"), "SOURCE_TYPE_MISMATCH", "PNG signature missing")
            if mime == "image/jpeg":
                require(content.startswith(b"\xff\xd8\xff"), "SOURCE_TYPE_MISMATCH", "JPEG signature missing")
            inputs.append((root_id, relative, content, mime))
        results = []
        preview_remaining = MAX_PREVIEW_BYTES
        with self.records.store.transaction():
            try:
                self.records.store.get("subject", subject_id, subject_id)
            except V2Error as exc:
                if exc.code != "NOT_FOUND":
                    raise
                self.records.register_subject(subject_id, subject_id)
            for root_id, relative, content, mime in inputs:
                registered = self.records.register_document(subject_id,
                    hashlib.sha256(content).hexdigest(), mime, len(content),
                    occurrence={"root_id": root_id, "relative_path": relative})
                version = self.records.store.get("document_version", registered["version_id"], subject_id)
                manifest = self.originals.preserve(subject_id, content, mime)
                self.records.store.put("original_manifest", self._manifest_id(version),
                    {"subject_id": subject_id, "version_id": version["version_id"], "manifest": manifest}, subject_id)
                prior_run = None
                if registered["deduplicated"] and not force_reextract:
                    try:
                        prior_run = self.records._latest_run(subject_id, version["version_id"])
                    except V2Error as exc:
                        if exc.code != "no_extraction":
                            raise
                if prior_run is not None:
                    issue_ids = [i["issue_id"] for i in self.records.store.list("import_issue", subject_id)
                                 if i["run_id"] == prior_run["run_id"]]
                    results.append({**registered, "run_id": prior_run["run_id"], "draft_ids": prior_run["draft_ids"],
                        "panel_ids": prior_run["panel_ids"], "source_ref": {"root_id": root_id, "relative_path": relative},
                        "saved_original": manifest, "issue_ids": issue_ids, "native_text": [],
                        "native_preview_truncated": False, "recognition_reused": True,
                        "document_texts": self._document_text_refs(subject_id, version["version_id"]),
                        "limitations": ["Existing scoped extraction reused; no new OCR or model verification performed"]})
                    continue
                rows, coverage, raw_text, limitations, issues = self._extract(content, mime, version)
                from .attachments import _native_pages
                from .document_io import DocumentIOService
                full_pages = _native_pages(content, mime, raw_text, coverage)
                if full_pages:
                    DocumentIOService(self.config, self.records, self)._save_native_document_text(
                        subject_id, version["version_id"], version["source_sha256"], full_pages,
                        method="native_text" if mime.startswith("text/") else "native_pdf_text")
                preview = []
                truncated = False
                for section in raw_text:
                    encoded = section["text"].encode("utf-8")
                    if len(encoded) > preview_remaining:
                        truncated = True
                    shown = encoded[:preview_remaining].decode("utf-8", errors="ignore")
                    if shown:
                        preview.append({"page": section["page"], "text": shown})
                    preview_remaining -= min(len(encoded), preview_remaining)
                if truncated:
                    limitations = [*limitations, "Native text preview truncated at shared 256 KiB response budget; source/extraction coverage is separate"]
                extraction = self.records.submit_extraction(subject_id, version["version_id"], rows, coverage)
                issue_ids = self.issues.register(subject_id, version["version_id"], extraction["run_id"], issues)
                results.append({**registered, **extraction, "source_ref": {"root_id": root_id, "relative_path": relative},
                                "saved_original": manifest, "issue_ids": issue_ids, "recognition_reused": False,
                                "document_texts": self._document_text_refs(subject_id, version["version_id"]),
                                "native_text": preview, "native_preview_truncated": truncated, "limitations": limitations})
        return {"subject_id": subject_id, "documents": results, "confirmed": False}

    def _document_text_refs(self, subject_id: str, version_id: str) -> list[dict]:
        from .document_io import validate_document_transcript
        fields = ("transcript_id", "method", "model", "page_count", "text_bytes", "recorded_at")
        result = []
        for header in self.records.store.list("document_transcript", subject_id):
            if header.get("version_id") == version_id:
                validate_document_transcript(header, subject_id=subject_id)
                result.append({key: header[key] for key in fields})
        return result

    def refresh_source_status(self, subject_id: str, version_ids: list[str]) -> dict:
        require(isinstance(version_ids, list) and 1 <= len(version_ids) <= 20
                and all(isinstance(v, str) for v in version_ids) and len(set(version_ids)) == len(version_ids),
                "INPUT_LIMIT", "Source refresh accepts 1 to 20 distinct version IDs")
        versions = [self.records.store.get("document_version", v, subject_id) for v in version_ids]
        statuses = []
        # Validate scope before any write. Results are check-time observations,
        # not a promise of future availability or medical validity.
        with self.records.store.transaction():
            for version in versions:
                try:
                    self.check_current_source(version)
                    available, status = True, "available"
                except V2Error as exc:
                    if exc.code not in {"SOURCE_CHANGED", "SOURCE_UNAVAILABLE", "ORIGINAL_UNAVAILABLE",
                                        "ORIGINAL_INTEGRITY_FAILURE", "UNSAFE_ORIGINAL_PATH"}:
                        raise
                    available = False
                    status = "source_changed" if exc.code == "SOURCE_CHANGED" else "integrity_failure" if exc.code in {"ORIGINAL_INTEGRITY_FAILURE", "UNSAFE_ORIGINAL_PATH"} else "unavailable"
                event = self.records.record_source_availability(subject_id, version["version_id"], available)
                statuses.append({**event, "checked_status": status,
                                 "check_basis": "saved_original_sha256" if self._saved_manifest(version) else "bounded_current_source_sha256",
                                 "archive_sources": self._archive_status(version), "future_availability": "not_guaranteed"})
        return {"subject_id": subject_id, "sources": statuses}

    def _extract(self, content: bytes, mime: str, version: dict) -> tuple[list, dict, list, list, list]:
        coverage = {"status": "partial", "expected_count": None, "expected_count_basis": "unknown",
                    "processed_pages": [], "unprocessed_pages": [], "errors": [],
                    "method": "native_table", "model": None, "provider": "v2", "extractor_version": "1"}
        rows: list[dict] = []
        raw_text = []
        limitations = []
        issues = []
        from .delimited import extract_delimited, unmapped_text_issues
        if mime in {"text/csv", "text/plain"}:
            text = _text(content)
            try:
                rows, table_issues = extract_delimited(text, version, locator_kind="csv" if mime == "text/csv" else "text")
                issues.extend(table_issues)
                coverage.update(status="complete", expected_count=len(rows), expected_count_basis="source_count")
            except V2Error as exc:
                if exc.code not in {"TABLE_MAPPING_REQUIRED", "AMBIGUOUS_COLUMNS"}:
                    raise
                coverage["errors"].append(exc.code)
                raw_text = [{"page": None, "text": text}]
                issues.extend(unmapped_text_issues(text, version, exc.code))
                limitations.append("Explicit column mapping/transcription required; no values guessed")
            if issues:
                coverage.update(status="partial" if rows else "visual_required", expected_count=None, expected_count_basis="unknown")
                coverage["errors"] = sorted(set(coverage["errors"]) | {code for issue in issues for code in issue["reason_codes"]})
        else:
            from .layout import propose_lab_rows
            blocks, limitations = (self.image_extractor(content) if mime.startswith("image/") else self.pdf_extractor(content))
            pages = set()
            document_incomplete = not blocks
            layout_pages = []
            if mime.startswith("image/") and not blocks:
                # PNG/JPEG have exactly one image page even before visual text
                # is supplied; absence of OCR is not a PDF parser failure.
                pages.add(1)
                coverage["unprocessed_pages"].append(1)
                coverage["method"] = "source_index"
            for block in blocks:
                locator = getattr(block, "locator", None)
                page = getattr(block, "page", None) or getattr(block, "page_number", None)
                if page is None and locator is not None:
                    page = getattr(locator, "page", None)
                if page is None:
                    for key, value in getattr(block, "metadata", ()):
                        if key == "page_number":
                            page = int(value)
                text = getattr(block, "text", "") or ""
                if isinstance(block, dict):
                    page, text = block.get("page"), block.get("text", "")
                document_incomplete = document_incomplete or (block.get("document_incomplete", False)
                    if isinstance(block, dict) else getattr(block, "document_incomplete", False))
                if page is not None:
                    pages.add(page)
                if text.strip() or (isinstance(block, dict) and block.get("source") == "vision_ocr"):
                    raw_text.append({"page": page, "text": text})
                    if mime.startswith("image/") or (isinstance(block, dict) and block.get("source") == "vision_ocr"):
                        layout_pages.append(block)
                        continue
                    try:
                        table_rows, table_issues = extract_delimited(text, version, locator_kind="pdf", page=page)
                        rows.extend(table_rows)
                        issues.extend(table_issues)
                    except V2Error as exc:
                        if exc.code not in {"TABLE_MAPPING_REQUIRED", "AMBIGUOUS_COLUMNS"}:
                            raise
                        layout_pages.append(block if isinstance(block, dict) and block.get("source") in {"pdf_text", "vision_ocr"}
                            else {"page": page, "text": text, "blocks": [], "width": 1, "height": 1, "source": "pdf_text"})
                elif page:
                    coverage["unprocessed_pages"].append(page)
                    issues.append({"page": page, "source": "pdf_text", "raw_text": "", "raw_cells": [],
                        "reason_codes": ["NO_NATIVE_TEXT"], "alternatives": [], "proposed_row": None})
            if layout_pages:
                pending_before_layout = set(coverage["unprocessed_pages"])
                proposed = propose_lab_rows(layout_pages, version, locator_kind="image" if mime.startswith("image/") else "pdf")
                rows.extend(proposed["rows"])
                issues.extend(proposed["issues"])
                from .ocr_review import annotate_ocr_rows, preserve_unmapped_ocr_candidates
                issues.extend(annotate_ocr_rows(proposed["rows"], layout_pages))
                issues.extend(preserve_unmapped_ocr_candidates(proposed["rows"], layout_pages, version,
                    locator_kind="image" if mime.startswith("image/") else "pdf"))
                coverage.update(proposed["coverage"])
                coverage["unprocessed_pages"] = sorted(pending_before_layout | set(coverage["unprocessed_pages"]))
                # Quality warnings are source uncertainty, even if OCR's
                # confidence is high. Do not drop orientation/mirroring flags
                # while converting page geometry into laboratory rows.
                for layout_page in layout_pages:
                    codes = [str(code).upper() for code in layout_page.get("metadata", {}).get("issues", [])
                             if code not in {"unit_glyph_review_required", "ocr_candidate_conflict"}]
                    if not codes:
                        continue
                    matching = []
                    for row in proposed["rows"]:
                        anchors = row["field_anchors"]["result"]
                        anchors = anchors if isinstance(anchors, list) else [anchors]
                        if any(a["locator"].get("page") == layout_page["page"] for a in anchors):
                            row.setdefault("field_status", {})["result"] = "ambiguous"
                            raw_cells = []
                            for field, values in row["field_anchors"].items():
                                if values is None:
                                    continue
                                values = values if isinstance(values, list) else [values]
                                raw_cells.append({"column": None, "role": field,
                                    "text": "\n".join(a["excerpt"] for a in values), "anchors": values})
                            matching.append({"page": layout_page["page"], "source": layout_page["source"],
                                "raw_text": "\n".join(a["excerpt"] for a in anchors), "raw_cells": raw_cells,
                                "reason_codes": codes, "alternatives": [], "proposed_row": row})
                    issues.extend(matching or [{"page": layout_page["page"], "source": layout_page["source"],
                        "raw_text": "", "raw_cells": [], "reason_codes": codes, "alternatives": [], "proposed_row": None}])
                    coverage["errors"] = sorted(set(coverage["errors"]) | set(codes))
            require(len(rows) <= MAX_EXTRACTED_ROWS, "ROW_LIMIT", "PDF exceeds whole-row extraction limit")
            require(len(rows) + sum(issue.get("proposed_row") is None for issue in issues) <= MAX_EXTRACTED_ROWS,
                    "ROW_LIMIT", "Split document explicitly; source-row candidates exceed 1000")
            coverage["unprocessed_pages"] = sorted(set(coverage["unprocessed_pages"]))
            coverage["processed_pages"] = sorted(pages - set(coverage["unprocessed_pages"]))
            coverage["status"] = "partial" if rows else "visual_required"
            if document_incomplete and mime == "application/pdf":
                coverage["errors"].append("PDF_DOCUMENT_INCOMPLETE")
            if rows and not document_incomplete and not coverage["unprocessed_pages"] and not coverage["errors"]:
                coverage.update(status="complete", expected_count=len(rows), expected_count_basis="extractor_count")
            if issues:
                coverage.update(status="partial" if rows else "visual_required", expected_count=None, expected_count_basis="unknown")
        return rows, coverage, raw_text, limitations, issues

    def submit_visual(self, subject_id: str, version_id: str, rows: list[dict], coverage: dict) -> dict:
        require(isinstance(coverage, dict), "INVALID_COVERAGE", "Visual coverage must be an object")
        version = self.records.store.get("document_version", version_id, subject_id)
        self.check_current_source(version)
        require(coverage.get("method") in {"model_vision", "manual_transcription"},
                "INVALID_EXTRACTION_METHOD", "Visual submission must identify its actual method")
        require(isinstance(rows, list) and len(rows) <= MAX_EXTRACTED_ROWS,
                "INVALID_ROWS", "Visual rows must be a bounded list")
        from .contracts import extraction_coverage
        extraction_coverage(coverage, len(rows))
        # Whole-document completeness is not proven by a model's row count or
        # a caller-authored page list. Native intake supplies its own coverage;
        # this untrusted visual entrypoint accepts partial proposals only.
        require(coverage.get("status") != "complete" and coverage.get("expected_count") is None
                and coverage.get("expected_count_basis", "unknown") == "unknown",
                "VISUAL_COVERAGE_UNVERIFIED", "Visual proposals cannot declare complete source coverage or a verified source count")
        anchored_pages = set()
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get("field_anchors", {}), dict),
                    "INVALID_ROWS", "Visual rows and anchors must be objects")
            for field, anchors in row.get("field_anchors", {}).items():
                if anchors is None:
                    continue
                for anchor in anchors if isinstance(anchors, list) else [anchors]:
                    require(isinstance(anchor, dict), "INVALID_ANCHOR", "Visual anchor must be an object")
                    require(isinstance(anchor.get("locator"), dict), "INVALID_ANCHOR", "Visual locator must be an object")
                    require(anchor.get("version_id") == version_id and anchor.get("source_sha256") == version["source_sha256"],
                            "ANCHOR_SCOPE_MISMATCH", "Visual anchor does not match the actual source")
                    require(anchor.get("locator", {}).get("kind") in {"pdf", "image", "text", "csv"},
                            "INVALID_ANCHOR", "Visual transcription needs a source locator")
                    if version["mime"].startswith("image/"):
                        require(anchor["locator"].get("kind") == "image" and anchor["locator"].get("page") == 1,
                                "INVALID_ANCHOR", "An image source has exactly one image page")
                    page = anchor["locator"].get("page")
                    if page is not None:
                        require(type(page) is int and 1 <= page <= 500,
                                "INVALID_ANCHOR", "Visual source pages must be bounded one-based integers")
                        anchored_pages.add(page)
        require(set(coverage.get("processed_pages", [])) <= anchored_pages,
                "VISUAL_COVERAGE_UNVERIFIED", "Visual processed pages must have actual submitted source anchors")
        result = self.records.submit_extraction(subject_id, version_id, rows, coverage)
        return {**result, "confirmed": False, "verification": "model_proposed"}
