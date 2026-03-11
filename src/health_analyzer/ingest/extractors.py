"""Built-in safe fallbacks and optional provider adapters."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from typing import Protocol, runtime_checkable

from .models import (
    BlockDraft,
    BlockKind,
    DocumentArtifact,
    ExtractionCapability,
)
from .registry import ExtractorDescriptor, ExtractorFailure


def decode_text(content: bytes) -> str:
    """Decode explicit Unicode encodings without lossy replacement."""

    try:
        if content.startswith((b"\xff\xfe", b"\xfe\xff")):
            return content.decode("utf-16")
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ExtractorFailure(
            "unsupported_text_encoding",
            "Text is neither valid UTF-8 nor BOM-marked UTF-16.",
        ) from error


class PlainTextExtractor:
    descriptor = ExtractorDescriptor(
        extractor_id="stdlib-plain-text",
        version="1.0",
        mime_types=("text/*",),
        capabilities=frozenset({ExtractionCapability.NATIVE_TEXT}),
        priority=10,
    )

    def extract(self, artifact: DocumentArtifact) -> tuple[BlockDraft, ...]:
        text = decode_text(artifact.content)
        lines = text.splitlines()
        blocks: list[BlockDraft] = []
        paragraph: list[str] = []
        paragraph_start = 1

        def flush(end_line: int) -> None:
            nonlocal paragraph
            if paragraph:
                blocks.append(
                    BlockDraft(
                        kind=BlockKind.TEXT,
                        text="\n".join(paragraph),
                        line_start=paragraph_start,
                        line_end=end_line,
                        confidence=1.0,
                    )
                )
                paragraph = []

        for line_number, line in enumerate(lines, start=1):
            if line.strip():
                if not paragraph:
                    paragraph_start = line_number
                paragraph.append(line)
            else:
                flush(line_number - 1)
        flush(len(lines))

        if not blocks:
            raise ExtractorFailure("empty_text", "Text document has no non-empty blocks.")
        return tuple(blocks)


class CSVExtractor:
    descriptor = ExtractorDescriptor(
        extractor_id="stdlib-csv",
        version="1.2",
        mime_types=("text/csv", "application/csv"),
        capabilities=frozenset({ExtractionCapability.TABLE}),
        priority=100,
    )

    def __init__(
        self,
        *,
        max_input_bytes: int = 16 * 1024 * 1024,
        max_rows: int = 20_000,
        max_columns: int = 256,
        max_cell_bytes: int = 32 * 1024,
        max_cells: int = 1_000_000,
    ) -> None:
        limits = {
            "max_input_bytes": max_input_bytes,
            "max_rows": max_rows,
            "max_columns": max_columns,
            "max_cell_bytes": max_cell_bytes,
            "max_cells": max_cells,
        }
        for name, value in limits.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if max_input_bytes > 64 * 1024 * 1024:
            raise ValueError("max_input_bytes must not exceed 64 MiB")
        if max_rows > 1_000_000 or max_columns > 4096 or max_cells > 4_000_000:
            raise ValueError("CSV structural limits exceed the supported safety ceiling")
        if max_cell_bytes > 1024 * 1024:
            raise ValueError("max_cell_bytes must not exceed 1 MiB")
        self.max_input_bytes = max_input_bytes
        self.max_rows = max_rows
        self.max_columns = max_columns
        self.max_cell_bytes = max_cell_bytes
        self.max_cells = max_cells
        fingerprint = hashlib.sha256(
            json.dumps(limits, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        self.descriptor = ExtractorDescriptor(
            extractor_id=type(self).descriptor.extractor_id,
            version=type(self).descriptor.version,
            mime_types=type(self).descriptor.mime_types,
            capabilities=type(self).descriptor.capabilities,
            priority=type(self).descriptor.priority,
            configuration_fingerprint=fingerprint,
        )

    def extract(self, artifact: DocumentArtifact) -> tuple[BlockDraft, ...]:
        if artifact.byte_size > self.max_input_bytes:
            raise ExtractorFailure(
                "csv_input_size_limit_exceeded",
                "CSV input exceeds the configured byte limit.",
                recoverable=False,
            )
        text = decode_text(artifact.content)
        sample = text[:8192]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        try:
            reader = csv.reader(io.StringIO(text, newline=""), dialect)
            rows: list[tuple[str, ...]] = []
            total_cells = 0
            for row in reader:
                if len(rows) >= self.max_rows:
                    raise ExtractorFailure(
                        "csv_row_limit_exceeded",
                        "CSV row count exceeds the configured limit.",
                        recoverable=False,
                    )
                if len(row) > self.max_columns:
                    raise ExtractorFailure(
                        "csv_column_limit_exceeded",
                        "CSV column count exceeds the configured limit.",
                        recoverable=False,
                    )
                total_cells += len(row)
                if total_cells > self.max_cells:
                    raise ExtractorFailure(
                        "csv_cell_count_limit_exceeded",
                        "CSV cell count exceeds the configured limit.",
                        recoverable=False,
                    )
                frozen_row = tuple(row)
                if any(
                    len(cell.encode("utf-8")) > self.max_cell_bytes
                    for cell in frozen_row
                ):
                    raise ExtractorFailure(
                        "csv_cell_size_limit_exceeded",
                        "A CSV cell exceeds the configured byte limit.",
                        recoverable=False,
                    )
                rows.append(frozen_row)
            physical_line_end = reader.line_num
        except ExtractorFailure:
            raise
        except csv.Error as error:
            raise ExtractorFailure(
                "malformed_csv",
                "CSV parser rejected the document.",
            ) from error
        if not rows or not any(any(cell != "" for cell in row) for row in rows):
            raise ExtractorFailure("empty_table", "CSV document has no non-empty rows.")
        width = max(len(row) for row in rows)
        if len(rows) * width > self.max_cells:
            raise ExtractorFailure(
                "csv_cell_count_limit_exceeded",
                "CSV rectangularization exceeds the configured cell limit.",
                recoverable=False,
            )
        padded = tuple(row + ("",) * (width - len(row)) for row in rows)
        return (
            BlockDraft(
                kind=BlockKind.TABLE,
                rows=padded,
                line_start=1,
                line_end=physical_line_end,
                confidence=1.0,
                limitations=(
                    "CSV contains no standard header declaration; candidate generation may "
                    "use the first unique, non-empty row as labels, but retains that row as "
                    "positional candidates requiring review.",
                ),
            ),
        )


@runtime_checkable
class PDFProvider(Protocol):
    provider_id: str
    version: str

    def extract_pdf(self, content: bytes) -> tuple[BlockDraft, ...]: ...


@runtime_checkable
class OCRProvider(Protocol):
    provider_id: str
    version: str

    def recognize(self, content: bytes, media_type: str) -> tuple[BlockDraft, ...]: ...


class PDFProviderExtractor:
    """Adapter only; no PDF dependency is imported by core."""

    def __init__(self, provider: PDFProvider, *, priority: int = 50) -> None:
        self.provider = provider
        advertised_capabilities = getattr(provider, "capabilities", frozenset())
        configuration_fingerprint = getattr(
            provider,
            "configuration_fingerprint",
            "",
        )
        self.descriptor = ExtractorDescriptor(
            extractor_id=f"pdf-provider:{provider.provider_id}",
            version=provider.version,
            mime_types=("application/pdf",),
            capabilities=frozenset(
                {ExtractionCapability.PDF, *advertised_capabilities}
            ),
            priority=priority,
            configuration_fingerprint=configuration_fingerprint,
        )

    def extract(self, artifact: DocumentArtifact) -> tuple[BlockDraft, ...]:
        try:
            blocks = tuple(self.provider.extract_pdf(artifact.content))
        except ExtractorFailure:
            raise
        except Exception as error:
            raise ExtractorFailure(
                "pdf_provider_failure",
                f"PDF provider failed with {type(error).__name__}.",
            ) from None
        if not blocks:
            raise ExtractorFailure("empty_pdf_extraction", "PDF provider returned no blocks.")
        return blocks


class OCRProviderExtractor:
    """Adapter for optional OCR providers; output remains untrusted OCR data."""

    def __init__(
        self,
        provider: OCRProvider,
        *,
        mime_types: tuple[str, ...] = ("image/*",),
        priority: int = 50,
    ) -> None:
        self.provider = provider
        configuration_fingerprint = getattr(
            provider,
            "configuration_fingerprint",
            "",
        )
        self.descriptor = ExtractorDescriptor(
            extractor_id=f"ocr-provider:{provider.provider_id}",
            version=provider.version,
            mime_types=mime_types,
            capabilities=frozenset({ExtractionCapability.IMAGE, ExtractionCapability.OCR}),
            priority=priority,
            configuration_fingerprint=configuration_fingerprint,
        )

    def extract(self, artifact: DocumentArtifact) -> tuple[BlockDraft, ...]:
        try:
            blocks = tuple(self.provider.recognize(artifact.content, artifact.media_type))
        except ExtractorFailure:
            raise
        except Exception as error:
            raise ExtractorFailure(
                "ocr_provider_failure",
                f"OCR provider failed with {type(error).__name__}.",
            ) from None
        if not blocks:
            raise ExtractorFailure("empty_ocr_extraction", "OCR provider returned no blocks.")
        for block in blocks:
            if block.kind not in (BlockKind.OCR, BlockKind.TABLE, BlockKind.IMAGE):
                raise ExtractorFailure(
                    "invalid_ocr_block",
                    "OCR provider must label text as OCR, not native text.",
                    recoverable=False,
                )
        return blocks


class ImagePassthroughExtractor:
    """Records image payload identity when no OCR is requested or available."""

    descriptor = ExtractorDescriptor(
        extractor_id="stdlib-image-passthrough",
        version="1.0",
        mime_types=("image/*",),
        capabilities=frozenset({ExtractionCapability.IMAGE}),
        priority=1,
    )

    def extract(self, artifact: DocumentArtifact) -> tuple[BlockDraft, ...]:
        return (
            BlockDraft(
                kind=BlockKind.IMAGE,
                payload_sha256=hashlib.sha256(artifact.content).hexdigest(),
                page=1,
                document_incomplete=True,
                limitations=(
                    "Image bytes were indexed only; no OCR provider was used and "
                    "the document requires OCR before textual ingestion is complete.",
                ),
            ),
        )


def default_extractors() -> tuple[object, ...]:
    # PypdfTextProvider imports pypdf only when it receives a PDF.  Keeping the
    # adapter registered gives callers a structured missing-dependency failure
    # instead of making the whole ingestion package depend on pypdf at import time.
    from .pypdf_provider import PypdfTextProvider

    return (
        CSVExtractor(),
        PlainTextExtractor(),
        PDFProviderExtractor(PypdfTextProvider()),
        ImagePassthroughExtractor(),
    )
