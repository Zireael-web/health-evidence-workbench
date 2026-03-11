"""Immutable, type-independent document-ingestion models.

Nothing in this module assigns medical meaning.  It preserves source bytes,
ordered extractor output, generic candidates, and the metadata required for a
human to verify every transition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import math
import mimetypes
import os
from pathlib import Path
import re
import stat
from typing import Any

from health_analyzer.contracts import VerificationStatus


class IngestionError(RuntimeError):
    """Base error for deterministic ingestion failures."""


class SourceChangedDuringReadError(IngestionError):
    """Source bytes changed while an artifact was being constructed."""


MAX_ARTIFACT_SOURCE_BYTES = 64 * 1024 * 1024


def _read_stable_path(
    source: Path,
    *,
    maximum_bytes: int = MAX_ARTIFACT_SOURCE_BYTES,
) -> bytes:
    """Read one regular file through a stable descriptor with a hard byte cap."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(source, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise IngestionError("artifact source is not a regular file")
        if before.st_size > maximum_bytes:
            raise IngestionError("artifact source exceeds the 64 MiB size limit")

        content = bytearray()
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > maximum_bytes:
                raise IngestionError("artifact source exceeds the 64 MiB size limit")

        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or len(content) != after.st_size:
            raise SourceChangedDuringReadError(str(source))
        return bytes(content)
    finally:
        os.close(descriptor)


class BlockKind(StrEnum):
    TEXT = "text"
    TABLE = "table"
    IMAGE = "image"
    OCR = "ocr"


class CandidateKind(StrEnum):
    FIELD = "field"
    STATEMENT = "statement"


class ExtractionCapability(StrEnum):
    NATIVE_TEXT = "native_text"
    TABLE = "table"
    IMAGE = "image"
    PDF = "pdf"
    OCR = "ocr"


def canonical_json(payload: Any) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def content_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def deterministic_id(prefix: str, *parts: str) -> str:
    framed = "\0".join(("health-analyzer-ingest-v1", prefix, *parts))
    digest = hashlib.sha256(framed.encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:32]}"


def normalize_media_type(media_type: str) -> str:
    normalized = media_type.split(";", maxsplit=1)[0].strip().casefold()
    if "/" not in normalized:
        raise ValueError(f"invalid MIME type: {media_type!r}")
    return normalized


def sniff_media_type(content: bytes) -> str | None:
    """Return a MIME type only for strong, bounded binary signatures.

    The generic ingestion layer deliberately does not guess medical document
    types.  This helper only prevents a misleading file extension from routing
    unmistakable PDF or image bytes to an incompatible text extractor.
    """

    prefix = bytes(content[:1024])
    pdf_header = re.match(rb"\A%PDF-(?:1\.[0-7]|2\.0)(?:\r\n|\r|\n|[ \t])", prefix)
    if pdf_header and b"%%EOF" in bytes(content[-4096:]):
        return "application/pdf"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if prefix.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    if prefix.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if prefix.startswith(b"BM"):
        return "image/bmp"
    return None


@dataclass(frozen=True, slots=True)
class DocumentArtifact:
    artifact_id: str
    content_sha256: str
    media_type: str
    byte_size: int
    content: bytes = field(repr=False)
    source_name: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", bytes(self.content))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        if hashlib.sha256(self.content).hexdigest() != self.content_sha256:
            raise ValueError("content bytes do not match content_sha256")
        if self.byte_size != len(self.content):
            raise ValueError("byte_size does not match content")
        if self.artifact_id != deterministic_id("art", self.content_sha256):
            raise ValueError("artifact_id is not derived from content hash")
        object.__setattr__(self, "media_type", normalize_media_type(self.media_type))

    @classmethod
    def from_bytes(
        cls,
        content: bytes,
        *,
        media_type: str,
        source_name: str | None = None,
        metadata: tuple[tuple[str, str], ...] = (),
        limitations: tuple[str, ...] = (),
    ) -> "DocumentArtifact":
        immutable = bytes(content)
        digest = hashlib.sha256(immutable).hexdigest()
        return cls(
            artifact_id=deterministic_id("art", digest),
            content_sha256=digest,
            media_type=media_type,
            byte_size=len(immutable),
            content=immutable,
            source_name=source_name,
            metadata=tuple(metadata),
            limitations=tuple(limitations),
        )

    @classmethod
    def from_detected_bytes(
        cls,
        content: bytes,
        *,
        source_name: str | None = None,
        media_type: str | None = None,
        metadata: tuple[tuple[str, str], ...] = (),
        limitations: tuple[str, ...] = (),
    ) -> "DocumentArtifact":
        """Create an artifact using content signatures before filename hints.

        Explicit or extension-derived MIME values remain in metadata when a
        strong signature disagrees, so the routing decision is auditable.
        """

        immutable = bytes(content)
        hinted = (
            normalize_media_type(media_type)
            if media_type is not None
            else (
                mimetypes.guess_type(source_name or "")[0]
                or "application/octet-stream"
            )
        )
        detected = sniff_media_type(immutable)
        resolved = detected or hinted
        extra_metadata: tuple[tuple[str, str], ...]
        extra_limitations: tuple[str, ...]
        if detected is not None and detected != hinted:
            extra_metadata = (
                ("media_type_hint", hinted),
                ("media_type_detection", "strong_content_signature"),
            )
            extra_limitations = (
                "A strong content signature disagreed with the supplied or filename-derived "
                "media type; extractor routing used the content signature.",
            )
        else:
            extra_metadata = (
                (
                    "media_type_detection",
                    "strong_content_signature" if detected else "supplied_or_filename_hint",
                ),
            )
            extra_limitations = ()
        return cls.from_bytes(
            immutable,
            media_type=resolved,
            source_name=source_name,
            metadata=(*metadata, *extra_metadata),
            limitations=(*limitations, *extra_limitations),
        )

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        media_type: str | None = None,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> "DocumentArtifact":
        source = Path(path)
        content = _read_stable_path(source)
        return cls.from_detected_bytes(
            content,
            media_type=media_type,
            source_name=source.name,
            metadata=metadata,
        )


@dataclass(frozen=True, slots=True)
class InstructionFinding:
    finding_id: str
    pattern_id: str
    category: str
    severity: str
    line: int | None
    matched_text_sha256: str
    description: str


@dataclass(frozen=True, slots=True)
class BlockDraft:
    """Provider output before deterministic block IDs and hashes are assigned."""

    kind: BlockKind
    text: str | None = None
    rows: tuple[tuple[str, ...], ...] = ()
    payload_sha256: str | None = None
    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    line_start: int | None = None
    line_end: int | None = None
    confidence: float | None = None
    document_incomplete: bool = False
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rows", _freeze_rows(self.rows))
        object.__setattr__(self, "bbox", _freeze_bbox(self.bbox))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        if self.kind in (BlockKind.TEXT, BlockKind.OCR) and self.text is None:
            raise ValueError("text/OCR blocks require text")
        if (
            self.kind in (BlockKind.TEXT, BlockKind.OCR)
            and self.text is not None
            and not self.text.strip()
        ):
            object.__setattr__(self, "document_incomplete", True)
            object.__setattr__(
                self,
                "limitations",
                tuple(
                    dict.fromkeys(
                        (
                            *self.limitations,
                            "Extractor returned no non-whitespace text; document "
                            "ingestion remains incomplete.",
                        )
                    )
                ),
            )
        if self.kind is BlockKind.TABLE and not self.rows:
            raise ValueError("table blocks require rows")
        if self.kind is BlockKind.IMAGE and self.payload_sha256 is None:
            raise ValueError("image blocks require a payload hash")
        if self.kind is BlockKind.IMAGE:
            object.__setattr__(self, "document_incomplete", True)
            object.__setattr__(
                self,
                "limitations",
                tuple(
                    dict.fromkeys(
                        (
                            *self.limitations,
                            "Image bytes alone do not establish complete textual "
                            "ingestion; OCR or explicit image review is required.",
                        )
                    )
                ),
            )
        _validate_location(self.page, self.bbox, self.line_start, self.line_end)
        _validate_confidence(self.confidence)

    @property
    def row_spans(self) -> tuple[tuple[int | None, int | None], ...]:
        """Return source-line spans derived from ordered table rows.

        Blank CSV records remain rows, and embedded CR/LF sequences remain in
        parsed cells, so the mapping is deterministic without a format-specific
        side channel through the ingestion pipeline.
        """

        return _table_row_spans(self.rows, self.line_start)


@dataclass(frozen=True, slots=True)
class ExtractionBlock:
    block_id: str
    artifact_id: str
    artifact_sha256: str
    ordinal: int
    kind: BlockKind
    block_sha256: str
    extractor_id: str
    extractor_version: str
    text: str | None = None
    rows: tuple[tuple[str, ...], ...] = ()
    payload_sha256: str | None = None
    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    line_start: int | None = None
    line_end: int | None = None
    confidence: float | None = None
    document_incomplete: bool = False
    instruction_findings: tuple[InstructionFinding, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rows", _freeze_rows(self.rows))
        object.__setattr__(self, "bbox", _freeze_bbox(self.bbox))
        object.__setattr__(
            self,
            "instruction_findings",
            tuple(self.instruction_findings),
        )
        object.__setattr__(self, "limitations", tuple(self.limitations))
        if self.ordinal < 0:
            raise ValueError("block ordinal must be non-negative")
        if self.kind in (BlockKind.TEXT, BlockKind.OCR) and self.text is None:
            raise ValueError("text/OCR blocks require text")
        if (
            self.kind in (BlockKind.TEXT, BlockKind.OCR)
            and self.text is not None
            and not self.text.strip()
        ):
            object.__setattr__(self, "document_incomplete", True)
            object.__setattr__(
                self,
                "limitations",
                tuple(
                    dict.fromkeys(
                        (
                            *self.limitations,
                            "Extractor returned no non-whitespace text; document "
                            "ingestion remains incomplete.",
                        )
                    )
                ),
            )
        if self.kind is BlockKind.TABLE and not self.rows:
            raise ValueError("table blocks require rows")
        if self.kind is BlockKind.IMAGE and self.payload_sha256 is None:
            raise ValueError("image blocks require a payload hash")
        if self.kind is BlockKind.IMAGE:
            object.__setattr__(self, "document_incomplete", True)
            object.__setattr__(
                self,
                "limitations",
                tuple(
                    dict.fromkeys(
                        (
                            *self.limitations,
                            "Image bytes alone do not establish complete textual "
                            "ingestion; OCR or explicit image review is required.",
                        )
                    )
                ),
            )
        _validate_location(self.page, self.bbox, self.line_start, self.line_end)
        _validate_confidence(self.confidence)
        if self.block_sha256 != content_hash(self.content_payload()):
            raise ValueError("block content does not match block_sha256")
        expected_id = deterministic_id(
            "blk",
            self.artifact_id,
            str(self.ordinal),
            self.block_sha256,
            self.extractor_id,
            self.extractor_version,
        )
        if self.block_id != expected_id:
            raise ValueError("block_id is not derived from block content and extractor")

    def content_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "text": self.text,
            "rows": [list(row) for row in self.rows],
            "payload_sha256": self.payload_sha256,
            "page": self.page,
            "bbox": list(self.bbox) if self.bbox else None,
            "line_start": self.line_start,
            "line_end": self.line_end,
        }

    @property
    def row_spans(self) -> tuple[tuple[int | None, int | None], ...]:
        """Return source-line spans derived from ordered table rows."""

        return _table_row_spans(self.rows, self.line_start)


@dataclass(frozen=True, slots=True)
class CandidateProvenance:
    artifact_id: str
    artifact_sha256: str
    block_id: str
    block_sha256: str
    extractor_id: str
    extractor_version: str
    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    line_start: int | None = None
    line_end: int | None = None
    row_index: int | None = None
    column_index: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "bbox", _freeze_bbox(self.bbox))
        _validate_location(self.page, self.bbox, self.line_start, self.line_end)
        if self.row_index is not None and self.row_index < 1:
            raise ValueError("row_index must be one-based")
        if self.column_index is not None and self.column_index < 1:
            raise ValueError("column_index must be one-based")


@dataclass(frozen=True, slots=True)
class ReviewEvent:
    event_id: str
    from_status: VerificationStatus
    to_status: VerificationStatus
    reviewer_id: str
    reviewed_at: str
    note: str | None = None


@dataclass(frozen=True, slots=True)
class Candidate:
    candidate_id: str
    candidate_sha256: str
    kind: CandidateKind
    raw_value: str
    field_name: str | None
    confidence: float | None
    provenance: tuple[CandidateProvenance, ...]
    verification: VerificationStatus = VerificationStatus.EXTRACTED
    instruction_findings: tuple[InstructionFinding, ...] = ()
    review_history: tuple[ReviewEvent, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "provenance", tuple(self.provenance))
        object.__setattr__(
            self,
            "instruction_findings",
            tuple(self.instruction_findings),
        )
        object.__setattr__(self, "review_history", tuple(self.review_history))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        if self.kind is CandidateKind.FIELD and not self.field_name:
            raise ValueError("field candidates require field_name")
        if self.kind is CandidateKind.STATEMENT and self.field_name is not None:
            raise ValueError("statement candidates cannot have field_name")
        if not self.provenance:
            raise ValueError("candidate requires provenance")
        _validate_confidence(self.confidence)


@dataclass(frozen=True, slots=True)
class ExtractionFailure:
    failure_id: str
    code: str
    message: str
    extractor_id: str | None = None
    extractor_version: str | None = None
    recoverable: bool = True


@dataclass(frozen=True, slots=True)
class IngestionResult:
    artifact: DocumentArtifact
    blocks: tuple[ExtractionBlock, ...]
    candidates: tuple[Candidate, ...]
    failures: tuple[ExtractionFailure, ...] = ()
    limitations: tuple[str, ...] = ()
    deduplicated: bool = False
    duplicate_of_artifact_id: str | None = None
    complete: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "blocks", tuple(self.blocks))
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "failures", tuple(self.failures))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        ordinals = tuple(block.ordinal for block in self.blocks)
        if ordinals != tuple(range(len(self.blocks))):
            raise ValueError("blocks must be ordered with contiguous ordinals")
        if self.complete and not self.blocks:
            raise ValueError("complete ingestion requires at least one block")
        if self.complete and self.failures:
            raise ValueError("complete ingestion cannot contain extraction failures")
        if self.complete and any(block.document_incomplete for block in self.blocks):
            raise ValueError("complete ingestion cannot contain incomplete document blocks")


def _validate_location(
    page: int | None,
    bbox: tuple[float, float, float, float] | None,
    line_start: int | None,
    line_end: int | None,
) -> None:
    if page is not None and page < 1:
        raise ValueError("page must be one-based")
    if bbox is not None:
        if len(bbox) != 4 or not all(math.isfinite(value) for value in bbox):
            raise ValueError("bbox must contain four finite values")
        if bbox[2] <= bbox[0] or bbox[3] <= bbox[1]:
            raise ValueError("bbox must have positive area")
    if line_start is not None and line_start < 1:
        raise ValueError("line_start must be one-based")
    if line_end is not None and (line_start is None or line_end < line_start):
        raise ValueError("line_end requires a preceding line_start")


def _validate_confidence(confidence: float | None) -> None:
    if confidence is not None and not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")


def _freeze_metadata(
    metadata: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    frozen: list[tuple[str, str]] = []
    for item in metadata:
        pair = tuple(item)
        if len(pair) != 2 or not all(isinstance(value, str) for value in pair):
            raise ValueError("metadata must contain string key/value pairs")
        frozen.append((pair[0], pair[1]))
    return tuple(frozen)


def _freeze_rows(rows: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
    frozen: list[tuple[str, ...]] = []
    for row in rows:
        if isinstance(row, str):
            raise ValueError("table rows must be sequences of cells, not strings")
        cells = tuple(row)
        if not all(isinstance(cell, str) for cell in cells):
            raise ValueError("table cells must be strings")
        frozen.append(cells)
    return tuple(frozen)


def _table_row_spans(
    rows: tuple[tuple[str, ...], ...],
    line_start: int | None,
) -> tuple[tuple[int | None, int | None], ...]:
    if not rows:
        return ()
    if line_start is None:
        return tuple((None, None) for _ in rows)

    spans: list[tuple[int, int]] = []
    current = line_start
    for row in rows:
        embedded_breaks = sum(
            cell.count("\n") + cell.count("\r") - cell.count("\r\n")
            for cell in row
        )
        end = current + embedded_breaks
        spans.append((current, end))
        current = end + 1
    return tuple(spans)


def _freeze_bbox(
    bbox: tuple[float, float, float, float] | None,
) -> tuple[float, float, float, float] | None:
    if bbox is None:
        return None
    return tuple(bbox)  # type: ignore[return-value]
