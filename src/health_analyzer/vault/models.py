"""Value objects for the private, read-only source vault.

The vault never rewrites source documents.  These objects describe immutable
source bytes and precise locations inside those bytes or their rendered pages.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import math


class VaultError(RuntimeError):
    """Base class for vault failures."""


class SourceOutsideVaultError(VaultError):
    """Raised when a caller attempts to ingest a non-allowlisted path."""


class SourceChangedDuringReadError(VaultError):
    """Raised when source bytes change while their digest is being computed."""


class CrossSubjectDocumentError(VaultError):
    """Raised when one source path is assigned to more than one subject."""


class UnknownSubjectError(VaultError):
    """Raised when an operation is attempted for an unregistered subject."""


@dataclass(frozen=True, slots=True)
class AllowedRoot:
    """An allowlisted read-only source root with a non-sensitive identifier."""

    root_id: str
    path: Path

    def __post_init__(self) -> None:
        if not self.root_id or any(char in self.root_id for char in "/\\\0"):
            raise ValueError("root_id must be a non-empty path-safe identifier")
        object.__setattr__(self, "path", self.path.expanduser().resolve(strict=True))
        if not self.path.is_dir():
            raise ValueError(f"allowed root is not a directory: {self.path}")


@dataclass(frozen=True, slots=True)
class LocationHint:
    """A page/table/text location supplied during ingestion.

    Page numbers and lines are one-based.  Bounding boxes use the coordinate
    space of the source rendering; they are not assumed to be normalized.
    """

    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    line_start: int | None = None
    line_end: int | None = None
    char_start: int | None = None
    char_end: int | None = None

    def __post_init__(self) -> None:
        if self.page is not None and (
            not isinstance(self.page, int)
            or isinstance(self.page, bool)
            or self.page < 1
        ):
            raise ValueError("page must be a one-based integer")
        if self.bbox is not None:
            try:
                frozen_bbox = tuple(self.bbox)
            except TypeError:
                raise ValueError(
                    "bbox must contain four finite coordinates"
                ) from None
            object.__setattr__(self, "bbox", frozen_bbox)
            if len(self.bbox) != 4 or not all(
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                for value in self.bbox
            ):
                raise ValueError("bbox must contain four finite coordinates")
            x0, y0, x1, y1 = self.bbox
            if x1 <= x0 or y1 <= y0:
                raise ValueError("bbox must have positive width and height")
        if self.line_start is not None and (
            not isinstance(self.line_start, int)
            or isinstance(self.line_start, bool)
            or self.line_start < 1
        ):
            raise ValueError("line_start must be a one-based integer")
        if self.line_end is not None:
            if self.line_start is None:
                raise ValueError("line_end requires line_start")
            if not isinstance(self.line_end, int) or isinstance(self.line_end, bool):
                raise ValueError("line_end must be an integer")
            if self.line_end < self.line_start:
                raise ValueError("line_end must not precede line_start")
        if self.char_start is not None and (
            not isinstance(self.char_start, int)
            or isinstance(self.char_start, bool)
            or self.char_start < 0
        ):
            raise ValueError("char_start must be a non-negative integer")
        if self.char_end is not None:
            if self.char_start is None:
                raise ValueError("char_end requires char_start")
            if not isinstance(self.char_end, int) or isinstance(self.char_end, bool):
                raise ValueError("char_end must be an integer")
            if self.char_end < self.char_start:
                raise ValueError("char_end must not precede char_start")

    def to_dict(self) -> dict[str, Any]:
        return {
            "page": self.page,
            "bbox": list(self.bbox) if self.bbox is not None else None,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "char_start": self.char_start,
            "char_end": self.char_end,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceLocator:
    """A content-addressed pointer to an exact source location."""

    source_id: str
    sha256: str
    locator: str | None = None
    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    line_start: int | None = None
    line_end: int | None = None
    char_start: int | None = None
    char_end: int | None = None
    excerpt: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_id, str)
            or not self.source_id.strip()
            or "\0" in self.source_id
        ):
            raise ValueError("source_id must be non-empty text without NUL")
        if not isinstance(self.sha256, str):
            raise ValueError("sha256 must be a lowercase hexadecimal SHA-256 digest")
        if len(self.sha256) != 64 or any(ch not in "0123456789abcdef" for ch in self.sha256):
            raise ValueError("sha256 must be a lowercase hexadecimal SHA-256 digest")
        for name in ("locator", "excerpt"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str) or not value.strip() or "\0" in value
            ):
                raise ValueError(f"{name} must be non-empty text without NUL or null")
        hint = LocationHint(
            page=self.page,
            bbox=self.bbox,
            line_start=self.line_start,
            line_end=self.line_end,
            char_start=self.char_start,
            char_end=self.char_end,
        )
        object.__setattr__(self, "bbox", hint.bbox)

    @classmethod
    def from_hint(
        cls,
        source_id: str,
        sha256: str,
        hint: LocationHint,
    ) -> "ProvenanceLocator":
        return cls(source_id=source_id, sha256=sha256, **_hint_constructor_dict(hint))

    def to_dict(self) -> dict[str, Any]:
        payload = LocationHint(
            page=self.page,
            bbox=self.bbox,
            line_start=self.line_start,
            line_end=self.line_end,
            char_start=self.char_start,
            char_end=self.char_end,
        ).to_dict()
        return {
            "source_id": self.source_id,
            "sha256": self.sha256,
            "locator": self.locator,
            **payload,
            "excerpt": self.excerpt,
        }


def _hint_constructor_dict(hint: LocationHint) -> dict[str, Any]:
    return {
        "page": hint.page,
        "bbox": hint.bbox,
        "line_start": hint.line_start,
        "line_end": hint.line_end,
        "char_start": hint.char_start,
        "char_end": hint.char_end,
    }


@dataclass(frozen=True, slots=True)
class SourceDocument:
    source_id: str
    subject_id: str
    root_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    mtime_ns: int
    media_type: str
    indexed_at: str
    provenance: tuple[ProvenanceLocator, ...] = ()

    def to_manifest_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "root_id": self.root_id,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "mtime_ns": self.mtime_ns,
            "media_type": self.media_type,
            "indexed_at": self.indexed_at,
            "provenance": [locator.to_dict() for locator in self.provenance],
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    source_id: str
    status: str
    expected_sha256: str
    actual_sha256: str | None = None
    detail: str | None = None
