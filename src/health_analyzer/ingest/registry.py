"""Extractor protocols and deterministic MIME/capability registry."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .models import (
    BlockDraft,
    DocumentArtifact,
    ExtractionCapability,
    content_hash,
    normalize_media_type,
)


class ExtractorFailure(RuntimeError):
    def __init__(self, code: str, message: str, *, recoverable: bool = True) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.recoverable = recoverable


@dataclass(frozen=True, slots=True)
class ExtractorDescriptor:
    extractor_id: str
    version: str
    mime_types: tuple[str, ...]
    capabilities: frozenset[ExtractionCapability]
    priority: int = 0
    configuration_fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.extractor_id or not self.version:
            raise ValueError("extractor ID and version are required")
        object.__setattr__(self, "mime_types", tuple(self.mime_types))
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        for mime in self.mime_types:
            if mime != "*/*" and not mime.endswith("/*"):
                normalize_media_type(mime)


@runtime_checkable
class Extractor(Protocol):
    descriptor: ExtractorDescriptor

    def extract(self, artifact: DocumentArtifact) -> tuple[BlockDraft, ...]: ...


def _mime_matches(pattern: str, media_type: str) -> bool:
    pattern = pattern.casefold()
    if pattern == "*/*":
        return True
    if pattern.endswith("/*"):
        return media_type.startswith(pattern[:-1])
    return normalize_media_type(pattern) == media_type


class ExtractorRegistry:
    def __init__(self, extractors: Iterable[Extractor] = ()) -> None:
        self._extractors: dict[str, Extractor] = {}
        self._frozen = False
        self._fingerprint: str | None = None
        for extractor in extractors:
            self.register(extractor)

    def register(self, extractor: Extractor) -> None:
        if self._frozen:
            raise RuntimeError("extractor registry is frozen")
        descriptor = extractor.descriptor
        if descriptor.extractor_id in self._extractors:
            raise ValueError(f"duplicate extractor ID: {descriptor.extractor_id}")
        self._extractors[descriptor.extractor_id] = extractor

    def freeze(self) -> "ExtractorRegistry":
        if not self._frozen:
            self._fingerprint = content_hash(
                [
                    {
                        "extractor_id": item.extractor_id,
                        "version": item.version,
                        "mime_types": list(item.mime_types),
                        "capabilities": sorted(value.value for value in item.capabilities),
                        "priority": item.priority,
                        "configuration_fingerprint": item.configuration_fingerprint,
                    }
                    for item in self.descriptors()
                ]
            )
            self._frozen = True
        return self

    @property
    def frozen(self) -> bool:
        return self._frozen

    @property
    def fingerprint(self) -> str:
        if not self._frozen or self._fingerprint is None:
            raise RuntimeError("extractor registry must be frozen before fingerprinting")
        return self._fingerprint

    def select(
        self,
        artifact: DocumentArtifact,
        *,
        required_capabilities: frozenset[ExtractionCapability] = frozenset(),
    ) -> tuple[Extractor, ...]:
        selected = [
            extractor for extractor in self._extractors.values()
            if required_capabilities <= extractor.descriptor.capabilities
            and any(
                _mime_matches(pattern, artifact.media_type)
                for pattern in extractor.descriptor.mime_types
            )
        ]
        selected.sort(
            key=lambda item: (
                -item.descriptor.priority,
                item.descriptor.extractor_id,
                item.descriptor.version,
            )
        )
        return tuple(selected)

    def descriptors(self) -> tuple[ExtractorDescriptor, ...]:
        return tuple(
            self._extractors[key].descriptor for key in sorted(self._extractors)
        )
