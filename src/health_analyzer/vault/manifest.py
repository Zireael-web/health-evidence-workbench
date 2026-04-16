"""Canonical, content-addressed per-subject manifests."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .models import SourceDocument


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


@dataclass(frozen=True, slots=True)
class SubjectManifest:
    subject_id: str
    documents: tuple[SourceDocument, ...]
    schema_version: str = "1.0"

    def payload(self) -> dict[str, Any]:
        ordered = sorted(
            self.documents,
            key=lambda item: (item.root_id, item.relative_path, item.source_id),
        )
        return {
            "schema_version": self.schema_version,
            "subject_id": self.subject_id,
            "documents": [item.to_manifest_dict() for item in ordered],
        }

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.payload()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "manifest_sha256": self.manifest_sha256}

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            indent=indent,
        )
