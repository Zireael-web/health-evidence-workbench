"""Private, patient-scoped, read-only source ingestion."""

from .identity import SubjectPseudonymizer
from .manifest import SubjectManifest, canonical_json
from .models import (
    AllowedRoot,
    CrossSubjectDocumentError,
    LocationHint,
    ProvenanceLocator,
    SourceChangedDuringReadError,
    SourceDocument,
    SourceOutsideVaultError,
    UnknownSubjectError,
    VaultError,
    VerificationResult,
)
from .store import VaultIndex, sha256_file

__all__ = [
    "AllowedRoot",
    "CrossSubjectDocumentError",
    "LocationHint",
    "ProvenanceLocator",
    "SourceChangedDuringReadError",
    "SourceDocument",
    "SourceOutsideVaultError",
    "SubjectManifest",
    "SubjectPseudonymizer",
    "UnknownSubjectError",
    "VaultError",
    "VaultIndex",
    "VerificationResult",
    "canonical_json",
    "sha256_file",
]
