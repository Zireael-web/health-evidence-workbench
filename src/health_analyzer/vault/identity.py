"""Deterministic pseudonymous subject identifiers.

Plain hashes of names or dates of birth are vulnerable to dictionary attacks.
This module therefore requires a private HMAC key and expects callers to pass a
stable local record key, not free-form demographics.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import unicodedata


@dataclass(frozen=True, slots=True)
class SubjectPseudonymizer:
    secret: bytes
    namespace: str = "default"

    def __post_init__(self) -> None:
        if len(self.secret) < 32:
            raise ValueError("pseudonymization secret must contain at least 32 bytes")
        if not self.namespace.strip():
            raise ValueError("namespace must not be empty")

    def subject_id(self, local_patient_key: str) -> str:
        canonical = unicodedata.normalize("NFKC", local_patient_key).strip()
        if not canonical:
            raise ValueError("local_patient_key must not be empty")
        message = (
            b"health-analyzer/subject-id/v1\0"
            + self.namespace.encode("utf-8")
            + b"\0"
            + canonical.encode("utf-8")
        )
        digest = hmac.new(self.secret, message, hashlib.sha256).hexdigest()
        return f"subj_{digest[:32]}"
