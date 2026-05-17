#!/usr/bin/env python3
"""Reject obvious identifiers at the public MCP boundary.

This hook is deliberately narrow and is only defense in depth. Hooks can be
disabled, and hosted tools such as WebSearch do not traverse the local tool-hook
path. It cannot establish privacy or regulatory compliance. The public/private
MCP zone split remains the actual architectural boundary.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any


PUBLIC_TOOLS = frozenset(
    {
        "route_science_question",
        "load_public_evidence_packet",
        "load_public_evidence_baseline",
        "plan_guidance_discovery",
        "plan_evidence_search",
        "search_pubmed",
        "search_crossref",
        "register_evidence_claim_candidate",
        "review_evidence_claim_candidate",
        "store_evidence",
        "resolve_guidance",
        "register_guidance_claim_candidate",
        "review_guidance_claim_candidate",
        "store_guidance_evidence",
        "audit_public_claims",
    }
)

SENSITIVE_KEYS = frozenset(
    {
        "address",
        "birth_date",
        "case_packet",
        "case_packet_id",
        "date_of_birth",
        "dob",
        "document_text",
        "email",
        "family_name",
        "file_path",
        "full_name",
        "given_name",
        "insurance_id",
        "medical_record_number",
        "mrn",
        "passport",
        "patient_id",
        "patient_name",
        "phone",
        "policy_number",
        "raw_document",
        "raw_value",
        "snils",
        "source_hashes",
        "source_path",
        "subject_id",
    }
)

EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
SNILS_PATTERN = re.compile(r"(?<!\d)\d{3}[- ]?\d{3}[- ]?\d{3}[ -]?\d{2}(?!\d)")
SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
OPAQUE_ID_PATTERN = re.compile(
    r"(?:retr|eclaimcand|eclaim_rcpt|evclaim|evidence|guidance_review|"
    r"guidance_claim|query|run)_[a-f0-9]{20,64}\Z"
)
DIGEST_KEYS = frozenset(
    {
        "confirmed_source_document_sha256",
        "confirmed_source_snapshot_sha256",
        "content_hash",
        "content_sha256",
        "sha256",
        "source_document_sha256",
        "source_snapshot_sha256",
    }
)


def _is_present(value: Any) -> bool:
    return value not in (None, "", [], {})


def _find_identifier(value: Any, path: str = "$") -> str | None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).strip().lower().replace("-", "_")
            child_path = f"{path}.{raw_key}"
            if key in SENSITIVE_KEYS and _is_present(item):
                return child_path
            if (
                isinstance(item, str)
                and (
                    (key in DIGEST_KEYS and SHA256_PATTERN.fullmatch(item))
                    or OPAQUE_ID_PATTERN.fullmatch(item)
                )
            ):
                continue
            found = _find_identifier(item, child_path)
            if found:
                return found
        return None

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            found = _find_identifier(item, f"{path}[{index}]")
            if found:
                return found
        return None

    if isinstance(value, str):
        if OPAQUE_ID_PATTERN.fullmatch(value):
            return None
        if EMAIL_PATTERN.search(value) or SNILS_PATTERN.search(value):
            return path
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, TypeError):
        return 0

    tool_name = str(payload.get("tool_name", ""))
    tool = tool_name.rsplit("__", 1)[-1]
    if tool not in PUBLIC_TOOLS:
        return 0

    identifier_path = _find_identifier(payload.get("tool_input", {}))
    if identifier_path is None:
        return 0

    result = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "Public evidence tools accept de-identified inputs only; "
                f"possible private identifier found at {identifier_path}. "
                "Remove it in the offline/private zone before retrying."
            ),
        }
    }
    json.dump(result, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
