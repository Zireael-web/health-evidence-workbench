#!/usr/bin/env python3
"""Self-contained heuristic guard for this plugin's public MCP input only.

No transcript, local file, archive, credential, registry or network reads.
Explicit denial uses the supported PreToolUse protocol. A disabled/untrusted
hook or host hook failure can still skip enforcement; runtime validation and
manual de-identification remain necessary. Hosted WebSearch is not covered.
"""
from __future__ import annotations

import json
import re
import sys
from urllib.parse import unquote

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_NODES = 10000
MAX_VALUE_CHARS = 32768
PUBLIC_TOOL = re.compile(r"^mcp__.*health[-_]analyzer[-_]v2.*public[-_]research__.*$")
SENSITIVE_KEYS = frozenset({
    "subject_id", "patient_id", "patient_name", "full_name", "given_name", "family_name",
    "birth_date", "date_of_birth", "dob", "phone", "email", "address", "passport",
    "medical_record_number", "mrn", "insurance_id", "iin", "snils",
    "case_packet", "case_packet_id", "case_selection", "case_selection_id",
    "file_path", "local_path", "source_path", "vault_path", "archive_path", "archive_root",
    "raw_document", "raw_health_document", "document_text", "raw_value",
    "фио", "пациент", "имя_пациента", "дата_рождения", "номер_карты", "иин",
})
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
LOCAL_PATH = re.compile(r"(?:file://|(?<![\w.-])/(?:Users|home|private|tmp|Volumes|Library)/|[A-Za-z]:[\\/](?:Users|Documents|Desktop)[\\/]|analyses-all[\\/])", re.I)
PRIVATE_LABEL = re.compile(r"(?:patient[_ ]name|full[_ ]name|date[_ ]of[_ ]birth|dob|medical[_ ]record[_ ]number|mrn|phone|e-?mail|фио|пациент(?:ка)?|иин|дата\s+рождения|номер\s+карты|телефон)\s*[:=]\s*\S", re.I)
FORMATTED_PHONE = re.compile(r"(?<!\w)\+\d{1,3}[ -](?:\(?\d{2,4}\)?[ -]){1,3}\d{2,4}(?!\w)")
# Public review/run/plan/source IDs intentionally remain allowed. These
# prefixes identify only private records, or private extraction artifacts.
PRIVATE_ID = re.compile(r"\b(?:observation|revision|document|version|snapshot|context|case|extraction|occurrence|panel)_[a-f0-9]{32,64}\b", re.I)


def _present(value) -> bool:
    return value not in (None, "", [], {})


def _scan_input(value) -> str | None:
    pending = [value]
    visited = 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > MAX_NODES:
            return "complexity"
        if isinstance(item, dict):
            for raw_key, child in item.items():
                key = raw_key.strip().casefold().replace("-", "_").replace(" ", "_")
                if key in SENSITIVE_KEYS and _present(child):
                    return "identifier"
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            if len(item) > MAX_VALUE_CHARS:
                return "size"
            # Decode only for detection, never rewrite source/query text.
            decoded = unquote(unquote(item))
            if PRIVATE_ID.search(decoded) or ("@" in decoded and EMAIL.search(decoded)) or LOCAL_PATH.search(decoded) or PRIVATE_LABEL.search(decoded) or FORMATTED_PHONE.search(decoded):
                return "identifier"
    return None


def _deny(reason: str) -> int:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}, ensure_ascii=False))
    return 0


def main() -> int:
    try:
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            return _deny("Public research input exceeds the guard limit; prepare a smaller de-identified request.")
        event = json.loads(data)
        if not isinstance(event, dict):
            return _deny("The public research guard received an invalid event.")
        name = event.get("tool_name")
        if not isinstance(name, str):
            return _deny("The public research guard received no canonical tool name.")
        if not PUBLIC_TOOL.fullmatch(name):
            return 0
        if "tool_input" not in event:
            return _deny("The public research guard received no tool input.")
        reason = _scan_input(event["tool_input"])
        if reason in {"size", "complexity"}:
            return _deny("Public input exceeds inspection limits. Split a large public draft into smaller complete claim batches and review every batch; do not silently truncate it.")
        if reason == "identifier":
            return _deny("Possible private identifiers or local health data in public research input. Prepare a minimal de-identified question in the private context.")
        return 0
    except (ValueError, UnicodeError, RecursionError, OSError, TypeError):
        return _deny("The public research guard could not validate the request; do not send it publicly.")


if __name__ == "__main__":
    raise SystemExit(main())
