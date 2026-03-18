"""Instruction-like content detection for untrusted documents.

Findings are metadata only.  They are never interpreted as executable policy,
prompts, or tool calls.
"""

from __future__ import annotations

from bisect import bisect_right
import hashlib
import re

from ..privacy.gate import DEFAULT_INSTRUCTION_PATTERNS, InstructionPattern
from .models import InstructionFinding, deterministic_id

DEFAULT_PATTERNS = DEFAULT_INSTRUCTION_PATTERNS


class InstructionDetector:
    def __init__(self, patterns: tuple[InstructionPattern, ...] = DEFAULT_PATTERNS) -> None:
        self.patterns = patterns

    def scan(self, text: str, *, line_offset: int = 0) -> tuple[InstructionFinding, ...]:
        findings: list[InstructionFinding] = []
        scope_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        newline_ends = tuple(
            match.end() for match in re.finditer(r"\r\n|\r|\n", text)
        )
        for pattern in self.patterns:
            for match in pattern.expression.finditer(text):
                # CSV permits CRLF, LF, and bare CR record separators. Count
                # every universal newline once so finding locators remain
                # aligned with physical source lines across all three forms.
                line = line_offset + bisect_right(newline_ends, match.start()) + 1
                matched = match.group(0)
                matched_hash = hashlib.sha256(matched.encode("utf-8")).hexdigest()
                finding_id = deterministic_id(
                    "inj",
                    pattern.pattern_id,
                    str(line),
                    matched_hash,
                    scope_hash,
                )
                findings.append(
                    InstructionFinding(
                        finding_id=finding_id,
                        pattern_id=pattern.pattern_id,
                        category=pattern.category,
                        severity=pattern.severity,
                        line=line,
                        matched_text_sha256=matched_hash,
                        description=pattern.description,
                    )
                )
        return tuple(sorted(findings, key=lambda item: (item.line or 0, item.pattern_id)))
