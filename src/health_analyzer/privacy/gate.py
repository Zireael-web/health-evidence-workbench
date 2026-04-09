"""Deterministic privacy gates for data leaving the private trust zone.

This is deliberately a fail-closed policy for public searches.  Redaction is
provided for operator review, but redacted text is not silently submitted to a
remote service: the caller must inspect and explicitly use it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
import hashlib
import hmac
import re
import unicodedata


class PrivacyViolation(ValueError):
    """Raised when private or identifying data reaches a public boundary."""


@dataclass(frozen=True, slots=True)
class PrivacyFinding:
    kind: str
    start: int
    end: int
    fingerprint: str


@dataclass(frozen=True, slots=True)
class InstructionPattern:
    """One canonical instruction-like-content rule used at every trust boundary."""

    pattern_id: str
    category: str
    severity: str
    expression: re.Pattern[str]
    description: str


_DIRECT_IDENTIFIER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.I)),
    (
        "phone",
        re.compile(r"(?<!\d)(?:\+?7|8)[\s()\-]*\d{3}[\s()\-]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)"),
    ),
    (
        "international_phone",
        re.compile(r"(?<!\w)\+(?:\d[\s().-]*){7,14}\d(?!\w)"),
    ),
    (
        "labelled_phone",
        re.compile(
            r"(?:phone|telephone|tel\.?|телефон|моб(?:ильный)?)\s*[:=-]?\s*"
            r"\+?\d(?:[\s().-]*\d){6,14}(?!\d)",
            re.I,
        ),
    ),
    ("snils", re.compile(r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}[ -]?\d{2}(?!\d)")),
    (
        "labelled_birth_date",
        re.compile(
            r"(?:дата\s+рождени[яе]|date\s+of\s+birth|\bdob\b)\s*[:=-]?\s*"
            r"(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}-\d{2}-\d{2})",
            re.I,
        ),
    ),
    (
        "labelled_patient_name",
        re.compile(
            r"(?:фио|пациент|patient|name|full\s+name)\s*[:=-]\s*"
            r"[A-ZА-ЯЁ][A-Za-zА-Яа-яЁё'-]+(?:\s+[A-ZА-ЯЁ][A-Za-zА-Яа-яЁё'-]+){1,2}",
            re.I,
        ),
    ),
    (
        "unlabelled_cyrillic_full_name",
        re.compile(
            r"\b[А-ЯЁ][А-Яа-яЁё'-]+\s+[А-ЯЁ][А-Яа-яЁё'-]+\s+"
            r"[А-ЯЁ][А-Яа-яЁё'-]+(?:вич|евич|овна|евна|ична)\b"
        ),
    ),
    (
        "exact_calendar_date",
        re.compile(
            r"(?<!\d)(?:\d{1,2}[./-]\d{1,2}[./-](?:19|20)\d{2}|"
            r"(?:19|20)\d{2}[./-]\d{1,2}[./-]\d{1,2})(?!\d)"
        ),
    ),
    (
        "labelled_address",
        re.compile(
            r"(?:адрес|address|место\s+жительства)\s*[:=-]\s*[^,;\n]{5,120}",
            re.I,
        ),
    ),
    (
        "passport",
        re.compile(r"(?:паспорт|passport)\s*[:=-]?\s*[A-ZА-Я0-9 -]{6,20}", re.I),
    ),
    (
        "medical_record_number",
        re.compile(
            r"(?:номер|№|no\.?|id)\s*(?:истории\s+болезни|карты|medical\s+record)\s*[:=-]?\s*[A-ZА-Я0-9/-]+",
            re.I,
        ),
    ),
    (
        "private_packet_marker",
        re.compile(
            r'(?:"(?:subject_id|source_hashes|raw_value)"\s*:|\b(?:subj|case|src)_[a-f0-9]{12,}\b)',
            re.I,
        ),
    ),
    (
        "local_path",
        re.compile(r"(?:file://|/(?:Users|home|private|Volumes)/|[A-Z]:\\Users\\)", re.I),
    ),
)

DEFAULT_INSTRUCTION_PATTERNS: tuple[InstructionPattern, ...] = (
    InstructionPattern(
        "ignore-prior-en",
        "prompt_override",
        "high",
        re.compile(
            r"\b(?:ignore|disregard)\s+(?:all\s+|the\s+)?"
            r"(?:(?:previous|prior)\s+instructions?|(?:system|developer)\s+"
            r"(?:message|prompt|instructions))\b",
            re.I,
        ),
        "Text asks an agent to disregard earlier instructions.",
    ),
    InstructionPattern(
        "ignore-prior-ru",
        "prompt_override",
        "high",
        re.compile(
            r"\bигнорир(?:уй|уйте)\s+(?:все\s+)?"
            r"(?:предыдущие|системные)\s+инструкции\b",
            re.I,
        ),
        "Текст просит игнорировать предыдущие инструкции.",
    ),
    InstructionPattern(
        "system-prompt",
        "prompt_disclosure",
        "medium",
        re.compile(
            r"\b(?:system prompt|developer (?:message|prompt)|"
            r"системн(?:ый|ые)\s+(?:промпт|инструкции))\b",
            re.I,
        ),
        "Text refers to hidden system/developer instructions.",
    ),
    InstructionPattern(
        "prompt-disclosure-request",
        "prompt_disclosure",
        "high",
        re.compile(
            r"\bраскрой(?:те)?\s+(?:системный|developer)\s+"
            r"(?:промпт|prompt)\b",
            re.I,
        ),
        "Текст просит раскрыть скрытые системные инструкции.",
    ),
    InstructionPattern(
        "tool-command",
        "tool_execution",
        "high",
        re.compile(
            r"\b(?:run|execute|call|выполни(?:ть)?|запусти(?:ть)?)\s+"
            r"(?:this\s+)?(?:command|tool|shell|команду|инструмент)\b",
            re.I,
        ),
        "Text asks an agent to execute a command or tool.",
    ),
    InstructionPattern(
        "data-exfiltration",
        "data_exfiltration",
        "high",
        re.compile(
            r"\b(?:upload|send|exfiltrate|отправь|загрузи)\b.{0,40}"
            r"\b(?:file|data|secret|document|файл|данные|секрет|документ)\b",
            re.I,
        ),
        "Text asks for data or file transfer.",
    ),
)

_PUBLIC_QUERY_QUASI_IDENTIFIER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "probable_two_component_name",
        re.compile(
            r"(?:\b[А-ЯЁ][а-яё'-]{2,}(?:ов|ев|ин|ский|ская|ко)\s+"
            r"[А-ЯЁ][а-яё'-]{2,}\b|"
            r"\b[А-ЯЁ][а-яё'-]{2,}\s+"
            r"[А-ЯЁ][а-яё'-]{2,}(?:ов|ев|ин|ский|ская|ко)\b|"
            r"\b[A-Z][a-z'-]{2,}(?:ov|ev|sky|ski|ko)\s+"
            r"[A-Z][a-z'-]{2,}\b|"
            r"\b[A-Z][a-z'-]{2,}\s+"
            r"[A-Z][a-z'-]{2,}(?:ov|ev|sky|ski|ko)\b)",
        ),
    ),
    (
        "unlabelled_long_identifier",
        re.compile(
            r"(?<!PMID:)(?<!pmid:)(?<!\d)\d{6,16}(?!\d)|"
            r"(?<!\d)(?:\d{4}[ -]){3}\d{4}(?!\d)"
        ),
    ),
    (
        "probable_unlabelled_address",
        re.compile(
            r"(?:\b[А-ЯЁ][а-яё'-]{3,}(?:ская|ский|ная|ный|овой|евой)\s+\d{1,4}[А-Яа-я]?\b|"
            r"\b[A-Z][A-Za-z'-]{2,}\s+(?:Street|St|Road|Rd|Avenue|Ave)\s+\d{1,5}\b)"
        ),
    ),
)


_PUBLIC_METADATA_DATE_FIELDS = frozenset(
    {
        "applies_from",
        "applies_until",
        "as_of",
        "checked_at",
        "created_at",
        "date_from",
        "date_to",
        "effective_from",
        "effective_until",
        "executed_at",
        "last_checked_at",
        "generated_at",
        "published_at",
        "published_on",
        "registered_at",
        "retrieved_at",
        "reviewed_at",
        "source_review_valid_until",
        "status_changed_on",
        "updated_at",
        "withdrawn_on",
    }
)

_PUBLIC_DIGEST_FIELDS = frozenset(
    {
        "binding_hmac",
        "candidate_sha256",
        "content_hash",
        "content_sha256",
        "confirmed_source_document_sha256",
        "confirmed_source_snapshot_sha256",
        "execution_sha256",
        "item_sha256s",
        "query_sha256",
        "results_sha256",
        "sha256",
        "source_document_sha256",
        "source_snapshot_sha256",
    }
)
_PUBLIC_OPAQUE_ID = re.compile(
    r"(?:retr|eclaimcand|eclaim_rcpt|evclaim|evidence|guidance_review|"
    r"guidance_claim|query|run)_[a-f0-9]{20,64}\Z"
)
_PUBLIC_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


def _is_iso_metadata_date(value: str) -> bool:
    """Accept a date only when its mapping key already gives it public semantics."""

    try:
        if "T" in value or " " in value:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _is_typed_public_opaque_value(field_name: str | None, value: str) -> bool:
    """Exclude validated public handles from identifier regexes, not from bounds.

    Downstream receipt/digest consumers still verify the exact format and HMAC.
    Free text and private ``case_*``/``subj_*`` handles are never exempted.
    """

    return bool(
        _PUBLIC_OPAQUE_ID.fullmatch(value)
        or (
            field_name in _PUBLIC_DIGEST_FIELDS
            and _PUBLIC_SHA256.fullmatch(value)
        )
    )


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def pseudonymous_subject_id(identity: str, secret: bytes, *, prefix: str = "subj") -> str:
    """Create a stable pseudonym without storing the supplied identity."""

    if len(secret) < 16:
        raise ValueError("pseudonymization secret must contain at least 16 bytes")
    normalized = unicodedata.normalize("NFKC", identity).strip().casefold()
    if not normalized:
        raise ValueError("identity must not be empty")
    digest = hmac.new(secret, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{prefix}_{digest[:24]}"


def detect_prompt_injection(text: str) -> tuple[str, ...]:
    """Detect instruction-like text inside untrusted source documents."""

    return tuple(
        pattern.expression.pattern
        for pattern in DEFAULT_INSTRUCTION_PATTERNS
        if pattern.expression.search(text)
    )


class PrivacyGate:
    """Fail-closed validator for the public research boundary."""

    @staticmethod
    def _bounded_payload_strings(payload: object) -> tuple[str, ...]:
        """Collect strings while enforcing deterministic JSON-like input bounds."""

        strings: list[str] = []
        text_characters = 0
        stack: list[tuple[str | None, object]] = [(None, payload)]
        visited = 0
        while stack:
            field_name, value = stack.pop()
            visited += 1
            if visited > 20_000:
                raise PrivacyViolation("payload exceeds the structural inspection limit")
            if isinstance(value, str):
                if not (
                    (
                        field_name in _PUBLIC_METADATA_DATE_FIELDS
                        and _is_iso_metadata_date(value)
                    )
                    or _is_typed_public_opaque_value(field_name, value)
                ):
                    strings.append(value)
                text_characters += len(value)
            elif isinstance(value, Mapping):
                for key, item in value.items():
                    key_text = str(key)
                    strings.append(key_text)
                    text_characters += len(key_text)
                    stack.append((key_text, item))
            elif isinstance(value, (list, tuple, set, frozenset)):
                stack.extend((field_name, item) for item in value)

            if text_characters > 250_000:
                raise PrivacyViolation("payload exceeds the text inspection limit")

        return tuple(strings)

    def inspect(self, text: str) -> tuple[PrivacyFinding, ...]:
        findings: list[PrivacyFinding] = []
        for kind, pattern in _DIRECT_IDENTIFIER_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    PrivacyFinding(
                        kind=kind,
                        start=match.start(),
                        end=match.end(),
                        fingerprint=_fingerprint(match.group(0)),
                    )
                )
        findings.sort(key=lambda finding: (finding.start, finding.end, finding.kind))
        return tuple(findings)

    def inspect_quasi_identifiers(self, text: str) -> tuple[PrivacyFinding, ...]:
        """Locate conservative public-query quasi-identifier heuristics.

        This exposes the same spans used by :meth:`assert_public_query` so a
        local-only egress preview can remove them before asking an operator to
        approve the exact outbound payload.  A match is a heuristic privacy
        finding, not proof that the source text identifies a person.
        """

        findings: list[PrivacyFinding] = []
        for kind, pattern in _PUBLIC_QUERY_QUASI_IDENTIFIER_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    PrivacyFinding(
                        kind=kind,
                        start=match.start(),
                        end=match.end(),
                        fingerprint=_fingerprint(match.group(0)),
                    )
                )
        findings.sort(key=lambda finding: (finding.start, finding.end, finding.kind))
        return tuple(findings)

    def assert_public_query(self, text: str) -> None:
        if not text.strip():
            raise PrivacyViolation("public evidence query must not be empty")
        if len(text) > 4_000:
            raise PrivacyViolation("public evidence query exceeds the 4000 character limit")
        findings = self.inspect(text)
        if findings:
            kinds = ", ".join(sorted({finding.kind for finding in findings}))
            raise PrivacyViolation(f"public evidence query contains direct identifiers: {kinds}")
        quasi_identifiers = {
            kind
            for kind, pattern in _PUBLIC_QUERY_QUASI_IDENTIFIER_PATTERNS
            if pattern.search(text)
        }
        if quasi_identifiers:
            raise PrivacyViolation(
                "public evidence query contains probable quasi-identifiers: "
                + ", ".join(sorted(quasi_identifiers))
            )
        if detect_prompt_injection(text):
            raise PrivacyViolation("public evidence query contains instruction-like source text")

    def assert_minimized_case_text(self, text: str) -> None:
        """Reject identifiers and instruction text before a record crosses zones."""

        if not isinstance(text, str) or not text.strip():
            raise PrivacyViolation("case text must not be empty")
        findings = self.inspect(text)
        if findings:
            kinds = ", ".join(sorted({finding.kind for finding in findings}))
            raise PrivacyViolation(f"case text contains direct identifiers: {kinds}")
        quasi_identifiers = {
            kind
            for kind, pattern in _PUBLIC_QUERY_QUASI_IDENTIFIER_PATTERNS
            if pattern.search(text)
        }
        if quasi_identifiers:
            raise PrivacyViolation(
                "case text contains probable quasi-identifiers: "
                + ", ".join(sorted(quasi_identifiers))
            )
        if detect_prompt_injection(text):
            raise PrivacyViolation("case text contains instruction-like source text")

    def assert_public_payload(self, payload: object) -> None:
        """Inspect every string in a JSON-like payload before public processing."""
        strings = self._bounded_payload_strings(payload)
        findings = tuple(
            finding
            for value in strings
            for finding in self.inspect(value)
        )
        if findings:
            kinds = ", ".join(sorted({finding.kind for finding in findings}))
            raise PrivacyViolation(f"public payload contains direct identifiers: {kinds}")
        if any(detect_prompt_injection(value) for value in strings):
            raise PrivacyViolation("public payload contains instruction-like source text")

    def assert_public_semantic_payload(self, payload: object) -> None:
        """Apply direct- and quasi-identifier checks to caller-authored prose."""

        strings = self._bounded_payload_strings(payload)
        findings = tuple(
            finding
            for value in strings
            for finding in self.inspect(value)
        )
        if findings:
            kinds = ", ".join(sorted({finding.kind for finding in findings}))
            raise PrivacyViolation(
                f"public semantic payload contains direct identifiers: {kinds}"
            )
        quasi_identifiers = {
            kind
            for value in strings
            for kind, pattern in _PUBLIC_QUERY_QUASI_IDENTIFIER_PATTERNS
            if pattern.search(value)
        }
        if quasi_identifiers:
            raise PrivacyViolation(
                "public semantic payload contains probable quasi-identifiers: "
                + ", ".join(sorted(quasi_identifiers))
            )
        if any(detect_prompt_injection(value) for value in strings):
            raise PrivacyViolation(
                "public semantic payload contains instruction-like source text"
            )

    def assert_bounded_payload(self, payload: object) -> None:
        """Apply only structural/text limits for an offline, non-public boundary."""

        self._bounded_payload_strings(payload)

    def redact_for_review(self, text: str) -> tuple[str, tuple[PrivacyFinding, ...]]:
        findings = self.inspect(text)
        redacted = text
        for finding in reversed(findings):
            replacement = f"[REDACTED:{finding.kind}]"
            redacted = redacted[: finding.start] + replacement + redacted[finding.end :]
        return redacted, findings
