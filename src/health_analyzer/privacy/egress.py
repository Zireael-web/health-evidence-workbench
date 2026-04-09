"""Local-only construction of previewable, minimized case payloads.

The outbound packet deliberately has no source identifiers, provenance, source
digests, local paths, or exact calendar dates.  Every invocation creates fresh
packet-local identifiers, so two requests cannot be linked through identifiers
created by this module.  These deterministic redaction rules reduce disclosure;
they do not guarantee anonymity or eliminate re-identification risk from a rare
combination of clinical facts.

This module performs no network I/O.  Building a packet is not authorization to
send it: callers must show ``EgressCasePacket.payload`` (or the canonical JSON)
to the operator before any separate network-capable component uses it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import hmac
import json
import re
import secrets
from typing import Any

from ..contracts import (
    CasePacket,
    Observation,
    ReferenceInterval,
    Statement,
    StatementKind,
    VerificationStatus,
)
from .gate import PrivacyGate, PrivacyViolation


EGRESS_SCHEMA_VERSION = "1.0"
MAX_EGRESS_RECORDS = 100
MAX_EGRESS_PAYLOAD_BYTES = 8 * 1024 * 1024
DEIDENTIFICATION_NOTICE = (
    "Direct identifiers, exact calendar dates, named facilities, locations, "
    "local provenance, and internal identifiers were removed by local rules. "
    "This reduces disclosure but does not guarantee anonymity or prevent "
    "re-identification from clinical details."
)

_SOURCE_PACKET_ID = re.compile(r"case_[a-f0-9]{20,64}\Z")
_SOURCE_SUBJECT_ID = re.compile(r"subj_[a-f0-9]{16,64}\Z")
_SOURCE_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_STANDARD_CODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}\Z")
_ID_ALPHABET = "abcdefghjkmnpqrstuvwxyz"

# Only codes from an explicitly named public terminology cross the boundary.
# A code with a missing or local code system may itself be an internal record ID.
_SAFE_CODE_SYSTEMS: dict[str, str] = {
    "atc": "ATC",
    "icd-10": "ICD-10",
    "icd-10-cm": "ICD-10-CM",
    "icd-11": "ICD-11",
    "loinc": "LOINC",
    "rxnorm": "RxNorm",
    "snomed": "SNOMED CT",
    "snomed ct": "SNOMED CT",
    "ucum": "UCUM",
}
_REFERENCE_LABELS = frozenset(
    {"laboratory_reference", "decision_threshold", "target", "critical_threshold"}
)

_MONTH_RU = (
    "января|февраля|марта|апреля|мая|июня|июля|августа|"
    "сентября|октября|ноября|декабря"
)
_MONTH_EN = (
    "January|February|March|April|May|June|July|August|September|"
    "October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|"
    "Sept|Oct|Nov|Dec"
)

# These rules intentionally prefer removing too much of a header over leaking a
# named provider or location.  Callers can add exact local names through
# ``additional_identifiers`` without placing those names in the resulting packet.
_EGRESS_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "local_path",
        re.compile(
            r"(?:file://)?/(?:Users|home|private|Volumes)/[^\s,;|)\]}]+|"
            r"[A-Z]:\\Users\\[^\s,;|)\]}]+",
            re.I,
        ),
    ),
    (
        "numeric_calendar_date",
        re.compile(
            r"(?<!\d)(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|"
            r"(?:19|20)\d{2}[./-]\d{1,2}[./-]\d{1,2})(?!\d)"
        ),
    ),
    (
        "written_calendar_date",
        re.compile(
            rf"(?<!\w)\d{{1,2}}\s+(?:{_MONTH_RU})\s+(?:19|20)\d{{2}}"
            rf"(?:\s*г(?:ода|\.)?)?(?!\w)|"
            rf"(?<!\w)(?:{_MONTH_EN})\s+\d{{1,2}}(?:st|nd|rd|th)?[,]?\s+"
            rf"(?:19|20)\d{{2}}(?!\w)|"
            rf"(?<!\w)\d{{1,2}}(?:st|nd|rd|th)?\s+(?:{_MONTH_EN})\s+"
            rf"(?:19|20)\d{{2}}(?!\w)",
            re.I,
        ),
    ),
    (
        "labelled_facility",
        re.compile(
            r"\b(?:лечебное\s+учреждение|медицинская\s+организация|"
            r"медицинский\s+центр|медцентр|клиника|больница|госпиталь|"
            r"поликлиника|лаборатория|facility|clinic|hospital|medical\s+"
            r"cent(?:er|re)|laborator(?:y|ies))\s*[:=\-]\s*[^\n;|]{2,160}",
            re.I,
        ),
    ),
    (
        "named_facility",
        re.compile(
            r"\b(?:клиника|больница|госпиталь|поликлиника|медицинский\s+"
            r"центр|медцентр|лаборатория|clinic|hospital|medical\s+"
            r"cent(?:er|re)|laborator(?:y|ies))\s+[«\"']?"
            r"[A-ZА-ЯЁ][^\n,;|]{1,120}",
            re.I,
        ),
    ),
    (
        "legal_facility_name",
        re.compile(
            r"\b(?:КГП|ГКП|РГП|НАО|ТОО|LLP|JSC)\b(?:\s+на\s+ПХВ)?\s+"
            r"[^\n,;|]{2,160}",
            re.I,
        ),
    ),
    (
        "labelled_location",
        re.compile(
            r"\b(?:город|city|location|местонахождение|насел[её]нный\s+пункт)"
            r"\s*[:=\-]\s*[^\n,;|]{2,100}",
            re.I,
        ),
    ),
    (
        "city_abbreviation",
        re.compile(
            r"(?<!\w)(?:г\.|city\s+of)\s*[A-ZА-ЯЁ][A-Za-zА-Яа-яЁё'\-]+"
            r"(?:\s+[A-ZА-ЯЁ][A-Za-zА-Яа-яЁё'\-]+){0,2}",
            re.I,
        ),
    ),
    (
        "known_city",
        re.compile(
            r"\b(?:New\s+York|London|Paris|Berlin|Tokyo|Sydney|"
            r"Exampletown|Sampleville)\b",
            re.I,
        ),
    ),
    (
        "labelled_clinician",
        re.compile(
            r"\b(?:врач|доктор|doctor|physician|лаборант)\s*[:=\-]\s*"
            r"[^\n,;|]{2,100}",
            re.I,
        ),
    ),
    (
        "internal_identifier",
        re.compile(
            r"\b(?:subject|patient|packet|record|document|source|artifact|root|"
            r"receipt|observation|statement)[_-]?id\s*[:=]\s*"
            r"[A-Za-z0-9._:/\-]{3,160}",
            re.I,
        ),
    ),
    (
        "labelled_national_or_order_identifier",
        re.compile(
            r"\b(?:ИИН|ИНН|IIN|TIN|СНИЛС|полис|insurance(?:\s+number)?|"
            r"accession|номер\s+(?:заказа|исследования|образца))\s*[:=№#\-]?\s*"
            r"[A-Za-zА-Яа-я0-9/\-]{4,40}",
            re.I,
        ),
    ),
    (
        "probable_national_or_barcode_identifier",
        re.compile(r"(?<!\d)\d{10,16}(?!\d)"),
    ),
    (
        "source_digest",
        re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"),
    ),
)


@dataclass(frozen=True, slots=True)
class EgressRedaction:
    """Non-sensitive local summary of a removed category."""

    field: str
    kind: str
    count: int = 1

    def __post_init__(self) -> None:
        if not self.field or not self.kind or self.count < 1:
            raise ValueError("egress redaction summary is malformed")


@dataclass(frozen=True, slots=True)
class EgressCasePacket:
    """An exact local preview plus a hash of the canonical outbound JSON.

    ``redactions`` is local review metadata and is intentionally not part of
    ``payload``.  The payload property returns a new object on every access so a
    caller cannot mutate the canonical representation stored by this object.
    """

    canonical_payload_json: str
    canonical_payload_sha256: str
    redactions: tuple[EgressRedaction, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.canonical_payload_json, str):
            raise ValueError("canonical_payload_json must be text")
        encoded = self.canonical_payload_json.encode("utf-8")
        if len(encoded) > MAX_EGRESS_PAYLOAD_BYTES:
            raise ValueError("egress payload exceeds the canonical byte limit")
        expected = hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(expected, self.canonical_payload_sha256):
            raise ValueError("egress payload hash does not match its canonical JSON")
        try:
            payload = json.loads(self.canonical_payload_json)
        except (TypeError, ValueError):
            raise ValueError("canonical_payload_json must contain valid JSON") from None
        if not isinstance(payload, dict):
            raise ValueError("egress payload must be a JSON object")
        canonical = _canonical_json(payload)
        if canonical != self.canonical_payload_json:
            raise ValueError("egress payload JSON is not canonical")
        if any(not isinstance(item, EgressRedaction) for item in self.redactions):
            raise ValueError("egress redactions must contain EgressRedaction values")
        object.__setattr__(self, "redactions", tuple(self.redactions))

    @property
    def payload(self) -> dict[str, Any]:
        """Return the exact outbound payload represented by the canonical hash."""

        payload = json.loads(self.canonical_payload_json)
        if not isinstance(payload, dict):  # guarded in __post_init__; keeps typing honest
            raise RuntimeError("stored egress payload is not an object")
        return payload

    def preview(self) -> dict[str, Any]:
        """Return local review material; only ``payload`` is outbound content."""

        return {
            "payload": self.payload,
            "canonical_payload_sha256": self.canonical_payload_sha256,
            "redactions": [asdict(item) for item in self.redactions],
        }


@dataclass(frozen=True, slots=True)
class _Span:
    start: int
    end: int
    kinds: frozenset[str]


class _RedactionLog:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, str], int] = {}

    def add(self, field: str, kind: str, count: int = 1) -> None:
        if count < 1:
            return
        key = (field, kind)
        self._counts[key] = self._counts.get(key, 0) + count

    def freeze(self) -> tuple[EgressRedaction, ...]:
        return tuple(
            EgressRedaction(field=field, kind=kind, count=count)
            for (field, kind), count in sorted(self._counts.items())
        )


def _canonical_json(payload: dict[str, Any]) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise ValueError("egress payload must contain only finite JSON values") from None


def _fresh_token(length: int = 24) -> str:
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(length))


def _fresh_id(prefix: str, *, forbidden: set[str], used: set[str]) -> str:
    for _ in range(32):
        candidate = f"{prefix}_{_fresh_token()}"
        if candidate not in forbidden and candidate not in used:
            used.add(candidate)
            return candidate
    raise RuntimeError("could not allocate a fresh packet-local identifier")


def _validated_additional_identifiers(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError("additional_identifiers must be an iterable of strings")
    resolved: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or len(value.strip()) < 3
            or len(value) > 256
            or "\0" in value
        ):
            raise ValueError(
                "additional identifiers must be 3-256 character strings without NUL"
            )
        resolved.append(value.strip())
        if len(resolved) > 100:
            raise ValueError("at most 100 additional identifiers may be supplied")
    return tuple(sorted(set(resolved), key=lambda item: (-len(item), item.casefold())))


def _merge_spans(spans: list[_Span]) -> tuple[_Span, ...]:
    if not spans:
        return ()
    ordered = sorted(spans, key=lambda item: (item.start, item.end))
    merged: list[_Span] = [ordered[0]]
    for item in ordered[1:]:
        previous = merged[-1]
        if item.start < previous.end:
            merged[-1] = _Span(
                start=previous.start,
                end=max(previous.end, item.end),
                kinds=previous.kinds | item.kinds,
            )
        else:
            merged.append(item)
    return tuple(merged)


def _redact_text(
    value: str,
    *,
    field: str,
    log: _RedactionLog,
    additional_identifiers: tuple[tuple[str, str], ...],
    quasi_identifiers: bool,
    preserve_clinical_numbers: bool = False,
) -> str:
    if not isinstance(value, str) or "\0" in value:
        raise PrivacyViolation(f"{field} must be text without NUL")
    if len(value.encode("utf-8")) > MAX_EGRESS_PAYLOAD_BYTES:
        raise PrivacyViolation(f"{field} exceeds the egress text limit")

    gate = PrivacyGate()
    spans: list[_Span] = []
    for finding in gate.inspect(value):
        spans.append(_Span(finding.start, finding.end, frozenset({finding.kind})))
    if quasi_identifiers:
        for finding in gate.inspect_quasi_identifiers(value):
            if (
                preserve_clinical_numbers
                and finding.kind == "unlabelled_long_identifier"
            ):
                continue
            spans.append(_Span(finding.start, finding.end, frozenset({finding.kind})))
    for kind, pattern in _EGRESS_TEXT_PATTERNS:
        for match in pattern.finditer(value):
            spans.append(_Span(match.start(), match.end(), frozenset({kind})))
    for identifier, identifier_kind in additional_identifiers:
        pattern = re.compile(re.escape(identifier), re.I)
        for match in pattern.finditer(value):
            spans.append(
                _Span(
                    match.start(),
                    match.end(),
                    frozenset({identifier_kind}),
                )
            )

    redacted = value
    merged_spans = _merge_spans(spans)
    for span in merged_spans:
        for kind in span.kinds:
            log.add(field, kind)
    for span in reversed(merged_spans):
        kinds = "+".join(sorted(span.kinds))
        redacted = redacted[: span.start] + f"[REMOVED:{kinds}]" + redacted[span.end :]

    # The second pass is deliberately a rejection check.  It catches mistakes
    # in span composition and instruction-like document text instead of silently
    # allowing a partially sanitized packet to cross the boundary.
    gate.assert_public_payload({"value": redacted})
    if quasi_identifiers:
        residual_quasi = tuple(
            finding
            for finding in gate.inspect_quasi_identifiers(redacted)
            if not (
                preserve_clinical_numbers
                and finding.kind == "unlabelled_long_identifier"
            )
        )
        if residual_quasi:
            kinds = ", ".join(sorted({item.kind for item in residual_quasi}))
            raise PrivacyViolation(
                f"{field} contains residual probable quasi-identifiers: {kinds}"
            )
    return redacted


def _validate_source_packet(packet: CasePacket) -> None:
    if not isinstance(packet, CasePacket):
        raise TypeError("case_packet must be a CasePacket")
    if not isinstance(packet.packet_id, str) or not _SOURCE_PACKET_ID.fullmatch(
        packet.packet_id
    ):
        raise ValueError("source CasePacket packet_id is malformed")
    if not isinstance(packet.subject_id, str) or not _SOURCE_SUBJECT_ID.fullmatch(
        packet.subject_id
    ):
        raise ValueError("source CasePacket subject_id is malformed")
    if packet.schema_version != "1.0":
        raise ValueError("source CasePacket schema_version is unsupported")
    if not isinstance(packet.observations, tuple) or not isinstance(packet.statements, tuple):
        raise ValueError("source CasePacket record collections must be immutable tuples")
    if not isinstance(packet.limitations, tuple) or any(
        not isinstance(item, str) or "\0" in item for item in packet.limitations
    ):
        raise ValueError("source CasePacket limitations are malformed")
    record_count = len(packet.observations) + len(packet.statements)
    if record_count < 1:
        raise ValueError("source CasePacket requires at least one record")
    if record_count > MAX_EGRESS_RECORDS:
        raise ValueError(f"egress accepts at most {MAX_EGRESS_RECORDS} records")

    record_ids: set[str] = set()
    provenance_hashes: set[str] = set()
    for observation in packet.observations:
        if not isinstance(observation, Observation):
            raise ValueError("source CasePacket observation is malformed")
        if observation.subject_id != packet.subject_id:
            raise ValueError("source CasePacket mixes subjects")
        if observation.verification is not VerificationStatus.VERIFIED:
            raise ValueError("egress accepts only transcription-confirmed records")
        if (
            not isinstance(observation.observation_id, str)
            or not observation.observation_id
            or observation.observation_id in record_ids
        ):
            raise ValueError("source CasePacket record identifiers must be unique")
        if (
            not isinstance(observation.display, str)
            or not observation.display.strip()
            or not isinstance(observation.raw_value, str)
            or not observation.raw_value.strip()
        ):
            raise ValueError("source CasePacket observation is incomplete")
        if not observation.provenance:
            raise ValueError("source CasePacket observation lacks provenance")
        if not isinstance(observation.reference_intervals, tuple) or any(
            not isinstance(item, ReferenceInterval)
            for item in observation.reference_intervals
        ):
            raise ValueError("source CasePacket reference intervals are malformed")
        if not isinstance(observation.notes, tuple) or any(
            not isinstance(item, str) or "\0" in item for item in observation.notes
        ):
            raise ValueError("source CasePacket observation notes are malformed")
        record_ids.add(observation.observation_id)
        provenance_hashes.update(locator.sha256 for locator in observation.provenance)

    for statement in packet.statements:
        if not isinstance(statement, Statement):
            raise ValueError("source CasePacket statement is malformed")
        if statement.subject_id not in (None, packet.subject_id):
            raise ValueError("source CasePacket mixes subjects")
        if statement.verification is not VerificationStatus.VERIFIED:
            raise ValueError("egress accepts only transcription-confirmed records")
        if (
            not isinstance(statement.statement_id, str)
            or not statement.statement_id
            or statement.statement_id in record_ids
        ):
            raise ValueError("source CasePacket record identifiers must be unique")
        if (
            not isinstance(statement.text, str)
            or not statement.text.strip()
            or not statement.provenance
        ):
            raise ValueError("source CasePacket statement is incomplete")
        if not isinstance(statement.kind, StatementKind):
            raise ValueError("source CasePacket statement kind is malformed")
        if any(not isinstance(item, str) or not item for item in statement.support_ids):
            raise ValueError("source CasePacket statement support is malformed")
        if len(set(statement.support_ids)) != len(statement.support_ids):
            raise ValueError("source CasePacket statement support must be unique")
        record_ids.add(statement.statement_id)
        provenance_hashes.update(locator.sha256 for locator in statement.provenance)

    if (
        not isinstance(packet.source_hashes, tuple)
        or any(
            not isinstance(value, str) or not _SOURCE_SHA256.fullmatch(value)
            for value in packet.source_hashes
        )
        or len(set(packet.source_hashes)) != len(packet.source_hashes)
        or set(packet.source_hashes) != provenance_hashes
    ):
        raise ValueError("source CasePacket provenance coverage is malformed")


def _relative_days(packet: CasePacket) -> dict[str, int]:
    dated: list[tuple[str, datetime]] = []
    for observation in packet.observations:
        if observation.observed_at is None:
            continue
        text = observation.observed_at
        if "T" not in text and " " not in text:
            parsed = datetime.fromisoformat(text + "T00:00:00+00:00")
        else:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("source observation date-time must include a timezone")
        # Only calendar-day distance is retained.  Discard clock time and UTC
        # offset because both can reveal more context than this packet needs.
        dated.append((observation.observation_id, parsed))
    if not dated:
        return {}
    latest = max(item[1].date() for item in dated)
    return {
        record_id: (parsed.date() - latest).days
        for record_id, parsed in dated
    }


def _optional_text(
    value: str | None,
    *,
    field: str,
    log: _RedactionLog,
    additional_identifiers: tuple[tuple[str, str], ...],
    quasi_identifiers: bool = True,
    preserve_clinical_numbers: bool = False,
) -> str | None:
    if value is None:
        return None
    return _redact_text(
        value,
        field=field,
        log=log,
        additional_identifiers=additional_identifiers,
        quasi_identifiers=quasi_identifiers,
        preserve_clinical_numbers=preserve_clinical_numbers,
    )


def build_egress_case_packet(
    case_packet: CasePacket,
    *,
    question: str | None = None,
    additional_identifiers: Iterable[str] = (),
) -> EgressCasePacket:
    """Build a fresh, preview-only outbound packet from one verified subject.

    ``additional_identifiers`` is a local deny-list for exact patient, provider,
    facility, and location strings that generic rules cannot know.  Its values
    are never copied into the result.  The caller remains responsible for human
    review because clinical combinations can be identifying even after these
    fields are removed.
    """

    _validate_source_packet(case_packet)
    identifier_kinds = {
        identifier: "operator_supplied_identifier"
        for identifier in _validated_additional_identifiers(additional_identifiers)
    }
    if question is not None and (not isinstance(question, str) or not question.strip()):
        raise ValueError("question must be non-empty text or null")

    log = _RedactionLog()
    log.add("packet", "source_packet_id")
    log.add("packet", "source_subject_id")
    log.add("packet", "source_created_at")
    if case_packet.source_hashes:
        log.add("packet", "source_digest", len(case_packet.source_hashes))

    forbidden_ids = {case_packet.packet_id, case_packet.subject_id}
    forbidden_ids.update(item.observation_id for item in case_packet.observations)
    forbidden_ids.update(item.statement_id for item in case_packet.statements)
    # Removing structured fields is not enough: a note/question can repeat the
    # same internal ID verbatim without a label recognized by the generic gate.
    # Include source/support IDs too, but never source excerpts or local paths as
    # identifier-discovery material. The original packet is not mutated.
    known_ids = forbidden_ids | set(case_packet.source_hashes)
    for record in (*case_packet.observations, *case_packet.statements):
        known_ids.update(locator.source_id for locator in record.provenance)
    for statement in case_packet.statements:
        known_ids.update(statement.support_ids)
    identifier_kinds.update((value, "known_internal_identifier") for value in known_ids)
    identifiers = tuple(sorted(
        identifier_kinds.items(), key=lambda item: (-len(item[0]), item[0].casefold())
    ))
    used_ids: set[str] = set()
    egress_packet_id = _fresh_id("egress", forbidden=forbidden_ids, used=used_ids)
    patient_ref = _fresh_id("person", forbidden=forbidden_ids, used=used_ids)

    id_map: dict[str, str] = {}
    for observation in case_packet.observations:
        id_map[observation.observation_id] = _fresh_id(
            "obs", forbidden=forbidden_ids, used=used_ids
        )
    for statement in case_packet.statements:
        id_map[statement.statement_id] = _fresh_id(
            "stmt", forbidden=forbidden_ids, used=used_ids
        )
    if id_map:
        log.add("records", "internal_record_id", len(id_map))

    relative_days = _relative_days(case_packet)
    observations: list[dict[str, Any]] = []
    for index, observation in enumerate(case_packet.observations):
        field = f"observations[{index}]"
        output: dict[str, Any] = {
            "record_ref": id_map[observation.observation_id],
            "display": _redact_text(
                observation.display,
                field=f"{field}.display",
                log=log,
                additional_identifiers=identifiers,
                quasi_identifiers=True,
            ),
            "raw_value": _redact_text(
                observation.raw_value,
                field=f"{field}.raw_value",
                log=log,
                additional_identifiers=identifiers,
                quasi_identifiers=True,
                preserve_clinical_numbers=True,
            ),
            "original_unit": _optional_text(
                observation.original_unit,
                field=f"{field}.original_unit",
                log=log,
                additional_identifiers=identifiers,
                quasi_identifiers=True,
                preserve_clinical_numbers=True,
            ),
            "normalized_value": _optional_text(
                observation.normalized_value,
                field=f"{field}.normalized_value",
                log=log,
                additional_identifiers=identifiers,
                quasi_identifiers=True,
                preserve_clinical_numbers=True,
            ),
            "ucum_unit": _optional_text(
                observation.ucum_unit,
                field=f"{field}.ucum_unit",
                log=log,
                additional_identifiers=identifiers,
                quasi_identifiers=True,
                preserve_clinical_numbers=True,
            ),
            "comparator": _optional_text(
                observation.comparator,
                field=f"{field}.comparator",
                log=log,
                additional_identifiers=identifiers,
                quasi_identifiers=True,
                preserve_clinical_numbers=True,
            ),
            "specimen": _optional_text(
                observation.specimen,
                field=f"{field}.specimen",
                log=log,
                additional_identifiers=identifiers,
            ),
            "method": _optional_text(
                observation.method,
                field=f"{field}.method",
                log=log,
                additional_identifiers=identifiers,
            ),
            "device": _optional_text(
                observation.device,
                field=f"{field}.device",
                log=log,
                additional_identifiers=identifiers,
            ),
            "reference_intervals": [],
            "notes": [
                _redact_text(
                    note,
                    field=f"{field}.notes[{note_index}]",
                    log=log,
                    additional_identifiers=identifiers,
                    quasi_identifiers=True,
                )
                for note_index, note in enumerate(observation.notes)
            ],
            "source_status": "transcription_confirmed",
        }
        if observation.observed_at is not None:
            log.add(f"{field}.observed_at", "exact_date")
            output["days_before_latest_observation"] = relative_days[
                observation.observation_id
            ]
        if observation.code_system is not None or observation.code is not None:
            normalized_system = (observation.code_system or "").strip().casefold()
            public_system = _SAFE_CODE_SYSTEMS.get(normalized_system)
            if public_system is not None and observation.code is not None:
                if not _STANDARD_CODE.fullmatch(observation.code):
                    raise PrivacyViolation(
                        f"{field}.code is malformed for a public terminology"
                    )
                output["code_system"] = public_system
                output["code"] = observation.code
            else:
                log.add(f"{field}.code", "local_or_untyped_code")
        for interval_index, interval in enumerate(observation.reference_intervals):
            interval_field = f"{field}.reference_intervals[{interval_index}]"
            if interval.label not in _REFERENCE_LABELS:
                raise PrivacyViolation(
                    f"{interval_field}.label is not a supported public label"
                )
            output["reference_intervals"].append(
                {
                    "low": _optional_text(
                        interval.low,
                        field=f"{interval_field}.low",
                        log=log,
                        additional_identifiers=identifiers,
                        quasi_identifiers=True,
                        preserve_clinical_numbers=True,
                    ),
                    "high": _optional_text(
                        interval.high,
                        field=f"{interval_field}.high",
                        log=log,
                        additional_identifiers=identifiers,
                        quasi_identifiers=True,
                        preserve_clinical_numbers=True,
                    ),
                    "unit": _optional_text(
                        interval.unit,
                        field=f"{interval_field}.unit",
                        log=log,
                        additional_identifiers=identifiers,
                        quasi_identifiers=True,
                        preserve_clinical_numbers=True,
                    ),
                    "comparator": _optional_text(
                        interval.comparator,
                        field=f"{interval_field}.comparator",
                        log=log,
                        additional_identifiers=identifiers,
                        quasi_identifiers=True,
                        preserve_clinical_numbers=True,
                    ),
                    "label": interval.label,
                    "population": _optional_text(
                        interval.population,
                        field=f"{interval_field}.population",
                        log=log,
                        additional_identifiers=identifiers,
                    ),
                }
            )
        log.add(f"{field}.provenance", "local_provenance", len(observation.provenance))
        observations.append(output)

    statements: list[dict[str, Any]] = []
    for index, statement in enumerate(case_packet.statements):
        field = f"statements[{index}]"
        support_refs: list[str] = []
        for support_id in statement.support_ids:
            mapped = id_map.get(support_id)
            if mapped is None:
                log.add(f"{field}.support_ids", "external_or_internal_reference")
            else:
                support_refs.append(mapped)
        statements.append(
            {
                "record_ref": id_map[statement.statement_id],
                "kind": statement.kind.value,
                "text": _redact_text(
                    statement.text,
                    field=f"{field}.text",
                    log=log,
                    additional_identifiers=identifiers,
                    quasi_identifiers=True,
                ),
                "support_refs": support_refs,
                "certainty": _optional_text(
                    statement.certainty,
                    field=f"{field}.certainty",
                    log=log,
                    additional_identifiers=identifiers,
                    quasi_identifiers=True,
                    preserve_clinical_numbers=True,
                ),
                "source_status": "transcription_confirmed",
            }
        )
        log.add(f"{field}.provenance", "local_provenance", len(statement.provenance))

    payload: dict[str, Any] = {
        "schema_version": EGRESS_SCHEMA_VERSION,
        "egress_packet_id": egress_packet_id,
        "patient_ref": patient_ref,
        "question": (
            _redact_text(
                question,
                field="question",
                log=log,
                additional_identifiers=identifiers,
                quasi_identifiers=True,
            )
            if question is not None
            else None
        ),
        "observations": observations,
        "statements": statements,
        "limitations": [
            _redact_text(
                limitation,
                field=f"limitations[{index}]",
                log=log,
                additional_identifiers=identifiers,
                quasi_identifiers=True,
            )
            for index, limitation in enumerate(case_packet.limitations)
        ],
        "deidentification_notice": DEIDENTIFICATION_NOTICE,
    }

    # Defense in depth over the entire exact object.  Structured numeric values
    # are not subjected to the long-number quasi-ID heuristic because values
    # such as cell counts and viral loads may legitimately have six digits.
    PrivacyGate().assert_public_payload(payload)
    canonical = _canonical_json(payload)
    encoded = canonical.encode("utf-8")
    if len(encoded) > MAX_EGRESS_PAYLOAD_BYTES:
        raise ValueError("egress payload exceeds the canonical byte limit")
    digest = hashlib.sha256(encoded).hexdigest()
    return EgressCasePacket(
        canonical_payload_json=canonical,
        canonical_payload_sha256=digest,
        redactions=log.freeze(),
    )
