"""Tamper-evident explicit-review receipts for public source-level claims.

The ledger accepts only source descriptors that the public server has already
verified.  It never downloads source content or opens caller-supplied paths.
Registration freezes one candidate; review requires exact confirmation of the
source, statement, and locator before issuing a keyed receipt and a typed
``ReviewedEvidenceClaim``.

The receipt proves integrity of the locally recorded review.  It does not prove
source authenticity, entailment, reviewer identity, methodological quality, or
guideline currency.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any

from ..contracts import (
    EvidenceItem,
    ProvenanceLocator,
    ReviewedEvidenceClaim,
    StatementKind,
    VerificationStatus,
    to_dict,
    utc_now,
)
from ..privacy import PrivacyGate
from .retrieval_ledger import RetrievedEvidence, evidence_item_snapshot_sha256


__all__ = [
    "DuplicateEvidenceClaimReceiptError",
    "EvidenceClaimCandidate",
    "EvidenceClaimReviewLedger",
    "EvidenceClaimReviewReceipt",
    "EvidenceReviewLedgerIntegrityError",
    "GuidelineSourceDescriptor",
    "UnknownEvidenceClaimCandidateError",
    "UnknownEvidenceClaimReceiptError",
]


MAX_RECEIPTS_PER_LOAD = 100
MAX_REVIEW_BATCH_JSON_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BINDING_JSON_BYTES = 512 * 1024
MAX_CLAIM_JSON_BYTES = 64 * 1024
MAX_QUESTION_BYTES = 16 * 1024
MAX_STATEMENT_BYTES = 8 * 1024
MAX_EXCERPT_BYTES = 8 * 1024
MAX_LOCATOR_BYTES = 1024
MAX_OPTIONAL_TEXT_BYTES = 4 * 1024
MAX_REVIEW_NOTE_BYTES = 4 * 1024
MAX_LIMITATIONS = 50

_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_CANDIDATE_ID = re.compile(r"eclaimcand_[a-f0-9]{32}\Z")
_RECEIPT_ID = re.compile(r"eclaim_rcpt_[a-f0-9]{32}\Z")
_RETRIEVAL_RECEIPT_ID = re.compile(r"retr_[a-f0-9]{32}\Z")
_CLAIM_TYPES = frozenset({"finding", "effect", "harm", "recommendation"})
_SOURCE_KINDS = frozenset({"retrieval_item", "guideline_recommendation"})


class UnknownEvidenceClaimCandidateError(ValueError):
    """Raised when review references an unregistered candidate."""


class UnknownEvidenceClaimReceiptError(ValueError):
    """Raised when packet construction references an unknown review receipt."""


class DuplicateEvidenceClaimReceiptError(ValueError):
    """Raised when a receipt batch repeats an opaque receipt ID."""


class EvidenceReviewLedgerIntegrityError(RuntimeError):
    """Raised when a candidate, source binding, or review receipt was modified."""


@dataclass(frozen=True, slots=True)
class GuidelineSourceDescriptor:
    """Server-verified guideline recommendation projected into public evidence.

    The public MCP server must construct this only after the guidance registry
    has verified the document/recommendation HMACs.  The ledger deliberately
    has no API that retrieves a URL or accepts a local source path.
    """

    question: str
    recommendation_id: str
    evidence_item: EvidenceItem
    verbatim_text: str
    provenance: ProvenanceLocator
    native_grade_system: str
    native_grade: str
    population: str | None = None
    outcome: str | None = None
    effect: str | None = None
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceClaimCandidate:
    candidate_id: str
    candidate_sha256: str
    question: str
    source_kind: str
    source_root_id: str
    source_evidence_id: str
    source_snapshot_sha256: str
    statement_kind: StatementKind
    claim_type: str
    text: str
    provenance: ProvenanceLocator
    registered_at: str
    population: str | None = None
    outcome: str | None = None
    effect: str | None = None
    native_grade_system: str | None = None
    native_grade: str | None = None
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceClaimReviewReceipt:
    receipt_id: str
    claim_id: str
    candidate_id: str
    candidate_sha256: str
    source_root_id: str
    source_evidence_id: str
    source_snapshot_sha256: str
    reviewer_id: str
    review_note: str | None
    reviewed_at: str
    binding_hmac: str
    claim: ReviewedEvidenceClaim

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["claim"] = to_dict(self.claim)
        return payload


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_text(
    value: str,
    *,
    name: str,
    maximum_bytes: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    if "\0" in value:
        raise ValueError(f"{name} must not contain NUL")
    resolved = value.strip()
    if len(resolved.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{name} exceeds the UTF-8 byte limit")
    return resolved


def _optional_text(value: str | None, *, name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, name=name, maximum_bytes=MAX_OPTIONAL_TEXT_BYTES)


def _limitations(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError("limitations must be a tuple")
    if len(values) > MAX_LIMITATIONS:
        raise ValueError("limitations exceeds the item limit")
    return tuple(
        _require_text(
            value,
            name="limitation",
            maximum_bytes=MAX_OPTIONAL_TEXT_BYTES,
        )
        for value in values
    )


def _statement_kind(value: StatementKind | str) -> StatementKind:
    try:
        resolved = StatementKind(value)
    except (TypeError, ValueError):
        raise ValueError("statement_kind is unsupported") from None
    if resolved not in {
        StatementKind.EXTERNAL_EVIDENCE,
        StatementKind.GUIDELINE_RECOMMENDATION,
    }:
        raise ValueError("statement_kind is unsupported for reviewed public evidence")
    return resolved


def _validate_kind_mapping(
    source_kind: str,
    statement_kind: StatementKind,
    claim_type: str,
) -> None:
    if source_kind not in _SOURCE_KINDS:
        raise ValueError("source_kind is unsupported")
    if claim_type not in _CLAIM_TYPES:
        raise ValueError("claim_type is unsupported")
    expected = (
        StatementKind.GUIDELINE_RECOMMENDATION
        if claim_type == "recommendation"
        else StatementKind.EXTERNAL_EVIDENCE
    )
    if statement_kind is not expected:
        raise ValueError("claim_type and statement_kind do not match")
    if source_kind == "guideline_recommendation" and claim_type != "recommendation":
        raise ValueError("guideline sources can produce recommendation claims only")
    if source_kind == "retrieval_item" and claim_type == "recommendation":
        raise ValueError(
            "metadata retrieval cannot promote an item to a guideline recommendation"
        )


def _validated_provenance(
    value: ProvenanceLocator,
    *,
    source_evidence_id: str,
) -> ProvenanceLocator:
    if not isinstance(value, ProvenanceLocator):
        raise TypeError("provenance must be a ProvenanceLocator")
    if value.source_id != source_evidence_id:
        raise ValueError("provenance source_id must match source_evidence_id")
    if not isinstance(value.sha256, str) or not _SHA256.fullmatch(value.sha256):
        raise ValueError("provenance sha256 must be a lowercase SHA-256 digest")
    locator = _require_text(
        value.locator or "",
        name="provenance locator",
        maximum_bytes=MAX_LOCATOR_BYTES,
    )
    excerpt = _require_text(
        value.excerpt or "",
        name="provenance excerpt",
        maximum_bytes=MAX_EXCERPT_BYTES,
    )
    for name in ("page", "line_start", "line_end"):
        item = getattr(value, name)
        if item is not None and (
            not isinstance(item, int) or isinstance(item, bool) or item < 1
        ):
            raise ValueError(f"provenance {name} must be a positive integer")
    for name in ("char_start", "char_end"):
        item = getattr(value, name)
        if item is not None and (
            not isinstance(item, int) or isinstance(item, bool) or item < 0
        ):
            raise ValueError(f"provenance {name} must be a non-negative integer")
    if (
        value.line_start is not None
        and value.line_end is not None
        and value.line_end < value.line_start
    ):
        raise ValueError("provenance line_end cannot precede line_start")
    if (
        value.char_start is not None
        and value.char_end is not None
        and value.char_end < value.char_start
    ):
        raise ValueError("provenance char_end cannot precede char_start")
    if value.bbox is not None and (
        len(value.bbox) != 4
        or any(
            not isinstance(item, (int, float))
            or isinstance(item, bool)
            or not math.isfinite(item)
            for item in value.bbox
        )
    ):
        raise ValueError("provenance bbox must contain four finite numbers")
    resolved = ProvenanceLocator(
        source_id=value.source_id,
        sha256=value.sha256,
        locator=locator,
        page=value.page,
        bbox=tuple(float(item) for item in value.bbox) if value.bbox else None,
        line_start=value.line_start,
        line_end=value.line_end,
        char_start=value.char_start,
        char_end=value.char_end,
        excerpt=excerpt,
    )
    PrivacyGate().assert_public_payload({"provenance": asdict(resolved)})
    return resolved


def _provenance_from_json(value: str) -> ProvenanceLocator:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise TypeError("provenance JSON must be an object")
    bbox = payload.get("bbox")
    if bbox is not None:
        if not isinstance(bbox, list):
            raise TypeError("provenance bbox must be an array")
        payload["bbox"] = tuple(bbox)
    return ProvenanceLocator(**payload)


def _assert_public_claim_content(
    candidate: EvidenceClaimCandidate,
    *,
    source_item: dict[str, Any] | None = None,
    reviewer_id: str | None = None,
    review_note: str | None = None,
) -> None:
    """Gate untrusted semantic content without reclassifying server timestamps.

    ``PrivacyGate`` knows typed public metadata dates such as ``retrieved_at``,
    but opaque receipt timestamps are integrity metadata rather than source
    content.  They are HMAC-bound separately and intentionally omitted here.
    """

    PrivacyGate().assert_public_query(candidate.question)
    semantic_payload: dict[str, Any] = {
        "text": candidate.text,
        "locator": candidate.provenance.locator,
        "excerpt": candidate.provenance.excerpt,
        "population": candidate.population,
        "outcome": candidate.outcome,
        "effect": candidate.effect,
        "native_grade_system": candidate.native_grade_system,
        "native_grade": candidate.native_grade,
        "limitations": list(candidate.limitations),
    }
    if reviewer_id is not None:
        semantic_payload["reviewer_id"] = reviewer_id
    if review_note is not None:
        semantic_payload["review_note"] = review_note
    PrivacyGate().assert_public_semantic_payload(semantic_payload)
    payload: dict[str, Any] = {
        "source_evidence_id": candidate.source_evidence_id,
        "statement_kind": candidate.statement_kind.value,
        "claim_type": candidate.claim_type,
        "provenance": asdict(candidate.provenance),
    }
    if source_item is not None:
        payload["evidence_item"] = source_item
    PrivacyGate().assert_public_payload(payload)


class EvidenceClaimReviewLedger:
    """Append-only, source-bound HMAC ledger for public evidence claims."""

    def __init__(self, database_path: str | Path, *, integrity_key: bytes) -> None:
        self.database_path = Path(database_path)
        self._integrity_key = bytes(integrity_key)
        if len(self._integrity_key) < 32:
            raise ValueError("evidence-review integrity key must contain at least 32 bytes")
        if str(self.database_path) == ":memory:":
            raise ValueError("evidence-review ledger requires a persistent database")
        self._prepare_database()
        self._initialize()

    def _mac(self, value: Any) -> str:
        return hmac.new(
            self._integrity_key,
            _canonical_json(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _prepare_database(self) -> None:
        parent = self.database_path.parent
        if parent.is_symlink():
            raise ValueError("evidence-review parent must not be a symbolic link")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("evidence-review parent must be a private directory")
        parent.chmod(0o700)
        if self.database_path.is_symlink():
            raise ValueError("evidence-review database must not be a symbolic link")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.database_path, flags, 0o600)
        try:
            state = os.fstat(descriptor)
            if not stat.S_ISREG(state.st_mode) or state.st_nlink != 1:
                raise ValueError(
                    "evidence-review database must be a singly linked regular file"
                )
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def _connect(self) -> sqlite3.Connection:
        parent_state = self.database_path.parent.lstat()
        database_state = self.database_path.lstat()
        if (
            stat.S_ISLNK(parent_state.st_mode)
            or not stat.S_ISDIR(parent_state.st_mode)
            or stat.S_IMODE(parent_state.st_mode) & 0o077
            or stat.S_ISLNK(database_state.st_mode)
            or not stat.S_ISREG(database_state.st_mode)
            or database_state.st_nlink != 1
            or stat.S_IMODE(database_state.st_mode) & 0o177
        ):
            raise ValueError("evidence-review ledger path is unsafe")
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_claim_candidate (
                    candidate_id TEXT PRIMARY KEY,
                    candidate_sha256 TEXT NOT NULL UNIQUE,
                    question TEXT NOT NULL,
                    source_kind TEXT NOT NULL CHECK(
                        source_kind IN ('retrieval_item', 'guideline_recommendation')
                    ),
                    source_root_id TEXT NOT NULL,
                    source_evidence_id TEXT NOT NULL,
                    source_snapshot_sha256 TEXT NOT NULL,
                    source_binding_json TEXT NOT NULL,
                    statement_kind TEXT NOT NULL CHECK(
                        statement_kind IN ('external_evidence', 'guideline_recommendation')
                    ),
                    claim_type TEXT NOT NULL CHECK(
                        claim_type IN ('finding', 'effect', 'harm', 'recommendation')
                    ),
                    claim_text TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    population TEXT,
                    outcome TEXT,
                    effect TEXT,
                    native_grade_system TEXT,
                    native_grade TEXT,
                    limitations_json TEXT NOT NULL,
                    registered_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reviewed_evidence_claim (
                    receipt_id TEXT PRIMARY KEY,
                    claim_id TEXT NOT NULL UNIQUE,
                    candidate_id TEXT NOT NULL UNIQUE
                        REFERENCES evidence_claim_candidate(candidate_id),
                    candidate_sha256 TEXT NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    review_note TEXT,
                    reviewed_at TEXT NOT NULL,
                    claim_json TEXT NOT NULL,
                    binding_hmac TEXT NOT NULL UNIQUE
                );
                """
            )
        self.database_path.chmod(0o600)
        self.database_path.parent.chmod(0o700)

    @staticmethod
    def _retrieval_binding(
        source: RetrievedEvidence,
        source_evidence_id: str,
    ) -> tuple[str, str, str, str, dict[str, Any]]:
        if not isinstance(source, RetrievedEvidence):
            raise TypeError("retrieval source must be verified RetrievedEvidence")
        if source.receipt.item_count != len(source.items) or len(
            source.receipt.item_sha256s
        ) != len(source.items):
            raise EvidenceReviewLedgerIntegrityError(
                "retrieval source item count binding is invalid"
            )
        matches = [
            (ordinal, item)
            for ordinal, item in enumerate(source.items)
            if item.evidence_id == source_evidence_id
        ]
        if len(matches) != 1:
            raise ValueError("source_evidence_id must select one retrieved item")
        ordinal, item = matches[0]
        item_payload = asdict(item)
        receipt_item_sha256 = _sha256_json(item_payload)
        if not hmac.compare_digest(
            receipt_item_sha256,
            source.receipt.item_sha256s[ordinal],
        ):
            raise EvidenceReviewLedgerIntegrityError(
                "retrieval item does not match its verified source snapshot"
            )
        if (
            not _RETRIEVAL_RECEIPT_ID.fullmatch(source.receipt.receipt_id)
            or not _SHA256.fullmatch(source.receipt.query_sha256)
            or not _SHA256.fullmatch(source.receipt.execution_sha256)
            or not _SHA256.fullmatch(source.receipt.results_sha256)
        ):
            raise EvidenceReviewLedgerIntegrityError(
                "retrieval receipt contains an invalid source binding"
            )
        question = _require_text(
            source.query.question,
            name="question",
            maximum_bytes=MAX_QUESTION_BYTES,
        )
        binding = {
            "schema": "evidence-claim-retrieval-source-v1",
            "receipt": asdict(source.receipt),
            "query_id": source.query.query_id,
            "question": question,
            "ordinal": ordinal,
            "item": item_payload,
            "item_sha256": receipt_item_sha256,
            "source_snapshot_sha256": evidence_item_snapshot_sha256(item),
        }
        return (
            question,
            source.receipt.receipt_id,
            item.evidence_id,
            evidence_item_snapshot_sha256(item),
            binding,
        )

    @staticmethod
    def _guideline_binding(
        source: GuidelineSourceDescriptor,
    ) -> tuple[str, str, str, str, dict[str, Any]]:
        if not isinstance(source, GuidelineSourceDescriptor):
            raise TypeError("guideline source must be a GuidelineSourceDescriptor")
        question = _require_text(
            source.question,
            name="question",
            maximum_bytes=MAX_QUESTION_BYTES,
        )
        recommendation_id = _require_text(
            source.recommendation_id,
            name="recommendation_id",
            maximum_bytes=512,
        )
        if source.evidence_item.source_type != "clinical_guideline":
            raise ValueError("guideline descriptor requires a clinical_guideline item")
        provenance = _validated_provenance(
            source.provenance,
            source_evidence_id=source.evidence_item.evidence_id,
        )
        verbatim = _require_text(
            source.verbatim_text,
            name="verbatim_text",
            maximum_bytes=MAX_STATEMENT_BYTES,
        )
        if provenance.excerpt != verbatim:
            raise ValueError("guideline excerpt must exactly equal verbatim_text")
        if source.evidence_item.content_hash != provenance.sha256:
            raise ValueError(
                "guideline EvidenceItem content_hash must match source provenance"
            )
        item_payload = asdict(source.evidence_item)
        item_sha256 = _sha256_json(item_payload)
        source_snapshot_sha256 = evidence_item_snapshot_sha256(
            source.evidence_item
        )
        binding = {
            "schema": "evidence-claim-guideline-source-v1",
            "recommendation_id": recommendation_id,
            "question": question,
            "item": item_payload,
            "item_sha256": item_sha256,
            "source_snapshot_sha256": source_snapshot_sha256,
            "verbatim_text": verbatim,
            "provenance": asdict(provenance),
            "native_grade_system": source.native_grade_system,
            "native_grade": source.native_grade,
        }
        return (
            question,
            recommendation_id,
            source.evidence_item.evidence_id,
            source_snapshot_sha256,
            binding,
        )

    def register_candidate(
        self,
        source: RetrievedEvidence | GuidelineSourceDescriptor,
        *,
        source_evidence_id: str | None = None,
        statement_kind: StatementKind | str | None = None,
        claim_type: str | None = None,
        text: str | None = None,
        provenance: ProvenanceLocator | None = None,
        population: str | None = None,
        outcome: str | None = None,
        effect: str | None = None,
        native_grade_system: str | None = None,
        native_grade: str | None = None,
        limitations: tuple[str, ...] = (),
    ) -> EvidenceClaimCandidate:
        """Freeze one claim candidate from an already verified public source."""

        if isinstance(source, RetrievedEvidence):
            selected_id = _require_text(
                source_evidence_id or "",
                name="source_evidence_id",
                maximum_bytes=512,
            )
            (
                question,
                source_root_id,
                selected_id,
                source_snapshot_sha256,
                source_binding,
            ) = self._retrieval_binding(source, selected_id)
            resolved_kind = _statement_kind(statement_kind or "")
            resolved_claim_type = _require_text(
                claim_type or "",
                name="claim_type",
                maximum_bytes=32,
            )
            resolved_text = _require_text(
                text or "",
                name="text",
                maximum_bytes=MAX_STATEMENT_BYTES,
            )
            resolved_provenance = _validated_provenance(
                provenance,  # type: ignore[arg-type]
                source_evidence_id=selected_id,
            )
            resolved_population = _optional_text(population, name="population")
            resolved_outcome = _optional_text(outcome, name="outcome")
            resolved_effect = _optional_text(effect, name="effect")
            resolved_grade_system = _optional_text(
                native_grade_system,
                name="native_grade_system",
            )
            resolved_grade = _optional_text(native_grade, name="native_grade")
            resolved_limitations = _limitations(limitations)
            if resolved_grade_system is not None or resolved_grade is not None:
                raise ValueError("retrieval-item claims cannot assert a native guideline grade")
        elif isinstance(source, GuidelineSourceDescriptor):
            (
                question,
                source_root_id,
                selected_id,
                source_snapshot_sha256,
                source_binding,
            ) = self._guideline_binding(source)
            if source_evidence_id is not None and source_evidence_id != selected_id:
                raise ValueError("guideline source_evidence_id override is forbidden")
            resolved_kind = _statement_kind(
                statement_kind or StatementKind.GUIDELINE_RECOMMENDATION
            )
            resolved_claim_type = claim_type or "recommendation"
            resolved_text = text if text is not None else source.verbatim_text
            resolved_provenance = provenance or source.provenance
            resolved_population = population if population is not None else source.population
            resolved_outcome = outcome if outcome is not None else source.outcome
            resolved_effect = effect if effect is not None else source.effect
            resolved_grade_system = (
                native_grade_system
                if native_grade_system is not None
                else source.native_grade_system
            )
            resolved_grade = native_grade if native_grade is not None else source.native_grade
            resolved_limitations = limitations or source.limitations
            exact_values = (
                (resolved_kind, StatementKind.GUIDELINE_RECOMMENDATION),
                (resolved_claim_type, "recommendation"),
                (resolved_text, source.verbatim_text),
                (resolved_provenance, source.provenance),
                (resolved_population, source.population),
                (resolved_outcome, source.outcome),
                (resolved_effect, source.effect),
                (resolved_grade_system, source.native_grade_system),
                (resolved_grade, source.native_grade),
                (tuple(resolved_limitations), tuple(source.limitations)),
            )
            if any(actual != expected for actual, expected in exact_values):
                raise ValueError("guideline source fields cannot be caller-overridden")
            resolved_text = _require_text(
                resolved_text,
                name="text",
                maximum_bytes=MAX_STATEMENT_BYTES,
            )
            resolved_provenance = _validated_provenance(
                resolved_provenance,
                source_evidence_id=selected_id,
            )
            resolved_population = _optional_text(
                resolved_population,
                name="population",
            )
            resolved_outcome = _optional_text(resolved_outcome, name="outcome")
            resolved_effect = _optional_text(resolved_effect, name="effect")
            resolved_grade_system = _optional_text(
                resolved_grade_system,
                name="native_grade_system",
            )
            resolved_grade = _optional_text(resolved_grade, name="native_grade")
            if resolved_grade_system is None or resolved_grade is None:
                raise ValueError("guideline source requires native grade fields")
            resolved_limitations = _limitations(tuple(resolved_limitations))
        else:
            raise TypeError(
                "source must be server-verified RetrievedEvidence or GuidelineSourceDescriptor"
            )

        _validate_kind_mapping(
            (
                "retrieval_item"
                if isinstance(source, RetrievedEvidence)
                else "guideline_recommendation"
            ),
            resolved_kind,
            resolved_claim_type,
        )
        if resolved_claim_type == "effect" and resolved_effect is None:
            raise ValueError("effect claims require an exact effect field")
        source_kind = (
            "retrieval_item"
            if isinstance(source, RetrievedEvidence)
            else "guideline_recommendation"
        )
        source_binding_json = _canonical_json(source_binding)
        if len(source_binding_json.encode("utf-8")) > MAX_SOURCE_BINDING_JSON_BYTES:
            raise ValueError("source binding exceeds the canonical size limit")
        material = {
            "schema": "evidence-claim-candidate-v1",
            "question": question,
            "source_kind": source_kind,
            "source_root_id": source_root_id,
            "source_evidence_id": selected_id,
            "source_snapshot_sha256": source_snapshot_sha256,
            "source_binding": source_binding,
            "statement_kind": resolved_kind.value,
            "claim_type": resolved_claim_type,
            "text": resolved_text,
            "provenance": asdict(resolved_provenance),
            "population": resolved_population,
            "outcome": resolved_outcome,
            "effect": resolved_effect,
            "native_grade_system": resolved_grade_system,
            "native_grade": resolved_grade,
            "limitations": list(resolved_limitations),
        }
        candidate_sha256 = _sha256_json(material)
        candidate_id = "eclaimcand_" + candidate_sha256[:32]
        registered_at = utc_now()
        candidate = EvidenceClaimCandidate(
            candidate_id=candidate_id,
            candidate_sha256=candidate_sha256,
            question=question,
            source_kind=source_kind,
            source_root_id=source_root_id,
            source_evidence_id=selected_id,
            source_snapshot_sha256=source_snapshot_sha256,
            statement_kind=resolved_kind,
            claim_type=resolved_claim_type,
            text=resolved_text,
            provenance=resolved_provenance,
            registered_at=registered_at,
            population=resolved_population,
            outcome=resolved_outcome,
            effect=resolved_effect,
            native_grade_system=resolved_grade_system,
            native_grade=resolved_grade,
            limitations=resolved_limitations,
        )
        _assert_public_claim_content(
            candidate,
            source_item=source_binding["item"],
        )
        with self._connect() as connection:
            # Make deterministic candidate registration idempotent across
            # concurrent callers. The second writer waits, then verifies and
            # returns the exact row committed by the first.
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM evidence_claim_candidate WHERE candidate_id = ?",
                (candidate_id,),
            ).fetchone()
            if existing is not None:
                loaded = self._candidate_from_row(existing)
                if loaded.candidate_sha256 != candidate_sha256:
                    raise EvidenceReviewLedgerIntegrityError(
                        "candidate ID is bound to different content"
                    )
                return loaded
            connection.execute(
                """
                INSERT INTO evidence_claim_candidate(
                    candidate_id, candidate_sha256, question, source_kind,
                    source_root_id, source_evidence_id, source_snapshot_sha256,
                    source_binding_json, statement_kind, claim_type, claim_text,
                    provenance_json, population, outcome, effect,
                    native_grade_system, native_grade, limitations_json,
                    registered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_id,
                    candidate_sha256,
                    question,
                    source_kind,
                    source_root_id,
                    selected_id,
                    source_snapshot_sha256,
                    source_binding_json,
                    resolved_kind.value,
                    resolved_claim_type,
                    resolved_text,
                    _canonical_json(asdict(resolved_provenance)),
                    resolved_population,
                    resolved_outcome,
                    resolved_effect,
                    resolved_grade_system,
                    resolved_grade,
                    _canonical_json(list(resolved_limitations)),
                    registered_at,
                ),
            )
        return candidate

    def _candidate_from_row(self, row: sqlite3.Row) -> EvidenceClaimCandidate:
        try:
            source_binding = json.loads(row["source_binding_json"])
            if not isinstance(source_binding, dict):
                raise TypeError("source binding must be an object")
            canonical_source_binding = _canonical_json(source_binding)
            if (
                canonical_source_binding != row["source_binding_json"]
                or len(canonical_source_binding.encode("utf-8"))
                > MAX_SOURCE_BINDING_JSON_BYTES
            ):
                raise ValueError("source binding is not canonical")
            item = source_binding.get("item")
            if not isinstance(item, dict):
                raise TypeError("source binding item is missing")
            item_sha256 = _sha256_json(item)
            item_snapshot_sha256 = evidence_item_snapshot_sha256(
                EvidenceItem(
                    **{
                        **item,
                        "limitations": tuple(item.get("limitations", ())),
                        "supersedes": tuple(item.get("supersedes", ())),
                    }
                )
            )
            if (
                source_binding.get("item_sha256") != item_sha256
                or source_binding.get("source_snapshot_sha256")
                != item_snapshot_sha256
                or row["source_snapshot_sha256"] != item_snapshot_sha256
                or item.get("evidence_id") != row["source_evidence_id"]
            ):
                raise ValueError("source snapshot binding mismatch")
            provenance = _provenance_from_json(row["provenance_json"])
            provenance = _validated_provenance(
                provenance,
                source_evidence_id=row["source_evidence_id"],
            )
            if row["source_kind"] == "retrieval_item":
                receipt = source_binding.get("receipt")
                ordinal = source_binding.get("ordinal")
                item_hashes = receipt.get("item_sha256s") if isinstance(receipt, dict) else None
                if (
                    source_binding.get("schema")
                    != "evidence-claim-retrieval-source-v1"
                    or not isinstance(receipt, dict)
                    or receipt.get("receipt_id") != row["source_root_id"]
                    or not _RETRIEVAL_RECEIPT_ID.fullmatch(row["source_root_id"])
                    or source_binding.get("question") != row["question"]
                    or not isinstance(ordinal, int)
                    or isinstance(ordinal, bool)
                    or ordinal < 0
                    or not isinstance(item_hashes, list)
                    or ordinal >= len(item_hashes)
                    or item_hashes[ordinal] != item_sha256
                ):
                    raise ValueError("retrieval root binding mismatch")
            elif row["source_kind"] == "guideline_recommendation":
                if (
                    source_binding.get("schema")
                    != "evidence-claim-guideline-source-v1"
                    or source_binding.get("recommendation_id")
                    != row["source_root_id"]
                    or source_binding.get("question") != row["question"]
                    or source_binding.get("verbatim_text") != row["claim_text"]
                    or _canonical_json(source_binding.get("provenance"))
                    != _canonical_json(asdict(provenance))
                ):
                    raise ValueError("guideline root binding mismatch")
            else:
                raise ValueError("source kind is invalid")
            limitations_payload = json.loads(row["limitations_json"])
            if not isinstance(limitations_payload, list):
                raise TypeError("limitations must be an array")
            limitations = _limitations(tuple(limitations_payload))
            statement_kind = _statement_kind(row["statement_kind"])
            claim_type = _require_text(
                row["claim_type"],
                name="claim_type",
                maximum_bytes=32,
            )
            _validate_kind_mapping(row["source_kind"], statement_kind, claim_type)
            question = _require_text(
                row["question"],
                name="question",
                maximum_bytes=MAX_QUESTION_BYTES,
            )
            text = _require_text(
                row["claim_text"],
                name="text",
                maximum_bytes=MAX_STATEMENT_BYTES,
            )
            population = _optional_text(row["population"], name="population")
            outcome = _optional_text(row["outcome"], name="outcome")
            effect = _optional_text(row["effect"], name="effect")
            native_grade_system = _optional_text(
                row["native_grade_system"],
                name="native_grade_system",
            )
            native_grade = _optional_text(row["native_grade"], name="native_grade")
            material = {
                "schema": "evidence-claim-candidate-v1",
                "question": question,
                "source_kind": row["source_kind"],
                "source_root_id": row["source_root_id"],
                "source_evidence_id": row["source_evidence_id"],
                "source_snapshot_sha256": row["source_snapshot_sha256"],
                "source_binding": source_binding,
                "statement_kind": statement_kind.value,
                "claim_type": claim_type,
                "text": text,
                "provenance": asdict(provenance),
                "population": population,
                "outcome": outcome,
                "effect": effect,
                "native_grade_system": native_grade_system,
                "native_grade": native_grade,
                "limitations": list(limitations),
            }
            candidate_sha256 = _sha256_json(material)
            candidate_id = "eclaimcand_" + candidate_sha256[:32]
            if (
                row["candidate_sha256"] != candidate_sha256
                or row["candidate_id"] != candidate_id
                or row["provenance_json"] != _canonical_json(asdict(provenance))
                or row["limitations_json"] != _canonical_json(list(limitations))
            ):
                raise ValueError("candidate canonical binding mismatch")
            candidate = EvidenceClaimCandidate(
                candidate_id=candidate_id,
                candidate_sha256=candidate_sha256,
                question=question,
                source_kind=row["source_kind"],
                source_root_id=row["source_root_id"],
                source_evidence_id=row["source_evidence_id"],
                source_snapshot_sha256=row["source_snapshot_sha256"],
                statement_kind=statement_kind,
                claim_type=claim_type,
                text=text,
                provenance=provenance,
                registered_at=row["registered_at"],
                population=population,
                outcome=outcome,
                effect=effect,
                native_grade_system=native_grade_system,
                native_grade=native_grade,
                limitations=limitations,
            )
            _assert_public_claim_content(candidate, source_item=item)
            return candidate
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise EvidenceReviewLedgerIntegrityError(
                "evidence claim candidate binding is invalid"
            ) from error

    def review_candidate(
        self,
        candidate_id: str,
        *,
        confirmed_question: str,
        confirmed_source_root_id: str,
        confirmed_source_evidence_id: str,
        confirmed_source_snapshot_sha256: str,
        confirmed_statement_kind: StatementKind | str,
        confirmed_claim_type: str,
        confirmed_text: str,
        confirmed_provenance: ProvenanceLocator,
        confirmed_limitations: tuple[str, ...],
        reviewer_id: str,
        confirmed_population: str | None = None,
        confirmed_outcome: str | None = None,
        confirmed_effect: str | None = None,
        confirmed_native_grade_system: str | None = None,
        confirmed_native_grade: str | None = None,
        review_note: str | None = None,
    ) -> EvidenceClaimReviewReceipt:
        """Issue one receipt only after every material field matches exactly."""

        candidate_key = _require_text(
            candidate_id,
            name="candidate_id",
            maximum_bytes=128,
        )
        if not _CANDIDATE_ID.fullmatch(candidate_key):
            raise ValueError("candidate_id must be an opaque eclaimcand_ identifier")
        reviewer = _require_text(
            reviewer_id,
            name="reviewer_id",
            maximum_bytes=512,
        )
        note = (
            _require_text(
                review_note,
                name="review_note",
                maximum_bytes=MAX_REVIEW_NOTE_BYTES,
            )
            if review_note is not None
            else None
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM evidence_claim_candidate WHERE candidate_id = ?",
                (candidate_key,),
            ).fetchone()
            if row is None:
                raise UnknownEvidenceClaimCandidateError(
                    "evidence claim candidate is not present in the ledger"
                )
            candidate = self._candidate_from_row(row)
            confirmations = (
                (confirmed_question, candidate.question),
                (confirmed_source_root_id, candidate.source_root_id),
                (confirmed_source_evidence_id, candidate.source_evidence_id),
                (
                    confirmed_source_snapshot_sha256,
                    candidate.source_snapshot_sha256,
                ),
                (_statement_kind(confirmed_statement_kind), candidate.statement_kind),
                (confirmed_claim_type, candidate.claim_type),
                (confirmed_text, candidate.text),
                (confirmed_provenance, candidate.provenance),
                (confirmed_population, candidate.population),
                (confirmed_outcome, candidate.outcome),
                (confirmed_effect, candidate.effect),
                (confirmed_native_grade_system, candidate.native_grade_system),
                (confirmed_native_grade, candidate.native_grade),
                (confirmed_limitations, candidate.limitations),
            )
            if any(actual != expected for actual, expected in confirmations):
                raise ValueError(
                    "confirmed evidence claim fields must exactly match the candidate"
                )
            existing = connection.execute(
                """
                SELECT c.*,
                       r.receipt_id, r.claim_id,
                       r.candidate_sha256 AS reviewed_candidate_sha256,
                       r.reviewer_id, r.review_note, r.reviewed_at,
                       r.claim_json, r.binding_hmac
                FROM reviewed_evidence_claim r
                JOIN evidence_claim_candidate c ON c.candidate_id = r.candidate_id
                WHERE r.candidate_id = ?
                """,
                (candidate_key,),
            ).fetchone()
            if existing is not None:
                receipt = self._verified_receipt_row(existing)
                if receipt.reviewer_id != reviewer or receipt.review_note != note:
                    raise ValueError(
                        "evidence claim candidate was already reviewed with different attribution"
                    )
                return receipt
            _assert_public_claim_content(
                candidate,
                reviewer_id=reviewer,
                review_note=note,
            )
            reviewed_at = utc_now()
            claim_id = "evclaim_" + self._mac(
                {
                    "schema": "reviewed-evidence-claim-id-v1",
                    "candidate_sha256": candidate.candidate_sha256,
                }
            )[:32]
            review_material = {
                "schema": "evidence-claim-review-v1",
                "candidate_id": candidate.candidate_id,
                "candidate_sha256": candidate.candidate_sha256,
                "claim_id": claim_id,
                "reviewer_id": reviewer,
                "review_note": note,
                "reviewed_at": reviewed_at,
            }
            receipt_id = "eclaim_rcpt_" + self._mac(review_material)[:32]
            claim = ReviewedEvidenceClaim(
                claim_id=claim_id,
                question=candidate.question,
                source_kind=candidate.source_kind,
                source_evidence_id=candidate.source_evidence_id,
                source_snapshot_sha256=candidate.source_snapshot_sha256,
                statement_kind=candidate.statement_kind,
                claim_type=candidate.claim_type,
                text=candidate.text,
                provenance=candidate.provenance,
                review_receipt_id=receipt_id,
                reviewed_at=reviewed_at,
                reviewer_id=reviewer,
                verification=VerificationStatus.VERIFIED,
                population=candidate.population,
                outcome=candidate.outcome,
                effect=candidate.effect,
                native_grade_system=candidate.native_grade_system,
                native_grade=candidate.native_grade,
                limitations=candidate.limitations,
            )
            claim_json = _canonical_json(to_dict(claim))
            if len(claim_json.encode("utf-8")) > MAX_CLAIM_JSON_BYTES:
                raise ValueError("reviewed evidence claim exceeds the canonical size limit")
            binding_hmac = self._mac(
                {
                    "schema": "evidence-claim-review-receipt-binding-v1",
                    "review": review_material,
                    "claim_json": claim_json,
                }
            )
            connection.execute(
                """
                INSERT INTO reviewed_evidence_claim(
                    receipt_id, claim_id, candidate_id, candidate_sha256,
                    reviewer_id, review_note, reviewed_at, claim_json, binding_hmac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    claim_id,
                    candidate.candidate_id,
                    candidate.candidate_sha256,
                    reviewer,
                    note,
                    reviewed_at,
                    claim_json,
                    binding_hmac,
                ),
            )
        return EvidenceClaimReviewReceipt(
            receipt_id=receipt_id,
            claim_id=claim_id,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            source_root_id=candidate.source_root_id,
            source_evidence_id=candidate.source_evidence_id,
            source_snapshot_sha256=candidate.source_snapshot_sha256,
            reviewer_id=reviewer,
            review_note=note,
            reviewed_at=reviewed_at,
            binding_hmac=binding_hmac,
            claim=claim,
        )

    def _verified_receipt_row(self, row: sqlite3.Row) -> EvidenceClaimReviewReceipt:
        candidate = self._candidate_from_row(row)
        try:
            reviewer = _require_text(
                row["reviewer_id"],
                name="reviewer_id",
                maximum_bytes=512,
            )
            note = (
                _require_text(
                    row["review_note"],
                    name="review_note",
                    maximum_bytes=MAX_REVIEW_NOTE_BYTES,
                )
                if row["review_note"] is not None
                else None
            )
            claim_id = "evclaim_" + self._mac(
                {
                    "schema": "reviewed-evidence-claim-id-v1",
                    "candidate_sha256": candidate.candidate_sha256,
                }
            )[:32]
            review_material = {
                "schema": "evidence-claim-review-v1",
                "candidate_id": candidate.candidate_id,
                "candidate_sha256": candidate.candidate_sha256,
                "claim_id": claim_id,
                "reviewer_id": reviewer,
                "review_note": note,
                "reviewed_at": row["reviewed_at"],
            }
            receipt_id = "eclaim_rcpt_" + self._mac(review_material)[:32]
            claim = ReviewedEvidenceClaim(
                claim_id=claim_id,
                question=candidate.question,
                source_kind=candidate.source_kind,
                source_evidence_id=candidate.source_evidence_id,
                source_snapshot_sha256=candidate.source_snapshot_sha256,
                statement_kind=candidate.statement_kind,
                claim_type=candidate.claim_type,
                text=candidate.text,
                provenance=candidate.provenance,
                review_receipt_id=receipt_id,
                reviewed_at=row["reviewed_at"],
                reviewer_id=reviewer,
                verification=VerificationStatus.VERIFIED,
                population=candidate.population,
                outcome=candidate.outcome,
                effect=candidate.effect,
                native_grade_system=candidate.native_grade_system,
                native_grade=candidate.native_grade,
                limitations=candidate.limitations,
            )
            claim_json = _canonical_json(to_dict(claim))
            if len(claim_json.encode("utf-8")) > MAX_CLAIM_JSON_BYTES:
                raise ValueError("claim size limit exceeded")
            binding_hmac = self._mac(
                {
                    "schema": "evidence-claim-review-receipt-binding-v1",
                    "review": review_material,
                    "claim_json": claim_json,
                }
            )
            if (
                row["reviewed_candidate_sha256"] != candidate.candidate_sha256
                or row["claim_id"] != claim_id
                or row["receipt_id"] != receipt_id
                or row["claim_json"] != claim_json
                or not hmac.compare_digest(row["binding_hmac"], binding_hmac)
            ):
                raise ValueError("receipt binding mismatch")
            _assert_public_claim_content(
                candidate,
                reviewer_id=reviewer,
                review_note=note,
            )
            return EvidenceClaimReviewReceipt(
                receipt_id=receipt_id,
                claim_id=claim_id,
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.candidate_sha256,
                source_root_id=candidate.source_root_id,
                source_evidence_id=candidate.source_evidence_id,
                source_snapshot_sha256=candidate.source_snapshot_sha256,
                reviewer_id=reviewer,
                review_note=note,
                reviewed_at=row["reviewed_at"],
                binding_hmac=binding_hmac,
                claim=claim,
            )
        except (TypeError, ValueError) as error:
            raise EvidenceReviewLedgerIntegrityError(
                "evidence claim review receipt binding is invalid"
            ) from error

    def load_receipt(self, receipt_id: str) -> EvidenceClaimReviewReceipt:
        return self.load_receipts([receipt_id])[0]

    def load_receipts(
        self,
        receipt_ids: list[str],
    ) -> tuple[EvidenceClaimReviewReceipt, ...]:
        """Load verified receipts in caller order with a hard batch bound."""

        if not isinstance(receipt_ids, list) or not receipt_ids:
            raise ValueError("receipt_ids must be a non-empty list")
        if len(receipt_ids) > MAX_RECEIPTS_PER_LOAD:
            raise ValueError(
                f"receipt_ids must contain at most {MAX_RECEIPTS_PER_LOAD} entries"
            )
        if any(not isinstance(receipt_id, str) for receipt_id in receipt_ids):
            raise ValueError("receipt_id must be an opaque eclaim_rcpt_ identifier")
        if len(set(receipt_ids)) != len(receipt_ids):
            raise DuplicateEvidenceClaimReceiptError(
                "receipt_ids must not contain duplicate review receipts"
            )
        if any(not _RECEIPT_ID.fullmatch(receipt_id) for receipt_id in receipt_ids):
            raise ValueError("receipt_id must be an opaque eclaim_rcpt_ identifier")

        output: list[EvidenceClaimReviewReceipt] = []
        total_bytes = 0
        with self._connect() as connection:
            for receipt_id in receipt_ids:
                row = connection.execute(
                    """
                    SELECT c.*,
                           r.receipt_id, r.claim_id,
                           r.candidate_sha256 AS reviewed_candidate_sha256,
                           r.reviewer_id, r.review_note, r.reviewed_at,
                           r.claim_json, r.binding_hmac
                    FROM reviewed_evidence_claim r
                    JOIN evidence_claim_candidate c ON c.candidate_id = r.candidate_id
                    WHERE r.receipt_id = ?
                    """,
                    (receipt_id,),
                ).fetchone()
                if row is None:
                    raise UnknownEvidenceClaimReceiptError(
                        "evidence claim review receipt is not present in the ledger"
                    )
                receipt = self._verified_receipt_row(row)
                total_bytes += len(row["claim_json"].encode("utf-8"))
                if total_bytes > MAX_REVIEW_BATCH_JSON_BYTES:
                    raise ValueError("reviewed evidence claims exceed the batch size limit")
                output.append(receipt)
        return tuple(output)
