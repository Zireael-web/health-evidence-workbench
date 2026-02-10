"""Evidence-to-claim traceability for generated answers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3

from ..contracts import (
    AnswerBundle,
    CasePacket,
    EvidencePacket,
    RiskIntent,
    StatementKind,
    VerificationStatus,
    utc_now,
)


@dataclass(frozen=True, slots=True)
class AuditIssue:
    severity: str
    code: str
    message: str
    claim_id: str | None = None


@dataclass(frozen=True, slots=True)
class AuditReport:
    bundle_id: str
    passed: bool
    issues: tuple[AuditIssue, ...]
    audited_at: str
    structural_traceability_passed: bool
    bundle_sha256: str = ""


def _bundle_sha256(bundle: AnswerBundle) -> str:
    """Bind an audit to exact content, not only a caller-chosen bundle ID."""

    return hashlib.sha256(
        json.dumps(
            asdict(bundle), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def audit_answer(
    bundle: AnswerBundle,
    *,
    case_packet: CasePacket | None = None,
    evidence_packet: EvidencePacket | None = None,
) -> AuditReport:
    """Validate that every claim has the right kind of traceable support."""

    issues: list[AuditIssue] = []
    if not isinstance(bundle.bundle_id, str) or not bundle.bundle_id.strip():
        issues.append(AuditIssue("error", "invalid_bundle_id", "AnswerBundle ID is required."))
    if not isinstance(bundle.question, str) or not bundle.question.strip():
        issues.append(AuditIssue("error", "empty_question", "AnswerBundle question is required."))
    if bundle.schema_version != "1.1":
        issues.append(
            AuditIssue("error", "unsupported_schema", "AnswerBundle schema_version must be 1.1.")
        )
    if bundle.review_required is not True:
        issues.append(
            AuditIssue(
                "error",
                "review_not_required",
                "Medical AnswerBundle output must remain marked for human review.",
            )
        )
    if not bundle.claims:
        issues.append(AuditIssue("error", "empty_claims", "AnswerBundle contains no claims."))
    case_ids: set[str] = set()
    case_verification: dict[str, str] = {}
    case_support_kinds: dict[str, StatementKind] = {}
    if case_packet:
        if any(
            item.subject_id != case_packet.subject_id
            for item in case_packet.observations
        ) or any(
            item.subject_id not in (None, case_packet.subject_id)
            for item in case_packet.statements
        ):
            issues.append(AuditIssue(
                "error", "case_subject_mismatch",
                "Case support contains records from a different subject.",
            ))
        case_ids.update(observation.observation_id for observation in case_packet.observations)
        case_ids.update(statement.statement_id for statement in case_packet.statements)
        case_support_kinds.update(
            (observation.observation_id, StatementKind.SOURCE_FACT)
            for observation in case_packet.observations
        )
        case_support_kinds.update(
            (statement.statement_id, statement.kind)
            for statement in case_packet.statements
        )
        case_verification.update(
            (observation.observation_id, observation.verification.value)
            for observation in case_packet.observations
        )
        case_verification.update(
            (statement.statement_id, statement.verification.value)
            for statement in case_packet.statements
        )

    evidence_item_ids: set[str] = set()
    evidence_ids: set[str] = set()
    evidence_support_kinds: dict[str, StatementKind] = {}
    evidence_verification: dict[str, str] = {}
    if evidence_packet:
        evidence_item_ids.update(item.evidence_id for item in evidence_packet.items)
        evidence_ids.update(claim.claim_id for claim in evidence_packet.reviewed_claims)
        evidence_support_kinds.update(
            (claim.claim_id, claim.statement_kind)
            for claim in evidence_packet.reviewed_claims
        )
        evidence_verification.update(
            (claim.claim_id, claim.verification.value)
            for claim in evidence_packet.reviewed_claims
        )
        if len(evidence_item_ids) != len(evidence_packet.items):
            issues.append(
                AuditIssue("error", "duplicate_evidence_id", "Evidence identifiers must be unique.")
            )
        if len(evidence_ids) != len(evidence_packet.reviewed_claims):
            issues.append(
                AuditIssue(
                    "error",
                    "duplicate_reviewed_evidence_claim_id",
                    "Reviewed evidence claim identifiers must be unique.",
                )
            )

    if case_packet:
        case_item_count = len(case_packet.observations) + len(case_packet.statements)
        if len(case_ids) != case_item_count:
            issues.append(AuditIssue("error", "duplicate_case_id", "Case support identifiers must be unique."))

    if case_ids & (evidence_ids | evidence_item_ids):
        issues.append(AuditIssue(
            "error", "ambiguous_support_id",
            "Case and public evidence support identifiers must not overlap.",
        ))

    supplied_case_packet_id = case_packet.packet_id if case_packet else None
    if bundle.case_packet_id != supplied_case_packet_id:
        issues.append(
            AuditIssue(
                "error",
                "case_packet_mismatch",
                "AnswerBundle CasePacket binding does not match the supplied packet.",
            )
        )
    supplied_evidence_packet_id = evidence_packet.packet_id if evidence_packet else None
    if bundle.evidence_packet_id != supplied_evidence_packet_id:
        issues.append(
            AuditIssue(
                "error",
                "evidence_packet_mismatch",
                "AnswerBundle EvidencePacket binding does not match the supplied packet.",
            )
        )
    if not bundle.risk_envelope.is_explicit:
        issues.append(
            AuditIssue(
                "error",
                "answer_risk_unspecified",
                "AnswerBundle must declare an explicit risk intent; a legacy "
                "payload cannot pass audit.",
            )
        )
    if evidence_packet and not evidence_packet.risk_envelope.is_explicit:
        issues.append(
            AuditIssue(
                "error",
                "evidence_risk_unspecified",
                "Legacy EvidencePacket risk is unspecified and cannot support "
                "an audited answer.",
            )
        )
    if evidence_packet and bundle.question != evidence_packet.question:
        issues.append(
            AuditIssue(
                "error",
                "evidence_question_mismatch",
                "AnswerBundle question does not exactly match the supplied EvidencePacket question.",
            )
        )
    if (
        evidence_packet
        and bundle.risk_envelope != evidence_packet.risk_envelope
    ):
        issues.append(
            AuditIssue(
                "error",
                "risk_envelope_mismatch",
                "AnswerBundle risk intent and confirmation contract do not "
                "match the supplied EvidencePacket.",
            )
        )
    if bundle.risk_envelope.intent is RiskIntent.CLINICAL_ACTION:
        issues.append(
            AuditIssue(
                "error",
                "clinician_confirmation_not_obtained",
                "The risk envelope declares that clinician confirmation is "
                "required; it is not a confirmation receipt. This clinical-action "
                "bundle remains a structurally audited draft.",
            )
        )

    claim_ids = {claim.claim_id for claim in bundle.claims}
    if len(claim_ids) != len(bundle.claims):
        issues.append(AuditIssue("error", "duplicate_claim_id", "Claim identifiers must be unique."))

    allowed_certainty = {"low", "moderate", "high", "not_applicable"}
    for claim in bundle.claims:
        if not isinstance(claim.claim_id, str) or not claim.claim_id.strip():
            issues.append(AuditIssue(
                "error", "invalid_claim_id", "Claim ID is required.",
            ))
        if not isinstance(claim.kind, StatementKind):
            issues.append(AuditIssue(
                "error", "invalid_claim_kind", "Claim kind is unsupported.", claim.claim_id,
            ))
            continue
        if not claim.text.strip():
            issues.append(AuditIssue("error", "empty_claim", "Claim text is empty.", claim.claim_id))
        if claim.certainty not in allowed_certainty:
            issues.append(
                AuditIssue(
                    "error",
                    "invalid_certainty",
                    f"Unsupported certainty label: {claim.certainty}",
                    claim.claim_id,
                )
            )
        if claim.status is VerificationStatus.REJECTED:
            issues.append(
                AuditIssue(
                    "error",
                    "rejected_claim",
                    "A rejected claim cannot pass an answer audit.",
                    claim.claim_id,
                )
            )
        elif claim.status is not VerificationStatus.VERIFIED:
            issues.append(
                AuditIssue(
                    "error",
                    "unverified_output_claim",
                    "An extracted or needs-review claim may be structurally "
                    "traceable, but cannot pass the final answer audit.",
                    claim.claim_id,
                )
            )
        if not claim.support_ids:
            issues.append(
                AuditIssue("error", "unsupported_claim", "Claim has no support identifiers.", claim.claim_id)
            )
            continue
        if len(set(claim.support_ids)) != len(claim.support_ids):
            issues.append(
                AuditIssue(
                    "error",
                    "duplicate_support_id",
                    "Claim support identifiers must be unique.",
                    claim.claim_id,
                )
            )

        metadata_only = sorted(set(claim.support_ids) & evidence_item_ids)
        if metadata_only:
            issues.append(
                AuditIssue(
                    "error",
                    "metadata_only_support",
                    "Bibliographic metadata cannot support a substantive claim; use a reviewed evidence claim ID: "
                    + ", ".join(metadata_only),
                    claim.claim_id,
                )
            )
        unknown = set(claim.support_ids) - case_ids - evidence_ids - evidence_item_ids
        if unknown:
            issues.append(
                AuditIssue(
                    "error",
                    "unknown_support",
                    "Claim references support that is absent from the supplied packets: "
                    + ", ".join(sorted(unknown)),
                    claim.claim_id,
                )
            )

        has_case = bool(set(claim.support_ids) & case_ids)
        has_evidence = bool(set(claim.support_ids) & evidence_ids)
        claim_case_ids = set(claim.support_ids) & case_ids
        claim_evidence_ids = set(claim.support_ids) & evidence_ids
        if (
            claim.kind is not StatementKind.INFERENCE
            and claim_case_ids
            and (claim_evidence_ids or metadata_only)
        ):
            issues.append(
                AuditIssue(
                    "error",
                    "mixed_support_requires_inference",
                    "A claim combining case and external-evidence support must be "
                    "typed as inference.",
                    claim.claim_id,
                )
            )
        unverified_evidence = sorted(
            support_id
            for support_id in claim_evidence_ids
            if evidence_verification.get(support_id) != "verified"
        )
        if unverified_evidence:
            issues.append(
                AuditIssue(
                    "error",
                    "unverified_evidence_support",
                    "Evidence claims may only use reviewed evidence support: "
                    + ", ".join(unverified_evidence),
                    claim.claim_id,
                )
            )
        unverified_case = sorted(
            support_id
            for support_id in set(claim.support_ids) & case_ids
            if case_verification.get(support_id) != "verified"
        )
        if unverified_case:
            issues.append(
                AuditIssue(
                    "error",
                    "unverified_case_support",
                    "Personal claims may only use human-verified case support: "
                    + ", ".join(unverified_case),
                    claim.claim_id,
                )
            )
        if claim.kind in {StatementKind.SOURCE_FACT, StatementKind.USER_NOTE, StatementKind.CALCULATED}:
            if not has_case:
                issues.append(
                    AuditIssue(
                        "error",
                        "missing_case_support",
                        f"{claim.kind.value} requires support from a CasePacket.",
                        claim.claim_id,
                    )
                )
            else:
                expected_case_kind = claim.kind
                incompatible = sorted(
                    support_id
                    for support_id in claim_case_ids
                    if case_support_kinds.get(support_id) is not expected_case_kind
                )
                if incompatible:
                    issues.append(
                        AuditIssue(
                            "error",
                            "case_support_kind_mismatch",
                            f"{claim.kind.value} cannot be supported by differently typed case records: "
                            + ", ".join(incompatible),
                            claim.claim_id,
                        )
                    )
        elif claim.kind in {
            StatementKind.EXTERNAL_EVIDENCE,
            StatementKind.GUIDELINE_RECOMMENDATION,
        }:
            if not has_evidence:
                issues.append(
                    AuditIssue(
                        "error",
                        "missing_evidence_support",
                        f"{claim.kind.value} requires support from an EvidencePacket.",
                        claim.claim_id,
                    )
                )
            else:
                incompatible = sorted(
                    support_id
                    for support_id in claim_evidence_ids
                    if evidence_support_kinds.get(support_id) is not claim.kind
                )
                if incompatible:
                    issues.append(
                        AuditIssue(
                            "error",
                            "evidence_support_kind_mismatch",
                            f"{claim.kind.value} cannot be supported by differently typed reviewed evidence: "
                            + ", ".join(incompatible),
                            claim.claim_id,
                        )
                    )
            if claim.kind is StatementKind.GUIDELINE_RECOMMENDATION and not any(
                evidence_support_kinds.get(support_id)
                is StatementKind.GUIDELINE_RECOMMENDATION
                for support_id in claim_evidence_ids
            ):
                issues.append(
                    AuditIssue(
                        "error",
                        "missing_guideline_support",
                        "A guideline recommendation requires at least one clinical_guideline source.",
                        claim.claim_id,
                    )
                )
        elif claim.kind is StatementKind.INFERENCE:
            if not (has_case and has_evidence):
                issues.append(
                    AuditIssue(
                        "error",
                        "missing_inference_support",
                        "A personal inference requires both verified case support and external evidence support.",
                        claim.claim_id,
                    )
                )

        for conflict_id in claim.conflicts_with:
            if conflict_id == claim.claim_id or conflict_id not in claim_ids:
                issues.append(
                    AuditIssue(
                        "error",
                        "invalid_conflict_reference",
                        f"Invalid conflicting claim reference: {conflict_id}",
                        claim.claim_id,
                    )
                )

    draft_only_codes = {
        "rejected_claim",
        "unverified_output_claim",
        "clinician_confirmation_not_obtained",
    }
    structural_traceability_passed = not any(
        issue.severity == "error" and issue.code not in draft_only_codes
        for issue in issues
    )
    passed = not any(issue.severity == "error" for issue in issues)
    return AuditReport(
        bundle_id=bundle.bundle_id,
        passed=passed,
        issues=tuple(issues),
        audited_at=utc_now(),
        structural_traceability_passed=structural_traceability_passed,
        bundle_sha256=_bundle_sha256(bundle),
    )


class ClaimLedger:
    """Append-oriented SQLite ledger of answer bundles and their audits."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS answer_bundle (
                    bundle_id TEXT PRIMARY KEY,
                    question TEXT NOT NULL,
                    case_packet_id TEXT,
                    evidence_packet_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS claim (
                    claim_id TEXT PRIMARY KEY,
                    bundle_id TEXT NOT NULL REFERENCES answer_bundle(bundle_id),
                    kind TEXT NOT NULL,
                    text TEXT NOT NULL,
                    certainty TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS claim_support (
                    claim_id TEXT NOT NULL REFERENCES claim(claim_id),
                    support_id TEXT NOT NULL,
                    PRIMARY KEY (claim_id, support_id)
                );
                CREATE TABLE IF NOT EXISTS answer_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bundle_id TEXT NOT NULL REFERENCES answer_bundle(bundle_id),
                    passed INTEGER NOT NULL,
                    audited_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )

    def append(self, bundle: AnswerBundle, report: AuditReport) -> None:
        if report.bundle_id != bundle.bundle_id:
            raise ValueError("audit report belongs to a different answer bundle")
        if report.bundle_sha256 != _bundle_sha256(bundle):
            raise ValueError("audit report is not bound to this exact answer bundle content")
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO answer_bundle
                (bundle_id, question, case_packet_id, evidence_packet_id, created_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    bundle.bundle_id,
                    bundle.question,
                    bundle.case_packet_id,
                    bundle.evidence_packet_id,
                    bundle.created_at,
                    json.dumps(asdict(bundle), ensure_ascii=False, sort_keys=True),
                ),
            )
            for claim in bundle.claims:
                connection.execute(
                    """INSERT INTO claim
                    (claim_id, bundle_id, kind, text, certainty, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        claim.claim_id,
                        bundle.bundle_id,
                        claim.kind.value,
                        claim.text,
                        claim.certainty,
                        json.dumps(asdict(claim), ensure_ascii=False, sort_keys=True),
                    ),
                )
                connection.executemany(
                    "INSERT INTO claim_support (claim_id, support_id) VALUES (?, ?)",
                    ((claim.claim_id, support_id) for support_id in claim.support_ids),
                )
            connection.execute(
                """INSERT INTO answer_audit (bundle_id, passed, audited_at, payload_json)
                VALUES (?, ?, ?, ?)""",
                (
                    bundle.bundle_id,
                    int(report.passed),
                    report.audited_at,
                    json.dumps(asdict(report), ensure_ascii=False, sort_keys=True),
                ),
            )

    def latest_audit(self, bundle_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload_json FROM answer_audit
                WHERE bundle_id = ? ORDER BY audit_id DESC LIMIT 1""",
                (bundle_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None
