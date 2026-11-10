"""Exact-kind private answer resolution; no model or medical release authority.

The backend checks selected immutable values and provenance bindings. Claim
prose remains unchecked. An accepted preparation is always a private draft
needing semantic, medical and human review.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Callable

from .common import SignedStore, V2Error, canonical, digest, new_id, require, utc_now
from .contracts import SHA256_RE, identifier, iso_timestamp
from .records import TRUSTED_ASSURANCE

DRAFT_SCHEMA = "health-analyzer.private-answer-draft/2.0"
REVIEW_SCHEMA = "health-analyzer.private-answer-review/2.0"
PRIVATE_CLAIM_TYPES = {"source_fact", "user_note", "calculated"}
PRIVATE_INTENTS = {"personal_interpretation", "clinical_action"}
SOURCE_ASSERTION_FIELDS = {"analyte_raw", "analyte_key", "mapping_status",
    "measurement_property", "subtype", "loinc", "result", "unit_raw",
    "unit_code", "clinical_time", "reference_intervals", "specimen", "method",
    "device", "lab_flag_raw", "panel_key"}
NOTE_ASSERTION_FIELDS = {"text", "fields", "event_type", "effective_time"}
CASE_ID_RE = re.compile(r"^case_[0-9a-f]{32,64}$")
MAX_DRAFT_BYTES = 256 * 1024
Lookup = Callable[[str, str, str], dict]


def _object(value: Any, fields: set[str], required: set[str] | None = None) -> dict:
    require(isinstance(value, dict), "invalid_private_answer", "Expected a private answer object")
    require(all(isinstance(key, str) for key in value), "invalid_private_answer", "Object keys must be strings")
    require(set(value) <= fields, "unknown_private_answer_field", "Unexpected private answer fields")
    require((fields if required is None else required) <= set(value), "missing_private_answer_field", "Missing private answer fields")
    return value


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    require(isinstance(value, str) and bool(value.strip()) and len(value) <= maximum,
            "invalid_private_answer", f"{label} must be a bounded non-empty string")
    return value


def _case_id(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(CASE_ID_RE.fullmatch(value)),
            "invalid_private_answer_id", f"{label} must use the private case identifier domain")
    return value


def _sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(SHA256_RE.fullmatch(value)),
            "invalid_private_answer_hash", f"Invalid {label}")
    return value


def _bounded_json(value: Any) -> None:
    """Bound recursion before serialization of an untrusted caller object."""
    count = 0
    def visit(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        require(depth <= 20 and count <= 10000, "private_answer_limit", "Private answer JSON nesting or item limit exceeded")
        if isinstance(item, dict):
            require(all(isinstance(key, str) for key in item), "invalid_private_answer", "JSON object keys must be strings")
            for nested in item.values():
                visit(nested, depth + 1)
        elif isinstance(item, list):
            for nested in item:
                visit(nested, depth + 1)
        else:
            require(item is None or type(item) in {str, int, float, bool}, "invalid_private_answer", "Private answer values must be JSON data")
    visit(value, 0)


def validate_private_answer_draft(value: Any) -> dict:
    """Validate only the caller's bounded contract; never accept review flags."""
    _object(value, {"intent", "claims"}, {"claims"})
    _bounded_json(value)
    require(len(canonical(value)) <= MAX_DRAFT_BYTES, "private_answer_limit", "Private draft exceeds the size limit")
    intent = value.get("intent", "personal_interpretation")
    require(isinstance(intent, str) and intent in PRIVATE_INTENTS,
            "invalid_private_answer", "Unknown private answer intent")
    claims = value["claims"]
    require(isinstance(claims, list) and 1 <= len(claims) <= 100,
            "private_answer_limit", "Private draft needs 1-100 claims")
    seen = set()
    for claim in claims:
        _object(claim, {"claim_id", "type", "text", "support_id", "assertion"})
        claim_id = identifier(claim["claim_id"], "claim_id")
        require(claim_id not in seen, "duplicate_claim", "Private claim IDs must be unique")
        seen.add(claim_id)
        kind = claim["type"]
        require(isinstance(kind, str) and kind in PRIVATE_CLAIM_TYPES,
                "invalid_private_claim_kind", "Only private exact-kind claims are accepted")
        _bounded_text(claim["text"], "claim text", 6000)
        identifier(claim["support_id"], "support_id")
        assertion = claim["assertion"]
        if kind == "calculated":
            _case_id(claim["support_id"], "calculation ID")
            _object(assertion, {"receipt_sha256", "metric"})
            _sha(assertion["receipt_sha256"], "calculation receipt hash")
            require(isinstance(assertion["metric"], str) and assertion["metric"] in {"delta", "percent_change"},
                    "invalid_private_calculation_assertion", "Unknown backend calculation metric")
        else:
            _object(assertion, {"field", "expected_value"})
            fields = SOURCE_ASSERTION_FIELDS if kind == "source_fact" else NOTE_ASSERTION_FIELDS
            require(isinstance(assertion["field"], str) and assertion["field"] in fields,
                    "invalid_private_assertion", "Assertion must name one allowed whole top-level field")
            # The exact canonical comparison below checks nested keys and JSON
            # types against the authoritative typed field, including bool/int.
            canonical(assertion["expected_value"])
    return copy.deepcopy(value)


def _resolve_claims(draft: dict, resolved: dict, lookup: Lookup) -> tuple[list[dict], dict]:
    selection = resolved["selection"]
    subject = selection["subject_id"]
    states, observations, events, calculations = [], {}, {}, {}
    for claim in draft["claims"]:
        support_id, kind, assertion = claim["support_id"], claim["type"], claim["assertion"]
        state = {"claim_id": claim["claim_id"], "type": kind, "support_id": support_id,
                 "assertion": copy.deepcopy(assertion), "semantic_alignment": "not_checked_by_backend"}
        if kind == "source_fact":
            require(support_id in resolved["observations"], "private_support_kind_mismatch", "Source facts need a selected observation revision")
            revision = resolved["observations"][support_id]
            binding = resolved["revision_bindings"].get(support_id)
            require(isinstance(binding, dict) and revision.get("subject_id") == subject
                    and revision.get("revision_id") == support_id
                    and revision.get("confirmation_assurance") in TRUSTED_ASSURANCE,
                    "untrusted_private_support", "Source fact revision must have trusted confirmation in this subject")
            require(binding.get("revision_sha256") == digest(revision)
                    and binding.get("row_sha256") == digest(revision["row"]),
                    "private_support_hash_mismatch", "Selected revision binding differs from the immutable revision")
            field = assertion["field"]
            require(field in revision["row"] and canonical(assertion["expected_value"]) == canonical(revision["row"][field]),
                    "private_assertion_mismatch", "Source assertion must equal the complete typed field")
            origin = "review_corrected" if revision["row"].get("field_status", {}).get(field) == "review_corrected" else "selected_revision_field"
            state.update(resolution="exact_selected_revision_field", field_origin=origin,
                         literal_printed_proof="not_provided", confirmation_assurance=revision["confirmation_assurance"])
            observations[support_id] = {"revision_id": support_id, **copy.deepcopy(binding)}
        elif kind == "user_note":
            require(support_id in resolved["context_events"], "private_support_kind_mismatch", "User notes need an exact selected context event")
            event = resolved["context_events"][support_id]
            require(event.get("subject_id") == subject and event.get("context_event_id") == support_id
                    and event.get("kind") == "user_note" and event.get("fact_status") == "user_note",
                    "private_support_kind_mismatch", "Source statements and laboratory facts are not user notes")
            field = assertion["field"]
            require(field in event and canonical(assertion["expected_value"]) == canonical(event[field]),
                    "private_assertion_mismatch", "User note assertion must equal the complete selected event field")
            state.update(resolution="exact_selected_user_note_field", field_origin="user_note", clinical_truth="not_provided")
            events[support_id] = {"context_event_id": support_id, "context_event_sha256": digest(event),
                                 "kind": "user_note", "fact_status": "user_note"}
        else:
            from .private_calculations import validate_calculation_receipt
            receipt = lookup("private_calculation", support_id, subject)
            validate_calculation_receipt(receipt, lookup)
            require(receipt.get("subject_id") == subject and receipt.get("calculation_id") == support_id
                    and receipt.get("selection_id") == selection["selection_id"]
                    and receipt.get("selection_sha256") == selection["selection_sha256"],
                    "private_calculation_scope_mismatch", "Calculation must be bound to this exact selected case")
            require(receipt.get("calculation_sha256") == assertion["receipt_sha256"]
                    and receipt.get("metric") == assertion["metric"],
                    "private_calculation_assertion_mismatch", "Calculation assertion must match the backend receipt ID, hash and metric")
            state.update(resolution="exact_backend_private_calculation", numeric_result=copy.deepcopy(receipt["numeric_result"]),
                         numeric_assurance="backend_decimal_comparator")
            calculations[support_id] = {"calculation_id": support_id, "calculation_sha256": receipt["calculation_sha256"],
                                       "metric": receipt["metric"], "input_manifest_sha256": digest(receipt["input_manifest"])}
        states.append(state)
    manifest = {"observations": [observations[key] for key in sorted(observations)],
                "context_events": [events[key] for key in sorted(events)],
                "calculations": [calculations[key] for key in sorted(calculations)]}
    return states, manifest


def _review_body(draft: dict, resolved: dict, lookup: Lookup) -> dict:
    states, manifest = _resolve_claims(draft, resolved, lookup)
    claim_ids = [claim["claim_id"] for claim in draft["claims"]]
    return {"intent": draft.get("intent", "personal_interpretation"), "claim_readiness": states,
            "support_manifest": manifest, "release_state": "needs_revision",
            "checks": [{"check": "structural", "status": "ok", "coverage": claim_ids,
                        "assurance": "backend_exact_kind_and_field_resolution"},
                       {"check": "semantic_alignment", "status": "not_checked", "coverage": [], "assurance": "not_performed"},
                       {"check": "medical_safety", "status": "not_checked", "coverage": [], "assurance": "not_performed"},
                       {"check": "human_review", "status": "not_checked", "coverage": [], "assurance": "not_performed"}],
            "semantic_validation": "not_provided", "medical_validation": "not_provided", "human_validation": "not_provided",
            "scope": "private_selected_case_only",
            "limitations": ["Exact selected values and provenance do not establish semantic entailment or clinical truth",
                            "Claim text has not been semantically checked",
                            "Review corrections are preserved as corrections, never literal printed proof",
                            "No model, medical or authenticated human review is provided"]}


def _request(subject_id: str, selection_id: str, selection_sha256: str, draft: dict) -> dict:
    return {"subject_id": subject_id, "selection_id": selection_id,
            "selection_sha256": selection_sha256, "draft": draft}


def validate_private_answer_artifacts(draft: dict, report: dict, lookup: Lookup) -> None:
    """Pure recovery validation of the frozen graph, with no freshness calls."""
    _bounded_json(draft)
    _bounded_json(report)
    _object(draft, {"schema_version", "kind", "draft_id", "review_id", "subject_id", "selection_id",
                    "selection_sha256", "draft_sha256", "draft", "created_at"})
    require(draft["schema_version"] == DRAFT_SCHEMA and draft["kind"] == "private_answer_draft",
            "invalid_private_answer_artifact", "Wrong private draft schema or kind")
    identifier(draft["subject_id"], "subject_id")
    for field in ("draft_id", "review_id", "selection_id"):
        _case_id(draft[field], field)
    require(draft["draft_id"] != draft["review_id"], "invalid_private_answer_artifact", "Draft and report IDs must differ")
    _sha(draft["selection_sha256"], "selection hash")
    _sha(draft["draft_sha256"], "draft hash")
    iso_timestamp(draft["created_at"], "created_at")
    value = validate_private_answer_draft(draft["draft"])
    require(draft["draft_sha256"] == digest(value), "private_answer_hash_mismatch", "Private draft hash does not match")
    _object(report, {"schema_version", "kind", "review_id", "draft_id", "subject_id", "selection_id",
                     "selection_sha256", "draft_sha256", "reviewed_at", "preparation_freshness", "report_sha256",
                     "intent", "claim_readiness", "support_manifest", "release_state", "checks", "semantic_validation",
                     "medical_validation", "human_validation", "scope", "limitations"})
    require(report["schema_version"] == REVIEW_SCHEMA and report["kind"] == "private_answer_review",
            "invalid_private_answer_artifact", "Wrong private review schema or kind")
    for field in ("subject_id", "review_id", "draft_id", "selection_id", "selection_sha256", "draft_sha256"):
        require(report[field] == draft[field], "private_answer_link_mismatch", "Private answer draft/report links differ")
    iso_timestamp(report["reviewed_at"], "reviewed_at")
    require(report["reviewed_at"] == draft["created_at"], "private_answer_link_mismatch", "Draft and review preparation times differ")
    freshness = _object(report["preparation_freshness"], {"state", "reasons", "source_bytes_checked", "basis"})
    require(freshness["state"] == "current" and freshness["reasons"] == []
            and freshness["source_bytes_checked"] is False
            and freshness["basis"] == "one signed database snapshot; not clinical applicability or live source bytes",
            "invalid_private_answer_artifact", "Preparation requires an originally current case")
    _sha(report["report_sha256"], "report hash")
    require(report["report_sha256"] == digest({k: v for k, v in report.items() if k != "report_sha256"}),
            "private_answer_hash_mismatch", "Private review hash does not match")
    selection = lookup("case_selection", draft["selection_id"], draft["subject_id"])
    require(selection.get("selection_sha256") == draft["selection_sha256"],
            "private_answer_link_mismatch", "Private answer selection hash differs")
    require(selection.get("recorded_as_of") is None, "invalid_private_answer_artifact", "Private answers cannot originate from historical selections")
    from .private_cases import validate_case_snapshot
    resolved = validate_case_snapshot(selection, lookup)
    expected = _review_body(value, resolved, lookup)
    require(all(canonical(report[key]) == canonical(expected[key]) for key in expected),
            "invalid_private_answer_artifact", "Private review body differs from backend exact-kind resolution")


def validate_private_answer_idempotency(payload: dict, lookup: Lookup) -> None:
    """Check an original ACK without upgrading its historical freshness."""
    _bounded_json(payload)
    _object(payload, {"subject_id", "request_sha256", "result", "recorded_at"})
    identifier(payload["subject_id"], "subject_id")
    _sha(payload["request_sha256"], "idempotency request hash")
    iso_timestamp(payload["recorded_at"], "recorded_at")
    report = _object(payload["result"], {"schema_version", "kind", "review_id", "draft_id", "subject_id", "selection_id",
                     "selection_sha256", "draft_sha256", "reviewed_at", "preparation_freshness", "report_sha256",
                     "intent", "claim_readiness", "support_manifest", "release_state", "checks", "semantic_validation",
                     "medical_validation", "human_validation", "scope", "limitations"})
    require(report["subject_id"] == payload["subject_id"], "private_answer_link_mismatch", "Retry subject differs")
    require(payload["recorded_at"] == report["reviewed_at"], "private_answer_link_mismatch", "Retry preparation time differs")
    require(canonical(report) == canonical(lookup("private_answer_review", report["review_id"], payload["subject_id"])),
            "private_answer_link_mismatch", "Retry result differs from its immutable review")
    draft = lookup("private_answer_draft", report["draft_id"], payload["subject_id"])
    validate_private_answer_artifacts(draft, report, lookup)
    request = _request(draft["subject_id"], draft["selection_id"], draft["selection_sha256"], draft["draft"])
    require(payload["request_sha256"] == digest(request), "private_answer_hash_mismatch", "Retry request hash differs from its draft")


class PrivateAnswerService:
    def __init__(self, records: Any, calculations: Any = None, case_resolver: Callable | None = None):
        require(isinstance(records.store, SignedStore) and records.store.domain == "private-data",
                "wrong_domain", "Private answers require the private-data records store")
        if calculations is not None:
            require(calculations.records.store is records.store, "wrong_domain", "Calculation resolver must use this private records store")
        self.records, self.store, self.calculations = records, records.store, calculations
        self.case_resolver = case_resolver

    def _resolve(self, subject_id: str, selection_id: str, selection_sha256: str, *, require_current: bool) -> dict:
        if self.case_resolver is None:
            from .private_cases import resolve_case
            resolver = resolve_case
        else:
            resolver = self.case_resolver
        return resolver(self.records, subject_id, selection_id, selection_sha256, require_current=require_current)

    def prepare_private_answer(self, subject_id: str, selection_id: str, selection_sha256: str,
                               draft: dict, idempotency_key: str) -> dict:
        identifier(subject_id, "subject_id")
        _case_id(selection_id, "selection_id")
        _sha(selection_sha256, "selection hash")
        _bounded_text(idempotency_key, "idempotency key", 200)
        value = validate_private_answer_draft(draft)
        request = _request(subject_id, selection_id, selection_sha256, value)
        ack_id = "case_" + digest({"subject_id": subject_id, "operation": "prepare_private_answer", "key": idempotency_key})
        with self.store.transaction():
            self.records._subject(subject_id)
            try:
                prior = self.store.get("idempotency", ack_id, subject_id)
            except V2Error as exc:
                if exc.code != "NOT_FOUND":
                    raise
            else:
                require(prior.get("request_sha256") == digest(request), "idempotency_conflict", "Idempotency key was used for another request")
                validate_private_answer_idempotency(prior, self.store.get)
                return prior["result"]
            resolved = self._resolve(subject_id, selection_id, selection_sha256, require_current=True)
            body = _review_body(value, resolved, self.store.get)
            # Recheck inside the same write transaction immediately before
            # persisting; retain the case resolver's stated freshness bounds.
            final = self._resolve(subject_id, selection_id, selection_sha256, require_current=True)
            require(canonical(resolved["revision_bindings"]) == canonical(final["revision_bindings"]),
                    "stale_private_answer", "Case inputs changed during preparation")
            now, draft_id, review_id = utc_now(), new_id("case"), new_id("case")
            frozen_draft = {"schema_version": DRAFT_SCHEMA, "kind": "private_answer_draft", "draft_id": draft_id,
                            "review_id": review_id, "subject_id": subject_id, "selection_id": selection_id,
                            "selection_sha256": selection_sha256, "draft_sha256": digest(value), "draft": value, "created_at": now}
            report = {"schema_version": REVIEW_SCHEMA, "kind": "private_answer_review", "review_id": review_id,
                      "draft_id": draft_id, "subject_id": subject_id, "selection_id": selection_id,
                      "selection_sha256": selection_sha256, "draft_sha256": digest(value), "reviewed_at": now,
                      "preparation_freshness": copy.deepcopy(final["freshness"]), **body}
            report["report_sha256"] = digest(report)
            validate_private_answer_artifacts(frozen_draft, report, self.store.get)
            self.store.put("private_answer_draft", draft_id, frozen_draft, subject_id)
            self.store.put("private_answer_review", review_id, report, subject_id)
            self.store.put("idempotency", ack_id, {"subject_id": subject_id, "request_sha256": digest(request),
                                                  "result": report, "recorded_at": now}, subject_id)
            return copy.deepcopy(report)

    def get_private_answer_review(self, subject_id: str, review_id: str) -> dict:
        identifier(subject_id, "subject_id")
        _case_id(review_id, "review_id")
        with self.store.transaction(readonly=True):
            self.records._subject(subject_id)
            report = self.store.get("private_answer_review", review_id, subject_id)
            require(report.get("review_id") == review_id and report.get("subject_id") == subject_id,
                    "private_answer_scope_mismatch", "Stored private review differs from its requested identity or subject")
            draft = self.store.get("private_answer_draft", report["draft_id"], subject_id)
            validate_private_answer_artifacts(draft, report, self.store.get)
            current = self._resolve(subject_id, report["selection_id"], report["selection_sha256"], require_current=False)
            return {"report": report, "draft": draft, "freshness": copy.deepcopy(current["freshness"])}
