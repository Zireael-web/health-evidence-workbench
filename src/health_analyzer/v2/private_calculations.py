"""Private immutable receipts for two-row production comparisons.

The comparator is the RecordsService implementation. This module selects a
supported output; it never evaluates a caller formula or implements arithmetic.
Frozen validation proves the saved calculation against its original graph and
reports live freshness separately. It is not a live source-byte check.
"""
from __future__ import annotations

import copy
from typing import Callable

from .common import V2Error, digest, new_id, require, utc_now
from .contracts import SHA256_RE, identifier, iso_timestamp, extraction_coverage
from .records import RecordsService


CALCULATION_SCHEMA = "health-analyzer.private-calculation/2.0"
METRICS = {"delta", "percent_change"}
REQUEST_FIELDS = {"subject_id", "selection_id", "selection_sha256", "revision_ids",
                  "metric", "idempotency_key"}
RECEIPT_FIELDS = {"schema_version", "subject_id", "calculation_id", "calculation_sha256",
                  "selection_id", "selection_sha256", "case_binding", "input_manifest",
                  "operation", "metric", "comparison_snapshot", "numeric_result",
                  "arithmetic_policy", "recorded_at", "boundary", "validation_basis"}
BOUNDARY = "private; do not forward this receipt to public-research"
VALIDATION_BASIS = "verified_frozen_case_and_production_comparator; live_freshness_separate; not_source_byte_proof"
Lookup = Callable[[str, str, str], dict]


def _sha256(value: object, label: str) -> str:
    require(isinstance(value, str) and bool(SHA256_RE.fullmatch(value)),
            "invalid_hash", f"{label} must be a lowercase SHA-256")
    return value


def validate_calculation_request(request: dict) -> dict:
    """Strict transport-independent request validation, with no caller values."""
    require(isinstance(request, dict) and set(request) == REQUEST_FIELDS,
            "invalid_calculation_request", "Calculation accepts only the six declared request fields")
    identifier(request["subject_id"], "subject_id")
    identifier(request["selection_id"], "selection_id")
    _sha256(request["selection_sha256"], "selection_sha256")
    ids = request["revision_ids"]
    require(isinstance(ids, list) and len(ids) == 2 and all(isinstance(rid, str) for rid in ids),
            "calculation_pair_required", "Calculation requires exactly two explicit revision IDs")
    for rid in ids:
        identifier(rid, "revision_id")
    require(len(set(ids)) == 2, "calculation_pair_required", "Calculation requires two distinct revision IDs")
    require(isinstance(request["metric"], str) and request["metric"] in METRICS,
            "unsupported_calculation_metric", "Only delta and percent_change are supported")
    require(isinstance(request["idempotency_key"], str) and len(request["idempotency_key"]) <= 200,
            "invalid_idempotency_key", "Idempotency key must be a bounded string")
    return copy.deepcopy(request)


def _manifest(case: dict, revision_ids: list[str]) -> list[dict]:
    return [{"revision_id": rid,
             "observation_id": case["observations"][rid]["observation_id"],
             "revision": copy.deepcopy(case["observations"][rid]),
             **copy.deepcopy(case["revision_bindings"][rid])} for rid in revision_ids]


class _FrozenStore:
    """No writes, current projection, source reads or arithmetic in this view."""
    def __init__(self, case: dict):
        self.case = case
        self.domain = "private-data"

    def get(self, kind: str, object_id: str, subject_id: str | None = None) -> dict:
        require(subject_id == self.case["selection"]["subject_id"],
                "calculation_scope_mismatch", "Frozen comparator is subject scoped")
        if kind == "observation_revision" and object_id in self.case["observations"]:
            return copy.deepcopy(self.case["observations"][object_id])
        raise V2Error("NOT_FOUND", "Object is outside the frozen comparison view")


class _FrozenComparisonRecords(RecordsService):
    """Use the production comparator with an authenticated historical case graph.

    Only its data access is replaced. Currentness means selected-at-case-capture
    inside this explicitly frozen view, never currentness in the live store.
    """
    def __init__(self, case: dict):
        super().__init__(_FrozenStore(case))
        self.case = case

    def _subject(self, subject_id: str) -> dict:
        require(subject_id == self.case["selection"]["subject_id"],
                "calculation_scope_mismatch", "Frozen comparator subject differs")
        return {"subject_id": subject_id}

    def _history_projection(self, subject_id: str, as_of: str | None = None) -> dict:
        self._subject(subject_id)
        return {"current": list(copy.deepcopy(self.case["observations"]).values()),
                "historical": [], "contextual": [],
                "conflicts": copy.deepcopy(self.case["selection"]["conflicts"])}

    def _availability(self, subject_id: str, version_id: str, as_of: str | None = None) -> dict:
        self._subject(subject_id)
        candidates = [item["source_availability"] for item in self.case["selection"]["observations"]
                      if item["source_version_id"] == version_id]
        require(bool(candidates), "calculation_scope_mismatch", "Frozen source version is not selected")
        require(all(item == candidates[0] for item in candidates),
                "calculation_scope_mismatch", "Frozen source availability is inconsistent")
        return copy.deepcopy(candidates[0])

    def query_history(self, subject_id: str, *args, **kwargs) -> dict:
        self._subject(subject_id)
        return {"coverage": copy.deepcopy(self.case["selection"]["coverage"])}


def _core_snapshot(comparison: dict) -> dict:
    """Documented core projection; volatile metadata stays in the signed receipt.

    Source availability and review coverage can change without changing selected
    confirmed inputs. They are captured informational metadata, not evidence of
    live bytes or operands of this calculation. All other fields are compared.
    """
    snapshot = copy.deepcopy(comparison)
    snapshot.pop("coverage", None)
    for category in ("included", "contextual_only", "excluded_with_reasons"):
        require(isinstance(snapshot.get(category), list), "invalid_calculation_receipt",
                "Comparison row categories must be lists")
        for item in snapshot[category]:
            require(isinstance(item, dict), "invalid_calculation_receipt", "Comparison items must be objects")
            item.pop("source_availability", None)
    return snapshot


def _validate_captured_metadata(comparison: dict, case: dict) -> None:
    """Bound informational capture fields without upgrading them into proof."""
    availability_fields = {"version_id", "status", "checked_at", "occurrence_count", "limitation"}
    for item in comparison["included"]:
        metadata = item.get("source_availability")
        require(isinstance(metadata, dict) and set(metadata) == availability_fields
                and metadata["version_id"] == case["observations"][item["revision_id"]]["source_version_id"]
                and isinstance(metadata["status"], str) and metadata["status"] in {"available", "unavailable", "unknown"}
                and type(metadata["occurrence_count"]) is int and metadata["occurrence_count"] >= 0
                and (metadata["limitation"] is None or metadata["limitation"] == "not_a_live_filesystem_check"),
                "invalid_calculation_receipt", "Captured availability metadata has an unsupported shape")
        if metadata["checked_at"] is not None:
            iso_timestamp(metadata["checked_at"], "captured availability.checked_at")
        require((metadata["status"] == "unknown") == (metadata["checked_at"] is None),
                "invalid_calculation_receipt", "Captured availability check-time differs from its status")
    base_fields = {"status", "expected_count", "expected_count_basis", "processed_pages",
                   "unprocessed_pages", "errors", "method", "model", "provider", "extractor_version"}
    capture_fields = {"unreviewed", "reviewed", "rejected", "deferred", "run_id", "version_id", "absence_means", "known_extracted_rows"}
    coverage = comparison.get("coverage")
    require(isinstance(coverage, list) and len(coverage) <= 10000,
            "invalid_calculation_receipt", "Captured coverage must be a bounded list")
    for item in coverage:
        require(isinstance(item, dict) and set(item) <= base_fields | capture_fields
                and capture_fields <= set(item), "invalid_calculation_receipt", "Captured coverage has unknown or missing fields")
        counts = [item[field] for field in ("unreviewed", "reviewed", "rejected", "deferred")]
        require(all(type(value) is int and value >= 0 for value in counts),
                "invalid_calculation_receipt", "Captured review coverage counts must be nonnegative integers")
        normalized = extraction_coverage({key: copy.deepcopy(value) for key, value in item.items() if key in base_fields},
                                         sum(counts))
        require(normalized == {key: value for key, value in item.items() if key in base_fields | {"known_extracted_rows"}}
                and item["absence_means"] == "no_saved_row_does_not_prove_test_not_performed",
                "invalid_calculation_receipt", "Captured extraction coverage differs from its typed shape")
        identifier(item["run_id"], "captured coverage.run_id")
        identifier(item["version_id"], "captured coverage.version_id")


def _require_computable(comparison: dict, revision_ids: list[str], metric: str) -> None:
    require(comparison.get("comparison_status") == "comparable"
            and comparison.get("mode") == "strict"
            and isinstance(comparison.get("included"), list)
            and len(comparison["included"]) == 2
            and all(isinstance(item, dict) and isinstance(item.get("revision_id"), str) for item in comparison["included"])
            and {item.get("revision_id") for item in comparison["included"]} == set(revision_ids)
            and comparison.get("contextual_only") == []
            and comparison.get("excluded_with_reasons") == [],
            "calculation_not_comparable", "The exact requested pair must be strictly comparable without contextual or excluded rows")
    require(all(isinstance(item.get("row"), dict) and isinstance(item["row"].get("result"), dict)
                and item["row"]["result"].get("kind") == "numeric_exact" for item in comparison["included"]),
            "calculation_exact_numeric_required", "Calculation requires two exact numeric results")
    require(isinstance(comparison.get("clinical_order"), dict)
            and comparison["clinical_order"].get("status") == "established",
            "calculation_order_ambiguous", "Printed clinical times must establish the pair order")
    arithmetic = comparison.get("arithmetic", {})
    require(isinstance(arithmetic, dict) and arithmetic.get("status") == "computed", "calculation_not_computable",
            "The production comparator must compute arithmetic")
    require({arithmetic.get("baseline_revision_id"), arithmetic.get("last_revision_id")} == set(revision_ids),
            "calculation_endpoint_mismatch", "Computed endpoints must be the exact requested pair")
    if metric == "percent_change":
        require(isinstance(arithmetic.get("percent_change"), dict)
                and arithmetic["percent_change"].get("status") == "computed",
                "calculation_zero_baseline", "Percent change is unavailable with a zero baseline")


def _numeric_result(comparison: dict, metric: str) -> dict:
    arithmetic = comparison["arithmetic"]
    if metric == "delta":
        return {"metric": metric, "decimal": arithmetic["delta"], "unit_raw": arithmetic["unit_raw"]}
    return {"metric": metric, **copy.deepcopy(arithmetic["percent_change"])}


def _arithmetic_policy(comparison: dict) -> dict:
    arithmetic = comparison["arithmetic"]
    return {key: copy.deepcopy(arithmetic[key]) for key in
            ("rule", "formula", "rounding_policy", "unit_raw", "baseline_revision_id",
             "last_revision_id", "time_interval")} | {"conversion_policy": copy.deepcopy(comparison["conversion_policy"])}


def _case_binding(selection: dict) -> dict:
    return {"selection_id": selection["selection_id"],
            "selection_sha256": selection["selection_sha256"],
            "recorded_as_of": selection["recorded_as_of"],
            "frozen_revision_ids": copy.deepcopy(selection["revision_ids"])}


def _request_body(request: dict) -> dict:
    # The opaque key locates an acknowledgement; its clinical request hash is
    # reconstructable from the receipt without saving the caller's key.
    return {key: copy.deepcopy(value) for key, value in request.items() if key != "idempotency_key"}


def validate_calculation_idempotency(acknowledgement: dict, lookup: Lookup) -> dict:
    """Validate a reference-only retry acknowledgement against its receipt."""
    require(isinstance(acknowledgement, dict)
            and set(acknowledgement) == {"subject_id", "request_sha256", "result", "recorded_at"},
            "invalid_calculation_idempotency", "Calculation acknowledgement shape differs")
    subject = identifier(acknowledgement["subject_id"], "subject_id")
    _sha256(acknowledgement["request_sha256"], "request_sha256")
    iso_timestamp(acknowledgement["recorded_at"], "acknowledgement.recorded_at")
    result = acknowledgement["result"]
    require(isinstance(result, dict) and set(result) == {"calculation_id", "calculation_sha256"},
            "invalid_calculation_idempotency", "Calculation acknowledgement must contain only its exact immutable receipt link")
    identifier(result["calculation_id"], "calculation_id")
    _sha256(result["calculation_sha256"], "calculation_sha256")
    receipt = lookup("private_calculation", result["calculation_id"], subject)
    require(receipt.get("subject_id") == subject and receipt.get("calculation_id") == result["calculation_id"]
            and receipt.get("calculation_sha256") == result["calculation_sha256"],
            "invalid_calculation_idempotency", "Calculation acknowledgement differs from its exact immutable receipt")
    validate_calculation_receipt(receipt, lookup)
    expected = {"subject_id": subject, "selection_id": receipt["selection_id"],
                "selection_sha256": receipt["selection_sha256"],
                "revision_ids": receipt["operation"]["revision_ids"], "metric": receipt["metric"]}
    require(acknowledgement["request_sha256"] == digest(expected),
            "invalid_calculation_idempotency", "Calculation acknowledgement request hash differs from its receipt")
    return copy.deepcopy(acknowledgement)


def validate_calculation_receipt(receipt: dict, lookup: Lookup) -> dict:
    """Validate an immutable receipt with its original case/revision graph.

    The lookup is ``lookup(kind, object_id, subject_id)``. Recovery can supply its
    authenticated inventory. No live projection is consulted and no replacement
    revision is substituted; an old valid receipt survives later corrections.
    """
    from .private_cases import validate_case_snapshot

    require(isinstance(receipt, dict) and set(receipt) == RECEIPT_FIELDS,
            "invalid_calculation_receipt", "Unexpected or missing calculation receipt fields")
    require(receipt["schema_version"] == CALCULATION_SCHEMA and receipt["boundary"] == BOUNDARY
            and receipt["validation_basis"] == VALIDATION_BASIS,
            "invalid_calculation_receipt", "Calculation receipt schema or boundary differs")
    identifier(receipt["calculation_id"], "calculation_id")
    require(receipt["calculation_id"].startswith("case_") and len(receipt["calculation_id"]) == 37
            and all(char in "0123456789abcdef" for char in receipt["calculation_id"][5:]),
            "invalid_calculation_receipt", "Calculation ID must use the private case ID namespace")
    _sha256(receipt["calculation_sha256"], "calculation_sha256")
    require(digest({key: value for key, value in receipt.items() if key != "calculation_sha256"})
            == receipt["calculation_sha256"], "calculation_hash_mismatch", "Immutable calculation hash differs")
    iso_timestamp(receipt["recorded_at"], "calculation.recorded_at")
    operation = receipt["operation"]
    require(isinstance(operation, dict) and set(operation) == {"name", "mode", "revision_ids", "metric"}
            and operation["name"] == "compare_observations" and operation["mode"] == "strict"
            and operation["metric"] == receipt["metric"],
            "invalid_calculation_receipt", "Calculation operation must be the declared production comparison")
    request = validate_calculation_request({"subject_id": receipt["subject_id"],
                                          "selection_id": receipt["selection_id"],
                                          "selection_sha256": receipt["selection_sha256"],
                                          "revision_ids": operation["revision_ids"],
                                          "metric": receipt["metric"], "idempotency_key": ""})
    selection = lookup("case_selection", request["selection_id"], request["subject_id"])
    require(isinstance(selection, dict) and selection.get("subject_id") == request["subject_id"]
            and selection.get("selection_id") == request["selection_id"]
            and selection.get("selection_sha256") == request["selection_sha256"],
            "calculation_case_mismatch", "Calculation selection hash differs")
    case = validate_case_snapshot(selection, lookup)
    require(selection.get("recorded_as_of") is None, "calculation_historical_snapshot",
            "A calculation receipt requires a current-state case at creation")
    require(set(request["revision_ids"]) <= set(case["observations"]),
            "calculation_case_mismatch", "Calculation inputs must belong to its exact frozen case")
    require(receipt["case_binding"] == _case_binding(selection)
            and receipt["input_manifest"] == _manifest(case, request["revision_ids"]),
            "calculation_input_mismatch", "Full calculation input manifest differs from the immutable case graph")
    comparison = receipt["comparison_snapshot"]
    require(isinstance(comparison, dict), "invalid_calculation_receipt", "Comparison snapshot must be an object")
    _require_computable(comparison, request["revision_ids"], request["metric"])
    _validate_captured_metadata(comparison, case)
    frozen_comparison = _FrozenComparisonRecords(case).compare_observations(
        request["subject_id"], request["revision_ids"], "strict")
    require(set(comparison) == set(frozen_comparison)
            and isinstance(comparison.get("coverage"), list)
            and all(isinstance(item.get("source_availability"), dict) for item in comparison["included"])
            and _core_snapshot(comparison) == _core_snapshot(frozen_comparison),
            "calculation_comparison_mismatch", "Saved core comparison differs from the production comparator on the verified frozen pair")
    require(receipt["numeric_result"] == _numeric_result(frozen_comparison, request["metric"])
            and receipt["arithmetic_policy"] == _arithmetic_policy(frozen_comparison),
            "calculation_result_mismatch", "Saved numeric result or policy differs from the production comparison")
    return copy.deepcopy(receipt)


class PrivateCalculationService:
    def __init__(self, records: RecordsService, case_resolver: Callable | None = None):
        require(records.store.domain == "private-data", "wrong_domain", "Private calculations require a private-data store")
        self.records = records
        self.store = records.store
        self.case_resolver = case_resolver

    def _idempotency(self, request: dict) -> tuple[str | None, dict | None]:
        key = request["idempotency_key"]
        if not key:
            return None, None
        subject = request["subject_id"]
        object_id = "case_" + digest({"subject_id": subject, "operation": "create_private_calculation", "key": key})
        try:
            saved = self.store.get("idempotency", object_id, subject)
        except V2Error as exc:
            if exc.code == "NOT_FOUND":
                return object_id, None
            raise
        require(saved.get("request_sha256") == digest(_request_body(request)),
                "idempotency_conflict", "Idempotency key was used for another request")
        validate_calculation_idempotency(saved, self.store.get)
        return object_id, saved["result"]

    def _resolve(self, subject_id: str, selection_id: str, selection_sha256: str,
                 *, require_current: bool) -> dict:
        if self.case_resolver is None:
            from .private_cases import resolve_case
            return resolve_case(self.records, subject_id, selection_id, selection_sha256,
                                require_current=require_current)
        return self.case_resolver(self.records, subject_id, selection_id, selection_sha256,
                                  require_current=require_current)

    def create_private_calculation(self, subject_id: str, selection_id: str, selection_sha256: str,
                                   revision_ids: list[str], metric: str,
                                   idempotency_key: str = "") -> dict:
        request = validate_calculation_request({"subject_id": subject_id, "selection_id": selection_id,
                                               "selection_sha256": selection_sha256,
                                               "revision_ids": revision_ids, "metric": metric,
                                               "idempotency_key": idempotency_key})
        with self.store.transaction():
            self.records._subject(subject_id)
            # Immutable retry identity is saved separately from live freshness.
            idem_id, prior = self._idempotency(request)
            if prior is not None:
                require(isinstance(prior, dict) and set(prior) == {"calculation_id", "calculation_sha256"},
                        "invalid_calculation_idempotency", "Saved calculation retry reference differs")
                result = self.get_private_calculation(subject_id, prior["calculation_id"])
                require(result["receipt"]["calculation_sha256"] == prior["calculation_sha256"],
                        "invalid_calculation_idempotency", "Saved retry hash differs from its calculation")
                return result
            case = self._resolve(subject_id, selection_id, selection_sha256, require_current=True)
            require(case["selection"].get("recorded_as_of") is None,
                    "calculation_historical_snapshot", "New calculations require a current-state case")
            require(set(revision_ids) <= set(case["observations"]),
                    "calculation_case_mismatch", "The explicit pair must be selected by this case")
            comparison = self.records.compare_observations(subject_id, revision_ids, "strict")
            _require_computable(comparison, revision_ids, metric)
            frozen_comparison = _FrozenComparisonRecords(case).compare_observations(subject_id, revision_ids, "strict")
            require(_core_snapshot(comparison) == _core_snapshot(frozen_comparison),
                    "calculation_comparison_mismatch", "Live selected operands or policy differ from the verified frozen pair")
            receipt = {"schema_version": CALCULATION_SCHEMA, "subject_id": subject_id,
                       "calculation_id": new_id("case"), "selection_id": selection_id,
                       "selection_sha256": selection_sha256,
                       "case_binding": _case_binding(case["selection"]),
                       "input_manifest": _manifest(case, revision_ids),
                       "operation": {"name": "compare_observations", "mode": "strict",
                                     "revision_ids": copy.deepcopy(revision_ids), "metric": metric},
                       "metric": metric, "comparison_snapshot": copy.deepcopy(comparison),
                       "numeric_result": _numeric_result(comparison, metric),
                       "arithmetic_policy": _arithmetic_policy(comparison), "recorded_at": utc_now(),
                       "boundary": BOUNDARY, "validation_basis": VALIDATION_BASIS}
            receipt["calculation_sha256"] = digest(receipt)
            validate_calculation_receipt(receipt, self.store.get)
            self.store.put("private_calculation", receipt["calculation_id"], receipt, subject_id)
            self.records._put_idempotency(subject_id, idem_id, _request_body(request),
                                          {"calculation_id": receipt["calculation_id"],
                                           "calculation_sha256": receipt["calculation_sha256"]})
            return {"receipt": receipt, "freshness": copy.deepcopy(case["freshness"])}

    def get_private_calculation(self, subject_id: str, calculation_id: str) -> dict:
        identifier(subject_id, "subject_id")
        identifier(calculation_id, "calculation_id")
        with self.store.transaction(readonly=True):
            self.records._subject(subject_id)
            receipt = self.store.get("private_calculation", calculation_id, subject_id)
            require(receipt.get("subject_id") == subject_id and receipt.get("calculation_id") == calculation_id,
                    "calculation_scope_mismatch", "Stored calculation differs from its identity or scope")
            validate_calculation_receipt(receipt, self.store.get)
            case = self._resolve(subject_id, receipt["selection_id"], receipt["selection_sha256"], require_current=False)
            return {"receipt": receipt, "freshness": copy.deepcopy(case["freshness"])}
