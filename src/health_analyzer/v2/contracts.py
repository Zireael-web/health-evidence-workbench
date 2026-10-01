"""One typed contract for v2 laboratory rows; no legacy coercion or float maths.

Source text is untrusted data. These validators establish shape and lineage, not
OCR correctness, clinical meaning, or human identity.
"""
from __future__ import annotations

import copy
import re
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .common import V2Error, require

SCHEMA_VERSION = "health-analyzer.records/2.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DECIMAL_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d+)?|\.\d+)$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
RESULT_KINDS = {"numeric_exact", "numeric_censored", "qualitative", "semiquantitative", "text_unparsed", "no_result"}
ROW_FIELDS = {"analyte_raw", "analyte_key", "mapping_status", "measurement_property", "subtype", "loinc", "result", "unit_raw", "unit_code", "clinical_time", "reference_intervals", "specimen", "method", "device", "lab_flag_raw", "field_anchors", "missing_reasons", "field_status", "panel_key", "extraction_method"}
MISSING_STATUSES = {"not_reported", "unknown", "ambiguous", "not_applicable"}


def identifier(value: Any, label: str = "identifier") -> str:
    require(isinstance(value, str) and bool(IDENTIFIER_RE.fullmatch(value)), "invalid_identifier", f"Invalid {label}")
    return value


def text(value: Any, label: str, *, nullable: bool = False, maximum: int = 4000) -> str | None:
    if nullable and value is None:
        return None
    require(isinstance(value, str) and 0 < len(value) <= maximum, "invalid_field", f"{label} must be a bounded non-empty string")
    return value


def decimal_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and len(value) <= 128 and bool(DECIMAL_RE.fullmatch(value)), "invalid_decimal", f"{label} must be a plain Decimal string, never a float")
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise V2Error("invalid_decimal", f"Invalid {label}") from exc
    require(number.is_finite(), "invalid_decimal", f"{label} must be finite")
    return value


def result(value: Any) -> dict:
    require(isinstance(value, dict), "invalid_result", "Result must be a tagged object")
    value = copy.deepcopy(value)
    kind = value.get("kind")
    require(kind in RESULT_KINDS, "invalid_result", "Unknown result kind")
    if kind == "no_result" and value.get("raw") == "":
        pass  # The original blank cell is not an invented token.
    else:
        text(value.get("raw"), "result.raw")
    allowed = {"kind", "raw"}
    if kind == "numeric_exact":
        decimal_string(value.get("decimal"), "result.decimal")
        allowed.add("decimal")
    elif kind == "numeric_censored":
        require(value.get("operator") in {"<", "<=", ">", ">=", "≤", "≥"}, "invalid_result", "A censored result needs its original inequality")
        decimal_string(value.get("decimal"), "result.decimal")
        allowed |= {"decimal", "operator"}
    elif kind in {"qualitative", "semiquantitative"}:
        if value.get("value") is not None:
            text(value["value"], "result.value")
        allowed.add("value")
    elif kind == "no_result":
        require(value.get("reason") in {"not_reported", "cancelled", "invalid_specimen", "not_performed", "unknown"}, "invalid_result", "No-result reason must be explicit")
        allowed.add("reason")
    if kind in {"numeric_exact", "numeric_censored"}:
        token = value["raw"].strip()
        if kind == "numeric_censored":
            operator = value["operator"]
            require(token.startswith(operator), "invalid_result", "Censor operator must match the original token")
            token = token[len(operator):].strip()
        token = token.replace(",", ".")
        require(bool(DECIMAL_RE.fullmatch(token)), "invalid_result", "Numeric raw must be one scalar, not combined columns")
        require(Decimal(token) == Decimal(value["decimal"]), "invalid_result", "Parsed Decimal must match the original scalar")
    require(set(value) <= allowed, "invalid_result", "Unexpected result fields; values cannot change the declared result kind")
    return value


def iso_timestamp(value: Any, label: str = "timestamp") -> str:
    text(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise V2Error("invalid_time", f"Invalid {label}") from exc
    require(parsed.tzinfo is not None, "invalid_time", f"{label} must include a timezone")
    return value


def clinical_time(value: Any) -> dict:
    require(isinstance(value, dict), "invalid_time", "clinical_time must be an object")
    value = copy.deepcopy(value)
    require(set(value) <= {"raw", "role", "precision", "value", "timezone", "start", "end", "start_inclusive", "end_inclusive"}, "invalid_time", "Unexpected clinical-time fields")
    require(value.get("role") in {"collected", "performed", "reported", "unknown"}, "invalid_time", "Unknown clinical-time role")
    precision = value.get("precision")
    require(precision in {"datetime", "date", "month", "year", "interval", "unknown"}, "invalid_time", "Unknown clinical-time precision")
    if value.get("raw") is not None:
        text(value["raw"], "clinical_time.raw", maximum=1000)
    if value.get("timezone") is not None:
        text(value["timezone"], "clinical_time.timezone", maximum=100)
    if precision != "unknown":
        text(value.get("raw"), "clinical_time.raw", maximum=1000)
    if precision == "unknown":
        require(value.get("value") is None and value.get("start") is None and value.get("end") is None, "invalid_time", "Unknown clinical time cannot contain a fabricated date")
    elif precision == "interval":
        require(value.get("value") is None, "invalid_time", "An interval is not a single date")
        bounds = []
        for key in ("start", "end"):
            token = text(value.get(key), f"clinical_time.{key}", maximum=64)
            try:
                bound = datetime.fromisoformat(token.replace("Z", "+00:00")) if "T" in token else date.fromisoformat(token)
            except ValueError as exc:
                raise V2Error("invalid_time", "Invalid interval bound") from exc
            bounds.append(bound)
        require(type(bounds[0]) is type(bounds[1]), "invalid_time", "Interval bounds must have the same precision")
        if isinstance(bounds[0], datetime):
            require((bounds[0].tzinfo is None) == (bounds[1].tzinfo is None), "invalid_time", "Interval timezone bounds must agree")
        require(bounds[0] <= bounds[1], "invalid_time", "Interval start must not follow its end")
        for key in ("start_inclusive", "end_inclusive"):
            require(isinstance(value.get(key), bool), "invalid_time", "Interval inclusivity must be explicit")
    else:
        token = text(value.get("value"), "clinical_time.value", maximum=64)
        try:
            if precision == "date":
                require(bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", token)), "invalid_time", "Date must preserve date precision")
                date.fromisoformat(token)
            elif precision == "datetime":
                require("T" in token, "invalid_time", "Datetime needs time")
                datetime.fromisoformat(token.replace("Z", "+00:00"))
            elif precision == "month":
                require(bool(re.fullmatch(r"\d{4}-\d{2}", token)), "invalid_time", "Month must not invent a day")
                date.fromisoformat(token + "-01")
            else:
                require(bool(re.fullmatch(r"\d{4}", token)), "invalid_time", "Year must not invent a month")
                date.fromisoformat(token + "-01-01")
        except ValueError as exc:
            raise V2Error("invalid_time", "Invalid clinical-time value") from exc
        require(value.get("start") is None and value.get("end") is None, "invalid_time", "Only intervals have bounds")
    return value


def reference_interval(value: Any) -> dict:
    require(isinstance(value, dict), "invalid_reference", "Reference must be an object")
    value = copy.deepcopy(value)
    require(set(value) <= {"kind", "raw", "low", "high", "low_inclusive", "high_inclusive", "unit_raw", "population", "context", "text"}, "invalid_reference", "Unexpected reference fields")
    require(value.get("kind") in {"laboratory_reference", "diagnostic_decision_limit", "therapeutic_target"}, "invalid_reference", "Reference kind must be explicit")
    text(value.get("raw"), "reference.raw")
    for key in ("low", "high"):
        if value.get(key) is not None:
            decimal_string(value[key], f"reference.{key}")
            require(isinstance(value.get(key + "_inclusive"), bool), "invalid_reference", "Reference boundary inclusivity must be explicit")
    if value.get("low") is not None and value.get("high") is not None:
        require(Decimal(value["low"]) <= Decimal(value["high"]), "invalid_reference", "Reference lower bound exceeds upper bound")
    for key in ("unit_raw", "population", "context", "text"):
        if value.get(key) is not None:
            text(value[key], f"reference.{key}")
    return value


def anchor(value: Any, field: str, version_id: str, source_sha256: str) -> dict:
    require(isinstance(value, dict), "invalid_anchor", f"{field} needs a structured source anchor")
    value = copy.deepcopy(value)
    require(set(value) <= {"version_id", "source_sha256", "field", "locator", "excerpt", "inherited"}, "invalid_anchor", "Unexpected source-anchor fields")
    require(value.get("version_id") == version_id and value.get("source_sha256") == source_sha256, "anchor_scope_mismatch", "Source anchor must refer to the registered source version")
    require(value.get("field") == field, "anchor_scope_mismatch", "Source anchor field does not match")
    text(value.get("excerpt"), "anchor.excerpt", maximum=8000)
    locator = value.get("locator")
    require(isinstance(locator, dict), "invalid_anchor", "Source locator must be structured")
    kind = locator.get("kind")
    require(kind in {"csv", "csv_cell", "text", "pdf", "image"}, "invalid_anchor", "Unsupported source locator")
    if kind in {"csv", "csv_cell"}:
        require(set(locator) <= {"kind", "row", "column", "column_name"}, "invalid_anchor", "Unexpected CSV locator fields")
        require(isinstance(locator.get("row"), int) and not isinstance(locator["row"], bool) and locator["row"] >= 1, "invalid_anchor", "CSV row is one-based")
        require((isinstance(locator.get("column"), int) and not isinstance(locator["column"], bool) and locator["column"] >= 1) or isinstance(locator.get("column_name"), str), "invalid_anchor", "CSV field needs a column")
    elif kind == "text":
        require(set(locator) <= {"kind", "start", "end", "line"}, "invalid_anchor", "Unexpected text locator fields")
        if "line" in locator:
            require(isinstance(locator["line"], int) and not isinstance(locator["line"], bool) and locator["line"] >= 1, "invalid_anchor", "Text line is one-based")
        else:
            require(isinstance(locator.get("start"), int) and not isinstance(locator["start"], bool) and isinstance(locator.get("end"), int) and not isinstance(locator["end"], bool) and 0 <= locator["start"] < locator["end"], "invalid_anchor", "Text range must be ordered")
    else:
        require(set(locator) <= {"kind", "page", "region", "line"}, "invalid_anchor", "Unexpected visual locator fields")
        require(isinstance(locator.get("page"), int) and not isinstance(locator["page"], bool) and 1 <= locator["page"] <= 500, "invalid_anchor", "Visual page must be one-based and bounded")
        require("region" in locator or "line" in locator, "invalid_anchor", "Visual anchor needs a region or line, not a fabricated page-only precision")
        if "region" in locator:
            region = locator["region"]
            require(isinstance(region, list) and len(region) == 4 and all(isinstance(n, (int, float)) and not isinstance(n, bool) and 0 <= n <= 1 for n in region), "invalid_anchor", "Visual region is normalized x0,y0,x1,y1")
            require(region[0] < region[2] and region[1] < region[3], "invalid_anchor", "Visual region must be ordered")
        if "line" in locator:
            require(isinstance(locator["line"], (str, int)), "invalid_anchor", "Visual line must be bounded")
    if "inherited" in value:
        require(isinstance(value["inherited"], bool), "invalid_anchor", "Inherited flag must be boolean")
    return value


def lab_observation(value: Any, version_id: str, source_sha256: str, *, correction: bool = False) -> dict:
    require(isinstance(value, dict), "invalid_row", "Observation must be an object")
    require(set(value) <= ROW_FIELDS, "invalid_row", "Unknown row fields or caller-authored review/assurance fields")
    row = copy.deepcopy(value)
    text(row.get("analyte_raw"), "analyte_raw", maximum=1000)
    row["result"] = result(row.get("result"))
    row["clinical_time"] = clinical_time(row.get("clinical_time", {"raw": None, "role": "unknown", "precision": "unknown", "value": None}))
    row.setdefault("unit_raw", None)
    row.setdefault("reference_intervals", [])
    row.setdefault("missing_reasons", {})
    row.setdefault("field_status", {})
    row.setdefault("mapping_status", "unmapped")
    require(row["mapping_status"] in {"unmapped", "proposed", "confirmed", "ambiguous"}, "invalid_mapping", "Invalid mapping status")
    if row.get("analyte_key") is not None:
        identifier(row["analyte_key"], "analyte_key")
    else:
        require(row["mapping_status"] != "confirmed", "invalid_mapping", "Confirmed mapping requires an analyte key")
    for key in ("unit_raw", "unit_code", "measurement_property", "subtype", "loinc", "specimen", "method", "device", "lab_flag_raw", "panel_key", "extraction_method"):
        row.setdefault(key, None)
        text(row[key], key, nullable=True)
    require(isinstance(row["reference_intervals"], list) and len(row["reference_intervals"]) <= 20, "invalid_reference", "References must be a bounded list")
    row["reference_intervals"] = [reference_interval(item) for item in row["reference_intervals"]]
    reasons = row["missing_reasons"]
    require(isinstance(reasons, dict) and set(reasons) <= ROW_FIELDS, "invalid_row", "Missing reasons must be field-bound")
    for key, reason in reasons.items():
        require(reason in MISSING_STATUSES, "invalid_row", f"Invalid missing reason for {key}")
    statuses = row["field_status"]
    require(isinstance(statuses, dict) and set(statuses) <= ROW_FIELDS, "invalid_row", "Field statuses must be field-bound")
    permitted_statuses = {"extracted", "proposed", *MISSING_STATUSES} | ({"review_corrected"} if correction else set())
    require(all(status in permitted_statuses for status in statuses.values()), "invalid_row", "Caller cannot assign confirmed field status")
    anchors = row.get("field_anchors")
    require(isinstance(anchors, dict) and set(anchors) <= ROW_FIELDS, "invalid_anchor", "Field anchors must be a field mapping")
    for field, item in anchors.items():
        if item is not None:
            if isinstance(item, list):
                require(0 < len(item) <= 20, "invalid_anchor", "Anchor list must be bounded")
                anchors[field] = [anchor(a, field, version_id, source_sha256) for a in item]
            else:
                anchors[field] = anchor(item, field, version_id, source_sha256)
    present_fields = ["analyte_raw", "result"]
    for field in ("unit_raw", "specimen", "method", "device", "lab_flag_raw"):
        if row.get(field) is not None:
            present_fields.append(field)
    if row["clinical_time"].get("raw") is not None:
        present_fields.append("clinical_time")
    if row["reference_intervals"]:
        present_fields.append("reference_intervals")
    for field in present_fields:
        require(anchors.get(field) is not None or (correction and statuses.get(field) == "review_corrected"), "missing_provenance", f"Present field {field} needs its source anchor or explicit correction lineage")
    for field in ("unit_raw", "specimen", "method"):
        if row.get(field) is None:
            require(field in reasons, "missing_reason", f"Unknown {field} needs an explicit missing reason")
    if row["clinical_time"]["precision"] == "unknown":
        require("clinical_time" in reasons, "missing_reason", "Unknown clinical time needs an explicit missing reason")
    if not row["reference_intervals"]:
        require("reference_intervals" in reasons, "missing_reason", "Absent reference needs an explicit missing reason")
    return row


def extraction_coverage(value: Any, row_count: int) -> dict:
    require(isinstance(value, dict), "invalid_coverage", "Coverage must be an object")
    require(set(value) <= {"status", "expected_count", "expected_count_basis", "processed_pages", "unprocessed_pages", "errors", "method", "model", "provider", "extractor_version"}, "invalid_coverage", "Unexpected coverage fields")
    value = copy.deepcopy(value)
    require(value.get("status") in {"complete", "partial", "visual_required", "error"}, "invalid_coverage", "Coverage status required")
    expected = value.get("expected_count")
    require(expected is None or (isinstance(expected, int) and not isinstance(expected, bool) and expected >= row_count), "invalid_coverage", "Expected row count cannot understate known rows")
    basis = value.get("expected_count_basis", "unknown")
    require(basis in {"unknown", "source_count", "extractor_count"}, "invalid_coverage", "Expected-count basis must be explicit")
    require(not (basis == "unknown" and expected is not None), "invalid_coverage", "Unknown expected count must remain null")
    value["expected_count_basis"] = basis
    value["expected_count"] = expected
    for key in ("processed_pages", "unprocessed_pages"):
        pages = value.setdefault(key, [])
        require(isinstance(pages, list) and len(pages) <= 500 and all(isinstance(page, int) and not isinstance(page, bool) and 1 <= page <= 500 for page in pages), "invalid_coverage", "Coverage pages must be bounded one-based IDs")
        require(len(pages) == len(set(pages)), "invalid_coverage", "Duplicate coverage page")
    require(not (set(value["processed_pages"]) & set(value["unprocessed_pages"])), "invalid_coverage", "A page cannot be both processed and unprocessed")
    if value["status"] == "complete":
        require(not value["unprocessed_pages"], "invalid_coverage", "Complete extraction cannot have unprocessed pages")
    errors = value.setdefault("errors", [])
    require(isinstance(errors, list) and len(errors) <= 100 and all(isinstance(error, str) and len(error) <= 1000 for error in errors), "invalid_coverage", "Errors must be bounded text")
    value["known_extracted_rows"] = row_count
    return value
