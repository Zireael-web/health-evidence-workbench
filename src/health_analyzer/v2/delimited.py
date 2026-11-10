"""Conservative delimiter tables with complete source-row quarantine."""
from __future__ import annotations

import csv
import io
import re

from .common import V2Error, canonical, digest, require


def extract_delimited(text: str, version: dict, *, delimiter: str | None = None,
                      locator_kind: str = "csv", page: int | None = None) -> tuple[list, list]:
    from .ingest import (MAX_EXTRACTED_ROWS, _field_columns, parse_clinical_time,
                         parse_reference, parse_result)
    from .contracts import lab_observation
    first = text.splitlines()[0] if text.splitlines() else ""
    if delimiter is None:
        options = [d for d in ("\t", ";", ",") if d in first]
        require(bool(options), "TABLE_MAPPING_REQUIRED", "No explicit table separator found")
        delimiter = max(options, key=first.count)
    require(delimiter in {"\t", ";", ","}, "TABLE_MAPPING_REQUIRED", "Unsupported delimiter")
    physical = text.splitlines(keepends=True)
    stream = csv.reader(io.StringIO(text), delimiter=delimiter, strict=True)
    rows, issues = [], []

    def source_anchor(field, raw, number, line_start, line_end, column, label):
        locator = {"kind": "csv", "row": number, "column": column + 1, "column_name": label}
        if locator_kind == "text":
            locator = {"kind": "text", "line": line_start}
        elif locator_kind == "pdf":
            locator = {"kind": "pdf", "page": page, "line": line_start if line_start == line_end else f"{line_start}-{line_end}"}
        return {"version_id": version["version_id"], "source_sha256": version["source_sha256"],
                "field": field, "locator": locator, "excerpt": raw}

    def preserve(raw, cells, reasons, row=None, alternatives=None, number=1, start=1, end=1):
        issue = {"page": page, "source": "native_table", "raw_text": raw, "raw_cells": cells,
                 "reason_codes": reasons, "alternatives": alternatives or [], "proposed_row": row}
        if len(raw) <= 8000 and len(cells) <= 32 and len(alternatives or []) <= 16 and all(
                (c["column"] is None or c["column"] <= 32) and len(c["column_label"] or "") <= 200 and len(c["text"]) <= 8000 for c in cells
                ) and len(canonical(issue)) <= 64 * 1024:
            issues.append(issue)
            return
        # Complete source stream, not a reconstructed/truncated subset of cells.
        group = "table_span_" + digest({"version": version["version_id"], "row": number, "raw": raw})
        parts = [(i, raw[i:i + 1600]) for i in range(0, len(raw), 1600)] or [(0, "")]
        require(len(parts) <= 1000, "ISSUE_LIMIT", "Source row exceeds bounded issue capacity")
        for index, (offset, part) in enumerate(parts, 1):
            a = source_anchor("unresolved_source_span", part, number, start, end, 0, "unresolved_source_span") if part else None
            issues.append({"page": page, "source": "native_table", "raw_text": part,
                "raw_cells": [{"column": None, "column_label": None, "role": "unresolved_source_span", "text": part, "anchors": [a] if a else []}],
                "reason_codes": [*reasons, "SOURCE_SPAN_FRAGMENT"], "proposed_row": None,
                "alternatives": [{"kind": "ordered_source_fragment", "group_id": group, "index": index,
                    "count": len(parts), "start_character": offset, "end_character": offset + len(part),
                    "previous_index": index - 1 if index > 1 else None,
                    "next_index": index + 1 if index < len(parts) else None}]})
        require(len(issues) <= 1000, "ISSUE_LIMIT", "Source issues exceed bounded capacity")

    try:
        header = next(stream)
        columns = _field_columns(header)
        inverse = {column: field for field, column in columns.items()}
        previous_line = stream.line_num
        candidates = 0
        for number, values in enumerate(stream, 2):
            start, end = previous_line + 1, stream.line_num
            previous_line = end
            if not values or all(not v.strip() for v in values):
                continue
            candidates += 1
            require(candidates <= MAX_EXTRACTED_ROWS, "ROW_LIMIT", "Table exceeds 1000 whole source rows")
            raw = "".join(physical[start - 1:end])
            cells = []
            for index, value in enumerate(values):
                label = header[index] if index < len(header) else "unmapped extra cell"
                role = inverse.get(index, "prior_result" if re.search(r"previous|prior|предыдущ|\d{2}\.\d{2}|\d{4}-\d{2}", label, re.I) else "unknown_column")
                cells.append({"column": index, "column_label": label or None, "role": role, "text": value,
                    "anchors": [source_anchor(role, value, number, start, end, index, label)] if value else []})
            if len(values) != len(header):
                preserve(raw, cells, ["TABLE_SHAPE_MISMATCH"], number=number, start=start, end=end)
                continue
            get = lambda field: values[columns[field]].strip() or None if field in columns else None
            reasons = []
            if not get("analyte_raw"):
                reasons.append("ANALYTE_MISSING")
            raw_result = values[columns["result"]]
            result = parse_result(raw_result)
            if not raw_result.strip():
                reasons.append("MISSING_RESULT")
            elif result["kind"] == "text_unparsed":
                reasons.append("RESULT_UNPARSED")
            extras = [c for c in cells if c["column"] not in inverse and c["text"].strip()]
            alternatives = [{"kind": "separate_prior_result", "column_label": c["column_label"], "raw": c["text"], "field_anchors": c["anchors"]}
                            for c in extras if c["role"] == "prior_result"]
            if extras:
                reasons.append("PRIOR_RESULT_UNRESOLVED" if all(c["role"] == "prior_result" for c in extras) else "UNMAPPED_SOURCE_COLUMN")
            if set(reasons) & {"ANALYTE_MISSING", "MISSING_RESULT"}:
                preserve(raw, cells, reasons, alternatives=alternatives, number=number, start=start, end=end)
                continue
            unit = get("unit_raw")
            clinical = parse_clinical_time(get("clinical_time"), header[columns["clinical_time"]] if "clinical_time" in columns else None)
            row = {"analyte_raw": get("analyte_raw"), "result": result, "unit_raw": unit,
                "clinical_time": clinical, "reference_intervals": parse_reference(get("reference_intervals"), unit),
                "specimen": get("specimen"), "method": get("method"), "lab_flag_raw": get("lab_flag_raw"),
                "field_anchors": {}, "missing_reasons": {}, "field_status": {}, "extraction_method": "native_table"}
            for field in ("unit_raw", "specimen", "method", "reference_intervals"):
                if not row[field]:
                    row["missing_reasons"][field] = "not_reported"
                    row["field_anchors"][field] = None
            for field, column in columns.items():
                value = values[column]
                if value.strip():
                    row["field_anchors"][field] = source_anchor(field, value, number, start, end, column, header[column])
                    row["field_status"][field] = "proposed"
            if result["kind"] == "text_unparsed":
                row["field_status"]["result"] = "ambiguous"
            if clinical["precision"] == "unknown":
                row["missing_reasons"]["clinical_time"] = "ambiguous" if clinical["raw"] else "not_reported"
                if clinical["raw"]:
                    row["field_status"]["clinical_time"] = "ambiguous"
                    reasons.append("CLINICAL_TIME_AMBIGUOUS")
                else:
                    row["field_anchors"]["clinical_time"] = None
            try:
                row = lab_observation(row, version["version_id"], version["source_sha256"])
            except V2Error:
                preserve(raw, cells, [*reasons, "SOURCE_FIELD_UNPARSED"], number=number, start=start, end=end)
                continue
            rows.append(row)
            if reasons:
                preserve(raw, cells, reasons, row, alternatives, number, start, end)
        require(len(issues) <= 1000, "ISSUE_LIMIT", "Source issues exceed bounded capacity")
        return rows, issues
    except (StopIteration, csv.Error) as exc:
        raise V2Error("INVALID_TABLE", "Table cannot be decoded safely") from exc


def unmapped_text_issues(text: str, version: dict, code: str, *, locator_kind: str = "text", page=None) -> list:
    """Retain an unresolved document as bounded ordered, explicitly broad spans."""
    group = "unmapped_table_" + digest({"version": version["version_id"], "page": page, "text": text})
    parts = [(i, text[i:i + 1600]) for i in range(0, len(text), 1600)] or [(0, "")]
    require(len(parts) <= 1000, "ISSUE_LIMIT", "Unmapped source exceeds bounded issue capacity")
    issues = []
    for index, (offset, part) in enumerate(parts, 1):
        start = 1 + text[:offset].count("\n")
        end = start + part.rstrip("\n").count("\n")
        locator = {"kind": "text", "line": start}
        if locator_kind == "pdf":
            locator.update(kind="pdf", page=page, line=start if start == end else f"{start}-{end}")
        a = {"version_id": version["version_id"], "source_sha256": version["source_sha256"],
             "field": "unresolved_source_span", "locator": locator, "excerpt": part}
        issues.append({"page": page, "source": "native_table", "raw_text": part,
            "raw_cells": [{"column": None, "column_label": None, "role": "unresolved_source_span", "text": part, "anchors": [a] if part else []}],
            "reason_codes": [code, "TABLE_HEADER_UNRECOGNIZED", "SOURCE_SPAN_FRAGMENT"], "proposed_row": None,
            "alternatives": [{"kind": "ordered_source_fragment", "group_id": group, "index": index, "count": len(parts),
                "start_character": offset, "end_character": offset + len(part), "previous_index": index - 1 if index > 1 else None,
                "next_index": index + 1 if index < len(parts) else None}]})
    return issues
