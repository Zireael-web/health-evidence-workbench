"""Bind OCR hypotheses to source fields without replacing source text."""
from __future__ import annotations

from .unit_text import inspect_unit


def _inside(block: dict, page: dict, region: list | None) -> bool:
    if not region:
        return False
    box = [block["x"]/page["width"], block["y"]/page["height"],
           (block["x"]+block["width"])/page["width"], (block["y"]+block["height"])/page["height"]]
    intersection = max(0, min(box[2], region[2])-max(box[0], region[0])) * max(0, min(box[3], region[3])-max(box[1], region[1]))
    area = (box[2]-box[0])*(box[3]-box[1])
    return bool(area and intersection/area >= .95)


def annotate_ocr_rows(rows: list[dict], pages: list[dict]) -> list[dict]:
    issues = []
    for row in rows:
        if row.get("extraction_method") != "local_ocr":
            continue
        reasons, alternatives = [], []
        anchors_by_field = row["field_anchors"]
        field_values = {"analyte_raw": row["analyte_raw"], "result": row["result"]["raw"],
                        "unit_raw": row.get("unit_raw"), "clinical_time": row["clinical_time"].get("raw"),
                        "reference_intervals": "\n".join(item["raw"] for item in row.get("reference_intervals", [])) or None,
                        "specimen": row.get("specimen"), "method": row.get("method"), "lab_flag_raw": row.get("lab_flag_raw")}
        selected_page = None
        for field, value in field_values.items():
            anchors = anchors_by_field.get(field)
            if not anchors or value is None:
                continue
            anchors = anchors if isinstance(anchors, list) else [anchors]
            candidate_values = []
            for a in anchors:
                loc = a["locator"]
                for page in pages:
                    if page.get("source") != "vision_ocr" or page["page"] != loc.get("page"):
                        continue
                    selected_page = page
                    for block in page["blocks"]:
                        if not _inside(block, page, loc.get("region")):
                            continue
                        for candidate in block.get("candidates", [])[1:]:
                            if candidate["text"] == block["text"]:
                                continue
                            item = {"field": field, "observed_source_text": block["text"], **candidate,
                                    "source_anchors": [a]}
                            if item not in candidate_values:
                                candidate_values.append(item)
            if field == "unit_raw":
                # Only whole-cell candidates can be interpreted as unit tokens.
                # Larger containing boxes remain source-bound hypotheses and
                # cannot be selected as a replacement for a header substring.
                unit_candidates = [item for item in candidate_values if item["observed_source_text"].strip() == value.strip()]
                assessment = inspect_unit(value, unit_candidates)
                if assessment["status"] == "known":
                    row["unit_code"] = assessment["unit_code"]
                    row.setdefault("field_status", {})["unit_code"] = "proposed"
                else:
                    row.setdefault("field_status", {})["unit_raw"] = "ambiguous"
                    reasons.extend(assessment["reason_codes"])
                alternatives.extend({"kind": "unit_reading_hypothesis", **item} for item in assessment["alternatives"])
                if candidate_values and not unit_candidates:
                    row.setdefault("field_status", {})["unit_raw"] = "ambiguous"
                    reasons.append("OCR_UNIT_CONTAINING_CELL_CONFLICT")
            elif candidate_values:
                row.setdefault("field_status", {})[field] = "ambiguous"
                reasons.append("OCR_" + field.upper() + "_CANDIDATES_CONFLICT")
            alternatives.extend({"kind": "source_ocr_candidate", **item} for item in candidate_values)
        if not reasons and not alternatives:
            continue
        raw_cells = []
        for field, value in field_values.items():
            a = anchors_by_field.get(field)
            if a and value is not None:
                raw_cells.append({"column": None, "role": field, "text": value,
                                  "anchors": a if isinstance(a, list) else [a]})
        # Keep all alternatives in separately bounded issues; no truncation of
        # a source hypothesis merely to fit one response object.
        for start in range(0, max(1, len(alternatives)), 16):
            issues.append({"page": selected_page["page"] if selected_page else None, "source": "vision_ocr",
                "raw_text": " | ".join(v for v in field_values.values() if isinstance(v, str)),
                "raw_cells": raw_cells, "reason_codes": sorted(set(reasons)) or ["OCR_UNIT_EQUIVALENT_NOTATION_ALTERNATIVES"],
                "alternatives": alternatives[start:start+16], "proposed_row": row})
    return issues


def preserve_unmapped_ocr_candidates(rows: list[dict], pages: list[dict], version: dict, *, locator_kind: str) -> list[dict]:
    """Retain actual alternatives even when no laboratory row can be assembled.

    A raw source block remains evidence, never a fabricated laboratory value.
    Existing hard issue/document caps and atomic registration still apply.
    """
    issues = []
    for page in pages:
        if page.get("source") != "vision_ocr":
            continue
        regions = []
        for row in rows:
            if row.get("extraction_method") != "local_ocr":
                continue
            for anchors in row.get("field_anchors", {}).values():
                for anchor in anchors if isinstance(anchors, list) else [anchors] if anchors else []:
                    locator = anchor["locator"]
                    if locator.get("page") == page["page"] and locator.get("region"):
                        regions.append(locator["region"])
        for block in page["blocks"]:
            candidates = block.get("candidates", [])
            if not any(candidate["text"] != block["text"] for candidate in candidates):
                continue
            if any(_inside(block, page, region) for region in regions):
                continue
            region = [block["x"]/page["width"], block["y"]/page["height"],
                      (block["x"]+block["width"])/page["width"], (block["y"]+block["height"])/page["height"]]
            anchor = {"version_id": version["version_id"], "source_sha256": version["source_sha256"],
                      "field": "unmapped_ocr_block", "locator": {"kind": locator_kind, "page": page["page"], "region": region},
                      "excerpt": block["text"], "inherited": False}
            alternatives = [{"kind": "source_ocr_candidate", "observed_source_text": block["text"],
                             **candidate, "source_anchors": [anchor]} for candidate in candidates]
            receipt = page.get("metadata", {}).get("recognition")
            if receipt:
                alternatives.append({"kind": "ocr_recognition_receipt", **receipt})
            issues.append({"page": page["page"], "source": "vision_ocr", "raw_text": block["text"],
                           "raw_cells": [{"column": None, "role": "unmapped_ocr_block", "text": block["text"], "anchors": [anchor]}],
                           "reason_codes": ["UNMAPPED_OCR_CANDIDATES"], "alternatives": alternatives, "proposed_row": None})
    return issues
