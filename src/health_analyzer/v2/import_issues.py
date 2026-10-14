"""Private, append-only whole-source-row quarantine; never accepts observations."""
from __future__ import annotations

import copy

from .common import V2Error, canonical, digest, require, utc_now
from .contracts import anchor, identifier, lab_observation, text

MAX_ISSUES = 1000
MAX_ISSUE_BYTES = 64 * 1024


def validate_issue(value: dict, version: dict) -> dict:
    fields = {"page", "source", "raw_text", "raw_cells", "reason_codes", "alternatives", "proposed_row"}
    require(isinstance(value, dict) and set(value) <= fields, "INVALID_IMPORT_ISSUE", "Issue fields must describe the source row, not a review decision")
    require(len(canonical(value)) <= MAX_ISSUE_BYTES, "ISSUE_LIMIT", "Whole-row issue exceeds 64 KiB")
    issue = copy.deepcopy(value)
    page = issue.get("page")
    require(page is None or (type(page) is int and 1 <= page <= 500), "INVALID_IMPORT_ISSUE", "Issue page is one-based")
    text(issue.get("source"), "issue.source", maximum=100)
    require(isinstance(issue.get("raw_text"), str) and len(issue["raw_text"]) <= 8000, "INVALID_IMPORT_ISSUE", "Raw row must remain bounded text")
    codes = issue.get("reason_codes")
    require(isinstance(codes, list) and 1 <= len(codes) <= 20 and all(isinstance(x, str) and 0 < len(x) <= 100 for x in codes), "INVALID_IMPORT_ISSUE", "Issue needs bounded reasons")
    cells = issue.setdefault("raw_cells", [])
    require(isinstance(cells, list) and len(cells) <= 32, "ISSUE_LIMIT", "Source row may have at most 32 cells")
    for cell in cells:
        require(isinstance(cell, dict) and set(cell) <= {"column", "column_label", "role", "text", "anchors"}, "INVALID_IMPORT_ISSUE", "Source cells have explicit text and anchors")
        require(cell.get("column") is None or (type(cell["column"]) is int and 0 <= cell["column"] <= 32), "INVALID_IMPORT_ISSUE", "Cell column must be bounded or unknown")
        if cell.get("column_label") is not None:
            text(cell["column_label"], "issue.column_label", maximum=200)
        text(cell.get("role"), "issue.cell.role", maximum=100)
        require(isinstance(cell.get("text"), str) and len(cell["text"]) <= 8000, "INVALID_IMPORT_ISSUE", "Cell text must be bounded")
        anchors = cell.setdefault("anchors", [])
        require(isinstance(anchors, list) and len(anchors) <= 20, "INVALID_IMPORT_ISSUE", "Cell anchors must be bounded")
        for a in anchors:
            require(isinstance(a, dict), "INVALID_IMPORT_ISSUE", "Cell needs a source anchor")
            anchor(a, a.get("field"), version["version_id"], version["source_sha256"])
    alternatives = issue.setdefault("alternatives", [])
    require(isinstance(alternatives, list) and len(alternatives) <= 16 and all(isinstance(x, dict) for x in alternatives), "INVALID_IMPORT_ISSUE", "Alternatives are hypotheses, never accepted values")
    if issue.get("proposed_row") is not None:
        issue["proposed_row"] = lab_observation(issue["proposed_row"], version["version_id"], version["source_sha256"])
    else:
        issue["proposed_row"] = None
    return issue


class ImportIssueService:
    def __init__(self, records):
        self.records = records
        self.store = records.store

    def register(self, subject_id: str, version_id: str, run_id: str, issues: list[dict]) -> list[str]:
        version = self.records._version(subject_id, version_id)
        require(isinstance(issues, list) and len(issues) <= MAX_ISSUES, "ISSUE_LIMIT", "Import issue count exceeds 1000")
        normalized = [validate_issue(x, version) for x in issues]
        ids = []
        for value in normalized:
            identity = {"subject_id": subject_id, "version_id": version_id, "run_id": run_id, "source": value}
            issue_id = "issue_" + digest(identity)
            try:
                self.store.get("import_issue", issue_id, subject_id)
            except V2Error as exc:
                if exc.code != "NOT_FOUND":
                    raise
                self.store.put("import_issue", issue_id, {**identity, "issue_id": issue_id,
                    "source_sha256": version["source_sha256"], "verification": "unreviewed",
                    "recorded_at": utc_now()}, subject_id)
            ids.append(issue_id)
        return ids

    def _states(self, subject_id: str) -> dict:
        states = {}
        for event in self.store.list("import_issue_event", subject_id):
            states[event["issue_id"]] = event
        return states

    @staticmethod
    def _bind_row_to_issue(row: dict, issue: dict) -> None:
        """Version equality alone cannot resolve a different source result cell."""
        from .records import result_locator
        source = issue["source"]
        cells = source["raw_cells"]
        result_cells = [c for c in cells if c["role"] in {"result", "prior_result"} and c["anchors"]]
        if result_cells:
            expected = [result_locator({"field_anchors": {"result": c["anchors"]}}) for c in result_cells]
            require(result_locator(row) in expected, "ISSUE_ANCHOR_SCOPE_MISMATCH", "Proposed row belongs to another source result cell")
            return
        require(not set(source["reason_codes"]) & {"TABLE_HEADER_UNRECOGNIZED", "NO_READABLE_LAYOUT", "NO_NATIVE_TEXT"},
                "ISSUE_SCOPE_REQUIRES_VISUAL_BATCH", "A whole unresolved page needs a visual extraction batch; one row cannot resolve the page")
        locations = [a["locator"] for c in cells for a in c["anchors"]]
        proposed = result_locator(row)
        proposed = proposed if isinstance(proposed, list) else [proposed]
        require(bool(locations), "ISSUE_ANCHOR_SCOPE_MISMATCH", "Issue has no source row location")
        for locator in proposed:
            same_row = any(locator.get("kind") in {"csv", "csv_cell"} and a.get("kind") in {"csv", "csv_cell"}
                           and locator.get("row") == a.get("row") for a in locations)
            same_line = any(locator.get("kind") == a.get("kind") and locator.get("page") == a.get("page")
                           and locator.get("line") is not None and locator.get("line") == a.get("line") for a in locations)
            # A missing/illegible result may need a region entered after visual
            # review. Constrain it to the same source row's vertical extent.
            regions = [a["region"] for a in locations if a.get("kind") == locator.get("kind")
                       and a.get("page") == locator.get("page") and a.get("region")]
            region = locator.get("region")
            same_band = bool(region and regions and min(r[1] for r in regions) <= region[1]
                             and region[3] <= max(r[3] for r in regions))
            require(same_row or same_line or same_band, "ISSUE_ANCHOR_SCOPE_MISMATCH", "Result must stay within the unresolved source row")

    def list(self, subject_id: str, version_id: str | None = None, status: str | None = None,
             offset: int = 0, limit: int = 25) -> dict:
        self.records._subject(subject_id)
        if version_id is not None:
            self.records._version(subject_id, version_id)
        require(status in {None, "pending", "deferred", "discarded", "proposed"}, "INVALID_ISSUE_STATUS", "Unknown issue state")
        require(type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 100, "INPUT_LIMIT", "Issue page contains 1–100 whole rows")
        states = self._states(subject_id)
        selected = []
        for issue in self.store.list("import_issue", subject_id):
            if version_id is not None and issue["version_id"] != version_id:
                continue
            event = states.get(issue["issue_id"])
            current = event["status"] if event else "pending"
            if status is None or status == current:
                run = self.records._latest_run(subject_id, issue["version_id"])
                selected.append({**issue, "status": current, "latest_event": event, "current_run_id": run["run_id"],
                                 "current_selection_token": run.get("selection_token")})
        return {"subject_id": subject_id, "issues": selected[offset:offset + limit],
                "offset": offset, "limit": limit, "total": len(selected), "confirmed": False}

    def resolve(self, subject_id: str, issue_id: str, action: str, reason: str,
                row: dict | None = None, expected_event_id: str | None = None,
                expected_run_id: str | None = None,
                expected_selection_token: str | None = None,
                idempotency_key: str = "") -> dict:
        """A resolution produces only another draft. Normal frozen review is required."""
        self.records._subject(subject_id)
        identifier(issue_id, "issue_id")
        require(action in {"defer", "discard", "propose"}, "INVALID_ISSUE_ACTION", "Resolve by defer, discard or propose; confirmation is a separate workflow")
        text(reason, "issue resolution reason", maximum=2000)
        require(action == "propose" or row is None, "INVALID_ISSUE_ACTION", "Only propose may contain a typed row")
        request = {"issue_id": issue_id, "action": action, "reason": reason, "row": row,
                   "expected_event_id": expected_event_id, "expected_run_id": expected_run_id,
                   "expected_selection_token": expected_selection_token}
        with self.store.transaction():
            idem_id, prior = self.records._idempotency(subject_id, "resolve_import_issue", idempotency_key, request)
            if prior is not None:
                return prior
            issue = self.store.get("import_issue", issue_id, subject_id)
            current = self._states(subject_id).get(issue_id)
            require((current["event_id"] if current else None) == expected_event_id,
                    "STALE_IMPORT_ISSUE", "Issue changed after its displayed state")
            version = self.records._version(subject_id, issue["version_id"])
            extraction = None
            if action == "propose":
                normalized = lab_observation(row, version["version_id"], version["source_sha256"])
                self._bind_row_to_issue(normalized, issue)
                self.records._check_source(version)
                latest = self.records._latest_run(subject_id, version["version_id"])
                require(expected_run_id == latest["run_id"], "STALE_IMPORT_ISSUE", "Refresh the issue page before proposing into a changed extraction")
                require(expected_selection_token == latest.get("selection_token"), "STALE_IMPORT_ISSUE", "Extraction attempt changed after this issue display")
                rows = [self.store.get("observation_draft", d, subject_id)["row"] for d in latest["draft_ids"]]
                from .records import result_locator
                locator = result_locator(normalized)
                def same_location(existing):
                    return result_locator(existing) == locator
                rows = [existing for existing in rows if not same_location(existing)] + [normalized]
                coverage = {k: v for k, v in latest["coverage"].items() if k != "known_extracted_rows"}
                coverage.update(status="partial", expected_count=None, expected_count_basis="unknown")
                extraction = self.records.submit_extraction(subject_id, version["version_id"], rows, coverage)
            event_id = "issue_event_" + digest({"request": request, "previous": current["event_id"] if current else None,
                                               "subject_id": subject_id})
            event = {"subject_id": subject_id, "issue_id": issue_id, "event_id": event_id,
                "previous_event_id": current["event_id"] if current else None, "action": action,
                "status": {"defer": "deferred", "discard": "discarded", "propose": "proposed"}[action],
                "reason": reason, "extraction": extraction, "verification": "unreviewed",
                "recorded_at": utc_now()}
            self.store.put("import_issue_event", event_id, event, subject_id)
            result = {**event, "confirmed": False, "requires_frozen_review": action == "propose"}
            self.records._put_idempotency(subject_id, idem_id, request, result)
            return result
