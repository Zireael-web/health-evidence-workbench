"""Private v2 records, frozen reviews and immutable clinical/event history.

All methods are subject scoped. No method reads legacy stores or migrates data.
Conversation decisions are attributed, not independently authenticated. An
integrity MAC protects stored attribution; it never upgrades its assurance.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone, date
from decimal import Decimal, localcontext, ROUND_HALF_EVEN
import csv
import io
from typing import Callable, Any

from .common import SignedStore, V2Error, canonical, digest, new_id, require, utc_now
from .contracts import (SCHEMA_VERSION, SHA256_RE, ROW_FIELDS, identifier, text,
                        iso_timestamp, clinical_time, lab_observation,
                        extraction_coverage, anchor)

TRUSTED_ASSURANCE = {"conversation_attested", "local_operator_confirmed"}
CONFIRM_ACTIONS = {"confirm", "correct_and_confirm"}


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _within_as_of(payload: dict, as_of: str | None) -> bool:
    return as_of is None or _timestamp(payload["recorded_at"]) <= _timestamp(as_of)


def _identity(row: dict) -> str:
    return row.get("analyte_key") if row.get("mapping_status") == "confirmed" and row.get("analyte_key") else "raw:" + row["analyte_raw"]


def result_locator(row: dict) -> dict | list[dict]:
    """Canonical source location, independent of anchor wrapping/order/excerpt.

    A singleton anchor list and an anchor object refer to the same source cell.
    Multiple locations are an unordered, duplicate-free set; this helper never
    rewrites an existing row or assumes that nearby geometric boxes are equal.
    """
    require(isinstance(row, dict) and isinstance(row.get("field_anchors"), dict),
            "invalid_anchor", "A row needs result source anchors")
    anchors = row["field_anchors"].get("result")
    anchors = anchors if isinstance(anchors, list) else [anchors]
    require(bool(anchors) and all(isinstance(item, dict) and isinstance(item.get("locator"), dict) for item in anchors),
            "invalid_anchor", "Result source anchors need structured locators")
    locations = {canonical(item["locator"]): copy.deepcopy(item["locator"]) for item in anchors}
    ordered = [locations[key] for key in sorted(locations)]
    return ordered[0] if len(ordered) == 1 else ordered


def _field_known(row: dict, field: str, *, trusted: bool = False) -> bool:
    # An attested whole-row decision covers displayed source proposals. Keep
    # the original extraction status immutable; model-only rows and explicitly
    # missing/ambiguous fields remain outside strict comparisons.
    missing = {"unknown", "not_reported", "not_applicable", "ambiguous"}
    state = row.get("field_status", {}).get(field)
    return (row.get(field) is not None and state not in missing
            and (state != "proposed" or trusted)
            and row.get("missing_reasons", {}).get(field) not in missing)


def _is_trusted(revision: dict) -> bool:
    return revision["confirmation_assurance"] in TRUSTED_ASSURANCE


def _clinical_bounds(time: dict) -> tuple[str, str] | None:
    """Filtering ranges do not upgrade the printed time's precision or role."""
    precision = time["precision"]
    if precision == "unknown":
        return None
    if precision == "interval":
        return time["start"][:10], time["end"][:10]
    value = time["value"]
    if precision in {"datetime", "date"}:
        return value[:10], value[:10]
    if precision == "year":
        return value + "-01-01", value + "-12-31"
    year, month = map(int, value.split("-"))
    next_month = date(year + (month == 12), 1 if month == 12 else month + 1, 1)
    from datetime import timedelta
    return value + "-01", (next_month - timedelta(days=1)).isoformat()


def _time_identity(time: dict) -> tuple:
    """A printed spelling is not a separate collection time."""
    return (time["role"], time["precision"], time.get("value"), time.get("start"), time.get("end"), time.get("timezone"))


def _strict_time(row: dict, *, trusted: bool = False) -> bool:
    time = row["clinical_time"]
    return _field_known(row, "clinical_time", trusted=trusted) and time["role"] in {"collected", "performed"} and time["precision"] in {"date", "datetime"}


def _comparison_order(items: list[dict]) -> tuple[list[dict], dict]:
    """Order only as far as printed precision/timezones establish.

    Date-only results denote a whole local day, not midnight. Aware datetimes
    compare in UTC. We do not assign a timezone to a naive time or date, nor
    choose the order of overlapping collection windows by revision ID.
    """
    windows = []
    for item in items:
        printed = item["row"]["clinical_time"]
        if printed["precision"] == "date":
            day = date.fromisoformat(printed["value"])
            start = datetime(day.year, day.month, day.day)
            end = start.replace(hour=23, minute=59, second=59, microsecond=999999)
            regime = ("local", printed.get("timezone"))
        else:
            point = datetime.fromisoformat(printed["value"].replace("Z", "+00:00"))
            if point.tzinfo is not None:
                start = end = point.astimezone(timezone.utc)
                regime = ("aware", None)
            else:
                start = end = point
                regime = ("local", printed.get("timezone"))
        windows.append((item, regime, start, end))
    regimes = {window[1] for window in windows}
    if len(regimes) > 1:
        return list(items), {"status": "ambiguous", "reason": "mixed_timezone_awareness_or_unresolved_timezones", "display_order": "requested_order; not clinical chronology"}
    windows.sort(key=lambda window: window[2])
    ordered = [window[0] for window in windows]
    overlapping = any(previous[3] >= following[2] for previous, following in zip(windows, windows[1:]))
    if overlapping:
        return ordered, {"status": "ambiguous", "reason": "overlapping_clinical_time_precision", "display_order": "partial printed-time order; equal/overlapping points have no established sequence"}
    return ordered, {"status": "established", "basis": "UTC-aware instants" if regimes == {("aware", None)} else "non-overlapping printed local time windows", "display_order": "clinical chronology"}


class RecordsService:
    MAX_EXTRACTION_ROWS = 1000
    MAX_REVIEW_ROWS = 100

    def __init__(self, store: SignedStore, source_checker: Callable[[dict], Any] | None = None):
        require(store.domain == "private-data", "wrong_domain", "Records require a private-data store")
        self.store = store
        self.source_checker = source_checker

    def _subject(self, subject_id: str) -> dict:
        identifier(subject_id, "subject_id")
        return self.store.get("subject", subject_id, subject_id)

    def _list(self, kind: str, subject_id: str, as_of: str | None = None) -> list[dict]:
        return [p for p in self.store.list(kind, subject_id) if _within_as_of(p, as_of)]

    def register_subject(self, subject_id: str, label: str) -> dict:
        identifier(subject_id, "subject_id")
        text(label, "label", maximum=200)
        with self.store.transaction():
            existing = self.store.list("subject", subject_id)
            if existing:
                require(existing[0]["label"] == label, "immutable_conflict", "Subject label is already registered")
                return existing[0]
            payload = {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "label": label, "recorded_at": utc_now()}
            return self.store.put("subject", subject_id, payload, subject_id)

    def register_document(self, subject_id: str, source_sha256: str, mime: str, size: int,
                          occurrence: dict | None = None, document_id: str | None = None) -> dict:
        """Internal import entrypoint. ImportService computes hash from read bytes.

        Supplying a hash here is not proof of reading a source; this method must
        not be exposed as a model-authored 'verified bytes' MCP operation.
        """
        self._subject(subject_id)
        require(isinstance(source_sha256, str) and bool(SHA256_RE.fullmatch(source_sha256)), "invalid_hash", "Source SHA-256 must be lowercase hex")
        text(mime, "mime", maximum=100)
        require(isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= 64 * 1024 * 1024, "size_limit", "Source size exceeds the 64 MiB limit")
        if document_id is not None:
            identifier(document_id, "document_id")
        if occurrence is not None:
            require(isinstance(occurrence, dict) and set(occurrence) <= {"root_id", "relative_path", "snapshot_path", "source_mode"}, "invalid_occurrence", "Occurrence fields are import-owned")
            identifier(occurrence.get("root_id"), "root_id")
            path = text(occurrence.get("relative_path"), "relative_path", maximum=4000)
            from pathlib import PurePosixPath
            require(not PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts and "\x00" not in path, "unsafe_path", "Occurrence path must remain relative to its bound root")
            if occurrence.get("snapshot_path") is not None:
                text(occurrence["snapshot_path"], "snapshot_path", maximum=4000)
            require(occurrence.get("source_mode", "archive") in {"archive", "immutable_snapshot", "synthetic"}, "invalid_occurrence", "Unknown source mode")
        with self.store.transaction():
            same_bytes = [v for v in self.store.list("document_version", subject_id) if v["source_sha256"] == source_sha256]
            if same_bytes:
                version = same_bytes[0]
                require(version["mime"] == mime and version["size"] == size, "source_identity_conflict", "Same byte hash must have the same registered source metadata")
                require(document_id is None or version["document_id"] == document_id, "source_identity_conflict", "Identical bytes already belong to a scoped document")
                deduplicated = True
            else:
                doc_id = document_id or new_id("document")
                documents = [p for p in self.store.list("document", subject_id) if p["document_id"] == doc_id]
                if not documents:
                    self.store.put("document", doc_id, {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "document_id": doc_id, "recorded_at": utc_now()}, subject_id)
                now = utc_now()
                version = {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "document_id": doc_id, "version_id": new_id("version"), "source_sha256": source_sha256, "mime": mime, "size": size, "imported_at": now, "recorded_at": now}
                self.store.put("document_version", version["version_id"], version, subject_id)
                deduplicated = False
            if occurrence is not None:
                payload = {"subject_id": subject_id, "version_id": version["version_id"], "document_id": version["document_id"], **copy.deepcopy(occurrence)}
                payload["occurrence_id"] = "occurrence_" + digest(payload)
                try:
                    self.store.get("file_occurrence", payload["occurrence_id"], subject_id)
                except V2Error as exc:
                    if exc.code != "NOT_FOUND":
                        raise
                    payload["recorded_at"] = utc_now()
                    self.store.put("file_occurrence", payload["occurrence_id"], payload, subject_id)
            return {**version, "deduplicated": deduplicated}

    def _version(self, subject_id: str, version_id: str) -> dict:
        self._subject(subject_id)
        return self.store.get("document_version", version_id, subject_id)

    def submit_extraction(self, subject_id: str, version_id: str, rows: list[dict], coverage: dict) -> dict:
        version = self._version(subject_id, version_id)
        require(isinstance(rows, list) and len(rows) <= self.MAX_EXTRACTION_ROWS, "extraction_limit", "Extraction may contain at most 1000 whole laboratory rows")
        normalized = [lab_observation(row, version_id, version["source_sha256"]) for row in rows]
        normalized_coverage = extraction_coverage(coverage, len(rows))
        fingerprint = {"version_id": version_id, "rows": normalized, "coverage": normalized_coverage}
        run_id = "extraction_" + digest(fingerprint)
        with self.store.transaction():
            previous_selection = self._selection_state(subject_id, version_id)
            # Reuse a unique existing identity at the canonical same-version
            # source location, including identities assigned by earlier v2
            # anchor-container conventions. No historical object is rewritten.
            old_identities: dict[str, set[str]] = {}
            for draft in self.store.list("observation_draft", subject_id):
                if draft["source_version_id"] == version_id:
                    location_key = digest(result_locator(draft["row"]))
                    old_identities.setdefault(location_key, set()).add(draft["observation_id"])
            identities = []
            row_identities = set()
            for row in normalized:
                location = result_locator(row)
                location_key = digest(location)
                require(location_key not in row_identities, "duplicate_source_row", "Two extracted rows claim the same result source location")
                row_identities.add(location_key)
                prior_ids = old_identities.get(location_key, set())
                require(len(prior_ids) <= 1, "ambiguous_observation_identity", "Existing drafts assign conflicting observations to the same canonical source location")
                identities.append(next(iter(prior_ids)) if prior_ids else "observation_" + digest({"version_id": version_id, "result_locator": location}))
            try:
                prior = self.store.get("extraction_run", run_id, subject_id)
                selection = self._select_run(subject_id, version_id, run_id, previous_selection)
                return {"run_id": run_id, "draft_ids": prior["draft_ids"], "panel_ids": prior["panel_ids"], "deduplicated": True, **selection}
            except V2Error as exc:
                if exc.code != "NOT_FOUND":
                    raise
            now = utc_now()
            draft_ids = []
            panels: dict[str, list[str]] = {}
            for index, row in enumerate(normalized):
                # Locator identity excludes the extracted value. A corrected
                # extraction of the same source row revises one observation.
                draft_id = "draft_" + digest({"run_id": run_id, "index": index})
                observation_id = identities[index]
                panel_key = row.get("panel_key") or "default"
                panel_id = "panel_" + digest({"run_id": run_id, "panel_key": panel_key})
                panels.setdefault(panel_id, []).append(draft_id)
                draft = {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "draft_id": draft_id, "observation_id": observation_id, "source_version_id": version_id, "source_sha256": version["source_sha256"], "extraction_run_id": run_id, "panel_id": panel_id, "row": row, "review_status": "unreviewed", "recorded_at": now}
                self.store.put("observation_draft", draft_id, draft, subject_id)
                draft_ids.append(draft_id)
            for panel_id, members in panels.items():
                self.store.put("panel", panel_id, {"subject_id": subject_id, "panel_id": panel_id, "run_id": run_id, "version_id": version_id, "draft_ids": members, "recorded_at": now}, subject_id)
            run = {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "run_id": run_id, "version_id": version_id, "source_sha256": version["source_sha256"], "coverage": normalized_coverage, "draft_ids": draft_ids, "panel_ids": list(panels), "recorded_at": now}
            self.store.put("extraction_run", run_id, run, subject_id)
            selection = self._select_run(subject_id, version_id, run_id, previous_selection)
            return {"run_id": run_id, "draft_ids": draft_ids, "panel_ids": list(panels), "deduplicated": False, **selection}

    @staticmethod
    def _legacy_selection_token(subject_id: str, version_id: str, run_id: str) -> str:
        return "selection_legacy_" + digest({"subject_id": subject_id, "version_id": version_id, "run_id": run_id})

    def _selection_state(self, subject_id: str, version_id: str) -> dict | None:
        """Read a per-version selection chain; timestamps never order attempts."""
        runs = [r for r in self.store.list("extraction_run", subject_id) if r["version_id"] == version_id]
        events = [event for event in self.store.list("extraction_selection", subject_id) if event["version_id"] == version_id]
        if not events:
            if not runs:
                return None
            run = runs[-1]  # Compatibility with earlier append-only v2 runs.
            return {"run_id": run["run_id"], "sequence": 0,
                    "selection_token": self._legacy_selection_token(subject_id, version_id, run["run_id"]),
                    "previous_selection_token": None}
        available = {run["run_id"] for run in runs}
        require(all(isinstance(event.get("sequence"), int) and not isinstance(event["sequence"], bool) and event["sequence"] > 0 for event in events),
                "extraction_selection_conflict", "Extraction selection sequences must be positive integers")
        events.sort(key=lambda event: event["sequence"])
        legacy_tokens = {self._legacy_selection_token(subject_id, version_id, run_id) for run_id in available}
        previous = None
        for sequence, event in enumerate(events, 1):
            require(event["sequence"] == sequence and event.get("run_id") in available,
                    "extraction_selection_conflict", "Extraction selections contain a gap, fork or unknown run")
            predecessor = event.get("previous_selection_token")
            require(predecessor == previous if sequence > 1 else predecessor is None or predecessor in legacy_tokens,
                    "extraction_selection_conflict", "Extraction selection predecessor chain conflicts")
            expected_token = "selection_" + digest({"subject_id": subject_id, "version_id": version_id,
                                                    "run_id": event["run_id"], "sequence": sequence,
                                                    "previous_selection_token": predecessor})
            require(event.get("selection_token") == expected_token,
                    "extraction_selection_conflict", "Extraction selection token differs from its bound attempt")
            previous = expected_token
        return events[-1]

    def _select_run(self, subject_id: str, version_id: str, run_id: str, previous: dict | None) -> dict:
        """Append only a changed selection; repeated current recognition is inert."""
        if previous is not None and previous["run_id"] == run_id:
            return {"selection_token": previous["selection_token"], "selection_changed": False}
        body = {"subject_id": subject_id, "version_id": version_id, "run_id": run_id,
                "sequence": previous["sequence"] + 1 if previous else 1,
                "previous_selection_token": previous["selection_token"] if previous else None}
        event = {"schema_version": SCHEMA_VERSION, **body, "selection_token": "selection_" + digest(body), "recorded_at": utc_now()}
        self.store.put("extraction_selection", event["selection_token"], event, subject_id)
        return {"selection_token": event["selection_token"], "selection_changed": True}

    def _latest_run(self, subject_id: str, version_id: str) -> dict:
        selection = self._selection_state(subject_id, version_id)
        require(selection is not None, "no_extraction", "No extraction is available for this source version")
        run = self.store.get("extraction_run", selection["run_id"], subject_id)
        return {**run, "selection_token": selection["selection_token"], "selection_sequence": selection["sequence"]}

    def _review_tokens(self, subject_id: str) -> dict[str, str]:
        tokens = {}
        for event in self.store.list("review_event", subject_id):
            for decision in event.get("decisions", []):
                tokens[decision["draft_id"]] = event["review_event_id"]
        return tokens

    def _latest_revisions(self, subject_id: str) -> dict[str, dict]:
        result = {}
        for revision in self.store.list("observation_revision", subject_id):
            result[revision["observation_id"]] = revision
        return result

    def prepare_review(self, subject_id: str, version_id: str, panel_id: str | None = None,
                       offset: int = 0, limit: int = 25) -> dict:
        version = self._version(subject_id, version_id)
        require(isinstance(offset, int) and not isinstance(offset, bool) and offset >= 0, "invalid_pagination", "Offset must be non-negative")
        require(isinstance(limit, int) and not isinstance(limit, bool) and 1 <= limit <= self.MAX_REVIEW_ROWS, "review_limit", "Review page must contain 1–100 whole rows")
        with self.store.transaction():
            run = self._latest_run(subject_id, version_id)
            draft_ids = run["draft_ids"]
            if panel_id is not None:
                panel = self.store.get("panel", panel_id, subject_id)
                require(panel["run_id"] == run["run_id"] and panel["version_id"] == version_id, "stale_panel", "Panel belongs to another or older extraction")
                draft_ids = panel["draft_ids"]
            selected = draft_ids[offset:offset + limit]
            require(bool(selected), "empty_review", "Review page has no extracted rows")
            rows = [self.store.get("observation_draft", draft_id, subject_id) for draft_id in selected]
            tokens = self._review_tokens(subject_id)
            revisions = self._latest_revisions(subject_id)
            payload = {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "snapshot_id": new_id("snapshot"), "version_id": version_id, "source_sha256": version["source_sha256"], "run_id": run["run_id"], "selection_token": run["selection_token"], "panel_id": panel_id, "rows": rows, "displayed_draft_ids": selected, "review_tokens": {d: tokens.get(d) for d in selected}, "observation_tokens": {row["observation_id"]: revisions.get(row["observation_id"], {}).get("revision_id") for row in rows}, "coverage": self._coverage(subject_id, run), "offset": offset, "limit": limit, "total_in_selection": len(draft_ids), "recorded_at": utc_now()}
            payload["snapshot_sha256"] = digest(payload)
            self.store.put("review_snapshot", payload["snapshot_id"], payload, subject_id)
            return payload

    def get_review_snapshot(self, subject_id: str, snapshot_id: str) -> dict:
        """Read an existing signed preview and its state without any writes.

        Freshness is a consistent database-state check, not source-byte,
        human-decision or clinical validation. Never recreate the preview.
        """
        identifier(snapshot_id, "snapshot_id")
        with self.store.transaction(readonly=True):
            self._subject(subject_id)
            snapshot = self.store.get("review_snapshot", snapshot_id, subject_id)
            require(snapshot.get("subject_id") == subject_id and snapshot.get("snapshot_id") == snapshot_id,
                    "snapshot_scope_mismatch", "Stored preview identity differs from its scope")
            body = {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
            snapshot_hash = snapshot.get("snapshot_sha256")
            require(isinstance(snapshot_hash, str) and bool(SHA256_RE.fullmatch(snapshot_hash))
                    and digest(body) == snapshot_hash,
                    "snapshot_hash_mismatch", "Frozen review snapshot is inconsistent")
            version = self._version(subject_id, snapshot.get("version_id"))
            require(snapshot.get("source_sha256") == version["source_sha256"],
                    "snapshot_source_mismatch", "Frozen preview belongs to different source bytes")
            run = self.store.get("extraction_run", snapshot.get("run_id"), subject_id)
            require(run.get("version_id") == version["version_id"]
                    and run.get("source_sha256") == version["source_sha256"],
                    "snapshot_source_mismatch", "Frozen preview extraction differs from its source version")
            rows = snapshot.get("rows")
            displayed = snapshot.get("displayed_draft_ids")
            require(isinstance(rows, list) and 1 <= len(rows) <= self.MAX_REVIEW_ROWS
                    and all(isinstance(row, dict) for row in rows)
                    and isinstance(displayed, list) and all(isinstance(item, str) for item in displayed)
                    and displayed == [row.get("draft_id") for row in rows]
                    and len(set(displayed)) == len(displayed)
                    and set(displayed) <= set(run["draft_ids"]),
                    "snapshot_scope_mismatch", "Frozen preview rows differ from its displayed extraction")
            for row in rows:
                require(row.get("subject_id") == subject_id
                        and row.get("source_version_id") == version["version_id"]
                        and row.get("source_sha256") == version["source_sha256"]
                        and isinstance(row.get("observation_id"), str)
                        and row.get("extraction_run_id") == run["run_id"]
                        and row == self.store.get("observation_draft", row["draft_id"], subject_id),
                        "snapshot_scope_mismatch", "Frozen preview row differs from its immutable draft")
            review_tokens = snapshot.get("review_tokens")
            observation_tokens = snapshot.get("observation_tokens")
            require(isinstance(review_tokens, dict) and set(review_tokens) == set(displayed)
                    and isinstance(observation_tokens, dict)
                    and set(observation_tokens) == {row["observation_id"] for row in rows},
                    "snapshot_scope_mismatch", "Frozen preview state tokens have different row scope")
            current_run = self._latest_run(subject_id, version["version_id"])
            tokens = self._review_tokens(subject_id)
            latest = self._latest_revisions(subject_id)
            reasons = []
            if current_run["run_id"] != snapshot["run_id"]:
                reasons.append("extraction_run_changed")
            selection_current = (snapshot["selection_token"] == current_run["selection_token"]
                                 if "selection_token" in snapshot else current_run["selection_sequence"] == 0)
            if not selection_current:
                reasons.append("extraction_selection_changed")
            if any(tokens.get(draft_id) != review_tokens[draft_id] for draft_id in displayed):
                reasons.append("review_state_changed")
            if any(latest.get(observation_id, {}).get("revision_id") != revision_id
                   for observation_id, revision_id in observation_tokens.items()):
                reasons.append("observation_revision_changed")
            verification = {"method": "signed_store_hmac", "checked_at": utc_now(),
                            "state": "stale" if reasons else "current", "reasons": reasons,
                            "snapshot_sha256": snapshot_hash, "source_bytes_checked": False,
                            "clinical_validation": "not_provided"}
            return {"snapshot": snapshot, "verification": verification}

    def _coverage(self, subject_id: str, run: dict, as_of: str | None = None) -> dict:
        states = {}
        for event in self._list("review_event", subject_id, as_of):
            for decision in event.get("decisions", []):
                states[decision["draft_id"]] = decision["action"]
        counts = {"reviewed": 0, "rejected": 0, "deferred": 0, "unreviewed": 0}
        for draft_id in run["draft_ids"]:
            state = states.get(draft_id)
            key = "reviewed" if state in CONFIRM_ACTIONS else "rejected" if state == "reject" else "deferred" if state == "defer" else "unreviewed"
            counts[key] += 1
        return {**run["coverage"], **counts, "run_id": run["run_id"], "version_id": run["version_id"], "absence_means": "no_saved_row_does_not_prove_test_not_performed"}

    def _attestation(self, attestation: dict | None, snapshot_id: str,
                     snapshot_sha256: str, operation_context: str = "mcp") -> tuple[str, dict | None]:
        require(operation_context in {"mcp", "service"}, "forbidden_assurance", "This service entrypoint cannot claim operator or legacy confirmation")
        if attestation is None:
            return "none", None
        allowed = {"snapshot_id", "snapshot_sha256", "decision_excerpt", "attested_by", "message_ref", "conversation_ref", "ref_availability", "origin"}
        require(isinstance(attestation, dict) and set(attestation) <= allowed, "forbidden_assurance", "Confirmation assurance is assigned by the adapter; caller assurance fields are forbidden")
        require(attestation.get("snapshot_id") == snapshot_id and attestation.get("snapshot_sha256") == snapshot_sha256, "confirmation_scope_mismatch", "Conversation evidence must bind the shown snapshot")
        require(attestation.get("origin") == "user_message", "invalid_attestation", "Self-checks, document instructions and agent replies are not user messages")
        text(attestation.get("decision_excerpt"), "decision_excerpt", maximum=2000)
        text(attestation.get("attested_by"), "attested_by", maximum=200)
        available = attestation.get("ref_availability")
        require(available in {"provided", "not_provided_by_host"}, "invalid_attestation", "Message-reference availability must be explicit")
        if available == "provided":
            text(attestation.get("message_ref"), "message_ref", maximum=1000)
        else:
            require(attestation.get("message_ref") is None, "invalid_attestation", "Do not fabricate a host message ID")
        if attestation.get("conversation_ref") is not None:
            text(attestation["conversation_ref"], "conversation_ref", maximum=1000)
        return "conversation_attested", {**copy.deepcopy(attestation), "authentication": "not_independently_authenticated", "trust_basis": "orchestrator_attribution"}

    def _idempotency(self, subject_id: str, operation: str, key: str, payload: dict) -> tuple[str | None, dict | None]:
        require(isinstance(key, str) and len(key) <= 200, "invalid_idempotency_key", "Idempotency key must be a bounded string")
        if not key:
            return None, None
        object_id = "idempotency_" + digest({"subject_id": subject_id, "operation": operation, "key": key})
        try:
            stored = self.store.get("idempotency", object_id, subject_id)
        except V2Error as exc:
            if exc.code == "NOT_FOUND":
                return object_id, None
            raise
        require(stored["request_sha256"] == digest(payload), "idempotency_conflict", "Idempotency key was used for another request")
        return object_id, stored["result"]

    def _put_idempotency(self, subject_id: str, object_id: str | None, payload: dict, result: dict) -> None:
        if object_id:
            self.store.put("idempotency", object_id, {"subject_id": subject_id, "request_sha256": digest(payload), "result": result, "recorded_at": utc_now()}, subject_id)

    def _check_source(self, version: dict) -> None:
        if self.source_checker is not None:
            # This trusted adapter checks the current source hash. An earlier
            # check-time availability event cannot overrule newly verified
            # bytes, e.g. a report restored unchanged after temporary removal.
            require(self.source_checker(version) is not False, "stale_source", "Source bytes changed or source is unavailable")
            self.record_source_availability(version["subject_id"], version["version_id"], True)
            return
        availability = self._availability(version["subject_id"], version["version_id"])
        require(availability["status"] != "unavailable", "source_unavailable", "A new review cannot commit against an unavailable source")

    def _patch_row(self, row: dict, patch: dict, version: dict) -> dict:
        allowed = ROW_FIELDS - {"field_anchors", "panel_key", "extraction_method", "field_status"}
        require(isinstance(patch, dict) and bool(patch) and set(patch) <= allowed, "invalid_patch", "Correction must name typed fields; source anchors and assurance cannot be rewritten")
        changed = copy.deepcopy(row)
        changed.update(copy.deepcopy(patch))
        statuses = dict(changed.get("field_status", {}))
        for field in patch:
            if field != "missing_reasons":
                statuses[field] = "review_corrected"
        changed["field_status"] = statuses
        # Missing source fields corrected by the user retain explicit correction
        # lineage; they get no invented source locator. Typed validation permits
        # that field only as user_corrected with an old/null source anchor.
        for field in patch:
            if field in {"unit_raw", "specimen", "method", "device", "lab_flag_raw", "clinical_time", "reference_intervals"} and changed.get("field_anchors", {}).get(field) is None:
                changed.setdefault("field_anchors", {})[field] = None
        return lab_observation(changed, version["version_id"], version["source_sha256"], correction=True)

    def _confirmable(self, row: dict) -> None:
        require(row["result"]["kind"] != "text_unparsed", "unresolved_result", "Unparsed text cannot be confirmed as a fully typed laboratory result")
        require(row["result"]["kind"] != "no_result" or bool(row["result"]["raw"].strip()),
                "unresolved_result", "A blank source cell cannot prove an explicit no-result conclusion")
        require(not any(state == "ambiguous" for state in row.get("field_status", {}).values()), "unresolved_field", "Ambiguous typed fields must be corrected or deferred")
        require(not any(state == "ambiguous" for state in row.get("missing_reasons", {}).values()), "unresolved_field", "Ambiguous missing fields must be resolved or deferred")
        require(row["mapping_status"] != "ambiguous", "unresolved_mapping", "Ambiguous mapping must remain deferred or be resolved")

    def commit_review(self, subject_id: str, snapshot_id: str, snapshot_sha256: str,
                      decisions: list[dict], conversation_attestation: dict | None = None,
                      idempotency_key: str = "", operation_context: str = "mcp") -> dict:
        self._subject(subject_id)
        request = {"snapshot_id": snapshot_id, "snapshot_sha256": snapshot_sha256, "decisions": decisions, "conversation_attestation": conversation_attestation, "operation_context": operation_context}
        with self.store.transaction():
            idem_id, prior = self._idempotency(subject_id, "commit_review", idempotency_key, request)
            if prior is not None:
                return prior
            snapshot = self.store.get("review_snapshot", snapshot_id, subject_id)
            require(snapshot["snapshot_sha256"] == snapshot_sha256, "snapshot_hash_mismatch", "Displayed review snapshot hash differs")
            snapshot_body = {k: v for k, v in snapshot.items() if k != "snapshot_sha256"}
            require(digest(snapshot_body) == snapshot_sha256, "snapshot_hash_mismatch", "Frozen review snapshot is inconsistent")
            require(isinstance(decisions, list) and 0 < len(decisions) <= self.MAX_REVIEW_ROWS, "invalid_decisions", "Review needs 1–100 decisions")
            displayed = {row["draft_id"]: row for row in snapshot["rows"]}
            used = set()
            prepared = []
            for decision in decisions:
                require(isinstance(decision, dict) and set(decision) <= {"draft_id", "action", "patch", "reason"}, "invalid_decision", "Unexpected decision or assurance fields")
                draft_id = decision.get("draft_id")
                require(draft_id in displayed and draft_id not in used, "unshown_row", "Each decision must name one shown row exactly once")
                used.add(draft_id)
                action = decision.get("action")
                require(action in {*CONFIRM_ACTIONS, "reject", "defer"}, "invalid_decision", "Unknown review action")
                draft = displayed[draft_id]
                row = draft["row"]
                if action == "correct_and_confirm":
                    row = self._patch_row(row, decision.get("patch"), self._version(subject_id, snapshot["version_id"]))
                    text(decision.get("reason"), "correction reason", maximum=2000)
                else:
                    require("patch" not in decision, "invalid_decision", "Only correct_and_confirm may contain a patch")
                if action in CONFIRM_ACTIONS:
                    self._confirmable(row)
                if decision.get("reason") is not None:
                    text(decision["reason"], "decision reason", maximum=2000)
                prepared.append((decision, draft, row))
            assurance, evidence = self._attestation(conversation_attestation, snapshot_id, snapshot_sha256, operation_context)
            current_run = self._latest_run(subject_id, snapshot["version_id"])
            require(current_run["run_id"] == snapshot["run_id"], "stale_extraction", "A new extraction was created after this preview")
            require(snapshot.get("selection_token") == current_run["selection_token"] if "selection_token" in snapshot else current_run["selection_sequence"] == 0,
                    "stale_extraction", "The selected extraction changed after this preview, including a return to an earlier run")
            tokens = self._review_tokens(subject_id)
            latest = self._latest_revisions(subject_id)
            for draft_id in snapshot["displayed_draft_ids"]:
                require(tokens.get(draft_id) == snapshot["review_tokens"][draft_id], "stale_review", "A displayed row was reviewed after this preview")
            for observation_id, revision_id in snapshot["observation_tokens"].items():
                require(latest.get(observation_id, {}).get("revision_id") == revision_id, "stale_review", "An observation changed after this preview")
            version = self._version(subject_id, snapshot["version_id"])
            self._check_source(version)
            event_id = new_id("review")
            now = utc_now()
            revision_ids = []
            for decision, draft, row in prepared:
                if decision["action"] not in CONFIRM_ACTIONS:
                    continue
                previous = latest.get(draft["observation_id"])
                revision_id = new_id("revision")
                revision = {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "observation_id": draft["observation_id"], "revision_id": revision_id, "supersedes_revision_id": previous["revision_id"] if previous else None, "source_version_id": version["version_id"], "source_sha256": version["source_sha256"], "extraction_run_id": draft["extraction_run_id"], "draft_id": draft["draft_id"], "row": row, "decision": "corrected" if decision["action"] == "correct_and_confirm" else "accepted", "review_status": "user_confirmed" if assurance in TRUSTED_ASSURANCE else "model_checked", "confirmation_assurance": assurance, "review_event_id": event_id, "reason": decision.get("reason"), "recorded_at": now}
                self.store.put("observation_revision", revision_id, revision, subject_id)
                revision_ids.append(revision_id)
            event = {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "review_event_id": event_id, "snapshot_id": snapshot_id, "snapshot_sha256": snapshot_sha256, "displayed_draft_ids": snapshot["displayed_draft_ids"], "decisions": copy.deepcopy(decisions), "decisions_sha256": digest(decisions), "confirmation_assurance": assurance, "confirmation_evidence": evidence, "revision_ids": revision_ids, "recorded_at": now}
            self.store.put("review_event", event_id, event, subject_id)
            result = {"review_event_id": event_id, "revision_ids": revision_ids, "confirmation_assurance": assurance, "review_status": "user_confirmed" if assurance in TRUSTED_ASSURANCE else "model_checked", "coverage": self._coverage(subject_id, current_run), "recorded_at": now}
            self._put_idempotency(subject_id, idem_id, request, result)
            return result

    def correct_observation(self, subject_id: str, observation_id: str, patch: dict, reason: str,
                            conversation_attestation: dict | None = None,
                            idempotency_key: str = "") -> dict:
        self._subject(subject_id)
        text(reason, "correction reason", maximum=2000)
        request = {"observation_id": observation_id, "patch": patch, "reason": reason, "conversation_attestation": conversation_attestation}
        with self.store.transaction():
            idem_id, prior_result = self._idempotency(subject_id, "correct_observation", idempotency_key, request)
            if prior_result is not None:
                return prior_result
            previous = self._latest_revisions(subject_id).get(observation_id)
            require(previous is not None, "not_found", "Observation was not found in this subject")
            version = self._version(subject_id, previous["source_version_id"])
            self._check_source(version)
            row = self._patch_row(previous["row"], patch, version)
            self._confirmable(row)
            assurance, evidence = self._attestation(conversation_attestation, previous["revision_id"], digest(previous))
            event_id = new_id("correction")
            revision_id = new_id("revision")
            now = utc_now()
            revision = {**copy.deepcopy(previous), "revision_id": revision_id, "supersedes_revision_id": previous["revision_id"], "row": row, "decision": "corrected", "review_status": "user_confirmed" if assurance in TRUSTED_ASSURANCE else "model_checked", "confirmation_assurance": assurance, "review_event_id": event_id, "reason": reason, "recorded_at": now}
            self.store.put("observation_revision", revision_id, revision, subject_id)
            self.store.put("correction_event", event_id, {"subject_id": subject_id, "correction_event_id": event_id, "observation_id": observation_id, "previous_revision_id": previous["revision_id"], "revision_id": revision_id, "patch": copy.deepcopy(patch), "reason": reason, "confirmation_assurance": assurance, "confirmation_evidence": evidence, "recorded_at": now}, subject_id)
            result = {"revision": revision, "confirmation_context": {"snapshot_id": revision_id, "snapshot_sha256": digest(revision)}}
            self._put_idempotency(subject_id, idem_id, request, result)
            return result

    def set_document_relation(self, subject_id: str, version_id: str, relation: str,
                              target_version_id: str, reason: str,
                              conversation_attestation: dict | None = None) -> dict:
        source = self._version(subject_id, version_id)
        target = self._version(subject_id, target_version_id)
        require(version_id != target_version_id, "invalid_relation", "A source version cannot relate to itself")
        require(relation in {"duplicate_of", "supersedes", "alternate_rendition"}, "invalid_relation", "Unsupported document relation")
        text(reason, "relation reason", maximum=2000)
        assurance, evidence = self._attestation(conversation_attestation, version_id, digest(source))
        with self.store.transaction():
            if assurance in TRUSTED_ASSURANCE and relation in {"duplicate_of", "supersedes"}:
                # Direction: version supersedes target; version duplicate_of target.
                active = [r for r in self.store.list("document_relation", subject_id) if r["confirmation_assurance"] in TRUSTED_ASSURANCE and r["relation"] in {"duplicate_of", "supersedes"}]
                edges = [(r["version_id"] if r["relation"] == "duplicate_of" else r["target_version_id"], r["target_version_id"] if r["relation"] == "duplicate_of" else r["version_id"]) for r in active]
                edge = (version_id, target_version_id) if relation == "duplicate_of" else (target_version_id, version_id)
                frontier = [edge[1]]
                visited = set()
                while frontier:
                    node = frontier.pop()
                    require(node != edge[0], "relation_cycle", "Clinical relation would create a cycle")
                    if node in visited:
                        continue
                    visited.add(node)
                    frontier.extend(b for a, b in edges if a == node)
            event = {"subject_id": subject_id, "relation_id": new_id("relation"), "version_id": version_id, "target_version_id": target["version_id"], "relation": relation, "reason": reason, "confirmation_assurance": assurance, "confirmation_evidence": evidence, "recorded_at": utc_now()}
            self.store.put("document_relation", event["relation_id"], event, subject_id)
            return event

    def record_source_availability(self, subject_id: str, version_id: str, available: bool) -> dict:
        self._version(subject_id, version_id)
        require(isinstance(available, bool), "invalid_availability", "Availability must be boolean")
        event = {"subject_id": subject_id, "availability_id": new_id("availability"), "version_id": version_id, "available": available, "recorded_at": utc_now()}
        return self.store.put("source_availability", event["availability_id"], event, subject_id)

    def _availability(self, subject_id: str, version_id: str, as_of: str | None = None) -> dict:
        events = [p for p in self._list("source_availability", subject_id, as_of) if p["version_id"] == version_id]
        latest = events[-1] if events else None
        occurrences = [p for p in self._list("file_occurrence", subject_id, as_of) if p["version_id"] == version_id]
        return {"version_id": version_id, "status": "available" if latest and latest["available"] else "unavailable" if latest else "unknown", "checked_at": latest["recorded_at"] if latest else None, "occurrence_count": len(occurrences), "limitation": "not_a_live_filesystem_check" if latest is None else None}

    def _history_projection(self, subject_id: str, as_of: str | None = None) -> dict:
        revisions = self._list("observation_revision", subject_id, as_of)
        trusted_latest = {}
        untrusted_latest = {}
        for revision in revisions:
            target = trusted_latest if _is_trusted(revision) else untrusted_latest
            target[revision["observation_id"]] = revision
        current = list(trusted_latest.values())
        relations = self._list("document_relation", subject_id, as_of)
        deactivated: dict[str, dict] = {}
        for relation in relations:
            if relation["confirmation_assurance"] not in TRUSTED_ASSURANCE or relation["relation"] == "alternate_rendition":
                continue
            old = relation["version_id"] if relation["relation"] == "duplicate_of" else relation["target_version_id"]
            new = relation["target_version_id"] if relation["relation"] == "duplicate_of" else relation["version_id"]
            old_groups, new_groups = {}, {}
            for revision in current:
                key = (_identity(revision["row"]), _time_identity(revision["row"]["clinical_time"]))
                if revision["source_version_id"] == old:
                    old_groups.setdefault(key, []).append(revision)
                if revision["source_version_id"] == new:
                    new_groups.setdefault(key, []).append(revision)
            for key, old_members in old_groups.items():
                replacements = new_groups.get(key, [])
                # A document-level relation is insufficient to choose among
                # multiple real collections. Do not discard unmatched or
                # ambiguous rows under an analyte-only mapping.
                if len(old_members) == 1 and len(replacements) == 1:
                    revision, replacement = old_members[0], replacements[0]
                    deactivated[revision["revision_id"]] = {"reason": relation["relation"], "relation_id": relation["relation_id"], "replacing_revision_id": replacement["revision_id"]}
        eligible = [r for r in current if r["revision_id"] not in deactivated]
        current_ids = {r["revision_id"] for r in eligible}
        contextual = list(untrusted_latest.values())
        contextual_ids = {r["revision_id"] for r in contextual}
        historical = []
        for revision in revisions:
            if revision["revision_id"] in current_ids or revision["revision_id"] in contextual_ids:
                continue
            historical.append({**revision, "history_status": deactivated.get(revision["revision_id"], {}).get("reason", "revised"), "replacement": deactivated.get(revision["revision_id"])} )
        conflicts = self._source_conflicts(subject_id, eligible, relations, as_of)
        return {"current": eligible, "historical": historical, "contextual": contextual, "conflicts": conflicts, "relations": relations}

    def _source_conflicts(self, subject_id: str, current: list[dict], relations: list[dict], as_of: str | None) -> list[dict]:
        versions = {p["version_id"]: p for p in self._list("document_version", subject_id, as_of)}
        locations: dict[str, set[tuple[str, str]]] = {}
        for occurrence in self._list("file_occurrence", subject_id, as_of):
            locations.setdefault(occurrence["version_id"], set()).add((occurrence["root_id"], occurrence["relative_path"]))
        # Indexed candidate groups avoid an O(all history squared) scan.
        groups: dict[tuple, dict[str, dict]] = {}
        for revision in current:
            version_id = revision["source_version_id"]
            row_key = (_identity(revision["row"]), _time_identity(revision["row"]["clinical_time"]))
            bindings = [("document", versions[version_id]["document_id"])]
            bindings.extend(("file", *location) for location in locations.get(version_id, set()))
            for binding in bindings:
                groups.setdefault((binding, row_key), {})[revision["revision_id"]] = revision
        conflicts = []
        seen = set()
        for members in groups.values():
            by_version: dict[str, list[dict]] = {}
            for member in members.values():
                by_version.setdefault(member["source_version_id"], []).append(member)
            if len(by_version) < 2:
                continue
            version_ids = set(by_version)
            # Fully resolved direct pairs can leave unmatched rows; those still
            # need an explicit observation mapping, so are not silently dropped.
            ids = sorted(members)
            signature = tuple(ids)
            if signature in seen:
                continue
            seen.add(signature)
            conflicts.append({"revision_ids": ids, "source_version_ids": sorted(version_ids), "reason": "unresolved_source_version_relation", "effect": "all_visible_but_no_joint_arithmetic"})
        return conflicts

    def query_history(self, subject_id: str, clinical_interval: dict | None = None,
                      recorded_as_of: str | None = None, filters: dict | None = None) -> dict:
        self._subject(subject_id)
        if recorded_as_of is not None:
            iso_timestamp(recorded_as_of, "recorded_as_of")
        filters = filters or {}
        require(isinstance(filters, dict) and set(filters) <= {"analyte_key", "analyte_raw", "version_id", "observation_id", "include_contextual"}, "invalid_filter", "Unsupported history filter")
        interval = None
        if clinical_interval is not None:
            require(isinstance(clinical_interval, dict) and set(clinical_interval) <= {"start", "end"}, "invalid_interval", "Clinical interval accepts date start/end")
            try:
                start = date.fromisoformat(clinical_interval["start"])
                end = date.fromisoformat(clinical_interval["end"])
            except (ValueError, KeyError, TypeError) as exc:
                raise V2Error("invalid_interval", "Clinical interval needs valid ISO dates") from exc
            require(start <= end, "invalid_interval", "Clinical interval is reversed")
            interval = (start.isoformat(), end.isoformat())
        projection = self._history_projection(subject_id, recorded_as_of)
        excluded_unknown_time = []
        def selected(revision: dict) -> bool:
            row = revision["row"]
            for key in ("analyte_key", "analyte_raw"):
                if filters.get(key) is not None and row.get(key) != filters[key]:
                    return False
            if filters.get("version_id") is not None and revision["source_version_id"] != filters["version_id"]:
                return False
            if filters.get("observation_id") is not None and revision["observation_id"] != filters["observation_id"]:
                return False
            if interval:
                bounds = _clinical_bounds(row["clinical_time"])
                if bounds is None:
                    excluded_unknown_time.append(revision["revision_id"])
                    return False
                if bounds[1] < interval[0] or bounds[0] > interval[1]:
                    return False
            return True
        result = {}
        for category in ("current", "historical", "contextual"):
            if category == "contextual" and filters.get("include_contextual") is False:
                result[category] = []
                continue
            items = [copy.deepcopy(r) for r in projection[category] if selected(r)]
            items.sort(key=lambda r: (_clinical_bounds(r["row"]["clinical_time"]) or ("9999-99-99", "9999-99-99"), r["recorded_at"], r["revision_id"]))
            for item in items:
                item["source_availability"] = self._availability(subject_id, item["source_version_id"], recorded_as_of)
                item["strict_time_eligible"] = _strict_time(item["row"], trusted=_is_trusted(item))
                item["confirmation_context"] = {"snapshot_id": item["revision_id"], "snapshot_sha256": digest({k: v for k, v in item.items() if k not in {"source_availability", "strict_time_eligible", "history_status", "replacement"}})}
            result[category] = items
        selected_ids = {r["revision_id"] for category in ("current", "historical", "contextual") for r in result[category]}
        coverage = [self._coverage(subject_id, run, recorded_as_of) for run in self._list("extraction_run", subject_id, recorded_as_of)]
        return {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "clinical_interval": clinical_interval, "recorded_as_of": recorded_as_of, **result, "unknown_time_excluded_from_interval": sorted(set(excluded_unknown_time)), "conflicts": [c for c in projection["conflicts"] if selected_ids & set(c["revision_ids"])], "coverage": coverage, "relations": projection["relations"], "context_events": self._list("context_event", subject_id, recorded_as_of), "absence_limitation": "No saved row does not establish that a test was not performed"}

    def compare_observations(self, subject_id: str, revision_ids: list[str], mode: str = "auto") -> dict:
        self._subject(subject_id)
        require(isinstance(revision_ids, list) and 1 <= len(revision_ids) <= 100 and len(set(revision_ids)) == len(revision_ids), "comparison_limit", "Comparison needs 1–100 distinct revision IDs")
        require(mode in {"auto", "strict", "contextual"}, "invalid_mode", "Unsupported comparison mode")
        revisions = [self.store.get("observation_revision", rid, subject_id) for rid in revision_ids]
        projection = self._history_projection(subject_id)
        current_ids = {r["revision_id"] for r in projection["current"]}
        conflict_ids = {rid for c in projection["conflicts"] for rid in c["revision_ids"]}
        included, contextual, excluded = [], [], []
        first_row = revisions[0]["row"]
        first_trusted = _is_trusted(revisions[0])
        for revision in revisions:
            row = revision["row"]
            trusted = _is_trusted(revision)
            contextual_reasons = []
            excluded_reasons = []
            if not _is_trusted(revision):
                contextual_reasons.append("not_user_confirmed")
            if _is_trusted(revision) and revision["revision_id"] not in current_ids:
                excluded_reasons.append("historical_or_clinically_replaced")
            if revision["revision_id"] in conflict_ids:
                contextual_reasons.append("unresolved_source_version_relation")
            if not _strict_time(row, trusted=trusted):
                contextual_reasons.append("clinical_time_not_exact_collection_or_performance")
            if not _field_known(row, "analyte_key", trusted=trusted) or row["mapping_status"] != "confirmed":
                contextual_reasons.append("analyte_identity_not_confirmed")
            if first_row.get("analyte_key") and row.get("analyte_key") and first_row["analyte_key"] != row["analyte_key"]:
                excluded_reasons.append("different_analyte")
            for field in ("measurement_property", "subtype"):
                a, b = first_row.get(field), row.get(field)
                if a is not None and b is not None and a != b:
                    excluded_reasons.append("different_" + field)
                elif (a is None) != (b is None):
                    contextual_reasons.append(field + "_unknown")
            for field in ("specimen", "method"):
                a, b = first_row.get(field), row.get(field)
                if not _field_known(first_row, field, trusted=first_trusted) or not _field_known(row, field, trusted=trusted):
                    contextual_reasons.append(field + "_unknown")
                elif a != b:
                    excluded_reasons.append("different_" + field)
            if not _field_known(row, "unit_raw", trusted=trusted) or not _field_known(first_row, "unit_raw", trusted=first_trusted):
                if row["result"]["kind"] in {"numeric_exact", "numeric_censored"}:
                    contextual_reasons.append("unit_unknown")
            elif row["unit_raw"] != first_row["unit_raw"]:
                excluded_reasons.append("unit_conversion_rule_not_supported")
            numeric_kinds = {"numeric_exact", "numeric_censored"}
            if ((first_row["result"]["kind"] in numeric_kinds) != (row["result"]["kind"] in numeric_kinds)) or (first_row["result"]["kind"] not in numeric_kinds and row["result"]["kind"] != first_row["result"]["kind"]):
                excluded_reasons.append("different_result_scale")
            if row["result"]["kind"] == "no_result":
                excluded_reasons.append("no_result:" + row["result"]["reason"])
            elif row["result"]["kind"] == "text_unparsed":
                excluded_reasons.append("result_unparsed")
            if mode == "contextual":
                contextual_reasons.append("contextual_mode_requested")
            item = {"revision_id": revision["revision_id"], "observation_id": revision["observation_id"], "row": row, "source_availability": self._availability(subject_id, revision["source_version_id"]), "confirmation_assurance": revision["confirmation_assurance"]}
            if excluded_reasons:
                excluded.append({**item, "reasons": sorted(set(excluded_reasons))})
            elif contextual_reasons:
                contextual.append({**item, "reasons": sorted(set(contextual_reasons))})
            else:
                included.append(item)
        included, clinical_order = _comparison_order(included)
        arithmetic = {"status": "not_computable", "reason": "need_two_comparable_exact_numeric_results", "policy": "exact_same_units_only/1; Decimal, no censored imputation", "derived": []}
        if len(included) >= 2 and not contextual and not excluded and clinical_order["status"] != "established":
            arithmetic["reason"] = "clinical_order_ambiguous"
            arithmetic["clinical_order_reason"] = clinical_order["reason"]
        if len(included) >= 2 and not contextual and not excluded and clinical_order["status"] == "established":
            baseline, last = included[0], included[-1]
            if all(item["row"]["result"]["kind"] == "numeric_exact" for item in included):
                with localcontext() as context:
                    context.prec = 512  # Exact subtraction for bounded 128-character inputs.
                    context.rounding = ROUND_HALF_EVEN
                    a = Decimal(baseline["row"]["result"]["decimal"])
                    b = Decimal(last["row"]["result"]["decimal"])
                    delta = b - a
                    context.prec = 50
                    percent = None if a == 0 else (delta / a) * Decimal(100)
                arithmetic = {"status": "computed", "rule": "exact_same_units/1", "baseline_revision_id": baseline["revision_id"], "last_revision_id": last["revision_id"], "delta": str(delta), "percent_change": {"status": "not_computable", "reason": "zero_baseline"} if a == 0 else {"status": "computed", "decimal": str(percent), "denominator": str(a)}, "formula": "delta=last-baseline; percent=(last-baseline)/baseline*100", "rounding_policy": "Delta exact for bounded inputs; percent Decimal precision 50 ROUND_HALF_EVEN; no further display rounding", "unit_raw": baseline["row"]["unit_raw"], "time_interval": {"start": baseline["row"]["clinical_time"], "end": last["row"]["clinical_time"]}}
            elif any(item["row"]["result"]["kind"] == "numeric_censored" for item in included):
                arithmetic["reason"] = "censored_values_are_bounds_not_exact_numbers"
            else:
                arithmetic["reason"] = "qualitative_or_semiquantitative_values_have_no_numeric_delta"
        category = "comparable" if included and not contextual and not excluded else "not_comparable" if excluded and not included and not contextual else "contextual_only"
        return {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "mode": mode, "comparison_status": category, "included": included, "contextual_only": contextual, "excluded_with_reasons": excluded, "clinical_order": clinical_order, "arithmetic": arithmetic, "coverage": self.query_history(subject_id)["coverage"], "absence_limitation": "No saved row does not establish that a test was not performed", "conversion_policy": {"version": "exact_same_units/1", "supported": "identical original unit strings", "unsupported": "unit conversions including mass-to-molar; no implicit coefficients"}}

    def select_case_context(self, subject_id: str, selector: dict | None = None,
                            recorded_as_of: str | None = None) -> dict:
        # Freeze rows, availability and selected context in the same committed
        # state as the new immutable case, rather than between concurrent reads.
        with self.store.transaction():
            return self._select_case_context(subject_id, selector, recorded_as_of)

    def _select_case_context(self, subject_id: str, selector: dict | None,
                             recorded_as_of: str | None) -> dict:
        selector = selector or {}
        require(isinstance(selector, dict) and set(selector) <= {"revision_ids", "analyte_keys", "context_event_ids", "limit"}, "invalid_selector", "Unsupported case selector")
        limit = selector.get("limit", 50)
        require(isinstance(limit, int) and not isinstance(limit, bool) and 1 <= limit <= 100, "case_limit", "Case selection is limited to 100 records")
        history = self.query_history(subject_id, recorded_as_of=recorded_as_of)
        rows = history["current"]
        if selector.get("revision_ids") is not None:
            ids = selector["revision_ids"]
            require(isinstance(ids, list) and len(ids) <= 100 and all(isinstance(i, str) for i in ids) and len(ids) == len(set(ids)), "invalid_selector", "Revision IDs must be a bounded distinct list")
            known = {r["revision_id"] for r in rows}
            require(set(ids) <= known, "case_not_current", "Case selection only accepts current user-confirmed revisions of this subject")
            rows = [r for r in rows if r["revision_id"] in ids]
        if selector.get("analyte_keys") is not None:
            keys = selector["analyte_keys"]
            require(isinstance(keys, list) and len(keys) <= 100 and all(isinstance(k, str) and 0 < len(k) <= 200 for k in keys) and len(keys) == len(set(keys)), "invalid_selector", "Analyte keys must be a bounded distinct list")
            rows = [r for r in rows if r["row"].get("analyte_key") in keys]
        chosen = rows[-limit:]
        events = history["context_events"]
        if selector.get("context_event_ids") is not None:
            ids = selector["context_event_ids"]
            require(isinstance(ids, list) and len(ids) <= 100 and all(isinstance(i, str) for i in ids) and len(ids) == len(set(ids)) and set(ids) <= {e["context_event_id"] for e in events}, "invalid_selector", "Distinct context events must belong to this subject")
            events = [event for event in events if event["context_event_id"] in ids]
        else:
            events = []  # Minimize context; notes are never silently attached.
        from .private_cases import selected_conflicts
        selected_ids = {r["revision_id"] for r in chosen}
        selected_runs = {r["extraction_run_id"] for r in chosen}
        payload = {"schema_version": "health-analyzer.case-selection/2.0", "subject_id": subject_id, "selection_id": new_id("case"), "recorded_as_of": recorded_as_of, "selector": selector, "revision_ids": [r["revision_id"] for r in chosen], "observations": [{"revision_id": r["revision_id"], "observation_id": r["observation_id"], "row": r["row"], "confirmation_assurance": r["confirmation_assurance"], "source_version_id": r["source_version_id"], "source_availability": r["source_availability"]} for r in chosen], "context_events": events, "conflicts": selected_conflicts(history["conflicts"], selected_ids), "coverage": [c for c in history["coverage"] if c.get("run_id") in selected_runs], "truncated": len(rows) > limit, "recorded_at": utc_now(), "boundary": "private; do not forward this packet to public-research"}
        payload["selection_sha256"] = digest(payload)
        return self.store.put("case_selection", payload["selection_id"], payload, subject_id)

    def get_case_selection(self, subject_id: str, selection_id: str, selection_sha256: str) -> dict:
        """Read verified selected context and separate freshness; never refresh source files."""
        from .private_cases import resolve_case
        verified = resolve_case(self, subject_id, selection_id, selection_sha256, require_current=False)
        return {"context": verified["minimal_context"], "freshness": verified["freshness"],
                "verification": "schema, exact selected graph and immutable confirmation lineage",
                "semantic_validation": "not_provided", "medical_validation": "not_provided"}

    def record_context_event(self, subject_id: str, event: dict) -> dict:
        self._subject(subject_id)
        allowed = {"kind", "event_type", "text", "effective_time", "fields", "source_version_id", "field_anchors"}
        require(isinstance(event, dict) and set(event) <= allowed, "invalid_context_event", "Unexpected context event or caller assurance fields")
        require(event.get("kind") in {"user_note", "source_statement"}, "invalid_context_event", "Context origin must distinguish user note from source statement")
        identifier(event.get("event_type"), "event_type")
        text(event.get("text"), "context text", maximum=8000)
        event = copy.deepcopy(event)
        event["effective_time"] = clinical_time(event.get("effective_time", {"raw": None, "role": "unknown", "precision": "unknown", "value": None}))
        fields = event.get("fields", {})
        require(isinstance(fields, dict) and len(canonical(fields)) <= 8000, "invalid_context_event", "Context fields must be bounded JSON")
        if event["kind"] == "source_statement":
            version = self._version(subject_id, event.get("source_version_id"))
            anchors = event.get("field_anchors")
            require(isinstance(anchors, dict) and anchors.get("text") is not None, "missing_provenance", "Source statement needs a text anchor")
            event["field_anchors"] = {field: anchor(item, field, version["version_id"], version["source_sha256"]) for field, item in anchors.items()}
        else:
            require(event.get("source_version_id") is None and not event.get("field_anchors"), "invalid_context_event", "A user note must not be represented as a document fact")
        payload = {"schema_version": SCHEMA_VERSION, "subject_id": subject_id, "context_event_id": new_id("context"), **event, "recorded_at": utc_now(), "fact_status": "user_note" if event["kind"] == "user_note" else "unreviewed_source_statement"}
        return self.store.put("context_event", payload["context_event_id"], payload, subject_id)

    def export_history(self, subject_id: str, format: str = "json", recorded_as_of: str | None = None) -> dict:
        history = self.query_history(subject_id, recorded_as_of=recorded_as_of)
        require(format in {"json", "csv"}, "invalid_export", "Export format must be json or csv")
        if format == "json":
            kinds = ("subject", "document", "document_version", "file_occurrence", "extraction_run", "panel", "observation_draft", "observation_revision", "review_snapshot", "review_event", "correction_event", "document_relation", "source_availability", "context_event", "case_selection")
            return {"schema_version": "health-analyzer.history-export/2.0", "subject_id": subject_id, "recorded_as_of": recorded_as_of, "history": history, "objects": {kind: self._list(kind, subject_id, recorded_as_of) for kind in kinds}, "limitation": "Domain-scoped payload export; not a recovery bundle with signing keys or source bytes"}
        buffer = io.StringIO(newline="")
        fields = ["revision_id", "observation_id", "status", "analyte_raw", "analyte_key", "result_kind", "result_raw", "decimal", "operator", "unit_raw", "clinical_time_role", "clinical_time_precision", "clinical_time_value", "specimen", "method", "confirmation_assurance", "source_version_id", "recorded_at"]
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writeheader()
        # Prefix spreadsheet formulas. Exact raw text remains in JSON export.
        def safe(value):
            return "'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else value
        for status in ("current", "historical", "contextual"):
            for revision in history[status]:
                row, scalar, time = revision["row"], revision["row"]["result"], revision["row"]["clinical_time"]
                projected = {"revision_id": revision["revision_id"], "observation_id": revision["observation_id"], "status": status, "analyte_raw": row["analyte_raw"], "analyte_key": row.get("analyte_key"), "result_kind": scalar["kind"], "result_raw": scalar["raw"], "decimal": scalar.get("decimal"), "operator": scalar.get("operator"), "unit_raw": row["unit_raw"], "clinical_time_role": time["role"], "clinical_time_precision": time["precision"], "clinical_time_value": time.get("value"), "specimen": row.get("specimen"), "method": row.get("method"), "confirmation_assurance": revision["confirmation_assurance"], "source_version_id": revision["source_version_id"], "recorded_at": revision["recorded_at"]}
                writer.writerow({key: safe(value) for key, value in projected.items()})
        return {"schema_version": "health-analyzer.history-csv/2.0", "subject_id": subject_id, "csv": buffer.getvalue(), "limitation": "Table projection omits anchors, references, revisions and full lineage; leading formula characters escaped; JSON preserves exact raw text"}
