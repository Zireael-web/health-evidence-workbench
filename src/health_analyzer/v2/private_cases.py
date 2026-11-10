"""Private stored-case lineage, without source-file I/O or assurance upgrades."""
from __future__ import annotations

import copy
from typing import Callable

from .common import V2Error, canonical, digest, require
from .contracts import SCHEMA_VERSION, SHA256_RE, anchor, clinical_time, extraction_coverage, identifier, iso_timestamp, lab_observation, text
from .records import RecordsService, TRUSTED_ASSURANCE

CASE_SCHEMA = "health-analyzer.case-selection/2.0"
CASE_FIELDS = {"schema_version", "subject_id", "selection_id", "selection_sha256",
               "recorded_as_of", "selector", "revision_ids", "observations", "context_events",
               "conflicts", "coverage", "truncated", "recorded_at", "boundary"}
MAX_LINEAGE_OBJECTS = 10000
MAX_CORRECTION_DEPTH = 256
COVERAGE_INPUT_FIELDS = {"status", "expected_count", "expected_count_basis", "processed_pages", "unprocessed_pages",
                         "errors", "method", "model", "provider", "extractor_version"}
COVERAGE_EXTRA_FIELDS = {"known_extracted_rows", "reviewed", "rejected", "deferred", "unreviewed", "run_id", "version_id", "absence_means"}


def _selector(value: dict, ids: list[str], rows: list[dict], contexts: list[dict]) -> None:
    require(isinstance(value, dict) and set(value) <= {"revision_ids", "analyte_keys", "context_event_ids", "limit"},
            "case_selection_schema", "Case selector has unsupported fields")
    limit = value.get("limit", 50)
    require(type(limit) is int and 1 <= limit <= 100 and len(ids) <= limit,
            "case_selection_limit", "Case selector limit must be a bounded integer")
    for field in ("revision_ids", "analyte_keys", "context_event_ids"):
        given = value.get(field)
        if given is None: continue
        require(isinstance(given, list) and len(given) <= 100
                and all(isinstance(i, str) and 0 < len(i) <= 200 for i in given)
                and len(given) == len(set(given)), "case_selection_schema", "Selector IDs must be distinct bounded strings")
    if value.get("revision_ids") is not None:
        require(set(ids) <= set(value["revision_ids"]), "case_selection_revision_mismatch", "Frozen revisions differ from selector")
    if value.get("analyte_keys") is not None:
        require(all(r.get("row", {}).get("analyte_key") in value["analyte_keys"] for r in rows),
                "case_selection_revision_mismatch", "Frozen analytes differ from selector")
    actual_notes = [c.get("context_event_id") for c in contexts if isinstance(c, dict)]
    expected_notes = value.get("context_event_ids")
    require((not actual_notes if expected_notes is None else set(actual_notes) == set(expected_notes)),
            "case_selection_snapshot_mismatch", "Notes must be exactly explicitly selected")


def _availability(value: dict, version_id: str) -> None:
    require(isinstance(value, dict) and set(value) == {"version_id", "status", "checked_at", "occurrence_count", "limitation"}
            and value["version_id"] == version_id and value["status"] in {"available", "unavailable", "unknown"}
            and type(value["occurrence_count"]) is int and value["occurrence_count"] >= 0,
            "case_selection_source_mismatch", "Availability is a typed cached source snapshot, not an assurance flag")
    if value["status"] == "unknown":
        require(value["checked_at"] is None and value["limitation"] == "not_a_live_filesystem_check",
                "case_selection_source_mismatch", "Unknown availability must retain its limitation")
    else:
        iso_timestamp(value["checked_at"], "availability checked_at")
        require(value["limitation"] is None, "case_selection_source_mismatch", "Unexpected cached availability limitation")


def selected_conflicts(conflicts: list[dict], revision_ids: set[str]) -> list[dict]:
    """Expose a blocking selected edge without unrelated row/source details."""
    require(isinstance(conflicts, list), "case_selection_schema", "Conflicts must be a list")
    result = []
    for item in conflicts:
        require(isinstance(item, dict) and isinstance(item.get("revision_ids"), list),
                "case_selection_schema", "Conflict needs revision identities")
        ids = item["revision_ids"]
        require(all(isinstance(i, str) for i in ids), "case_selection_schema", "Conflict identities must be strings")
        chosen = sorted(revision_ids.intersection(ids))
        if chosen:
            result.append({"revision_ids": chosen,
                           "has_unselected_members": bool(set(ids) - revision_ids) or bool(item.get("has_unselected_members", False)),
                           "reason": item.get("reason", "unresolved_source_version_relation")})
    return sorted(result, key=digest)


def validate_case_snapshot(selection: dict, lookup: Callable[[str, str, str], dict]) -> dict:
    """Validate an immutable graph. This does not claim present-day freshness.

    Lookup is a trusted internal signed-store or authenticated recovery-graph
    reader. No caller supplies replacement revisions, evidence or assurance.
    """
    require(isinstance(selection, dict) and set(selection) == CASE_FIELDS,
            "case_selection_schema", "Stored case has an unsupported shape")
    require(selection["schema_version"] == CASE_SCHEMA, "case_selection_schema", "Unsupported case schema")
    subject = identifier(selection["subject_id"], "subject_id")
    case_id = identifier(selection["selection_id"], "selection_id")
    body_hash = selection["selection_sha256"]
    require(isinstance(body_hash, str) and SHA256_RE.fullmatch(body_hash) is not None
            and digest({k: v for k, v in selection.items() if k != "selection_sha256"}) == body_hash,
            "case_selection_hash_mismatch", "Stored case body differs from its snapshot hash")
    require(len(canonical(selection)) <= 2 * 1024 * 1024,
            "case_selection_limit", "Case exceeds the bounded object size")
    iso_timestamp(selection["recorded_at"], "case recorded_at")
    if selection["recorded_as_of"] is not None:
        iso_timestamp(selection["recorded_as_of"], "case recorded_as_of")
    require(isinstance(selection["selector"], dict) and type(selection["truncated"]) is bool
            and isinstance(selection["boundary"], str) and isinstance(selection["coverage"], list),
            "case_selection_schema", "Case metadata has invalid primitive types")
    ids, rows, contexts = selection["revision_ids"], selection["observations"], selection["context_events"]
    require(isinstance(ids, list) and len(ids) <= 100 and all(isinstance(i, str) for i in ids)
            and len(ids) == len(set(ids)) and isinstance(rows, list) and len(rows) == len(ids),
            "case_selection_revision_mismatch", "Case needs distinct exact selected revisions")
    require(isinstance(contexts, list) and len(contexts) <= 100,
            "case_selection_limit", "Selected context exceeds its limit")
    _selector(selection["selector"], ids, rows, contexts)
    cache: dict[tuple[str, str], dict] = {}

    def get(kind: str, object_id: str, id_field: str, *, schema: bool = True) -> dict:
        identifier(object_id, id_field)
        key = (kind, object_id)
        if key not in cache:
            require(len(cache) < MAX_LINEAGE_OBJECTS, "case_lineage_limit", "Case lineage exceeds its bounded inventory")
            value = lookup(kind, object_id, subject)
            require(isinstance(value, dict) and value.get("subject_id") == subject
                    and value.get(id_field) == object_id,
                    "case_selection_scope_mismatch", "Stored payload differs from its exact identity/scope")
            if schema:
                require(value.get("schema_version") == SCHEMA_VERSION,
                        "case_selection_schema", "Unsupported referenced object schema")
            cache[key] = copy.deepcopy(value)
        return cache[key]

    get("subject", subject, "subject_id")
    bindings: dict[str, dict] = {}
    revisions: dict[str, dict] = {}
    active: set[str] = set()

    def evidence(assurance: str, supplied: dict | None, target: str, target_hash: str) -> None:
        # This adapter does not authenticate a human. It verifies only the
        # exact attribution shape that the production record service issued.
        if assurance == "none":
            require(supplied is None, "case_selection_assurance_mismatch", "Model-only ancestry cannot invent attributed evidence")
            return
        require(assurance == "conversation_attested" and isinstance(supplied, dict),
                "case_selection_assurance_mismatch", "Selected revision lacks supported attributed evidence")
        raw = {k: v for k, v in supplied.items() if k not in {"authentication", "trust_basis"}}
        actual, expected = RecordsService._attestation(None, raw, target, target_hash)
        require(actual == assurance and expected == supplied,
                "case_selection_assurance_mismatch", "Stored attribution differs from its immutable target")

    def revision(revision_id: str, depth: int = 0) -> dict:
        if revision_id in bindings:
            return revisions[revision_id]
        require(depth <= MAX_CORRECTION_DEPTH and revision_id not in active,
                "case_lineage_limit", "Revision ancestry is cyclic or exceeds its limit")
        active.add(revision_id)
        r = get("observation_revision", revision_id, "revision_id")
        require((r.get("confirmation_assurance"), r.get("review_status")) in {
                    ("conversation_attested", "user_confirmed"), ("none", "model_checked")},
                "case_untrusted_revision", "Stored revision assurance/status differ from their supported attribution")
        version = get("document_version", r.get("source_version_id"), "version_id")
        require(isinstance(version.get("source_sha256"), str) and SHA256_RE.fullmatch(version["source_sha256"]) is not None
                and r.get("source_sha256") == version.get("source_sha256"),
                "case_selection_source_mismatch", "Revision and source version hashes differ")
        get("document", version.get("document_id"), "document_id")
        normalized = lab_observation(r.get("row"), version["version_id"], version["source_sha256"], correction=True)
        require(normalized == r["row"], "case_selection_revision_mismatch", "Revision row contract differs")
        RecordsService._confirmable(None, r["row"])
        draft = get("observation_draft", r.get("draft_id"), "draft_id")
        require(draft.get("observation_id") == r.get("observation_id")
                and draft.get("source_version_id") == version["version_id"]
                and draft.get("source_sha256") == version["source_sha256"]
                and draft.get("extraction_run_id") == r.get("extraction_run_id"),
                "case_selection_revision_mismatch", "Revision differs from its source-bound draft")
        run = get("extraction_run", r.get("extraction_run_id"), "run_id")
        require(run.get("version_id") == version["version_id"] and run.get("source_sha256") == version["source_sha256"]
                and r["draft_id"] in run.get("draft_ids", []),
                "case_selection_source_mismatch", "Draft does not belong to its recorded extraction")
        event_id = r.get("review_event_id")
        require(isinstance(event_id, str), "case_selection_snapshot_mismatch", "Revision lacks a confirmation event")
        if event_id.startswith("review_"):
            event = get("review_event", event_id, "review_event_id")
            snapshot = get("review_snapshot", event.get("snapshot_id"), "snapshot_id")
            shash = snapshot.get("snapshot_sha256")
            require(isinstance(shash, str) and digest({k: v for k, v in snapshot.items() if k != "snapshot_sha256"}) == shash
                    and event.get("snapshot_sha256") == shash
                    and snapshot.get("version_id") == version["version_id"]
                    and snapshot.get("source_sha256") == version["source_sha256"]
                    and snapshot.get("run_id") == run["run_id"],
                    "case_selection_snapshot_mismatch", "Initial confirmation snapshot differs")
            shown = snapshot.get("displayed_draft_ids")
            snap_rows = snapshot.get("rows")
            require(isinstance(shown, list) and len(shown) <= 100 and len(shown) == len(set(shown))
                    and isinstance(snap_rows, list) and [d.get("draft_id") for d in snap_rows if isinstance(d, dict)] == shown
                    and r["draft_id"] in shown and event.get("displayed_draft_ids") == shown,
                    "case_selection_snapshot_mismatch", "Confirmed draft was not in the exact displayed snapshot")
            for item in snap_rows:
                require(item == get("observation_draft", item["draft_id"], "draft_id"),
                        "case_selection_snapshot_mismatch", "Frozen displayed row differs from its stored draft")
            decisions = event.get("decisions")
            require(isinstance(decisions, list) and digest(decisions) == event.get("decisions_sha256")
                    and len({d.get("draft_id") for d in decisions if isinstance(d, dict)}) == len(decisions)
                    and revision_id in event.get("revision_ids", []),
                    "case_selection_snapshot_mismatch", "Confirmation decision/record identities differ")
            for d in decisions:
                require(isinstance(d, dict) and set(d) <= {"draft_id", "action", "patch", "reason"}
                        and d.get("draft_id") in shown and d.get("action") in {"confirm", "correct_and_confirm", "reject", "defer"},
                        "case_selection_snapshot_mismatch", "Stored decision is not an exact displayed action")
                require((isinstance(d.get("patch"), dict) and bool(d["patch"])) if d["action"] == "correct_and_confirm" else "patch" not in d,
                        "case_selection_snapshot_mismatch", "Only corrected confirmation may contain a patch")
                if d.get("reason") is not None:
                    require(isinstance(d["reason"], str) and 0 < len(d["reason"]) <= 2000,
                            "case_selection_snapshot_mismatch", "Decision reason is bounded text")
            confirmed = [d for d in decisions if d["action"] in {"confirm", "correct_and_confirm"}]
            issued = event.get("revision_ids")
            require(isinstance(issued, list) and len(issued) == len(confirmed) and len(issued) == len(set(issued)),
                    "case_selection_snapshot_mismatch", "Review revisions must exactly match confirmed decisions")
            for d, issued_id in zip(confirmed, issued):
                issued_revision = get("observation_revision", issued_id, "revision_id")
                issued_draft = get("observation_draft", d["draft_id"], "draft_id")
                target_row = (RecordsService._patch_row(None, issued_draft["row"], d["patch"], version)
                              if d["action"] == "correct_and_confirm" else issued_draft["row"])
                require(issued_revision.get("draft_id") == d["draft_id"] and issued_revision.get("review_event_id") == event_id
                        and issued_revision.get("observation_id") == issued_draft.get("observation_id")
                        and issued_revision.get("source_version_id") == version["version_id"]
                        and issued_revision.get("source_sha256") == version["source_sha256"]
                        and issued_revision.get("extraction_run_id") == run["run_id"]
                        and issued_revision.get("confirmation_assurance") == event.get("confirmation_assurance")
                        and issued_revision.get("row") == target_row
                        and issued_revision.get("recorded_at") == event.get("recorded_at")
                        and issued_revision.get("supersedes_revision_id") == snapshot.get("observation_tokens", {}).get(issued_revision["observation_id"]),
                        "case_selection_snapshot_mismatch", "Review revision order/body differs from its exact decision")
            chosen = [d for d in decisions if d.get("draft_id") == r["draft_id"]]
            require(len(chosen) == 1 and chosen[0].get("action") in {"confirm", "correct_and_confirm"},
                    "case_selection_snapshot_mismatch", "Selected fact lacks its exact confirmed decision")
            decision = chosen[0]
            expected_row = (RecordsService._patch_row(None, draft["row"], decision.get("patch"), version)
                            if decision["action"] == "correct_and_confirm" else draft["row"])
            require(expected_row == r["row"] and event.get("confirmation_assurance") == r["confirmation_assurance"],
                    "case_selection_revision_mismatch", "Confirmed row/assurance differs from its decision")
            evidence(r["confirmation_assurance"], event.get("confirmation_evidence"), snapshot["snapshot_id"], shash)
            confirmation = {"kind": "review_event", "event_id": event_id, "event_sha256": digest(event),
                            "snapshot_id": snapshot["snapshot_id"], "snapshot_sha256": shash}
        elif event_id.startswith("correction_"):
            event = get("correction_event", event_id, "correction_event_id", schema=False)
            previous_id = r.get("supersedes_revision_id")
            require(event.get("revision_id") == revision_id and event.get("previous_revision_id") == previous_id
                    and event.get("observation_id") == r.get("observation_id")
                    and event.get("confirmation_assurance") == r["confirmation_assurance"],
                    "case_selection_snapshot_mismatch", "Correction event does not bind this exact revision")
            previous = revision(previous_id, depth + 1)
            require(previous["observation_id"] == r["observation_id"]
                    and previous["source_version_id"] == r["source_version_id"]
                    and previous["source_sha256"] == r["source_sha256"]
                    and RecordsService._patch_row(None, previous["row"], event.get("patch"), version) == r["row"],
                    "case_selection_revision_mismatch", "Correction changed its origin or differs from its patch")
            evidence(r["confirmation_assurance"], event.get("confirmation_evidence"), previous_id, digest(previous))
            confirmation = {"kind": "correction_event", "event_id": event_id, "event_sha256": digest(event),
                            "previous_revision_id": previous_id, "previous_revision_sha256": digest(previous),
                            "previous_confirmation_binding": bindings[previous_id]["confirmation_binding"]}
        else:
            raise V2Error("case_selection_snapshot_mismatch", "Unsupported confirmation event kind")
        if r.get("supersedes_revision_id") and not event_id.startswith("correction_"):
            previous = revision(r["supersedes_revision_id"], depth + 1)
            require(previous.get("observation_id") == r.get("observation_id"),
                    "case_selection_revision_mismatch", "Superseded revision belongs to another observation")
            confirmation.update(supersedes_revision_id=previous["revision_id"],
                                supersedes_revision_sha256=digest(previous),
                                previous_confirmation_binding=copy.deepcopy(bindings[previous["revision_id"]]["confirmation_binding"]))
        confirmation["confirmation_assurance"] = r["confirmation_assurance"]
        confirmation["review_status"] = r["review_status"]
        active.remove(revision_id)
        revisions[revision_id] = r
        bindings[revision_id] = {"object_kind": "observation_revision", "revision_id": revision_id,
                                "revision_sha256": digest(r), "row_sha256": digest(r["row"]),
                                "source_version_id": version["version_id"], "source_sha256": version["source_sha256"],
                                "confirmation_assurance": r["confirmation_assurance"],
                                "confirmation_binding": confirmation,
                                "field_origin": copy.deepcopy(r["row"].get("field_status", {}))}
        return r

    observations = {}
    expected_projection = {"revision_id", "observation_id", "row", "confirmation_assurance", "source_version_id", "source_availability"}
    for rid, selected in zip(ids, rows):
        require(isinstance(selected, dict) and set(selected) == expected_projection and selected["revision_id"] == rid,
                "case_selection_revision_mismatch", "Case observation identities/order differ")
        r = revision(rid)
        require(r["confirmation_assurance"] in TRUSTED_ASSURANCE and r["review_status"] == "user_confirmed",
                "case_untrusted_revision", "Selected factual support cannot promote a model-only ancestor")
        require(all(selected[k] == r[k] for k in ("revision_id", "observation_id", "row", "confirmation_assurance", "source_version_id")),
                "case_selection_revision_mismatch", "Frozen observation differs from its authoritative revision")
        _availability(selected["source_availability"], r["source_version_id"])
        observations[rid] = copy.deepcopy(r)
    selected_context = {}
    for event in contexts:
        require(isinstance(event, dict) and isinstance(event.get("context_event_id"), str)
                and event["context_event_id"] not in selected_context,
                "case_selection_schema", "Context identities must be distinct")
        stored = get("context_event", event["context_event_id"], "context_event_id")
        require(stored == event, "case_selection_snapshot_mismatch", "Selected context differs from stored event")
        require((stored.get("kind"), stored.get("fact_status")) in {
            ("user_note", "user_note"), ("source_statement", "unreviewed_source_statement")},
            "case_selection_schema", "Context kind cannot upgrade its fact status")
        require(set(stored) <= {"schema_version", "subject_id", "context_event_id", "kind", "event_type", "text", "effective_time", "fields", "source_version_id", "field_anchors", "recorded_at", "fact_status"}
                and isinstance(stored.get("fields", {}), dict) and len(canonical(stored.get("fields", {}))) <= 8000,
                "case_selection_schema", "Context has unsupported fields or bounded-data contract")
        identifier(stored.get("event_type"), "context event_type")
        text(stored.get("text"), "context text", maximum=8000)
        require(clinical_time(stored.get("effective_time")) == stored["effective_time"],
                "case_selection_schema", "Context time differs from its declared precision")
        iso_timestamp(stored["recorded_at"], "context recorded_at")
        if stored["kind"] == "user_note":
            require(stored.get("source_version_id") is None and not stored.get("field_anchors"),
                    "case_selection_source_mismatch", "User note cannot masquerade as a document source")
        else:
            version = get("document_version", stored.get("source_version_id"), "version_id")
            anchors = stored.get("field_anchors")
            require(isinstance(anchors, dict) and anchors.get("text") is not None,
                    "case_selection_source_mismatch", "Unreviewed source statement still needs exact source scope")
            require(all(anchor(item, field, version["version_id"], version["source_sha256"]) == item
                        for field, item in anchors.items()),
                    "case_selection_source_mismatch", "Source statement anchors differ")
        selected_context[stored["context_event_id"]] = stored
    selected_bindings = {rid: copy.deepcopy(bindings[rid]) for rid in ids}
    run_ids = {r["extraction_run_id"] for r in observations.values()}
    coverage = []
    covered_runs = set()
    for item in selection["coverage"]:
        require(isinstance(item, dict) and set(item) <= COVERAGE_INPUT_FIELDS | COVERAGE_EXTRA_FIELDS
                and COVERAGE_EXTRA_FIELDS <= set(item), "case_selection_schema", "Coverage has unsupported/missing fields")
        run = get("extraction_run", item.get("run_id"), "run_id")
        require(item["run_id"] not in covered_runs and item["version_id"] == run["version_id"],
                "case_selection_source_mismatch", "Coverage does not bind a distinct extraction")
        covered_runs.add(item["run_id"])
        total = len(run["draft_ids"])
        base_coverage = {k: v for k, v in item.items() if k in COVERAGE_INPUT_FIELDS}
        require(extraction_coverage(base_coverage, total) == run["coverage"]
                and type(item["known_extracted_rows"]) is int and item["known_extracted_rows"] == total,
                "case_selection_source_mismatch", "Coverage differs from its immutable extraction")
        count_keys = ("reviewed", "rejected", "deferred", "unreviewed")
        require(all(type(item[k]) is int and 0 <= item[k] <= total for k in count_keys)
                and sum(item[k] for k in count_keys) == total,
                "case_selection_schema", "Review coverage counts must be actual bounded integers")
        require(item["absence_means"] == "no_saved_row_does_not_prove_test_not_performed",
                "case_selection_schema", "Coverage must retain its source limitation")
        if item["run_id"] in run_ids: coverage.append(copy.deepcopy(item))
    require(run_ids <= covered_runs, "case_selection_source_mismatch", "Selected extraction coverage is missing")
    conflicts = selected_conflicts(selection["conflicts"], set(ids))
    minimal = {"schema_version": "health-analyzer.private-case-context/1", "subject_id": subject,
               "selection_id": case_id, "selection_sha256": body_hash,
               "recorded_as_of": selection["recorded_as_of"], "observations": copy.deepcopy(rows),
               "context_events": copy.deepcopy(contexts), "revision_bindings": selected_bindings,
               "conflicts": conflicts, "coverage": coverage, "truncated": selection["truncated"],
               "boundary": "private; never forward to public-research"}
    return {"selection": copy.deepcopy(selection), "observations": observations,
            "context_events": selected_context, "revision_bindings": selected_bindings,
            "minimal_context": minimal}


def resolve_case(records: RecordsService, subject_id: str, selection_id: str,
                 selection_sha256: str, *, require_current: bool = True) -> dict:
    require(records.store.domain == "private-data", "WRONG_DOMAIN", "Case resolution is private only")
    identifier(subject_id, "subject_id"); identifier(selection_id, "selection_id")
    require(isinstance(selection_sha256, str) and SHA256_RE.fullmatch(selection_sha256) is not None,
            "case_selection_hash_mismatch", "Expected snapshot hash is required")
    with records.store.transaction(readonly=True):
        selected = records.store.get("case_selection", selection_id, subject_id)
        require(selected.get("subject_id") == subject_id and selected.get("selection_id") == selection_id,
                "case_selection_scope_mismatch", "Saved case identity differs")
        require(selected.get("selection_sha256") == selection_sha256,
                "case_selection_hash_mismatch", "Expected case hash differs")
        verified = validate_case_snapshot(selected, records.store.get)
        history = records._history_projection(subject_id)
        current = {r["revision_id"] for r in history["current"]}
        ids = set(selected["revision_ids"])
        reasons = []
        if selected["recorded_as_of"] is not None:
            reasons.append("historical_case_not_supported_for_new_claims")
        if not ids <= current:
            reasons.append("selected_revision_not_current")
        if selected_conflicts(history["conflicts"], ids) != verified["minimal_context"]["conflicts"]:
            reasons.append("selected_conflict_state_changed")
        verified["freshness"] = {"state": "historical" if selected["recorded_as_of"] is not None else "stale" if reasons else "current",
                                 "reasons": reasons, "source_bytes_checked": False,
                                 "basis": "one signed database snapshot; not clinical applicability or live source bytes"}
        if require_current:
            require(not reasons, "case_not_current", "New private claims require a current saved case: " + ", ".join(reasons))
        return verified
