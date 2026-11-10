"""Synthetic regressions for source identity and immutable extraction selection."""
import copy

import pytest

from health_analyzer.v2.common import V2Error, digest
from health_analyzer.v2.contracts import SCHEMA_VERSION, extraction_coverage, lab_observation
from health_analyzer.v2.records import result_locator
from test_records import make_row, coverage, commit, document, records


SUBJECT = "subject_demo"


def submit(service, version, value="5.4", row=None):
    return service.submit_extraction(SUBJECT, version["version_id"], [row or make_row(version, value)], coverage(1))


def draft(service, run):
    return service.store.get("observation_draft", run["draft_ids"][0], SUBJECT)


def legacy_run(service, version, value="5.4", *, list_anchor=False, observation_id=None):
    """Seed the earlier v2 object format in a brand-new synthetic test store."""
    row = make_row(version, value)
    source_location = row["field_anchors"]["result"]["locator"]
    if list_anchor:
        row["field_anchors"]["result"] = [row["field_anchors"]["result"]]
        source_location = [source_location]
    row = lab_observation(row, version["version_id"], version["source_sha256"])
    normalized_coverage = extraction_coverage(coverage(1), 1)
    run_id = "extraction_" + digest({"version_id": version["version_id"], "rows": [row], "coverage": normalized_coverage})
    draft_id = "draft_" + digest({"run_id": run_id, "index": 0})
    observation_id = observation_id or "observation_" + digest({"version_id": version["version_id"], "result_locator": source_location})
    panel_id = "panel_" + digest({"run_id": run_id, "panel_key": "default"})
    now = "2026-01-01T00:00:00Z"
    payload = {"schema_version": SCHEMA_VERSION, "subject_id": SUBJECT, "draft_id": draft_id,
               "observation_id": observation_id, "source_version_id": version["version_id"],
               "source_sha256": version["source_sha256"], "extraction_run_id": run_id,
               "panel_id": panel_id, "row": row, "review_status": "unreviewed", "recorded_at": now}
    run = {"schema_version": SCHEMA_VERSION, "subject_id": SUBJECT, "run_id": run_id,
           "version_id": version["version_id"], "source_sha256": version["source_sha256"],
           "coverage": normalized_coverage, "draft_ids": [draft_id], "panel_ids": [panel_id], "recorded_at": now}
    with service.store.transaction():
        service.store.put("observation_draft", draft_id, payload, SUBJECT)
        service.store.put("panel", panel_id, {"subject_id": SUBJECT, "panel_id": panel_id, "run_id": run_id,
                                             "version_id": version["version_id"], "draft_ids": [draft_id], "recorded_at": now}, SUBJECT)
        service.store.put("extraction_run", run_id, run, SUBJECT)
    return run


def legacy_snapshot(service, version):
    snapshot = service.prepare_review(SUBJECT, version["version_id"])
    snapshot.pop("selection_token")
    snapshot["snapshot_id"] = "snapshot_synthetic_legacy"
    snapshot.pop("snapshot_sha256")
    snapshot["snapshot_sha256"] = digest(snapshot)
    service.store.put("review_snapshot", snapshot["snapshot_id"], snapshot, SUBJECT)
    return snapshot


def test_result_locator_collapses_singletons_and_sorts_deduplicates_without_mutating(records):
    version = document(records)
    row = make_row(version)
    original = copy.deepcopy(row)
    wrapped = copy.deepcopy(row)
    wrapped["field_anchors"]["result"] = [wrapped["field_anchors"]["result"]]
    assert result_locator(wrapped) == result_locator(row)
    a = copy.deepcopy(row["field_anchors"]["result"])
    b = copy.deepcopy(a)
    b["locator"]["row"] = 3
    c = copy.deepcopy(a)
    c["excerpt"] = "Different extraction text is not a different location"
    wrapped["field_anchors"]["result"] = [b, c, a, b]
    reversed_row = copy.deepcopy(wrapped)
    reversed_row["field_anchors"]["result"].reverse()
    assert len(result_locator(wrapped)) == 2
    assert result_locator(wrapped) == result_locator(reversed_row)
    assert row == original


def test_anchor_dict_and_singleton_list_revise_one_observation(records):
    version = document(records)
    first = submit(records, version)
    commit(records, records.prepare_review(SUBJECT, version["version_id"]))
    wrapped = make_row(version, "5.6")
    wrapped["field_anchors"]["result"] = [wrapped["field_anchors"]["result"]]
    second = submit(records, version, row=wrapped)
    assert draft(records, first)["observation_id"] == draft(records, second)["observation_id"]
    commit(records, records.prepare_review(SUBJECT, version["version_id"]))
    history = records.query_history(SUBJECT)
    assert len(history["current"]) == 1 and len(history["historical"]) == 1
    assert history["current"][0]["supersedes_revision_id"] == history["historical"][0]["revision_id"]


def test_reordered_duplicate_multilocators_keep_identity(records):
    version = document(records)
    row = make_row(version)
    a = row["field_anchors"]["result"]
    b = copy.deepcopy(a)
    b["locator"]["row"] = 3
    row["field_anchors"]["result"] = [a, b]
    first = submit(records, version, row=row)
    changed = copy.deepcopy(row)
    changed["field_anchors"]["result"] = [b, a, b]
    second = submit(records, version, row=changed)
    assert draft(records, first)["observation_id"] == draft(records, second)["observation_id"]


def test_existing_unique_earlier_v2_list_identity_is_preserved_without_rewrites(records):
    version = document(records)
    earlier = legacy_run(records, version, list_anchor=True)
    old_draft = copy.deepcopy(draft(records, earlier))
    canonical_new_id = "observation_" + digest({"version_id": version["version_id"], "result_locator": result_locator(make_row(version))})
    assert old_draft["observation_id"] != canonical_new_id
    changed = submit(records, version, "5.6")
    assert draft(records, changed)["observation_id"] == old_draft["observation_id"]
    assert records.store.get("observation_draft", old_draft["draft_id"], SUBJECT) == old_draft
    assert records.store.get("extraction_run", earlier["run_id"], SUBJECT) == earlier


def test_conflicting_existing_canonical_identities_fail_atomically(records):
    version = document(records)
    legacy_run(records, version, "5.4", list_anchor=True)
    legacy_run(records, version, "5.6", list_anchor=False)
    before_runs = records.store.list("extraction_run", SUBJECT)
    before_drafts = records.store.list("observation_draft", SUBJECT)
    with pytest.raises(V2Error) as error:
        submit(records, version, "5.7")
    assert error.value.code == "ambiguous_observation_identity"
    assert records.store.list("extraction_run", SUBJECT) == before_runs
    assert records.store.list("observation_draft", SUBJECT) == before_drafts
    assert records.store.list("extraction_selection", SUBJECT) == []


def test_equivalent_container_duplicate_rows_are_rejected_before_writes(records):
    version = document(records)
    a, b = make_row(version), make_row(version, "5.6")
    b["field_anchors"]["result"] = [b["field_anchors"]["result"]]
    with pytest.raises(V2Error) as error:
        records.submit_extraction(SUBJECT, version["version_id"], [a, b], coverage(2))
    assert error.value.code == "duplicate_source_row"
    assert records.store.list("extraction_run", SUBJECT) == []
    assert records.store.list("observation_draft", SUBJECT) == []
    assert records.store.list("extraction_selection", SUBJECT) == []


def test_reselect_a_after_b_uses_dedup_a_but_invalidates_earlier_a_snapshot(records, monkeypatch):
    monkeypatch.setattr("health_analyzer.v2.records.utc_now", lambda: "2026-01-01T00:00:00Z")
    version = document(records)
    a = submit(records, version, "5.4")
    before = records.prepare_review(SUBJECT, version["version_id"])
    b = submit(records, version, "5.6")
    again_a = submit(records, version, "5.4")
    assert again_a["deduplicated"] is True and again_a["run_id"] == a["run_id"]
    assert again_a["selection_changed"] is True
    assert again_a["selection_token"] != a["selection_token"]
    assert records._latest_run(SUBJECT, version["version_id"])["run_id"] == a["run_id"]
    assert len(records.store.list("extraction_run", SUBJECT)) == 2
    events = records.store.list("extraction_selection", SUBJECT)
    assert [event["sequence"] for event in events] == [1, 2, 3]
    assert [event["run_id"] for event in events] == [a["run_id"], b["run_id"], a["run_id"]]
    assert events[2]["previous_selection_token"] == events[1]["selection_token"]
    with pytest.raises(V2Error) as error:
        commit(records, before)
    assert error.value.code == "stale_extraction"
    assert records.store.list("observation_revision", SUBJECT) == []
    after = records.prepare_review(SUBJECT, version["version_id"])
    assert after["selection_token"] == again_a["selection_token"]
    assert after["rows"][0]["row"]["result"]["decimal"] == "5.4"
    commit(records, after)


def test_reusing_current_run_leaves_selection_and_review_valid(records):
    version = document(records)
    a = submit(records, version)
    preview = records.prepare_review(SUBJECT, version["version_id"])
    for _ in range(3):
        reused = submit(records, version)
        assert reused["selection_token"] == a["selection_token"]
        assert reused["selection_changed"] is False
    assert len(records.store.list("extraction_selection", SUBJECT)) == 1
    commit(records, preview)


def test_legacy_runs_and_snapshot_reuse_remain_compatible_without_migration(records):
    version = document(records)
    earlier = legacy_run(records, version)
    snapshot = legacy_snapshot(records, version)
    reused = submit(records, version)
    assert reused["run_id"] == earlier["run_id"] and reused["deduplicated"] is True
    assert reused["selection_changed"] is False
    assert records.store.list("extraction_selection", SUBJECT) == []
    assert records.store.get("extraction_run", earlier["run_id"], SUBJECT) == earlier
    commit(records, snapshot)


def test_legacy_snapshot_is_stale_after_changed_selection_returns_to_legacy_a(records):
    version = document(records)
    earlier = legacy_run(records, version)
    preview = legacy_snapshot(records, version)
    submit(records, version, "5.6")
    again = submit(records, version, "5.4")
    assert again["run_id"] == earlier["run_id"]
    assert records._latest_run(SUBJECT, version["version_id"])["selection_sequence"] == 2
    with pytest.raises(V2Error) as error:
        commit(records, preview)
    assert error.value.code == "stale_extraction"


def test_selection_is_per_version_and_same_locator_does_not_cross_versions(records):
    a_version, b_version = document(records), document(records, "b")
    a = submit(records, a_version)
    preview = records.prepare_review(SUBJECT, a_version["version_id"])
    b = submit(records, b_version)
    assert draft(records, a)["observation_id"] != draft(records, b)["observation_id"]
    assert records._latest_run(SUBJECT, a_version["version_id"])["selection_token"] == a["selection_token"]
    assert records._latest_run(SUBJECT, b_version["version_id"])["selection_sequence"] == 1
    commit(records, preview)


def test_selection_fork_fails_closed(records):
    version = document(records)
    first = submit(records, version)
    second = submit(records, version, "5.6")
    fork = {"schema_version": SCHEMA_VERSION, "subject_id": SUBJECT, "version_id": version["version_id"],
            "run_id": first["run_id"], "sequence": 2, "previous_selection_token": first["selection_token"]}
    token_body = {key: value for key, value in fork.items() if key != "schema_version"}
    fork.update(selection_token="selection_" + digest(token_body), recorded_at="2026-01-01T00:00:00Z")
    assert fork["selection_token"] != second["selection_token"]
    records.store.put("extraction_selection", fork["selection_token"], fork, SUBJECT)
    with pytest.raises(V2Error) as error:
        records.prepare_review(SUBJECT, version["version_id"])
    assert error.value.code == "extraction_selection_conflict"
