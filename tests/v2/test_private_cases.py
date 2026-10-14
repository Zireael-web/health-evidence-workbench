"""Authoritative frozen case graph; all inputs and attestations fictional."""
import copy
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import SignedStore, V2Error, digest
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.private_cases import resolve_case, validate_case_snapshot
from health_analyzer.v2.records import RecordsService


@pytest.fixture
def fixture(tmp_path):
    archive = tmp_path / "artificial-csv"; archive.mkdir()
    store = SignedStore(tmp_path / "synthetic-private.sqlite3", b"OWNED ARTIFICIAL CASE TEST KEY!!!", "private-data")
    records = RecordsService(store)
    for sid in ("fictional_a", "fictional_b"):
        records.register_subject(sid, "Wholly fictional fixture")
    imports = ImportService(SimpleNamespace(archive_roots={"fake": {"path": archive, "subject_id": "fictional_a"}}), records)
    yield archive, store, records, imports
    store.close()


def evidence(identifier, sha):
    return {"snapshot_id": identifier, "snapshot_sha256": sha,
        "decision_excerpt": "SYNTHETIC SIMULATED fixture decision; no actual human",
        "attested_by": "synthetic_test_orchestrator", "origin": "user_message", "message_ref": None,
        "conversation_ref": None, "ref_availability": "not_provided_by_host"}


def accept(fixture, *, name="one.csv", value="5.4", corrected=False):
    archive, store, records, imports = fixture
    (archive / name).write_text("analyte;result;unit;collected;specimen;method\n"
                              f"Artificial analyte;{value};test-u;2026-01-01;artificial fluid;artificial method\n")
    version = imports.prepare_import("fictional_a", [{"root_id": "fake", "relative_path": name}])["documents"][0]
    preview = records.prepare_review("fictional_a", version["version_id"])
    decision = {"draft_id": preview["rows"][0]["draft_id"], "action": "confirm"}
    if corrected:
        decision.update(action="correct_and_confirm", patch={"analyte_key": "artificial_alpha", "mapping_status": "confirmed"}, reason="SYNTHETIC explicit identity mapping")
    result = records.commit_review("fictional_a", preview["snapshot_id"], preview["snapshot_sha256"], [decision],
                                   evidence(preview["snapshot_id"], preview["snapshot_sha256"]))
    return store.get("observation_revision", result["revision_ids"][0], "fictional_a")


def selected(fixture, revision_ids=None, context_ids=None):
    _, _, records, _ = fixture
    selector = {}
    if revision_ids is not None: selector["revision_ids"] = revision_ids
    if context_ids is not None: selector["context_event_ids"] = context_ids
    return records.select_case_context("fictional_a", selector)


def test_initial_and_correct_and_confirm_graphs_are_verified_not_rewritten(fixture):
    _, store, records, _ = fixture
    a = accept(fixture)
    b = accept(fixture, name="two.csv", value="6.4", corrected=True)
    case = selected(fixture)
    before = records.export_history("fictional_a")
    verified = resolve_case(records, "fictional_a", case["selection_id"], case["selection_sha256"])
    assert set(verified["observations"]) == {a["revision_id"], b["revision_id"]}
    assert verified["freshness"]["state"] == "current"
    assert all(bind["confirmation_binding"]["kind"] == "review_event" for bind in verified["revision_bindings"].values())
    assert records.export_history("fictional_a") == before
    assert store.get("case_selection", case["selection_id"], "fictional_a") == case


def test_correction_uses_previous_revision_digest_and_stale_case_remains_readable(fixture):
    _, store, records, _ = fixture
    previous = accept(fixture)
    old = selected(fixture)
    correction = records.correct_observation("fictional_a", previous["observation_id"],
        {"result": {"kind": "numeric_exact", "raw": "5.5", "decimal": "5.5"}}, "SYNTHETIC test correction",
        evidence(previous["revision_id"], digest(previous)))
    with pytest.raises(V2Error, match="New private claims require"):
        resolve_case(records, "fictional_a", old["selection_id"], old["selection_sha256"])
    frozen = records.get_case_selection("fictional_a", old["selection_id"], old["selection_sha256"])
    assert frozen["freshness"]["state"] == "stale"
    assert frozen["context"]["observations"][0]["row"] == previous["row"]
    new = selected(fixture)
    resolved = resolve_case(records, "fictional_a", new["selection_id"], new["selection_sha256"])
    binding = resolved["revision_bindings"][correction["revision"]["revision_id"]]["confirmation_binding"]
    assert binding["kind"] == "correction_event"
    assert binding["previous_revision_sha256"] == digest(previous)
    assert binding["previous_confirmation_binding"]["kind"] == "review_event"
    assert store.get("case_selection", old["selection_id"], "fictional_a") == old


def test_notes_and_coverage_are_explicitly_selected_and_unrelated_history_does_not_stale(fixture):
    _, _, records, _ = fixture
    revision = accept(fixture)
    note = records.record_context_event("fictional_a", {"kind": "user_note", "event_type": "synthetic", "text": "Chosen fictional note"})
    records.record_context_event("fictional_a", {"kind": "user_note", "event_type": "synthetic", "text": "Unselected fictional note"})
    case = selected(fixture, [revision["revision_id"]], [note["context_event_id"]])
    accept(fixture, name="unrelated.csv", value="8.4")
    view = resolve_case(records, "fictional_a", case["selection_id"], case["selection_sha256"])
    assert view["freshness"]["state"] == "current"
    assert list(view["context_events"]) == [note["context_event_id"]]
    assert len(view["minimal_context"]["coverage"]) == 1


def test_wrong_subject_and_case_hash_are_refused(fixture):
    _, _, records, _ = fixture
    accept(fixture); case = selected(fixture)
    with pytest.raises(V2Error) as error:
        resolve_case(records, "fictional_b", case["selection_id"], case["selection_sha256"])
    assert error.value.code == "WRONG_SUBJECT"
    with pytest.raises(V2Error) as error:
        resolve_case(records, "fictional_a", case["selection_id"], "f" * 64)
    assert error.value.code == "case_selection_hash_mismatch"


@pytest.mark.parametrize("field,value", [("row", {"made_up": True}), ("confirmation_assurance", "authenticated_human"),
                                         ("source_version_id", "version_wrong"), ("observation_id", "observation_wrong")])
def test_even_rehashed_case_cannot_change_its_authoritative_projection(fixture, field, value):
    _, store, _, _ = fixture
    accept(fixture); case = selected(fixture)
    bad = copy.deepcopy(case); bad["observations"][0][field] = value
    bad["selection_sha256"] = digest({k: v for k, v in bad.items() if k != "selection_sha256"})
    with pytest.raises(V2Error): validate_case_snapshot(bad, store.get)


def test_historical_snapshot_is_not_silently_used_for_current_calculation(fixture):
    _, _, records, _ = fixture
    r = accept(fixture)
    case = records.select_case_context("fictional_a", recorded_as_of=r["recorded_at"])
    read = records.get_case_selection("fictional_a", case["selection_id"], case["selection_sha256"])
    assert read["freshness"]["state"] == "historical"
    with pytest.raises(V2Error): resolve_case(records, "fictional_a", case["selection_id"], case["selection_sha256"])


def test_duplicate_support_selectors_are_rejected(fixture):
    _, _, records, _ = fixture
    r = accept(fixture)
    with pytest.raises(V2Error): selected(fixture, [r["revision_id"], r["revision_id"]])


def test_later_attributed_review_preserves_model_only_ancestor_without_promoting_it(fixture):
    archive, store, records, imports = fixture
    (archive / "model.csv").write_text("analyte;result;unit;collected;specimen;method\nArtificial;1.0;test-u;2026-01-01;fake fluid;fake method\n")
    version = imports.prepare_import("fictional_a", [{"root_id": "fake", "relative_path": "model.csv"}])["documents"][0]
    first = records.prepare_review("fictional_a", version["version_id"])
    ack = records.commit_review("fictional_a", first["snapshot_id"], first["snapshot_sha256"],
                               [{"draft_id": first["rows"][0]["draft_id"], "action": "confirm"}])
    ancestor = store.get("observation_revision", ack["revision_ids"][0], "fictional_a")
    assert ancestor["confirmation_assurance"] == "none"
    later = records.prepare_review("fictional_a", version["version_id"])
    accepted = records.commit_review("fictional_a", later["snapshot_id"], later["snapshot_sha256"],
        [{"draft_id": later["rows"][0]["draft_id"], "action": "confirm"}], evidence(later["snapshot_id"], later["snapshot_sha256"]))
    case = selected(fixture)
    verified = resolve_case(records, "fictional_a", case["selection_id"], case["selection_sha256"])
    binding = verified["revision_bindings"][accepted["revision_ids"][0]]["confirmation_binding"]
    assert binding["supersedes_revision_sha256"] == digest(ancestor)
    assert binding["previous_confirmation_binding"]["confirmation_assurance"] == "none"
    assert binding["previous_confirmation_binding"]["review_status"] == "model_checked"
    assert store.get("observation_revision", ancestor["revision_id"], "fictional_a") == ancestor
    assert list(verified["observations"]) == accepted["revision_ids"]
