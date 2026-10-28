"""Cross-module acceptance using owned fictional stores and test keys only."""
import sqlite3
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import digest
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.migration import (
    CONTEXT_RULE, OriginRegistry, SyntheticLegacyAdapter, SyntheticLegacyFixture,
)
from health_analyzer.v2.originals import OriginalsStore
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.recovery import SyntheticRecovery, SyntheticStore, TestKey

LEGACY_KEY = b"ARTIFICIAL-INTEGRATION-LEGACY-KEY!!"
KEY = TestKey("test_integration", b"ARTIFICIAL-INTEGRATION-V2-KEY!!!!!")


def attestation(identifier, sha):
    return {"snapshot_id": identifier, "snapshot_sha256": sha,
            "decision_excerpt": "SIMULATED artificial test decision; no actual human confirmation",
            "attested_by": "synthetic_test_orchestrator", "origin": "user_message",
            "message_ref": None, "conversation_ref": None,
            "ref_availability": "not_provided_by_host"}


@pytest.mark.parametrize("project_context", [False, True])
def test_origin_partition_raw_bytes_and_post_cutover_ack_survive_restore_and_rollback(tmp_path, project_context):
    root = tmp_path / "artificial-exercise"
    create_synthetic_exercise(root)
    raw = b'{ "status":"FUTURE_RAW", "assurance":"old_raw_confirmation", "reviewed_at":"UNKNOWN_RAW_DATE", "extension":[1,2] }\n'
    inputs = [
        {"legacy_id": "raw-a", "kind": "raw_field_confirmation", "scope": {"subject_id": "fictional-a"}, "payload": raw},
        {"legacy_id": "raw-b", "kind": "raw_field_confirmation", "scope": {"subject_id": "fictional-b"}, "payload": raw},
        {"legacy_id": "note-a", "kind": "user_note", "scope": {"subject_id": "fictional-a"},
         "payload": {"subject_id": "fictional-a", "text": "Fictional note", "status": "old_accepted", "assurance": "legacy_attested"}},
        {"legacy_id": "calc-b", "kind": "calculation", "scope": {"subject_id": "fictional-b"},
         "payload": {"subject_id": "fictional-b", "formula": "2+2", "value": 4, "status": "calculated"}},
        {"legacy_id": "quarantine-b", "kind": "user_note", "scope": {"subject_id": "fictional-b"},
         "payload": {"subject_id": "fictional-b", "text": "Fictional corrupt-signature record"}},
    ]
    source = SyntheticLegacyFixture.create(root, root / "legacy.sqlite3", inputs, LEGACY_KEY,
        snapshot_id="artificial-origin-generation", store_id="artificial-origin-store")
    # Deliberate corruption of our own sealed artificial fixture, never a real source.
    with sqlite3.connect(source) as db:
        db.execute("UPDATE synthetic_records SET signature=? WHERE legacy_id=?", ("artificial bad signature", "quarantine-b"))
    source_bytes = source.read_bytes()
    snapshot = SyntheticLegacyAdapter(root, source, LEGACY_KEY).read(salvage=True)
    registry = OriginRegistry(root, root / "private.sqlite3", KEY.material)
    rules = [CONTEXT_RULE] if project_context else []
    initial = registry.import_snapshot(snapshot, projection_rules=rules)
    assert initial["counts"] == {"source": 5, "captured": 5, "preserved_only": 2 if project_context else 4,
                                 "quarantined": 1, "trusted_projected": 2 if project_context else 0}
    origin_inventory = registry.export_inventory()
    service = RecordsService(registry.store)
    for subject in ("fictional-a", "fictional-b"):
        service.register_subject(subject, "Artificial subject only")
    recovery = SyntheticRecovery(root, test_keys={KEY.key_id: KEY})
    spec = SyntheticStore("private", registry.store.path, "private-data", KEY.key_id)
    recovery.create_backup(root / "base-bundle", [spec], source_generation="synthetic-base")
    archive = root / "artificial-csv"; archive.mkdir(mode=0o700)
    report_path = archive / "new.csv"
    report_path.write_text("analyte;result;unit;collected;specimen;method\nFictional assay;2.0;test-u;2026-10-02;artificial-fluid;fixture-assay\n")
    report_path.chmod(0o600)
    config = SimpleNamespace(archive_roots={"artificial": {"path": archive, "subject_id": "fictional-a"}})
    imports = ImportService(config, service)
    document = imports.prepare_import("fictional-a", [{"root_id": "artificial", "relative_path": "new.csv"}])["documents"][0]
    preview = service.prepare_review("fictional-a", document["version_id"])
    request = {"subject_id": "fictional-a", "snapshot_id": preview["snapshot_id"], "snapshot_sha256": preview["snapshot_sha256"],
               "decisions": [{"draft_id": preview["rows"][0]["draft_id"], "action": "confirm"}],
               "conversation_attestation": attestation(preview["snapshot_id"], preview["snapshot_sha256"]),
               "idempotency_key": "artificial-accept"}
    accepted = service.commit_review(**request)
    revision = registry.store.get("observation_revision", accepted["revision_ids"][0], "fictional-a")
    correction_request = {"subject_id": "fictional-a", "observation_id": revision["observation_id"],
        "patch": {"result": {"kind": "numeric_exact", "raw": "2.5", "decimal": "2.5"}},
        "reason": "Artificial test correction",
        "conversation_attestation": attestation(revision["revision_id"], digest(revision)), "idempotency_key": "artificial-correct"}
    corrected = service.correct_observation(**correction_request)
    context = service.record_context_event("fictional-b", {"kind": "user_note", "event_type": "artificial_fixture", "text": "Fictional separate subject context"})
    complete = service.export_history("fictional-a")
    recovery.create_backup(root / "latest-bundle", [spec], source_generation="synthetic-latest")
    restored = recovery.restore_bundle(root / "latest-bundle", root / "restored")
    rollback = recovery.reconstruct_rollback(root / "base-bundle", [spec], root / "rollback", source_generation="synthetic-rollback")
    registry.close()
    for result in (restored, rollback):
        path = result["stores"][0]["path"]
        checked = OriginRegistry(root, path, KEY.material)
        assert checked.export_inventory() == origin_inventory
        assert checked.reconcile(snapshot, run_id=initial["run_id"])["counts"] == initial["counts"]
        assert checked.import_snapshot(snapshot, projection_rules=rules) == initial
        for origin in snapshot.records:
            assert checked.payload_bytes(origin.origin_id) == origin.raw_payload
        records = RecordsService(checked.store)
        # Explicit still-present artificial originals are outside the backup bundle.
        ImportService(config, records, originals=OriginalsStore(root / "originals", readonly=True))
        assert records.commit_review(**request) == accepted
        assert records.correct_observation(**correction_request) == corrected
        assert checked.store.get("context_event", context["context_event_id"], "fictional-b") == context
        assert records.export_history("fictional-a") == complete
        assert len(records.query_history("fictional-a")["current"]) == 1
        assert records.query_history("fictional-b")["current"] == []
        assert all(p["confirmation_assurance"] == "none" and p["measurement"] is False
                   for subject in ("fictional-a", "fictional-b") for p in checked.store.list("legacy_projection", subject))
        checked.close()
    assert source.read_bytes() == source_bytes
