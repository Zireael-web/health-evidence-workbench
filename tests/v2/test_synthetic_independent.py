"""Independent bounded checks; every source, key and decision is artificial."""
import base64
import copy
import os
from pathlib import Path
import sqlite3

import pytest

from health_analyzer.v2.common import V2Error
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.migration import (
    CONTEXT_RULE, OriginRegistry, SyntheticLegacyAdapter, SyntheticLegacyFixture,
)
from health_analyzer.v2.recovery import SyntheticStore

# Reuse the existing actual subprocess fixture, rather than a simulated crash.
from test_synthetic_recovery import (
    KEY, PUBLIC_KEY, hashes, killed_acknowledged_writer, opened, setup,
)

LEGACY_KEY = b"INDEPENDENT-ARTIFICIAL-LEGACY-KEY!" * 2
TARGET_KEY = b"INDEPENDENT-ARTIFICIAL-TARGET-KEY!" * 2


def legacy_fixture(tmp_path, *, kind="user_note", payload=None):
    root = tmp_path / "exercise"
    create_synthetic_exercise(root)
    source = SyntheticLegacyFixture.create(root, root / "legacy.sqlite3", [{
        "legacy_id": "independent_fake_origin", "kind": kind,
        "scope": {"subject_id": "independent_fake_subject", "extension": "scope preserved"},
        "payload": payload if payload is not None else {
            "text": "Artificial context", "status": "unknown-old-state",
            "assurance": "old-artificial-assurance", "created_at": "literal old time",
        },
    }], LEGACY_KEY)
    registry = OriginRegistry(root, root / "target.sqlite3", TARGET_KEY)
    return root, source, registry


def replace_signed(registry, kind, object_id, value, subject=None):
    """Deliberate owned test-key corruption, so the semantic guard is tested."""
    registry.store._db.execute("DELETE FROM v2_objects WHERE kind=? AND object_id=?", (kind, object_id))
    registry.store.put(kind, object_id, value, subject)


def test_later_unsafe_source_is_rejected_before_first_source_io(tmp_path, monkeypatch):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    unsafe = root / "shared-directory"
    unsafe.mkdir(mode=0o755)
    source = unsafe / "fake.sqlite3"
    source.write_bytes(b"Artificial sentinel; must not be opened")
    source.chmod(0o600)
    reads, connects = [], []
    monkeypatch.setattr(recovery, "_bytes", lambda path: reads.append(path))
    monkeypatch.setattr("health_analyzer.v2.recovery.sqlite3.connect", lambda *a, **k: connects.append(a))
    try:
        with pytest.raises(V2Error) as error:
            recovery.create_backup(root / "rejected", [spec, SyntheticStore(
                "public", source, "public-research", PUBLIC_KEY.key_id,
            )], source_generation="synthetic_preflight", synthetic_quiesced=True)
        assert error.value.code == "SYNTHETIC_SCOPE_PATH"
        assert reads == connects == []
        assert not (root / "rejected").exists()
    finally:
        store.close()


def test_fifo_legacy_source_is_rejected_without_source_open(tmp_path, monkeypatch):
    root = tmp_path / "exercise"
    create_synthetic_exercise(root)
    fifo = root / "fake-source.sqlite3"
    os.mkfifo(fifo, mode=0o600)
    source_opens = []
    original = os.open
    def guarded_open(path, *args, **kwargs):
        if Path(path) == fifo:
            source_opens.append(path)
            pytest.fail("Nonregular artificial source was opened")
        return original(path, *args, **kwargs)
    monkeypatch.setattr("health_analyzer.v2.migration.os.open", guarded_open)
    with pytest.raises(V2Error) as error:
        SyntheticLegacyAdapter(root, fifo, LEGACY_KEY).read(salvage=True)
    assert error.value.code == "SYNTHETIC_SOURCE"
    assert source_opens == []


def test_duplicate_json_scope_is_quarantined_with_exact_scope_and_payload(tmp_path):
    raw = b'{  "status":null, "extension":["fake", 42] }\n'
    root, source, registry = legacy_fixture(tmp_path, kind="raw_field_confirmation", payload=raw)
    scope_raw = b'{ "subject_id":"fake-first", "subject_id":"fake-second" }\n'
    db = sqlite3.connect(source)
    db.execute("UPDATE synthetic_records SET scope=?", (sqlite3.Binary(scope_raw),))
    db.commit(); db.close()
    before = source.read_bytes()
    try:
        snapshot = SyntheticLegacyAdapter(root, source, LEGACY_KEY).read(salvage=True)
        assert snapshot.records[0].scope_bytes == scope_raw
        assert "invalid_scope" in snapshot.records[0].integrity_reasons
        report = registry.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
        origin = snapshot.records[0].origin_id
        captured = registry.store.get("legacy_records", origin)
        assert base64.b64decode(captured["scope_bytes_b64"]) == scope_raw
        assert registry.payload_bytes(origin) == raw
        assert report["counts"]["quarantined"] == 1
        assert report["counts"]["trusted_projected"] == 0
        assert source.read_bytes() == before
    finally:
        registry.close()


def test_later_projection_request_cannot_upgrade_an_immutable_disposition(tmp_path):
    root, source, registry = legacy_fixture(tmp_path)
    try:
        snapshot = SyntheticLegacyAdapter(root, source, LEGACY_KEY).read()
        first = registry.import_snapshot(snapshot)
        origin = snapshot.records[0].origin_id
        before = {kind: registry.store.get(kind, origin) for kind in (
            "legacy_records", "legacy_mapping", "migration_disposition",
        )}
        projected_request = registry.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
        assert projected_request["counts"] == first["counts"]
        assert projected_request["counts"]["preserved_only"] == 1
        assert registry.store.list("legacy_projection", "independent_fake_subject") == []
        assert {kind: registry.store.get(kind, origin) for kind in before} == before
        inventory = registry.export_inventory()
        assert registry.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE]) == projected_request
        assert registry.export_inventory() == inventory
    finally:
        registry.close()


def test_one_origin_cannot_gain_two_distinct_signed_projection_links(tmp_path):
    root, source, registry = legacy_fixture(tmp_path)
    try:
        snapshot = SyntheticLegacyAdapter(root, source, LEGACY_KEY).read()
        registry.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
        origin = snapshot.records[0].origin_id
        projection = copy.deepcopy(registry.store.list("legacy_projection", "independent_fake_subject")[0])
        projection["projection_id"] = "independent_fake_second_projection"
        registry.store.put("legacy_projection", projection["projection_id"], projection, "independent_fake_subject")
        mapping = registry.store.get("legacy_mapping", origin)
        mapping["projection_ids"].append(projection["projection_id"])
        replace_signed(registry, "legacy_mapping", origin, mapping)
        with pytest.raises(V2Error):
            registry.reconcile(snapshot)
    finally:
        registry.close()


@pytest.mark.parametrize("corruption", ["run_counts", "run_identity", "group_counts"])
def test_signed_run_and_group_cannot_disagree_with_recomputed_reconciliation(tmp_path, corruption):
    root, source, registry = legacy_fixture(tmp_path)
    try:
        snapshot = SyntheticLegacyAdapter(root, source, LEGACY_KEY).read()
        report = registry.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
        run = registry.store.get("migration_run", report["run_id"])
        if corruption == "group_counts":
            object_id = run["group_ids"][0]
            value = registry.store.get("migration_reconciliation_group", object_id)
            value["source_count"] += 1
            kind = "migration_reconciliation_group"
        else:
            kind, object_id, value = "migration_run", report["run_id"], run
            if corruption == "run_counts":
                value["counts"]["source"] += 1
            else:
                value["source_identity_bytes_b64"] = base64.b64encode(b"unrelated artificial identity").decode()
        replace_signed(registry, kind, object_id, value)
        with pytest.raises(V2Error):
            registry.reconcile(snapshot, run_id=report["run_id"])
    finally:
        registry.close()


def test_real_sigkill_witness_distinguishes_committed_wal_from_main_only_copy(tmp_path):
    root, store, _, _, recovery, spec = setup(tmp_path)
    store.close()
    ack = killed_acknowledged_writer(root)
    revision_id = ack["correction"]["revision"]["revision_id"]
    before = hashes(spec)
    main_copy = root / "deliberate-main-only-copy.sqlite3"
    main_copy.write_bytes(Path(spec.path).read_bytes())
    main_copy.chmod(0o600)
    # This artificial negative witness deliberately ignores WAL. Recovery uses
    # ordinary mode=ro and SQLite backup, never this immutable main-copy read.
    db = sqlite3.connect(main_copy.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        assert db.execute("SELECT count(*) FROM v2_objects WHERE object_id=?", (revision_id,)).fetchone()[0] == 0
    finally:
        db.close()
    manifest = recovery.create_backup(root / "latest", [spec], source_generation="acknowledged_wal")
    report = recovery.restore_bundle(root / "latest", root / "restored")
    restored = opened(report)
    try:
        assert restored.get("observation_revision", revision_id, "synthetic_demo") == ack["correction"]["revision"]
        assert restored.get("context_event", ack["context"]["context_event_id"], "synthetic_demo") == ack["context"]
        assert manifest["stores"][0]["inventory"]["latest_events"]["context_event"]["object_id"] == ack["context"]["context_event_id"]
        assert hashes(spec) == before
    finally:
        restored.close()
