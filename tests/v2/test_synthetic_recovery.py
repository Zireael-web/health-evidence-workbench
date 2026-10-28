"""Owned artificial stores only: no live DB, archive, credential or network."""
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import SignedStore, V2Error, canonical, digest
from health_analyzer.v2.contracts import SCHEMA_VERSION
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.recovery import SyntheticRecovery, SyntheticStore, TestKey

KEY = TestKey("test_private", b"ARTIFICIAL-RECOVERY-TEST-KEY-ONLY!!")
PUBLIC_KEY = TestKey("test_public", b"ARTIFICIAL-PUBLIC-TEST-KEY-ONLY!!!")


def setup(tmp_path, *, baseline=True):
    root = tmp_path / "exercise"
    create_synthetic_exercise(root)
    archive = root / "artificial-csv"; archive.mkdir(mode=0o700)
    state = root / "state"; state.mkdir(mode=0o700)
    store = SignedStore(state / "private.sqlite3", KEY.material, "private-data")
    records = RecordsService(store)
    records.register_subject("synthetic_demo", "Artificial fixture, no real human")
    imports = ImportService(SimpleNamespace(archive_roots={"synthetic": {
        "path": archive, "subject_id": "synthetic_demo"}}), records)
    if baseline:
        write_csv(archive / "base.csv", "Base artificial analyte", "1.0")
        accept(imports, records, "base.csv", "base_accept")
    recovery = SyntheticRecovery(root, test_keys={KEY.key_id: KEY, PUBLIC_KEY.key_id: PUBLIC_KEY})
    spec = SyntheticStore("private", store.path, "private-data", KEY.key_id)
    return root, store, records, imports, recovery, spec


def write_csv(path, analyte, value):
    path.write_text("analyte;result;unit;collected;specimen;method\n"
                    f"{analyte};{value};test-u;2026-10-01;artificial-fluid;fixture-assay\n")
    path.chmod(0o600)


def evidence(snapshot):
    return {"snapshot_id": snapshot["snapshot_id"], "snapshot_sha256": snapshot["snapshot_sha256"],
            "decision_excerpt": "SIMULATED test conversation accepts this artificial row; no real human",
            "attested_by": "synthetic_test_orchestrator", "origin": "user_message",
            "message_ref": None, "conversation_ref": None, "ref_availability": "not_provided_by_host"}


def accept(imports, records, filename, key):
    document = imports.prepare_import("synthetic_demo", [{"root_id": "synthetic", "relative_path": filename}])["documents"][0]
    snapshot = records.prepare_review("synthetic_demo", document["version_id"])
    request = {"subject_id": "synthetic_demo", "snapshot_id": snapshot["snapshot_id"],
               "snapshot_sha256": snapshot["snapshot_sha256"],
               "decisions": [{"draft_id": row["draft_id"], "action": "confirm"} for row in snapshot["rows"]],
               "conversation_attestation": evidence(snapshot), "idempotency_key": key}
    return records.commit_review(**request), request, document


def hashes(spec):
    return {suffix: hashlib.sha256(Path(str(spec.path) + suffix).read_bytes()).hexdigest()
            if Path(str(spec.path) + suffix).exists() else None for suffix in ("", "-wal", "-journal")}


def seal_fixture(store):
    # This explicit fixture writer owns the artificial DB. Recovery never does
    # this to a source. Sealed main files avoid dormant WAL sidecar creation.
    store._db.execute("PRAGMA journal_mode=DELETE")
    store.close()


def opened(report, name="private", *, readonly=True):
    path = next(item["path"] for item in report["stores"] if item["name"] == name)
    return SignedStore(path, KEY.material, "private-data", readonly=readonly)


def resign_manifest(bundle, mutation):
    """Deliberate test-key fixture corruption; never production signing."""
    path = bundle / "manifest.json"
    data = json.loads(path.read_bytes())
    mutation(data)
    body = {k: v for k, v in data.items() if k != "manifest_hmacs"}
    test_keys = {KEY.key_id: KEY, PUBLIC_KEY.key_id: PUBLIC_KEY}
    data["manifest_hmacs"] = {k: hmac.new(test_keys[k].material, canonical(body), hashlib.sha256).hexdigest()
                              for k in data["manifest_hmacs"]}
    path.write_bytes(canonical(data))


CHILD = r'''
import json, os, signal, sys
from pathlib import Path
from types import SimpleNamespace
from health_analyzer.v2.common import SignedStore, digest
from health_analyzer.v2.exercise_scope import require_owned_synthetic_path
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.records import RecordsService
root = Path(sys.argv[1])
keyfd = int(os.environ["SYNTHETIC_RECOVERY_KEY_FD"])
key = os.read(keyfd, 128); os.close(keyfd)
path = require_owned_synthetic_path(root, root / "state/private.sqlite3", must_exist=True)
store = SignedStore(path, key, "private-data")
# Only this owned synthetic fixture writer sets its own durability/WAL options.
store._db.execute("PRAGMA wal_autocheckpoint=0")
records = RecordsService(store)
archive = root / "artificial-csv"
csvpath = require_owned_synthetic_path(root, archive / "post-cutover.csv")
csvpath.write_text("analyte;result;unit;collected;specimen;method\n"
                   "Post-cutover artificial analyte;2.0;test-u;2026-10-02;artificial-fluid;fixture-assay\n")
csvpath.chmod(0o600)
imports = ImportService(SimpleNamespace(archive_roots={"synthetic": {
    "path": archive, "subject_id": "synthetic_demo"}}), records)
document = imports.prepare_import("synthetic_demo", [{"root_id": "synthetic", "relative_path": "post-cutover.csv"}])["documents"][0]
snapshot = records.prepare_review("synthetic_demo", document["version_id"])
def attestation(sid, shash):
    return {"snapshot_id": sid, "snapshot_sha256": shash,
        "decision_excerpt": "SIMULATED artificial fixture decision, no real human",
        "attested_by": "synthetic_test_orchestrator", "origin": "user_message", "message_ref": None,
        "conversation_ref": None, "ref_availability": "not_provided_by_host"}
review_request = {"subject_id": "synthetic_demo", "snapshot_id": snapshot["snapshot_id"],
    "snapshot_sha256": snapshot["snapshot_sha256"], "decisions": [{"draft_id": snapshot["rows"][0]["draft_id"], "action": "confirm"}],
    "conversation_attestation": attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"]), "idempotency_key": "post_accept"}
review = records.commit_review(**review_request)
previous = store.get("observation_revision", review["revision_ids"][0], "synthetic_demo")
correction_request = {"subject_id": "synthetic_demo", "observation_id": previous["observation_id"],
    "patch": {"result": {"kind": "numeric_exact", "raw": "2.5", "decimal": "2.5"}},
    "reason": "SIMULATED correction to artificial test value",
    "conversation_attestation": attestation(previous["revision_id"], digest(previous)), "idempotency_key": "post_correct"}
correction = records.correct_observation(**correction_request)
context = records.record_context_event("synthetic_demo", {"kind": "user_note", "event_type": "synthetic_fixture",
    "text": "SIMULATED post-cutover context event; no real person or health data"})
ack = {"review": review, "review_request": review_request, "accepted_revision": previous,
    "correction": correction, "correction_request": correction_request, "context": context, "document": document}
# The successful service return is acknowledged while this WAL writer is open.
print(json.dumps(ack, sort_keys=True), flush=True)
signal.pause()
'''


def killed_acknowledged_writer(root):
    readfd, writefd = os.pipe()
    env = dict(os.environ)
    env["SYNTHETIC_RECOVERY_KEY_FD"] = str(readfd)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    process = subprocess.Popen([sys.executable, "-B", "-c", CHILD, str(root)],
                               env=env, pass_fds=(readfd,), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    os.close(readfd)
    try:
        os.write(writefd, KEY.material)
    finally:
        os.close(writefd)
    try:
        # select bounds the acknowledgement wait; no key is printed or in argv.
        import select
        ready, _, _ = select.select([process.stdout], [], [], 15)
        assert ready, "Synthetic child did not acknowledge within the bounded timeout"
        line = process.stdout.readline()
        assert line, process.stderr.read(4096)
        ack = json.loads(line)
        process.kill()  # POSIX SIGKILL, not a clean service shutdown.
        process.wait(timeout=10)
        assert process.returncode == -signal.SIGKILL
        return ack
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=10)
        process.stdout.close(); process.stderr.close()


def test_sigkill_wal_restore_and_rollback_keep_exact_acknowledged_records_and_retry(tmp_path):
    root, store, records, imports, recovery, spec = setup(tmp_path)
    base = root / "base-bundle"
    recovery.create_backup(base, [spec], source_generation="base")
    base_export = records.export_history("synthetic_demo")
    store.close()
    ack = killed_acknowledged_writer(root)
    assert Path(str(spec.path) + "-wal").stat().st_size > 0
    before = hashes(spec)
    view = recovery.read_recovery_view([spec])
    objects = view["stores"][0]["objects"]
    assert next(o["payload"] for o in objects if o["object_id"] == ack["accepted_revision"]["revision_id"]) == ack["accepted_revision"]
    assert next(o["payload"] for o in objects if o["object_id"] == ack["context"]["context_event_id"]) == ack["context"]
    latest = root / "latest-bundle"
    manifest = recovery.create_backup(latest, [spec], source_generation="post_cutover")
    assert hashes(spec) == before  # No source checkpoint or implicit writable recovery.
    assert manifest["stores"][0]["inventory"]["latest_events"]["context_event"]["object_id"] == ack["context"]["context_event_id"]
    restored_report = recovery.restore_bundle(latest, root / "restore")
    restored = opened(restored_report)
    restored_records = RecordsService(restored)
    restored_history = restored_records.query_history("synthetic_demo")
    correction = ack["correction"]["revision"]
    assert restored.get("observation_revision", correction["revision_id"], "synthetic_demo") == correction
    assert restored_history["context_events"] == [ack["context"]]
    assert len(restored_history["current"]) == 2  # Base and post-cutover collection, no unrelated duplicate.
    assert len(restored_history["historical"]) == 1
    assert restored_history["historical"][0]["row"]["result"]["decimal"] == "2.0"
    restored.close()
    rollback = recovery.reconstruct_rollback(base, [spec], root / "rollback",
                                             source_generation="rollback_latest")
    assert hashes(spec) == before
    assert rollback["mode"] == "read_only_rollback_reconstruction"
    reconstructed = opened(rollback, readonly=False)  # Explicit new fixture writer, after reconstruction.
    service = RecordsService(reconstructed)
    config = SimpleNamespace(archive_roots={"synthetic": {"path": root / "artificial-csv", "subject_id": "synthetic_demo"}})
    # Originals deliberately outside the bundle, supplied explicitly from our
    # still-present artificial fixture. Physical-original recovery is not claimed.
    from health_analyzer.v2.originals import OriginalsStore
    ImportService(config, service, originals=OriginalsStore(root / "state/originals", readonly=True))
    assert service.commit_review(**ack["review_request"]) == ack["review"]
    assert service.correct_observation(**ack["correction_request"]) == ack["correction"]
    assert reconstructed.get("observation_revision", correction["revision_id"], "synthetic_demo") == correction
    assert reconstructed.get("context_event", ack["context"]["context_event_id"], "synthetic_demo") == ack["context"]
    assert len(reconstructed.list("review_event", "synthetic_demo")) == 2
    assert len(reconstructed.list("correction_event", "synthetic_demo")) == 1
    for kind, values in base_export["objects"].items():
        for value in values:
            assert value in reconstructed.list(kind, "synthetic_demo")
    assert "not_included" in rollback["originals"]
    # No raw key bytes, key repr, packaged secrets or argv/environment keys.
    assert KEY.material not in canonical(manifest)
    assert KEY.material.decode() not in repr(KEY)
    assert {p.name for p in latest.iterdir()} == {"private.sqlite3", "manifest.json"}
    reconstructed.close()


def test_paths_rejected_before_any_database_open_and_source_bytes_unchanged(tmp_path, monkeypatch):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    seal_fixture(store)
    before = hashes(spec)
    link = root / "linked.sqlite3"; link.symlink_to(spec.path)
    hard = root / "hard.sqlite3"; os.link(spec.path, hard)
    calls = []
    real = sqlite3.connect
    monkeypatch.setattr("health_analyzer.v2.recovery.sqlite3.connect", lambda *a, **k: calls.append(a) or real(*a, **k))
    for path in (link, hard, tmp_path / "outside.sqlite3", root / "../outside.sqlite3"):
        with pytest.raises(V2Error):
            recovery.create_backup(root / "bad", [SyntheticStore("private", path, "private-data", KEY.key_id)], source_generation="test")
    assert calls == []
    assert hashes(spec) == before
    hard.unlink()  # Only our deliberately created test hardlink.
    sidecar = Path(str(spec.path) + "-wal"); sidecar.symlink_to(root / "unused")
    with pytest.raises(V2Error): recovery.create_backup(root / "bad", [spec], source_generation="test")
    assert calls == []


def test_foreign_hot_journal_and_unknown_schema_never_initialized_or_restored(tmp_path):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    store.close()
    foreign = root / "foreign.sqlite3"
    fd = os.open(foreign, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
    child = r'''
import signal, sqlite3, sys
db = sqlite3.connect(sys.argv[1], isolation_level=None)
db.execute("PRAGMA journal_mode=DELETE")
db.execute("PRAGMA cache_size=4")
db.execute("CREATE TABLE artificial_foreign(id INTEGER PRIMARY KEY, value BLOB)")
db.execute("BEGIN IMMEDIATE")
db.executemany("INSERT INTO artificial_foreign VALUES (?,?)", [(n, b"x" * 4096) for n in range(64)])
db.execute("COMMIT")
db.execute("BEGIN IMMEDIATE")
db.execute("UPDATE artificial_foreign SET value=?", (b"y" * 4096,))
print("synthetic uncommitted foreign fixture", flush=True)
signal.pause()
'''
    process = subprocess.Popen([sys.executable, "-B", "-c", child, str(foreign)], stdout=subprocess.PIPE, text=True)
    try:
        import select
        assert select.select([process.stdout], [], [], 10)[0]
        assert process.stdout.readline().strip() == "synthetic uncommitted foreign fixture"
        process.kill(); process.wait(timeout=10)
        assert process.returncode == -signal.SIGKILL
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=10)
        process.stdout.close()
    journal = Path(str(foreign) + "-journal")
    assert journal.read_bytes()[:8] == bytes.fromhex("d9d505f920a163d7")
    assert journal.stat().st_size > 512
    before = (foreign.read_bytes(), journal.read_bytes())
    with pytest.raises(V2Error) as error:
        recovery.create_backup(root / "foreign-bundle", [SyntheticStore("private", foreign, "private-data", KEY.key_id)], source_generation="foreign")
    assert error.value.code in {"RECOVERY_INCOMPATIBLE", "RECOVERY_FOREIGN_OR_CORRUPT"}
    assert (foreign.read_bytes(), journal.read_bytes()) == before
    assert not (root / "foreign-bundle").exists()
    writable = SignedStore(spec.path, KEY.material, "private-data")
    writable.put("future_kind", "future", {"subject_id": "synthetic_demo", "schema_version": "future/9"}, "synthetic_demo")
    seal_fixture(writable)
    before = hashes(spec)
    with pytest.raises(V2Error, match="Unknown object kind"):
        recovery.create_backup(root / "future-bundle", [spec], source_generation="future")
    assert hashes(spec) == before and not (root / "future-bundle").exists()


def test_wrong_test_key_tamper_and_incomplete_bundle_fail_without_target(tmp_path):
    root, store, _, _, recovery, spec = setup(tmp_path)
    bundle = root / "bundle"; recovery.create_backup(bundle, [spec], source_generation="valid"); store.close()
    wrong = TestKey(KEY.key_id, b"different artificial key material!")
    mismatch = SyntheticRecovery(root, test_keys={wrong.key_id: wrong})
    with pytest.raises(V2Error): mismatch.restore_bundle(bundle, root / "wrong-restore")
    assert not (root / "wrong-restore").exists()
    manifest_raw = (bundle / "manifest.json").read_bytes()
    data = json.loads(manifest_raw); data["stores"][0]["inventory"]["object_count"] += 1
    (bundle / "manifest.json").write_bytes(canonical(data))
    with pytest.raises(V2Error, match="authentication"):
        recovery.restore_bundle(bundle, root / "tampered-restore")
    assert not (root / "tampered-restore").exists()
    (bundle / "manifest.json").write_bytes(manifest_raw)
    snapshot = bundle / "private.sqlite3"
    raw = snapshot.read_bytes(); snapshot.write_bytes(raw[:-100])
    with pytest.raises(V2Error): recovery.restore_bundle(bundle, root / "truncated-restore")
    assert not (root / "truncated-restore").exists()
    snapshot.write_bytes(raw)
    (bundle / "manifest.json").unlink()
    with pytest.raises(V2Error): recovery.restore_bundle(bundle, root / "partial-restore")
    assert not (root / "partial-restore").exists()


def test_authenticated_manifest_cannot_hide_deleted_or_bad_hmac_objects(tmp_path):
    root, store, _, _, recovery, spec = setup(tmp_path)
    bundle = root / "bundle"; recovery.create_backup(bundle, [spec], source_generation="valid"); store.close()
    snapshot = bundle / "private.sqlite3"
    db = sqlite3.connect(snapshot)
    db.execute("UPDATE v2_objects SET mac=? WHERE kind='context_event'", ("0" * 64,))
    # There is no baseline context; corrupt the committed typed revision instead.
    db.execute("UPDATE v2_objects SET mac=? WHERE kind='observation_revision'", ("0" * 64,)); db.commit(); db.close()
    raw = snapshot.read_bytes()
    resign_manifest(bundle, lambda m: m["stores"][0].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    with pytest.raises(V2Error, match="HMAC"):
        recovery.restore_bundle(bundle, root / "bad-object")
    assert not (root / "bad-object").exists()


def test_multi_domain_requires_explicit_quiesce_and_whole_batch_cap_is_atomic(tmp_path):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    public = SignedStore(root / "state/public.sqlite3", PUBLIC_KEY.material, "public-research")
    public.put("answer_draft", "artificial_answer", {"draft_id": "artificial_answer", "claims": []})
    pubspec = SyntheticStore("public", public.path, "public-research", PUBLIC_KEY.key_id)
    with pytest.raises(V2Error) as error:
        recovery.create_backup(root / "unquiesced", [spec, pubspec], source_generation="multi")
    assert error.value.code == "RECOVERY_QUIESCE_REQUIRED"
    limited = SyntheticRecovery(root, test_keys={KEY.key_id: KEY, PUBLIC_KEY.key_id: PUBLIC_KEY}, max_objects=1)
    before = (hashes(spec), hashes(pubspec))
    with pytest.raises(V2Error) as error:
        limited.create_backup(root / "over-cap", [spec, pubspec], source_generation="multi", synthetic_quiesced=True)
    assert error.value.code == "RECOVERY_LIMIT"
    assert not (root / "over-cap").exists()
    assert (hashes(spec), hashes(pubspec)) == before
    bundle = root / "multi"
    manifest = recovery.create_backup(bundle, [spec, pubspec], source_generation="multi", synthetic_quiesced=True)
    assert manifest["cross_store_atomic_transaction"] is False
    assert len(manifest["stores"]) == 2
    report = recovery.restore_bundle(bundle, root / "multi-restore")
    assert len(report["stores"]) == 2
    # A corrupt second domain never publishes the first restored store.
    snapshot = bundle / "public.sqlite3"; snapshot.write_bytes(snapshot.read_bytes()[:100])
    with pytest.raises(V2Error): recovery.restore_bundle(bundle, root / "no-partial-restore")
    assert not (root / "no-partial-restore").exists()
    store.close(); public.close()


def test_existing_destination_and_bundle_path_escape_are_never_overwritten(tmp_path):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    existing = root / "existing"; existing.mkdir(mode=0o700)
    sentinel = existing / "sentinel"; sentinel.write_bytes(b"keep owned synthetic bytes"); sentinel.chmod(0o600)
    with pytest.raises(V2Error): recovery.create_backup(existing, [spec], source_generation="valid")
    bundle = root / "bundle"; recovery.create_backup(bundle, [spec], source_generation="valid")
    with pytest.raises(V2Error): recovery.restore_bundle(bundle, existing)
    assert sentinel.read_bytes() == b"keep owned synthetic bytes"
    raw = (bundle / "manifest.json").read_bytes()
    data = json.loads(raw); data["stores"][0]["snapshot"] = "../state/private.sqlite3"
    (bundle / "manifest.json").write_bytes(canonical(data))
    with pytest.raises(V2Error): recovery.restore_bundle(bundle, root / "escape")
    assert not (root / "escape").exists()
    store.close()


@pytest.mark.parametrize("mode", ["delete", "conflict"])
def test_rollback_refuses_missing_base_objects_or_same_id_changes(tmp_path, mode):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    base = root / "base"; recovery.create_backup(base, [spec], source_generation="base")
    if mode == "delete":
        store._db.execute("DELETE FROM v2_objects WHERE kind='subject'")
    else:
        original = store.get("subject", "synthetic_demo", "synthetic_demo")
        changed = {**original, "label": "Changed artificial label"}
        envelope = {"domain": "private-data", "kind": "subject", "object_id": "synthetic_demo",
                    "subject_id": "synthetic_demo", "payload": changed}
        store._db.execute("UPDATE v2_objects SET payload=?,mac=? WHERE kind='subject'",
                          (canonical(changed).decode(), store._mac(envelope)))
    seal_fixture(store)
    before = hashes(spec)
    with pytest.raises(V2Error) as error:
        recovery.reconstruct_rollback(base, [spec], root / "rollback", source_generation="current")
    assert error.value.code == ("RECOVERY_BASE_MISSING" if mode == "delete" else "RECOVERY_IMMUTABLE_CONFLICT")
    assert not (root / "rollback").exists() and hashes(spec) == before


def test_wrong_scope_unknown_code_and_byte_caps_fail_closed(tmp_path):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    bundle = root / "bundle"; recovery.create_backup(bundle, [spec], source_generation="valid")
    with pytest.raises(V2Error): recovery.verify_bundle(bundle, expected_generation="wrong")
    resign_manifest(bundle, lambda m: m.update(code_version="unsupported/99"))
    with pytest.raises(V2Error) as error:
        recovery.restore_bundle(bundle, root / "future")
    assert error.value.code == "RECOVERY_INCOMPATIBLE"
    assert not (root / "future").exists()
    limited = SyntheticRecovery(root, test_keys={KEY.key_id: KEY}, max_total_bytes=100)
    before = hashes(spec)
    with pytest.raises(V2Error): limited.create_backup(root / "bytes", [spec], source_generation="valid")
    assert not (root / "bytes").exists() and hashes(spec) == before
    store.close()


def test_bad_subject_envelope_and_typed_source_link_rejected(tmp_path):
    root, store, _, _, recovery, spec = setup(tmp_path)
    # Signed but contract-invalid artificial payload: HMAC is not schema proof.
    store.put("context_event", "bad_scope", {"schema_version": SCHEMA_VERSION,
              "context_event_id": "bad_scope", "subject_id": "other_artificial_subject"}, "synthetic_demo")
    with pytest.raises(V2Error) as error:
        recovery.create_backup(root / "bad-scope", [spec], source_generation="valid")
    assert error.value.code == "RECOVERY_SCOPE"
    store._db.execute("DELETE FROM v2_objects WHERE object_id='bad_scope'")
    rev = store.list("observation_revision", "synthetic_demo")[0]
    changed = {**rev, "source_sha256": "0" * 64}
    env = {"domain": "private-data", "kind": "observation_revision", "object_id": rev["revision_id"],
           "subject_id": "synthetic_demo", "payload": changed}
    store._db.execute("UPDATE v2_objects SET payload=?,mac=? WHERE object_id=?",
                      (canonical(changed).decode(), store._mac(env), rev["revision_id"]))
    with pytest.raises(V2Error) as error:
        recovery.create_backup(root / "bad-link", [spec], source_generation="valid")
    assert error.value.code == "RECOVERY_LINK"
    store.close()


def test_dormant_wal_is_rejected_before_open_without_creating_sidecars(tmp_path, monkeypatch):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    store.close()  # SQLite removes WAL/SHM, main header remains in WAL mode.
    assert not Path(str(spec.path) + "-wal").exists()
    before = hashes(spec)
    calls = []
    monkeypatch.setattr("health_analyzer.v2.recovery.sqlite3.connect", lambda *a, **k: calls.append(a))
    with pytest.raises(V2Error) as error:
        recovery.create_backup(root / "dormant", [spec], source_generation="closed")
    assert error.value.code == "RECOVERY_DORMANT_WAL"
    assert not calls and hashes(spec) == before
    assert not Path(str(spec.path) + "-shm").exists()
    assert not (root / "dormant").exists()


def test_source_writer_change_prevents_publication(tmp_path, monkeypatch):
    root, store, records, _, recovery, spec = setup(tmp_path, baseline=False)
    original = recovery._read
    def competing_fixture_writer(source, destination=None):
        result = original(source, destination)
        if destination is not None:
            records.record_context_event("synthetic_demo", {"kind": "user_note", "event_type": "synthetic_concurrent",
                                         "text": "Artificial concurrent writer deliberately invalidates snapshot generation"})
        return result
    monkeypatch.setattr(recovery, "_read", competing_fixture_writer)
    with pytest.raises(V2Error) as error:
        recovery.create_backup(root / "concurrent", [spec], source_generation="unstable")
    assert error.value.code == "RECOVERY_SOURCE_CHANGED"
    assert not (root / "concurrent").exists()
    store.close()


def test_publication_failure_leaves_no_acceptable_partial_bundle_or_restore(tmp_path, monkeypatch):
    root, store, _, _, recovery, spec = setup(tmp_path, baseline=False)
    original = os.rename
    def fail_manifest_publication(source, target):
        if Path(source).name == "manifest.json":
            raise OSError("Artificial publication interruption")
        return original(source, target)
    monkeypatch.setattr("health_analyzer.v2.recovery.os.rename", fail_manifest_publication)
    with pytest.raises(OSError, match="Artificial publication"):
        recovery.create_backup(root / "interrupted", [spec], source_generation="interrupted")
    with pytest.raises(V2Error): recovery.verify_bundle(root / "interrupted")
    with pytest.raises(V2Error): recovery.restore_bundle(root / "interrupted", root / "from-partial")
    assert not (root / "from-partial").exists()
    assert not (root / "interrupted/manifest.json").exists()
    store.close()
