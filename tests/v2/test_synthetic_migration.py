import base64
import hashlib
import json
import os
import sqlite3

import pytest

from health_analyzer.v2.common import V2Error, canonical
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.migration import (
    CONTEXT_RULE, MAX_PAYLOAD_BYTES, OriginRegistry, SCHEMAS,
    SyntheticLegacyAdapter, SyntheticLegacyFixture,
)

KEY = b'artificial legacy test key only!!' * 2
TARGET_KEY = b'artificial v2 target test key!!!!' * 2


@pytest.fixture
def exercise(tmp_path):
    root = tmp_path / 'exercise'
    create_synthetic_exercise(root)
    return root


def row(legacy_id='raw-01', *, kind='raw_field_confirmation', subject='fictional-a', payload=None):
    if payload is None:
        payload = {'subject_id': subject, 'status': 'legacy_confirmed_raw',
                   'assurance': 'legacy_attested', 'raw_value': 'test value',
                   'clinical_time': 'unknown', 'reviewed_at': 'old raw date, not clinical',
                   'imported_at': 'future? literal 2099', 'binding': {'version': 'test-source-v1'},
                   'extension': {'unrecognized_status': ['future', 42]}}
    return {'legacy_id': legacy_id, 'kind': kind,
            'scope': {'subject_id': subject, 'source_scope': 'fictional-source'}, 'payload': payload}


def fixture(root, records=None, *, name='legacy.sqlite3', snapshot_id='synthetic-snapshot-1', store_id='synthetic-store-1'):
    path = SyntheticLegacyFixture.create(root, root / name, records or [row()], KEY,
                                        snapshot_id=snapshot_id, store_id=store_id)
    return path


def read(root, path, *, key=KEY, salvage=False):
    return SyntheticLegacyAdapter(root, path, key).read(salvage=salvage)


def registry(root):
    return OriginRegistry(root, root / 'target.sqlite3', TARGET_KEY)


def mutate(path, sql, args=()):
    db = sqlite3.connect(path)
    try:
        db.execute(sql, args)
        db.commit()
    finally:
        db.close()


def test_exact_bytes_ids_unknown_status_dates_kind_and_retry(exercise):
    raw = b'{  "subject_id":"fictional-a", "status":"unknown_FUTURE_42", "assurance":"legacy_confirmed_raw", "raw_value":"synthetic", "reviewed_at":"13/??/1900 RAW", "clinical_time":null, "extra":{"binding_id":"raw-binding","unknown":[1,2]} }\n'
    path = fixture(exercise, [row('precise ID а / 01', payload=raw), row('another ID', payload=raw)])
    before = path.read_bytes()
    snapshot = read(exercise, path)
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    inventory = reg.export_inventory()
    again = reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    assert again == result
    assert reg.export_inventory() == inventory
    assert result['counts'] == {'source': 2, 'captured': 2, 'preserved_only': 2, 'quarantined': 0, 'trusted_projected': 0}
    assert result['groups'][0]['legacy_status']['value'] == 'unknown_FUTURE_42'
    assert result['groups'][0]['source_origin_payload_sha256'] == result['groups'][0]['captured_origin_payload_sha256']
    for origin in snapshot.records:
        assert reg.payload_bytes(origin.origin_id) == raw
        stored = reg.store.get('legacy_records', origin.origin_id)
        assert stored['origin']['legacy_id'] == origin.identity['legacy_id']
        assert stored['migration_audit_at'] != '13/??/1900 RAW'
    assert len({record.origin_id for record in snapshot.records}) == 2
    assert reg.store.list('observations', 'fictional-a') == []
    assert reg.store.list('user_confirmations', 'fictional-a') == []
    assert path.read_bytes() == before
    assert not path.with_name(path.name + '-wal').exists()
    assert reg.reconcile(snapshot, run_id=result['run_id'])['counts'] == result['counts']
    reg.close()


def test_opt_in_context_keeps_note_and_calculated_kind(exercise):
    path = fixture(exercise, [row('note', kind='user_note', payload={'subject_id': 'fictional-a', 'text': 'a fictional note', 'status': 'accepted', 'assurance': 'legacy_attested', 'created_at': 'exact old timestamp'}),
                              row('calc', kind='calculation', payload={'subject_id': 'fictional-a', 'formula': '2+2', 'value': 4, 'status': 'calculated'})])
    snapshot = read(exercise, path)
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    assert result['counts']['trusted_projected'] == 2
    projections = reg.store.list('legacy_projection', 'fictional-a')
    assert {p['record_kind'] for p in projections} == {'user_note', 'calculated'}
    assert all(p['confirmation_assurance'] == 'none' and not p['measurement'] and not p['human_validated'] and not p['medical_validated'] for p in projections)
    assert all(p['validation'] == 'integrity_and_rule_structure_only' for p in projections)
    assert projections[0]['legacy_payload'] in [r.parsed_payload for r in snapshot.records]
    reg.close()


def test_default_preserves_even_projectable_context(exercise):
    path = fixture(exercise, [row('note', kind='user_note', payload={'text': 'fictional'})])
    reg = registry(exercise)
    assert reg.import_snapshot(read(exercise, path))['counts']['preserved_only'] == 1
    assert reg.store.list('legacy_projection', 'fictional-a') == []
    reg.close()


@pytest.mark.parametrize('tamper,reason', [
    ('payload', 'record_hmac_failure'), ('signature', 'record_hmac_failure'),
    ('identity_signature', 'fixture_identity_hmac_failure'), ('unknown_schema', 'unknown_schema'),
    ('wrong_key', 'key_mismatch'),
])
def test_integrity_failures_are_explicit_quarantine_with_exact_bytes(exercise, tamper, reason):
    path = fixture(exercise, [row('note', kind='user_note', payload={'text': 'artificial note', 'status': 'accepted', 'assurance': 'legacy_attested'})])
    key = KEY
    if tamper == 'payload':
        mutate(path, 'UPDATE synthetic_records SET payload=?', (b'{"text":"tampered synthetic", "status":"accepted"}',))
    elif tamper == 'signature':
        mutate(path, "UPDATE synthetic_records SET signature='bad signature'")
    elif tamper == 'identity_signature':
        mutate(path, "UPDATE synthetic_identity SET signature='bad identity signature'")
    elif tamper == 'unknown_schema':
        db = sqlite3.connect(path)
        metadata = json.loads(db.execute('SELECT metadata FROM synthetic_identity').fetchone()[0]); db.close()
        metadata['schema_version'] = 'foreign-logical-schema/900'
        mutate(path, 'UPDATE synthetic_identity SET metadata=?', (canonical(metadata),))
    else:
        key = b'explicit other artificial test key' * 2
    before = path.read_bytes()
    with pytest.raises(V2Error) as err:
        read(exercise, path, key=key)
    assert err.value.code == 'SYNTHETIC_INTEGRITY'
    snapshot = read(exercise, path, key=key, salvage=True)
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    assert result['counts']['quarantined'] == 1 and result['counts']['trusted_projected'] == 0
    origin = snapshot.records[0]
    quarantine = reg.store.get('quarantine', origin.origin_id)
    assert reason in quarantine['reasons']
    assert quarantine['payload_reference'] == origin.origin_id
    assert reg.payload_bytes(origin.origin_id) == origin.raw_payload
    assert reg.export_inventory()['object_counts']['legacy_records'] == 1
    assert path.read_bytes() == before
    reg.close()


def test_cross_subject_payload_cannot_be_projected(exercise):
    path = fixture(exercise, [row('note', kind='user_note', payload={'subject_id': 'fictional-b', 'text': 'synthetic'})])
    snapshot = read(exercise, path, salvage=True)
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    assert result['counts']['quarantined'] == 1
    assert 'subject_binding_mismatch' in snapshot.records[0].integrity_reasons
    reg.close()


def test_identical_value_distinct_scopes_stores_and_ids_do_not_merge(exercise):
    path = fixture(exercise, [row('same', subject='fictional-a'), row('same', subject='fictional-b'), row('different', subject='fictional-a')])
    reg = registry(exercise)
    result = reg.import_snapshot(read(exercise, path))
    other = fixture(exercise, [row('same')], name='other.sqlite3', store_id='other-synthetic-store')
    reg.import_snapshot(read(exercise, other))
    assert result['counts']['source'] == 3
    assert reg.export_inventory()['object_counts']['legacy_records'] == 4
    reg.close()


def test_same_origin_conflicting_payload_rolls_back_whole_batch(exercise):
    original = fixture(exercise)
    reg = registry(exercise)
    reg.import_snapshot(read(exercise, original))
    before = reg.export_inventory()
    conflict = fixture(exercise, [row('new'), row(payload={'raw_value': 'changed artificial'})], name='conflict.sqlite3')
    with pytest.raises(V2Error) as err:
        reg.import_snapshot(read(exercise, conflict))
    assert err.value.code == 'MIGRATION_ORIGIN_CONFLICT'
    assert reg.export_inventory() == before
    reg.close()


def test_duplicate_origin_is_not_silently_collapsed(exercise):
    path = fixture(exercise)
    mutate(path, 'INSERT INTO synthetic_records SELECT * FROM synthetic_records')
    with pytest.raises(V2Error) as err:
        read(exercise, path, salvage=True)
    assert err.value.code == 'MIGRATION_DUPLICATE_ORIGIN'


def test_source_count_cap_fail_closed(exercise):
    path = fixture(exercise)
    db = sqlite3.connect(path)
    try:
        record = db.execute('SELECT * FROM synthetic_records').fetchone()
        db.executemany('INSERT INTO synthetic_records VALUES (?,?,?,?,?,?)', [record] * 10_000)
        db.commit()
    finally:
        db.close()
    with pytest.raises(V2Error) as err:
        read(exercise, path, salvage=True)
    assert err.value.code == 'MIGRATION_COUNT_LIMIT'


def test_payload_cap_and_full_size_exact_bytes(exercise):
    raw = b'{"text":"' + b'x' * (MAX_PAYLOAD_BYTES - len(b'{"text":""}')) + b'"}'
    assert len(raw) == MAX_PAYLOAD_BYTES
    path = fixture(exercise, [row(payload=raw)])
    reg = registry(exercise)
    snapshot = read(exercise, path)
    reg.import_snapshot(snapshot)
    assert reg.payload_bytes(snapshot.records[0].origin_id) == raw
    assert reg.export_inventory()['object_counts']['legacy_payload_chunk'] == 2
    mutate(path, 'UPDATE synthetic_records SET payload=?', (raw + b' ',))
    with pytest.raises(V2Error) as err:
        read(exercise, path, salvage=True)
    assert err.value.code == 'MIGRATION_PAYLOAD_LIMIT'
    reg.close()


def test_aggregate_byte_cap_before_signature_or_capture(exercise, monkeypatch):
    import health_analyzer.v2.migration as module
    path = fixture(exercise, [row('one'), row('two')])
    monkeypatch.setattr(module, 'MAX_BATCH_BYTES', 100)
    with pytest.raises(V2Error) as err:
        read(exercise, path, salvage=True)
    assert err.value.code == 'MIGRATION_BYTE_LIMIT'


def test_late_transaction_failure_has_no_partial_capture(exercise, monkeypatch):
    snapshot = read(exercise, fixture(exercise, [row('one'), row('two')]))
    reg = registry(exercise)
    original_put = reg.store.put
    def fail(kind, *args, **kwargs):
        if kind == 'migration_disposition':
            raise RuntimeError('synthetic injected late failure')
        return original_put(kind, *args, **kwargs)
    monkeypatch.setattr(reg.store, 'put', fail)
    with pytest.raises(RuntimeError):
        reg.import_snapshot(snapshot)
    assert all(value == 0 for value in reg.export_inventory()['object_counts'].values())
    monkeypatch.setattr(reg.store, 'put', original_put)
    assert reg.import_snapshot(snapshot)['counts']['captured'] == 2
    reg.close()


@pytest.mark.parametrize('injection,code', [('orphan', 'MIGRATION_ORPHAN'), ('cross_subject', 'MIGRATION_CROSS_SUBJECT'), ('extra_disposition', 'MIGRATION_PARTITION'), ('invalid_disposition', 'MIGRATION_PARTITION')])
def test_reconciliation_rejects_orphan_cross_subject_and_bad_partition(exercise, injection, code):
    snapshot = read(exercise, fixture(exercise, [row('note', kind='user_note', payload={'text': 'synthetic'})]))
    reg = registry(exercise)
    reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    origin = snapshot.records[0].origin_id
    if injection == 'orphan':
        reg._put('legacy_projection', 'orphan-projection', {'projection_id': 'orphan-projection', 'origin_id': 'absent', 'subject_id': 'fictional-z'}, 'fictional-z')
    elif injection == 'extra_disposition':
        reg._put('migration_disposition', 'absent', {'origin_id': 'absent', 'subject_id': 'fictional-a', 'disposition': 'preserved_only'})
    else:
        # Re-sign intentional synthetic corruption so structural checks, rather
        # than the storage MAC alone, must reject it.
        kind = 'legacy_mapping' if injection == 'cross_subject' else 'migration_disposition'
        value = reg.store.get(kind, origin)
        if injection == 'cross_subject':
            value['subject_id'] = 'fictional-b'
        else:
            value['disposition'] = 'both trusted and preserved'
        reg.store._db.execute('DELETE FROM v2_objects WHERE kind=? AND object_id=?', (kind, origin))
        reg.store.put(kind, origin, value)
    with pytest.raises(V2Error) as err:
        reg.reconcile(snapshot)
    assert err.value.code == code
    reg.close()


def test_signed_duplicate_payload_identity_is_rejected(exercise):
    snapshot = read(exercise, fixture(exercise))
    reg = registry(exercise)
    reg.import_snapshot(snapshot)
    value = reg.store.get('legacy_records', snapshot.records[0].origin_id)
    reg.store.put('legacy_records', 'extra-object-same-origin', value)
    with pytest.raises(V2Error) as err:
        reg.reconcile(snapshot)
    assert err.value.code == 'MIGRATION_OBJECT_IDENTITY'
    reg.close()


def test_external_symlink_hardlink_and_other_exercise_rejected(exercise, tmp_path):
    path = fixture(exercise)
    external = tmp_path / 'outside.sqlite3'
    external.write_bytes(path.read_bytes())
    with pytest.raises(V2Error):
        read(exercise, external)
    link = exercise / 'link.sqlite3'; link.symlink_to(external)
    with pytest.raises(V2Error):
        read(exercise, link)
    hard = exercise / 'hard.sqlite3'; os.link(external, hard)
    with pytest.raises(V2Error):
        read(exercise, hard)
    other = tmp_path / 'other'; create_synthetic_exercise(other)
    copied = other / 'copied.sqlite3'; copied.write_bytes(path.read_bytes())
    with pytest.raises(V2Error) as err:
        read(other, copied, salvage=True)
    assert err.value.code == 'SYNTHETIC_IDENTITY'


def test_live_wal_and_foreign_physical_schema_rejected_without_writes(exercise):
    path = fixture(exercise)
    db = sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('INSERT INTO synthetic_records SELECT * FROM synthetic_records'); db.commit()
    main = path.read_bytes(); wal = path.with_name(path.name + '-wal').read_bytes()
    with pytest.raises(V2Error) as err:
        read(exercise, path, salvage=True)
    assert err.value.code == 'SYNTHETIC_NOT_SEALED'
    assert path.read_bytes() == main and path.with_name(path.name + '-wal').read_bytes() == wal
    db.close()
    foreign = exercise / 'foreign.sqlite3'
    db = sqlite3.connect(foreign); db.execute('CREATE TABLE foreign_data (x)'); db.commit(); db.close()
    before = foreign.read_bytes()
    with pytest.raises(V2Error) as err:
        read(exercise, foreign, salvage=True)
    assert err.value.code == 'SYNTHETIC_FOREIGN_SCHEMA'
    assert foreign.read_bytes() == before


def test_snapshot_object_or_source_change_rejected_before_target_capture(exercise):
    path = fixture(exercise)
    snapshot = read(exercise, path)
    snapshot.records[0].identity['legacy_id'] = 'caller alteration'
    reg = registry(exercise)
    with pytest.raises(V2Error) as err:
        reg.import_snapshot(snapshot)
    assert err.value.code == 'SYNTHETIC_SOURCE_CHANGED'
    assert reg.export_inventory()['object_counts']['legacy_records'] == 0
    reg.close()


def test_wal_header_without_sidecars_is_not_adopted(exercise):
    path = fixture(exercise)
    db = sqlite3.connect(path); db.execute('PRAGMA journal_mode=WAL'); db.close()
    assert not path.with_name(path.name + '-wal').exists()
    before = path.read_bytes()
    with pytest.raises(V2Error) as err:
        read(exercise, path, salvage=True)
    assert err.value.code == 'SYNTHETIC_NOT_SEALED'
    assert path.read_bytes() == before
    assert not path.with_name(path.name + '-wal').exists()
    assert not path.with_name(path.name + '-shm').exists()


@pytest.mark.parametrize('raw', [b'{"status":"first","status":"second"}', b'not json at all', b'{"x":NaN}', b''])
def test_unparseable_or_ambiguous_payload_is_quarantined_without_byte_rewrite(exercise, raw):
    path = fixture(exercise, [row('ambiguous', payload=raw)])
    snapshot = read(exercise, path, salvage=True)
    assert 'unparseable_payload' in snapshot.records[0].integrity_reasons
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    assert result['counts']['quarantined'] == 1
    assert reg.payload_bytes(snapshot.records[0].origin_id) == raw
    reg.close()


def test_projection_payload_status_and_assurance_cannot_be_changed(exercise):
    snapshot = read(exercise, fixture(exercise, [row('note', kind='user_note', payload={'text': 'synthetic', 'status': 'raw accepted', 'assurance': 'legacy_attested'})]))
    reg = registry(exercise)
    reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    projection = reg.store.list('legacy_projection', 'fictional-a')[0]
    projection['legacy_payload']['assurance'] = 'invented human proof'
    object_id = projection['projection_id']
    reg.store._db.execute('DELETE FROM v2_objects WHERE kind=? AND object_id=?', ('legacy_projection', object_id))
    reg.store.put('legacy_projection', object_id, projection, 'fictional-a')
    with pytest.raises(V2Error) as err:
        reg.reconcile(snapshot)
    assert err.value.code == 'MIGRATION_STATUS_UPGRADE'
    reg.close()


def test_non_ascii_signature_is_explicit_quarantine(exercise):
    path = fixture(exercise)
    mutate(path, 'UPDATE synthetic_records SET signature=?', ('не подпись',))
    snapshot = read(exercise, path, salvage=True)
    assert 'record_hmac_failure' in snapshot.records[0].integrity_reasons
    reg = registry(exercise)
    assert reg.import_snapshot(snapshot)['counts']['quarantined'] == 1
    reg.close()


def replace_signed_object(reg, kind, object_id, payload, subject=None):
    # Deliberately re-sign synthetic corruption, exercising semantic invariants
    # independently of the storage HMAC. No actual legacy/production DB is used.
    reg.store._db.execute('DELETE FROM v2_objects WHERE kind=? AND object_id=?', (kind, object_id))
    reg.store.put(kind, object_id, payload, subject)


def test_multiple_distinct_projections_for_fixed_single_origin_are_rejected(exercise):
    snapshot = read(exercise, fixture(exercise, [row('note', kind='user_note', payload={'text': 'synthetic'})]))
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot, projection_rules=[CONTEXT_RULE])
    original = reg.store.list('legacy_projection', 'fictional-a')[0]
    duplicate = dict(original)
    duplicate['projection_id'] = 'distinct-signed-projection-alias'
    reg.store.put('legacy_projection', duplicate['projection_id'], duplicate, 'fictional-a')
    origin_id = snapshot.records[0].origin_id
    mapping = reg.store.get('legacy_mapping', origin_id)
    mapping['projection_ids'].append(duplicate['projection_id'])
    replace_signed_object(reg, 'legacy_mapping', origin_id, mapping)
    with pytest.raises(V2Error) as err:
        reg.reconcile(snapshot, run_id=result['run_id'])
    assert err.value.code == 'MIGRATION_PARTITION'
    reg.close()


@pytest.mark.parametrize('field,value', [
    ('counts', {'source': 999}), ('mapping_version', 'unreviewed-new-rule/999'),
    ('source_snapshot', {'schema_version': 'invented'}), ('source_identity_signature', 'changed identity signature'),
    ('source_identity_bytes_b64', 'YWx0ZXJlZA=='), ('source_hash_scope', 'unproven_live_database'),
    ('target_schema', 'unrelated-target/900'), ('salvage', True),
    ('projection_rules', ['foreign-rule/999']), ('group_ids', []), ('stage', 'real-cutover-complete'),
])
def test_signed_run_semantic_field_tampering_is_rejected(exercise, field, value):
    snapshot = read(exercise, fixture(exercise))
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot)
    run_id = result['run_id']
    run = reg.store.get('migration_run', run_id)
    run[field] = value
    replace_signed_object(reg, 'migration_run', run_id, run)
    with pytest.raises(V2Error) as err:
        reg.reconcile(snapshot, run_id=run_id)
    assert err.value.code == 'MIGRATION_RECONCILIATION'
    reg.close()


@pytest.mark.parametrize('change', ['count', 'payload_hash', 'status', 'missing', 'extra'])
def test_persisted_run_groups_are_verified_and_compared_to_recomputed_groups(exercise, change):
    snapshot = read(exercise, fixture(exercise))
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot)
    run_id = result['run_id']
    group_id = reg.store.get('migration_run', run_id)['group_ids'][0]
    group = reg.store.get('migration_reconciliation_group', group_id)
    if change == 'missing':
        reg.store._db.execute('DELETE FROM v2_objects WHERE kind=? AND object_id=?', ('migration_reconciliation_group', group_id))
    elif change == 'extra':
        group['group_id'] = 'extra-signed-group'
        reg.store.put('migration_reconciliation_group', group['group_id'], group)
    else:
        if change == 'count':
            group['captured_count'] = 999
        elif change == 'payload_hash':
            group['source_origin_payload_sha256'] = '0' * 64
        else:
            group['legacy_status']['value'] = 'changed-status'
        replace_signed_object(reg, 'migration_reconciliation_group', group_id, group)
    with pytest.raises(V2Error) as err:
        reg.reconcile(snapshot, run_id=run_id)
    assert err.value.code == 'MIGRATION_RECONCILIATION'
    reg.close()


def test_repeat_import_revalidates_existing_run_before_acknowledgement(exercise):
    snapshot = read(exercise, fixture(exercise))
    reg = registry(exercise)
    result = reg.import_snapshot(snapshot)
    run = reg.store.get('migration_run', result['run_id'])
    run['counts']['captured'] = 999
    replace_signed_object(reg, 'migration_run', result['run_id'], run)
    with pytest.raises(V2Error) as err:
        reg.import_snapshot(snapshot)
    assert err.value.code == 'MIGRATION_RECONCILIATION'
    reg.close()
