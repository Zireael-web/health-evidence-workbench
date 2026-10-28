"""Synthetic read-only preview retrieval, WAL and integrity acceptance."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

import pytest

from health_analyzer.v2 import cli
from health_analyzer.v2.common import SignedStore, V2Error, digest
from health_analyzer.v2.configuration import initialize, open_domain_key, read_key_fd
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.runtime import open_services
from test_records import make_row, coverage, attest

KEY = b's' * 32  # Synthetic domain key, never an installed key.


def seed(path, key=KEY):
    store = SignedStore(path, key, 'private-data')
    records = RecordsService(store)
    records.register_subject('demo', 'Synthetic preview')
    records.register_subject('other', 'Other synthetic preview')
    version = records.register_document('demo', 'a' * 64, 'text/csv', 100)
    records.submit_extraction('demo', version['version_id'], [make_row(version)], coverage(1))
    snapshot = records.prepare_review('demo', version['version_id'])
    return store, records, version, snapshot


def state_bytes(path):
    return {suffix: p.read_bytes() for suffix in ('', '-wal')
            if (p := Path(str(path) + suffix)).exists()}


def test_readonly_missing_store_creates_no_directory_or_file(tmp_path):
    missing = tmp_path / 'absent-parent' / 'missing.sqlite3'
    with pytest.raises(V2Error) as error:
        SignedStore(missing, KEY, 'private-data', readonly=True)
    assert error.value.code == 'STORE_READ_ONLY'
    assert not missing.parent.exists()


@pytest.mark.parametrize('payload', [b'', b'not a database'])
def test_readonly_uninitialized_store_does_not_create_schema_or_files(tmp_path, payload):
    path = tmp_path / 'uninitialized.sqlite3'
    path.write_bytes(payload)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(V2Error):
        SignedStore(path, KEY, 'private-data', readonly=True)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_readonly_foreign_hot_journal_remains_byte_exact(tmp_path):
    path = tmp_path / 'foreign.sqlite3'
    con = sqlite3.connect(path)
    con.execute('CREATE TABLE legacy (value TEXT)')
    con.executemany('INSERT INTO legacy VALUES (?)', [('x' * 1000,) for _ in range(1000)])
    con.commit()
    con.close()
    program = """import os,sqlite3,sys
c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA cache_size=1')
c.execute('BEGIN IMMEDIATE'); c.execute("UPDATE legacy SET value='synthetic unfinished update'")
os._exit(0)
"""
    subprocess.run([sys.executable, '-c', program, str(path)], check=True, timeout=10)
    journal = Path(str(path) + '-journal')
    assert journal.is_file() and journal.stat().st_size > 0
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(V2Error) as error:
        SignedStore(path, KEY, 'private-data', readonly=True)
    assert error.value.code == 'FOREIGN_STORE'
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_readonly_put_and_write_sql_fail_with_no_mutation(tmp_path):
    path = tmp_path / 'private.sqlite3'
    writer, _, _, _ = seed(path)
    before = state_bytes(path)
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    trace = []
    reader._db.set_trace_callback(trace.append)
    with pytest.raises(V2Error) as error:
        reader.put('event', 'forbidden', {}, 'demo')
    assert error.value.code == 'STORE_READ_ONLY'
    with pytest.raises(sqlite3.OperationalError):
        reader._db.execute("DELETE FROM v2_objects")
    with reader.transaction():
        assert reader.list('subject', 'demo')
    assert 'BEGIN' in trace and 'BEGIN IMMEDIATE' not in trace
    assert not any('journal_mode' in item.lower() or 'synchronous' in item.lower()
                   or 'checkpoint' in item.lower() for item in trace)
    reader.close()
    assert state_bytes(path) == before
    writer.close()


def test_readonly_latest_acknowledged_wal_visible_and_close_preserves_bytes(tmp_path):
    path = tmp_path / 'acknowledged.sqlite3'
    program = """from health_analyzer.v2.common import SignedStore
import os,sys
s=SignedStore(sys.argv[1],b's'*32,'private-data')
s.put('event','acknowledged',{'synthetic':'latest WAL'},'demo')
print('acknowledged',flush=True); os._exit(0)
"""
    env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[2] / 'src'),
           'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run([sys.executable, '-B', '-c', program, str(path)], env=env,
                            capture_output=True, text=True, check=True, timeout=10)
    assert result.stdout.strip() == 'acknowledged'
    before = state_bytes(path)
    assert '-wal' in before and before['-wal']
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    assert reader.get('event', 'acknowledged', 'demo') == {'synthetic': 'latest WAL'}
    reader.close()
    assert state_bytes(path) == before


def test_snapshot_read_is_exact_current_and_never_checks_source_or_writes(tmp_path):
    path = tmp_path / 'private.sqlite3'
    writer, _, _, snapshot = seed(path)
    before = state_bytes(path)
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    def forbidden(_):
        pytest.fail('Snapshot state check must not inspect source bytes or write availability events')
    records = RecordsService(reader, source_checker=forbidden)
    first = records.get_review_snapshot('demo', snapshot['snapshot_id'])
    second = records.get_review_snapshot('demo', snapshot['snapshot_id'])
    assert first['snapshot'] == snapshot == second['snapshot']
    assert first['snapshot']['snapshot_sha256'] == digest({k: v for k, v in snapshot.items()
                                                         if k != 'snapshot_sha256'})
    assert first['verification']['method'] == 'signed_store_hmac'
    assert first['verification']['state'] == 'current' and first['verification']['reasons'] == []
    assert first['verification']['source_bytes_checked'] is False
    assert first['verification']['clinical_validation'] == 'not_provided'
    assert len(reader.list('review_snapshot', 'demo')) == 1
    assert reader.list('review_event', 'demo') == reader.list('source_availability', 'demo') == []
    reader.close()
    assert state_bytes(path) == before
    writer.close()


def test_snapshot_hmac_and_canonical_hash_tamper_fail(tmp_path):
    path = tmp_path / 'private.sqlite3'
    writer, _, _, snapshot = seed(path)
    row = writer._db.execute("SELECT * FROM v2_objects WHERE kind='review_snapshot'").fetchone()
    changed = copy.deepcopy(snapshot)
    changed['offset'] = 999
    # Tampered bytes without a new HMAC must fail before trusting their digest.
    writer._db.execute("UPDATE v2_objects SET payload=? WHERE kind='review_snapshot'",
                       (json.dumps(changed),))
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    with pytest.raises(V2Error) as error:
        RecordsService(reader).get_review_snapshot('demo', snapshot['snapshot_id'])
    assert error.value.code == 'INTEGRITY_FAILURE'
    reader.close()
    # A synthetically signed bad frozen digest is independently rejected too.
    mac = writer._mac({'domain': 'private-data', 'kind': 'review_snapshot',
                       'object_id': row['object_id'], 'subject_id': 'demo', 'payload': changed})
    writer._db.execute("UPDATE v2_objects SET mac=? WHERE kind='review_snapshot'", (mac,))
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    with pytest.raises(V2Error) as error:
        RecordsService(reader).get_review_snapshot('demo', snapshot['snapshot_id'])
    assert error.value.code == 'snapshot_hash_mismatch'
    reader.close()
    writer.close()


def test_wrong_subject_snapshot_read_rejected(tmp_path):
    path = tmp_path / 'private.sqlite3'
    writer, _, _, snapshot = seed(path)
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    with pytest.raises(V2Error) as error:
        RecordsService(reader).get_review_snapshot('other', snapshot['snapshot_id'])
    assert error.value.code == 'WRONG_SUBJECT'
    reader.close()
    writer.close()


def test_signed_digest_valid_snapshot_cannot_claim_other_source_bytes(tmp_path):
    path = tmp_path / 'private.sqlite3'
    writer, _, _, snapshot = seed(path)
    forged = copy.deepcopy(snapshot)
    forged['source_sha256'] = 'b' * 64
    forged['snapshot_sha256'] = digest({k: v for k, v in forged.items() if k != 'snapshot_sha256'})
    mac = writer._mac({'domain': 'private-data', 'kind': 'review_snapshot',
                       'object_id': snapshot['snapshot_id'], 'subject_id': 'demo', 'payload': forged})
    writer._db.execute("UPDATE v2_objects SET payload=?,mac=? WHERE kind='review_snapshot'",
                       (json.dumps(forged), mac))
    before = state_bytes(path)
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    with pytest.raises(V2Error) as error:
        RecordsService(reader).get_review_snapshot('demo', snapshot['snapshot_id'])
    assert error.value.code == 'snapshot_source_mismatch'
    reader.close()
    assert state_bytes(path) == before
    writer.close()


def test_snapshot_selection_staleness_including_return_to_same_run(tmp_path):
    path = tmp_path / 'private.sqlite3'
    writer, records, version, snapshot = seed(path)
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    readonly_records = RecordsService(reader)
    records.submit_extraction('demo', version['version_id'], [make_row(version, '5.6')], coverage(1))
    changed = readonly_records.get_review_snapshot('demo', snapshot['snapshot_id'])
    assert set(changed['verification']['reasons']) == {'extraction_run_changed', 'extraction_selection_changed'}
    records.submit_extraction('demo', version['version_id'], [make_row(version)], coverage(1))
    before = state_bytes(path)
    returned = readonly_records.get_review_snapshot('demo', snapshot['snapshot_id'])
    assert returned['verification']['reasons'] == ['extraction_selection_changed']
    assert returned['snapshot'] == snapshot
    reader.close()
    assert state_bytes(path) == before
    writer.close()


def test_review_and_revision_staleness_does_not_change_events(tmp_path):
    path = tmp_path / 'private.sqlite3'
    writer, records, version, snapshot = seed(path)
    decisions = [{'draft_id': snapshot['rows'][0]['draft_id'], 'action': 'confirm'}]
    records.commit_review('demo', snapshot['snapshot_id'], snapshot['snapshot_sha256'], decisions,
                          attest(snapshot), 'synthetic-confirm')
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    stale = RecordsService(reader).get_review_snapshot('demo', snapshot['snapshot_id'])
    assert set(stale['verification']['reasons']) == {'review_state_changed', 'observation_revision_changed'}
    fresh = records.prepare_review('demo', version['version_id'])
    previous = records._latest_revisions('demo')[snapshot['rows'][0]['observation_id']]
    evidence = {**attest(fresh), 'snapshot_id': previous['revision_id'], 'snapshot_sha256': digest(previous)}
    records.correct_observation('demo', previous['observation_id'],
                                {'result': {'kind': 'numeric_exact', 'raw': '5.7', 'decimal': '5.7'}},
                                'Synthetic corrected reading', evidence)
    before = state_bytes(path)
    revised = RecordsService(reader).get_review_snapshot('demo', fresh['snapshot_id'])
    assert revised['verification']['reasons'] == ['observation_revision_changed']
    assert len(reader.list('review_event', 'demo')) == 1
    assert len(reader.list('correction_event', 'demo')) == 1
    assert len(reader.list('review_snapshot', 'demo')) == 2
    reader.close()
    assert state_bytes(path) == before
    writer.close()


def test_read_transaction_is_consistent_while_writer_commits(tmp_path):
    path = tmp_path / 'private.sqlite3'
    writer = SignedStore(path, KEY, 'private-data')
    writer.put('event', 'first', {'n': 1}, 'demo')
    reader = SignedStore(path, KEY, 'private-data', readonly=True)
    with reader.transaction():
        assert reader.list('event', 'demo') == [{'n': 1}]
        writer.put('event', 'second', {'n': 2}, 'demo')
        assert reader.list('event', 'demo') == [{'n': 1}]
    assert reader.list('event', 'demo') == [{'n': 1}, {'n': 2}]
    reader.close()
    writer.close()


def test_runtime_readonly_surface_has_exactly_eight_private_tools(tmp_path):
    config = initialize(tmp_path / 'config.json', tmp_path / 'data', isolation='host')
    key = read_key_fd(open_domain_key(config, 'private-data'))
    writer, _, _, snapshot = seed(config.store_path('private-data'), key)
    before = state_bytes(writer.path)
    private = open_services(config, 'private-data', key, readonly=True)
    assert set(private.tools) == {'get_review_snapshot', 'get_source_version',
                                 'get_case_selection', 'get_private_calculation',
                                 'get_private_answer_review', 'get_document_text',
                                 'list_document_texts', 'get_document_view'}
    assert private.call('get_review_snapshot', {'subject_id': 'demo', 'snapshot_id': snapshot['snapshot_id']})['snapshot'] == snapshot
    with pytest.raises(V2Error) as error:
        private.call('prepare_review', {'subject_id': 'demo'})
    assert error.value.code == 'tool_unavailable'
    private.close()
    assert state_bytes(writer.path) == before
    public_key = read_key_fd(open_domain_key(config, 'public-research'))
    public = open_services(config, 'public-research', public_key)
    assert 'get_review_snapshot' not in public.tools and 'get_source_version' not in public.tools
    public.close()
    with pytest.raises(V2Error) as error:
        open_services(config, 'public-research', public_key, readonly=True)
    assert error.value.code == 'scope_violation'
    writer.close()


@pytest.mark.parametrize('tool', ['get_review_snapshot', 'get_source_version'])
def test_cli_read_call_uses_existing_synthetic_store_without_events(tmp_path, tool):
    config = initialize(tmp_path / 'config.json', tmp_path / 'data', isolation='host')
    key = read_key_fd(open_domain_key(config, 'private-data'))
    writer, _, version, snapshot = seed(config.store_path('private-data'), key)
    before = state_bytes(writer.path)
    arguments = {'subject_id': 'demo', 'snapshot_id': snapshot['snapshot_id']} if tool == 'get_review_snapshot' else {
        'subject_id': 'demo', 'version_id': version['version_id']}
    request = tmp_path / 'request.json'
    request.write_text(json.dumps(arguments))
    result = subprocess.run([sys.executable, '-I', '-B', str(cli.entry_path()), '--config', str(config.path),
                             'call', '--zone', 'private-data', '--tool', tool,
                             '--arguments-file', str(request)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output['snapshot'] == snapshot if tool == 'get_review_snapshot' else output['version_id'] == version['version_id']
    assert state_bytes(writer.path) == before
    assert writer.list('review_event', 'demo') == []
    assert writer.list('source_availability', 'demo') == []
    assert len(writer.list('review_snapshot', 'demo')) == 1
    writer.close()


def test_cli_read_call_cannot_initialize_missing_private_store(tmp_path):
    config = initialize(tmp_path / 'config.json', tmp_path / 'data', isolation='host')
    path = config.store_path('private-data')
    # Remove only this newly initialized synthetic test database.
    path.unlink()
    assert not path.exists()
    request = tmp_path / 'request.json'
    request.write_text('{"subject_id":"demo","snapshot_id":"snapshot_missing"}')
    result = subprocess.run([sys.executable, '-I', '-B', str(cli.entry_path()), '--config', str(config.path),
                             'call', '--zone', 'private-data', '--tool', 'get_review_snapshot',
                             '--arguments-file', str(request)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 2 and 'STORE_READ_ONLY' in result.stderr
    assert not path.exists()


def tree_state(root):
    """No direct reads of even synthetic key bytes; include key metadata only."""
    state = {}
    for path in [root, *sorted(root.rglob('*'))]:
        relative = path.relative_to(root)
        if path.name.endswith('-shm'):
            continue  # Normal SQLite read-lock coordination, not DB/WAL data.
        metadata = path.stat()
        value = (metadata.st_mode, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        if path.is_file() and 'keys' not in relative.parts:
            value += (path.read_bytes(),)
        state[str(relative)] = value
    return state


@pytest.mark.skipif(sys.platform != 'darwin', reason='Actual enforced macOS readonly launch')
@pytest.mark.parametrize('tool', ['get_review_snapshot', 'get_source_version'])
def test_enforced_readonly_cli_preserves_profiles_native_originals_and_database(tmp_path, tool):
    from health_analyzer.v2.ingest import ImportService
    archive = tmp_path / 'synthetic-archive'
    archive.mkdir()
    source = archive / 'synthetic.csv'
    source.write_text('analyte;result;unit;collected;specimen;method\nSynthetic;5;u;2026-01-01;serum;m1\n')
    config = initialize(tmp_path / 'config.json', tmp_path / 'data', isolation='macos_enforced',
                        archive_roots={'demo': {'path': str(archive), 'subject_id': 'demo'}})
    key = read_key_fd(open_domain_key(config, 'private-data'))
    writer = SignedStore(config.store_path('private-data'), key, 'private-data')
    records = RecordsService(writer)
    records.register_subject('demo', 'Synthetic enforced preview')
    imported = ImportService(config, records).prepare_import('demo', [{'root_id': 'demo', 'relative_path': source.name}])
    document = imported['documents'][0]
    snapshot = records.prepare_review('demo', document['version_id'])
    old_policy = config.data_root / 'bootstrap' / 'private-data.sb'
    old_policy.write_bytes(b'SYNTHETIC existing profile; must not be used or overwritten')
    native = config.data_root / 'bootstrap' / 'native'
    native.mkdir()
    (native / 'synthetic-marker').write_bytes(b'Existing synthetic native metadata')
    arguments = {'subject_id': 'demo', 'snapshot_id': snapshot['snapshot_id']} if tool == 'get_review_snapshot' else {
        'subject_id': 'demo', 'version_id': document['version_id']}
    request = tmp_path / 'request.json'
    request.write_text(json.dumps(arguments))
    before_tree = tree_state(config.data_root)
    before_config = config.path.read_bytes()
    before_source = source.read_bytes()
    result = subprocess.run([sys.executable, '-I', '-B', str(cli.entry_path()), '--config', str(config.path),
                             'call', '--zone', 'private-data', '--tool', tool,
                             '--arguments-file', str(request)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    if tool == 'get_review_snapshot':
        assert output['snapshot'] == snapshot and output['verification']['state'] == 'current'
    else:
        assert output['saved_status'] == 'available'
        assert output['archive_sources'][0]['status'] == 'same_bytes'
    assert tree_state(config.data_root) == before_tree
    assert config.path.read_bytes() == before_config and source.read_bytes() == before_source
    assert writer.list('review_event', 'demo') == writer.list('source_availability', 'demo') == []
    assert len(writer.list('review_snapshot', 'demo')) == 1
    writer.close()


@pytest.mark.skipif(sys.platform != 'darwin', reason='Actual enforced macOS temporary policy')
def test_temporary_readonly_policy_keeps_private_network_denial(tmp_path):
    config = initialize(tmp_path / 'config.json', tmp_path / 'data', isolation='macos_enforced')
    before = tree_state(config.data_root)
    with tempfile.TemporaryDirectory(prefix='ha-v2-test-read-policy-') as scratch:
        prefix = cli._sandbox_prefix(config, 'private-data', _policy_dir=Path(scratch).resolve())
        policy = Path(prefix[-1])
        assert policy.read_text() == cli.sandbox_policy(config, 'private-data')
        program = """import errno,json,socket
try:
 s=socket.socket(); s.settimeout(.5); s.connect(('127.0.0.1',9)); result=False
except OSError as e:
 result=e.errno in (errno.EPERM,errno.EACCES)
print(json.dumps({'network_denied':result}))
"""
        result = subprocess.run(prefix + [sys.executable, '-I', '-B', '-c', program],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {'network_denied': True}
    assert not policy.exists()
    assert tree_state(config.data_root) == before


def test_readonly_runtime_rejects_pdf_bridge_before_key_read(tmp_path):
    config = initialize(tmp_path / 'config.json', tmp_path / 'data', isolation='macos_enforced')
    config_fd = cli._pipe(json.dumps(config.to_dict(domain='private-data')).encode())
    with pytest.raises(V2Error) as error:
        cli.runtime_main(['--_runtime-zone', 'private-data', '--_config-fd', str(config_fd),
                          '--_key-fd', '99', '--_action', 'call', '--_tool', 'get_review_snapshot',
                          '--_pdf-request-fd', '100', '--_pdf-response-fd', '101'])
    assert error.value.code == 'scope_violation'
