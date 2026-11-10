import hashlib
import sqlite3
import os
import subprocess
import sys
from pathlib import Path

import pytest

from health_analyzer.v2.common import SignedStore, V2Error


def test_foreign_database_rejected_without_touching_legacy(tmp_path):
    path = tmp_path / 'old.sqlite3'
    con = sqlite3.connect(path)
    con.execute('CREATE TABLE legacy (value TEXT)')
    con.execute("INSERT INTO legacy VALUES ('preserve me')")
    con.commit(); con.close()
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(V2Error, match='no v2 marker'):
        SignedStore(path, b'a' * 32, 'private-data')
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert not path.with_name(path.name + '-wal').exists()


def test_identity_key_subject_and_mac_are_bound(tmp_path):
    path = tmp_path / 'v2.sqlite3'
    store = SignedStore(path, b'a' * 32, 'private-data')
    store.put('observation', 'r1', {'value': '3.2'}, 'alice')
    with pytest.raises(V2Error) as error:
        store.get('observation', 'r1', 'bob')
    assert error.value.code == 'WRONG_SUBJECT'
    assert store.list('observation', 'bob') == []
    con = sqlite3.connect(path)
    con.execute("UPDATE v2_objects SET payload=? WHERE object_id='r1'", ('{"value":"9.9"}',))
    con.commit(); con.close()
    with pytest.raises(V2Error) as error:
        store.get('observation', 'r1', 'alice')
    assert error.value.code == 'INTEGRITY_FAILURE'
    store.close()
    with pytest.raises(V2Error):
        SignedStore(path, b'b' * 32, 'private-data')
    with pytest.raises(V2Error):
        SignedStore(path, b'a' * 32, 'public-research')


def test_atomic_nested_write_and_idempotence_survive_restart(tmp_path):
    path = tmp_path / 'v2.sqlite3'
    store = SignedStore(path, b'a' * 32, 'private-data')
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.put('event', 'first', {'value': '1'}, 'subject')
            store.put('event', 'second', {'value': '2'}, 'subject')
            raise RuntimeError('abort whole batch')
    assert store.list('event', 'subject') == []
    store.put('event', 'third', {'value': '3'}, 'subject')
    assert store.put('event', 'third', {'value': '3'}, 'subject') == {'value': '3'}
    with pytest.raises(V2Error):
        store.put('event', 'third', {'value': '4'}, 'subject')
    store.close()
    store = SignedStore(path, b'a' * 32, 'private-data')
    assert store.list('event', 'subject') == [{'value': '3'}]
    assert store._db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
    assert store._db.execute('PRAGMA synchronous').fetchone()[0] == 2
    store.close()


def test_public_scope_symlinks_and_list_limit_fail_closed(tmp_path):
    store = SignedStore(tmp_path / 'public.sqlite3', b'a' * 32, 'public-research')
    with pytest.raises(V2Error):
        store.put('source', 's1', {}, 'person')
    store.MAX_LIST = 1
    store.put('source', 's1', {})
    store.put('source', 's2', {})
    with pytest.raises(V2Error) as error:
        store.list('source')
    assert error.value.code == 'QUERY_LIMIT'
    store.close()
    link = tmp_path / 'linked.sqlite3'
    link.symlink_to(tmp_path / 'public.sqlite3')
    with pytest.raises(V2Error):
        SignedStore(link, b'a' * 32, 'public-research')


def test_acknowledged_wal_write_survives_immediate_process_exit(tmp_path):
    path = tmp_path / 'acknowledged.sqlite3'
    script = '''from health_analyzer.v2.common import SignedStore
import os,sys
store=SignedStore(sys.argv[1],b'a'*32,'private-data')
store.put('event','acknowledged',{'value':'synthetic'},'demo')
print('acknowledged',flush=True)
os._exit(0)
'''
    env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[2] / 'src')}
    completed = subprocess.run([sys.executable, '-c', script, str(path)], env=env,
                               capture_output=True, text=True, timeout=10, check=True)
    assert completed.stdout.strip() == 'acknowledged'
    store = SignedStore(path, b'a' * 32, 'private-data')
    assert store.get('event', 'acknowledged', 'demo') == {'value': 'synthetic'}
    store.close()
