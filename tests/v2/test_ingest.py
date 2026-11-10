from pathlib import Path
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.ingest import ImportService, parse_result, read_source


def setup(tmp_path, pdf_extractor=None, image_extractor=None):
    root = tmp_path / 'archive'; root.mkdir()
    store = SignedStore(tmp_path / 'state/private.sqlite3', b'x' * 32, 'private-data')
    records = RecordsService(store)
    config = SimpleNamespace(archive_roots={'demo': {'path': root, 'subject_id': 'demo'}})
    return root, records, ImportService(config, records, pdf_extractor=pdf_extractor, image_extractor=image_extractor)


def attestation(snapshot):
    return {'snapshot_id': snapshot['snapshot_id'], 'snapshot_sha256': snapshot['snapshot_sha256'],
            'decision_excerpt': 'Принимаю показанные строки', 'origin': 'user_message',
            'attested_by': 'synthetic_test', 'ref_availability': 'not_provided_by_host',
            'message_ref': None}


def test_26_by_4_is_whole_rows_not_cells_and_reimport_deduplicates(tmp_path):
    root, records, imports = setup(tmp_path)
    content = 'Показатель;Результат;Единица;Референс\n' + ''.join(
        f'Показатель {i};{i},5;ед/л;0–50\n' for i in range(26))
    (root / 'report.csv').write_text(content)
    records.register_subject('demo', 'Локальный профиль')
    response = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'report.csv'}])
    doc = response['documents'][0]
    assert len(doc['draft_ids']) == 26
    assert records.store.get('subject', 'demo', 'demo')['label'] == 'Локальный профиль'
    a = records.prepare_review('demo', doc['version_id'], limit=25)
    assert len(a['rows']) == 25
    decisions = [{'draft_id': row['draft_id'], 'action': 'confirm'} for row in a['rows']]
    records.commit_review('demo', a['snapshot_id'], a['snapshot_sha256'], decisions,
                          attestation(a), 'batch_a')
    b = records.prepare_review('demo', doc['version_id'], offset=25, limit=25)
    records.commit_review('demo', b['snapshot_id'], b['snapshot_sha256'],
                          [{'draft_id': b['rows'][0]['draft_id'], 'action': 'confirm'}], attestation(b), 'batch_b')
    assert len(records.store.list('observation_revision', 'demo')) == 26
    repeat = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'report.csv'}])
    assert repeat['documents'][0]['version_id'] == doc['version_id']
    assert repeat['documents'][0]['run_id'] == doc['run_id']
    assert len(records.store.list('observation_revision', 'demo')) == 26
    records.store.close()


def test_numeric_censor_no_result_qualitative_and_dates_keep_provenance(tmp_path):
    root, records, imports = setup(tmp_path)
    (root / 'report.csv').write_text('analyte;result;unit;collected;reference\nA;<0,01;u;2026-01-01;0–1\nB;не обнаружено;;2026-01;\nC;;;01/02/26;\n')
    doc = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'report.csv'}])['documents'][0]
    snapshot = records.prepare_review('demo', doc['version_id'])
    rows = [r['row'] for r in snapshot['rows']]
    assert rows[0]['result'] == {'kind': 'numeric_censored', 'raw': '<0,01', 'operator': '<', 'decimal': '0.01'}
    assert rows[0]['clinical_time']['role'] == 'collected'
    assert rows[1]['result']['kind'] == 'qualitative'
    assert rows[1]['clinical_time']['precision'] == 'month'
    assert len(rows) == 2
    issue = imports.issues.list('demo', doc['version_id'])['issues'][0]
    assert 'MISSING_RESULT' in issue['source']['reason_codes']
    assert 'C;;;01/02/26;' in issue['source']['raw_text']
    assert issue['source']['proposed_row'] is None
    for row in rows:
        assert row['field_anchors']['result']['source_sha256'] == doc['source_sha256']
    assert parse_result('>=5')['operator'] == '>='
    assert parse_result('5 mmol/L')['kind'] == 'text_unparsed'
    records.store.close()


def test_symlink_escape_subject_and_batch_failure_have_no_partial_state(tmp_path):
    root, records, imports = setup(tmp_path)
    outside = tmp_path / 'outside.csv'; outside.write_text('analyte;result\nA;1\n')
    (root / 'linked.csv').symlink_to(outside)
    with pytest.raises(V2Error): read_source(root, 'linked.csv')
    with pytest.raises(V2Error): read_source(root, '../outside.csv')
    with pytest.raises(V2Error): imports.prepare_import('other', [{'root_id': 'demo', 'relative_path': 'linked.csv'}])
    (root / 'good.csv').write_text('analyte;result\nA;1\n')
    (root / 'bad.csv').write_text('analyte;result\nA;1;extra\n')
    prepared = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'good.csv'},
                                             {'root_id': 'demo', 'relative_path': 'bad.csv'}])
    assert len(prepared['documents'][0]['draft_ids']) == 1
    assert prepared['documents'][1]['draft_ids'] == []
    assert 'TABLE_SHAPE_MISMATCH' in imports.issues.list('demo', prepared['documents'][1]['version_id'])['issues'][0]['source']['reason_codes']
    assert records.query_history('demo')['current'] == []
    records.store.close()


def test_saved_version_review_survives_archive_changes_without_replacing_original(tmp_path):
    root, records, imports = setup(tmp_path)
    path = root / 'a.csv'; path.write_text('analyte;result;unit;collected;specimen;method\nA;1;u;2026-01-01;serum;m1\n')
    doc = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'a.csv'}])['documents'][0]
    snapshot = records.prepare_review('demo', doc['version_id'])
    decision = [{'draft_id': snapshot['rows'][0]['draft_id'], 'action': 'confirm'}]
    path.write_text('analyte;result\nA;9\n')
    source = imports.get_source_version('demo', doc['version_id'])
    assert source['archive_sources'][0]['status'] == 'source_changed'
    assert source['saved_status'] == 'available'
    assert Path(source['verified_saved_source_path']).read_text().endswith('A;1;u;2026-01-01;serum;m1\n')
    records.commit_review('demo', snapshot['snapshot_id'], snapshot['snapshot_sha256'], decision, attestation(snapshot), 'accepted')
    path.unlink()
    assert len(records.query_history('demo')['current']) == 1
    refreshed = imports.refresh_source_status('demo', [doc['version_id']])
    assert refreshed['sources'][0]['checked_status'] == 'available'
    assert refreshed['sources'][0]['check_basis'] == 'saved_original_sha256'
    assert refreshed['sources'][0]['archive_sources'][0]['status'] == 'SOURCE_UNAVAILABLE'
    assert records.query_history('demo')['current'][0]['source_availability']['status'] == 'available'
    records.store.close()


def test_image_and_partial_pdf_use_same_draft_path_without_false_coverage(tmp_path):
    extractor = lambda content: ([{'page': 1, 'text': 'analyte;result;unit\nA;5;u\n', 'document_incomplete': True}], ['synthetic extractor'])
    root, records, imports = setup(tmp_path, extractor, lambda content: ([], ['synthetic unavailable OCR']))
    (root / 'scan.png').write_bytes(b'\x89PNG\r\n\x1a\nsynthetic')
    image = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'scan.png'}])['documents'][0]
    run = records.store.get('extraction_run', image['run_id'], 'demo')
    assert run['coverage']['status'] == 'visual_required' and image['draft_ids'] == []
    (root / 'report.pdf').write_bytes(b'%PDF-1.4\nsynthetic')
    pdf = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'report.pdf'}])['documents'][0]
    run = records.store.get('extraction_run', pdf['run_id'], 'demo')
    assert len(pdf['draft_ids']) == 1
    assert run['coverage']['status'] == 'partial'
    assert run['coverage']['expected_count'] is None
    records.store.close()


def test_aggregate_input_cap_fails_without_any_registration(tmp_path, monkeypatch):
    root, records, imports = setup(tmp_path)
    content = 'analyte;result\nA;5\n'
    (root / 'one.csv').write_text(content)
    (root / 'two.csv').write_text(content)
    monkeypatch.setattr('health_analyzer.v2.ingest.MAX_IMPORT_BYTES', len(content.encode()))
    with pytest.raises(V2Error) as error:
        imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'one.csv'},
                                       {'root_id': 'demo', 'relative_path': 'two.csv'}])
    assert error.value.code == 'INPUT_LIMIT'
    assert records.store.list('document_version', 'demo') == []
    records.store.close()
