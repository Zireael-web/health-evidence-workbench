"""End-to-end synthetic ingress checks; never production history or PHI."""
import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.records import RecordsService


def setup(tmp_path, *, pdf=None, image=None):
    root = tmp_path / 'archive'; root.mkdir()
    store = SignedStore(tmp_path / 'data/private.sqlite3', b'u' * 32, 'private-data')
    records = RecordsService(store)
    imports = ImportService(SimpleNamespace(archive_roots={'demo': {'path': root, 'subject_id': 'demo'}}),
                            records, pdf_extractor=pdf, image_extractor=image)
    return root, records, imports


def page(*values, source='pdf_text'):
    header = f"{'Показатель':<24}{'Результат':<16}{'Единицы':<16}Референсные значения"
    body = [f'{name:<24}{value:<16}{unit:<16}{reference}' for name, value, unit, reference in values]
    return {'page': 1, 'text': '\n'.join(['Дата взятия образца: 23.01.2026 08:15', header, *body]),
            'blocks': [], 'width': 1000, 'height': 1000, 'source': source}


def test_native_layout_keeps_bad_source_rows_in_a_paginated_scoped_queue(tmp_path):
    sample = page(('Синтетический A', '<0,01', 'ед/л', '0 - 1'),
                  ('Синтетический B', '1 2', 'ед/л', '0 - 5'),
                  ('Синтетический C', '', 'ед/л', '0 - 5'))
    root, records, imports = setup(tmp_path, pdf=lambda _: ([sample], ['synthetic text provider']))
    (root/'report.pdf').write_bytes(b'%PDF-1.4\nsynthetic provider input')
    doc = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'report.pdf'}])['documents'][0]
    snapshot = records.prepare_review('demo', doc['version_id'])
    assert len(snapshot['rows']) == 1
    assert snapshot['rows'][0]['row']['result']['kind'] == 'numeric_censored'
    issues = imports.issues.list('demo', doc['version_id'], limit=1)
    assert issues['total'] == 2 and len(issues['issues']) == 1
    second = imports.issues.list('demo', doc['version_id'], offset=1, limit=1)['issues'][0]
    assert 'MISSING_RESULT' in second['source']['reason_codes']
    assert second['source']['proposed_row'] is None
    assert records.query_history('demo')['current'] == []
    records.register_subject('other', 'Synthetic other')
    with pytest.raises(V2Error): imports.issues.resolve('other', second['issue_id'], 'discard', 'wrong scope')
    records.store.close()


def test_issue_resolution_is_only_a_draft_and_invalidates_previous_frozen_review(tmp_path):
    sample = page(('Синтетический A', '3', 'ед/л', '0 - 5'), ('Синтетический B', '4 1', 'ед/л', '0 - 5'))
    root, records, imports = setup(tmp_path, pdf=lambda _: ([sample], ['synthetic provider']))
    (root/'report.pdf').write_bytes(b'%PDF-1.4\nsynthetic provider input')
    doc = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'report.pdf'}])['documents'][0]
    previous = records.prepare_review('demo', doc['version_id'])
    issue = imports.issues.list('demo', doc['version_id'])['issues'][0]
    row = copy.deepcopy(previous['rows'][0]['row'])
    source = issue['source']['raw_cells']
    name = next(c for c in source if c['role'] == 'analyte_raw')
    value = next(c for c in source if c['role'] == 'result')
    row['analyte_raw'] = name['text']
    row['result'] = {'kind': 'numeric_exact', 'raw': '4,1', 'decimal': '4.1'}
    row['field_anchors']['analyte_raw'] = name['anchors']
    row['field_anchors']['result'] = value['anchors']
    # Other present fields retain the ambiguous source row's own provenance.
    for field in ['unit_raw', 'reference_intervals']:
        cell = next(c for c in source if c['role'] == field)
        row['field_anchors'][field] = cell['anchors']
    result = imports.issues.resolve('demo', issue['issue_id'], 'propose', 'Synthetic reread; not a real user decision',
        row=row, expected_run_id=issue['current_run_id'], expected_selection_token=issue['current_selection_token'],
        idempotency_key='synthetic-proposal')
    assert result['confirmed'] is False and result['requires_frozen_review']
    assert len(records.prepare_review('demo', doc['version_id'])['rows']) == 2
    assert records.query_history('demo')['current'] == []
    assert imports.issues.resolve('demo', issue['issue_id'], 'propose', 'Synthetic reread; not a real user decision',
        row=row, expected_run_id=issue['current_run_id'], expected_selection_token=issue['current_selection_token'],
        idempotency_key='synthetic-proposal') == result
    with pytest.raises(V2Error) as error:
        imports.issues.resolve('demo', issue['issue_id'], 'defer', 'stale displayed state')
    assert error.value.code == 'STALE_IMPORT_ISSUE'
    with pytest.raises(V2Error) as error:
        records.commit_review('demo', previous['snapshot_id'], previous['snapshot_sha256'],
            [{'draft_id': previous['rows'][0]['draft_id'], 'action': 'confirm'}])
    assert error.value.code == 'stale_extraction'
    records.store.close()


def test_reimport_reuses_recognition_without_repeating_nondeterministic_ocr(tmp_path):
    calls = []
    def image(content):
        calls.append(content)
        return [page(('Synthetic marker', str(len(calls)), 'u', '0 - 9'), source='vision_ocr')], ['synthetic OCR, not Apple Vision']
    root, records, imports = setup(tmp_path, image=image)
    (root/'photo.png').write_bytes(b'\x89PNG\r\n\x1a\nsynthetic provider input')
    ref = [{'root_id': 'demo', 'relative_path': 'photo.png'}]
    first = imports.prepare_import('demo', ref)['documents'][0]
    repeated = imports.prepare_import('demo', ref)['documents'][0]
    assert len(calls) == 1 and repeated['recognition_reused']
    assert first['run_id'] == repeated['run_id']
    revised = imports.prepare_import('demo', ref, force_reextract=True)['documents'][0]
    assert len(calls) == 2 and revised['run_id'] != first['run_id']
    assert records.query_history('demo')['current'] == []
    records.store.close()


def test_corrupt_saved_original_blocks_review_and_is_never_healed_from_archive(tmp_path):
    root, records, imports = setup(tmp_path)
    source = root/'source.csv'; source.write_text('analyte;result;unit\nSynthetic;3;u\n')
    doc = imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'source.csv'}])['documents'][0]
    preview = records.prepare_review('demo', doc['version_id'])
    saved = Path(imports.get_source_version('demo', doc['version_id'])['verified_saved_source_path'])
    saved.chmod(0o600); saved.write_bytes(b'damaged synthetic blob')
    with pytest.raises(V2Error) as error:
        records.commit_review('demo', preview['snapshot_id'], preview['snapshot_sha256'],
            [{'draft_id': preview['rows'][0]['draft_id'], 'action': 'confirm'}])
    assert error.value.code == 'ORIGINAL_INTEGRITY_FAILURE'
    with pytest.raises(V2Error): imports.prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'source.csv'}])
    assert saved.read_bytes() == b'damaged synthetic blob'
    assert source.read_text().endswith('Synthetic;3;u\n')
    assert records.query_history('demo')['current'] == []
    records.store.close()
