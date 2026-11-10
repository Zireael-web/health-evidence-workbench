import os
import sys
import subprocess
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from health_analyzer.v2.common import SignedStore
from health_analyzer.v2.ingest import ImportService, extract_pdf
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.configuration import initialize


def synthetic_pdf(text=None):
    content = b'' if text is None else (
        b'BT /F1 10 Tf 36 750 Td (' + text[0].encode('ascii') + b') Tj '
        b'0 -16 Td (' + text[1].encode('ascii') + b') Tj ET')
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
        b'<< /Length ' + str(len(content)).encode() + b' >>\nstream\n' + content + b'\nendstream',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    out = bytearray(b'%PDF-1.4\n')
    offsets = []
    for index, obj in enumerate(objects, 1):
        offsets.append(len(out)); out.extend(f'{index} 0 obj\n'.encode() + obj + b'\nendobj\n')
    xref = len(out)
    out.extend(f'xref\n0 {len(objects)+1}\n0000000000 65535 f \n'.encode())
    for offset in offsets: out.extend(f'{offset:010} 00000 n \n'.encode())
    out.extend(f'trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return bytes(out)


pytestmark = pytest.mark.skipif(
    sys.platform == 'darwin' and os.environ.get('HA_V2_TEST_NESTED_PDF') != '1',
    reason='Run explicitly with HA_V2_TEST_NESTED_PDF=1 where nested Seatbelt is available')


def test_real_bounded_worker_enters_same_typed_review_path(tmp_path):
    root = tmp_path / 'archive'; root.mkdir()
    (root / 'native.pdf').write_bytes(synthetic_pdf(('analyte;result;unit;collected;specimen;method', 'A;5;u;2026-01-01;serum;m1')))
    store = SignedStore(tmp_path / 'state/private.sqlite3', b'x' * 32, 'private-data')
    records = RecordsService(store)
    config = SimpleNamespace(archive_roots={'demo': {'path': root, 'subject_id': 'demo'}})
    imported = ImportService(config, records).prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'native.pdf'}])
    doc = imported['documents'][0]
    snapshot = records.prepare_review('demo', doc['version_id'])
    assert snapshot['rows'][0]['row']['result']['decimal'] == '5'
    assert snapshot['rows'][0]['row']['field_anchors']['result']['locator']['page'] == 1
    assert records.query_history('demo')['current'] == []
    store.close()


def test_image_only_pdf_is_registered_for_visual_review_not_failed(tmp_path):
    root = tmp_path / 'archive'; root.mkdir()
    (root / 'scan.pdf').write_bytes(synthetic_pdf())
    store = SignedStore(tmp_path / 'state/private.sqlite3', b'x' * 32, 'private-data')
    records = RecordsService(store)
    config = SimpleNamespace(archive_roots={'demo': {'path': root, 'subject_id': 'demo'}})
    doc = ImportService(config, records).prepare_import('demo', [{'root_id': 'demo', 'relative_path': 'scan.pdf'}])['documents'][0]
    run = store.get('extraction_run', doc['run_id'], 'demo')
    assert run['coverage']['status'] == 'visual_required'
    assert run['coverage']['expected_count'] is None
    assert doc['draft_ids'] == []
    assert store.get('document_version', doc['version_id'], 'demo')['mime'] == 'application/pdf'
    store.close()


def test_pdf_worker_runs_inside_private_runtime_without_archive_writes(tmp_path):
    if sys.platform != 'darwin':
        pytest.skip('This acceptance checks nested macOS Seatbelt')
    archive = tmp_path / 'archive'; archive.mkdir()
    source = archive / 'native.pdf'
    source_bytes = synthetic_pdf(('analyte;result;unit', 'A;5;u'))
    source.write_bytes(source_bytes)
    config = initialize(tmp_path / 'config.json', tmp_path / 'data', isolation='macos_enforced',
                        archive_roots={'demo': {'path': str(archive), 'subject_id': 'demo'}})
    arguments = tmp_path / 'request.json'
    arguments.write_text(json.dumps({'subject_id': 'demo', 'input_refs': [{'root_id': 'demo', 'relative_path': 'native.pdf'}]}))
    entry = Path(__file__).resolve().parents[2] / 'src/health_analyzer/v2/entry.py'
    r = subprocess.run([sys.executable, '-I', '-B', str(entry), '--config', str(config.path),
                        'call', '--zone', 'private-data', '--tool', 'prepare_import',
                        '--arguments-file', str(arguments)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)['documents'][0]
    assert len(doc['draft_ids']) == 1
    assert source.read_bytes() == source_bytes
    assert sorted(p.name for p in archive.iterdir()) == ['native.pdf']
