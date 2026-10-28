"""Synthetic whole-row preview boundary and proposal regressions."""
from __future__ import annotations

import base64
import copy
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import random
import stat
import zlib

import pytest

from health_analyzer.v2.common import V2Error, digest
from health_analyzer.v2.contracts import SCHEMA_VERSION, lab_observation
from health_analyzer.v2.preview import (DECISION_SCHEMA, SCRIPT, STYLE, confirmation_blockers,
                                       export_preview, prepare_decisions, render_preview,
                                       validate_bundles)


class PreviewParser(HTMLParser):
    def __init__(self, output):
        super().__init__(convert_charrefs=True)
        self.manifest_chunks, self.tags, self.script_types, self.current_script = [], [], [], None
        self.feed(output)
        self.manifest = json.loads(''.join(self.manifest_chunks))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == 'script':
            self.script_types.append(attrs.get('type'))
            self.current_script = attrs.get('id')

    def handle_endtag(self, tag):
        if tag == 'script':
            self.current_script = None

    def handle_data(self, data):
        if self.current_script == 'preview-manifest':
            self.manifest_chunks.append(data)


def synthetic_bundle(count=2, *, subject='subject_synthetic_a', sourcechar='a'):
    version, source, run = 'version_' + subject, sourcechar * 64, 'run_' + subject
    rows = []
    for index in range(count):
        row = {
            'analyte_raw': 'Синтетический показатель ' + str(index + 1),
            'analyte_key': None, 'mapping_status': 'unmapped',
            'result': {'kind': 'numeric_censored', 'raw': '<0,01', 'operator': '<', 'decimal': '0.01'},
            'unit_raw': 'ммоль/л',
            'clinical_time': {'raw': '2026-01', 'role': 'reported', 'precision': 'month', 'value': '2026-01'},
            'reference_intervals': [{'kind': 'laboratory_reference', 'raw': '0,02–0,04', 'low': '0.02', 'high': '0.04', 'low_inclusive': True, 'high_inclusive': False, 'unit_raw': 'ммоль/л', 'population': 'синтетическая группа', 'context': 'исходный контекст'}],
            'specimen': None, 'method': None,
            'missing_reasons': {'specimen': 'not_reported', 'method': 'unknown'},
            'field_status': {'result': 'proposed', 'clinical_time': 'proposed'},
            'field_anchors': {},
        }
        for col, field in enumerate(('analyte_raw', 'result', 'unit_raw', 'clinical_time', 'reference_intervals')):
            excerpt = row['result']['raw'] if field == 'result' else row['clinical_time']['raw'] if field == 'clinical_time' else row['reference_intervals'][0]['raw'] if field == 'reference_intervals' else row[field]
            row['field_anchors'][field] = {'version_id': version, 'source_sha256': source, 'field': field, 'locator': {'kind': 'pdf', 'page': 1 + index // 25, 'region': [.05 + col * .1, .1, .1 + col * .1, .15]}, 'excerpt': excerpt, 'inherited': field == 'clinical_time'}
        row = lab_observation(row, version, source)
        draft_id = 'draft_' + subject + '_' + str(index)
        rows.append({'schema_version': SCHEMA_VERSION, 'subject_id': subject, 'draft_id': draft_id, 'observation_id': 'observation_' + subject + '_' + str(index), 'source_version_id': version, 'source_sha256': source, 'extraction_run_id': run, 'panel_id': 'panel_' + subject, 'row': row, 'review_status': 'unreviewed', 'recorded_at': '2026-01-01T00:00:00Z'})
    snapshot = {'schema_version': SCHEMA_VERSION, 'subject_id': subject, 'snapshot_id': 'snapshot_' + subject, 'version_id': version, 'source_sha256': source, 'run_id': run, 'selection_token': 'selection_' + subject, 'panel_id': None, 'rows': rows, 'displayed_draft_ids': [d['draft_id'] for d in rows], 'review_tokens': {d['draft_id']: None for d in rows}, 'observation_tokens': {d['observation_id']: None for d in rows}, 'coverage': {'status': 'partial', 'expected_count': None, 'expected_count_basis': 'unknown', 'processed_pages': [1], 'unprocessed_pages': [2], 'errors': [], 'reviewed': 0, 'rejected': 0, 'deferred': 0, 'unreviewed': count, 'run_id': run, 'version_id': version, 'absence_means': 'no_saved_row_does_not_prove_test_not_performed'}, 'offset': 0, 'limit': max(count, 25), 'total_in_selection': count + 5, 'recorded_at': '2026-01-01T00:00:00Z'}
    snapshot['snapshot_sha256'] = digest(snapshot)
    bundle = {'profile': {'subject_id': subject, 'label': 'Синтетический профиль ' + sourcechar}, 'document': {'document_id': 'document_' + subject, 'label': 'Синтетический отчёт'}, 'snapshot': snapshot, 'source_state': {'subject_id': subject, 'version_id': version, 'source_sha256': source, 'status': 'unchanged', 'observed_source_sha256': source, 'checked_at': '2026-01-01T00:00:00Z', 'archive_drift': 'not_checked'}, 'fragments': []}
    # Synthetic backend-wrapper fixture, not a real store or human attestation.
    bundle['snapshot_verification'] = {'method': 'signed_store_hmac', 'checked_at': '2026-01-01T00:00:00Z', 'state': 'current', 'reasons': [], 'snapshot_sha256': snapshot['snapshot_sha256'], 'source_bytes_checked': False, 'clinical_validation': 'not_provided'}
    for draft in rows:
        for field, anchor in draft['row']['field_anchors'].items():
            bundle['fragments'].append({**{key: snapshot[key] for key in ('subject_id', 'version_id', 'source_sha256', 'snapshot_id', 'snapshot_sha256')}, 'draft_id': draft['draft_id'], 'field': field, 'anchor_index': 0, 'locator': copy.deepcopy(anchor['locator']), 'kind': 'literal_anchor_excerpt', 'text': anchor['excerpt'], 'provenance': {'kind': 'source_anchor', 'receipt_id': None}, 'quality': {'status': 'unknown'}})
    return bundle


def rebind(bundle):
    snapshot = bundle['snapshot']
    snapshot['snapshot_sha256'] = digest({k: v for k, v in snapshot.items() if k != 'snapshot_sha256'})
    for fragment in bundle['fragments']:
        fragment['snapshot_sha256'] = snapshot['snapshot_sha256']
    if bundle.get('snapshot_verification') is not None:
        bundle['snapshot_verification']['snapshot_sha256'] = snapshot['snapshot_sha256']


def test_two_profiles_and_all_frozen_fields_preserved_with_distinct_versions():
    bundles = [synthetic_bundle(), synthetic_bundle(subject='subject_synthetic_b', sourcechar='b')]
    before = copy.deepcopy(bundles)
    parser = PreviewParser(render_preview(bundles))
    assert bundles == before
    assert parser.manifest['page_size'] == 25
    for source, rendered in zip(bundles, parser.manifest['bundles']):
        assert source['snapshot'] == rendered['snapshot']
        assert rendered['snapshot']['coverage']['expected_count'] is None
        row = rendered['snapshot']['rows'][0]['row']
        assert row['result'] == {'kind': 'numeric_censored', 'raw': '<0,01', 'operator': '<', 'decimal': '0.01'}
        assert row['clinical_time']['role'] == 'reported' and row['clinical_time']['precision'] == 'month'
        assert row['reference_intervals'][0]['population'] == 'синтетическая группа'
        assert row['field_anchors']['clinical_time']['inherited'] is True
    assert len({b['profile']['subject_id'] for b in parser.manifest['bundles']}) == 2
    assert len([a for tag, a in parser.tags if tag == 'section' and a.get('class') == 'bundle']) == 2


def test_explicit_two_profile_groups_preserve_three_subject_namespaces(tmp_path):
    first = synthetic_bundle()
    father_pdf = synthetic_bundle(subject='subject_synthetic_b', sourcechar='b')
    father_photo = synthetic_bundle(subject='subject_synthetic_c', sourcechar='c')
    first['profile'].update(group_id='self', label='Синтетический профиль A')
    father_pdf['profile'].update(group_id='father', label='Синтетический профиль B')
    father_photo['profile'].update(group_id='father', label='Синтетический профиль B')
    bundles = [first, father_pdf, father_photo]
    before = copy.deepcopy(bundles)
    metadata = export_preview(bundles, tmp_path / 'groups.html')
    assert metadata['profiles'] == 2 and metadata['subject_namespaces'] == 3
    assert bundles == before
    for bundle in (father_pdf, father_photo):
        draft_id = bundle['snapshot']['displayed_draft_ids'][0]
        packet = prepare_decisions(bundle, [{'draft_id': draft_id, 'action': 'confirm'}], visible_draft_ids=[draft_id])
        assert packet['subject_id'] == bundle['snapshot']['subject_id']
        assert packet['profile_group_id'] == 'father'
    father_photo['profile']['label'] = 'Conflicting synthetic identity label'
    with pytest.raises(V2Error):
        render_preview(bundles)


@pytest.mark.parametrize('location', ['profile', 'row', 'fragment', 'source_state'])
def test_wrong_subject_is_rejected_even_with_self_consistent_snapshot_hash(location):
    bundle = synthetic_bundle()
    if location == 'profile':
        bundle['profile']['subject_id'] = 'subject_other'
    elif location == 'row':
        bundle['snapshot']['rows'][0]['subject_id'] = 'subject_other'
        rebind(bundle)
    elif location == 'fragment':
        bundle['fragments'][0]['subject_id'] = 'subject_other'
    else:
        bundle['source_state']['subject_id'] = 'subject_other'
    with pytest.raises(V2Error):
        render_preview([bundle])


@pytest.mark.parametrize('mutation', ['draft_version', 'fragment_version', 'fragment_snapshot', 'fragment_locator', 'row_order', 'raw_value'])
def test_wrong_version_snapshot_locator_or_row_content_fails_closed(mutation):
    bundle = synthetic_bundle()
    if mutation == 'draft_version':
        bundle['snapshot']['rows'][0]['source_version_id'] = 'version_other'
        rebind(bundle)
    elif mutation == 'fragment_version':
        bundle['fragments'][0]['version_id'] = 'version_other'
    elif mutation == 'fragment_snapshot':
        bundle['fragments'][0]['snapshot_sha256'] = 'f' * 64
    elif mutation == 'fragment_locator':
        bundle['fragments'][0]['locator']['page'] = 5
    elif mutation == 'row_order':
        bundle['snapshot']['displayed_draft_ids'].reverse()
        rebind(bundle)
    else:
        bundle['snapshot']['rows'][0]['row']['result']['raw'] = '<0,02'
    with pytest.raises(V2Error):
        render_preview([bundle])


@pytest.mark.parametrize('extra', [{'url': 'https://invalid.example/crop.png'}, {'path': '/synthetic/crop.png'}, {'confidence': .999}, {'mime': 'image/svg+xml', 'data_base64': base64.b64encode(b'<svg onload="alert(1)"></svg>').decode()}])
def test_asset_paths_urls_active_formats_and_float_confidence_are_rejected(extra):
    bundle = synthetic_bundle()
    bundle['fragments'][0].update(extra)
    with pytest.raises(V2Error):
        render_preview([bundle])


def test_inline_crop_bytes_have_hash_but_derivation_remains_declared():
    bundle = synthetic_bundle()
    fragment = bundle['fragments'][0]
    # Public-domain synthetic 1x1 PNG bytes; no report or PHI.
    encoded = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII='
    fragment.pop('text')
    fragment.update(kind='image_crop', mime='image/png', data_base64=encoded, provenance={'kind': 'local_source_render', 'receipt_id': 'synthetic_render_receipt'})
    parser = PreviewParser(render_preview([bundle]))
    asset = parser.manifest['bundles'][0]['fragments'][0]
    assert asset['asset_sha256'] == hashlib.sha256(base64.b64decode(encoded)).hexdigest()
    assert asset['provenance']['kind'] == 'local_source_render'
    assert any(tag == 'img' and attrs['src'].startswith('data:image/png;base64,') for tag, attrs in parser.tags)
    fragment['data_base64'] = base64.b64encode(b'<script>alert(1)</script>').decode()
    with pytest.raises(V2Error):
        render_preview([bundle])


def test_document_header_context_is_separate_source_bound_image_not_fake_row_anchor():
    bundle = synthetic_bundle()
    snapshot = bundle['snapshot']
    fragment = {**{key: snapshot[key] for key in ('subject_id', 'version_id', 'source_sha256', 'snapshot_id', 'snapshot_sha256')}, 'page': 1, 'region': [0, 0, 1, .2], 'purpose': 'identity_header', 'kind': 'image_crop', 'mime': 'image/png', 'data_base64': 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'provenance': {'kind': 'local_source_render', 'receipt_id': 'synthetic_header_render'}, 'quality': {'status': 'readable'}}
    bundle['document_fragments'] = [fragment]
    before = copy.deepcopy(snapshot)
    output = render_preview([bundle])
    parser = PreviewParser(output)
    assert parser.manifest['bundles'][0]['snapshot'] == before
    context = parser.manifest['bundles'][0]['document_fragments'][0]
    assert context['purpose'] == 'identity_header' and 'draft_id' not in context and 'field' not in context
    assert 'Шапка оригинала' in output
    for mutation in ({'subject_id': 'subject_other'}, {'snapshot_sha256': 'f' * 64}, {'region': [0, 0, 1, 2]}, {'draft_id': snapshot['displayed_draft_ids'][0]}, {'url': 'https://synthetic.invalid/header.png'}):
        changed = copy.deepcopy(bundle)
        changed['document_fragments'][0].update(mutation)
        with pytest.raises(V2Error):
            render_preview([changed])


def test_huge_decode_dimensions_and_missing_jpeg_frame_are_rejected_without_decoding():
    bundle = synthetic_bundle()
    fragment = bundle['fragments'][0]
    fragment.pop('text')
    fragment.update(kind='image_crop', mime='image/png', provenance={'kind': 'local_source_render', 'receipt_id': None})
    tiny = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
    for width, height in ((0, 1), (12001, 1), (10000, 10000)):
        bad = bytearray(tiny)
        bad[16:20] = width.to_bytes(4, 'big')
        bad[20:24] = height.to_bytes(4, 'big')
        bad[29:33] = zlib.crc32(bad[12:29]).to_bytes(4, 'big')
        fragment['data_base64'] = base64.b64encode(bad).decode()
        with pytest.raises(V2Error) as error:
            render_preview([bundle])
        assert error.value.code == 'preview_asset_limit'
    fragment.update(mime='image/jpeg', data_base64=base64.b64encode(b'\xff\xd8\xff\xd9').decode())
    with pytest.raises(V2Error):
        render_preview([bundle])
    # Dimension-bearing synthetic header can be inspected without pixel decoding.
    jpeg_header = b'\xff\xd8\xff\xc0\x00\x0b\x08' + (10000).to_bytes(2, 'big') + (10000).to_bytes(2, 'big') + b'\x01\x01\x11\x00\xff\xd9'
    fragment['data_base64'] = base64.b64encode(jpeg_header).decode()
    with pytest.raises(V2Error) as error:
        render_preview([bundle])
    assert error.value.code == 'preview_asset_limit'


def test_large_pixels_are_included_once_with_scope_sha_preserved_and_lazy_decoding():
    bundle = synthetic_bundle()
    fragment = bundle['fragments'][0]
    width, height = 2000, 1000
    random_pixels = random.Random(23).randbytes(width * height)
    pixels = b''.join(b'\x00' + random_pixels[row * width:(row + 1) * width] for row in range(height))
    def chunk(kind, value):
        return len(value).to_bytes(4, 'big') + kind + value + zlib.crc32(kind + value).to_bytes(4, 'big')
    raw = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', width.to_bytes(4, 'big') + height.to_bytes(4, 'big') + b'\x08\x00\x00\x00\x00') + chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b'')
    encoded = base64.b64encode(raw).decode()
    fragment.pop('text')
    fragment.update(kind='image_crop', mime='image/png', data_base64=encoded, provenance={'kind': 'local_source_render', 'receipt_id': None})
    before = copy.deepcopy(bundle)
    output = render_preview([bundle])
    parser = PreviewParser(output)
    metadata = parser.manifest['bundles'][0]['fragments'][0]
    assert 'data_base64' not in metadata
    assert metadata['asset_sha256'] == hashlib.sha256(raw).hexdigest()
    assert metadata['snapshot_sha256'] == bundle['snapshot']['snapshot_sha256']
    assert output.count(encoded) == 1
    assert len(output.encode()) < len(encoded) + 150_000
    assert any(tag == 'img' and attrs.get('loading') == 'lazy' and attrs['src'].endswith(encoded) for tag, attrs in parser.tags)
    assert bundle == before


def test_script_closing_tags_quotes_and_html_in_untrusted_text_cannot_execute():
    bundle = synthetic_bundle()
    attack = '</script><script>alert("synthetic")</script><img src=x onerror=alert(1)>\u2028&'
    bundle['profile']['label'] = attack
    bundle['snapshot']['rows'][0]['row']['analyte_raw'] = attack
    bundle['snapshot']['rows'][0]['row']['field_anchors']['analyte_raw']['excerpt'] = attack
    bundle['fragments'][0]['text'] = attack
    rebind(bundle)
    output = render_preview([bundle], title=attack)
    parser = PreviewParser(output)
    assert parser.script_types == ['application/json', None]
    assert not any(tag == 'img' for tag, attrs in parser.tags)
    assert not any(key.startswith('on') for _, attrs in parser.tags for key in attrs)
    assert parser.manifest['bundles'][0]['snapshot']['rows'][0]['row']['analyte_raw'] == attack
    assert '\\u003c/script\\u003e' in output
    csp = next(attrs['content'] for tag, attrs in parser.tags if tag == 'meta' and attrs.get('http-equiv') == 'Content-Security-Policy')
    for content in (SCRIPT, STYLE):
        assert base64.b64encode(hashlib.sha256(content.encode()).digest()).decode() in csp
    assert "connect-src 'none'" in csp and "default-src 'none'" in csp
    assert not any(tag in {'iframe', 'object', 'link'} or 'src' in attrs and not attrs['src'].startswith('data:') for tag, attrs in parser.tags)


def test_missing_material_fragment_blocks_confirmation_without_hiding_row():
    bundle = synthetic_bundle()
    draft = bundle['snapshot']['rows'][0]
    bundle['fragments'] = [f for f in bundle['fragments'] if not (f['draft_id'] == draft['draft_id'] and f['field'] == 'result')]
    validated = validate_bundles([bundle])[0]
    assert confirmation_blockers(validated, draft['draft_id'])
    assert 'data-blocked="1"' in render_preview([bundle])
    with pytest.raises(V2Error) as error:
        prepare_decisions(bundle, [{'draft_id': draft['draft_id'], 'action': 'confirm'}], visible_draft_ids=[draft['draft_id']])
    assert error.value.code == 'preview_confirmation_blocked'
    assert prepare_decisions(bundle, [{'draft_id': draft['draft_id'], 'action': 'defer'}], visible_draft_ids=[draft['draft_id']])['state'] == 'PROPOSED'


@pytest.mark.parametrize('kind', ['field', 'mapping', 'flag', 'identity_conflict', 'source_changed', 'degraded'])
def test_ambiguous_reading_identity_and_changed_source_block_confirm_proposals(kind):
    bundle = synthetic_bundle()
    draft = bundle['snapshot']['rows'][0]
    if kind == 'field':
        draft['row']['field_status']['result'] = 'ambiguous'
        rebind(bundle)
    elif kind == 'mapping':
        draft['row']['mapping_status'] = 'ambiguous'
        rebind(bundle)
    elif kind in {'flag', 'identity_conflict'}:
        bundle['review_flags'] = [{'draft_id': draft['draft_id'] if kind == 'flag' else None, 'field': 'clinical_time' if kind == 'flag' else None, 'code': 'not_visually_supported' if kind == 'flag' else 'identity_conflict', 'note': 'Synthetic visual-source discrepancy'}]
    elif kind == 'source_changed':
        bundle['source_state'].update(status='changed', observed_source_sha256='f' * 64)
    else:
        bundle['fragments'][0]['quality']['status'] = 'degraded'
    with pytest.raises(V2Error) as error:
        prepare_decisions(bundle, [{'draft_id': draft['draft_id'], 'action': 'confirm'}], visible_draft_ids=[draft['draft_id']])
    assert error.value.code == 'preview_confirmation_blocked'
    assert prepare_decisions(bundle, [{'draft_id': draft['draft_id'], 'action': 'reject'}], visible_draft_ids=[draft['draft_id']])['confirmation_assurance'] == 'none'


def test_archive_drift_is_visible_but_not_confused_with_saved_source_integrity():
    bundle = synthetic_bundle()
    bundle['source_state']['archive_drift'] = 'changed'
    draft_id = bundle['snapshot']['rows'][0]['draft_id']
    packet = prepare_decisions(bundle, [{'draft_id': draft_id, 'action': 'confirm'}], visible_draft_ids=[draft_id])
    assert packet['source_state']['archive_drift'] == 'changed'
    assert packet['state'] == 'PROPOSED' and packet['confirmation_assurance'] == 'none'


@pytest.mark.parametrize('state', ['missing', 'stale'])
def test_missing_or_stale_backend_wrapper_blocks_confirm_and_survives_defer(state):
    bundle = synthetic_bundle()
    draft_id = bundle['snapshot']['displayed_draft_ids'][0]
    if state == 'missing':
        del bundle['snapshot_verification']
    else:
        bundle['snapshot_verification'].update(state='stale', reasons=['review_state_changed'])
    with pytest.raises(V2Error) as error:
        prepare_decisions(bundle, [{'draft_id': draft_id, 'action': 'confirm'}], visible_draft_ids=[draft_id])
    assert error.value.code == 'preview_confirmation_blocked'
    packet = prepare_decisions(bundle, [{'draft_id': draft_id, 'action': 'defer'}], visible_draft_ids=[draft_id])
    assert packet['snapshot_verification'] == bundle.get('snapshot_verification')
    bundle['snapshot_verification'] = {'method': 'signed_store_hmac', 'checked_at': '2026-01-01T00:00:00Z', 'state': 'current', 'reasons': [], 'snapshot_sha256': 'f' * 64, 'source_bytes_checked': False, 'clinical_validation': 'not_provided'}
    with pytest.raises(V2Error):
        render_preview([bundle])


def test_proposals_are_selected_visible_subset_without_receipts_or_history_writes():
    bundle = synthetic_bundle()
    before = copy.deepcopy(bundle)
    first, second = bundle['snapshot']['displayed_draft_ids']
    packet = prepare_decisions(bundle, [{'draft_id': first, 'action': 'confirm'}], visible_draft_ids=[first])
    assert packet['schema_version'] == DECISION_SCHEMA
    assert packet['selected_draft_ids'] == [first] and second not in packet['selected_draft_ids']
    assert packet['snapshot_sha256'] == bundle['snapshot']['snapshot_sha256']
    assert packet['confirmation_assurance'] == 'none' and 'confirmation_evidence' not in packet
    assert bundle == before
    with pytest.raises(V2Error):
        prepare_decisions(bundle, [{'draft_id': second, 'action': 'confirm'}], visible_draft_ids=[first])
    with pytest.raises(V2Error):
        prepare_decisions(bundle, [], visible_draft_ids=[first])
    with pytest.raises(V2Error):
        prepare_decisions(bundle, [{'draft_id': first, 'action': 'confirm', 'confirmation_assurance': 'local_operator_confirmed'}], visible_draft_ids=[first])
    note = 'Синтетическое исправление: результат должен быть <0,02'
    corrected = prepare_decisions(bundle, [{'draft_id': first, 'action': 'request_correction', 'correction_note': note}], visible_draft_ids=[first])
    assert corrected['decisions'][0]['correction_note'] == note
    assert bundle == before


def test_default_25_and_max_100_do_not_silently_truncate_source_or_snapshot():
    bundle = synthetic_bundle(100)
    parser = PreviewParser(render_preview([bundle]))
    assert parser.manifest['page_size'] == 25
    assert len(parser.manifest['bundles'][0]['snapshot']['rows']) == 100
    assert len([attrs for tag, attrs in parser.tags if tag == 'article' and attrs.get('class') == 'row-card']) == 100
    assert PreviewParser(render_preview([bundle], page_size=100)).manifest['page_size'] == 100
    for size in (0, 101, True):
        with pytest.raises(V2Error):
            render_preview([bundle], page_size=size)
    too_many = synthetic_bundle(101)
    with pytest.raises(V2Error):
        render_preview([too_many])


def test_flags_must_name_shown_fields_and_normalized_bundles_are_idempotent():
    bundle = synthetic_bundle()
    assert validate_bundles(validate_bundles([bundle])) == validate_bundles([bundle])
    bundle['review_flags'] = [{'draft_id': 'draft_unknown', 'field': 'result', 'code': 'unresolved_reading', 'note': 'Synthetic issue'}]
    with pytest.raises(V2Error):
        render_preview([bundle])


def test_export_is_private_exclusive_and_never_overwrites_original(tmp_path):
    bundle = synthetic_bundle()
    target = tmp_path / 'synthetic-preview.html'
    result = export_preview([bundle], target)
    assert result['confirmed_records'] == 0 and result['profiles'] == 1
    assert result['sha256'] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    old = target.read_bytes()
    with pytest.raises(FileExistsError):
        export_preview([bundle], target)
    assert target.read_bytes() == old
    symlink = tmp_path / 'synthetic-symlink.html'
    symlink.symlink_to(target)
    with pytest.raises(V2Error):
        export_preview([bundle], symlink)
    assert target.read_bytes() == old
