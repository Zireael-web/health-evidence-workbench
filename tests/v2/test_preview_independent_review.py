"""Independent synthetic adversarial checks over the real preview/read path.

No installed keys, archives, PHI, raw-source files, or rendered crops are used.
"""
import base64
import copy
import json
import shutil
import subprocess
import zlib

import pytest

from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.preview import (
    SCRIPT, confirmation_blockers, prepare_decisions, render_preview, validate_bundles,
)
from health_analyzer.v2.records import RecordsService


SYNTHETIC_KEY = b"independent-preview-test-key-0000"
SUBJECT = "subject_independent_synthetic"


def _row(version, index=0, value="5.4", *, unit_ambiguous=False):
    row = {
        "analyte_raw": "Independent synthetic analyte",
        "result": {"kind": "numeric_exact", "raw": value, "decimal": value},
        "unit_raw": "mmol/L",
        "clinical_time": {"raw": "2026-01-01", "role": "collected", "precision": "date", "value": "2026-01-01"},
        "reference_intervals": [], "specimen": None, "method": None,
        "missing_reasons": {"reference_intervals": "not_reported", "specimen": "not_reported", "method": "unknown"},
        "field_status": {"unit_raw": "ambiguous"} if unit_ambiguous else {},
        "field_anchors": {},
    }
    for column, field in enumerate(("analyte_raw", "result", "unit_raw", "clinical_time"), 1):
        excerpt = value if field == "result" else row["clinical_time"]["raw"] if field == "clinical_time" else row[field]
        row["field_anchors"][field] = {
            "version_id": version["version_id"], "source_sha256": version["source_sha256"], "field": field,
            "locator": {"kind": "csv_cell", "row": index + 2, "column": column}, "excerpt": excerpt,
        }
    return row


def _coverage(count):
    return {"status": "complete", "expected_count": count, "expected_count_basis": "source_count",
            "processed_pages": [], "unprocessed_pages": [], "errors": []}


@pytest.fixture
def seeded(tmp_path):
    store = SignedStore(tmp_path / "synthetic-only.sqlite3", SYNTHETIC_KEY, "private-data")
    records = RecordsService(store)
    records.register_subject(SUBJECT, "Synthetic independent profile")
    version = records.register_document(SUBJECT, "d" * 64, "text/csv", 100)
    yield records, version
    store.close()


def _bundle(records, version, *, count=1, unit_ambiguous=False):
    records.submit_extraction(SUBJECT, version["version_id"],
        [_row(version, index, unit_ambiguous=unit_ambiguous) for index in range(count)], _coverage(count))
    snapshot = records.prepare_review(SUBJECT, version["version_id"], limit=max(25, count))
    checked = records.get_review_snapshot(SUBJECT, snapshot["snapshot_id"])
    return _from_checked(version, checked)


def _from_checked(version, checked):
    snapshot = checked["snapshot"]
    binding = {key: snapshot[key] for key in ("subject_id", "version_id", "source_sha256", "snapshot_id", "snapshot_sha256")}
    fragments = []
    for draft in snapshot["rows"]:
        for field, anchors in draft["row"]["field_anchors"].items():
            anchors = anchors if isinstance(anchors, list) else [anchors] if anchors is not None else []
            for index, anchor in enumerate(anchors):
                fragments.append({**binding, "draft_id": draft["draft_id"], "field": field,
                    "anchor_index": index, "locator": copy.deepcopy(anchor["locator"]),
                    "kind": "literal_anchor_excerpt", "text": anchor["excerpt"],
                    "provenance": {"kind": "source_anchor"}, "quality": {"status": "readable"}})
    return {"profile": {"subject_id": SUBJECT, "label": "Synthetic independent profile"},
            "document": {"document_id": version["document_id"], "label": "Synthetic report"},
            "snapshot": snapshot, "snapshot_verification": checked["verification"],
            "source_state": {"subject_id": SUBJECT, "version_id": version["version_id"],
                "source_sha256": version["source_sha256"], "status": "unchanged",
                "observed_source_sha256": version["source_sha256"], "checked_at": "2026-01-01T00:00:00Z"},
            "fragments": fragments}


def _confirm(bundle):
    draft_id = bundle["snapshot"]["displayed_draft_ids"][0]
    return prepare_decisions(bundle, [{"draft_id": draft_id, "action": "confirm"}], visible_draft_ids=[draft_id])


def test_snapshot_endpoint_is_consistent_when_review_commits_mid_read(seeded, monkeypatch):
    records, version = seeded
    bundle = _bundle(records, version)
    snapshot = bundle["snapshot"]
    reader = SignedStore(records.store.path, SYNTHETIC_KEY, "private-data", readonly=True)
    try:
        read_records = RecordsService(reader)
        original_get = reader.get
        committed = False

        def get_then_concurrent_commit(kind, object_id, subject_id=None):
            nonlocal committed
            result = original_get(kind, object_id, subject_id)
            if kind == "review_snapshot" and not committed:
                committed = True
                records.commit_review(SUBJECT, snapshot["snapshot_id"], snapshot["snapshot_sha256"],
                    [{"draft_id": snapshot["displayed_draft_ids"][0], "action": "defer"}])
            return result

        monkeypatch.setattr(reader, "get", get_then_concurrent_commit)
        within_transaction = read_records.get_review_snapshot(SUBJECT, snapshot["snapshot_id"])
        assert within_transaction["snapshot"] == snapshot
        assert within_transaction["verification"]["state"] == "current"
        later = read_records.get_review_snapshot(SUBJECT, snapshot["snapshot_id"])
        assert later["snapshot"] == snapshot
        assert later["verification"]["reasons"] == ["review_state_changed"]
        assert reader._db.total_changes == 0
        assert len(reader.list("review_event", SUBJECT)) == 1
    finally:
        reader.close()


def test_return_to_same_extraction_never_resurrects_html_confirm(seeded):
    records, version = seeded
    initial = _bundle(records, version)
    records.submit_extraction(SUBJECT, version["version_id"], [_row(version, value="5.6")], _coverage(1))
    records.submit_extraction(SUBJECT, version["version_id"], [_row(version)], _coverage(1))
    checked = records.get_review_snapshot(SUBJECT, initial["snapshot"]["snapshot_id"])
    stale = _from_checked(version, checked)
    assert stale["snapshot"] == initial["snapshot"]
    assert checked["verification"]["reasons"] == ["extraction_selection_changed"]
    assert 'data-blocked="1"' in render_preview([stale])
    with pytest.raises(V2Error) as error:
        _confirm(stale)
    assert error.value.code == "preview_confirmation_blocked"
    assert records.store.list("review_event", SUBJECT) == []


def test_cached_current_wrapper_never_overrules_live_backend_tokens(seeded):
    records, version = seeded
    bundle = _bundle(records, version)
    proposal = _confirm(bundle)
    snapshot = bundle["snapshot"]
    draft_id = snapshot["displayed_draft_ids"][0]
    records.commit_review(SUBJECT, snapshot["snapshot_id"], snapshot["snapshot_sha256"],
                          [{"draft_id": draft_id, "action": "defer"}])
    # An offline HTML wrapper remains an as-of statement. It has no database
    # connection; the real subsequent commit is the authoritative stale gate.
    assert _confirm(bundle)["snapshot_verification"]["state"] == "current"
    with pytest.raises(V2Error) as error:
        records.commit_review(SUBJECT, proposal["snapshot_id"], proposal["snapshot_sha256"],
                              proposal["decisions"])
    assert error.value.code == "stale_review"
    assert len(records.store.list("review_event", SUBJECT)) == 1
    assert records.store.list("observation_revision", SUBJECT) == []


@pytest.mark.parametrize("mutation", ["missing", "wrong_sha", "wrong_method", "false_clinical", "empty_stale", "reasons_current"])
def test_verification_wrapper_cannot_be_missing_or_claim_stronger_evidence(seeded, mutation):
    records, version = seeded
    bundle = _bundle(records, version)
    wrapper = bundle["snapshot_verification"]
    if mutation == "missing":
        del bundle["snapshot_verification"]
        expected = "preview_confirmation_blocked"
    else:
        expected = "preview_verification"
        if mutation == "wrong_sha": wrapper["snapshot_sha256"] = "e" * 64
        if mutation == "wrong_method": wrapper["method"] = "model_self_check"
        if mutation == "false_clinical": wrapper["clinical_validation"] = "verified"
        if mutation == "empty_stale": wrapper["state"] = "stale"
        if mutation == "reasons_current": wrapper["reasons"] = ["review_state_changed"]
    with pytest.raises(V2Error) as error:
        _confirm(bundle)
    assert error.value.code == expected
    assert records.store.list("observation_revision", SUBJECT) == []


def _png_chunk(kind, data):
    return len(data).to_bytes(4, "big") + kind + data + zlib.crc32(kind + data).to_bytes(4, "big")


def _png(*extra_chunks, include_pixels=True):
    header = (1).to_bytes(4, "big") * 2 + b"\x08\x00\x00\x00\x00"
    chunks = [_png_chunk(b"IHDR", header), *extra_chunks]
    if include_pixels:
        chunks.append(_png_chunk(b"IDAT", zlib.compress(b"\x00\x00")))
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks) + _png_chunk(b"IEND", b"")


def _crop(bundle, content):
    fragment = bundle["fragments"][0]
    fragment.pop("text")
    fragment.update(kind="image_crop", mime="image/png", data_base64=base64.b64encode(content).decode(),
                    provenance={"kind": "local_source_render"})


def _header(bundle):
    snapshot = bundle["snapshot"]
    binding = {key: snapshot[key] for key in ("subject_id", "version_id", "source_sha256", "snapshot_id", "snapshot_sha256")}
    bundle["document_fragments"] = [{**binding, "page": 1, "region": [0, 0, 1, .2],
        "purpose": "identity_header", "kind": "image_crop", "mime": "image/png",
        "data_base64": base64.b64encode(_png()).decode(), "provenance": {"kind": "local_source_render"},
        "quality": {"status": "readable"}}]


def test_animated_png_cannot_bypass_static_crop_decoding_budget(seeded):
    records, version = seeded
    bundle = _bundle(records, version)
    # Complete, synthetic two-frame APNG. Static canvas dimensions alone do
    # not bound animation work. No image decoder or crop file is created.
    static = _png()
    animation = _png_chunk(b"acTL", (2).to_bytes(4, "big") + (0).to_bytes(4, "big"))
    def frame(sequence):
        return _png_chunk(b"fcTL", sequence.to_bytes(4, "big") + (1).to_bytes(4, "big") * 2
                          + (0).to_bytes(4, "big") * 2 + b"\x00\x01\x00\x01\x00\x00")
    second_pixels = _png_chunk(b"fdAT", (2).to_bytes(4, "big") + zlib.compress(b"\x00\x01"))
    apng = static[:33] + animation + frame(0) + static[33:-12] + frame(1) + second_pixels + static[-12:]
    _crop(bundle, apng)
    with pytest.raises(V2Error) as error:
        render_preview([bundle])
    assert error.value.code in {"preview_asset", "preview_asset_limit"}


def test_missing_png_pixel_stream_cannot_be_a_readable_material_fragment(seeded):
    records, version = seeded
    bundle = _bundle(records, version)
    _crop(bundle, _png(include_pixels=False))
    with pytest.raises(V2Error) as error:
        _confirm(bundle)
    assert error.value.code in {"preview_asset", "preview_confirmation_blocked"}


def test_identity_header_does_not_replace_missing_row_fragment_or_resolve_flag(seeded):
    records, version = seeded
    bundle = _bundle(records, version)
    snapshot = bundle["snapshot"]
    draft_id = snapshot["displayed_draft_ids"][0]
    bundle["fragments"] = [fragment for fragment in bundle["fragments"] if fragment["field"] != "result"]
    _header(bundle)
    bundle["review_flags"] = [{"draft_id": None, "field": None, "code": "identity_conflict", "note": "Synthetic unresolved identity mismatch"}]
    normalized = validate_bundles([bundle])[0]
    blockers = confirmation_blockers(normalized, draft_id)
    assert any("Synthetic unresolved identity mismatch" in blocker for blocker in blockers)
    assert any("Результат" in blocker for blocker in blockers)
    with pytest.raises(V2Error) as error:
        _confirm(bundle)
    assert error.value.code == "preview_confirmation_blocked"


def test_ambiguous_unit_is_not_cleared_by_current_verification_or_readable_crop(seeded):
    records, version = seeded
    bundle = _bundle(records, version, unit_ambiguous=True)
    assert bundle["snapshot_verification"]["state"] == "current"
    with pytest.raises(V2Error) as error:
        _confirm(bundle)
    assert error.value.code == "preview_confirmation_blocked"


def _browser_proposal(bundle, *, image=None, trigger_error=False):
    """Execute the actual inline script in a DOM stub with no I/O APIs.

    This asserts script packet/scope behavior, not browser rendering or CSP.
    """
    node = shutil.which("node")
    assert node is not None, "Node is required to exercise the actual inline script"
    payload = {"script": SCRIPT, "bundle": validate_bundles([bundle])[0],
               "image": image, "trigger_error": trigger_error}
    harness = r'''
const vm=require('node:vm');
const fs=require('node:fs');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
class Element {
  constructor(){this.value='';this.textContent='';this.children=[];this.events={};this.checked=false;this.disabled=false;}
  replaceChildren(){this.children=[];this.value='';}
  append(child){this.children.push(child);if(this.children.length===1)this.value=String(child.value);}
  addEventListener(name,fn){this.events[name]=fn;}
}
const controls={}; for(const id of ['profile','document','snapshot','source-page','page-label','previous','next','packet','export','status','select-visible','clear-selection','action','prepare'])controls[id]=new Element();
controls.action.value='confirm';
controls['preview-manifest']={textContent:JSON.stringify({page_size:25,bundles:[input.bundle]})};
const images=[];
const cards=input.bundle.snapshot.rows.map(d=>({dataset:{draft:d.draft_id,pages:'[]',blocked:'0'},hidden:true,checkbox:new Element(),note:new Element(),querySelector(selector){return selector==='.row-select'?this.checkbox:this.note;},querySelectorAll(selector){return selector.includes('img')?images.filter(i=>i.card===this):[];}}));
const section={hidden:true,querySelectorAll(selector){return selector==='.row-card'?cards:selector.includes('img')?images.filter(i=>i.card===null):[];}};
if(input.image){const i=new Element();i.dataset={material:'1'};i.complete=input.image.state!=='pending';i.naturalWidth=input.image.state==='ready'?1:0;i.card=input.image.kind==='material'?cards[0]:null;i.parentElement=new Element();i.closest=selector=>selector==='.row-card'?i.card:section;images.push(i);}
const document={getElementById:id=>controls[id],createElement:()=>new Element(),querySelectorAll:selector=>selector==='.bundle'?[section]:selector==='.row-select,.correction-note'?cards.flatMap(c=>[c.checkbox,c.note]):selector==='img'?images:[]};
vm.runInNewContext(input.script,{document,console},{timeout:1000});
controls['select-visible'].events.click(); controls.prepare.events.click();
const first=controls.export.disabled?null:JSON.parse(controls.packet.textContent);
if(input.trigger_error){images[0].complete=true;images[0].naturalWidth=0;images[0].events.error();}
else controls.next.events.click();
const invalidated=controls.export.disabled;
controls['select-visible'].events.click(); controls.prepare.events.click();
const second=controls.export.disabled?null:JSON.parse(controls.packet.textContent);
process.stdout.write(JSON.stringify({first,second,invalidated}));
'''
    result = subprocess.run([node, "-e", harness], input=json.dumps(payload), capture_output=True,
                            text=True, check=True, timeout=5)
    return json.loads(result.stdout)


def test_actual_inline_script_preserves_verification_and_only_selects_current_25(seeded):
    records, version = seeded
    bundle = _bundle(records, version, count=26)
    actual = _browser_proposal(bundle)
    displayed = bundle["snapshot"]["displayed_draft_ids"]
    assert actual["first"]["visible_draft_ids"] == displayed[:25]
    assert actual["first"]["selected_draft_ids"] == displayed[:25]
    assert actual["invalidated"] is True
    assert actual["second"]["visible_draft_ids"] == displayed[25:]
    assert actual["second"]["selected_draft_ids"] == displayed[25:]
    expected = prepare_decisions(bundle, actual["first"]["decisions"], visible_draft_ids=displayed[:25])
    assert actual["first"] == expected
    assert expected["snapshot_verification"] == bundle["snapshot_verification"]
    assert expected["confirmation_assurance"] == "none" and expected["state"] == "PROPOSED"
    assert records.store.list("review_event", SUBJECT) == []


@pytest.mark.parametrize("kind", ["material", "header"])
def test_actual_inline_script_blocks_pending_images_before_confirm_export(seeded, kind):
    records, version = seeded
    bundle = _bundle(records, version)
    _crop(bundle, _png()) if kind == "material" else _header(bundle)
    actual = _browser_proposal(bundle, image={"kind": kind, "state": "pending"})
    assert actual["first"] is None
    assert actual["second"] is None
    assert actual["invalidated"] is True


@pytest.mark.parametrize("kind", ["material", "header"])
def test_actual_inline_script_decode_failure_revokes_packet_and_blocks_reprepare(seeded, kind):
    records, version = seeded
    bundle = _bundle(records, version)
    _crop(bundle, _png()) if kind == "material" else _header(bundle)
    actual = _browser_proposal(bundle, image={"kind": kind, "state": "ready"}, trigger_error=True)
    assert actual["first"]["state"] == "PROPOSED"
    assert actual["invalidated"] is True
    assert actual["second"] is None
