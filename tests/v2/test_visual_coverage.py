"""Untrusted visual coverage cannot promote a proposed subset to complete."""
from types import SimpleNamespace
import pytest
from health_analyzer.v2.common import SignedStore, V2Error
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.ingest import ImportService
from health_analyzer.v2.layout import propose_lab_rows
from health_analyzer.v2.originals import OriginalsStore


def fixture(tmp_path):
    root=tmp_path / "synthetic-archive"; root.mkdir()
    root.joinpath("source.png").write_bytes(b"\x89PNG\r\n\x1a\nsynthetic")
    store=SignedStore(tmp_path / "state/private.sqlite3",b"c"*32,"private-data")
    records=RecordsService(store)
    config=SimpleNamespace(archive_roots={"demo":{"path":root,"subject_id":"demo"}})
    imports=ImportService(config,records,image_extractor=lambda data:([],["synthetic unavailable OCR"]))
    records.register_subject("demo","Synthetic")
    doc=imports.prepare_import("demo",[{"root_id":"demo","relative_path":"source.png"}])["documents"][0]
    page={"page":1,"source":"vision_ocr","text":"","width":700,"height":200,"blocks":[]}
    for r,cells in enumerate([["Test","Result","Units","Reference range"],["Synthetic A","2,50","g/L","0-4"]]):
        for c,t in enumerate(cells): page["blocks"].append({"text":t,"x":[10,230,350,470][c],"y":40+r*40,"width":130 if c in {0,3} else 80,"height":20,"confidence":.99})
    row=propose_lab_rows([page],doc,locator_kind="image")["rows"][0]
    return root,store,records,imports,doc,row


@pytest.mark.parametrize("patch",[
    {"status":"complete"},
    {"expected_count":1,"expected_count_basis":"source_count"},
    {"expected_count":1,"expected_count_basis":"extractor_count"},
    {"processed_pages":[1,2]},
])
def test_caller_counts_and_unanchored_pages_cannot_raise_coverage(tmp_path,patch):
    root,store,records,imports,doc,row=fixture(tmp_path)
    before={kind:store.list(kind,"demo") for kind in ["extraction_run","extraction_selection","observation_draft"]}
    coverage={"status":"partial","expected_count":None,"expected_count_basis":"unknown","processed_pages":[1],"method":"model_vision"};coverage.update(patch)
    try:
        with pytest.raises(V2Error) as e: imports.submit_visual("demo",doc["version_id"],[row],coverage)
        assert e.value.code=="VISUAL_COVERAGE_UNVERIFIED"
        assert before=={kind:store.list(kind,"demo") for kind in before}
        assert records.query_history("demo")["current"]==[]
        assert root.joinpath("source.png").read_bytes()==b"\x89PNG\r\n\x1a\nsynthetic"
    finally:store.close()


def test_partial_visual_rows_keep_unknown_expected_count_and_actual_row_count(tmp_path):
    root,store,records,imports,doc,row=fixture(tmp_path)
    try:
        result=imports.submit_visual("demo",doc["version_id"],[row],{"status":"partial","expected_count":None,"expected_count_basis":"unknown","processed_pages":[1],"method":"model_vision"})
        view=records.prepare_review("demo",doc["version_id"])
        assert result["confirmed"] is False and view["coverage"]["status"]=="partial"
        assert view["coverage"]["expected_count"] is None and view["coverage"]["known_extracted_rows"]==1
        assert view["rows"][0]["row"]["result"]["raw"]=="2,50"
        assert records.query_history("demo")["current"]==[]
    finally:store.close()


def test_readonly_original_lookup_does_not_create_missing_base_or_publish(tmp_path):
    base=tmp_path / "missing"
    with pytest.raises(V2Error): OriginalsStore(base,readonly=True)
    assert not base.exists()
    writable=OriginalsStore(base)
    content=b"synthetic original"; manifest=writable.preserve("demo",content,"text/plain")
    reader=OriginalsStore(base,readonly=True)
    assert reader.read_manifest("demo",manifest)==content
    with pytest.raises(V2Error) as e: reader.preserve("demo",b"new","text/plain")
    assert e.value.code=="ORIGINALS_READ_ONLY"
    assert reader.read_manifest("demo",manifest)==content
