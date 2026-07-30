"""Synthetic CLI tests; never read a real health document or private store."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from health_analyzer.cli import main
from health_analyzer.local_cli import _write_new_json


def _stub_inspect(monkeypatch):
    from health_analyzer import local_documents

    calls = []

    def inspect(path, *, isolation):
        calls.append((path, isolation))
        return {"sha256": "a" * 64, "page_count": 1, "review_status": "needs_review", "pages": []}

    monkeypatch.setattr(local_documents, "inspect_local_pdf", inspect)
    return calls


def test_local_inspection_writes_new_private_artifact(monkeypatch, tmp_path, capsys):
    calls = _stub_inspect(monkeypatch)
    output = tmp_path / "synthetic.json"
    main(["local-pdf", "inspect", "synthetic.pdf", "--isolation", "host", "--output", str(output)])
    assert calls == [(Path("synthetic.pdf"), "host")]
    assert json.loads(output.read_text())["review_status"] == "needs_review"
    assert output.stat().st_mode & 0o777 == 0o600
    assert json.loads(capsys.readouterr().out)["page_count"] == 1
    with pytest.raises(FileExistsError):
        main(["local-pdf", "inspect", "synthetic.pdf", "--output", str(output)])


def test_ingest_binds_copy_to_inspected_digest(monkeypatch, capsys):
    from health_analyzer import local_intake

    _stub_inspect(monkeypatch)
    calls = []

    def copy(source, root, destination, *, expected_sha256):
        calls.append((source, root, destination, expected_sha256))
        return SimpleNamespace(path=root / "synthetic.pdf", sha256=expected_sha256, status="copied")

    monkeypatch.setattr(local_intake, "copy_authorized_pdf", copy)
    main(["local-pdf", "ingest", "synthetic.pdf", "--archive-root", "/synthetic/archive"])
    assert calls == [(Path("synthetic.pdf"), Path("/synthetic/archive"), None, "a" * 64)]
    result = json.loads(capsys.readouterr().out)
    assert result["intake"]["identity_assignment"] == "caller_confirmed_archive_root"


def test_copy_is_not_called_after_extraction_failure(monkeypatch):
    from health_analyzer import local_documents, local_intake

    def fail(*args, **kwargs):
        raise ValueError("synthetic hard cap")

    monkeypatch.setattr(local_documents, "inspect_local_pdf", fail)
    monkeypatch.setattr(local_intake, "copy_authorized_pdf", lambda *a, **k: pytest.fail("unexpected copy"))
    with pytest.raises(ValueError, match="hard cap"):
        main(["local-pdf", "ingest", "synthetic.pdf", "--archive-root", "/synthetic/archive"])


def test_json_output_rejects_symlink_and_traversal(tmp_path):
    original = tmp_path / "original.json"
    original.write_text("untouched")
    link = tmp_path / "linked.json"
    link.symlink_to(original)
    with pytest.raises(FileExistsError):
        _write_new_json(link, {})
    parent_link = tmp_path / "linked-dir"
    parent_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        _write_new_json(parent_link / "new.json", {})
    with pytest.raises(ValueError):
        _write_new_json(tmp_path / ".." / "new.json", {})
    assert original.read_text() == "untouched"


def test_ingest_requires_explicit_patient_root():
    with pytest.raises(SystemExit):
        main(["local-pdf", "ingest", "synthetic.pdf"])


def test_render_cli_requires_explicit_host_mode_and_emits_manifest(monkeypatch, capsys):
    from health_analyzer import local_documents

    calls = []

    def render(path, parent, *, dpi, isolation):
        calls.append((path, parent, dpi, isolation))
        return {"page_count": 2, "pages": [{"page": 1}, {"page": 2}], "review_status": "needs_review"}

    monkeypatch.setattr(local_documents, "render_local_pdf", render)
    main(["local-pdf", "render", "synthetic.pdf", "--render-parent", "/synthetic/renders", "--isolation", "host", "--dpi", "100"])
    assert calls == [(Path("synthetic.pdf"), Path("/synthetic/renders"), 100, "host")]
    assert json.loads(capsys.readouterr().out)["page_count"] == 2
    with pytest.raises(SystemExit):
        main(["local-pdf", "render", "synthetic.pdf", "--render-parent", "/synthetic/renders"])


def test_output_conflict_prevents_inspection_and_intake(monkeypatch, tmp_path):
    from health_analyzer import local_documents

    output = tmp_path / "existing.json"
    output.write_text("untouched")
    monkeypatch.setattr(local_documents, "inspect_local_pdf", lambda *a, **k: pytest.fail("unexpected read"))
    with pytest.raises(FileExistsError):
        main(["local-pdf", "ingest", "synthetic.pdf", "--archive-root", "/synthetic/archive", "--output", str(output)])
    assert output.read_text() == "untouched"


def test_output_publication_is_complete_and_no_replace(monkeypatch, tmp_path):
    import os

    output = tmp_path / "synthetic.json"
    original_link = os.link

    def observe(source, target, **kwargs):
        assert not output.exists()
        assert json.loads((tmp_path / source).read_text()) == {"synthetic": "complete"}
        original_link(source, target, **kwargs)

    monkeypatch.setattr(os, "link", observe)
    _write_new_json(output, {"synthetic": "complete"})
    assert list(tmp_path.iterdir()) == [output]


def test_concurrent_output_is_not_deleted(monkeypatch, tmp_path):
    import os

    output = tmp_path / "synthetic.json"

    def collision(*args, **kwargs):
        output.write_text("other writer")
        raise FileExistsError("synthetic concurrent output")

    monkeypatch.setattr(os, "link", collision)
    with pytest.raises(FileExistsError):
        _write_new_json(output, {})
    assert output.read_text() == "other writer"
    assert list(tmp_path.iterdir()) == [output]
