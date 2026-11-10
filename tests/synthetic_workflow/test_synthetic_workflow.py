"""Engineering checks on invented PDFs, not model or clinical validation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat

import pytest

from health_analyzer.local_intake import IntakeConflictError, copy_authorized_pdf, save_model_transcript


SPEC = importlib.util.spec_from_file_location("synthetic_generator", Path(__file__).with_name("generate.py"))
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


def test_generated_pdfs_are_readable_and_match_synthetic_page_manifest(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    destination = tmp_path / "invented"
    generator.generate(destination)
    manifest = json.loads((destination / "expected.json").read_text())
    assert "no real persons" in manifest["origin"]
    for name, expected in manifest["documents"].items():
        reader = pypdf.PdfReader(destination / name, strict=True)
        assert len(reader.pages) == len(expected["pages"])
        for page, expected_lines in zip(reader.pages, expected["pages"], strict=True):
            text = page.extract_text()
            for line in expected_lines:
                assert line in text


def test_copy_sidecar_retry_and_conflict_in_multiple_arbitrary_roots(tmp_path):
    fixtures = tmp_path / "invented"
    generator.generate(fixtures)
    roots = [tmp_path / "profile-a", tmp_path / "profile-b", tmp_path / "профиль-в"]
    for root in roots:
        root.mkdir()
    source = fixtures / "lab_panel.pdf"
    original_bytes = source.read_bytes()
    page_text = "\n\f\n".join("\n".join(page) for page in generator.DOCUMENTS[source.name])
    for root in roots:
        first = copy_authorized_pdf(source, root)
        assert first.status == "copied" and first.path.read_bytes() == original_bytes
        assert stat.S_IMODE(first.path.stat().st_mode) == 0o600
        text = save_model_transcript(first.path, page_text, expected_sha256=first.sha256)
        assert text.path.read_text(encoding="utf-8") == page_text
        assert stat.S_IMODE(text.path.stat().st_mode) == 0o600
        assert copy_authorized_pdf(source, root).status == "already_present"
        assert save_model_transcript(first.path, page_text, expected_sha256=first.sha256).status == "already_present"
        with pytest.raises(IntakeConflictError):
            save_model_transcript(first.path, "different proposed text", expected_sha256=first.sha256)
        assert text.path.read_text(encoding="utf-8") == page_text
        assert first.path.read_bytes() == original_bytes
    # Explicit roots are supplied by the caller. The storage helper does not infer identity.
    assert len({(root / source.name).resolve() for root in roots}) == len(roots)


def test_generator_refuses_existing_directory(tmp_path):
    with pytest.raises(FileExistsError):
        generator.generate(tmp_path)
