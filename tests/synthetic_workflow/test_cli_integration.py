"""Exercise actual local CLI entrypoints using invented documents only."""
from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("synthetic_cli_generator", Path(__file__).with_name("generate.py"))
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


def invoke(entry: str, *args: object, stdin: str | None = None):
    return subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts" / entry),
                           *map(str, args)], input=stdin, text=True,
                          capture_output=True, cwd=ROOT, check=False)


def test_explicit_profiles_copy_transcript_retry_isolated_search_and_coverage(tmp_path):
    # Resolve the macOS /var symlink; CLI intentionally disallows symlink ancestors.
    base = tmp_path.resolve()
    fixtures = base / "synthetic"
    generator.generate(fixtures)
    names = ("Тест Альфа", "Δοκιμή Бета", "試験 第三")
    roots = []
    for i in range(3):
        root = base / f"profile-{i}"
        root.mkdir(mode=0o700)
        roots.append(root)
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [{"id": f"p{i}", "label": label, "root": str(roots[i])}
                                               for i, label in enumerate(names)]}, ensure_ascii=False),
                      encoding="utf-8")
    config.chmod(0o600)

    saved_names = []
    for i, (label, name) in enumerate(zip(names, generator.DOCUMENTS, strict=False)):
        source = fixtures / name
        copied = invoke("health-document", "copy", "--source", source, "--config", config, "--profile", label)
        assert copied.returncode == 0, copied.stderr + copied.stdout
        details = json.loads(copied.stdout)
        assert details["status"] == "copied" and details["identity_assignment"] == "explicit_profile"
        assert Path(details["path"]).parent == roots[i] and Path(details["path"]).read_bytes() == source.read_bytes()
        transcript = base / f"transcript-{i}.txt"
        text = "\n\f\n".join("\n".join(page) for page in generator.DOCUMENTS[name])
        transcript.write_text(text, encoding="utf-8")
        saved = invoke("health-document", "save-text", "--document", details["path"], "--config", config,
                       "--profile", label, "--text-file", transcript, "--expected-sha256", details["sha256"])
        assert saved.returncode == 0, saved.stderr + saved.stdout
        saved_details = json.loads(saved.stdout)
        saved_names.append(Path(saved_details["path"]).name)
        assert saved_details["review_status"] == "unverified"
        assert Path(saved_details["path"]).read_text(encoding="utf-8") == text
        repeat = invoke("health-document", "copy", "--source", source, "--config", config, "--profile", label)
        assert repeat.returncode == 0 and json.loads(repeat.stdout)["status"] == "already_present"
        repeat_text = invoke("health-document", "save-text", "--document", details["path"], "--config", config,
                             "--profile", label, "--text-file", transcript, "--expected-sha256", details["sha256"])
        assert repeat_text.returncode == 0 and json.loads(repeat_text.stdout)["status"] == "already_present"
        transcript.write_text("different invented text", encoding="utf-8")
        conflict = invoke("health-document", "save-text", "--document", details["path"], "--config", config,
                          "--profile", label, "--text-file", transcript, "--expected-sha256", details["sha256"])
        assert conflict.returncode != 0 and Path(saved_details["path"]).read_text(encoding="utf-8") == text
        transcript.write_text(text, encoding="utf-8")
        # The other two archive roots must never receive this profile's document.
        assert all(not (other / name).exists() for j, other in enumerate(roots) if j != i)

    found = invoke("health-files", "--config", config, "--profile", names[0], stdin="Marker A\n")
    assert found.returncode == 0, found.stderr
    result = json.loads(found.stdout)
    assert result["profile_id"] == "p0" and len(result["matches"]) == 1
    assert result["matches"][0]["path"] == saved_names[0]
    assert result["coverage"]["search_scope"] == "utf8_txt_files_only"
    assert result["coverage"]["source_document_coverage"] == "unknown"
    assert result["coverage"]["text_files_scanned"] == 1
    other = invoke("health-files", "--config", config, "--profile", names[1], stdin="Marker A\n")
    assert other.returncode == 0 and json.loads(other.stdout)["matches"] == []

    # Existing original without text cannot be treated as indexed source coverage.
    (roots[0] / "pending.pdf").write_bytes((fixtures / "other_sample.pdf").read_bytes())
    coverage = invoke("health-files", "--config", config, "--profile", names[0], stdin="unreadable\n")
    assert coverage.returncode == 0
    assert json.loads(coverage.stdout)["coverage"]["source_document_coverage"] == "unknown"
    assert json.loads(coverage.stdout)["coverage"]["other_files"] >= 2

    # A wrong selected profile cannot write the text next to another profile's file.
    wrong_profile = invoke("health-document", "save-text", "--document", roots[0] / "lab_panel.pdf",
                           "--config", config, "--profile", names[1], "--text-file", base / "transcript-0.txt",
                           "--expected-sha256", hashlib.sha256((roots[0] / "lab_panel.pdf").read_bytes()).hexdigest())
    assert wrong_profile.returncode != 0

    no_profile = invoke("health-document", "copy", "--source", fixtures / "other_sample.pdf", "--config", config)
    assert no_profile.returncode != 0
    assert all(not (root / "other_sample.pdf").exists() for root in roots)
    unknown = invoke("health-files", "--config", config, "--profile", "unknown", stdin="Marker A\n")
    assert unknown.returncode != 0


def test_duplicate_cli_finds_same_bytes_only_in_selected_profile_and_reports_incomplete(tmp_path):
    base = tmp_path.resolve()
    fixtures = base / "invented"
    generator.generate(fixtures)
    source = fixtures / "lab_panel.pdf"
    first = base / "profile-1"
    second = base / "profile-2"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [
        {"id": "a", "label": "Первый пример", "root": str(first)},
        {"id": "b", "label": "Другой пример", "root": str(second)},
    ]}, ensure_ascii=False), encoding="utf-8")
    config.chmod(0o600)
    identical = source.read_bytes()
    (first / "different-name.pdf").write_bytes(identical)
    (second / "other-profile.pdf").write_bytes(identical)

    def scan():
        result = invoke("health-duplicates", "--config", config, "--profile", "Первый пример", "--source", source)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    result = scan()
    assert result["profile_id"] == "a" and result["matches"] == ["different-name.pdf"]
    assert result["coverage"]["search_complete"] is True
    assert result["coverage"]["match_meaning"] == "same_sha256_and_size_not_identity_or_role"

    # Change exactly one byte, preserving length. The match in profile b must not leak into profile a.
    changed = bytearray(identical)
    changed[-2] ^= 1
    (first / "different-name.pdf").write_bytes(changed)
    result = scan()
    assert result["matches"] == [] and result["coverage"]["search_complete"] is True
    assert (second / "other-profile.pdf").read_bytes() == identical

    # A skipped symlink makes the scan explicitly incomplete, rather than asserting absence.
    (first / "skipped-link").symlink_to(second / "other-profile.pdf")
    result = scan()
    assert result["matches"] == [] and result["coverage"]["search_complete"] is False
    assert result["coverage"]["skipped_or_unreadable"] >= 1


def test_create_folder_copy_document_and_find_text_in_only_selected_profile(tmp_path):
    base = tmp_path.resolve()
    fixtures = base / "invented"
    generator.generate(fixtures)
    first, second = base / "profile-one", base / "profile-two"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [
        {"id": "first", "label": "Испытание А", "root": str(first)},
        {"id": "second", "label": "Испытание Б", "root": str(second)},
    ]}, ensure_ascii=False), encoding="utf-8")
    config.chmod(0o600)

    folder = "Documents/Reports"
    create = invoke("health-document", "ensure-folder", "--config", config,
                    "--profile", "Испытание А", "--folder", folder)
    assert create.returncode == 0, create.stderr + create.stdout
    created = json.loads(create.stdout)
    assert created["status"] == "created" and Path(created["path"]) == first / folder
    assert created["created_count"] == 2
    assert not (second / "Documents").exists()
    repeat = invoke("health-document", "ensure-folder", "--config", config,
                    "--profile", "Испытание А", "--folder", folder)
    assert repeat.returncode == 0 and json.loads(repeat.stdout)["status"] == "already_present"

    source = fixtures / "exam_report.pdf"
    copy = invoke("health-document", "copy", "--config", config, "--profile", "Испытание А",
                  "--source", source, "--destination", f"{folder}/{source.name}")
    assert copy.returncode == 0, copy.stderr + copy.stdout
    saved = json.loads(copy.stdout)
    assert Path(saved["path"]).read_bytes() == source.read_bytes()
    transcript = base / "invented-transcript.txt"
    transcript.write_text("\n".join(generator.DOCUMENTS[source.name][0]), encoding="utf-8")
    saved_text = invoke("health-document", "save-text", "--config", config, "--profile", "Испытание А",
                        "--document", saved["path"], "--text-file", transcript,
                        "--expected-sha256", saved["sha256"])
    assert saved_text.returncode == 0, saved_text.stderr + saved_text.stdout
    text_path = Path(json.loads(saved_text.stdout)["path"])
    result = invoke("health-files", "--config", config, "--profile", "Испытание А", stdin="observation Z\n")
    assert result.returncode == 0, result.stderr
    hits = json.loads(result.stdout)["matches"]
    assert len(hits) == 1 and hits[0]["path"] == str(text_path.relative_to(first))
    other = invoke("health-files", "--config", config, "--profile", "Испытание Б", stdin="observation Z\n")
    assert other.returncode == 0 and json.loads(other.stdout)["matches"] == []
    assert not (second / "Documents").exists()
