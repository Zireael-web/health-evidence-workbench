"""Black-box tests of the synthetic local check; no personal archive is used."""

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "check-simple-setup"


def test_synthetic_check_runs_outside_checkout_without_writing_to_cwd(tmp_path):
    result = subprocess.run([sys.executable, "-I", "-B", str(CHECK), "--json"],
                            cwd=tmp_path, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "passed"
    assert any("Codex" in item for item in report["not_checked"])
    assert any("medical" in item for item in report["not_checked"])
    assert list(tmp_path.iterdir()) == []


def test_incomplete_checkout_reports_failure_without_traceback(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    isolated_check = scripts / CHECK.name
    shutil.copyfile(CHECK, isolated_check)
    result = subprocess.run([sys.executable, "-I", "-B", str(isolated_check), "--json"],
                            cwd=tmp_path, capture_output=True, text=True, timeout=45)
    assert result.returncode != 0
    assert json.loads(result.stdout)["status"] == "failed"
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("broken_script", "fake_response", "expected_error"),
    [
        ("health-document", '{"status":"created","created_count":2,"path":"missing"}', "folder"),
        ("health-duplicates", '{"coverage":{"search_complete":true},"matches":[]}', "duplicate"),
        ("health-files", '{"matches":[]}', "transcript"),
    ],
)
def test_broken_search_does_not_report_success(tmp_path, broken_script, fake_response, expected_error):
    isolated = tmp_path / "synthetic-checkout"
    scripts = isolated / "scripts"
    scripts.mkdir(parents=True)
    for name in ("check-simple-setup", "health-document", "health-duplicates", "health-files"):
        shutil.copyfile(ROOT / "scripts" / name, scripts / name)
    shutil.copytree(ROOT / "src" / "health_analyzer", isolated / "src" / "health_analyzer",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (scripts / broken_script).write_text("print(" + repr(fake_response) + ")\n", encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", "-B", str(scripts / CHECK.name), "--json"],
                            cwd=tmp_path, capture_output=True, text=True, timeout=45)
    assert result.returncode != 0
    report = json.loads(result.stdout)
    assert report["status"] == "failed"
    assert expected_error in report["error"]
    assert "Traceback" not in result.stderr
