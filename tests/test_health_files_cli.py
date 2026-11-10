"""Synthetic-only command-line tests; no real private archive is accessed."""
import json
import os
from pathlib import Path
import subprocess
import sys

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "health-files"


def setup_private_archive(tmp_path):
    base = tmp_path.resolve()
    root = base / "subject"
    root.mkdir()
    (root / "report.txt").write_text("Synthetic marker: blue\n", encoding="utf-8")
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [{"id": "sample", "label": "Тест", "root": str(root)}]}, ensure_ascii=False))
    return config, root


def run_cli(args, *, input_bytes=b""):
    return subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), *args], input=input_bytes,
                          capture_output=True, check=False)


def test_query_from_stdin_and_explicit_profile(tmp_path):
    config, root = setup_private_archive(tmp_path)
    proc = run_cli(["--config", str(config), "--profile", "Тест"], input_bytes=b"marker\n")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["matches"][0]["path"] == "report.txt"
    assert result["matches"][0]["excerpt"] == "Synthetic marker: blue"
    assert result["coverage"]["text_search_complete"] is True
    assert result["coverage"]["source_document_coverage"] == "unknown"
    assert set(root.iterdir()) == {root / "report.txt"}


def test_query_file_and_unsafe_link_rejection(tmp_path):
    config, _ = setup_private_archive(tmp_path)
    query_file = tmp_path.resolve() / "query.txt"
    query_file.write_text("marker\n")
    args = ["--config", str(config), "--profile", "sample", "--query-file", str(query_file)]
    assert json.loads(run_cli(args).stdout)["matches"]
    linked = tmp_path.resolve() / "linked-query.txt"
    linked.symlink_to(query_file)
    proc = run_cli(["--config", str(config), "--profile", "sample", "--query-file", str(linked)])
    assert proc.returncode == 2
    assert json.loads(proc.stderr)["error"] == "search_unavailable"
    assert proc.stdout == b""


def test_rejects_missing_unknown_profile_query_args_and_large_input(tmp_path):
    config, root = setup_private_archive(tmp_path)
    common = ["--config", str(config)]
    for args, query in [
        (common, b"marker"),
        (common + ["--profile", "unknown"], b"marker"),
        (common + ["--profile", "sample", "marker"], b""),
        (common + ["--profile", "sample"], b"x" * 4097),
        (common + ["--profile", "sample"], b"\xff"),
    ]:
        proc = run_cli(args, input_bytes=query)
        assert proc.returncode == 2
        assert not proc.stdout
        assert json.loads(proc.stderr)["error"] in {"invalid_arguments", "search_unavailable"}
        assert b"marker" not in proc.stderr
    assert set(root.iterdir()) == {root / "report.txt"}


def test_safe_actionable_profile_error_does_not_echo_private_query(tmp_path):
    config, _ = setup_private_archive(tmp_path)
    proc = run_cli(["--config", str(config), "--profile", "unknown"], input_bytes=b"private-marker")
    error = json.loads(proc.stderr)
    assert error["message"] == "The selected profile is unknown or ambiguous."
    assert "private-marker" not in proc.stderr.decode()
