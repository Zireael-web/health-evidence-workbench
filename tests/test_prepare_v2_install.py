"""Exercise preparation without registering a plugin or touching an archive."""
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
PREPARE = ROOT / "scripts" / "prepare-v2-install"


def invoke(output, *extra):
    return subprocess.run([sys.executable, "-I", "-B", str(PREPARE), "--output", str(output),
                           "--isolation", "host", *extra], capture_output=True,
                          text=True, timeout=120)


def test_existing_output_is_never_reused_or_changed(tmp_path):
    output = tmp_path / "occupied"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("leave this alone", encoding="utf-8")
    result = invoke(output)
    assert result.returncode != 0
    assert json.loads(result.stderr)["status"] == "failed"
    assert marker.read_text(encoding="utf-8") == "leave this alone"
    assert list(output.iterdir()) == [marker]


def test_invalid_interpreter_fails_before_creating_output(tmp_path):
    output = tmp_path / "not-created"
    result = invoke(output, "--python", str(tmp_path / "missing-python"))
    assert result.returncode != 0
    assert not output.exists()


def test_symlink_output_is_never_followed(tmp_path):
    target = tmp_path / "existing"
    target.mkdir()
    output = tmp_path / "linked"
    output.symlink_to(target, target_is_directory=True)
    result = invoke(output)
    assert result.returncode != 0
    assert list(target.iterdir()) == []


@pytest.mark.skipif(importlib.util.find_spec("mcp") is None, reason="optional MCP extra is not installed")
def test_prepared_catalog_runs_public_server_without_installation(tmp_path):
    # Spaces test that the displayed shell commands remain correctly quoted.
    output = tmp_path.resolve() / "prepared catalog"
    result = invoke(output, "--python", sys.executable)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "prepared_inactive"
    assert report["doctor_status"] == "logical_host_only"
    assert report["public_research_provider"] == "pubmed_configured_not_searched"
    assert report["archive_bindings"] == "none"
    assert any("hook trust" in item for item in report["not_checked"])
    assert any("PubMed network" in item for item in report["not_checked"])

    config = json.loads((output / "deployment.json").read_text(encoding="utf-8"))
    assert config["archive_roots"] == {}
    assert config["research_provider"] == {"name": "pubmed"}
    market = output / "marketplace"
    catalog = json.loads((market / ".agents/plugins/marketplace.json").read_text(encoding="utf-8"))
    assert (market / catalog["plugins"][0]["source"]["path"]).is_dir()
    prepared_plugin = market / "plugins/health-analyzer-v2"
    server = json.loads((prepared_plugin / ".mcp.json").read_text(encoding="utf-8"))
    assert set(server["mcpServers"]) == {"health-analyzer-v2-public-research"}
    # A plain directory copy retains the locator; Codex cache behavior itself
    # still requires verification in a fresh installed session.
    copied_plugin = tmp_path / "synthetic-cache-copy"
    shutil.copytree(prepared_plugin, copied_plugin)
    locator = json.loads((copied_plugin / ".local-install.json").read_text(encoding="utf-8"))
    assert locator["schema"] == "health-analyzer.local-install/1"
    assert Path(locator["source_root"]) == ROOT
    assert Path(locator["source_root"], "scripts/health-document").is_file()
    assert Path(locator["source_root"], "scripts/health-files").is_file()
    assert Path(locator["python"]).is_file()
    assert shlex.split(report["commands_not_executed"][0])[4] == str(market)
    assert shlex.split(report["commands_not_executed"][1])[3] == (
        "health-analyzer-v2@" + catalog["name"])
    assert json.loads((output / "preparation-summary.json").read_text(encoding="utf-8")) == report
