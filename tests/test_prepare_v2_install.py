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


def test_invalid_private_profiles_are_rejected_before_output_is_created(tmp_path):
    base = tmp_path.resolve()
    output = base / "not-created"
    config = base / "private-profiles.json"
    config.write_text('{"profiles":[{"id":"p","label":"Example","root":"/nonexistent-profile-root"}]}')
    result = invoke(output, "--profiles-config", str(config))
    assert result.returncode != 0 and not output.exists()
    assert str(config) not in result.stderr
    assert "nonexistent-profile-root" not in result.stderr


def test_profile_config_symlink_and_overlapping_roots_are_rejected(tmp_path):
    base = tmp_path.resolve()
    archive = base / "profile"
    archive.mkdir()
    nested = archive / "nested"
    nested.mkdir()
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [
        {"id": "a", "label": "Example A", "root": str(archive)},
        {"id": "b", "label": "Example B", "root": str(nested)},
    ]}))
    output = base / "not-created"
    rejected = invoke(output, "--profiles-config", str(config))
    assert rejected.returncode != 0 and not output.exists()

    config.write_text(json.dumps({"profiles": [{"id": "a", "label": "Example A", "root": str(archive)}]}))
    alias = base / "profiles-link.json"
    alias.symlink_to(config)
    rejected = invoke(output, "--profiles-config", str(alias))
    assert rejected.returncode != 0 and not output.exists()


def test_private_config_and_archive_cannot_overlap_checkout_or_output(tmp_path):
    base = tmp_path.resolve()
    # The source checkout must never become a private subject archive.
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [{"id": "p", "label": "Example", "root": str(ROOT)}]}))
    output = base / "not-created"
    rejected = invoke(output, "--profiles-config", str(config))
    assert rejected.returncode != 0 and not output.exists()

    # Preparing inside a profile archive would mix program assets with records.
    archive = base / "synthetic-profile"
    archive.mkdir()
    config.write_text(json.dumps({"profiles": [{"id": "p", "label": "Example", "root": str(archive)}]}))
    rejected = invoke(archive / "not-created", "--profiles-config", str(config))
    assert rejected.returncode != 0 and not (archive / "not-created").exists()


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
    assert "profiles_config" not in locator
    assert report["local_profiles"] == "not_configured"
    assert report["local_profile_permission_warnings"] == []
    assert Path(locator["source_root"]) == ROOT
    assert Path(locator["source_root"], "scripts/health-document").is_file()
    assert Path(locator["source_root"], "scripts/health-files").is_file()
    assert Path(locator["python"]).is_file()
    assert shlex.split(report["commands_not_executed"][0])[4] == str(market)
    assert shlex.split(report["commands_not_executed"][1])[3] == (
        "health-analyzer-v2@" + catalog["name"])
    assert json.loads((output / "preparation-summary.json").read_text(encoding="utf-8")) == report


@pytest.mark.skipif(importlib.util.find_spec("mcp") is None, reason="optional MCP extra is not installed")
def test_private_profile_locator_is_bound_without_copying_archive_data(tmp_path):
    base = tmp_path.resolve()
    archive = base / "synthetic-profile"
    archive.mkdir(mode=0o700)
    document = archive / "invented-document.txt"
    document.write_text("Synthetic private sentinel", encoding="utf-8")
    config = base / "private-profiles.json"
    config.write_text(json.dumps({"profiles": [{"id": "p", "label": "Example profile", "root": str(archive)}]}))
    config.chmod(0o600)
    output = base / "prepared"

    result = invoke(output, "--python", sys.executable, "--profiles-config", str(config))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["local_profiles"] == "configuration_and_roots_validated"
    assert report["local_profile_permission_warnings"] == ["acl_and_parent_access_not_checked"]
    assert str(config) not in result.stdout and str(archive) not in result.stdout
    plugin = output / "marketplace/plugins/health-analyzer-v2"
    locator_path = plugin / ".local-install.json"
    locator = json.loads(locator_path.read_text(encoding="utf-8"))
    assert locator["profiles_config"] == str(config)
    assert locator_path.stat().st_mode & 0o777 == 0o600
    assert "Example profile" not in locator_path.read_text(encoding="utf-8")
    assert not any(path.name == document.name for path in plugin.rglob("*"))
    assert document.read_text(encoding="utf-8") == "Synthetic private sentinel"

    # A synthetic cache copy retains only the locator, not profile contents.
    cache_copy = base / "cache-copy"
    shutil.copytree(plugin, cache_copy)
    assert json.loads((cache_copy / ".local-install.json").read_text())["profiles_config"] == str(config)
    assert not any(path.name == document.name for path in cache_copy.rglob("*"))


@pytest.mark.skipif(importlib.util.find_spec("mcp") is None, reason="optional MCP extra is not installed")
def test_broad_profile_modes_warn_without_changing_permissions(tmp_path):
    base = tmp_path.resolve()
    archive = base / "synthetic-profile"
    archive.mkdir()
    archive.chmod(0o755)
    config = base / "private-profiles.json"
    config.write_text(json.dumps({"profiles": [{"id": "p", "label": "Example profile", "root": str(archive)}]}))
    config.chmod(0o644)
    output = base / "prepared"

    result = invoke(output, "--python", sys.executable, "--profiles-config", str(config))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert set(report["local_profile_permission_warnings"]) == {
        "acl_and_parent_access_not_checked", "profile_config_group_or_other_mode_bits",
        "profile_root_group_or_other_mode_bits",
    }
    assert config.stat().st_mode & 0o777 == 0o644
    assert archive.stat().st_mode & 0o777 == 0o755
