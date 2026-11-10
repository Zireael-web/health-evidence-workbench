import json
from pathlib import Path
import subprocess
import sys
import shutil
from types import SimpleNamespace

import pytest

from health_analyzer.v2 import cli
from health_analyzer.v2.common import V2Error
from health_analyzer.v2.configuration import initialize


def test_subprocess_service_call_uses_fd_keys_and_persists_new_history(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    arguments = tmp_path / "arguments.json"
    arguments.write_text(json.dumps({"subject_id": "subject_demo", "label": "Synthetic subject"}))
    command = [sys.executable, "-I", "-B", str(cli.code_root() / "scripts/ha-v2"),
               "--config", str(config.path), "call", "--zone", "private-data",
               "--tool", "register_subject", "--arguments-file", str(arguments)]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["subject_id"] == "subject_demo"
    arguments.write_text('{"subject_id":"subject_demo"}')
    command[command.index("register_subject")] = "query_history"
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["subject_id"] == "subject_demo"
    assert "key" not in result.stdout.lower()


def test_host_doctor_never_claims_os_boundary(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    report = cli.doctor(config)
    assert report["status"] == "logical_host_only"
    assert report["os_isolation"] == "not_enforced"
    assert report["clinical_archive_opened"] is False


def test_enforced_missing_platform_fails_without_host_fallback(tmp_path, monkeypatch):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="macos_enforced")
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    with pytest.raises(V2Error, match="no host fallback"):
        cli.launch_runtime(config, "private-data", action="serve")
    report = cli.doctor(config)
    assert report["status"] == "unavailable"
    assert report["os_isolation"] == "unconfirmed"
    assert not list(config.zone_root("private-data").glob("doctor-*"))


def test_policy_denies_private_archive_and_keys_without_broad_code_root(tmp_path):
    archive = tmp_path / "synthetic"
    archive.mkdir()
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="macos_enforced",
                        archive_roots={"demo": {"path": str(archive), "subject_id": "subject_demo"}})
    public = cli.sandbox_policy(config, "public-research")
    private = cli.sandbox_policy(config, "private-data")
    assert '(deny default)' in public and '(deny default)' in private
    assert f'(deny file-read* file-write* (subpath "{archive}"))' in public
    assert f'(deny file-write* (subpath "{archive}"))' in private
    assert '(deny network*)' in private
    assert 'Library/Keychains' in public and 'Library/Keychains' in private
    assert f'(subpath "{cli.code_root()}")' not in public


def test_http_and_implicit_config_rejected(tmp_path):
    command = [sys.executable, "-I", "-B", str(cli.code_root() / "scripts/ha-v2")]
    result = subprocess.run(command + ["serve", "--zone", "private-data"], capture_output=True, text=True)
    assert result.returncode == 2 and "--config" in result.stderr
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    result = subprocess.run(command + ["--config", str(config.path), "serve", "--zone", "public-research",
                                       "--transport", "streamable-http"], capture_output=True, text=True)
    assert result.returncode == 2 and "invalid choice" in result.stderr


def test_config_pipe_supports_multiple_profiles_without_secret_args():
    value = {"profiles": [{"label": "synthetic" * 100} for _ in range(100)]}
    fd = cli._pipe(json.dumps(value).encode())
    assert cli._read_fd_json(fd) == value


def test_inactive_registration_refuses_overwrite_and_pins_stdio(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    destination = tmp_path / "inactive"
    result = cli.deployment_assets(config, destination)
    assert result["status"] == "generated_inactive" and result["active_plugin_changed"] is False
    servers = json.loads((destination / ".mcp.json").read_text())["mcpServers"]
    assert len(servers) == 2
    for entry in servers.values():
        assert entry["args"][-2:] == ["--transport", "stdio"]
        assert str(config.path) in entry["args"]
        assert "key" not in json.dumps(entry)
    original = (destination / ".mcp.json").read_bytes()
    with pytest.raises(V2Error, match="absent or empty"):
        cli.deployment_assets(config, destination)
    assert (destination / ".mcp.json").read_bytes() == original


def test_source_launcher_works_after_checkout_relocation(tmp_path):
    target = tmp_path / "relocated-code"
    shutil.copytree(cli.code_root() / "src", target / "src", ignore=shutil.ignore_patterns("__pycache__"))
    (target / "scripts").mkdir()
    shutil.copy2(cli.code_root() / "scripts/ha-v2", target / "scripts/ha-v2")
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    request = tmp_path / "request.json"
    request.write_text('{"subject_id":"subject_move","label":"Synthetic relocation"}')
    result = subprocess.run([sys.executable, "-I", "-B", str(target / "scripts/ha-v2"),
                            "--config", str(config.path), "call", "--zone", "private-data",
                            "--tool", "register_subject", "--arguments-file", str(request)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["subject_id"] == "subject_move"


def test_packaged_entry_works_without_checkout_scripts(tmp_path):
    library = tmp_path / "installed-library"
    shutil.copytree(cli.library_root() / "health_analyzer", library / "health_analyzer",
                    ignore=shutil.ignore_patterns("__pycache__"))
    entry = library / "health_analyzer/v2/entry.py"
    assert entry.is_file() and not (library / "scripts").exists()
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    request = tmp_path / "request.json"
    request.write_text('{"subject_id":"subject_installed","label":"Synthetic installed package"}')
    result = subprocess.run([sys.executable, "-I", "-B", str(entry),
                            "--config", str(config.path), "call", "--zone", "private-data",
                            "--tool", "register_subject", "--arguments-file", str(request)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["subject_id"] == "subject_installed"
    destination = tmp_path / "inactive-installed"
    result = subprocess.run([sys.executable, "-I", "-B", str(entry), "--config", str(config.path),
                             "deployment-assets", "--output-dir", str(destination)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    entries = json.loads((destination / ".mcp.json").read_text())["mcpServers"].values()
    assert all(str(entry) in item["args"] for item in entries)


def test_root_startup_permission_is_literal_not_recursive(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="macos_enforced")
    policy = cli.sandbox_policy(config, "private-data")
    assert '(allow file-read-data (literal "/"))' in policy
    assert '(subpath "/")' not in policy


def test_pdf_bridge_descriptors_are_only_passed_to_enforced_private(tmp_path, monkeypatch):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="macos_enforced")
    commands = []
    monkeypatch.setattr(cli, "_sandbox_prefix", lambda config, zone: [])
    def synthetic_process(command, **kwargs):
        commands.append((command, kwargs["pass_fds"]))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(cli.subprocess, "run", synthetic_process)
    assert cli.launch_runtime(config, "public-research", action="call", tool="plan_search", arguments={}) == 0
    assert cli.launch_runtime(config, "private-data", action="call", tool="query_history", arguments={}) == 0
    public, private = commands
    assert "--_pdf-request-fd" not in public[0] and len(public[1]) == 2
    assert "--_pdf-request-fd" in private[0] and "--_pdf-response-fd" in private[0] and len(private[1]) == 4


def test_public_runtime_rejects_pdf_bridge_before_opening_store(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    config_fd = cli._pipe(json.dumps(config.to_dict(domain="public-research")).encode())
    with pytest.raises(V2Error) as error:
        cli.runtime_main(["--_runtime-zone", "public-research", "--_config-fd", str(config_fd),
                          "--_key-fd", "99", "--_action", "call", "--_tool", "plan_search",
                          "--_pdf-request-fd", "100", "--_pdf-response-fd", "101"])
    assert error.value.code == "scope_violation"
