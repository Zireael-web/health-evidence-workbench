import os
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "plugins/health-analyzer-v2"
LAUNCHER = PLUGIN / "scripts/launch.py"


def test_portable_launcher_has_no_live_default_and_rejects_unexpanded_config():
    env = {key: value for key, value in os.environ.items() if not key.startswith("HEALTH_ANALYZER_V2_")}
    result = subprocess.run([sys.executable, "-I", "-B", str(LAUNCHER)], env=env,
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 2 and "configuration_required" in result.stderr
    env.update(HEALTH_ANALYZER_V2_CODE_ROOT="${UNKNOWN_ROOT}", HEALTH_ANALYZER_V2_CONFIG="${UNKNOWN_CONFIG}")
    result = subprocess.run([sys.executable, "-I", "-B", str(LAUNCHER)], env=env,
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 2 and "configuration_required" in result.stderr


def test_launcher_pins_public_zone_and_forwards_only_explicit_configuration(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    configuration = tmp_path / "explicit-config.json"
    captured = []
    from health_analyzer.v2 import cli
    monkeypatch.setenv("HEALTH_ANALYZER_V2_CODE_ROOT", str(root))
    monkeypatch.setenv("HEALTH_ANALYZER_V2_CONFIG", str(configuration))
    monkeypatch.delenv("HEALTH_ANALYZER_V2_PYTHON", raising=False)
    monkeypatch.setattr(cli, "main", lambda arguments: captured.append(arguments) or 0)
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(LAUNCHER), run_name="__main__")
    assert error.value.code == 0
    assert captured == [["--config", str(configuration), "serve", "--zone", "public-research", "--transport", "stdio"]]


def test_launcher_rejects_relative_interpreter_override(tmp_path):
    env = {key: value for key, value in os.environ.items() if not key.startswith("HEALTH_ANALYZER_V2_")}
    env["HEALTH_ANALYZER_V2_PYTHON"] = "./python"
    result = subprocess.run([sys.executable, "-I", "-B", str(LAUNCHER)], env=env,
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 2 and "runtime_unavailable" in result.stderr
