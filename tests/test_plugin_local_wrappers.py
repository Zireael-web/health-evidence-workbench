"""Synthetic subprocess tests for installed-plugin file helper launchers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import subprocess
import sys
import termios
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "health-analyzer-v2"
COMMANDS = ("health-document", "health-files", "health-duplicates")


@pytest.fixture
def deployment(tmp_path):
    base = tmp_path.resolve() / "synthetic cache"
    plugin = base / "plugin"
    shutil.copytree(PLUGIN / "scripts", plugin / "scripts")
    checkout = base / "synthetic checkout"
    (checkout / "scripts").mkdir(parents=True)
    code = (
        "import json,os,sys\n"
        "data='' if '--text-tty' in sys.argv else sys.stdin.read()\n"
        "print(json.dumps({'args':sys.argv[1:],'isatty':os.isatty(0),'stdin':data}))\n"
    )
    for name in COMMANDS:
        (checkout / "scripts" / name).write_text(code, encoding="utf-8")
    locator = {"schema": "health-analyzer.local-install/1", "source_root": str(checkout),
               "python": sys.executable, "configuration": str(base / "public.json"),
               "profiles_config": str(base / "private-profile-config.json")}
    path = plugin / ".local-install.json"
    path.write_text(json.dumps(locator), encoding="utf-8")
    path.chmod(0o600)
    return plugin, locator


def invoke(plugin, command, *arguments, input_text=""):
    return subprocess.run([sys.executable, "-I", "-B", str(plugin / "scripts" / command), *arguments],
                          input=input_text, capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize("command", COMMANDS)
def test_explicit_profile_adds_only_local_config_and_preserves_stdin(deployment, command):
    plugin, locator = deployment
    args = ["--profile", "person_alpha", "--arbitrary", "synthetic"]
    result = invoke(plugin, command, *args, input_text="synthetic query\n")
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["args"] == [*args, "--config", locator["profiles_config"]]
    assert observed["stdin"] == "synthetic query\n"
    # Config is intentionally absent: wrappers pass its name, never open it.
    assert not Path(locator["profiles_config"]).exists()


@pytest.mark.parametrize("explicit", ["--config", "--config=/different/config", "--archive-root"])
def test_explicit_configuration_is_never_replaced(deployment, explicit):
    plugin, _ = deployment
    args = ["copy", "--profile", "person_alpha", explicit]
    if "=" not in explicit:
        args.append("/different/synthetic")
    result = invoke(plugin, "health-document", *args)
    assert result.returncode == 0
    assert json.loads(result.stdout)["args"] == args


@pytest.mark.parametrize("name", ["--conf", "--conf=/sensitive", "--prof", "--archive-r"])
def test_abbreviated_identity_options_fail_closed_without_echoing_arguments(deployment, name):
    plugin, _ = deployment
    result = invoke(plugin, "health-document", "copy", name, "private-sentinel", "--profile", "person_alpha")
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "local_runtime_unavailable"
    assert "private-sentinel" not in result.stderr


def test_profile_option_after_end_of_options_does_not_enable_default(deployment):
    plugin, _ = deployment
    result = invoke(plugin, "health-files", "--", "--profile", "sentinel")
    assert result.returncode == 0
    assert json.loads(result.stdout)["args"] == ["--", "--profile", "sentinel"]


def test_generated_config_is_inserted_before_end_of_options(deployment):
    plugin, locator = deployment
    result = invoke(plugin, "health-files", "--profile", "person_alpha", "--", "sentinel")
    assert result.returncode == 0
    assert json.loads(result.stdout)["args"] == ["--profile", "person_alpha", "--config", locator["profiles_config"], "--", "sentinel"]


def test_help_and_missing_profile_do_not_read_default_config(deployment):
    plugin, _ = deployment
    assert json.loads(invoke(plugin, "health-document", "--help").stdout)["args"] == ["--help"]
    assert json.loads(invoke(plugin, "health-files").stdout)["args"] == []


def test_tty_and_text_tty_arguments_survive_exec(deployment):
    plugin, locator = deployment
    master, slave = pty.openpty()
    try:
        result = subprocess.run([sys.executable, "-I", "-B", str(plugin / "scripts" / "health-document"),
                                 "save-text", "--profile", "person_alpha", "--text-tty"],
                                stdin=slave, capture_output=True, text=True, timeout=15)
    finally:
        os.close(slave)
        os.close(master)
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed["isatty"] is True
    assert observed["args"] == ["save-text", "--profile", "person_alpha", "--text-tty",
                                 "--config", locator["profiles_config"]]


@pytest.mark.parametrize("mutation", ["missing", "schema", "duplicate", "wide_mode", "symlink", "relative", "extra"])
def test_invalid_locator_fails_with_neutral_error(deployment, mutation):
    plugin, locator = deployment
    path = plugin / ".local-install.json"
    if mutation == "missing":
        path.unlink()
    elif mutation == "schema":
        locator["schema"] = "bad-private-sentinel"
        path.write_text(json.dumps(locator))
    elif mutation == "duplicate":
        path.write_text('{"schema":"a","schema":"bad-private-sentinel"}')
    elif mutation == "wide_mode":
        path.chmod(0o644)
    elif mutation == "symlink":
        path.unlink()
        path.symlink_to("/private/nonexistent-private-sentinel")
    elif mutation == "relative":
        locator["source_root"] = "relative-private-sentinel"
        path.write_text(json.dumps(locator))
    else:
        locator["unexpected"] = "private-sentinel"
        path.write_text(json.dumps(locator))
    result = invoke(plugin, "health-files", "--profile", "private-sentinel")
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "local_runtime_unavailable"
    assert "private-sentinel" not in result.stderr


def test_real_target_rejects_absent_default_config_without_echoing_path(deployment):
    plugin, locator = deployment
    locator["source_root"] = str(ROOT)
    path = plugin / ".local-install.json"
    path.write_text(json.dumps(locator))
    result = invoke(plugin, "health-duplicates", "--profile", "person_alpha", "--source", "/no-such-source")
    assert result.returncode != 0
    assert locator["profiles_config"] not in result.stderr
    assert "/no-such-source" not in result.stderr


def _pty_line(fd):
    line = bytearray()
    deadline = time.monotonic() + 10
    while not line.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([fd], [], [], remaining)[0]
        line.extend(os.read(fd, 1))
    return bytes(line).replace(b"\r\n", b"\n")


def test_real_document_tty_handshake_preserves_terminal_and_saves_transcript(deployment, tmp_path):
    plugin, locator = deployment
    archive = tmp_path.resolve() / "fictional-profile"
    archive.mkdir()
    original = archive / "fictional.bin"
    original.write_bytes(b"fictional document")
    profiles = Path(locator["profiles_config"])
    profiles.write_text(json.dumps({"profiles": [
        {"id": "person_alpha", "label": "Sample person", "root": str(archive)}
    ]}))
    profiles.chmod(0o600)
    locator["source_root"] = str(ROOT)
    (plugin / ".local-install.json").write_text(json.dumps(locator))
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    process = subprocess.Popen([sys.executable, "-I", "-B", str(plugin / "scripts" / "health-document"),
                                "save-text", "--profile", "person_alpha", "--text-tty",
                                "--document", str(original), "--expected-sha256",
                                hashlib.sha256(original.read_bytes()).hexdigest()],
                               stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    try:
        assert _pty_line(master) == b"READY\n"
        assert not (termios.tcgetattr(slave)[3] & termios.ECHO)
        transcript = "Synthetic text with Unicode: пример\n".encode()
        os.write(master, transcript + b"\x04")
        confirm = _pty_line(master)
        assert re.fullmatch(rb"CONFIRM:[0-9a-f]{32}\n", confirm)
        os.write(master, confirm)
        output = _pty_line(master)
        assert json.loads(output)["status"] == "copied"
        assert transcript not in confirm + output
        assert process.wait(timeout=5) == 0
        assert (archive / "fictional.bin.txt").read_bytes() == transcript
        assert termios.tcgetattr(slave) == before
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
        os.close(slave)
