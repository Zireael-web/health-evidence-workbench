from pathlib import Path
import json
import os
import stat
import subprocess
import sys

import pytest

from health_analyzer.v2.common import V2Error
from health_analyzer.v2 import configuration
from health_analyzer.v2.configuration import (DOMAINS, MARKER, initialize, load_config,
                                             open_domain_key, read_key_fd)


def test_init_new_namespace_and_domain_keys_only(tmp_path):
    legacy = tmp_path / "legacy.sqlite3"
    legacy.write_bytes(b"do not inspect or overwrite")
    config = initialize(tmp_path / "config.json", tmp_path / "new-v2", isolation="host")
    assert load_config(config.path).deployment_id == config.deployment_id
    assert legacy.read_bytes() == b"do not inspect or overwrite"
    assert json.loads((config.data_root / MARKER).read_text())["deployment_id"] == config.deployment_id
    keys = [read_key_fd(open_domain_key(config, zone)) for zone in DOMAINS]
    assert all(len(key) == 32 for key in keys) and keys[0] != keys[1]
    for zone in DOMAINS:
        assert config.store_path(zone).is_file()
        assert stat.S_IMODE(config.key_path(zone).stat().st_mode) == 0o600


def test_existing_root_is_rejected_without_modification(tmp_path):
    root = tmp_path / "existing"
    root.mkdir()
    old = root / "old.sqlite3"
    old.write_bytes(b"legacy")
    with pytest.raises(V2Error, match="absent or empty"):
        initialize(tmp_path / "config.json", root, isolation="host")
    assert old.read_bytes() == b"legacy"
    assert not (tmp_path / "config.json").exists()


def test_relative_paths_and_public_configuration_have_no_archive_bindings(tmp_path):
    archive = tmp_path / "approved-demo"
    archive.mkdir()
    config = initialize(tmp_path / "config.json", "new-v2", isolation="host",
                        archive_roots={"demo": {"path": "approved-demo", "subject_id": "subject_demo"}})
    assert config.archive_roots["demo"]["path"] == archive
    assert config.to_dict(domain="public-research")["archive_roots"] == {}
    assert config.to_dict(domain="private-data")["archive_roots"]["demo"]["path"] == str(archive)


def test_archive_state_overlap_and_symlink_roots_rejected(tmp_path):
    archive = tmp_path / "archive"
    archive.mkdir()
    with pytest.raises(V2Error, match="must not overlap"):
        initialize(tmp_path / "config.json", archive / "state", isolation="host",
                   archive_roots={"demo": {"path": str(archive), "subject_id": "subject_demo"}})
    link = tmp_path / "linked"
    link.symlink_to(archive, target_is_directory=True)
    with pytest.raises(V2Error, match="symlinks"):
        initialize(tmp_path / "config.json", link / "state", isolation="host")


def test_configuration_cannot_be_created_inside_archive(tmp_path):
    archive = tmp_path / "synthetic-archive"
    archive.mkdir()
    (archive / "original-report.txt").write_bytes(b"Synthetic immutable report bytes")
    before = {p.name: p.read_bytes() for p in archive.iterdir()}
    with pytest.raises(V2Error, match="inside an archive"):
        initialize(archive / "config.json", tmp_path / "v2", isolation="host",
                   archive_roots={"demo": {"path": str(archive), "subject_id": "subject_demo"}})
    assert not (archive / "config.json").exists()
    assert not (tmp_path / "v2").exists()
    assert {p.name: p.read_bytes() for p in archive.iterdir()} == before


def test_unknown_config_and_wrong_marker_rejected(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    value = json.loads(config.path.read_text())
    value["legacy_state"] = "/forbidden"
    config.path.write_text(json.dumps(value))
    with pytest.raises(V2Error, match="fields"):
        load_config(config.path)
    value.pop("legacy_state")
    config.path.write_text(json.dumps(value))
    (config.data_root / MARKER).write_text('{"schema_version":"legacy"}')
    with pytest.raises(V2Error, match="marker differ"):
        load_config(config.path)


def test_key_fd_closes_and_key_permissions_fail_closed(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    fd = open_domain_key(config, "private-data")
    assert len(read_key_fd(fd)) == 32
    with pytest.raises(OSError):
        os.fstat(fd)
    os.chmod(config.key_path("private-data"), 0o644)
    with pytest.raises(V2Error, match="owner-only"):
        open_domain_key(config, "private-data")


def test_configuration_fifo_rejected_without_waiting_for_writer(tmp_path):
    from health_analyzer.v2.cli import code_root
    fifo = tmp_path / "config-fifo"
    os.mkfifo(fifo, 0o600)
    script = """import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from health_analyzer.v2.configuration import _read_regular
from health_analyzer.v2.common import V2Error
try:
 _read_regular(Path(sys.argv[2]),limit=4096)
except V2Error as exc:
 print(exc.code)
else:
 raise SystemExit(3)
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script,
                             str(code_root() / "src"), str(fifo)],
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "configuration_invalid"


def test_domain_key_fifo_rejected_without_waiting_for_writer(tmp_path):
    from health_analyzer.v2.cli import code_root
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    config.key_path("private-data").unlink()
    os.mkfifo(config.key_path("private-data"), 0o600)
    script = """import sys
sys.path.insert(0,sys.argv[1])
from health_analyzer.v2.configuration import load_config,open_domain_key
from health_analyzer.v2.common import V2Error
try:
 open_domain_key(load_config(sys.argv[2]),'private-data')
except V2Error as exc:
 print(exc.code)
else:
 raise SystemExit(3)
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script,
                             str(code_root() / "src"), str(config.path)],
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "key_invalid"


@pytest.mark.parametrize("target", ["data", "archive", "configuration"])
def test_private_paths_cannot_overlap_shared_runtime_roots(tmp_path, monkeypatch, target):
    shared = tmp_path / "synthetic-shared-runtime"
    shared.mkdir()
    (shared / "synthetic-library.py").write_bytes(b"# synthetic library bytes")
    monkeypatch.setattr(configuration, "protected_runtime_roots", lambda: (shared,))
    config_path = tmp_path / "config.json"
    data_root = tmp_path / "new-v2"
    roots = {}
    if target == "data":
        data_root = shared / "new-data"
    elif target == "archive":
        archive = shared / "archive"
        archive.mkdir()
        (archive / "original.txt").write_bytes(b"synthetic immutable source")
        roots = {"demo": {"path": str(archive), "subject_id": "subject_demo"}}
    else:
        config_path = shared / "config.json"
    before = {str(p.relative_to(shared)): p.read_bytes() for p in shared.rglob("*") if p.is_file()}
    with pytest.raises(V2Error) as error:
        initialize(config_path, data_root, isolation="host", archive_roots=roots)
    assert error.value.code == "configuration_invalid"
    assert not config_path.exists() and not data_root.exists()
    assert {str(p.relative_to(shared)): p.read_bytes() for p in shared.rglob("*") if p.is_file()} == before
