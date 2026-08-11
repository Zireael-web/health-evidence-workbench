from __future__ import annotations

import hashlib
import json
import os
import runpy
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "scripts" / "update-runtime-manifest"
OLD_PIN = "1" * 64


def test_runtime_file_modes_survive_git_checkout_without_unsafe_write_bits() -> None:
    executables = [
        ROOT / "scripts" / "run-audit-mcp",
        ROOT / "scripts" / "run-private-mcp",
        ROOT / "scripts" / "run-public-mcp",
        ROOT / "scripts" / "run-synthesis-mcp",
        UPDATER,
        ROOT / "scripts" / "verify-runtime-integrity",
    ]
    for path in executables:
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode & stat.S_IXUSR, path
        assert mode & 0o022 == 0, path

    for path in sorted((ROOT / "policies").glob("*.sb")):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode & 0o111 == 0, path
        assert mode & 0o022 == 0, path


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _synthetic_project(root: Path) -> None:
    declaration = {
        "schema_version": 1,
        "tree_roots": ["policies", "schemas", "scripts", "src"],
        "root_files": ["pyproject.toml", "uv.lock"],
        "excludes": ["policies/runtime-manifest.json"],
        "prune_directories": ["__pycache__"],
    }
    _write(
        root / "policies/runtime-inventory.json",
        json.dumps(declaration, indent=2) + "\n",
    )
    _write(root / "policies/runtime-manifest.json", "{}\n")
    _write(root / "schemas/packet.schema.json", "{}\n")
    _write(root / "scripts/runtime-tool", "#!/bin/sh\nexit 0\n")
    _write(root / "src/sitecustomize.pyc", "synthetic sourceless startup\n")
    _write(
        root / "src/__pycache__/ignored.pyc",
        "generated cache is outside the declared inventory\n",
    )
    _write(
        root / "pyproject.toml",
        """[project]
name = "health-analyzer"
version = "9.8.7"
""",
    )
    _write(
        root / "uv.lock",
        """version = 1

[[package]]
name = "health-analyzer"
version = "9.8.7"

[[package]]
name = "mcp"
version = "2.0.0"

[[package]]
name = "pypdf"
version = "6.15.0"
""",
    )
    _write(
        root / "plugins/human-science-workbench/.mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "health-analyzer": {
                        "args": [
                            "zsh",
                            "${HEALTH_ANALYZER_PROJECT_ROOT}/scripts/run-public-mcp",
                            "--expected-runtime-manifest-sha256",
                            OLD_PIN,
                        ]
                    }
                }
            },
            indent=2,
        )
        + "\n",
    )
    _write(
        root / "README.md",
        "scripts/run-public-mcp --expected-runtime-manifest-sha256 \\\n"
        f"  {OLD_PIN}\n",
    )


def _run(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(UPDATER),
            "--project-root",
            str(root),
            *arguments,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def _updater_namespace() -> dict[str, object]:
    return runpy.run_path(str(UPDATER), run_name="runtime_manifest_update_test")


def _manifest_hash(root: Path) -> str:
    return hashlib.sha256(
        (root / "policies/runtime-manifest.json").read_bytes()
    ).hexdigest()


def _assert_all_pins(root: Path, expected: str) -> None:
    plugin = json.loads(
        (root / "plugins/human-science-workbench/.mcp.json").read_text(
            encoding="utf-8"
        )
    )
    assert plugin["mcpServers"]["health-analyzer"]["args"] == [
        "zsh",
        "${HEALTH_ANALYZER_PROJECT_ROOT}/scripts/run-public-mcp",
        "--expected-runtime-manifest-sha256",
        expected,
    ]
    assert (root / "README.md").read_text(encoding="utf-8").endswith(
        f"  {expected}\n"
    )


def test_updater_is_deterministic_and_updates_every_pin_consumer(
    tmp_path: Path,
) -> None:
    _synthetic_project(tmp_path)

    stale = _run(tmp_path, "--check")
    assert stale.returncode == 1
    assert "policies/runtime-manifest.json" in stale.stderr
    assert "plugins/human-science-workbench/.mcp.json" in stale.stderr

    applied = _run(tmp_path)
    assert applied.returncode == 0, applied.stderr
    first_manifest = (tmp_path / "policies/runtime-manifest.json").read_bytes()
    first_hash = _manifest_hash(tmp_path)
    _assert_all_pins(tmp_path, first_hash)

    manifest = json.loads(first_manifest)
    paths = [entry["path"] for entry in manifest["files"]]
    assert paths == sorted(paths)
    assert "policies/runtime-inventory.json" in paths
    assert "scripts/runtime-tool" in paths
    assert "src/sitecustomize.pyc" in paths
    assert "src/__pycache__/ignored.pyc" not in paths
    assert "policies/runtime-manifest.json" not in paths
    assert manifest["required_distributions"] == {
        "health-analyzer": "9.8.7",
        "mcp": "2.0.0",
        "pypdf": "6.15.0",
    }

    current = _run(tmp_path, "--check")
    assert current.returncode == 0, current.stderr
    no_op = _run(tmp_path)
    assert no_op.returncode == 0, no_op.stderr
    assert (tmp_path / "policies/runtime-manifest.json").read_bytes() == first_manifest

    _write(tmp_path / "scripts/runtime-tool", "#!/bin/sh\nexit 7\n")
    changed = _run(tmp_path, "--check")
    assert changed.returncode == 1
    assert "policies/runtime-manifest.json" in changed.stderr

    reapplied = _run(tmp_path)
    assert reapplied.returncode == 0, reapplied.stderr
    second_hash = _manifest_hash(tmp_path)
    assert second_hash != first_hash
    _assert_all_pins(tmp_path, second_hash)
    assert _run(tmp_path, "--check").returncode == 0


def test_updater_rejects_a_noncanonical_inventory_declaration(
    tmp_path: Path,
) -> None:
    _synthetic_project(tmp_path)
    declaration_path = tmp_path / "policies/runtime-inventory.json"
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["excludes"].append("scripts/unreviewed")
    declaration_path.write_text(
        json.dumps(declaration, indent=2) + "\n",
        encoding="utf-8",
    )

    rejected = _run(tmp_path)
    assert rejected.returncode == 2
    assert "excludes do not match the canonical runtime inventory" in rejected.stderr
    assert (tmp_path / "policies/runtime-manifest.json").read_text(
        encoding="utf-8"
    ) == "{}\n"


def test_updater_and_verifier_reject_narrowed_runtime_roots(
    tmp_path: Path,
) -> None:
    _synthetic_project(tmp_path)
    declaration_path = tmp_path / "policies/runtime-inventory.json"
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["tree_roots"].remove("src")
    declaration_path.write_text(
        json.dumps(declaration, indent=2) + "\n",
        encoding="utf-8",
    )

    rejected = _run(tmp_path)
    assert rejected.returncode == 2
    assert "tree_roots do not match the canonical runtime inventory" in rejected.stderr

    verifier = runpy.run_path(
        str(ROOT / "scripts/verify-runtime-integrity"),
        run_name="runtime_integrity_declaration_test",
    )
    load_declaration = verifier["_load_inventory_declaration"]
    load_declaration.__globals__["PROJECT_ROOT"] = tmp_path
    load_declaration.__globals__["MANIFEST_PATH"] = (
        tmp_path / "policies/runtime-manifest.json"
    )
    load_declaration.__globals__["INVENTORY_PATH"] = declaration_path
    with pytest.raises(
        verifier["IntegrityError"],
        match="tree_roots do not match the canonical runtime inventory",
    ):
        load_declaration()


def test_atomic_apply_aborts_without_overwriting_a_concurrent_edit(
    tmp_path: Path,
) -> None:
    _synthetic_project(tmp_path)
    updater = _updater_namespace()
    desired, expected_current = updater["_desired_files"](tmp_path)
    victim = tmp_path / "plugins/human-science-workbench/.mcp.json"
    victim.write_text(
        victim.read_text(encoding="utf-8") + "# concurrent edit must survive\n",
        encoding="utf-8",
    )

    with pytest.raises(updater["UpdateError"], match="concurrent drift detected"):
        updater["_atomic_write_batch"](desired, expected_current)

    assert victim.read_text(encoding="utf-8").endswith(
        "# concurrent edit must survive\n"
    )
    assert not list(tmp_path.rglob(".*.tmp"))


def test_replace_failure_restores_every_target_and_removes_staged_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _synthetic_project(tmp_path)
    updater = _updater_namespace()
    desired, expected_current = updater["_desired_files"](tmp_path)
    originals = {target: target.read_bytes() for target in desired}
    manifest = tmp_path / "policies/runtime-manifest.json"
    real_replace = os.replace
    injected = False

    def fail_once(source: str | Path, destination: str | Path) -> None:
        nonlocal injected
        if Path(destination) == manifest and not injected:
            injected = True
            raise OSError("injected replacement failure")
        real_replace(source, destination)

    monkeypatch.setattr(updater["os"], "replace", fail_once)
    with pytest.raises(updater["UpdateError"], match="prior files restored"):
        updater["_atomic_write_batch"](desired, expected_current)

    assert injected is True
    assert all(target.read_bytes() == original for target, original in originals.items())
    assert not list(tmp_path.rglob(".*.tmp"))


def test_post_replace_interrupt_is_rolled_back_without_orphans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _synthetic_project(tmp_path)
    updater = _updater_namespace()
    desired, expected_current = updater["_desired_files"](tmp_path)
    originals = {target: target.read_bytes() for target in desired}
    real_replace = os.replace
    injected = False

    def interrupt_once(source: str | Path, destination: str | Path) -> None:
        nonlocal injected
        real_replace(source, destination)
        if not injected:
            injected = True
            raise KeyboardInterrupt("injected after successful replacement")

    monkeypatch.setattr(updater["os"], "replace", interrupt_once)
    with pytest.raises(updater["UpdateError"], match="prior files restored"):
        updater["_atomic_write_batch"](desired, expected_current)

    assert injected is True
    assert all(target.read_bytes() == original for target, original in originals.items())
    assert not list(tmp_path.rglob(".*.tmp"))


def test_updater_rejects_symlinked_pin_consumer_without_following_it(
    tmp_path: Path,
) -> None:
    _synthetic_project(tmp_path)
    victim = tmp_path / "README.md"
    outside = tmp_path.parent / f"{tmp_path.name}-outside-readme"
    outside.write_text("outside must not be read or changed\n", encoding="utf-8")
    victim.unlink()
    victim.symlink_to(outside)
    try:
        rejected = _run(tmp_path)
        assert rejected.returncode == 2
        assert "README.md is unavailable" in rejected.stderr
        assert outside.read_text(encoding="utf-8") == (
            "outside must not be read or changed\n"
        )
    finally:
        outside.unlink(missing_ok=True)
