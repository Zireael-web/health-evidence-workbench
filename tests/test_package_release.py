from __future__ import annotations

import os
import subprocess
import tarfile
import tomllib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def test_sdist_uses_a_narrow_source_allowlist() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)
    assert config["tool"]["hatch"]["build"]["targets"]["sdist"]["include"] == [
        "/src/health_analyzer",
        "/README.md",
        "/pyproject.toml",
    ]


def test_sdist_contains_only_package_metadata_and_runtime_source(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(tmp_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    archives = list(tmp_path.glob("health_analyzer-*.tar.gz"))
    assert len(archives) == 1

    with tarfile.open(archives[0], mode="r:gz") as archive:
        relative_paths: set[PurePosixPath] = set()
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            assert not path.is_absolute()
            assert ".." not in path.parts
            assert len(path.parts) >= 2
            relative_paths.add(PurePosixPath(*path.parts[1:]))

    assert PurePosixPath("src/health_analyzer/__init__.py") in relative_paths
    assert (
        PurePosixPath(
            "src/health_analyzer/data/guidance-source-catalog.json"
        )
        in relative_paths
    )
    assert PurePosixPath("README.md") in relative_paths
    assert PurePosixPath("pyproject.toml") in relative_paths
    assert {path.parts[0] for path in relative_paths} <= {
        ".gitignore",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "src",
    }

    forbidden_roots = {
        ".agents",
        ".codex",
        "fixtures",
        "plugins",
        "policies",
        "schemas",
        "scripts",
        "state",
        "tests",
    }
    assert not {
        path
        for path in relative_paths
        if path.parts and path.parts[0] in forbidden_roots
    }


def test_installed_wheel_can_plan_guidance_from_packaged_catalog(
    tmp_path: Path,
) -> None:
    wheel_dir = tmp_path / "wheel"
    target = tmp_path / "site"
    result = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheel_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    wheels = list(wheel_dir.glob("health_analyzer-*.whl"))
    assert len(wheels) == 1

    installed = subprocess.run(
        ["uv", "pip", "install", "--target", str(target), str(wheels[0])],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert installed.returncode == 0, installed.stderr

    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(target)
    planned = subprocess.run(
        [
            "python3",
            "-m",
            "health_analyzer.cli",
            "guidance-plan",
            "What current cardiology guidance applies?",
            "--domain",
            "cardiology",
            "--risk-level",
            "information",
        ],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert planned.returncode == 0, planned.stderr
    assert '"source_id": "who"' in planned.stdout
