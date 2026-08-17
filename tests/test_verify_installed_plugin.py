from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-installed-plugin"


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    source = tmp_path / "source"
    cache_root = tmp_path / "cache"
    cached = cache_root / "personal" / "synthetic-plugin" / "1.2.3"
    for root in (source, cached):
        (root / ".codex-plugin").mkdir(parents=True)
        (root / ".codex-plugin" / "plugin.json").write_text(
            json.dumps({"name": "synthetic-plugin", "version": "1.2.3"})
        )
        (root / "asset.txt").write_text("same bytes")
    listing = tmp_path / "plugins.json"
    listing.write_text(
        json.dumps(
            {
                "installed": [
                    {
                        "pluginId": "synthetic-plugin@personal",
                        "version": "1.2.3",
                        "installed": True,
                        "enabled": True,
                    }
                ]
            }
        )
    )
    return source, cache_root, listing


def _run(source: Path, cache_root: Path, listing: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source",
            str(source),
            "--cache-root",
            str(cache_root),
            "--plugin-list-json",
            str(listing),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_installed_plugin_verifier_accepts_exact_selected_cache(tmp_path: Path) -> None:
    source, cache_root, listing = _fixture(tmp_path)
    generated = (
        cache_root
        / "personal"
        / "synthetic-plugin"
        / "1.2.3"
        / "__pycache__"
        / "generated.pyc"
    )
    generated.parent.mkdir()
    generated.write_bytes(b"runtime cache")

    completed = _run(source, cache_root, listing)

    assert completed.returncode == 0, completed.stderr
    assert "verified synthetic-plugin@personal 1.2.3" in completed.stdout


def test_installed_plugin_verifier_rejects_stale_or_changed_cache(tmp_path: Path) -> None:
    source, cache_root, listing = _fixture(tmp_path)
    cached_asset = (
        cache_root / "personal" / "synthetic-plugin" / "1.2.3" / "asset.txt"
    )
    cached_asset.write_text("changed")

    changed = _run(source, cache_root, listing)

    assert changed.returncode == 1
    assert "installed plugin bytes differ" in changed.stderr

    cached_asset.write_text("same bytes")
    payload = json.loads(listing.read_text())
    payload["installed"][0]["version"] = "1.2.2"
    listing.write_text(json.dumps(payload))
    stale = _run(source, cache_root, listing)

    assert stale.returncode == 1
    assert "selected plugin version is stale" in stale.stderr


def test_installed_plugin_verifier_rejects_symlink_even_with_ignored_suffix(
    tmp_path: Path,
) -> None:
    source, cache_root, listing = _fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    (source / "generated.pyc").symlink_to(outside)

    completed = _run(source, cache_root, listing)

    assert completed.returncode == 1
    assert "symbolic link" in completed.stderr
