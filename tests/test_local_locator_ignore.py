"""Protect generated local plugin locators without hiding example files."""

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("git") is None, reason="git is unavailable")
def test_private_locators_are_ignored_at_every_depth(tmp_path):
    # An independent repository tests Git's actual ignore semantics without
    # reading or modifying any real user plugin, profile configuration or data.
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    shutil.copyfile(ROOT / ".gitignore", tmp_path / ".gitignore")
    candidates = [
        ".local-install.json",
        "packaged/.local-install.json",
        "packaged/plugins/example/.local-install.json",
        "packaged/plugins/example/.local-install.json.example",
        "packaged/plugins/example/local-install.json",
    ]
    result = subprocess.run(
        ["git", "-C", str(tmp_path), "check-ignore", "--no-index", "-z", "--stdin"],
        input="\0".join(candidates) + "\0", capture_output=True, text=True, check=True,
    )
    assert set(result.stdout.split("\0")) - {""} == set(candidates[:3])
