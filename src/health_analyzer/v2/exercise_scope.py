"""Owned synthetic exercises only; not authorization for real migration.

No runtime/MCP/CLI exposes these helpers. A marker prevents accidental use of
ordinary deployment paths; it cannot prove that caller-supplied data is fictitious
or defend against a malicious process with the same OS identity.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from .common import V2Error, canonical, new_id, require, utc_now

MARKER_NAME = ".ha-synthetic-exercise.json"
MARKER_SCHEMA = "health-analyzer.synthetic-exercise/1"


def create_synthetic_exercise(root: str | Path) -> dict:
    path = Path(root).absolute()
    require(".." not in path.parts and not path.is_symlink() and
            not any(p.is_symlink() for p in path.parents),
            "SYNTHETIC_SCOPE_PATH", "Exercise paths must not traverse symlinks or parent escapes")
    require(path.parent.is_dir(), "SYNTHETIC_SCOPE_PATH", "Exercise parent must exist")
    require(not path.exists(), "SYNTHETIC_SCOPE_EXISTS", "Exercise root must be new; no real deployment is adopted")
    path.mkdir(mode=0o700)
    marker = {"schema_version": MARKER_SCHEMA, "exercise_id": new_id("synthetic_exercise"),
              "root": str(path), "scope": "synthetic_only", "created_at": utc_now()}
    target = path / MARKER_NAME
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream:
            stream.write(canonical(marker));stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    return marker


def verify_synthetic_exercise(root: str | Path) -> dict:
    path = Path(root).absolute()
    require(".." not in path.parts and not path.is_symlink() and
            not any(p.is_symlink() for p in path.parents),
            "SYNTHETIC_SCOPE_PATH", "Exercise paths must not traverse symlinks or parent escapes")
    require(path.is_dir(), "SYNTHETIC_SCOPE_REQUIRED", "An owned synthetic exercise is required")
    info = path.stat()
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "SYNTHETIC_SCOPE_REQUIRED", "Exercise root must be private and owned")
    target = path / MARKER_NAME
    try:
        fd = os.open(target, os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_NONBLOCK",0))
        try:
            meta = os.fstat(fd)
            require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid() and
                    stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1 and meta.st_size <= 4096,
                    "SYNTHETIC_SCOPE_REQUIRED", "Exercise marker must be an owned private regular file")
            raw=os.read(fd,4097)
        finally:os.close(fd)
        data=json.loads(raw)
    except (OSError,ValueError,UnicodeError) as exc:
        raise V2Error("SYNTHETIC_SCOPE_REQUIRED","Valid synthetic exercise marker unavailable") from exc
    require(isinstance(data,dict) and set(data)=={"schema_version","exercise_id","root","scope","created_at"}
            and data["schema_version"]==MARKER_SCHEMA and data["scope"]=="synthetic_only"
            and data["root"]==str(path) and isinstance(data["exercise_id"],str)
            and data["exercise_id"].startswith("synthetic_exercise_"),
            "SYNTHETIC_SCOPE_REQUIRED","Marker does not bind this owned synthetic exercise")
    return data


def require_owned_synthetic_path(root: str | Path, path: str | Path, *, must_exist: bool = False) -> Path:
    """Validate scope before any source DB/payload opening; no directory creation."""
    verify_synthetic_exercise(root)
    base=Path(root).absolute();candidate=Path(path)
    if not candidate.is_absolute():candidate=base/candidate
    require(".." not in candidate.parts and candidate != base and candidate.is_relative_to(base),
            "SYNTHETIC_SCOPE_PATH","Source and destination must be inside the owned exercise")
    for part in [candidate,*candidate.parents]:
        if part==base:break
        require(not part.is_symlink(),"SYNTHETIC_SCOPE_PATH","Synthetic paths cannot follow symlinks")
    require(not must_exist or candidate.exists(),"SYNTHETIC_SCOPE_PATH","Synthetic input is missing")
    if candidate.exists() and candidate.is_file():
        info=candidate.stat()
        require(info.st_uid==os.geteuid() and info.st_nlink==1,
                "SYNTHETIC_SCOPE_PATH","Synthetic input cannot adopt an external hard link or owner")
    return candidate
