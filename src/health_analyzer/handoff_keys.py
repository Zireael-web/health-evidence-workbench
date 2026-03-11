"""Bootstrap and load HMAC keys kept outside mutable handoff databases."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import stat
from typing import Literal


PacketKind = Literal["case", "evidence"]


def handoff_key_path(state_root: str | Path, kind: PacketKind) -> Path:
    if kind not in {"case", "evidence"}:
        raise ValueError("handoff key kind must be case or evidence")
    return Path(state_root) / "handoff" / "keys" / f"{kind}-integrity-v1.bin"


def _validate_parent(parent: Path, *, create: bool) -> None:
    if parent.is_symlink():
        raise ValueError("handoff-key parent must not be a symbolic link")
    if create:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError("handoff-key parent must be a private directory")
    if create:
        parent.chmod(0o700)


def _read_key_descriptor(descriptor: int) -> bytes:
    state = os.fstat(descriptor)
    if not stat.S_ISREG(state.st_mode) or state.st_nlink != 1 or state.st_size != 32:
        raise ValueError("handoff key must be a singly linked 32-byte regular file")
    os.lseek(descriptor, 0, os.SEEK_SET)
    key = os.read(descriptor, 33)
    if len(key) != 32:
        raise ValueError("handoff key is incomplete")
    return key


def ensure_handoff_key(state_root: str | Path, kind: PacketKind) -> Path:
    """Create a private key before entering a zone sandbox, or validate it."""

    path = handoff_key_path(state_root, kind)
    _validate_parent(path.parent, create=True)
    if path.is_symlink():
        raise ValueError("handoff key must not be a symbolic link")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o400)
    except FileExistsError:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
        try:
            _read_key_descriptor(descriptor)
        finally:
            os.close(descriptor)
        return path
    try:
        key = secrets.token_bytes(32)
        written = os.write(descriptor, key)
        if written != len(key):
            raise OSError("handoff key write was incomplete")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        state = os.fstat(descriptor)
        if not stat.S_ISREG(state.st_mode) or state.st_nlink != 1:
            raise ValueError("handoff key must be a singly linked regular file")
    finally:
        os.close(descriptor)
    return path


def load_handoff_key(state_root: str | Path, kind: PacketKind) -> bytes:
    """Load an existing key without creating or modifying filesystem state."""

    path = handoff_key_path(state_root, kind)
    _validate_parent(path.parent, create=False)
    if path.is_symlink():
        raise ValueError("handoff key must not be a symbolic link")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        return _read_key_descriptor(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Bootstrap one Human Science handoff key")
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--kind", choices=("case", "evidence"), required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        load_handoff_key(args.state_root, args.kind)
    else:
        ensure_handoff_key(args.state_root, args.kind)


if __name__ == "__main__":
    main()
