"""Launch a local file helper using the installation's private locator.

The locator is deployment-local configuration, not proof that an executable or
checkout is trustworthy. No profile data is opened here; the target helper
validates it only after an explicit profile selection.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys

_SCHEMA = "health-analyzer.local-install/1"
_ALLOWED = {"health-document", "health-files", "health-duplicates"}
_MAX_LOCATOR_BYTES = 16 * 1024


class LocatorError(ValueError):
    pass


def _fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise LocatorError
        result[key] = value
    return result


def _path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise LocatorError
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or value.startswith("${"):
        raise LocatorError
    return path


def _read_locator(path: Path) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not all(hasattr(os, item) for item in ("O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY")):
        raise LocatorError
    parent_flags = flags | os.O_NOFOLLOW | os.O_DIRECTORY
    parent = os.open(path.parent, parent_flags)
    try:
        parent_before = os.fstat(parent)
        fd = os.open(path.name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_LOCATOR_BYTES
                    or before.st_nlink != 1 or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) & 0o077):
                raise LocatorError
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(_MAX_LOCATOR_BYTES + 1)
            after = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink,
                                     item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            if (len(raw) > _MAX_LOCATOR_BYTES or len(raw) != before.st_size
                    or identity(before) != identity(after) or identity(before) != identity(named)):
                raise LocatorError
            current_parent = os.open(path.parent, parent_flags)
            try:
                current_stat = os.fstat(current_parent)
                if (parent_before.st_dev, parent_before.st_ino) != (current_stat.st_dev, current_stat.st_ino):
                    raise LocatorError
            finally:
                os.close(current_parent)
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_fields)
    required = {"schema", "source_root", "python", "configuration"}
    if (not isinstance(value, dict) or value.keys() - (required | {"profiles_config"})
            or not required <= value.keys() or value["schema"] != _SCHEMA):
        raise LocatorError
    for key in required - {"schema"}:
        _path(value[key])
    if "profiles_config" in value:
        _path(value["profiles_config"])
    return value


def _has_option(arguments: list[str], option: str) -> bool:
    for argument in arguments:
        if argument == "--":
            break
        if argument == option or argument.startswith(option + "="):
            return True
    return False


def _reject_ambiguous_profile_options(arguments: list[str]) -> None:
    # argparse accepts abbreviated long options. An abbreviated explicit
    # --config must never be silently overridden by a generated default.
    protected = ("--config", "--profile", "--archive-root")
    for argument in arguments:
        if argument == "--":
            break
        name = argument.split("=", 1)[0]
        if name.startswith("--") and len(name) > 2 and any(
            option.startswith(name) and option != name for option in protected
        ):
            raise LocatorError


def main(command: str) -> None:
    try:
        if command not in _ALLOWED:
            raise LocatorError
        plugin_root = Path(__file__).resolve().parent.parent
        locator = _read_locator(plugin_root / ".local-install.json")
        python = _path(locator["python"])
        source_root = _path(locator["source_root"])
        entry = source_root / "scripts" / command
        if not python.is_file() or not os.access(python, os.X_OK) or not entry.is_file() or entry.is_symlink():
            raise LocatorError
        args = list(sys.argv[1:])
        _reject_ambiguous_profile_options(args)
        # The profile config remains unopened until the target helper validates
        # the explicit selection. Explicit config and root always take priority.
        if (_has_option(args, "--profile") and not _has_option(args, "--config")
                and not _has_option(args, "--archive-root")):
            selected = locator.get("profiles_config")
            if selected is None:
                raise LocatorError
            index = args.index("--") if "--" in args else len(args)
            args[index:index] = ["--config", str(_path(selected))]
        os.execv(str(python), [str(python), "-I", "-B", str(entry), *args])
    except (LocatorError, OSError, UnicodeError, ValueError, TypeError, AttributeError, NotImplementedError):
        # Paths, profile names, source content and traceback stay private.
        print(json.dumps({"error": "local_runtime_unavailable", "message": "The local installation or selected configuration is unavailable."}), file=sys.stderr)
        raise SystemExit(2)
