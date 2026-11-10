"""Explicit deployment configuration for the parallel v2 stores.

This module never inspects or migrates a legacy deployment. Bootstrap is the
only reader of key files; a runtime receives one domain key through an FD.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import SignedStore, V2Error, require

SCHEMA = "health-analyzer.deployment/2.0"
DOMAINS = ("private-data", "public-research")
MODES = ("host", "macos_enforced")
MARKER = ".health-analyzer-v2.json"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_CONFIG_FIELDS = {"schema_version", "deployment_id", "data_root", "isolation", "archive_roots"}
_OPTIONAL_CONFIG_FIELDS = {"research_provider"}


def _absolute(value: str | Path, base: Path) -> Path:
    require(isinstance(value, (str, Path)) and bool(str(value)), "configuration_invalid", "A nonempty path is required")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    # Existing symlink traversal is rejected rather than silently broadening a
    # read/write root. Normalize .. only after checking all existing ancestors.
    current = path
    while current != current.parent:
        require(not current.is_symlink(), "symlink_forbidden", "Configured paths cannot traverse symlinks")
        current = current.parent
    return path.resolve(strict=False)


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def protected_runtime_roots() -> tuple[Path, ...]:
    """Content roots allowed to both runtimes/the PDF worker, never data roots.

    Shared code/interpreter grants must not accidentally include an archive,
    domain key or v2 database. Keep the system roots in sync with the packaged
    PDF/runtime policies. This returns paths only, not directory inventories.
    """
    return tuple({Path(__file__).resolve().parents[2], Path(sys.prefix).resolve(),
                  Path(sys.base_prefix).resolve(), Path("/System/Library"),
                  Path("/usr/lib"), Path("/Library/Apple/System/Library"),
                  Path("/private/etc"), Path("/private/var/db")})


@dataclass(frozen=True)
class DeploymentConfig:
    path: Path
    deployment_id: str
    data_root: Path
    isolation: str
    archive_roots: dict[str, dict[str, Any]]
    research_provider: dict[str, str] | None = None

    def zone_root(self, domain: str) -> Path:
        require(domain in DOMAINS, "zone_invalid", "Unknown v2 runtime zone")
        return self.data_root / ("private" if domain == "private-data" else "public")

    def store_path(self, domain: str) -> Path:
        return self.zone_root(domain) / ("private.sqlite3" if domain == "private-data" else "public.sqlite3")

    def temp_root(self, domain: str) -> Path:
        return self.zone_root(domain) / "tmp"

    def key_path(self, domain: str) -> Path:
        require(domain in DOMAINS, "zone_invalid", "Unknown v2 runtime zone")
        return self.data_root / "keys" / f"{domain}.key"

    def to_dict(self, *, domain: str | None = None) -> dict[str, Any]:
        require(domain is None or domain in DOMAINS, "zone_invalid", "Unknown v2 runtime zone")
        roots = {} if domain == "public-research" else {
            key: {"path": str(item["path"]), "subject_id": item["subject_id"]}
            for key, item in self.archive_roots.items()
        }
        value = {"schema_version": SCHEMA, "deployment_id": self.deployment_id,
                "data_root": str(self.data_root), "isolation": self.isolation,
                "archive_roots": roots}
        if self.research_provider is not None:
            value["research_provider"] = dict(self.research_provider)
        return value


def config_from_dict(value: dict[str, Any], *, path: Path) -> DeploymentConfig:
    require(isinstance(value, dict) and _CONFIG_FIELDS <= set(value)
            and set(value) <= _CONFIG_FIELDS | _OPTIONAL_CONFIG_FIELDS,
            "configuration_invalid", "Configuration fields must match the v2 schema")
    provider = value.get("research_provider")
    require(provider is None or (isinstance(provider, dict)
            and provider == {"name": "pubmed"}), "configuration_invalid",
            "Only the explicit public PubMed provider is supported")
    require(value["schema_version"] == SCHEMA, "configuration_invalid", "Not a v2 deployment configuration")
    require(isinstance(value["deployment_id"], str) and bool(_ID.fullmatch(value["deployment_id"])),
            "configuration_invalid", "Invalid deployment ID")
    require(value["isolation"] in MODES, "configuration_invalid", "Select host or macos_enforced explicitly")
    root = _absolute(value["data_root"], path.parent)
    protected = protected_runtime_roots()
    require(not any(_overlaps(root, shared) for shared in protected),
            "configuration_invalid", "Data root cannot overlap shared code, interpreter or system runtime roots")
    require(not any(path == shared or shared in path.parents for shared in protected),
            "configuration_invalid", "Configuration cannot reside in shared runtime code or libraries")
    roots = value["archive_roots"]
    require(isinstance(roots, dict) and len(roots) <= 100, "configuration_invalid", "Archive bindings must be a bounded object")
    bindings: dict[str, dict[str, Any]] = {}
    for root_id, binding in roots.items():
        require(isinstance(root_id, str) and bool(_ID.fullmatch(root_id)) and
                isinstance(binding, dict) and set(binding) == {"path", "subject_id"},
                "configuration_invalid", "Each archive binding requires root ID, path and subject ID")
        subject = binding["subject_id"]
        require(isinstance(subject, str) and bool(_ID.fullmatch(subject)), "configuration_invalid", "Invalid subject ID")
        archive = _absolute(binding["path"], path.parent)
        require(not any(_overlaps(archive, shared) for shared in protected),
                "configuration_invalid", "Archive roots cannot overlap shared code, interpreter or system runtime roots")
        require(path != archive and archive not in path.parents,
                "configuration_invalid", "Configuration cannot be written inside an archive root")
        require(not _overlaps(root, archive), "configuration_invalid", "Data and archive roots must not overlap")
        require(archive.is_dir(), "archive_unavailable", "A configured archive root is not a directory")
        require(not any(_overlaps(archive, other["path"]) for other in bindings.values()),
                "configuration_invalid", "Archive roots must not overlap")
        bindings[root_id] = {"path": archive, "subject_id": subject}
    return DeploymentConfig(path=path, deployment_id=value["deployment_id"], data_root=root,
                            isolation=value["isolation"], archive_roots=bindings,
                            research_provider=dict(provider) if provider else None)


def _read_regular(path: Path, *, limit: int) -> bytes:
    # Reject FIFOs/devices after fstat without blocking inside open first.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= limit,
                    "configuration_invalid", "Configuration input must be a bounded regular file")
            data = os.read(descriptor, limit + 1)
            require(len(data) <= limit, "configuration_invalid", "Configuration input is too large")
            return data
        finally:
            os.close(descriptor)
    except V2Error:
        raise
    except OSError as exc:
        raise V2Error("configuration_unavailable", "Cannot read deployment configuration") from exc


def load_config(path: str | Path, *, check_marker: bool = True) -> DeploymentConfig:
    resolved = _absolute(path, Path.cwd())
    try:
        value = json.loads(_read_regular(resolved, limit=1024 * 1024))
    except (ValueError, UnicodeError) as exc:
        raise V2Error("configuration_invalid", "Configuration is not UTF-8 JSON") from exc
    config = config_from_dict(value, path=resolved)
    if check_marker:
        try:
            marker = json.loads(_read_regular(config.data_root / MARKER, limit=4096))
        except (ValueError, UnicodeError) as exc:
            raise V2Error("deployment_invalid", "Invalid v2 deployment marker") from exc
        require(marker == {"schema_version": SCHEMA, "deployment_id": config.deployment_id},
                "deployment_invalid", "Configuration and v2 deployment marker differ")
    return config


def _exclusive_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def initialize(config_path: str | Path, data_root: str | Path, *, isolation: str,
               deployment_id: str | None = None,
               archive_roots: dict[str, dict[str, str]] | None = None,
               research_provider: dict[str, str] | None = None) -> DeploymentConfig:
    """Create a new namespace only. Existing files are never overwritten."""
    path = _absolute(config_path, Path.cwd())
    root = _absolute(data_root, path.parent)
    value = {"schema_version": SCHEMA, "deployment_id": deployment_id or f"v2_{secrets.token_hex(8)}",
             "data_root": str(root), "isolation": isolation, "archive_roots": archive_roots or {}}
    if research_provider is not None:
        value["research_provider"] = research_provider
    config = config_from_dict(value, path=path)
    require(not path.exists() and not path.is_symlink(), "deployment_exists", "Configuration already exists")
    require(path.parent.is_dir(), "configuration_invalid", "Configuration parent must already exist")
    require(not root.exists() or (root.is_dir() and not any(root.iterdir())),
            "deployment_exists", "New v2 data root must be absent or empty")
    require(not _overlaps(root, path.parent) or path.parent != root,
            "configuration_invalid", "Place configuration outside its new data root")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    for relative in ("private", "public", "private/tmp", "public/tmp", "keys", "bootstrap"):
        (root / relative).mkdir(mode=0o700)
    # Keys never derive from legacy credentials. Failed initialization leaves
    # an explicit unconfigured new directory rather than deleting user files.
    for domain in DOMAINS:
        _exclusive_write(config.key_path(domain), secrets.token_bytes(32))
        key_fd = open_domain_key(config, domain)
        key = read_key_fd(key_fd)
        store = SignedStore(config.store_path(domain), key=key, domain=domain)
        store.close()
    marker = {"schema_version": SCHEMA, "deployment_id": config.deployment_id}
    _exclusive_write(root / MARKER, json.dumps(marker, sort_keys=True).encode())
    _exclusive_write(path, json.dumps(config.to_dict(), indent=2, ensure_ascii=False).encode() + b"\n")
    return config


def open_domain_key(config: DeploymentConfig, domain: str) -> int:
    """Bootstrap-only: return an FD for exactly one domain key."""
    path = _absolute(config.key_path(domain), config.path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size == 32 and
                metadata.st_uid == os.getuid() and metadata.st_mode & 0o077 == 0,
                "key_invalid", "Domain key must be an owner-only 32-byte regular file")
        return fd
    except Exception:
        if "fd" in locals():
            os.close(fd)
        raise


def read_key_fd(fd: int) -> bytes:
    require(type(fd) is int and fd > 2, "key_invalid", "A dedicated inherited key FD is required")
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISFIFO(metadata.st_mode) or
                (stat.S_ISREG(metadata.st_mode) and metadata.st_size == 32 and metadata.st_mode & 0o077 == 0),
                "key_invalid", "Inherited key FD must be a bootstrap pipe or protected regular file")
        key = os.read(fd, 33)
        require(len(key) == 32, "key_invalid", "Inherited key FD must contain exactly 32 bytes")
        return key
    except OSError as exc:
        raise V2Error("key_unavailable", "Cannot read inherited domain key") from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
