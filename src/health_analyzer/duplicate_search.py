"""Read-only, bounded, profile-scoped search for byte-identical files.

Matching bytes do not prove a document's owner, type, role, or provenance.
Results contain private paths and must never be sent to public tools. A result
is a snapshot, not a lock against changes after return. Source and archive are
never modified. Search limits are cooperative; filesystem calls can still block.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import time

from .file_archive import ArchiveError, Profile, _absolute_path, _open_dir, _snapshot, select_profile

MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_HASH_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 50_000
MAX_DEPTH = 32
MAX_MATCHES = 100
MAX_SECONDS = 20.0
CHUNK = 1024 * 1024


def _open_regular(parent: int, name: str) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ArchiveError("File must be regular and have exactly one link.")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _digest(fd: int, expected: os.stat_result, deadline: float) -> str:
    if _snapshot(os.fstat(fd)) != _snapshot(expected):
        raise ArchiveError("File changed before hashing.")
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    count = 0
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("Search time limit reached.")
        chunk = os.read(fd, CHUNK)
        if not chunk:
            break
        count += len(chunk)
        if count > expected.st_size:
            raise ArchiveError("File changed while hashing.")
        digest.update(chunk)
    if count != expected.st_size or _snapshot(os.fstat(fd)) != _snapshot(expected):
        raise ArchiveError("File changed while hashing.")
    return digest.hexdigest()


def _open_descendant(root_fd: int, parts: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def find_duplicates(profiles: tuple[Profile, ...], profile: str, source: str | Path) -> dict:
    """Find exact-byte matches for one source in one explicitly selected profile.

    A complete scan covers regular files in this root at the time of scanning;
    skipped links, inaccessible entries, changes and limits make it incomplete.
    Even a complete scan cannot protect against concurrent changes after return.
    """
    chosen = select_profile(profiles, profile)
    path = _absolute_path(str(source))
    deadline = time.monotonic() + MAX_SECONDS
    try:
        source_parent = _open_dir(path.parent)
        try:
            source_fd = _open_regular(source_parent, path.name)
            try:
                source_stat = os.fstat(source_fd)
                if source_stat.st_size > MAX_SOURCE_BYTES:
                    raise ArchiveError("Selected source exceeds the size limit.")
                source_hash = _digest(source_fd, source_stat, deadline)
                return _scan(chosen, source_parent, source_fd, path, source_stat, source_hash, deadline)
            finally:
                os.close(source_fd)
        finally:
            os.close(source_parent)
    except (OSError, TimeoutError) as exc:
        raise ArchiveError("Source or selected profile is unavailable or unsafe.") from exc


def _scan(chosen: Profile, source_parent: int, source_fd: int, source: Path,
          source_stat: os.stat_result, source_hash: str, deadline: float) -> dict:
    root_fd = _open_dir(chosen.root)
    try:
        root_stat = os.fstat(root_fd)
        if (root_stat.st_dev, root_stat.st_ino) != (chosen.device, chosen.inode):
            raise ArchiveError("Selected profile root changed; reload the configuration.")
        directories: list[tuple[tuple[str, ...], tuple]] = [((), _snapshot(root_stat))]
        files: list[tuple[tuple[str, ...], str, tuple]] = []
        matches: list[str] = []
        stats = {"entries_examined": 0, "files_examined": 0, "files_hashed": 0,
                 "bytes_hashed": 0, "skipped_or_unreadable": 0, "matching_files": 0}
        limits: set[str] = set()

        def walk(fd: int, parts: tuple[str, ...], depth: int) -> None:
            try:
                with os.scandir(fd) as entries:
                    for entry in entries:
                        if time.monotonic() >= deadline:
                            limits.add("time")
                            return
                        if stats["entries_examined"] >= MAX_ENTRIES:
                            limits.add("entries")
                            return
                        stats["entries_examined"] += 1
                        try:
                            info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                if depth >= MAX_DEPTH:
                                    limits.add("depth")
                                    continue
                                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                                try:
                                    opened = os.fstat(child)
                                    if _snapshot(opened) != _snapshot(info):
                                        raise ArchiveError("Directory changed during search.")
                                    directories.append((parts + (entry.name,), _snapshot(opened)))
                                    walk(child, parts + (entry.name,), depth + 1)
                                finally:
                                    os.close(child)
                            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                                stats["files_examined"] += 1
                                files.append((parts, entry.name, _snapshot(info)))
                                if info.st_size == source_stat.st_size:
                                    if stats["bytes_hashed"] + info.st_size > MAX_HASH_BYTES:
                                        limits.add("bytes")
                                        continue
                                    candidate = _open_regular(fd, entry.name)
                                    try:
                                        candidate_hash = _digest(candidate, info, deadline)
                                        if _snapshot(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) != _snapshot(info):
                                            raise ArchiveError("File changed during search.")
                                    finally:
                                        os.close(candidate)
                                    stats["files_hashed"] += 1
                                    stats["bytes_hashed"] += info.st_size
                                    if candidate_hash == source_hash:
                                        stats["matching_files"] += 1
                                        if len(matches) < MAX_MATCHES:
                                            matches.append("/".join(parts + (entry.name,)))
                            else:
                                stats["skipped_or_unreadable"] += 1
                        except TimeoutError:
                            limits.add("time")
                            return
                        except (OSError, ArchiveError):
                            stats["skipped_or_unreadable"] += 1
            except OSError:
                stats["skipped_or_unreadable"] += 1

        walk(root_fd, (), 0)
        valid = True
        try:
            # Source and each visited path must still be the same snapshot. Check
            # even files skipped on size, which could otherwise become matches.
            if (_snapshot(os.fstat(source_fd)) != _snapshot(source_stat)
                    or _snapshot(os.stat(source.name, dir_fd=source_parent, follow_symlinks=False)) != _snapshot(source_stat)):
                raise ArchiveError("Source changed during duplicate search.")
            parent_now = _open_dir(source.parent)
            try:
                original_parent = os.fstat(source_parent)
                linked_parent = os.fstat(parent_now)
                if ((original_parent.st_dev, original_parent.st_ino)
                        != (linked_parent.st_dev, linked_parent.st_ino)):
                    raise ArchiveError("Source directory changed during duplicate search.")
            finally:
                os.close(parent_now)
            check_root = _open_dir(chosen.root)
            try:
                if _snapshot(os.fstat(check_root)) != _snapshot(root_stat):
                    valid = False
            finally:
                os.close(check_root)
            for parts, expected in directories:
                if time.monotonic() >= deadline:
                    limits.add("time")
                    valid = False
                    break
                check_fd = _open_descendant(root_fd, parts)
                try:
                    if _snapshot(os.fstat(check_fd)) != expected:
                        valid = False
                        break
                finally:
                    os.close(check_fd)
            if valid:
                for parts, name, expected in files:
                    if time.monotonic() >= deadline:
                        limits.add("time")
                        valid = False
                        break
                    check_fd = _open_descendant(root_fd, parts)
                    try:
                        if _snapshot(os.stat(name, dir_fd=check_fd, follow_symlinks=False)) != expected:
                            valid = False
                            break
                    finally:
                        os.close(check_fd)
        except OSError:
            valid = False
        if not valid:
            # Avoid returning stale path claims if archive changed during search.
            matches.clear()
            stats["matching_files"] = 0
            stats["skipped_or_unreadable"] += 1
        complete = valid and not limits and stats["skipped_or_unreadable"] == 0
        return {"profile_id": chosen.id, "source_sha256": source_hash,
                "source_size": source_stat.st_size, "matches": matches,
                "coverage": {**stats, "search_complete": complete,
                             "limits_reached": sorted(limits),
                             "matches_truncated": stats["matching_files"] > len(matches),
                             "scope": "regular_files_in_selected_profile",
                             "match_meaning": "same_sha256_and_size_not_identity_or_role"}}
    finally:
        os.close(root_fd)
