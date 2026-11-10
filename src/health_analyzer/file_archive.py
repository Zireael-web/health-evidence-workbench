"""Read-only, explicitly scoped search of existing private text archives.

This module does not infer a person's identity, follow links, alter files,
connect to a network, or turn filenames into a claim that two files match.
Profiles are supplied by an explicitly selected local JSON file. Search results
are private, untrusted document content and must not be sent to public tools.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import unicodedata

MAX_CONFIG_BYTES = 256 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_SEARCH_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 50_000
MAX_DEPTH = 32
MAX_MATCHES = 100
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


class ArchiveError(ValueError):
    """Invalid profile selection, inaccessible configuration, or unsafe root."""


@dataclass(frozen=True, slots=True)
class Profile:
    id: str
    label: str
    root: Path
    device: int
    inode: int


def _name_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _absolute_path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ArchiveError("Expected a nonempty absolute local path.")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path == Path(path.anchor):
        raise ArchiveError("Select an absolute non-root path without traversal.")
    return path


def _open_dir(path: Path, ancestry: list[tuple[int, int]] | None = None) -> int:
    """Open each component individually; links are forbidden, not resolved."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        if ancestry is not None:
            info = os.fstat(fd)
            ancestry.append((info.st_dev, info.st_ino))
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            if ancestry is not None:
                info = os.fstat(fd)
                ancestry.append((info.st_dev, info.st_ino))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _snapshot(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_bounded(parent_fd: int, name: str, limit: int, *, expected: os.stat_result | None = None) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        if expected is not None and _snapshot(before) != _snapshot(expected):
            raise ArchiveError("File changed before it could be read.")
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ArchiveError("File must be a bounded regular file with a single link.")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if len(data) > limit or len(data) != before.st_size or _snapshot(before) != _snapshot(os.fstat(fd)) or _snapshot(before) != _snapshot(current):
            raise ArchiveError("File changed or exceeded its size limit while being read.")
        return data
    finally:
        os.close(fd)


def _no_duplicate_fields(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ArchiveError("Duplicate JSON fields are not allowed.")
        result[key] = value
    return result


def load_profiles(config_path: str | Path) -> tuple[Profile, ...]:
    """Load explicit profiles from a private JSON file; make no filesystem writes.

    The JSON has exactly `profiles`, a nonempty array of objects with `id`,
    `label` and an absolute existing `root`. IDs are stable ASCII tokens;
    display labels may contain Unicode. Distinct profile roots must not overlap.
    No profile is privileged or selected by default.
    """
    try:
        path = _absolute_path(str(config_path))
        parent = _open_dir(path.parent)
        try:
            raw = _read_bounded(parent, path.name, MAX_CONFIG_BYTES)
        finally:
            os.close(parent)
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_fields)
        if not isinstance(data, dict) or set(data) != {"profiles"} or not isinstance(data["profiles"], list) or not 1 <= len(data["profiles"]) <= 100:
            raise ArchiveError("Configuration must contain between 1 and 100 explicit profiles.")
        profiles: list[Profile] = []
        profile_ancestries: list[list[tuple[int, int]]] = []
        names: dict[str, int] = {}
        for item in data["profiles"]:
            if not isinstance(item, dict) or set(item) != {"id", "label", "root"}:
                raise ArchiveError("Each profile needs an id, label and root.")
            profile_id, label = item["id"], item["label"]
            if not isinstance(profile_id, str) or not _ID.fullmatch(profile_id):
                raise ArchiveError("Profile id must be a short ASCII identifier.")
            if not isinstance(label, str) or not label or len(label) > 100 or label != label.strip() or any(unicodedata.category(c).startswith("C") and c not in {"\u200c", "\u200d"} for c in label):
                raise ArchiveError("Profile label must be a bounded, printable name.")
            root = _absolute_path(item["root"])
            ancestry: list[tuple[int, int]] = []
            fd = _open_dir(root, ancestry)
            try:
                st = os.fstat(fd)
            finally:
                os.close(fd)
            if not stat.S_ISDIR(st.st_mode):
                raise ArchiveError("Profile root must be a directory.")
            for previous, previous_ancestry in zip(profiles, profile_ancestries):
                if ((previous.device, previous.inode) in ancestry
                        or (st.st_dev, st.st_ino) in previous_ancestry):
                    raise ArchiveError("Profile roots must not overlap or refer to the same directory.")
            index = len(profiles)
            for value in (profile_id, label):
                key = _name_key(value)
                if key in names and names[key] != index:
                    raise ArchiveError("Profile identifiers and labels must be unambiguous.")
                names[key] = index
            profiles.append(Profile(profile_id, label, root, st.st_dev, st.st_ino))
            profile_ancestries.append(ancestry)
        return tuple(profiles)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError("Cannot load the selected profile configuration safely.") from exc


def select_profile(profiles: tuple[Profile, ...], selection: str) -> Profile:
    """Select exactly one profile by explicit ID or label, never by default."""
    if not isinstance(selection, str) or not selection.strip():
        raise ArchiveError("An explicit profile ID or label is required.")
    key = _name_key(selection)
    matches = [p for p in profiles if key in {_name_key(p.id), _name_key(p.label)}]
    if len(matches) != 1:
        raise ArchiveError("The selected profile is unknown or ambiguous.")
    return matches[0]



def _matching_excerpt(line: str, normalized_line: str, query_key: str) -> tuple[str | None, bool]:
    """Return original characters around the match, never a transformed quote.

    Normalization can expand or combine characters, so offsets in the matching
    string cannot be applied directly to the original. Locate a nearby original
    offset, then verify the candidate after normalization. If an adversarial
    normalization needs a very large context, omit the quote rather than report
    a misleading excerpt; the caller still has the exact file and line number.
    """
    hit = normalized_line.find(query_key)
    if line.isascii():
        original_offset = hit
    else:
        low, high = 0, len(line)
        while low < high:
            mid = (low + high) // 2
            if len(_name_key(line[:mid])) < hit:
                low = mid + 1
            else:
                high = mid
        original_offset = low
    radius = max(512, len(query_key) + 64)
    while radius <= 16384:
        start = max(0, original_offset - radius)
        end = min(len(line), original_offset + radius)
        excerpt = line[start:end]
        if query_key in _name_key(excerpt):
            return excerpt, start != 0 or end != len(line)
        if start == 0 and end == len(line):
            break
        radius *= 2
    return None, True


def search_text(profiles: tuple[Profile, ...], profile: str, query: str, *, max_matches: int = 25) -> dict:
    """Search bounded UTF-8 .txt files in the selected root and report coverage.

    Matching is case-insensitive and line-based. Returned paths are relative to
    the selected private root; snippets are untrusted and may contain health
    information. A complete *text search* does not establish full archive
    coverage or that any TXT belongs to a particular original document.
    """
    chosen = select_profile(profiles, profile)
    if not isinstance(query, str) or not query.strip() or len(query) > 512 or "\n" in query or "\r" in query or "\x00" in query:
        raise ArchiveError("Query must be one nonempty bounded line.")
    if type(max_matches) is not int or not 1 <= max_matches <= MAX_MATCHES:
        raise ArchiveError("Invalid match limit.")
    try:
        root_fd = _open_dir(chosen.root)
    except OSError as exc:
        raise ArchiveError("Selected profile root is unavailable or unsafe.") from exc
    try:
        root_stat = os.fstat(root_fd)
        if (root_stat.st_dev, root_stat.st_ino) != (chosen.device, chosen.inode):
            raise ArchiveError("Selected profile root changed; reload and review the configuration.")
        query_key = _name_key(query)
        results: list[dict] = []
        observed_dirs: list[tuple[tuple[str, ...], tuple[int, int, int, int, int, int, int]]] = []
        observed_files: list[tuple[tuple[str, ...], str, tuple[int, int, int, int, int, int, int]]] = []
        stats = {"entries_examined": 0, "text_files_scanned": 0, "other_files": 0,
                 "skipped_or_unreadable": 0, "total_matches": 0, "bytes_read": 0}
        limited = False

        def walk(fd: int, parts: tuple[str, ...], depth: int) -> None:
            nonlocal limited
            try:
                with os.scandir(fd) as entries:
                    for entry in entries:
                        if stats["entries_examined"] >= MAX_ENTRIES:
                            limited = True
                            return
                        stats["entries_examined"] += 1
                        try:
                            info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                            if stat.S_ISLNK(info.st_mode):
                                stats["skipped_or_unreadable"] += 1
                            elif stat.S_ISDIR(info.st_mode):
                                if depth >= MAX_DEPTH:
                                    limited = True
                                    continue
                                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                                before_stats = dict(stats)
                                before_results = len(results)
                                try:
                                    opened = os.fstat(child)
                                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                                        raise ArchiveError("Directory changed while it was opened.")
                                    observed_dirs.append((parts + (entry.name,), _snapshot(opened)))
                                    walk(child, parts + (entry.name,), depth + 1)
                                    try:
                                        linked = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                                        current = os.fstat(child)
                                        still_linked = (stat.S_ISDIR(linked.st_mode)
                                                        and (linked.st_dev, linked.st_ino) == (opened.st_dev, opened.st_ino)
                                                        and (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino))
                                    except OSError:
                                        still_linked = False
                                    if not still_linked:
                                        del results[before_results:]
                                        for key in ("text_files_scanned", "other_files", "total_matches"):
                                            stats[key] = before_stats[key]
                                        stats["skipped_or_unreadable"] += 1
                                    elif _snapshot(opened) != _snapshot(current):
                                        stats["skipped_or_unreadable"] += 1
                                finally:
                                    os.close(child)
                                if limited and stats["entries_examined"] >= MAX_ENTRIES:
                                    return
                            elif stat.S_ISREG(info.st_mode) and entry.name.casefold().endswith(".txt"):
                                if info.st_size > MAX_TEXT_BYTES or stats["bytes_read"] + info.st_size > MAX_SEARCH_BYTES:
                                    stats["skipped_or_unreadable"] += 1
                                    limited = True
                                    continue
                                content = _read_bounded(fd, entry.name, MAX_TEXT_BYTES, expected=info)
                                stats["bytes_read"] += len(content)
                                text = content.decode("utf-8")
                                observed_files.append((parts, entry.name, _snapshot(info)))
                                stats["text_files_scanned"] += 1
                                for line_number, line in enumerate(text.splitlines(), 1):
                                    normalized_line = _name_key(line)
                                    if query_key in normalized_line:
                                        stats["total_matches"] += 1
                                        if len(results) < max_matches:
                                            excerpt, truncated = _matching_excerpt(line, normalized_line, query_key)
                                            results.append({"path": "/".join(parts + (entry.name,)),
                                                            "line": line_number,
                                                            "excerpt": excerpt,
                                                            "excerpt_truncated": truncated})
                            elif stat.S_ISREG(info.st_mode):
                                stats["other_files"] += 1
                            else:
                                stats["skipped_or_unreadable"] += 1
                        except (OSError, UnicodeError, ArchiveError):
                            stats["skipped_or_unreadable"] += 1
            except OSError:
                stats["skipped_or_unreadable"] += 1

        walk(root_fd, (), 0)
        try:
            checked_root = _open_dir(chosen.root)
            try:
                current_root = os.fstat(checked_root)
                root_still_linked = ((current_root.st_dev, current_root.st_ino) == (root_stat.st_dev, root_stat.st_ino))
            finally:
                os.close(checked_root)
        except OSError:
            root_still_linked = False
        paths_still_valid = root_still_linked
        if root_still_linked:
            for parts, expected in observed_dirs:
                check_fd = os.dup(root_fd)
                try:
                    for part in parts:
                        child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=check_fd)
                        os.close(check_fd)
                        check_fd = child_fd
                    current = _snapshot(os.fstat(check_fd))
                    if current[:2] != expected[:2]:
                        paths_still_valid = False
                        break
                    if current != expected:
                        stats["skipped_or_unreadable"] += 1
                except OSError:
                    paths_still_valid = False
                    break
                finally:
                    os.close(check_fd)
        if paths_still_valid:
            for parts, name, expected in observed_files:
                check_fd = os.dup(root_fd)
                try:
                    for part in parts:
                        child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=check_fd)
                        os.close(check_fd)
                        check_fd = child_fd
                    current = os.stat(name, dir_fd=check_fd, follow_symlinks=False)
                    if not stat.S_ISREG(current.st_mode) or _snapshot(current) != expected:
                        paths_still_valid = False
                        break
                except OSError:
                    paths_still_valid = False
                    break
                finally:
                    os.close(check_fd)
        if not paths_still_valid:
            # Do not return potentially stale paths or content from a moved subtree.
            results.clear()
            stats["text_files_scanned"] = 0
            stats["other_files"] = 0
            stats["total_matches"] = 0
            stats["skipped_or_unreadable"] += 1
        elif _snapshot(root_stat) != _snapshot(current_root):
            stats["skipped_or_unreadable"] += 1
        return {"profile_id": chosen.id, "matches": results, "coverage": {
            **stats, "text_search_complete": not limited and stats["skipped_or_unreadable"] == 0,
            "results_truncated": stats["total_matches"] > len(results),
            "source_document_coverage": "unknown", "search_scope": "utf8_txt_files_only"}}
    finally:
        os.close(root_fd)
