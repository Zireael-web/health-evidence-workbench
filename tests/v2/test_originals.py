from concurrent.futures import ThreadPoolExecutor
import copy
import errno
import hashlib
import os
import stat

import pytest

from health_analyzer.v2.common import V2Error
from health_analyzer.v2.originals import OriginalsStore


CONTENT = b"analyte;result\nSynthetic A;1\n"


def make_store(tmp_path):
    (tmp_path / "private").mkdir(mode=0o700, exist_ok=True)
    return OriginalsStore(tmp_path / "private" / "originals")


def blob_path(store, subject="demo", content=CONTENT):
    digest = hashlib.sha256(content).hexdigest()
    scope = hashlib.sha256(subject.encode()).hexdigest()
    return store.base / scope / digest[:2] / digest


def version(manifest):
    return {key: manifest[key] for key in ("subject_id", "source_sha256", "size", "mime")}


def assert_code(code, operation):
    with pytest.raises(V2Error) as error:
        operation()
    assert error.value.code == code


def test_roundtrip_reuses_verified_blob_and_private_modes(tmp_path):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    assert manifest["source_mode"] == "immutable_snapshot"
    assert manifest["source_sha256"] == hashlib.sha256(CONTENT).hexdigest()
    assert manifest["size"] == len(CONTENT)
    assert not manifest["snapshot_ref"].startswith("/")
    path = store.verified_path("demo", manifest, version(manifest))
    inode = path.stat().st_ino
    assert store.read_manifest("demo", manifest, version(manifest)) == CONTENT
    assert store.preserve("demo", CONTENT, "text/csv") == manifest
    assert path.stat().st_ino == inode
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    for directory in (store.base, path.parent, path.parent.parent):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert list(path.parent.glob(".staging-*")) == []
    assert store.availability("demo", manifest["source_sha256"], len(CONTENT)) == {
        "status": "available", "available": True}


def test_identical_bytes_are_physically_separated_by_subject(tmp_path):
    store = make_store(tmp_path)
    first = store.preserve("demo", CONTENT, "text/csv")
    other = store.preserve("another", CONTENT, "text/csv")
    assert first["source_sha256"] == other["source_sha256"]
    assert first["snapshot_ref"] != other["snapshot_ref"]
    first_path = store.verified_path("demo", first)
    other_path = store.verified_path("another", other)
    assert first_path != other_path
    assert first_path.stat().st_ino != other_path.stat().st_ino
    assert_code("WRONG_SUBJECT", lambda: store.read_manifest("another", first))
    assert_code("ORIGINAL_UNAVAILABLE", lambda: store.read("unregistered", first["source_sha256"], len(CONTENT)))


def test_saved_versions_survive_archive_change_and_rename_without_changing_archive(tmp_path):
    store = make_store(tmp_path)
    archive = tmp_path / "archive"
    archive.mkdir()
    source = archive / "report.csv"
    source.write_bytes(CONTENT)
    before = source.stat()
    old = store.preserve("demo", source.read_bytes(), "text/csv")
    after = source.stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
    changed = CONTENT.replace(b";1", b";9")
    source.write_bytes(changed)
    latest = store.preserve("demo", source.read_bytes(), "text/csv")
    source.rename(archive / "renamed.csv")
    assert old["source_sha256"] != latest["source_sha256"]
    assert store.read_manifest("demo", old, version(old)) == CONTENT
    assert store.read_manifest("demo", latest, version(latest)) == changed
    assert (archive / "renamed.csv").read_bytes() == changed


@pytest.mark.parametrize("subject", ["../outside", "/outside", "a/b", "a\\b", "", "x\x00y"])
def test_subject_traversal_is_rejected(tmp_path, subject):
    store = make_store(tmp_path)
    assert_code("invalid_identifier", lambda: store.preserve(subject, CONTENT, "text/csv"))
    assert list(store.base.iterdir()) == []


@pytest.mark.parametrize("sha256", ["../outside", "A" * 64, "f" * 63, "0" * 64 + "/x", None])
def test_hash_and_size_traversal_is_rejected(tmp_path, sha256):
    store = make_store(tmp_path)
    assert_code("INVALID_ORIGINAL", lambda: store.read("demo", sha256, len(CONTENT)))
    assert list(store.base.iterdir()) == []


@pytest.mark.parametrize("size", [-1, True, 1.0, None, 64 * 1024 * 1024 + 1])
def test_invalid_sizes_fail_before_path_access(tmp_path, size):
    store = make_store(tmp_path)
    assert_code("INVALID_ORIGINAL", lambda: store.availability("demo", "0" * 64, size))


def test_bounded_inputs_and_empty_original(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    assert_code("INVALID_ORIGINAL", lambda: store.preserve("demo", bytearray(CONTENT), "text/csv"))
    assert_code("INVALID_ORIGINAL", lambda: store.preserve("demo", CONTENT, "text/csv\npath"))
    monkeypatch.setattr("health_analyzer.v2.originals.MAX_ORIGINAL_BYTES", 5)
    assert_code("INVALID_ORIGINAL", lambda: store.preserve("demo", CONTENT, "text/csv"))
    empty = store.preserve("demo", b"", "application/octet-stream")
    assert store.read_manifest("demo", empty) == b""


def test_manifest_and_version_bind_scope_ref_hash_size_and_mime(tmp_path):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    for key, value in (("snapshot_ref", "/private/arbitrary"), ("snapshot_ref", "../report")):
        altered = {**manifest, key: value}
        assert_code("INVALID_ORIGINAL_MANIFEST", lambda: store.read_manifest("demo", altered))
    arbitrary = {**manifest, "snapshot_path": "/private/arbitrary"}
    assert_code("INVALID_ORIGINAL_MANIFEST", lambda: store.read_manifest("demo", arbitrary))
    assert_code("WRONG_SUBJECT", lambda: store.read_manifest("demo", manifest, {**version(manifest), "subject_id": "another"}))
    for key, value in (("source_sha256", "0" * 64), ("size", len(CONTENT) + 1), ("mime", "text/plain")):
        different = {**version(manifest), key: value}
        assert_code("ORIGINAL_VERSION_MISMATCH", lambda: store.read_manifest("demo", manifest, different))
    bad_size = {**version(manifest), "size": True}
    assert_code("INVALID_ORIGINAL", lambda: store.read_manifest("demo", manifest, bad_size))


def test_corrupt_blob_cannot_be_read_reused_or_overwritten(tmp_path):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    path = blob_path(store)
    path.chmod(0o600)
    corruption = b"x" * len(CONTENT)
    path.write_bytes(corruption)
    inode = path.stat().st_ino
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.read_manifest("demo", manifest))
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.preserve("demo", CONTENT, "text/csv"))
    assert store.availability("demo", manifest["source_sha256"], len(CONTENT)) == {
        "status": "integrity_failure", "available": False, "error_code": "ORIGINAL_INTEGRITY_FAILURE"}
    assert path.read_bytes() == corruption
    assert path.stat().st_ino == inode
    assert list(path.parent.glob(".staging-*")) == []


def test_missing_blob_is_unavailable_and_wrong_size_is_integrity_failure(tmp_path):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.read("demo", manifest["source_sha256"], len(CONTENT) + 1))
    blob_path(store).unlink()
    assert store.availability("demo", manifest["source_sha256"], len(CONTENT)) == {
        "status": "unavailable", "available": False, "error_code": "ORIGINAL_UNAVAILABLE"}


def test_unsafe_existing_permissions_are_rejected_without_repair(tmp_path):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    path = blob_path(store)
    path.chmod(0o644)
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.preserve("demo", CONTENT, "text/csv"))
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    path.chmod(0o400)
    path.parent.chmod(0o755)
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.read_manifest("demo", manifest))
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o755


@pytest.mark.parametrize("level", ["base", "ancestor"])
def test_symlink_base_or_ancestor_is_rejected_without_writing_target(tmp_path, level):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    path = link if level == "base" else link / "originals"
    assert_code("UNSAFE_ORIGINAL_PATH", lambda: OriginalsStore(path))
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("level", ["subject", "shard", "blob"])
def test_symlink_subject_shard_or_blob_never_reads_or_changes_outside(tmp_path, level):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    path = blob_path(store)
    selected = {"subject": path.parent.parent, "shard": path.parent, "blob": path}[level]
    held = selected.with_name(selected.name + "-held")
    selected.rename(held)
    outside = tmp_path / "outside"
    if level == "blob":
        outside.write_bytes(CONTENT)
        outside.chmod(0o400)
    else:
        outside.mkdir(mode=0o700)
    selected.symlink_to(outside, target_is_directory=level != "blob")
    code = "ORIGINAL_INTEGRITY_FAILURE" if level == "blob" else "UNSAFE_ORIGINAL_PATH"
    assert_code(code, lambda: store.read_manifest("demo", manifest))
    assert_code(code, lambda: store.preserve("demo", CONTENT, "text/csv"))
    assert outside.read_bytes() == CONTENT if level == "blob" else list(outside.iterdir()) == []


def test_fifo_blob_is_rejected_without_blocking(tmp_path):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    path = blob_path(store)
    path.unlink()
    os.mkfifo(path, mode=0o600)
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.read_manifest("demo", manifest))


def test_replaced_base_is_not_silently_adopted(tmp_path):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    held = store.base.with_name("held-originals")
    store.base.rename(held)
    replacement = OriginalsStore(store.base)
    replacement.preserve("demo", CONTENT, "text/csv")
    assert_code("UNSAFE_ORIGINAL_PATH", lambda: store.read_manifest("demo", manifest))
    assert_code("UNSAFE_ORIGINAL_PATH", lambda: store.preserve("demo", CONTENT, "text/csv"))
    assert (held / blob_path(store).relative_to(store.base)).read_bytes() == CONTENT


def test_directory_rename_and_symlink_race_is_detected_before_publication(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    scope = hashlib.sha256(b"demo").hexdigest()
    original_open = os.open
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    moved = store.base / (scope + "-held")
    raced = False

    def race_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal raced
        fd = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == scope and dir_fd is not None and not raced:
            raced = True
            (store.base / scope).rename(moved)
            (store.base / scope).symlink_to(outside, target_is_directory=True)
        return fd

    monkeypatch.setattr(os, "open", race_open)
    assert_code("UNSAFE_ORIGINAL_PATH", lambda: store.preserve("demo", CONTENT, "text/csv"))
    assert raced
    assert list(outside.iterdir()) == []
    assert not any(p.is_file() for p in moved.rglob("*"))


def test_changed_bytes_during_descriptor_read_fail_closed(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    path = blob_path(store)
    original_read = os.read
    changed = False

    def race_read(fd, size):
        nonlocal changed
        data = original_read(fd, size)
        if data and not changed:
            changed = True
            path.chmod(0o600)
            path.write_bytes(b"x" * len(CONTENT))
            path.chmod(0o400)
        return data

    monkeypatch.setattr(os, "read", race_read)
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.read_manifest("demo", manifest))
    assert changed


def test_directory_permissions_changed_during_read_fail_closed(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    path = blob_path(store)
    original_read = os.read
    changed = False

    def race_read(fd, size):
        nonlocal changed
        data = original_read(fd, size)
        if data and not changed:
            changed = True
            path.parent.chmod(0o755)
        return data

    monkeypatch.setattr(os, "read", race_read)
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.read_manifest("demo", manifest))
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o755


def test_exclusive_publication_refuses_a_tampered_racing_blob(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    original_link = os.link
    corruption = b"x" * len(CONTENT)

    def racing_link(source, target, **kwargs):
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=kwargs["dst_dir_fd"])
        try:
            os.write(fd, corruption)
        finally:
            os.close(fd)
        return original_link(source, target, **kwargs)

    monkeypatch.setattr(os, "link", racing_link)
    assert_code("ORIGINAL_INTEGRITY_FAILURE", lambda: store.preserve("demo", CONTENT, "text/csv"))
    assert blob_path(store).read_bytes() == corruption
    assert list(blob_path(store).parent.glob(".staging-*")) == []


def test_failed_publication_cleans_only_its_staging_file(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    original_link = os.link

    def fail_link(*args, **kwargs):
        raise OSError(errno.ENOSPC, "synthetic no space")

    monkeypatch.setattr(os, "link", fail_link)
    assert_code("ORIGINAL_PUBLICATION_FAILED", lambda: store.preserve("demo", CONTENT, "text/csv"))
    assert not blob_path(store).exists()
    assert list(blob_path(store).parent.glob(".staging-*")) == []
    monkeypatch.setattr(os, "link", original_link)
    assert store.read_manifest("demo", store.preserve("demo", CONTENT, "text/csv")) == CONTENT


def test_failure_after_exclusive_link_retains_verified_unreferenced_blob(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    original_link, original_fsync = os.link, os.fsync
    published = False

    def linked(*args, **kwargs):
        nonlocal published
        result = original_link(*args, **kwargs)
        published = True
        return result

    def fail_once_after_link(fd):
        nonlocal published
        if published:
            published = False
            raise OSError(errno.EIO, "synthetic durability failure")
        return original_fsync(fd)

    monkeypatch.setattr(os, "link", linked)
    monkeypatch.setattr(os, "fsync", fail_once_after_link)
    assert_code("ORIGINAL_PUBLICATION_FAILED", lambda: store.preserve("demo", CONTENT, "text/csv"))
    retained = blob_path(store)
    assert retained.read_bytes() == CONTENT
    inode = retained.stat().st_ino
    monkeypatch.setattr(os, "link", original_link)
    monkeypatch.setattr(os, "fsync", original_fsync)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    assert retained.stat().st_ino == inode
    assert store.read_manifest("demo", manifest) == CONTENT


def test_concurrent_publishers_reuse_one_complete_blob(tmp_path):
    (tmp_path / "private").mkdir(mode=0o700)
    base = tmp_path / "private" / "originals"
    stores = [OriginalsStore(base) for _ in range(4)]
    with ThreadPoolExecutor(max_workers=4) as executor:
        manifests = list(executor.map(lambda store: store.preserve("demo", CONTENT, "text/csv"), stores))
    assert all(manifest == manifests[0] for manifest in manifests)
    assert stores[0].read_manifest("demo", manifests[0]) == CONTENT
    assert list(blob_path(stores[0]).parent.glob(".staging-*")) == []


def test_opaque_ref_is_not_an_arbitrary_path_input(tmp_path):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")
    changed = copy.deepcopy(manifest)
    changed["snapshot_ref"] = str(blob_path(store))
    assert_code("INVALID_ORIGINAL_MANIFEST", lambda: store.verified_path("demo", changed))
    changed["snapshot_ref"] = store.snapshot_ref("another", manifest["source_sha256"])
    assert_code("INVALID_ORIGINAL_MANIFEST", lambda: store.verified_path("demo", changed))


def test_existing_ancestors_and_base_never_receive_mkdir_or_fsync(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    base = private / "originals"
    base.mkdir(mode=0o700)

    def reject_write(*args, **kwargs):
        raise AssertionError("Existing ancestor received a write request")

    monkeypatch.setattr(os, "mkdir", reject_write)
    monkeypatch.setattr(os, "fsync", reject_write)
    store = OriginalsStore(base)
    assert store.base == base.absolute()


def test_initialization_creates_only_base_and_syncs_only_its_private_parent(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    base = private / "originals"
    parent_identity = (private.stat().st_dev, private.stat().st_ino)
    original_mkdir, original_fsync = os.mkdir, os.fsync
    mkdir_calls = []
    fsync_calls = []

    def constrained_mkdir(name, mode=0o777, *, dir_fd=None):
        assert name == "originals" and dir_fd is not None
        metadata = os.fstat(dir_fd)
        assert (metadata.st_dev, metadata.st_ino) == parent_identity
        mkdir_calls.append(name)
        return original_mkdir(name, mode, dir_fd=dir_fd)

    def constrained_fsync(fd):
        metadata = os.fstat(fd)
        assert (metadata.st_dev, metadata.st_ino) == parent_identity
        fsync_calls.append(fd)
        return original_fsync(fd)

    monkeypatch.setattr(os, "mkdir", constrained_mkdir)
    monkeypatch.setattr(os, "fsync", constrained_fsync)
    OriginalsStore(base)
    OriginalsStore(base)
    assert mkdir_calls == ["originals"]
    assert len(fsync_calls) == 1


def test_missing_deployment_parent_fails_without_creating_ancestors(tmp_path, monkeypatch):
    missing_parent = tmp_path / "unprovisioned"
    base = missing_parent / "originals"

    def reject_write(*args, **kwargs):
        raise AssertionError("Store attempted to provision an ancestor")

    monkeypatch.setattr(os, "mkdir", reject_write)
    monkeypatch.setattr(os, "fsync", reject_write)
    assert_code("ORIGINAL_UNAVAILABLE", lambda: OriginalsStore(base))
    assert not missing_parent.exists()


def test_existing_subject_directories_are_reused_without_create_attempts(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    manifest = store.preserve("demo", CONTENT, "text/csv")

    def reject_write(*args, **kwargs):
        raise AssertionError("Existing original received a directory write request")

    monkeypatch.setattr(os, "mkdir", reject_write)
    monkeypatch.setattr(os, "fsync", reject_write)
    assert store.preserve("demo", CONTENT, "text/csv") == manifest
    assert store.read_manifest("demo", manifest, version(manifest)) == CONTENT
