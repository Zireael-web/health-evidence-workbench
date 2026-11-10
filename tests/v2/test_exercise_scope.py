"""No real deployment can be silently adopted as a synthetic exercise."""
import os
from pathlib import Path
import pytest
from health_analyzer.v2.common import V2Error
from health_analyzer.v2.exercise_scope import create_synthetic_exercise,verify_synthetic_exercise,require_owned_synthetic_path,MARKER_NAME


def test_new_owned_scope_binds_root_and_never_adopts_existing_directory(tmp_path):
    root=tmp_path/"exercise";marker=create_synthetic_exercise(root)
    assert verify_synthetic_exercise(root)==marker
    assert require_owned_synthetic_path(root,"new/file.db")==root/"new/file.db"
    assert not (root/"new").exists()
    before=(root/MARKER_NAME).read_bytes()
    with pytest.raises(V2Error) as e:create_synthetic_exercise(root)
    assert e.value.code=="SYNTHETIC_SCOPE_EXISTS" and (root/MARKER_NAME).read_bytes()==before


def test_outside_escape_and_symlinks_rejected_without_source_reads(tmp_path):
    root=tmp_path/"exercise";create_synthetic_exercise(root)
    outside=tmp_path/"ordinary-store.db";outside.write_bytes(b"synthetic external sentinel")
    for path in [outside,root/".."/outside.name]:
        with pytest.raises(V2Error):require_owned_synthetic_path(root,path,must_exist=True)
    (root/"link.db").symlink_to(outside)
    with pytest.raises(V2Error):require_owned_synthetic_path(root,root/"link.db",must_exist=True)
    os.link(outside,root/"hard.db")
    with pytest.raises(V2Error):require_owned_synthetic_path(root,root/"hard.db",must_exist=True)
    assert outside.read_bytes()==b"synthetic external sentinel"


def test_marker_root_rebinding_and_unsafe_mode_fail_closed(tmp_path):
    root=tmp_path/"exercise";create_synthetic_exercise(root)
    moved=tmp_path/"moved";root.rename(moved)
    with pytest.raises(V2Error):verify_synthetic_exercise(moved)
    moved.rename(root);root.chmod(0o755)
    with pytest.raises(V2Error):verify_synthetic_exercise(root)
    root.chmod(0o700)
    assert verify_synthetic_exercise(root)["scope"]=="synthetic_only"


def test_ordinary_existing_directory_without_marker_not_read_as_store(tmp_path):
    root=tmp_path/"ordinary";root.mkdir(mode=0o700)
    (root/"private.sqlite3").write_bytes(b"not a store")
    with pytest.raises(V2Error):require_owned_synthetic_path(root,root/"private.sqlite3",must_exist=True)
    assert not (root/MARKER_NAME).exists()
