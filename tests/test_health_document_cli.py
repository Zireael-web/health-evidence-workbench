"""CLI integration exercises exclusively invented files in temporary folders."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import runpy
import signal
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "health-document"


def invoke(*args: object, stdin_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-B", str(SCRIPT), *(str(arg) for arg in args)],
        input=stdin_text, text=True, encoding="utf-8", capture_output=True, check=False,
    )


def test_copy_then_save_supplied_text_in_selected_profile(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    first, second = base / "profile_a", base / "profile_b"
    first.mkdir()
    second.mkdir()
    selected = base / "invented.scan"
    data = b"fictional document bytes"
    selected.write_bytes(data)
    transcript = base / "staged.txt"
    transcript.write_text("Вымышленный отчёт\n", encoding="utf-8")

    copied = invoke("copy", "--source", selected, "--archive-root", first)
    assert copied.returncode == 0
    payload = json.loads(copied.stdout)
    assert payload["status"] == "copied"
    assert payload["sha256"] == hashlib.sha256(data).hexdigest()
    assert Path(payload["path"]).read_bytes() == data
    assert list(second.iterdir()) == []
    assert invoke("copy", "--source", selected, "--archive-root", first).returncode == 0

    saved = invoke("save-text", "--document", payload["path"], "--archive-root", first,
                   "--text-file", transcript, "--expected-sha256", payload["sha256"])
    assert saved.returncode == 0
    result = json.loads(saved.stdout)
    assert result["status"] == "copied"
    assert result["review_status"] == "unverified"
    assert Path(result["path"]).name == "invented.scan.txt"
    assert Path(result["path"]).read_text(encoding="utf-8") == "Вымышленный отчёт\n"
    assert list(second.iterdir()) == []
    assert "Вымышленный отчёт" not in saved.stdout
    assert transcript.read_text(encoding="utf-8") == "Вымышленный отчёт\n"


def test_stdin_saves_without_staging_or_echo_and_can_retry(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    document = archive / "invented.scan"
    document.write_bytes(b"fictional document")
    unrelated = base / "unrelated.txt"
    unrelated.write_text("preserve caller file", encoding="utf-8")
    digest = hashlib.sha256(document.read_bytes()).hexdigest()
    content = "Синтетический текст\r\nПустая строка\n"
    args = ("save-text", "--document", document, "--archive-root", archive,
            "--text-stdin", "--expected-sha256", digest)

    first = invoke(*args, stdin_text=content)
    assert first.returncode == 0 and json.loads(first.stdout)["status"] == "copied"
    assert (archive / "invented.scan.txt").read_bytes() == content.encode("utf-8")
    assert content not in first.stdout + first.stderr
    assert sorted(p.name for p in base.iterdir()) == ["archive", "unrelated.txt"]
    assert sorted(p.name for p in archive.iterdir()) == ["invented.scan", "invented.scan.txt"]
    assert unrelated.read_text(encoding="utf-8") == "preserve caller file"

    retry = invoke(*args, stdin_text=content)
    assert retry.returncode == 0 and json.loads(retry.stdout)["status"] == "already_present"
    conflict = invoke(*args, stdin_text="different supplied text")
    assert conflict.returncode == 1
    assert json.loads(conflict.stdout)["error"] == "destination_conflict"
    assert (archive / "invented.scan.txt").read_bytes() == content.encode("utf-8")
    assert unrelated.read_text(encoding="utf-8") == "preserve caller file"


@pytest.mark.parametrize("payload", [pytest.param(b"\xff", id="invalid-utf8"),
                                     pytest.param(b"x" * (8 * 1024 * 1024 + 1), id="oversize")])
def test_stdin_invalid_or_oversize_fails_without_writes_or_echo(tmp_path: Path, payload: bytes) -> None:
    archive = tmp_path.resolve() / "archive"
    archive.mkdir()
    document = archive / "invented.bin"
    document.write_bytes(b"fictional")
    command = [sys.executable, "-I", "-B", str(SCRIPT), "save-text", "--document", str(document),
               "--archive-root", str(archive), "--text-stdin", "--expected-sha256",
               hashlib.sha256(document.read_bytes()).hexdigest()]
    result = subprocess.run(command, input=payload, capture_output=True, check=False)
    assert result.returncode == 1
    assert json.loads(result.stdout)["error"] == "operation_failed"
    assert not result.stderr
    assert payload[:32] not in result.stdout
    assert sorted(p.name for p in archive.iterdir()) == ["invented.bin"]


def test_stdin_wrong_hash_and_symlink_never_touch_user_files(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    document = archive / "invented.bin"
    document.write_bytes(b"fictional")
    unrelated = base / "unrelated.txt"
    unrelated.write_text("preserve caller file", encoding="utf-8")
    args = ("save-text", "--document", document, "--archive-root", archive, "--text-stdin")
    failed = invoke(*args, "--expected-sha256", "0" * 64, stdin_text="fictional text")
    assert failed.returncode == 1 and json.loads(failed.stdout)["error"] == "operation_failed"
    assert not (archive / "invented.bin.txt").exists()
    (archive / "invented.bin.txt").symlink_to(unrelated)
    blocked = invoke(*args, "--expected-sha256", hashlib.sha256(b"fictional").hexdigest(),
                     stdin_text="fictional text")
    assert blocked.returncode == 1
    assert unrelated.read_text(encoding="utf-8") == "preserve caller file"
    assert (archive / "invented.bin.txt").is_symlink()
    assert document.read_bytes() == b"fictional"


def test_stdin_rejects_tty_without_reading_or_writing(tmp_path: Path, monkeypatch, capsys) -> None:
    archive = tmp_path.resolve() / "archive"
    archive.mkdir()
    document = archive / "invented.bin"
    document.write_bytes(b"fictional")
    namespace = runpy.run_path(str(SCRIPT))
    entry = namespace["main"]

    class SyntheticTTY(io.TextIOWrapper):
        def isatty(self) -> bool:
            return True

    tty = SyntheticTTY(io.BytesIO(b"fictional text"), encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", tty)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "save-text", "--document", str(document),
        "--archive-root", str(archive), "--text-stdin", "--expected-sha256", "0" * 64])
    assert entry() == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_arguments"}
    assert tty.buffer.tell() == 0
    assert sorted(p.name for p in archive.iterdir()) == ["invented.bin"]


def test_file_input_is_never_removed_after_save_or_conflict(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    document = archive / "invented.bin"
    document.write_bytes(b"fictional")
    user_file = base / "caller-supplied.txt"
    user_file.write_text("original input", encoding="utf-8")
    args = ("save-text", "--document", document, "--archive-root", archive,
            "--text-file", user_file, "--expected-sha256", hashlib.sha256(b"fictional").hexdigest())
    assert invoke(*args).returncode == 0
    assert user_file.read_text(encoding="utf-8") == "original input"
    user_file.write_text("different input", encoding="utf-8")
    assert invoke(*args).returncode == 1
    assert user_file.read_text(encoding="utf-8") == "different input"
    assert (archive / "invented.bin.txt").read_text(encoding="utf-8") == "original input"


@pytest.mark.parametrize("extra", [[], ["--document", "/private-sensitive-name"]])
def test_invalid_arguments_do_not_echo_supplied_private_values(extra: list[str]) -> None:
    process = invoke("save-text", *extra)
    assert process.returncode == 2
    assert json.loads(process.stdout) == {"error": "invalid_arguments"}
    assert not process.stderr
    assert "private-sensitive-name" not in process.stdout


def test_conflict_rejected_and_error_excludes_contents_and_paths(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "secret-person-path"
    archive.mkdir()
    source = base / "file-with-sensitive-name.png"
    source.write_bytes(b"one")
    assert invoke("copy", "--source", source, "--archive-root", archive).returncode == 0
    source.write_bytes(b"different")
    conflict = invoke("copy", "--source", source, "--archive-root", archive)
    assert conflict.returncode == 1
    assert json.loads(conflict.stdout) == {"error": "destination_conflict", "partial_write_possible": True}
    assert not conflict.stderr
    assert "secret-person-path" not in conflict.stdout
    assert "file-with-sensitive-name" not in conflict.stdout
    assert (archive / source.name).read_bytes() == b"one"


def test_wrong_hash_and_profile_fail_without_writing_or_leaking_values(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    first, second = base / "profile_a", base / "profile_b"
    first.mkdir()
    second.mkdir()
    document = first / "synthetic.bin"
    document.write_bytes(b"fictional")
    text = base / "staged.txt"
    text.write_text("private-text-marker", encoding="utf-8")
    result = invoke("save-text", "--document", document, "--archive-root", second,
                    "--text-file", text, "--expected-sha256", "0" * 64)
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"error": "operation_failed", "partial_write_possible": True}
    assert not result.stderr
    assert "private-text-marker" not in result.stdout
    assert "profile_a" not in result.stdout
    assert list(second.iterdir()) == []
    assert sorted(path.name for path in first.iterdir()) == ["synthetic.bin"]


def test_text_is_read_from_file_not_command_argument(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    document = archive / "invented.bin"
    document.write_bytes(b"invented")
    result = invoke("save-text", "--document", document, "--archive-root", archive,
                    "--text", "sensitive-plaintext", "--expected-sha256", "0" * 64)
    assert result.returncode == 2
    assert "sensitive-plaintext" not in result.stdout + result.stderr
    assert not (archive / "invented.bin.txt").exists()


def test_configured_unicode_profiles_isolate_operations(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    first, second = base / "archive_1", base / "archive_2"
    first.mkdir()
    second.mkdir()
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [
        {"id": "a1", "label": "Вымышленный А", "root": str(first)},
        {"id": "b2", "label": "Вымышленный Б", "root": str(second)},
    ]}, ensure_ascii=False), encoding="utf-8")
    source = base / "sample.image"
    source.write_bytes(b"fictional data")
    result = invoke("copy", "--config", config, "--profile", "Вымышленный Б", "--source", source)
    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    assert parsed["identity_assignment"] == "explicit_profile"
    assert parsed["warnings"] == []
    assert (second / source.name).read_bytes() == b"fictional data"
    assert list(first.iterdir()) == []
    stage = base / "stage.txt"
    stage.write_text("fictional transcription", encoding="utf-8")
    text = invoke("save-text", "--config", config, "--profile", "b2", "--document", second / source.name,
                  "--text-file", stage, "--expected-sha256", parsed["sha256"])
    assert text.returncode == 0
    assert (second / "sample.image.txt").read_text() == "fictional transcription"
    assert list(first.iterdir()) == []


@pytest.mark.parametrize("profile_args", [[], ["--profile", "unknown"], ["--profile", ""],
                                           ["--profile", "x", "--archive-root", "/tmp"]])
def test_missing_unknown_and_conflicting_profiles_fail_without_writes(tmp_path: Path, profile_args) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [{"id": "p", "label": "Пример", "root": str(archive)}]}))
    source = base / "doc.bin"
    source.write_bytes(b"invented")
    result = invoke("copy", "--config", config, "--source", source, *profile_args)
    assert result.returncode != 0
    assert json.loads(result.stdout)["error"] in {"invalid_arguments", "operation_failed"}
    assert list(archive.iterdir()) == []


def test_reused_broad_permission_and_sidecar_role_warnings_are_visible(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    original = base / "document.pdf"
    original.write_bytes(b"invented")
    first = json.loads(invoke("copy", "--source", original, "--archive-root", archive).stdout)
    target = Path(first["path"])
    target.chmod(0o644)
    reused = json.loads(invoke("copy", "--source", original, "--archive-root", archive).stdout)
    assert "existing_permissions_allow_group_or_other_mode_bits" in reused["warnings"]
    stage = base / "stage.txt"
    stage.write_text("invented transcript")
    args = ("save-text", "--document", target, "--archive-root", archive,
            "--text-file", stage, "--expected-sha256", first["sha256"])
    json.loads(invoke(*args).stdout)
    repeated = json.loads(invoke(*args).stdout)
    assert "source_permissions_allow_group_or_other_mode_bits" in repeated["warnings"]
    assert "existing_text_role_and_source_unverified" in repeated["warnings"]
    assert (target.stat().st_mode & 0o777) == 0o644


def test_profile_rebinding_after_copy_fails_with_partial_write_notice(tmp_path: Path, monkeypatch, capsys) -> None:
    base = tmp_path.resolve()
    first, second = base / "archive_a", base / "archive_b"
    first.mkdir()
    second.mkdir()
    config = base / "profiles.json"

    def write_config(root: Path) -> None:
        config.write_text(json.dumps({"profiles": [{"id": "p", "label": "Пример", "root": str(root)}]}))

    write_config(first)
    source = base / "sample.bin"
    source.write_bytes(b"invented")
    namespace = runpy.run_path(str(SCRIPT))
    entry = namespace["main"]
    environment = entry.__globals__
    real_copy = environment["copy_authorized_document"]

    def change_profile_after_copy(*args, **kwargs):
        result = real_copy(*args, **kwargs)
        write_config(second)
        return result

    monkeypatch.setitem(environment, "copy_authorized_document", change_profile_after_copy)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "copy", "--source", str(source),
                                       "--config", str(config), "--profile", "p"])
    assert entry() == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {"error": "operation_failed", "partial_write_possible": True}
    assert not output.err
    assert (first / source.name).read_bytes() == b"invented"
    assert list(second.iterdir()) == []


def test_actual_process_death_after_publication_requires_read_only_inspection(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    source = base / "synthetic.bin"
    source.write_bytes(b"invented")
    # Synthetic child exits immediately after the OS publishes the hardlink,
    # before the normal finally-block can remove its temporary name.
    crash = """
import os, signal, sys
from pathlib import Path
from health_analyzer import document_files
real_link = os.link
def terminate_after_link(*args, **kwargs):
    real_link(*args, **kwargs)
    os.kill(os.getpid(), signal.SIGKILL)
os.supports_dir_fd.add(terminate_after_link)
os.link = terminate_after_link
document_files.copy_authorized_document(Path(sys.argv[1]), Path(sys.argv[2]))
"""
    child = subprocess.run([sys.executable, "-c", crash, str(source), str(archive)],
                           capture_output=True, text=True, check=False)
    assert child.returncode == -signal.SIGKILL
    destination = archive / source.name
    assert destination.read_bytes() == b"invented" and destination.stat().st_nlink == 2
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    before = sorted(p.name for p in archive.iterdir())
    retry = invoke("copy", "--source", source, "--archive-root", archive)
    assert retry.returncode == 1
    assert json.loads(retry.stdout) == {"error": "hardlink_review_required", "partial_write_possible": True,
                                        "next_step": "inspect_pending_without_deleting"}
    check = invoke("inspect-pending", "--archive-root", archive, "--destination", source.name,
                   "--expected-sha256", digest)
    assert check.returncode == 0
    result = json.loads(check.stdout)
    assert result["status"] == "possible_interrupted_publication"
    assert result["origin_of_candidate"] == "unverified" and result["automatic_changes"] is False
    candidate = archive / result["candidate_name"]
    assert candidate.stat().st_ino == destination.stat().st_ino
    assert sorted(p.name for p in archive.iterdir()) == before
    # A human/operator could separately verify and remove the appropriate link;
    # this synthetic test exercises that decision, never automatic deletion.
    candidate.unlink()
    assert invoke("copy", "--source", source, "--archive-root", archive).returncode == 0


def test_inspection_never_infers_or_deletes_a_foreign_hardlink(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    destination = archive / "synthetic.bin"
    destination.write_bytes(b"invented")
    import os
    other = archive / "different-original.bin"
    os.link(destination, other)
    result = invoke("inspect-pending", "--archive-root", archive, "--destination", destination.name,
                    "--expected-sha256", hashlib.sha256(b"invented").hexdigest())
    assert result.returncode == 0
    parsed = json.loads(result.stdout)
    assert parsed["status"] == "manual_review_required"
    assert parsed["candidate_name"] is None and parsed["automatic_changes"] is False
    assert destination.exists() and other.exists()


def test_ensure_folder_uses_selected_unicode_profile_only(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    first, second = base / "archive_a", base / "archive_b"
    first.mkdir()
    second.mkdir()
    config = base / "profiles.json"
    config.write_text(json.dumps({"profiles": [
        {"id": "a1", "label": "Вымышленный А", "root": str(first)},
        {"id": "b2", "label": "Вымышленный Б", "root": str(second)},
    ]}, ensure_ascii=False), encoding="utf-8")
    args = ("ensure-folder", "--config", config, "--profile", "Вымышленный Б", "--folder", "тест/отчёты")
    result = invoke(*args)
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "created" and payload["created_count"] == 2
    assert "concurrent_folder_moves_are_not_isolated" in payload["warnings"]
    assert (second / "тест" / "отчёты").is_dir()
    assert list(first.iterdir()) == []
    repeated = invoke(*args)
    assert repeated.returncode == 0
    assert json.loads(repeated.stdout)["status"] == "already_present"
    assert list(first.iterdir()) == []


def test_ensure_folder_failure_reports_possible_partial_folders_without_private_paths(tmp_path: Path) -> None:
    base = tmp_path.resolve()
    archive = base / "private-profile"
    archive.mkdir()
    (archive / "blocked").write_bytes(b"invented")
    result = invoke("ensure-folder", "--archive-root", archive, "--folder", "blocked/inner")
    assert result.returncode == 1
    parsed = json.loads(result.stdout)
    assert parsed["error"] == "operation_failed"
    assert parsed["partial_write_possible"] and parsed["partial_folder_possible"]
    assert parsed["concurrent_moves_may_leave_folders_outside_root"]
    assert "private-profile" not in result.stdout + result.stderr
    assert (archive / "blocked").read_bytes() == b"invented"


def test_config_replaced_with_equal_content_is_detected_before_folder_creation(tmp_path: Path, monkeypatch, capsys) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    config = base / "profiles.json"
    content = json.dumps({"profiles": [{"id": "p", "label": "Пример", "root": str(archive)}]})
    config.write_text(content)
    namespace = runpy.run_path(str(SCRIPT))
    entry = namespace["main"]
    environment = entry.__globals__
    real_load = environment["load_profiles"]

    def swap_after_loading(*args, **kwargs):
        profiles = real_load(*args, **kwargs)
        config.rename(base / "old-config.json")
        config.write_text(content)
        return profiles

    monkeypatch.setitem(environment, "load_profiles", swap_after_loading)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "ensure-folder", "--config", str(config),
                                       "--profile", "p", "--folder", "intended"])
    assert entry() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["partial_folder_possible"] and payload["error"] == "operation_failed"
    assert list(archive.iterdir()) == []


def test_config_replaced_after_folder_creation_reports_partial_state(tmp_path: Path, monkeypatch, capsys) -> None:
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    config = base / "profiles.json"
    content = json.dumps({"profiles": [{"id": "p", "label": "Пример", "root": str(archive)}]})
    config.write_text(content)
    namespace = runpy.run_path(str(SCRIPT))
    entry = namespace["main"]
    environment = entry.__globals__
    real_ensure = environment["ensure_folder"]

    def swap_after_folder_creation(*args, **kwargs):
        result = real_ensure(*args, **kwargs)
        config.rename(base / "old-config.json")
        config.write_text(content)
        return result

    monkeypatch.setitem(environment, "ensure_folder", swap_after_folder_creation)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "ensure-folder", "--config", str(config),
                                       "--profile", "p", "--folder", "intended"])
    assert entry() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["partial_folder_possible"] and payload["error"] == "operation_failed"
    assert (archive / "intended").is_dir()
