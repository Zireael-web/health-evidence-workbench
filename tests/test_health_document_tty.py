"""Synthetic PTY transcript protocol tests; no personal or medical data."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import termios
import time
import fcntl

import pytest

from health_analyzer import document_files as storage
from health_analyzer.local_intake import LocalIntakeError


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "health-document"


def _line(fd: int, timeout: float = 10.0) -> bytes:
    result = bytearray()
    deadline = time.monotonic() + timeout
    while not result.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([fd], [], [], remaining)[0], "PTY output timed out"
        result.extend(os.read(fd, 1))
    return bytes(result).replace(b"\r\n", b"\n")


def _send(fd: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        remaining = remaining[os.write(fd, remaining):]


@pytest.fixture
def terminal_process(tmp_path: Path):
    base = tmp_path.resolve()
    archive = base / "archive"
    archive.mkdir()
    document = archive / "synthetic.bin"
    document.write_bytes(b"fictional source")
    user_file = base / "caller-owned.txt"
    user_file.write_bytes(b"unchanged caller file")
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    original_blocking = os.get_blocking(slave)
    args = [sys.executable, "-I", "-B", str(SCRIPT), "save-text", "--text-tty",
            "--document", str(document), "--archive-root", str(archive),
            "--expected-sha256", hashlib.sha256(document.read_bytes()).hexdigest()]
    process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    try:
        yield process, master, slave, original, original_blocking, archive, document, user_file
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
        os.close(slave)


def _assert_restored(slave: int, original: list, blocking: bool) -> None:
    assert termios.tcgetattr(slave) == original
    assert os.get_blocking(slave) == blocking


def test_tty_long_unicode_roundtrip_has_no_echo_or_staging(terminal_process) -> None:
    process, master, slave, original, blocking, archive, document, user_file = terminal_process
    assert _line(master) == b"READY\n"
    actual = termios.tcgetattr(slave)
    assert not (actual[3] & (termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG))
    text = "ВЫМЫШЛЕННАЯ СТРОКА: абвгд\r\n" * 1000
    _send(master, text.encode("utf-8") + b"\x04")
    confirmation = _line(master)
    assert re.fullmatch(rb"CONFIRM:[0-9a-f]{32}\n", confirmation)
    _send(master, confirmation)
    response = _line(master)
    assert json.loads(response)["status"] == "copied"
    assert text.encode("utf-8")[:50] not in confirmation + response
    assert process.wait(timeout=5) == 0
    assert (archive / "synthetic.bin.txt").read_bytes() == text.encode("utf-8")
    assert sorted(p.name for p in archive.iterdir()) == ["synthetic.bin", "synthetic.bin.txt"]
    assert user_file.read_bytes() == b"unchanged caller file"
    assert document.read_bytes() == b"fictional source"
    _assert_restored(slave, original, blocking)


def test_second_process_inheriting_same_tty_is_rejected_before_changing_state(tmp_path: Path) -> None:
    archive = tmp_path.resolve() / "archive"
    archive.mkdir()
    document = archive / "synthetic.bin"
    document.write_bytes(b"fictional source")
    master, slave = pty.openpty()
    original, blocking = termios.tcgetattr(slave), os.get_blocking(slave)
    args = [sys.executable, "-I", "-B", str(SCRIPT), "save-text", "--text-tty",
            "--document", str(document), "--archive-root", str(archive),
            "--expected-sha256", hashlib.sha256(document.read_bytes()).hexdigest()]
    first = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    second = None
    try:
        assert first.stdout is not None and _line(first.stdout.fileno()) == b"READY\n"
        first_state = termios.tcgetattr(slave)
        assert not (first_state[3] & termios.ECHO)
        # Both children inherit the SAME slave open-file description. The
        # second must not be able to obtain the independently opened device lock.
        second = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, errors = second.communicate(timeout=5)
        assert second.returncode == 1 and json.loads(output)["error"] == "operation_failed"
        assert b"READY" not in output and not errors
        assert termios.tcgetattr(slave) == first_state

        text = "Синтетический текст\n".encode("utf-8")
        _send(master, text + b"\x04")
        confirmation = _line(first.stdout.fileno())
        assert re.fullmatch(rb"CONFIRM:[0-9a-f]{32}\n", confirmation)
        assert not select.select([master], [], [], 0.05)[0], "input was echoed to the terminal"
        _send(master, confirmation)
        assert json.loads(_line(first.stdout.fileno()))["status"] == "copied"
        assert first.wait(timeout=5) == 0
        assert (archive / "synthetic.bin.txt").read_bytes() == text
        _assert_restored(slave, original, blocking)
    finally:
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        os.close(master)
        os.close(slave)


def test_terminal_lock_fails_closed_if_exclusivity_is_not_enforced(monkeypatch) -> None:
    master, slave = pty.openpty()
    original, blocking = termios.tcgetattr(slave), os.get_blocking(slave)
    stream = os.fdopen(os.dup(slave), "rb", buffering=0)
    marks: list[str] = []
    monkeypatch.setattr(fcntl, "flock", lambda _fd, _operation: None)
    try:
        with pytest.raises(LocalIntakeError, match="not exclusive"):
            storage.read_supplied_transcript_tty(stream, marks.append)
        assert marks == []
        _assert_restored(slave, original, blocking)
    finally:
        stream.close()
        os.close(master)
        os.close(slave)


def test_tty_eot_in_content_fails_without_saving(terminal_process) -> None:
    process, master, slave, original, blocking, archive, _, user_file = terminal_process
    assert _line(master) == b"READY\n"
    _send(master, b"fictional prefix\x04fictional suffix\x04")
    first = _line(master)
    # If the suffix arrived in a later OS read, it is rejected as an invalid
    # confirmation; otherwise the initial frame is rejected immediately.
    if first.startswith(b"CONFIRM:"):
        first = _line(master)
    assert json.loads(first)["error"] == "operation_failed"
    assert process.wait(timeout=5) == 1
    assert not (archive / "synthetic.bin.txt").exists()
    assert user_file.read_bytes() == b"unchanged caller file"
    _assert_restored(slave, original, blocking)


def test_tty_wrong_nonce_fails_without_saving(terminal_process) -> None:
    process, master, slave, original, blocking, archive, _, _ = terminal_process
    assert _line(master) == b"READY\n"
    _send(master, b"fictional text\x04")
    confirmation = _line(master)
    assert confirmation.startswith(b"CONFIRM:")
    _send(master, b"CONFIRM:" + b"z" * 32 + b"\n")
    assert json.loads(_line(master))["error"] == "operation_failed"
    assert process.wait(timeout=5) == 1
    assert not (archive / "synthetic.bin.txt").exists()
    _assert_restored(slave, original, blocking)


def test_tty_nonce_cannot_be_replayed_in_another_session(terminal_process) -> None:
    process, master, slave, original, blocking, archive, document, user_file = terminal_process
    assert _line(master) == b"READY\n"
    _send(master, b"fictional text\x04")
    old_confirmation = _line(master)
    _send(master, b"wrong confirmation\n")
    assert json.loads(_line(master))["error"] == "operation_failed"
    assert process.wait(timeout=5) == 1
    _assert_restored(slave, original, blocking)

    next_master, next_slave = pty.openpty()
    next_original, next_blocking = termios.tcgetattr(next_slave), os.get_blocking(next_slave)
    args = [sys.executable, "-I", "-B", str(SCRIPT), "save-text", "--text-tty",
            "--document", str(document), "--archive-root", str(archive),
            "--expected-sha256", hashlib.sha256(document.read_bytes()).hexdigest()]
    next_process = subprocess.Popen(args, stdin=next_slave, stdout=next_slave, stderr=next_slave, close_fds=True)
    try:
        assert _line(next_master) == b"READY\n"
        _send(next_master, b"fictional text\x04")
        new_confirmation = _line(next_master)
        assert re.fullmatch(rb"CONFIRM:[0-9a-f]{32}\n", new_confirmation)
        assert new_confirmation != old_confirmation
        _send(next_master, old_confirmation)
        assert json.loads(_line(next_master))["error"] == "operation_failed"
        assert next_process.wait(timeout=5) == 1
        assert not (archive / "synthetic.bin.txt").exists()
        assert user_file.read_bytes() == b"unchanged caller file"
        _assert_restored(next_slave, next_original, next_blocking)
    finally:
        if next_process.poll() is None:
            next_process.kill()
            next_process.wait(timeout=5)
        os.close(next_master)
        os.close(next_slave)


def test_tty_invalid_utf8_fails_without_confirming_or_saving(terminal_process) -> None:
    process, master, slave, original, blocking, archive, _, _ = terminal_process
    assert _line(master) == b"READY\n"
    _send(master, b"\xff\x04")
    assert json.loads(_line(master))["error"] == "operation_failed"
    assert process.wait(timeout=5) == 1
    assert not (archive / "synthetic.bin.txt").exists()
    _assert_restored(slave, original, blocking)


def test_tty_interruption_at_confirmation_restores_terminal(terminal_process) -> None:
    process, master, slave, original, blocking, archive, _, _ = terminal_process
    assert _line(master) == b"READY\n"
    _send(master, b"fictional text\x04")
    assert _line(master).startswith(b"CONFIRM:")
    process.send_signal(signal.SIGTERM)
    assert json.loads(_line(master))["error"] == "operation_failed"
    assert process.wait(timeout=5) == 1
    assert not (archive / "synthetic.bin.txt").exists()
    _assert_restored(slave, original, blocking)


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGTSTP])
def test_tty_interrupt_restores_terminal_without_saving(terminal_process, signum: int) -> None:
    process, master, slave, original, blocking, archive, _, _ = terminal_process
    assert _line(master) == b"READY\n"
    process.send_signal(signum)
    assert json.loads(_line(master))["error"] == "operation_failed"
    assert process.wait(timeout=5) == 1
    assert not (archive / "synthetic.bin.txt").exists()
    _assert_restored(slave, original, blocking)


def test_tty_refuses_non_terminal_without_ready_or_write(tmp_path: Path) -> None:
    archive = tmp_path.resolve() / "archive"
    archive.mkdir()
    document = archive / "synthetic.bin"
    document.write_bytes(b"fictional")
    args = [sys.executable, "-I", "-B", str(SCRIPT), "save-text", "--text-tty",
            "--document", str(document), "--archive-root", str(archive),
            "--expected-sha256", hashlib.sha256(b"fictional").hexdigest()]
    result = subprocess.run(args, input=b"fictional\x04", capture_output=True, check=False)
    assert result.returncode == 1
    assert json.loads(result.stdout)["error"] == "operation_failed"
    assert b"READY" not in result.stdout and not result.stderr
    assert list(archive.iterdir()) == [document]


def test_tty_closed_input_fails_without_saving(tmp_path: Path) -> None:
    archive = tmp_path.resolve() / "archive"
    archive.mkdir()
    document = archive / "synthetic.bin"
    document.write_bytes(b"fictional")
    master, slave = pty.openpty()
    args = [sys.executable, "-I", "-B", str(SCRIPT), "save-text", "--text-tty",
            "--document", str(document), "--archive-root", str(archive),
            "--expected-sha256", hashlib.sha256(b"fictional").hexdigest()]
    process = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    master_open = True
    try:
        assert process.stdout is not None and process.stdout.readline() == b"READY\n"
        os.close(master)
        master_open = False
        output, error = process.communicate(timeout=5)
        assert process.returncode != 0
        assert json.loads(output)["error"] == "operation_failed"
        assert not error
        assert list(archive.iterdir()) == [document]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if master_open:
            os.close(master)
        os.close(slave)


def test_tty_timeout_and_reentrancy_restore_state(monkeypatch) -> None:
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    blocking = os.get_blocking(slave)
    original_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    monkeypatch.setattr(storage, "_TTY_INPUT_TIMEOUT_SECONDS", 0.03)
    marks: list[str] = []
    stream = os.fdopen(os.dup(slave), "rb", buffering=0)

    def announce(mark: str) -> None:
        marks.append(mark)
        if mark == "READY":
            with pytest.raises(LocalIntakeError, match="already active"):
                storage.read_supplied_transcript_tty(stream, lambda _mark: None)

    try:
        with pytest.raises(LocalIntakeError, match="timed out"):
            storage.read_supplied_transcript_tty(stream, announce)
        assert marks == ["READY"]
        _assert_restored(slave, original, blocking)
        assert {sig: signal.getsignal(sig) for sig in original_handlers} == original_handlers
    finally:
        stream.close()
        os.close(master)
        os.close(slave)


def test_repeated_signals_during_cleanup_do_not_skip_terminal_restoration(monkeypatch) -> None:
    master, slave = pty.openpty()
    original, blocking = termios.tcgetattr(slave), os.get_blocking(slave)
    stream = os.fdopen(os.dup(slave), "rb", buffering=0)
    monkeypatch.setattr(storage, "_TTY_INPUT_TIMEOUT_SECONDS", 0.03)
    previous_handler = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda _number, _frame: None)
    original_mask = signal.pthread_sigmask
    injected = False

    def inject_at_cleanup(how, mask):
        nonlocal injected
        if how == signal.SIG_BLOCK and not injected:
            injected = True
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGTERM)
        return original_mask(how, mask)

    monkeypatch.setattr(signal, "pthread_sigmask", inject_at_cleanup)
    try:
        with pytest.raises(LocalIntakeError, match="interrupted"):
            storage.read_supplied_transcript_tty(stream, lambda _mark: None)
        assert injected
        _assert_restored(slave, original, blocking)
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        stream.close()
        os.close(master)
        os.close(slave)


def test_signal_after_confirmation_aborts_instead_of_returning_text(monkeypatch) -> None:
    master, slave = pty.openpty()
    original, blocking = termios.tcgetattr(slave), os.get_blocking(slave)
    stream = os.fdopen(os.dup(slave), "rb", buffering=0)
    real_read = os.read
    injected = False

    def read_and_interrupt(fd: int, count: int) -> bytes:
        nonlocal injected
        data = real_read(fd, count)
        if data.startswith(b"CONFIRM:") and not injected:
            injected = True
            os.kill(os.getpid(), signal.SIGINT)
        return data

    def announce(mark: str) -> None:
        if mark == "READY":
            _send(master, b"fictional text\x04")
        elif mark.startswith("CONFIRM:"):
            _send(master, (mark + "\n").encode("ascii"))

    monkeypatch.setattr(os, "read", read_and_interrupt)
    try:
        with pytest.raises(LocalIntakeError, match="interrupted"):
            storage.read_supplied_transcript_tty(stream, announce)
        assert injected
        _assert_restored(slave, original, blocking)
    finally:
        stream.close()
        os.close(master)
        os.close(slave)


def test_tty_confirmation_timeout_restores_state(monkeypatch) -> None:
    master, slave = pty.openpty()
    original, blocking = termios.tcgetattr(slave), os.get_blocking(slave)
    monkeypatch.setattr(storage, "_TTY_CONFIRM_TIMEOUT_SECONDS", 0.03)
    marks: list[str] = []
    stream = os.fdopen(os.dup(slave), "rb", buffering=0)

    def announce(mark: str) -> None:
        marks.append(mark)
        if mark == "READY":
            _send(master, b"fictional text\x04")

    try:
        with pytest.raises(LocalIntakeError, match="timed out"):
            storage.read_supplied_transcript_tty(stream, announce)
        assert marks[0] == "READY" and marks[1].startswith("CONFIRM:")
        _assert_restored(slave, original, blocking)
    finally:
        stream.close()
        os.close(master)
        os.close(slave)


def test_tty_partial_configuration_failure_restores_state(monkeypatch) -> None:
    master, slave = pty.openpty()
    original, blocking = termios.tcgetattr(slave), os.get_blocking(slave)
    original_setattr = termios.tcsetattr
    calls = 0
    marks: list[str] = []
    stream = os.fdopen(os.dup(slave), "rb", buffering=0)

    def fail_after_setting(fd: int, action: int, state: list) -> None:
        nonlocal calls
        calls += 1
        original_setattr(fd, action, state)
        if calls == 1:
            raise termios.error("synthetic terminal failure")

    monkeypatch.setattr(termios, "tcsetattr", fail_after_setting)
    try:
        with pytest.raises(LocalIntakeError, match="failed"):
            storage.read_supplied_transcript_tty(stream, marks.append)
        assert not marks and calls == 2
        _assert_restored(slave, original, blocking)
    finally:
        stream.close()
        os.close(master)
        os.close(slave)


def test_tty_exceeds_bounded_limit_without_confirmation(monkeypatch) -> None:
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    blocking = os.get_blocking(slave)
    monkeypatch.setattr(storage, "MAX_TEXT_BYTES", 3)
    marks: list[str] = []
    stream = os.fdopen(os.dup(slave), "rb", buffering=0)

    def announce(mark: str) -> None:
        marks.append(mark)
        if mark == "READY":
            _send(master, b"four")

    try:
        with pytest.raises(LocalIntakeError, match="limit"):
            storage.read_supplied_transcript_tty(stream, announce)
        assert marks == ["READY"]
        _assert_restored(slave, original, blocking)
    finally:
        stream.close()
        os.close(master)
        os.close(slave)
